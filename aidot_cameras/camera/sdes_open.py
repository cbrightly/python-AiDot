"""SDES-SRTP stream-open state machine, split out of client.py.

``CameraMixin._open_sdes_stream`` is the ~3.6k-line SDES open path (isDTLS=='0'
cameras: battery / PTZ).  It lives here as a mixin to keep client.py readable;
behaviour-preserving (the method body is unchanged except for a lazy import that
breaks the client<->sdes_open cycle).  CameraMixin inherits this mixin, so
``self`` is a full CameraMixin at runtime.
"""

import asyncio
import json
import logging
import os
import random
import re
import secrets as _secrets_mod
import time
from typing import Callable, Optional  # noqa: F401 - method annotations

from ..exceptions import AidotCameraBusy, AidotCameraNoMedia
from .constants import (
    _LIVE_PLAY_NOT_READY,
    SDES_SPEAKERSTART_DELAY,
    stun_server_uris,
)
from .models import VideoFrame  # noqa: F401 - forward-ref annotation
from .sdes import SdesSession
from .protocol import (
    AVIO_HDR_LEN,
    REMB_TARGET_BPS,
    AvioResponseRouter,
    NackTracker,
    build_nack,
    build_remb,
    build_tmmbr,
    _build_sprop,
    parse_avio_response,
    _build_stun_binding_success_response,
    _extract_param_sets_from_rtp,
    _grab_free_port,
    _inject_sprop,
    _load_sprop,
    _make_sdp_tempfile,
    _rewrite_serve_port,
    _save_sprop,
    _write_text_file,
)

import os as _os

_LOGGER = logging.getLogger(__name__)


#: What we ask the kernel for on a media receive socket.  The kernel clamps to
#: ``net.core.rmem_max`` (4 MB on Home Assistant OS), and doubles what it grants
#: for bookkeeping, so asking for more than the cap is harmless.
_MEDIA_RCVBUF_BYTES = 4 * 1024 * 1024


#: Most a half-assembled SCTP message may grow to before we drop it. The
#: largest real reply measured is a ~2.8 KB SD listing page; this is ~23x that,
#: so it bounds a stream that never sends its E fragment without truncating
#: anything the camera actually sends.
_SCTP_REASSEMBLY_CAP = 64 * 1024


def _sctp_reassemble(flags: int, stream_id: int, payload: bytes,
                     buf: dict) -> "Optional[bytes]":
    """Reassemble a fragmented SCTP DATA message, or None until it is complete.

    RFC 4960 s3.3.1 puts two flags in the DATA chunk header: **B** (0x02) begins
    a message and **E** (0x01) ends it. A chunk with both set is a whole
    message; a large one arrives as B, then zero or more middles, then E.

    We never did this. The camera's SD listing reply is ~2.8 KB and arrives as
    several ~1.2 KB fragments, and every fragment was handed to
    ``parse_avio_response`` as if it were a complete frame. The first was
    REJECTED (its declared payload length overruns the fragment, and the parser
    correctly refuses to hand back a truncated payload), and the rest decoded as
    junk commands - `cmd=0`, `cmd=304939521`. So the reply sat on the wire while
    the caller timed out and Home Assistant told the user "the camera did not
    answer when asked what it holds".

    aiortc reassembles for the DTLS path, which is exactly why SD listing worked
    there and never on SDES.

    ``buf`` is per-association state, keyed by stream id. A middle or end
    fragment with no beginning is dropped rather than guessed at, and a stream
    that never sends its E fragment is capped rather than allowed to grow.
    """
    begins = bool(flags & 0x02)
    ends = bool(flags & 0x01)
    if begins and ends:
        buf.pop(stream_id, None)
        return payload
    if begins:
        buf[stream_id] = bytearray(payload)
        return None
    held = buf.get(stream_id)
    if held is None:
        # A continuation for a message we never saw the start of. Guessing here
        # would feed the AVIO parser a body with no header.
        return None
    held += payload
    if len(held) > _SCTP_REASSEMBLY_CAP:
        buf.pop(stream_id, None)
        return None
    if ends:
        return bytes(buf.pop(stream_id))
    return None


async def _await_rtsp_publish_target(url: "Optional[str]", *,
                                     timeout: float = 20.0) -> bool:
    """Wait until an ``rtsp://host:port`` target accepts a connection.

    Publishing into go2rtc is a race after a Home Assistant restart: the serve
    ffmpeg is launched as soon as media arrives, and go2rtc's RTSP listener may
    not be back yet. ffmpeg then fails its very first connect with
    ``Connection refused``, reports ``Could not write header (incorrect codec
    parameters ?)``, and exits 145 -- which reads as "stream ended" and takes
    that camera's view down until something retries.

    Measured on a live box: every occurrence of that failure sat inside a
    one-minute window around an HA restart (11:32, 11:43, 11:49, 11:52, 11:54,
    11:56, 11:57 on 2026-09-01, and the same shape the night before), and none
    in steady state.

    Returns True when the port accepts, False on timeout. False is not fatal --
    the caller launches ffmpeg anyway, because a target that never opens is a
    different problem and should surface as ffmpeg's own error rather than as a
    silent refusal to start.
    """
    if not url or not url.startswith("rtsp://"):
        return True
    try:
        rest = url[len("rtsp://"):]
        hostport = rest.split("/", 1)[0]
        if "@" in hostport:
            hostport = hostport.rsplit("@", 1)[1]
        if hostport.startswith("["):            # IPv6 literal
            if "]" not in hostport:
                return True                      # malformed: do not block
            host, _, tail = hostport[1:].partition("]")
            port = int(tail.lstrip(":") or 554)
        else:
            host, _, port_s = hostport.partition(":")
            port = int(port_s or 554)
    except (ValueError, IndexError):
        return True                              # unparseable: do not block

    _deadline = time.monotonic() + timeout
    _attempt = 0
    while time.monotonic() < _deadline:
        _attempt += 1
        try:
            _r, _w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0)
            _w.close()
            try:
                await _w.wait_closed()
            except Exception:
                pass
            if _attempt > 1:
                _LOGGER.info(
                    "publish target %s:%s accepted after %d attempts",
                    host, port, _attempt)
            return True
        except (OSError, TimeoutError):
            await asyncio.sleep(0.5)
    _LOGGER.warning(
        "publish target %s:%s did not accept a connection within %.0fs - "
        "launching ffmpeg anyway so its own error surfaces", host, port, timeout)
    return False


def _local_ipv4_networks():
    """The IPv4 networks this host is actually on, as ``ipaddress`` networks.

    Best-effort and deliberately conservative: it asks the OS which source
    address it would use to reach the internet and assumes a /24 around it,
    which is the common home case. A wrong guess here must never block a
    candidate, so callers treat "not in this set" as a hint, not a verdict.
    """
    import ipaddress as _ipa
    import socket as _sk
    nets = []
    try:
        _s = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM)
        try:
            _s.connect(("8.8.8.8", 53))
            _ip = _s.getsockname()[0]
        finally:
            _s.close()
        nets.append(_ipa.ip_network(f"{_ip}/24", strict=False))
    except Exception:
        pass
    return nets


def _candidate_is_off_subnet(ip: str) -> bool:
    """True when ``ip`` is a private address on a subnet this host is not on.

    A camera whose only ICE candidate is such an address cannot be reached
    directly, no matter how long we wait: the packets leave via the default
    gateway and are dropped. Measured on an A001513 advertising
    ``192.168.100.4`` to a host on ``192.168.0.0/24`` -- STUN binding successes
    still accumulate (they come back by other paths), the data channel never
    establishes, and the session spends its whole 75 s first-media budget on a
    path that never had a chance.

    Public addresses return False: those are relay and reflexive candidates and
    are reached through the gateway by design.
    """
    import ipaddress as _ipa
    try:
        _a = _ipa.ip_address(ip)
    except ValueError:
        return False
    if not _a.is_private or _a.is_loopback or _a.is_link_local:
        return False
    nets = _local_ipv4_networks()
    if not nets:
        return False                      # cannot tell - never call it off-subnet
    return not any(_a in _n for _n in nets)


def _sctp_sack_chunk(cum_tsn: int, a_rwnd: int = 131072) -> bytes:
    """An SCTP SACK (RFC 4960 s3.3.4) with no gap blocks and no duplicates.

    SCTP puts acknowledgement on the RECEIVER. We were never sending one: the
    camera pushed a DATA chunk every ~3 s on the control channel and we replied
    to none of them, so its retransmission timer ran to exhaustion and it tore
    the association down with an ABORT at 61.42 s (sd 0.10, n=47) -- after which
    our AVIO heartbeat could no longer refresh the camera's keepalive clock and
    ``rtc_session_check_keepalive`` disconnected the whole session 20 s later.
    That is the 80.2 s cliff, and it is also why PTZ, talkback and SD listing
    stopped answering about a minute into every session: they all ride this
    channel.

    Reporting no gap blocks when a chunk IS missing is legal and conservative -
    the cumulative ack simply does not advance, and the camera retransmits what
    we have not acknowledged.
    """
    import struct as _st_sk
    body = _st_sk.pack("!IIHH", cum_tsn & 0xFFFFFFFF, a_rwnd, 0, 0)
    return _st_sk.pack("!BBH", 3, 0, 4 + len(body)) + body


def _sctp_advance_cum_tsn(cum: "Optional[int]", tsn: int) -> int:
    """The cumulative TSN ack after receiving ``tsn``.

    ``cum`` None means this is the first DATA chunk of the association, which
    defines the base -- the association's initial TSN comes from the handshake,
    but a camera that starts numbering elsewhere must not wedge us at a
    cumulative ack it will never reach.

    Only an exactly-next TSN advances the ack. A gap leaves it where it is (the
    camera retransmits), and so does a duplicate. Arithmetic is modulo 2**32
    because TSNs wrap.
    """
    if cum is None:
        return tsn & 0xFFFFFFFF
    if ((tsn - cum) & 0xFFFFFFFF) == 1:
        return tsn & 0xFFFFFFFF
    return cum


def _sctp_abort_chunk() -> bytes:
    """An SCTP ABORT chunk (RFC 4960 s3.3.7): type 6, T=0, no parameters.

    Sent at teardown so the camera learns the association is over rather than
    timing it out. Measured 2026-08-07: reopening 2s after a close is refused
    with -50002 (session-exceed) while 8s is fine, and we were the only one of
    the three implementations saying nothing - the official app disposes its
    data channel and our own DTLS path (aiortc) sends this same chunk.

    T=0 because we hold the peer's verification tag and send it in the common
    header; the T bit is for an endpoint reflecting a tag it does not have.
    """
    import struct as _st_ab
    return _st_ab.pack("!BBH", 6, 0, 4)


def _key_fingerprint(key: str) -> str:
    """A truncated SHA-256 of the key -- deliberately NOT a prefix of it.

    This line goes through _status, which logs, so it lands in
    home-assistant.log on real installs, and users paste that file into
    public issue reports as a matter of course.  An SDES inline key is
    base64 of a 30-byte master key + salt, so printing its first 8
    characters would put roughly 48 bits of real key material in those
    reports -- a reduction of the brute-force space, not a nickname.

    A hash costs the note nothing.  ``_origin`` decides offer/answer/other
    by comparing the keys directly, so the only job this field has is
    telling two keys apart across log lines, and a fingerprint does that
    exactly as well.  Do not "simplify" this back to ``key[:8]``.
    """
    if not key:
        return "none"
    import hashlib as _hl_kf
    return _hl_kf.sha256(key.encode()).hexdigest()[:8]


def _srtp_tx_key_note(sender: str, used_key: str, offer_key: str,
                      answer_key: str) -> str:
    """Record which SRTP key an outbound RTCP sender encrypted with.

    Diagnostic only -- nothing branches on this.

    Three RTCP senders share the we-to-camera direction on the SDES bridge --
    PLI, REMB and RR, all with sender SSRC 0xAB12CD34 -- but only two key
    selections: REMB reuses the PLI's cached SRTP session rather than choosing
    for itself, so instrumenting the PLI covers it.  The two selections do not
    agree.  The PLI encrypts with our own offer key; the RR prefers the camera's
    answer key and falls back to ours.  SRTP keys are per-direction, so at most
    one of those can be the key the camera authenticates our RTCP against.  No
    symptom has ever been reported for any of the three, and until now no log
    line said which key went out, so a live capture could not settle it.

    ``differ=no`` means the camera echoed our key and the two senders were
    identical anyway -- the question does not arise in that session.  A run with
    ``differ=yes`` is the one that answers it, and the PLI is the sender that
    answers it: a PLI the camera authenticates is followed by a keyframe, so a
    ``differ=yes`` session whose PLIs produce keyframes says the offer key is
    the one the camera accepts on this direction.  The RR has no comparably
    sharp outcome -- a camera keeps sending audio whether or not it accepted our
    report -- so the RR line is there to record which key it used, not to prove
    that key right.

    A caller emitting this must emit it again if the key it selects can change:
    ``_cam_key_audio`` is parsed late on the wake path, after the bridge is
    running, so a first-send-only note on a sender that re-selects per packet
    would record ``answer=none differ=no`` for precisely the session in which
    the two senders diverged.

    Keys are recorded as truncated SHA-256 fingerprints, never as prefixes of
    the key itself: this line is logged, so it reaches home-assistant.log and
    the public issue reports users paste it into.  See _key_fingerprint.
    """
    def _origin(key: str) -> str:
        if not key:
            return "none"
        if key == offer_key:
            return "offer"
        if key == answer_key:
            return "answer"
        return "other"

    differ = bool(offer_key) and bool(answer_key) and offer_key != answer_key
    return (
        f"SRTP-TX-KEY sender={sender} used={_origin(used_key)}"
        f"({_key_fingerprint(used_key)}) offer={_key_fingerprint(offer_key)}"
        f" answer={_key_fingerprint(answer_key)}"
        f" differ={'yes' if differ else 'no'}"
    )


def _sctp_parse_init_ack(pkt: bytes, state: dict) -> Optional[bytes]:
    """Read the camera's INIT-ACK into ``state`` and return its State Cookie.

    RFC 4960 s3.3.3: the INIT-ACK carries the *peer's* Initiate Tag and the
    *peer's* Initial TSN -- both describe the sequence the camera will send on,
    so both belong in the peer half of the association state.  Our own TSN is
    the one we picked for our INIT and keep counting from in ``_sctp_data``;
    nothing in the answer may move it.

    Returns None when the packet holds no INIT-ACK chunk or that chunk carries
    no State Cookie parameter, which is the caller's signal to keep waiting.
    """
    import struct as _st_sc
    pos = 12
    while pos + 4 <= len(pkt):
        ctype, _, clen = _st_sc.unpack_from('!BBH', pkt, pos)
        if clen < 4:
            break
        cdata = pkt[pos + 4:pos + clen]
        if ctype == 0x02 and len(cdata) >= 16:
            state['peer_tag'] = _st_sc.unpack_from('!I', cdata)[0]
            state['peer_tsn'] = _st_sc.unpack_from('!I', cdata, 12)[0]
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


def _dispatch_sctp_avio(responses, payload) -> bool:
    """Offer an inbound SCTP DATA payload to the AVIO response router.

    This is where the camera's replies actually arrive on SDES: an encrypted
    SCTP DATA chunk (PPID 53) on the same channel we send LIVING, the heartbeat
    and SPEAKERSTART on - not the TUTK-audio framing the audio forward path
    watches. Wiring only the latter is why a camera that answered SPEAKERSTART
    in moments looked silent.

    True if it answered something we were waiting for. Never raises and never
    blocks: it runs inline on the bridge receive loop, where a bad frame must
    not be able to take the media path down with it.
    """
    if responses is None or not payload:
        return False
    answered = False
    try:
        view = memoryview(payload)
        while len(view) >= AVIO_HDR_LEN:
            frame = parse_avio_response(bytes(view))
            if frame is None:
                break
            if responses.dispatch(bytes(view)):
                answered = True
            # One chunk can carry more than one frame: 5377 declares a 12-byte
            # payload and has been seen arriving in a 140-byte chunk.  Reading
            # only the first would lose a reply batched behind a notify, which
            # presents as the camera intermittently not answering.
            view = view[AVIO_HDR_LEN + len(frame.payload):]
    except Exception:
        return answered
    return answered


def _widen_media_rcvbuf(sock, kind: str, device_id: str = "?") -> int:
    """Ask for a large receive buffer on a camera media socket.

    These sockets ran on the OS default, which is 208 KB on Home Assistant OS.
    A keyframe from an A001064 is 146-190 KB and arrives as one burst of ~130
    packets, so a single keyframe nearly fills that buffer: any delay in the
    reader - the GIL while another camera's bridge runs, an ffmpeg write
    blocking - and the kernel drops the tail of the burst.  ffmpeg then reports
    ``RTP: missed N packets`` and backs up its input queue.

    Returns the buffer the kernel actually granted (it reports double what it
    reserves), or 0 if the option could not be set.  Best-effort by design: a
    platform that refuses the option must not stop a camera from streaming.
    """
    try:
        import socket as _sock_rb

        sock.setsockopt(_sock_rb.SOL_SOCKET, _sock_rb.SO_RCVBUF,
                        _MEDIA_RCVBUF_BYTES)
        got = sock.getsockopt(_sock_rb.SOL_SOCKET, _sock_rb.SO_RCVBUF)
    except Exception:
        _LOGGER.debug("camera %s: could not widen the %s receive buffer",
                      device_id, kind, exc_info=True)
        return 0
    _LOGGER.debug("camera %s: %s receive buffer %d bytes (asked %d)",
                  device_id, kind, got, _MEDIA_RCVBUF_BYTES)
    return got


def _env_positive(name: str, cast=int, off=None):
    """Parse ``name`` as a positive number; anything else means ``off``.

    One body for the experiment knobs below - the third copy of this parser
    was the rule-of-three moment.  ``off`` is the knob's disabled value (None
    for the ints, 0.0 for the delay), and unparseable input is disabled rather
    than an error: these are read while sessions are being built, and a typo
    must not take a camera off the air.
    """
    raw = os.environ.get(name)
    if raw is None:
        return off
    try:
        value = cast(raw.strip())
    except ValueError:
        return off
    return value if value > 0 else off


def _turn_entry_ips(entries) -> set:
    """The server addresses named by ICE entries' ``Uris`` lists.

    Entries look like ``{"Uris": ["stun:3.230.182.123:3478",
    "turn:3.230.182.123:5349?transport=udp"], ...}``.  The address is what
    media source classification needs; scheme, port and query are noise.
    """
    ips = set()
    for entry in entries or ():
        for uri in (entry.get("Uris") or ()):
            body = str(uri).split(":", 1)[-1]
            host = body.split("?", 1)[0].rsplit(":", 1)[0].strip("[]")
            if host:
                ips.add(host)
    return ips


def _classify_media_path(src_ip, turn_ips) -> "Optional[str]":
    """"direct" or "relay" for a media source address, or None when unknown.

    Media arriving FROM a TURN server address is relayed - that covers both
    shapes on this fleet: the camera's own allocation on the vendor TURN (the
    relayed A001513's media arrives from the TURN address on the camera's
    allocation port, so the PORT must not participate) and a Data Indication
    through ours.  Anything else came to us directly.
    """
    if not src_ip:
        return None
    return "relay" if src_ip in turn_ips else "direct"


def _sdes_offer_media_endpoint(mode: str, default_ip: str, default_port: int,
                               relay_addr, public_ip):
    """Where the offer's c=/m= points for one media section: (ip, port, is_relay).

    This fleet's firmware nominates by dialing c=/m=, not by reading candidate
    lines - measured 2026-08-24, an A001064 and an A001513 both dialed direct
    with only the relay candidate on offer.  So forcing the relay means moving
    c=/m= to the allocation, which was this path's ORIGINAL design (see the
    allocation helper's comment) before it was backed out over dropped media.

    The missing piece back then was the permission: the camera's packets reach
    the TURN server from the house WAN address - OUR srflx address - and
    without a CreatePermission for it the relay drops everything.  Relay mode
    therefore requires a known public_ip; without one (or without an
    allocation) it falls back to the direct endpoint, because a stream on the
    wrong path beats no stream.
    """
    if mode == "relay" and relay_addr and public_ip:
        return relay_addr[0], relay_addr[1], True
    return default_ip, default_port, False


def _sdes_offer_candidate_lines(mode: str, local_ip: str, port: int,
                                public_ip, relay_addr) -> str:
    """The a=candidate block for one media section, shaped by the mode.

    ``auto``  - host + srflx (when a public IP is known) + relay (when the
                pre-allocation succeeded), in that priority order.  This is the
                shipped behaviour: the LAN wins by ICE priority (host
                2130706431 > srflx 1694498815 > relay 16777215) and the relay
                is the last resort - measured on the full fleet 2026-08-24,
                six of seven cameras direct and only the unit with no route to
                us on the relay.
    ``lan``   - host + srflx only.  Normally moot (lan mode also skips the
                relay pre-allocation, so there is no relay_addr to omit), but
                enforced here too so the two levers cannot disagree.
    ``relay`` - the relay candidate ONLY, so an ICE-speaking camera has
                nothing else to nominate.  The relay address must still never
                appear in c=/m= - TURN drops every camera packet without a
                CreatePermission for the camera's public address, which is
                unknown - so candidate lines are the entire steering surface,
                and firmware that ignores ICE and dials c=/m= directly cannot
                be steered.  With no allocation to offer this falls back to
                the auto block: an offer with zero candidates is a session
                that cannot start, and a stream on the wrong path beats no
                stream.
    """
    host = f"a=candidate:1 1 udp 2130706431 {local_ip} {port} typ host\r\n"
    srflx = (f"a=candidate:2 1 udp 1694498815 {public_ip} {port}"
             f" typ srflx raddr {local_ip} rport {port}\r\n"
             if public_ip else "")
    relay = (f"a=candidate:3 1 udp 16777215 {relay_addr[0]} {relay_addr[1]}"
             f" typ relay raddr {local_ip} rport {port}\r\n"
             if relay_addr else "")
    if mode == "relay" and relay:
        return relay
    if mode == "lan":
        return host + srflx
    return host + srflx + relay


def _sdes_offer_bandwidth_kbps():
    """A receive-bandwidth ceiling for the offer, in kbps, or None for none."""
    return _env_positive("AIDOT_SDES_OFFER_BANDWIDTH_KBPS")


def _offer_bandwidth_line(kbps) -> str:
    """``b=AS:<kbps>`` (RFC 4566 s5.8) for the offer, or "" for no ceiling.

    A receiver telling a sender how much it is willing to accept. This is the
    last standards-defined bitrate control left after the others were killed
    on evidence, and the only one we emit ourselves rather than mirror from
    the app -- the app sends no ``b=`` line at all.

    Anything that is not a positive integer count of kilobits yields no line.
    ``b=AS:0`` is NOT "unlimited" in RFC 4566; it asks for zero bandwidth, so
    the off case must omit the line entirely.
    """
    try:
        value = int(kbps)
    except (TypeError, ValueError):
        return ""
    if value <= 0:
        return ""
    return f"b=AS:{value}\r\n"


def _sdes_nack_enabled() -> bool:
    """Whether to ask the camera to resend video packets that never arrived.

    ON by default, unlike REMB. REMB ships off because it was measured to do
    nothing; this was measured to be needed. An A001064 over SDES loses ~0.7%
    of its video RTP packets on the air -- 37 of 56 losses landing INSIDE a
    frame, same RTP timestamp either side of the sequence gap -- and its
    keyframes are ~155 packets each, so roughly two thirds of them arrive
    damaged. ffmpeg reassembles the truncated slice and forwards it; a
    browser's WebRTC decoder conceals that, and Media Source Extensions kills
    the pipeline outright (``PIPELINE_ERROR_DECODE``, always on a keyframe).

    The default is ON rather than opt-in because, unlike a bitrate cap, a NACK
    cannot degrade a camera that ignores it: unsupported feedback is dropped,
    and a camera on a clean link generates no requests at all -- driveway,
    measured the same day on the same bridge, has 0.05% loss and zero
    mid-frame losses. The cost on a healthy fleet is nothing sent.

    Read per call, not at import, so it can be flipped without a restart.
    """
    return os.environ.get("AIDOT_SDES_NACK", "1").strip().lower() not in (
        "0", "", "false", "no", "off")


#: How long a retransmission has to arrive in to still be worth forwarding.
#: The serve runs ``-max_delay 500000``; a repeat later than that is discarded
#: by ffmpeg anyway, having already emitted the damaged frame.  Same env var as
#: the serve so the two cannot drift apart.
_SERVE_REORDER_BUDGET_S = min(
    float(os.environ.get("AIDOT_SERVE_MAX_DELAY_US", "500000") or 500000) / 1e6,
    0.5,
)


def _video_repeat_too_late(bridge_fn, seq: int, now: float,
                           budget: float = _SERVE_REORDER_BUDGET_S) -> bool:
    """Is this video packet a retransmission that missed the decoder's window?

    A repeat that beats ffmpeg's reorder window is put back in place and
    repairs the frame -- that is the whole point of asking for it. One that
    arrives after it cannot: the damaged frame is already out, so forwarding
    the repeat only inserts an out-of-order packet and the muxer clamps its
    output DTS. Seen in production once NACK was live, as
    ``RTP: dropping old packet received too late`` plus a run of
    ``Non-monotonic DTS`` with the sequence number 4 to 115 behind the newest.

    Shares the NACK tracker deliberately: a second one would not know which
    packets had ever been missing, so nothing would ever look late.

    **Measured 2026-09-12: this guard drops NOTHING in practice.** Over a
    22-hour window on the box, ffmpeg reported 1612 backward DTS jumps (p50
    0.48 s, p90 1.73 s, max 2.60 s) and `_nack_late_drops` stayed at zero. The
    obvious explanations were checked and both are wrong: at the measured
    47 packets/s, `max_behind=200` is a 4.3 s prune horizon and `max_gap=250`
    needs 5.3 s of loss to reset, so every one of those jumps falls inside the
    band this guard can see. The late packets are therefore **not
    retransmissions the tracker ever asked for**, and what they actually are is
    still unknown - see project_aidot_dts_bursts_are_the_serve_seam. Do not
    assume this guard covers the DTS bursts; it does not.
    """
    tracker = getattr(bridge_fn, "_nack_tracker", None)
    if tracker is None:
        tracker = NackTracker()
        bridge_fn._nack_tracker = tracker
    age = tracker.repeat_age(seq, now)
    return age is not None and age > budget


def _video_nack_seqs(bridge_fn, seq: int, now: float,
                     enabled: "Optional[bool]" = None) -> "list":
    """Sequence numbers to ask the camera to resend, given one forwarded packet.

    The tracker is cached on ``bridge_fn`` (the same place the PLI and REMB
    state lives) because it has to see the whole sequence: one rebuilt per
    packet would never observe a gap, which is the quiet way this could ship
    doing nothing at all.
    """
    if enabled is None:
        enabled = _sdes_nack_enabled()
    if not enabled:
        return []
    tracker = getattr(bridge_fn, "_nack_tracker", None)
    if tracker is None:
        tracker = NackTracker()
        bridge_fn._nack_tracker = tracker
    return tracker.observe(seq, now)


def _send_video_nack(send, srtcp_sess, sender_ssrc: int,
                     media_ssrc: int, lost_seqs: "list") -> bool:
    """Put one Generic NACK on the camera's RTCP path.  True if it went out.

    ``send`` is the bridge's relay-aware sender (``_br_send_to_cam`` bound to
    the current socket and peer), NOT a raw socket.  When the camera reached
    us through our TURN relay the address a packet arrived FROM is the relay,
    and a raw write there is parsed as a malformed STUN message and dropped --
    so a socket-and-address form is silently inert on a relayed session while
    still reporting that it sent something.  The RR and the AVIO trigger go
    out the same way for the same reason.

    Uses the same SRTCP session as the PLI, so it inherits the key selection
    that a PLI has already been observed to authenticate (the RR prefers a
    different key -- see the SRTP-TX-KEY note).

    That session is built lazily on the first PLI tick, which is scheduled for
    the moment the first video packet arrives. A loss in the handful of packets
    before it exists goes out unprotected and the camera will drop it, exactly
    as the PLI's own plain-text fallback does. The window is a few milliseconds
    wide and costs at most the first loss event of a session.

    Never raises: this runs inside the bridge's packet loop, and taking the
    whole stream down to avoid one dropped video packet is a bad trade.
    """
    if not lost_seqs:
        return False
    return _send_rtcp_fb(
        send, srtcp_sess, build_nack(sender_ssrc, media_ssrc, lost_seqs))


def _sdes_tmmbr_bps():
    """The bitrate bound to ask the camera for, in bits/s, or None for none.

    Off unless ``AIDOT_SDES_TMMBR_BPS`` names a positive integer.  Unparseable
    is off rather than an error: this is read while a session is running.
    """
    return _env_positive("AIDOT_SDES_TMMBR_BPS")


def _sdes_tmmbr_after_s() -> float:
    """Seconds of MEDIA to let pass before the first TMMBR.  0 = immediately.

    Exists so the bound can be measured within a session -- window A before it,
    window B after -- instead of between sessions.  On this camera a
    between-session comparison has twice produced a wrong answer: it read a
    codec split as a bandwidth-cap effect, and the encoder's own drift as a
    working SD control.  Both windows of one session share the codec and the
    scene, so neither can confound it.
    """
    return _env_positive("AIDOT_SDES_TMMBR_AFTER_S", cast=float, off=0.0)


#: Measurement scaffolding, OFF unless an operator names a file.
#:
#: This used to be the hardcoded string "/config/aidot_expt_cap", which meant a
#: published library opened a Home Assistant path on the event loop for every
#: session - Home Assistant's own blocking-call detector reports it, and a
#: transport library has no business knowing where HA keeps its config. Reading
#: the env var at import costs nothing and leaves the knob available to whoever
#: is screening a camera.
EXPT_CAP_FILE = _os.environ.get("AIDOT_EXPT_CAP_FILE")


#: How long to wait for the broker to echo our own livePlayReq back before
#: proceeding. Was 5.0 s (1.5 s with fast-liveplay), and it is pure latency:
#: across 22 h of one deployment the wait ran 169 times and timed out 169 times,
#: never once ending early, and not a single inbound `livePlayReq` was seen among
#: 5000+ messages the cameras and broker did send. The success branch has never
#: executed. On timeout the code proceeds anyway, so the wait has never changed
#: behaviour - only delayed it, by 44% of a measured 11.4 s time-to-first-frame
#: on an A001064.
#:
#: Kept rather than deleted, and still honoured, because a broker or firmware
#: that does echo should still short-circuit the wait; only the price of its
#: absence changes. Override with AIDOT_SDES_LIVEPLAY_ECHO_S (seconds, 0
#: disables the wait entirely) to measure it against the old value.
_LIVEPLAY_ECHO_S = 0.25
#: The fast-liveplay path used to keep the 1.5 s it was given, because the
#: 169/169 evidence above was gathered on the non-fast wait only and nothing
#: had measured this one.  It has now been measured, and it behaves identically:
#: over 3 h on 2026-09-03 the fast wait ran 22 times and timed out 22 times, at
#: 1500-1501 ms every time, with zero "livePlayReq echo received" among them.
#: So it is the same pure latency as its sibling, and it costs 1.25 s of a
#: 5.4 s time-to-first-media on a cold battery camera - roughly a quarter of the
#: whole connect.  Same value, same reasoning, same override.
_LIVEPLAY_ECHO_S_FAST = 0.25


def _sdes_liveplay_echo_timeout(fast_liveplay: bool) -> float:
    """Seconds to wait for the livePlayReq echo. Never negative.

    A malformed env value is ignored rather than raising: this runs on every
    open, and an unparseable knob must not be able to stop a camera streaming.
    """
    raw = _os.environ.get("AIDOT_SDES_LIVEPLAY_ECHO_S")
    if raw is not None:
        try:
            val = float(raw)
        except (TypeError, ValueError):
            val = None
        if val is not None and val >= 0.0:
            return val
    return _LIVEPLAY_ECHO_S_FAST if fast_liveplay else _LIVEPLAY_ECHO_S


def _sdes_max_session_s(device_id: str, path: "Optional[str]" = None) -> float:
    """Seconds of media after which to end THIS device's session.  0 = off.

    Measurement scaffolding.  The 80.2 s cliff is decided once per session, so a
    session that reaches 90 s has already passed it and the next twenty minutes
    carry no information.  Session throughput is coupled to the outcome - a stall
    yields a fresh session every ~110 s, a pass yields none for tens of minutes -
    so without a cap the arm that works starves its own sample.

    The file names one device: ``<device_id>:<seconds>``.  The scoping is not
    cosmetic: an unscoped cap hits every camera on the SDES path, one of which is
    a battery device that normally opens about twice an hour and was forced to
    ~30x that rate before this was caught.  So it FAILS CLOSED - anything that
    cannot be attributed to a specific device caps nothing.
    """
    path = path if path is not None else EXPT_CAP_FILE
    if not path:
        # The overwhelmingly common case: no scaffolding, no file I/O at all.
        return 0.0
    try:
        with open(path) as _fh:
            raw = _fh.read().strip()
    except OSError:
        return 0.0
    head, sep, tail = raw.partition(":")
    if not sep or not head.strip() or head.strip() != device_id:
        return 0.0
    try:
        seconds = float(tail.strip())
    except ValueError:
        return 0.0
    return seconds if seconds > 0.0 else 0.0


def _session_cap_reached(first_media_ts, now: float, cap_s: float) -> bool:
    """Whether this session has run its allotted media time.

    ``first_media_ts`` None means no media has arrived yet, and an open in
    progress must never be cut short - the cap measures a session's life, not its
    birth.  The caller must set a cap ABOVE the 80.2 s cliff; below it every
    session would read as a stall.
    """
    if not cap_s or first_media_ts is None:
        return False
    return (now - first_media_ts) >= cap_s


def _tmmbr_ready(first_video_ts, now: float, after_s: float) -> bool:
    """Whether enough MEDIA has passed to start asking for the bound.

    Measured from the first video packet, not from the open: a camera that
    takes twelve seconds to wake would otherwise spend all of window A capped.
    """
    if first_video_ts is None:
        return False
    return (now - first_video_ts) >= after_s


def _send_rtcp_fb(send, srtcp_sess, raw: bytes) -> bool:
    """Protect-and-send tail shared by the NACK, TMMBR and REMB helpers.

    One body for the ``protect_rtcp``-if-session-else-raw dance and the
    swallow-and-debug-log error policy.  It was written three times before
    this, and the copy that drifted (REMB's, still inline in the loop body)
    is the one where the raw-socket relay bug hid.  Never raises: these run
    inside the bridge's packet loop.
    """
    try:
        send(srtcp_sess.protect_rtcp(raw) if srtcp_sess is not None else raw)
        return True
    except Exception:
        _LOGGER.debug("RTCP feedback send failed", exc_info=True)
        return False


def _send_video_remb(send, srtcp_sess, sender_ssrc: int,
                     media_ssrc: int, target_bps) -> bool:
    """Put one REMB on the camera's RTCP path.  True if it went out.

    Same shape and same relay-aware ``send`` contract as
    :func:`_send_video_nack` - the REMB logic previously lived inline in the
    loop body, and being the only feedback path without a helper is exactly
    how it kept the raw-socket write long after the NACK path was fixed.
    """
    if not target_bps or target_bps <= 0:
        return False
    return _send_rtcp_fb(
        send, srtcp_sess, build_remb(sender_ssrc, [media_ssrc], target_bps))


def _send_video_tmmbr(send, srtcp_sess, sender_ssrc: int,
                      media_ssrc: int, bitrate_bps) -> bool:
    """Put one TMMBR on the camera's RTCP path.  True if it went out.

    ``send`` is the bridge's relay-aware sender, NOT a raw socket, for the
    reason spelled out on :func:`_send_video_nack`: via TURN the address media
    arrived from is the relay, and a raw write there is dropped as a malformed
    STUN message while still reporting success.  (``REMB`` still writes to the
    socket directly and is inert on a relayed session for exactly that reason;
    it is latent only because its target defaults to 0.)

    Never raises: this runs inside the bridge's packet loop.
    """
    if not bitrate_bps or bitrate_bps <= 0:
        return False
    return _send_rtcp_fb(
        send, srtcp_sess, build_tmmbr(sender_ssrc, media_ssrc, bitrate_bps))


#: Sender SSRC on every RTCP we send the camera.  Load-bearing, not cosmetic:
#: the SRTP TX policy is keyed `ssrc_value=_CAM_RTCP_SENDER_SSRC`, so the PLI,
#: REMB, RR and NACK must all agree or the camera drops the packet.
_CAM_RTCP_SENDER_SSRC = 0xAB12CD34

#: ffmpeg lines the serve emits continuously on a healthy-but-lossy stream, and
#: which therefore cannot be allowed to fill a fixed-size tail.  Both camera
#: families step their RTP timestamp backward every exactly 30.0 s (measured
#: 2026-08-23: A001064 by 0.05-0.35 s, A001513 by ~2.195 s), and `-c copy` then
#: emits one "Non-monotonic DTS" per frame until the input catches up -- tens of
#: lines, several times a minute.  Every lost packet adds the other two.  A tail
#: of the last N lines is guaranteed to hold only this, which is why three
#: investigations of a camera that dies every ~3 minutes never saw the reason.
_SERVE_STDERR_NOISE = (
    "Non-monotonic DTS",
    "RTP: missed",
    "max delay reached",
)


def _start_serve_stderr_drain(proc, *, maxlines: int = 40,
                              notable_lines: int = 20) -> None:
    """Drain a serve ffmpeg's stderr continuously into a bounded tail on the proc.

    The serve is spawned with ``stderr=PIPE`` but the bridge loop only polls the
    process and reads its RTP sockets - it never reads stderr.  An un-drained
    ``PIPE`` fills its ~64KB kernel buffer and then blocks ffmpeg on its next
    stderr write, stalling the serve; and when ffmpeg exits non-zero the reason is
    otherwise lost (the RTSP-push ANNOUNCE error in particular).  Read it on a
    daemon thread that ends at EOF when the process exits, keeping the last
    ``maxlines`` lines on ``proc._aidot_stderr_tail`` for the exit logger.

    Also keeps ``proc._aidot_stderr_notable``: the last ``notable_lines`` lines
    that are NOT in ``_SERVE_STDERR_NOISE``.  The raw tail says what the stream
    was doing; this one says why it stopped, and on a lossy camera it is the
    only one that can.
    """
    import collections
    import threading

    tail = collections.deque(maxlen=maxlines)
    notable = collections.deque(maxlen=notable_lines)
    proc._aidot_stderr_tail = tail
    proc._aidot_stderr_notable = notable
    if proc.stderr is None:
        return

    def _drain() -> None:
        try:
            for _line in iter(proc.stderr.readline, b""):
                text = _line.decode("utf-8", "replace").rstrip()
                tail.append(text)
                if not any(n in text for n in _SERVE_STDERR_NOISE):
                    notable.append(text)
        except Exception:
            pass

    threading.Thread(
        target=_drain, daemon=True, name="aidot-sdes-serve-stderr"
    ).start()


# Strong references to detached per-session helper tasks, so the event loop
# cannot garbage-collect one mid-flight.  Entries remove themselves on done.
_SDES_BACKGROUND_TASKS: set = set()


# Payload types the ffmpeg SDP advertises per media line, and their alternates.
# The SDP offers both because the camera picks one per session.
# Video payloads the cameras negotiate: 96=H.264, 97/98=H.265 (two variants).
_SDP_VIDEO_PTS = (96, 97, 98)
_SDP_AUDIO_PTS = (0, 8)

# Which payload type OUR ffmpeg SDP carries for each video codec.  The template
# writes 96=H.264 and 97=H.265, so an answer that negotiates H.265 narrows to 97
# even when the camera numbers that codec differently on the wire - it is our own
# SDP being rewritten, not the camera's.
_SDP_VIDEO_PT_BY_CODEC = {"H264": 96, "H265": 97}

#: RFC 5245 s15.4: ``ice-char = ALPHA / DIGIT / "+" / "/"``. Base64, NOT
#: base64URL - `-` and `_` are not ice-chars. `secrets.token_urlsafe` emits the
#: URL-safe alphabet, and measured over 4000 generations that put a character
#: outside this set into 12.5% of our ufrags and 49.9% of our passwords.
_ICE_CHARS = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
              "abcdefghijklmnopqrstuvwxyz"
              "0123456789+/")

#: What the vendor app actually sends, read out of its own signalling log:
#: ufrag 4 chars, password 24. The RFC floor for a password is 22; 24 is what
#: this fleet's cameras see from the client they were built against.
_ICE_UFRAG_LEN = 4
_ICE_PWD_LEN = 24


def _new_ice_credentials() -> "tuple":
    """One ``(ufrag, pwd)`` pair for a whole offer, shaped like the app's.

    ONE pair, and the reason is local and provable rather than inferred from
    the vendor app. ``_compress_sdp_req`` - the function that builds the
    wPayload offer the camera actually receives - keeps only the FIRST
    ``ice-ufrag`` and the FIRST ``ice-pwd`` in the whole document and DROPS the
    later ones; it does not rewrite them. Verified by replicating its filter on
    a two-section SDP: the video section comes out with no ICE attributes at
    all.

    So while we generated a pair per m-section, the camera only ever received
    the audio pair - and our video socket then computed STUN MESSAGE-INTEGRITY
    with ``_pwd_v``, a password the camera had never seen. Generating one pair
    makes both sockets authenticate with the credentials the camera actually
    holds.

    That the vendor app also sends a single pair (measured from its own
    signalling log: one ufrag repeated across every m-section, 4 chars, and a
    24-char password) is corroboration, not the reason.

    The firmware treats that first pair as session-wide, which is what makes
    dropping the later ones survivable. Measured on the wire 2026-09-05 by
    counting inbound STUN per socket across a real A001064 open::

        {('bridge', 'audio'): 2, ('success', 'audio'): 3,
         ('bridge', 'video'): 2, ('success', 'video'): 3}

    The camera sends Binding Requests to the VIDEO socket and completes the
    exchange there, despite the compressed offer carrying no ICE attributes in
    the video m-section at all. So video ICE inherits, and one pair is
    sufficient - it is not merely tolerated.

    NOTE for anyone changing ``_compress_sdp_req`` to preserve per-section
    credentials: doing that alone reintroduces the mismatch, because the two
    sites are ~2350 lines apart. The behavioural test in
    tests/test_ice_credentials_match_the_app.py asserts on the COMPRESSED SDP
    for exactly that reason.
    """
    return (
        "".join(_secrets_mod.choice(_ICE_CHARS)
                for _ in range(_ICE_UFRAG_LEN)),
        "".join(_secrets_mod.choice(_ICE_CHARS)
                for _ in range(_ICE_PWD_LEN)),
    )


_SDP_CODEC_BY_VIDEO_PT = {pt: codec for codec, pt in _SDP_VIDEO_PT_BY_CODEC.items()}


def describe_video_profile(pt) -> str:
    """Name the video profile a session negotiated, for the log.

    An A001064 was measured serving two profiles for identical requests - H264
    1280x720 at 2.5-4.0 Mbps and H265 2560x1440 at ~1.1 Mbps - varying per
    session with nothing on our side asking for either.  What selects it is
    unknown, and it is unknown because nothing recorded it: bitrate figures
    gathered before 2026-08-07 cannot be compared, since the codec that produced
    each one was never written down.

    Instrumentation, not a fix.  It asserts no cause.

    Deliberately limited to the payload type and its codec name, which is what
    the bridge knows when the first video packet lands.  Frame dimensions would
    mean parsing H264/H265 parameter sets out of the stream - far more than the
    question needs, and on the camera measured codec and resolution moved
    together in 11 of 11 sessions, so the codec stratifies it today.

    Never raises: this runs on the media path, and nothing here may be able to
    break an otherwise healthy stream.  An unmapped payload type is reported as
    ``unknown``, which is a finding worth having rather than a reason to skip
    the record.
    """
    return f"pt={pt} codec={_SDP_CODEC_BY_VIDEO_PT.get(pt) or 'unknown'}"

# How long to wait for the FIRST media of a session before launching the serve.
# Nothing useful can happen before then: the payload types are unknown, so the SDP
# cannot be narrowed, and ffmpeg would bind the wrong depacketizers.  Sized to the
# documented cold-start window for a battery camera (25-70s).  Measured: a cold
# session started media at ~21s, which the previous 15s deadline missed entirely -
# it launched blind with BOTH payload types still unknown, which is what left the
# audio line advertising PCMU on a PCMA camera.
_FIRST_MEDIA_WAIT_S = 75.0

# How long a BATTERY camera that only announced itself mid-wait is given to send
# media before the attempt is abandoned to the retry.
#
# A cold battery camera normally serves fast: measured 2026-09-03 across cold
# opens with a 150 s settle, first media landed 5.3 s and 10.0 s after the open,
# with the camera's own wakeupStatus at +5.4 s.  That matches the vendor app,
# which pulls these cameras up almost instantly.
#
# But the first attempt does sometimes stall completely, and when it does the
# camera answers our livePlayReq after waking and then sends nothing at all -
# measured, it answered at +46.4 s with 48 s of this window still to run and no
# media ever arrived, and the open finished at +103.6 s.  The retry that follows
# publishes a fresh offer and is served in ~5 s.  So a stalled attempt is not
# worth the rest of a 75 s window, and this ends it early.
#
# The grace is bounded from both sides.  Below, by the healthy distribution: it
# has to sit clear of the slowest good open (10.0 s here, 10.7 s historically)
# so a merely slow attempt is never mistaken for a stalled one.  Above, by the
# camera's own sleep timer: a battery camera that wakes for us and gets no
# session goes back to sleep about 29 s later (measured: awake at +10.9 s,
# asleep again at +39.8 s), and the retry is only cheap while the camera is
# still awake - once it has slept, the retry has to wake it all over again.
# Abandoning at first-sighting + 15 s puts the retry's offer at roughly +25 s to
# +30 s, inside that window on both measured wake times.
#
# Set AIDOT_BATTERY_STALE_OFFER_GRACE_S=0 to restore the previous behaviour.
_BATTERY_STALE_OFFER_GRACE_S = float(
    os.environ.get("AIDOT_BATTERY_STALE_OFFER_GRACE_S", "15")
)


# How long a BATTERY camera's offer waits for the camera to answer first.
#
# **Measured on hardware and shipped OFF.** This is the app's own shape - its
# live view fires keepAliveHandle(), sends the wake, and renders
# IPC.Status.Sleep rather than opening a session until the device reports
# itself awake - and on this camera family it is self-defeating, because the
# live-play signalling is what wakes the camera.  Withholding the offer
# withholds the wake.
#
# Two runs say so.  At 30 s the camera produced no message for the whole gate,
# the offer went out at +32.1 s and the open ended at +116.8 s against a 75 s
# failure without it.  At 20 s, on a camera settled for ten minutes: gate
# elapsed 20044 ms answered=False, webrtcReq at +20.9 s, the camera's own
# wakeupStatus at +23.6 s - AFTER the offer - and first media at +27.0 s,
# against 5.4-10.0 s on the same camera with no gate.
#
# So the wake evidence follows the offer rather than preceding it, and the
# useful order is the one we already had: offer immediately, re-assert the
# keep-alive the moment the camera answers, and abandon an attempt that has
# stalled (see _BATTERY_STALE_OFFER_GRACE_S).
#
# Kept, off, as a lever for anyone re-testing this on other firmware - set
# AIDOT_BATTERY_WAKE_GATE_S to a number of seconds to enable it.
_BATTERY_WAKE_GATE_S = float(os.environ.get("AIDOT_BATTERY_WAKE_GATE_S", "0"))


def _battery_wake_gate_s(battery: bool, budget: float) -> float:
    """Seconds to wait for the camera's own answer before offering; 0 = no gate.

    Mains cameras never sleep, so there is nothing to wait for - and the A001064
    PTZ is mains, which keeps this away from the role-reversal path, whose
    timing is delicate.
    """
    return budget if (battery and budget > 0) else 0.0


def _stale_offer_abandon_due(*, battery: bool, seen_at_start, first_seen_ts,
                             now: float, grace_s: float) -> bool:
    """Whether this attempt's offer is stale and the wait should end now.

    ``seen_at_start`` is when the camera had last been heard from as the media
    wait began, and it is the arming decision: a warm camera has already
    answered livePlayResp by then, so the detector stays disarmed for the whole
    attempt - including every retry attempt, where the camera is awake and
    talking throughout.  Only an attempt that began with silence, and then heard
    the camera, can be abandoned.

    ``first_seen_ts`` is when the camera FIRST turned up in this attempt, not
    the last time it said anything.  Measuring from the latest message lets a
    chatty camera - one emitting a motion event every 5 s while its handshake
    goes nowhere - keep pushing the decision back: measured, that delayed the
    abandon to 47 s when the camera had already been present for 29 s of it,
    and by then the camera had gone back to sleep and the retry had to wake it
    all over again.

    A camera that never speaks at all is a different shape (unreachable, or on
    an unroutable subnet) and keeps the full window it has today.
    """
    if not battery or grace_s <= 0:
        return False
    if seen_at_start is not None:
        return False
    if first_seen_ts is None:
        return False
    return (now - first_seen_ts) >= grace_s

# How long to wait for the camera's webrtcResp before parsing it for the ICE
# credentials the nomination needs.  The STUN window ahead of it closes on a
# fixed schedule, and the answer lands about 2.4 s AFTER it does (measured on an
# A001513: webrtcReq -> answer 2.9 s), so the harvest below used to give the
# answer a single event-loop cycle and almost always read an empty string.
# Everything downstream then behaved as if the camera had never answered.
# Bounded so a camera that truly never answers still falls through to the
# existing no-answer/DTLS-fallback path on its own schedule.
_PRE_LAUNCH_ANSWER_WAIT_S = 8.0

# Extra time for the audio payload type once video is known.  Measured on an
# A001513: audio follows video by 40-70ms, because the camera answers BUNDLE and
# both share one 5-tuple - so audio is never "late" and this only absorbs jitter.
# Kept tight so a camera that genuinely sends no audio barely delays the picture.
_AUDIO_PT_GRACE_S = 1.0

# Extra seconds to wait for the FIRST media packet when the stale-offer backstop
# ended the wait and nothing has been observed yet.
#
# The serve SDP is built from the payload types actually observed, so a wait
# that ends while the first packets are still in flight produces a video-only
# serve for the whole session.  Measured 2026-09-03: the backstop ended the wait
# at +39 s, the serve was launched 1 s later with neither type seen ("no video
# observed ... no audio observed"), and media arrived 4.2 s after that.  The
# card played and had no sound.
#
# _AUDIO_PT_GRACE_S does not cover this: 1 s is sized for a session whose video
# is already flowing and whose audio is a beat behind, not for one whose media
# has not started.
#
# Only the backstop path gets this.  It fires only after the camera itself has
# been heard from, which is exactly when media is plausibly imminent; on the
# plain timeout path the camera never spoke, and waiting longer would just add
# to a failure that has already taken 75 s.
#
# Set AIDOT_ABANDONED_MEDIA_GRACE_S=0 to disable.
_ABANDONED_MEDIA_GRACE_DEFAULT_S = 8.0


def _abandoned_media_grace_s() -> float:
    """Seconds of grace after the backstop. Never negative, never raises.

    Read per call and guarded, like `_sdes_liveplay_echo_timeout` and
    `_sdes_echo_wait_timeout`. Parsed at import this was a ValueError on any
    non-numeric value - `AIDOT_ABANDONED_MEDIA_GRACE_S=8s` would stop the whole
    module importing and take the integration down at setup rather than
    degrading. Reading it per call also makes the documented `=0` escape hatch
    work without a process restart, which the import-time version silently
    required.
    """
    raw = _os.environ.get("AIDOT_ABANDONED_MEDIA_GRACE_S")
    if raw is not None:
        try:
            val = float(raw)
        except (TypeError, ValueError):
            val = None
        if val is not None and val >= 0.0:
            return val
    return _ABANDONED_MEDIA_GRACE_DEFAULT_S


def _post_abandon_media_grace_s(*, abandoned: bool, have_video: bool,
                                grace_s: float) -> float:
    """Extra seconds to wait for the first media before building the serve SDP."""
    if not abandoned or have_video or grace_s <= 0:
        return 0.0
    return grace_s


def _should_skip_doomed_serve(*, abandoned: bool, have_video: bool,
                              serving: bool = True) -> bool:
    """Whether to abandon this attempt instead of serving nothing.

    What makes a serve doomed is that **no video was observed**, not which wait
    ended.  A serve built with no observed payload types is video-only and then
    receives no media at all: measured 2026-09-03 as ~14 s of delay and a lost
    audio track before the retry that actually worked.

    This once applied only to the stale-offer backstop, on the reasoning that
    the plain timeout path was a transient the stream worker tolerated and
    retried into.  **That is retracted.**  Measured 2026-09-05 on a camera that
    dropped off the WiFi: every attempt ran the full first-media wait, timed out
    with nothing observed, launched the serve anyway, and ffmpeg died at once -

        Could not find codec parameters for stream 1 (Video: h264, none):
                                                            unspecified size
        [rtsp] dimensions not set
        [out#0/rtsp] Could not write header (incorrect codec parameters ?)

    11 attempts and 6 stalls in 25 minutes, each spawning an ffmpeg that could
    not start.  That is not a transient being tolerated, it is a permanent
    failure being looped on, so the timeout path is covered too.

    ``serving`` is what keeps this to the case it is named for. The open path
    is shared: ``async_speak`` (press-to-talk, siren, announce) and
    ``async_snapshot`` run the same first-media wait with no serve to build,
    and outbound talk does not need inbound media at all - the SRTP session and
    the ICE nomination are already up. Aborting those because no video arrived
    would break the siren on exactly the cameras this was written to help.

    ``AIDOT_SKIP_DOOMED_SERVE=0`` restores the old behaviour on the timeout
    path without a release; the backstop case it always covered is unchanged.
    A malformed value is ignored rather than allowed to alter a media path.
    """
    if not serving:
        return False
    if have_video:
        return False
    if abandoned:
        return True
    raw = _os.environ.get("AIDOT_SKIP_DOOMED_SERVE")
    if raw is not None and raw.strip().lower() in ("0", "false", "no", "off"):
        return False
    return True


# --------------------------------------------------------------------------- #
# Reading the camera's answer, and leaving the STUN window once it is readable
# --------------------------------------------------------------------------- #
#
# The ICE responder window below runs synchronously and blocks the event loop,
# so it was written on the assumption stated above the answer harvest: that it
# "closes ~2.4 s before the camera answers".  Cutting the livePlayReq echo wait
# from 5.0 s to 0.25 s inverted that.  Measured on a cold A001064 open:
#
#     +0.45 s  webrtcReq
#     +0.72 s  the camera's webrtcResp answer      <- credentials in hand
#     +5.05 s  window closes on 1.5 s of ICE silence
#     +5.06 s  USE-CANDIDATE
#     +6.66 s  first SRTP
#
# 4.3 s of a 6.7 s connect spent holding an answer nothing was looking at.
# Leaving early costs nothing: the bridge thread takes over responding to the
# camera's binding requests the moment the window closes, and it is the bridge -
# not the window - that learns peer-reflexive candidates and re-nominates every
# 2.5 s, so the relay-only and off-subnet recovery paths are untouched.
# Two of the five parses this replaced ended at a bare ``typ`` and captured no
# type token, and one accepted a line with no ``a=`` prefix (trickled candidates
# arrive bare).  Both shapes are accepted so the collapse cannot reject a line
# one of the old copies would have taken.
#
# The type token is optional but still anchored: ``typ ?(\w*)`` also matched
# ``typo host`` and ``typhoon``, which every parse it replaced rejected, and a
# corrupt candidate line reaching the nomination gets a TURN permission and a
# USE-CANDIDATE probe.  ``(?!\w)`` keeps the widening to the one direction the
# collapse needs.
_ICE_CAND_RE = re.compile(
    r"(?:a=)?candidate:\S+ \d+ udp \d+ ([\d.]+) (\d+) typ(?: (\w+))?(?!\w)"
)


def _parse_candidate_line(line):
    """One ``a=candidate:`` line as ``(ip, port, typ)``, or None.

    Shared with the trickle path, which reads candidates one at a time off
    ``iceCandidateReq`` rather than out of an SDP, and which kept its own copy
    of this pattern until the two could disagree about the same line.
    """
    m = _ICE_CAND_RE.match((line or "").strip())
    if not m:
        return None
    return m.group(1), int(m.group(2)), (m.group(3) or "")


def _parse_answer_ice(sdp):
    """Pull ICE credentials and UDP candidates out of a camera's answer SDP.

    Returns ``(ufrag, pwd, candidates, host)``: the first ice-ufrag and
    ice-pwd in the SDP, every udp candidate as an ``(ip, port)`` tuple in the
    order offered, and the first ``typ host`` candidate - which is the one SCTP
    is addressed to, and is not necessarily the first candidate listed.

    Taking the FIRST credential pair is now measured, not assumed.  Our own
    offer carries distinct per-media credentials and the nomination sends
    USE-CANDIDATE on both sockets with the single pair this returns, which is
    only correct if the camera answers one pair for the whole session.  Logging
    every a=ice-ufrag / a=ice-pwd line of the answer per m-section across four
    cold opens on two models (A001064 mains, A001513 battery) on 2026-09-04:
    every answer carried ONE pair, repeated identically in the audio, video and
    application sections.  The shape is pinned in
    test_the_first_credential_pair_is_the_only_pair; a camera that answered
    per-media credentials would need this split before it could be nominated on
    both sockets.

    One parser, used by both the nomination and the window's exit predicate.
    The exit means "the nomination this is about to reach will succeed", and it
    only means that while both sides read the same SDP the same way.
    """
    ufrag = ""
    pwd = ""
    cands: list = []
    host: tuple = ()
    for line in (sdp or "").splitlines():
        if line.startswith("a=ice-ufrag:") and not ufrag:
            ufrag = line[len("a=ice-ufrag:"):].strip()
        elif line.startswith("a=ice-pwd:") and not pwd:
            pwd = line[len("a=ice-pwd:"):].strip()
        elif line.startswith("a=candidate:"):
            parsed = _parse_candidate_line(line)
            if parsed:
                addr = (parsed[0], parsed[1])
                cands.append(addr)
                if parsed[2] == "host" and not host:
                    host = addr
    return ufrag, pwd, cands, host


def _answer_sdp_can_nominate(sdp) -> bool:
    """Whether this answer carries everything USE-CANDIDATE needs.

    Deliberately the whole precondition and not a proxy for it: an answer with
    credentials but no candidate, or candidates but no credentials, leaves the
    nomination with nothing to address, and leaving the window on it would
    trade 4.3 s of responding for a session that never nominates at all.
    """
    ufrag, pwd, cands, _host = _parse_answer_ice(sdp)
    return bool(ufrag and pwd and cands)


def _answer_ready_for_this_open(stamp, open_started_at) -> bool:
    """Whether the answer-ready marker was set by the open now running.

    The marker is per-camera state driving a per-open decision.  It is cleared
    at the start of every open, which covers the ordinary sequential case, but
    two opens overlapping on one camera object would otherwise let one leave its
    STUN window on the other's answer - or lose its own stamp to the other's
    reset.  Comparing against this open's own start makes a stale stamp inert
    instead.
    """
    return stamp is not None and stamp >= open_started_at


def _stun_window_answer_exit_due(*, stun_seen: bool,
                                 answer_ready: bool) -> bool:
    """Whether the STUN responder window has nothing left to wait for.

    Every branch of the window carries the delay, so this is not scoped to one.
    Measured on two cold A001064 opens that took different branches:

      * echo received, webrtcResp sent (the 20 s window): answer at +0.72 s,
        window ran to +5.05 s and left on 1.5 s of ICE silence.
      * no echo (the 2.5 s window): answer at +0.22 s, window ran the full
        2.5 s cap and left on the deadline.

    Both held the answer for the whole window.  Nothing else in the window is
    load-bearing by then either: an SRTP packet already breaks out of it, a
    camera that never probes already leaves on ``_pre_stun_idle``, and the
    bridge thread picks the responder role back up ~30 ms later.

    ``stun_seen`` is the camera's own evidence that it is running ICE: a probe
    this host actually answered, which is why it is set where the reply is sent
    and not where the request is parsed - a self-loop Data Indication is a
    binding request too, and it is our own address coming back through the
    relay.  Without such a probe there is nothing to nominate a pair *with*, and
    a relay-only camera that answers early and probes late keeps the behaviour
    it has today.
    """
    return bool(stun_seen and answer_ready)


def video_pt_from_answer_sdp(sdp_text: str) -> Optional[int]:
    """Which video payload type to narrow to, taken from the camera's answer SDP.

    This is the fallback for the case where no video RTP packet arrives before
    the serve launches.  Without it the ffmpeg SDP keeps advertising both codecs,
    and :func:`narrow_sdp_payload_types` documents what that costs: ffmpeg binds
    its depacketizer to the FIRST payload type and silently discards the rest,
    and the RTSP-push ANNOUNCE carries a parameterless H.265 stream that go2rtc
    rejects - so the publisher never attaches and every viewer gets a 404.

    The answer already states which codec the camera agreed to send, so this is a
    negotiated fact rather than a guess.  Only the *first* video m-line is read,
    and only ``a=rtpmap`` lines inside that section, so a payload number reused in
    the audio section cannot leak into the answer.

    Returns the payload type **our** template uses for that codec (96/97) - the
    camera's own numbering need not agree - or None when the answer names no video
    codec we write, which leaves the existing behaviour untouched.
    """
    pts: list = []
    rtpmap: dict = {}
    section = None
    for raw in (sdp_text or "").splitlines():
        line = raw.strip()
        if line.startswith("m="):
            if section == "video":
                break  # the first video section has been read in full
            section = "video" if line.startswith("m=video") else "other"
            if section == "video":
                # "m=video <port> <proto> <pt> [<pt> ...]"
                pts = line.split()[3:]
            continue
        if section == "video" and line.startswith("a=rtpmap:"):
            body = line[len("a=rtpmap:"):]
            pt, _, enc = body.partition(" ")
            if pt and enc:
                rtpmap[pt.strip()] = enc.strip().split("/", 1)[0].upper()
    for pt in pts:
        codec = rtpmap.get(pt)
        if codec in _SDP_VIDEO_PT_BY_CODEC:
            return _SDP_VIDEO_PT_BY_CODEC[codec]
    return None


def answer_pt_kinds(sdp_text: str) -> dict:
    """Map each payload type in the camera's answer to the kind that owns it.

    The bridge demuxes a BUNDLEd stream by RTP payload type, and until this
    existed it did so from a fixed table: 96/97/98 video, 0/8 audio.  That
    table is wrong for this fleet.  Measured 2026-08-26 across 107 A001064
    opens, **15 of them (14%) negotiated H265 on payload type 0** -- announced
    correctly in the answer as ``m=video ... 0`` with ``a=rtpmap:0 H265/90000``
    -- and then sent 2668 full-size (1222 B) video packets on pt=0 while audio
    ran normally on pt=8.  The fixed table posted every one of those video
    packets to ffmpeg's AUDIO loopback, so no video was ever observed, the 75 s
    first-media wait ran out, and the serve launched into an empty stream and
    exited: 82 s wasted, then a full reopen.  The other 92 opens answered
    ``m=video ... 96`` and worked.  Perfect separation, both directions.

    The answer is the authority on this and is already in hand: PT numbering is
    per-m-section by definition, so a section's fmt list names the kind of every
    payload type in it.  ``tests/test_answer_section_selection.py`` records the
    same renumbering on the A000088 (PT 0 carrying H265), and the DTLS path
    already selects sections by content for it; the SDES bridge was the one
    place still trusting a static tuple.

    A payload type claimed by BOTH an audio and a video section is dropped from
    the map rather than guessed at -- an ambiguous answer is not better evidence
    than the fallback table, and silently preferring one section would be the
    same class of assumption this function exists to remove.  Malformed m= lines
    are skipped, never raised on: this feeds a media path.
    """
    kinds: dict = {}
    dropped: set = set()
    for raw in (sdp_text or "").splitlines():
        line = raw.strip()
        if not line.startswith("m=audio") and not line.startswith("m=video"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        kind = "video" if line.startswith("m=video") else "audio"
        for tok in parts[3:]:
            try:
                pt = int(tok)
            except ValueError:
                continue
            if not 0 <= pt <= 127:
                continue
            if kinds.get(pt, kind) != kind:
                dropped.add(pt)
            kinds[pt] = kind
    for pt in dropped:
        kinds.pop(pt, None)
    return kinds


def rewrite_rtp_payload_type(pkt: bytes, pt: int) -> bytes:
    """Return ``pkt`` with its RTP payload type replaced, marker bit preserved.

    Used only where the bridge itself decrypted the packet (``_use_plain_rtp``),
    so what is being edited is plaintext on its way to our own loopback -- never
    a packet ffmpeg will authenticate, where a changed byte would fail the SRTP
    auth tag.  RTP byte 1 is ``M(1) | PT(7)`` (RFC 3550), so only the low seven
    bits move.

    A packet too short to hold that byte is returned untouched rather than
    rejected: this is the media path, and a malformed packet is ffmpeg's to
    discard, not the bridge's to raise on.
    """
    if len(pkt) < 2:
        return pkt
    return pkt[:1] + bytes([(pkt[1] & 0x80) | (pt & 0x7F)]) + pkt[2:]


#: Video payload types the SDES answer template advertises (H264, H265).
_SDES_ANSWER_VIDEO_PTS = (96, 97)


def _should_capture_sprop(kind, decrypted: bool, sprop_done: bool) -> bool:
    """May this packet's payload be mined for SPS/PPS and cached to disk?

    ``decrypted`` is the load-bearing term and it used to be missing.  The
    bridge's ``_fwd_pkt`` starts as the raw inbound packet and is rebound only
    when ``unprotect`` succeeds, so it stays ciphertext whenever there is no
    SRTP receive session - pylibsrtp is in the optional ``webrtc`` extra, so a
    base install never has one - or when ``unprotect`` raised, since that
    handler logs a few lines and falls through.

    SRTP leaves the RTP header in clear, so the payload offset comes out right
    and random ciphertext reaches the NAL demux; ``payload[0] & 0x1F`` draws 7
    and 8 at about 1/32 each, and on a 30 fps stream both appear within seconds.

    The result is written to ``~/.config/aidot/sprop/<devid>.sprop`` and injected
    as ``sprop-parameter-sets=`` by every later session, so a poisoned cache
    outlives the session that created it: installing pylibsrtp afterwards does
    not clear the file, and the first correct capture then differs from it and
    trips the ``.unstable`` marker, disabling injection for that camera for good.
    A bad frame is cheap; a bad file is not.

    Returning False for a packet nobody decrypted is right even where ffmpeg
    does its own decryption: what we hold is still ciphertext, so anything mined
    from it would be noise either way.
    """
    return bool(kind == "video" and decrypted and not sprop_done)


def _should_count_media(decrypted: bool, plain_rtp: bool) -> bool:
    """Did this forward deliver media the consumer can actually use?

    ``_media_progress`` and ``_media_counts`` are the only in-process evidence
    that media flowed on the SDES path - nothing is decoded in this process, so
    ``on_frame`` never fires and these counters are what every health check
    reads: ``SdesSession.last_media_monotonic`` feeds ``SdesSession.is_stalled``,
    the keepalive's ``_healthy`` is ``last_media_monotonic > 0.0``, and
    ``_healthy`` is what resets the streak ``_should_abandon_keepalive`` counts.
    Counting a packet the consumer throws away therefore does not just skew a
    statistic: it makes a session report healthy forever while the viewer sees
    black, because every one of those checks is satisfied by a counter that
    keeps moving.

    The question is not "did we decrypt it" but "is the forwarded packet
    plaintext by the time ffmpeg reads it", and who owes the decryption depends
    on the camera:

    * ``plain_rtp`` (``_use_plain_rtp``, the ``_PLAIN_RTP_MODELS`` substring
      allowlist): the ffmpeg SDP is ``RTP/AVP`` with no ``a=crypto``, so the
      BRIDGE owes the decryption.  ``_fwd_pkt`` is rebound only when
      ``unprotect`` succeeds, and two paths leave it as ciphertext - no SRTP
      receive session (pylibsrtp is in the optional ``webrtc`` extra) and an
      ``unprotect`` that raised.  ffmpeg discards those, so they are not
      delivered media.  Non-TUTK packets on this path are SRTP by then: the
      camera switches from TUTK SFrames to standard SRTP after LIVING, and the
      SFrames are handled and ``continue``-d well before this point.
    * Otherwise the SDP is ``RTP/SAVP`` with ``a=crypto`` and FFMPEG owes the
      decryption.  Forwarding ciphertext is exactly right there, ``decrypted``
      is always False, and the packet IS delivered media - so the ``plain_rtp``
      term is load-bearing.  ``is_sdes_camera`` is a cloud property
      (``enableSdes == '1'``), a different and wider set than the model
      allowlist, so this path is reachable by any SDES camera not named in it.
      Without the second term such a camera would report ``last_media`` 0.0
      forever, trip ``is_stalled`` at the grace deadline while streaming fine,
      and eventually have its keepalive abandoned.
    """
    return bool(decrypted or not plain_rtp)


def _resolve_sdes_video_pt() -> Optional[int]:
    """EXPERIMENTAL (opt-in, default off): pin the OFFER to one video codec.

    The offer sent in webrtcReq advertises BOTH 96 (H264) and 97 (H265) and
    expresses no preference, so the camera chooses which to send in its answer.
    Measured on an A001064 across eleven sessions in one afternoon it chose H264
    nine times and H265 twice for an otherwise identical request, and the codec
    it chose determined the resolution (H264 -> 1280x720, H265 -> 2560x1440, 11
    of 11).  A consumer that cannot decode a sudden 2560x1440 H265 stream, or
    cannot absorb the bitrate change either way, has no means today of
    preventing the flip.  Pinning removes the choice: measured 2026-08-07, an
    offer pinned to 96 produced h264 1280x720 in 4 of 4 sessions.

    It is the OFFER that matters, not the answer.  Traced live with every status
    line printed: this path sends webrtcReq carrying our offer and then reports
    "Using camera's video SRTP key from answer" - the camera answers, we do not.
    An earlier version of this pinned the answer builder instead and changed
    nothing at all, while the arms still came out looking like it had worked.

    **Do not set this to 97.**  An H265-only offer returned NO VIDEO - audio
    only, no video stream in the recording - in 3 of 3 interleaved rounds
    against 3 of 3 successes for 96 in the same run.  The efficient H265 profile
    is real and reproducible, but only when BOTH codecs are offered; narrowing
    to it removes the option rather than selecting it.

    Left unset this returns None and the offer is byte-identical to today.  The
    SDES offer path is shared by every SDES camera, and this project's CHANGELOG
    records fleet-wide blackouts caused by changes to shared paths, so the
    default has to be inert.  Anything unparseable, or a payload type the
    template does not advertise, also returns None: narrowing to a payload type
    the camera was never offered would leave it nothing to send.
    """
    raw = (os.environ.get("AIDOT_SDES_VIDEO_PT", "") or "").strip()
    if not raw.isdigit():
        return None
    pt = int(raw)
    return pt if pt in _SDES_ANSWER_VIDEO_PTS else None


def _serve_video_pt(observed, answer, pinned) -> "Optional[int]":
    """Which video payload type the serve SDP should narrow to.

    Precedence: **observed beats pinned beats answer.**

    An observed payload type is fact -- it is what is arriving. A pin is our
    own constraint on the offer, so narrowing past it can only produce a stream
    the camera was never asked to send. The answer is the weakest of the three
    because it can be absent or stale, not because it lies: trusting it when
    video had not yet been observed once built an hevc-only SDP that no hevc
    ever filled -- ffmpeg could not determine dimensions, could not write the
    RTSP header, and the serve died at startup. That was invisible until the
    exit reason stopped being flushed out of the stderr tail by Non-monotonic
    DTS noise.

    This docstring used to say the reference A001064 "ANSWERS 97 (H.265) and
    SENDS 96 (H.264) in every observed session". That is RETRACTED. Measured on
    2026-09-04 by reading the first decrypted NAL of 44 cold opens: the answer
    and the wire agree every time. The camera simply picks a codec per session
    -- 40 of the 44 negotiated H.264 (payload begins 0x67, an H.264 SPS with
    profile_idc 0x4D level 0x1F, matching the avc1.4D001F go2rtc reports) and 4
    negotiated H.265 (0x40/0x42/0x44 -- VPS, SPS, PPS -- then 0x62 FU
    fragments). Both are served correctly today. The retracted claim reads as a
    demux bug and very nearly bought a fix for one that does not exist.

    Returns None when nothing is known; the caller keeps its own "could not
    narrow" path rather than having a payload type invented for it.
    """
    if observed in _SDP_VIDEO_PTS:
        return int(observed)
    if pinned is not None:
        return int(pinned)
    return answer


#: The video codecs the SDES OFFER advertises, keyed by payload type, with the
#: rtpmap/fmtp lines that describe each one.  Deliberately NOT reusing
#: ``_SDES_ANSWER_VIDEO_PTS``: that tuple is what the answer template carries
#: and what the pin is validated against, and coupling the offer's wire order to
#: it means a later reorder of one silently reorders the other.
_SDES_OFFER_VIDEO_CODECS = {
    96: (
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;"
        "profile-level-id=42e01f\r\n"
    ),
    97: (
        "a=rtpmap:97 H265/90000\r\n"
        "a=fmtp:97 level-id=93\r\n"
    ),
}

#: The order those codecs go on the wire today: H264 first, H265 second.  This
#: is the shipped default and changing it changes every SDES camera's
#: negotiation, so it is overridden per-run by env and never edited here.
_SDES_OFFER_VIDEO_PT_ORDER = (96, 97)


def _resolve_sdes_video_pt_order() -> tuple:
    """EXPERIMENTAL (opt-in, default off): reorder the OFFER's video codec list.

    RFC 3264 section 5.1 makes the ``m=video`` payload-type list a *preference*
    list, most-preferred first.  The offer this module sends carries ``96 97``,
    i.e. it already states a preference for H264 -- so the often-repeated
    shorthand that our offer "expresses no preference" is not what the SDP says.
    What is true is that nothing here ever *chose* that order: the line arrived
    verbatim when this path was extracted from ``client.py`` and has never been
    varied.

    Measured on an A001064, the camera answers H264 most of the time and H265
    occasionally for an otherwise identical request (nine and two across eleven
    sessions one afternoon).  Read against the offer, that is a camera which
    honours our stated first choice most of the time and disregards it some of
    the time -- which is a reason to expect *less* of reordering than of the
    pin, and is recorded here so nobody reads this knob as established.

    Why it is worth having anyway: the efficient profile (hevc 2560x1440 at
    ~1.1 Mbps against h264 1280x720 at 2.5-4.0 Mbps) has only ever appeared when
    BOTH codecs are on the wire.  ``AIDOT_SDES_VIDEO_PT=97`` narrows to H265 and
    returns no video at all, 3 of 3 rounds -- narrowing removes the option
    rather than selecting it.  Reordering is the only untried lever that leaves
    both codecs offered, so the camera can still fall back to H264.

    Accepts a comma- or space-separated payload-type list (``97,96``, ``97``).
    Whatever is named goes first, in the order named; every advertised codec not
    named is appended in the default order.  So this can express a preference
    and can never narrow the offer: the result is always a permutation of the
    full advertised set, and an empty or entirely unusable value yields exactly
    today's order.  Narrowing already has its own variable, and the one time it
    was measured it cost the picture.

    Unknown payload types and duplicates are dropped rather than honoured: a
    payload type this offer does not advertise has no rtpmap to go with it, and
    listing one on the m-line would name a codec the camera was never given the
    parameters for.
    """
    raw = os.environ.get("AIDOT_SDES_VIDEO_PT_ORDER", "") or ""
    named: list = []
    for tok in raw.replace(",", " ").split():
        if not tok.isdigit():
            continue
        pt = int(tok)
        if pt in _SDES_OFFER_VIDEO_CODECS and pt not in named:
            named.append(pt)
    return tuple(named) + tuple(
        pt for pt in _SDES_OFFER_VIDEO_PT_ORDER if pt not in named
    )


def _sdes_offer_video_codec_lines(order=None) -> tuple:
    """Build the offer's video codec list and its rtpmap/fmtp block.

    Returns ``(pt_list, attrs)`` where ``pt_list`` is the payload-type list for
    the ``m=video`` line ("96 97") and ``attrs`` is the rtpmap/fmtp lines for
    those payload types, in the same order.  Both have to move together: an
    m-line naming a payload type whose rtpmap was left behind is an offer the
    camera cannot act on.

    ``order`` of None is today's shipped order, so the default output is
    byte-identical to the literal this replaced.  Anything not advertised is
    dropped, and an order that ends up empty falls back to the default -- an
    ``m=video`` line with no payload type at all leaves the camera nothing to
    send, which is the one outcome worse than an unpinned choice.
    """
    pts = tuple(
        pt for pt in (order if order is not None else _SDES_OFFER_VIDEO_PT_ORDER)
        if pt in _SDES_OFFER_VIDEO_CODECS
    )
    if not pts:
        pts = _SDES_OFFER_VIDEO_PT_ORDER
    return (
        " ".join(str(pt) for pt in pts),
        "".join(_SDES_OFFER_VIDEO_CODECS[pt] for pt in pts),
    )


def narrow_sdp_payload_types(sdp_text: str, keep_video=None, keep_audio=None) -> str:
    """Rewrite an SDP to advertise a single payload type per media line.

    ffmpeg binds each RTP depacketizer to the FIRST payload type on the m-line and
    silently discards packets carrying any other one.  The SDP written for the
    bridge lists both candidates per line (``m=video ... 96 97`` for H.264/H.265,
    ``m=audio ... 0 8`` for PCMU/PCMA) because which one the camera uses varies per
    session, so whichever it actually sends has to be promoted before launch.

    Getting this wrong on the VIDEO line costs the picture.  Getting it wrong on the
    AUDIO line costs the picture too, and less obviously: the mpegts mux withholds
    its PAT/PMT until every mapped stream has produced a packet, so an audio stream
    whose packets are all discarded means the consumer receives zero bytes - video
    included - while every other signal looks healthy.

    ``keep_video`` / ``keep_audio`` of None leaves that line alone.

    Handles any payload list on the m-line (``96 97``, ``96 97 98``, ...): the
    kept line advertises ONLY the kept payload and the rtpmap/fmtp lines of
    every dropped payload are removed.  The old implementation replaced the
    literal ``" 96 97"``, so the day the SDP template grew a third video
    payload (98, the second H.265 variant) narrowing silently stopped working
    for it - and an un-narrowed multi-codec SDP makes the RTSP-push ANNOUNCE
    carry a parameterless H.265 stream that go2rtc rejects with 400.
    """
    drop: set = set()
    kept = []
    for line in sdp_text.splitlines(keepends=True):
        stripped = line.lstrip()
        m_kind = keep = None
        if stripped.startswith("m=video"):
            m_kind, keep = "video", keep_video
        elif stripped.startswith("m=audio"):
            m_kind, keep = "audio", keep_audio
        if m_kind is not None and keep is not None:
            head, _, pts = stripped.partition(" RTP/")
            proto, _, pt_list = pts.partition(" ")
            listed = pt_list.split()
            if str(keep) in listed:
                drop.update(p for p in listed if p != str(keep))
                line = (line[: len(line) - len(stripped)]
                        + f"{head} RTP/{proto} {keep}"
                        + ("\r\n" if line.endswith("\r\n") else "\n"))
        elif any(
            stripped.startswith(f"a={attr}:{pt}{sep}")
            for pt in drop
            for attr, sep in (("rtpmap", " "), ("fmtp", " "), ("fmtp", ";"))
        ):
            continue
        kept.append(line)
    return "".join(kept)


def _build_restart_sdp(
    *,
    ts: int,
    lo_audio_port: int,
    lo_video_port: int,
    use_plain_rtp: bool,
    srtp_key_audio: str,
    srtp_key_video: str,
    first_video_pt=None,
    answer_video_pt=None,
    first_audio_pt=None,
) -> str:
    """Build the SDP the SRTP key-restart hands to the relaunched ffmpeg.

    The restart rebuilds the bridge SDP from scratch, and it has to match the
    PRIMARY SDP on two counts or it undoes two shipped fixes at once.

    Transport: for ``_use_plain_rtp`` models - which is every SDES camera this
    library supports - the bridge decrypts and forwards PLAIN RTP, so the
    primary SDP is RTP/AVP with no a=crypto.  Writing RTP/SAVP here makes
    ffmpeg try to authenticate already-decrypted packets: every one fails its
    HMAC check and a working stream drops to zero bytes mid-session.

    Payload types: hard-coding "0 8" and "96 97" throws away the narrowing, and
    ffmpeg binds the FIRST type on each line - so an H.265 camera silently
    loses all video (and with it the PAT/PMT, hence the whole output), and a
    PCMA camera loses its audio.  Both types are known by now, so the selection
    lives here rather than at the call site: a caller free to pass a payload
    type of its own is a caller free to reintroduce the hard-coding.

    Pure: no I/O, no clock, no ``self``.  ``ts`` is passed in and the
    sprop-parameter-sets injection and the on-disk rewrite stay with the
    caller.
    """
    _proto = "RTP/AVP" if use_plain_rtp else "RTP/SAVP"

    def _crypto(key: str) -> str:
        if use_plain_rtp:
            return ""
        return (f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
                f"inline:{key}\r\n")

    sdp = (
        "v=0\r\n"
        f"o=- {ts} {ts} IN IP4 0.0.0.0\r\n"
        "s=aidot-sdes-rx\r\n"
        "t=0 0\r\n"
        f"m=audio {lo_audio_port} {_proto} 0 8\r\n"
        "c=IN IP4 127.0.0.1\r\n"
        f"{_crypto(srtp_key_audio)}"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=rtcp-mux\r\n"
        f"m=video {lo_video_port} {_proto} 96 97\r\n"
        "c=IN IP4 127.0.0.1\r\n"
        f"{_crypto(srtp_key_video)}"
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;"
        "profile-level-id=42e01f\r\n"
        "a=rtpmap:97 H265/90000\r\n"
        "a=fmtp:97 level-id=93\r\n"
        "a=rtcp-mux\r\n"
    )
    return narrow_sdp_payload_types(
        sdp,
        # Same answer-SDP fallback as the pre-launch narrowing: this restart
        # rebuilds the dual-codec template, so without it a session that never
        # saw a video packet reproduces the unnarrowed SDP on every watchdog
        # cycle.
        keep_video=(first_video_pt
                    if first_video_pt in _SDP_VIDEO_PTS
                    else answer_video_pt),
        keep_audio=(first_audio_pt if first_audio_pt in (0, 8) else None),
    )


async def _sdes_await_answer_or_terminal(
    answer_fut, terminal_error_fut, timeout: float, _status=None
):
    """Await the camera's SDES answer, but give up at once on a terminal ack.

    A terminal webrtcResp ack (-50002 max-streams / -50015 SD-cap) means the
    camera REFUSED this stream; the whole point of classifying it as terminal
    is that neither waiting nor retrying can help.  The SDES path used to watch
    only ``answer_fut``, so a refusal cost the full answer budget and then a
    pointless DTLS-fallback offer on top.

    Raises ``AidotCameraBusy`` the moment the refusal lands, ``TimeoutError``
    if neither arrives in ``timeout`` (the caller's existing no-answer path).
    """
    if terminal_error_fut is None:
        return await asyncio.wait_for(answer_fut, timeout=timeout)

    _waits = {answer_fut, terminal_error_fut}
    _done, _pending = await asyncio.wait(
        _waits, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
    )
    if terminal_error_fut in _done:
        code, desc = terminal_error_fut.result()
        if _status is not None:
            _status(f"camera refused: ack {code} {desc} - terminal, not retrying")
        raise AidotCameraBusy(code, desc)
    if answer_fut in _done:
        return answer_fut.result()
    # Timed out.  ``answer_fut`` MUST be cancelled here, exactly as the
    # ``asyncio.wait_for(answer_fut, ...)`` this replaced did.  The MQTT handler
    # routes a late webrtcResp to ``second_answer_fut`` only ``if
    # answer_fut.done()`` (webrtc_open.py), and the late-ICE-credential recovery
    # reads ``second_answer_fut``.  Leaving it pending swallows the late answer,
    # so USE-CANDIDATE is never sent, the camera stays in ICE "Checking" and the
    # view shows a black frame with no media - the 0.12.16 failure mode.
    #
    # ``terminal_error_fut`` is deliberately NOT cancelled: it is checked again
    # after the open returns (webrtc_open.py) to surface a refusal that landed
    # during the fallback.
    answer_fut.cancel()
    # Builtin TimeoutError (asyncio.TimeoutError is an alias since 3.11); this
    # is what the caller's `except TimeoutError` no-answer path already catches,
    # which is what triggers the DTLS fallback.
    raise TimeoutError()


# Seconds a role-reversal camera gets to echo our webrtcReq back.
#
# This was 2.0 s on the reading that A001064 "needs the resulting webrtcResp".
# Measured over 18 hours of logs on 2026-09-03/04: of 61 SDES opens, the 17 that
# took this wait timed out 17/17 at a mean of 2.086 s, and neither `camera
# webrtcReq echo received` nor `webrtcResp sent (SDES` appears once in the whole
# log.  The webrtcResp was never built, and all 17 streamed regardless - so the
# 2.0 s was 45 percent of a 4.2 s cold connect, spent on nothing.
#
# Shortened rather than removed, exactly as the livePlayReq echo wait was
# (5.0 -> 0.25 s, 169/169 timeouts): the evidence says the wait times out, not
# that the branch is wrong, so a camera that does echo promptly still gets its
# webrtcResp.  Raise AIDOT_SDES_ECHO_WAIT_S to put the old behaviour back
# without a release.
#
# The measurement is one fleet.  An echo that lands between this value and the
# old 2.0 s would now miss the wait, and _cam_echo_received is a branch
# selector, not just a log line: it decides whether the webrtcResp is built,
# whether the ICE window runs 20 s or 2.5 s, and whether the quickConn
# reconnect retry is armed.  A late echo is therefore reported loudly at the
# end of the STUN window rather than passing unnoticed, so an operator on a
# fleet whose band is not empty gets a line naming the knob.
_SDES_ECHO_WAIT_S = 0.25
#: What the wait was before it was measured, and what a device that has actually
#: produced an echo goes back to.
_SDES_ECHO_WAIT_LEGACY_S = 2.0


def _sdes_echo_wait_timeout(skip_liveplay: bool,
                            echo_seen: bool = False) -> float:
    """Seconds to block on the camera's webrtcReq echo. Never negative.

    ``echo_seen`` is this device's own history: once an echo has been observed
    from it - during the wait or, more usefully, after the wait had already
    expired - every later open on that device waits the full
    ``_SDES_ECHO_WAIT_LEGACY_S`` again.  That is what keeps the shortened wait
    honest on a fleet the 17/17 measurement never saw: such a camera pays the
    miss once, says so in the log, and is never shortened again.  An explicit
    env value still wins over both.

    The echo only ever arrives for role-reversal models (e.g. A001064), which
    build a webrtcResp from it and run with ``skip_liveplay`` False (they are
    hard-excluded from sdes_fast_liveplay).  For A001513-class cameras
    (``skip_liveplay`` True, the default) the echo never arrives at all, so they
    do not block on it.

    Read per call and clamped, like its sibling
    :func:`_sdes_liveplay_echo_timeout`: a malformed env value is ignored rather
    than raising, because parsing it at import time makes one typo on an HA box
    an ImportError that takes down every camera, and freezing it at import means
    an operator changing it sees nothing until a full restart.
    """
    raw = _os.environ.get("AIDOT_SDES_ECHO_WAIT_S")
    if raw is not None:
        try:
            val = float(raw)
        except (TypeError, ValueError):
            val = None
        if val is not None and val >= 0.0:
            return 0.0 if skip_liveplay else val
    if skip_liveplay:
        return 0.0
    return _SDES_ECHO_WAIT_LEGACY_S if echo_seen else _SDES_ECHO_WAIT_S


# ffmpeg returns AVERROR(EPIPE) = -32 when its output consumer disappears, and a
# process exit status is truncated to an unsigned byte: -32 & 0xFF = 224.
_FFMPEG_EXIT_EPIPE = 224


#: What ffmpeg returns when it exits because it received a signal it handled.
#: `exit_program()` uses 255 whenever `received_nb_signals` is set, so our
#: SIGTERM-first teardown produces a POSITIVE 255, not a negative rc.
_FFMPEG_EXIT_SIGNALLED = 255


def _classify_ffmpeg_exit(rc: int, teardown_requested: bool) -> int:
    """Log level for the bridge observe loop's "ffmpeg exited" line.

    Teardown here is SIGTERM-first with a SIGKILL fallback (SdesSession.stop(),
    the cold-open _reap(), the key-restart proc replace, and the DTLS-fallback
    abort).

    A teardown ends one of two ways and BOTH are expected:

    * ``rc < 0`` - the SIGKILL fallback, or a SIGTERM the process did not
      handle. Python reports a negative value only when the child is killed BY
      a signal.
    * ``rc == 255`` - **SIGTERM that ffmpeg handled.** ffmpeg installs its own
      handler, unwinds, and calls ``exit_program()``, which returns 255 when a
      signal was received. This is the normal path and it is POSITIVE.

    Missing the second case is what made every deliberate stop of an SDES serve
    look like a crash: exit code 255, no stderr at all (ffmpeg's "Exiting
    normally, received signal 15." is INFO and the serve runs at
    ``-loglevel warning``), on the idle-release cadence. Three investigations
    of a camera that "died every ~3 minutes" were investigating a teardown.

    Anything else non-zero - a signal death or a 255 with NO teardown in
    flight, or a genuine ffmpeg error code during one - is unexpected and stays
    loud. Pure function so the policy is unit-testable without a live bridge.
    """
    if teardown_requested and (rc < 0 or rc == _FFMPEG_EXIT_SIGNALLED):
        return logging.DEBUG
    if rc == _FFMPEG_EXIT_EPIPE:
        # Broken pipe: the consumer went away. That is the NORMAL end of a
        # `-listen 1` serve - go2rtc disconnects and ffmpeg exits - so warning
        # about it trains the reader to ignore real failures. A process exit
        # status is an unsigned byte, so AVERROR(EPIPE) = -32 surfaces as 224.
        return logging.DEBUG
    return logging.WARNING


#: Mid-session stall nudge (see _stall_nudge_due): enabled by default;
#: ``AIDOT_SDES_STALL_NUDGE=0`` turns it off and
#: ``AIDOT_SDES_STALL_NUDGE_AFTER_S`` moves the trigger point.
_STALL_NUDGE_ENABLED = os.environ.get("AIDOT_SDES_STALL_NUDGE", "1") != "0"
_STALL_NUDGE_AFTER_S = float(
    os.environ.get("AIDOT_SDES_STALL_NUDGE_AFTER_S", "2.5"))


def _stall_nudge_due(
    *,
    silence_s: float,
    nudges_sent: int,
    since_last_nudge_s: float,
    stall_after_s: float = 2.5,
    max_nudges: int = 3,
    interval_s: float = 2.0,
) -> bool:
    """Whether the bridge should re-send AVIO LIVING for a mid-session stall.

    The A001064 episodically stops transmitting mid-session with no teardown
    signal; every reopen afterwards succeeds immediately, so the camera is
    awake and answering handshakes seconds after it stopped (measured
    2026-08-24/25).  LIVING is the message that starts media on a fresh
    session, so re-sending it on the live session is the cheapest possible
    revive attempt.  Bounded (a few sends, spaced out) so a camera that is
    truly asleep or out of range is not spammed - the serve's input timeout
    and the keepalive reopen remain the unchanged fallback.  Pure function so
    the policy is unit-testable without a live bridge.
    """
    if silence_s <= stall_after_s:
        return False
    if nudges_sent >= max_nudges:
        return False
    return since_last_nudge_s >= interval_s


def _bridge_should_break(rc, teardown_requested: bool) -> bool:
    """Whether the bridge observe loop should end on this poll() result.

    rc is the held proc's poll() result (None while it is still running).
    Ending the loop is only correct when ffmpeg has actually exited AND no
    locally-initiated teardown is in flight for it: a non-None rc seen while
    teardown_requested is True is the key-restart window (or any other
    flagged local kill) - the OLD proc's exit, not a reason to stop.  That
    window always resolves promptly one of two ways, so skipping the break
    here cannot hang the bridge thread: either the key-restart repoints
    _proc_holder[0] at the live new proc (next poll() is None again), or a
    genuine teardown closes the loopback sockets, which makes the loop's
    select() raise and exit via its own except-break.  Pure function so the
    policy is unit-testable without a live bridge thread.
    """
    return rc is not None and not teardown_requested


# Cap on peer-reflexive candidates learned from inbound probes.  A camera has
# one working path; a handful of source addresses is normal churn (NAT rebind,
# audio vs video socket), anything beyond that is noise and must not be allowed
# to grow the nomination set without bound.
_MAX_PRFLX_CANDS = 4


def _is_self_transport_address(ip, port, *, local_ip, public_ip, own_ports):
    """Is this address US, rather than a peer that merely looks like us?

    The guard exists so we never nominate our own address: doing that has this
    host answering its own connectivity check, which would arm the media trigger
    at nobody.  What it must NOT do is refuse the camera, and for one common
    deployment it did - a camera in the same house reaches the TURN server from
    the same public IP we do, so an address-only comparison called it us.  Seven
    first-media stalls were that (`vetoed-self-ip`, ROAD-TO-1.0 item 3): the
    camera's relay-carried Binding Request could not be answered, because the
    branch that wraps the response in a Send Indication is guarded by this, so
    ICE never completed and no media ever started.

    ICE identifies a candidate by its transport address, and so does this: our
    own is one ip:PORT, and a peer sharing our NAT has the same ip with a
    different port.  Comparing the pair keeps the guard exactly as strong for
    the case it was written for and stops it catching the camera.

    ``port`` may be None where a caller genuinely does not know it. That keeps
    the old, conservative answer - widening a decision on an address we cannot
    fully identify would be guessing, and this guard is the safe default.

    Loopback and this host's own LAN address are us on ANY port: a different
    port there is still this machine.

    Pure, so the policy is testable without a camera.
    """
    if not ip:
        return False
    if ip in {"127.0.0.1", "0.0.0.0", local_ip}:
        return True
    if public_ip and ip == public_ip:
        return port is None or port in set(own_ports or ())
    return False


def _record_peer_reflexive(known, discovered, observed, is_self=None):
    """Learn the address a STUN probe actually arrived from.

    ICE calls this a peer-reflexive candidate (RFC 8445 s7.3.1.3): the camera
    is reachable at the source of its own connectivity check whether or not it
    ever advertised that address.  We were nominating only what the answer SDP
    listed, which fails whenever the listed address is not reachable from here
    - a camera on a foreign subnet advertises a private candidate we have no
    route to, the nomination goes into a black hole, and the session sits in
    ICE "Checking" while the camera's probes keep arriving from an address we
    never nominate.  Observed on the A001064 PTZ while it was on a separate
    192.168.9.0/24: it advertised 192.168.9.13 as its only candidate.

    Returns the new discovered list, or ``discovered`` unchanged when there is
    nothing to learn.  Callers must REBIND rather than mutate in place - the
    bridge thread iterates this list and must never see it change under it.

    Pure function so the policy is unit-testable without a camera.
    """
    if not observed:
        return discovered
    _ip, _port = observed
    if not _ip or not _port:
        return discovered
    if is_self is not None and is_self(_ip, _port):
        return discovered
    if observed in known or observed in discovered:
        return discovered
    if len(discovered) >= _MAX_PRFLX_CANDS:
        return discovered
    return [*discovered, observed]


#: How many distinct inbound probe sources the stall report will name. Beyond
#: this the count alone is kept - a stall is explained by the first few sources,
#: and an unbounded list would turn one WARNING into a wall of text.
_MAX_PROBE_SOURCES = 6


def _probe_source_verdict(src, turn_peer_ip, turn_peer_port, *,
                          cam_peer, observed, known, learned):
    """Say why one inbound STUN probe's source was, or was not, learned.

    Nomination can only aim at an address, and when the camera's answer lists
    one this host cannot route to, the only usable addresses are the ones its
    own probes arrive from.  Two vetoes drop a relay-carried probe before it can
    become a peer-reflexive candidate, and both are silent in the code they
    guard, so a session that stalls for one reason is indistinguishable from a
    session that stalled for the other.  This names them apart.

    Takes the values the bridge already computed rather than re-deriving them:
    ``cam_peer`` is ``_br_cam_peer`` (None once ``_is_self_peer_ip`` has refused
    the XOR-PEER-ADDRESS) and ``observed`` is ``_br_obs`` (None once the
    ``_bsrc`` fallback has refused the TURN server's own address too).  A copy
    of the decision here would rot the first time either site changed.

    ``known`` is "this address is already in the nomination set" and ``learned``
    is "this call grew the peer-reflexive set"; without both, an address that
    ``_record_peer_reflexive`` refused on its own policy would be reported as
    one we are already nominating, which is the opposite of the truth.

    Pure, so the classification is testable without a camera.
    """
    if observed:
        if learned:
            return "learned"
        if known:
            return "known"
        # _record_peer_reflexive took it and gave nothing back: its own self-IP
        # check, or the peer-reflexive cap.
        return "prflx-refused"
    if turn_peer_ip and not turn_peer_port:
        return "vetoed-no-peer-port"
    if turn_peer_ip and not cam_peer:
        # _is_self_peer_ip matched the XOR-PEER-ADDRESS.
        return "vetoed-self-ip"
    # No usable peer address at all, and the packet came from the relay, so the
    # _bsrc fallback had nothing to offer but the TURN server itself.
    return "vetoed-turn-source"


def _stall_answer_candidates(pre_launch_sdp, answer_fut):
    """How many ICE candidates the camera's answer carried, for the stall report.

    Three outcomes, deliberately not two:

      * an integer - the answer arrived and carried this many candidates, which
        may be zero;
      * ``None`` - the camera never answered;
      * ``-1`` - nobody could tell, so the report says nothing at all.

    The distinction that matters is the first against the second, because
    ``nominated=none`` means one of them and they are investigated in different
    subsystems. Getting it wrong here would be the same mistake the field exists
    to prevent, so arrival is decided by whether a RESULT came back, never by
    whether its SDP string is non-empty: an answer carrying an empty SDP is
    falsy and is still an answer.

    A future that failed is ``-1`` and not ``None``: an exception is not
    evidence the camera stayed silent, and it may well have been ours.

    Pure, so the classification is testable without a camera.
    """
    if pre_launch_sdp:
        return pre_launch_sdp.count("a=candidate:")
    if answer_fut is None:
        return -1
    if answer_fut.cancelled():
        return None
    if not answer_fut.done():
        return -1
    try:
        if answer_fut.exception() is not None:
            return -1
        result = answer_fut.result()
    except Exception:
        return -1
    if result is None:
        return -1
    return (result.get("sdp", "") or "").count("a=candidate:")


def _first_media_stall_report(device_id, waited_s, nominated,
                              use_candidate_sent, binding_success,
                              trigger_sent, probes, probes_dropped=0,
                              cancelled=False, media_pkts=0, decrypt_fails=0,
                              answer_cands=-1, trigger_acked=None):
    """Build the one line a first-media stall emits.

    A session that never delivers a byte looks, in a log, exactly like one that
    delivered late: the wait expires, the serve launches with unknown payload
    types, and nothing states the reason.  The reason is knowable at that
    moment.  Media only ever follows the AVIO LIVING trigger, that trigger is
    armed only by an inbound STUN Binding Success Response, and that response
    only comes back if something we nominated was reachable - so the nominated
    set, the Binding Success count, the trigger flag and the verdict on every
    inbound probe source are between them the whole explanation.

    Addresses and counts only.  This line reaches ``home-assistant.log`` and
    users paste that file into public issue reports.

    ``probes`` is a sequence of ``(source_label, verdict)`` from
    :func:`_probe_source_verdict`.  Pure, so the wording is testable.
    """
    _cands = ", ".join(f"{_ip}:{_port}" for _ip, _port in (nominated or []))
    _probes = "; ".join(
        f"{_where} -> {_verdict}" for _where, _verdict in (probes or [])
    )
    if probes_dropped:
        _probes += f"; (+{probes_dropped} more source(s))"
    _why = ""
    if not binding_success:
        _why = (
            " No inbound STUN Binding Success arrived, so the AVIO LIVING"
            " trigger was never armed and the camera never started sending."
        )
    elif not trigger_sent:
        _why = (
            " A Binding Success arrived and the trigger still did not go -"
            " the trigger is not gated on anything else."
        )
    # ``cancelled`` distinguishes the two ways this line gets written, because
    # they are different facts about the session: the wait ran its full course,
    # or a caller gave up sooner - a snapshot does, at its own budget - and the
    # session might still have delivered.  Without saying which, an early number
    # reads as a shorter deadline than the one that actually applies.
    # `nominated=none` has two causes that want different subsystems looked at:
    # the camera never answered, or it answered carrying no candidates. The
    # existing corpus already holds a "(no ICE creds in answer)" row that
    # nothing since has been able to tell apart from a lost answer. -1 means the
    # caller could not determine it, and is reported as nothing at all rather
    # than as a zero - "we did not look" and "there were none" is the confusion
    # this whole line exists to undo.
    # `trigger=sent` only ever meant "we transmitted", and the kill showed that
    # is not enough: a session can send it, complete ICE, and receive nothing.
    # 0x1500 is SESSION_MODE_REQ in the vendor's definitions and 0x1501 is its
    # RESP, so the camera is expected to answer - and whether it did separates a
    # command that never arrived (ours: it is SCTP DATA on a channel whose
    # transport address we choose) from one it accepted and ignored (theirs).
    # None means nobody recorded it, which reports nothing rather than a guess.
    _trigger = "sent" if trigger_sent else "not-sent"
    if trigger_sent and trigger_acked is not None:
        _trigger += "(acked)" if trigger_acked else "(unacked)"

    _answer = ""
    if answer_cands is None:
        _answer = " answer=none;"
        _why += ("  The camera never answered, so there was nothing to"
                 " nominate - this is signaling, not ICE.")
    elif answer_cands >= 0:
        _answer = " answer=%d-candidates;" % answer_cands

    # The counters exist to separate two sessions that otherwise write the same
    # line: one where the camera sent nothing, and one where it sent media that
    # every SRTP unprotect rejected.  Media counters are gated on the packet
    # being readable - correctly, since an undecryptable packet is not delivered
    # media - so without these the second case leaves no trace at all.  They
    # want opposite investigations: the camera, or our keys.
    if media_pkts and decrypt_fails >= media_pkts:
        _why += (
            "  Every one of the %d inbound media packet(s) could not be"
            " decrypted, so the camera DID send and this is a key problem on"
            " our side, not silence on its side." % media_pkts
        )
    _how = " - caller cancelled the wait" if cancelled else ""
    return (
        "camera %s: SDES first media never arrived (%.0fs%s)."
        " nominated=%s;%s use-candidate=%s; binding-success=%d; trigger=%s;"
        " inbound-media=%d; decrypt-failed=%d; probes=%s.%s"
        % (
            device_id,
            waited_s,
            _how,
            _cands or "none",
            _answer,
            "sent" if use_candidate_sent else "not-sent",
            binding_success,
            _trigger,
            media_pkts,
            decrypt_fails,
            _probes or "none",
            _why,
        )
    )


def _ensure_srtp_rx_session(holder, key, build, *, on_built=None, on_error=None):
    """Return the bridge's SRTP receive session, rebuilt when ``key`` changes.

    For every model in ``_PLAIN_RTP_MODELS`` -- which is every SDES camera this
    library supports -- the bridge is the only decryptor: the ffmpeg SDP is
    RTP/AVP with no ``a=crypto``, so a receive session holding the wrong key
    means no media at all, not a degraded stream.  The camera can hand us a
    different key partway through the open (the second webrtcResp on
    echo-reversal cameras), so "built once" is not good enough; the session has
    to follow the key it was built from.

    ``build(key)`` constructs the session; the caller keeps ``pylibsrtp`` out of
    this module so a base install without the ``webrtc`` extra still imports.
    Nothing is stored unless ``build`` returns, so a construction error is
    retried on the next packet rather than latched off for the stream.  A
    missing SRTP module is the exception: an ``ImportError`` cannot start
    succeeding later in the process, and this runs per packet, so it is
    remembered and not retried.

    ``on_built`` is called with True for the first successful build and False
    for a rebuild; ``on_error`` receives the exception ``build`` raised.
    """
    if not key or getattr(holder, "_srtp_rx_unavailable", False):
        return None
    sess = getattr(holder, "_srtp_rx_sess", None)
    if sess is not None and getattr(holder, "_srtp_rx_key", None) == key:
        return sess
    try:
        new_sess = build(key)
    except Exception as exc:
        # Drop the old session too: it was built from a different key, so
        # everything it "decrypts" from here on is noise.
        holder._srtp_rx_sess = None
        holder._srtp_rx_key = None
        if isinstance(exc, ImportError):
            holder._srtp_rx_unavailable = True
        if on_error is not None:
            on_error(exc)
        return None
    first = not getattr(holder, "_srtp_rx_built_once", False)
    holder._srtp_rx_sess = new_sess
    holder._srtp_rx_key = key
    holder._srtp_rx_built_once = True
    if on_built is not None:
        on_built(first)
    return new_sess


class _SdesOpenMixin:
    async def _open_sdes_stream(self, **kwargs) -> "SdesSession":
        """Allocate-and-hand-off wrapper around _open_sdes_stream_impl.

        The impl reserves two UDP sockets, starts a bridge thread, launches
        ffmpeg and writes a temp SDP, then hands them to the returned
        SdesSession (whose stop() releases them).  If the cold open is cancelled
        mid-handshake (25-70s) - or raises before that hand-off - none of that
        has an owner yet, so a plain call leaks the fds, the thread and a /tmp
        file on every cancelled attempt (eventually "Too many open files").
        The impl registers each resource on an ExitStack as it is allocated;
        close the stack unless the impl actually returned a session.
        """
        from contextlib import ExitStack

        _cleanup = ExitStack()
        _ok = False
        try:
            _session = await self._open_sdes_stream_impl(_cleanup=_cleanup, **kwargs)
            _ok = True
            return _session
        finally:
            if not _ok:
                # Closing the reservation sockets also unblocks the bridge
                # thread's recv so it exits; ffmpeg is killed and the SDP file
                # unlinked.  LIFO, and every callback swallows so this never
                # masks the original CancelledError/exception.
                _cleanup.close()

    async def _open_sdes_stream_impl(
        self,
        *,
        _cleanup=None,
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
        # Required, not defaulted: the bridge's per-packet sites call it
        # unguarded, so a None default would surface a caller that forgot as
        # an AttributeError inside the bridge thread rather than a TypeError
        # at the call.  Keyword-only, so ordering after a default is legal.
        _trace,
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
        talk: bool = False,
        ice_cands_seen=None,
        # So the SDES answer-wait can abandon at once when the camera says
        # -50002/-50015 instead of waiting out its budget and then paying for a
        # DTLS-fallback offer that cannot succeed.
        terminal_error_fut=None,
    ) -> "SdesSession":
        """SDES-SRTP streaming path using a hand-crafted SDP offer and ffmpeg.

        SDES cameras negotiate SRTP keys inline in the SDP (``a=crypto:`` lines)
        rather than via a DTLS handshake.  aiortc does not support SDES-SRTP, so
        this path sends a manually constructed SDP offer, waits for the camera's
        SDP answer, writes it to a temp file, and launches ffmpeg to receive and
        record the SRTP stream.
        """
        # When this open began.  The answer-ready marker lives on the camera
        # object, not the open, so a marker older than this belongs to a
        # previous open and must not fire this one's early exit.
        _open_started_at = time.monotonic()
        from .client import CameraMixin, _build_sdes_serve_cmd, _ffmpeg_path, _resolve_serve_input_timeout_s, _spawn_bg  # lazy: break client<->sdes_open cycle
        import base64
        import subprocess

        # Stop the MQTT signaling thread on ANY abnormal exit from this impl.
        # The explicit `outgoing_q.put_nowait(None)` calls further down cover the
        # paths that existed when they were written, but an exception raised
        # before one of them is reached (AidotCameraBusy on a terminal ack, or a
        # CancelledError mid-handshake) skipped the sentinel entirely and left
        # `_mqtt_session_sync` running in an executor thread for its full 3600s.
        # Those orphans all reconnect with the same stable account clientId, so
        # they take the session away from later opens and signaling for other
        # cameras on the account stops being delivered until HA restarts.
        # The wrapper only closes this stack when the impl did NOT return a
        # session, so a live session is unaffected.  A duplicate sentinel on the
        # paths that already send one is harmless - the reader exits on the first.
        if outgoing_q is not None:
            def _stop_mqtt_thread() -> None:
                try:
                    outgoing_q.put_nowait(None)
                except Exception:
                    _LOGGER.debug("camera %s: could not signal MQTT thread to exit",
                                  getattr(self, "device_id", "?"), exc_info=True)
            _cleanup.callback(_stop_mqtt_thread)

        # SDES path: fast_connect's wait-skips / TURN-strip destabilise the SCTP
        # handshake (session churns ~every 60-90s -> live view drops to snapshot),
        # so the SDES path always uses the full, stable handshake.
        _fast_connect = False

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
        # Substring-matched, NOT equality: a revision suffix ("LK.IPC.A001513-1",
        # the way A000088-1 exists on the DTLS side) is the same firmware and needs
        # the same framing.  An exact match silently read such a camera as a plain
        # SRTP model, so ffmpeg tried to decrypt TUTK frames with the announced
        # fake key and the bridge never stripped the TUTK header - a session that
        # negotiates and delivers nothing decodable.
        _model_id = getattr(getattr(self, "info", None), "model_id", None) or ""
        _use_plain_rtp = any(m in _model_id for m in self._PLAIN_RTP_MODELS)
        # powerType/p2pCache - IpcServiceImpl.java:B() returns 2 for battery
        # models; 1 for wired.  Derived from is_battery_camera (see live_power_type)
        # so the wire value and the battery guards cannot drift apart.  All tested
        # cameras report p2pCache=2 in their setDevAttrNotif device attributes.
        # App parity: LivePlayPaylodBean declares these as INT, not String - send
        # ints so a strict camera JSON parser accepts the livePlayReq (battery cams
        # appear stricter; a rejected livePlayReq leaves the cam un-armed).
        _live_power_type = self.live_power_type
        _live_p2p_cache = 2

        webrtc_req_topic = f"iot/v1/s/{user_id}/IPC/webrtcReq"

        def _seq() -> str:
            return f"ap{random.randint(1000000, 9999999)}"

        # Register a resource with the wrapper's cleanup stack so it is released
        # if the cold open is cancelled/raises before the SdesSession takes
        # ownership.  Each step swallows so ExitStack.close() can never mask the
        # original CancelledError/exception.  No-op if called without a stack.
        def _cl(fn, *a):
            if _cleanup is None:
                return
            def _run():
                try:
                    fn(*a)
                except Exception:
                    _LOGGER.debug(
                        "camera %s: swallowed sdes-open cleanup step",
                        getattr(self, "device_id", "?"), exc_info=True,
                    )
            _cleanup.callback(_run)

        def _reap(p):
            # This is a locally-initiated kill (cold open cancelled/raised
            # before hand-off) - flag it so the bridge observe loop treats the
            # resulting signal death as expected, not a WARNING-worthy crash.
            # Set first (before the kill/reap below), matching the other
            # kill sites, so the bridge thread can never observe the exit
            # code with the flag still False.
            try:
                _teardown_holder[0] = True
            except Exception:
                pass
            try:
                p.kill()
            except Exception:
                pass
            try:
                p.poll()   # reap the killed child so it does not linger as a zombie
            except Exception:
                pass

        # --- Allocate UDP ports and determine local IP ---------------------- #
        import socket as _socket

        _audio_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        _widen_media_rcvbuf(_audio_sock, "audio", getattr(self, "device_id", "?"))
        _audio_sock.bind(("0.0.0.0", 0))
        audio_port = _audio_sock.getsockname()[1]
        _cl(_audio_sock.close)   # also unblocks the bridge thread's recv on cleanup

        _video_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        _widen_media_rcvbuf(_video_sock, "video", getattr(self, "device_id", "?"))
        _video_sock.bind(("0.0.0.0", 0))
        video_port = _video_sock.getsockname()[1]
        _cl(_video_sock.close)

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
            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_open_sdes_stream', exc_info=True)

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
            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_open_sdes_stream', exc_info=True)

        # --- TURN relay allocation helper ------------------------------------ #
        # Defined BEFORE the offer so relay IP/port can be embedded in the
        # offer's c= and m= lines.  Pure-SDES cameras (no ICE) read the OFFER's
        # c= address and stream SRTP there directly - if we put the relay address
        # in the offer, the camera's SRTP reaches us through port-restricted NAT.
        # sock -> (relay_ip, relay_port, realm, nonce, t_host, t_port, key, user).
        # All eight fields are required: CreatePermission has to re-authenticate
        # with USERNAME/REALM/NONCE and the long-term-credential key, so any path
        # that stores a shorter tuple silently disables the relay permission.
        _relay_addrs: dict = {}

        def _turn_allocate_udp(_ta_sock, _ta_host, _ta_port, _ta_user, _ta_pass):
            """RFC 5766 TURN relay allocation with long-term credential auth.
            Returns (relay_ip, relay_port, realm, nonce) or None on failure."""
            import hashlib as _ha
            import hmac as _hm
            import struct as _st_ta
            import select as _sl_ta
            import time as _tm_ta

            _MAGIC_TA = b'\x21\x12\xa4\x42'

            def _a(_t, _v):
                _p = (-len(_v)) % 4
                return _st_ta.pack('!HH', _t, len(_v)) + _v + b'\x00' * _p

            def _stun_message_integrity(_k, _m):
                # Patch Length to include the MI attribute (4 hdr + 20 digest = 24)
                _patched = _m[:2] + _st_ta.pack('!H', len(_m) - 20 + 24) + _m[4:]
                return _hm.new(_k, _patched, _ha.sha1).digest()

            # Step 1: unauthenticated Allocate -> get REALM and NONCE from 401
            _tid1 = os.urandom(12)
            _b1 = _a(0x0019, b'\x11\x00\x00\x00')  # REQUESTED-TRANSPORT = UDP(17), RFC 5766 section 14.7 protocol in MSB
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
                + _a(0x0019, b'\x11\x00\x00\x00')     # REQUESTED-TRANSPORT = UDP, RFC 5766 section 14.7 protocol in MSB
            )
            _h2 = b'\x00\x03' + _st_ta.pack('!H', len(_b2) + 24) + _MAGIC_TA + _tid2
            _b2 += _a(0x0008, _stun_message_integrity(_key_ta, _h2 + _b2))  # MESSAGE-INTEGRITY
            _r2 = b'\x00\x03' + _st_ta.pack('!H', len(_b2)) + _MAGIC_TA + _tid2 + _b2
            try:
                _ta_sock.sendto(_r2, (_ta_host, _ta_port))
            except Exception:
                return None
            # Same TID-matching loop - if step 1's 401 was still in the buffer,
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
                    _xb = bytes(a ^ b for a, b in zip(_av[4:8], _MAGIC_TA, strict=False))
                    _r_ip_ta = '.'.join(str(b) for b in _xb)
                    # Do NOT pre-create permissions for our own srflx IP or
                    # TURN server IP. That can cause TURN self-loop Data
                    # Indications and massive STUN echo storms.
                    return _r_ip_ta, _xp, _realm_ta, _nonce_ta
            return None

        # --- Early TURN relay allocation (before offer build) --------------- #
        # Allocate relay now so offer c= and m= carry relay IP/port.
        # Camera reads offer's c= to know where to send SRTP - relay address
        # here means SRTP reaches us even through port-restricted / hairpin NAT.
        # AIDOT_FAST_CONNECT skips this blocking pre-allocation (LAN-direct mode):
        # the offer goes out immediately with host/srflx candidates and the LAN
        # path connects without waiting on a cloud TURN Allocate round-trip.
        # AIDOT_SDES_SKIP_TURN_PREALLOC (experimental, opt-in) does the same skip
        # for SDES specifically, where _fast_connect is force-off (see
        # _resolve_sdes_skip_turn).  Either way the cost is instrumented below so
        # the saving is measurable: grep ``signaling-wait[`` for sdes-turn-prealloc.
        _skip_turn_prealloc = self._resolve_sdes_skip_turn()
        # Which media path to offer (auto | lan | relay).  Resolved once per
        # open; the candidate blocks below are built from it.  A receipt goes
        # out whenever it is not the default, because a run that cannot show
        # the knob was applied cannot tell a result from a coincidence.
        _conn_mode = self._resolve_sdes_connection_mode()
        if _conn_mode != "auto" and _status:
            _status(f"SDES: connection mode {_conn_mode}")
        _turn_t0 = time.monotonic()
        _turn_did = False
        if _sdes_turn_entries and not _fast_connect and not _skip_turn_prealloc:
            _turn_did = True
            try:
                import re as _re_pre
                import hashlib as _hlk_pre
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
                                _t_host_pre, _t_port_pre, _r_key_pre, _t_user_pre,
                            )
                            _status(
                                f"TURN relay pre-allocated (offer): {_pre_name}"
                                f" -> {_r_ip_pre}:{_r_port_pre}"
                            )
            except Exception as _pre_exc:
                _LOGGER.warning("TURN pre-allocation error: %s", _pre_exc)
        if _skip_turn_prealloc and _sdes_turn_entries:
            _status(
                "AIDOT_SDES_SKIP_TURN_PREALLOC: skipping TURN relay"
                " pre-allocation (~2-3s) - host/srflx candidates only, LAN-direct"
            )
        _LOGGER.info(
            "signaling-wait[%s] sdes-turn-prealloc elapsed=%dms allocated=%d skipped=%s",
            self.device_id,
            int((time.monotonic() - _turn_t0) * 1000),
            len(_relay_addrs), bool(_skip_turn_prealloc))

        # --- DTLS certificate for m=application probe ----------------------- #
        # PreCon cameras (sptPreconn=1) need SESSION_MODE_REQ via SCTP datachannel.
        # Include m=application in offer so camera answers with its own DataChannel
        # section.  Use cryptography (already a dependency) - no aiortc needed.
        _dc_probe_fp = ""
        try:
            from cryptography import x509 as _cx509
            from cryptography.x509.oid import NameOID as _CNOID
            from cryptography.hazmat.primitives import hashes as _ch, serialization as _cser
            from cryptography.hazmat.primitives.asymmetric import ec as _cec
            from cryptography.hazmat.backends import default_backend as _cbd
            import datetime as _dt_dc
            import hashlib as _hs_dc
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
        # Use a CSPRNG: the PSK is media-keying material carried over signaling,
        # so it must not come from the predictable Mersenne-Twister (random).
        import secrets as _secrets_psk_early
        _psk_charset_req = "123456789abcdef"
        _psk_value_req = "".join(
            _secrets_psk_early.choice(_psk_charset_req)
            for _ in range(64)
        )

        # --- Build SDES SDP offer ------------------------------------------ #
        # AES_CM_128_HMAC_SHA1_80: 16-byte key + 14-byte salt = 30 bytes.
        srtp_key_audio = base64.b64encode(os.urandom(30)).decode()
        srtp_key_video = base64.b64encode(os.urandom(30)).decode()
        # DEBUG is not low enough for real key material.  This used to log the
        # decoded master key AND salt in full hex - the whole secret, not a
        # prefix - on the reasoning that DEBUG is not "production-level".  But
        # Home Assistant users turn this integration's logger to debug precisely
        # when something is wrong, and then paste the log into a public issue.
        _LOGGER.debug(
            "sdes: offer key=%s psk=%s",
            _key_fingerprint(srtp_key_audio),
            _psk_value_req,
        )
        ts = int(time.time())
        # SDES-SRTP cameras use SIP-era plain SDP (RFC 3264 + RFC 3711).
        # Use RTP/SAVPF (RFC 4585) - Leedarson firmware expects the feedback
        # profile and silently ignores offers with plain RTP/SAVP.
        # Include ICE credentials and a host candidate so that newer PTZ
        # firmware (e.g. LK.IPC.A001064) that requires ICE for address
        # discovery will respond.  Older cameras that don't understand ICE
        # ignore those attributes and use the port in the m= line directly.
        # ONE pair for the whole offer, not one per m-section - see
        # _new_ice_credentials for why, and note _compress_sdp_req below keeps
        # only the first of each attribute anyway.
        import secrets as _secrets
        # One pair for the whole offer - see _new_ice_credentials. The video
        # names are kept as aliases rather than removed: they are threaded
        # through the STUN responder, the nomination and the bridge, and
        # collapsing 23 call sites would obscure a change whose whole point is
        # that the two values are now equal.
        _ufrag_a, _pwd_a = _new_ice_credentials()
        _ufrag_v = _ufrag_a
        _pwd_v = _pwd_a
        # Use srflx (public) IP and direct port in c= and m= for the offer too,
        # for consistency with the answer.  TURN relay requires CreatePermission
        # for the camera's public IP which is unknown; relay in c= causes TURN to
        # drop every camera packet.  Relay is still in a=candidate: for ICE.
        # For LAN cameras (_public_ip is None) fall back to local_ip directly.
        _offer_audio_ip, _offer_audio_port, _relay_in_c_a = _sdes_offer_media_endpoint(
            _conn_mode, _public_ip or local_ip, audio_port,
            _relay_addrs.get(_audio_sock), _public_ip)
        _offer_video_ip, _offer_video_port, _relay_in_c_v = _sdes_offer_media_endpoint(
            _conn_mode, _public_ip or local_ip, video_port,
            _relay_addrs.get(_video_sock), _public_ip)
        _relay_in_c = _relay_in_c_a or _relay_in_c_v
        if _conn_mode == "relay" and not _relay_in_c and _status:
            _status("SDES: relay mode fell back to the direct endpoint"
                    " (no allocation or no public ip)")
        elif _relay_in_c and _status:
            _status("SDES: c=/m= at the relay allocation (relay mode)")
        _bundle_hdr_line = (
            "a=group:BUNDLE 0 1 2\r\n" if _dc_probe_fp else "a=group:BUNDLE 0 1\r\n"
        )
        # Outbound talk: a talk-intended open advertises audio as sendrecv WITH an
        # a=ssrc so the camera builds a receive path for our PCMA (cname required -
        # _compress_sdp_req keeps a=ssrc lines only when "cname" is present).  Pure
        # streaming opens keep audio recvonly (the validated 72s/49s path, untouched).
        _talk_offer = talk
        _offer_audio_ssrc = int.from_bytes(os.urandom(4), "big") or 1
        _offer_audio_cname = _secrets.token_urlsafe(12)[:12]
        _audio_dir_line  = "a=sendrecv\r\n" if _talk_offer else "a=recvonly\r\n"
        _audio_ssrc_line = (
            f"a=ssrc:{_offer_audio_ssrc} cname:{_offer_audio_cname}\r\n"
            if _talk_offer else ""
        )
        # Shared talk state (only for talk-capable opens).  The bridge fills
        # src/sock on first inbound audio; SdesSession.async_start_talk sets
        # provider + sends SPEAKERSTART(848); the talk pump thread reads this to
        # emit outbound PCMA as SRTP at our offer SSRC.  srtp_key_audio here is
        # our offer key (captured before it is reassigned to the camera key after
        # the answer); the immutable str is safe to hold.
        _talk_state = {
            "provider": None,       # set by async_start_talk; cleared on stop/clip-end
            "src": None,            # camera media addr (bridge sets on first media)
            "sock": None,           # media socket (bridge)
            "ssrc": _offer_audio_ssrc,
            "key": srtp_key_audio,  # our offer key (immutable str; safe to hold)
            "want_speaker": False,    # async_start/stop_talk flips this
            "speaker_on": False,      # bridge sets after it sends SPEAKERSTART
            "spk_eligible_ts": None,  # bridge: first time SPEAKERSTART is eligible
            "stop": False,
        } if _talk_offer else None
        # Video codec preference, expressed by m-line order (RFC 3264 5.1).
        # Default is today's 96 97 and the bytes are identical to the literal
        # this replaced; AIDOT_SDES_VIDEO_PT_ORDER reorders it without ever
        # narrowing it.
        _video_pt_order = _resolve_sdes_video_pt_order()
        # Read ONCE and feed both the SDP line and the status receipt below:
        # two independent env reads let the receipt name a value that never
        # reached the wire, which is the false-receipt trap the receipt
        # exists to close.
        _bw_kbps = _sdes_offer_bandwidth_kbps()
        _video_pt_list, _video_codec_attrs = _sdes_offer_video_codec_lines(
            _video_pt_order)
        sdes_offer_sdp = (
            "v=0\r\n"
            f"o=- {ts} {ts} IN IP4 {local_ip}\r\n"
            "s=-\r\n"
            f"t=0 0\r\n{_bundle_hdr_line}"
            # audio m-section
            # a=crypto MUST precede ICE attributes (RFC 4568 section 9.1) so that
            # linear-parsing camera firmware recognises this as an SDES offer
            # rather than a pure-ICE offer and does not discard the key.
            f"m=audio {_offer_audio_port} RTP/SAVPF 0 8\r\n"
            f"c=IN IP4 {_offer_audio_ip}\r\n"
            + _audio_dir_line
            + "a=mid:0\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            # a=rtcp-mux: multiplexes RTCP onto the RTP port so the camera does
            # not send RTCP to audio_port+1 (which is never bound), and so that
            # ffmpeg does not try to open a separate RTCP socket.
            "a=rtcp-mux\r\n"
            + _audio_ssrc_line
            # PSK is sent in wPayload only - real app does NOT inject a=psk: into
            # the SDP body (confirmed from logcat ground truth 2026-05-22).
            + f"a=ice-ufrag:{_ufrag_a}\r\n"
            f"a=ice-pwd:{_pwd_a}\r\n"
            + _sdes_offer_candidate_lines(
                _conn_mode, local_ip, audio_port, _public_ip,
                _relay_addrs.get(_audio_sock))
            # video m-section
            + f"m=video {_offer_video_port} RTP/SAVPF {_video_pt_list}\r\n"
            f"c=IN IP4 {_offer_video_ip}\r\n"
            + _offer_bandwidth_line(_bw_kbps)
            + "a=recvonly\r\n"
            "a=mid:1\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
            + _video_codec_attrs
            + "a=rtcp-mux\r\n"
            f"a=ice-ufrag:{_ufrag_v}\r\n"
            f"a=ice-pwd:{_pwd_v}\r\n"
            + _sdes_offer_candidate_lines(
                _conn_mode, local_ip, video_port, _public_ip,
                _relay_addrs.get(_video_sock))
            # m=application SCTP DataChannel section for SDES cameras.
            # Ground truth from real Leedarson app logcat (2026-05-22):
            #   m=application 9 SCTP webrtc-datachannel
            #   a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key}
            # That is ALL - no a=setup, no a=sctp-port, no fingerprint.
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

        # Receipt for the codec order above, emitted only when it differs from
        # the shipped one.  A run that cannot show the knob was applied cannot
        # tell a result from a coincidence: an earlier attempt on this question
        # read as a confirmed effect for two sessions before the missing receipt
        # showed the pin had never reached the SDP at all.  Ordering happens
        # before the pin below, so with both set the pin wins and the order is
        # moot - which is why both lines print rather than one.
        if _video_pt_order != _SDES_OFFER_VIDEO_PT_ORDER and _status:
            _status(f"SDES: offer video codec order={_video_pt_list}")

        # Same receipt, same reason, for the receive-bandwidth ceiling: the log
        # carries the camera's ANSWER, not our offer, so "the env var was set"
        # is not evidence the line reached the wire.  Measured 2026-08-23: a
        # b=AS arm scored identically to its control and the only available
        # check for the knob was reading the env back out of the harness.
        if _bw_kbps and _status:
            _status(f"SDES: offer receive-bandwidth ceiling b=AS:{_bw_kbps}")

        # Opt-in: NARROW the OFFER to one video codec rather than advertising
        # both 96/97 and letting the camera decide in its answer.  Distinct from
        # the ordering above, which only states which of the two we would
        # rather have and always leaves both on the wire; this one takes the
        # other away, which for 97 took the video with it.
        #
        # The offer is the SDP that matters here.  Traced live 2026-08-07 with
        # every status line printed: this path sends webrtcReq carrying OUR
        # offer and then reports "Using camera's video SRTP key from answer" -
        # the camera answers, we do not.  The answer builder further down runs
        # only on the branch where the camera offers first, which this camera
        # did not take, so pinning there changed nothing at all while the
        # arms still came out looking like the pin had worked.  Inert unless set.
        _pin_video_pt = _resolve_sdes_video_pt()
        if _pin_video_pt is not None:
            sdes_offer_sdp = narrow_sdp_payload_types(
                sdes_offer_sdp, keep_video=_pin_video_pt)
            if _status:
                _status(f"SDES: offer pinned to video pt={_pin_video_pt}")

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
                "dseq": self._next_dseq(),
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
        # SDES fast-liveplay (sdes_fast_liveplay, DEFAULT ON since 0.7.32 - the
        # official app fire-and-forgets too): instrumentation showed the echo and
        # livePlayResp waits BOTH always time out for the SDES cameras measured
        # (echo/resp never arrive) yet streaming succeeds - i.e. ~6 s of dead
        # padding.  When on (the default), cap the echo wait short and skip the
        # livePlayResp wait; the full ICE/TURN/SCTP handshake is untouched.  This
        # is the SDES path's OWN livePlay waits (the DTLS gate above never runs for
        # SDES: use_sdes is True there).  VALIDATED in a 3 h live soak (15 SDES
        # opens across battery cameras, 0 churn / 0 fail, ~4.5 s signaling saved)
        # and shipped default-on across 0.8/0.9.x.  Role-reversal models
        # (_NO_FAST_LIVEPLAY_MODELS, e.g. A001064) are always excluded; disable
        # elsewhere via AIDOT_SDES_FAST_LIVEPLAY={0,false,no,off}.
        _skip_lp = self._resolve_sdes_fast_liveplay()
        _echo_timeout = _sdes_liveplay_echo_timeout(_skip_lp)
        _echo_t0 = time.monotonic()
        try:
            await _asyncio.wait_for(liveplay_echo_ev.wait(), timeout=_echo_timeout)
            _status("livePlayReq echo received - sending webrtcReq, ICE, then launching ffmpeg")
        except TimeoutError:
            _status(f"no livePlayReq echo in {_echo_timeout:.1f}s - sending webrtcReq,"
                    " ICE, then launching ffmpeg anyway")
        _LOGGER.info(
            "signaling-wait[%s] livePlayReq-echo elapsed=%dms (timeout=%.1fs)",
            self.device_id, int((time.monotonic() - _echo_t0) * 1000), _echo_timeout)
        # App parity: do not offer to a battery camera until the camera itself
        # has said something.  See _battery_wake_gate_s.  Mains cameras skip
        # this entirely, so the PTZ's role-reversal timing is untouched.
        _wake_gate_s = _battery_wake_gate_s(
            bool(getattr(self, "is_battery_camera", False)),
            _BATTERY_WAKE_GATE_S)
        if _wake_gate_s > 0:
            _wg_t0 = time.monotonic()
            while (getattr(self, "_camera_device_seen_ts", None) is None
                    and time.monotonic() - _wg_t0 < _wake_gate_s):
                await _asyncio.sleep(0.05)
            _wg_seen = getattr(self, "_camera_device_seen_ts", None) is not None
            _LOGGER.info(
                "signaling-wait[%s] battery-wake-gate elapsed=%dms answered=%s"
                " (budget=%.0fs)",
                self.device_id, int((time.monotonic() - _wg_t0) * 1000),
                _wg_seen, _wake_gate_s)
            if _wg_seen:
                _status("camera answered after %.1fs - offering now"
                        % (time.monotonic() - _wg_t0))
            else:
                _status("camera said nothing in %.0fs - offering anyway"
                        % _wake_gate_s)

        # livePlayResp: explicit camera accept/reject before SDP/ICE.
        if _skip_lp:
            _LOGGER.info(
                "signaling-wait[%s] livePlayResp skipped (sdes_fast_liveplay)",
                self.device_id)
        else:
            _lp_t0 = time.monotonic()
            _lp_arrived = False
            try:
                _lp_resp_sdes = await _asyncio.wait_for(
                    _asyncio.shield(liveplay_resp_fut), timeout=1.0
                )
                _lp_arrived = True
                _lp_code_sdes = int(_lp_resp_sdes.get("code", 200))
                _lp_on_sdes = int(_lp_resp_sdes.get("livePlay", 1))
                # Only an explicit livePlay=0 is an unambiguous refusal (fast-fail).
                # Numeric codes (e.g. -50019 "not ready" on a waking battery cam)
                # are transient - the camera recovers and streams - so log and
                # proceed rather than abort on a code we can't classify as terminal
                # (genuine terminal rejects are still caught on the webrtcResp ack).
                if _lp_on_sdes == 0:
                    # Match the sibling raises: close the reserved sockets and
                    # signal the MQTT thread before propagating.  (No sdp_path
                    # unlink here - it is not created until later, below.)
                    for _rsock in (_audio_sock, _video_sock):
                        try:
                            _rsock.close()
                        except Exception:
                            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                    outgoing_q.put_nowait(None)   # stop MQTT thread
                    raise RuntimeError(
                        f"livePlay refused by camera (livePlay=0, code={_lp_code_sdes})")
                elif _lp_code_sdes not in (0, 200):
                    _status(f"livePlayResp: non-OK code {_lp_code_sdes}"
                            f"{' (not ready, transient)' if _lp_code_sdes == _LIVE_PLAY_NOT_READY else ''}"
                            " - proceeding")
            except TimeoutError:
                pass
            _LOGGER.info(
                "signaling-wait[%s] livePlayResp elapsed=%dms arrived=%s",
                self.device_id, int((time.monotonic() - _lp_t0) * 1000), _lp_arrived)

        # --- Build local-receiver SDP for ffmpeg ----------------------------- #
        # Built BEFORE sending webrtcReq so ffmpeg is already listening on the
        # reserved ports when the camera starts streaming.  Launching ffmpeg
        # after webrtcReq means the first seconds of SRTP data land in the
        # Python reservation sockets (or trigger ICMP port-unreachable after
        # they are closed), causing 0-frame output.
        # ffmpeg_sdp uses only audio_port/video_port and srtp_key_* - all known
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

        sdp_path = await asyncio.get_running_loop().run_in_executor(
            # _inject_sprop reads the sprop cache from disk; keep it inside the
            # executor (not as an eagerly-evaluated arg) so the blocking open()
            # does not run on the event loop.
            None, lambda: _make_sdp_tempfile(_inject_sprop(ffmpeg_sdp, self.device_id)))
        _cl(os.unlink, sdp_path)   # released with the sockets on a cancelled open

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
        # Advertise an ICE server to the camera only when we actually have a
        # URI for it.  With AIDOT_STUN_SERVERS="" this used to put
        # {"Uris": []} into webrtcReq - an entry the camera must parse and
        # that names no server.
        _sdes_stun_uris = stun_server_uris()
        _sdes_ice_server_list = [{"Uris": _sdes_stun_uris}] if _sdes_stun_uris else []
        _sdes_ice_server_list.extend(_sdes_turn_entries)
        # _psk_value_req was generated before the SDP offer (see above).
        # Reused here in webrtcReq and webrtcResp for consistency.
        def _compress_sdp_req(_sdp: str) -> str:
            """g.b() equivalent - selective SDP filter for wPayload."""
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
                                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_k', exc_info=True)
                        elif "H265/90000" in _ln and _seen.get("H265/90000") is None:
                            _k(_ln, "H265/90000")
                            try:
                                _seen["H265/90000_pt"] = _ln.split(":")[1].split(" ")[0]
                            except Exception:
                                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_k', exc_info=True)
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
                # Legacy flat fields - older firmware parses payload.peerid directly.
                "peerid":  peer_id,
                "devId":   device_id,
                "offer":   {"type": "offer", "sdp": sdes_offer_sdp},
                "trackId": 0,
                # Decompiled reference app (tyrus/o.java) sets dstAddr=deviceId
                # for webrtcReq.
                "dstAddr": device_id,
                "encOffer": 1,
                "liveMqtt": 1,
                # powerType / p2pCache ride on the webrtcReq payload, alongside
                # encOffer and liveMqtt - the same object the reference client
                # puts them on (LDSMQTTClient.sendSdpOffer, smali :2967-2969,
                # put at :3017/:3022).  They are STRINGS on the wire there: the
                # app stringifies the ints it reads from the IPC device info,
                # and its no-device-info fallback puts the literals "1" / "0".
                # The DTLS webrtcReq has carried both for a long time
                # (webrtc_open.py, per docs/official_camera_network_calls.md
                # section 5.2) and sends them as ints; that path is fleet-proven,
                # so it is deliberately left alone rather than churned to match.
                "powerType": str(_live_power_type),
                "p2pCache": str(_live_p2p_cache),
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
        self._cold_phase("webrtcReq (sdes)")
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
        # Only role-reversal models (A001064, _skip_lp False) echo our webrtcReq
        # and need the webrtcResp built below; for A001513-class (_skip_lp True,
        # default) the echo never arrives, so don't block ~2s on it.
        _echo_wait_s = _sdes_echo_wait_timeout(
            _skip_lp, echo_seen=bool(getattr(self, "_sdes_echo_seen", False)))
        _echo_wait_t0 = time.monotonic()
        try:
            await _asyncio.wait_for(
                _asyncio.shield(_echo_fut),
                timeout=_echo_wait_s,
            )
            _cam_echo_received = True
            self._sdes_echo_seen = True
            _status("camera webrtcReq echo received - building webrtcResp")
            # Seed _sdes_turn_entries from the echo's IceServerList if the HTTP
            # ice_config fetch returned nothing (empty list).  The echo carries
            # our userId TURN credentials - extract them so the hole-punch and
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
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_k', exc_info=True)
            # Allocate TURN relay if not already done before offer build.
            # When ice_config provided TURN entries, pre-allocation already ran
            # and _relay_addrs is populated - skip to avoid double-allocation.
            if not _relay_addrs:
                try:
                    import re as _re_relay_e
                    import hashlib as _hlk_e
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
                                        _t_host_e, _t_port_e, _r_key_e, _t_user_e,
                                    )
                                    _status(
                                        f"TURN relay allocated (echo fallback): "
                                        f"{'audio' if _alloc_sock_e is _audio_sock else 'video'}"
                                        f" -> {_r_ip_e}:{_r_port_e}"
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
                + _sdes_offer_candidate_lines(
                    _conn_mode, local_ip, audio_port, _public_ip,
                    _relay_addrs.get(_audio_sock))
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
                + _sdes_offer_candidate_lines(
                    _conn_mode, local_ip, video_port, _public_ip,
                    _relay_addrs.get(_video_sock))
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
        except TimeoutError:
            # No echo - camera uses a different signalling variant; proceed.
            # Logged rather than swallowed: `except TimeoutError: pass` is how
            # 2.0 s of dead time here stayed invisible, and the elapsed line is
            # what will show it if this wait ever starts being used.
            _LOGGER.info(
                "signaling-wait[%s] webrtcReq-echo elapsed=%dms"
                " (timeout=%.2fs)",
                getattr(self, "device_id", "?"),
                int((time.monotonic() - _echo_wait_t0) * 1000),
                _echo_wait_s,
            )

        # --- Announce our ICE candidates via MQTT (iceCandidateReq) ----------- #
        # The iOS app always sends iceCandidateReq after webrtcReq/webrtcResp.
        # ICE-capable cameras (e.g. LK.IPC.A001064) wait for this trickle-ICE
        # message before initiating STUN connectivity checks, even when the same
        # candidates are already present in the SDP a=candidate lines.  Without
        # this step the camera sits idle and never sends STUN - resulting in 0
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
        # Skipped in AIDOT_FAST_CONNECT (LAN-direct): no relay alloc, host/srflx
        # candidates only (the synchronous allocate would block the post-offer
        # candidate trickle on a cloud round-trip).
        if not _relay_addrs and not _fast_connect:
            try:
                import re as _re_relay
                import hashlib as _hlk
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
                                    _t_host_r, _t_port_r, _r_key, _t_user_r,
                                )
                                _status(
                                    f"TURN relay allocated: "
                                    f"{'audio' if _alloc_sock is _audio_sock else 'video'}"
                                    f" -> {_r_ip}:{_r_port}"
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
            # srflx candidate (public IP) - announced separately so the camera
            # triggers a new ICE check to our public address even if it already
            # processed the SDP host candidate.
            if _public_ip:
                _send_sdes_ice_cand(
                    f"candidate:2 1 udp 1694498815 {_public_ip} {_ice_port}"
                    f" typ srflx raddr {local_ip} rport {_ice_port}",
                    _ice_mid,
                )
            # relay candidate - advertised so the camera can probe us via TURN
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
        _hp_host = None
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
            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_open_sdes_stream', exc_info=True)
        # When the cloud supplied no TURN entry, fall back to the vendor's TURN
        # server only to open a NAT mapping.  This sends a STUN packet to a
        # hardcoded third-party host; AIDOT_SDES_HOLEPUNCH_HOST overrides it
        # (set it empty to disable the hardcoded fallback entirely).
        if not _hp_host:
            _hp_env = os.environ.get("AIDOT_SDES_HOLEPUNCH_HOST")
            if _hp_env is not None:
                _hp_host = _hp_env.strip() or None
            else:
                _hp_host = "3.230.182.123"   # fallback: Arnoo TURN server
                _LOGGER.warning(
                    "camera %s: no TURN entry from cloud; NAT hole-punch will send "
                    "a STUN packet to the hardcoded vendor host %s. Set "
                    "AIDOT_SDES_HOLEPUNCH_HOST to override (empty to disable).",
                    getattr(self, "device_id", "?"), _hp_host,
                )
        _hp_stun = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + os.urandom(12)
        _hp_port2 = 5349
        if not _hp_host:
            _status("NAT hole-punch: skipped (no TURN host)")
        else:
            for _hp_sock in (_audio_sock, _video_sock):
                try:
                    _hp_sock.sendto(_hp_stun, (_hp_host, _hp_port))
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_send_sdes_ice_cand', exc_info=True)
            # Punch to TURN allocation port (5349) as well so port-restricted NAT
            # allows traffic from either TURN port (3478 STUN or 5349 allocation).
            if _hp_port != _hp_port2:
                for _hp_sock in (_audio_sock, _video_sock):
                    try:
                        _hp_sock.sendto(_hp_stun, (_hp_host, _hp_port2))
                    except Exception:
                        _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_send_sdes_ice_cand', exc_info=True)
            _status(
                f"NAT hole-punch: sent from audio={audio_port}"
                f" video={video_port} -> {_hp_host}:{_hp_port}"
                + (f" and :{_hp_port2}" if _hp_port != _hp_port2 else "")
            )

        # The ports our own srflx candidates advertise - the only ports on the
        # public IP that are actually this host. Anything else there is another
        # device behind the same NAT, which for this fleet means the camera.
        _own_srflx_ports = (audio_port, video_port)

        def _is_self_peer_ip(_ip: "Optional[str]", _port: "Optional[int]" = None
                             ) -> bool:
            return _is_self_transport_address(
                _ip, _port,
                local_ip=local_ip, public_ip=_public_ip,
                own_ports=_own_srflx_ports,
            )

        _selfloop_drop_count = 0
        _bridge_selfloop_drop_count = 0
        _prefer_direct_stun = {_audio_sock: False, _video_sock: False}

        # --- ICE STUN responder (runs while reservation sockets are still open) #
        # Two-phase window:
        #   Normal (no echo-reversal): exit after 0.5 s idle, max 2.5 s total.
        #   Echo-reversal, SDES confirmed (webrtcResp sent): up to 20 s for ICE.
        #   Echo-reversal, dtls_fallback_ok (webrtcResp suppressed): 5 s max -
        #     camera won't stream without webrtcResp so no STUN/SRTP will arrive;
        #     exit quickly so the DTLS fallback starts sooner.
        #   SRTP early exit: if a non-STUN packet arrives (SRTP), ICE is done -
        #     close sockets immediately so ffmpeg can bind.
        import struct as _struct
        import select as _select
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
            _stun_max = 20.0   # webrtcResp sent - camera may do ICE; give it time
        else:
            _stun_max = 5.0    # webrtcResp suppressed - no STUN expected; exit fast
        _idle_limit = 1.5      # exit after ICE silence once first STUN seen
        _pre_stun_idle = 0.5   # exit early if no packet at all (non-ICE camera)
        _stun_deadline = time.monotonic() + _stun_max
        _last_pkt_t = time.monotonic()
        _stun_window_t0 = time.monotonic()
        for _rsock in (_audio_sock, _video_sock):
            try:
                _rsock.setblocking(False)
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_is_self_peer_ip', exc_info=True)
        while time.monotonic() < _stun_deadline:
            # Answer-exit: the only reason to sit here is that the credentials
            # the nomination needs have not arrived yet.  Once they have - and
            # the camera has proved it is running ICE by probing us - waiting
            # longer just delays USE-CANDIDATE, and the bridge thread below
            # picks the responder role straight back up.  Checked before the
            # idle test because the answer usually lands while the camera is
            # still probing hard, so no idle threshold would ever be crossed.
            if _stun_window_answer_exit_due(
                    stun_seen=_stun_seen,
                    answer_ready=_answer_ready_for_this_open(
                        getattr(self, "_camera_answer_ice_ready_ts", None),
                        _open_started_at)):
                _status(
                    "STUN window: leaving early after %.2fs - answer ICE"
                    " credentials in hand and camera probing; nominating now"
                    " (%d binding request(s) answered)"
                    % (time.monotonic() - _stun_window_t0, _stun_count)
                )
                break
            # Idle-exit: threshold depends on whether we've seen any STUN yet
            idle = time.monotonic() - _last_pkt_t
            if _stun_seen:
                if idle > _idle_limit:
                    break   # ICE done (silence after STUN) - ffmpeg will pick up SRTP
            elif not _cam_echo_received and idle > _pre_stun_idle:
                break       # no STUN at all - non-ICE camera, skip window
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
                                a ^ b for a, b in zip(_sw_av[4:8], _STUN_MAGIC, strict=False)
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
                    # STUN packet - only Binding Requests (0x0001) indicate that
                    # ICE is active.  Error/Success responses (e.g. hole-punch
                    # replies) must NOT set _stun_seen or they'd trigger the 1.5s
                    # idle-exit prematurely, before camera probes arrive.
                    if _pkt[:2] == b'\x00\x01':
                        # Binding Request - reply with Binding Success Response.
                        # _stun_seen is NOT set here.  A self-loop Data
                        # Indication - our own address echoed back through the
                        # relay - is a Binding Request too, and the branch below
                        # drops it precisely because it is not the camera.
                        # Setting the flag here made one of those count as "the
                        # camera has started ICE", which is the one thing the
                        # answer-exit is gated on.  It is set where a probe is
                        # actually answered instead.
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
                                    and not _is_self_peer_ip(_turn_peer_ip_sw,
                                                             _turn_peer_port_sw)):
                                # Arrived via TURN - respond via Send Indication
                                _ri_sw = _relay_addrs[_sock]
                                _t_host_sw, _t_port_sw = _ri_sw[4], _ri_sw[5]
                                _si_pip = bytes(
                                    int(x) for x in _turn_peer_ip_sw.split('.')
                                )
                                _si_xip = bytes(
                                    a ^ b for a, b in zip(_si_pip, _STUN_MAGIC, strict=False)
                                )
                                _si_xport = (_turn_peer_port_sw ^ 0x2112) & 0xFFFF
                                _si_xpa = (b'\x00\x01'
                                           + _struct.pack('!H', _si_xport)
                                           + _si_xip)

                                def _build_stun_attr(_t, _v):
                                    _p = (-len(_v)) % 4
                                    return (_struct.pack('!HH', _t, len(_v))
                                            + _v + b'\x00' * _p)

                                _si_body = _build_stun_attr(0x0012, _si_xpa) + _build_stun_attr(0x0013, _resp)
                                _send_ind = (b'\x00\x16'
                                             + _struct.pack('!H', len(_si_body))
                                             + _STUN_MAGIC + os.urandom(12)
                                             + _si_body)
                                _sock.sendto(_send_ind, (_t_host_sw, _t_port_sw))
                                _stun_seen = True
                            elif _turn_peer_ip_sw and _is_self_peer_ip(
                                    _turn_peer_ip_sw, _turn_peer_port_sw):
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
                                _stun_seen = True
                            _stun_count += 1
                        except Exception:
                            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_is_self_peer_ip', exc_info=True)
                else:
                    # Non-STUN packet = SRTP arriving - ICE is done, hand off to ffmpeg now
                    _srtp_detected = True
                    break   # inner per-socket loop
            if _srtp_detected:
                break       # outer while loop
        # An echo that missed the shortened wait but turned up anyway.  Recorded,
        # not acted on: the webrtcResp this would have built has to be sent
        # BEFORE the relay allocation and the ICE window, so building it now
        # would be a reordering with no camera to measure it against.  What it
        # does do is make the NEXT open on this device wait the full legacy
        # window - so a fleet whose echo band is not empty pays the miss once
        # and says so, instead of losing the branch silently forever.
        if (not _cam_echo_received and _echo_fut is not None
                and not getattr(self, "_sdes_echo_seen", False)):
            try:
                _late_echo = _echo_fut.done() and not _echo_fut.cancelled()
            except Exception:
                _late_echo = False
            if _late_echo:
                self._sdes_echo_seen = True
                _LOGGER.warning(
                    "camera %s: the webrtcReq echo arrived %.2fs after a %.2fs"
                    " wait expired, so no webrtcResp was built for this open."
                    " Later opens on this camera will wait %.1fs again. Set"
                    " AIDOT_SDES_ECHO_WAIT_S=%.1f to make that permanent.",
                    getattr(self, "device_id", "?"),
                    time.monotonic() - _echo_wait_t0, _echo_wait_s,
                    _SDES_ECHO_WAIT_LEGACY_S, _SDES_ECHO_WAIT_LEGACY_S,
                )
        for _rsock in (_audio_sock, _video_sock):
            try:
                _rsock.setblocking(True)
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_is_self_peer_ip', exc_info=True)
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
            _status("SRTP detected - exiting STUN window, handing off to ffmpeg")

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
                " - re-sending webrtcResp + ICE candidates"
            )
            await asyncio.sleep(0.3)   # let camera re-subscribe before re-send
            if _webrtc_resp_sdes is not None and _sdes_webrtcresp_sent:
                # Only re-send webrtcResp if we sent it originally (isDTLS='0').
                # For dtls_fallback_ok cameras the SDES session was intentionally
                # suppressed - do not retroactively start one on reconnect.
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
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_is_self_peer_ip', exc_info=True)
            # Retry STUN window (8 s)
            _stun_deadline = time.monotonic() + 8.0
            _last_pkt_t = time.monotonic()
            _stun_seen = False
            while time.monotonic() < _stun_deadline:
                # Same exit as the first window.  A camera that quickConns after
                # signalling re-runs ICE here, and without this it sat the full
                # 8 s on credentials it already had - the same delay the first
                # window was fixed for, in the window the fix had not reached.
                if _stun_window_answer_exit_due(
                        stun_seen=_stun_seen,
                        answer_ready=_answer_ready_for_this_open(
                            getattr(self, "_camera_answer_ice_ready_ts", None),
                            _open_started_at)):
                    _status(
                        "STUN window (retry %d): leaving early after %.2fs -"
                        " answer ICE credentials in hand and camera probing"
                        % (_sdes_retries,
                           time.monotonic() - (_stun_deadline - 8.0)))
                    break
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
                            _stun_seen = True
                            _stun_count += 1
                        except Exception:
                            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_is_self_peer_ip', exc_info=True)
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
                    " - exiting STUN window, handing off to ffmpeg"
                )

        # --- Harvest camera's webrtcResp answer --- #
        # The asyncio event loop was blocked by the synchronous STUN loop.  Any
        # call_soon_threadsafe(answer_fut.set_result, ...) from the MQTT thread is
        # queued but hasn't fired yet.  One asyncio cycle resolves it.
        await asyncio.sleep(0)
        # ...but one cycle only helps if the answer had already ARRIVED.  When it
        # has, the window above now leaves as soon as it is readable and this
        # harvest is a formality; when it has not, the window ran to its own
        # deadline and this wait is the whole story.  Either way, wait for it:
        # the ICE credentials it carries are what the nomination below needs -
        # without them the camera is never nominated, stays in ICE "Checking",
        # and never sends SRTP no matter how long the first-media wait runs.
        # (This comment used to assert the window "closes ~2.4 s before the
        # camera answers".  That stopped being true when the livePlayReq echo
        # wait was cut to 0.25 s, and the window then sat on the answer for
        # seconds - see _stun_window_answer_exit_due.)
        # shield() so a timeout here cannot cancel the future the real answer
        # await (and the DTLS-fallback path) still consume further down.
        # A TERMINAL refusal races the harvest.  A camera at its viewer cap acks
        # -50002/-50015 about a second after webrtcReq and then, by definition,
        # never answers - so without this the refusal sat unread for the whole
        # _PRE_LAUNCH_ANSWER_WAIT_S before the later checks could see it, and we
        # launched a bridge for a stream the camera had already declined.
        if not answer_fut.done():
            _ans_wait_t0 = time.monotonic()
            try:
                _harvest_waits = [asyncio.shield(answer_fut)]
                if terminal_error_fut is not None:
                    _harvest_waits.append(asyncio.shield(terminal_error_fut))
                _h_done, _h_pending = await asyncio.wait(
                    _harvest_waits,
                    timeout=_PRE_LAUNCH_ANSWER_WAIT_S,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                # Cancel the shield WRAPPERS only; the futures they guard are
                # owned by the MQTT handler and are still consumed below.
                for _h in _h_pending:
                    _h.cancel()
                if terminal_error_fut is not None and terminal_error_fut.done():
                    _code, _desc = terminal_error_fut.result()
                    _status(f"camera refused: ack {_code} {_desc}"
                            " - terminal, not launching the bridge")
                    raise AidotCameraBusy(_code, _desc)
                if answer_fut.done():
                    _status("webrtcResp answer harvested after %.2fs"
                            % (time.monotonic() - _ans_wait_t0))
                else:
                    _status(
                        "no webrtcResp answer within %.0fs - proceeding without ICE"
                        " credentials (nomination will retry during the first-media"
                        " wait)" % _PRE_LAUNCH_ANSWER_WAIT_S
                    )
            except AidotCameraBusy:
                raise
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception awaiting answer",
                              getattr(self, "device_id", "?"), exc_info=True)
        _pre_launch_answer_sdp: str = ""
        _our_tx_srtp_key_audio = srtp_key_audio  # our TX key; set early in case answer absent
        _cam_key_audio: str = ""   # camera's answer key; set in SDP parse block below
        _cam_key_video: str = ""   # camera's video SRTP key; set in SDP parse block below
        _dc_answer_has_app: bool = False  # set True if camera echoes m=application; init here so bridge closure never sees NameError on late-wake path
        _sctp: dict = {              # initialized here for the same reason - bridge closure
            'state': 'CLOSED', 'local_tag': 0, 'peer_tag': 0,
            'local_tsn': 0, 'peer_tsn': 0, 'stream_seq': 0,
        }
        if answer_fut.done():
            try:
                _pre_ans = answer_fut.result()
                _pre_launch_answer_sdp = (_pre_ans or {}).get("sdp", "")
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_is_self_peer_ip', exc_info=True)
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
                        " in its answer - BUNDLE+DTLS unsupported on this firmware"
                    )

            # SCTP DataChannel for SDES cameras.
            # Source analysis (f0.java g2()) confirmed SESSION_MODE_REQ (5376)
            # must be sent via DataChannel.send(), NOT raw TUTK 0xC8 UDP.
            # Camera uses plain SCTP over UDP (same ICE port), no DTLS.
            # We are the SCTP client (proactive INIT), camera is server.
            _dc_answer_has_app = "m=application" in _pre_launch_answer_sdp
            _sctp = {
                'state': 'CLOSED',    # INIT_SENT -> COOKIE_ECHOED -> ESTABLISHED -> DONE
                'local_tag': 0,       # our verification tag (sent in INIT)
                'peer_tag': 0,        # camera's verification tag (from INIT-ACK)
                'local_tsn': 0,       # our TSN counter
                'peer_tsn': 0,        # camera's Initial TSN (from its INIT/INIT-ACK)
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
                await asyncio.get_running_loop().run_in_executor(
                    None, lambda: _write_text_file(sdp_path, _inject_sprop(_updated_sdp, self.device_id)))
            except Exception as _sdp_exc:
                _LOGGER.warning("_open_sdes_stream: could not rewrite SDP: %s", _sdp_exc)

        # --- SCTP helper functions (always defined - even when answer arrives late) --- #
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
            import struct as _st_sc
            import random as _r_sc
            if _sctp['local_tag'] == 0:
                _sctp['local_tag'] = _r_sc.randint(1, 0xFFFFFFFF)
                _sctp['local_tsn'] = _r_sc.randint(1, 0xFFFFFFFF)
            body = _st_sc.pack('!IIHHI', _sctp['local_tag'],
                               131072, 1024, 2048, _sctp['local_tsn'])
            return _sctp_pkt(0, _sctp_chunk(0x01, 0, body))

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
            import struct as _st_sc
            import random as _r_sc
            # RFC 4960 section 5.2.1: reuse local_tag/tsn from our INIT in simultaneous open
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
            import struct as _st_sc
            import random as _r_sc
            import time as _t_sc
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

        # Parse camera's ICE credentials and UDP candidates from its answer SDP.
        # Credentials and candidates from the camera's answer.  _cam_ice_host is
        # the typ host candidate, which is what SCTP is addressed to.
        _cam_ice_ufrag: str
        _cam_ice_pwd:   str
        _cam_ice_cands: list        # list of (ip, port) tuples
        _cam_ice_host:  tuple
        # Through the shared parser, not a second copy: the STUN window's early
        # exit above means "the nomination below will succeed", and it only
        # means that while both read the same SDP the same way.
        (_cam_ice_ufrag, _cam_ice_pwd, _cam_ice_cands,
         _cam_ice_host) = _parse_answer_ice(_pre_launch_answer_sdp)

        def _send_use_candidate(sock, our_ufrag, our_pwd, cam_ufrag, cam_pwd, cam_addr):
            """Send a STUN Binding Request with ICE-CONTROLLING + USE-CANDIDATE."""
            import struct as _st_uc
            import os as _os_uc
            import hmac as _hm_uc
            import hashlib as _hs_uc
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
            # FINGERPRINT (RFC 5389 section 15.5): CRC32 XOR 0x5354554E, after MI.
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
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_send_use_candidate', exc_info=True)
            # Probe the same peer a second time, out of our relay allocation.
            # These are two different candidate pairs (host->peer and
            # relay->peer) and ICE validates pairs, not addresses: without the
            # relayed copy the camera never sees a check whose source is the
            # relay candidate we advertised, so it never nominates that pair,
            # never sends media to it, and nothing ever arrives - which also
            # means the reactive Send-indication path can never bootstrap.
            # Measured on a live A001513: permissions installed and CONFIRMED
            # by the TURN server for the camera's host, srflx and relay
            # addresses, and still ZERO relay-carried inbound packets.
            # The direct send above is untouched, so directly reachable
            # cameras behave exactly as before.
            if not _is_self_peer_ip(cam_addr[0], cam_addr[1]):
                _turn_send_indication(sock, cam_addr[0], cam_addr[1], _req)

        # Every candidate this session actually sent USE-CANDIDATE to, in the
        # order it was nominated.  Instrumentation only, and it exists because
        # _bridge_uc_info cannot answer the question on the shape that stalls:
        # on a late answer - measured at +1.3 s, missing the pre-launch snapshot
        # - it is _nominate_from_answer_sdp below that nominates, and it neither
        # appends to _bridge_uc_info["cands"] nor flips ["sent"].  Reporting the
        # stall from that dict alone would print "nominated=none" on an open
        # that did nominate, and make "the answer carried no ICE credentials"
        # indistinguishable from "the answer carried one unroutable candidate".
        _nominated_seen: list = []

        def _nominate_from_answer_sdp(sdp_text) -> int:
            """Nominate every candidate in ``sdp_text``; return how many.

            Same parse as the post-wait path, factored out so the first-media
            wait can use it.  ``_pre_launch_answer_sdp`` is snapshotted before
            the camera has answered, so for A001513/A001064 the parse above
            finds no credentials and nothing is ever nominated - and a camera
            that never sees USE-CANDIDATE stays in ICE "Checking" and never
            sends SRTP (see the note above).  Returns 0 while the answer is
            still absent, so the caller can keep polling.
            """
            if not sdp_text:
                return 0
            _u, _p, _cands, _ = _parse_answer_ice(sdp_text)
            if not (_u and _p and _cands):
                return 0
            # Open the relay's door before probing, same invariant the setup and
            # bridge paths hold: a check sent to a peer the relay has no
            # permission for is discarded, so nominating first would probe a
            # black hole on any camera we cannot reach directly.
            _turn_install_permissions(_cands, "answer")
            for _c_ip, _c_port in _cands:
                _send_use_candidate(
                    _audio_sock, _ufrag_a, _pwd_a, _u, _p, (_c_ip, _c_port))
                _send_use_candidate(
                    _video_sock, _ufrag_v, _pwd_v, _u, _p, (_c_ip, _c_port))
                if (_c_ip, _c_port) not in _nominated_seen:
                    _nominated_seen.append((_c_ip, _c_port))
            return len(_cands)

        # Open the TURN relay's door for the camera BEFORE probing it.
        #
        # A TURN server drops everything from a peer until a permission exists
        # for that peer's address (RFC 5766 s9).  We advertise the relay as a
        # candidate, but the only thing that ever created a permission here was
        # a Send indication emitted while HANDLING data that had already arrived
        # through the relay - which cannot happen until the permission exists.
        # That deadlock made the advertised relay candidate a black hole:
        # measured on a live A001513 whose host could not be reached directly,
        # ZERO packets ever arrived from the relay, so the camera had no working
        # path and sent no media at all, while the same camera streamed to a
        # host it COULD reach directly.  (The DTLS path never hit this because
        # aiortc does full TURN.)
        #
        # Defined at function scope rather than inside the branch below on
        # purpose: relay-only battery cams (LAN IP unknown) answer AFTER the
        # STUN window, so they never enter that branch at all and the bridge
        # thread is the only place their permissions can be installed.
        def _turn_create_permission(_cp_sock, _cp_peer_ip, _cp_peer_port):
            """Authenticated CreatePermission for one peer on _cp_sock's relay."""
            import hashlib as _cp_hashlib
            import hmac as _cp_hmac
            import socket as _cp_socket
            import struct as _cp_struct

            _cp = _relay_addrs.get(_cp_sock)
            if not _cp or len(_cp) < 8:
                return False
            (_, _, _cp_realm, _cp_nonce, _cp_thost, _cp_tport,
             _cp_key, _cp_user) = _cp[:8]

            def _cp_attr(_t, _v):
                return (_cp_struct.pack('!HH', _t, len(_v))
                        + _v + b'\x00' * ((-len(_v)) % 4))

            # XOR-PEER-ADDRESS: family, port ^ magic[:2], addr ^ magic
            _cp_ip_b = _cp_socket.inet_aton(_cp_peer_ip)
            _cp_xport = (_cp_peer_port ^ 0x2112) & 0xFFFF
            _cp_xaddr = bytes(a ^ b for a, b in zip(_cp_ip_b, _STUN_MAGIC, strict=True))
            _cp_xpa = b'\x00\x01' + _cp_struct.pack('!H', _cp_xport) + _cp_xaddr

            _cp_tid = os.urandom(12)
            _cp_body = (_cp_attr(0x0012, _cp_xpa)          # XOR-PEER-ADDRESS
                        + _cp_attr(0x0006, _cp_user)       # USERNAME
                        + _cp_attr(0x0014, _cp_realm)      # REALM
                        + _cp_attr(0x0015, _cp_nonce))     # NONCE
            _cp_hdr = (b'\x00\x08'                        # CreatePermission request
                       + _cp_struct.pack('!H', len(_cp_body) + 24)
                       + _STUN_MAGIC + _cp_tid)
            _cp_mi = _cp_hmac.new(_cp_key, _cp_hdr + _cp_body, _cp_hashlib.sha1).digest()
            _cp_body += _cp_attr(0x0008, _cp_mi)           # MESSAGE-INTEGRITY
            _cp_msg = (b'\x00\x08' + _cp_struct.pack('!H', len(_cp_body))
                       + _STUN_MAGIC + _cp_tid + _cp_body)
            try:
                _cp_sock.sendto(_cp_msg, (_cp_thost, _cp_tport))
                return True
            except Exception:
                _LOGGER.debug("CreatePermission send failed", exc_info=True)
                return False

        def _turn_refresh_allocation(_rf_sock, _rf_lifetime=600):
            """Refresh _rf_sock's allocation before the server expires it.

            The relay is granted for a limited LIFETIME (measured against this
            camera's TURN server: 600 s) and the server tears it down silently
            when it lapses.  Stock libwebrtc, which is what the vendor app
            runs, keeps a scheduled Refresh for exactly this reason; without
            one a held session loses its relay mid-stream and the failure looks
            like the camera stopping rather than the allocation expiring.
            """
            import hashlib as _rf_hashlib
            import hmac as _rf_hmac
            import struct as _rf_struct

            _rf = _relay_addrs.get(_rf_sock)
            if not _rf or len(_rf) < 8:
                return False
            (_, _, _rf_realm, _rf_nonce, _rf_thost, _rf_tport,
             _rf_key, _rf_user) = _rf[:8]

            def _rf_attr(_t, _v):
                return (_rf_struct.pack('!HH', _t, len(_v))
                        + _v + b'\x00' * ((-len(_v)) % 4))

            _rf_tid = os.urandom(12)
            _rf_body = (_rf_attr(0x000D, _rf_struct.pack('!I', _rf_lifetime))
                        + _rf_attr(0x0006, _rf_user)      # USERNAME
                        + _rf_attr(0x0014, _rf_realm)     # REALM
                        + _rf_attr(0x0015, _rf_nonce))    # NONCE
            _rf_hdr = (b'\x00\x04'                       # Refresh request
                       + _rf_struct.pack('!H', len(_rf_body) + 24)
                       + _STUN_MAGIC + _rf_tid)
            _rf_mi = _rf_hmac.new(
                _rf_key, _rf_hdr + _rf_body, _rf_hashlib.sha1).digest()
            _rf_body += _rf_attr(0x0008, _rf_mi)          # MESSAGE-INTEGRITY
            _rf_msg = (b'\x00\x04' + _rf_struct.pack('!H', len(_rf_body))
                       + _STUN_MAGIC + _rf_tid + _rf_body)
            try:
                _rf_sock.sendto(_rf_msg, (_rf_thost, _rf_tport))
                return True
            except Exception:
                _LOGGER.debug("TURN Refresh send failed", exc_info=True)
                return False

        def _turn_send_indication(_si_sock, _si_peer_ip, _si_peer_port, _si_data):
            """Send _si_data to a peer THROUGH _si_sock's relay allocation.

            Egress from the relay address is the whole point: ICE validates a
            candidate PAIR, so a camera can only nominate the relay candidate
            we advertised if it receives packets whose source IS that relay.
            Writing straight to the camera from the host socket leaves the
            advertised relay candidate permanently unvalidated.

            Send indications carry no MESSAGE-INTEGRITY (RFC 5766 s10.2), so
            this needs the allocation's server address and nothing else.
            """
            import struct as _si_struct

            _si = _relay_addrs.get(_si_sock)
            if not _si or len(_si) < 6:
                return False
            _si_thost, _si_tport = _si[4], _si[5]

            def _si_attr(_t, _v):
                return (_si_struct.pack('!HH', _t, len(_v))
                        + _v + b'\x00' * ((-len(_v)) % 4))

            try:
                _si_ip_b = bytes(int(_o) for _o in _si_peer_ip.split('.'))
            except Exception:
                return False
            if len(_si_ip_b) != 4:
                return False
            _si_xport = (_si_peer_port ^ 0x2112) & 0xFFFF
            _si_xaddr = bytes(
                a ^ b for a, b in zip(_si_ip_b, _STUN_MAGIC, strict=True))
            _si_xpa = b'\x00\x01' + _si_struct.pack('!H', _si_xport) + _si_xaddr

            _si_body = _si_attr(0x0012, _si_xpa) + _si_attr(0x0013, _si_data)
            _si_msg = (b'\x00\x16'                     # Send indication
                       + _si_struct.pack('!H', len(_si_body))
                       + _STUN_MAGIC + os.urandom(12) + _si_body)
            try:
                _si_sock.sendto(_si_msg, (_si_thost, _si_tport))
                return True
            except Exception:
                _LOGGER.debug("TURN Send indication failed", exc_info=True)
                return False

        def _turn_install_permissions(_ip_cands, _ip_why, _log=None):
            """CreatePermission for every camera candidate on both allocations.

            Non-fatal by design: a socket with no allocation is a no-op, so the
            direct path is untouched.  Returns the number of requests sent.

            ``_log`` is the channel to report on.  The open-time install is a
            once-per-session lifecycle fact and belongs at INFO; the bridge
            re-installs every 120 s for the life of the session, which does
            not.
            """
            _log = _log or _status
            _perm_ok = 0
            for _c_ip, _c_port in _ip_cands:
                for _p_sock in (_audio_sock, _video_sock):
                    if _turn_create_permission(_p_sock, _c_ip, _c_port):
                        _perm_ok += 1
            if _perm_ok:
                _log(
                    f"TURN: installed {_perm_ok} relay permission(s) for"
                    f" {len(_ip_cands)} camera candidate(s) [{_ip_why}] - relay"
                    f" path is now usable if the camera cannot be reached"
                    f" directly"
                )
            elif _ip_cands and _relay_addrs:
                _log(
                    f"TURN: NO relay permission installed for {len(_ip_cands)}"
                    f" camera candidate(s) [{_ip_why}] despite"
                    f" {len(_relay_addrs)} allocation(s) - relay path stays a"
                    f" black hole if the camera cannot be reached directly"
                )
            return _perm_ok

        # Relay mode only: the camera dials our relay allocation, and its
        # packets arrive at the TURN server from the house WAN address - OUR
        # public address - so that address needs a permission or the path is a
        # black hole.  Deliberately NOT done outside relay mode: a permission
        # for our own srflx caused TURN self-loop Data Indications and STUN
        # echo storms when it was installed indiscriminately (see the warning
        # in the allocation helper).  In relay mode nothing of ours is sent to
        # our own allocation, so the loop has no driver.
        if _relay_in_c and _public_ip:
            _turn_install_permissions([(_public_ip, 9)], "relay-mode WAN")

        if _cam_ice_ufrag and _cam_ice_pwd and _cam_ice_cands:
            # Say it plainly when every address the camera offered is on a
            # subnet this host is not on. Nothing downstream can recover from
            # that -- the packets leave by the default gateway and are dropped
            # -- and the symptom otherwise reads as "first media never
            # arrived", which sends people looking at the camera.
            _off = [(_i, _p_) for _i, _p_ in _cam_ice_cands
                    if _candidate_is_off_subnet(_i)]
            if _off and len(_off) == len(_cam_ice_cands):
                _LOGGER.warning(
                    "camera %s: every candidate it offered is on a subnet this"
                    " host cannot reach (%s). Direct media is impossible; only"
                    " the relay can carry it. If this camera never streams,"
                    " it is on a different network segment (a mesh node,"
                    " extender or guest SSID) rather than broken.",
                    self.device_id,
                    ", ".join(f"{_i}:{_p_}" for _i, _p_ in _off))
            _turn_install_permissions(_cam_ice_cands, "setup")

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
        # bind them, ffmpeg cannot respond to STUN -> ICE fails -> camera never
        # sends SRTP -> 0-byte output file.
        #
        # Fix: allocate fresh loopback ports for ffmpeg, rewrite the SDP to point
        # at those ports, and keep the original sockets alive in a bridge thread
        # that:
        #   - responds to STUN Binding Requests on the original sockets
        #   - forwards all non-STUN packets (SRTP) to ffmpeg's loopback ports
        # When the session ends, SdesSession.stop() closes the original sockets,
        # which causes the bridge thread's select() to raise and it exits cleanly.
        import threading as _threading_br
        import socket as _socket_br

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
        # (Out-of-band SPS/PPS is injected at the write below via _inject_sprop.)
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
            await asyncio.get_running_loop().run_in_executor(
                None, lambda: _write_text_file(sdp_path, _inject_sprop(_br_sdp, self.device_id)))
        except Exception as _br_sdp_exc:
            _LOGGER.warning("bridge: could not rewrite SDP: %s", _br_sdp_exc)

        # Shared channel: bridge thread sets [0] to a persistent send function
        # once the SCTP DataChannel is established.  SdesSession reads it via
        # _cmd_chan[0] to dispatch PTZ / IOCtrl commands from the main thread.
        _cmd_chan: list = [None]
        # Bridge installs the SCTP ABORT sender here once the command
        # channel is up; teardown calls it to close the association.
        _abort_chan: list = [None]
        # The other direction: matches the camera's AVIO replies to the commands
        # that asked for them.  Created here, not in SdesSession, because the
        # bridge thread starts dispatching into it before the session object
        # exists; the session is handed the same instance so both sides share
        # one registry.
        _avio_responses = AvioResponseRouter()
        # Proc holder: set to the ffmpeg Popen object after launch so the
        # bridge thread can poll for exit without a NameError race.
        _proc_holder: list = [None]
        # Teardown holder: [0] flips True the moment ANY locally-initiated
        # ffmpeg-kill path fires (_reap() above on a cancelled cold open, the
        # key-restart proc replace, or the DTLS-fallback abort below - plus
        # SdesSession.stop() once the session is handed off, via the
        # teardown_requested= kwarg at construction).  The bridge observe loop
        # reads it via _classify_ffmpeg_exit() to demote an expected signal
        # death (our own SIGTERM/SIGKILL) from an unexpected ffmpeg crash.
        _teardown_holder: list = [False]
        # Camera's actual video payload type (96=H.264 / 97=H.265), set by the
        # bridge on the first video RTP packet so the ffmpeg SDP can be narrowed
        # to the matching single codec before ffmpeg is launched.
        _first_video_pt: list = [None]
        _media_path: list = [None]
        # Every TURN server address this session could be relayed through:
        # our allocations plus the ICE entries themselves - the camera can
        # arrive via its OWN vendor allocation even when ours was skipped.
        _bridge_turn_ips = ({a[0] for a in _relay_addrs.values()}
                            | _turn_entry_ips(_sdes_turn_entries))
        # Fallback for the above, filled from the camera's negotiated answer SDP
        # when the wait below expires without a single video packet. Kept in a
        # list for the same reason as _first_video_pt: the serve-restart path
        # reads it from a nested scope.
        _answer_video_pt: list = [None]
        # PT -> "video"/"audio" from the camera's answer, read by the
        # bridge demux. Empty until the answer lands (the bridge starts
        # first), which is exactly when the static-tuple fallback applies.
        _answer_pt_kinds: dict = {}
        # Same for audio: the ffmpeg SDP advertises BOTH PCMU (0) and PCMA (8),
        # and ffmpeg binds the depacketizer to the first one listed - so the line
        # has to be narrowed to the payload type the camera actually sends, the
        # same way the video line already is.
        _first_audio_pt: list = [None]
        # Media-liveness: bridge sets [0] = time.monotonic() on every forwarded
        # media packet; the keepalive watchdog reads it via SdesSession to
        # restart a session the camera silently stopped feeding.
        _media_progress: list = [0.0]
        _ice_progress: list = [0.0]
        # Shared with the bridge thread: [packets, bytes] actually forwarded to
        # ffmpeg.  The SDES path decodes nothing in-process, so on_frame never
        # fires and these counters are the only in-process proof media flowed -
        # see SdesSession.media_stats(), which the live-validation gate reads.
        _media_counts: list = [0, 0]

        # SRTP receive side for _use_plain_rtp cameras.  Defined once per open
        # rather than per packet; the bridge calls _ensure_srtp_rx_session with
        # these deep inside its receive loop.  pylibsrtp is imported here, not at
        # module scope, because it lives in the optional "webrtc" extra.
        def _build_srtp_rx(_rx_key):
            import base64 as _b64_srx

            import pylibsrtp as _plsrtp_rx
            _rx_pol = _plsrtp_rx.Policy(
                key=_b64_srx.b64decode(_rx_key),
                ssrc_type=_plsrtp_rx.Policy.SSRC_ANY_INBOUND,
                srtp_profile=_plsrtp_rx.Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
            )
            _rx_pol.allow_repeat_tx = True
            return _plsrtp_rx.Session(policy=_rx_pol)

        def _on_srtp_rx_built(_first):
            # first-media marks the cold-start timeline; a re-key mid-open is a
            # rebuild, not a second first packet.
            if _first:
                self._cold_phase("first-media")
            _status("bridge: SRTP RX session ready (cam->us)")

        def _on_srtp_rx_error(_exc):
            # Capped: a build that keeps failing is retried per packet by
            # design, and the log must not follow it at frame rate.
            _n = getattr(_bridge_fn, '_srtp_rx_err_n', 0)
            if _n < 8:
                _bridge_fn._srtp_rx_err_n = _n + 1
                _status(f"bridge: SRTP RX init failed: {_exc}")

        def _bridge_fn():
            nonlocal _br_first_di_logged, _br_first_srtp_logged, _br_first_req_dumped
            nonlocal _br_first_audio_logged, _br_first_video_logged, _avio_living_sent
            nonlocal _bridge_selfloop_drop_count  # incremented below; needs nonlocal
            _STUN_MAGIC_BR = b'\x21\x12\xa4\x42'
            import struct as _st_br
            import select as _sel_br
            import time as _time_br
            _br_prefer_direct_stun = {_audio_sock: False, _video_sock: False}
            _br_last_uc = 0.0
            _br_last_perm = 0.0     # last CreatePermission install (monotonic)
            _br_perm_cands = ()     # candidate set those permissions covered
            # Seeded to now, not 0: the allocation was just created, so the
            # first refresh belongs one interval out, not on the first tick.
            _br_last_alloc_refresh = _time_br.monotonic()

            def _br_send_to_cam(_s, _data, _addr, _peer):
                """Reply to the camera, relayed or direct as the peer requires.

                _addr is where the packet we are answering arrived FROM; when
                the camera reached us through our relay that is the TURN
                server, and _peer carries the camera's real address so the
                payload can be wrapped.  _peer None => plain direct send.
                """
                if _peer and _turn_send_indication(_s, _peer[0], _peer[1], _data):
                    return
                _s.sendto(_data, _addr)
            _br_stun_resp_count = 0
            _tutk_trigger_sent = False
            # Instrumentation for the first-media stall report.  These four are
            # bridge-thread locals that the main coroutine has to be able to
            # read when the wait expires, so each is mirrored onto _bridge_fn at
            # its write site - the same publication _sprop_done uses.  Nothing
            # here is read by the bridge itself; they only ever describe.
            _br_binding_success_count = 0   # inbound STUN Binding Success (0x0101)
            _br_probe_verdicts: dict = {}   # probe source -> why it was/wasn't learned
            # A SET, not a counter: one unrecorded source probing fifty times
            # is one source, and a per-packet count would put a wrong number in
            # the report for someone to reason from.
            _br_probe_overflow: set = set()  # sources past _MAX_PROBE_SOURCES
            _bridge_fn._tutk_trigger_sent = False
            _bridge_fn._br_stun_resp_count = 0
            _bridge_fn._br_binding_success_count = 0
            _bridge_fn._br_probe_verdicts = {}
            _bridge_fn._br_probe_overflow = 0
            _last_trigger_ts    = 0.0     # time of last AVIO LIVING send
            _trigger_bs         = None    # socket used for trigger
            _trigger_bsrc       = None    # camera addr for trigger
            _trigger_peer       = None    # camera's real addr when relayed
            _sdes_probe_received = False  # True after first 0xC8 probe from camera
            _last_hb_ts         = 0.0     # time of last AVIO HEARTBEAT send
            _stall_nudges_sent  = 0       # LIVING re-sends for the CURRENT stall
            _stall_last_nudge   = 0.0     # wall time of the last stall nudge
            _stall_active       = False   # media had started, then went silent
            # One-shot guard for the "ffmpeg exited" log below: while the held
            # proc keeps reporting the same stale exit code across a
            # teardown-window skip (see _bridge_should_break), only the first
            # tick logs it.  Reset to False whenever the held proc is next
            # seen alive (poll() None), so a later, genuine exit of THAT proc
            # still gets its own line.
            _br_exit_logged = False
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
                    # Stop the bridge when ffmpeg exits (normal end or crash) -
                    # but NOT on a stale exit seen during a flagged teardown
                    # window (key-restart proc replace, stop(), _reap(), the
                    # DTLS-fallback abort): _bridge_should_break() skips the
                    # break there, and the loop resolves it either via the
                    # key-restart's _proc_holder[0] repoint (next poll() None,
                    # below) or via a genuine teardown closing the loopback
                    # sockets, which raises out of the select() above.
                    _br_proc = _proc_holder[0]
                    if _br_proc is not None:
                        _br_rc = _br_proc.poll()
                        if _br_rc is not None:
                            _br_teardown_requested = bool(_teardown_holder[0])
                            if _br_rc != 0 and not _br_exit_logged:
                                _br_exit_logged = True
                                import logging as _log_br
                                _br_level = _classify_ffmpeg_exit(
                                    _br_rc, _br_teardown_requested
                                )
                                # Name the camera.  These lines used to carry no
                                # device id at all, and this account runs several
                                # SDES cameras at once, so a burst of exits could
                                # not be attributed to one of them without extra
                                # tooling - which sent a live investigation down
                                # the wrong path once already.
                                _br_dev = getattr(self, "device_id", "?")
                                _br_msg = (
                                    "camera %s: SDES bridge: ffmpeg exited with"
                                    " code %d - stopped by teardown"
                                    if _br_level < _log_br.WARNING else
                                    "camera %s: SDES bridge: ffmpeg exited with"
                                    " code %d - stream ended"
                                )
                                _log_br.getLogger(__name__).log(
                                    _br_level, _br_msg, _br_dev, _br_rc
                                )
                                if _br_level >= _log_br.WARNING:
                                    _serr_tail = getattr(
                                        _br_proc, "_aidot_stderr_tail", None)
                                    # The reason first, then the raw tail. On a
                                    # lossy camera the raw tail is all
                                    # Non-monotonic DTS and says nothing about
                                    # why ffmpeg stopped.
                                    _serr_why = getattr(
                                        _br_proc, "_aidot_stderr_notable", None)
                                    if _serr_why:
                                        _log_br.getLogger(__name__).warning(
                                            "camera %s: SDES serve ffmpeg exit"
                                            " reason (last %d non-repetitive"
                                            " lines; %d NACK(s) sent for %d"
                                            " packet(s), %d late repeat(s) dropped this session):\n%s",
                                            _br_dev, len(_serr_why),
                                            getattr(_br_proc,
                                                    "_aidot_nack_sent", 0)
                                            or getattr(_bridge_fn,
                                                       "_nack_sent", 0),
                                            getattr(_bridge_fn,
                                                    "_nack_seqs", 0),
                                            getattr(_bridge_fn,
                                                    "_nack_late_drops", 0),
                                            "\n".join(_serr_why),
                                        )
                                    if _serr_tail:
                                        _log_br.getLogger(__name__).warning(
                                            "camera %s: SDES serve ffmpeg stderr"
                                            " (last %d lines):\n%s", _br_dev,
                                            len(_serr_tail),
                                            "\n".join(_serr_tail),
                                        )
                            if _bridge_should_break(
                                _br_rc, _br_teardown_requested
                            ):
                                break
                        else:
                            _br_exit_logged = False

                    # AVIO HEARTBEAT (cmd=5156) every 10s, sent as an ENCRYPTED SCTP
                    # DATA chunk (PPID=53) - exactly like LIVING - NOT a raw 0xC8 AVIO
                    # frame.  The camera's control channel is SCTP-inside-0xC8: a raw
                    # 0xC8 AVIO frame is not a valid SCTP packet, so the camera's SCTP
                    # layer discards it and the app-layer keepalive never lands.  With
                    # the old raw-0xC8 heartbeat the firmware tore the session down at
                    # ~18-22 s - confirmed 2026-06-02: recorded video duration was
                    # pinned at ~18 s regardless of motion (brief tap-past 18.3 s vs
                    # sustained 40 s motion 17.6 s), while raw-0xC8 heartbeats *were*
                    # firing.  The official app sends this via DataChannel.customSend
                    # (= SCTP) on a 10 s timer (f0.java Z2() -> CMD_AVIO_CTRL_HEARTHEAT_REQ).
                    #
                    # Gating on dcep_sock confines this to the encrypted-SCTP path
                    # (battery SDES cams), which is where the watchdog bites and where
                    # _enc_c8_sctp is in scope (defined in the packet loop below, set up
                    # by the time SCTP reaches DONE - same closure pattern as the LIVING
                    # send at the DCEP_WAIT branch).  Mains plain-RTP cams never sleep
                    # and leave dcep_sock None, so they simply skip the heartbeat.
                    _hb_sock = _sctp.get('dcep_sock')
                    _hb_src  = _sctp.get('dcep_src')
                    if (_sdes_probe_received
                            and _hb_sock is not None and _hb_src is not None
                            and _time_br.time() - _last_hb_ts >= 10.0):
                        import struct as _st_hb
                        import random as _r_hb
                        _hb_seq = _r_hb.randint(0, 0x7FFFFFFF)
                        _hb_ts  = int(_time_br.time() * 1000)
                        # 28-byte AVIO header, cmd=5156 (HEARTHEAT_REQ), empty payload.
                        _hb_avio = _st_hb.pack('<IIqII4x', _hb_seq, 5156, _hb_ts, 0, 0)
                        try:
                            _hb_chunk = _sctp_data(53, _hb_avio)
                            _hb_sock.sendto(
                                _enc_c8_sctp(_sctp_pkt(_sctp['peer_tag'], _hb_chunk)),  # noqa: F821
                                _hb_src,
                            )
                            _last_hb_ts = _time_br.time()
                            _trace(
                                f"SDES: sent AVIO HEARTBEAT(5156) via SCTP"
                                f" TSN={(_sctp['local_tsn']-1) & 0xFFFFFFFF}"
                                f" -> {_hb_src[0]}:{_hb_src[1]}"
                            )
                        except Exception as _hb_e:
                            _status(f"SDES: SCTP heartbeat send failed: {_hb_e}")

                    # Two-way audio speaker control - MUST run on the bridge thread.
                    # SPEAKERSTART/STOP are SCTP DATA chunks; _sctp_data() mutates the
                    # shared SCTP TSN/stream-seq, so issuing them from the talk pump
                    # thread races the heartbeat here and the camera drops the chunk
                    # (no 851 ACK).  async_start_talk/async_stop_talk only flip the
                    # want_speaker flag; the actual command is sent from here once the
                    # command channel (_cmd_chan[0], set after LIVING) is up.
                    if _talk_state is not None and _cmd_chan[0] is not None:
                        if _talk_state.get("want_speaker") and not _talk_state.get("speaker_on"):
                            # Defer SPEAKERSTART ~0.6 s after the command channel comes
                            # up.  The camera ignores it if sent immediately after LIVING
                            # (validated: the working spike sent it on first-audio,
                            # ~0.58 s post-LIVING and got the 851 ACK; sending at +22 ms
                            # gets no ACK - the camera's media/audio pipeline isn't ready).
                            _now_spk = _time_br.time()
                            if _talk_state.get("spk_eligible_ts") is None:
                                _talk_state["spk_eligible_ts"] = _now_spk
                            elif _now_spk - _talk_state["spk_eligible_ts"] >= SDES_SPEAKERSTART_DELAY:
                                try:
                                    _cmd_chan[0](848, b'\x00' * 8)  # SPEAKERSTART
                                    _talk_state["speaker_on"] = True
                                    _status("SDES talk: sent SPEAKERSTART(848) (bridge thread)")
                                except Exception:
                                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                        elif _talk_state.get("speaker_on") and not _talk_state.get("want_speaker"):
                            try:
                                _cmd_chan[0](849, b'\x00' * 8)  # SPEAKERSTOP
                                _talk_state["speaker_on"] = False
                                _status("SDES talk: sent SPEAKERSTOP(849) (bridge thread)")
                            except Exception:
                                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)

                    # RTCP PLI (Picture Loss Indication) - forces camera to
                    # resend IDR + VPS/SPS/PPS so ffmpeg gets codec params.
                    # STARTUP BURST then SLOW SAFETY: fire at 5 s for the first
                    # few PLIs to win the codec-params race (the original intent),
                    # then drop to 30 s.  A *perpetual* 5 s PLI forces an IDR every
                    # 5 s, and at a fixed camera bitrate each IDR is a bandwidth
                    # spike / P-frame quality dip - a deterministic 5 s stutter
                    # cadence (the official app sends ZERO app-level PLI and relies
                    # on the camera's own GOP).  We can't decode here to detect the
                    # first keyframe, so we time-box the burst and keep a slow
                    # safety PLI in case the camera's GOP is long.
                    # P2: front-load the burst so the first decodable IDR arrives
                    # sooner on a cold open.  Was 3 PLIs at a flat 5 s (first IDR
                    # up to ~10 s); now a denser early ramp, then the same 30 s
                    # safety PLI.  AIDOT_SDES_PLI_GAPS overrides the early gaps
                    # (comma-sep seconds; e.g. "5,5,5" restores the old cadence).
                    _pli_gaps = getattr(_bridge_fn, '_pli_gaps', None)
                    if _pli_gaps is None:
                        try:
                            _pli_gaps = tuple(
                                float(_x) for _x in os.environ.get(
                                    "AIDOT_SDES_PLI_GAPS", "0,1.5,2,3").split(",")
                                if _x.strip()
                            ) or (0.0, 1.5, 2.0, 3.0)
                        except ValueError:
                            _pli_gaps = (0.0, 1.5, 2.0, 3.0)
                        _bridge_fn._pli_gaps = _pli_gaps
                    # REMB names the VIDEO stream, which is the one to
                    # limit. An earlier version rode the audio Receiver Report
                    # and so named the audio SSRC - it asked the camera to keep
                    # PCMA under the target, which it already was, and left the
                    # video untouched. Measured no change, correctly.
                    #
                    # Own cadence: the PLI timer backs off to 30s once the
                    # stream is up, which is too slow to hold a rate.
                    # Goes out the relay-aware sender, NOT the socket: via TURN
                    # the address media arrived from is the relay, and a raw
                    # write there is dropped as a malformed STUN message while
                    # sendto still reports success.  That is the bug the NACK
                    # path already had and had fixed; REMB was left behind, so
                    # on a relayed camera it never arrived -- which also means
                    # "REMB was measured to do nothing" cannot have been a valid
                    # measurement on such a session.  No fallback to the socket:
                    # skipping a tick until the sender exists costs a second,
                    # falling back costs correctness on the very sessions this
                    # is for.
                    # Guard order is cost order: the module constant first,
                    # so the default REMB-off config pays nothing per packet
                    # (the sender lookup used to sit above this line and ran
                    # ~300x/s for a feature that ships disabled).
                    if (REMB_TARGET_BPS > 0
                            and hasattr(_bridge_fn, '_cam_video_ssrc')
                            and (_remb_send := getattr(
                                _bridge_fn, '_send_to_cam', None)) is not None
                            and _time_br.time() - getattr(
                                _bridge_fn, '_last_remb_ts', 0.0) >= 1.0):
                        _bridge_fn._last_remb_ts = _time_br.time()
                        if _send_video_remb(
                                _remb_send,
                                getattr(_bridge_fn, '_pli_tx_sess', None),
                                _CAM_RTCP_SENDER_SSRC,
                                _bridge_fn._cam_video_ssrc,
                                REMB_TARGET_BPS,
                        ) and not getattr(_bridge_fn, '_remb_logged', False):
                            _bridge_fn._remb_logged = True
                            _status(
                                f"SDES: sent REMB {REMB_TARGET_BPS // 1000} kbps"
                                f" for video SSRC"
                                f" 0x{_bridge_fn._cam_video_ssrc:08x}")

                    # TMMBR: a BOUND, where REMB above is an ESTIMATE.  Two
                    # different RFC 5104 / 4585 messages, and this firmware can
                    # honour one without the other -- it already acts on NACKs
                    # it never negotiated (our SDES offer carries no a=rtcp-fb
                    # line at all), so "the answer does not advertise ccm
                    # tmmbr" is not a reason to withhold it.  Off by default;
                    # every bitrate control tried on this camera so far has
                    # been acked and ignored, and an unmeasured one must not
                    # reach the four cameras that stream fine today.
                    # Same cost ordering: the per-session bps attr is the
                    # one cheap read the off-default pays; the cadence gate
                    # runs before _tmmbr_ready so the readiness math and the
                    # sender lookup happen at most once a second, not per
                    # packet, and one time.time() serves both checks.
                    _tmmbr_bps = getattr(_bridge_fn, '_tmmbr_bps', None)
                    if (_tmmbr_bps
                            and hasattr(_bridge_fn, '_cam_video_ssrc')
                            and (_tmmbr_now := _time_br.time()) - getattr(
                                _bridge_fn, '_last_tmmbr_ts', 0.0) >= 1.0
                            and _tmmbr_ready(
                                getattr(_bridge_fn, '_first_video_ts', None),
                                _tmmbr_now,
                                getattr(_bridge_fn, '_tmmbr_after_s', 0.0))
                            and (_tmmbr_send := getattr(
                                _bridge_fn, '_send_to_cam', None)) is not None):
                        _bridge_fn._last_tmmbr_ts = _tmmbr_now
                        if _send_video_tmmbr(
                                _tmmbr_send,
                                getattr(_bridge_fn, '_pli_tx_sess', None),
                                _CAM_RTCP_SENDER_SSRC,
                                _bridge_fn._cam_video_ssrc,
                                _tmmbr_bps,
                        ) and not getattr(_bridge_fn, '_tmmbr_logged', False):
                            _bridge_fn._tmmbr_logged = True
                            _status(
                                f"SDES: sent TMMBR {_tmmbr_bps // 1000} kbps"
                                f" for video SSRC"
                                f" 0x{_bridge_fn._cam_video_ssrc:08x}")

                    _pli_done       = getattr(_bridge_fn, '_pli_count', 0)
                    _pli_interval   = (_pli_gaps[_pli_done]
                                       if _pli_done < len(_pli_gaps) else 30.0)
                    if (hasattr(_bridge_fn, '_cam_video_ssrc')
                            and hasattr(_bridge_fn, '_cam_srtp_sock')
                            and _time_br.time() - getattr(
                                _bridge_fn, '_last_pli_ts', 0.0) >= _pli_interval):
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
                        # Hoisted out of the session-build below only so the
                        # SRTP-TX-KEY note can report the key that actually went
                        # out rather than re-deriving it.  Same expression, same
                        # result - no behavior change.
                        _pli_key_b64 = (
                            _our_tx_srtp_key_audio
                            or srtp_key_audio
                        )
                        try:
                            import pylibsrtp as _plsrtp_pli
                            if not hasattr(_bridge_fn, '_pli_tx_sess'):
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
                            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                        if not _pli_sent:
                            try:
                                _bridge_fn._cam_srtp_sock.sendto(
                                    _pli_raw, _bridge_fn._cam_srtp_src)
                            except Exception:
                                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                        _bridge_fn._last_pli_ts = _time_br.time()
                        _pli_n = getattr(_bridge_fn, '_pli_count', 0) + 1
                        _bridge_fn._pli_count = _pli_n
                        if _pli_n <= len(_pli_gaps):
                            _trace(
                                f"SDES: sent RTCP PLI #{_pli_n}"
                                f" -> SSRC=0x{_pli_media_ssrc:08x}"
                                f" ({'SRTCP' if _pli_sent else 'plain'})"
                            )
                        # First send only, unlike the RR note below: the PLI
                        # SRTP session is built once and cached on _bridge_fn,
                        # so the key the first PLI went out with is the key
                        # every later PLI goes out with.
                        if _pli_n == 1 and _pli_sent:
                            _status(_srtp_tx_key_note(
                                "PLI", _pli_key_b64,
                                _our_tx_srtp_key_audio, _cam_key_audio))

                    # DCEP_WAIT -> send LIVING 300ms after DCEP_OPEN.
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
                                    f"SDES DC: DCEP_WAIT -> LIVING(5376)"
                                    f" TSN={_sctp['local_tsn']-1}"
                                    f" (300ms after DCEP_OPEN)"
                                )
                                # Build persistent command sender for PTZ/IOCtrl/talk.
                                # Computes timestamp fresh on every call so commands
                                # are not stale.  AVIO IOCtrl over SDES MUST go out as an
                                # encrypted SCTP DATA chunk (PPID=53) - identical to LIVING
                                # and the keepalive heartbeat - NOT a raw 0xC8 AVIO frame.
                                # The camera's control channel is SCTP-inside-0xC8; a raw
                                # 0xC8 AVIO frame is not a valid SCTP packet, so the camera's
                                # SCTP layer silently drops it (proven by the ~18s heartbeat
                                # watchdog cutoff that disappeared once the heartbeat was
                                # SCTP-wrapped, 2026-06-02).  _enc_c8_sctp/_sctp_data/_sctp_pkt
                                # are in scope by the time this runs (DCEP_WAIT is only reached
                                # after the encrypted-SCTP handshake defines them; same closure
                                # pattern as the LIVING send above).  dcep_sock/dcep_src are the
                                # socket+addr the SCTP handshake (and LIVING) used.
                                import struct as _st_pcmd

                                def _persistent_sdes_cmd(_cmd, _extra=b''):
                                    # dSeq, not a random number.  The app's
                                    # sendCtrl() takes this from a per-client
                                    # counter that starts at 100 and increments
                                    # on every control command, and we keep the
                                    # same counter for livePlayReq already.
                                    # Filling the slot randomly was the only
                                    # field in the 28-byte header that differed
                                    # from the app's.  Parity, not a fix: PTZ
                                    # (AVIO 0x1001) pans through this very
                                    # builder with a random dSeq, so the camera
                                    # is not validating it.
                                    _seq = self._next_dseq()
                                    _ts  = int(_time_br.time() * 1000)
                                    _avio = _st_pcmd.pack('<IIqII4x', _seq, _cmd, _ts,
                                                          len(_extra), 0) + _extra
                                    _csock = _sctp.get('dcep_sock')
                                    _csrc  = _sctp.get('dcep_src')
                                    if _csock is None or _csrc is None:
                                        return
                                    try:
                                        _chunk = _sctp_data(53, _avio)
                                        _csock.sendto(
                                            _enc_c8_sctp(_sctp_pkt(_sctp['peer_tag'], _chunk)),
                                            _csrc,
                                        )
                                    except Exception:
                                        _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_persistent_sdes_cmd', exc_info=True)

                                def _persistent_sdes_abort():
                                    """ABORT the association from the same socket the commands use.

                                    Lives here rather than in the bridge's main
                                    loop because this is where the encrypted
                                    SCTP context actually is - the dcep socket,
                                    the peer tag and the encrypt helper. An
                                    earlier attempt to send it from the media
                                    loop referenced none of them and would not
                                    have compiled.
                                    """
                                    _csock = _sctp.get('dcep_sock')
                                    _csrc  = _sctp.get('dcep_src')
                                    if _csock is None or _csrc is None:
                                        return False
                                    _csock.sendto(
                                        _enc_c8_sctp(_sctp_pkt(_sctp['peer_tag'],
                                                               _sctp_abort_chunk())),
                                        _csrc,
                                    )
                                    return True

                                _cmd_chan[0] = _persistent_sdes_cmd
                                _abort_chan[0] = _persistent_sdes_abort
                            except Exception as _dw_e:
                                _status(f"SDES DC: DCEP_WAIT LIVING err: {_dw_e}")

                    # One LIVING wire-build, shared by the pre-probe retrigger
                    # below and the mid-session stall nudge: resend the AVIO
                    # LIVING(5376) that starts media, encrypted then plaintext
                    # exactly like the original trigger.
                    # Default-arg binding (not closure capture): re-defined each
                    # tick, so the CURRENT trigger socket/addrs are bound at
                    # definition time and B023 cannot bite.
                    def _resend_avio_living(
                            _tb=_trigger_bs,
                            _tsrc=_trigger_bsrc,
                            _tpeer=_trigger_peer) -> None:
                        import struct as _st_re2
                        import random as _r_re2
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
                            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                        for _rp in [_re_enc, _re_plain]:
                            if _rp is None:
                                continue
                            _rsz = len(_rp)
                            try:
                                _br_send_to_cam(
                                    _tb,
                                    bytes([0xC8, 0x00, _rsz >> 8, _rsz & 0xFF]) + _rp,
                                    _tsrc,
                                    _tpeer,
                                )
                            except Exception:
                                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)

                    # Periodic retrigger: resend AVIO LIVING every 2s until probe
                    # received (camera acknowledged our trigger).
                    if (_avio_living_sent
                            and not _sdes_probe_received
                            and _trigger_bs is not None
                            and _time_br.time() - _last_trigger_ts >= 2.0):
                        _resend_avio_living()
                        _last_trigger_ts = _time_br.time()

                    # Mid-session stall nudge: the camera episodically stops
                    # transmitting with no teardown signal (A001064, measured
                    # 2026-08-24/25), the serve's input then times out and the
                    # session dies - yet the camera answers a FRESH handshake
                    # immediately afterwards.  So before letting it die, re-send
                    # the LIVING that starts media.  The AVIO HEARTBEAT alone
                    # does not do this: heartbeats kept flowing right through
                    # measured stalls while the media stayed silent.  Bounded by
                    # _stall_nudge_due; the input timeout and the keepalive
                    # reopen remain the unchanged fallback.
                    if (_STALL_NUDGE_ENABLED
                            and _sdes_probe_received
                            and _trigger_bs is not None
                            and _media_progress[0] > 0.0):
                        _stall_silence = (
                            _time_br.monotonic() - _media_progress[0])
                        if _stall_silence <= _STALL_NUDGE_AFTER_S:
                            if _stall_active:
                                _stall_active = False
                                _stall_nudges_sent = 0
                                # Ask for an immediate IDR so recovery is not
                                # hostage to the 30s PLI cadence.
                                _bridge_fn._last_pli_ts = 0.0
                                _status(
                                    "SDES: media resumed after stall"
                                    " - PLI re-armed")
                        elif _stall_nudge_due(
                                silence_s=_stall_silence,
                                nudges_sent=_stall_nudges_sent,
                                since_last_nudge_s=(
                                    _time_br.time() - _stall_last_nudge),
                                stall_after_s=_STALL_NUDGE_AFTER_S):
                            _stall_active = True
                            _stall_nudges_sent += 1
                            _stall_last_nudge = _time_br.time()
                            _status(
                                f"SDES: no media for {_stall_silence:.1f}s"
                                f" - LIVING nudge {_stall_nudges_sent}/3")
                            _resend_avio_living()

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
                                            _br_av[4:8], _STUN_MAGIC_BR, strict=False)
                                    )
                                    _br_turn_peer_ip = '.'.join(
                                        str(b) for b in _br_xb)
                                    _br_turn_peer_port = _br_xp
                                elif _br_at == 0x0013:  # DATA
                                    _br_inner = _br_av
                            if _br_inner:
                                _bpkt = _br_inner

                        # When this packet came through our relay, _bsrc is the
                        # TURN server, not the camera.  Everything we send back
                        # in response therefore has to be wrapped in a Send
                        # indication addressed to the camera's real address -
                        # writing raw SRTP or AVIO bytes to the TURN server
                        # would be parsed as a malformed STUN message and
                        # dropped.  None when the camera reached us directly,
                        # which keeps the direct path byte-for-byte unchanged.
                        _br_cam_peer = (
                            (_br_turn_peer_ip, _br_turn_peer_port)
                            if _br_turn_peer_ip and _br_turn_peer_port
                            and not _is_self_peer_ip(_br_turn_peer_ip,
                                                     _br_turn_peer_port)
                            else None
                        )

                        if (len(_bpkt) >= 20
                                and _bpkt[4:8] == _STUN_MAGIC_BR
                                and _bpkt[:2] == b'\x00\x01'):
                            # STUN Binding Request - send Binding Success Response
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
                            # Learn where this probe actually came from.  The
                            # camera reached us from here, so this address is
                            # known-good in a way an advertised one is not.
                            # Relay-carried probes carry the camera's real
                            # address in XOR-PEER-ADDRESS; _bsrc is the TURN
                            # server and would be useless to nominate.
                            _br_obs = (
                                _br_cam_peer if _br_cam_peer
                                else (None if _bsrc[0] == _hp_host else _bsrc)
                            )
                            _br_prflx_was = _bridge_uc_info["prflx"]
                            _br_prflx_now = _record_peer_reflexive(
                                _bridge_uc_info["cands"], _br_prflx_was,
                                _br_obs, _is_self_peer_ip,
                            )
                            if _br_prflx_now is not _br_prflx_was:
                                # Rebind, never append: the nomination tick
                                # iterates this list.
                                _bridge_uc_info["prflx"] = _br_prflx_now
                                _status(
                                    f"ICE: learned peer-reflexive camera"
                                    f" candidate {_br_obs[0]}:{_br_obs[1]}"
                                    f" (not in the {len(_bridge_uc_info['cands'])}"
                                    f" advertised candidate(s)) - will nominate it"
                                )
                            # Record why this probe's source was, or was not,
                            # usable.  Both refusals above are silent, and which
                            # of them fired decides what a fix would change - so
                            # the fact is kept here and reported once, on the
                            # stall path, rather than logged per packet.
                            try:
                                _br_pv_where = f"{_bsrc[0]}:{_bsrc[1]}"
                                if _br_turn_peer_ip:
                                    _br_pv_where += (
                                        f" via {_br_turn_peer_ip}"
                                        f":{_br_turn_peer_port}"
                                    )
                                if _br_pv_where in _br_probe_verdicts:
                                    pass
                                elif len(_br_probe_verdicts) >= _MAX_PROBE_SOURCES:
                                    _br_probe_overflow.add(_br_pv_where)
                                    _bridge_fn._br_probe_overflow = len(
                                        _br_probe_overflow)
                                else:
                                    _br_probe_verdicts[_br_pv_where] = (
                                        _probe_source_verdict(
                                            _bsrc,
                                            _br_turn_peer_ip,
                                            _br_turn_peer_port,
                                            cam_peer=_br_cam_peer,
                                            observed=_br_obs,
                                            known=bool(
                                                _br_obs is not None
                                                and (_br_obs in _br_prflx_was
                                                     or _br_obs in
                                                     _bridge_uc_info["cands"])
                                            ),
                                            learned=(
                                                _br_prflx_now is not _br_prflx_was
                                            ),
                                        )
                                    )
                                    # Rebind, never mutate: the reader is the
                                    # main coroutine on another thread.
                                    _bridge_fn._br_probe_verdicts = dict(
                                        _br_probe_verdicts)
                            except Exception:
                                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_probe_source_verdict', exc_info=True)
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
                                        and not _is_self_peer_ip(
                                            _br_turn_peer_ip,
                                            _br_turn_peer_port)):
                                    # Arrived via TURN - respond via Send Indication
                                    _bri = _relay_addrs[_bs]
                                    _br_t_host, _br_t_port = _bri[4], _bri[5]
                                    _br_pip = bytes(
                                        int(x) for x in _br_turn_peer_ip.split('.')
                                    )
                                    _br_xip2 = bytes(
                                        a ^ b for a, b in zip(
                                            _br_pip, _STUN_MAGIC_BR, strict=False)
                                    )
                                    _br_xport2 = (
                                        _br_turn_peer_port ^ 0x2112) & 0xFFFF
                                    _br_xpa = (b'\x00\x01'
                                               + _st_br.pack('!H', _br_xport2)
                                               + _br_xip2)

                                    def _build_stun_attr(_t, _v):
                                        _p = (-len(_v)) % 4
                                        return (_st_br.pack('!HH', _t, len(_v))
                                                + _v + b'\x00' * _p)

                                    _br_si_body = (
                                        _build_stun_attr(0x0012, _br_xpa)
                                        + _build_stun_attr(0x0013, _bresp)
                                    )
                                    _br_send_ind = (
                                        b'\x00\x16'
                                        + _st_br.pack('!H', len(_br_si_body))
                                        + _STUN_MAGIC_BR + os.urandom(12)
                                        + _br_si_body
                                    )
                                    _bs.sendto(_br_send_ind, (_br_t_host, _br_t_port))
                                elif _br_turn_peer_ip and _is_self_peer_ip(
                                        _br_turn_peer_ip, _br_turn_peer_port):
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
                                    _bridge_fn._br_stun_resp_count = (
                                        _br_stun_resp_count)
                                # Late USE-CANDIDATE: send when answer arrived
                                # after bridge started (empty at setup time).
                                if not _bridge_uc_info["sent"] and _bridge_uc_info["ufrag"]:
                                    _bridge_uc_info["sent"] = True
                                    # Nominate BOTH the audio and video sockets, not
                                    # just the one that happened to receive this probe.
                                    # The early (answer-in-time) path nominates both;
                                    # the late path previously nominated only _bs (the
                                    # socket with the first BindingReq, typically audio),
                                    # so the video pair was never nominated and the
                                    # camera never started video RTP (audio/control
                                    # recovered, video stayed dark).
                                    for _br_ci, _br_cp in _bridge_uc_info["cands"]:
                                        for _uc_sock, _uc_ufrag, _uc_pwd in (
                                            (_audio_sock, _ufrag_a, _pwd_a),
                                            (_video_sock, _ufrag_v, _pwd_v),
                                        ):
                                            try:
                                                _send_use_candidate(
                                                    _uc_sock, _uc_ufrag, _uc_pwd,
                                                    _bridge_uc_info["ufrag"],
                                                    _bridge_uc_info["pwd"],
                                                    (_br_ci, _br_cp),
                                                )
                                            except Exception:
                                                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                                    _status(
                                        f"bridge: late USE-CANDIDATE sent (audio+video) to"
                                        f" {len(_bridge_uc_info['cands'])} camera candidate(s)"
                                        " (answer arrived after bridge started)"
                                    )
                            except Exception:
                                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                        elif len(_bpkt) >= 20 and _bpkt[4:8] == _STUN_MAGIC_BR:
                            # CreatePermission response from the TURN server.
                            # 0x0108 = success (the relay door is open for that
                            # peer); 0x0118 = error.  438 Stale Nonce is routine
                            # and recoverable: the server hands back a fresh
                            # NONCE, so adopt it and retry once.  401 means the
                            # credentials themselves are wrong, which is worth a
                            # warning because the relay stays shut.
                            if _bpkt[:2] in (b'\x01\x08', b'\x01\x18',
                                             b'\x01\x04', b'\x01\x14'):
                                _cp_err = 0
                                _cp_new_nonce = b''
                                _cp_i = 20
                                _cp_end = min(
                                    20 + _st_br.unpack('!H', _bpkt[2:4])[0],
                                    len(_bpkt),
                                )
                                while _cp_i + 4 <= _cp_end:
                                    _cp_at, _cp_al = _st_br.unpack_from(
                                        '!HH', _bpkt, _cp_i)
                                    _cp_v = _bpkt[_cp_i + 4:_cp_i + 4 + _cp_al]
                                    if _cp_at == 0x0009 and len(_cp_v) >= 4:
                                        _cp_err = _cp_v[2] * 100 + _cp_v[3]
                                    elif _cp_at == 0x0015:
                                        _cp_new_nonce = _cp_v
                                    _cp_i += 4 + _cp_al + ((-_cp_al) % 4)
                                _cp_what = ("CreatePermission"
                                            if _bpkt[1] == 0x08 else "Refresh")
                                if _bpkt[:2] in (b'\x01\x08', b'\x01\x04'):
                                    _cp_seen = f"_cp_ok_logged_{_cp_what}"
                                    if not getattr(_bridge_fn, _cp_seen, False):
                                        setattr(_bridge_fn, _cp_seen, True)
                                        _status(
                                            f"TURN: {_cp_what} confirmed by"
                                            f" server (success)"
                                        )
                                elif _cp_err == 438 and _cp_new_nonce:
                                    _cp_old = _relay_addrs.get(_bs)
                                    if _cp_old and len(_cp_old) >= 8:
                                        _relay_addrs[_bs] = (
                                            *_cp_old[:3], _cp_new_nonce,
                                            *_cp_old[4:],
                                        )
                                        _trace(
                                            f"TURN: stale nonce on {_cp_what}"
                                            " - refreshed and retrying"
                                        )
                                        # Re-arm both gates: whichever request
                                        # hit the stale nonce, the fresh one
                                        # should be used immediately.
                                        _br_last_perm = 0.0
                                        _br_perm_cands = ()
                                        _br_last_alloc_refresh = 0.0
                                else:
                                    _status(
                                        f"TURN: {_cp_what} rejected"
                                        f" (error {_cp_err or 'unknown'}) -"
                                        f" relay path unusable"
                                    )
                                continue
                            # Count the inbound Binding Success BEFORE the
                            # trigger gate below.  Counting inside it would make
                            # this an alias for _tutk_trigger_sent and collapse
                            # two different diagnoses - "none ever arrived" and
                            # "one arrived and the trigger still did not go" -
                            # into a single indistinguishable state.
                            # Transport liveness: the camera's binding
                            # successes and keepalive indications both stop the
                            # instant its ICE agent tears down, which is what
                            # tells a teardown apart from a media pause.
                            if _bpkt[:2] in (b'\x01\x01', b'\x00\x11'):
                                _ice_progress[0] = _time_br.monotonic()
                            if _bpkt[:2] == b'\x01\x01':
                                _br_binding_success_count += 1
                                _bridge_fn._br_binding_success_count = (
                                    _br_binding_success_count)
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
                                _bridge_fn._tutk_trigger_sent = True
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
                                    _padded  = _pad_tk(_avio_plain, 16)  # PKCS#7 -> 64B
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
                                        _br_send_to_cam(_bs, _pkt, _bsrc, _br_cam_peer)
                                        _status(
                                            f"SDES: sent trigger ({_label})"
                                            f" len={_sz}"
                                            f" -> {_bsrc[0]}:{_bsrc[1]}"
                                        )
                                    except Exception:
                                        _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_persistent_sdes_cmd', exc_info=True)
                                _avio_living_sent = True
                                _last_trigger_ts = _time_br.time()
                                _trigger_bs   = _bs
                                _trigger_bsrc = _bsrc
                                _trigger_peer = _br_cam_peer

                                # Camera is SCTP initiator (a=setup:active).
                                # Be pure SCTP server: wait for camera's INIT,
                                # reply INIT-ACK, wait for COOKIE-ECHO, then send data.
                                if _dc_answer_has_app:
                                    _status(
                                        "SDES DC: m=application present"
                                        " - waiting for camera SCTP INIT"
                                        f" our_key={_key_fingerprint(_our_tx_srtp_key_audio)}"
                                        f" cam_key={_key_fingerprint(_cam_key_audio)}"
                                    )
                        else:
                            # Non-STUN packet - demux by first byte.
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
                            # Camera is a=setup:active (SCTP client - initiates INIT).
                            # We are SCTP server: wait for camera's INIT, reply INIT-ACK,
                            # then complete: COOKIE-ECHO -> COOKIE-ACK ->
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
                                            _br_send_to_cam(_bs, _ack_pkt, _bsrc, _br_cam_peer)
                                            _status(
                                                f"SDES DC: camera sent SCTP INIT"
                                                f" (peer_tag=0x{peer_tag:08x})"
                                                f" - sent INIT-ACK"
                                            )
                                        except Exception as _iae:
                                            _status(f"SCTP INIT-ACK failed: {_iae}")
                                elif st in ('INIT_SENT', 'COOKIE_WAIT'):
                                    cookie = _sctp_parse_init_ack(_bpkt, _sctp)
                                    if cookie:
                                        _sctp['state'] = 'COOKIE_ECHOED'
                                        try:
                                            _br_send_to_cam(_bs, _sctp_cookie_echo(cookie), _bsrc, _br_cam_peer)
                                            _status(
                                                f"SDES DC: plain INIT-ACK"
                                                f" (cookie {len(cookie)}B)"
                                                f" -> sent COOKIE-ECHO"
                                            )
                                        except Exception as _sce:
                                            _status(f"SCTP COOKIE-ECHO failed: {_sce}")
                                    else:
                                        _status("SDES DC: plain SCTP pkt in INIT_SENT/COOKIE_WAIT"
                                                " - parse_init_ack found no cookie")
                                elif st == 'COOKIE_ECHOED':
                                    # Any SCTP packet (COOKIE-ACK = type 0x0B) signals
                                    # SCTP is established.
                                    _sctp['state'] = 'ESTABLISHED'
                                    _status("SDES DC: SCTP COOKIE-ACK - DataChannel OPEN")
                                    try:
                                        _sctp_send_living(_bs, _bsrc)
                                    except Exception as _sle:
                                        _LOGGER.warning("SDES DC: send living failed: %s",
                                                        _sle)
                                elif st == 'DONE':
                                    pass  # ignore further SCTP (SACKs etc.)
                                continue
                            # Log DTLS packets (first byte 0x14-0x17) if they arrive.
                            # Camera is a=setup:active (DTLS client) - if it sends
                            # DTLS ClientHello, we'd see 0x16 here.
                            if len(_bpkt) >= 4 and 0x14 <= _bpkt[0] <= 0x17:
                                _trace(
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
                                    _trace(
                                        f"bridge: non-0xC8 after DONE:"
                                        f" {len(_bpkt)}B byte0=0x{_bpkt[0]:02x}"
                                        f" {_bpkt[:24].hex()}"
                                    )
                            if len(_bpkt) >= 1 and _bpkt[0] in (0xC8, 0xC9):
                                if not hasattr(_bridge_fn, '_c8_raw_count'):
                                    _bridge_fn._c8_raw_count = 0
                                _bridge_fn._c8_raw_count += 1
                                if _bridge_fn._c8_raw_count <= 10:
                                    _sdes_k_fp = _key_fingerprint(_our_tx_srtp_key_audio)
                                    _sdes_v_fp = _key_fingerprint(
                                        _cam_key_audio or _our_tx_srtp_key_audio)
                                    _trace(
                                        f"bridge: RAW 0x{_bpkt[0]:02x} {len(_bpkt)}B"
                                        f" #{_bridge_fn._c8_raw_count}"
                                        f" our_key={_sdes_k_fp}"
                                        f" cam_key={_sdes_v_fp}"
                                        f" [{_bpkt[:24].hex()}]"
                                    )
                            # TUTK SFrame detection (A001064 / _use_plain_rtp):
                            # The camera sends TUTK-framed data instead of SRTP.
                            # Wire-capture analysis (2026-05-02) confirmed:
                            #   byte0=0xC8 -> TUTK audio SFrame
                            #   byte0=0xC9 -> TUTK video SFrame (expected)
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
                                # Guard on a counter that is actually assigned.
                                # This used to test `_tutk_seq`, a name nothing
                                # ever set, so hasattr was False on EVERY packet
                                # and both counters were reset to 0 each time -
                                # every synthesized packet went out with
                                # sequence number 1.  ffmpeg reads a constant
                                # sequence as a stream of discontinuities and
                                # reports `RTP: missed N packets` for loss that
                                # never happened.
                                if not hasattr(_bridge_fn, '_tutk_seq_v'):
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
                                    _trace(
                                        f"bridge: TUTK {_kind} SFrame"
                                        f" type=0x{_tk_type:02x} ssrc={_tk_ssrc}"
                                        f" ts={_tk_ts} payload={len(_tk_payload)}B"
                                        f" #{_bridge_fn._tutk_count} (+{_elapsed:.1f}s)"
                                    )
                                    if _bridge_fn._tutk_count <= 5:
                                        _trace(
                                            f"bridge: TUTK raw"
                                            f" type=0x{_tk_type:02x}"
                                            f" ts={_tk_ts} ssrc=0x{_tk_ssrc:08x}"
                                            f" payload={len(_tk_payload)}B"
                                            f" [{_tk_payload[:32].hex()}]"
                                        )
                                        if _pd_plain is not None:
                                            _trace(
                                                f"bridge: TUTK decrypt ->"
                                                f" {len(_pd_plain)}B"
                                                f" [{_pd_plain[:32].hex()}]"
                                            )
                                # -- Encrypted SCTP state machine (SDES path) --
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
                                        # Camera SCTP INIT (or retransmit) -> send encrypted INIT-ACK.
                                        # Handle retransmits in COOKIE_WAIT: re-send INIT-ACK
                                        # (our first may have been lost).
                                        _sc_p = _sctp_parse_init(_pd_plain)
                                        if _sc_p:
                                            try:
                                                _iak_plain = _sctp_init_ack_pkt()
                                                _iak_bytes = _enc_c8_sctp(_iak_plain)
                                                _br_send_to_cam(_bs, _iak_bytes, _bsrc, _br_cam_peer)
                                                _sctp['state'] = 'COOKIE_WAIT'
                                                _status(
                                                    f"SDES DC: INIT(peer=0x{_sc_p:08x})"
                                                    f" -> INIT-ACK {len(_iak_bytes)}B"
                                                    f" to {_bsrc[0]}:{_bsrc[1]}"
                                                    f" plain[{len(_iak_plain)}B]="
                                                    f"{_iak_plain[:32].hex()}"
                                                )
                                            except Exception as _sce8:
                                                _status(f"SDES DC: enc INIT-ACK err: {_sce8}")
                                    elif _pd_ct8 == 0x02 and _sct in ('INIT_SENT', 'COOKIE_WAIT'):
                                        # Camera SCTP INIT-ACK -> send encrypted COOKIE-ECHO
                                        _sc_ck = _sctp_parse_init_ack(_pd_plain, _sctp)
                                        if _sc_ck:
                                            try:
                                                _br_send_to_cam(_bs, _enc_c8_sctp(_sctp_cookie_echo(_sc_ck)), _bsrc, _br_cam_peer)
                                                _sctp['state'] = 'COOKIE_ECHOED'
                                                _status(
                                                    f"SDES DC: enc INIT-ACK"
                                                    f" (cookie {len(_sc_ck)}B)"
                                                    f" -> sent enc COOKIE-ECHO"
                                                )
                                            except Exception as _sce8:
                                                _status(f"SDES DC: enc COOKIE-ECHO err: {_sce8}")
                                    elif _pd_ct8 == 0x0A and _sct in ('COOKIE_WAIT', 'COOKIE_ECHOED'):
                                        # Camera COOKIE-ECHO -> send COOKIE-ACK + DCEP_OPEN,
                                        # then wait 300ms before sending LIVING (PPID=53).
                                        # Without DCEP_OPEN (PPID=50), LIVING arrives on an
                                        # unregistered stream and is silently discarded by the
                                        # camera's SCTP application layer (SACK confirms transport
                                        # delivery, but no audio/video results). The DTLS path in
                                        # client.py (the COOKIE-ECHO/COOKIE-ACK + DCEP_OPEN handler)
                                        # does exactly this sleep - required.
                                        try:
                                            _cak8 = _sctp_pkt(_sctp['peer_tag'], _sctp_chunk(0x0B, 0, b''))
                                            _br_send_to_cam(_bs, _enc_c8_sctp(_cak8), _bsrc, _br_cam_peer)
                                            _dc8 = _sctp_data(50, _dcep_open_msg())
                                            _br_send_to_cam(_bs, _enc_c8_sctp(_sctp_pkt(_sctp['peer_tag'], _dc8)), _bsrc, _br_cam_peer)
                                            _sctp['state'] = 'DCEP_WAIT'
                                            _sctp['dcep_sent_ts'] = _time_br.time()
                                            _sctp['dcep_sock'] = _bs
                                            _sctp['dcep_src'] = _bsrc
                                            _status(
                                                "SDES DC: COOKIE-ECHO"
                                                " -> COOKIE-ACK + DCEP_OPEN(50),"
                                                " waiting 300ms before LIVING"
                                            )
                                        except Exception as _sce8:
                                            _status(f"SDES DC: enc COOKIE-ACK err: {_sce8}")
                                    elif _pd_ct8 == 0x0B and _sct == 'COOKIE_ECHOED':
                                        # Camera COOKIE-ACK -> send encrypted LIVING only
                                        try:
                                            _lv8 = _sctp_data(53, _session_mode_req_msg())
                                            _br_send_to_cam(_bs, _enc_c8_sctp(_sctp_pkt(_sctp['peer_tag'], _lv8)), _bsrc, _br_cam_peer)
                                            _sctp['state'] = 'DONE'
                                            _sdes_probe_received = True
                                            _last_hb_ts = _time_br.time()
                                            _status("SDES DC: enc COOKIE-ACK -> sent enc LIVING")
                                        except Exception as _sce8:
                                            _status(f"SDES DC: enc LIVING err: {_sce8}")
                                    elif _pd_ct8 == 0x00 and _sct == 'DONE':
                                        # SCTP DATA from camera.  ACKNOWLEDGE IT
                                        # FIRST: SCTP puts acknowledgement on the
                                        # receiver, and sending nothing let the
                                        # camera's retransmission timer run out and
                                        # ABORT the association at ~61.4 s, which is
                                        # what produced the 80.2 s cliff and what
                                        # stopped PTZ/talkback/SD answering a minute
                                        # into every session.  Ack before dispatch so
                                        # a handler that raises cannot cost us the ack.
                                        if len(_pd_plain) >= 20:
                                            _sc_tsn = int.from_bytes(_pd_plain[16:20], 'big')
                                            _sc_first_sack = _sctp.get('peer_cum_tsn') is None
                                            _sctp['peer_cum_tsn'] = _sctp_advance_cum_tsn(
                                                _sctp.get('peer_cum_tsn'), _sc_tsn)
                                            if _sc_first_sack:
                                                # One line per session: the build tag for the
                                                # SACK fix, and the thing to look for if the
                                                # 61.4 s ABORT ever comes back.
                                                _status(
                                                    f"SDES DC: SACK enabled"
                                                    f" - acking camera DATA from"
                                                    f" TSN={_sc_tsn:#010x}"
                                                )
                                            try:
                                                _br_send_to_cam(
                                                    _bs,
                                                    _enc_c8_sctp(_sctp_pkt(
                                                        _sctp['peer_tag'],
                                                        _sctp_sack_chunk(_sctp['peer_cum_tsn']))),
                                                    _bsrc, _br_cam_peer)
                                            except Exception as _sackerr:
                                                _status(f"SDES DC: SACK send failed: {_sackerr}")
                                        # Reassemble before parsing.  A DATA chunk
                                        # carries B/E flags (RFC 4960 s3.3.1) and a
                                        # large reply - the ~2.8 KB SD listing page -
                                        # arrives as several ~1.2 KB fragments.  Taking
                                        # each one for a whole AVIO frame got the first
                                        # rejected (declared length overruns the
                                        # fragment) and the rest read as junk commands,
                                        # so the reply was reported as "the camera did
                                        # not answer".  Use the chunk's own length
                                        # rather than the rest of the packet: the
                                        # declared length is what bounds this chunk.
                                        _sc_flags = _pd_plain[13] if len(_pd_plain) > 13 else 0x03
                                        _sc_clen = (int.from_bytes(_pd_plain[14:16], 'big')
                                                    if len(_pd_plain) >= 16 else 0)
                                        _sc_sid = (int.from_bytes(_pd_plain[20:22], 'big')
                                                   if len(_pd_plain) >= 22 else 0)
                                        _sc_frag = (_pd_plain[28:28 + (_sc_clen - 16)]
                                                    if _sc_clen >= 16 and len(_pd_plain) > 28
                                                    else (_pd_plain[28:] if len(_pd_plain) > 28 else b''))
                                        _sc_ppid = (int.from_bytes(_pd_plain[24:28], 'big')
                                                    if len(_pd_plain) >= 28 else 0)
                                        _sc_pay = _sctp_reassemble(
                                            _sc_flags, _sc_sid, _sc_frag,
                                            _sctp.setdefault('rx_frag', {}))
                                        # A mid-message fragment: nothing to parse yet.
                                        # Its TSN is acknowledged above, so the camera
                                        # will not retransmit it.  Guarded rather than
                                        # `continue`d - the nearest enclosing loop is the
                                        # per-socket one, and skipping it would drop the
                                        # rest of this socket's turn.
                                        if _sc_pay is not None:
                                            _sc_cmd = (int.from_bytes(_sc_pay[4:8], 'little')
                                                       if len(_sc_pay) >= 8 else 0)
                                            # This is where the camera's answers
                                            # come back on SDES.  They were parsed
                                            # and logged here long before anything
                                            # could receive them; hand them to
                                            # whoever asked.
                                            if _sc_cmd == 5377:
                                                # SESSION_MODE_RESP: the camera's
                                                # answer to the LIVING trigger.
                                                # Counted whether or not anything
                                                # was waiting for it, because the
                                                # question the stall report asks is
                                                # "did the trigger arrive", and the
                                                # trigger is fire-and-forget.
                                                _bridge_fn._br_session_mode_resp = (
                                                    getattr(
                                                        _bridge_fn,
                                                        '_br_session_mode_resp', 0) + 1)
                                            _sc_answered = _dispatch_sctp_avio(
                                                _avio_responses, _sc_pay)
                                            _trace(
                                                f"SDES DC: enc DATA ppid={_sc_ppid}"
                                                f" cmd={_sc_cmd} {len(_sc_pay)}B"
                                                f"{' (answered a request)' if _sc_answered else ''}"
                                                f" {_sc_pay[:32].hex()}"
                                            )
                                    else:
                                        # Log SACK (0x03) with cumulative TSN ack for diagnostics
                                        if _pd_ct8 == 0x03 and len(_pd_plain) >= 20:
                                            _cum_tsn = int.from_bytes(_pd_plain[16:20], 'big')
                                            _trace(
                                                f"SDES DC: SACK cum_tsn={_cum_tsn:#010x}"
                                                f" state={_sct}"
                                            )
                                        else:
                                            _trace(
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
                                    # Hoisted purely so the SRTP-TX-KEY note can
                                    # report the key that actually went out.
                                    # Same expression - no behavior change.
                                    _rr_key_b64 = (
                                        _cam_key_audio or _our_tx_srtp_key_audio)
                                    try:
                                        import pylibsrtp as _plsrtp_rr
                                        import base64 as _b64_rr
                                        _rr_key = _b64_rr.b64decode(_rr_key_b64)
                                        _rr_pol = _plsrtp_rr.Policy(
                                            key=_rr_key,
                                            ssrc_type=_plsrtp_rr.Policy.SSRC_SPECIFIC,
                                            ssrc_value=_rr_our_ssrc,
                                            srtp_profile=_plsrtp_rr.Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
                                        )
                                        _rr_pol.allow_repeat_tx = True
                                        _rr_sess = _plsrtp_rr.Session(policy=_rr_pol)
                                        _br_send_to_cam(_bs, _rr_sess.protect_rtcp(_rr_pkt), _bsrc, _br_cam_peer)
                                        _rtcp_sent = True
                                    except Exception:
                                        _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_persistent_sdes_cmd', exc_info=True)
                                    if not _rtcp_sent:
                                        try:
                                            _br_send_to_cam(_bs, _rr_pkt, _bsrc, _br_cam_peer)
                                        except Exception:
                                            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_enc_c8_sctp', exc_info=True)
                                    if _bridge_fn._tutk_count == 1:
                                        _status(
                                            f"SDES: sent RTCP RR to camera"
                                            f" (SSRC=0x{_tk_ssrc:08x})"
                                        )
                                    # Re-noted whenever the selected key changes,
                                    # not just on the first RR: this branch
                                    # rebuilds its SRTP session from the current
                                    # expression on every packet, and
                                    # _cam_key_audio can be set after the bridge
                                    # is already running (late-wake answer
                                    # parse), so the RR key does flip mid-session
                                    # on battery cameras.  A first-send-only note
                                    # would have recorded "answer=none differ=no"
                                    # for exactly that session.  Bounded: the
                                    # answer key is only ever set once.
                                    if (_rtcp_sent and getattr(
                                            _bridge_fn, '_rr_key_noted', None)
                                            != _rr_key_b64):
                                        _bridge_fn._rr_key_noted = _rr_key_b64
                                        _status(_srtp_tx_key_note(
                                            "RR", _rr_key_b64,
                                            _our_tx_srtp_key_audio,
                                            _cam_key_audio))
                                # Forward decrypted PCMA audio to ffmpeg loopback.
                                # AVIO control frames (SESSION_MODE_RESP=5377, etc.) are
                                # identified by cmd field and skipped; raw PCMA bytes are sent.
                                if _tk_audio and _pd_plain is not None:
                                    _fwd_cmd = (int.from_bytes(_pd_plain[4:8], 'little')
                                                if len(_pd_plain) >= 8 else 0)
                                    # AVIO control frames identified by cmd field - never
                                    # forward these to ffmpeg's audio port.  804 =
                                    # LdsTrackSwitchNotify (device->client track-id change,
                                    # f0.java:3224): the camera can send it unsolicited, and
                                    # without it here an 804 frame is misrouted as PCMA noise.
                                    _avio_cmds = {5376, 5377, 5156, 5157, 768, 769, 511, 804}
                                    # No response dispatch here.  Measured
                                    # 2026-08-07: the camera's replies come back
                                    # as encrypted SCTP DATA (see
                                    # _dispatch_sctp_avio), never in this
                                    # framing.  Offering every audio packet to
                                    # the router would be per-packet work on the
                                    # media path for something that has never
                                    # arrived on it.
                                    if _fwd_cmd not in _avio_cmds:
                                        try:
                                            _lo_a.sendto(
                                                _rtp_hdr + _pd_plain,
                                                ('127.0.0.1', _lo_audio_port),
                                            )
                                            # Count it: media_stats() documents
                                            # itself as "media actually forwarded
                                            # to ffmpeg by the bridge", and
                                            # scripts/live_validate.py uses it as
                                            # the SDES release gate.  This is a
                                            # real forward, so omitting it made a
                                            # camera whose audio arrives on the
                                            # TUTK path under-report - far enough
                                            # to fail an otherwise healthy release.
                                            _media_progress[0] = _time_br.monotonic()
                                            _media_counts[0] += 1
                                            _media_counts[1] += len(_rtp_hdr) + len(_pd_plain)
                                            if not _br_first_audio_logged:
                                                _br_first_audio_logged = True
                                                # Record the payload type this path
                                                # SYNTHESISES (_tk_pt, PCMA) so the
                                                # SDP can be narrowed to it.  Without
                                                # this the m=audio line keeps
                                                # advertising "0 8", ffmpeg binds
                                                # PCMU and discards every packet, and
                                                # the mpegts PMT is never written - so
                                                # the consumer gets zero bytes and the
                                                # VIDEO is lost with the audio.
                                                _first_audio_pt[0] = _tk_pt
                                                _status(
                                                    f"bridge: first SDES audio -> ffmpeg"
                                                    f" loopback:{_lo_audio_port}"
                                                    f" ({len(_pd_plain)}B PCMA)"
                                                    f" pt={_tk_pt}"
                                                )
                                        except Exception:
                                            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_enc_c8_sctp', exc_info=True)
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
                                    " first4=%s (PT=%d) - camera switched to SRTP",
                                    len(_bpkt), _bsrc[0], _bsrc[1],
                                    _bpkt[:4].hex(),
                                    (_bpkt[1] & 0x7F) if len(_bpkt) > 1 else -1,
                                )
                            _pt_byte = _bpkt[1] if len(_bpkt) > 1 else 0
                            if _pt_byte < 200 or _pt_byte > 204:
                                # Every inbound RTP packet, counted BEFORE any
                                # decryption decision. The media counters are
                                # deliberately gated on the packet being
                                # readable, so a session where the camera sent
                                # plenty and none of it could be decrypted has,
                                # until here, been indistinguishable from one
                                # where it sent nothing. Read only by the stall
                                # report, on a path a healthy open never takes.
                                _bridge_fn._br_media_pkts = getattr(
                                    _bridge_fn, '_br_media_pkts', 0) + 1
                            if 200 <= _pt_byte <= 204:
                                # SRTCP from camera.  For _use_plain_rtp cameras
                                # the ffmpeg SDP uses RTP/AVP (no crypto).  If we
                                # forward encrypted SRTCP, ffmpeg reads the
                                # encrypted NTP/RTP sender-info bytes as garbage
                                # and uses them to rebase its internal clock,
                                # producing wildly wrong DTS (~ Unix epoch us).
                                # Drop encrypted SRTCP entirely; ffmpeg works fine
                                # without RTCP SR - it uses only RTP timestamps.
                                if _use_plain_rtp:
                                    continue
                                # For SDES cameras (non-plain-rtp) ffmpeg uses
                                # SAVP and handles SRTCP itself - forward as-is.
                                try:
                                    _lo_a.sendto(_bpkt, ('127.0.0.1', _lo_audio_port))
                                except Exception:
                                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                                try:
                                    _lo_v.sendto(_bpkt, ('127.0.0.1', _lo_video_port))
                                except Exception:
                                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                                continue
                            _pt = _pt_byte & 0x7F
                            # The ANSWER decides which payload type is which
                            # kind; the tuples below are only the fallback for a
                            # packet that beats the answer in.  See
                            # answer_pt_kinds: this camera negotiates H265 on
                            # pt=0 in ~14% of sessions and the fixed tuples sent
                            # every one of those video streams to the AUDIO
                            # loopback.
                            _kind_answered = _answer_pt_kinds.get(_pt)
                            _pt_out = _pt
                            if _kind_answered == "video":
                                _btgt, _lo_target, _kind = (
                                    _lo_video_port, _lo_v, "video"
                                )
                                # The bridge starts before the answer lands, so
                                # a video packet on an unexpected PT can beat the
                                # map in by a few hundred ms and latch as the
                                # session's "first audio".  Left alone that
                                # narrows the serve's audio line to a payload
                                # type no audio uses, and the mpegts mux then
                                # withholds PAT/PMT waiting for a stream that
                                # never produces - costing the picture, not just
                                # the sound.  Undo it and let real audio latch.
                                if _first_audio_pt[0] == _pt:
                                    _first_audio_pt[0] = None
                                    _br_first_audio_logged = False
                                    _status(
                                        "bridge: pt=%d re-classified as video"
                                        " from the answer - clearing the audio"
                                        " latch it took first" % _pt)
                                # Our serve SDP describes video as 96=H264 /
                                # 97=H265 only, so a camera-numbered payload
                                # type we do not advertise must be translated
                                # into our numbering before ffmpeg sees it -
                                # the same translation video_pt_from_answer_sdp
                                # already performs for the SDP side ("the
                                # camera's own numbering need not agree").
                                # Gated on _use_plain_rtp because only there is
                                # the bridge the decryptor and the packet
                                # reaching ffmpeg plaintext; rewriting a byte
                                # ffmpeg will itself authenticate breaks SRTP.
                                if (_pt not in _SDP_VIDEO_PTS
                                        and _use_plain_rtp
                                        and _answer_video_pt[0] is not None):
                                    _pt_out = int(_answer_video_pt[0])
                            elif _kind_answered == "audio":
                                _btgt, _lo_target, _kind = (
                                    _lo_audio_port, _lo_a, "audio"
                                )
                            elif _pt in (96, 97, 98):
                                _btgt, _lo_target, _kind = (
                                    _lo_video_port, _lo_v, "video"
                                )
                            elif _pt in (0, 8):
                                _btgt, _lo_target, _kind = (
                                    _lo_audio_port, _lo_a, "audio"
                                )
                            else:
                                # Unknown PT - fall back to source-socket routing.
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
                                    f" -> {_kind} loopback:{_btgt}"
                                    f"  byte0=0x{_b0:02x} byte1=0x{_pt_byte:02x}"
                                    f" seq={_seq16} ts={_ts32}"
                                    f" ssrc={_ssrc32}"
                                    f" len={len(_bpkt)}"
                                    f" hex24={_hex24}"
                                )
                            if _kind == "audio" and not _br_first_audio_logged:
                                _br_first_audio_logged = True
                                _first_audio_pt[0] = _pt
                                _status(f"bridge: first audio RTP pt={_pt}")
                                # Capture the camera's audio return address so the talk
                                # pump (SdesSession.async_start_talk) can send outbound
                                # PCMA there.  Only meaningful on a talk-capable open
                                # (offer advertised sendrecv + a=ssrc); harmless otherwise.
                                # Guarded so a video-first capture (BUNDLE) is not lost.
                                if _talk_state is not None and _talk_state.get("src") is None:
                                    _talk_state["src"]  = _bsrc
                                    _talk_state["sock"] = _bs
                                    _status(
                                        f"SDES talk: camera audio addr captured"
                                        f" {_bsrc[0]}:{_bsrc[1]} (talk pump armed)"
                                    )
                            elif _kind == "video" and not _br_first_video_logged:
                                _br_first_video_logged = True
                                # _pt_out, not _pt: everything downstream (the
                                # serve SDP narrowing, _serve_video_pt's
                                # "observed beats pinned") speaks OUR numbering,
                                # and the wire PT is preserved in the log line.
                                _first_video_pt[0] = _pt_out
                                _status(
                                    f"bridge: first video RTP pt={_pt_out}"
                                    + (f" (camera numbered it {_pt})"
                                       if _pt_out != _pt else ""))
                                # At INFO, not DEBUG: this is the one line that
                                # makes a bitrate figure comparable to another
                                # one, and it is emitted once per session.
                                _LOGGER.info(
                                    "camera %s: video profile %s",
                                    getattr(self, "device_id", "?"),
                                    describe_video_profile(_pt_out),
                                )
                                # Camera answers BUNDLE (all media on one 5-tuple),
                                # so the talk destination is the same address as
                                # video.  Capture it here too - the camera may send
                                # video first (or send no inbound audio at all), so
                                # gating talk on first-audio alone is unreliable.
                                if _talk_state is not None and _talk_state.get("src") is None:
                                    _talk_state["src"]  = _bsrc
                                    _talk_state["sock"] = _bs
                                    _status(
                                        f"SDES talk: camera media addr captured"
                                        f" {_bsrc[0]}:{_bsrc[1]} (talk pump armed)"
                                    )
                                # Capture camera video SSRC for RTCP PLI.
                                if len(_bpkt) >= 12:
                                    _bridge_fn._cam_video_ssrc = _st_br.unpack_from(
                                        '!I', _bpkt, 8)[0]
                                if _media_path[0] is None:
                                    _media_path[0] = _classify_media_path(
                                        _bsrc[0], _bridge_turn_ips)
                                _bridge_fn._cam_srtp_src  = _bsrc
                                _bridge_fn._cam_srtp_sock = _bs
                                if getattr(_bridge_fn, '_first_video_ts',
                                           None) is None:
                                    _bridge_fn._first_video_ts = _time_br.time()
                                # Publish the relay-aware sender so the RTCP
                                # cadence blocks (which have no socket/peer in
                                # scope) can reach the camera the way the NACK
                                # does.  This branch runs ONCE per session (it
                                # sits inside the first-video gate), so the
                                # sender is frozen at the first video packet's
                                # source - the same adoption `_cam_srtp_src`
                                # has always used.  A 1 Hz cadence send to a
                                # stale address after a mid-session address
                                # change just drops; the NACK path keeps its
                                # own per-event binding for exactly that case.
                                _bridge_fn._send_to_cam = (
                                    lambda _d, _s=_bs, _a=_bsrc,
                                    _p=_br_cam_peer: _br_send_to_cam(
                                        _s, _d, _a, _p))
                                # Schedule immediate PLI so IDR+SPS arrives in
                                # the analyzeduration window.
                                _bridge_fn._last_pli_ts = 0.0
                                # Resolve the NACK switch ONCE per session: the
                                # per-packet path runs ~300x/s per camera and
                                # os.environ.get costs ~250ns of it.  A flip
                                # now takes effect on the next stream open.
                                _bridge_fn._nack_on = _sdes_nack_enabled()
                                # Same reason, same place: the RTCP cadence
                                # below sits on this loop, so its switches are
                                # resolved once here rather than read from the
                                # environment ~300x/s.  A flip takes effect on
                                # the next stream open, as the NACK switch does.
                                _bridge_fn._tmmbr_bps = _sdes_tmmbr_bps()
                                _bridge_fn._tmmbr_after_s = _sdes_tmmbr_after_s()
                            # For TUTK cameras (_use_plain_rtp) the ffmpeg SDP uses
                            # RTP/AVP (no crypto). After LIVING the camera switches
                            # from TUTK SFrames to standard SRTP, so we decrypt here
                            # before forwarding plain RTP to ffmpeg.
                            _fwd_pkt = _bpkt
                            # Whether _fwd_pkt is plaintext by the time anything
                            # below reads its PAYLOAD. False until something has
                            # actually decrypted it: forwarding ciphertext is
                            # inert (ffmpeg discards it), but MINING it is not -
                            # see _should_capture_sprop.
                            _decrypted = False
                            if _use_plain_rtp:
                                # srtp_key_audio, not _cam_key_audio: the
                                # second-webrtcResp handler adopts the camera's
                                # real key into srtp_key_audio (this is a live
                                # closure cell, so the rebind is visible here)
                                # and leaves _cam_key_audio at the first answer's
                                # value.  Preferring _cam_key_audio pinned the
                                # bridge - the only decryptor on this path - to a
                                # key the camera had stopped using.
                                _rx_sess = _ensure_srtp_rx_session(
                                    _bridge_fn, srtp_key_audio, _build_srtp_rx,
                                    on_built=_on_srtp_rx_built,
                                    on_error=_on_srtp_rx_error,
                                )
                                if _rx_sess is not None:
                                    try:
                                        _fwd_pkt = _rx_sess.unprotect(_bpkt)
                                        _decrypted = True
                                    except Exception as _srx_dec_e:
                                        # Uncapped, unlike the log counter below
                                        # which stops at 8 to keep the log
                                        # readable. The stall report needs the
                                        # real total: "8 failures" and "every
                                        # packet failed" are different findings.
                                        _bridge_fn._br_decrypt_fails = getattr(
                                            _bridge_fn, '_br_decrypt_fails', 0) + 1
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
                                            _trace(
                                                f"bridge: SRTP decrypt err:"
                                                f" {_srx_dec_e}"
                                                f" seq={_seq_d}"
                                                f" ssrc=0x{_ssrc_d:08x}"
                                                f" pt={_pt}"
                                            )
                            # Capture this camera's SPS/PPS once so future streams
                            # can inject sprop-parameter-sets (out-of-band decoder
                            # init, robust to in-band SPS loss).  Parses only until
                            # both are seen; then _sprop_done short-circuits.
                            if _should_capture_sprop(
                                    _kind, _decrypted,
                                    getattr(_bridge_fn, "_sprop_done", False)):
                                _ps = _extract_param_sets_from_rtp(_fwd_pkt)
                                if _ps:
                                    _psc = getattr(_bridge_fn, "_ps_cache", None)
                                    if _psc is None:
                                        _psc = {}
                                        _bridge_fn._ps_cache = _psc
                                    _psc.update(_ps)
                                    if 7 in _psc and 8 in _psc:
                                        _sprop_new = _build_sprop(_psc[7], _psc[8])
                                        if _sprop_new != _load_sprop(self.device_id):
                                            # Gated on the result: two of
                                            # _save_sprop's three outcomes write
                                            # nothing, and this is the only line
                                            # the sprop path ever emits.
                                            if _save_sprop(self.device_id,
                                                           _sprop_new):
                                                _status(
                                                    "bridge: cached sprop-parameter"
                                                    f"-sets for {self.device_id}")
                                            else:
                                                _status(
                                                    "bridge: parameter sets NOT "
                                                    f"cached for {self.device_id} "
                                                    "(camera marked unstable, or "
                                                    "the cache is unwritable) - "
                                                    "out-of-band injection stays "
                                                    "off for it")
                                        _bridge_fn._sprop_done = True
                            # Rebase RTP timestamps to start near 0.  Camera picks a
                            # random starting timestamp (RFC 3550 section 5.1); the 90 kHz
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
                            # Ask the camera to resend anything the air lost.
                            # The sequence number is in the clear even under
                            # SRTP, so this reads _bpkt and does not depend on
                            # the decrypt above having succeeded.
                            if (_kind == "video"
                                    and len(_bpkt) >= 12
                                    and hasattr(_bridge_fn, '_cam_video_ssrc')
                                    and hasattr(_bridge_fn, '_cam_srtp_sock')):
                                _nk_seq, _nk_ssrc = _st_br.unpack_from(
                                    '!H', _bpkt, 2)[0], _st_br.unpack_from(
                                    '!I', _bpkt, 8)[0]
                                if _nk_ssrc == _bridge_fn._cam_video_ssrc:
                                    _nk_lost = _video_nack_seqs(
                                        _bridge_fn, _nk_seq, _time_br.time(),
                                        enabled=getattr(_bridge_fn,
                                                        '_nack_on', True))
                                    if _nk_lost and _send_video_nack(
                                            # bound now: called synchronously
                                            # inside the helper, but the loop
                                            # vars must not be late-bound.
                                            lambda _d, _s=_bs, _a=_bsrc,
                                            _p=_br_cam_peer: _br_send_to_cam(
                                                _s, _d, _a, _p),
                                            getattr(_bridge_fn,
                                                    '_pli_tx_sess', None),
                                            _CAM_RTCP_SENDER_SSRC,
                                            _bridge_fn._cam_video_ssrc,
                                            _nk_lost):
                                        _bridge_fn._nack_sent = getattr(
                                            _bridge_fn, '_nack_sent', 0) + 1
                                        _bridge_fn._nack_seqs = getattr(
                                            _bridge_fn, '_nack_seqs', 0
                                        ) + len(_nk_lost)
                                        if _bridge_fn._nack_sent == 1:
                                            _status(
                                                f"SDES: sent RTCP NACK #1 for"
                                                f" {len(_nk_lost)} packet(s)"
                                                f" -> SSRC="
                                                f"0x{_bridge_fn._cam_video_ssrc:08x}"
                                            )
                            # A retransmission that missed ffmpeg's reorder
                            # window is worse than nothing: the damaged frame
                            # is already out, so forwarding it only inserts an
                            # out-of-order packet and the muxer clamps its
                            # output DTS.  Skip the send (not a `continue` -
                            # that would change loop control flow for the whole
                            # SDES fleet) and do not count it, since the
                            # consumer cannot use it.
                            _nk_late = (
                                _kind == "video"
                                and len(_bpkt) >= 4
                                and _video_repeat_too_late(
                                    _bridge_fn,
                                    _st_br.unpack_from('!H', _bpkt, 2)[0],
                                    _time_br.time())
                            )
                            if _nk_late:
                                _bridge_fn._nack_late_drops = getattr(
                                    _bridge_fn, '_nack_late_drops', 0) + 1
                            if _pt_out != _pt and _decrypted:
                                _fwd_pkt = rewrite_rtp_payload_type(
                                    _fwd_pkt, _pt_out)
                            try:
                                if not _nk_late:
                                    _lo_target.sendto(
                                        _fwd_pkt, ('127.0.0.1', _btgt)
                                    )
                                # Forward unconditionally - ciphertext ffmpeg
                                # discards is inert, and a `continue` here would
                                # change loop control flow for the whole SDES
                                # fleet.  But only COUNT what the consumer can
                                # use: these three are the only in-process proof
                                # media flowed, so counting a discarded packet
                                # keeps is_stalled from ever tripping and the
                                # session reports healthy while the viewer sees
                                # black.  See _should_count_media.
                                if not _nk_late and _should_count_media(
                                        _decrypted, _use_plain_rtp):
                                    _media_progress[0] = _time_br.monotonic()
                                    _media_counts[0] += 1
                                    _media_counts[1] += len(_fwd_pkt)
                            except Exception:
                                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                    # Periodic ICE controlling check: re-send USE-CANDIDATE every 2.5 s.
                    # Keeps the camera in ICE "Completed" state and satisfies consent
                    # refresh (RFC 7675).  Also handles the case where the initial
                    # USE-CANDIDATE (sent right after the STUN window) was lost.
                    _br_now = _time_br.monotonic()
                    # Relay-only battery cams (LAN IP unknown) answer AFTER the STUN
                    # window and send no probes, so the in-window proactive send saw
                    # empty _cam_ice_* and the probe-gated late-send above never runs.
                    # Fall back to the creds parsed late into _bridge_uc_info so this
                    # ungated periodic tick still nominates them.  [SDES-LATECREDS-FIX]
                    _uc_cands = _cam_ice_cands or _bridge_uc_info.get("cands")
                    # Union in anything learned from the camera's own probes.
                    # Advertised candidates stay FIRST and are still nominated,
                    # so a camera we can already reach directly is unaffected;
                    # this only adds a path where there was none.
                    _uc_prflx = _bridge_uc_info.get("prflx")
                    if _uc_prflx:
                        _uc_cands = [
                            *(_uc_cands or []),
                            *(c for c in _uc_prflx if c not in (_uc_cands or [])),
                        ]
                    _uc_cufrag = _cam_ice_ufrag or _bridge_uc_info.get("ufrag")
                    _uc_cpwd = _cam_ice_pwd or _bridge_uc_info.get("pwd")
                    if _uc_cands and _uc_cufrag and _uc_cpwd and (_br_now - _br_last_uc) >= 2.5:
                        _br_last_uc = _br_now
                        # Same RFC 5766 s9 door as the setup path, but this is
                        # the only place it can be opened for a relay-only
                        # battery cam: its candidates arrive after the STUN
                        # window, so the setup-time install above never ran and
                        # nominating without a permission probes a black hole.
                        # Re-install when the candidate set changes and every
                        # 120 s thereafter - a TURN permission expires 300 s
                        # after it is installed (RFC 5766 s8).
                        _perm_key = tuple(sorted(_uc_cands))
                        if (_perm_key != _br_perm_cands
                                or (_br_now - _br_last_perm) >= 120.0):
                            _br_perm_cands = _perm_key
                            _br_last_perm = _br_now
                            _turn_install_permissions(_uc_cands, "bridge", _trace)
                        # Keep the allocation itself alive.  The server grants
                        # it for a LIFETIME (600 s here) and drops it silently
                        # when that lapses, so refresh well inside the window.
                        if (_relay_addrs
                                and (_br_now - _br_last_alloc_refresh) >= 240.0):
                            _br_last_alloc_refresh = _br_now
                            _rf_ok = sum(
                                1 for _rf_s in (_audio_sock, _video_sock)
                                if _turn_refresh_allocation(_rf_s)
                            )
                            if _rf_ok:
                                _trace(
                                    f"TURN: refreshed {_rf_ok} relay"
                                    f" allocation(s)"
                                )
                        for _c_ip, _c_port in _uc_cands:
                            _send_use_candidate(
                                _audio_sock, _ufrag_a, _pwd_a,
                                _uc_cufrag, _uc_cpwd, (_c_ip, _c_port),
                            )
                            _send_use_candidate(
                                _video_sock, _ufrag_v, _pwd_v,
                                _uc_cufrag, _uc_cpwd, (_c_ip, _c_port),
                            )
            finally:
                try:
                    _lo_a.close()
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
                try:
                    _lo_v.close()
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)

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
            # Addresses the camera's own probes arrived from, which may differ
            # from anything it advertised.  Written by the bridge thread only;
            # read there too, so no cross-thread ordering to reason about.
            "prflx":   [],
        }

        _bridge_thread = _threading_br.Thread(
            target=_bridge_fn, daemon=True, name="sdes-bridge"
        )
        _bridge_thread.start()
        _status(
            f"bridge thread started - camera sockets audio={audio_port}"
            f" video={video_port} -> ffmpeg loopback {_lo_audio_port}/{_lo_video_port}"
        )

        async def _consume_camera_trickle():
            """Feed the camera's trickled candidates to TURN and to nomination.

            The answer SDP carries only the camera's host candidate - a private
            address.  A TURN permission is matched against the peer's source
            address AS THE RELAY SEES IT, so a permission built from that host
            candidate authorises an address that can never arrive, and the relay
            keeps discarding the camera exactly as if no permission existed.
            Measured on a live A001513: CreatePermission for the host candidate
            drew a success response and still produced ZERO relay-carried
            inbound packets.

            The addresses that can actually reach us - the camera's srflx and
            its own relay allocation - arrive later, by iceCandidateReq trickle.
            Permission each one as it appears, and add it to the nomination set:
            when the camera is not directly reachable, USE-CANDIDATE aimed only
            at its host candidate cannot be delivered either.
            """
            _tk_deadline = time.monotonic() + min(max(timeout, 30.0), 90.0)
            _tk_next = 0
            _tk_seen: set = set()
            while time.monotonic() < _tk_deadline:
                while _tk_next < len(ice_cands_seen):
                    _tk_line = (ice_cands_seen[_tk_next].get("candidate") or "")
                    _tk_next += 1
                    # The shared parser, so a candidate the answer path
                    # nominates cannot be one this path silently skips.
                    _tk_parsed = _parse_candidate_line(_tk_line)
                    if not _tk_parsed:
                        continue
                    _tk_ip = _tk_parsed[0]
                    _tk_port = _tk_parsed[1]
                    _tk_typ = _tk_parsed[2]
                    if (_tk_ip, _tk_port) in _tk_seen:
                        continue
                    _tk_seen.add((_tk_ip, _tk_port))
                    _turn_install_permissions(
                        [(_tk_ip, _tk_port)], f"trickle {_tk_typ}")
                    _tk_cur = _bridge_uc_info["cands"]
                    if (_tk_ip, _tk_port) not in _tk_cur:
                        # Rebind to a NEW list rather than appending: the bridge
                        # thread iterates this and must never see it mutate.
                        _bridge_uc_info["cands"] = [
                            *_tk_cur, (_tk_ip, _tk_port)]
                await asyncio.sleep(0.25)

        if ice_cands_seen is not None:
            # Hold a strong reference: a task referenced only by a local can be
            # garbage-collected mid-flight once this coroutine returns.
            _trickle_task = loop.create_task(_consume_camera_trickle())
            _SDES_BACKGROUND_TASKS.add(_trickle_task)
            _trickle_task.add_done_callback(_SDES_BACKGROUND_TASKS.discard)

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
        # cannot do DTLS - webrtc_internals_dump confirms LK.IPC.A001064 uses
        # DTLS (UDP/TLS/RTP/SAVPF) when given a proper DTLS offer.  The
        # property means SDES is available, not that DTLS is absent.
        if (_cam_echo_received
                and _stun_count == 0
                and _camera_side_pkt_count == 0
                and not _srtp_detected
                and dtls_fallback_ok):
            _status(
                "echo-reversal camera: no STUN or SRTP received in ICE window"
                " - camera likely requires DTLS; falling back"
            )
            # Stop bridge thread by closing its sockets before we raise.
            for _rsock in (_audio_sock, _video_sock):
                try:
                    _rsock.close()
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
            try:
                os.unlink(sdp_path)
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
            outgoing_q.put_nowait(None)   # stop MQTT thread
            raise CameraMixin._SdesNoAnswerError()
        elif (_cam_echo_received
              and _stun_count == 0
              and _camera_side_pkt_count == 0
              and not _srtp_detected
              and not dtls_fallback_ok):
            _status(
                "echo-reversal camera: no STUN or SRTP received in ICE window"
                " - DTLS fallback disabled by camera flags; continuing SDES path"
            )

        if rtsp_push_url and rtsp_push_url.startswith("http"):
            # Cold-start relay: when the keepalive loop is holding the public
            # serve port, point ffmpeg at a fresh internal port and let the relay
            # splice the public port to it - so an early go2rtc pull waits through
            # this handshake instead of being refused.  set_backend retries the
            # dial until ffmpeg's -listen socket binds (only after input frames).
            _relay = getattr(self, "_serve_relay", None)
            if _relay is not None:
                _ff_port = _grab_free_port()
                rtsp_push_url = _rewrite_serve_port(rtsp_push_url, _ff_port)
                _relay.set_backend(_ff_port)
            # PULL model: SERVE the decrypted stream over an HTTP-listen socket so
            # go2rtc / HA's stream integration pull it the standard way - the only
            # per-camera side effect here is the cold-start serve-relay rewrite
            # above; the destination + audio args (and the PMT-stall rationale for
            # audio being opt-in) live in _build_sdes_serve_cmd, built once below.
        elif output_path:
            # Ensure the output directory exists before ffmpeg opens the file
            # (ffmpeg fails with "No such file or directory" otherwise).
            out_dir = os.path.dirname(output_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
        # The ffmpeg command is built once below, AFTER the first-media wait
        # resolves the real payload types (single source of truth:
        # _build_sdes_serve_cmd) - so both the SDP narrowing and the push
        # video-only decision see the observed codecs.
        _serve_audio = self._resolve_sdes_serve_audio()
        # --- H.265 fix: narrow the ffmpeg SDP to the camera's actual codec ----
        # The camera streams H.264 (pt=96) OR H.265 (pt=97), varying per session.
        # An m=video line listing both ("96 97") makes ffmpeg bind the RTP
        # depacketizer to the FIRST pt (96/H.264) and silently drop the camera's
        # H.265 packets -> 0 frames.  Wait for the bridge to observe the real
        # video pt, then rewrite the SDP to that single codec before launch.
        # ffmpeg recovers on the next periodic keyframe, so the small spawn delay
        # is harmless.  Falls back to the dual-codec SDP if no video is seen.
        # When audio is being served the same wait has to cover the AUDIO payload
        # type, and for a stricter reason: an unnarrowed video line merely risks the
        # picture, while an unnarrowed audio line guarantees the mux never writes its
        # PAT/PMT, which loses the picture AND the audio.  Wait for both, then take
        # whatever has been observed by the deadline.
        # Wait for the session's first media, then briefly for audio.
        #
        # Measured on an A001513: a cold session's media starts at ~21s, and its
        # video and audio payload types then arrive 40-70ms apart because the camera
        # answers BUNDLE.  So audio is never "late" relative to video - the old 15s
        # video deadline simply expired BEFORE any media at all, and the serve
        # launched with both payload types unknown.  Waiting for first media costs
        # no picture latency: ffmpeg cannot produce before media exists, and
        # launching earlier only binds the wrong depacketizers.
        # The camera's answer carries the ICE credentials we need to nominate a
        # pair, and it lands about a second after webrtcReq - but it is not
        # awaited until AFTER this wait.  So for a camera whose answer misses the
        # _pre_launch_answer_sdp snapshot, USE-CANDIDATE was only ever sent once
        # this window had already expired, the camera sat in ICE "Checking"
        # forever, and the wait below could not do anything but time out.
        # Measured on an A001513: answer at +1.3 s, nomination at +81 s.
        # Nominate as soon as the answer is readable instead.
        _early_nominated = bool(_cam_ice_ufrag and _cam_ice_pwd and _cam_ice_cands)
        _media_deadline = time.monotonic() + _FIRST_MEDIA_WAIT_S
        _media_wait_started = time.monotonic()
        _pt_kinds_read = False
        # Arming state for the stale-offer detector: what we had heard from the
        # camera ITSELF (not the cloud's ack for it) as this wait began.  See
        # _stale_offer_abandon_due.
        _seen_at_start = getattr(self, "_camera_device_seen_ts", None)
        _first_seen_ts = None
        _stale_offer_abandoned = False

        def _report_first_media_stall(_waited_s, _cancelled=False):
            """Emit the one line that says why nothing arrived.

            A local closure, not inline, because there are two ways to leave the
            wait without media and both need it.  The wait expiring is the
            obvious one.  The other is a caller giving up first, which is what a
            snapshot does at its own budget - measured at 50 s against this
            75 s wait - so the session that most needed explaining was cancelled
            25 s before the explanation would have been written.
            """
            try:
                # What the answer carried, so `nominated=none` says which
                # cause. Both sources are consulted inside the helper: the
                # pre-launch snapshot is empty on a late answer - measured at
                # +1.3 s - and the future is the only place that shape's SDP
                # ever appears.
                _stall_answer = _stall_answer_candidates(
                    _pre_launch_answer_sdp, answer_fut)
                _stall_probes = list(
                    (getattr(_bridge_fn, "_br_probe_verdicts", None) or {}).items()
                )
                # Union of every nomination source, deduped and order-preserving:
                # the answer-peek path records into _nominated_seen, the setup /
                # trickle / late-answer paths into _bridge_uc_info, and the
                # bridge's peer-reflexive learning into ["prflx"].  Any one of
                # them alone under-reports on some shape.
                _stall_nominated: list = []
                for _sn in (*_nominated_seen, *_bridge_uc_info["cands"],
                            *_bridge_uc_info["prflx"]):
                    if _sn not in _stall_nominated:
                        _stall_nominated.append(_sn)
                _LOGGER.warning("%s", _first_media_stall_report(
                    device_id=getattr(self, "device_id", "?"),
                    waited_s=_waited_s,
                    nominated=_stall_nominated,
                    use_candidate_sent=bool(
                        _bridge_uc_info["sent"] or _nominated_seen),
                    binding_success=int(
                        getattr(_bridge_fn, "_br_binding_success_count", 0)),
                    trigger_sent=bool(
                        getattr(_bridge_fn, "_tutk_trigger_sent", False)),
                    probes=_stall_probes,
                    probes_dropped=int(
                        getattr(_bridge_fn, "_br_probe_overflow", 0)),
                    cancelled=_cancelled,
                    media_pkts=int(getattr(_bridge_fn, "_br_media_pkts", 0)),
                    decrypt_fails=int(
                        getattr(_bridge_fn, "_br_decrypt_fails", 0)),
                    answer_cands=_stall_answer,
                    trigger_acked=bool(getattr(
                        _bridge_fn, "_br_session_mode_resp", 0)),
                ))
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s",
                              getattr(self, "device_id", "?"),
                              '_first_media_stall_report', exc_info=True)

        try:
            while _first_video_pt[0] is None and time.monotonic() < _media_deadline:
                if _first_seen_ts is None and _seen_at_start is None:
                    _first_seen_ts = getattr(
                        self, "_camera_device_seen_ts", None)
                if _stale_offer_abandon_due(
                        battery=bool(getattr(self, "is_battery_camera", False)),
                        seen_at_start=_seen_at_start,
                        first_seen_ts=_first_seen_ts,
                        now=time.monotonic(),
                        grace_s=_BATTERY_STALE_OFFER_GRACE_S):
                    # The camera was silent when this wait began and has since
                    # woken, answered, and sent no media for the whole grace.
                    # Our offer reached it while it was still asleep and it is
                    # not going to act on it; the retry's fresh offer will be
                    # served in seconds.  Stop paying for the rest of the window.
                    _stale_offer_abandoned = True
                    _status(
                        "camera turned up %.0fs into the wait and sent no media"
                        " for the %.0fs since - abandoning this attempt to the"
                        " retry, while the camera is still awake"
                        % (_first_seen_ts - _media_wait_started,
                           _BATTERY_STALE_OFFER_GRACE_S)
                    )
                    break
                if terminal_error_fut is not None and terminal_error_fut.done():
                    _code, _desc = terminal_error_fut.result()
                    _status(f"camera refused: ack {_code} {_desc}"
                            " - terminal, abandoning the first-media wait")
                    raise AidotCameraBusy(_code, _desc)
                if (not _pt_kinds_read and answer_fut is not None
                        and answer_fut.done() and not answer_fut.cancelled()):
                    # One-shot, here rather than in the answer-logging block
                    # further down: that block runs AFTER this wait, which is
                    # 75 s too late for the demux that the map exists to fix.
                    _pt_kinds_read = True
                    try:
                        if answer_fut.exception() is None:
                            _pk_sdp = (
                                answer_fut.result() or {}).get("sdp", "") or ""
                            if _pk_sdp:
                                _answer_pt_kinds.update(answer_pt_kinds(_pk_sdp))
                                _answer_video_pt[0] = video_pt_from_answer_sdp(
                                    _pk_sdp)
                                _vpts = sorted(
                                    pt for pt, k in _answer_pt_kinds.items()
                                    if k == "video")
                                if any(pt not in _SDP_VIDEO_PTS for pt in _vpts):
                                    _status(
                                        "answer numbers video on payload"
                                        " type(s) %s - demuxing by the answer,"
                                        " serving as our pt=%s"
                                        % (_vpts, _answer_video_pt[0]))
                    except Exception:
                        _LOGGER.debug(
                            "camera %s: swallowed exception in %s",
                            getattr(self, "device_id", "?"),
                            'answer_pt_kinds', exc_info=True)
                if (not _early_nominated and answer_fut is not None
                        and answer_fut.done() and not answer_fut.cancelled()):
                    # Read-only peek: the real await below still consumes this
                    # future and drives the answer/fallback paths unchanged.
                    # ``cancelled()`` is checked explicitly because the answer-wait
                    # cancels this future on timeout, and ``.exception()`` on a
                    # cancelled future raises CancelledError - a BaseException that
                    # the ``except Exception`` below would NOT catch.
                    _peek_sdp = ""
                    try:
                        if answer_fut.exception() is None:
                            _peek_sdp = (answer_fut.result() or {}).get("sdp", "") or ""
                    except Exception:
                        _peek_sdp = ""
                    _n_nom = _nominate_from_answer_sdp(_peek_sdp)
                    if _n_nom:
                        _early_nominated = True
                        _status(
                            "ICE controlling: nominated %d candidate(s) from the"
                            " camera's answer during the first-media wait" % _n_nom
                        )
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            # The caller gave up before the wait could expire - a snapshot
            # does exactly this at its own budget. Say why nothing arrived
            # while the evidence is still in hand, then let the
            # cancellation through untouched: this package has already
            # shipped one bug where a handler caught CancelledError and
            # returned normally, and diagnosing a stall must never become a
            # second one.
            if _first_video_pt[0] is None:
                _report_first_media_stall(
                    time.monotonic() - _media_wait_started, _cancelled=True)
            raise
        # The serve SDP below is built from what has actually been observed, so
        # ending the wait a moment before the first packets arrive costs this
        # session its audio for good.  See _abandoned_media_grace_s.
        #
        # The grace runs BEFORE the stall report, not after: a session the grace
        # rescues goes on to serve normally, and reporting a "first media never
        # arrived" WARNING for it would contradict that report's own invariant -
        # "an open that delivers media reaches none of it" - and poison the
        # signal this camera family is triaged with.
        _ab_grace = _post_abandon_media_grace_s(
            abandoned=_stale_offer_abandoned,
            have_video=_first_video_pt[0] is not None,
            grace_s=_abandoned_media_grace_s())
        if _ab_grace > 0:
            _ab_t0 = time.monotonic()
            try:
                while (_first_video_pt[0] is None
                        and time.monotonic() - _ab_t0 < _ab_grace):
                    # A terminal refusal can land inside the grace exactly as it
                    # can inside the main wait. Without this it falls through and
                    # is reported as AidotCameraNoMedia - whose own docstring
                    # calls it "the opposite of AidotCameraBusy" - and the loop
                    # retries at once on a camera that just said it has no free
                    # session.
                    if (terminal_error_fut is not None
                            and terminal_error_fut.done()):
                        _code, _desc = terminal_error_fut.result()
                        _status(f"camera refused: ack {_code} {_desc}"
                                " - terminal, abandoning the grace")
                        raise AidotCameraBusy(_code, _desc)
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                # Same blind spot the main wait closes: a snapshot cancels at
                # its own budget, and without this the evidence is discarded.
                if _first_video_pt[0] is None:
                    _report_first_media_stall(
                        time.monotonic() - _media_wait_started, _cancelled=True)
                raise
            if _first_video_pt[0] is not None:
                _status("media arrived %.1fs after the wait was abandoned"
                        " - mapping it rather than serving video only"
                        % (time.monotonic() - _ab_t0))
            else:
                _status("no media in the %.0fs after the wait was abandoned"
                        % _ab_grace)
        if _first_video_pt[0] is None:
            # The wait expired with nothing received. Everything needed to
            # say why is in hand at exactly this moment and was, until the
            # report existed, thrown away: media only ever follows the AVIO
            # LIVING trigger, that trigger is armed only by an inbound STUN
            # Binding Success, and that response only comes back if
            # something we nominated was reachable. One WARNING, on this
            # path only: an open that delivers media reaches none of it.
            _report_first_media_stall(
                time.monotonic() - _media_wait_started
                if _stale_offer_abandoned else _FIRST_MEDIA_WAIT_S)
        if _should_skip_doomed_serve(
                abandoned=_stale_offer_abandoned,
                have_video=_first_video_pt[0] is not None,
                serving=bool(rtsp_push_url or output_path)):
            # Serving now would build the SDP from nothing observed, produce a
            # video-only stream, and receive no media on it - measured as ~14 s
            # of delay and a dropped audio track ahead of the retry that worked.
            # Go straight to the retry instead.  The cleanup stack closes the
            # reserved sockets and stops the signalling thread on the way out.
            _waited = time.monotonic() - _media_wait_started
            _status("abandoning the attempt rather than serving a stream the"
                    " camera is not feeding - retrying")
            _LOGGER.info(
                "camera %s: no media %.0fs after the camera answered;"
                " abandoning this attempt to the retry rather than launching a"
                " serve with nothing to serve",
                getattr(self, "device_id", "?"), _waited,
            )
            raise AidotCameraNoMedia(waited_s=_waited)
        if _serve_audio and _first_audio_pt[0] is None:
            _apt_deadline = time.monotonic() + _AUDIO_PT_GRACE_S
            while _first_audio_pt[0] is None and time.monotonic() < _apt_deadline:
                await asyncio.sleep(0.1)
        _vpt = _first_video_pt[0]
        _apt = _first_audio_pt[0]
        # Which single payload type (if any) each line can be narrowed to. Audio
        # is usable only when its type was actually observed; otherwise the "0 8"
        # line cannot be narrowed.
        # NOTE: the no-video case this was written for no longer reaches here -
        # an open with nothing observed is abandoned above, so _vpt is always
        # set by this point. What is left is an OBSERVED but unadvertised
        # payload type, which is why the messages below no longer claim that
        # no video was seen.
        if (_vpt not in _SDP_VIDEO_PTS and answer_fut is not None
                and answer_fut.done() and not answer_fut.cancelled()):
            # No video packet arrived inside the window, but the camera's answer
            # still names the codec it agreed to send. Narrowing on that beats
            # leaving both codecs advertised: an unnarrowed video line makes
            # ffmpeg bind the wrong depacketizer, and makes the RTSP-push
            # ANNOUNCE carry a parameterless H.265 stream that go2rtc rejects
            # outright - no publisher, and every viewer sees a 404.
            try:
                if answer_fut.exception() is None:
                    _answer_video_pt[0] = video_pt_from_answer_sdp(
                        (answer_fut.result() or {}).get("sdp", "") or "")
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s",
                              getattr(self, "device_id", "?"),
                              'video_pt_from_answer_sdp', exc_info=True)
            _pin_pt = _resolve_sdes_video_pt()
            if _pin_pt is not None:
                _LOGGER.info(
                    "camera %s: the observed payload type is not one this SDP "
                    "advertises; narrowing to the PINNED payload type %d rather "
                    "than the camera's answer (%s).",
                    getattr(self, "device_id", "?"), _pin_pt,
                    _answer_video_pt[0],
                )
            elif _answer_video_pt[0] is not None:
                _LOGGER.info(
                    "camera %s: the observed payload type is not one this SDP "
                    "advertises; narrowing to payload type %d from the "
                    "camera's negotiated answer instead of advertising both.",
                    getattr(self, "device_id", "?"), _answer_video_pt[0],
                )
        # observed beats pinned beats answer -- see _serve_video_pt.  The pin
        # matters here: this camera answers H.265 and sends H.264, so trusting
        # the answer built an hevc-only SDP and killed the serve at startup.
        _keep_v = _serve_video_pt(_vpt, _answer_video_pt[0],
                                  _resolve_sdes_video_pt())
        _keep_a = int(_apt) if _apt in _SDP_AUDIO_PTS else None
        if _serve_audio and _keep_a is None:
            # No audio observed in the window, so the line cannot be narrowed and
            # mapping audio would stall the mux (pull) or break the ANNOUNCE
            # (push).  Serve video only rather than serving nothing, and say so.
            _LOGGER.warning(
                "camera %s: no audio observed before the serve launched, so the "
                "audio payload type is unknown; mapping it would stall the mpegts "
                "mux and serve no video. Continuing without audio.",
                getattr(self, "device_id", "?"),
            )
            _serve_audio = False
        # RTSP-PUSH copies EVERY input stream (-c copy). If the audio line was
        # never narrowed to a single type, its multi-PT ANNOUNCE is rejected by
        # the RTSP server (400 Bad Request) and takes the whole publish down - so
        # push must map video only whenever audio is not usable. (Pull already
        # gates audio via sdes_audio in _build_sdes_serve_cmd.)
        _is_push = bool(rtsp_push_url) and not rtsp_push_url.startswith("http")
        _push_video_only = _is_push and _keep_a is None
        # Only the -f null drain decodes; the rest are -c copy, so this is the
        # one place a decoder choice can pay.  Read the cache only - probing
        # shells out for several seconds on a cold host and would stall the
        # event loop for every camera; None just means "let ffmpeg choose", as
        # before, and an empty list is a real "software decoding" answer.
        from .hwaccel import cached_decoder  # lazy: keep import cost off setup
        _video_decoder = (
            cached_decoder("h264" if _keep_v == 96 else "hevc")
            if _keep_v is not None else None
        )
        cmd = _build_sdes_serve_cmd(
            sdp_path=sdp_path,
            rtsp_push_url=rtsp_push_url,
            output_path=output_path,
            max_seconds=max_seconds,
            sdes_audio=_serve_audio,
            audio_gain_db=self._resolve_sdes_audio_gain_db(),
            push_video_only=_push_video_only,
            video_decoder=_video_decoder,
            input_timeout_s=_resolve_serve_input_timeout_s(
                bool(getattr(self, "is_battery_camera", False))),
        )
        # Audio matters even more than video here.  A multi-PT m-line makes ffmpeg
        # bind the depacketizer to the FIRST payload type and silently discard the
        # rest, and the mpegts mux withholds its PAT/PMT until EVERY mapped stream
        # has produced a packet - so an audio line advertising "0 8" (PCMU first)
        # on a camera that sends PCMA discards every audio packet and the consumer
        # receives zero bytes.  That takes the video down with it, which is why
        # enabling serve audio appeared to break streaming outright.
        if _keep_v is not None or _keep_a is not None:
            def _read_sdp_file() -> str:
                with open(sdp_path, encoding="utf-8") as _f_sdp:
                    return _f_sdp.read()
            try:
                _cur_sdp = await asyncio.get_running_loop().run_in_executor(
                    None, _read_sdp_file)
                await asyncio.get_running_loop().run_in_executor(
                    None, _write_text_file, sdp_path,
                    narrow_sdp_payload_types(_cur_sdp, _keep_v, _keep_a))
                _status(
                    "SDES: narrowed ffmpeg SDP to"
                    + (f" video pt={_keep_v}"
                       f" ({'H264' if _keep_v == 96 else 'H265'})"
                       if _keep_v is not None else "")
                    + (f" audio pt={_keep_a}"
                       f" ({'PCMA' if _keep_a == 8 else 'PCMU'})"
                       if _keep_a is not None else ""))
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_open_sdes_stream', exc_info=True)
        # Do not launch the publisher into a listener that is not up yet.
        await _await_rtsp_publish_target(rtsp_push_url)
        _LOGGER.info("SDES ffmpeg cmd: %s", " ".join(cmd))
        if _ffmpeg_path() is None:
            # ffmpeg is not installed - clean up and surface a clear error
            # before launching (avoids a cryptic FileNotFoundError).
            for _rsock in (_audio_sock, _video_sock):
                try:
                    _rsock.close()
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
            try:
                os.unlink(sdp_path)
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
            outgoing_q.put_nowait(None)   # stop MQTT thread
            raise RuntimeError(
                "ffmpeg not found - install ffmpeg to stream SDES-SRTP cameras.\n"
                "  Ubuntu/Debian:  sudo apt install ffmpeg\n"
                "  macOS (Homebrew): brew install ffmpeg\n"
                "  Windows:         https://ffmpeg.org/download.html"
            )
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            _start_serve_stderr_drain(proc)
            _proc_holder[0] = proc
            _cl(_reap, proc)   # kill ffmpeg if the open is cancelled before hand-off
        except FileNotFoundError:
            # ffmpeg is not installed - clean up and surface a clear error.
            for _rsock in (_audio_sock, _video_sock):
                try:
                    _rsock.close()
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
            try:
                os.unlink(sdp_path)
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_bridge_fn', exc_info=True)
            outgoing_q.put_nowait(None)   # stop MQTT thread
            raise RuntimeError(
                "ffmpeg not found - install ffmpeg to stream SDES-SRTP cameras.\n"
                "  Ubuntu/Debian:  sudo apt install ffmpeg\n"
                "  macOS (Homebrew): brew install ffmpeg\n"
                "  Windows:         https://ffmpeg.org/download.html"
            )

        # Wait until ffmpeg has actually bound the UDP ports before sending
        # webrtcReq.  Popen() returns as soon as the process is created;
        # ffmpeg needs additional time to parse the SDP and call bind().
        # If we send webrtcReq before ffmpeg is listening, the camera's first
        # SRTP packets hit closed ports, the OS sends ICMP port-unreachable,
        # and the camera stops streaming - producing 0 frames.
        def _udp_port_bound(port: int) -> bool:
            """True if a UDP socket is currently bound to `port` on 127.0.0.1.

            Uses try-bind: if we can bind the port it's free; if EADDRINUSE
            it's taken - i.e. ffmpeg is listening.  Works on macOS and Linux
            without /proc/net/udp.
            """
            try:
                _s_pb = _socket_br.socket(
                    _socket_br.AF_INET, _socket_br.SOCK_DGRAM)
                try:
                    _s_pb.bind(('127.0.0.1', port))
                    return False   # bound cleanly -> port was free
                except OSError:
                    return True    # EADDRINUSE -> ffmpeg is listening
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
        self._cold_phase("serving (sdes ffmpeg bound)")
        if _bound:
            _status(
                f"SDES ffmpeg ready - loopback audio={_lo_audio_port}"
                f" video={_lo_video_port} bound in {_bind_ms} ms  (pid={proc.pid})"
            )
        else:
            # /proc/net/udp unavailable or ffmpeg very slow - use fixed delay
            _status(
                f"ffmpeg port bind not confirmed after {_bind_ms} ms"
                " - sleeping 1.5 s as fallback"
            )
            await asyncio.sleep(1.5)

        # --- Wait for SDP answer -------------------------------------------- #
        # Wait for the camera's SDP answer.  True SDES cameras (e.g.
        # LK.IPC.A001513) send webrtcResp within a few seconds.  If no
        # answer arrives the camera is not operating in SDES mode - most
        # likely it has enableSdes='1' set incorrectly and actually requires
        # DTLS.  In that case abort the ffmpeg process and raise
        # _SdesNoAnswerError so the caller retries with the DTLS path.
        # Battery SDES cameras (A001513 etc.) take up to ~15s to wake from
        # deep sleep - they answer webrtcReq well after the bridge starts.
        # Cameras with DTLS fallback keep 8s so the fallback fires quickly.
        _sdes_answer_timeout = (
            sdes_answer_timeout if sdes_answer_timeout is not None
            else min(timeout, 8.0 if dtls_fallback_ok else 20.0)
        )
        try:
            # Race the answer against a TERMINAL refusal (-50002 max-streams /
            # -50015 SD-cap).  Without this the SDES path is blind to a camera
            # that explicitly said no: it waited out its whole answer budget and
            # then handed a "no answer" to the DTLS fallback, which sent a second
            # offer and only THEN surfaced AidotCameraBusy.  Measured ~48s to
            # report a refusal that arrived in about one second - and two of the
            # three validated models (A001513, A001064) take this path.
            answer = await _sdes_await_answer_or_terminal(
                answer_fut, terminal_error_fut, _sdes_answer_timeout, _status,
            )
            _ans_sdp = answer.get("sdp", "")
            _ans_mlines = [ln for ln in _ans_sdp.splitlines() if ln.startswith("m=")]
            _status(
                "webrtcResp received (SDES) - answer m-sections (%d): %s"
                % (len(_ans_mlines), " | ".join(_ans_mlines))
            )
            # If the answer arrived late (after bridge started without ICE creds),
            # parse the camera's ICE credentials now and populate _bridge_uc_info
            # so the bridge can send USE-CANDIDATE on the next camera BindingReq.
            if not _bridge_uc_info["sent"] and not _bridge_uc_info["ufrag"] and _ans_sdp:
                _late_ufrag, _late_pwd, _late_cands, _ = _parse_answer_ice(
                    _ans_sdp)
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
                                    # Adopt it the same way the pre-launch answer
                                    # is adopted above.  srtp_key_audio is the one
                                    # key the bridge decrypts with, so a key
                                    # learned only here has to land in it or this
                                    # camera keeps being decrypted with our offer
                                    # key -- which it never used.
                                    #
                                    # Only where the bridge is the decryptor.
                                    # Adopting it on the other branch would make
                                    # the second-answer comparison below see the
                                    # key as already taken and skip the ffmpeg
                                    # restart - but there it is ffmpeg that holds
                                    # the key, and its SDP was written before this
                                    # answer arrived, so the restart is the only
                                    # thing that would deliver the new key.
                                    if _use_plain_rtp:
                                        srtp_key_audio = _cam_key_audio
                                    break
                    _status(
                        f"late ICE creds parsed - bridge will send USE-CANDIDATE"
                        f" to {len(_late_cands)} candidate(s)"
                        + (" [m=application present]" if _dc_answer_has_app else "")
                        + (f" [cam_key set: {_key_fingerprint(_cam_key_audio)}]" if _cam_key_audio else "")
                    )
            # For echo-reversal cameras (A001064) the first answer_fut was set by
            # the broker echo of our own webrtcResp.  Wait briefly for the camera's
            # real second webrtcResp, which may carry a different SRTP key.
            if second_answer_fut is not None and _cam_echo_received and not second_answer_fut.done():
                try:
                    _second_ans = await asyncio.wait_for(
                        asyncio.shield(second_answer_fut), timeout=5.0
                    )
                except TimeoutError:
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
                    _status("camera real webrtcResp - extracting SRTP keys")
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
                        _status("camera audio SRTP key differs from offer - restarting ffmpeg")
                        srtp_key_audio = _real_key_audio
                        _keys_changed = True
                    if _real_key_video and _real_key_video != srtp_key_video:
                        _status("camera video SRTP key differs from offer - restarting ffmpeg")
                        srtp_key_video = _real_key_video
                        _keys_changed = True
                    if _keys_changed:
                        # Locally-initiated kill (the offered key was wrong;
                        # restarting ffmpeg with the camera's real key) - flag it
                        # so the bridge observe loop does not warn on the old
                        # proc's signal death.  Reset once the NEW proc is live
                        # (below) so a later, genuine crash of the restarted
                        # ffmpeg is not silently swallowed as "expected teardown".
                        _teardown_holder[0] = True
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except Exception:
                            proc.kill()
                        _ts2 = int(time.time())
                        # Transport and payload-type selection both live in
                        # _build_restart_sdp, where they are unit-tested against
                        # the SDP it actually emits.
                        _new_sdp = _build_restart_sdp(
                            ts=_ts2,
                            lo_audio_port=_lo_audio_port,
                            lo_video_port=_lo_video_port,
                            use_plain_rtp=_use_plain_rtp,
                            srtp_key_audio=srtp_key_audio,
                            srtp_key_video=srtp_key_video,
                            first_video_pt=_first_video_pt[0],
                            answer_video_pt=_answer_video_pt[0],
                            first_audio_pt=_first_audio_pt[0],
                        )
                        try:
                            # Re-apply the cached sprop-parameter-sets here too:
                            # this serve-restart rewrite is the SDP the keepalive
                            # ffmpeg actually reads on every watchdog cycle, so
                            # without this the out-of-band SPS is lost on restart
                            # (the failure persisted live even for cached cameras).
                            with open(sdp_path, "w") as _f2:
                                _f2.write(_inject_sprop(_new_sdp, self.device_id))
                        except Exception as _sdp_exc2:
                            _LOGGER.warning("could not rewrite SDP for restart: %s", _sdp_exc2)
                        proc = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE,
                        )
                        _start_serve_stderr_drain(proc)
                        # Point the shared holder at the live proc immediately.
                        # The bridge thread polls _proc_holder[0]; if it still
                        # sees the terminated old proc it logs "stream ended",
                        # breaks, and closes the loopback sockets - starving the
                        # restarted ffmpeg (0-frame stream).
                        _proc_holder[0] = proc
                        # New proc is live and owns the holder; clear the
                        # teardown flag so this session's NEXT exit (the
                        # restarted ffmpeg's) is classified fresh.
                        _teardown_holder[0] = False
                        _status("ffmpeg restarted with camera's SRTP keys")
        except TimeoutError:
            if _cam_echo_received:
                # We already sent webrtcResp in response to the camera's echo.
                # The camera should now be streaming; keep ffmpeg running.
                _status(
                    f"no second webrtcResp in {_sdes_answer_timeout:.0f}s"
                    " - camera acknowledged; continuing with ffmpeg"
                )
            elif dtls_fallback_ok:
                # Camera likely requires DTLS despite enableSdes='1'.  Kill
                # ffmpeg and signal the caller to retry with the DTLS path.
                _status(
                    f"no webrtcResp in {_sdes_answer_timeout:.0f}s"
                    " - SDES handshake failed; aborting ffmpeg and falling back to DTLS"
                )
                # Locally-initiated abort (no answer; giving up on SDES for this
                # attempt) - flag it so the bridge observe loop does not warn on
                # the resulting signal death.  Nothing continues to use this
                # proc/holder afterward, so no reset is needed here.
                _teardown_holder[0] = True
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
                for _rsock in (_audio_sock, _video_sock):
                    try:
                        _rsock.close()
                    except Exception:
                        _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_udp_port_bound', exc_info=True)
                try:
                    os.unlink(sdp_path)
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_udp_port_bound', exc_info=True)
                outgoing_q.put_nowait(None)   # signal MQTT thread to exit
                raise CameraMixin._SdesNoAnswerError()
            else:
                # isDTLS='0': DTLS fallback is disabled by camera flags (NOT that
                # the camera lacks DTLS - see the NOTE above), so there is nothing
                # to fall back to.  Some SDES cameras (e.g. LK.IPC.A001064) start
                # streaming SRTP directly to our ports without sending a
                # webrtcResp SDP answer.  Keep ffmpeg running - it already
                # has the SRTP key it needs from the offered SDP, and the
                # camera's RTP should start arriving momentarily.
                _status(
                    f"no webrtcResp in {_sdes_answer_timeout:.0f}s"
                    " - isDTLS=0: DTLS fallback not available;"
                    " continuing with ffmpeg (camera may stream without SDP answer)"
                )
                # Battery cameras often answer after the 20s timeout (they take
                # 15-25s to wake).  The answer arrives as a second webrtcResp
                # (answer_fut was cancelled, so MQTT handler sets second_answer_fut).
                # Spawn a background task to pick it up and inject ICE credentials
                # into _bridge_uc_info so the bridge can send USE-CANDIDATE.
                if second_answer_fut is not None:
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
                                (_la_ufrag, _la_pwd, _la_cands,
                                 _) = _parse_answer_ice(_la_sdp)
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
                            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_late_second_answer_task', exc_info=True)
                    _spawn_bg(_late_second_answer_task())

        return SdesSession(
            proc=proc,
            sdp_path=sdp_path,
            outgoing_q=outgoing_q,
            mqtt_fut=mqtt_fut,
            audio_sock=_audio_sock,   # bridge thread keeps these open; stop() closes them
            video_sock=_video_sock,
            cmd_chan=_cmd_chan,
            talk_state=_talk_state,
            media_progress=_media_progress,
            ice_progress=_ice_progress,
            media_counts=_media_counts,
            media_path=_media_path,
            teardown_requested=_teardown_holder,
            first_video_pt=_first_video_pt,
            first_audio_pt=_first_audio_pt,
            device_id=getattr(self, "device_id", None),
            responses=_avio_responses,
            abort_chan=_abort_chan,
        )
