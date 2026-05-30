"""Pure-Python G.711 A-law encoder + test-tone generator.

No stdlib `audioop` dependency — that module was removed in Python 3.13, and
Home Assistant runs on 3.12/3.13.  This keeps the talk-audio path portable.

A-law encode follows the ITU-T G.711 reference (Sun g711.c linear2alaw).

Self-test (`python3 tools/g711_tone.py`) cross-checks every 16-bit sample
against stdlib audioop when it is available (e.g. Python 3.11), so we have
proof the pure-Python encoder is byte-identical to the reference.
"""

from __future__ import annotations

import math
import struct

_SEG_AEND = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)


def _search(value: int) -> int:
    for i, bound in enumerate(_SEG_AEND):
        if value <= bound:
            return i
    return 8


def linear2alaw(pcm_val: int) -> int:
    """Encode one signed 16-bit PCM sample to an 8-bit A-law byte."""
    pcm_val = pcm_val >> 3  # 16-bit -> 13-bit
    if pcm_val >= 0:
        mask = 0xD5
    else:
        mask = 0x55
        pcm_val = -pcm_val - 1
        if pcm_val < 0:
            pcm_val = 0
    seg = _search(pcm_val)
    if seg >= 8:
        return 0x7F ^ mask
    aval = seg << 4
    if seg < 2:
        aval |= (pcm_val >> 1) & 0x0F
    else:
        aval |= (pcm_val >> seg) & 0x0F
    return aval ^ mask


def pcm_to_alaw(pcm: bytes) -> bytes:
    """Encode little-endian signed 16-bit PCM bytes to A-law bytes."""
    n = len(pcm) // 2
    samples = struct.unpack(f"<{n}h", pcm[: n * 2])
    return bytes(linear2alaw(s) for s in samples)


def tone_pcm(freq_hz: float = 440.0, ms: int = 1000,
             rate: int = 8000, amplitude: float = 0.6) -> bytes:
    """Generate a mono 16-bit PCM sine tone (little-endian)."""
    n = int(rate * ms / 1000)
    peak = int(amplitude * 32767)
    out = bytearray()
    for i in range(n):
        v = int(peak * math.sin(2 * math.pi * freq_hz * i / rate))
        out += struct.pack("<h", v)
    return bytes(out)


def tone_alaw(freq_hz: float = 440.0, ms: int = 1000,
              rate: int = 8000, amplitude: float = 0.6) -> bytes:
    """Generate an A-law-encoded sine tone (8 kHz, mono)."""
    return pcm_to_alaw(tone_pcm(freq_hz, ms, rate, amplitude))


def _self_test() -> int:
    # Exhaustive cross-check against audioop where available.
    try:
        import audioop
    except ImportError:
        print("audioop unavailable (Python 3.13+) — skipping cross-check.")
        # Still verify a few invariants.
        assert len(tone_alaw(ms=20)) == 160, "20ms@8k should be 160 bytes"
        print("basic invariants OK")
        return 0

    mismatches = 0
    for s in range(-32768, 32768):
        ref = audioop.lin2alaw(struct.pack("<h", s), 2)[0]
        ours = linear2alaw(s)
        if ref != ours:
            mismatches += 1
            if mismatches <= 5:
                print(f"  mismatch sample={s}: ref=0x{ref:02x} ours=0x{ours:02x}")
    if mismatches:
        print(f"FAIL: {mismatches}/65536 samples differ")
        return 1
    print("PASS: all 65536 samples byte-identical to audioop.lin2alaw")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
