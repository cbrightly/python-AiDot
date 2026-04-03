"""
WebRTC ICE Fix Utilities for AiDot Cameras

Drop-in helpers to fix:
- Bad ICE candidate selection
- Role reversal SDP issues
"""


def filter_sdp_candidates(sdp: str) -> str:
    """Remove unusable ICE candidates (Docker, CGNAT, IPv6)."""
    lines = []
    for line in sdp.splitlines():
        if line.startswith("a=candidate:"):
            if any(bad in line for bad in ["172.17.", "100.", "fd", "::"]):
                continue
        lines.append(line)
    return "\n".join(lines)


async def apply_filtered_offer(pc):
    """Create and apply filtered SDP offer."""
    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    filtered_sdp = filter_sdp_candidates(pc.localDescription.sdp)

    # Replace local description safely
    pc._local_description = type(pc.localDescription)(
        sdp=filtered_sdp,
        type=pc.localDescription.type
    )

    return pc.localDescription


async def small_delay():
    """Timing fix for camera compatibility."""
    import asyncio
    await asyncio.sleep(0.15)
