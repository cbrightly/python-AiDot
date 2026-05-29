#!/usr/bin/env python3
"""Extract Aidot WebRTC signaling messages from a mitmproxy capture.

Usage:
    # 1. On the Pi, capture with mitmproxy in TCP+transparent mode for the
    #    Aidot MQTT broker (port 8443):
    #
    #       mitmdump --mode transparent --tcp-hosts '.*arnoo\\.com.*' \\
    #                --set 'block_global=false' \\
    #                -w /tmp/aidot-capture.flows
    #
    #    Then trigger one live-stream view in the Aidot iOS app and stop
    #    mitmdump (Ctrl-C).
    #
    # 2. On the dev workstation, scp the capture back, then:
    #
    #       python3 tools/extract_aidot_signaling.py /tmp/aidot-capture.flows
    #
    #    This writes:
    #      /tmp/aidot-official-offer.sdp   — the phone's webrtcReq offer SDP
    #      /tmp/aidot-official-answer.sdp  — the camera's webrtcResp answer SDP
    #      /tmp/aidot-signaling.jsonl      — every signaling message (chronological)
    #    and prints a one-line summary of each captured exchange.
    #
    # 3. Diff the official offer against our offer (from /tmp/aidot.log lines
    #    that follow "SDP offer (first 500 chars):") to find what attributes
    #    we're missing.
    #
    # Why TCP mode + tcp-hosts: the Aidot phone↔broker connection is MQTT-over-
    # TLS, not HTTPS.  mitmproxy's HTTP layer can't parse it; using --tcp-hosts
    # tells mitmproxy to MITM the TLS but pass the inner stream through as a
    # raw bidirectional byte sequence.  We parse MQTT framing here.
    #
    # Pinning analysis (research/decompiled_apk grep, 2026-04-29) confirmed no
    # app-level cert pinning for the broker host.  iOS user-installed CAs
    # always trusted, so no Frida/APK patching needed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Iterable, Iterator

# MQTT control packet types (high nibble of byte 0)
MQTT_CONNECT     = 0x10
MQTT_CONNACK     = 0x20
MQTT_PUBLISH     = 0x30
MQTT_PUBACK      = 0x40
MQTT_SUBSCRIBE   = 0x80
MQTT_SUBACK      = 0x90
MQTT_PINGREQ     = 0xC0
MQTT_PINGRESP    = 0xD0
MQTT_DISCONNECT  = 0xE0


def _decode_remaining_length(buf: bytes, offset: int) -> tuple[int, int]:
    """Decode MQTT variable-length integer; returns (value, bytes_consumed)."""
    multiplier = 1
    value = 0
    consumed = 0
    while True:
        if offset + consumed >= len(buf):
            raise ValueError("truncated remaining length")
        b = buf[offset + consumed]
        consumed += 1
        value += (b & 0x7F) * multiplier
        if not (b & 0x80):
            break
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            raise ValueError("malformed remaining length")
    return value, consumed


def parse_mqtt_packets(stream: bytes) -> Iterator[dict]:
    """Yield each MQTT packet in `stream` as a dict with type, header, payload.

    Stream is raw decrypted TCP bytes (one direction).  Skips packets we can't
    fully parse (truncated end of stream).
    """
    offset = 0
    while offset < len(stream):
        if offset + 2 > len(stream):
            return
        first = stream[offset]
        ptype = first & 0xF0
        try:
            remaining, rl_bytes = _decode_remaining_length(stream, offset + 1)
        except ValueError:
            return
        total = 1 + rl_bytes + remaining
        if offset + total > len(stream):
            # Truncated — wait for more data (can't, stream is bounded)
            return
        body = stream[offset + 1 + rl_bytes : offset + total]
        yield {"type": ptype, "flags": first & 0x0F, "body": body, "offset": offset}
        offset += total


def parse_publish(body: bytes, qos: int) -> tuple[str, bytes] | None:
    """Parse an MQTT PUBLISH variable header + payload. Returns (topic, payload)."""
    if len(body) < 2:
        return None
    topic_len = (body[0] << 8) | body[1]
    if 2 + topic_len > len(body):
        return None
    topic = body[2 : 2 + topic_len].decode("utf-8", errors="replace")
    rest = body[2 + topic_len :]
    if qos > 0:
        # 2-byte packet identifier
        if len(rest) < 2:
            return None
        rest = rest[2:]
    return topic, rest


def extract_from_flow(flow, outputs: dict) -> None:
    """Process one mitmproxy flow.  Updates `outputs` dict in place."""
    # Only TCP flows for our broker are interesting
    if not hasattr(flow, "messages"):
        return
    host = getattr(flow.client_conn, "address", None)
    server = getattr(flow.server_conn, "address", None)
    server_host = (server[0] if server else "") or ""
    if "arnoo" not in server_host and "arnoo" not in (host[0] if host else ""):
        # Not our broker — skip
        return

    # mitmproxy TCP flows: messages is a list with .from_client and .content
    direction_buffers: dict[bool, bytearray] = {True: bytearray(), False: bytearray()}
    for msg in flow.messages:
        direction_buffers[msg.from_client].extend(msg.content)

    for from_client, buf in direction_buffers.items():
        direction = "C→S" if from_client else "S→C"
        for pkt in parse_mqtt_packets(bytes(buf)):
            if pkt["type"] != MQTT_PUBLISH:
                continue
            qos = (pkt["flags"] >> 1) & 0x03
            parsed = parse_publish(pkt["body"], qos)
            if parsed is None:
                continue
            topic, payload = parsed
            # Only IPC signaling topics are interesting
            if "/IPC/" not in topic:
                continue
            try:
                envelope = json.loads(payload.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            method = envelope.get("method", "?")
            outputs["jsonl"].append({
                "direction": direction,
                "topic": topic,
                "method": method,
                "envelope": envelope,
            })

            # Cherry-pick: phone's webrtcReq carries the offer SDP we want
            inner_payload = envelope.get("payload") or {}
            offer_obj = inner_payload.get("offer") or {}
            sdp = offer_obj.get("sdp")
            if sdp:
                if method == "webrtcReq" and outputs["offer_sdp"] is None:
                    outputs["offer_sdp"] = sdp
                    print(f"  → captured OFFER SDP ({len(sdp)} bytes) from {topic}")
                elif method == "webrtcResp" and outputs["answer_sdp"] is None:
                    outputs["answer_sdp"] = sdp
                    print(f"  → captured ANSWER SDP ({len(sdp)} bytes) from {topic}")
            print(f"  {direction} {method:18s} {topic}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("flowfile", help="Path to mitmproxy .flows dump")
    parser.add_argument("--out-dir", default="/tmp", help="Where to write extracted SDPs (default /tmp)")
    args = parser.parse_args()

    try:
        from mitmproxy.io import FlowReader
    except ImportError:
        print("ERROR: mitmproxy not installed.  pip install mitmproxy", file=sys.stderr)
        return 2

    outputs = {"offer_sdp": None, "answer_sdp": None, "jsonl": []}
    with open(args.flowfile, "rb") as f:
        reader = FlowReader(f)
        for flow in reader.stream():
            extract_from_flow(flow, outputs)

    if outputs["offer_sdp"]:
        path = os.path.join(args.out_dir, "aidot-official-offer.sdp")
        with open(path, "w") as f:
            f.write(outputs["offer_sdp"])
        print(f"\nWrote {path}")
    else:
        print("\nWARNING: no webrtcReq offer SDP found in capture", file=sys.stderr)

    if outputs["answer_sdp"]:
        path = os.path.join(args.out_dir, "aidot-official-answer.sdp")
        with open(path, "w") as f:
            f.write(outputs["answer_sdp"])
        print(f"Wrote {path}")

    if outputs["jsonl"]:
        path = os.path.join(args.out_dir, "aidot-signaling.jsonl")
        with open(path, "w") as f:
            for entry in outputs["jsonl"]:
                f.write(json.dumps(entry) + "\n")
        print(f"Wrote {path} ({len(outputs['jsonl'])} signaling messages)")

    return 0 if outputs["offer_sdp"] else 1


if __name__ == "__main__":
    sys.exit(main())
