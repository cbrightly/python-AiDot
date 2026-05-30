#!/usr/bin/env python3
"""
Passive MQTT probe to determine if cameras push setDevAttrNotif when the app
announces user presence via iot/v1/cb/{userId}/user/connect.

Usage:
    python3 probe_user_connect.py [--device <name>]
"""
import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, ".")
import aiohttp
from aidot.client import AidotClient
from aidot.device_client import _mqtt_session

_CREDS = os.path.expanduser("~/.config/aidot/credentials.json")


async def run(args):
    creds = {}
    if os.path.exists(_CREDS):
        with open(_CREDS) as f:
            creds = json.load(f)

    username = args.username or creds.get("username") or os.environ.get("AIDOT_USERNAME")
    password = args.password or creds.get("password") or os.environ.get("AIDOT_PASSWORD")
    if not username or not password:
        print("ERROR: credentials needed (--username/--password or ~/.config/aidot/credentials.json)")
        sys.exit(1)

    async with aiohttp.ClientSession() as http:
        client = AidotClient(session=http, username=username, password=password)
        login_info = await client.async_post_login()
        user_id = login_info.get("id") or login_info.get("userId") or "?"
        print(f"Logged in as userId={user_id}")

        all_devices = (await client.async_get_all_device()).get("device_list") or []
        cameras = [d for d in all_devices if _is_camera(d)]
        if not cameras:
            print("No cameras found.")
            return

        cam = cameras[0]
        if args.device:
            q = args.device.strip().lower()
            matches = [c for c in cameras if q in (c.get("name") or "").lower() or c.get("id") == args.device]
            cam = matches[0] if matches else cam

        dc = client.get_device_client(cam)
        print(f"Using camera: {cam.get('name')} [{cam.get('modelId')}]  id={cam.get('id')}")

        # Get the same auth that async_get_camera_attributes uses
        smarthome_auth = await dc._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(dc.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        client_id = dc._user_info.get("mqttClientId") or f"app-{mqtt_user}"
        mqtt_url  = await dc._async_get_mqtt_url()

        print(f"MQTT: url={mqtt_url}  user={mqtt_user}  clientId={client_id}")
        print(f"Probe 1/2: subscribe-only (30s) — do cameras push on connect?")

        sub_topics = [
            f"iot/v1/c/{dc.user_id}/#",
            f"iot/v1/cb/{dc.user_id}/#",
            f"iot/v1/cb/{cam['id']}/#",
        ]

        received = []

        def _on_msg(topic, payload):
            ts = time.strftime("%H:%M:%S")
            print(f"  [{ts}] TOPIC: {topic}")
            try:
                body = json.loads(payload)
                method = body.get("method") or body.get("cmd") or "?"
                print(f"           method={method}  keys={list(body.keys())[:8]}")
                if "attr" in json.dumps(body):
                    print(f"           *** setDevAttrNotif payload: {json.dumps(body)[:300]}")
            except Exception:
                print(f"           raw: {payload[:200]}")
            received.append((topic, payload))

        msgs1 = await _mqtt_session(
            mqtt_url, mqtt_user, mqtt_pwd, client_id,
            subscribe_topics=sub_topics,
            publish_items=[],
            duration=30.0,
            on_message=_on_msg,
        )
        print(f"\nProbe 1 result: {len(msgs1)} messages received in 30s")
        notif1 = [t for t, _ in msgs1 if "setDevAttrNotif" in t]
        print(f"  setDevAttrNotif messages: {len(notif1)}")

        print(f"\nProbe 2/2: publish user/connect then wait 30s")
        received.clear()
        connect_topic = f"iot/v1/cb/{dc.user_id}/user/connect"
        connect_payload = json.dumps({"userId": str(dc.user_id)})
        print(f"  → publishing to {connect_topic}")

        msgs2 = await _mqtt_session(
            mqtt_url, mqtt_user, mqtt_pwd, client_id,
            subscribe_topics=sub_topics,
            publish_items=[(connect_topic, connect_payload)],
            duration=30.0,
            on_message=_on_msg,
        )
        print(f"\nProbe 2 result: {len(msgs2)} messages received in 30s")
        notif2 = [t for t, _ in msgs2 if "setDevAttrNotif" in t]
        print(f"  setDevAttrNotif messages: {len(notif2)}")

        print("\n─── CONCLUSION ───────────────────────────────────────────────────")
        if notif2:
            print("CASE 1: cameras push setDevAttrNotif on user/connect announcement")
            print("  → one-shot MQTT sessions will work for async_get_camera_attributes")
        elif msgs2:
            print("CASE 2: cameras push MQTT messages but NOT setDevAttrNotif")
            print(f"  topics seen: {[t for t, _ in msgs2[:10]]}")
        else:
            print("CASE 3: no messages received at all — camera may be offline")
            print("  → need persistent MQTT subscription with cached state")


def _is_camera(d):
    product    = d.get("product") or {}
    modules    = product.get("serviceModules") or []
    identities = [m.get("identity", "") for m in modules]
    model      = (d.get("modelId") or "").upper()
    return (any("camera" in i.lower() or "ipc" in i.lower() for i in identities)
            or "CAM" in model or "IPC" in model)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--device", default=None, help="Camera name or id")
    asyncio.run(run(parser.parse_args()))
