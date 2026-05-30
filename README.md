# python-aidot

Control AIDOT WiFi lights **and cameras** from Python and Home Assistant.

This is a camera-capable fork of the upstream lights-only
[`python-aidot`](https://github.com/Aidot-Development-Team/python-aidot). It adds
live WebRTC video streaming (DTLS and SDES-SRTP paths), snapshots, PTZ, camera
controls, cloud recordings/thumbnails, and two-way (push-to-talk) audio, plus a
Home Assistant custom component that exposes all of it.

## Library install

The camera support is **not published to PyPI** (PyPI only has the upstream
lights-only releases). Install this fork's library directly from the repo:

```bash
# lights + camera cloud/control only:
pip install "git+https://github.com/cbrightly/python-AiDot"
# add live WebRTC streaming, snapshots, and two-way audio:
pip install "python-aidot[webrtc] @ git+https://github.com/cbrightly/python-AiDot"
```

## Home Assistant component

The custom component lives in `custom_components/aidot/`. Its `manifest.json`
lists the third-party Python dependencies (aiortc, av, paho-mqtt, …) so Home
Assistant installs those automatically, **but the `aidot` library itself is not
on PyPI** — install it into Home Assistant's Python environment first:

```bash
# inside the HA venv / container
pip install "python-aidot[webrtc] @ git+https://github.com/cbrightly/python-AiDot"
```

Then copy `custom_components/aidot/` into your HA `config/custom_components/`
folder (or add this repo to HACS as a custom repository) and restart Home
Assistant.

## CLI

`test_camera.py` exercises the camera features directly — discovery, LAN probe,
WebRTC streaming, snapshots, recordings, attribute get/set, and two-way audio
(`--talk`). Run `python test_camera.py --help` for the full list.
