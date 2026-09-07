"""Human / vehicle / package / pet detection, read and written like sound.

The cameras type their detections today - `humanDetect` is already 1 on both
mains models - and Home Assistant sees none of it, only motion on/off plus a
sensitivity number.

Three things the live probe on 2026-09-07 settled, each of which this locks in:

- The payload is ``{"roi": [{...}]}`` with FIVE flags, the fifth being
  ``petDetect``.
- ``publicZone`` VARIES per camera (0 on an A000088, 1 on an A001064), so it is
  a real setting. A setter must echo the camera's own dict back with one flag
  changed, never rebuild it, or it clobbers a setting it does not model.
- A battery A001513 answers NOTHING - a null ``out``. That has to read as
  *unknown*, never as all-off, or the UI invents a state the camera never
  claimed.
"""

import asyncio

from aidot_cameras.camera.controls import _CameraControlsMixin


class _Cam(_CameraControlsMixin):
    """Just enough client to drive the two methods under test."""

    device_id = "cam1"

    def __init__(self, out):
        self._out = out
        self.queried: list = []
        self.triggered: list = []

    async def async_query_device_action(self, action, params=None, **kw):
        self.queried.append(action)
        return self._out

    async def async_trigger_device_action(self, action, params=None, **kw):
        self.triggered.append((action, params))
        return True


_LIVE = {"roi": [{"vehicleDetect": 0, "publicZone": 1, "packageDetect": 0,
                  "humanDetect": 1, "petDetect": 0}]}


def test_reads_every_flag_the_camera_reports():
    cam = _Cam(_LIVE)
    got = asyncio.run(cam.async_get_detection_types())
    assert got == {"vehicleDetect": False, "publicZone": True,
                   "packageDetect": False, "humanDetect": True,
                   "petDetect": False}
    assert cam.queried == ["getRoiHuman"]


def test_a_camera_that_does_not_answer_is_unknown_not_all_off():
    """The battery A001513 returns null. All-off would be a state it never
    claimed, and the UI would show four switches confidently turned off."""
    assert asyncio.run(_Cam(None).async_get_detection_types()) is None


def test_setting_one_flag_preserves_every_other_field():
    """publicZone is a real per-camera setting; rebuilding the dict loses it."""
    cam = _Cam(_LIVE)
    ok = asyncio.run(cam.async_set_detection_type("packageDetect", True))
    assert ok is True
    action, payload = cam.triggered[0]
    assert action == "setRoiHuman"
    roi = payload["roi"][0]
    assert roi["packageDetect"] == 1      # the one we changed
    assert roi["publicZone"] == 1         # preserved, not rebuilt
    assert roi["humanDetect"] == 1        # preserved
    assert set(roi) == set(_LIVE["roi"][0])


def test_a_key_the_camera_does_not_report_is_refused_not_invented():
    cam = _Cam(_LIVE)
    assert asyncio.run(cam.async_set_detection_type("faceDetect", True)) is False
    assert cam.triggered == []


def test_no_write_when_the_camera_will_not_say_what_it_has():
    cam = _Cam(None)
    assert asyncio.run(cam.async_set_detection_type("humanDetect", True)) is False
    assert cam.triggered == []
