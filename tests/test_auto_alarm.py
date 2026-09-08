"""The siren's automatic trigger: on/off, and what sets it off.

`getAutoAlarm` returns `[{autoAlarm, motionDetection, humanDetect}]` -- a master
switch plus which events fire it. Probed on real hardware 2026-09-07, and it is
NOT a mirror of anything already exposed: on an A000088 its `motionDetection`
read 0 while the camera's own motion-detection setting read True, and on an
A001064 its `humanDetect` read 0 while `getRoiHuman`'s read 1. Two independent
settings that happen to share field names.

Same discipline as the detection types: read-modify-write against the camera's
own object so a flag we do not model cannot be reset, and a camera that does not
answer is unknown rather than all-off.
"""

import asyncio

from aidot_cameras.camera.controls import _CameraControlsMixin


class _Cam(_CameraControlsMixin):
    device_id = "cam1"

    def __init__(self, out):
        self._out = out
        self.triggered: list = []

    async def async_query_device_action(self, action, params=None, **kw):
        return self._out

    async def async_trigger_device_action(self, action, params=None, **kw):
        self.triggered.append((action, params))
        return True


_LIVE = [{"autoAlarm": 0, "motionDetection": 0, "humanDetect": 1}]


def test_reads_the_master_and_both_triggers():
    got = asyncio.run(_Cam(_LIVE).async_get_auto_alarm())
    assert got == {"autoAlarm": False, "motionDetection": False,
                   "humanDetect": True}


def test_a_camera_that_does_not_answer_is_unknown_not_all_off():
    assert asyncio.run(_Cam(None).async_get_auto_alarm()) is None


def test_setting_one_flag_preserves_the_others():
    """Turning a trigger on must not silently disarm the master, or arm it."""
    cam = _Cam(_LIVE)
    assert asyncio.run(cam.async_set_auto_alarm("motionDetection", True)) is True
    action, payload = cam.triggered[0]
    assert action == "setAutoAlarm"
    row = payload[0]
    assert row["motionDetection"] == 1     # the one we changed
    assert row["autoAlarm"] == 0           # master untouched - still disarmed
    assert row["humanDetect"] == 1         # other trigger untouched
    assert set(row) == set(_LIVE[0])


def test_a_key_the_camera_does_not_report_is_refused():
    cam = _Cam(_LIVE)
    assert asyncio.run(cam.async_set_auto_alarm("sirenDetect", True)) is False
    assert cam.triggered == []


def test_no_write_when_the_camera_will_not_say_what_it_has():
    cam = _Cam(None)
    assert asyncio.run(cam.async_set_auto_alarm("autoAlarm", True)) is False
    assert cam.triggered == []
