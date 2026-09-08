"""The camera's "light up when someone appears" settings.

The vendor app calls the master toggle "When Someone Appears" and it is the
`autoLightEnable` attribute this library already exposes. The three settings
that sit UNDER it in the app were missing:

  lightBehavior   enum   Constant=0, Flash=1        (default 0)
  LingerDuration  enum   20 / 30 / 40 / 50 seconds  (default 30)
  Dimming         int    10..100 step 1             (default 100)

Read from the cloud device profile 2026-09-07 (LK.IPC.A001513, the L2), and
every one of the three is carried as a live property value by the L2 and by the
A000088 alike. Of the three, `LingerDuration` and `Dimming` were confirmed on
hardware to land (written, read back changed, restored); `lightBehavior` acks
and does NOT land on either model, so the library keeps the setter and Home
Assistant deliberately ships no control for it. The vendor app CAN set it
(confirmed 2026-09-08), so this is our request being wrong rather than the
camera lacking the feature -- see `async_set_light_behavior` for what has been
refuted. The A001064 has neither `lightBehavior` nor `LingerDuration` in
its profile or its properties, so those controls must stay absent there rather
than appear reading "unknown" -- which is why every getter here answers None
for a camera that never reported the key.
"""

import asyncio

import pytest

from aidot_cameras.camera.controls import (
    LIGHT_BEHAVIORS,
    LIGHT_LINGER_DURATIONS,
    _CameraControlsMixin,
)
from aidot_cameras.camera.models import CameraStatusData


class _Cam(_CameraControlsMixin):
    device_id = "cam1"

    def __init__(self):
        self.attrs: list = []

    async def async_set_device_attribute(self, attr, value, **kw):
        self.attrs.append((attr, value))
        return True


# --- reading -----------------------------------------------------------------

def test_light_behavior_reads_as_a_name_not_a_number():
    s = CameraStatusData()
    s.update_from_camera_attributes({"lightBehavior": "1"})
    assert s.light_behavior == "flash"
    s.update_from_camera_attributes({"lightBehavior": "0"})
    assert s.light_behavior == "constant"


def test_an_unmodelled_behavior_value_is_carried_through_not_dropped():
    """A firmware that grows a third mode must not read as one we know."""
    s = CameraStatusData()
    s.update_from_camera_attributes({"lightBehavior": "7"})
    assert s.light_behavior == "7"


def test_linger_duration_reads_as_seconds():
    s = CameraStatusData()
    s.update_from_camera_attributes({"LingerDuration": "40"})
    assert s.light_linger_duration == 40


def test_trigger_brightness_reads_from_dimming():
    s = CameraStatusData()
    s.update_from_camera_attributes({"Dimming": "80"})
    assert s.light_brightness == 80


def test_dimming_still_does_not_become_the_light_entity_brightness():
    """The camera's Dimming is its floodlight level, and it has its own field.

    It must not leak into `dimming`, which is the LIGHT platform's brightness
    and is why _LIGHT_ONLY_ATTR_KEYS filters the key in the first place.
    """
    s = CameraStatusData()
    s.update_from_camera_attributes({"Dimming": "80"})
    assert s.dimming is None


def test_a_camera_that_never_reported_them_is_unknown_not_defaulted():
    s = CameraStatusData()
    s.update_from_camera_attributes({"MotionDetection_Enable": "1"})
    assert s.light_behavior is None
    assert s.light_linger_duration is None
    assert s.light_brightness is None


def test_a_partial_push_does_not_clear_what_a_full_poll_established():
    s = CameraStatusData()
    s.update_from_camera_attributes(
        {"lightBehavior": "1", "LingerDuration": "50", "Dimming": "60"})
    s.update_from_camera_attributes({"Occupancy": "1"})
    assert (s.light_behavior, s.light_linger_duration, s.light_brightness) == (
        "flash", 50, 60)


# --- writing -----------------------------------------------------------------

def test_setting_the_behavior_sends_the_camera_its_own_number():
    cam = _Cam()
    assert asyncio.run(cam.async_set_light_behavior("flash")) is True
    assert cam.attrs == [("lightBehavior", 1)]


def test_an_unknown_behavior_is_refused_and_nothing_is_sent():
    cam = _Cam()
    with pytest.raises(ValueError):
        asyncio.run(cam.async_set_light_behavior("strobe"))
    assert cam.attrs == []


def test_setting_the_linger_duration_sends_seconds():
    cam = _Cam()
    assert asyncio.run(cam.async_set_light_linger_duration(20)) is True
    assert cam.attrs == [("LingerDuration", 20)]


def test_a_duration_the_camera_does_not_offer_is_refused():
    """The camera enumerates exactly four; 35 would be accepted and ignored."""
    cam = _Cam()
    with pytest.raises(ValueError):
        asyncio.run(cam.async_set_light_linger_duration(35))
    assert cam.attrs == []


def test_trigger_brightness_is_clamped_to_the_range_the_camera_declares():
    """The profile's minimum is 10, not 0 -- 0 is not "off", it is out of range."""
    cam = _Cam()
    asyncio.run(cam.async_set_light_brightness(0))
    asyncio.run(cam.async_set_light_brightness(150))
    asyncio.run(cam.async_set_light_brightness(55))
    assert cam.attrs == [("Dimming", 10), ("Dimming", 100), ("Dimming", 55)]


def test_the_offered_values_match_what_the_camera_profile_declares():
    assert LIGHT_BEHAVIORS == {"constant": 0, "flash": 1}
    assert LIGHT_LINGER_DURATIONS == (20, 30, 40, 50)
