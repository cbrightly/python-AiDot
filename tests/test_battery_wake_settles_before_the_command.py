"""A wake the camera never gets time to act on is decorative.

`_mqtt_device_cmd` published the low-power wake and the command in ONE batch,
back to back. A deeply asleep battery camera cannot process the wake before the
setDevAttrReq arrives behind it, so the command is dropped and the camera acks
nothing -- while the ack scan still reports success from the broker's own
response.

Measured 2026-09-08 on an A001513 (L2_185): writes to `lightBehavior` never
landed for hours; opening a keepalive session woke the camera in 13 s and the
identical write landed first try; and a wake followed by a 5 s gap then landed
it with no session at all. `Dimming` and `LingerDuration` hid the bug for
months because they land on a sleeping camera anyway -- the cloud shadows them.

These lock the decision, not the timing: the plan says WHETHER to wake and
whether the caller must wait, and a warm window stops a burst of attribute
writes from waking the camera once per attribute.
"""


from aidot_cameras.camera.client import WAKE_SETTLE_S, WAKE_WARM_S, _wake_plan


def test_a_mains_camera_is_never_woken_and_never_waits():
    plan = _wake_plan(is_battery=False, now=1000.0, last_wake=None)
    assert plan.wake is False
    assert plan.settle == 0.0


def test_a_sleeping_battery_camera_is_woken_and_the_caller_waits():
    plan = _wake_plan(is_battery=True, now=1000.0, last_wake=None)
    assert plan.wake is True
    assert plan.settle == WAKE_SETTLE_S
    assert plan.settle > 0, "a wake with no gap is the bug this fixes"


def test_a_second_write_inside_the_warm_window_does_not_wake_again():
    """Home Assistant writes attributes in bursts; one wake should cover them."""
    plan = _wake_plan(is_battery=True, now=1000.0 + WAKE_WARM_S - 1,
                      last_wake=1000.0)
    assert plan.wake is False
    assert plan.settle == 0.0


def test_the_warm_window_expires():
    plan = _wake_plan(is_battery=True, now=1000.0 + WAKE_WARM_S + 1,
                      last_wake=1000.0)
    assert plan.wake is True
    assert plan.settle == WAKE_SETTLE_S


def test_a_clock_that_goes_backwards_still_wakes():
    """Never let a bad timestamp silently disable the wake for good."""
    plan = _wake_plan(is_battery=True, now=500.0, last_wake=1000.0)
    assert plan.wake is True


def test_the_settle_is_long_enough_to_match_what_was_measured():
    """5 s was the shortest gap that worked; anything less is untested."""
    assert WAKE_SETTLE_S >= 5.0


def test_the_warm_window_is_shorter_than_the_camera_stays_up():
    """A write stopped landing 80 s after the camera was last awake.

    So the window must be well under that, or a burst tail lands on a camera
    that has gone back to sleep while we still think it is warm.
    """
    assert 0 < WAKE_WARM_S <= 60
