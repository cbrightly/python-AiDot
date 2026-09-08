"""What the MODEL declares it has, as distinct from what the cloud reports.

These are not the same thing, and the difference is what makes a control lie.
Measured 2026-09-08 on an A000088:

    cloud property list   LingerDuration = "30"
    the camera, asked
    directly over LAN     LingerDuration = absent
    writing it            acked, and nothing changed anywhere

The cloud carries a DEFAULT for a key that model has never implemented. Gating
a control on "the cloud reported a value" therefore offers it on cameras where
it cannot work -- which is exactly what shipped in 2.23.0 and had to be pulled
back. The vendor app gates on the product profile instead, and so must we.
"""

from aidot_cameras.camera.models import CameraDeviceInformation


def _device(props, **extra):
    d = {"id": "cam1", "aesKey": ["k" * 16], "password": "p",
         "product": {"serviceModules": [{"identity": "IPC/common attr",
                                         "properties": props}]}}
    d.update(extra)
    return d


def test_declared_properties_collects_what_the_model_offers():
    info = CameraDeviceInformation(_device([
        {"identity": "LingerDuration", "code": "LingerDuration"},
        {"identity": "Dimming", "code": "Dimming"},
    ]))
    assert "LingerDuration" in info.declared_properties
    assert "Dimming" in info.declared_properties


def test_a_placeholder_display_name_does_not_hide_a_property():
    """The profile's `name` is often `propertyName_<x>_<productId>`.

    Keying on it instead of `identity` reported "no model declares
    lightBehavior" when every model did.
    """
    info = CameraDeviceInformation(_device([
        {"identity": "lightBehavior", "code": "lightBehavior",
         "name": "propertyName_lightBehavior_1679075889207132162"},
    ]))
    assert "lightBehavior" in info.declared_properties


def test_a_property_with_only_a_code_is_still_collected():
    info = CameraDeviceInformation(_device([{"code": "Dimming"}]))
    assert "Dimming" in info.declared_properties


def test_a_device_with_no_profile_declares_nothing_and_does_not_raise():
    info = CameraDeviceInformation({"id": "c", "aesKey": ["k" * 16]})
    assert info.declared_properties == frozenset()


def test_a_malformed_profile_yields_nothing_rather_than_raising():
    """The profile is remote data of no guaranteed shape.

    Asserted against the collector directly, not through the constructor: the
    UPSTREAM base class parses the same profile first and indexes it without
    type checks, so a string where a list belongs raises there before this code
    runs. That fragility is pre-existing and shared with the light path, so it
    is noted rather than widened into here.
    """
    collect = CameraDeviceInformation._collect_declared_properties
    for bad in ({"product": {"serviceModules": "nope"}},
                {"product": {"serviceModules": [None]}},
                {"product": {"serviceModules": [{"properties": "nope"}]}},
                {"product": {"serviceModules": [{"properties": ["str"]}]}},
                {"product": "nope"},
                {}):
        assert collect(bad) == frozenset()


def test_declaring_nothing_is_not_the_same_as_reporting_nothing():
    """The A000088 case, locked in: the cloud reports it, the model does not.

    A gate built on the reported value would say yes here. That is the bug.
    """
    info = CameraDeviceInformation(_device([{"identity": "Dimming"}]))
    assert "LingerDuration" not in info.declared_properties
