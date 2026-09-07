"""Let one device's peer-id fields be overridden, so the camera's client-type
classification can be tested on the live camera.

The A001064 firmware parses the peer id with `%[^_]_%[^_]_%d_%d_%d`
(`parse_peer_id` at 0x298ef8) and takes its client class from the FIRST
CHARACTER of field 2 - `client_type = field2[0] - '0'` - against
EN_WEBRTC_CLIENT_TYPE_{APP_ANDROID,APP_IOS,WEB,ALEXA,GOOGLE_HOME} = 0..4. The
vendor app hard-codes a leading '0'; we generate six random hex digits, so we
announce a uniformly random class and an out-of-range one 11 times in 16. See
AIDOT-FINDINGS-client-type-is-peerid-field2-2026-08-31.md.

The override is SCOPED TO ONE DEVICE. It also sets the three trailing integers,
and an unscoped file would push an SDES `_2_0_1` tail at the DTLS cameras, which
discard a peer id with the wrong transport digit.

Off by default: with no override file the id is byte-identical to today's.
"""
import re

import pytest

from aidot_cameras.camera.client import CameraMixin
from aidot_cameras.camera import client as client_mod

SHAPE = re.compile(r"^[0-9a-f]{32}_[0-9a-f]{6}_(\d+)_(\d+)_(\d+)$")
DEV = "12b144cb12da4994945bffd4f1acfd0c"
OTHER = "338603b50fce46ef8d2545fc7362c967"


def _gen(**kw):
    return CameraMixin.generate_webrtc_peer_id(sdes=True, **kw)


class TestDefault:
    def test_shape_is_unchanged(self, tmp_path, monkeypatch):
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(tmp_path / "absent"))
        pid = _gen(device_id=DEV)
        assert SHAPE.match(pid), pid

    def test_sdes_and_dtls_defaults_are_untouched(self, tmp_path, monkeypatch):
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(tmp_path / "absent"))
        assert SHAPE.match(_gen(device_id=DEV)).groups() == ("2", "0", "1")
        assert SHAPE.match(
            CameraMixin.generate_webrtc_peer_id(sdes=False, device_id=DEV)
        ).groups() == ("2", "0", "2")

    def test_two_ids_differ_in_their_random_parts(self, tmp_path, monkeypatch):
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(tmp_path / "absent"))
        assert _gen(device_id=DEV) != _gen(device_id=DEV)


class TestOverride:
    def test_all_three_fields_can_be_set(self, tmp_path, monkeypatch):
        f = tmp_path / "pid"; f.write_text(f"{DEV}:3_0_1\n")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        assert SHAPE.match(_gen(device_id=DEV)).groups() == ("3", "0", "1")

    def test_the_random_parts_stay_random(self, tmp_path, monkeypatch):
        f = tmp_path / "pid"; f.write_text(f"{DEV}:3_0_1")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        a, b = _gen(device_id=DEV), _gen(device_id=DEV)
        assert a != b and a.split("_")[2:] == b.split("_")[2:]

    def test_four_fields_also_pin_the_terminal_id(self, tmp_path, monkeypatch):
        """Field 2 carries the client class, so it has to be pinnable."""
        f = tmp_path / "pid"; f.write_text(f"{DEV}:4a1b2c_2_0_1")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        pid = _gen(device_id=DEV)
        assert SHAPE.match(pid), pid
        assert pid.split("_")[1] == "4a1b2c"


class TestOneCharTerminalPinsOnlyTheClass:
    """The arm we actually want to run. Field 1 is already stable per process,
    so pinning all six characters of field 2 makes every peer id byte-identical
    across opens - that is cross-session peer-id reuse, and the camera has a
    dedup path keyed on the peer id. A result got that way could not separate
    the client class from the reuse. One character pins the class only."""

    def test_first_char_is_pinned_and_the_tail_stays_random(self, tmp_path, monkeypatch):
        f = tmp_path / "pid"; f.write_text(f"{DEV}:4_2_0_1")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        ids = [_gen(device_id=DEV) for _ in range(20)]
        for pid in ids:
            assert SHAPE.match(pid), pid
            assert pid.split("_")[1][0] == "4"
            assert len(pid.split("_")[1]) == 6
        tails = {pid.split("_")[1][1:] for pid in ids}
        assert len(tails) > 1, "the tail must stay random - this is not reuse"

    def test_the_length_never_changes(self, tmp_path, monkeypatch):
        f = tmp_path / "pid"; f.write_text(f"{DEV}:3_2_0_1")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        assert len(_gen(device_id=DEV).split("_")[1]) == 6

    @pytest.mark.parametrize("term", ["", "z", "44", "4a1b2", "4a1b2c7", "G"])
    def test_only_widths_one_and_six_are_accepted(self, tmp_path, monkeypatch, term):
        f = tmp_path / "pid"; f.write_text(f"{DEV}:{term}_2_0_1")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        pid = _gen(device_id=DEV)
        assert SHAPE.match(pid).groups() == ("2", "0", "1")

    @pytest.mark.parametrize("tail", ["", "  ", "3_0", "a_0_1", "3_0_x",
                                      "-1_0_1", "3_0_1 extra",
                                      "3_2_0_1",          # terminal not 6 hex
                                      "zzzzzz_2_0_1",     # terminal not hex
                                      "_2_0_1",           # empty terminal
                                      "aabbcc_2_0_1_9"])  # five fields
    def test_unusable_content_falls_back_to_the_default(self, tmp_path, monkeypatch, tail):
        """A half-written override must never produce a malformed peer id - the
        camera rejects those outright and the camera would simply stop working."""
        f = tmp_path / "pid"; f.write_text(f"{DEV}:{tail}")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        assert SHAPE.match(_gen(device_id=DEV)).groups() == ("2", "0", "1")

    def test_a_missing_file_falls_back(self, tmp_path, monkeypatch):
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(tmp_path / "nope"))
        assert SHAPE.match(_gen(device_id=DEV)).groups() == ("2", "0", "1")


class TestDeviceScoping:
    """The reason this file exists at all - an unscoped override reaches every
    camera, and the trailing transport digit is per-camera."""

    def test_another_device_is_untouched(self, tmp_path, monkeypatch):
        f = tmp_path / "pid"; f.write_text(f"{DEV}:4a1b2c_3_0_1")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        assert SHAPE.match(_gen(device_id=DEV)).groups() == ("3", "0", "1")
        other = CameraMixin.generate_webrtc_peer_id(sdes=False, device_id=OTHER)
        assert SHAPE.match(other).groups() == ("2", "0", "2")
        assert other.split("_")[1] != "4a1b2c"

    def test_no_device_id_never_applies(self, tmp_path, monkeypatch):
        """A caller that forgets to pass a device id must not be overridden."""
        f = tmp_path / "pid"; f.write_text(f"{DEV}:4a1b2c_3_0_1")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        assert SHAPE.match(_gen()).groups() == ("2", "0", "1")

    @pytest.mark.parametrize("raw", ["3_0_1",              # unscoped, legacy form
                                     "aabbcc_2_0_1",      # unscoped with terminal
                                     ":3_0_1",            # empty device
                                     "deadbeef:3_0_1"])   # some other device
    def test_an_unscoped_file_applies_to_nobody(self, tmp_path, monkeypatch, raw):
        f = tmp_path / "pid"; f.write_text(raw)
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        assert SHAPE.match(_gen(device_id=DEV)).groups() == ("2", "0", "1")

    def test_surrounding_whitespace_is_tolerated(self, tmp_path, monkeypatch):
        """Same leniency as _sdes_max_session_s - a file written by hand or by
        `echo` picks up whitespace, and refusing it would silently run the
        control arm while the operator believes the treatment is live."""
        f = tmp_path / "pid"; f.write_text(f"  {DEV}  : 3_0_1 \n")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        assert SHAPE.match(_gen(device_id=DEV)).groups() == ("3", "0", "1")


class TestEveryCallSitePassesADeviceId:
    """The scoping is worthless if a call site drops the device id."""

    def test_no_bare_call_survives_in_the_source(self):
        import inspect
        from aidot_cameras.camera import client as c, webrtc_open as w
        for mod in (c, w):
            src = inspect.getsource(mod)
            for i, line in enumerate(src.splitlines()):
                if "generate_webrtc_peer_id(" not in line:
                    continue
                if line.lstrip().startswith(("#", "*", '"', "'")):
                    continue
                if "def generate_webrtc_peer_id" in line:
                    continue
                call = "\n".join(src.splitlines()[i:i + 4])
                assert "device_id=" in call, (
                    f"{mod.__name__} line {i + 1} calls generate_webrtc_peer_id "
                    f"without a device_id:\n{call}"
                )


class TestTheClassCharacterIsWeb:
    """Field 2's first character announces the client class, and we announce
    '2' (WEB).

    The history matters, because the obvious reading of it is wrong. Pinning
    this character to '0' (APP_ANDROID) was tried on 2026-08-31 and reverted:
    against a drained fleet with Home Assistant stopped, three A000088 cameras
    went 0 for 3 over nine attempts, each completing DTLS in under two seconds
    and then receiving no media. That is real - across ten live-validation runs
    the A000088 is 29 of 30 with a random character, so a 3% baseline cannot
    explain 0 of 9.

    But it was recorded as "pinning the class breaks the A000088", which is one
    arm generalised into a rule. The vendor WEB app sends '2', and that arm was
    screened on 2026-09-07 through live-validate - same sha, only the
    environment differing - at **6 of 6 A000088 cameras across two independent
    runs**, nearly all on the first attempt.

    So the class is pinned to WEB, which is what a known-good vendor client
    announces, instead of a random hex digit that was out of range 11 times in
    16. Class 2 is NOT one of the smart-home classes (3 and 4) that skip the
    camera's keepalive watchdog, so this changes what we claim to be and
    nothing about how the session is policed.
    """

    def test_field2_announces_client_class_2(self, tmp_path, monkeypatch):
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", None)
        monkeypatch.delenv("AIDOT_EXPT_PEERID_CLASS", raising=False)
        firsts = {_gen(device_id=DEV).split("_")[1][0] for _ in range(120)}
        assert firsts == {"2"}, (
            "field 2's first character is the client class; it must announce "
            f"WEB ('2'), got {sorted(firsts)}")

    def test_the_rest_of_field2_stays_random(self, tmp_path, monkeypatch):
        """Pinning all six would make every peer id identical across opens -
        cross-session reuse, which the camera dedups on."""
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", None)
        monkeypatch.delenv("AIDOT_EXPT_PEERID_CLASS", raising=False)
        tails = {_gen(device_id=DEV).split("_")[1][1:] for _ in range(40)}
        assert len(tails) > 1, "field 2 is fully pinned - that is peer-id reuse"

    def test_field2_is_still_six_hex(self, tmp_path, monkeypatch):
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", None)
        monkeypatch.delenv("AIDOT_EXPT_PEERID_CLASS", raising=False)
        for _ in range(20):
            f2 = _gen(device_id=DEV).split("_")[1]
            assert len(f2) == 6 and all(c in "0123456789abcdef" for c in f2)

    def test_the_override_can_still_screen_another_class(self, tmp_path, monkeypatch):
        """The knob has to be able to contradict the default, or the class can
        never be screened again."""
        f = tmp_path / "pid"; f.write_text(f"{DEV}:4_2_0_1")
        monkeypatch.setattr(client_mod, "EXPT_PEERID_FILE", str(f))
        assert _gen(device_id=DEV).split("_")[1][0] == "4"
