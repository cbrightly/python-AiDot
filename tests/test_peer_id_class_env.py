"""An env-var route to pinning the peer id's client class, for screening only.

The camera reads its client class from field 2's first character. Pinning it to
'0' (APP_ANDROID) was tried and reverted: three A000088 cameras went 0 for 3
over nine attempts, each completing DTLS and then receiving no media. That
finding is real - checked against ten live-validation runs, the A000088 is
29/30 PASS with the random character, so a 3% baseline cannot explain 0/9.

But it only ever tested '0'. The vendor WEB app sends '2' (WEB), and that arm
has never been run. `_expt_peer_id_fields` exists to screen this, and it reads
a FILE - which the live-validation harness cannot write, it only passes env
vars. This is that route and nothing more.

It pins ONLY the class character. It deliberately cannot touch the three
trailing integers: those encode transport, and an SDES tail pushed at a DTLS
camera is silently discarded, which is how an earlier unscoped knob forced a
battery camera to ~30x its wake rate.
"""

from aidot_cameras.camera.client import _expt_peer_id_class


def test_unset_means_no_override(monkeypatch):
    monkeypatch.delenv("AIDOT_EXPT_PEERID_CLASS", raising=False)
    assert _expt_peer_id_class() is None


def test_a_single_hex_digit_is_accepted(monkeypatch):
    monkeypatch.setenv("AIDOT_EXPT_PEERID_CLASS", "2")
    assert _expt_peer_id_class() == "2"


def test_whitespace_is_tolerated(monkeypatch):
    monkeypatch.setenv("AIDOT_EXPT_PEERID_CLASS", " 2 ")
    assert _expt_peer_id_class() == "2"


def test_anything_that_would_change_the_id_shape_is_refused(monkeypatch):
    """A wrong width changes the peer id's length and the camera rejects a
    malformed id outright - fail closed rather than break every open."""
    for bad in ("22", "", "zz", "0x2", "-1"):
        monkeypatch.setenv("AIDOT_EXPT_PEERID_CLASS", bad)
        assert _expt_peer_id_class() is None, bad


def test_it_pins_only_the_first_character(monkeypatch):
    """The other five stay random: pinning all six would make every peer id
    identical across opens, which is cross-session REUSE and would confound the
    class with the camera's session-dedup path."""
    from aidot_cameras.camera.client import CameraMixin
    monkeypatch.setenv("AIDOT_EXPT_PEERID_CLASS", "2")
    monkeypatch.delenv("AIDOT_EXPT_PEERID_FILE", raising=False)

    # staticmethod: no instance, and device_id left unset so only the env knob
    # can act (the file override needs a device id and must not interfere).
    ids = {CameraMixin.generate_webrtc_peer_id(live_type=2, stream_id=0)
           for _ in range(12)}
    fields = [i.split("_") for i in ids]
    assert all(f[1][0] == "2" for f in fields), "class not pinned"
    assert len({f[1][1:] for f in fields}) > 1, "tail stopped being random"
    # and the transport digits are untouched by this knob
    assert all(f[2:] == ["2", "0", "2"] for f in fields), fields[0]
