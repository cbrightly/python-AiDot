"""Guard against NameError-class regressions in the camera open paths.

`ast.parse`/`py_compile` only catch syntax errors, not undefined names used at
runtime (e.g. a variable referenced in one method but defined only in another).
That class of bug shipped once (0.5.5/0.5.6: `_fast_connect` referenced in
`_open_sdes_stream` but defined only in `_async_open_webrtc_stream_impl`,
breaking every SDES camera open). This test runs pyflakes and fails on any
undefined name except a small allowlist of intentional closure patterns.

It covers every module where that bug class can live: the three big open paths
carry deeply nested closures whose names are read from sibling scopes, which is
exactly the shape pyflakes catches and review does not.

**pyflakes must be installed for this to mean anything.** It was not - not in
the venv and not in CI - so from the day it was written until 2026-09-07 this
test skipped everywhere and guarded nothing. The dependency is now declared in
CI; if you see it skip locally, `pip install pyflakes` before trusting a green
run.
"""

import pathlib
import subprocess
import sys

import pytest

_CAMERA = pathlib.Path(__file__).resolve().parent.parent / "aidot_cameras" / "camera"
_SOURCES = [
    _CAMERA / "client.py",
    _CAMERA / "webrtc_open.py",
    _CAMERA / "sdes_open.py",
    _CAMERA / "protocol.py",
]

# Names pyflakes can't resolve because they're bound in an inner runtime scope
# (closure) and referenced from a sibling scope; verified working in production
# and already marked `# noqa: F821` in the source.
_ALLOWLIST = {"_enc_c8_sctp"}


@pytest.mark.parametrize("src", _SOURCES, ids=lambda p: p.name)
def test_camera_module_has_no_undefined_names(src):
    # Guard against the check going vacuous: pyflakes writes "no such file" to
    # stderr and leaves stdout empty, so a stale path would silently pass.
    assert src.is_file(), f"source under test not found: {src}"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pyflakes", str(src)],
            capture_output=True, text=True,
        )
    except FileNotFoundError:  # pragma: no cover
        pytest.skip("pyflakes not available")
    if "No module named pyflakes" in proc.stderr:  # pragma: no cover
        pytest.skip("pyflakes not installed")

    undefined = [
        line for line in proc.stdout.splitlines()
        if "undefined name" in line
        and not any(name in line for name in _ALLOWLIST)
    ]
    assert not undefined, "Undefined names (NameError risk):\n" + "\n".join(undefined)
