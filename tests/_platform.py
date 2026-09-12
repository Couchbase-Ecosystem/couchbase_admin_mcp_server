"""Platform capabilities the suite needs, probed once rather than assumed.

Six tests in this suite prove a security property by building the attack: they
create a symlink where a log or audit file is expected and assert the server
refuses to follow it. Creating a symlink on Windows needs either Developer Mode
or an elevated process (``SeCreateSymbolicLinkPrivilege``), so on an ordinary
developer machine those six failed with ``OSError: [WinError 1314] A required
privilege is not held by the client`` -- a failure of the test's own setup, not
of the property under test, but indistinguishable from a real regression in a
list of 37 failures.

Probed rather than inferred from ``os.name``: Developer Mode is common enough on
Windows that a blanket platform check would skip tests that would have run, and
the probe costs one file operation for the whole session.
"""

from __future__ import annotations

import os
import tempfile

import pytest


def _symlinks_available() -> bool:
    if not hasattr(os, "symlink"):
        return False
    with tempfile.TemporaryDirectory() as directory:
        target = os.path.join(directory, "target")
        link = os.path.join(directory, "link")
        with open(target, "w", encoding="utf-8"):
            pass
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError, AttributeError):
            return False
        return True


#: True where this process may create symlinks.
SYMLINKS_AVAILABLE = _symlinks_available()

#: Decorator for a test whose SETUP needs a symlink. Do not use it to skip a test
#: that merely asserts on symlink handling by other means -- the refusal logic
#: itself is platform independent and should stay covered everywhere.
requires_symlinks = pytest.mark.skipif(
    not SYMLINKS_AVAILABLE,
    reason=(
        "creating a symlink requires Developer Mode or an elevated process on "
        "this platform; the test builds one as its fixture"
    ),
)

#: True where a file's permission bits mean something. Windows has no mode to
#: set, so logging_config._restrict_to_owner deliberately does nothing there and
#: any test asserting on 0600 is asserting about POSIX, not about this server.
FILE_MODES_AVAILABLE = hasattr(os, "fchmod")

requires_file_modes = pytest.mark.skipif(
    not FILE_MODES_AVAILABLE,
    reason="file permission bits are not available on this platform",
)
