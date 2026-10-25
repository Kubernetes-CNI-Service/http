"""Explicit Linux-manager test port; never native Linux evidence on Darwin."""
from contextlib import contextmanager
import os
import sys
from unittest import mock

@contextmanager
def declared_linux_fdinfo_for_darwin_fixture(api):
    """Adapt only a declared Linux-manager fixture on actual Darwin.

    The original Darwin lock guard still runs against the real FD and path.
    Its existing native limitations remain; this is not a Linux current-OFD
    witness. Actual Linux keeps the untouched production /proc reader.
    Never install this around the independent Linux fdinfo negative tests.
    """
    if sys.platform != "darwin":
        yield
        return
    native_guard = api._require_runtime_lock_guard

    def declared_current_fd(descriptor):
        with mock.patch.object(api, "runtime_os", return_value="Darwin"):
            native_guard(descriptor)
        metadata = os.fstat(descriptor)
        return (
            f"pos:\t0\nflags:\t0100002\nmnt_id:\t31\nino:\t{metadata.st_ino}\n"
            f"lock:\t1: FLOCK ADVISORY WRITE {os.getpid()} "
            f"{os.major(metadata.st_dev):02x}:{os.minor(metadata.st_dev):02x}:"
            f"{metadata.st_ino} 0 EOF\n"
        ).encode("ascii")

    with mock.patch.object(api, "_read_runtime_lock_fdinfo", side_effect=declared_current_fd):
        yield
