"""Copy source tools without importing unbound operator runtime output."""
from __future__ import annotations

from pathlib import Path
import shutil
import stat


ROOT = Path(__file__).resolve().parents[1]
OPERATOR_RUNTIME_LINKS = frozenset({
    "lldp-analyze-tool/99-output-p2p",
    "lldp-analyze-tool/99-output-monitor",
    "ibdiagnet-analyze-tool/99-output-p2p",
})


def copy_source_tools(destination, *, source_root=ROOT):
    """Retain copytree semantics for source bytes, modes and destination errors.

    The three declared output paths are not source, regardless of their type.
    Never follow any other source symlink.  This is a frozen test-fixture
    copier, not a replacement for production FD/authority validation.
    """
    source = Path(source_root) / "tools"
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise AssertionError("source tools root must be an actual directory")

    def ignore_runtime(directory, names):
        ignored = set()
        for name in names:
            path = Path(directory) / name
            relative = path.relative_to(source).as_posix()
            if relative in OPERATOR_RUNTIME_LINKS:
                ignored.add(name)
            elif path.is_symlink():
                raise AssertionError("unexpected symlink in source tools tree: " + relative)
        return ignored

    return shutil.copytree(source, destination, ignore=ignore_runtime)
