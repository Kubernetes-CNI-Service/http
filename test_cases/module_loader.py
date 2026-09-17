"""Shared source loader: remove only helper-owned paths, not module authority.

Production modules may establish import paths used by later lazy imports.
Those entries must survive loading; callers needing process isolation should
use a subprocess, not silently remove a module's declared paths.
"""
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


class _HelperPath(str):
    """Distinct identity even when a path string was interned by a caller."""


def load_script(name: str, path: Path):
    path = Path(path)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    owned = [_HelperPath(str(parent)) for parent in (path.parent, ROOT / "tools", ROOT)]
    sys.path[:0] = owned
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        raise
    finally:
        for entry in owned:
            for index, current in enumerate(sys.path):
                if current is entry:
                    del sys.path[index]
                    break
        if previous is not None:
            sys.modules[name] = previous
    # Keep a newly registered module for dataclasses and other name lookups.
    return module
