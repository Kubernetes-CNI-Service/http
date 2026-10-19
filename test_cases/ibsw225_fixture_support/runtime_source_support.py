"""NEW source-only canonical bootstrap proposal, not an old sealed helper recovery.

Only fixed local runtime paths may be imported. This module never calls a CLI,
acquires a guard, opens project inputs, or grants device/transport permissions.
"""
from pathlib import Path
import importlib
import importlib.util
from importlib.machinery import ModuleSpec, SourceFileLoader
import sys
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "infiniband/bringup/xdr-upgrade/upgrade.py"
TOOLS = ROOT / "tools"
ENTRY_NAME = "_ibsw225_canonical_cli_source"
REGISTRY = (
    ("project_contract", "project_contract.py"),
    ("_package_common", "_package_common.py"),
    ("ssh_key_preparation", "ssh_key_preparation.py"),
    ("ibsw_upgrade_contract", "ibsw_upgrade_contract.py"),
    ("ibsw_upgrade_inputs", "ibsw_upgrade_inputs.py"),
    ("ibsw_upgrade_driver", "ibsw_upgrade_driver.py"),
    ("ibsw_upgrade_schedule", "ibsw_upgrade_schedule.py"),
    ("ibsw_upgrade_component", "ibsw_upgrade_component.py"),
    ("ibsw_upgrade_observer", "ibsw_upgrade_observer.py"),
    ("ibsw_upgrade_executor", "ibsw_upgrade_executor.py"),
    ("ibsw_upgrade_access", "ibsw_upgrade_access.py"),
    ("ibsw_upgrade_pipeline", "ibsw_upgrade_pipeline.py"),
)

def _same_file(module, path, name):
    # This is a fixed test-source identity check, not a hostile-Python sandbox.
    if type(module) is not ModuleType:
        return False
    spec = getattr(module, "__spec__", None)
    if type(spec) is not ModuleSpec or type(spec.loader) is not SourceFileLoader:
        return False
    return (module.__name__ == name and spec.name == name
            and spec.origin == str(path) and spec.loader.name == name
            and spec.loader.path == str(path)
            and getattr(module, "__loader__", None) is spec.loader
            and getattr(module, "__file__", None) is not None
            and Path(module.__file__).resolve() == path)

def support(case):
    """Normal import fixed real files, with no business operation or return mocks."""
    case.assertTrue(ENTRY.is_file(), "Canonical IB runtime entry is missing")
    case.assertTrue(TOOLS.is_dir(), "Canonical IB tools directory is missing")
    for name, relative in REGISTRY:
        target = TOOLS / relative
        case.assertTrue(target.is_file(), "Canonical fixed runtime source is missing: " + relative)
        if name in sys.modules:
            case.assertTrue(_same_file(sys.modules[name], target, name),
                            "Foreign runtime module cannot satisfy canonical bootstrap: " + name)
    # Check the entry alongside every fixed runtime cache BEFORE any import/path change.
    # Never overwrite/remove a caller-supplied foreign object, including cached None.
    if ENTRY_NAME in sys.modules:
        case.assertTrue(_same_file(sys.modules[ENTRY_NAME], ENTRY, ENTRY_NAME),
                        "Foreign CLI module cannot satisfy canonical bootstrap")
    # Fixed dependency root only. No PATH/home/cwd resolver or optional fallback.
    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))
    loaded = {}
    for name, relative in REGISTRY:
        module = importlib.import_module(name)
        case.assertTrue(_same_file(module, TOOLS / relative, name),
                        "Canonical runtime import did not bind its declared source: " + name)
        loaded[name] = module
    app = sys.modules.get(ENTRY_NAME)
    if app is None:
        spec = importlib.util.spec_from_file_location(ENTRY_NAME, ENTRY)
        case.assertIsNotNone(spec)
        case.assertIsNotNone(spec.loader)
        app = importlib.util.module_from_spec(spec)
        sys.modules[ENTRY_NAME] = app
        try:
            spec.loader.exec_module(app)
        except BaseException:
            # Never keep an incompletely initialized entry as a valid import.
            if sys.modules.get(ENTRY_NAME) is app:
                del sys.modules[ENTRY_NAME]
            raise
    case.assertTrue(_same_file(app, ENTRY, ENTRY_NAME), "Foreign CLI module cannot satisfy canonical bootstrap")
    return SimpleNamespace(ROOT=ROOT, app=app,
        contract=loaded["ibsw_upgrade_contract"], driver=loaded["ibsw_upgrade_driver"],
        inputs=loaded["ibsw_upgrade_inputs"], schedule=loaded["ibsw_upgrade_schedule"],
        component=loaded["ibsw_upgrade_component"], observer=loaded["ibsw_upgrade_observer"],
        executor=loaded["ibsw_upgrade_executor"], access=loaded["ibsw_upgrade_access"],
        pipeline=loaded["ibsw_upgrade_pipeline"])
