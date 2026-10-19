"""Fixed test-only fixture namespace; no filesystem search or business execution.

This is a NEW SOURCE proposal, not an old helper identity recovery.
Original method-local imports retain their original bodies via fixed aliases.
Only normal test_ibsw225_* files are discovered; these helpers are not suites.
"""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REGISTRY = (
    ("test_upgrade_cli", "_fixture_test_upgrade_cli"),
    ("test_known_hosts", "_fixture_test_known_hosts"),
    ("test_manual_execution", "_fixture_test_manual_execution"),
    ("test_nvos_observations", "_fixture_test_nvos_observations"),
    ("test_three_component_workflow", "_fixture_test_three_component_workflow"),
    ("test_access_recovery", "_fixture_test_access_recovery"),
    ("test_grouped_summary", "_fixture_test_grouped_summary"),
    ("test_runtime_budgets", "_fixture_test_runtime_budgets"),
    ("test_os_alternatives", "_fixture_test_os_alternatives"),
    ("test_input_isolation", "_fixture_test_input_isolation"),
    ("test_health_upgrade_gate", "_fixture_test_health_upgrade_gate"),
    ("test_compact_summary", "_fixture_test_compact_summary"),
    ("test_os_download_telemetry", "_fixture_test_os_download_telemetry"),
    ("test_standalone_links", "_fixture_test_standalone_links"),
)
OWNED = {}  # Only module objects created by this exact registry instance may be cached.

def _owned(module, relative):
    actual = getattr(module, "__file__", None)
    spec = getattr(module, "__spec__", None)
    loader = getattr(module, "__loader__", None)
    expected = HERE / (relative + ".py")
    return (actual is not None and Path(actual).resolve() == expected
        and spec is not None and Path(spec.origin).resolve() == expected
        and getattr(loader, "path", None) == str(expected))

def install_fixed_fixtures():
    """Load real complete fixtures in fixed eager dependency order, no result mocks."""
    loaded = {}
    for legacy, leaf in REGISTRY:
        canonical = "test_cases.ibsw225_fixture_support." + leaf
        path = HERE / (leaf + ".py")
        if not path.is_file() or path.is_symlink():
            raise AssertionError("Fixed canonical fixture source missing: " + leaf)
        module = sys.modules.get(canonical)
        old = sys.modules.get(legacy)
        if module is not None:
            if OWNED.get(canonical) is not module or old is not module or not _owned(module, leaf):
                raise AssertionError("Foreign or split canonical/legacy fixture identity")
        else:
            if old is not None:
                raise AssertionError("Foreign legacy fixture cannot satisfy fixed namespace")
            spec = importlib.util.spec_from_file_location(canonical, path)
            if spec is None or spec.loader is None:
                raise AssertionError("Fixed fixture source loader unavailable")
            module = importlib.util.module_from_spec(spec)
            # Exact aliases share one real object before original eager imports.
            sys.modules[canonical] = module
            sys.modules[legacy] = module
            try:
                spec.loader.exec_module(module)
                OWNED[canonical] = module
            except BaseException:
                if sys.modules.get(canonical) is module:
                    del sys.modules[canonical]
                if sys.modules.get(legacy) is module:
                    del sys.modules[legacy]
                raise
        if not _owned(module, leaf) or sys.modules.get(legacy) is not module:
            raise AssertionError("Canonical fixture source/alias identity drift")
        loaded[legacy] = module
    return loaded
