"""Independent canonical IB runtime and manifest source contracts; SOURCE only.

Read/render is not upgrade execution. The snapshot micro-fixture calls the real
runner as a hash consumer, not the full test runner and never a ledger writer.
"""
import fnmatch
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
ENTRY = "infiniband/bringup/xdr-upgrade/upgrade.py"
SHELLS = (
    "infiniband/bringup/xdr-upgrade/upgrade.sh",
    "infiniband/bringup/xdr-upgrade/upgrade-component.sh",
    "infiniband/bringup/xdr-upgrade/upgrade-owned-runner.sh",
)
PYTHON_RUNTIME = (ENTRY,) + tuple("tools/" + name for name in (
    "ibsw_upgrade_contract.py", "ibsw_upgrade_inputs.py", "ibsw_upgrade_schedule.py",
    "ibsw_upgrade_component.py", "ibsw_upgrade_driver.py", "ibsw_upgrade_executor.py",
    "ibsw_upgrade_observer.py", "ibsw_upgrade_access.py", "ibsw_upgrade_pipeline.py",
    "project_contract.py", "_package_common.py", "ssh_key_preparation.py",
))
GUARD = "tools/ib_bringup_runtime_guard.py"
REQUIREMENTS = "infiniband/bringup/xdr-upgrade/requirements.txt"
NORMAL_MODULES = (
    "test_cases.test_ibsw225_runtime_source_manifest_contract",
    "test_cases.test_ibsw225_ib_alias_derivation_workflow",
)
# Frozen approved 2.25 original bytes, not values copied from the tested tree.
# Composed entry/project/package/guard are intentionally NOT given flat hashes.
FROZEN_SHA256 = {
    "tools/ibsw_upgrade_contract.py": "eab213b06e6885eb7861cfb010e4863ae5008b6bf061afc508197a95d4d83088",
    "tools/ibsw_upgrade_inputs.py": "75c700e576b9fb6bd8ce5a117aa2f0c0f6e7ea96f9a1a12bc973ef814a13cbae",
    "tools/ibsw_upgrade_schedule.py": "547f957b99e7df2c8d1dfe682e501a37c31cf03e601f86564135d9bc3a287fb2",
    "tools/ibsw_upgrade_component.py": "106ddd7095e28503a355e9637dfb4fbd7fa151a2d4198e951590233da02ec45a",
    "tools/ibsw_upgrade_driver.py": "3c76f3bf02f2a41e2338bf78b38681dc5defb63a957d31155709de85f0eaffe2",
    "tools/ibsw_upgrade_executor.py": "d2b81d44d2a3a5b4682be705d3a43ed2a18e94097e8ccab6d7dd842306d373c9",
    "tools/ibsw_upgrade_observer.py": "46614501ad84e3d0d6b98fa83c9671df55431ee64e3e31901159152e5e67ece9",
    "tools/ibsw_upgrade_access.py": "aa05f8394ac390a0d0dd5313938cca6137b1c1e37dc1d5d8a83fec266de7d89f",
    "tools/ibsw_upgrade_pipeline.py": "559afde86615eb8a0d8ab518e05ffaae5da242ba0805bd5e64b9a2342ddd30ac",
    "tools/ssh_key_preparation.py": "16a383dfff78cfb9410db50d63ae4b25ad885021445ce8567c9a6d95f2a36352",
    SHELLS[0]: "0ddbbf01f920bb3f4d6dcd9406083c8ca407d8edba94aad49669b8bb36899e65",
    SHELLS[1]: "ad082ec6bbeafff9ab4921815b00a45769b65e14f1a211a1b34614df0fe3a635",
    SHELLS[2]: "cb9cc7d68fda9e24972e6335e58e5c6fa196e8d685532d949b78e290e654e1e2",
}
# Independent literal inverse of the two approved SFTP lifetime hunks.
# FROZEN_SHA256 remains the upstream source oracle, including access aa05...;
# this is not a hash whitelist for arbitrary composed implementations.
ACCESS_APPROVED_COMPOSITION = (
    (
        b"    except SharedUpgradeHold:\n"
        b"        raise\n"
        b"    except Exception as error:\n"
        b"        if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS): raise\n"
        b"        if sftp is not None:\n"
        b"            _close_sftp(sftp,'AUTHORIZED_KEYS_READ_FAILED')\n",
        b"    except BaseException as error:\n"
        b"        if sftp is not None:\n"
        b"            _close_sftp(sftp,'AUTHORIZED_KEYS_READ_FAILED')\n"
        b"        if not isinstance(error,Exception) or isinstance(error,SharedUpgradeHold):\n"
        b"            raise\n"
        b"        if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS): raise\n",
    ),
    (
        b"        if not isinstance(cleanup, Exception):\n"
        b"            raise\n"
        b"        if original is not None and not isinstance(original,Exception): return\n",
        b"        if original is not None and not isinstance(original,Exception): return\n"
        b"        if not isinstance(cleanup, Exception):\n"
        b"            raise\n",
    ),
)


def _access_upstream_bytes_from_exact_composition(payload):
    if type(payload) is not bytes:
        raise TypeError("exact source bytes required")
    # Check every new hunk before replacing any; absent/duplicate is not a
    # partially admissible source. Outside these two regions no byte changes.
    if any(payload.count(integrated) != 1 for original, integrated in ACCESS_APPROVED_COMPOSITION):
        raise ValueError("missing or duplicate approved access source hunk")
    for original, integrated in ACCESS_APPROVED_COMPOSITION:
        payload = payload.replace(integrated, original, 1)
    if any(payload.count(original) != 1 for original, integrated in ACCESS_APPROVED_COMPOSITION):
        raise ValueError("restored access source hunk is not unique")
    return payload


class AccessExactSourceCompositionTests(unittest.TestCase):
    def test_exact_two_literal_hunks_restore_only_the_original_regions(self):
        first_old, first_new = ACCESS_APPROVED_COMPOSITION[0]
        second_old, second_new = ACCESS_APPROVED_COMPOSITION[1]
        integrated = b"prefix\n" + first_new + b"middle\n" + second_new + b"suffix\n"
        expected = b"prefix\n" + first_old + b"middle\n" + second_old + b"suffix\n"
        self.assertEqual(_access_upstream_bytes_from_exact_composition(integrated), expected)

    def test_missing_unfixed_deleted_and_duplicate_hunks_are_refused(self):
        first_old, first_new = ACCESS_APPROVED_COMPOSITION[0]
        second_old, second_new = ACCESS_APPROVED_COMPOSITION[1]
        for malformed in (
            first_old + second_old,             # Upstream bytes without fix.
            first_new + second_old,             # Only the first fix.
            first_old + second_new,             # Only the second fix.
            first_new + second_new[:-1],        # A deleted hunk byte.
            first_new + first_new + second_new, # Duplicate acquisition fix.
            first_new + second_new + second_new,# Duplicate close fix.
            first_old + first_new + second_new, # Extra original hunk also refused.
        ):
            with self.subTest(source=malformed):
                with self.assertRaises(ValueError):
                    _access_upstream_bytes_from_exact_composition(malformed)

    def test_bytes_outside_hunks_are_not_normalized_or_hidden(self):
        first_old, first_new = ACCESS_APPROVED_COMPOSITION[0]
        second_old, second_new = ACCESS_APPROVED_COMPOSITION[1]
        expected = b"prefix\n" + first_old + second_old + b"suffix\n"
        integrated = b"prefix\n" + first_new + second_new + b"suffix\n"
        for drift in (b"extra\n" + integrated, integrated + b"extra\n",
                      integrated.replace(b"prefix\n", b"changed-prefix\n", 1)):
            with self.subTest(source=drift):
                restored = _access_upstream_bytes_from_exact_composition(drift)
                self.assertNotEqual(restored, expected)
                self.assertNotEqual(hashlib.sha256(restored).hexdigest(), hashlib.sha256(expected).hexdigest())


# Literal inverse of the twelve reviewed V7 LOCAL-source DATA hunks.
# No new driver hash is accepted; the original 3c76 FROZEN entry remains.
DRIVER_SOURCE_DATA_APPROVED_COMPOSITION = (
    # package-source DATA graph validator
    (
        b'             else row["returncode"] == 0) for row in rows)\n'
        b'\n'
        b'\n'
        b'def _validate_component_graph(files, binding, read, *, switch_dir):\n'
        b'    """Separate schema2 byte graph. No file or JSON field grants dispatch."""\n'
        b'    files = set(files)\n',
        b'             else row["returncode"] == 0) for row in rows)\n'
        b'\n'
        b'\n'
        b'def _validate_package_source_data_graph(files, binding, read):\n'
        b'    """Strict persisted DATA only; never reconstruct a live package owner."""\n'
        b"    if 'package-source.json' not in files:\n"
        b'        return\n'
        b"    names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')\n"
        b'    if not set(names).issubset(files):\n'
        b"        raise ValueError('source DATA requires complete original request/runner')\n"
        b"    raw = read('package-source.json')\n"
        b'    document = json.loads(raw)\n'
        b'    if (type(document) is not dict or set(document) != {\n'
        b"            'schema_version', 'state', 'execution_state', 'activation_state',\n"
        b"            'binding', 'declared_method', 'originals_sha256', 'packages'}\n"
        b"            or type(document['schema_version']) is not int or document['schema_version'] != 1\n"
        b"            or document['state'] != 'PACKAGE_SOURCE_PRELAUNCH_DATA_ONLY'\n"
        b"            or document['execution_state'] != 'NOT_EXECUTED'\n"
        b"            or document['activation_state'] != 'UNKNOWN'\n"
        b"            or document['binding'] != binding or document['declared_method'] != 'local'\n"
        b"            or re.findall(rb'(?m)^IBSW_METHOD=([a-z]+)$', read('step.sh')) != [b'local']\n"
        b'            or raw != _json_bytes(document)\n'
        b"            or document['originals_sha256'] != {name: hashlib.sha256(read(name)).hexdigest() for name in names}):\n"
        b"        raise ValueError('original source DATA/hash graph changed')\n"
        b"    request = json.loads(read('request.json'))\n"
        b"    token = request.get('request_id') if type(request) is dict else None\n"
        b"    if (type(token) is not str or not re.fullmatch(r'[0-9a-f]{32}', token)\n"
        b"            or read('request.json') != _json_bytes(dict(schema_version=1, state='REQUESTED',\n"
        b"                activation_state='UNKNOWN', execution_state='NOT_EXECUTED', binding=binding, request_id=token))):\n"
        b"        raise ValueError('source DATA requires actual original request bytes')\n"
        b"    packages = document['packages']\n"
        b"    if type(packages) is not dict or len(packages) != (2 if binding['component'] == 'cpld' else 1):\n"
        b"        raise ValueError('exact component package DATA set required')\n"
        b'    for path, row in packages.items():\n'
        b'        if (type(path) is not str or not posixpath.isabs(path) or posixpath.normpath(path) != path\n'
        b'                or any(ord(c) < 32 or ord(c) == 127 for c in path)\n'
        b"                or type(row) is not dict or set(row) != {'size', 'sha256'}\n"
        b"                or type(row['size']) is not int or row['size'] <= 0\n"
        b"                or type(row['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])):\n"
        b"            raise ValueError('strict package source DATA fields required')\n"
        b'\n'
        b'\n'
        b'\n'
        b'\n'
        b'def _validate_component_graph(files, binding, read, *, switch_dir):\n'
        b'    """Separate schema2 byte graph. No file or JSON field grants dispatch."""\n'
        b'    files = set(files)\n',
    ),
    # component graph member plus validation
    (
        b'               "component-preflight.json", "request.json", "runner.sh", "runner-binding.json",\n'
        b'               "component-dispatch.json", "component-completion.json", "after.commands", "missing.commands",\n'
        b'               "component-repair.json", "component-repair-result.json", "observed-after.commands",\n'
        b'               "repaired.commands", "configuration-diff.json", "versions.json", "execution.stdout", "execution.stderr"} | _NVUED_CHECK_FILES | _DOWNLOAD_FILES\n'
        b'    if not files <= allowed or not {"step.sh", "step-binding.json", "before.commands", "before-binding.json",\n'
        b'                                     "component-preflight.json"} <= files:\n'
        b'        raise ValueError("partial/unknown component stage graph")\n'
        b'    before, before_binding = read("before.commands"), read("before-binding.json")\n'
        b'    if not before or before_binding != _json_bytes(_before_commands_binding(binding, before)):\n'
        b'        raise ValueError("original component before hash graph changed")\n',
        b'               "component-preflight.json", "request.json", "runner.sh", "runner-binding.json",\n'
        b'               "component-dispatch.json", "component-completion.json", "after.commands", "missing.commands",\n'
        b'               "component-repair.json", "component-repair-result.json", "observed-after.commands",\n'
        b'               "repaired.commands", "configuration-diff.json", "versions.json", "execution.stdout", "execution.stderr"} | _NVUED_CHECK_FILES | _DOWNLOAD_FILES | {"package-source.json"}\n'
        b'    if not files <= allowed or not {"step.sh", "step-binding.json", "before.commands", "before-binding.json",\n'
        b'                                     "component-preflight.json"} <= files:\n'
        b'        raise ValueError("partial/unknown component stage graph")\n'
        b'    _validate_package_source_data_graph(files, binding, read)\n'
        b'    before, before_binding = read("before.commands"), read("before-binding.json")\n'
        b'    if not before or before_binding != _json_bytes(_before_commands_binding(binding, before)):\n'
        b'        raise ValueError("original component before hash graph changed")\n',
    ),
    # historical stage member
    (
        b'\n'
        b'def _stage_data_members(files):\n'
        b'    remainder, phases = set(files), []\n'
        b'    health = []\n'
        b'    for phase in _STAGE_HEALTH_PHASES:\n'
        b'        group = _stage_health_files(phase)\n',
        b'\n'
        b'def _stage_data_members(files):\n'
        b'    remainder, phases = set(files), []\n'
        b'    remainder.discard("package-source.json")\n'
        b'    health = []\n'
        b'    for phase in _STAGE_HEALTH_PHASES:\n'
        b'        group = _stage_health_files(phase)\n',
    ),
    # historical graph validation
    (
        b'    if "component-preflight.json" in files:\n'
        b'        return _validate_component_graph(files, step_binding, read, switch_dir=switch_dir)\n'
        b'    remainder, phases, has_restore, has_patch = _stage_data_members(files)\n'
        b'    originals = {}\n'
        b'    for phase in phases:\n'
        b'        raw_name, meta_name = phase + ".commands", phase + "-binding.json"\n',
        b'    if "component-preflight.json" in files:\n'
        b'        return _validate_component_graph(files, step_binding, read, switch_dir=switch_dir)\n'
        b'    remainder, phases, has_restore, has_patch = _stage_data_members(files)\n'
        b'    _validate_package_source_data_graph(files, step_binding, read)\n'
        b'    originals = {}\n'
        b'    for phase in phases:\n'
        b'        raw_name, meta_name = phase + ".commands", phase + "-binding.json"\n',
    ),
    # fixed provider source/object audit
    (
        b'        self.closed = True\n'
        b'\n'
        b'\n'
        b'class _PreparedRunScope:\n'
        b'    """Live local DATA transaction only. No dispatcher or device-result writer."""\n'
        b'    def __init__(self, entry, cwd, args, run_directory, *, manual_execution=False):\n',
        b'        self.closed = True\n'
        b'\n'
        b'\n'
        b'\n'
        b'def _fixed_package_source_api(scope):\n'
        b'    """Fresh fixed sibling source/object proof; never import by search path.\n'
        b'\n'
        b'    Existing no-follow input owners close before a package factory may run.\n'
        b'    Compiled source is compared, not executed for an already loaded provider.\n'
        b'    Missing providers execute only the held fixed bytes, never a foreign loader.\n'
        b'    This is a fixed local source contract, not a hostile-interpreter sandbox.\n'
        b'    """\n'
        b'    import builtins\n'
        b'    import errno as stdlib_errno\n'
        b'    import importlib.machinery\n'
        b'    import importlib.util\n'
        b'    import math as stdlib_math\n'
        b'    import time as stdlib_time\n'
        b'    from types import CodeType, FunctionType, ModuleType\n'
        b'    from ibsw_upgrade_inputs import _HeldDirectory\n'
        b'\n'
        b"    name = 'ibsw_upgrade_scp'\n"
        b"    path = Path(__file__).absolute().parent / (name + '.py')\n"
        b'    directory = source = None\n'
        b'    module = created = result = None\n'
        b'    primary = None\n'
        b'    cleanup = []\n'
        b'    try:\n'
        b'        directory = _HeldDirectory(path.parent)\n'
        b'        source = _HeldFile(path, directory)\n'
        b'        info = os.fstat(source.fd)\n'
        b'        if info.st_nlink != 1 or info.st_mode & 0o022:\n'
        b"            raise SharedUpgradeHold('fixed package provider source is unsafe')\n"
        b"        code = compile(source.payload, str(path), 'exec',\n"
        b'                       dont_inherit=True, optimize=sys.flags.optimize)\n'
        b'\n'
        b'        def original_code(parent, selected):\n'
        b'            matches = [item for item in parent.co_consts\n'
        b'                       if type(item) is CodeType and item.co_name == selected]\n'
        b'            if len(matches) != 1:\n'
        b"                raise SharedUpgradeHold('fixed provider definition is not unique')\n"
        b'            return matches[0]\n'
        b'\n'
        b'        module = sys.modules.get(name)\n'
        b'        if name in sys.modules and module is None:\n'
        b"            raise SharedUpgradeHold('cached absent provider marker is not import permission')\n"
        b'        if module is None:\n'
        b'            spec = importlib.util.spec_from_file_location(name, str(path))\n'
        b'            module = importlib.util.module_from_spec(spec)\n'
        b'            created = module\n'
        b'            sys.modules[name] = module  # Dataclass declaration needs its own slot.\n'
        b'            exec(code, module.__dict__)\n'
        b'        if type(module) is not ModuleType or sys.modules.get(name) is not module:\n'
        b"            raise SharedUpgradeHold('foreign package provider module')\n"
        b'        namespace = vars(module)\n'
        b"        spec, loader = namespace.get('__spec__'), namespace.get('__loader__')\n"
        b"        if (namespace.get('__name__') != name or namespace.get('__file__') != str(path)\n"
        b'                or type(spec) is not importlib.machinery.ModuleSpec\n'
        b'                or type(loader) is not importlib.machinery.SourceFileLoader\n'
        b'                or spec.name != name or spec.origin != str(path) or spec.loader is not loader\n'
        b'                or loader.name != name or loader.path != str(path)\n'
        b"                or namespace.get('__builtins__') is not builtins.__dict__):\n"
        b"            raise SharedUpgradeHold('fixed package provider origin changed')\n"
        b'\n'
        b'        def function(value, expected):\n'
        b'            if (type(value) is not FunctionType or value.__globals__ is not namespace\n'
        b'                    or value.__module__ != name or value.__code__ != expected\n'
        b'                    or value.__closure__ is not None or value.__defaults__ is not None\n'
        b'                    or value.__kwdefaults__ is not None):\n'
        b"                raise SharedUpgradeHold('foreign package provider function')\n"
        b'            return value\n'
        b'\n'
        b"        factory = function(namespace.get('package_content_owner'),\n"
        b"                           original_code(code, 'package_content_owner'))\n"
        b"        for selected in ('_identity', '_directory_identity', '_object_key'):\n"
        b'            function(namespace.get(selected), original_code(code, selected))\n'
        b"        owner_class = namespace.get('_PackageContentOwner')\n"
        b'        if (type(owner_class) is not type or owner_class.__bases__ != (object,)\n'
        b'                or owner_class.__module__ != name):\n'
        b"            raise SharedUpgradeHold('foreign package provider class')\n"
        b"        class_code = original_code(code, '_PackageContentOwner')\n"
        b'        methods = {item.co_name: item for item in class_code.co_consts if type(item) is CodeType}\n'
        b'        members = vars(owner_class)\n'
        b"        if (set(members) != set(methods) | {'__module__', '__doc__', '__dict__', '__weakref__'}\n"
        b"                or members['__doc__'] is not None):\n"
        b"            raise SharedUpgradeHold('package provider class namespace changed')\n"
        b'        for selected, expected in methods.items():\n'
        b'            function(members.get(selected), expected)\n'
        b"        error_class = namespace.get('ContentHold')\n"
        b'        if (type(error_class) is not type or error_class.__bases__ != (ValueError,)\n'
        b'                or error_class.__module__ != name\n'
        b"                or not set(vars(error_class)) <= {'__module__', '__doc__', '__weakref__'}):\n"
        b"            raise SharedUpgradeHold('package provider error class changed')\n"
        b'        for selected, expected in (\n'
        b"                ('os', os), ('Path', Path), ('stat', stat), ('hashlib', hashlib),\n"
        b"                ('threading', threading), ('time', stdlib_time),\n"
        b"                ('math', stdlib_math), ('errno', stdlib_errno)):\n"
        b'            if namespace.get(selected) is not expected:\n'
        b"                raise SharedUpgradeHold('package provider original dependency changed')\n"
        b'        source.verify()\n'
        b'        if (sys.modules.get(name) is not module\n'
        b"                or namespace.get('package_content_owner') is not factory\n"
        b"                or namespace.get('_PackageContentOwner') is not owner_class):\n"
        b"            raise SharedUpgradeHold('package provider original object joint changed')\n"
        b'        result = module, factory, owner_class\n'
        b'    except BaseException as error:\n'
        b'        primary = error\n'
        b'    finally:\n'
        b'        for held in (source, directory):\n'
        b'            if held is not None:\n'
        b'                try:\n'
        b'                    held.close()\n'
        b'                except BaseException as error:\n'
        b'                    cleanup.append(error)\n'
        b'                    if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):\n'
        b'                        primary = error\n'
        b'        if cleanup:\n'
        b'            # Unknown source cleanup poisons this actual scope; never retry FDs.\n'
        b'            scope.cleanup_issues.extend(cleanup)\n'
        b'            if scope._package_source_lifecycle_failure is None:\n'
        b'                scope._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                    'fixed package provider source cleanup uncertain; parent retained')\n"
        b'        if primary is not None and created is not None and sys.modules.get(name) is created:\n'
        b'            del sys.modules[name]\n'
        b'    if primary is not None:\n'
        b'        if not isinstance(primary, Exception):\n'
        b'            raise primary\n'
        b"        raise SharedUpgradeHold('fixed package source provider audit failed') from None\n"
        b'    return result\n'
        b'\n'
        b'\n'
        b'class _PreparedRunScope:\n'
        b'    """Live local DATA transaction only. No dispatcher or device-result writer."""\n'
        b'    def __init__(self, entry, cwd, args, run_directory, *, manual_execution=False):\n',
    ),
    # scope source ownership state
    (
        b'        self._native_schedule_started = False\n'
        b'        self._cooperative_status_snapshots = False\n'
        b'        self._native_completions = {}\n'
        b'        self._native_component_canaries = {}\n'
        b'        self.run_directory = Path(run_directory)\n'
        b'        try:\n',
        b'        self._native_schedule_started = False\n'
        b'        self._cooperative_status_snapshots = False\n'
        b'        self._native_completions = {}\n'
        b'        self._package_source_owner = None\n'
        b'        self._package_source_owner_class = None\n'
        b'        self._package_source_parent = None\n'
        b'        self._package_source_selection = None\n'
        b'        self._package_source_owns = False\n'
        b'        self._package_source_borrowers = set()\n'
        b'        self._package_source_lifecycle_failure = None\n'
        b'        self._native_component_canaries = {}\n'
        b'        self.run_directory = Path(run_directory)\n'
        b'        try:\n',
    ),
    # freeze/capture/borrow lifecycle
    (
        b'        if stat.S_IMODE(os.fstat(directory.fd).st_mode) != 0o700:\n'
        b'            raise ValueError("private node/stage/run directory must be 0700")\n'
        b'\n'
        b'    def fork_readiness_scope(self, node, source_baselines=()):\n'
        b'        """Independent startup owner; never concurrently mutate parent maps."""\n'
        b'        if self.closed or self._native_schedule_started or node not in self.devices:\n'
        b"            raise SharedUpgradeHold('startup scope is outside the original pre-upgrade selection')\n"
        b'        child = _PreparedRunScope(*self._open_context, self.run_directory,\n'
        b'                                  manual_execution=self.manual_execution)\n'
        b'        try:\n',
        b'        if stat.S_IMODE(os.fstat(directory.fd).st_mode) != 0o700:\n'
        b'            raise ValueError("private node/stage/run directory must be 0700")\n'
        b'\n'
        b'    def freeze_package_sources(self, selections, *, deadline, max_fds):\n'
        b'        """Freeze explicit LOCAL declaration sources, not device-current authority."""\n'
        b'        self.verify()\n'
        b'        provider, package_content_owner, owner_class = _fixed_package_source_api(self)\n'
        b"        if (not self.manual_execution or self.parsed.method != 'local'\n"
        b'                or self._native_schedule_started or self._package_source_owner is not None\n'
        b'                or self._package_source_parent is not None\n'
        b'                or type(selections) is not tuple or not selections):\n'
        b"            raise SharedUpgradeHold('original parent LOCAL source DATA selection required')\n"
        b'        selected, paths = [], set()\n'
        b'        for row in selections:\n'
        b'            if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not str\n'
        b'                    or type(row[1]) is not int or row[0] not in self.parsed.selected):\n'
        b"                raise SharedUpgradeHold('original selected component/index required')\n"
        b'            selected.append(row)\n'
        b'            paths.update(Path(p.path) for p in self._package_source_packages(*row))\n'
        b'        if len(set(selected)) != len(selected):\n'
        b"            raise SharedUpgradeHold('duplicate source stage selection')\n"
        b"        if (sys.modules.get('ibsw_upgrade_scp') is not provider\n"
        b"                or vars(provider).get('package_content_owner') is not package_content_owner\n"
        b"                or vars(provider).get('_PackageContentOwner') is not owner_class):\n"
        b"            raise SharedUpgradeHold('original package provider changed before factory')\n"
        b'        try:\n'
        b'            owner = package_content_owner(self.policy.package_dir, tuple(sorted(paths)),\n'
        b'                                          deadline=deadline, max_fds=max_fds)\n'
        b'        except BaseException:\n'
        b'            # The real constructor owns any partial originals/cleanup. No owner\n'
        b'            # returned to adopt; revoke this parent group before another freeze.\n'
        b'            if self._package_source_lifecycle_failure is None:\n'
        b'                self._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                    'original package source acquisition failed; parent group retained')\n"
        b'            raise  # Preserve the original error/NI object and its existing cause.\n'
        b'        # Register the actual owner before any later verification can fail.\n'
        b'        self._package_source_owner = owner\n'
        b'        self._package_source_owner_class = owner_class\n'
        b'        self._package_source_owns = True\n'
        b'        self._package_source_selection = (tuple(sorted(selected)), self.policy,\n'
        b'                                         self.run_directory, self.plan_sha256)\n'
        b'        try:\n'
        b'            self.verify()\n'
        b'        except BaseException as original:\n'
        b'            try:\n'
        b'                owner.close()\n'
        b'            except BaseException as cleanup:\n'
        b'                self.cleanup_issues.append(cleanup)\n'
        b'                if isinstance(original, Exception) and not isinstance(cleanup, Exception):\n'
        b'                    raise\n'
        b'            raise\n'
        b'        return owner\n'
        b'\n'
        b'    def _package_source_packages(self, component, index):\n'
        b'        if component not in self.parsed.selected or type(index) is not int:\n'
        b"            raise SharedUpgradeHold('foreign declared package source stage')\n"
        b"        if component == 'os' and 0 <= index < len(self.policy.os):\n"
        b'            return (self.policy.os[index],)\n'
        b"        if index == 0 and component == 'bios' and self.policy.bios is not None:\n"
        b'            return (self.policy.bios,)\n'
        b"        if index == 0 and component == 'cpld' and self.policy.cpld_burn is not None and self.policy.cpld_refresh is not None:\n"
        b'            return (self.policy.cpld_burn, self.policy.cpld_refresh)\n'
        b"        raise SharedUpgradeHold('foreign declared source index')\n"
        b'\n'
        b'    def _verify_package_source_owner(self):\n'
        b'        if self._package_source_lifecycle_failure is not None:\n'
        b'            raise self._package_source_lifecycle_failure\n'
        b'        owner = self._package_source_owner\n'
        b'        if owner is None:\n'
        b'            return\n'
        b'        parent = self if self._package_source_owns else self._package_source_parent\n'
        b'        if type(parent) is _PreparedRunScope and parent._package_source_lifecycle_failure is not None:\n'
        b'            raise parent._package_source_lifecycle_failure\n'
        b'        if (type(parent) is not _PreparedRunScope\n'
        b'                or self._package_source_owner_class is not parent._package_source_owner_class\n'
        b'                or type(owner) is not parent._package_source_owner_class\n'
        b'                or parent.closed or parent.cleanup_issues or not parent._package_source_owns\n'
        b'                or parent._package_source_owner is not owner\n'
        b'                or self._package_source_selection is not parent._package_source_selection\n'
        b'                or self._package_source_selection[1:] != (self.policy, self.run_directory, self.plan_sha256)\n'
        b"                or (parent is not self and (getattr(self, '_readiness_parent', None) is not parent\n"
        b"                    or getattr(self, '_readiness_node', None) not in self.devices))):\n"
        b"            raise SharedUpgradeHold('original parent source owner/borrow changed')\n"
        b'        # No parent.verify recursion and no source descriptor reopening.\n'
        b'        owner.verify()\n'
        b'\n'
        b'    def _capture_package_source_data_locked(self, leaf, component, package_index):\n'
        b'        """Persist original LOCAL prelaunch DATA. No SCP wire/launch/ACK."""\n'
        b'        if (self._active_request_lease is None or self.closed or not self.manual_execution\n'
        b"                or self.parsed.method != 'local' or type(leaf) is not _ReadonlyQueryInputs\n"
        b'                or leaf.scope is not self or leaf._original_selection[0] is not self\n'
        b'                or self._package_source_parent is None\n'
        b"                or getattr(self, '_readiness_node', None) != leaf.node.hostname):\n"
        b"            raise SharedUpgradeHold('original leased child DATA scope required')\n"
        b'        try:\n'
        b'            self._verify_package_source_owner()\n'
        b'            if (component, package_index) not in self._package_source_selection[0]:\n'
        b"                raise SharedUpgradeHold('unfrozen source stage')\n"
        b'            stage, binding, args = self._owned_runner_stage(leaf, component, package_index)\n'
        b"            names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')\n"
        b'            held = {name: self._hold(stage, name) for name in names}\n'
        b'            packages = {}\n'
        b'            for package in self._package_source_packages(component, package_index):\n'
        b'                row = self._package_source_owner._files.get(Path(package.path))\n'
        b'                if row is None or type(row[4]) is not str:\n'
        b"                    raise SharedUpgradeHold('original package not retained by parent')\n"
        b'                packages[package.path] = dict(size=row[3][6], sha256=row[4])\n'
        b"            document = dict(schema_version=1, state='PACKAGE_SOURCE_PRELAUNCH_DATA_ONLY',\n"
        b"                execution_state='NOT_EXECUTED', activation_state='UNKNOWN', binding=binding,\n"
        b"                declared_method='local', originals_sha256={name: hashlib.sha256(obj.payload).hexdigest()\n"
        b'                    for name, obj in held.items()}, packages=packages)\n'
        b'            payload = _json_bytes(document)\n'
        b'            originals = {name: obj.payload for name, obj in held.items()}\n'
        b"            originals['package-source.json'] = payload\n"
        b'            _validate_package_source_data_graph(set(originals), binding, originals.__getitem__)\n'
        b'            self.verify(); leaf.verify()\n'
        b"            if 'package-source.json' in os.listdir(stage.fd):\n"
        b"                self._hold(stage, 'package-source.json', payload)\n"
        b'            else:\n'
        b"                self._commit_exclusive_binding(stage, payload, 'package-source.json')\n"
        b'            self.verify(); leaf.verify()\n'
        b'            return None\n'
        b'\n'
        b'        except BaseException:\n'
        b'            # Revoke this entire original source group, without altering the\n'
        b'            # primary exception object/cause or adopting any persisted DATA.\n'
        b'            parent = self._package_source_parent\n'
        b'            if (type(parent) is _PreparedRunScope\n'
        b"                    and getattr(self, '_readiness_parent', None) is parent\n"
        b'                    and self._package_source_owner is not None\n'
        b'                    and self._package_source_owner is parent._package_source_owner):\n'
        b'                if parent._package_source_lifecycle_failure is None:\n'
        b'                    parent._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                        'original source companion capture uncertain; shared group retained')\n"
        b'                if self._package_source_lifecycle_failure is None:\n'
        b'                    self._package_source_lifecycle_failure = parent._package_source_lifecycle_failure\n'
        b'            raise\n'
        b'\n'
        b'    def fork_readiness_scope(self, node, source_baselines=()):\n'
        b'        """Independent startup owner; never concurrently mutate parent maps."""\n'
        b'        if self.closed or self._native_schedule_started or node not in self.devices:\n'
        b"            raise SharedUpgradeHold('startup scope is outside the original pre-upgrade selection')\n"
        b'        # A source-group failure rejects another borrower before any child FD opens.\n'
        b'        self._verify_package_source_owner()\n'
        b'        child = _PreparedRunScope(*self._open_context, self.run_directory,\n'
        b'                                  manual_execution=self.manual_execution)\n'
        b'        try:\n',
    ),
    # readiness child exact borrow
    (
        b"                raise SharedUpgradeHold('startup worker original inputs differ from parent')\n"
        b'            child._readiness_parent, child._readiness_node = self, node\n'
        b'            child._os_source_baselines = dict(source_baselines)\n'
        b'            return child\n'
        b'        except BaseException as original:\n'
        b'            try:\n',
        b"                raise SharedUpgradeHold('startup worker original inputs differ from parent')\n"
        b'            child._readiness_parent, child._readiness_node = self, node\n'
        b'            child._os_source_baselines = dict(source_baselines)\n'
        b'            if self._package_source_owner is not None:\n'
        b'                child._package_source_owner = self._package_source_owner\n'
        b'                child._package_source_owner_class = self._package_source_owner_class\n'
        b'                child._package_source_parent = self\n'
        b'                child._package_source_selection = self._package_source_selection\n'
        b'                self._package_source_borrowers.add(child)\n'
        b'                child._verify_package_source_owner()\n'
        b'            return child\n'
        b'        except BaseException as original:\n'
        b'            try:\n',
    ),
    # scope verification
    (
        b'            raise ValueError("prepared run scope is closed")\n'
        b'        if self.cleanup_issues:\n'
        b'            raise ValueError("HOLD: unknown journal cleanup residue; scope cannot be reused")\n'
        b'        self.session.verify()\n'
        b'        for held in self.files.values():\n'
        b'            held.verify()\n',
        b'            raise ValueError("prepared run scope is closed")\n'
        b'        if self.cleanup_issues:\n'
        b'            raise ValueError("HOLD: unknown journal cleanup residue; scope cannot be reused")\n'
        b'        self._verify_package_source_owner()\n'
        b'        self.session.verify()\n'
        b'        for held in self.files.values():\n'
        b'            held.verify()\n',
    ),
    # exclusive source companion member
    (
        b'        return self._commit_exclusive_binding(directory, payload, "query-binding.json")\n'
        b'\n'
        b'    def _commit_exclusive_binding(self, directory, payload, final_name):\n'
        b'        if final_name not in _NVUED_CHECK_FILES | _DOWNLOAD_FILES | {"query-binding.json", "before-binding.json", "after-binding.json",\n'
        b'                              "repaired-binding.json", "restore-binding.json", "pending-diff-binding.json", "os-dispatch.json", "post-binding.json",\n'
        b'                              "runner-binding.json", "owned-exit-binding.json", "before-health-binding.json", "after-health-binding.json",\n'
        b'                              "component-preflight.json", "component-dispatch.json", "component-completion.json",\n',
        b'        return self._commit_exclusive_binding(directory, payload, "query-binding.json")\n'
        b'\n'
        b'    def _commit_exclusive_binding(self, directory, payload, final_name):\n'
        b'        if final_name not in _NVUED_CHECK_FILES | _DOWNLOAD_FILES | {"package-source.json", "query-binding.json", "before-binding.json", "after-binding.json",\n'
        b'                              "repaired-binding.json", "restore-binding.json", "pending-diff-binding.json", "os-dispatch.json", "post-binding.json",\n'
        b'                              "runner-binding.json", "owned-exit-binding.json", "before-health-binding.json", "after-health-binding.json",\n'
        b'                              "component-preflight.json", "component-dispatch.json", "component-completion.json",\n',
    ),
    # early/repeated close HOLD
    (
        b'\n'
        b'    def close(self):\n'
        b'        if self.closed:\n'
        b'            return\n'
        b'        self.closed = True\n'
        b'        issues = list(self.cleanup_issues)\n'
        b'        for held in reversed(tuple(self.files.values())):\n',
        b'\n'
        b'    def close(self):\n'
        b'        if self.closed:\n'
        b'            if self._package_source_owner is not None or self._package_source_lifecycle_failure is not None:\n'
        b'                # Repeat calls report original source cleanup uncertainty but\n'
        b'                # never touch or retry potentially reused numeric FD slots.\n'
        b'                _raise_cleanup_issues(self.cleanup_issues)\n'
        b'            if self._package_source_lifecycle_failure is not None:\n'
        b'                raise self._package_source_lifecycle_failure\n'
        b'            return\n'
        b'        if self._package_source_owns and self._package_source_borrowers:\n'
        b'            # Revocation only. Keep original FDs while children still own borrows.\n'
        b'            # This marker is never cleared when the last borrower is released.\n'
        b'            if self._package_source_lifecycle_failure is None:\n'
        b'                self._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                    'original package owner still has live or unknown child borrows')\n"
        b'            raise self._package_source_lifecycle_failure\n'
        b'        self.closed = True\n'
        b'        issues = list(self.cleanup_issues)\n'
        b'        for held in reversed(tuple(self.files.values())):\n',
    ),
    # actual holder cleanup and sticky issues
    (
        b'                held.close()\n'
        b'            except BaseException as error:\n'
        b'                issues.append(error)\n'
        b'        if self.session is not None:\n'
        b'            try:\n'
        b'                self.session.close()\n'
        b'            except BaseException as error:\n'
        b'                issues.append(error)\n'
        b'        for error in issues:\n'
        b'            if not isinstance(error, Exception):\n'
        b'                raise error  # After every owned cleanup attempt, retain NI exact.\n',
        b'                held.close()\n'
        b'            except BaseException as error:\n'
        b'                issues.append(error)\n'
        b'        if self._package_source_owns and self._package_source_owner is not None:\n'
        b'            try:\n'
        b'                self._package_source_owner.close()\n'
        b'            except BaseException as error:\n'
        b'                issues.append(error)\n'
        b'        if self.session is not None:\n'
        b'            try:\n'
        b'                self.session.close()\n'
        b'            except BaseException as error:\n'
        b'                issues.append(error)\n'
        b'        if self._package_source_parent is not None and not issues:\n'
        b'            self._package_source_parent._package_source_borrowers.discard(self)\n'
        b'        # A lifecycle failure does not skip actual owned cleanup after borrows\n'
        b'        # release. Surface HOLD only after all files/holder/session were attempted.\n'
        b'        if (self._package_source_lifecycle_failure is not None\n'
        b'                and not any(issue is self._package_source_lifecycle_failure for issue in issues)):\n'
        b'            issues.append(self._package_source_lifecycle_failure)\n'
        b'        self.cleanup_issues = issues\n'
        b'        for error in issues:\n'
        b'            if not isinstance(error, Exception):\n'
        b'                raise error  # After every owned cleanup attempt, retain NI exact.\n',
    ),
)


def _driver_upstream_bytes_from_exact_composition(payload):
    if type(payload) is not bytes:
        raise TypeError('exact driver source bytes required')
    spans = []
    for original, integrated in DRIVER_SOURCE_DATA_APPROVED_COMPOSITION:
        if payload.count(integrated) != 1 or payload.count(original) != 0:
            raise ValueError('missing/duplicate/new-plus-old driver source hunk')
        start = payload.index(integrated)
        spans.append((start, start + len(integrated), original))
    # The literal order is source order; do not sort malformed input into validity.
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        raise ValueError('overlapping or reordered driver source hunks')
    pieces, end = [], 0
    for start, stop, original in spans:
        pieces.extend((payload[end:start], original))
        end = stop
    pieces.append(payload[end:])
    restored = b''.join(pieces)  # One reverse pass; no cascading replacement.
    if any(restored.count(old) != 1 or restored.count(new) != 0
           for old, new in DRIVER_SOURCE_DATA_APPROVED_COMPOSITION):
        raise ValueError('restored driver source hunks are not unique')
    return restored


class DriverSourceDataExactCompositionTests(unittest.TestCase):
    def test_twelve_literal_hunks_restore_original_regions_in_one_pass(self):
        hunks = DRIVER_SOURCE_DATA_APPROVED_COMPOSITION
        self.assertEqual(12, len(hunks))
        source = b'prefix\n' + b'middle\n'.join(new for old, new in hunks) + b'suffix\n'
        expected = b'prefix\n' + b'middle\n'.join(old for old, new in hunks) + b'suffix\n'
        self.assertEqual(expected, _driver_upstream_bytes_from_exact_composition(source))
        self.assertEqual('3c76f3bf02f2a41e2338bf78b38681dc5defb63a957d31155709de85f0eaffe2',
                         FROZEN_SHA256['tools/ibsw_upgrade_driver.py'])

    def test_missing_old_truncated_deleted_duplicate_and_extra_old_are_refused(self):
        hunks = DRIVER_SOURCE_DATA_APPROVED_COMPOSITION
        source = b'middle\n'.join(new for old, new in hunks)
        for index, (old, new) in enumerate(hunks):
            for label, replacement in (
                ('missing', b''), ('old', old), ('truncated', new[:len(new)//2]),
                ('deleted', new[:-1]), ('duplicate', new + new), ('extra-old', old + new),
            ):
                with self.subTest(hunk=index, fault=label):
                    with self.assertRaises(ValueError):
                        _driver_upstream_bytes_from_exact_composition(source.replace(new, replacement, 1))

    def test_order_must_remain_literal_and_input_must_be_bytes(self):
        hunks = DRIVER_SOURCE_DATA_APPROVED_COMPOSITION
        with self.assertRaises(ValueError):
            _driver_upstream_bytes_from_exact_composition(b'middle\n'.join(new for old, new in reversed(hunks)))
        # Adjacent transposition also must not be normalized by sorting positions.
        swapped = list(hunks)
        swapped[5], swapped[6] = swapped[6], swapped[5]
        with self.assertRaises(ValueError):
            _driver_upstream_bytes_from_exact_composition(b'middle\n'.join(new for old, new in swapped))
        with self.assertRaises(TypeError):
            _driver_upstream_bytes_from_exact_composition('not bytes')

    def test_prefix_middle_and_suffix_drift_remain_visible_to_frozen_hash(self):
        hunks = DRIVER_SOURCE_DATA_APPROVED_COMPOSITION
        source = b'prefix\n' + b'middle\n'.join(new for old, new in hunks) + b'suffix\n'
        expected = b'prefix\n' + b'middle\n'.join(old for old, new in hunks) + b'suffix\n'
        for label, drift in (
            ('prefix', b'outside-prefix\n' + source),
            ('middle', source.replace(b'middle\n', b'outside-middle\n', 1)),
            ('suffix', source + b'outside-suffix\n'),
        ):
            with self.subTest(fault=label):
                restored = _driver_upstream_bytes_from_exact_composition(drift)
                self.assertNotEqual(expected, restored)
                self.assertNotEqual(hashlib.sha256(expected).digest(), hashlib.sha256(restored).digest())


# Independent literal inverse of the reviewed declaration-only SCP hunk.
# No FROZEN hash changes; this is not native SCP/dispatch admission.
COMPONENT_SCP_DECLARATION_COMPOSITION = (
    b'    if method not in {"local", "http"}:\n'
    b'        raise ValueError("component renderer currently covers local/http only; no HTTPS")\n',
    b'    if method not in {"local", "http", "scp"}:\n'
    b'        raise ValueError("component declarations cover local/http/scp only; no HTTPS")\n',
)


def _component_upstream_bytes_from_exact_scp_declaration(payload):
    if type(payload) is not bytes:
        raise TypeError('exact component source bytes required')
    original, integrated = COMPONENT_SCP_DECLARATION_COMPOSITION
    if payload.count(integrated) != 1 or payload.count(original) != 0:
        raise ValueError('missing/duplicate/new-plus-old component declaration hunk')
    start = payload.index(integrated)
    restored = payload[:start] + original + payload[start + len(integrated):]
    if restored.count(original) != 1 or restored.count(integrated) != 0:
        raise ValueError('restored component declaration hunk is not unique')
    return restored


class ComponentScpDeclarationExactCompositionTests(unittest.TestCase):
    def test_literal_declaration_inverse_preserves_original_bytes_and_frozen_hash(self):
        source = (
            b'prefix\n'
            b'    if method not in {"local", "http", "scp"}:\n'
            b'        raise ValueError("component declarations cover local/http/scp only; no HTTPS")\n'
            b'suffix\n')
        expected = (
            b'prefix\n'
            b'    if method not in {"local", "http"}:\n'
            b'        raise ValueError("component renderer currently covers local/http only; no HTTPS")\n'
            b'suffix\n')
        self.assertEqual(expected, _component_upstream_bytes_from_exact_scp_declaration(source))
        self.assertEqual('106ddd7095e28503a355e9637dfb4fbd7fa151a2d4198e951590233da02ec45a',
                         FROZEN_SHA256['tools/ibsw_upgrade_component.py'])

    def test_missing_partial_duplicate_extra_old_and_outside_drift_cannot_be_hidden(self):
        # Independent literals, not output sampled from a component or inverse.
        old = (b'    if method not in {"local", "http"}:\n'
               b'        raise ValueError("component renderer currently covers local/http only; no HTTPS")\n')
        new = (b'    if method not in {"local", "http", "scp"}:\n'
               b'        raise ValueError("component declarations cover local/http/scp only; no HTTPS")\n')
        for label, malformed in (
                ('missing', b''), ('old', old),
                ('only-method-line', new.splitlines(keepends=True)[0]),
                ('only-message-line', new.splitlines(keepends=True)[1]),
                ('deleted-byte', new[:-1]), ('duplicate', new + new),
                ('old-before-new', old + new), ('old-after-new', new + old)):
            with self.subTest(source=label):
                with self.assertRaises(ValueError):
                    _component_upstream_bytes_from_exact_scp_declaration(malformed)
        with self.assertRaises(TypeError):
            _component_upstream_bytes_from_exact_scp_declaration('not bytes')
        source = b'prefix\n' + new + b'suffix\n'
        expected = b'prefix\n' + old + b'suffix\n'
        for label, drift, expected_drift in (
                ('prefix', b'extra\n' + source, b'extra\n' + expected),
                ('middle', source.replace(b'suffix\n', b'middle-drift\nsuffix\n', 1),
                 expected.replace(b'suffix\n', b'middle-drift\nsuffix\n', 1)),
                ('suffix', source + b'extra\n', expected + b'extra\n')):
            with self.subTest(outside=label):
                restored = _component_upstream_bytes_from_exact_scp_declaration(drift)
                self.assertEqual(expected_drift, restored)
                self.assertNotEqual(expected, restored)
                self.assertNotEqual(hashlib.sha256(expected).digest(), hashlib.sha256(restored).digest())



# Independent literal inverse of seven reviewed SCP request-content DATA hunks.
# Withdraw these first, then require the unchanged original LOCAL inverse.
DRIVER_SCP_REQUEST_APPROVED_COMPOSITION = (
    # schema2 SCP request validator
    (
        b"            raise ValueError('strict package source DATA fields required')\n"
        b'\n'
        b'\n'
        b'\n'
        b'\n'
        b'def _validate_component_graph(files, binding, read, *, switch_dir):\n',
        b"            raise ValueError('strict package source DATA fields required')\n"
        b'\n'
        b'\n'
        b'def _validate_scp_request_content_graph(files, binding, read):\n'
        b'    """Strict schema2 SCP request DATA only; never reconstruct a live owner."""\n'
        b"    if 'scp-source-request.json' not in files:\n"
        b'        return\n'
        b"    names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')\n"
        b'    if not set(names).issubset(files):\n'
        b"        raise ValueError('SCP request content DATA requires complete original request/runner')\n"
        b"    raw = read('scp-source-request.json')\n"
        b'    document = json.loads(raw)\n'
        b'    if (type(document) is not dict or set(document) != {\n'
        b"            'schema_version', 'state', 'execution_state', 'activation_state',\n"
        b"            'binding', 'declared_method', 'request_id', 'originals_sha256', 'packages'}\n"
        b"            or type(document['schema_version']) is not int or document['schema_version'] != 2\n"
        b"            or document['state'] != 'SCP_REQUEST_CONTENT_DATA_ONLY'\n"
        b"            or document['execution_state'] != 'NOT_EXECUTED'\n"
        b"            or document['activation_state'] != 'UNKNOWN'\n"
        b"            or type(binding) is not dict or binding.get('component') not in ('os', 'bios', 'cpld')\n"
        b"            or document['binding'] != binding or document['declared_method'] != 'scp'\n"
        b"            or re.findall(rb'(?m)^IBSW_METHOD=([a-z]+)$', read('step.sh')) != [b'scp']\n"
        b'            or raw != _json_bytes(document)\n'
        b"            or document['originals_sha256'] != {name: hashlib.sha256(read(name)).hexdigest() for name in names}):\n"
        b"        raise ValueError('original SCP request content/hash graph changed')\n"
        b"    request = json.loads(read('request.json'))\n"
        b"    token = request.get('request_id') if type(request) is dict else None\n"
        b"    if (type(token) is not str or not re.fullmatch(r'[0-9a-f]{32}', token)\n"
        b"            or document['request_id'] != token\n"
        b"            or read('request.json') != _json_bytes(dict(schema_version=1, state='REQUESTED',\n"
        b"                activation_state='UNKNOWN', execution_state='NOT_EXECUTED', binding=binding, request_id=token))):\n"
        b"        raise ValueError('SCP request content DATA requires actual original request bytes')\n"
        b"    packages = document['packages']\n"
        b"    if type(packages) is not dict or len(packages) != (2 if binding['component'] == 'cpld' else 1):\n"
        b"        raise ValueError('exact SCP component package DATA set required')\n"
        b'    for path, row in packages.items():\n'
        b'        if (type(path) is not str or not posixpath.isabs(path) or posixpath.normpath(path) != path\n'
        b'                or any(ord(c) < 32 or ord(c) == 127 for c in path)\n'
        b"                or type(row) is not dict or set(row) != {'size', 'sha256'}\n"
        b"                or type(row['size']) is not int or row['size'] <= 0\n"
        b"                or type(row['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])):\n"
        b"            raise ValueError('strict SCP package source DATA fields required')\n"
        b'\n'
        b'\n'
        b'\n'
        b'def _validate_component_graph(files, binding, read, *, switch_dir):\n',
    ),
    # component graph member and validation
    (
        b'               "component-preflight.json", "request.json", "runner.sh", "runner-binding.json",\n'
        b'               "component-dispatch.json", "component-completion.json", "after.commands", "missing.commands",\n'
        b'               "component-repair.json", "component-repair-result.json", "observed-after.commands",\n'
        b'               "repaired.commands", "configuration-diff.json", "versions.json", "execution.stdout", "execution.stderr"} | _NVUED_CHECK_FILES | _DOWNLOAD_FILES | {"package-source.json"}\n'
        b'    if not files <= allowed or not {"step.sh", "step-binding.json", "before.commands", "before-binding.json",\n'
        b'                                     "component-preflight.json"} <= files:\n'
        b'        raise ValueError("partial/unknown component stage graph")\n'
        b'    _validate_package_source_data_graph(files, binding, read)\n'
        b'    before, before_binding = read("before.commands"), read("before-binding.json")\n'
        b'    if not before or before_binding != _json_bytes(_before_commands_binding(binding, before)):\n'
        b'        raise ValueError("original component before hash graph changed")\n',
        b'               "component-preflight.json", "request.json", "runner.sh", "runner-binding.json",\n'
        b'               "component-dispatch.json", "component-completion.json", "after.commands", "missing.commands",\n'
        b'               "component-repair.json", "component-repair-result.json", "observed-after.commands",\n'
        b'               "repaired.commands", "configuration-diff.json", "versions.json", "execution.stdout", "execution.stderr"} | _NVUED_CHECK_FILES | _DOWNLOAD_FILES | {"package-source.json", "scp-source-request.json"}\n'
        b'    if not files <= allowed or not {"step.sh", "step-binding.json", "before.commands", "before-binding.json",\n'
        b'                                     "component-preflight.json"} <= files:\n'
        b'        raise ValueError("partial/unknown component stage graph")\n'
        b'    _validate_package_source_data_graph(files, binding, read)\n'
        b'    _validate_scp_request_content_graph(files, binding, read)\n'
        b'    before, before_binding = read("before.commands"), read("before-binding.json")\n'
        b'    if not before or before_binding != _json_bytes(_before_commands_binding(binding, before)):\n'
        b'        raise ValueError("original component before hash graph changed")\n',
    ),
    # stage DATA member
    (
        b'def _stage_data_members(files):\n'
        b'    remainder, phases = set(files), []\n'
        b'    remainder.discard("package-source.json")\n'
        b'    health = []\n'
        b'    for phase in _STAGE_HEALTH_PHASES:\n'
        b'        group = _stage_health_files(phase)\n',
        b'def _stage_data_members(files):\n'
        b'    remainder, phases = set(files), []\n'
        b'    remainder.discard("package-source.json")\n'
        b'    remainder.discard("scp-source-request.json")\n'
        b'    health = []\n'
        b'    for phase in _STAGE_HEALTH_PHASES:\n'
        b'        group = _stage_health_files(phase)\n',
    ),
    # generic command graph validation
    (
        b'        return _validate_component_graph(files, step_binding, read, switch_dir=switch_dir)\n'
        b'    remainder, phases, has_restore, has_patch = _stage_data_members(files)\n'
        b'    _validate_package_source_data_graph(files, step_binding, read)\n'
        b'    originals = {}\n'
        b'    for phase in phases:\n'
        b'        raw_name, meta_name = phase + ".commands", phase + "-binding.json"\n',
        b'        return _validate_component_graph(files, step_binding, read, switch_dir=switch_dir)\n'
        b'    remainder, phases, has_restore, has_patch = _stage_data_members(files)\n'
        b'    _validate_package_source_data_graph(files, step_binding, read)\n'
        b'    _validate_scp_request_content_graph(files, step_binding, read)\n'
        b'    originals = {}\n'
        b'    for phase in phases:\n'
        b'        raw_name, meta_name = phase + ".commands", phase + "-binding.json"\n',
    ),
    # SCP parent source freeze insertion
    (
        b'    def freeze_package_sources(self, selections, *, deadline, max_fds):\n'
        b'        """Freeze explicit LOCAL declaration sources, not device-current authority."""\n'
        b'        self.verify()\n'
        b'        provider, package_content_owner, owner_class = _fixed_package_source_api(self)\n'
        b"        if (not self.manual_execution or self.parsed.method != 'local'\n"
        b'                or self._native_schedule_started or self._package_source_owner is not None\n'
        b'                or self._package_source_parent is not None\n'
        b'                or type(selections) is not tuple or not selections):\n'
        b"            raise SharedUpgradeHold('original parent LOCAL source DATA selection required')\n"
        b'        selected, paths = [], set()\n'
        b'        for row in selections:\n'
        b'            if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not str\n'
        b'                    or type(row[1]) is not int or row[0] not in self.parsed.selected):\n'
        b"                raise SharedUpgradeHold('original selected component/index required')\n"
        b'            selected.append(row)\n'
        b'            paths.update(Path(p.path) for p in self._package_source_packages(*row))\n'
        b'        if len(set(selected)) != len(selected):\n'
        b"            raise SharedUpgradeHold('duplicate source stage selection')\n"
        b"        if (sys.modules.get('ibsw_upgrade_scp') is not provider\n"
        b"                or vars(provider).get('package_content_owner') is not package_content_owner\n"
        b"                or vars(provider).get('_PackageContentOwner') is not owner_class):\n"
        b"            raise SharedUpgradeHold('original package provider changed before factory')\n"
        b'        try:\n'
        b'            owner = package_content_owner(self.policy.package_dir, tuple(sorted(paths)),\n'
        b'                                          deadline=deadline, max_fds=max_fds)\n'
        b'        except BaseException:\n'
        b'            # The real constructor owns any partial originals/cleanup. No owner\n'
        b'            # returned to adopt; revoke this parent group before another freeze.\n'
        b'            if self._package_source_lifecycle_failure is None:\n'
        b'                self._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                    'original package source acquisition failed; parent group retained')\n"
        b'            raise  # Preserve the original error/NI object and its existing cause.\n'
        b'        # Register the actual owner before any later verification can fail.\n'
        b'        self._package_source_owner = owner\n'
        b'        self._package_source_owner_class = owner_class\n'
        b'        self._package_source_owns = True\n'
        b'        self._package_source_selection = (tuple(sorted(selected)), self.policy,\n'
        b'                                         self.run_directory, self.plan_sha256)\n'
        b'        try:\n'
        b'            self.verify()\n'
        b'        except BaseException as original:\n'
        b'            try:\n'
        b'                owner.close()\n'
        b'            except BaseException as cleanup:\n'
        b'                self.cleanup_issues.append(cleanup)\n'
        b'                if isinstance(original, Exception) and not isinstance(cleanup, Exception):\n'
        b'                    raise\n'
        b'            raise\n'
        b'        return owner\n'
        b'\n'
        b'    def _package_source_packages(self, component, index):\n',
        b'    def freeze_package_sources(self, selections, *, deadline, max_fds):\n'
        b'        """Freeze explicit LOCAL declaration sources, not device-current authority."""\n'
        b'        self.verify()\n'
        b'        provider, package_content_owner, owner_class = _fixed_package_source_api(self)\n'
        b"        if (not self.manual_execution or self.parsed.method != 'local'\n"
        b'                or self._native_schedule_started or self._package_source_owner is not None\n'
        b'                or self._package_source_parent is not None\n'
        b'                or type(selections) is not tuple or not selections):\n'
        b"            raise SharedUpgradeHold('original parent LOCAL source DATA selection required')\n"
        b'        selected, paths = [], set()\n'
        b'        for row in selections:\n'
        b'            if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not str\n'
        b'                    or type(row[1]) is not int or row[0] not in self.parsed.selected):\n'
        b"                raise SharedUpgradeHold('original selected component/index required')\n"
        b'            selected.append(row)\n'
        b'            paths.update(Path(p.path) for p in self._package_source_packages(*row))\n'
        b'        if len(set(selected)) != len(selected):\n'
        b"            raise SharedUpgradeHold('duplicate source stage selection')\n"
        b"        if (sys.modules.get('ibsw_upgrade_scp') is not provider\n"
        b"                or vars(provider).get('package_content_owner') is not package_content_owner\n"
        b"                or vars(provider).get('_PackageContentOwner') is not owner_class):\n"
        b"            raise SharedUpgradeHold('original package provider changed before factory')\n"
        b'        try:\n'
        b'            owner = package_content_owner(self.policy.package_dir, tuple(sorted(paths)),\n'
        b'                                          deadline=deadline, max_fds=max_fds)\n'
        b'        except BaseException:\n'
        b'            # The real constructor owns any partial originals/cleanup. No owner\n'
        b'            # returned to adopt; revoke this parent group before another freeze.\n'
        b'            if self._package_source_lifecycle_failure is None:\n'
        b'                self._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                    'original package source acquisition failed; parent group retained')\n"
        b'            raise  # Preserve the original error/NI object and its existing cause.\n'
        b'        # Register the actual owner before any later verification can fail.\n'
        b'        self._package_source_owner = owner\n'
        b'        self._package_source_owner_class = owner_class\n'
        b'        self._package_source_owns = True\n'
        b'        self._package_source_selection = (tuple(sorted(selected)), self.policy,\n'
        b'                                         self.run_directory, self.plan_sha256)\n'
        b'        try:\n'
        b'            self.verify()\n'
        b'        except BaseException as original:\n'
        b'            try:\n'
        b'                owner.close()\n'
        b'            except BaseException as cleanup:\n'
        b'                self.cleanup_issues.append(cleanup)\n'
        b'                if isinstance(original, Exception) and not isinstance(cleanup, Exception):\n'
        b'                    raise\n'
        b'            raise\n'
        b'        return owner\n'
        b'\n'
        b'    def freeze_scp_package_sources(self, selections, *, deadline, max_fds):\n'
        b'        """Freeze explicit SCP declaration sources, never native dispatch permission."""\n'
        b'        self.verify()\n'
        b'        provider, package_content_owner, owner_class = _fixed_package_source_api(self)\n'
        b"        if (not self.manual_execution or self.parsed.method != 'scp'\n"
        b'                or self._native_schedule_started or self._package_source_owner is not None\n'
        b'                or self._package_source_parent is not None\n'
        b'                or type(selections) is not tuple or not selections):\n'
        b"            raise SharedUpgradeHold('original parent SCP source DATA selection required')\n"
        b'        selected, paths = [], set()\n'
        b'        for row in selections:\n'
        b'            if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not str\n'
        b'                    or type(row[1]) is not int or row[0] not in self.parsed.selected):\n'
        b"                raise SharedUpgradeHold('original selected component/index required')\n"
        b'            selected.append(row)\n'
        b'            paths.update(Path(p.path) for p in self._package_source_packages(*row))\n'
        b'        if len(set(selected)) != len(selected):\n'
        b"            raise SharedUpgradeHold('duplicate source stage selection')\n"
        b"        if (sys.modules.get('ibsw_upgrade_scp') is not provider\n"
        b"                or vars(provider).get('package_content_owner') is not package_content_owner\n"
        b"                or vars(provider).get('_PackageContentOwner') is not owner_class):\n"
        b"            raise SharedUpgradeHold('original package provider changed before factory')\n"
        b'        try:\n'
        b'            owner = package_content_owner(self.policy.package_dir, tuple(sorted(paths)),\n'
        b'                                          deadline=deadline, max_fds=max_fds)\n'
        b'        except BaseException:\n'
        b'            # The real constructor owns any partial originals/cleanup. No owner\n'
        b'            # returned to adopt; revoke this parent group before another freeze.\n'
        b'            if self._package_source_lifecycle_failure is None:\n'
        b'                self._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                    'original package source acquisition failed; parent group retained')\n"
        b'            raise  # Preserve the original error/NI object and its existing cause.\n'
        b'        # Register the actual owner before any later verification can fail.\n'
        b'        self._package_source_owner = owner\n'
        b'        self._package_source_owner_class = owner_class\n'
        b'        self._package_source_owns = True\n'
        b'        self._package_source_selection = (tuple(sorted(selected)), self.policy,\n'
        b'                                         self.run_directory, self.plan_sha256)\n'
        b'        try:\n'
        b'            self.verify()\n'
        b'        except BaseException as original:\n'
        b'            try:\n'
        b'                owner.close()\n'
        b'            except BaseException as cleanup:\n'
        b'                self.cleanup_issues.append(cleanup)\n'
        b'                if isinstance(original, Exception) and not isinstance(cleanup, Exception):\n'
        b'                    raise\n'
        b'            raise\n'
        b'        return owner\n'
        b'\n'
        b'    def _package_source_packages(self, component, index):\n',
    ),
    # SCP child request companion insertion
    (
        b'    def _capture_package_source_data_locked(self, leaf, component, package_index):\n'
        b'        """Persist original LOCAL prelaunch DATA. No SCP wire/launch/ACK."""\n'
        b'        if (self._active_request_lease is None or self.closed or not self.manual_execution\n'
        b"                or self.parsed.method != 'local' or type(leaf) is not _ReadonlyQueryInputs\n"
        b'                or leaf.scope is not self or leaf._original_selection[0] is not self\n'
        b'                or self._package_source_parent is None\n'
        b"                or getattr(self, '_readiness_node', None) != leaf.node.hostname):\n"
        b"            raise SharedUpgradeHold('original leased child DATA scope required')\n"
        b'        try:\n'
        b'            self._verify_package_source_owner()\n'
        b'            if (component, package_index) not in self._package_source_selection[0]:\n'
        b"                raise SharedUpgradeHold('unfrozen source stage')\n"
        b'            stage, binding, args = self._owned_runner_stage(leaf, component, package_index)\n'
        b"            names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')\n"
        b'            held = {name: self._hold(stage, name) for name in names}\n'
        b'            packages = {}\n'
        b'            for package in self._package_source_packages(component, package_index):\n'
        b'                row = self._package_source_owner._files.get(Path(package.path))\n'
        b'                if row is None or type(row[4]) is not str:\n'
        b"                    raise SharedUpgradeHold('original package not retained by parent')\n"
        b'                packages[package.path] = dict(size=row[3][6], sha256=row[4])\n'
        b"            document = dict(schema_version=1, state='PACKAGE_SOURCE_PRELAUNCH_DATA_ONLY',\n"
        b"                execution_state='NOT_EXECUTED', activation_state='UNKNOWN', binding=binding,\n"
        b"                declared_method='local', originals_sha256={name: hashlib.sha256(obj.payload).hexdigest()\n"
        b'                    for name, obj in held.items()}, packages=packages)\n'
        b'            payload = _json_bytes(document)\n'
        b'            originals = {name: obj.payload for name, obj in held.items()}\n'
        b"            originals['package-source.json'] = payload\n"
        b'            _validate_package_source_data_graph(set(originals), binding, originals.__getitem__)\n'
        b'            self.verify(); leaf.verify()\n'
        b"            if 'package-source.json' in os.listdir(stage.fd):\n"
        b"                self._hold(stage, 'package-source.json', payload)\n"
        b'            else:\n'
        b"                self._commit_exclusive_binding(stage, payload, 'package-source.json')\n"
        b'            self.verify(); leaf.verify()\n'
        b'            return None\n'
        b'\n'
        b'        except BaseException:\n'
        b'            # Revoke this entire original source group, without altering the\n'
        b'            # primary exception object/cause or adopting any persisted DATA.\n'
        b'            parent = self._package_source_parent\n'
        b'            if (type(parent) is _PreparedRunScope\n'
        b"                    and getattr(self, '_readiness_parent', None) is parent\n"
        b'                    and self._package_source_owner is not None\n'
        b'                    and self._package_source_owner is parent._package_source_owner):\n'
        b'                if parent._package_source_lifecycle_failure is None:\n'
        b'                    parent._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                        'original source companion capture uncertain; shared group retained')\n"
        b'                if self._package_source_lifecycle_failure is None:\n'
        b'                    self._package_source_lifecycle_failure = parent._package_source_lifecycle_failure\n'
        b'            raise\n'
        b'\n'
        b'    def fork_readiness_scope(self, node, source_baselines=()):\n',
        b'    def _capture_package_source_data_locked(self, leaf, component, package_index):\n'
        b'        """Persist original LOCAL prelaunch DATA. No SCP wire/launch/ACK."""\n'
        b'        if (self._active_request_lease is None or self.closed or not self.manual_execution\n'
        b"                or self.parsed.method != 'local' or type(leaf) is not _ReadonlyQueryInputs\n"
        b'                or leaf.scope is not self or leaf._original_selection[0] is not self\n'
        b'                or self._package_source_parent is None\n'
        b"                or getattr(self, '_readiness_node', None) != leaf.node.hostname):\n"
        b"            raise SharedUpgradeHold('original leased child DATA scope required')\n"
        b'        try:\n'
        b'            self._verify_package_source_owner()\n'
        b'            if (component, package_index) not in self._package_source_selection[0]:\n'
        b"                raise SharedUpgradeHold('unfrozen source stage')\n"
        b'            stage, binding, args = self._owned_runner_stage(leaf, component, package_index)\n'
        b"            names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')\n"
        b'            held = {name: self._hold(stage, name) for name in names}\n'
        b'            packages = {}\n'
        b'            for package in self._package_source_packages(component, package_index):\n'
        b'                row = self._package_source_owner._files.get(Path(package.path))\n'
        b'                if row is None or type(row[4]) is not str:\n'
        b"                    raise SharedUpgradeHold('original package not retained by parent')\n"
        b'                packages[package.path] = dict(size=row[3][6], sha256=row[4])\n'
        b"            document = dict(schema_version=1, state='PACKAGE_SOURCE_PRELAUNCH_DATA_ONLY',\n"
        b"                execution_state='NOT_EXECUTED', activation_state='UNKNOWN', binding=binding,\n"
        b"                declared_method='local', originals_sha256={name: hashlib.sha256(obj.payload).hexdigest()\n"
        b'                    for name, obj in held.items()}, packages=packages)\n'
        b'            payload = _json_bytes(document)\n'
        b'            originals = {name: obj.payload for name, obj in held.items()}\n'
        b"            originals['package-source.json'] = payload\n"
        b'            _validate_package_source_data_graph(set(originals), binding, originals.__getitem__)\n'
        b'            self.verify(); leaf.verify()\n'
        b"            if 'package-source.json' in os.listdir(stage.fd):\n"
        b"                self._hold(stage, 'package-source.json', payload)\n"
        b'            else:\n'
        b"                self._commit_exclusive_binding(stage, payload, 'package-source.json')\n"
        b'            self.verify(); leaf.verify()\n'
        b'            return None\n'
        b'\n'
        b'        except BaseException:\n'
        b'            # Revoke this entire original source group, without altering the\n'
        b'            # primary exception object/cause or adopting any persisted DATA.\n'
        b'            parent = self._package_source_parent\n'
        b'            if (type(parent) is _PreparedRunScope\n'
        b"                    and getattr(self, '_readiness_parent', None) is parent\n"
        b'                    and self._package_source_owner is not None\n'
        b'                    and self._package_source_owner is parent._package_source_owner):\n'
        b'                if parent._package_source_lifecycle_failure is None:\n'
        b'                    parent._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                        'original source companion capture uncertain; shared group retained')\n"
        b'                if self._package_source_lifecycle_failure is None:\n'
        b'                    self._package_source_lifecycle_failure = parent._package_source_lifecycle_failure\n'
        b'            raise\n'
        b'\n'
        b'    def _capture_scp_request_content_locked(self, leaf, component, package_index):\n'
        b'        """Persist original SCP request content DATA. No wire/launch/ACK."""\n'
        b'        if (self._active_request_lease is None or self.closed or not self.manual_execution\n'
        b"                or self.parsed.method != 'scp' or type(leaf) is not _ReadonlyQueryInputs\n"
        b'                or leaf.scope is not self or leaf._original_selection[0] is not self\n'
        b'                or self._package_source_parent is None\n'
        b"                or getattr(self, '_readiness_node', None) != leaf.node.hostname):\n"
        b"            raise SharedUpgradeHold('original leased SCP child DATA scope required')\n"
        b'        try:\n'
        b'            self._verify_package_source_owner()\n'
        b'            if (component, package_index) not in self._package_source_selection[0]:\n'
        b"                raise SharedUpgradeHold('unfrozen source stage')\n"
        b'            stage, binding, args = self._owned_runner_stage(leaf, component, package_index)\n'
        b"            names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')\n"
        b'            held = {name: self._hold(stage, name) for name in names}\n'
        b'            packages = {}\n'
        b'            for package in self._package_source_packages(component, package_index):\n'
        b'                row = self._package_source_owner._files.get(Path(package.path))\n'
        b'                if row is None or type(row[4]) is not str:\n'
        b"                    raise SharedUpgradeHold('original package not retained by parent')\n"
        b'                packages[package.path] = dict(size=row[3][6], sha256=row[4])\n'
        b"            document = dict(schema_version=2, state='SCP_REQUEST_CONTENT_DATA_ONLY',\n"
        b"                execution_state='NOT_EXECUTED', activation_state='UNKNOWN', binding=binding,\n"
        b"                declared_method='scp', request_id=json.loads(held['request.json'].payload)['request_id'],\n"
        b'                originals_sha256={name: hashlib.sha256(obj.payload).hexdigest()\n'
        b'                    for name, obj in held.items()}, packages=packages)\n'
        b'            payload = _json_bytes(document)\n'
        b'            originals = {name: obj.payload for name, obj in held.items()}\n'
        b"            originals['scp-source-request.json'] = payload\n"
        b'            _validate_scp_request_content_graph(set(originals), binding, originals.__getitem__)\n'
        b'            self.verify(); leaf.verify()\n'
        b"            if 'scp-source-request.json' in os.listdir(stage.fd):\n"
        b"                self._hold(stage, 'scp-source-request.json', payload)\n"
        b'            else:\n'
        b"                self._commit_exclusive_binding(stage, payload, 'scp-source-request.json')\n"
        b'            self.verify(); leaf.verify()\n'
        b'            return None\n'
        b'\n'
        b'        except BaseException:\n'
        b'            # Revoke this entire original source group, without altering the\n'
        b'            # primary exception object/cause or adopting any persisted DATA.\n'
        b'            parent = self._package_source_parent\n'
        b'            if (type(parent) is _PreparedRunScope\n'
        b"                    and getattr(self, '_readiness_parent', None) is parent\n"
        b'                    and self._package_source_owner is not None\n'
        b'                    and self._package_source_owner is parent._package_source_owner):\n'
        b'                if parent._package_source_lifecycle_failure is None:\n'
        b'                    parent._package_source_lifecycle_failure = SharedUpgradeHold(\n'
        b"                        'original SCP request content capture uncertain; shared group retained')\n"
        b'                if self._package_source_lifecycle_failure is None:\n'
        b'                    self._package_source_lifecycle_failure = parent._package_source_lifecycle_failure\n'
        b'            raise\n'
        b'\n'
        b'    def fork_readiness_scope(self, node, source_baselines=()):\n',
    ),
    # exclusive companion member
    (
        b'        return self._commit_exclusive_binding(directory, payload, "query-binding.json")\n'
        b'\n'
        b'    def _commit_exclusive_binding(self, directory, payload, final_name):\n'
        b'        if final_name not in _NVUED_CHECK_FILES | _DOWNLOAD_FILES | {"package-source.json", "query-binding.json", "before-binding.json", "after-binding.json",\n'
        b'                              "repaired-binding.json", "restore-binding.json", "pending-diff-binding.json", "os-dispatch.json", "post-binding.json",\n'
        b'                              "runner-binding.json", "owned-exit-binding.json", "before-health-binding.json", "after-health-binding.json",\n'
        b'                              "component-preflight.json", "component-dispatch.json", "component-completion.json",\n',
        b'        return self._commit_exclusive_binding(directory, payload, "query-binding.json")\n'
        b'\n'
        b'    def _commit_exclusive_binding(self, directory, payload, final_name):\n'
        b'        if final_name not in _NVUED_CHECK_FILES | _DOWNLOAD_FILES | {"package-source.json", "scp-source-request.json", "query-binding.json", "before-binding.json", "after-binding.json",\n'
        b'                              "repaired-binding.json", "restore-binding.json", "pending-diff-binding.json", "os-dispatch.json", "post-binding.json",\n'
        b'                              "runner-binding.json", "owned-exit-binding.json", "before-health-binding.json", "after-health-binding.json",\n'
        b'                              "component-preflight.json", "component-dispatch.json", "component-completion.json",\n',
    ),
)




def _driver_upstream_bytes_from_exact_scp_request_content(payload):
    if type(payload) is not bytes:
        raise TypeError('exact SCP request source bytes required')
    spans = []
    for original, integrated in DRIVER_SCP_REQUEST_APPROVED_COMPOSITION:
        if payload.count(integrated) != 1 or payload.count(original) != 0:
            raise ValueError('missing/duplicate/new-plus-old SCP request source hunk')
        start = payload.index(integrated)
        spans.append((start, start + len(integrated), original))
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        raise ValueError('overlapping or reordered SCP request source hunks')
    pieces, end = [], 0
    for start, stop, original in spans:
        pieces.extend((payload[end:start], original))
        end = stop
    pieces.append(payload[end:])
    restored = b''.join(pieces)
    if any(restored.count(old) != 1 or restored.count(new) != 0
           for old, new in DRIVER_SCP_REQUEST_APPROVED_COMPOSITION):
        raise ValueError('restored SCP request source hunks are not unique')
    return restored


class DriverScpRequestExactCompositionTests(unittest.TestCase):
    def test_seven_literal_regions_restore_before_unchanged_local_inverse(self):
        hunks = DRIVER_SCP_REQUEST_APPROVED_COMPOSITION
        self.assertEqual(7, len(hunks))
        integrated = b'prefix\n' + b'middle\n'.join(new for old, new in hunks) + b'suffix\n'
        original = b'prefix\n' + b'middle\n'.join(old for old, new in hunks) + b'suffix\n'
        self.assertEqual(original, _driver_upstream_bytes_from_exact_scp_request_content(integrated))
        self.assertEqual('3c76f3bf02f2a41e2338bf78b38681dc5defb63a957d31155709de85f0eaffe2',
                         FROZEN_SHA256['tools/ibsw_upgrade_driver.py'])
        self.assertEqual(12, len(DRIVER_SOURCE_DATA_APPROVED_COMPOSITION))

    def test_each_missing_old_truncated_deleted_duplicate_and_extra_old_region_is_refused(self):
        hunks = DRIVER_SCP_REQUEST_APPROVED_COMPOSITION
        integrated = b'middle\n'.join(new for old, new in hunks)
        for index, (old, new) in enumerate(hunks):
            for label, replacement in (
                ('missing', b''), ('old', old), ('truncated', new[:len(new)//2]),
                ('deleted', new[:-1]), ('duplicate', new + new), ('extra-old', old + new),
            ):
                with self.subTest(region=index, fault=label):
                    with self.assertRaises(ValueError):
                        _driver_upstream_bytes_from_exact_scp_request_content(
                            integrated.replace(new, replacement, 1))

    def test_order_type_and_outside_bytes_cannot_be_normalized_into_approval(self):
        hunks = DRIVER_SCP_REQUEST_APPROVED_COMPOSITION
        reversed_source = b'middle\n'.join(new for old, new in reversed(hunks))
        swapped = list(hunks)
        swapped[4], swapped[5] = swapped[5], swapped[4]
        for malformed in (reversed_source, b'middle\n'.join(new for old, new in swapped)):
            with self.subTest(source=malformed):
                with self.assertRaises(ValueError):
                    _driver_upstream_bytes_from_exact_scp_request_content(malformed)
        for nonbytes in ('source', bytearray(b'source'), None):
            with self.subTest(type=type(nonbytes).__name__):
                with self.assertRaises(TypeError):
                    _driver_upstream_bytes_from_exact_scp_request_content(nonbytes)
        integrated = b'prefix\n' + b'middle\n'.join(new for old, new in hunks) + b'suffix\n'
        expected = b'prefix\n' + b'middle\n'.join(old for old, new in hunks) + b'suffix\n'
        for label, drift, expected_drift in (
            ('prefix', b'outside\n' + integrated, b'outside\n' + expected),
            ('middle', integrated.replace(b'middle\n', b'outside\n', 1),
             expected.replace(b'middle\n', b'outside\n', 1)),
            ('suffix', integrated + b'outside\n', expected + b'outside\n'),
        ):
            with self.subTest(fault=label):
                restored = _driver_upstream_bytes_from_exact_scp_request_content(drift)
                self.assertEqual(expected_drift, restored)
                self.assertNotEqual(hashlib.sha256(expected).digest(), hashlib.sha256(restored).digest())

GLOBAL = """schema_version: 2
common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.254
      port: 8088
      http_root: /var/www/html
switches:
- ib:
    version: '25.03.1010'
    upgrade:
      packages:
        os:
          files:
          - file: nvos-amd64-25.02.8008.bin
          - file: nvos-amd64-25.03.1010.bin
"""


class CanonicalRuntimeManifestContractTests(unittest.TestCase):
    def test_literal_runtime_inventory_sources_have_direct_and_real_workflow_mapping(self):
        self.assertTrue(all((ROOT / name).is_file() and not (ROOT / name).is_symlink()
                            for name in PYTHON_RUNTIME + SHELLS + (GUARD,)),
                        "complete literal canonical runtime capability missing")
        manifest = json.loads((ROOT / "test_cases/script_test_manifest.json").read_text())
        self.assertEqual(len(PYTHON_RUNTIME), 13)
        self.assertEqual(len(SHELLS), 3)
        for relative in PYTHON_RUNTIME + SHELLS + (GUARD,):
            with self.subTest(relative=relative):
                path = ROOT / relative
                self.assertTrue(path.is_file() and not path.is_symlink(), "missing canonical runtime capability")
                self.assertEqual(manifest["scripts"].get(relative), relative)
                self.assertTrue(any(any(fnmatch.fnmatchcase(relative, p) for p in r["paths"])
                                    for r in manifest["test_rules"]), "direct mapping absent")
                flows = [r for r in manifest["workflows"]
                         if any(fnmatch.fnmatchcase(relative, p) for p in r["members"])]
                self.assertTrue(flows, "workflow mapping absent")
                for flow in flows:
                    targets = {target for name, target in manifest["scripts"].items()
                               if any(fnmatch.fnmatchcase(name, p) for p in flow["members"])}
                    self.assertGreaterEqual(len(targets), 2)
        for relative, expected in FROZEN_SHA256.items():
            with self.subTest(original=relative):
                payload = (ROOT / relative).read_bytes()
                if relative == "tools/ibsw_upgrade_access.py":
                    payload = _access_upstream_bytes_from_exact_composition(payload)
                elif relative == "tools/ibsw_upgrade_driver.py":
                    payload = _driver_upstream_bytes_from_exact_scp_request_content(payload)
                    payload = _driver_upstream_bytes_from_exact_composition(payload)
                if relative == "tools/ibsw_upgrade_component.py":
                    payload = _component_upstream_bytes_from_exact_scp_declaration(payload)
                self.assertEqual(hashlib.sha256(payload).hexdigest(), expected)
        self.assertIn(REQUIREMENTS, manifest["tracked_support"])

    def test_normal_modules_and_complete_real_helper_files_are_explicitly_hash_bound(self):
        manifest = json.loads((ROOT / "test_cases/script_test_manifest.json").read_text())
        for name in NORMAL_MODULES:
            path = ROOT / (name.replace(".", "/") + ".py")
            self.assertTrue(path.is_file() and not path.is_symlink(), "normal top-level contract missing")
        helper_root = ROOT / "test_cases/ibsw225_fixture_support"
        self.assertTrue(helper_root.is_dir() and not helper_root.is_symlink(), "fixed helper capability missing")
        self.assertTrue((helper_root / "runtime_source_support.py").is_file())
        self.assertTrue((helper_root / "_fixture_test_upgrade_cli.py").is_file())
        entries = [p for p in helper_root.rglob("*") if "__pycache__" not in p.parts]
        for path in entries:
            self.assertFalse(path.is_symlink(), "helper closure cannot hide a foreign directory/file")
            self.assertTrue(path.is_dir() or path.is_file(), "nonregular helper entry")
        helper_files = [p for p in entries if p.is_file()]
        self.assertTrue(helper_files, "empty helper glob is not complete binding")
        self.assertTrue(any(r.get("complete_tracked_support") is True
                            and "test_cases/ibsw225_fixture_support/*.py" in r["paths"]
                            for r in manifest["path_rules"]), "unlisted helper additions must invalidate proof")
        for path in helper_files + [ROOT / REQUIREMENTS]:
            relative = str(path.relative_to(ROOT))
            self.assertFalse(path.is_symlink())
            self.assertIn(relative, manifest["tracked_support"])
            rules = [r for r in manifest["path_rules"]
                     if any(fnmatch.fnmatchcase(relative, p) for p in r["paths"])]
            self.assertTrue(rules, "tracked helper lacks impact rule")
            self.assertTrue(any(r.get("tests") or r.get("full_suite") is True for r in rules))
        suite_tests = [name for suite in manifest["test_suites"] for name in suite["tests"]]
        for name in NORMAL_MODULES:
            self.assertEqual(suite_tests.count(name), 1)

    def test_real_canonical_entry_driver_renderer_and_owned_template_keep_local_sources(self):
        self.assertTrue(all((ROOT / name).is_file() and not (ROOT / name).is_symlink()
                            for name in PYTHON_RUNTIME + SHELLS + (GUARD,)),
                        "complete literal canonical renderer bundle capability missing")
        app = load_script("ibsw_new_contract_actual_entry", ROOT / ENTRY)
        driver = app._fixed_driver()
        self.assertEqual(Path(driver.__file__).resolve(), ROOT / "tools/ibsw_upgrade_driver.py")
        contract = importlib.import_module("ibsw_upgrade_contract")
        component = importlib.import_module("ibsw_upgrade_component")
        executor = importlib.import_module("ibsw_upgrade_executor")
        for module in (contract, component, executor):
            self.assertEqual(Path(module.__file__).resolve().parent, ROOT / "tools")
        self.assertEqual(component._TEMPLATE, ROOT / SHELLS[1])
        policy = contract.normalize_upgrade(contract.load_global_text(GLOBAL), selected=("os",), method="http")
        node = contract.InventoryDevice("ib-contract", "192.0.2.21", "02:00:00:00:00:21")
        step = component.render_declared_step(policy, node, component="os", package_index=1,
            run_id="contract", method="http", switch_dir="/home/admin")
        self.assertIn("nvos-amd64-25.03.1010.bin", step.script)
        self.assertIn("nv action install system image", step.script)
        binding = dict(run_id="contract", node=dict(hostname="ib-contract"), stage="os-0001",
                       component="os", script_sha256="a" * 64)
        remote = "/home/admin/.ibsw-contract-ib-contract-os-0001-" + "b" * 32 + "/step.sh"
        payload = executor._owned_runner_bytes(binding, remote)
        self.assertTrue(payload.endswith((ROOT / SHELLS[2]).read_bytes()))
        self.assertIn(b"IBSW_OWNED_EXIT_V1", payload)

    def test_real_runner_snapshots_handwritten_helper_bytes_and_rejects_private_test_ids(self):
        runner = load_script("ibsw_new_contract_actual_runner", ROOT / "test_cases/run_related_tests.py")
        self.assertEqual(Path(runner.path_disposition.__globals__["__file__"]).resolve(),
                         ROOT / "tools/project_contract.py")
        first = b"VALUE = 'source-before'\n"
        second = b"VALUE = 'source-after'\n"
        with tempfile.TemporaryDirectory(prefix="ibsw-manifest-hash-") as folder:
            root = Path(folder)
            cases = root / "test_cases"
            helpers = cases / "ibsw225_fixture_support"
            helpers.mkdir(parents=True)
            (cases / "test_contract.py").write_text(
                "import unittest\nclass LiteralCase(unittest.TestCase):\n"
                "    def test_literal_contract(self):\n        self.assertEqual('source', 'source')\n",
                encoding="ascii")
            helper = helpers / "literal_helper.py"
            helper.write_bytes(first)
            support = "test_cases/ibsw225_fixture_support/literal_helper.py"
            manifest_path = root / "manifest.json"
            manifest = dict(tracked_support=[support], path_rules=[dict(
                paths=["test_cases/ibsw225_fixture_support/*.py"],
                tests=["test_cases.test_contract"], complete_tracked_support=True)])
            manifest_path.write_text(json.dumps(manifest), encoding="ascii")
            self.assertEqual(set(runner.discover_tests(root)), {"test_cases.test_contract"})
            runner._validate_test_ids(root, ["test_cases.test_contract"], "literal normal module")
            with self.assertRaises(runner.ImpactError):
                runner._validate_test_ids(root,
                    ["test_cases.ibsw225_fixture_support.literal_helper"], "private helper is not a test")
            with self.assertRaises(runner.ImpactError):
                runner._validate_test_ids(root,
                    ["test_cases.test_contract.Case.test_one"], "method is not a manifest module")
            before = runner.make_snapshot(root, manifest_path, manifest)
            self.assertEqual(before.support[support], hashlib.sha256(first).hexdigest())
            helper.write_bytes(second)
            after = runner.make_snapshot(root, manifest_path, manifest)
            self.assertEqual(after.support[support], hashlib.sha256(second).hexdigest())
            self.assertNotEqual(before.support[support], after.support[support])
            (helpers / "unrecorded_helper.py").write_bytes(b"VALUE = 'not-approved'\n")
            with self.assertRaises(runner.ImpactError):
                runner.make_snapshot(root, manifest_path, manifest)
