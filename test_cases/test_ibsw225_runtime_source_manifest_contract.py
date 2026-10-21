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


# Reviewed layout fix only. Original FROZEN_SHA256/access inverse stay unchanged.
# These are independent literal preimage/postimage hunks, not runtime-derived.
LAYOUT_APPROVED_COMPOSITION = {
    'tools/ibsw_upgrade_contract.py': (
        b'def normalize_upgrade(document, *, selected, method, package_dir=None):\n',
        b'''def _fixed_layout(module_file):
    """One complete fixed bundle; canonical identity wins over local decoys."""
    from pathlib import Path
    directory = Path(module_file).resolve().parent
    canonical = directory.parent / 'infiniband/bringup/xdr-upgrade'
    if directory.name == 'tools' and (canonical / 'upgrade.py').is_file():
        if (directory / 'upgrade.py').is_file():
            raise ValueError('ambiguous fixed runtime layouts')
        if (canonical / 'ibsw_upgrade_driver.py').is_file():
            raise ValueError('fixed runtime layout/source disagreement')
        scripts = canonical
    else:
        scripts = directory
        if not (scripts / 'upgrade.py').is_file():
            raise ValueError('complete fixed flat runtime entry required')
    modules = ('ibsw_upgrade_driver', 'ibsw_upgrade_contract', 'ibsw_upgrade_inputs',
               'ibsw_upgrade_component', 'ibsw_upgrade_schedule', 'ibsw_upgrade_observer',
               'ibsw_upgrade_executor', 'ibsw_upgrade_access', 'ibsw_upgrade_pipeline',
               '_package_common', 'project_contract', 'ssh_key_preparation',
               'ib_bringup_runtime_guard')
    if (any(not (directory / (name + '.py')).is_file() for name in modules)
            or any(not (scripts / name).is_file() for name in
                   ('upgrade.py', 'upgrade.sh', 'upgrade-component.sh',
                    'upgrade-owned-runner.sh', 'requirements.txt'))):
        raise ValueError('incomplete selected fixed runtime bundle')
    return scripts


def normalize_upgrade(document, *, selected, method, package_dir=None):
'''),
    'tools/ibsw_upgrade_component.py': (
        b'''_MODULE_DIR = Path(__file__).resolve().parent
_TEMPLATE = (_MODULE_DIR.parent / "infiniband/bringup/xdr-upgrade/upgrade-component.sh"
             if _MODULE_DIR.name == "tools" else _MODULE_DIR / "upgrade-component.sh")
''',
        b'''from ibsw_upgrade_contract import _fixed_layout
_MODULE_DIR = Path(__file__).resolve().parent
_TEMPLATE = _fixed_layout(__file__) / "upgrade-component.sh"
'''),
    'tools/ibsw_upgrade_executor.py': (
        b'''    module_dir = Path(__file__).resolve().parent
    runner = (module_dir.parent / "infiniband/bringup/xdr-upgrade/upgrade-owned-runner.sh"
              if module_dir.name == "tools" else module_dir / "upgrade-owned-runner.sh")
    body = runner.read_bytes()
''',
        b'''    if _fixed_layout(__file__) / "upgrade-owned-runner.sh" != _RUNNER:
        raise ValueError("fixed owned runner layout changed")
    body = _RUNNER.read_bytes()
'''),
}


COMPONENT_TEMPLATE_READ_COMPOSITION = (
    b'    template = _TEMPLATE.read_text(encoding="utf-8")\n',
    b'    if _fixed_layout(__file__) / "upgrade-component.sh" != _TEMPLATE:\n'
    b'        raise ValueError("fixed component template layout changed")\n'
    b'    template = _TEMPLATE.read_text(encoding="utf-8")\n',
)


EXECUTOR_RUNNER_INITIAL_COMPOSITION = (
    b'_OS_COMMAND = "nv show system version"\n',
    b'from ibsw_upgrade_contract import _fixed_layout\n'
    b'_RUNNER = _fixed_layout(__file__) / "upgrade-owned-runner.sh"\n'
    b'\n'
    b'_OS_COMMAND = "nv show system version"\n',
)


def _layout_composition_hunks(relative):
    if type(relative) is not str or relative not in LAYOUT_APPROVED_COMPOSITION:
        raise ValueError('unapproved layout composition source')
    hunks = (LAYOUT_APPROVED_COMPOSITION[relative],)
    if relative == 'tools/ibsw_upgrade_component.py':
        hunks += (COMPONENT_TEMPLATE_READ_COMPOSITION,)
    if relative == 'tools/ibsw_upgrade_executor.py':
        hunks += (EXECUTOR_RUNNER_INITIAL_COMPOSITION,)
    return hunks


def _layout_upstream_bytes_from_exact_composition(relative, payload):
    if type(payload) is not bytes:
        raise TypeError('exact source bytes required')
    hunks = _layout_composition_hunks(relative)
    if any(payload.count(integrated) != 1 for original, integrated in hunks):
        raise ValueError('missing or duplicate approved layout source hunk')
    for original, integrated in hunks:
        payload = payload.replace(integrated, original, 1)
    if any(payload.count(original) != 1 for original, integrated in hunks):
        raise ValueError('restored layout source hunk is not unique')
    return payload


class FixedLayoutExactSourceCompositionTests(unittest.TestCase):
    def test_literal_exact_replacements_restore_only_original_regions(self):
        self.assertEqual(2, len(_layout_composition_hunks('tools/ibsw_upgrade_executor.py')),
                         'executor requires both initial binding and read-site composition')
        self.assertEqual({
            'tools/ibsw_upgrade_contract.py', 'tools/ibsw_upgrade_component.py',
            'tools/ibsw_upgrade_executor.py',
        }, set(LAYOUT_APPROVED_COMPOSITION))
        for relative in LAYOUT_APPROVED_COMPOSITION:
            hunks = _layout_composition_hunks(relative)
            expected = b'prefix\n' + b'middle\n'.join(old for old, new in hunks) + b'suffix\n'
            integrated = b'prefix\n' + b'middle\n'.join(new for old, new in hunks) + b'suffix\n'
            with self.subTest(source=relative):
                self.assertEqual(expected, _layout_upstream_bytes_from_exact_composition(relative, integrated))

    def test_missing_old_partial_deleted_duplicate_and_extra_original_are_refused(self):
        for relative in LAYOUT_APPROVED_COMPOSITION:
            hunks = _layout_composition_hunks(relative)
            whole = b'middle\n'.join(new for old, new in hunks)
            for index, (original, integrated) in enumerate(hunks):
                for label, replacement in (
                    ('missing', b''), ('unfixed', original),
                    ('partial', integrated[:len(integrated)//2]),
                    ('deleted-byte', integrated[:-1]),
                    ('duplicated', integrated + integrated),
                    ('extra-old', original + integrated),
                ):
                    malformed = whole.replace(integrated, replacement, 1)
                    with self.subTest(source=relative, hunk=index, fault=label):
                        with self.assertRaises(ValueError):
                            _layout_upstream_bytes_from_exact_composition(relative, malformed)

    def test_outside_hunk_drift_is_preserved_and_changes_the_restored_hash(self):
        for relative in LAYOUT_APPROVED_COMPOSITION:
            hunks = _layout_composition_hunks(relative)
            expected = b'prefix\n' + b'middle\n'.join(old for old, new in hunks) + b'suffix\n'
            source = b'prefix\n' + b'middle\n'.join(new for old, new in hunks) + b'suffix\n'
            for drift in (b'extra\n' + source, source + b'extra\n',
                          source.replace(b'prefix\n', b'changed-prefix\n', 1)):
                with self.subTest(source=relative, drift=drift):
                    restored = _layout_upstream_bytes_from_exact_composition(relative, drift)
                    self.assertNotEqual(expected, restored)
                    self.assertNotEqual(hashlib.sha256(expected).digest(), hashlib.sha256(restored).digest())
        with self.assertRaises(ValueError):
            _layout_upstream_bytes_from_exact_composition('tools/foreign.py', b'')
        with self.assertRaises(TypeError):
            _layout_upstream_bytes_from_exact_composition('tools/ibsw_upgrade_contract.py', 'not bytes')


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

# Reviewed native source layer; SOURCE candidate NOT RUN.
NATIVE_SCP_FIXED_PATHS = (
    'tools/ibsw_upgrade_driver.py',
    'tools/ibsw_upgrade_executor.py',
    'tools/ibsw_upgrade_component.py',
    'tools/ibsw_upgrade_pipeline.py',
    'tools/ibsw_upgrade_scp.py',
    'infiniband/bringup/xdr-upgrade/upgrade.py',
    'infiniband/bringup/xdr-upgrade/upgrade-component.sh',
)

NATIVE_SCP_APPROVED_COMPOSITION = {
    'tools/ibsw_upgrade_driver.py': (
        # Region 1: original, integrated, retained original count.
        (
            (
                b'import hashlib\n'
                b'import hmac\n'
                b'import json\n'
                b'import os\n'
                b'from pathlib import Path\n'
                b'import posixpath\n'
                b'import re\n'
                b'import secrets\n'
                b'import stat\n'
                b'import sys\n'
                b'import threading\n'
                b'\n'
                b'from _package_common import _package_project_identity, _source_identity\n'
                b'from ibsw_upgrade_contract import (\n'
            ),
            (
                b'import hashlib\n'
                b'import hmac\n'
                b'import json\n'
                b'import math\n'
                b'import os\n'
                b'from pathlib import Path\n'
                b'import posixpath\n'
                b'import re\n'
                b'import secrets\n'
                b'import shlex\n'
                b'import stat\n'
                b'import sys\n'
                b'import threading\n'
                b'import time\n'
                b'\n'
                b'from _package_common import _package_project_identity, _source_identity\n'
                b'from ibsw_upgrade_contract import (\n'
            ),
            0,
        ),
        # Region 2: original, integrated, retained original count.
        (
            (
                b'from project_contract import BRINGUP_OUTPUT_SPECS\n'
                b'from ssh_key_preparation import public_key_identity_bytes\n'
                b'\n'
                b'\n'
                b'_LOCAL_REQUEST_LOCK = threading.RLock()\n'
                b'\n'
            ),
            (
                b'from project_contract import BRINGUP_OUTPUT_SPECS\n'
                b'from ssh_key_preparation import public_key_identity_bytes\n'
                b'\n'
                b'\n'
                b'# Finite probe-runtime baseline at trusted driver import, before any invocation\n'
                b'# or test IO seam. This is not a whole-stdlib / prior-interpreter attestation.\n'
                b'_SCP_PROBE_MODULES = (json, base64, shlex, math, time, threading)\n'
                b'_SCP_PROBE_LEAVES = (json.loads, json.dumps, base64.b64encode, shlex.quote,\n'
                b'    math.isfinite, time.monotonic, time.sleep, threading.Lock, threading.Timer, threading.Event)\n'
                b"_SCP_PROBE_LEAF_STATE = tuple((type(value), getattr(value, '__code__', None),\n"
                b"    getattr(value, '__globals__', None)) for value in _SCP_PROBE_LEAVES)\n"
                b'_SCP_PROBE_CONTEXT = (contextmanager, contextmanager.__code__, contextmanager.__globals__,\n'
                b"    contextmanager.__globals__['_GeneratorContextManager'], sys.modules['contextlib'])\n"
                b'\n'
                b'\n'
                b'def _capture_native_scp_cpld_bootstrap():\n'
                b'    """Trusted normal driver-import originals, never a runtime refresh.\n'
                b'\n'
                b'    This does not attest an interpreter already hostile before driver import.\n'
                b'    Nothing is captured successfully unless every temporary owner closes.\n'
                b'    """\n'
                b'    from types import ModuleType\n'
                b'    from ibsw_upgrade_inputs import _HeldDirectory\n'
                b"    component = sys.modules.get('ibsw_upgrade_component')\n"
                b"    if type(component) is not ModuleType or vars(component).get('render_declared_step') is not render_declared_step:\n"
                b"        raise SharedUpgradeHold('fixed CPLD renderer bootstrap unavailable')\n"
                b'    namespace = vars(component)\n'
                b"    rendered = namespace.get('RenderedStep')\n"
                b'    if type(rendered) is not type:\n'
                b"        raise SharedUpgradeHold('fixed CPLD rendered class bootstrap unavailable')\n"
                b'    class_members = tuple(vars(rendered).items())\n'
                b"    layout = namespace['_fixed_layout'](__file__)\n"
                b"    paths = (namespace['_TEMPLATE'], layout / 'upgrade-owned-runner.sh')\n"
                b'    if any(type(path) is not type(Path()) for path in paths):\n'
                b"        raise SharedUpgradeHold('fixed CPLD bootstrap paths unavailable')\n"
                b'    directory = None\n'
                b'    held = []\n'
                b'    images = []\n'
                b'    primary = None\n'
                b'    try:\n'
                b'        directory = _HeldDirectory(layout)\n'
                b'        for path in paths:\n'
                b'            if path.parent != layout:\n'
                b"                raise SharedUpgradeHold('fixed CPLD bootstrap layout changed')\n"
                b'            original = _HeldFile(path, directory)\n'
                b'            held.append(original)\n'
                b'            item = os.fstat(original.fd)\n'
                b'            if item.st_nlink != 1 or item.st_mode & 0o022:\n'
                b"                raise SharedUpgradeHold('fixed CPLD bootstrap template unsafe')\n"
                b'            identity = (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,\n'
                b'                        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)\n'
                b'            images.append((str(path), identity, original.payload))\n'
                b'        for original in held:\n'
                b'            original.verify()\n'
                b'        directory.verify()\n'
                b'    except BaseException as error:\n'
                b'        primary = error\n'
                b'    finally:\n'
                b'        for original in tuple(reversed(held)) + ((directory,) if directory is not None else ()):\n'
                b'            try:\n'
                b'                original.close()\n'
                b'            except BaseException as error:\n'
                b'                if primary is None or isinstance(primary, Exception) and not isinstance(error, Exception):\n'
                b'                    primary = error\n'
                b'    if primary is not None:\n'
                b'        if not isinstance(primary, Exception):\n'
                b'            raise primary\n'
                b"        raise SharedUpgradeHold('fixed CPLD bootstrap originals uncertain') from None\n"
                b'    return component, rendered, class_members, tuple(images), paths\n'
                b'\n'
                b'\n'
                b'_SCP_CPLD_BOOTSTRAP = _capture_native_scp_cpld_bootstrap()\n'
                b'\n'
                b'_LOCAL_REQUEST_LOCK = threading.RLock()\n'
                b'\n'
            ),
            0,
        ),
        # Region 3: original, integrated, retained original count.
        (
            (
                b'\n'
                b'\n'
                b'\n'
                b'def _validate_component_graph(files, binding, read, *, switch_dir):\n'
                b'    """Separate schema2 byte graph. No file or JSON field grants dispatch."""\n'
                b'    files = set(files)\n'
            ),
            (
                b'\n'
                b'\n'
                b'\n'
                b'def _scp_component_launch_command_data(remote, runner_sha256, step_sha256):\n'
                b'    """Pure command DATA from the unique literal in the fixed original image.\n'
                b'\n'
                b'    Do not call a mutable cached provider function during graph validation.\n'
                b'    Native writer/consumer separately require the live compiled producer joint.\n'
                b'    """\n'
                b'    import ast\n'
                b'    directory = Path(__file__).resolve().parent\n'
                b'    rows, primary, raw = [], None, None\n'
                b'\n'
                b'    def identity(info):\n'
                b'        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)\n'
                b'\n'
                b'    def facts(info):\n'
                b'        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,\n'
                b'                info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)\n'
                b'\n'
                b'    def opened(name, flags, parent=None):\n'
                b'        named = os.stat(name, dir_fd=parent, follow_symlinks=False)\n'
                b"        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0), dir_fd=parent)\n"
                b'        rows.append((fd, identity(named)))\n'
                b'        if identity(os.fstat(fd)) != identity(named):\n'
                b"            raise ValueError('fixed graph image original identity changed')\n"
                b'        return fd, named\n'
                b'\n'
                b'    try:\n'
                b'        parent, before_parent = opened(str(directory), os.O_RDONLY | os.O_DIRECTORY)\n'
                b"        fd, before = opened('ibsw_upgrade_scp.py', os.O_RDONLY, parent)\n"
                b'        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1\n'
                b'                or before.st_mode & 0o022 or not 0 < before.st_size <= MAXIMUM_INPUT_BYTES):\n'
                b"            raise ValueError('bounded readonly original SCP image required')\n"
                b'        chunks, count = [], 0\n'
                b'        while count < before.st_size:\n'
                b'            part = os.read(fd, min(65536, before.st_size - count))\n'
                b"            if not part: raise ValueError('partial original SCP image')\n"
                b'            chunks.append(part); count += len(part)\n'
                b'        if (os.read(fd, 1) or facts(os.fstat(fd)) != facts(before)\n'
                b"                or facts(os.stat('ibsw_upgrade_scp.py', dir_fd=parent, follow_symlinks=False)) != facts(before)\n"
                b'                or identity(os.fstat(parent)) != identity(before_parent)\n'
                b'                or identity(os.stat(directory, follow_symlinks=False)) != identity(before_parent)):\n'
                b"            raise ValueError('original SCP image changed during graph read')\n"
                b"        raw = b''.join(chunks)\n"
                b'    except BaseException as error:\n'
                b'        primary = error\n'
                b'    finally:\n'
                b'        for fd, original in reversed(rows):\n'
                b'            try:\n'
                b'                if identity(os.fstat(fd)) != original:\n'
                b"                    raise ValueError('original graph source descriptor changed; no numeric retry')\n"
                b'                os.close(fd)\n'
                b'            except BaseException as error:\n'
                b'                if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):\n'
                b'                    primary = error\n'
                b'    if primary is not None: raise primary\n'
                b'    tree = ast.parse(raw)\n'
                b'    matches = [node for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))\n'
                b"        and any(isinstance(target, ast.Name) and target.id == '_STDIN_LAUNCHER'\n"
                b'                for target in (node.targets if isinstance(node, ast.Assign) else (node.target,)))]\n'
                b'    if (len(matches) != 1 or not isinstance(matches[0].value, ast.Constant)\n'
                b'            or type(matches[0].value.value) is not str):\n'
                b"        raise ValueError('unique literal fixed stdin launcher required')\n"
                b"    expression = 'import base64;exec(base64.b64decode(' + repr(base64.b64encode(\n"
                b"        matches[0].value.value.encode()).decode()) + '))'\n"
                b"    return '/usr/bin/python3 -c ' + shlex.quote(expression) + ''.join(\n"
                b"        ' ' + shlex.quote(value) for value in (remote, runner_sha256, step_sha256))\n"
                b'\n'
                b'\n'
                b'def _validate_component_graph(files, binding, read, *, switch_dir):\n'
                b'    """Separate schema2 byte graph. No file or JSON field grants dispatch."""\n'
                b'    files = set(files)\n'
            ),
            1,
        ),
        # Region 4: original, integrated, retained original count.
        (
            (
                b'        document = json.loads(read("component-dispatch.json"))\n'
                b'        if (document.get("schema_version") != 2 or document.get("binding") != binding\n'
                b'                or document.get("request_sha256") != hashlib.sha256(read("request.json")).hexdigest()\n'
                b'                or document.get("runner_binding_sha256") != hashlib.sha256(read("runner-binding.json")).hexdigest()\n'
                b'                or document.get("launch_kind") != "OWNED_RUNNER_V1"):\n'
                b'            raise ValueError("original component dispatch binding changed")\n'
                b'        records = _component_raw_records(document["records"])\n'
                b'        from ibsw_upgrade_executor import _owned_launch_command\n'
                b'        if records[-1]["command"] != _owned_launch_command(document["remote_script"]):\n'
                b'            raise ValueError("original component launch chain changed")\n'
                b'    repair_files = {"after.commands", "missing.commands", "component-repair.json"}\n'
                b'    for name in sorted(files & _DOWNLOAD_FILES):\n'
            ),
            (
                b'        document = json.loads(read("component-dispatch.json"))\n'
                b'        if (document.get("schema_version") != 2 or document.get("binding") != binding\n'
                b'                or document.get("request_sha256") != hashlib.sha256(read("request.json")).hexdigest()\n'
                b'                or document.get("runner_binding_sha256") != hashlib.sha256(read("runner-binding.json")).hexdigest()):\n'
                b'            raise ValueError("original component dispatch binding changed")\n'
                b'        records = _component_raw_records(document["records"])\n'
                b"        if document.get('launch_kind') == 'SCP_STDIN_OWNED_RUNNER_V2':\n"
                b"            if (set(document) != {'schema_version', 'state', 'binding', 'request_sha256',\n"
                b"                    'remote_script', 'records', 'launch_kind', 'runner_binding_sha256', 'scp_companion_sha256'}\n"
                b"                    or document.get('state') != 'COMPONENT_DISPATCH_DATA_ONLY'\n"
                b"                    or binding['component'] != 'cpld' or 'scp-source-request.json' not in files\n"
                b"                    or 'package-source.json' in files\n"
                b"                    or document.get('scp_companion_sha256') != hashlib.sha256(read('scp-source-request.json')).hexdigest()\n"
                b"                    or posixpath.dirname(posixpath.dirname(document['remote_script'])) != switch_dir\n"
                b"                    or runner_binding.get('remote_script') != document['remote_script']\n"
                b"                    or records[-1]['stdout_base64'] != base64.b64encode(b'IBSW_LAUNCH_REQUESTED\\n').decode('ascii')\n"
                b"                    or records[-1]['stderr_base64'] != '' or records[-1]['returncode'] != 0\n"
                b"                    or records[-1]['stream_complete'] is not True):\n"
                b"                raise ValueError('original SCP-only CPLD companion/remote graph required')\n"
                b"            expected = _scp_component_launch_command_data(document['remote_script'],\n"
                b"                hashlib.sha256(read('runner.sh')).hexdigest(), hashlib.sha256(read('step.sh')).hexdigest())\n"
                b"        elif document.get('launch_kind') == 'OWNED_RUNNER_V1':\n"
                b"            if 'scp-source-request.json' in files or 'scp_companion_sha256' in document:\n"
                b"                raise ValueError('SCP companion cannot authorize a V1 dispatch')\n"
                b'            from ibsw_upgrade_executor import _owned_launch_command\n'
                b"            expected = _owned_launch_command(document['remote_script'])\n"
                b'        else:\n'
                b"            raise ValueError('unknown original component launch kind')\n"
                b'        if records[-1]["command"] != expected:\n'
                b'            raise ValueError("original component launch chain changed")\n'
                b'    repair_files = {"after.commands", "missing.commands", "component-repair.json"}\n'
                b'    for name in sorted(files & _DOWNLOAD_FILES):\n'
            ),
            0,
        ),
        # Region 5: original, integrated, retained original count.
        (
            (
                b'    return result\n'
                b'\n'
                b'\n'
                b'class _PreparedRunScope:\n'
                b'    """Live local DATA transaction only. No dispatcher or device-result writer."""\n'
                b'    def __init__(self, entry, cwd, args, run_directory, *, manual_execution=False):\n'
            ),
            (
                b'    return result\n'
                b'\n'
                b'\n'
                b'def _fixed_scp_source_api(scope, *, probe=False):\n'
                b'    """Fresh fixed-source/object joint, not source-instance or native authority.\n'
                b'\n'
                b'    Cached provider code is compiled for comparison, never re-executed. The\n'
                b'    returned references are internal original-object anchors, not a permit.\n'
                b'    The old package-source audit/default is deliberately independent/unchanged.\n'
                b'    """\n'
                b'    import ast\n'
                b'    import base64 as std_base64\n'
                b'    import builtins\n'
                b'    import dataclasses\n'
                b'    import importlib.machinery\n'
                b'    import importlib.util\n'
                b'    import ipaddress\n'
                b'    import struct\n'
                b'    from types import CodeType, FunctionType, GetSetDescriptorType, ModuleType\n'
                b'    from ibsw_upgrade_inputs import _HeldDirectory\n'
                b'\n'
                b'    if type(probe) is not bool:\n'
                b"        raise SharedUpgradeHold('fixed SCP source probe mode must be bool')\n"
                b'    if type(scope) is not _PreparedRunScope:\n'
                b"        raise SharedUpgradeHold('original SCP source scope required')\n"
                b'    scope.verify()  # A poisoned/closed parent must not reopen audit sources.\n'
                b'    if scope.closed or scope.cleanup_issues or scope._package_source_lifecycle_failure is not None:\n'
                b"        raise SharedUpgradeHold('fixed SCP source scope is not reusable')\n"
                b'    directory = None\n'
                b'    held = []\n'
                b'    created = module = result = primary = None\n'
                b'    cleanup = []\n'
                b"    name = 'ibsw_upgrade_scp'\n"
                b'    root = Path(__file__).absolute().parent\n'
                b'\n'
                b'    def refuse():\n'
                b"        raise SharedUpgradeHold('fixed SCP source provider joint changed')\n"
                b'\n'
                b'    def text(value, expected):\n'
                b'        return type(value) is str and value == expected\n'
                b'\n'
                b'    def unique_code(parent, selected):\n'
                b'        values = [value for value in parent.co_consts\n'
                b'                  if type(value) is CodeType and value.co_name == selected]\n'
                b'        if len(values) != 1:\n'
                b'            refuse()\n'
                b'        return values[0]\n'
                b'\n'
                b'    def function(value, expected, namespace, module_name, cells=(), annotations=None):\n'
                b'        if (type(value) is not FunctionType or value.__globals__ is not namespace\n'
                b'                or not text(value.__module__, module_name) or value.__code__ != expected\n'
                b'                or value.__defaults__ is not None or value.__kwdefaults__ is not None\n'
                b'                or type(value.__annotations__) is not dict):\n'
                b'            refuse()\n'
                b'        if annotations is not None:\n'
                b'            actual_annotations = value.__annotations__\n'
                b'            if (any(type(key) is not str for key in actual_annotations)\n'
                b'                    or set(actual_annotations) != set(annotations)):\n'
                b'                refuse()\n'
                b'            for key, original in annotations.items():\n'
                b'                if ((original is None and actual_annotations[key] is not None)\n'
                b'                        or original is not None and not text(actual_annotations[key], original)):\n'
                b'                    refuse()\n'
                b'        actual = () if value.__closure__ is None else value.__closure__\n'
                b'        if len(actual) != len(cells):\n'
                b'            refuse()\n'
                b'        for cell, original in zip(actual, cells):\n'
                b'            if cell.cell_contents is not original:\n'
                b'                refuse()\n'
                b'        return value\n'
                b'\n'
                b'    def producer_function(value, expected, namespace, module_name, *, tuple_default=False,\n'
                b'                          native_keywords=False, cells=()):\n'
                b'        # Narrow additional signatures only. The default source19 function\n'
                b'        # validator and all its old call sites remain byte-for-byte unchanged.\n'
                b'        if (type(value) is not FunctionType or value.__globals__ is not namespace\n'
                b'                or not text(value.__module__, module_name) or value.__code__ != expected\n'
                b'                or type(value.__annotations__) is not dict or value.__annotations__):\n'
                b'            refuse()\n'
                b'        defaults = value.__defaults__\n'
                b'        if tuple_default:\n'
                b'            if (type(defaults) is not tuple or len(defaults) != 1\n'
                b'                    or type(defaults[0]) is not tuple or defaults[0]):\n'
                b'                refuse()\n'
                b'        elif defaults is not None:\n'
                b'            refuse()\n'
                b'        keywords = value.__kwdefaults__\n'
                b'        if native_keywords:\n'
                b'            if (type(keywords) is not dict or any(type(key) is not str for key in keywords)\n'
                b"                    or set(keywords) != {'capture_raw', 'reason_code'}\n"
                b"                    or keywords['capture_raw'] is not None\n"
                b"                    or not text(keywords['reason_code'], 'READONLY_QUERY_FAILED')):\n"
                b'                refuse()\n'
                b'        elif keywords is not None:\n'
                b'            refuse()\n'
                b'        actual = () if value.__closure__ is None else value.__closure__\n'
                b'        if len(actual) != len(cells) or any(cell.cell_contents is not original\n'
                b'                                         for cell, original in zip(actual, cells)):\n'
                b'            refuse()\n'
                b'        return value\n'
                b'\n'
                b'\n'
                b'    def fixed_module(value, expected_name, path):\n'
                b'        if type(value) is not ModuleType or sys.modules.get(expected_name) is not value:\n'
                b'            refuse()\n'
                b'        namespace = vars(value)\n'
                b"        spec, loader = namespace.get('__spec__'), namespace.get('__loader__')\n"
                b"        if (not text(namespace.get('__name__'), expected_name) or not text(namespace.get('__file__'), str(path))\n"
                b'                or type(spec) is not importlib.machinery.ModuleSpec\n'
                b'                or type(loader) is not importlib.machinery.SourceFileLoader\n'
                b'                or not text(spec.name, expected_name) or not text(spec.origin, str(path)) or spec.loader is not loader\n'
                b'                or not text(loader.name, expected_name) or not text(loader.path, str(path))\n'
                b"                or namespace.get('__builtins__') is not builtins.__dict__):\n"
                b'            refuse()\n'
                b'        return namespace\n'
                b'\n'
                b'    def original_data(tree, selected):\n'
                b'        values = [node.value for node in tree.body if isinstance(node, ast.Assign)\n'
                b'                  and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)\n'
                b'                  and node.targets[0].id == selected]\n'
                b'        if len(values) != 1:\n'
                b'            refuse()\n'
                b'        return ast.literal_eval(values[0])\n'
                b'\n'
                b'    try:\n'
                b'        directory = _HeldDirectory(root)\n'
                b'        images = {}\n'
                b"        filenames = ('ibsw_upgrade_scp.py', 'ssh_key_preparation.py', Path(__file__).name)\n"
                b'        if probe:\n'
                b"            filenames += ('ibsw_upgrade_observer.py',)\n"
                b'        for filename in filenames:\n'
                b'            original = _HeldFile(root / filename, directory)\n'
                b'            held.append(original)  # Before any subsequent metadata/compile operation.\n'
                b'            info = os.fstat(original.fd)\n'
                b'            if info.st_nlink != 1 or info.st_mode & 0o022:\n'
                b'                refuse()\n'
                b'            images[filename] = (original, compile(original.payload, str(root / filename),\n'
                b"                'exec', dont_inherit=True, optimize=sys.flags.optimize))\n"
                b"        provider, code = images['ibsw_upgrade_scp.py']\n"
                b'        module = sys.modules.get(name)\n'
                b'        if name in sys.modules and module is None:\n'
                b'            refuse()  # A cached None is not cold-import permission.\n'
                b'        if module is None:\n'
                b"            spec = importlib.util.spec_from_file_location(name, str(root / 'ibsw_upgrade_scp.py'))\n"
                b'            module = importlib.util.module_from_spec(spec)\n'
                b'            created = module\n'
                b'            sys.modules[name] = module\n'
                b'            exec(code, vars(module))  # Only genuinely absent fixed held source.\n'
                b"        namespace = fixed_module(module, name, root / 'ibsw_upgrade_scp.py')\n"
                b"        factory = function(namespace.get('source_from_known_hosts'),\n"
                b"                           unique_code(code, 'source_from_known_hosts'), namespace, name)\n"
                b"        read_trust = function(namespace.get('_read_trust'), unique_code(code, '_read_trust'), namespace, name)\n"
                b"        shared_verify = function(namespace.get('verify_source_shared'),\n"
                b"                                 unique_code(code, 'verify_source_shared'), namespace, name)\n"
                b"        errors = namespace.get('ERRORS')\n"
                b"        expected_errors = original_data(ast.parse(provider.payload), 'ERRORS')\n"
                b'        if (type(errors) is not dict or type(expected_errors) is not dict\n'
                b'                or any(type(key) is not str or type(value) is not str for key, value in errors.items())\n'
                b'                or any(type(key) is not str or type(value) is not str for key, value in expected_errors.items())\n'
                b'                or errors != expected_errors):\n'
                b'            refuse()\n'
                b"        error_class = namespace.get('ScpHold')\n"
                b'        if (type(error_class) is not type or error_class.__bases__ != (ValueError,)\n'
                b'                or not text(error_class.__module__, name)\n'
                b"                or set(vars(error_class)) != {'__module__', '__doc__', '__init__', '__weakref__'}):\n"
                b'            refuse()\n'
                b"        error_init = function(vars(error_class)['__init__'],\n"
                b"            unique_code(unique_code(code, 'ScpHold'), '__init__'), namespace, name, (error_class,))\n"
                b'\n'
                b'        # The genuine public-key and endpoint parsers are part of this actual\n'
                b'        # factory call graph; a correct provider filename alone is insufficient.\n'
                b"        key_module = sys.modules.get('ssh_key_preparation')\n"
                b"        key_namespace = fixed_module(key_module, 'ssh_key_preparation', root / 'ssh_key_preparation.py')\n"
                b"        key_code = images['ssh_key_preparation.py'][1]\n"
                b"        key_parser = function(key_namespace.get('public_key_identity_bytes'),\n"
                b"            unique_code(key_code, 'public_key_identity_bytes'), key_namespace, 'ssh_key_preparation')\n"
                b"        key_error = key_namespace.get('SshKeyPreparationError')\n"
                b'        if (type(key_error) is not type or key_error.__bases__ != (ValueError,)\n'
                b"                or not text(key_error.__module__, 'ssh_key_preparation')\n"
                b"                or set(vars(key_error)) != {'__module__', '__doc__', '__weakref__'}\n"
                b"                or key_namespace.get('PUBLIC_KEY_LIMIT') != 65536\n"
                b"                or type(key_namespace.get('PUBLIC_KEY_LIMIT')) is not int):\n"
                b'            refuse()\n'
                b"        for selected, expected in (('base64', std_base64), ('struct', struct)):\n"
                b'            if key_namespace.get(selected) is not expected:\n'
                b'                refuse()\n'
                b'        driver_module = sys.modules.get(__name__)\n'
                b'        driver_namespace = fixed_module(driver_module, __name__, root / Path(__file__).name)\n'
                b"        if driver_namespace is not globals() or driver_namespace.get('public_key_identity_bytes') is not key_parser:\n"
                b'            refuse()\n'
                b"        endpoint_parser = function(driver_namespace.get('_known_host_endpoint_matches'),\n"
                b"            unique_code(images[Path(__file__).name][1], '_known_host_endpoint_matches'),\n"
                b'            driver_namespace, __name__)\n'
                b'\n'
                b"        source_class = namespace.get('ScpSource')\n"
                b'        if (type(source_class) is not type or source_class.__bases__ != (object,)\n'
                b"                or not text(source_class.__module__, name) or not text(source_class.__qualname__, 'ScpSource')):\n"
                b'            refuse()\n'
                b'        members = dict(vars(source_class))  # Original object snapshot, not a live mappingproxy alias.\n'
                b"        field_names = ('host', 'user', 'port', 'known_hosts_path', 'host_keys', 'password', '_identity')\n"
                b"        field_types = dict(zip(field_names, ('str', 'str', 'int', 'Path', 'bytes', 'str', 'tuple')))\n"
                b'        model = sys.version_info[:2]\n'
                b'        if model not in ((3, 9), (3, 12)):\n'
                b'            refuse()  # Only these reviewed generator shapes; no name-only fallback.\n'
                b"        expected_members = {'__module__', '__annotations__', '__dict__', '__weakref__', '__doc__',\n"
                b"            'verify', 'public_document', '__dataclass_params__', '__dataclass_fields__',\n"
                b"            '__init__', '__repr__', '__eq__', '__setattr__', '__delattr__', '__hash__'}\n"
                b'        if model == (3, 12):\n'
                b"            expected_members.add('__match_args__')\n"
                b"        if (set(members) != expected_members or type(members['__annotations__']) is not dict\n"
                b"                or any(type(key) is not str or type(value) is not str for key, value in members['__annotations__'].items())\n"
                b"                or members['__annotations__'] != field_types\n"
                b"                or model == (3, 12) and (type(members['__match_args__']) is not tuple\n"
                b"                    or any(type(value) is not str for value in members['__match_args__'])\n"
                b"                    or members['__match_args__'] != field_names)):\n"
                b'            refuse()\n'
                b"        for selected in ('__dict__', '__weakref__'):\n"
                b'            descriptor = members[selected]\n'
                b'            if (type(descriptor) is not GetSetDescriptorType\n'
                b'                    or descriptor.__objclass__ is not source_class or descriptor.__name__ != selected):\n'
                b'                refuse()\n'
                b"        class_code = unique_code(code, 'ScpSource')\n"
                b"        source_verify = function(members['verify'], unique_code(class_code, 'verify'), namespace, name)\n"
                b"        source_document = function(members['public_document'],\n"
                b"                                   unique_code(class_code, 'public_document'), namespace, name)\n"
                b"        params, fields = members['__dataclass_params__'], members['__dataclass_fields__']\n"
                b'        if (type(params) is not dataclasses._DataclassParams or type(fields) is not dict\n'
                b'                or any(type(key) is not str for key in fields) or tuple(fields) != field_names):\n'
                b'            refuse()\n'
                b"        for selected, expected in (('init', True), ('repr', True), ('eq', True),\n"
                b"                ('order', False), ('unsafe_hash', False), ('frozen', True)):\n"
                b'            if getattr(params, selected) is not expected:\n'
                b'                refuse()\n'
                b'        if model == (3, 12):\n'
                b"            for selected, expected in (('match_args', True), ('kw_only', False), ('slots', False), ('weakref_slot', False)):\n"
                b'                if getattr(params, selected) is not expected:\n'
                b'                    refuse()\n'
                b'        for selected in field_names:\n'
                b'            field = fields[selected]\n'
                b'            if (type(field) is not dataclasses.Field or not text(field.name, selected)\n'
                b'                    or not text(field.type, field_types[selected]) or field.default is not dataclasses.MISSING\n'
                b'                    or field.default_factory is not dataclasses.MISSING or field.init is not True\n'
                b'                    or field.compare is not True or field.hash is not None\n'
                b"                    or field.repr is not (selected not in ('password', '_identity'))\n"
                b'                    or field._field_type is not dataclasses._FIELD\n'
                b'                    or field.metadata is not dataclasses._EMPTY_METADATA\n'
                b'                    or model == (3, 12) and field.kw_only is not False):\n'
                b'                refuse()\n'
                b'\n'
                b'        # Compiler inputs below come only from these reviewed fixed fields and\n'
                b'        # the two original stdlib generator shapes, not candidate method output.\n'
                b'        def generated(selected, args, body, local_names=(), returns=False):\n'
                b'            local_names = list(local_names)\n'
                b"            if model == (3, 9) and 'BUILTINS' not in local_names:\n"
                b"                local_names.append('BUILTINS')  # Apple3.9 _create_fn source.\n"
                b"            annotation = ''\n"
                b'            if returns:\n'
                b"                variable = '_return_type' if model == (3, 9) else '__dataclass_return_type__'\n"
                b'                local_names.append(variable)\n'
                b"                annotation = '->' + variable\n"
                b"            text = ('def __create_fn__(' + ', '.join(local_names) + '):\\n'\n"
                b"                + ' def ' + selected + '(' + ','.join(args) + ')' + annotation + ':\\n'\n"
                b"                + '\\n'.join('  ' + line for line in body) + '\\n return ' + selected)\n"
                b"            compiled = compile(text, '<string>', 'exec', dont_inherit=True, optimize=sys.flags.optimize)\n"
                b"            return unique_code(unique_code(compiled, '__create_fn__'), selected)\n"
                b'\n'
                b"        type_names = [('_type_' + selected if model == (3, 9)\n"
                b"                       else '__dataclass_type_' + selected + '__') for selected in field_names]\n"
                b"        init_locals = type_names + (['MISSING', '_HAS_DEFAULT_FACTORY'] if model == (3, 9)\n"
                b"                                  else ['__dataclass_HAS_DEFAULT_FACTORY__', '__dataclass_builtins_object__'])\n"
                b"        target = 'BUILTINS.object' if model == (3, 9) else '__dataclass_builtins_object__'\n"
                b"        init_code = generated('__init__', ['self'] + [selected + ':' + variable\n"
                b'            for selected, variable in zip(field_names, type_names)],\n'
                b"            [target + '.__setattr__(self,' + repr(selected) + ',' + selected + ')' for selected in field_names],\n"
                b'            init_locals, returns=True)\n'
                b"        init = function(members['__init__'], init_code, namespace, name,\n"
                b"            (builtins,) if model == (3, 9) else (object,), dict(field_types, **{'return': None}))\n"
                b"        self_tuple = '(' + ','.join('self.' + selected for selected in field_names) + ',)'\n"
                b"        other_tuple = '(' + ','.join('other.' + selected for selected in field_names) + ',)'\n"
                b"        equality = function(members['__eq__'], generated('__eq__', ('self', 'other'),\n"
                b"            ['if other.__class__ is self.__class__:', ' return ' + self_tuple + '==' + other_tuple,\n"
                b"             'return NotImplemented']), namespace, name, annotations={})\n"
                b"        hashing = function(members['__hash__'], generated('__hash__', ('self',),\n"
                b"            ['return hash(' + self_tuple + ')']), namespace, name, annotations={})\n"
                b"        condition = ('type(self) is cls or name in (' + ','.join(repr(selected) for selected in field_names) + ',)'\n"
                b"            if model == (3, 9) else 'type(self) is cls or name in {' + ', '.join(repr(selected) for selected in field_names) + '}')\n"
                b'        frozen = []\n'
                b"        for method, word in (('__setattr__', 'assign to'), ('__delattr__', 'delete')):\n"
                b"            expected = generated(method, ('self', 'name', 'value') if method == '__setattr__' else ('self', 'name'),\n"
                b'                [\'if \' + condition + \':\', \' raise FrozenInstanceError(f"cannot \' + word + \' field {name!r}")\',\n'
                b"                 'super(cls, self).' + method + '(name' + (', value)' if method == '__setattr__' else ')')],\n"
                b"                ('cls', 'FrozenInstanceError'))\n"
                b"            cells = {'cls': source_class, 'FrozenInstanceError': dataclasses.FrozenInstanceError}\n"
                b'            frozen.append(function(members[method], expected, namespace, name,\n'
                b'                tuple(cells[selected] for selected in expected.co_freevars), annotations={}))\n'
                b"        representation = members['__repr__']\n"
                b"        wrapper_code = unique_code(dataclasses._recursive_repr.__code__, 'wrapper')\n"
                b'        if (type(representation) is not FunctionType or representation.__code__ != wrapper_code\n'
                b'                or representation.__globals__ is not vars(dataclasses)\n'
                b'                or not text(representation.__module__, name) or representation.__defaults__ is not None\n'
                b'                or representation.__kwdefaults__ is not None or representation.__annotations__ != {}\n'
                b'                or representation.__closure__ is None or len(representation.__closure__) != 2):\n'
                b'            refuse()\n'
                b'        repr_cells = dict(zip(wrapper_code.co_freevars,\n'
                b'                              (cell.cell_contents for cell in representation.__closure__)))\n'
                b"        if set(repr_cells) != {'repr_running', 'user_function'} or type(repr_cells['repr_running']) is not set:\n"
                b'            refuse()\n'
                b'        repr_names = field_names[:-2]\n'
                b"        raw_repr = function(repr_cells['user_function'], generated('__repr__', ('self',),\n"
                b'            [\'return self.__class__.__qualname__ + f"(\' + \', \'.join(\n'
                b'                selected + \'={self.\' + selected + \'!r}\' for selected in repr_names) + \')"\']),\n'
                b'            namespace, name, annotations={})\n'
                b"        if vars(representation).get('__wrapped__') is not raw_repr:\n"
                b'            refuse()\n'
                b'\n'
                b"        for selected, expected in (('os', os), ('Path', Path), ('stat', stat), ('hashlib', hashlib),\n"
                b"                ('base64', std_base64), ('ipaddress', ipaddress), ('re', re),\n"
                b"                ('dataclass', dataclasses.dataclass), ('field', dataclasses.field)):\n"
                b'            if namespace.get(selected) is not expected:\n'
                b'                refuse()\n'
                b'        # Recheck the complete actually used namespace/object joint after all\n'
                b'        # validation, before releasing the original source images.\n'
                b"        anchors = {'source_from_known_hosts': factory, '_read_trust': read_trust,\n"
                b"            'verify_source_shared': shared_verify, 'ScpSource': source_class, 'ScpHold': error_class,\n"
                b"            'ERRORS': errors}\n"
                b'        if (sys.modules.get(name) is not module or any(namespace.get(key) is not value for key, value in anchors.items())\n'
                b"                or errors != expected_errors or vars(error_class).get('__init__') is not error_init\n"
                b"                or sys.modules.get('ssh_key_preparation') is not key_module\n"
                b"                or key_namespace.get('public_key_identity_bytes') is not key_parser\n"
                b"                or driver_namespace.get('_known_host_endpoint_matches') is not endpoint_parser\n"
                b'                or any(vars(source_class).get(key) is not members[key] for key in expected_members)):\n'
                b'            refuse()\n'
                b'        probe_refs = None\n'
                b'        if probe:\n'
                b'            # Only the finite new producer branch sees runtime leaves. In\n'
                b'            # particular default source19 never rejects a legacy sleep IO mock.\n'
                b'            runtime_modules = (json, std_base64, shlex, math, time, threading)\n'
                b'            if (len(_SCP_PROBE_MODULES) != 6 or len(_SCP_PROBE_LEAVES) != 10\n'
                b'                    or len(_SCP_PROBE_LEAF_STATE) != 10\n'
                b'                    or any(type(value) is not ModuleType for value in runtime_modules)\n'
                b'                    or any(actual is not original for actual, original in zip(runtime_modules, _SCP_PROBE_MODULES))):\n'
                b'                refuse()\n'
                b"            for selected, original in zip(('json', 'base64', 'shlex', 'math', 'time', 'threading'), runtime_modules):\n"
                b'                if (sys.modules.get(selected) is not original or namespace.get(selected) is not original\n'
                b'                        or driver_namespace.get(selected) is not original):\n'
                b'                    refuse()\n'
                b'            runtime_leaves = (json.loads, json.dumps, std_base64.b64encode, shlex.quote,\n'
                b'                math.isfinite, time.monotonic, time.sleep, threading.Lock, threading.Timer, threading.Event)\n'
                b'            if any(actual is not original for actual, original in zip(runtime_leaves, _SCP_PROBE_LEAVES)):\n'
                b'                refuse()\n'
                b'            for value, (kind, original_code, original_globals) in zip(runtime_leaves, _SCP_PROBE_LEAF_STATE):\n'
                b"                if (type(value) is not kind or getattr(value, '__code__', None) is not original_code\n"
                b"                        or getattr(value, '__globals__', None) is not original_globals):\n"
                b'                    refuse()\n'
                b"            fixed_probe = producer_function(namespace.get('_probe_source_channel'),\n"
                b"                unique_code(code, '_probe_source_channel'), namespace, name)\n"
                b"            payload = producer_function(namespace.get('launch_payload'),\n"
                b"                unique_code(code, 'launch_payload'), namespace, name, tuple_default=True)\n"
                b"            helper_bytes = producer_function(namespace.get('remote_helper_bytes'),\n"
                b"                unique_code(code, 'remote_helper_bytes'), namespace, name)\n"
                b"            python_command = producer_function(namespace.get('_python_command'),\n"
                b"                unique_code(code, '_python_command'), namespace, name)\n"
                b"            helper = namespace.get('_REMOTE_HELPER')\n"
                b"            expected_helper = original_data(ast.parse(provider.payload), '_REMOTE_HELPER')\n"
                b'            if type(helper) is not str or type(expected_helper) is not str or helper != expected_helper:\n'
                b'                refuse()\n'
                b'\n'
                b"            observer_name = 'ibsw_upgrade_observer'\n"
                b'            observer = sys.modules.get(observer_name)\n'
                b"            observer_namespace = fixed_module(observer, observer_name, root / (observer_name + '.py'))\n"
                b"            observer_original, observer_code = images[observer_name + '.py']\n"
                b"            if (observer_namespace.get('time') is not runtime_modules[4]\n"
                b"                    or observer_namespace.get('threading') is not runtime_modules[5]\n"
                b"                    or observer_namespace.get('SharedUpgradeHold') is not SharedUpgradeHold):\n"
                b'                refuse()\n'
                b'            context, context_code, context_globals, generator_cm, context_module = _SCP_PROBE_CONTEXT\n'
                b'            if (type(context) is not FunctionType or context is not contextmanager\n'
                b'                    or context.__code__ is not context_code or context.__globals__ is not context_globals\n'
                b"                    or type(context_module) is not ModuleType or sys.modules.get('contextlib') is not context_module\n"
                b'                    or context_globals is not vars(context_module)\n'
                b"                    or context_globals.get('contextmanager') is not context\n"
                b"                    or context_globals.get('_GeneratorContextManager') is not generator_cm\n"
                b"                    or observer_namespace.get('contextmanager') is not context):\n"
                b'                refuse()\n'
                b"            owned = observer_namespace.get('_owned_phase')\n"
                b"            if type(owned) is not FunctionType or set(vars(owned)) != {'__wrapped__'}:\n"
                b'                refuse()\n'
                b"            owned_inner = producer_function(vars(owned)['__wrapped__'],\n"
                b"                unique_code(observer_code, '_owned_phase'), observer_namespace, observer_name)\n"
                b"            owned = producer_function(owned, unique_code(context_code, 'helper'),\n"
                b'                context_globals, observer_name, cells=(owned_inner,))\n'
                b"            remaining = producer_function(observer_namespace.get('_remaining'),\n"
                b"                unique_code(observer_code, '_remaining'), observer_namespace, observer_name)\n"
                b"            native_hold = observer_namespace.get('_NativeObservationHold')\n"
                b'            if (type(native_hold) is not type or native_hold.__bases__ != (ValueError,)\n'
                b'                    or not text(native_hold.__module__, observer_name)\n'
                b"                    or not text(native_hold.__name__, '_NativeObservationHold')\n"
                b"                    or not text(native_hold.__qualname__, '_NativeObservationHold')\n"
                b"                    or set(vars(native_hold)) != {'__module__', '__doc__', '__init__', '__weakref__'}\n"
                b"                    or vars(native_hold)['__doc__'] is not None):\n"
                b'                refuse()\n'
                b"            hold_init = producer_function(vars(native_hold)['__init__'],\n"
                b"                unique_code(unique_code(observer_code, '_NativeObservationHold'), '__init__'),\n"
                b'                observer_namespace, observer_name, tuple_default=True,\n'
                b'                native_keywords=True, cells=(native_hold,))\n'
                b'            hints = []\n'
                b"            for selected in ('READONLY_FAILURE_HINTS', 'UPGRADE_FAILURE_HINTS'):\n"
                b'                current_hints = observer_namespace.get(selected)\n'
                b'                expected_hints = original_data(ast.parse(observer_original.payload), selected)\n'
                b'                if (type(current_hints) is not dict or type(expected_hints) is not dict\n'
                b'                        or any(type(key) is not str or type(value) is not str for key, value in current_hints.items())\n'
                b'                        or current_hints != expected_hints):\n'
                b'                    refuse()\n'
                b'                hints.append(current_hints)\n'
                b'            # These are source/object references, never a source/operation grant.\n'
                b'            probe_refs = (fixed_probe, payload, helper_bytes, python_command, helper,\n'
                b'                observer, owned, owned_inner, remaining, native_hold, hold_init,\n'
                b'                hints[0], hints[1], context, generator_cm, context_module) + runtime_modules + runtime_leaves\n'
                b'            if (any(namespace.get(selected) is not original for selected, original in (\n'
                b"                    ('_probe_source_channel', fixed_probe), ('launch_payload', payload),\n"
                b"                    ('remote_helper_bytes', helper_bytes), ('_python_command', python_command), ('_REMOTE_HELPER', helper)))\n"
                b'                    or sys.modules.get(observer_name) is not observer\n'
                b'                    or any(observer_namespace.get(selected) is not original for selected, original in (\n'
                b"                        ('_owned_phase', owned), ('_remaining', remaining), ('_NativeObservationHold', native_hold),\n"
                b"                        ('READONLY_FAILURE_HINTS', hints[0]), ('UPGRADE_FAILURE_HINTS', hints[1])))\n"
                b"                    or vars(owned).get('__wrapped__') is not owned_inner\n"
                b"                    or vars(native_hold).get('__init__') is not hold_init):\n"
                b'                refuse()\n'
                b'\n'
                b'\n'
                b'        for original in held:\n'
                b'            original.verify()\n'
                b'        directory.verify()\n'
                b'        # Flat strong-reference joint; compare each item with is on reuse.\n'
                b'        # No secret/source instance is returned or persisted by this audit.\n'
                b'        result = (module, factory, source_class, shared_verify, read_trust, error_class,\n'
                b'                  init, source_verify, source_document, errors, endpoint_parser, key_parser,\n'
                b'                  error_init, equality, hashing, frozen[0], frozen[1], representation, raw_repr)\n'
                b'        if probe:\n'
                b'            result = (result, probe_refs)\n'
                b'    except BaseException as error:\n'
                b'        primary = error\n'
                b'    finally:\n'
                b'        for original in tuple(reversed(held)) + ((directory,) if directory is not None else ()):\n'
                b'            try:\n'
                b'                original.close()\n'
                b'            except BaseException as error:\n'
                b'                cleanup.append(error)\n'
                b'                if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):\n'
                b'                    primary = error\n'
                b'        if cleanup:\n'
                b'            scope.cleanup_issues.extend(cleanup)\n'
                b'            if scope._package_source_lifecycle_failure is None:\n'
                b'                scope._package_source_lifecycle_failure = SharedUpgradeHold(\n'
                b"                    'fixed SCP source provider cleanup uncertain; original parent retained')\n"
                b'        if primary is not None and created is not None and sys.modules.get(name) is created:\n'
                b'            del sys.modules[name]\n'
                b'    if primary is not None:\n'
                b'        if not isinstance(primary, Exception):\n'
                b'            raise primary\n'
                b"        raise SharedUpgradeHold('fixed SCP source provider audit failed') from None\n"
                b'    return result\n'
                b'\n'
                b'\n'
                b'def _fixed_native_scp_cpld_api(scope):\n'
                b'    """Finite original producer joint; no command/payload/native permission.\n'
                b'\n'
                b'    Default source19/probe32 are unchanged. Templates are checked against the\n'
                b"    closed trusted-import original image, never this call's new baseline.\n"
                b'    """\n'
                b'    import ast\n'
                b'    import builtins\n'
                b'    import dataclasses\n'
                b'    import importlib.machinery\n'
                b'    from types import CodeType, FunctionType, ModuleType, GetSetDescriptorType\n'
                b'    from ibsw_upgrade_inputs import _HeldDirectory\n'
                b'\n'
                b'    group = scope\n'
                b'    if type(scope) is not _PreparedRunScope:\n'
                b"        raise SharedUpgradeHold('fixed native CPLD source scope required')\n"
                b"    for candidate in (getattr(scope, '_package_source_parent', None),\n"
                b"                      getattr(scope, '_native_parent', None)):\n"
                b'        if (type(candidate) is _PreparedRunScope and candidate is not scope\n'
                b'                and type(candidate._package_source_borrowers) is set\n'
                b'                and scope in candidate._package_source_borrowers):\n'
                b'            group = candidate\n'
                b'            break\n'
                b'    held = []\n'
                b'    directories = []\n'
                b'    audited_functions = []\n'
                b'    primary = result = None\n'
                b'\n'
                b'    def refuse():\n'
                b"        raise SharedUpgradeHold('fixed native CPLD producer joint changed')\n"
                b'\n'
                b'    def text(value, expected):\n'
                b'        return type(value) is str and value == expected\n'
                b'\n'
                b'    def unique_code(parent, name):\n'
                b'        found = [value for value in parent.co_consts if type(value) is CodeType and value.co_name == name]\n'
                b'        if len(found) != 1:\n'
                b'            refuse()\n'
                b'        return found[0]\n'
                b'\n'
                b'    def module(name, path):\n'
                b'        value = sys.modules.get(name)\n'
                b'        if type(value) is not ModuleType:\n'
                b'            refuse()\n'
                b'        namespace = vars(value)\n'
                b"        spec, loader = namespace.get('__spec__'), namespace.get('__loader__')\n"
                b"        if (not text(namespace.get('__name__'), name) or not text(namespace.get('__file__'), str(path))\n"
                b'                or type(spec) is not importlib.machinery.ModuleSpec\n'
                b'                or type(loader) is not importlib.machinery.SourceFileLoader\n'
                b'                or not text(spec.name, name) or not text(spec.origin, str(path)) or spec.loader is not loader\n'
                b'                or not text(loader.name, name) or not text(loader.path, str(path))\n'
                b"                or namespace.get('__builtins__') is not builtins.__dict__):\n"
                b'            refuse()\n'
                b'        return value, namespace\n'
                b'\n'
                b'    def function(value, code, namespace, name, *, qualname=None, defaults=None, keywords=None,\n'
                b'                 annotations=None, cells=()):\n'
                b'        if (type(value) is not FunctionType or value.__code__ != code or value.__globals__ is not namespace\n'
                b'                or not text(value.__module__, name) or not text(value.__name__, code.co_name)\n'
                b'                or not text(value.__qualname__, qualname or code.co_name)\n'
                b'                or type(value.__annotations__) is not dict):\n'
                b'            refuse()\n'
                b'        if defaults is None:\n'
                b'            if value.__defaults__ is not None:\n'
                b'                refuse()\n'
                b'        else:\n'
                b'            if (type(value.__defaults__) is not tuple or len(value.__defaults__) != len(defaults)\n'
                b'                    or any(type(actual) is not type(expected) or actual != expected\n'
                b'                           for actual, expected in zip(value.__defaults__, defaults))):\n'
                b'                refuse()\n'
                b'        actual_keywords = value.__kwdefaults__\n'
                b'        if keywords is None:\n'
                b'            if actual_keywords is not None:\n'
                b'                refuse()\n'
                b'        elif (type(actual_keywords) is not dict or any(type(key) is not str for key in actual_keywords)\n'
                b'                or set(actual_keywords) != set(keywords)\n'
                b'                or any(type(actual_keywords[key]) is not type(expected) or actual_keywords[key] != expected\n'
                b'                       for key, expected in keywords.items())):\n'
                b'            refuse()\n'
                b'        expected_annotations = {} if annotations is None else annotations\n'
                b'        actual_annotations = value.__annotations__\n'
                b'        if (any(type(key) is not str for key in actual_annotations)\n'
                b'                or set(actual_annotations) != set(expected_annotations)\n'
                b'                or any(type(actual_annotations[key]) is not type(expected) or actual_annotations[key] != expected\n'
                b'                       for key, expected in expected_annotations.items())):\n'
                b'            refuse()\n'
                b'        actual_cells = () if value.__closure__ is None else value.__closure__\n'
                b'        if len(actual_cells) != len(cells) or any(cell.cell_contents is not expected\n'
                b'                                                for cell, expected in zip(actual_cells, cells)):\n'
                b'            refuse()\n'
                b'        audited_functions.append((value, code, namespace, name, qualname, defaults, keywords,\n'
                b'                                  annotations, cells))\n'
                b'        return value\n'
                b'\n'
                b'    def original_data(tree, name):\n'
                b'        values = [node.value for node in tree.body if isinstance(node, ast.Assign)\n'
                b'                  and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)\n'
                b'                  and node.targets[0].id == name]\n'
                b'        if len(values) != 1:\n'
                b'            refuse()\n'
                b'        return ast.literal_eval(values[0])\n'
                b'\n'
                b'    def identity(info):\n'
                b'        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,\n'
                b'                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)\n'
                b'\n'
                b'    try:\n'
                b'        scope.verify(); group.verify()\n'
                b"        if (not group.manual_execution or group.parsed.method != 'scp' or group.closed\n"
                b'                or not group._package_source_owns or group._package_source_owner is None\n'
                b"                or 'cpld' not in group.parsed.selected):\n"
                b'            refuse()\n'
                b'        source19, probe32 = _fixed_scp_source_api(group, probe=True)\n'
                b'        original_binding = group._scp_source_binding\n'
                b'        if (type(original_binding) is not tuple or len(original_binding) != 3\n'
                b'                or group._scp_source is not original_binding[0]\n'
                b'                or type(original_binding[1]) is not tuple or len(original_binding[1]) != 19\n'
                b'                or len(source19) != 19 or len(probe32) != 32\n'
                b'                or any(actual is not old for actual, old in zip(source19, original_binding[1]))):\n'
                b'            refuse()\n'
                b'        bootstrap = _SCP_CPLD_BOOTSTRAP\n'
                b'        if (type(bootstrap) is not tuple or len(bootstrap) != 5 or type(bootstrap[2]) is not tuple\n'
                b'                or type(bootstrap[3]) is not tuple or len(bootstrap[3]) != 2\n'
                b'                or type(bootstrap[4]) is not tuple or len(bootstrap[4]) != 2):\n'
                b'            refuse()\n'
                b'        root = Path(__file__).absolute().parent\n'
                b'        tools_directory = _HeldDirectory(root)\n'
                b'        directories.append(tools_directory)\n'
                b'        images = {}\n'
                b"        for filename in ('ibsw_upgrade_scp.py', 'ibsw_upgrade_component.py',\n"
                b"                         'ibsw_upgrade_executor.py', 'ibsw_upgrade_contract.py', Path(__file__).name):\n"
                b'            original = _HeldFile(root / filename, tools_directory)\n'
                b'            held.append(original)\n'
                b'            info = os.fstat(original.fd)\n'
                b'            if info.st_nlink != 1 or info.st_mode & 0o022:\n'
                b'                refuse()\n'
                b'            images[filename] = (original, ast.parse(original.payload),\n'
                b"                compile(original.payload, str(root / filename), 'exec', dont_inherit=True,\n"
                b'                        optimize=sys.flags.optimize))\n'
                b"        provider, p = module('ibsw_upgrade_scp', root / 'ibsw_upgrade_scp.py')\n"
                b"        component, c = module('ibsw_upgrade_component', root / 'ibsw_upgrade_component.py')\n"
                b"        executor, e = module('ibsw_upgrade_executor', root / 'ibsw_upgrade_executor.py')\n"
                b"        contract, k = module('ibsw_upgrade_contract', root / 'ibsw_upgrade_contract.py')\n"
                b'        driver, d = module(__name__, root / Path(__file__).name)\n'
                b'        if (provider is not source19[0] or component is not bootstrap[0] or d is not globals()\n'
                b"                or p.get('_python_command') is not probe32[3] or p.get('remote_helper_bytes') is not probe32[2]\n"
                b"                or p.get('_REMOTE_HELPER') is not probe32[4]):\n"
                b'            refuse()\n'
                b"        provider_code = images['ibsw_upgrade_scp.py'][2]\n"
                b"        command = function(p.get('_stdin_launch_command'), unique_code(provider_code, '_stdin_launch_command'),\n"
                b"                           p, 'ibsw_upgrade_scp')\n"
                b"        launcher = p.get('_STDIN_LAUNCHER')\n"
                b"        expected_launcher = original_data(images['ibsw_upgrade_scp.py'][1], '_STDIN_LAUNCHER')\n"
                b'        if type(launcher) is not str or type(expected_launcher) is not str or launcher != expected_launcher:\n'
                b'            refuse()\n'
                b"        component_code = images['ibsw_upgrade_component.py'][2]\n"
                b"        render = function(c.get('_render'), unique_code(component_code, '_render'), c,\n"
                b"            'ibsw_upgrade_component', keywords={'refresh': None, 'effect': 'REBOOT_EXPECTED'})\n"
                b"        declared = function(c.get('render_declared_step'), unique_code(component_code, 'render_declared_step'),\n"
                b"            c, 'ibsw_upgrade_component', keywords={'package_index': 0, 'switch_dir': '/home/admin'})\n"
                b"        validate = function(c.get('_validate_plan'), unique_code(component_code, '_validate_plan'),\n"
                b"                            c, 'ibsw_upgrade_component')\n"
                b"        url = function(c.get('_package_url'), unique_code(component_code, '_package_url'), c,\n"
                b"                       'ibsw_upgrade_component')\n"
                b"        runner = function(e.get('_owned_runner_bytes'),\n"
                b"            unique_code(images['ibsw_upgrade_executor.py'][2], '_owned_runner_bytes'), e,\n"
                b"            'ibsw_upgrade_executor')\n"
                b"        layout = function(k.get('_fixed_layout'), unique_code(images['ibsw_upgrade_contract.py'][2], '_fixed_layout'),\n"
                b"                          k, 'ibsw_upgrade_contract')\n"
                b"        class_code = unique_code(images[Path(__file__).name][2], '_PreparedRunScope')\n"
                b"        context = function(vars(_PreparedRunScope).get('_native_scp_launch_context'),\n"
                b"            unique_code(class_code, '_native_scp_launch_context'), d, __name__,\n"
                b"            qualname='_PreparedRunScope._native_scp_launch_context')\n"
                b'        # Missing composition is HOLD, never an optional bypass of an existing\n'
                b'        # foreign method. Root must combine the original fixed wrapper first.\n'
                b"        wrapper = function(vars(_PreparedRunScope).get('_launch_native_scp_cpld'),\n"
                b"            unique_code(class_code, '_launch_native_scp_cpld'), d, __name__,\n"
                b"            qualname='_PreparedRunScope._launch_native_scp_cpld')\n"
                b"        capture = function(d.get('_capture_native_scp_cpld_bootstrap'),\n"
                b"            unique_code(images[Path(__file__).name][2], '_capture_native_scp_cpld_bootstrap'), d, __name__)\n"
                b"        if (d.get('render_declared_step') is not declared or c.get('_fixed_layout') is not layout\n"
                b"                or e.get('_fixed_layout') is not layout or c.get('InventoryDevice') is not k.get('InventoryDevice')\n"
                b"                or c.get('UpgradePolicy') is not k.get('UpgradePolicy') or c.get('dataclass') is not dataclasses.dataclass\n"
                b"                or any(c.get(name) is not value for name, value in (('json', json), ('re', re),\n"
                b"                    ('shlex', shlex), ('Path', Path)))\n"
                b"                or any(e.get(name) is not value for name, value in (('hashlib', hashlib), ('re', re),\n"
                b"                    ('posixpath', posixpath), ('shlex', shlex)))\n"
                b"                or c.get('_file') is not k.get('_file') or c.get('_root') is not k.get('_root')):\n"
                b'            refuse()\n'
                b"        project = sys.modules.get('project_contract')\n"
                b'        if type(project) is not ModuleType or any(c.get(name) is not vars(project).get(name)\n'
                b"                for name in ('normalize_redundancy_mac', 'validate_service_endpoint')):\n"
                b'            refuse()\n'
                b'        # Exact import-time class identity plus independent five-field original\n'
                b'        # generator schema. Capturing a late replacement at first audit is forbidden.\n'
                b"        rendered = c.get('RenderedStep')\n"
                b'        if type(rendered) is not type or rendered is not bootstrap[1] or rendered.__bases__ != (object,):\n'
                b'            refuse()\n'
                b'        members = dict(vars(rendered))\n'
                b'        if (len(bootstrap[2]) != len(members) or any(type(row) is not tuple or len(row) != 2\n'
                b'                or type(row[0]) is not str or members.get(row[0]) is not row[1] for row in bootstrap[2])\n'
                b"                or not text(rendered.__module__, 'ibsw_upgrade_component')\n"
                b"                or not text(rendered.__qualname__, 'RenderedStep')):\n"
                b'            refuse()\n'
                b"        names = ('script', 'target_version', 'binding', 'expected_install_effect', 'activation_state')\n"
                b"        types = dict(zip(names, ('str', 'str', 'tuple[str, ...]', 'str', 'str')))\n"
                b"        defaults = ('REBOOT_EXPECTED', 'UNKNOWN')\n"
                b"        allowed = {'__module__', '__annotations__', '__dict__', '__weakref__', '__doc__',\n"
                b"            '__dataclass_params__', '__dataclass_fields__', '__init__', '__repr__', '__eq__',\n"
                b"            '__setattr__', '__delattr__', '__hash__', 'expected_install_effect', 'activation_state'}\n"
                b'        model = sys.version_info[:2]\n'
                b'        if model == (3, 12):\n'
                b"            allowed.add('__match_args__')\n"
                b'        if model not in ((3, 9), (3, 12)) or set(members) != allowed:\n'
                b'            refuse()\n'
                b"        if (type(members['__annotations__']) is not dict\n"
                b'                or any(type(key) is not str or type(value) is not str\n'
                b"                       for key, value in members['__annotations__'].items())\n"
                b"                or members['__annotations__'] != types\n"
                b'                or any(not text(members[name], value) for name, value in zip(names[-2:], defaults))\n'
                b"                or model == (3, 12) and (type(members['__match_args__']) is not tuple\n"
                b"                    or any(type(value) is not str for value in members['__match_args__'])\n"
                b"                    or members['__match_args__'] != names)):\n"
                b'            refuse()\n'
                b"        for selected in ('__dict__', '__weakref__'):\n"
                b'            value = members[selected]\n'
                b'            if type(value) is not GetSetDescriptorType or value.__objclass__ is not rendered or value.__name__ != selected:\n'
                b'                refuse()\n'
                b"        params, fields = members['__dataclass_params__'], members['__dataclass_fields__']\n"
                b'        if (type(params) is not dataclasses._DataclassParams or type(fields) is not dict\n'
                b'                or any(type(name) is not str for name in fields) or tuple(fields) != names):\n'
                b'            refuse()\n'
                b"        for name, value in (('init', True), ('repr', True), ('eq', True), ('order', False),\n"
                b"                            ('unsafe_hash', False), ('frozen', True)):\n"
                b'            if getattr(params, name) is not value:\n'
                b'                refuse()\n'
                b'        if model == (3, 12) and any(getattr(params, name) is not value for name, value in\n'
                b"                (('match_args', True), ('kw_only', False), ('slots', False), ('weakref_slot', False))):\n"
                b'            refuse()\n'
                b'        for index, name in enumerate(names):\n'
                b'            field = fields[name]\n'
                b'            expected = dataclasses.MISSING if index < 3 else defaults[index - 3]\n'
                b'            if (type(field) is not dataclasses.Field or not text(field.name, name) or not text(field.type, types[name])\n'
                b'                    or (field.default is not expected if index < 3 else not text(field.default, expected))\n'
                b'                    or field.default_factory is not dataclasses.MISSING or field.init is not True\n'
                b'                    or field.repr is not True or field.compare is not True or field.hash is not None\n'
                b'                    or field._field_type is not dataclasses._FIELD or field.metadata is not dataclasses._EMPTY_METADATA\n'
                b'                    or model == (3, 12) and field.kw_only is not False):\n'
                b'                refuse()\n'
                b"        type_names = [('_type_' + name if model == (3, 9) else '__dataclass_type_' + name + '__') for name in names]\n"
                b"        default_names = [('_dflt_' + name if model == (3, 9) else '__dataclass_dflt_' + name + '__') for name in names[-2:]]\n"
                b"        local_names = type_names + (['MISSING', '_HAS_DEFAULT_FACTORY'] if model == (3, 9)\n"
                b"                                   else ['__dataclass_HAS_DEFAULT_FACTORY__', '__dataclass_builtins_object__'])\n"
                b'        local_names += default_names\n'
                b'        if model == (3, 9):\n'
                b"            local_names.append('BUILTINS')\n"
                b"        returns = '_return_type' if model == (3, 9) else '__dataclass_return_type__'\n"
                b'        local_names.append(returns)\n'
                b"        arguments = ['self'] + [name + ':' + variable + ('=' + default_names[index - 3] if index >= 3 else '')\n"
                b'                                for index, (name, variable) in enumerate(zip(names, type_names))]\n'
                b"        target = 'BUILTINS.object' if model == (3, 9) else '__dataclass_builtins_object__'\n"
                b"        body = [target + '.__setattr__(self,' + repr(name) + ',' + name + ')' for name in names]\n"
                b"        template = ('def __create_fn__(' + ', '.join(local_names) + '):\\n def __init__(' + ','.join(arguments)\n"
                b"            + ')->' + returns + ':\\n' + '\\n'.join('  ' + line for line in body) + '\\n return __init__')\n"
                b"        generated = unique_code(unique_code(compile(template, '<string>', 'exec', dont_inherit=True,\n"
                b"                                                     optimize=sys.flags.optimize), '__create_fn__'), '__init__')\n"
                b"        init = function(members['__init__'], generated, c, 'ibsw_upgrade_component',\n"
                b"            qualname='__create_fn__.<locals>.__init__' if model == (3, 9) else 'RenderedStep.__init__', defaults=defaults,\n"
                b"            annotations=dict(types, **{'return': None}), cells=(builtins,) if model == (3, 9) else (object,))\n"
                b'        # CP3.12 adjusts the Function qualname; Apple3.9 preserves the factory\n'
                b'        # name. Both code objects retain their modeled source-generator shape.\n'
                b'        fixed_layout = layout(__file__)\n'
                b"        actual_paths = (c.get('_TEMPLATE'), e.get('_RUNNER'))\n"
                b'        template_directory = _HeldDirectory(fixed_layout)\n'
                b'        directories.append(template_directory)\n'
                b'        template_images = []\n'
                b'        for path, saved in zip(actual_paths, bootstrap[3]):\n'
                b'            if (type(path) is not type(Path()) or type(saved) is not tuple or len(saved) != 3\n'
                b'                    or type(saved[0]) is not str or type(saved[1]) is not tuple or len(saved[1]) != 9\n'
                b'                    or any(type(value) is not int for value in saved[1]) or type(saved[2]) is not bytes\n'
                b'                    or str(path) != saved[0] or path.parent != fixed_layout):\n'
                b'                refuse()\n'
                b'            original = _HeldFile(path, template_directory)\n'
                b'            held.append(original)\n'
                b'            if identity(os.fstat(original.fd)) != saved[1] or original.payload != saved[2]:\n'
                b'                refuse()\n'
                b'            template_images.append(original)\n'
                b'        if actual_paths[0] is not bootstrap[4][0]:\n'
                b'            refuse()\n'
                b'        # Stable namespace/class/path objects only. Fresh compile/payload bytes\n'
                b'        # stay in this audit and never enter cross-audit identity comparisons.\n'
                b'        launch_refs = (command, launcher, context, wrapper, probe32[3], provider, component, executor, contract,\n'
                b'            render, declared, validate, url, rendered, init, runner, layout,\n'
                b'            actual_paths[0], actual_paths[1], probe32[2], probe32[4], bootstrap,\n'
                b"            members['__dataclass_params__'], members['__dataclass_fields__'], capture)\n"
                b'        current19, current32 = _fixed_scp_source_api(group, probe=True)\n'
                b'        if (len(current19) != len(source19) or len(current32) != len(probe32)\n'
                b'                or any(a is not b for a, b in zip(source19, current19))\n'
                b'                or any(a is not b for a, b in zip(probe32, current32))\n'
                b'                or group._scp_source_binding is not original_binding or _SCP_CPLD_BOOTSTRAP is not bootstrap\n'
                b'                or any(sys.modules.get(name) is not value for name, value in\n'
                b"                    (('ibsw_upgrade_scp', provider), ('ibsw_upgrade_component', component),\n"
                b"                     ('ibsw_upgrade_executor', executor), ('ibsw_upgrade_contract', contract)))\n"
                b'                or any(p.get(name) is not value for name, value in\n'
                b"                    (('_stdin_launch_command', command), ('_STDIN_LAUNCHER', launcher),\n"
                b"                     ('remote_helper_bytes', probe32[2]), ('_REMOTE_HELPER', probe32[4])))\n"
                b"                or any(c.get(name) is not value for name, value in (('_render', render),\n"
                b"                    ('render_declared_step', declared), ('_validate_plan', validate), ('_package_url', url),\n"
                b"                    ('RenderedStep', rendered), ('_TEMPLATE', actual_paths[0]), ('_fixed_layout', layout)))\n"
                b"                or e.get('_owned_runner_bytes') is not runner or e.get('_RUNNER') is not actual_paths[1]\n"
                b"                or e.get('_fixed_layout') is not layout or k.get('_fixed_layout') is not layout\n"
                b"                or d.get('render_declared_step') is not declared\n"
                b"                or vars(_PreparedRunScope).get('_native_scp_launch_context') is not context\n"
                b"                or vars(_PreparedRunScope).get('_launch_native_scp_cpld') is not wrapper\n"
                b'                or any(vars(rendered).get(name) is not value for name, value in members.items())):\n'
                b'            refuse()\n'
                b'        for original in held:\n'
                b'            original.verify()\n'
                b'        for directory in directories:\n'
                b'            directory.verify()\n'
                b'        scope.verify(); group.verify()\n'
                b'        # Recheck actual function attributes, not only namespace is, after the\n'
                b'        # last original IO. The tuple is finite; do not iterate the growing log.\n'
                b'        for value, code, namespace, name, qualified, default, keyword, annotation, cells in tuple(audited_functions):\n'
                b'            function(value, code, namespace, name, qualname=qualified, defaults=default,\n'
                b'                     keywords=keyword, annotations=annotation, cells=cells)\n'
                b"        for name, value in (('ibsw_upgrade_scp', provider), ('ibsw_upgrade_component', component),\n"
                b"                            ('ibsw_upgrade_executor', executor), ('ibsw_upgrade_contract', contract),\n"
                b'                            (__name__, driver)):\n'
                b"            if module(name, root / (name + '.py' if name != __name__ else Path(__file__).name))[0] is not value:\n"
                b'                refuse()\n'
                b"        if (type(vars(rendered).get('__annotations__')) is not dict\n"
                b'                or any(type(name) is not str or type(value) is not str\n'
                b"                       for name, value in vars(rendered)['__annotations__'].items())\n"
                b"                or vars(rendered)['__annotations__'] != types\n"
                b'                or any(getattr(params, name) is not value for name, value in (\n'
                b"                    ('init', True), ('repr', True), ('eq', True), ('order', False),\n"
                b"                    ('unsafe_hash', False), ('frozen', True)))):\n"
                b'            refuse()\n'
                b'        if model == (3, 12) and any(getattr(params, name) is not value for name, value in\n'
                b"                (('match_args', True), ('kw_only', False), ('slots', False), ('weakref_slot', False))):\n"
                b'            refuse()\n'
                b'        for index, name in enumerate(names):\n'
                b'            field = fields[name]\n'
                b'            expected = dataclasses.MISSING if index < 3 else defaults[index - 3]\n'
                b'            if (type(field) is not dataclasses.Field or not text(field.name, name) or not text(field.type, types[name])\n'
                b'                    or (field.default is not expected if index < 3 else not text(field.default, expected))\n'
                b'                    or field.default_factory is not dataclasses.MISSING or field.init is not True\n'
                b'                    or field.repr is not True or field.compare is not True or field.hash is not None\n'
                b'                    or field._field_type is not dataclasses._FIELD or field.metadata is not dataclasses._EMPTY_METADATA\n'
                b'                    or model == (3, 12) and field.kw_only is not False):\n'
                b'                refuse()\n'
                b'        result = source19, probe32, launch_refs\n'
                b'    except BaseException as error:\n'
                b'        primary = error\n'
                b'    finally:\n'
                b'        failures = []\n'
                b'        for original in tuple(reversed(held)) + tuple(reversed(directories)):\n'
                b'            try:\n'
                b'                original.close()\n'
                b'            except BaseException as error:\n'
                b'                failures.append(error)\n'
                b'                if primary is None or isinstance(primary, Exception) and not isinstance(error, Exception):\n'
                b'                    primary = error\n'
                b'        if failures:\n'
                b'            group.cleanup_issues.extend(failures)\n'
                b'            if group._package_source_lifecycle_failure is None:\n'
                b'                group._package_source_lifecycle_failure = SharedUpgradeHold(\n'
                b"                    'fixed native CPLD producer cleanup uncertain; original group retained')\n"
                b'    if primary is not None:\n'
                b'        if group._package_source_lifecycle_failure is None:\n'
                b'            group._package_source_lifecycle_failure = SharedUpgradeHold(\n'
                b"                'fixed native CPLD producer source uncertain; original group retained')\n"
                b'        if not isinstance(primary, Exception) or isinstance(primary, SharedUpgradeHold):\n'
                b'            raise primary\n'
                b"        raise SharedUpgradeHold('fixed native CPLD producer audit failed') from None\n"
                b'    return result\n'
                b'\n'
                b'class _PreparedRunScope:\n'
                b'    """Live local DATA transaction only. No dispatcher or device-result writer."""\n'
                b'    def __init__(self, entry, cwd, args, run_directory, *, manual_execution=False):\n'
            ),
            0,
        ),
        # Region 6: original, integrated, retained original count.
        (
            (
                b'        self._package_source_owns = False\n'
                b'        self._package_source_borrowers = set()\n'
                b'        self._package_source_lifecycle_failure = None\n'
                b'        self._native_component_canaries = {}\n'
                b'        self.run_directory = Path(run_directory)\n'
                b'        try:\n'
            ),
            (
                b'        self._package_source_owns = False\n'
                b'        self._package_source_borrowers = set()\n'
                b'        self._package_source_lifecycle_failure = None\n'
                b'        self._scp_source = None\n'
                b'        self._scp_source_binding = None\n'
                b'        self._native_component_canaries = {}\n'
                b'        self.run_directory = Path(run_directory)\n'
                b'        try:\n'
            ),
            0,
        ),
        # Region 7: original, integrated, retained original count.
        (
            (
                b'            return (self.policy.cpld_burn, self.policy.cpld_refresh)\n'
                b"        raise SharedUpgradeHold('foreign declared source index')\n"
                b'\n'
                b'    def _verify_package_source_owner(self):\n'
                b'        if self._package_source_lifecycle_failure is not None:\n'
                b'            raise self._package_source_lifecycle_failure\n'
            ),
            (
                b'            return (self.policy.cpld_burn, self.policy.cpld_refresh)\n'
                b"        raise SharedUpgradeHold('foreign declared source index')\n"
                b'\n'
                b'    @staticmethod\n'
                b'    def _scp_source_fields(source, source_class, expected=None):\n'
                b'        """Immutable, in-memory seven-field snapshot; never diagnostic DATA."""\n'
                b'        if type(source) is not source_class:\n'
                b"            raise SharedUpgradeHold('original SCP source instance class required')\n"
                b"        fields = object.__getattribute__(source, '__dict__')\n"
                b"        names = ('host', 'user', 'port', 'known_hosts_path', 'host_keys', 'password', '_identity')\n"
                b'        if (type(fields) is not dict or any(type(name) is not str for name in fields)\n'
                b'                or set(fields) != set(names)):\n'
                b"            raise SharedUpgradeHold('original SCP source instance fields changed')\n"
                b'        def typed(host, user, port, path, keys, password, identity):\n'
                b'            if (type(host) is not str or not host or type(user) is not str or not user\n'
                b'                    or type(port) is not int or not 1 <= port <= 65535\n'
                b'                    or type(path) is not type(Path()) or type(keys) is not bytes or not keys\n'
                b'                    or type(password) is not str or type(identity) is not tuple or len(identity) != 7\n'
                b'                    or any(type(value) is not int or value < 0 for value in identity[:6])\n'
                b"                    or type(identity[6]) is not str or not re.fullmatch(r'[0-9a-f]{64}', identity[6])):\n"
                b"                raise SharedUpgradeHold('typed original SCP source fields required')\n"
                b'        host, user, port, path, keys, password, identity = (fields[name] for name in names)\n'
                b'        typed(host, user, port, path, keys, password, identity)\n'
                b'        # Hold the exact concrete Path as well as an independent string value.\n'
                b'        # Compare that object only with is, never a replaceable Path.__eq__.\n'
                b'        text = str(path)\n'
                b'        snapshot = (host, user, port, (path, text), keys, password, identity)\n'
                b'        if expected is not None:\n'
                b'            if (type(expected) is not tuple or len(expected) != 7\n'
                b'                    or type(expected[3]) is not tuple or len(expected[3]) != 2\n'
                b'                    or type(expected[3][1]) is not str):\n'
                b"                raise SharedUpgradeHold('original SCP source snapshot changed')\n"
                b'            typed(expected[0], expected[1], expected[2], expected[3][0],\n'
                b'                  expected[4], expected[5], expected[6])\n'
                b'            if (path is not expected[3][0] or text != expected[3][1]\n'
                b'                    or snapshot[:3] != expected[:3] or snapshot[4:] != expected[4:]):\n'
                b"                raise SharedUpgradeHold('original SCP source field values changed')\n"
                b'        return snapshot\n'
                b'\n'
                b'    def _bind_scp_source(self, source, api):\n'
                b'        """Bind one actual pre-schedule parent configuration, not permission."""\n'
                b'        try:\n'
                b'            if (type(self) is not _PreparedRunScope or not self.manual_execution\n'
                b"                    or self.parsed.method != 'scp' or self.closed or self.cleanup_issues\n"
                b'                    or self._native_schedule_started or self._has_native_package_source_provenance()\n'
                b'                    or self._package_source_parent is not None or self._package_source_owner is not None\n'
                b'                    or self._package_source_owner_class is not None or self._package_source_owns\n'
                b'                    or self._package_source_selection is not None or self._package_source_borrowers\n'
                b'                    or self._scp_source is not None or self._scp_source_binding is not None\n'
                b'                    or type(api) is not tuple or len(api) != 19):\n'
                b"                raise SharedUpgradeHold('single original pre-schedule SCP parent binding required')\n"
                b'            self.verify()\n'
                b'            current = _fixed_scp_source_api(self)\n'
                b'            if len(current) != 19 or any(left is not right for left, right in zip(api, current)):\n'
                b"                raise SharedUpgradeHold('original SCP source API objects changed before binding')\n"
                b'            snapshot = _PreparedRunScope._scp_source_fields(source, api[2])\n'
                b'            api[3](source)  # The audited original trust verifier, not its return value.\n'
                b'            current = _fixed_scp_source_api(self)\n'
                b'            _PreparedRunScope._scp_source_fields(source, api[2], snapshot)\n'
                b'            if (len(current) != 19 or any(left is not right for left, right in zip(api, current))\n'
                b'                    or self._scp_source is not None or self._scp_source_binding is not None):\n'
                b"                raise SharedUpgradeHold('original SCP source changed during binding')\n"
                b'            self._scp_source_binding = (source, api, snapshot)\n'
                b'            self._scp_source = source\n'
                b'        except BaseException as error:\n'
                b'            if self._package_source_lifecycle_failure is None:\n'
                b'                self._package_source_lifecycle_failure = SharedUpgradeHold(\n'
                b"                    'original SCP source binding failed; parent group retained')\n"
                b'            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):\n'
                b'                raise  # Preserve the first interruption/Shared object and preset cause.\n'
                b"            raise SharedUpgradeHold('original SCP source binding failed') from None\n"
                b'\n'
                b'    def _native_scp_source(self, leaf, component, package_index):\n'
                b'        """Revalidate the same parent source for one original native borrower.\n'
                b'\n'
                b'        No probe, secret wire, request, dispatch, ACK or positive permission.\n'
                b'        Generic scope.verify never calls this method or the source API auditor.\n'
                b'        """\n'
                b'        group = self\n'
                b'        try:\n'
                b"            parent = getattr(self, '_native_parent', None)\n"
                b'            # Either still-original edge can identify the registered group if\n'
                b'            # the other edge has drifted. Never adopt an unregistered parent.\n'
                b"            for original in (getattr(self, '_package_source_parent', None), parent):\n"
                b'                if (type(original) is _PreparedRunScope and original is not self\n'
                b'                        and type(original._package_source_borrowers) is set\n'
                b'                        and self in original._package_source_borrowers):\n'
                b'                    group = original\n'
                b'                    break\n'
                b'            if (type(self) is not _PreparedRunScope or group is self or parent is not group\n'
                b'                    or self.closed or parent.closed or self.cleanup_issues or parent.cleanup_issues\n'
                b'                    or type(leaf) is not _ReadonlyQueryInputs or leaf.closed\n'
                b'                    or leaf.scope is not self or type(leaf._original_selection) is not tuple\n'
                b'                    or len(leaf._original_selection) != 6 or leaf._original_selection[0] is not self\n'
                b'                    or leaf._original_selection[1] != leaf.node.hostname\n'
                b'                    or leaf._native_observation_consumed is not True\n'
                b'                    or type(component) is not str or type(package_index) is not int\n'
                b'                    or not self._is_native_package_source_child(parent, leaf.node.hostname, component)\n'
                b'                    or package_index not in self._native_package_indices\n'
                b'                    or (component, package_index) not in parent._package_source_selection[0]\n'
                b'                    or self._scp_source is not None or self._scp_source_binding is not None):\n'
                b"                raise SharedUpgradeHold('original native SCP leaf/parent/borrow/source selection required')\n"
                b'            self.verify()\n'
                b'            parent.verify()\n'
                b'            leaf.verify()\n'
                b'            binding = parent._scp_source_binding\n'
                b'            if type(binding) is not tuple or len(binding) != 3:\n'
                b"                raise SharedUpgradeHold('original parent SCP source binding missing')\n"
                b'            source, api, snapshot = binding\n'
                b'            if (type(api) is not tuple or len(api) != 19 or parent._scp_source is not source\n'
                b'                    or type(snapshot) is not tuple or len(snapshot) != 7):\n'
                b"                raise SharedUpgradeHold('original parent SCP source slot changed')\n"
                b'            current = _fixed_scp_source_api(parent)\n'
                b'            if len(current) != 19 or any(left is not right for left, right in zip(api, current)):\n'
                b"                raise SharedUpgradeHold('original parent SCP source API or fields changed')\n"
                b'            _PreparedRunScope._scp_source_fields(source, api[2], snapshot)\n'
                b'            api[3](source)\n'
                b'            leaf.verify()\n'
                b'            parent.verify()\n'
                b'            current = _fixed_scp_source_api(parent)\n'
                b'            if (len(current) != 19 or any(left is not right for left, right in zip(api, current))\n'
                b'                    or parent._scp_source_binding is not binding or parent._scp_source is not source\n'
                b'                    or not self._is_native_package_source_child(parent, leaf.node.hostname, component)\n'
                b'                    or package_index not in self._native_package_indices):\n'
                b"                raise SharedUpgradeHold('original parent SCP source changed while being checked')\n"
                b'            _PreparedRunScope._scp_source_fields(source, api[2], snapshot)\n'
                b'            return source\n'
                b'        except BaseException as error:\n'
                b'            if group._package_source_lifecycle_failure is None:\n'
                b'                group._package_source_lifecycle_failure = SharedUpgradeHold(\n'
                b"                    'original native SCP source changed; parent group retained')\n"
                b'            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):\n'
                b'                raise\n'
                b"            raise SharedUpgradeHold('original native SCP source cannot be verified') from None\n"
                b'\n'
                b'\n'
                b'    def _native_scp_launch_context(self, leaf, component, package_index):\n'
                b'        """Derive bounded private envelope DATA from live original native inputs.\n'
                b'\n'
                b'        No capture/write, package reread, wire, launch, dispatch or ACK. The\n'
                b'        returned bytes are not a permit and must never be logged or persisted.\n'
                b'        """\n'
                b'        group = self\n'
                b'        try:\n'
                b'            if type(self) is not _PreparedRunScope:\n'
                b"                raise SharedUpgradeHold('original native SCP DATA scope required')\n"
                b'            # Either still-original edge can identify the registered group even\n'
                b"            # when the child's owner slot or its other parent edge has drifted.\n"
                b"            for original in (getattr(self, '_package_source_parent', None),\n"
                b"                             getattr(self, '_native_parent', None)):\n"
                b'                if (type(original) is _PreparedRunScope and original is not self\n'
                b'                        and type(original._package_source_borrowers) is set\n'
                b'                        and self in original._package_source_borrowers):\n'
                b'                    group = original\n'
                b'                    break\n'
                b'            lease = self._active_request_lease\n'
                b'            if group is self or type(lease) is not _ManualJournalTransaction:\n'
                b"                raise SharedUpgradeHold('active original native SCP DATA lease required')\n"
                b'            lease.verify()\n'
                b'            source = self._native_scp_source(leaf, component, package_index)\n'
                b'            owner = group._package_source_owner\n'
                b'            binding_joint = group._scp_source_binding\n'
                b'            fields = _PreparedRunScope._scp_source_fields(\n'
                b'                source, binding_joint[1][2], binding_joint[2])\n'
                b'            # No path discovery/adoption: all six artifact originals must\n'
                b'            # already be held by this same native child before this call.\n'
                b'            stage_name = declared_step_key(self.policy, component, package_index)\n'
                b'            stage_path = self.run_directory / leaf.node.hostname / stage_name\n'
                b'            directory = self.session._directories.get(str(stage_path))\n'
                b'            if directory is None:\n'
                b"                raise SharedUpgradeHold('original SCP request stage is not held')\n"
                b'            self._private_directory(directory)\n'
                b"            names = ('request.json', 'step.sh', 'step-binding.json',\n"
                b"                     'runner.sh', 'runner-binding.json', 'scp-source-request.json')\n"
                b'            held, payloads = {}, {}\n'
                b'            for name in names:\n'
                b'                original = self.files.get((str(stage_path), name))\n'
                b'                if (type(original) is not _HeldFile or original.directory is not directory\n'
                b'                        or original.name != name or original.cleanup_issues):\n'
                b"                    raise SharedUpgradeHold('complete held SCP request originals required')\n"
                b'                original.verify()\n'
                b'                metadata = os.fstat(original.fd)\n'
                b'                if (metadata.st_uid != os.geteuid() or metadata.st_nlink != 1\n'
                b'                        or stat.S_IMODE(metadata.st_mode) != 0o600):\n'
                b"                    raise SharedUpgradeHold('private original SCP request artifact required')\n"
                b'                held[name], payloads[name] = original, original.payload\n'
                b'            script, binding = self._candidate(leaf.node.hostname, component, package_index, stage_name)\n'
                b"            if payloads['step.sh'] != script or payloads['step-binding.json'] != _json_bytes(binding):\n"
                b"                raise SharedUpgradeHold('original SCP stage declaration changed')\n"
                b'            _validate_scp_request_content_graph(set(payloads), binding, payloads.__getitem__)\n'
                b"            companion = json.loads(payloads['scp-source-request.json'])\n"
                b"            request = json.loads(payloads['request.json'])\n"
                b"            runner_binding = json.loads(payloads['runner-binding.json'])\n"
                b"            remote = runner_binding.get('remote_script') if type(runner_binding) is dict else None\n"
                b"            prefix = '.ibsw-' + self.run_id + '-' + leaf.node.hostname + '-' + stage_name + '-'\n"
                b'            from ibsw_upgrade_executor import _owned_runner_bytes\n'
                b'            if (type(remote) is not str or posixpath.normpath(remote) != remote\n'
                b"                    or posixpath.basename(remote) != 'step.sh'\n"
                b'                    or posixpath.dirname(posixpath.dirname(remote)) != self.parsed.switch_dir\n'
                b"                    or not re.fullmatch(re.escape(prefix) + '[0-9a-f]{32}',\n"
                b'                                        posixpath.basename(posixpath.dirname(remote)))\n'
                b"                    or payloads['runner.sh'] != _owned_runner_bytes(binding, remote)\n"
                b"                    or payloads['runner-binding.json'] != _json_bytes(\n"
                b"                        _owned_runner_binding(binding, remote, payloads['runner.sh']))):\n"
                b"                raise SharedUpgradeHold('original SCP runner binding changed')\n"
                b'            self._verify_package_source_owner()\n'
                b'            packages, original_rows = {}, []\n'
                b'            for package in self._package_source_packages(component, package_index):\n'
                b'                path = Path(package.path)\n'
                b'                row = owner._files.get(path)\n'
                b'                if (type(row) is not tuple or len(row) != 5\n'
                b'                        or type(row[3]) is not tuple or len(row[3]) != 9\n'
                b'                        or type(row[3][6]) is not int or row[3][6] <= 0\n'
                b"                        or type(row[4]) is not str or not re.fullmatch('[0-9a-f]{64}', row[4])):\n"
                b"                    raise SharedUpgradeHold('original SCP package digest rows required')\n"
                b'                packages[package.path] = dict(size=row[3][6], sha256=row[4])\n'
                b'                original_rows.append((path, row))\n'
                b"            if companion['packages'] != packages:\n"
                b"                raise SharedUpgradeHold('SCP companion differs from live original packages')\n"
                b'            content = dict(version=1,\n'
                b"                binding_sha256=hashlib.sha256(payloads['step-binding.json']).hexdigest(),\n"
                b"                request_id=request['request_id'],\n"
                b"                request_sha256=hashlib.sha256(payloads['request.json']).hexdigest(),\n"
                b"                companion_sha256=hashlib.sha256(payloads['scp-source-request.json']).hexdigest(),\n"
                b'                packages=packages)\n'
                b'            document = dict(host=fields[0], user=fields[1], port=fields[2],\n'
                b"                host_keys=fields[4].decode('ascii'), password=fields[5],\n"
                b"                paths={path: row['size'] for path, row in packages.items()},\n"
                b"                timeout_seconds=600 if component == 'os' else 300, content_binding=content)\n"
                b'            payload = (json.dumps(document, ensure_ascii=True, sort_keys=True,\n'
                b"                                  separators=(',', ':')) + '\\n').encode('utf-8')\n"
                b"            if not 1 <= len(payload) <= 65536 or payload.count(b'\\n') != 1:\n"
                b"                raise SharedUpgradeHold('bounded single-frame SCP context DATA required')\n"
                b'            # Recheck the SAME source/group/lease/artifact owners after all\n'
                b'            # derivation. No fresh baseline or package digest is acquired.\n'
                b'            if self._native_scp_source(leaf, component, package_index) is not source:\n'
                b"                raise SharedUpgradeHold('original SCP source changed at DATA tail')\n"
                b'            if (self._active_request_lease is not lease\n'
                b'                    or group._scp_source_binding is not binding_joint\n'
                b'                    or group._scp_source is not source\n'
                b'                    or self._package_source_owner is not owner\n'
                b'                    or group._package_source_owner is not owner\n'
                b'                    or self.session._directories.get(str(stage_path)) is not directory):\n'
                b"                raise SharedUpgradeHold('original SCP context owners changed at DATA tail')\n"
                b'            lease.verify()\n'
                b'            _PreparedRunScope._scp_source_fields(source, binding_joint[1][2], binding_joint[2])\n'
                b'            self._verify_package_source_owner()\n'
                b'            for path, row in original_rows:\n'
                b'                if owner._files.get(path) is not row:\n'
                b"                    raise SharedUpgradeHold('original SCP package digest row changed at DATA tail')\n"
                b'            for name, original in held.items():\n'
                b'                if (self.files.get((str(stage_path), name)) is not original\n'
                b'                        or original.payload != payloads[name]):\n'
                b"                    raise SharedUpgradeHold('original SCP request artifact changed at DATA tail')\n"
                b'                original.verify()\n'
                b'            self.verify(); leaf.verify(); group.verify()\n'
                b'            _validate_scp_request_content_graph(set(payloads), binding, payloads.__getitem__)\n'
                b'            return payload\n'
                b'        except BaseException as error:\n'
                b'            if (type(group) is _PreparedRunScope\n'
                b'                    and group._package_source_lifecycle_failure is None):\n'
                b'                group._package_source_lifecycle_failure = SharedUpgradeHold(\n'
                b"                    'original native SCP context DATA uncertain; shared group retained')\n"
                b'            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):\n'
                b'                raise  # Keep the original NI/Shared object and preset cause.\n'
                b"            raise SharedUpgradeHold('original native SCP context DATA could not be verified') from None\n"
                b'\n'
                b'    def _launch_native_scp_cpld(self, leaf, component, package_index, transport, deadline):\n'
                b'        """One fixed native CPLD stdin launch; never accepts caller wire DATA."""\n'
                b'        primary = None\n'
                b'        channel = None\n'
                b'        source = joint = payload = command = None\n'
                b'        lease = source_binding = package_owner = None\n'
                b'        fields_check = None\n'
                b'        originals = ()\n'
                b'        function_states = ()\n'
                b"        parent = getattr(self, '_native_parent', None)\n"
                b'        group = parent if type(parent) is _PreparedRunScope else self\n'
                b'        output, errors = bytearray(), bytearray()\n'
                b'        complete, status = False, None\n'
                b'        closed = False\n'
                b'        close_error = None\n'
                b'        lock = threading.Lock()\n'
                b'\n'
                b'        def remember(error):\n'
                b'            nonlocal primary\n'
                b'            if (primary is None or isinstance(primary, Exception) and not isinstance(error, Exception)\n'
                b'                    or isinstance(primary, Exception) and not isinstance(primary, SharedUpgradeHold)\n'
                b'                    and isinstance(error, SharedUpgradeHold)):\n'
                b'                primary = error\n'
                b'\n'
                b'        class OwnedChannel:\n'
                b'            def close(owner):\n'
                b'                nonlocal closed, close_error\n'
                b'                with lock:\n'
                b'                    if closed:\n'
                b'                        if close_error is not None:\n'
                b'                            raise close_error\n'
                b'                        return\n'
                b'                    closed = True\n'
                b'                try:\n'
                b'                    channel.close()\n'
                b'                except BaseException as error:\n'
                b'                    close_error = error\n'
                b'                    raise\n'
                b'\n'
                b'        owner = OwnedChannel()\n'
                b'\n'
                b'        def require_new_send():\n'
                b"            stop = getattr(self, '_pipeline_stop_event', None)\n"
                b'            if stop is not None and stop.is_set():\n'
                b"                raise SharedUpgradeHold('shared stop forbids another native CPLD stdin fragment')\n"
                b'\n'
                b'        def verify_current(*, full=True):\n'
                b'            # Same live child/parent/source, original six held files and fixed\n'
                b'            # producers. A new source/companion or caller envelope is not adopted.\n'
                b'            current = _fixed_native_scp_cpld_api(parent) if full else joint\n'
                b'            if (type(current) is not tuple or len(current) != 3\n'
                b'                    or any(type(old) is not tuple or type(new) is not tuple\n'
                b'                        or len(old) != len(new)\n'
                b'                        or any(left is not right for left, right in zip(old, new))\n'
                b'                        for old, new in zip(joint, current))):\n'
                b"                raise SharedUpgradeHold('fixed native CPLD launch producers changed')\n"
                b'            if (self._native_parent is not parent or self._active_request_lease is not lease\n'
                b'                    or parent._scp_source is not source or parent._scp_source_binding is not source_binding\n'
                b'                    or self._package_source_owner is not package_owner\n'
                b'                    or parent._package_source_owner is not package_owner):\n'
                b"                raise SharedUpgradeHold('original native CPLD request/source changed before wire')\n"
                b'            lease.verify()\n'
                b'            for name, original, image in originals:\n'
                b'                if self.files.get((str(directory), name)) is not original or original.payload is not image:\n'
                b"                    raise SharedUpgradeHold('original native CPLD held request changed')\n"
                b'                original.verify()\n'
                b'            for function, code, namespace, defaults, keywords, keyword_items in function_states:\n'
                b'                actual = function.__kwdefaults__\n'
                b'                if (function.__code__ is not code or function.__globals__ is not namespace\n'
                b'                        or function.__defaults__ is not defaults or actual is not keywords\n'
                b'                        or keywords is not None and (set(actual) != set(keyword_items)\n'
                b'                            or any(actual[name] is not value for name, value in keyword_items.items()))):\n'
                b"                    raise SharedUpgradeHold('native CPLD producer code/default joint changed')\n"
                b'            source_namespace = vars(current[0][0])\n'
                b"            if (source_namespace.get('ScpSource') is not current[0][2]\n"
                b"                    or source_namespace.get('verify_source_shared') is not current[0][3]\n"
                b"                    or source_namespace.get('_read_trust') is not current[0][4]\n"
                b"                    or source_namespace.get('ScpHold') is not current[0][5]\n"
                b"                    or source_namespace.get('ERRORS') is not current[0][9]\n"
                b"                    or vars(current[0][2]).get('verify') is not current[0][7]\n"
                b"                    or vars(current[0][5]).get('__init__') is not current[0][12]\n"
                b'                    or _PreparedRunScope._scp_source_fields is not fields_check):\n'
                b"                raise SharedUpgradeHold('native CPLD source verifier slots changed before send')\n"
                b'            fields_check(source, current[0][2], source_binding[2])\n'
                b'            current[0][3](source)\n'
                b'            self._verify_package_source_owner()\n'
                b'            leaf.verify_io_identity()\n'
                b'            if full and (self._native_scp_source(leaf, component, package_index) is not source\n'
                b'                    or current[2][2](self, leaf, component, package_index) != payload):\n'
                b"                raise SharedUpgradeHold('original native CPLD context changed at full wire gate')\n"
                b'            current[1][8](deadline)\n'
                b'\n'
                b'        try:\n'
                b'            if (type(self) is not _PreparedRunScope or type(parent) is not _PreparedRunScope\n'
                b'                    or type(leaf) is not _ReadonlyQueryInputs\n'
                b"                    or type(component) is not str or component != 'cpld'\n"
                b'                    or type(package_index) is not int or package_index != 0\n'
                b"                    or self.parsed.method != 'scp' or self._active_request_lease is None\n"
                b'                    or type(deadline) not in (int, float) or not math.isfinite(deadline)):\n'
                b"                raise SharedUpgradeHold('original native CPLD launch scope/lease required')\n"
                b"            # One bounded launch-response budget, independent of the receiver's\n"
                b'            # per-package firmware budget. Never extend the caller deadline.\n'
                b'            deadline = min(deadline, time.monotonic() + 25.0)\n'
                b'            source = self._native_scp_source(leaf, component, package_index)\n'
                b'            joint = _fixed_native_scp_cpld_api(parent)\n'
                b'            if type(joint) is not tuple or len(joint) != 3 or len(joint[2]) < 3:\n'
                b"                raise SharedUpgradeHold('fixed native CPLD producer joint required')\n"
                b'            remaining, owned_phase = joint[1][8], joint[1][6]\n'
                b'            remaining(deadline)\n'
                b'            payload = joint[2][2](self, leaf, component, package_index)\n'
                b'            stage = declared_step_key(self.policy, component, package_index)\n'
                b'            directory = self.run_directory / leaf.node.hostname / stage\n'
                b'            lease = self._active_request_lease\n'
                b'            source_binding = parent._scp_source_binding\n'
                b'            package_owner = self._package_source_owner\n'
                b'            fields_check = _PreparedRunScope._scp_source_fields\n'
                b"            names = ('request.json', 'step.sh', 'step-binding.json',\n"
                b"                     'runner.sh', 'runner-binding.json', 'scp-source-request.json')\n"
                b'            originals = tuple((name, self.files[(str(directory), name)],\n'
                b'                               self.files[(str(directory), name)].payload) for name in names)\n'
                b'            from types import FunctionType\n'
                b'            function_states = tuple((function, function.__code__, function.__globals__,\n'
                b'                    function.__defaults__, function.__kwdefaults__,\n'
                b'                    {} if function.__kwdefaults__ is None else dict(function.__kwdefaults__))\n'
                b'                for group_refs in joint + ((fields_check,),)\n'
                b'                for function in group_refs if type(function) is FunctionType)\n'
                b"            step = self.files[(str(directory), 'step.sh')]\n"
                b"            runner = self.files[(str(directory), 'runner.sh')]\n"
                b"            binding = self.files[(str(directory), 'runner-binding.json')]\n"
                b'            binding.verify(); step.verify(); runner.verify()\n'
                b"            remote = json.loads(binding.payload)['remote_script']\n"
                b'            command = joint[2][0](remote, hashlib.sha256(runner.payload).hexdigest(),\n'
                b'                                     hashlib.sha256(step.payload).hexdigest())\n'
                b'            verify_current()\n'
                b'            require_new_send()\n'
                b'            channel = transport.open_session(timeout=remaining(deadline))\n'
                b'            channel.settimeout(remaining(deadline))\n'
                b'            with owned_phase((owner,), deadline):\n'
                b'                try:\n'
                b'                    verify_current()\n'
                b'                    require_new_send()\n'
                b'                    channel.exec_command(command)\n'
                b'                    position = 0\n'
                b'                    while position < len(payload):\n'
                b'                        # No recompiling/refreezing per tiny partial send. Full\n'
                b'                        # source/context gates bracket the wire; each fragment\n'
                b'                        # still checks the same six held files/source/lease/\n'
                b'                        # package owner plus code/default object anchors.\n'
                b'                        verify_current(full=False)\n'
                b'                        require_new_send()\n'
                b'                        channel.settimeout(remaining(deadline))\n'
                b'                        count = channel.send(payload[position:])\n'
                b'                        if type(count) is not int or not 0 < count <= len(payload) - position:\n'
                b"                            raise SharedUpgradeHold('native CPLD stdin delivery uncertain')\n"
                b'                        position += count\n'
                b'                    verify_current(full=False)\n'
                b'                    channel.settimeout(remaining(deadline))\n'
                b'                    channel.shutdown_write()\n'
                b'                    while True:\n'
                b'                        leaf.verify_io_identity()\n'
                b'                        remaining(deadline)\n'
                b'                        for ready, receive, target in (\n'
                b'                                (channel.recv_ready, channel.recv, output),\n'
                b'                                (channel.recv_stderr_ready, channel.recv_stderr, errors)):\n'
                b'                            if ready():\n'
                b'                                channel.settimeout(remaining(deadline))\n'
                b'                                part = receive(65536)\n'
                b'                                if type(part) is not bytes:\n'
                b"                                    raise SharedUpgradeHold('native CPLD launch response uncertain')\n"
                b'                                target.extend(part)\n'
                b'                                if len(output) + len(errors) > 65536:\n'
                b"                                    raise SharedUpgradeHold('bounded native CPLD launch response required')\n"
                b'                        if channel.closed and not channel.recv_ready() and not channel.recv_stderr_ready():\n'
                b'                            if channel.exit_status_ready():\n'
                b'                                status = channel.recv_exit_status()\n'
                b'                            complete = channel.eof_received is True and type(status) is int and status == 0\n'
                b'                            break\n'
                b'                        if not transport.is_active():\n'
                b'                            break\n'
                b'                        time.sleep(min(.005, remaining(deadline)))\n'
                b'                except BaseException as error:\n'
                b'                    remember(error)\n'
                b'                finally:\n'
                b'                    try:\n'
                b'                        owner.close()\n'
                b'                    except BaseException as error:\n'
                b'                        remember(error)\n'
                b'                    try:\n'
                b'                        verify_current()\n'
                b'                    except BaseException as error:\n'
                b'                        remember(error)\n'
                b'        except BaseException as error:\n'
                b'            remember(error)\n'
                b'        finally:\n'
                b'            if channel is not None and not closed:\n'
                b'                try:\n'
                b'                    owner.close()\n'
                b'                except BaseException as error:\n'
                b'                    remember(error)\n'
                b'            if joint is not None and payload is not None:\n'
                b'                try:\n'
                b'                    verify_current()\n'
                b'                except BaseException as error:\n'
                b'                    remember(error)\n'
                b'            for verify in ((leaf.verify,) if type(leaf) is _ReadonlyQueryInputs else ()):\n'
                b'                try:\n'
                b'                    verify()\n'
                b'                except BaseException as error:\n'
                b'                    remember(error)\n'
                b"        if (primary is not None or not complete or bytes(output) != b'IBSW_LAUNCH_REQUESTED\\n'\n"
                b'                or errors or time.monotonic() >= deadline):\n'
                b'            if type(group) is _PreparedRunScope and group._package_source_lifecycle_failure is None:\n'
                b'                group._package_source_lifecycle_failure = SharedUpgradeHold(\n'
                b"                    'native CPLD launch uncertain; retain original request and shared parent')\n"
                b'            if primary is not None and (not isinstance(primary, Exception)\n'
                b'                                        or isinstance(primary, SharedUpgradeHold)):\n'
                b'                raise primary\n'
                b"            raise SharedUpgradeHold('native CPLD launch uncertain; no automatic retry') from None\n"
                b'        # Public asynchronous raw launch fact only. Never return payload/secret,\n'
                b'        # installer success, an ACK or a caller-created dispatch grant.\n'
                b"        return command, (b'IBSW_LAUNCH_REQUESTED\\n', b'', 0, True)\n"
                b'\n'
                b'    def _preflight_native_scp_source(self, leaf, component, package_index, transport, deadline):\n'
                b'        """Fixed signed-session probe fact only; backend remains unsupported."""\n'
                b'        parent, group = None, self\n'
                b'        source = audited = refs = primary = binding = None\n'
                b'\n'
                b'        def remember(error):\n'
                b'            nonlocal primary\n'
                b'            if (primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception))\n'
                b'                    or (isinstance(primary, Exception) and not isinstance(primary, SharedUpgradeHold)\n'
                b'                        and isinstance(error, SharedUpgradeHold))):\n'
                b'                primary = error\n'
                b'\n'
                b'        try:\n'
                b"            parent = getattr(self, '_native_parent', None)\n"
                b"            for original in (getattr(self, '_package_source_parent', None), parent):\n"
                b'                if (type(original) is _PreparedRunScope and original is not self\n'
                b'                        and type(original._package_source_borrowers) is set\n'
                b'                        and self in original._package_source_borrowers):\n'
                b'                    group = original\n'
                b'                    break\n'
                b'            source = self._native_scp_source(leaf, component, package_index)\n'
                b'            if (type(parent) is not _PreparedRunScope or parent is not self._native_parent\n'
                b'                    or type(deadline) not in (int, float) or not _SCP_PROBE_LEAVES[4](deadline)):\n'
                b"                raise SharedUpgradeHold('fixed native source probe original parent/deadline required')\n"
                b'            binding = parent._scp_source_binding\n'
                b'            audited, refs = _fixed_scp_source_api(parent, probe=True)\n'
                b'            if (len(audited) != 19 or any(actual is not original for actual, original\n'
                b'                    in zip(audited, parent._scp_source_binding[1]))):\n'
                b"                raise SharedUpgradeHold('fixed native source probe binding/API differs')\n"
                b'            refs[8](deadline)  # Audited original _remaining; no deadline extension.\n'
                b'            result = refs[0](leaf, transport, deadline, source)\n'
                b'            if result is not None:\n'
                b"                raise SharedUpgradeHold('fixed native source probe returned unknown DATA')\n"
                b'        except BaseException as error:\n'
                b'            remember(error)\n'
                b'        finally:\n'
                b'            # These are fresh read-only tail checks, not a producer/factory\n'
                b'            # retry. An ordinary wire error must not hide shared-source drift;\n'
                b'            # a pending body NI must remain the same object/cause over any tail.\n'
                b'            if source is not None:\n'
                b'                try:\n'
                b'                    if self._native_scp_source(leaf, component, package_index) is not source:\n'
                b"                        raise SharedUpgradeHold('fixed native source original instance changed at tail')\n"
                b'                except BaseException as error:\n'
                b'                    remember(error)\n'
                b'            try:\n'
                b'                leaf.verify()\n'
                b'            except BaseException as error:\n'
                b'                remember(error)\n'
                b'            if audited is not None and refs is not None:\n'
                b'                try:\n'
                b'                    current, current_refs = _fixed_scp_source_api(parent, probe=True)\n'
                b'                    if (len(current) != len(audited) or len(current_refs) != len(refs)\n'
                b'                            or any(actual is not original for actual, original in zip(current, audited))\n'
                b'                            or any(actual is not original for actual, original in zip(current_refs, refs))):\n'
                b"                        raise SharedUpgradeHold('fixed native source producer objects changed at tail')\n"
                b'                    if parent._scp_source_binding is not binding or parent._scp_source is not source:\n'
                b"                        raise SharedUpgradeHold('fixed native source binding changed at producer tail')\n"
                b'                    _PreparedRunScope._scp_source_fields(source, audited[2], binding[2])\n'
                b'                    current_refs[8](deadline)\n'
                b'                except BaseException as error:\n'
                b'                    remember(error)\n'
                b'        if primary is not None:\n'
                b'            if group._package_source_lifecycle_failure is None:\n'
                b'                group._package_source_lifecycle_failure = SharedUpgradeHold(\n'
                b"                    'fixed native source probe failed; original parent group retained')\n"
                b'            # Same original body/first-tail NI/cause and batch Shared object.\n'
                b'            # A genuine audited ordinary wire failure remains only a failure.\n'
                b'            if (not isinstance(primary, Exception) or isinstance(primary, SharedUpgradeHold)\n'
                b'                    or audited is not None and type(primary) is audited[5]\n'
                b'                    or refs is not None and type(primary) is refs[9]):\n'
                b'                raise primary\n'
                b"            raise SharedUpgradeHold('fixed native source probe could not be verified') from None\n"
                b'        return None\n'
                b'\n'
                b'    def _native_scp_needed_indices(self, node, component):\n'
                b'        """Select from this parent\'s real startup rows, not dispatch permission."""\n'
                b'        from ibsw_upgrade_contract import select_os_path\n'
                b"        if (not self.manual_execution or self.parsed.method != 'scp'\n"
                b'                or node not in self.devices or component not in self.parsed.selected):\n'
                b"            raise SharedUpgradeHold('original native SCP node/component required')\n"
                b"        rows = [row for row in getattr(self, '_version_plan', ())\n"
                b"                if row.get('hostname') == node and row.get('component') == component]\n"
                b'        if len(rows) != 1:\n'
                b"            raise SharedUpgradeHold('unique original startup component row required')\n"
                b'        row = rows[0]\n'
                b"        if any(issue.get('hostname') == node and issue.get('component') == component\n"
                b"               for issue in getattr(self, '_component_readiness_issues', ())):\n"
                b'            return ()  # No source acquisition for a startup-blocked component.\n'
                b"        if component == 'os':\n"
                b"            path = row.get('path')\n"
                b'            if (type(path) not in (list, tuple) or not path\n'
                b"                    or path[0] != row.get('current') or path[-1] != self.policy.final_os\n"
                b"                    or row.get('target') != self.policy.final_os):\n"
                b"                raise SharedUpgradeHold('original native OS route is incomplete')\n"
                b'            available = frozenset(package.path for package in self.policy.os\n'
                b'                                  if package.version in path[1:])\n'
                b"            selected = select_os_path(self.policy, row['current'], available=available)\n"
                b'            if (tuple(path[1:]) != tuple(package.version for package in selected)\n'
                b"                    or row.get('action') != ('UPGRADE_REQUIRED' if selected else 'AT_TARGET_NO_FLASH')):\n"
                b"                raise SharedUpgradeHold('native OS route differs from original approved path')\n"
                b'            return tuple(next(index for index, original in enumerate(self.policy.os)\n'
                b'                              if original is package) for package in selected)\n'
                b"        target = (self.policy.bios.version if component == 'bios' else\n"
                b"                  '+'.join(name+'_'+version for name,version in self.policy.cpld_targets))\n"
                b"        if row.get('target') != target or row.get('action') not in ('UPGRADE_REQUIRED','AT_TARGET_NO_FLASH'):\n"
                b"            raise SharedUpgradeHold('original native firmware plan is incomplete')\n"
                b"        return (0,) if row['action'] == 'UPGRADE_REQUIRED' else ()\n"
                b'\n'
                b'    def _has_native_package_source_provenance(self):\n'
                b'        # Presence, including a damaged/None value, fixes the native branch.\n'
                b'        # A failed native check must never fall back to readiness admission.\n'
                b'        return any(name in vars(self) for name in (\n'
                b"            '_native_parent', '_native_node', '_native_component', '_native_package_indices'))\n"
                b'\n'
                b'    def _is_native_package_source_child(self, parent, node=None, component=None):\n'
                b'        """Fixed live native provenance, never a readiness impersonation."""\n'
                b"        name = getattr(self, '_native_node', None)\n"
                b"        selected = getattr(self, '_native_component', None)\n"
                b"        return (not any(name in vars(self) for name in ('_readiness_parent', '_readiness_node'))\n"
                b'                and type(parent) is _PreparedRunScope and parent is not self\n'
                b"                and getattr(self, '_native_parent', None) is parent\n"
                b'                and self.manual_execution and parent.manual_execution\n'
                b"                and self.parsed.method == parent.parsed.method == 'scp'\n"
                b'                and self._native_schedule_started and parent._native_schedule_started\n'
                b'                and name in self.devices and name in parent.devices\n'
                b'                and selected in self.parsed.selected and selected in parent.parsed.selected\n'
                b'                and (node is None or node == name) and (component is None or component == selected)\n'
                b'                and self in parent._package_source_borrowers\n'
                b'                and self._package_source_parent is parent\n'
                b'                and self._package_source_owner is parent._package_source_owner\n'
                b'                and self._package_source_selection is parent._package_source_selection\n'
                b"                and getattr(self, '_native_package_indices', None) ==\n"
                b'                    parent._native_scp_needed_indices(name, selected)\n'
                b'                and bool(self._native_package_indices)\n'
                b'                and all((selected, index) in parent._package_source_selection[0]\n'
                b'                        for index in self._native_package_indices))\n'
                b'\n'
                b'    def fork_native_component_scope(self, node, component):\n'
                b'        """Borrow original frozen SCP sources after startup, never readiness."""\n'
                b'        self.verify()\n'
                b'        if (self.closed or not self._native_schedule_started\n'
                b"                or not self.manual_execution or self.parsed.method != 'scp'\n"
                b'                or self._package_source_parent is not None\n'
                b'                or not self._package_source_owns or self._package_source_owner is None):\n'
                b"            raise SharedUpgradeHold('original native SCP parent scope required')\n"
                b'        indices = self._native_scp_needed_indices(node, component)\n'
                b'        if not indices or any((component, index) not in self._package_source_selection[0] for index in indices):\n'
                b"            raise SharedUpgradeHold('needed native source stage was not frozen by original parent')\n"
                b'        child = None\n'
                b'        try:\n'
                b'            child = _PreparedRunScope(*self._open_context, self.run_directory,\n'
                b'                                      manual_execution=self.manual_execution)\n'
                b'            if (child.plan_sha256 != self.plan_sha256 or child.policy != self.policy\n'
                b'                    or [(p.identity,p.payload) for p in child.session._files] !=\n'
                b'                       [(p.identity,p.payload) for p in self.session._files]):\n'
                b"                raise SharedUpgradeHold('native child original inputs differ from parent')\n"
                b'            child._native_parent, child._native_node, child._native_component = self, node, component\n'
                b'            child._native_package_indices = indices\n'
                b'            child._native_schedule_started = True\n'
                b'            child._package_source_owner = self._package_source_owner\n'
                b'            child._package_source_owner_class = self._package_source_owner_class\n'
                b'            child._package_source_parent = self\n'
                b'            child._package_source_selection = self._package_source_selection\n'
                b'            self._package_source_borrowers.add(child)\n'
                b'            child._verify_package_source_owner()\n'
                b'            return child\n'
                b'        except BaseException as original:\n'
                b'            if self._package_source_lifecycle_failure is None:\n'
                b'                self._package_source_lifecycle_failure = SharedUpgradeHold(\n'
                b"                    'native source child acquisition uncertain; original parent retained')\n"
                b'            if child is not None:\n'
                b'                try:\n'
                b'                    child.close()\n'
                b'                except BaseException as cleanup:\n'
                b'                    if isinstance(original, Exception) and not isinstance(cleanup, Exception):\n'
                b'                        raise\n'
                b'            raise\n'
                b'\n'
                b'    def _verify_package_source_owner(self):\n'
                b'        if self._package_source_lifecycle_failure is not None:\n'
                b'            raise self._package_source_lifecycle_failure\n'
            ),
            0,
        ),
        # Region 8: original, integrated, retained original count.
        (
            (
                b'                or parent._package_source_owner is not owner\n'
                b'                or self._package_source_selection is not parent._package_source_selection\n'
                b'                or self._package_source_selection[1:] != (self.policy, self.run_directory, self.plan_sha256)\n'
                b"                or (parent is not self and (getattr(self, '_readiness_parent', None) is not parent\n"
                b"                    or getattr(self, '_readiness_node', None) not in self.devices))):\n"
                b"            raise SharedUpgradeHold('original parent source owner/borrow changed')\n"
                b'        # No parent.verify recursion and no source descriptor reopening.\n'
                b'        owner.verify()\n'
            ),
            (
                b'                or parent._package_source_owner is not owner\n'
                b'                or self._package_source_selection is not parent._package_source_selection\n'
                b'                or self._package_source_selection[1:] != (self.policy, self.run_directory, self.plan_sha256)\n'
                b'                or (parent is not self and\n'
                b'                    (not self._is_native_package_source_child(parent)\n'
                b'                     if self._has_native_package_source_provenance() else\n'
                b"                     (getattr(self, '_readiness_parent', None) is not parent\n"
                b"                      or getattr(self, '_readiness_node', None) not in self.devices)))):\n"
                b"            raise SharedUpgradeHold('original parent source owner/borrow changed')\n"
                b'        # No parent.verify recursion and no source descriptor reopening.\n'
                b'        owner.verify()\n'
            ),
            0,
        ),
        # Region 9: original, integrated, retained original count.
        (
            (
                b"                or self.parsed.method != 'scp' or type(leaf) is not _ReadonlyQueryInputs\n"
                b'                or leaf.scope is not self or leaf._original_selection[0] is not self\n'
                b'                or self._package_source_parent is None\n'
                b"                or getattr(self, '_readiness_node', None) != leaf.node.hostname):\n"
                b"            raise SharedUpgradeHold('original leased SCP child DATA scope required')\n"
                b'        try:\n'
                b'            self._verify_package_source_owner()\n'
            ),
            (
                b"                or self.parsed.method != 'scp' or type(leaf) is not _ReadonlyQueryInputs\n"
                b'                or leaf.scope is not self or leaf._original_selection[0] is not self\n'
                b'                or self._package_source_parent is None\n'
                b'                or not (self._is_native_package_source_child(self._package_source_parent,\n'
                b'                                                            leaf.node.hostname, component)\n'
                b'                        if self._has_native_package_source_provenance() else\n'
                b"                        getattr(self, '_readiness_node', None) == leaf.node.hostname)\n"
                b'                or (self._has_native_package_source_provenance()\n'
                b"                    and package_index not in getattr(self, '_native_package_indices', ()))):\n"
                b"            raise SharedUpgradeHold('original leased SCP child DATA scope required')\n"
                b'        try:\n'
                b'            self._verify_package_source_owner()\n'
            ),
            0,
        ),
        # Region 10: original, integrated, retained original count.
        (
            (
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
            ),
            (
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
                b"                    and ((getattr(self, '_native_parent', None) is parent\n"
                b'                          and self in parent._package_source_borrowers)\n'
                b'                         if self._has_native_package_source_provenance() else\n'
                b"                         getattr(self, '_readiness_parent', None) is parent)\n"
                b'                    and self._package_source_owner is not None\n'
                b'                    and self._package_source_owner is parent._package_source_owner):\n'
                b'                if parent._package_source_lifecycle_failure is None:\n'
            ),
            0,
        ),
        # Region 11: original, integrated, retained original count.
        (
            (
                b'            self._hold(directory, "component-preflight.json")\n'
                b'            runner_binding = self._hold(directory, "runner-binding.json")\n'
                b'            rows = _component_raw_records(records)\n'
                b'            if (rows[-1]["command"] != _owned_launch_command(remote)\n'
                b'                    or any((r["stream_complete"] is not True or r["returncode"] != 0 or r["stderr_base64"] != "")\n'
                b"                           and not (self.parsed.force_health and r['command']=='nv show system health')\n"
                b'                           for r in rows[:-1])):\n'
            ),
            (
                b'            self._hold(directory, "component-preflight.json")\n'
                b'            runner_binding = self._hold(directory, "runner-binding.json")\n'
                b'            rows = _component_raw_records(records)\n'
                b'            scp_companion = None\n'
                b"            if self.parsed.method == 'scp':\n"
                b"                if component != 'cpld':\n"
                b"                    raise ValueError('only original native CPLD has an SCP dispatch backend')\n"
                b'                parent = self._native_parent\n'
                b"                self._native_scp_source(leaf, component, data['package_index'])\n"
                b'                joint = _fixed_native_scp_cpld_api(parent)\n'
                b'                if (type(joint) is not tuple or len(joint) != 3\n'
                b'                        or len(joint[0]) != 19\n'
                b'                        or any(actual is not original for actual, original in zip(joint[0], parent._scp_source_binding[1]))\n'
                b'                        or type(joint[2]) is not tuple or len(joint[2]) <= 3\n'
                b'                        or joint[2][2] is not _PreparedRunScope._native_scp_launch_context\n'
                b'                        or joint[2][3] is not _PreparedRunScope._launch_native_scp_cpld):\n'
                b"                    raise ValueError('fixed native SCP dispatch producer joint changed')\n"
                b"                step = self._hold(directory, 'step.sh')\n"
                b"                runner = self._hold(directory, 'runner.sh')\n"
                b"                scp_companion = self._hold(directory, 'scp-source-request.json')\n"
                b"                if json.loads(runner_binding.payload).get('remote_script') != remote:\n"
                b"                    raise ValueError('SCP dispatch differs from original runner remote')\n"
                b"                _validate_scp_request_content_graph(set(os.listdir(directory.fd)), data['binding'],\n"
                b'                    lambda name: self._hold(directory, name).payload)\n'
                b'                expected_command = joint[2][0](remote, hashlib.sha256(runner.payload).hexdigest(),\n'
                b'                                               hashlib.sha256(step.payload).hexdigest())\n'
                b"                if (rows[-1]['stdout_base64'] != base64.b64encode(b'IBSW_LAUNCH_REQUESTED\\n').decode('ascii')\n"
                b"                        or rows[-1]['stderr_base64'] != '' or rows[-1]['returncode'] != 0\n"
                b"                        or rows[-1]['stream_complete'] is not True):\n"
                b"                    raise ValueError('complete fixed SCP launch delivery fact required')\n"
                b'            else:\n'
                b"                if 'scp-source-request.json' in os.listdir(directory.fd):\n"
                b"                    raise ValueError('SCP companion cannot authorize a V1 dispatch')\n"
                b'                expected_command = _owned_launch_command(remote)\n'
                b'            if (rows[-1]["command"] != expected_command\n'
                b'                    or any((r["stream_complete"] is not True or r["returncode"] != 0 or r["stderr_base64"] != "")\n'
                b"                           and not (self.parsed.force_health and r['command']=='nv show system health')\n"
                b'                           for r in rows[:-1])):\n'
            ),
            0,
        ),
        # Region 12: original, integrated, retained original count.
        (
            (
                b'            uid = [r for r in rows if r["command"] == "id -u"]\n'
                b'            if len(uid) != 1 or not re.fullmatch(rb"[0-9]+\\n", base64.b64decode(uid[0]["stdout_base64"], validate=True)):\n'
                b'                raise ValueError("one actual original uid required")\n'
                b'            payload = _json_bytes({"schema_version": 2, "state": "COMPONENT_DISPATCH_DATA_ONLY",\n'
                b'                "binding": data["binding"], "request_sha256": hashlib.sha256(request.payload).hexdigest(),\n'
                b'                "remote_script": remote, "records": rows, "launch_kind": "OWNED_RUNNER_V1",\n'
                b'                "runner_binding_sha256": hashlib.sha256(runner_binding.payload).hexdigest()})\n'
                b'            if len(payload) > MAXIMUM_INPUT_BYTES:\n'
                b'                raise ValueError("bounded original component chain exceeded")\n'
                b'            self._commit_exclusive_binding(directory, payload, "component-dispatch.json")\n'
            ),
            (
                b'            uid = [r for r in rows if r["command"] == "id -u"]\n'
                b'            if len(uid) != 1 or not re.fullmatch(rb"[0-9]+\\n", base64.b64decode(uid[0]["stdout_base64"], validate=True)):\n'
                b'                raise ValueError("one actual original uid required")\n'
                b'            document = {"schema_version": 2, "state": "COMPONENT_DISPATCH_DATA_ONLY",\n'
                b'                "binding": data["binding"], "request_sha256": hashlib.sha256(request.payload).hexdigest(),\n'
                b'                "remote_script": remote, "records": rows, "launch_kind": "OWNED_RUNNER_V1",\n'
                b'                "runner_binding_sha256": hashlib.sha256(runner_binding.payload).hexdigest()}\n'
                b'            if scp_companion is not None:\n'
                b"                document['launch_kind'] = 'SCP_STDIN_OWNED_RUNNER_V2'\n"
                b"                document['scp_companion_sha256'] = hashlib.sha256(scp_companion.payload).hexdigest()\n"
                b'            payload = _json_bytes(document)\n'
                b'            if len(payload) > MAXIMUM_INPUT_BYTES:\n'
                b'                raise ValueError("bounded original component chain exceeded")\n'
                b'            self._commit_exclusive_binding(directory, payload, "component-dispatch.json")\n'
            ),
            0,
        ),
    ),
    'tools/ibsw_upgrade_executor.py': (
        # Region 1: original, integrated, retained original count.
        (
            (
                b'            raise ValueError("unselected component")\n'
                b'        if not scope.manual_execution and "--exclusive-config-window" not in declared["argv"]:\n'
                b'            raise SharedUpgradeHold("explicit operator configuration maintenance window required")\n'
                b'        if args.method not in ("local", "http"):\n'
                b'            raise SharedUpgradeHold("selected transport has no fixed real component backend")\n'
                b'    except SharedUpgradeHold:\n'
                b'        raise\n'
            ),
            (
                b'            raise ValueError("unselected component")\n'
                b'        if not scope.manual_execution and "--exclusive-config-window" not in declared["argv"]:\n'
                b'            raise SharedUpgradeHold("explicit operator configuration maintenance window required")\n'
                b'        if args.method == "scp":\n'
                b'            # Preserve the original pre-session source rejection. The fixed\n'
                b'            # diagnostic rechecks fresh originals inside the signed session.\n'
                b'            scope._native_scp_source(leaf, component, scope._native_package_indices[0])\n'
                b'            with _signed_session(leaf, password=password) as (transport, deadline, _identity, _auth, _pin):\n'
                b'                scope._preflight_native_scp_source(leaf, component, scope._native_package_indices[0],\n'
                b'                                                   transport, deadline)\n'
                b'        if args.method not in ("local", "http") and not (args.method == \'scp\' and component == \'cpld\'):\n'
                b'            raise SharedUpgradeHold("selected transport has no fixed real component backend")\n'
                b'    except SharedUpgradeHold:\n'
                b'        raise\n'
            ),
            0,
        ),
        # Region 2: original, integrated, retained original count.
        (
            (
                b'                raise SharedUpgradeHold("shared stop before local original request")\n'
                b'            scope._request_prepared_step_locked(leaf.node.hostname,component,data["package_index"])\n'
                b'            request=scope._hold(directory,"request.json")\n'
                b'        leaf.verify(); request.verify(); runner.verify()\n'
                b'        if stop is not None and stop.is_set():\n'
                b"            raise SharedUpgradeHold('shared stop after retaining original request; installer was not dispatched')\n"
                b'        command = _owned_launch_command(remote)\n'
                b"        _progress(leaf, component, 'INSTALL_REQUEST_DISPATCH')\n"
                b'        observed = _read_channel(leaf, transport, command, time.monotonic() + _EXECUTION_SECONDS)\n'
                b'        chain.append(_raw_record(command, observed))\n'
                b'        try:\n'
                b'            with scope._request_namespace_lease():\n'
            ),
            (
                b'                raise SharedUpgradeHold("shared stop before local original request")\n'
                b'            scope._request_prepared_step_locked(leaf.node.hostname,component,data["package_index"])\n'
                b'            request=scope._hold(directory,"request.json")\n'
                b"            if args.method == 'scp':\n"
                b'                # Same actual lease: reliably finish the original schema2\n'
                b'                # companion before any bounded stdin send. No caller DTO/kind.\n'
                b"                scope._capture_scp_request_content_locked(leaf, component, data['package_index'])\n"
                b'                leaf.verify(); request.verify(); runner.verify()\n'
                b'                if stop is not None and stop.is_set():\n'
                b"                    raise SharedUpgradeHold('shared stop after SCP request capture; no secret sent')\n"
                b'                from ibsw_upgrade_driver import _fixed_native_scp_cpld_api\n'
                b'                joint = _fixed_native_scp_cpld_api(scope._native_parent)\n'
                b'                if (type(joint) is not tuple or len(joint) != 3\n'
                b'                        or type(joint[2]) is not tuple or len(joint[2]) <= 3\n'
                b'                        or joint[2][3] is not type(scope)._launch_native_scp_cpld):\n'
                b"                    raise SharedUpgradeHold('fixed native CPLD launcher wrapper changed')\n"
                b"                _progress(leaf, component, 'INSTALL_REQUEST_DISPATCH')\n"
                b"                command, observed = joint[2][3](scope, leaf, component, data['package_index'],\n"
                b'                                               transport, time.monotonic() + _EXECUTION_SECONDS)\n'
                b'        leaf.verify(); request.verify(); runner.verify()\n'
                b"        if args.method != 'scp' and stop is not None and stop.is_set():\n"
                b"            raise SharedUpgradeHold('shared stop after retaining original request; installer was not dispatched')\n"
                b"        if args.method != 'scp':\n"
                b'            command = _owned_launch_command(remote)\n'
                b"            _progress(leaf, component, 'INSTALL_REQUEST_DISPATCH')\n"
                b'            observed = _read_channel(leaf, transport, command, time.monotonic() + _EXECUTION_SECONDS)\n'
                b'        chain.append(_raw_record(command, observed))\n'
                b'        try:\n'
                b'            with scope._request_namespace_lease():\n'
            ),
            0,
        ),
        # Region 3: original, integrated, retained original count.
        (
            (
                b'        held = scope._hold(directory, "component-dispatch.json")\n'
                b'        document = json.loads(held.payload)\n'
                b'        if (document.get("schema_version") != 2 or document.get("binding") != binding\n'
                b'                or document.get("request_sha256") != hashlib.sha256(request.payload).hexdigest()\n'
                b'                or document.get("launch_kind") != "OWNED_RUNNER_V1"):\n'
                b'            raise ValueError("original component dispatch changed")\n'
                b'        remote = document["remote_script"]\n'
                b'        runner = _owned_runner_bytes(binding, remote)\n'
            ),
            (
                b'        held = scope._hold(directory, "component-dispatch.json")\n'
                b'        document = json.loads(held.payload)\n'
                b'        if (document.get("schema_version") != 2 or document.get("binding") != binding\n'
                b'                or document.get("request_sha256") != hashlib.sha256(request.payload).hexdigest()):\n'
                b'            raise ValueError("original component dispatch changed")\n'
                b'        remote = document["remote_script"]\n'
                b'        runner = _owned_runner_bytes(binding, remote)\n'
            ),
            0,
        ),
        # Region 4: original, integrated, retained original count.
        (
            (
                b'        scope._hold(directory, "runner-binding.json", runner_binding)\n'
                b'        if document.get("runner_binding_sha256") != hashlib.sha256(runner_binding).hexdigest():\n'
                b'            raise ValueError("original runner binding changed")\n'
                b'        records = document.get("records")\n'
                b'        if (type(records) is not list or not records\n'
                b'                or records[-1].get("command") != _owned_launch_command(remote)\n'
                b'                or tuple(records) != dispatch.raw_records):\n'
                b'            raise ValueError("original dispatch raw chain changed")\n'
                b'        leaf.verify()\n'
                b'        return scope, directory, binding, document, remote\n'
                b'    except Exception as error:\n'
            ),
            (
                b'        scope._hold(directory, "runner-binding.json", runner_binding)\n'
                b'        if document.get("runner_binding_sha256") != hashlib.sha256(runner_binding).hexdigest():\n'
                b'            raise ValueError("original runner binding changed")\n'
                b"        if args.method == 'scp':\n"
                b'            from ibsw_upgrade_driver import _fixed_native_scp_cpld_api, _validate_scp_request_content_graph\n'
                b"            if dispatch.component != 'cpld' or document.get('launch_kind') != 'SCP_STDIN_OWNED_RUNNER_V2':\n"
                b"                raise ValueError('only original SCP CPLD V2 dispatch is supported')\n"
                b'            source = scope._native_scp_source(leaf, dispatch.component, dispatch.package_index)\n'
                b'            parent = scope._native_parent\n'
                b'            joint = _fixed_native_scp_cpld_api(parent)\n'
                b'            if (type(joint) is not tuple or len(joint) != 3\n'
                b'                    or len(joint[0]) != 19\n'
                b'                    or any(actual is not original for actual, original in zip(joint[0], parent._scp_source_binding[1]))\n'
                b'                    or type(joint[2]) is not tuple or len(joint[2]) <= 3\n'
                b'                    or joint[2][2] is not type(scope)._native_scp_launch_context\n'
                b'                    or joint[2][3] is not type(scope)._launch_native_scp_cpld):\n'
                b"                raise ValueError('original SCP dispatch producer joint changed')\n"
                b"            names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh',\n"
                b"                     'runner-binding.json', 'scp-source-request.json')\n"
                b'            originals = tuple(scope._hold(directory, name) for name in names)\n'
                b'            companion = originals[-1]\n'
                b'            _validate_scp_request_content_graph(set(os.listdir(directory.fd)), binding,\n'
                b'                lambda name: scope._hold(directory, name).payload)\n'
                b"            if document.get('scp_companion_sha256') != hashlib.sha256(companion.payload).hexdigest():\n"
                b"                raise ValueError('original SCP dispatch companion changed')\n"
                b'            expected_command = joint[2][0](remote, hashlib.sha256(runner).hexdigest(),\n'
                b'                                           hashlib.sha256(script).hexdigest())\n'
                b'            if scope._native_scp_source(leaf, dispatch.component, dispatch.package_index) is not source:\n'
                b"                raise ValueError('original SCP dispatch source instance changed')\n"
                b'            current = _fixed_native_scp_cpld_api(parent)\n'
                b'            if (len(current) != len(joint) or any(len(a) != len(b) or\n'
                b'                    any(x is not y for x, y in zip(a, b)) for a, b in zip(current, joint))):\n'
                b"                raise ValueError('original SCP dispatch producer joint changed at read tail')\n"
                b'            for name, original in zip(names, originals):\n'
                b'                if scope._hold(directory, name) is not original:\n'
                b"                    raise ValueError('original SCP dispatch artifact owner changed')\n"
                b'                original.verify()\n'
                b'        else:\n'
                b"            if (document.get('launch_kind') != 'OWNED_RUNNER_V1'\n"
                b"                    or 'scp-source-request.json' in os.listdir(directory.fd)\n"
                b"                    or 'scp_companion_sha256' in document):\n"
                b"                raise ValueError('SCP companion cannot authorize an original V1 dispatch')\n"
                b'            expected_command = _owned_launch_command(remote)\n'
                b'        records = document.get("records")\n'
                b'        if (type(records) is not list or not records\n'
                b'                or records[-1].get("command") != expected_command\n'
                b'                or tuple(records) != dispatch.raw_records):\n'
                b'            raise ValueError("original dispatch raw chain changed")\n'
                b"        if args.method == 'scp' and (records[-1].get('stdout_base64') !=\n"
                b"                base64.b64encode(b'IBSW_LAUNCH_REQUESTED\\n').decode('ascii')\n"
                b"                or records[-1].get('stderr_base64') != '' or records[-1].get('returncode') != 0\n"
                b"                or records[-1].get('stream_complete') is not True):\n"
                b"            raise ValueError('original SCP launch delivery fact changed')\n"
                b'        leaf.verify()\n'
                b'        return scope, directory, binding, document, remote\n'
                b'    except Exception as error:\n'
            ),
            0,
        ),
    ),
    'tools/ibsw_upgrade_component.py': (
        # Region 1: original, integrated, retained original count.
        (
            (
                b'    if refresh is not None:\n'
                b'        values.update(IBSW_REFRESH_FILE=refresh.file, IBSW_REFRESH_URL=_package_url(refresh, method),\n'
                b'                      IBSW_REFRESH_LOCAL=str(Path(switch_dir) / refresh.file))\n'
                b'    header = "#!/bin/bash\\n# Generated IB NVOS component plan artifact; not execution permission.\\n"\n'
                b'    header += "\\n".join(key + "=" + shlex.quote(value) for key, value in values.items()) + "\\n"\n'
                b'    if _fixed_layout(__file__) / "upgrade-component.sh" != _TEMPLATE:\n'
            ),
            (
                b'    if refresh is not None:\n'
                b'        values.update(IBSW_REFRESH_FILE=refresh.file, IBSW_REFRESH_URL=_package_url(refresh, method),\n'
                b'                      IBSW_REFRESH_LOCAL=str(Path(switch_dir) / refresh.file))\n'
                b'    if method == "scp":\n'
                b'        import base64\n'
                b'        from ibsw_upgrade_scp import remote_helper_bytes\n'
                b'        # Fixed stdin-only target helper, never the old environment launcher.\n'
                b'        helper = b"import os\\nos.environ.pop(\'IBSW_SCP_AUTH\',None)\\n" + remote_helper_bytes()\n'
                b"        values.update(IBSW_SCP_HELPER_B64=base64.b64encode(helper).decode('ascii'),\n"
                b'                      IBSW_SCP_PACKAGE_PATH=package.path)\n'
                b'        if refresh is not None:\n'
                b"            values['IBSW_SCP_REFRESH_PATH'] = refresh.path\n"
                b'    header = "#!/bin/bash\\n# Generated IB NVOS component plan artifact; not execution permission.\\n"\n'
                b'    header += "\\n".join(key + "=" + shlex.quote(value) for key, value in values.items()) + "\\n"\n'
                b'    if _fixed_layout(__file__) / "upgrade-component.sh" != _TEMPLATE:\n'
            ),
            0,
        ),
    ),
    'tools/ibsw_upgrade_pipeline.py': (
        # Region 1: original, integrated, retained original count.
        (
            (
                b'\n'
                b'    def begin(self,name,component,canary,stop):\n'
                b'        stack=ExitStack()\n'
                b'        scope=stack.enter_context(self.driver.open_manual_run(\n'
                b'            self.entry,self.cwd,self.parsed.prepare_args,self.directory))\n'
                b'        scope._access_required=True\n'
                b'        if self.parent.policy.os_stages:\n'
                b'            # Live in-process context, never reconstruct a route from saved JSON.\n'
            ),
            (
                b'\n'
                b'    def begin(self,name,component,canary,stop):\n'
                b'        stack=ExitStack()\n'
                b"        if self.parent.parsed.method == 'scp':\n"
                b'            scope=stack.enter_context(self.parent.fork_native_component_scope(name,component))\n'
                b'        else:\n'
                b'            scope=stack.enter_context(self.driver.open_manual_run(\n'
                b'                self.entry,self.cwd,self.parsed.prepare_args,self.directory))\n'
                b'        scope._access_required=True\n'
                b'        if self.parent.policy.os_stages:\n'
                b'            # Live in-process context, never reconstruct a route from saved JSON.\n'
            ),
            0,
        ),
    ),
    'tools/ibsw_upgrade_scp.py': (
        # Region 1: original, integrated, retained original count.
        (
            (
                b'\n'
                b'def package_content_owner(root,paths,*,deadline,max_fds):\n'
                b'    return _PackageContentOwner(root,paths,deadline=deadline,max_fds=max_fds)\n'
            ),
            (
                b'\n'
                b'def package_content_owner(root,paths,*,deadline,max_fds):\n'
                b'    return _PackageContentOwner(root,paths,deadline=deadline,max_fds=max_fds)\n'
                b'\n'
                b'\n'
                b'def _probe_source_channel(leaf,transport,deadline,source):\n'
                b'    """Fixed stdin-only source probe fact, never native preflight permission.\n'
                b'\n'
                b'    This private protocol seam does not attest original native parent authority.\n'
                b'    The public preflight and nonempty execution payload remain HOLD. Raw wire\n'
                b'    buffers and the secret are never returned or attached to diagnostics.\n'
                b'    """\n'
                b'    from ibsw_upgrade_observer import _owned_phase, _remaining\n'
                b'    if type(source) is not ScpSource or type(deadline) not in (int,float) or not math.isfinite(deadline):\n'
                b"        raise ScpHold('SCP_SECRET_CHANNEL_FAILED')\n"
                b'    channel = None\n'
                b'    failure = None\n'
                b'    finished = False\n'
                b'    output,error = bytearray(),bytearray()\n'
                b'    status,complete = None,False\n'
                b'    close_lock = threading.Lock()\n'
                b'    close_attempted = False\n'
                b'    close_error = None\n'
                b'\n'
                b'    def remember(caught):\n'
                b'        nonlocal failure\n'
                b'        if failure is None or (isinstance(failure,Exception) and not isinstance(caught,Exception)):\n'
                b'            failure = caught\n'
                b'\n'
                b'    class OwnedChannel:\n'
                b'        def close(self):\n'
                b'            nonlocal close_attempted,close_error\n'
                b'            # The supervisor and synchronous tail share one actual object\n'
                b'            # close attempt; an unknown close is never retried by this helper.\n'
                b'            with close_lock:\n'
                b'                if close_attempted:\n'
                b'                    if close_error is not None:\n'
                b'                        raise close_error\n'
                b'                    return\n'
                b'                close_attempted = True\n'
                b'            try:\n'
                b'                channel.close()\n'
                b'            except BaseException as caught:\n'
                b'                close_error = caught\n'
                b'                raise\n'
                b'\n'
                b'    owner = OwnedChannel()\n'
                b'\n'
                b'    def finish():\n'
                b'        nonlocal finished\n'
                b'        if finished:\n'
                b'            return\n'
                b'        finished = True\n'
                b'        if channel is not None:\n'
                b'            try:\n'
                b'                owner.close()\n'
                b'            except BaseException as caught:\n'
                b'                remember(caught)\n'
                b'        for verify in (leaf.verify,lambda: verify_source_shared(source)):\n'
                b'            try:\n'
                b'                verify()\n'
                b'            except BaseException as caught:\n'
                b'                remember(caught)\n'
                b'\n'
                b'    try:\n'
                b'        _remaining(deadline)\n'
                b'        leaf.verify()\n'
                b'        verify_source_shared(source)\n'
                b'        payload = json.loads(launch_payload(source,()))\n'
                b"        payload['timeout_seconds'] = min(20.0,_remaining(deadline))\n"
                b"        payload = (json.dumps(payload,separators=(',',':'))+'\\n').encode()\n"
                b'        # The old receiver supports an environment compatibility context.\n'
                b'        # This fixed probe alone must instead consume the current stdin.\n'
                b'        body = b"import os\\nos.environ.pop(\'IBSW_SCP_AUTH\',None)\\n"+remote_helper_bytes()\n'
                b"        command = _python_command(body,'probe')\n"
                b'        channel = transport.open_session(timeout=_remaining(deadline))\n'
                b'        channel.settimeout(_remaining(deadline))\n'
                b'        with _owned_phase((owner,),deadline):\n'
                b'            try:\n'
                b'                leaf.verify()\n'
                b'                verify_source_shared(source)\n'
                b'                channel.exec_command(command)\n'
                b'                position = 0\n'
                b'                while position < len(payload):\n'
                b'                    leaf.verify_io_identity()\n'
                b'                    verify_source_shared(source)\n'
                b'                    channel.settimeout(_remaining(deadline))\n'
                b'                    count = channel.send(payload[position:])\n'
                b'                    if type(count) is not int or not 0 < count <= len(payload)-position:\n'
                b"                        raise ScpHold('SCP_SECRET_CHANNEL_FAILED')\n"
                b'                    position += count\n'
                b'                channel.settimeout(_remaining(deadline))\n'
                b'                channel.shutdown_write()\n'
                b'                while True:\n'
                b'                    leaf.verify_io_identity()\n'
                b'                    _remaining(deadline)\n'
                b'                    for ready,receive,target in ((channel.recv_ready,channel.recv,output),\n'
                b'                            (channel.recv_stderr_ready,channel.recv_stderr,error)):\n'
                b'                        if ready():\n'
                b'                            channel.settimeout(_remaining(deadline))\n'
                b'                            part = receive(65536)\n'
                b'                            if type(part) is not bytes:\n'
                b"                                raise ScpHold('SCP_SECRET_CHANNEL_FAILED')\n"
                b'                            target.extend(part)\n'
                b'                            if len(output)+len(error)>65536:\n'
                b"                                raise ScpHold('SCP_SECRET_CHANNEL_FAILED')\n"
                b'                    if channel.closed and not channel.recv_ready() and not channel.recv_stderr_ready():\n'
                b'                        if channel.exit_status_ready():\n'
                b'                            status = channel.recv_exit_status()\n'
                b'                        complete = channel.eof_received is True and type(status) is int and status == 0\n'
                b'                        break\n'
                b'                    if not transport.is_active():\n'
                b'                        break\n'
                b'                    time.sleep(min(.005,_remaining(deadline)))\n'
                b'            except BaseException as caught:\n'
                b'                remember(caught)\n'
                b'            finally:\n'
                b'                finish()\n'
                b'            try:\n'
                b'                _remaining(deadline)\n'
                b'            except BaseException as caught:\n'
                b'                remember(caught)\n'
                b'    except BaseException as caught:\n'
                b'        remember(caught)\n'
                b'    finally:\n'
                b'        finish()\n'
                b'    if failure is not None and not isinstance(failure,Exception):\n'
                b'        raise failure\n'
                b'    # A changed original shared source must retain batch-stop classification,\n'
                b'    # rather than becoming an ordinary per-device wire failure.\n'
                b'    from ibsw_upgrade_contract import SharedUpgradeHold\n'
                b'    if isinstance(failure,SharedUpgradeHold):\n'
                b'        raise failure\n'
                b'    if (failure is not None or time.monotonic()>=deadline or not complete\n'
                b"            or bytes(output)!=b'IBSW_SCP_SOURCE_VERIFIED\\n' or error):\n"
                b"        raise ScpHold('SCP_SECRET_CHANNEL_FAILED') from None\n"
                b'    return None\n'
                b'\n'
                b'\n'
                b'# Protocol-only fixed launcher. This is not used by the native backend and is\n'
                b'# deliberately distinct from the old environment-context _LAUNCHER.\n'
                b"_STDIN_LAUNCHER = r'''import base64,hashlib,ipaddress,json,os,posixpath,re,select,stat,subprocess,sys,time\n"
                b'\n'
                b'def fail():\n'
                b"    raise ValueError('fixed stdin launch refused')\n"
                b'\n'
                b'def key(info):\n'
                b'    return info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)\n'
                b'\n'
                b'def facts(info):\n'
                b'    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,\n'
                b'            info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns)\n'
                b'\n'
                b'def directory_facts(info):\n'
                b'    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid\n'
                b'\n'
                b'def pairs(values):\n'
                b'    result={}\n'
                b'    for name,value in values:\n'
                b'        if name in result: fail()\n'
                b'        result[name]=value\n'
                b'    return result\n'
                b'\n'
                b'def constant(value): fail()\n'
                b'\n'
                b'def integer(value):\n'
                b'    if len(value)>20: fail()\n'
                b'    return int(value)\n'
                b'\n'
                b'def hex_value(value,length):\n'
                b"    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None\n"
                b'\n'
                b'def source_path(value):\n'
                b"    return (type(value) is str and value.startswith('/') and value!='/'\n"
                b'        and len(value)<=4096 and posixpath.normpath(value)==value\n'
                b'        and not any(ord(char)<32 or ord(char)==127 for char in value))\n'
                b'\n'
                b'def frame(deadline):\n'
                b'    raw=bytearray()\n'
                b'    while True:\n'
                b'        remaining=deadline-time.monotonic()\n'
                b'        if remaining<=0: fail()\n'
                b'        ready,_,_=select.select([0],[],[],remaining)\n'
                b'        if not ready: fail()\n'
                b'        part=os.read(0,65537-len(raw))\n'
                b'        if not part: break\n'
                b'        raw.extend(part)\n'
                b'        if len(raw)>65536: fail()\n'
                b"    if not raw or raw[-1:]!=b'\\n' or raw.count(b'\\n')!=1: fail()\n"
                b"    value=json.loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_constant=constant,parse_int=integer)\n"
                b"    expected={'host','user','port','host_keys','password','paths','timeout_seconds','content_binding'}\n"
                b'    if type(value) is not dict or set(value)!=expected: fail()\n'
                b"    host,user,port=value['host'],value['user'],value['port']\n"
                b'    if (type(host) is not str or str(ipaddress.IPv4Address(host))!=host\n'
                b"        or type(user) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z0-9._-]{0,63}',user) is None\n"
                b'        or type(port) is not int or not 1<=port<=65535): fail()\n'
                b"    secret=value['password'];pins=value['host_keys']\n"
                b'    if (type(secret) is not str or len(secret.encode())>4096\n'
                b'        or any(ord(char)<32 or ord(char)==127 for char in secret)\n'
                b'        or type(pins) is not str or not pins or len(pins)>65536\n'
                b"        or not pins.endswith('\\n') or '\\r' in pins or '\\x00' in pins): fail()\n"
                b"    endpoint=host if port==22 else '['+host+']:'+str(port)\n"
                b"    for line in pins.encode('ascii').splitlines():\n"
                b'        fields=line.split()\n'
                b"        if len(fields)!=3 or fields[0]!=endpoint.encode('ascii'): fail()\n"
                b"        if re.fullmatch(br'[A-Za-z0-9@._+-]{1,128}',fields[1]) is None: fail()\n"
                b'        if not base64.b64decode(fields[2],validate=True): fail()\n'
                b"    paths=value['paths'];binding=value['content_binding']\n"
                b"    fields={'version','binding_sha256','request_id','request_sha256','companion_sha256','packages'}\n"
                b'    if (type(paths) is not dict or not paths or type(binding) is not dict or set(binding)!=fields\n'
                b"        or type(binding['version']) is not int or binding['version']!=1\n"
                b"        or not hex_value(binding['request_id'],32)\n"
                b"        or any(not hex_value(binding[name],64) for name in ('binding_sha256','request_sha256','companion_sha256'))\n"
                b"        or type(binding['packages']) is not dict or set(binding['packages'])!=set(paths)): fail()\n"
                b'    for path,size in paths.items():\n'
                b"        item=binding['packages'][path]\n"
                b'        if (not source_path(path) or type(size) is not int or not 0<size<2**63\n'
                b"            or type(item) is not dict or set(item)!={'size','sha256'}\n"
                b"            or type(item['size']) is not int or item['size']!=size\n"
                b"            or not hex_value(item['sha256'],64)): fail()\n"
                b'    return bytes(raw),value\n'
                b'\n'
                b'def launch():\n'
                b'    deadline=time.monotonic()+10\n'
                b'    rows=[];edges=[];named_files=[]\n'
                b'    child=None;stdin_attempted=False;primary=None;cleanup=[]\n'
                b'    def remaining():\n'
                b'        value=deadline-time.monotonic()\n'
                b'        if value<=0: fail()\n'
                b'        return value\n'
                b'    def remember(error):\n'
                b'        nonlocal primary\n'
                b'        if primary is None or isinstance(primary,Exception) and not isinstance(error,Exception): primary=error\n'
                b'    def opened(name,flags,parent=None):\n'
                b'        named=os.stat(name,dir_fd=parent,follow_symlinks=False)\n'
                b'        descriptor=os.open(name,flags,dir_fd=parent)\n'
                b'        row=[descriptor,key(named),False]\n'
                b'        rows.append(row) # Register from original named preimage before first fstat.\n'
                b'        compare=directory_facts if stat.S_ISDIR(named.st_mode) else facts\n'
                b'        if compare(os.fstat(descriptor))!=compare(named): fail()\n'
                b'        return descriptor,named,row\n'
                b'    def close_row(row):\n'
                b'        if row[2]: return\n'
                b'        row[2]=True # Never retry a close whose result is uncertain.\n'
                b'        if key(os.fstat(row[0]))!=row[1]: fail()\n'
                b'        os.close(row[0])\n'
                b'    def regular(info):\n'
                b'        return (stat.S_ISREG(info.st_mode) and info.st_nlink==1\n'
                b'                and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600)\n'
                b'    def read_source(parent,name,expected):\n'
                b'        fd,named,row=opened(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,parent)\n'
                b'        if not regular(named) or not 0<named.st_size<=4*1024*1024: fail()\n'
                b'        data=bytearray();offset=0\n'
                b'        while offset<named.st_size:\n'
                b'            remaining();part=os.pread(fd,min(65536,named.st_size-offset),offset)\n'
                b'            if not part: fail()\n'
                b'            data.extend(part);offset+=len(part)\n'
                b'        if os.pread(fd,1,offset) or hashlib.sha256(data).hexdigest()!=expected: fail()\n'
                b'        if facts(os.fstat(fd))!=facts(named) or facts(os.stat(name,dir_fd=parent,follow_symlinks=False))!=facts(named): fail()\n'
                b'        named_files.append((parent,name,fd,facts(named)))\n'
                b'        return bytes(data),row\n'
                b'    try:\n'
                b'        if len(sys.argv)!=4: fail()\n'
                b'        remote,runner_sha,step_sha=sys.argv[1:]\n'
                b"        if (not source_path(remote) or posixpath.basename(remote)!='step.sh'\n"
                b'            or not hex_value(runner_sha,64) or not hex_value(step_sha,64)): fail()\n'
                b'        raw,context=frame(deadline)\n'
                b'        directory=posixpath.dirname(remote)\n'
                b"        components=directory.split('/')[1:]\n"
                b'        if not components or len(components)>64 or any(not part for part in components): fail()\n'
                b'        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC\n'
                b"        parent,root_info,_=opened('/',flags)\n"
                b'        root_fd=parent\n'
                b'        for part in components:\n'
                b'            following,named,_=opened(part,flags,parent)\n'
                b'            if not stat.S_ISDIR(named.st_mode): fail()\n'
                b'            edges.append((parent,part,following,directory_facts(named)))\n'
                b'            parent=following\n'
                b'        info=os.fstat(parent)\n'
                b'        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: fail()\n'
                b"        runner,runner_row=read_source(parent,'runner.sh',runner_sha)\n"
                b"        step,step_row=read_source(parent,'step.sh',step_sha)\n"
                b"        component=re.findall(br'^IBSW_COMPONENT=(os|bios|cpld)$',step,re.M)\n"
                b"        method=re.findall(br'^IBSW_METHOD=([^\\n]*)$',step,re.M)\n"
                b"        if len(component)!=1 or method!=[b'scp']: fail()\n"
                b"        budget=600 if component[0]==b'os' else 300\n"
                b"        if type(context['timeout_seconds']) is not int or context['timeout_seconds']!=budget: fail()\n"
                b'        output=[]\n'
                b"        for name in ('execution.stdout','execution.stderr'):\n"
                b'            fd,named,row=opened(name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,parent)\n'
                b'            if not regular(named): fail()\n'
                b'            output.append(row)\n'
                b'        for ancestor,name,fd,original in edges:\n'
                b'            if directory_facts(os.fstat(fd))!=original or directory_facts(os.stat(name,dir_fd=ancestor,follow_symlinks=False))!=original: fail()\n'
                b'        if directory_facts(os.fstat(root_fd))!=directory_facts(root_info): fail()\n'
                b'        for ancestor,name,fd,original in named_files:\n'
                b'            if facts(os.fstat(fd))!=original or facts(os.stat(name,dir_fd=ancestor,follow_symlinks=False))!=original: fail()\n'
                b'        # All original source/directory FDs must close before actual Popen.\n'
                b'        for row in reversed(rows):\n'
                b'            if all(row is not value for value in output): close_row(row)\n'
                b'        remaining()\n'
                b"        child=subprocess.Popen(['/bin/bash','-p',directory+'/runner.sh'],stdin=subprocess.PIPE,\n"
                b'            stdout=output[0][0],stderr=output[1][0],close_fds=True,start_new_session=True,\n'
                b"            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TMPDIR':directory},cwd=directory)\n"
                b'        descriptor=child.stdin.fileno();os.set_blocking(descriptor,False)\n'
                b'        position=0\n'
                b'        while position<len(raw):\n'
                b'            _,ready,_=select.select([],[descriptor],[],remaining())\n'
                b'            if not ready: fail()\n'
                b'            try: count=os.write(descriptor,raw[position:])\n'
                b'            except BlockingIOError: continue\n'
                b'            if count<=0: fail()\n'
                b'            position+=count\n'
                b'        stdin_attempted=True\n'
                b'        child.stdin.close() # EOF and critical close, not environment delivery.\n'
                b'        for row in reversed(output): close_row(row)\n'
                b'        remaining()\n'
                b'    except BaseException as error:\n'
                b'        remember(error)\n'
                b'    finally:\n'
                b'        if child is not None and child.stdin is not None and not stdin_attempted:\n'
                b'            stdin_attempted=True\n'
                b'            try: child.stdin.close()\n'
                b'            except BaseException as error: cleanup.append(error);remember(error)\n'
                b'        for row in reversed(rows):\n'
                b'            if not row[2]:\n'
                b'                try: close_row(row)\n'
                b'                except BaseException as error: cleanup.append(error);remember(error)\n'
                b'    if primary is not None: raise primary\n'
                b'    if cleanup: fail()\n'
                b'    # Asynchronous delivery fact ONLY; no child success or native authority.\n'
                b"    print('IBSW_LAUNCH_REQUESTED',flush=True)\n"
                b'\n'
                b'try: launch()\n'
                b'except Exception:\n'
                b"    print('IBSW_SCP_ERROR=STDIN_LAUNCH_REFUSED',flush=True)\n"
                b'    raise SystemExit(65) from None\n'
                b"'''\n"
                b'\n'
                b'\n'
                b'def _stdin_launch_command(remote, runner_sha256, step_sha256):\n'
                b'    """Pure fixed protocol DATA; no parent/request/dispatch or SCP permission."""\n'
                b"    if (type(remote) is not str or not remote.startswith('/')\n"
                b"            or posixpath.normpath(remote) != remote or posixpath.basename(remote) != 'step.sh'\n"
                b'            or len(remote) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in remote)\n'
                b"            or any(type(value) is not str or re.fullmatch(r'[0-9a-f]{64}', value) is None\n"
                b'                   for value in (runner_sha256, step_sha256))):\n'
                b"        raise ScpHold('SCP_SOURCE_ARGUMENTS')\n"
                b'    return _python_command(_STDIN_LAUNCHER.encode(), remote, runner_sha256, step_sha256)\n'
            ),
            1,
        ),
    ),
    'infiniband/bringup/xdr-upgrade/upgrade.py': (
        # Region 1: original, integrated, retained original count.
        (
            (
                b'import queue\n'
                b'from pathlib import Path\n'
                b'import re\n'
                b'import socket\n'
                b'import stat\n'
                b'import sys\n'
                b'import threading\n'
                b'import time\n'
                b'import warnings\n'
            ),
            (
                b'import queue\n'
                b'from pathlib import Path\n'
                b'import re\n'
                b'import select\n'
                b'import socket\n'
                b'import stat\n'
                b'import sys\n'
                b'import termios\n'
                b'import threading\n'
                b'import time\n'
                b'import warnings\n'
            ),
            0,
        ),
        # Region 2: original, integrated, retained original count.
        (
            (
                b'    "--exclusive-config-window", "--force",\n'
                b')\n'
                b'_AUTH_VALUES = ("--known-hosts", "--user", "--identity", "--management-public-key")\n'
                b"_RUNTIME_VALUES = ('--parallel-limit','--os-download-jitter')\n"
                b'# These old options retain their meanings: they are NOT aliases for new auth.\n'
                b'_UNMIGRATED_VALUES = (\n'
                b'    "--ib-log", "--public-key", "--mgmt-server", "--mgmt-user",\n'
                b'    "--http-server", "--phase-wait",\n'
                b')\n'
                b'\n'
            ),
            (
                b'    "--exclusive-config-window", "--force",\n'
                b')\n'
                b'_AUTH_VALUES = ("--known-hosts", "--user", "--identity", "--management-public-key")\n'
                b"_SCP_VALUES = ('--mgmt-server', '--mgmt-user', '--mgmt-port', '--scp-known-hosts')\n"
                b"_RUNTIME_VALUES = ('--parallel-limit','--os-download-jitter')\n"
                b'# Remaining legacy options are not aliases for target/source authentication.\n'
                b'_UNMIGRATED_VALUES = (\n'
                b'    "--ib-log", "--public-key",\n'
                b'    "--http-server", "--phase-wait",\n'
                b')\n'
                b'\n'
            ),
            0,
        ),
        # Region 3: original, integrated, retained original count.
        (
            (
                b'                        help="run selected OS/BIOS/CPLD through the fixed verified workflow; requires --yes")\n'
                b'    parser.add_argument("--password", action="store_true",\n'
                b'                        help="hidden existing password prompt; actual upgrades always verify BOTH key and password login")\n'
                b'    for option in _AUTH_VALUES + _PREPARE_VALUES + _UNMIGRATED_VALUES + _RUNTIME_VALUES:\n'
                b'        parser.add_argument(option, action=_Once,\n'
                b'                            help=("lower startup/upgrade worker capacity (1..32); never raises the default formula"\n'
                b"                                  if option=='--parallel-limit' else\n"
            ),
            (
                b'                        help="run selected OS/BIOS/CPLD through the fixed verified workflow; requires --yes")\n'
                b'    parser.add_argument("--password", action="store_true",\n'
                b'                        help="hidden existing password prompt; actual upgrades always verify BOTH key and password login")\n'
                b'    for option in _AUTH_VALUES + _SCP_VALUES + _PREPARE_VALUES + _UNMIGRATED_VALUES + _RUNTIME_VALUES:\n'
                b'        parser.add_argument(option, action=_Once,\n'
                b'                            help=("lower startup/upgrade worker capacity (1..32); never raises the default formula"\n'
                b"                                  if option=='--parallel-limit' else\n"
            ),
            0,
        ),
        # Region 4: original, integrated, retained original count.
        (
            (
                b'    method = parsed.method\n'
                b'    if method is not None:\n'
                b'        method = {"1": "scp", "2": "http", "3": "local"}.get(method, method)\n'
                b'        if method != "http":\n'
                b'            raise _InspectionHold("HTTP-only upgrade entry; HTTPS, SCP and local transports are refused without fallback")\n'
                b'    if parsed.http_scheme is not None:\n'
                b'        if parsed.http_scheme != "http" or method not in (None, "http"):\n'
                b'            raise _InspectionHold("HTTPS or conflicting HTTP selector refused")\n'
            ),
            (
                b'    method = parsed.method\n'
                b'    if method is not None:\n'
                b'        method = {"1": "scp", "2": "http", "3": "local"}.get(method, method)\n'
                b'        if method not in ("http", "scp"):\n'
                b'            raise _InspectionHold("HTTP/SCP private entry; HTTPS and local transports are refused without fallback")\n'
                b"    if method != 'scp' and any(getattr(parsed, option[2:].replace('-', '_')) is not None\n"
                b'                               for option in _SCP_VALUES):\n'
                b"        raise _InspectionHold('Management-server SCP options require --method scp')\n"
                b'    if parsed.mgmt_port is not None:\n'
                b"        if re.fullmatch(r'[0-9]{1,5}', parsed.mgmt_port) is None or not 1 <= int(parsed.mgmt_port) <= 65535:\n"
                b"            raise _InspectionHold('SCP management SSH port must be 1..65535')\n"
                b'        parsed.mgmt_port = int(parsed.mgmt_port)\n'
                b'    if parsed.scp_known_hosts is not None:\n'
                b'        path = parsed.scp_known_hosts\n'
                b"        if not path or '\\x00' in path or not os.path.isabs(path) or os.path.normpath(path) != path:\n"
                b"            raise _InspectionHold('--scp-known-hosts must be an absolute normalized path')\n"
                b'    if parsed.http_scheme is not None:\n'
                b'        if parsed.http_scheme != "http" or method not in (None, "http"):\n'
                b'            raise _InspectionHold("HTTPS or conflicting HTTP selector refused")\n'
            ),
            0,
        ),
        # Region 5: original, integrated, retained original count.
        (
            (
                b'            prepare_args.extend((option, value))\n'
                b'        elif token in _PREPARE_FLAGS or token == "--scripts-only":\n'
                b'            prepare_args.append(token)\n'
                b'        elif option in _AUTH_VALUES + _RUNTIME_VALUES and not equal:\n'
                b'            index += 1\n'
                b'        index += 1\n'
                b'    parsed.prepare_args = tuple(prepare_args)\n'
                b'    if hasattr(parsed, "_seen_values"):\n'
                b'        del parsed._seen_values\n'
                b'    return parsed\n'
                b'\n'
                b'\n'
                b'def _read_password():\n'
            ),
            (
                b'            prepare_args.extend((option, value))\n'
                b'        elif token in _PREPARE_FLAGS or token == "--scripts-only":\n'
                b'            prepare_args.append(token)\n'
                b'        elif option in _AUTH_VALUES + _SCP_VALUES + _RUNTIME_VALUES and not equal:\n'
                b'            index += 1\n'
                b'        index += 1\n'
                b'    parsed.prepare_args = tuple(prepare_args)\n'
                b'    if hasattr(parsed, "_seen_values"):\n'
                b'        del parsed._seen_values\n'
                b'    return parsed\n'
                b'\n'
                b'\n'
                b'def _configure_scp_source(scope, parsed):\n'
                b'    """Pin original management-source trust across one hidden prompt.\n'
                b'\n'
                b'    Configuration only: no secret channel, source preflight or launch authority.\n'
                b'    """\n'
                b"    if scope.parsed.method != 'scp' or not any(row['action'] == 'UPGRADE_REQUIRED'\n"
                b"            for row in getattr(scope, '_version_plan', ())):\n"
                b'        return None\n'
                b'    from ibsw_upgrade_driver import _fixed_scp_source_api\n'
                b'    from ibsw_upgrade_contract import SharedUpgradeHold\n'
                b'    api = _fixed_scp_source_api(scope)\n'
                b'    source_from_known_hosts, source_class = api[1], api[2]\n'
                b'    verify_source_shared, ScpHold = api[3], api[5]\n'
                b'\n'
                b'    def audit_joint():\n'
                b'        current = _fixed_scp_source_api(scope)\n'
                b'        if len(current) != len(api) or any(left is not right for left, right in zip(api, current)):\n'
                b"            raise SharedUpgradeHold('SCP_SOURCE_CHANGED: fixed source API objects changed; no further dispatch')\n"
                b'\n'
                b'    if not sys.stdin.isatty():\n'
                b"        raise _InspectionHold('SCP upgrades require a TTY for independent management-server credentials; passwords in argv/files are not accepted')\n"
                b'    host = parsed.mgmt_server\n'
                b'    if host is None:\n'
                b"        sys.stderr.write('Management-server SSH IPv4 reachable from IB switches: ')\n"
                b'        sys.stderr.flush()\n'
                b'        host = sys.stdin.readline(128).strip()\n'
                b'    user = parsed.mgmt_user\n'
                b'    if user is None:\n'
                b'        default = getpass.getuser()\n'
                b"        sys.stderr.write('Management-server SCP username ['+default+']: ')\n"
                b'        sys.stderr.flush()\n'
                b'        entered = sys.stdin.readline(128).strip()\n'
                b'        user = entered or default\n'
                b'    port = parsed.mgmt_port or 22\n'
                b'    trust = parsed.scp_known_hosts or parsed.known_hosts\n'
                b"    first_source = source_from_known_hosts(host, user, port, trust, '')\n"
                b'    if type(first_source) is not source_class:\n'
                b"        raise SharedUpgradeHold('SCP_SOURCE_CHANGED: original source class required')\n"
                b'    audit_joint()\n'
                b"    sys.stderr.write('[SCP] This is the MANAGEMENT SERVER credential, not the IB switch password. '\n"
                b"                     'Existing switch-side source keys may be used; no private key is uploaded.\\n')\n"
                b'    with warnings.catch_warnings():\n'
                b"        warnings.simplefilter('error', getpass.GetPassWarning)\n"
                b'        try:\n'
                b"            password = getpass.getpass('Management-server SSH password (Enter: existing switch key only): ')\n"
                b'        except (EOFError, getpass.GetPassWarning):\n'
                b"            raise ScpHold('SCP_SOURCE_ARGUMENTS') from None\n"
                b'    # Keep the first genuine source. Never silently adopt trust reread after\n'
                b'    # prompting; validate it on both sides of the second actual factory call.\n'
                b'    audit_joint()  # Audit dynamic dependencies before executing a post-prompt verifier.\n'
                b'    verify_source_shared(first_source)\n'
                b'    source = source_from_known_hosts(host, user, port, trust, password)\n'
                b'    audit_joint()\n'
                b'    verify_source_shared(first_source)\n'
                b'    if (type(source) is not source_class or source._identity != first_source._identity\n'
                b'            or source.host_keys != first_source.host_keys):\n'
                b"        raise SharedUpgradeHold('SCP_SOURCE_CHANGED: original source trust changed; no further dispatch')\n"
                b'    scope._bind_scp_source(source, api)\n'
                b"    sys.stderr.write('[SCP] Source: '+user+'@'+host+':'+str(port)+'; pinned SSH trust; switch pulls packages.\\n')\n"
                b'    return source\n'
                b'\n'
                b'\n'
                b'def _choose_transfer_method(parsed):\n'
                b'    """Fixed nonsecret selector; does not grant source or native authority."""\n'
                b"    method = parsed.method or ('http' if parsed.http_scheme is not None else None)\n"
                b'    if method is None:\n'
                b"        method = 'http'\n"
                b'        if sys.stdin.isatty() and not (parsed.diagnose_inputs or parsed.scripts_only):\n'
                b"            sys.stderr.write('[METHOD] Package transfer: http (default) or scp.\\n'\n"
                b"                'Transfer method [http/scp; Enter or 15s timeout = http]: ')\n"
                b'            sys.stderr.flush()\n'
                b'            readable,_,_ = select.select([sys.stdin],[],[],15.0)\n'
                b'            if readable:\n'
                b'                answer = sys.stdin.readline(32).strip().lower()\n'
                b"                if answer not in ('','http','scp'):\n"
                b"                    raise _InspectionHold('Select http or scp; no transport was started')\n"
                b"                method = answer or 'http'\n"
                b'            else:\n'
                b'                try:\n'
                b'                    termios.tcflush(sys.stdin.fileno(),termios.TCIFLUSH)\n'
                b'                except (OSError,ValueError,AttributeError):\n'
                b'                    pass\n'
                b"            sys.stderr.write('\\n[METHOD] Selected '+method.upper()+'\\n')\n"
                b"    if method == 'http' and any(getattr(parsed,option[2:].replace('-','_')) is not None\n"
                b'                                for option in _SCP_VALUES):\n'
                b"        raise _InspectionHold('Management-server SCP options require SCP selection')\n"
                b'    return method\n'
                b'\n'
                b'\n'
                b'def _read_password():\n'
            ),
            0,
        ),
        # Region 6: original, integrated, retained original count.
        (
            (
                b'    """Entry-directory defaults; explicit relative overrides retain caller CWD."""\n'
                b'    args = list(parsed.prepare_args)\n'
                b'    args.append("--standalone-inputs")\n'
                b'    if parsed.method is None and parsed.http_scheme is None:\n'
                b'        args.extend(("--method", "http"))\n'
                b'    if parsed.project is not None:\n'
                b'        return tuple(args)\n'
                b'    root = Path(__file__).absolute().parent\n'
            ),
            (
                b'    """Entry-directory defaults; explicit relative overrides retain caller CWD."""\n'
                b'    args = list(parsed.prepare_args)\n'
                b'    args.append("--standalone-inputs")\n'
                b"    if '--method' not in args and parsed.http_scheme is None:\n"
                b'        args.extend(("--method", parsed.method or \'http\'))\n'
                b'    if parsed.project is not None:\n'
                b'        return tuple(args)\n'
                b'    root = Path(__file__).absolute().parent\n'
            ),
            0,
        ),
        # Region 7: original, integrated, retained original count.
        (
            (
                b'        raise SharedUpgradeHold("explicit exclusive configuration maintenance window required")\n'
                b'    scope.enable_cooperative_status_snapshots()\n'
                b'    scope.initialize_native_component_status_data()\n'
                b'    scope._native_schedule_started = True\n'
                b'    bus = _ProgressBus()\n'
                b'    scope._access_required = True\n'
            ),
            (
                b'        raise SharedUpgradeHold("explicit exclusive configuration maintenance window required")\n'
                b'    scope.enable_cooperative_status_snapshots()\n'
                b'    scope.initialize_native_component_status_data()\n'
                b"    if scope.parsed.method == 'scp':\n"
                b'        # Private exploration: derive needed sources from real startup rows,\n'
                b'        # not all declarations or caller-supplied current/permission DATA.\n'
                b'        needed = set()\n'
                b'        for node in ready:\n'
                b'            if scope.devices.get(node.hostname) is not node:\n'
                b"                raise SharedUpgradeHold('native SCP ready node is not an original target')\n"
                b'            for component in component_order(scope.parsed.selected):\n'
                b'                needed.update((component, index) for index in\n'
                b'                              scope._native_scp_needed_indices(node.hostname, component))\n'
                b'        if needed:\n'
                b'            scope.freeze_scp_package_sources(tuple(sorted(needed)),\n'
                b'                deadline=time.monotonic()+30.0, max_fds=64)\n'
                b'    scope._native_schedule_started = True\n'
                b'    bus = _ProgressBus()\n'
                b'    scope._access_required = True\n'
            ),
            0,
        ),
        # Region 8: original, integrated, retained original count.
        (
            (
                b'    parsed, prepare_arguments, entry, cwd = None, None, None, None\n'
                b'    prepared = None\n'
                b'    try:\n'
                b'        parsed = _parse_cli(tuple(sys.argv[1:] if argv is None else argv))\n'
                b'        is_upgrade = parsed.upgrade\n'
                b'        stage = "DEPENDENCIES"\n'
                b'        driver = _fixed_driver()\n'
                b'        entry, cwd = str(Path(__file__).resolve()), os.getcwd()\n'
                b'        parsed.prepare_args = _local_input_arguments(parsed, cwd)\n'
                b'        # Pure argument validation precedes any prompt or private-output creation.\n'
                b'        stage = "INPUT_PREFLIGHT"\n'
                b'        prepare_arguments = driver.parse_prepare_args(entry, cwd, parsed.prepare_args)\n'
                b'        if parsed.scripts_only and prepare_arguments.method not in ("local", "http"):\n'
                b'            raise _InspectionHold("SCP script declarations are not implemented")\n'
            ),
            (
                b'    parsed, prepare_arguments, entry, cwd = None, None, None, None\n'
                b'    prepared = None\n'
                b'    try:\n'
                b'        argv = tuple(sys.argv[1:] if argv is None else argv)\n'
                b'        parsed = _parse_cli(argv)\n'
                b'        is_upgrade = parsed.upgrade\n'
                b'        stage = "DEPENDENCIES"\n'
                b'        driver = _fixed_driver()\n'
                b'        entry, cwd = str(Path(__file__).resolve()), os.getcwd()\n'
                b'        # Pure argument validation precedes any prompt or private-output creation.\n'
                b'        stage = "INPUT_PREFLIGHT"\n'
                b'        driver.parse_prepare_args(entry, cwd, _local_input_arguments(parsed, cwd))\n'
                b'        method = _choose_transfer_method(parsed)\n'
                b'        if parsed.method is None and parsed.http_scheme is None:\n'
                b'            # Freeze only this public choice into the original argv. Recursive\n'
                b'            # password correction must not reopen a menu or change transport;\n'
                b'            # no credentials or prepared/source authority are carried forward.\n'
                b"            argv = (*argv, '--method', method)\n"
                b'            parsed.method = method\n'
                b'        parsed.prepare_args = _local_input_arguments(parsed, cwd)\n'
                b'        prepare_arguments = driver.parse_prepare_args(entry, cwd, parsed.prepare_args)\n'
                b'        if parsed.scripts_only and prepare_arguments.method not in ("local", "http"):\n'
                b'            raise _InspectionHold("SCP script declarations are not implemented")\n'
            ),
            0,
        ),
        # Region 9: original, integrated, retained original count.
        (
            (
                b'                        previous_password_attempt_runs=list(_password_history)))\n'
                b"                    raise _PasswordReentry(prepared['run_directory'])\n"
                b'            if parsed.upgrade:\n'
                b'                stage = "UPGRADE"\n'
                b'                sys.stderr.write("[NOTICE] Manual upgrade: no deployment or history gates. The CLI holds a "\n'
                b'                                 "host-local initialization/upgrade runtime guard; ensure no other server or "\n'
            ),
            (
                b'                        previous_password_attempt_runs=list(_password_history)))\n'
                b"                    raise _PasswordReentry(prepared['run_directory'])\n"
                b'            if parsed.upgrade:\n'
                b"                if prepare_arguments.method == 'scp':\n"
                b'                    stage = "SCP_SOURCE"\n'
                b'                    _configure_scp_source(scope, parsed)\n'
                b'                stage = "UPGRADE"\n'
                b'                sys.stderr.write("[NOTICE] Manual upgrade: no deployment or history gates. The CLI holds a "\n'
                b'                                 "host-local initialization/upgrade runtime guard; ensure no other server or "\n'
            ),
            0,
        ),
    ),
    'infiniband/bringup/xdr-upgrade/upgrade-component.sh': (
        # Region 1: original, integrated, retained original count.
        (
            (
                b'\n'
                b'temporary=""\n'
                b'install_requested=false\n'
                b'IBSW_OS_DOWNLOAD_TIMEOUT=600\n'
                b'IBSW_FIRMWARE_DOWNLOAD_TIMEOUT=300\n'
                b'finish_step() {\n'
                b'    rc=$?\n'
                b'    if [[ -n "$temporary" ]]; then\n'
                b'        rm -f -- "$temporary"\n'
                b'    fi\n'
            ),
            (
                b'\n'
                b'temporary=""\n'
                b'install_requested=false\n'
                b'ibsw_scp_context=""\n'
                b'ibsw_scp_context_read=false\n'
                b'IBSW_OS_DOWNLOAD_TIMEOUT=600\n'
                b'IBSW_FIRMWARE_DOWNLOAD_TIMEOUT=300\n'
                b'finish_step() {\n'
                b'    rc=$?\n'
                b'    unset ibsw_scp_context\n'
                b'    if [[ -n "$temporary" ]]; then\n'
                b'        rm -f -- "$temporary"\n'
                b'    fi\n'
            ),
            0,
        ),
        # Region 2: original, integrated, retained original count.
        (
            (
                b'\n'
                b'printf \'%s\\n\' "$IBSW_BINDING_JSON"\n'
                b'[[ -d "$IBSW_SWITCH_DIR" && ! -L "$IBSW_SWITCH_DIR" ]] || exit 65\n'
                b'prepare_package() {\n'
                b'    local IBSW_LOCAL_PACKAGE="$1" IBSW_PACKAGE_URL="$2"\n'
                b"    printf '%s\\n' 'IBSW_STAGE=PACKAGE_DOWNLOAD'\n"
                b'    [[ ! -L "$IBSW_LOCAL_PACKAGE" ]] || exit 65\n'
                b'    case "$IBSW_METHOD" in\n'
            ),
            (
                b'\n'
                b'printf \'%s\\n\' "$IBSW_BINDING_JSON"\n'
                b'[[ -d "$IBSW_SWITCH_DIR" && ! -L "$IBSW_SWITCH_DIR" ]] || exit 65\n'
                b'read_scp_context() {\n'
                b'    $ibsw_scp_context_read && return\n'
                b'    local deadline=$((SECONDS+10)) remaining extra="" rc=0\n'
                b'    remaining=$((deadline-SECONDS))\n'
                b'    (( remaining > 0 )) || exit 65\n'
                b'    IFS= read -r -n 65537 -t "$remaining" ibsw_scp_context || exit 64\n'
                b'    [[ -n "$ibsw_scp_context" && ${#ibsw_scp_context} -le 65535 ]] || exit 64\n'
                b'    export -n ibsw_scp_context\n'
                b'    remaining=$((deadline-SECONDS))\n'
                b'    (( remaining > 0 )) || exit 65\n'
                b'    IFS= read -r -n 1 -t "$remaining" extra || rc=$?\n'
                b'    [[ "$rc" == 1 ]] || exit 65\n'
                b'    exec 0</dev/null\n'
                b'    ibsw_scp_context_read=true\n'
                b'}\n'
                b'prepare_package() {\n'
                b'    local IBSW_LOCAL_PACKAGE="$1" IBSW_PACKAGE_URL="$2" scp_source="${3:-}"\n'
                b"    printf '%s\\n' 'IBSW_STAGE=PACKAGE_DOWNLOAD'\n"
                b'    [[ ! -L "$IBSW_LOCAL_PACKAGE" ]] || exit 65\n'
                b'    case "$IBSW_METHOD" in\n'
            ),
            0,
        ),
        # Region 3: original, integrated, retained original count.
        (
            (
                b'        mv -- "$temporary" "$IBSW_LOCAL_PACKAGE"\n'
                b'        temporary=""\n'
                b'        ;;\n'
                b'    local) ;;\n'
                b'    *) exit 64 ;;\n'
                b'    esac\n'
            ),
            (
                b'        mv -- "$temporary" "$IBSW_LOCAL_PACKAGE"\n'
                b'        temporary=""\n'
                b'        ;;\n'
                b'    scp)\n'
                b'        # No SCP OS installer until genuine SCP-only manager ACK is closed.\n'
                b'        [[ "$IBSW_COMPONENT" != os ]] || exit 64\n'
                b'        : "${scp_source:?bound source path required}"\n'
                b'        : "${IBSW_SCP_HELPER_B64:?fixed stdin-only helper required}"\n'
                b'        read_scp_context\n'
                b'        temporary=$(mktemp "$IBSW_SWITCH_DIR/.ibsw-$IBSW_RUN_ID-XXXXXX")\n'
                b'        local result rc=0 rest candidate content="" measurement=""\n'
                b'        result=$(builtin printf \'%s\\n\' "$ibsw_scp_context" | /usr/bin/python3 -c \\\n'
                b"            'import base64,sys;exec(base64.b64decode(sys.argv.pop(1)))' \\\n"
                b'            "$IBSW_SCP_HELPER_B64" fetch "$scp_source" "$temporary" 2>/dev/null) || rc=$?\n'
                b'        if [[ "$rc" != 0 ]]; then\n'
                b"            printf '%s\\n' 'IBSW_SCP_ERROR=TRANSFER_FAILED'\n"
                b'            exit "$rc"\n'
                b'        fi\n'
                b'        [[ -n "$result" && ${#result} -le 4096 ]] || exit 66\n'
                b'        rest="$result"\n'
                b'        while [[ -n "$rest" ]]; do\n'
                b'            if [[ "$rest" == *$\'\\n\'* ]]; then\n'
                b'                candidate="${rest%%$\'\\n\'*}"\n'
                b'                rest="${rest#*$\'\\n\'}"\n'
                b'            else\n'
                b'                candidate="$rest"\n'
                b'                rest=""\n'
                b'            fi\n'
                b'            if [[ "$candidate" =~ ^IBSW_SCP_CONTENT_VERIFIED=1\\|[0-9a-f]{64}\\|[A-Za-z0-9_-]+\\|[1-9][0-9]*\\|[0-9a-f]{64}$ ]]; then\n'
                b'                [[ -z "$content" ]] || exit 66\n'
                b'                content="$candidate"\n'
                b'            elif [[ "$candidate" =~ ^IBSW_SCP_DOWNLOAD_RESULT=1\\|[0-9]+\\|[0-9]+\\|0\\|0\\|[1-9][0-9]*\\|[0-9]+([.][0-9]+)?\\|[0-9]+([.][0-9]+)?$ ]]; then\n'
                b'                [[ -z "$measurement" ]] || exit 66\n'
                b'                measurement="$candidate"\n'
                b'            else\n'
                b'                exit 66 # No arbitrary helper stdout/stderr reflection.\n'
                b'            fi\n'
                b'        done\n'
                b'        [[ -n "$content" && -n "$measurement" && -s "$temporary" ]] || exit 66\n'
                b'        printf \'%s\\n\' "$content" "$measurement"\n'
                b'        mv -- "$temporary" "$IBSW_LOCAL_PACKAGE"\n'
                b'        temporary=""\n'
                b'        ;;\n'
                b'    local) ;;\n'
                b'    *) exit 64 ;;\n'
                b'    esac\n'
            ),
            1,
        ),
        # Region 4: original, integrated, retained original count.
        (
            (
                b'}\n'
                b'\n'
                b'# IBSW_BODY_OS\n'
                b'prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL"\n'
                b'# NVOS IB published FILE fetch, then default-reboot install. The latter can\n'
                b'# disconnect SSH before any final marker returns; do not resend it on timeout.\n'
                b"printf '%s\\n' 'IBSW_STAGE=IMAGE_FETCH'\n"
            ),
            (
                b'}\n'
                b'\n'
                b'# IBSW_BODY_OS\n'
                b'[[ "$IBSW_METHOD" != scp ]] || exit 64\n'
                b'prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL" "${IBSW_SCP_PACKAGE_PATH:-}"\n'
                b'# NVOS IB published FILE fetch, then default-reboot install. The latter can\n'
                b'# disconnect SSH before any final marker returns; do not resend it on timeout.\n'
                b"printf '%s\\n' 'IBSW_STAGE=IMAGE_FETCH'\n"
            ),
            0,
        ),
        # Region 5: original, integrated, retained original count.
        (
            (
                b'nv action install system image files "$IBSW_PACKAGE_FILE" force\n'
                b'\n'
                b'# IBSW_BODY_BIOS\n'
                b'prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL"\n'
                b"printf '%s\\n' 'IBSW_STAGE=BIOS_FETCH'\n"
                b'nv action fetch platform firmware BIOS "file://${IBSW_LOCAL_PACKAGE}"\n'
                b'install_requested=true\n'
            ),
            (
                b'nv action install system image files "$IBSW_PACKAGE_FILE" force\n'
                b'\n'
                b'# IBSW_BODY_BIOS\n'
                b'prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL" "${IBSW_SCP_PACKAGE_PATH:-}"\n'
                b"printf '%s\\n' 'IBSW_STAGE=BIOS_FETCH'\n"
                b'nv action fetch platform firmware BIOS "file://${IBSW_LOCAL_PACKAGE}"\n'
                b'install_requested=true\n'
            ),
            0,
        ),
        # Region 6: original, integrated, retained original count.
        (
            (
                b': "${IBSW_REFRESH_FILE:?bound REFRESH package required}"\n'
                b': "${IBSW_REFRESH_LOCAL:?bound REFRESH path required}"\n'
                b'# Validate/prepare both files before any firmware write is attempted.\n'
                b'prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL"\n'
                b'prepare_package "$IBSW_REFRESH_LOCAL" "$IBSW_REFRESH_URL"\n'
                b'nv action fetch platform firmware CPLD1 "file://${IBSW_LOCAL_PACKAGE}"\n'
                b"printf '%s\\n' 'IBSW_COMPONENT_STAGE=BURN_REQUESTED'\n"
                b"printf '%s\\n' 'IBSW_STAGE=CPLD_BURN'\n"
            ),
            (
                b': "${IBSW_REFRESH_FILE:?bound REFRESH package required}"\n'
                b': "${IBSW_REFRESH_LOCAL:?bound REFRESH path required}"\n'
                b'# Validate/prepare both files before any firmware write is attempted.\n'
                b'prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL" "${IBSW_SCP_PACKAGE_PATH:-}"\n'
                b'prepare_package "$IBSW_REFRESH_LOCAL" "$IBSW_REFRESH_URL" "${IBSW_SCP_REFRESH_PATH:-}"\n'
                b'nv action fetch platform firmware CPLD1 "file://${IBSW_LOCAL_PACKAGE}"\n'
                b"printf '%s\\n' 'IBSW_COMPONENT_STAGE=BURN_REQUESTED'\n"
                b"printf '%s\\n' 'IBSW_STAGE=CPLD_BURN'\n"
            ),
            0,
        ),
    ),
}



# Finite OS22 pre-layer copied byte-for-byte from reviewed gate7a961692
# literal table; old U whole hashes remain reverse targets, not candidate hashes.
_NATIVE_OS_EXPECTED_U = {
    'tools/ibsw_upgrade_driver.py': '887a3faf2808cfd2107849825cea2a14fe041f9468987249c5bba07c39030f01',
    'tools/ibsw_upgrade_executor.py': '1736c076376873e2de2a2ce14639cde357bf15f058f0e486fcbf176b5ef02f51',
    'tools/ibsw_upgrade_component.py': '1ab3b4b6bb75f11a01816f35ef788b701df2e16489e4c8054709502fd8f2f2d1',
    'infiniband/bringup/xdr-upgrade/upgrade-component.sh': 'a2bde38c42ff14cc73ed5c5cbd3859701e93a8193eb78ae67f2bd5575393b502',
}
# SOURCE ONLY finite layer from reviewed diff42b166; not a new whole-hash allowlist.
# Full three-line unified-hunk contexts are retained. Regions never overlap.
# Tuple: ordinal, original_U_offset, candidate_offset, old_literal, new_literal,
#        number of old_literal occurrences retained in the candidate (=0 here).
_NATIVE_OS_PATHS = [
    "tools/ibsw_upgrade_driver.py",
    "tools/ibsw_upgrade_executor.py",
    "tools/ibsw_upgrade_component.py",
    "infiniband/bringup/xdr-upgrade/upgrade-component.sh"
]
_NATIVE_OS_REGIONS = {
    "tools/ibsw_upgrade_driver.py": (
        # hunk1: old467B/015f12e9c5578390915987201696d51ecc5eb7ab55a5a17e90fb9bc287ec18c0, new802B/c1f76e35d5103ce44c2d58e3c802dd51b46ecb040b43f511c545bd7d3f4b82c6
        (1, 1211, 1211,
(
            b'    MAXIMUM_INPUT_BYTES, _CandidateDescriptor, _EvidenceIdentity, _HeldFile, _raise_cleanup_issues, open_managed_inputs,\n'
            b'    open_regular_inputs, open_standalone_inputs,\n'
            b')\n'
            b'from ibsw_upgrade_component import render_declared_step\n'
            b'from ibsw_upgrade_schedule import (declared_step_key, component_order, COMPONENT_REGISTRY,\n'
            b'    component_status_document, validate_component_status_document,\n'
            b'    native_component_status_document, validate_native_component_status_document)\n'
        ),
(
            b'    MAXIMUM_INPUT_BYTES, _CandidateDescriptor, _EvidenceIdentity, _HeldFile, _raise_cleanup_issues, open_managed_inputs,\n'
            b'    open_regular_inputs, open_standalone_inputs,\n'
            b')\n'
            b'from ibsw_upgrade_component import render_declared_step, _scp_download_pair as _SCP_DOWNLOAD_PAIR\n'
            b'# Trusted-driver-import code/object anchor for graph-only DATA parsing. The\n'
            b'# later live producer audit still independently holds/compiles the full source.\n'
            b'_SCP_DOWNLOAD_PAIR_IMAGE = (_SCP_DOWNLOAD_PAIR, _SCP_DOWNLOAD_PAIR.__code__,\n'
            b'                            _SCP_DOWNLOAD_PAIR.__globals__)\n'
            b'from ibsw_upgrade_schedule import (declared_step_key, component_order, COMPONENT_REGISTRY,\n'
            b'    component_status_document, validate_component_status_document,\n'
            b'    native_component_status_document, validate_native_component_status_document)\n'
        ), 0),
        # hunk2: old124B/fb137f901b950f767d362f32e554e9f6ba610da8bb03c0f52d711bc906b58e23, new3673B/3a59f9261ce300b80c536bd4dffc1345d8a5e3c6cc77c8de1c9070e42c7170ac
        (2, 29442, 29777,
(
            b'        raw_lines_base64=base64.b64encode(lines).decode(\'ascii\'),measurement=rows[-1])\n'
            b'\n'
            b'\n'
            b'_MAX_COMPONENT_RAW_RECORDS = 512\n'
            b'\n'
            b'\n'
        ),
(
            b'        raw_lines_base64=base64.b64encode(lines).decode(\'ascii\'),measurement=rows[-1])\n'
            b'\n'
            b'\n'
            b'def _scp_download_document(binding, dispatch_payload, read, lines):\n'
            b'    """Strict SCP measurement DATA; never infer a live owner from saved JSON."""\n'
            b'    from types import FunctionType\n'
            b'    image = _SCP_DOWNLOAD_PAIR_IMAGE\n'
            b'    if (type(image) is not tuple or len(image) != 3 or type(image[0]) is not FunctionType\n'
            b'            or _SCP_DOWNLOAD_PAIR is not image[0] or image[0].__code__ is not image[1]\n'
            b'            or image[0].__globals__ is not image[2] or image[0].__defaults__ is not None\n'
            b'            or image[0].__kwdefaults__ is not None or image[0].__closure__ is not None\n'
            b'            or image[2].get(\'_scp_download_pair\') is not image[0]\n'
            b'            or image[2].get(\'re\') is not re or image[2].get(\'math\') is not math):\n'
            b'        raise ValueError(\'original imported SCP DATA parser changed\')\n'
            b'    if type(binding) is not dict or binding.get(\'component\') != \'os\':\n'
            b'        raise ValueError(\'only original OS SCP measurement DATA\')\n'
            b'    names = {\'request.json\', \'step.sh\', \'step-binding.json\', \'runner.sh\',\n'
            b'             \'runner-binding.json\', \'scp-source-request.json\'}\n'
            b'    _validate_scp_request_content_graph(names, binding, read)\n'
            b'    if read(\'step-binding.json\') != _json_bytes(binding):\n'
            b'        raise ValueError(\'original SCP step binding bytes required\')\n'
            b'    request_payload = read(\'request.json\')\n'
            b'    companion_payload = read(\'scp-source-request.json\')\n'
            b'    companion = json.loads(companion_payload)\n'
            b'    dispatch = json.loads(dispatch_payload)\n'
            b'    if (type(dispatch) is not dict or dispatch.get(\'schema_version\') != 2\n'
            b'            or dispatch.get(\'state\') != \'COMPONENT_DISPATCH_DATA_ONLY\'\n'
            b'            or dispatch.get(\'launch_kind\') != \'SCP_STDIN_OWNED_RUNNER_V2\'\n'
            b'            or dispatch.get(\'binding\') != binding\n'
            b'            or dispatch.get(\'request_sha256\') != hashlib.sha256(request_payload).hexdigest()\n'
            b'            or dispatch.get(\'scp_companion_sha256\') != hashlib.sha256(companion_payload).hexdigest()\n'
            b'            or len(companion[\'packages\']) != 1):\n'
            b'        raise ValueError(\'original SCP dispatch/request/companion required\')\n'
            b'    path, package = next(iter(companion[\'packages\'].items()))\n'
            b'    expected = dict(binding_sha256=hashlib.sha256(read(\'step-binding.json\')).hexdigest(),\n'
            b'                    path=path, size=package[\'size\'], sha256=package[\'sha256\'])\n'
            b'    if (type(lines) is not bytes or len(lines) > 4096 or not lines.endswith(b\'\\n\')\n'
            b'            or lines.count(b\'\\n\') != 2 or b\'\\r\' in lines):\n'
            b'        raise ValueError(\'exact original SCP measurement packet required\')\n'
            b'    first, second, _tail = lines.split(b\'\\n\')\n'
            b'    if first.startswith(b\'IBSW_SCP_CONTENT_VERIFIED=\'):\n'
            b'        marker, numeric = first, second\n'
            b'    else:\n'
            b'        marker, numeric = second, first\n'
            b'    parsed, content = image[0](marker, numeric)\n'
            b'    if content != (expected[\'binding_sha256\'], path, package[\'size\'], package[\'sha256\']):\n'
            b'        raise ValueError(\'original SCP measurement content differs from companion\')\n'
            b'    measurement = dict(parsed)\n'
            b'    measurement[\'content_marker\'] = parsed[\'content_marker\'].decode(\'ascii\')\n'
            b'    measurement[\'raw_line\'] = parsed[\'raw_line\'].decode(\'ascii\')\n'
            b'    return dict(schema_version=2, state=\'SCP_DOWNLOAD_MEASUREMENT_DATA_ONLY\',\n'
            b'        binding=binding, dispatch_sha256=hashlib.sha256(dispatch_payload).hexdigest(),\n'
            b'        request_sha256=hashlib.sha256(request_payload).hexdigest(),\n'
            b'        companion_sha256=hashlib.sha256(companion_payload).hexdigest(),\n'
            b'        content_marker_sha256=hashlib.sha256(parsed[\'content_marker\']).hexdigest(),\n'
            b'        raw_lines_base64=base64.b64encode(lines).decode(\'ascii\'), measurement=measurement)\n'
            b'\n'
            b'\n'
            b'_MAX_COMPONENT_RAW_RECORDS = 512\n'
            b'\n'
            b'\n'
        ), 0),
        # hunk3: old655B/a647c57d1d5071cc1943e756c424a704bf045710d1b4ce9bc8f0b16a2409ebc6, new777B/3e0998cb0c782015bea97f6ac5dde81be5aa40b781c6962404876e512ae02076
        (3, 45237, 49121,
(
            b'            if (set(document) != {\'schema_version\', \'state\', \'binding\', \'request_sha256\',\n'
            b'                    \'remote_script\', \'records\', \'launch_kind\', \'runner_binding_sha256\', \'scp_companion_sha256\'}\n'
            b'                    or document.get(\'state\') != \'COMPONENT_DISPATCH_DATA_ONLY\'\n'
            b'                    or binding[\'component\'] != \'cpld\' or \'scp-source-request.json\' not in files\n'
            b'                    or \'package-source.json\' in files\n'
            b'                    or document.get(\'scp_companion_sha256\') != hashlib.sha256(read(\'scp-source-request.json\')).hexdigest()\n'
            b'                    or posixpath.dirname(posixpath.dirname(document[\'remote_script\'])) != switch_dir\n'
        ),
(
            b'            if (set(document) != {\'schema_version\', \'state\', \'binding\', \'request_sha256\',\n'
            b'                    \'remote_script\', \'records\', \'launch_kind\', \'runner_binding_sha256\', \'scp_companion_sha256\'}\n'
            b'                    or document.get(\'state\') != \'COMPONENT_DISPATCH_DATA_ONLY\'\n'
            b'                    or binding[\'component\'] not in (\'os\', \'cpld\')\n'
            b'                    or (binding[\'component\'] == \'cpld\' and binding[\'package_index\'] != 0)\n'
            b'                    or \'scp-source-request.json\' not in files\n'
            b'                    or \'package-source.json\' in files\n'
            b'                    or document.get(\'scp_companion_sha256\') != hashlib.sha256(read(\'scp-source-request.json\')).hexdigest()\n'
            b'                    or posixpath.dirname(posixpath.dirname(document[\'remote_script\'])) != switch_dir\n'
        ), 0),
        # hunk4: old643B/2b0229a3ecdcfa5c6b5d689a8439d205a3dc5d3349c5bd2fa11fd12903d7938e, new1019B/0de437c49dc63a9c83deda04a1483a0216ebae993253b945046cf909b2ec7446
        (4, 47200, 51206,
(
            b'    for name in sorted(files & _DOWNLOAD_FILES):\n'
            b'        document=json.loads(read(name))\n'
            b'        number=int(name[len(\'download-attempt-\'):-len(\'.json\')])\n'
            b'        if (\'component-dispatch.json\' not in files or document!=_download_document(binding,\n'
            b'                read(\'component-dispatch.json\'),base64.b64decode(document[\'raw_lines_base64\'],validate=True))\n'
            b'                or document[\'measurement\'][\'attempt\']!=number\n'
            b'                or any(f\'download-attempt-{i:02d}.json\' not in files for i in range(1,number))):\n'
            b'            raise ValueError(\'original download measurement graph changed\')\n'
            b'    for name in sorted(files & _NVUED_CHECK_FILES):\n'
        ),
(
            b'    for name in sorted(files & _DOWNLOAD_FILES):\n'
            b'        document=json.loads(read(name))\n'
            b'        number=int(name[len(\'download-attempt-\'):-len(\'.json\')])\n'
            b'        if \'component-dispatch.json\' not in files:\n'
            b'            raise ValueError(\'original download measurement graph changed\')\n'
            b'        lines = base64.b64decode(document[\'raw_lines_base64\'], validate=True)\n'
            b'        if \'scp-source-request.json\' in files:\n'
            b'            expected_download = _scp_download_document(binding,\n'
            b'                read(\'component-dispatch.json\'), read, lines)\n'
            b'        else:\n'
            b'            expected_download = _download_document(binding, read(\'component-dispatch.json\'), lines)\n'
            b'        if (\'component-dispatch.json\' not in files or document != expected_download\n'
            b'                or document[\'measurement\'][\'attempt\'] != number\n'
            b'                or any(f\'download-attempt-{i:02d}.json\' not in files for i in range(1,number))):\n'
            b'            raise ValueError(\'original download measurement graph changed\')\n'
            b'    for name in sorted(files & _NVUED_CHECK_FILES):\n'
        ), 0),
        # hunk5: old415B/bc349786ccb427ffc7b555145ecd75b800b49b24098fb20a21e52e265cfbf0de, new439B/db462ade871c505c882e0de7036bc3d26c8fcbe902b49ab2f76a493b70ab0e20
        (5, 139518, 143900,
(
            b'        scope.verify(); group.verify()\n'
            b'        if (not group.manual_execution or group.parsed.method != \'scp\' or group.closed\n'
            b'                or not group._package_source_owns or group._package_source_owner is None\n'
            b'                or \'cpld\' not in group.parsed.selected):\n'
            b'            refuse()\n'
            b'        source19, probe32 = _fixed_scp_source_api(group, probe=True)\n'
            b'        original_binding = group._scp_source_binding\n'
        ),
(
            b'        scope.verify(); group.verify()\n'
            b'        if (not group.manual_execution or group.parsed.method != \'scp\' or group.closed\n'
            b'                or not group._package_source_owns or group._package_source_owner is None\n'
            b'                or not set(group.parsed.selected).intersection((\'os\', \'cpld\'))):\n'
            b'            refuse()\n'
            b'        source19, probe32 = _fixed_scp_source_api(group, probe=True)\n'
            b'        original_binding = group._scp_source_binding\n'
        ), 0),
        # hunk6: old504B/331b0d32425c345b2f61d88a90711f1d9fe162b9d1c85a71c3068d783a52a622, new5994B/6b539848e69bc9b78bffa2adf0ee860476e59db3032a78aa9af1cf03ffe9c5e1
        (6, 144230, 148636,
(
            b'        wrapper = function(vars(_PreparedRunScope).get(\'_launch_native_scp_cpld\'),\n'
            b'            unique_code(class_code, \'_launch_native_scp_cpld\'), d, __name__,\n'
            b'            qualname=\'_PreparedRunScope._launch_native_scp_cpld\')\n'
            b'        capture = function(d.get(\'_capture_native_scp_cpld_bootstrap\'),\n'
            b'            unique_code(images[Path(__file__).name][2], \'_capture_native_scp_cpld_bootstrap\'), d, __name__)\n'
            b'        if (d.get(\'render_declared_step\') is not declared or c.get(\'_fixed_layout\') is not layout\n'
        ),
(
            b'        wrapper = function(vars(_PreparedRunScope).get(\'_launch_native_scp_cpld\'),\n'
            b'            unique_code(class_code, \'_launch_native_scp_cpld\'), d, __name__,\n'
            b'            qualname=\'_PreparedRunScope._launch_native_scp_cpld\')\n'
            b'        # Finite OS measurement/manager callees. Original launch_refs[0:25]\n'
            b'        # retain their meaning; these are actual objects from the held compiled\n'
            b'        # images, not matching names or caller-supplied callbacks.\n'
            b'        def driver_method(name):\n'
            b'            return function(vars(_PreparedRunScope).get(name), unique_code(class_code, name),\n'
            b'                d, __name__, qualname=\'_PreparedRunScope.\' + name)\n'
            b'        packet_pair = function(c.get(\'_scp_download_pair\'),\n'
            b'            unique_code(component_code, \'_scp_download_pair\'), c, \'ibsw_upgrade_component\')\n'
            b'        packet_parser = function(c.get(\'parse_scp_download_results\'),\n'
            b'            unique_code(component_code, \'parse_scp_download_results\'), c, \'ibsw_upgrade_component\')\n'
            b'        scp_ack = function(c.get(\'scp_download_ack_bytes\'),\n'
            b'            unique_code(component_code, \'scp_download_ack_bytes\'), c, \'ibsw_upgrade_component\')\n'
            b'        executor_code = images[\'ibsw_upgrade_executor.py\'][2]\n'
            b'        extractor = function(e.get(\'_scp_download_packet\'),\n'
            b'            unique_code(executor_code, \'_scp_download_packet\'), e, \'ibsw_upgrade_executor\')\n'
            b'        driver_code = images[Path(__file__).name][2]\n'
            b'        measurement_document = function(d.get(\'_scp_download_document\'),\n'
            b'            unique_code(driver_code, \'_scp_download_document\'), d, __name__)\n'
            b'        measurement_inputs = driver_method(\'_scp_download_inputs_locked\')\n'
            b'        measurement_record = driver_method(\'_record_scp_download_attempt\')\n'
            b'        record_entry = driver_method(\'_record_download_attempt\')\n'
            b'        component_graph = function(d.get(\'_validate_component_graph\'),\n'
            b'            unique_code(driver_code, \'_validate_component_graph\'), d, __name__)\n'
            b'        scp_graph = function(d.get(\'_validate_scp_request_content_graph\'),\n'
            b'            unique_code(driver_code, \'_validate_scp_request_content_graph\'), d, __name__)\n'
            b'        commit = driver_method(\'_commit_exclusive_binding\')\n'
            b'        journal_writer, output_scope = d.get(\'_JournalWriter\'), d.get(\'_OutputScope\')\n'
            b'        if (type(journal_writer) is not type or type(output_scope) is not type\n'
            b'                or journal_writer.__bases__ != (output_scope,) or output_scope.__bases__ != (object,)\n'
            b'                or not text(journal_writer.__module__, __name__)\n'
            b'                or not text(output_scope.__module__, __name__)\n'
            b'                or not text(journal_writer.__qualname__, \'_JournalWriter\')\n'
            b'                or not text(output_scope.__qualname__, \'_OutputScope\')\n'
            b'                or any(name in vars(journal_writer) for name in (\'__new__\', \'write\', \'close\'))\n'
            b'                or \'__new__\' in vars(output_scope)):\n'
            b'            refuse()\n'
            b'        writer_code = unique_code(driver_code, \'_JournalWriter\')\n'
            b'        output_code = unique_code(driver_code, \'_OutputScope\')\n'
            b'        writer_init = function(vars(journal_writer).get(\'__init__\'),\n'
            b'            unique_code(writer_code, \'__init__\'), d, __name__, qualname=\'_JournalWriter.__init__\')\n'
            b'        writer_verify = function(vars(journal_writer).get(\'verify\'),\n'
            b'            unique_code(writer_code, \'verify\'), d, __name__,\n'
            b'            qualname=\'_JournalWriter.verify\', cells=(journal_writer,))\n'
            b'        writer_finish = function(vars(journal_writer).get(\'finish\'),\n'
            b'            unique_code(writer_code, \'finish\'), d, __name__, qualname=\'_JournalWriter.finish\')\n'
            b'        output_write = function(vars(output_scope).get(\'write\'),\n'
            b'            unique_code(output_code, \'write\'), d, __name__, qualname=\'_OutputScope.write\')\n'
            b'        output_verify = function(vars(output_scope).get(\'verify\'),\n'
            b'            unique_code(output_code, \'verify\'), d, __name__, qualname=\'_OutputScope.verify\')\n'
            b'        output_close = function(vars(output_scope).get(\'close\'),\n'
            b'            unique_code(output_code, \'close\'), d, __name__, qualname=\'_OutputScope.close\')\n'
            b'        manager = function(e.get(\'_probe_component_exit_once\'),\n'
            b'            unique_code(executor_code, \'_probe_component_exit_once\'), e, \'ibsw_upgrade_executor\',\n'
            b'            keywords={\'_read_only\': False, \'_transport\': None})\n'
            b'        bound_consumer = function(e.get(\'_bound_component_postcondition_inputs\'),\n'
            b'            unique_code(executor_code, \'_bound_component_postcondition_inputs\'), e, \'ibsw_upgrade_executor\')\n'
            b'        log_reader = function(e.get(\'_read_component_log_prefix\'),\n'
            b'            unique_code(executor_code, \'_read_component_log_prefix\'), e, \'ibsw_upgrade_executor\')\n'
            b'        canonical_json = function(d.get(\'_json_bytes\'), unique_code(driver_code, \'_json_bytes\'), d, __name__)\n'
            b'        packet_image = d.get(\'_SCP_DOWNLOAD_PAIR_IMAGE\')\n'
            b'        if (type(packet_image) is not tuple or len(packet_image) != 3\n'
            b'                or packet_image[0] is not packet_pair or packet_image[1] is not packet_pair.__code__\n'
            b'                or packet_image[2] is not c or d.get(\'_SCP_DOWNLOAD_PAIR\') is not packet_pair\n'
            b'                or c.get(\'math\') is not math or e.get(\'json\') is not json\n'
            b'                or e.get(\'base64\') is not base64 or e.get(\'hashlib\') is not hashlib\n'
            b'                or e.get(\'_NativeObservationHold\') is not probe32[9]\n'
            b'                or e.get(\'SharedUpgradeHold\') is not SharedUpgradeHold):\n'
            b'            refuse()\n'
            b'        os_refs = (packet_pair, packet_parser, scp_ack, extractor, measurement_document,\n'
            b'            measurement_inputs, measurement_record, record_entry, component_graph, scp_graph, commit,\n'
            b'            journal_writer, output_scope, writer_init, writer_verify, writer_finish,\n'
            b'            output_write, output_verify, output_close, manager, bound_consumer, log_reader, canonical_json,\n'
            b'            packet_image)\n'
            b'        capture = function(d.get(\'_capture_native_scp_cpld_bootstrap\'),\n'
            b'            unique_code(images[Path(__file__).name][2], \'_capture_native_scp_cpld_bootstrap\'), d, __name__)\n'
            b'        if (d.get(\'render_declared_step\') is not declared or c.get(\'_fixed_layout\') is not layout\n'
        ), 0),
        # hunk7: old580B/e7334e65d8916d9bd251d8cacc47cb46c965439af81406b77780f4e3e83525bc, new590B/5a76ba402b3bc561307f6fd94a38b87bd01864214bd4ecf905cb9acc9c5b5862
        (7, 152689, 162585,
(
            b'        launch_refs = (command, launcher, context, wrapper, probe32[3], provider, component, executor, contract,\n'
            b'            render, declared, validate, url, rendered, init, runner, layout,\n'
            b'            actual_paths[0], actual_paths[1], probe32[2], probe32[4], bootstrap,\n'
            b'            members[\'__dataclass_params__\'], members[\'__dataclass_fields__\'], capture)\n'
            b'        current19, current32 = _fixed_scp_source_api(group, probe=True)\n'
            b'        if (len(current19) != len(source19) or len(current32) != len(probe32)\n'
            b'                or any(a is not b for a, b in zip(source19, current19))\n'
        ),
(
            b'        launch_refs = (command, launcher, context, wrapper, probe32[3], provider, component, executor, contract,\n'
            b'            render, declared, validate, url, rendered, init, runner, layout,\n'
            b'            actual_paths[0], actual_paths[1], probe32[2], probe32[4], bootstrap,\n'
            b'            members[\'__dataclass_params__\'], members[\'__dataclass_fields__\'], capture) + os_refs\n'
            b'        current19, current32 = _fixed_scp_source_api(group, probe=True)\n'
            b'        if (len(current19) != len(source19) or len(current32) != len(probe32)\n'
            b'                or any(a is not b for a, b in zip(source19, current19))\n'
        ), 0),
        # hunk8: old325B/9bf6fe939a54a9c6ab3bc11ddc63f325179bcc2660d6a8cb61b1d299067f3a8b, new2662B/8985df377fc275d8a522c98113e9edd7a2983ed500ffe20a5a9d8c9934a1ccb4
        (8, 157167, 167073,
(
            b'                    or field._field_type is not dataclasses._FIELD or field.metadata is not dataclasses._EMPTY_METADATA\n'
            b'                    or model == (3, 12) and field.kw_only is not False):\n'
            b'                refuse()\n'
            b'        result = source19, probe32, launch_refs\n'
            b'    except BaseException as error:\n'
            b'        primary = error\n'
        ),
(
            b'                    or field._field_type is not dataclasses._FIELD or field.metadata is not dataclasses._EMPTY_METADATA\n'
            b'                    or model == (3, 12) and field.kw_only is not False):\n'
            b'                refuse()\n'
            b'        for namespace, name, value in (\n'
            b'                (c, \'_scp_download_pair\', packet_pair), (c, \'parse_scp_download_results\', packet_parser),\n'
            b'                (c, \'scp_download_ack_bytes\', scp_ack), (e, \'_scp_download_packet\', extractor),\n'
            b'                (d, \'_scp_download_document\', measurement_document),\n'
            b'                (d, \'_validate_component_graph\', component_graph),\n'
            b'                (d, \'_validate_scp_request_content_graph\', scp_graph), (d, \'_json_bytes\', canonical_json),\n'
            b'                (d, \'_JournalWriter\', journal_writer), (d, \'_OutputScope\', output_scope),\n'
            b'                (e, \'_probe_component_exit_once\', manager),\n'
            b'                (e, \'_bound_component_postcondition_inputs\', bound_consumer),\n'
            b'                (e, \'_read_component_log_prefix\', log_reader)):\n'
            b'            if namespace.get(name) is not value:\n'
            b'                refuse()\n'
            b'        for name, value in ((\'_scp_download_inputs_locked\', measurement_inputs),\n'
            b'                (\'_record_scp_download_attempt\', measurement_record), (\'_record_download_attempt\', record_entry),\n'
            b'                (\'_commit_exclusive_binding\', commit)):\n'
            b'            if vars(_PreparedRunScope).get(name) is not value:\n'
            b'                refuse()\n'
            b'        for cls, name, value in ((journal_writer, \'__init__\', writer_init),\n'
            b'                (journal_writer, \'verify\', writer_verify), (journal_writer, \'finish\', writer_finish),\n'
            b'                (output_scope, \'write\', output_write), (output_scope, \'verify\', output_verify),\n'
            b'                (output_scope, \'close\', output_close)):\n'
            b'            if vars(cls).get(name) is not value:\n'
            b'                refuse()\n'
            b'        if (journal_writer.__bases__ != (output_scope,) or output_scope.__bases__ != (object,)\n'
            b'                or any(name in vars(journal_writer) for name in (\'__new__\', \'write\', \'close\'))\n'
            b'                or \'__new__\' in vars(output_scope)\n'
            b'                or d.get(\'_SCP_DOWNLOAD_PAIR_IMAGE\') is not packet_image\n'
            b'                or d.get(\'_SCP_DOWNLOAD_PAIR\') is not packet_pair\n'
            b'                or packet_pair.__code__ is not packet_image[1] or packet_pair.__globals__ is not packet_image[2]\n'
            b'                or c.get(\'math\') is not math\n'
            b'                or e.get(\'json\') is not json or e.get(\'base64\') is not base64\n'
            b'                or e.get(\'hashlib\') is not hashlib or e.get(\'_NativeObservationHold\') is not probe32[9]):\n'
            b'            refuse()\n'
            b'        result = source19, probe32, launch_refs\n'
            b'    except BaseException as error:\n'
            b'        primary = error\n'
        ), 0),
        # hunk9: old375B/93c16831bfabd4899753d1306b91b15ed44ae4ae09cfdb471c940e2ab21fea71, new384B/ede91a8b472b4e48865895a9e9cc41b8188669da1e96cf8e1671342dc5fbffaa
        (9, 188132, 200375,
(
            b'            raise SharedUpgradeHold(\'original native SCP context DATA could not be verified\') from None\n'
            b'\n'
            b'    def _launch_native_scp_cpld(self, leaf, component, package_index, transport, deadline):\n'
            b'        """One fixed native CPLD stdin launch; never accepts caller wire DATA."""\n'
            b'        primary = None\n'
            b'        channel = None\n'
            b'        source = joint = payload = command = None\n'
        ),
(
            b'            raise SharedUpgradeHold(\'original native SCP context DATA could not be verified\') from None\n'
            b'\n'
            b'    def _launch_native_scp_cpld(self, leaf, component, package_index, transport, deadline):\n'
            b'        """Fixed native CPLD/index0 or actual selected OS stdin launch; no caller wire."""\n'
            b'        primary = None\n'
            b'        channel = None\n'
            b'        source = joint = payload = command = None\n'
        ), 0),
        # hunk10: old589B/d9346dac1c466b101a7806ea4a27ddadabd7e29542134d0c85b146d336ef2e1e, new744B/feb2fd7e0dcbfbb7d950f2cb2a4e638b4b407be30271e6c042370b11e6285643
        (10, 193425, 205677,
(
            b'        try:\n'
            b'            if (type(self) is not _PreparedRunScope or type(parent) is not _PreparedRunScope\n'
            b'                    or type(leaf) is not _ReadonlyQueryInputs\n'
            b'                    or type(component) is not str or component != \'cpld\'\n'
            b'                    or type(package_index) is not int or package_index != 0\n'
            b'                    or self.parsed.method != \'scp\' or self._active_request_lease is None\n'
            b'                    or type(deadline) not in (int, float) or not math.isfinite(deadline)):\n'
            b'                raise SharedUpgradeHold(\'original native CPLD launch scope/lease required\')\n'
        ),
(
            b'        try:\n'
            b'            if (type(self) is not _PreparedRunScope or type(parent) is not _PreparedRunScope\n'
            b'                    or type(leaf) is not _ReadonlyQueryInputs\n'
            b'                    or type(component) is not str or component not in (\'os\', \'cpld\')\n'
            b'                    or type(package_index) is not int\n'
            b'                    or (component == \'cpld\' and package_index != 0)\n'
            b'                    or (component == \'os\' and package_index not in self._native_package_indices)\n'
            b'                    or self.parsed.method != \'scp\' or self._active_request_lease is None\n'
            b'                    or type(deadline) not in (int, float) or not math.isfinite(deadline)):\n'
            b'                raise SharedUpgradeHold(\'original native CPLD launch scope/lease required\')\n'
        ), 0),
        # hunk11: old446B/2593c6401d6ab6e60076ac870b018e4a8ecc7e151d175c869341f3b8363ad22d, new548B/41bca89b8d91ca5aee6f3d1688d6cb867b2fb9849c663041776ec29d7393e05f
        (11, 290157, 302564,
(
            b'            rows = _component_raw_records(records)\n'
            b'            scp_companion = None\n'
            b'            if self.parsed.method == \'scp\':\n'
            b'                if component != \'cpld\':\n'
            b'                    raise ValueError(\'only original native CPLD has an SCP dispatch backend\')\n'
            b'                parent = self._native_parent\n'
            b'                self._native_scp_source(leaf, component, data[\'package_index\'])\n'
            b'                joint = _fixed_native_scp_cpld_api(parent)\n'
        ),
(
            b'            rows = _component_raw_records(records)\n'
            b'            scp_companion = None\n'
            b'            if self.parsed.method == \'scp\':\n'
            b'                if (component not in (\'os\', \'cpld\')\n'
            b'                        or (component == \'cpld\' and data[\'package_index\'] != 0)):\n'
            b'                    raise ValueError(\'only original selected OS or CPLD has an SCP dispatch backend\')\n'
            b'                parent = self._native_parent\n'
            b'                self._native_scp_source(leaf, component, data[\'package_index\'])\n'
            b'                joint = _fixed_native_scp_cpld_api(parent)\n'
        ), 0),
        # hunk12: old315B/b55b90cd00dd36838c3f0aadc45fd1218c15091e0b7a89dcfe278c6b99b140d7, new10625B/8155ce6736184302fd61df253af8051bf7de9972087bc67c21fcc54562d66d48
        (12, 301874, 314383,
(
            b'                leaf.verify()\n'
            b'        except Exception as error:\n'
            b'            raise SharedUpgradeHold(\'OS route evidence could not be recorded; no following task\') from error\n'
            b'\n'
            b'    def _record_download_attempt(self,leaf,dispatch,rows):\n'
            b'        """Durably save original pre-reboot numeric telemetry before remote ACK.\n'
        ),
(
            b'                leaf.verify()\n'
            b'        except Exception as error:\n'
            b'            raise SharedUpgradeHold(\'OS route evidence could not be recorded; no following task\') from error\n'
            b'\n'
            b'    def _scp_download_inputs_locked(self, leaf, dispatch):\n'
            b'        """Same live OS parent/lease/seven originals; returned DATA is no permit."""\n'
            b'        group = self\n'
            b'        try:\n'
            b'            for candidate in (getattr(self, \'_native_parent\', None),\n'
            b'                              getattr(self, \'_package_source_parent\', None)):\n'
            b'                if (type(candidate) is _PreparedRunScope and candidate is not self\n'
            b'                        and type(candidate._package_source_borrowers) is set\n'
            b'                        and self in candidate._package_source_borrowers):\n'
            b'                    group = candidate\n'
            b'                    break\n'
            b'            lease = self._active_request_lease\n'
            b'            if (type(self) is not _PreparedRunScope or group is self\n'
            b'                    or type(lease) is not _ManualJournalTransaction or not self.manual_execution\n'
            b'                    or self.parsed.method != \'scp\' or type(dispatch) is not ComponentDispatchResult\n'
            b'                    or dispatch.component != \'os\' or dispatch.state != \'DISPATCHED_UNKNOWN\'\n'
            b'                    or type(leaf) is not _ReadonlyQueryInputs or leaf.scope is not self\n'
            b'                    or not getattr(leaf, \'_cooperative_completion\', False)\n'
            b'                    or dispatch.hostname != leaf.node.hostname):\n'
            b'                raise SharedUpgradeHold(\'original leased native SCP OS measurement scope required\')\n'
            b'            lease.verify()\n'
            b'            source = self._native_scp_source(leaf, \'os\', dispatch.package_index)\n'
            b'            joint = _fixed_native_scp_cpld_api(group)\n'
            b'            stage_name = declared_step_key(self.policy, \'os\', dispatch.package_index)\n'
            b'            if dispatch.stage != stage_name:\n'
            b'                raise SharedUpgradeHold(\'original native SCP OS measurement stage changed\')\n'
            b'            stage_path = self.run_directory / leaf.node.hostname / stage_name\n'
            b'            directory = self.session._directories.get(str(stage_path))\n'
            b'            if directory is None:\n'
            b'                raise SharedUpgradeHold(\'original native SCP OS stage is not held\')\n'
            b'            self._private_directory(directory)\n'
            b'            names = (\'request.json\', \'step.sh\', \'step-binding.json\', \'runner.sh\',\n'
            b'                     \'runner-binding.json\', \'scp-source-request.json\', \'component-dispatch.json\')\n'
            b'            originals = tuple(self.files.get((str(stage_path), name)) for name in names)\n'
            b'            if any(type(obj) is not _HeldFile or obj.directory is not directory\n'
            b'                   or obj.name != name or obj.cleanup_issues for name, obj in zip(names, originals)):\n'
            b'                raise SharedUpgradeHold(\'complete original native SCP OS measurement files required\')\n'
            b'            for obj in originals:\n'
            b'                obj.verify()\n'
            b'            values = joint[2][45](leaf, dispatch)\n'
            b'            if values[0] is not self or values[1] is not directory:\n'
            b'                raise SharedUpgradeHold(\'original native SCP bound consumer changed\')\n'
            b'            binding = values[2]\n'
            b'            if originals[2].payload != _json_bytes(binding):\n'
            b'                raise SharedUpgradeHold(\'original native SCP measurement binding changed\')\n'
            b'            joint[2][34](set(names), binding,\n'
            b'                         lambda name: self.files[(str(stage_path), name)].payload)\n'
            b'            companion = json.loads(originals[5].payload)\n'
            b'            owner = group._package_source_owner\n'
            b'            self._verify_package_source_owner()\n'
            b'            packages = self._package_source_packages(\'os\', dispatch.package_index)\n'
            b'            if len(packages) != 1 or type(companion[\'packages\']) is not dict:\n'
            b'                raise SharedUpgradeHold(\'one actual selected native SCP OS package required\')\n'
            b'            package = packages[0]\n'
            b'            row = owner._files.get(Path(package.path))\n'
            b'            if (type(row) is not tuple or len(row) != 5\n'
            b'                    or type(row[3]) is not tuple or len(row[3]) != 9\n'
            b'                    or type(row[3][6]) is not int or not 0 < row[3][6] < 2**63\n'
            b'                    or type(row[4]) is not str or re.fullmatch(\'[0-9a-f]{64}\', row[4]) is None\n'
            b'                    or companion[\'packages\'] != {package.path: dict(size=row[3][6], sha256=row[4])}):\n'
            b'                raise SharedUpgradeHold(\'native SCP measurement companion differs from original package\')\n'
            b'            expected = dict(binding_sha256=hashlib.sha256(originals[2].payload).hexdigest(),\n'
            b'                            path=package.path, size=row[3][6], sha256=row[4])\n'
            b'            if self._native_scp_source(leaf, \'os\', dispatch.package_index) is not source:\n'
            b'                raise SharedUpgradeHold(\'original native SCP measurement source changed at tail\')\n'
            b'            current = _fixed_native_scp_cpld_api(group)\n'
            b'            if (any(len(a) != len(b) or any(x is not y for x, y in zip(a, b))\n'
            b'                    for a, b in zip(joint, current))\n'
            b'                    or self._active_request_lease is not lease or self._native_parent is not group\n'
            b'                    or self._package_source_owner is not owner or group._package_source_owner is not owner\n'
            b'                    or owner._files.get(Path(package.path)) is not row\n'
            b'                    or self.session._directories.get(str(stage_path)) is not directory):\n'
            b'                raise SharedUpgradeHold(\'original native SCP measurement owners changed at tail\')\n'
            b'            lease.verify()\n'
            b'            for name, obj in zip(names, originals):\n'
            b'                if self.files.get((str(stage_path), name)) is not obj:\n'
            b'                    raise SharedUpgradeHold(\'original native SCP measurement file owner changed\')\n'
            b'                obj.verify()\n'
            b'            self.verify(); leaf.verify(); group.verify()\n'
            b'            return directory, binding, expected, originals, source, owner, lease, joint, group\n'
            b'        except BaseException as error:\n'
            b'            if (type(group) is _PreparedRunScope\n'
            b'                    and group._package_source_lifecycle_failure is None):\n'
            b'                group._package_source_lifecycle_failure = SharedUpgradeHold(\n'
            b'                    \'original native SCP OS measurement inputs uncertain; group retained\')\n'
            b'            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):\n'
            b'                raise\n'
            b'            raise SharedUpgradeHold(\'original native SCP OS measurement inputs unavailable\') from None\n'
            b'\n'
            b'    def _record_scp_download_attempt(self, leaf, dispatch, rows):\n'
            b'        """Record one strict original SCP pair; critical finish precedes return."""\n'
            b'        group = self\n'
            b'        try:\n'
            b'            for candidate in (getattr(self, \'_native_parent\', None),\n'
            b'                              getattr(self, \'_package_source_parent\', None)):\n'
            b'                if (type(candidate) is _PreparedRunScope and candidate is not self\n'
            b'                        and type(candidate._package_source_borrowers) is set\n'
            b'                        and self in candidate._package_source_borrowers):\n'
            b'                    group = candidate\n'
            b'                    break\n'
            b'            record = None\n'
            b'            with self._request_namespace_lease():\n'
            b'                joint = _fixed_native_scp_cpld_api(group)\n'
            b'                inputs = joint[2][30](self, leaf, dispatch)\n'
            b'                directory, binding, expected, originals, source, owner, lease, _joint, parent = inputs\n'
            b'                if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict\n'
            b'                        or type(rows[0].get(\'content_marker\')) is not bytes\n'
            b'                        or type(rows[0].get(\'raw_line\')) is not bytes):\n'
            b'                    raise SharedUpgradeHold(\'one complete original SCP measurement pair required\')\n'
            b'                packet = rows[0][\'content_marker\'] + b\'\\n\' + rows[0][\'raw_line\'] + b\'\\n\'\n'
            b'                parsed = joint[2][26](packet, expected)\n'
            b'                if parsed != rows[0]:\n'
            b'                    raise SharedUpgradeHold(\'foreign SCP measurement DATA\')\n'
            b'                read = lambda name: self._hold(directory, name).payload\n'
            b'                document = joint[2][29](binding, originals[6].payload, read, packet)\n'
            b'                payload = _json_bytes(document)\n'
            b'                name = \'download-attempt-01.json\'\n'
            b'                if name in os.listdir(directory.fd):\n'
            b'                    self._hold(directory, name, payload)\n'
            b'                else:\n'
            b'                    if \'component-completion.json\' in os.listdir(directory.fd):\n'
            b'                        raise SharedUpgradeHold(\'SCP measurement cannot be appended after completion\')\n'
            b'                    joint[2][35](self, directory, payload, name)\n'
            b'                    record = dict(hostname=leaf.node.hostname, stage=dispatch.stage,\n'
            b'                        target_version=dispatch.target_version, measurement=document[\'measurement\'],\n'
            b'                        path=str(directory.path / name))\n'
            b'                # The actual original writer finally/finish has already returned.\n'
            b'                # This second derivation cannot adopt a replacement/new package row.\n'
            b'                after = joint[2][30](self, leaf, dispatch)\n'
            b'                if (after[0] is not directory or after[4] is not source or after[5] is not owner\n'
            b'                        or after[6] is not lease or after[8] is not parent\n'
            b'                        or after[2] != expected\n'
            b'                        or any(a is not b for a, b in zip(after[3], originals))):\n'
            b'                    raise SharedUpgradeHold(\'original SCP measurement owners changed after commit\')\n'
            b'                saved = self._hold(directory, name, payload)\n'
            b'                saved.verify(); leaf.verify()\n'
            b'            # All required record and lease cleanup succeeded before callbacks\n'
            b'            # or the observable _record_download_attempt return can occur.\n'
            b'            if record is not None:\n'
            b'                self._download_measurements = getattr(self, \'_download_measurements\', []) + [record]\n'
            b'                callback = getattr(self, \'_download_callback\', None)\n'
            b'                if callback:\n'
            b'                    callback(record)\n'
            b'            return None\n'
            b'        except BaseException as error:\n'
            b'            if (type(group) is _PreparedRunScope\n'
            b'                    and group._package_source_lifecycle_failure is None):\n'
            b'                group._package_source_lifecycle_failure = SharedUpgradeHold(\n'
            b'                    \'native SCP OS measurement commit uncertain; shared group retained\')\n'
            b'            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):\n'
            b'                raise\n'
            b'            raise SharedUpgradeHold(\'SCP OS measurement was not reliably committed; ACK withheld\') from error\n'
            b'\n'
            b'    def _record_download_attempt(self,leaf,dispatch,rows):\n'
            b'        """Durably save original pre-reboot numeric telemetry before remote ACK.\n'
        ), 0),
        # hunk13: old266B/9bbd207c8fc21fa0d7c41cd9b6eb9a7b23038da9eccbb628d382229d081f30ec, new893B/f55309c823d90b96ed4fe0ae8f41d87d5663d52d57c523b4098a41804ce61824
        (13, 302190, 325009,
(
            b'        Repeated polls may return identical measurements, never different bytes\n'
            b'        under an already committed attempt. No speed measurement admits success.\n'
            b'        """\n'
            b'        try:\n'
            b'            with self._request_namespace_lease():\n'
            b'                leaf.verify()\n'
        ),
(
            b'        Repeated polls may return identical measurements, never different bytes\n'
            b'        under an already committed attempt. No speed measurement admits success.\n'
            b'        """\n'
            b'        if self.parsed.method == \'scp\':\n'
            b'            parent = self\n'
            b'            for candidate in (getattr(self, \'_native_parent\', None),\n'
            b'                              getattr(self, \'_package_source_parent\', None)):\n'
            b'                if (type(candidate) is _PreparedRunScope and candidate is not self\n'
            b'                        and type(candidate._package_source_borrowers) is set\n'
            b'                        and self in candidate._package_source_borrowers):\n'
            b'                    parent = candidate\n'
            b'                    break\n'
            b'            joint = _fixed_native_scp_cpld_api(parent)\n'
            b'            return joint[2][31](self, leaf, dispatch, rows)\n'
            b'        try:\n'
            b'            with self._request_namespace_lease():\n'
            b'                leaf.verify()\n'
        ), 0),
    ),
    "tools/ibsw_upgrade_executor.py": (
        # hunk1: old524B/b692bc4e89061c2ed9434f48b0ae59a868e892192e178d84a4876c3d13279792, new532B/1e9dbd8776f01e677490244cce1fd04d2988ac914720c7acb409de492f630e10
        (1, 58414, 58414,
(
            b'            with _signed_session(leaf, password=password) as (transport, deadline, _identity, _auth, _pin):\n'
            b'                scope._preflight_native_scp_source(leaf, component, scope._native_package_indices[0],\n'
            b'                                                   transport, deadline)\n'
            b'        if args.method not in ("local", "http") and not (args.method == \'scp\' and component == \'cpld\'):\n'
            b'            raise SharedUpgradeHold("selected transport has no fixed real component backend")\n'
            b'    except SharedUpgradeHold:\n'
            b'        raise\n'
        ),
(
            b'            with _signed_session(leaf, password=password) as (transport, deadline, _identity, _auth, _pin):\n'
            b'                scope._preflight_native_scp_source(leaf, component, scope._native_package_indices[0],\n'
            b'                                                   transport, deadline)\n'
            b'        if args.method not in ("local", "http") and not (args.method == \'scp\' and component in (\'os\', \'cpld\')):\n'
            b'            raise SharedUpgradeHold("selected transport has no fixed real component backend")\n'
            b'    except SharedUpgradeHold:\n'
            b'        raise\n'
        ), 0),
        # hunk2: old589B/2afda40482a352348f9c9e876fb6ed0f71b7d84af44f66ca1a477f4b7004a99c, new721B/01158651fe7206384dcd6fccd0bf4c05dc185b17b78dd0c1cf9d10875f5911e3
        (2, 72371, 72379,
(
            b'            raise ValueError("original runner binding changed")\n'
            b'        if args.method == \'scp\':\n'
            b'            from ibsw_upgrade_driver import _fixed_native_scp_cpld_api, _validate_scp_request_content_graph\n'
            b'            if dispatch.component != \'cpld\' or document.get(\'launch_kind\') != \'SCP_STDIN_OWNED_RUNNER_V2\':\n'
            b'                raise ValueError(\'only original SCP CPLD V2 dispatch is supported\')\n'
            b'            source = scope._native_scp_source(leaf, dispatch.component, dispatch.package_index)\n'
            b'            parent = scope._native_parent\n'
            b'            joint = _fixed_native_scp_cpld_api(parent)\n'
        ),
(
            b'            raise ValueError("original runner binding changed")\n'
            b'        if args.method == \'scp\':\n'
            b'            from ibsw_upgrade_driver import _fixed_native_scp_cpld_api, _validate_scp_request_content_graph\n'
            b'            if (dispatch.component not in (\'os\', \'cpld\')\n'
            b'                    or (dispatch.component == \'cpld\' and dispatch.package_index != 0)\n'
            b'                    or document.get(\'launch_kind\') != \'SCP_STDIN_OWNED_RUNNER_V2\'):\n'
            b'                raise ValueError(\'only original selected SCP OS/CPLD V2 dispatch is supported\')\n'
            b'            source = scope._native_scp_source(leaf, dispatch.component, dispatch.package_index)\n'
            b'            parent = scope._native_parent\n'
            b'            joint = _fixed_native_scp_cpld_api(parent)\n'
        ), 0),
        # hunk3: old286B/23f517086270f2388b5a37207ce6d60526df834629ef85ee8df6c6f8fe92abcf, new2046B/24771c7e8de3be163ecef9d8375397f3698c1c9dc918dcb7c6f7aaf3368da1ac
        (3, 93612, 93752,
(
            b'                "evidence_paths": (leaf.node.hostname + "/" + dispatch.stage + "/component-dispatch.json",)}\n'
            b'\n'
            b'\n'
            b'def _probe_component_exit_once(leaf,dispatch,*,password,deadline,_read_only=False,_transport=None):\n'
            b'    """One original diagnostic/telemetry probe, never an installer retry.\n'
            b'\n'
        ),
(
            b'                "evidence_paths": (leaf.node.hostname + "/" + dispatch.stage + "/component-dispatch.json",)}\n'
            b'\n'
            b'\n'
            b'def _scp_download_packet(snippet):\n'
            b'    """Select all reserved public SCP records, never filter bad candidates."""\n'
            b'    if type(snippet) is not bytes or len(snippet) > 512 * 1024:\n'
            b'        raise ValueError(\'bounded original SCP log prefix required\')\n'
            b'    content = measurement = None\n'
            b'    for line in snippet.splitlines(keepends=True):\n'
            b'        if not line.startswith(b\'IBSW_SCP_\'):\n'
            b'            continue\n'
            b'        if not line.endswith(b\'\\n\'):\n'
            b'            return None  # Growing final candidate is never a complete fact.\n'
            b'        if b\'\\r\' in line:\n'
            b'            raise ValueError(\'malformed reserved SCP log candidate\')\n'
            b'        value = line[:-1]\n'
            b'        if value.startswith(b\'IBSW_SCP_CONTENT_VERIFIED=\'):\n'
            b'            if (content is not None or re.fullmatch(\n'
            b'                    rb\'IBSW_SCP_CONTENT_VERIFIED=1\\|[0-9a-f]{64}\\|[A-Za-z0-9_-]+\\|[1-9][0-9]{0,18}\\|[0-9a-f]{64}\',\n'
            b'                    value) is None):\n'
            b'                raise ValueError(\'duplicate or malformed SCP content candidate\')\n'
            b'            content = value\n'
            b'        elif value.startswith(b\'IBSW_SCP_DOWNLOAD_RESULT=\'):\n'
            b'            if (measurement is not None or re.fullmatch(\n'
            b'                    rb\'IBSW_SCP_DOWNLOAD_RESULT=1\\|[0-9]{1,20}\\|[0-9]{1,20}\\|0\\|0\\|[1-9][0-9]{0,18}\\|[0-9]{1,20}(?:\\.[0-9]{1,9})?\\|[0-9]{1,20}(?:\\.[0-9]{1,9})?\',\n'
            b'                    value) is None):\n'
            b'                raise ValueError(\'duplicate or malformed SCP measurement candidate\')\n'
            b'            measurement = value\n'
            b'        else:\n'
            b'            raise ValueError(\'unknown or failed reserved SCP log candidate\')\n'
            b'    if content is None or measurement is None:\n'
            b'        return None\n'
            b'    packet = content + b\'\\n\' + measurement + b\'\\n\'\n'
            b'    if len(packet) > 4096:\n'
            b'        raise ValueError(\'SCP download packet exceeded bound\')\n'
            b'    return packet\n'
            b'\n'
            b'\n'
            b'def _probe_component_exit_once(leaf,dispatch,*,password,deadline,_read_only=False,_transport=None):\n'
            b'    """One original diagnostic/telemetry probe, never an installer retry.\n'
            b'\n'
        ), 0),
        # hunk4: old538B/608b885d643d58447fb15d587803e0221292fffad6d103be7c4e309a3afdebb2, new7465B/3946f6e85e92c751c23a0e240509008c284b49a32551f661a24797e2821da49c
        (4, 97675, 99575,
(
            b'                        if observed!=getattr(leaf,\'_observed_component_stage\',None):\n'
            b'                            leaf._observed_component_stage=observed\n'
            b'                            _progress(leaf,dispatch.component,observed)\n'
            b'                    if dispatch.component==\'os\' and not getattr(leaf,\'_download_acknowledged\',False):\n'
            b'                        from ibsw_upgrade_component import parse_download_results,download_ack_bytes\n'
            b'                        measurements=parse_download_results(snippet)\n'
            b'                        if measurements:\n'
        ),
(
            b'                        if observed!=getattr(leaf,\'_observed_component_stage\',None):\n'
            b'                            leaf._observed_component_stage=observed\n'
            b'                            _progress(leaf,dispatch.component,observed)\n'
            b'                    if (dispatch.component == \'os\' and scope.parsed.method == \'scp\'\n'
            b'                            and not getattr(leaf, \'_download_acknowledged\', False)):\n'
            b'                        from ibsw_upgrade_driver import _fixed_native_scp_cpld_api\n'
            b'                        parent = scope._package_source_parent\n'
            b'                        joint = _fixed_native_scp_cpld_api(parent)\n'
            b'                        try:\n'
            b'                            packet = joint[2][28](snippet)\n'
            b'                        except ValueError:\n'
            b'                            raise _NativeObservationHold(reason_code=\'COMPONENT_EXIT_BINDING_INVALID\',\n'
            b'                                capture_raw={\'safe_diagnostic\': {\'code\': \'SCP_DOWNLOAD_CONTENT_INVALID\'}}) from None\n'
            b'                        if packet is not None:\n'
            b'                            peer_failure = None\n'
            b'                            try:\n'
            b'                                with scope._request_namespace_lease():\n'
            b'                                    inputs = joint[2][30](scope, leaf, dispatch)\n'
            b'                                    try:\n'
            b'                                        measurement = joint[2][26](packet, inputs[2])\n'
            b'                                    except ValueError as error:\n'
            b'                                        peer_failure = error\n'
            b'                            except BaseException as error:\n'
            b'                                if parent._package_source_lifecycle_failure is None:\n'
            b'                                    parent._package_source_lifecycle_failure = SharedUpgradeHold(\n'
            b'                                        \'native SCP measurement input cleanup uncertain; group retained\')\n'
            b'                                if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):\n'
            b'                                    raise\n'
            b'                                raise SharedUpgradeHold(\'native SCP measurement input lease failed\') from error\n'
            b'                            if peer_failure is not None:\n'
            b'                                # Target content errors do not revoke a healthy\n'
            b'                                # shared source owner or turn a DTO into a grant.\n'
            b'                                raise _NativeObservationHold(reason_code=\'COMPONENT_EXIT_BINDING_INVALID\',\n'
            b'                                    capture_raw={\'safe_diagnostic\': {\'code\': \'SCP_DOWNLOAD_CONTENT_INVALID\'}}) from None\n'
            b'                            joint[2][32](scope, leaf, dispatch, [measurement])\n'
            b'                            # The real record entry has returned after actual\n'
            b'                            # writer.finish AND its request lease cleanup.\n'
            b'                            try:\n'
            b'                                with scope._request_namespace_lease():\n'
            b'                                    after = joint[2][30](scope, leaf, dispatch)\n'
            b'                                    if (after[0] is not inputs[0] or after[4] is not inputs[4]\n'
            b'                                            or after[5] is not inputs[5] or after[8] is not parent\n'
            b'                                            or after[2] != inputs[2]\n'
            b'                                            or any(a is not b for a, b in zip(after[3], inputs[3]))):\n'
            b'                                        raise SharedUpgradeHold(\'original native SCP ACK inputs changed\')\n'
            b'                                    saved = scope._hold(after[0], \'download-attempt-01.json\')\n'
            b'                                    document = joint[2][29](after[1], after[3][6].payload,\n'
            b'                                        lambda name: scope._hold(after[0], name).payload, packet)\n'
            b'                                    from ibsw_upgrade_driver import _json_bytes\n'
            b'                                    if saved.payload != _json_bytes(document):\n'
            b'                                        raise SharedUpgradeHold(\'original native SCP measurement record changed\')\n'
            b'                                    saved.verify()\n'
            b'                                    ack = joint[2][27](binding[\'run_id\'],\n'
            b'                                        measurement[\'content_marker\'], measurement[\'raw_line\'])\n'
            b'                            except BaseException as error:\n'
            b'                                if parent._package_source_lifecycle_failure is None:\n'
            b'                                    parent._package_source_lifecycle_failure = SharedUpgradeHold(\n'
            b'                                        \'native SCP ACK record/lease uncertain; shared group retained\')\n'
            b'                                if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):\n'
            b'                                    raise\n'
            b'                                raise SharedUpgradeHold(\'native SCP ACK record verification failed\') from error\n'
            b'                            if scope._native_scp_source(leaf, \'os\', dispatch.package_index) is not inputs[4]:\n'
            b'                                raise SharedUpgradeHold(\'native SCP source changed before ACK publication\')\n'
            b'                            stop = getattr(scope, \'_pipeline_stop_event\', None)\n'
            b'                            if stop is not None and stop.is_set():\n'
            b'                                raise SharedUpgradeHold(\'shared stop withholds native SCP ACK\')\n'
            b'                            ack_path=posixpath.join(posixpath.dirname(remote),\'download-ack\')\n'
            b'                            try: ack_item=sftp.lstat(ack_path)\n'
            b'                            except FileNotFoundError: ack_item=None\n'
            b'                            if ack_item is None:\n'
            b'                                temporary_ack=ack_path+\'-\'+secrets.token_hex(16)\n'
            b'                                handle=sftp.open(temporary_ack,\'wx\')\n'
            b'                                try:\n'
            b'                                    sftp.chmod(temporary_ack,0o600)\n'
            b'                                    handle.write(ack); handle.flush()\n'
            b'                                finally: handle.close()\n'
            b'                                check=_read_stable_component_file(leaf,sftp,temporary_ack,int(uid_raw[0]),deadline,1024,nonempty=True)\n'
            b'                                if check!=ack:\n'
            b'                                    raise _NativeObservationHold(reason_code=\'COMPONENT_EXIT_BINDING_INVALID\')\n'
            b'                                # Final name becomes visible only after complete bytes.\n'
            b'                                sftp.rename(temporary_ack,ack_path)\n'
            b'                                # Rename response commits the already-verified bytes.\n'
            b'                                # The installer can consume ACK and reboot immediately:\n'
            b'                                # a post-commit reread must not be a success prerequisite.\n'
            b'                            else:\n'
            b'                                readback=_read_stable_component_file(leaf,sftp,ack_path,int(uid_raw[0]),deadline,1024,nonempty=True)\n'
            b'                                if readback!=ack:\n'
            b'                                    raise _NativeObservationHold(reason_code=\'COMPONENT_EXIT_BINDING_INVALID\')\n'
            b'                            leaf._download_acknowledged=True\n'
            b'                            acknowledged_now=True\n'
            b'                    if (dispatch.component==\'os\' and scope.parsed.method != \'scp\'\n'
            b'                            and not getattr(leaf,\'_download_acknowledged\',False)):\n'
            b'                        from ibsw_upgrade_component import parse_download_results,download_ack_bytes\n'
            b'                        measurements=parse_download_results(snippet)\n'
            b'                        if measurements:\n'
        ), 0),
        # hunk5: old785B/82ecf8e5ca5e23cc77ae4bcdcc24de4dc553a84c8b2f36144473b69b21e75211, new1039B/1571f95a87b996ced9a60141cf10a13e720a2d01124d9f1473e0760fb8f1d20e
        (5, 102362, 111189,
(
            b'        finally:\n'
            b'            try: sftp.close()\n'
            b'            except BaseException as cleanup:\n'
            b'                if isinstance(cleanup,OSError) and cleanup.errno in _RESOURCE_ERRNOS:\n'
            b'                    if failure is None or isinstance(failure,Exception): failure=cleanup\n'
            b'                if failure is None:\n'
            b'                    safe={\'operation\':\'close\',\'stage\':dispatch.stage,\'code\':\'COMPONENT_SFTP_FAILED\'}\n'
            b'                    if isinstance(cleanup,OSError) and cleanup.errno is not None: safe[\'errno\']=cleanup.errno\n'
            b'                    failure=(_NativeObservationHold(reason_code="COMPONENT_SFTP_FAILED",capture_raw={\'safe_diagnostic\':safe})\n'
            b'                             if isinstance(cleanup,Exception) else cleanup)\n'
            b'        if failure is not None: raise failure\n'
            b'        return result\n'
            b'\n'
        ),
(
            b'        finally:\n'
            b'            try: sftp.close()\n'
            b'            except BaseException as cleanup:\n'
            b'                if scope.parsed.method == \'scp\' and not isinstance(cleanup, Exception):\n'
            b'                    if failure is None or isinstance(failure, Exception):\n'
            b'                        failure = cleanup\n'
            b'                else:\n'
            b'                    if isinstance(cleanup,OSError) and cleanup.errno in _RESOURCE_ERRNOS:\n'
            b'                        if failure is None or isinstance(failure,Exception): failure=cleanup\n'
            b'                    if failure is None:\n'
            b'                        safe={\'operation\':\'close\',\'stage\':dispatch.stage,\'code\':\'COMPONENT_SFTP_FAILED\'}\n'
            b'                        if isinstance(cleanup,OSError) and cleanup.errno is not None: safe[\'errno\']=cleanup.errno\n'
            b'                        failure=(_NativeObservationHold(reason_code="COMPONENT_SFTP_FAILED",capture_raw={\'safe_diagnostic\':safe})\n'
            b'                                 if isinstance(cleanup,Exception) else cleanup)\n'
            b'        if failure is not None: raise failure\n'
            b'        return result\n'
            b'\n'
        ), 0),
    ),
    "tools/ibsw_upgrade_component.py": (
        # hunk1: old141B/28840fae9e845ac21e740f8128a71f849579424737331a7c2c0ee3955c89f63f, new5110B/c03dafcad7af6bda281af565fdb5677153d051b989bce22a5c0e72fc655d64ca
        (1, 2744, 2744,
(
            b'    return b\'IBSW_DOWNLOAD_ACK_V1|\'+run_id.encode(\'ascii\')+b\'|\'+raw_line+b\'\\n\'\n'
            b'\n'
            b'\n'
            b'@dataclass(frozen=True)\n'
            b'class RenderedStep:\n'
            b'    script: str\n'
        ),
(
            b'    return b\'IBSW_DOWNLOAD_ACK_V1|\'+run_id.encode(\'ascii\')+b\'|\'+raw_line+b\'\\n\'\n'
            b'\n'
            b'\n'
            b'def _scp_download_pair(content_marker, raw_line):\n'
            b'    """Validate two public SCP DATA records, never an execution permission."""\n'
            b'    import base64\n'
            b'    if (type(content_marker) is not bytes or type(raw_line) is not bytes\n'
            b'            or len(content_marker) + len(raw_line) + 2 > 4096\n'
            b'            or any(char in content_marker or char in raw_line for char in (b\'\\n\', b\'\\r\'))):\n'
            b'        raise ValueError(\'bounded complete SCP download pair required\')\n'
            b'    try:\n'
            b'        marker = content_marker.decode(\'ascii\').split(\'|\')\n'
            b'        fields = raw_line.decode(\'ascii\').split(\'|\')\n'
            b'        if (len(marker) != 5 or marker[0] != \'IBSW_SCP_CONTENT_VERIFIED=1\'\n'
            b'                or re.fullmatch(r\'[0-9a-f]{64}\', marker[1]) is None\n'
            b'                or re.fullmatch(r\'[A-Za-z0-9_-]+\', marker[2]) is None\n'
            b'                or re.fullmatch(r\'[1-9][0-9]{0,18}\', marker[3]) is None\n'
            b'                or re.fullmatch(r\'[0-9a-f]{64}\', marker[4]) is None):\n'
            b'            raise ValueError()\n'
            b'        decoded = base64.b64decode(marker[2] + \'=\' * (-len(marker[2]) % 4),\n'
            b'                                   altchars=b\'-_\', validate=True)\n'
            b'        if base64.urlsafe_b64encode(decoded).rstrip(b\'=\').decode(\'ascii\') != marker[2]:\n'
            b'            raise ValueError()\n'
            b'        path = decoded.decode(\'utf-8\')\n'
            b'        if (not path.startswith(\'/\') or len(decoded) > 4096\n'
            b'                or any(ord(char) < 32 or ord(char) == 127 for char in path)):\n'
            b'            raise ValueError()\n'
            b'        size = int(marker[3])\n'
            b'        if not 0 < size < 2**63:\n'
            b'            raise ValueError()\n'
            b'        if (len(fields) != 8 or fields[0] != \'IBSW_SCP_DOWNLOAD_RESULT=1\'\n'
            b'                or any(re.fullmatch(r\'[0-9]{1,20}\', value) is None for value in fields[1:6])\n'
            b'                or fields[3:5] != [\'0\', \'0\']\n'
            b'                or any(re.fullmatch(r\'[0-9]{1,20}(?:\\.[0-9]{1,9})?\', value) is None\n'
            b'                       for value in fields[6:])):\n'
            b'            raise ValueError()\n'
            b'        start, end, code, status, downloaded = map(int, fields[1:6])\n'
            b'        elapsed, speed = map(float, fields[6:])\n'
            b'        if (end < start or downloaded != size\n'
            b'                or not all(math.isfinite(value) and value >= 0 for value in (elapsed, speed))):\n'
            b'            raise ValueError()\n'
            b'    except (ValueError, UnicodeError):\n'
            b'        raise ValueError(\'invalid SCP download pair\') from None\n'
            b'    row = dict(attempt=1, started_epoch=start, finished_epoch=end,\n'
            b'               scp_exit=code, reserved_status=status, bytes_downloaded=downloaded,\n'
            b'               elapsed_seconds=elapsed, average_bytes_per_second=speed,\n'
            b'               content_marker=content_marker, raw_line=raw_line)\n'
            b'    return row, (marker[1], path, size, marker[4])\n'
            b'\n'
            b'\n'
            b'def parse_scp_download_results(payload, expected_content):\n'
            b'    """Exact two-record SCP DATA packet; caller must separately govern stdout."""\n'
            b'    if (type(payload) is not bytes or len(payload) > 4096\n'
            b'            or not payload.endswith(b\'\\n\') or payload.count(b\'\\n\') != 2\n'
            b'            or b\'\\r\' in payload\n'
            b'            or type(expected_content) is not dict\n'
            b'            or set(expected_content) != {\'binding_sha256\', \'path\', \'size\', \'sha256\'}):\n'
            b'        raise ValueError(\'exact SCP download packet and content DATA required\')\n'
            b'    binding, path, size, digest = (expected_content[key] for key in\n'
            b'                                 (\'binding_sha256\', \'path\', \'size\', \'sha256\'))\n'
            b'    if (type(binding) is not str or re.fullmatch(r\'[0-9a-f]{64}\', binding) is None\n'
            b'            or type(digest) is not str or re.fullmatch(r\'[0-9a-f]{64}\', digest) is None\n'
            b'            or type(path) is not str or not path.startswith(\'/\')\n'
            b'            or type(size) is not int or not 0 < size < 2**63\n'
            b'            or any(ord(char) < 32 or ord(char) == 127 for char in path)):\n'
            b'        raise ValueError(\'invalid expected SCP content DATA\')\n'
            b'    try:\n'
            b'        if len(path.encode(\'utf-8\')) > 4096:\n'
            b'            raise ValueError()\n'
            b'    except UnicodeError:\n'
            b'        raise ValueError(\'invalid expected SCP content DATA\') from None\n'
            b'    first, second, _tail = payload.split(b\'\\n\')\n'
            b'    if first.startswith(b\'IBSW_SCP_CONTENT_VERIFIED=\'):\n'
            b'        marker, line = first, second\n'
            b'    elif second.startswith(b\'IBSW_SCP_CONTENT_VERIFIED=\'):\n'
            b'        marker, line = second, first\n'
            b'    else:\n'
            b'        raise ValueError(\'one SCP content marker required\')\n'
            b'    row, content = _scp_download_pair(marker, line)\n'
            b'    if content != (binding, path, size, digest):\n'
            b'        raise ValueError(\'SCP content DATA mismatch\')\n'
            b'    return row\n'
            b'\n'
            b'\n'
            b'def scp_download_ack_bytes(run_id, content_marker, raw_line):\n'
            b'    """Fixed V2 wire DATA; not an owner record, grant or ACK publication."""\n'
            b'    import hashlib\n'
            b'    if (type(run_id) is not str\n'
            b'            or re.fullmatch(r\'[A-Za-z0-9][A-Za-z0-9_-]{0,95}\', run_id) is None):\n'
            b'        raise ValueError(\'safe SCP download acknowledgement run required\')\n'
            b'    _scp_download_pair(content_marker, raw_line)\n'
            b'    return (b\'IBSW_SCP_DOWNLOAD_ACK_V2|\' + run_id.encode(\'ascii\') + b\'|\'\n'
            b'            + hashlib.sha256(content_marker).hexdigest().encode(\'ascii\')\n'
            b'            + b\'|\' + raw_line + b\'\\n\')\n'
            b'\n'
            b'\n'
            b'@dataclass(frozen=True)\n'
            b'class RenderedStep:\n'
            b'    script: str\n'
        ), 0),
    ),
    "infiniband/bringup/xdr-upgrade/upgrade-component.sh": (
        # hunk1: old314B/a057c0008336a2b051453a0d1aa41b71d313800c8aef1961d99f7eef5d2daa4f, new262B/89219e907db7bf6696948a11658855883428649a5ff5013333dc30221a0e9fc5
        (1, 4813, 4813,
(
            b'        temporary=""\n'
            b'        ;;\n'
            b'    scp)\n'
            b'        # No SCP OS installer until genuine SCP-only manager ACK is closed.\n'
            b'        [[ "$IBSW_COMPONENT" != os ]] || exit 64\n'
            b'        : "${scp_source:?bound source path required}"\n'
            b'        : "${IBSW_SCP_HELPER_B64:?fixed stdin-only helper required}"\n'
            b'        read_scp_context\n'
        ),
(
            b'        temporary=""\n'
            b'        ;;\n'
            b'    scp)\n'
            b'        # SCP OS waits for its exact content-bound manager V2 ACK below.\n'
            b'        : "${scp_source:?bound source path required}"\n'
            b'        : "${IBSW_SCP_HELPER_B64:?fixed stdin-only helper required}"\n'
            b'        read_scp_context\n'
        ), 0),
        # hunk2: old221B/8161eab25011de7df58bead05a344afb118a764e21652ce0dbc054a42be2df3d, new1239B/a450d05b68d218e4ebeeb0d46293b7e2b48e4312e9eb1695638d74ebbebf1e92
        (2, 6537, 6485,
(
            b'        done\n'
            b'        [[ -n "$content" && -n "$measurement" && -s "$temporary" ]] || exit 66\n'
            b'        printf \'%s\\n\' "$content" "$measurement"\n'
            b'        mv -- "$temporary" "$IBSW_LOCAL_PACKAGE"\n'
            b'        temporary=""\n'
            b'        ;;\n'
        ),
(
            b'        done\n'
            b'        [[ -n "$content" && -n "$measurement" && -s "$temporary" ]] || exit 66\n'
            b'        printf \'%s\\n\' "$content" "$measurement"\n'
            b'        if [[ "$IBSW_COMPONENT" == os ]]; then\n'
            b'            # Public content DATA alone cannot release installation. The real\n'
            b'            # manager must finish its original reliable record before V2 ACK.\n'
            b'            printf \'%s\\n\' \'IBSW_STAGE=WAIT_DOWNLOAD_RECORD\'\n'
            b'            local content_digest\n'
            b'            content_digest=$(/usr/bin/python3 -c \'import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode("ascii")).hexdigest())\' "$content") || exit 66\n'
            b'            local ack_path="${BASH_SOURCE[0]%/*}/download-ack"\n'
            b'            local expected="IBSW_SCP_DOWNLOAD_ACK_V2|$IBSW_RUN_ID|$content_digest|$measurement" ack="" waited=0\n'
            b'            while :; do\n'
            b'                if [[ -f "$ack_path" && ! -L "$ack_path" ]]; then\n'
            b'                    IFS= read -r ack < "$ack_path" || exit 66\n'
            b'                    [[ "$ack" == "$expected" ]] || exit 66\n'
            b'                    break\n'
            b'                fi\n'
            b'                (( waited < 300 )) || exit 75\n'
            b'                sleep 1\n'
            b'                waited=$((waited+1))\n'
            b'            done\n'
            b'        fi\n'
            b'        mv -- "$temporary" "$IBSW_LOCAL_PACKAGE"\n'
            b'        temporary=""\n'
            b'        ;;\n'
        ), 0),
        # hunk3: old299B/21e0a9042d2ef6ed8332fbf5bb6ef76fa4aa8594504d3b566b7a2d31f6972ba4, new260B/2b35780a611233545a58b0faa1b18867d9c975fcef079f0bf6d031d00499066c
        (3, 6948, 7914,
(
            b'}\n'
            b'\n'
            b'# IBSW_BODY_OS\n'
            b'[[ "$IBSW_METHOD" != scp ]] || exit 64\n'
            b'prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL" "${IBSW_SCP_PACKAGE_PATH:-}"\n'
            b'# NVOS IB published FILE fetch, then default-reboot install. The latter can\n'
            b'# disconnect SSH before any final marker returns; do not resend it on timeout.\n'
        ),
(
            b'}\n'
            b'\n'
            b'# IBSW_BODY_OS\n'
            b'prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL" "${IBSW_SCP_PACKAGE_PATH:-}"\n'
            b'# NVOS IB published FILE fetch, then default-reboot install. The latter can\n'
            b'# disconnect SSH before any final marker returns; do not resend it on timeout.\n'
        ), 0),
    ),
}


def _restore_native_os_layer(sources):
    """Reverse exactly all22 reviewed native OS hunks, then require old U SHA.

    Input/output are source bytes DATA. No file read, import, execution, image,
    producer grant or accepted candidate whole-hash is supplied by this API.
    """
    if type(sources) is not dict or set(sources) != set(_NATIVE_OS_PATHS):
        raise AssertionError('exact four native OS source paths required')
    restored = {}
    for path in _NATIVE_OS_PATHS:
        payload = sources[path]
        if type(payload) is not bytes:
            raise AssertionError('original source bytes required')
        spans = []
        previous_new_end = previous_old_end = 0
        difference = 0
        for ordinal, old_offset, new_offset, old, new, retained_old in _NATIVE_OS_REGIONS[path]:
            if (payload.count(new) != 1 or payload.find(new) != new_offset
                    or payload.count(old) != retained_old
                    or new_offset < previous_new_end or old_offset < previous_old_end
                    or new_offset + difference != old_offset):
                raise AssertionError('missing/duplicate/old/reordered native OS literal region')
            spans.append((new_offset, new, old))
            previous_new_end = new_offset + len(new)
            previous_old_end = old_offset + len(old)
            difference += len(old) - len(new)
        # One pass over ORIGINAL payload, never sequential global replacements:
        # inserted old bytes cannot be reinterpreted as a later new region.
        pieces, cursor = [], 0
        for position, new, old in spans:
            pieces.extend((payload[cursor:position], old))
            cursor = position + len(new)
        pieces.append(payload[cursor:])
        original = b''.join(pieces)
        if hashlib.sha256(original).hexdigest() != _NATIVE_OS_EXPECTED_U[path]:
            raise AssertionError('whole original U source SHA differs after finite native OS inverse')
        restored[path] = original
    return restored




# Historical U19 pair only; the original full vector consumer remains final.
_BIOS_U_TARGETS = {
    'tools/ibsw_upgrade_driver.py': '887a3faf2808cfd2107849825cea2a14fe041f9468987249c5bba07c39030f01',
    'tools/ibsw_upgrade_executor.py': '1736c076376873e2de2a2ce14639cde357bf15f058f0e486fcbf176b5ef02f51',
}
# Test-image source DATA: two-file B2 layer, exactly driver4/executor2 regions.
# The only final targets are previous OS22 bytes; no new whole-file permission.
_BIOS_TARGETS = {
    'tools/ibsw_upgrade_driver.py': '0f3670ad74a46147bd13d29d894aa5bb554ed8574ba4bd51239e0913d99a0dd5',
    'tools/ibsw_upgrade_executor.py': '31bb2577b9817a7cf3e105e64119bc6b1d49f3fbc8531e83ae1664526741036f',
}
_BIOS_REGIONS = {
    'tools/ibsw_upgrade_driver.py': (
        (1, 49121, 49121, b"            if (set(document) != {'schema_version', 'state', 'binding', 'request_sha256',\n                    'remote_script', 'records', 'launch_kind', 'runner_binding_sha256', 'scp_companion_sha256'}\n                    or document.get('state') != 'COMPONENT_DISPATCH_DATA_ONLY'\n                    or binding['component'] not in ('os', 'cpld')\n                    or (binding['component'] == 'cpld' and binding['package_index'] != 0)\n                    or 'scp-source-request.json' not in files\n                    or 'package-source.json' in files\n                    or document.get('scp_companion_sha256') != hashlib.sha256(read('scp-source-request.json')).hexdigest()\n", b"            if (set(document) != {'schema_version', 'state', 'binding', 'request_sha256',\n                    'remote_script', 'records', 'launch_kind', 'runner_binding_sha256', 'scp_companion_sha256'}\n                    or document.get('state') != 'COMPONENT_DISPATCH_DATA_ONLY'\n                    or binding['component'] not in ('os', 'bios', 'cpld')\n                    or (binding['component'] in ('bios', 'cpld') and binding['package_index'] != 0)\n                    or 'scp-source-request.json' not in files\n                    or 'package-source.json' in files\n                    or document.get('scp_companion_sha256') != hashlib.sha256(read('scp-source-request.json')).hexdigest()\n", 0),
        (2, 143900, 143918, b"        scope.verify(); group.verify()\n        if (not group.manual_execution or group.parsed.method != 'scp' or group.closed\n                or not group._package_source_owns or group._package_source_owner is None\n                or not set(group.parsed.selected).intersection(('os', 'cpld'))):\n            refuse()\n        source19, probe32 = _fixed_scp_source_api(group, probe=True)\n        original_binding = group._scp_source_binding\n", b"        scope.verify(); group.verify()\n        if (not group.manual_execution or group.parsed.method != 'scp' or group.closed\n                or not group._package_source_owns or group._package_source_owner is None\n                or not set(group.parsed.selected).intersection(('os', 'bios', 'cpld'))):\n            refuse()\n        source19, probe32 = _fixed_scp_source_api(group, probe=True)\n        original_binding = group._scp_source_binding\n", 0),
        (3, 205677, 205703, b"        try:\n            if (type(self) is not _PreparedRunScope or type(parent) is not _PreparedRunScope\n                    or type(leaf) is not _ReadonlyQueryInputs\n                    or type(component) is not str or component not in ('os', 'cpld')\n                    or type(package_index) is not int\n                    or (component == 'cpld' and package_index != 0)\n                    or (component == 'os' and package_index not in self._native_package_indices)\n                    or self.parsed.method != 'scp' or self._active_request_lease is None\n                    or type(deadline) not in (int, float) or not math.isfinite(deadline)):\n", b"        try:\n            if (type(self) is not _PreparedRunScope or type(parent) is not _PreparedRunScope\n                    or type(leaf) is not _ReadonlyQueryInputs\n                    or type(component) is not str or component not in ('os', 'bios', 'cpld')\n                    or type(package_index) is not int\n                    or (component in ('bios', 'cpld') and package_index != 0)\n                    or (component == 'os' and package_index not in self._native_package_indices)\n                    or self.parsed.method != 'scp' or self._active_request_lease is None\n                    or type(deadline) not in (int, float) or not math.isfinite(deadline)):\n", 0),
        (4, 302564, 302608, b"            rows = _component_raw_records(records)\n            scp_companion = None\n            if self.parsed.method == 'scp':\n                if (component not in ('os', 'cpld')\n                        or (component == 'cpld' and data['package_index'] != 0)):\n                    raise ValueError('only original selected OS or CPLD has an SCP dispatch backend')\n                parent = self._native_parent\n                self._native_scp_source(leaf, component, data['package_index'])\n                joint = _fixed_native_scp_cpld_api(parent)\n", b"            rows = _component_raw_records(records)\n            scp_companion = None\n            if self.parsed.method == 'scp':\n                if (component not in ('os', 'bios', 'cpld')\n                        or (component in ('bios', 'cpld') and data['package_index'] != 0)):\n                    raise ValueError('only original selected OS, BIOS or CPLD has an SCP dispatch backend')\n                parent = self._native_parent\n                self._native_scp_source(leaf, component, data['package_index'])\n                joint = _fixed_native_scp_cpld_api(parent)\n", 0),
    ),
    'tools/ibsw_upgrade_executor.py': (
        (1, 58414, 58414, b'            with _signed_session(leaf, password=password) as (transport, deadline, _identity, _auth, _pin):\n                scope._preflight_native_scp_source(leaf, component, scope._native_package_indices[0],\n                                                   transport, deadline)\n        if args.method not in ("local", "http") and not (args.method == \'scp\' and component in (\'os\', \'cpld\')):\n            raise SharedUpgradeHold("selected transport has no fixed real component backend")\n    except SharedUpgradeHold:\n        raise\n', b'            with _signed_session(leaf, password=password) as (transport, deadline, _identity, _auth, _pin):\n                scope._preflight_native_scp_source(leaf, component, scope._native_package_indices[0],\n                                                   transport, deadline)\n        if args.method not in ("local", "http") and not (args.method == \'scp\' and component in (\'os\', \'bios\', \'cpld\')):\n            raise SharedUpgradeHold("selected transport has no fixed real component backend")\n    except SharedUpgradeHold:\n        raise\n', 0),
        (2, 72379, 72387, b'            raise ValueError("original runner binding changed")\n        if args.method == \'scp\':\n            from ibsw_upgrade_driver import _fixed_native_scp_cpld_api, _validate_scp_request_content_graph\n            if (dispatch.component not in (\'os\', \'cpld\')\n                    or (dispatch.component == \'cpld\' and dispatch.package_index != 0)\n                    or document.get(\'launch_kind\') != \'SCP_STDIN_OWNED_RUNNER_V2\'):\n                raise ValueError(\'only original selected SCP OS/CPLD V2 dispatch is supported\')\n            source = scope._native_scp_source(leaf, dispatch.component, dispatch.package_index)\n            parent = scope._native_parent\n            joint = _fixed_native_scp_cpld_api(parent)\n', b'            raise ValueError("original runner binding changed")\n        if args.method == \'scp\':\n            from ibsw_upgrade_driver import _fixed_native_scp_cpld_api, _validate_scp_request_content_graph\n            if (dispatch.component not in (\'os\', \'bios\', \'cpld\')\n                    or (dispatch.component in (\'bios\', \'cpld\') and dispatch.package_index != 0)\n                    or document.get(\'launch_kind\') != \'SCP_STDIN_OWNED_RUNNER_V2\'):\n                raise ValueError(\'only original selected SCP OS/BIOS/CPLD V2 dispatch is supported\')\n            source = scope._native_scp_source(leaf, dispatch.component, dispatch.package_index)\n            parent = scope._native_parent\n            joint = _fixed_native_scp_cpld_api(parent)\n', 0),
    ),
}

def _restore_bios_layer(sources):
    if type(sources) is not dict or set(sources) != set(_BIOS_TARGETS):
        raise AssertionError('exact BIOS two-source vector required')
    restored = {}
    for path in _BIOS_TARGETS:
        raw = sources[path]
        if type(raw) is not bytes:
            raise AssertionError('original source bytes required')
        spans = []; old_end = new_end = 0; difference = 0
        for ordinal, old_offset, new_offset, old, new, retained in _BIOS_REGIONS[path]:
            if (raw.count(new) != 1 or raw.find(new) != new_offset
                    or raw.count(old) != retained or old_offset < old_end
                    or new_offset < new_end or new_offset + difference != old_offset):
                raise AssertionError('missing/duplicate/misordered BIOS source region')
            spans.append((new_offset, new, old))
            old_end, new_end = old_offset + len(old), new_offset + len(new)
            difference += len(old) - len(new)
        pieces = []; cursor = 0
        for offset, new, old in spans:
            pieces.extend((raw[cursor:offset], old)); cursor = offset + len(new)
        pieces.append(raw[cursor:])
        original = b''.join(pieces)
        if hashlib.sha256(original).hexdigest() != _BIOS_TARGETS[path]:
            raise AssertionError('whole previous OS22 source differs after BIOS inverse')
        restored[path] = original
    return restored


def _strip_bios_source_layer(sources):
    """Two-file source DATA only, never a whole vector/native permission.

    Preserve whole U or whole previous OS22 pair; otherwise require the exact
    complete two-file B2 inverse. The original four-file/19-pin consumer still
    rejects any mixed/outside source changes after this optional pre-layer.
    """
    if type(sources) is not dict or set(sources) != set(_BIOS_TARGETS):
        raise AssertionError('exact BIOS two-source vector required')
    if any(type(sources[p]) is not bytes for p in _BIOS_TARGETS):
        raise AssertionError('original source bytes required')
    for pins in (_BIOS_U_TARGETS, _BIOS_TARGETS):
        if all(hashlib.sha256(sources[p]).hexdigest() == pins[p] for p in pins):
            return {p: sources[p] for p in _BIOS_TARGETS}
    return _restore_bios_layer(sources)


def _native_os_sources_before_native34(sources):
    """Whole four-vector old U OR exact OS22 inverse; never mix or adopt current.

    This is source-oracle DATA only. No source is executed or imported, and
    entry/display is deliberately outside this four-file/FROZEN13 layer.
    """
    if type(sources) is not dict or set(sources) != set(_NATIVE_OS_PATHS):
        raise AssertionError('exact four native OS source paths required')
    if any(type(sources[p]) is not bytes for p in _NATIVE_OS_PATHS):
        raise AssertionError('original source bytes required')
    sources = dict(sources)
    if all(hashlib.sha256(sources[p]).hexdigest() == _NATIVE_OS_EXPECTED_U[p]
           for p in _NATIVE_OS_PATHS):
        return {p: sources[p] for p in _NATIVE_OS_PATHS}
    # A complete fixed B2 region is only a routing witness, never permission.
    # If any is present, BOTH BIOS files must pass the exact full inverse.
    # With no witness, the original strict OS22 whole-hash inverse remains
    # responsible for old DATA UNIT inputs and all partial/outside changes.
    if any(new in sources[path] for path, regions in _BIOS_REGIONS.items()
           for _ordinal, _old_offset, _new_offset, _old, new, _retained in regions):
        sources.update(_restore_bios_layer({p: sources[p] for p in _BIOS_TARGETS}))
    return _restore_native_os_layer(sources)


def _native_upstream_bytes_from_exact_composition(relative, payload):
    """Test-side fixed source inverse, not runtime/dispatch permission.

    All locations refer to the same unmodified input. Validate every span and
    retained-old occurrence first; copy outside bytes exactly in one pass.
    """
    if type(payload) is not bytes:
        raise TypeError('exact native source bytes required')
    if type(relative) is not str or relative not in NATIVE_SCP_FIXED_PATHS:
        raise ValueError('unapproved native source path')
    regions = NATIVE_SCP_APPROVED_COMPOSITION[relative]

    def occurrences(needle, haystack):
        positions, offset = [], 0
        while True:
            start = haystack.find(needle, offset)
            if start < 0:
                return positions
            positions.append(start)
            offset = start + 1  # Include overlapping duplicates, not count().

    if type(regions) is not tuple or not regions:
        raise ValueError('fixed native source region set required')
    spans = []
    for region in regions:
        if type(region) is not tuple or len(region) != 3:
            raise ValueError('fixed native source region shape changed')
        original, integrated, retained = region
        if (type(original) is not bytes or not original
                or type(integrated) is not bytes or not integrated
                or original == integrated or type(retained) is not int
                or retained not in (0, 1)):
            raise ValueError('fixed native source region fields changed')
        matches = occurrences(integrated, payload)
        if len(matches) != 1:
            raise ValueError('missing or duplicate native source hunk')
        start = matches[0]
        stop = start + len(integrated)
        old_matches = occurrences(original, payload)
        # Exactly three reviewed regions retain one original inside their
        # own new span. No original outside that span may be silently erased.
        if (len(occurrences(original, integrated)) != retained
                or len(old_matches) != retained
                or any(not (start <= p and p + len(original) <= stop)
                       for p in old_matches)):
            raise ValueError('extra or misplaced original native source hunk')
        spans.append((start, stop, original))
    # The literal table already has source order. Never sort malformed input.
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        raise ValueError('reordered or overlapping native source hunks')
    pieces, previous = [], 0
    for start, stop, original in spans:
        pieces.extend((payload[previous:start], original))
        previous = stop
    pieces.append(payload[previous:])
    restored = b''.join(pieces)
    if any(len(occurrences(old, restored)) != 1
           or occurrences(new, restored) for old, new, _retained in regions):
        raise ValueError('restored native source hunk multiplicity changed')
    return restored


class NativeScpExactSourceCompositionTests(unittest.TestCase):
    def literal_inverse(self, payload, regions=None):
        # Explicit UNIT table seam for the inverse algorithm only. The actual
        # seven-source gate is never run with this table and never grants IO.
        # These small independent pre/postimages are not production outputs.
        from unittest.mock import patch
        if regions is None:
            regions = (
                (b'OLD-A\n', b'NEW-A[OLD-A\n]END-A\n', 1),
                (b'OLD-B\n', b'NEW-B\n', 0),
            )
        with patch.dict(NATIVE_SCP_APPROVED_COMPOSITION,
                        {'tools/ibsw_upgrade_component.py': regions}):
            return _native_upstream_bytes_from_exact_composition(
                'tools/ibsw_upgrade_component.py', payload)

    def test_fixed_seven_paths_and_thirtyfour_region_counts_are_literal(self):
        self.assertEqual((
            'tools/ibsw_upgrade_driver.py',
            'tools/ibsw_upgrade_executor.py',
            'tools/ibsw_upgrade_component.py',
            'tools/ibsw_upgrade_pipeline.py',
            'tools/ibsw_upgrade_scp.py',
            'infiniband/bringup/xdr-upgrade/upgrade.py',
            'infiniband/bringup/xdr-upgrade/upgrade-component.sh',
        ), NATIVE_SCP_FIXED_PATHS)
        self.assertEqual(NATIVE_SCP_FIXED_PATHS, tuple(NATIVE_SCP_APPROVED_COMPOSITION))
        self.assertEqual((12, 4, 1, 1, 1, 9, 6), tuple(
            len(NATIVE_SCP_APPROVED_COMPOSITION[p]) for p in NATIVE_SCP_FIXED_PATHS))
        self.assertEqual(34, sum(map(len, NATIVE_SCP_APPROVED_COMPOSITION.values())))
        self.assertEqual({
            ('tools/ibsw_upgrade_driver.py', 3),
            ('tools/ibsw_upgrade_scp.py', 1),
            ('infiniband/bringup/xdr-upgrade/upgrade-component.sh', 3),
        }, {(p, i + 1) for p in NATIVE_SCP_FIXED_PATHS
            for i, (_old, _new, count) in enumerate(NATIVE_SCP_APPROVED_COMPOSITION[p])
            if count == 1})
        self.assertEqual(13, len(FROZEN_SHA256))
        self.assertEqual(12, len(DRIVER_SOURCE_DATA_APPROVED_COMPOSITION))
        self.assertEqual(7, len(DRIVER_SCP_REQUEST_APPROVED_COMPOSITION))
        self.assertEqual(2, len(ACCESS_APPROVED_COMPOSITION))
        # Actual fixed files, not the UNIT table seam below. For five paths
        # the unchanged original FROZEN loop separately checks the whole result.
        # Entry/provider have no FROZEN13 permission hash: their outside bytes
        # remain intact and are not newly approved by these region assertions.
        native_os_sources = _native_os_sources_before_native34({
            p: (ROOT / p).read_bytes() for p in _NATIVE_OS_PATHS})
        for relative in NATIVE_SCP_FIXED_PATHS:
            with self.subTest(source=relative):
                path = ROOT / relative
                self.assertTrue(path.is_file() and not path.is_symlink())
                restored = _native_upstream_bytes_from_exact_composition(
                    relative, native_os_sources[relative]
                    if relative in native_os_sources else path.read_bytes())
                for old, new, _retained in NATIVE_SCP_APPROVED_COMPOSITION[relative]:
                    self.assertEqual(1, restored.count(old))
                    self.assertNotIn(new, restored)

    def test_small_literal_regions_restore_once_without_consuming_retained_old_twice(self):
        integrated = b'prefix\nNEW-A[OLD-A\n]END-A\nmiddle\nNEW-B\nsuffix\n'
        expected = b'prefix\nOLD-A\nmiddle\nOLD-B\nsuffix\n'
        self.assertEqual(expected, self.literal_inverse(integrated))
        self.assertEqual(1, expected.count(b'OLD-A\n'))
        self.assertEqual(1, expected.count(b'OLD-B\n'))

    def test_missing_partial_duplicate_reverse_overlap_extra_old_and_nonbytes_are_refused(self):
        for label, malformed in (
            ('missing-first', b'NEW-B\n'),
            ('old-not-new', b'OLD-A\nNEW-B\n'),
            ('missing-second', b'NEW-A[OLD-A\n]END-A\n'),
            ('partial-first', b'NEW-A[OLD-A\n]END-NEW-B\n'),
            ('deleted-byte', b'NEW-A[OLD-A\n]END-A\nNEW-B'),
            ('duplicate-first', b'NEW-A[OLD-A\n]END-A\nNEW-A[OLD-A\n]END-A\nNEW-B\n'),
            ('duplicate-second', b'NEW-A[OLD-A\n]END-A\nNEW-B\nNEW-B\n'),
            ('reverse', b'NEW-B\nNEW-A[OLD-A\n]END-A\n'),
            ('extra-old-prefix', b'OLD-A\nNEW-A[OLD-A\n]END-A\nNEW-B\n'),
            ('extra-old-middle', b'NEW-A[OLD-A\n]END-A\nOLD-B\nNEW-B\n'),
            ('extra-old-suffix', b'NEW-A[OLD-A\n]END-A\nNEW-B\nOLD-A\n'),
        ):
            with self.subTest(fault=label):
                with self.assertRaises(ValueError):
                    self.literal_inverse(malformed)
        with self.assertRaises(ValueError):
            self.literal_inverse(b'LEFT-SHARED-RIGHT', (
                (b'ORIGINAL-LEFT', b'LEFT-SHARED', 0),
                (b'ORIGINAL-RIGHT', b'SHARED-RIGHT', 0),
            ))
        for nonbytes in ('not bytes', bytearray(b'not bytes'), memoryview(b'not bytes'), None):
            with self.subTest(type=type(nonbytes).__name__):
                with self.assertRaises(TypeError):
                    self.literal_inverse(nonbytes)
        for foreign in ('tools/foreign.py', '../tools/ibsw_upgrade_driver.py', None):
            with self.subTest(path=foreign):
                with self.assertRaises(ValueError):
                    _native_upstream_bytes_from_exact_composition(foreign, b'')

    def test_outside_literal_drift_is_preserved_for_the_historical_hash_gate(self):
        integrated = b'prefix\nNEW-A[OLD-A\n]END-A\nmiddle\nNEW-B\nsuffix\n'
        expected = b'prefix\nOLD-A\nmiddle\nOLD-B\nsuffix\n'
        for label, drift, expected_drift in (
            ('prefix', b'outside\n' + integrated,
             b'outside\nprefix\nOLD-A\nmiddle\nOLD-B\nsuffix\n'),
            ('middle', b'prefix\nNEW-A[OLD-A\n]END-A\nchanged\nNEW-B\nsuffix\n',
             b'prefix\nOLD-A\nchanged\nOLD-B\nsuffix\n'),
            ('suffix', integrated + b'outside\n',
             b'prefix\nOLD-A\nmiddle\nOLD-B\nsuffix\noutside\n'),
        ):
            with self.subTest(fault=label):
                restored = self.literal_inverse(drift)
                self.assertEqual(expected_drift, restored)
                self.assertNotEqual(expected, restored)
                self.assertNotEqual(hashlib.sha256(expected).digest(),
                                    hashlib.sha256(restored).digest())



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
        native_os_sources = _native_os_sources_before_native34({
            p: (ROOT / p).read_bytes() for p in _NATIVE_OS_PATHS})
        for relative, expected in FROZEN_SHA256.items():
            with self.subTest(original=relative):
                payload = (native_os_sources[relative] if relative in native_os_sources
                           else (ROOT / relative).read_bytes())
                if relative in NATIVE_SCP_APPROVED_COMPOSITION:
                    payload = _native_upstream_bytes_from_exact_composition(relative, payload)
                if relative == "tools/ibsw_upgrade_access.py":
                    payload = _access_upstream_bytes_from_exact_composition(payload)
                elif relative == "tools/ibsw_upgrade_driver.py":
                    payload = _driver_upstream_bytes_from_exact_scp_request_content(payload)
                    payload = _driver_upstream_bytes_from_exact_composition(payload)
                elif relative in LAYOUT_APPROVED_COMPOSITION:
                    payload = _layout_upstream_bytes_from_exact_composition(relative, payload)
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


class NativeOsPreNative34CompositionTests(unittest.TestCase):
    def test_exact_four_source_os22_preinverse_keeps_all_historical_cardinalities(self):
        self.assertTrue(all(name in globals() for name in ('_NATIVE_OS_PATHS', '_NATIVE_OS_EXPECTED_U', '_NATIVE_OS_REGIONS', '_restore_native_os_layer', '_native_os_sources_before_native34')), 'native OS source preinverse API missing')
        expected_u = {
            'tools/ibsw_upgrade_driver.py': '887a3faf2808cfd2107849825cea2a14fe041f9468987249c5bba07c39030f01',
            'tools/ibsw_upgrade_executor.py': '1736c076376873e2de2a2ce14639cde357bf15f058f0e486fcbf176b5ef02f51',
            'tools/ibsw_upgrade_component.py': '1ab3b4b6bb75f11a01816f35ef788b701df2e16489e4c8054709502fd8f2f2d1',
            'infiniband/bringup/xdr-upgrade/upgrade-component.sh': 'a2bde38c42ff14cc73ed5c5cbd3859701e93a8193eb78ae67f2bd5575393b502',
        }
        self.assertEqual(tuple(expected_u), tuple(_NATIVE_OS_PATHS))
        self.assertEqual(expected_u, _NATIVE_OS_EXPECTED_U)
        self.assertEqual((13, 5, 1, 3), tuple(len(_NATIVE_OS_REGIONS[p]) for p in expected_u))
        self.assertEqual(22, sum(map(len, _NATIVE_OS_REGIONS.values())))
        payloads = {p: (ROOT / p).read_bytes() for p in expected_u}
        restored = _native_os_sources_before_native34(payloads)
        self.assertEqual(tuple(expected_u), tuple(restored))
        for p, wanted in expected_u.items():
            with self.subTest(source=p):
                self.assertEqual(wanted, hashlib.sha256(restored[p]).hexdigest())
        self.assertEqual(13, len(FROZEN_SHA256))
        self.assertEqual(12, len(DRIVER_SOURCE_DATA_APPROVED_COMPOSITION))
        self.assertEqual(7, len(DRIVER_SCP_REQUEST_APPROVED_COMPOSITION))
        self.assertEqual(2, len(ACCESS_APPROVED_COMPOSITION))
        self.assertEqual((12, 4, 1, 1, 1, 9, 6), tuple(
            len(NATIVE_SCP_APPROVED_COMPOSITION[p]) for p in NATIVE_SCP_FIXED_PATHS))
        self.assertEqual(34, sum(map(len, NATIVE_SCP_APPROVED_COMPOSITION.values())))
        self.assertEqual('3c76f3bf02f2a41e2338bf78b38681dc5defb63a957d31155709de85f0eaffe2',
                         FROZEN_SHA256['tools/ibsw_upgrade_driver.py'])
        self.assertEqual('aa05f8394ac390a0d0dd5313938cca6137b1c1e37dc1d5d8a83fec266de7d89f',
                         FROZEN_SHA256['tools/ibsw_upgrade_access.py'])

    def test_literal_four_cohort_refuses_partial_missing_truncated_duplicate_order_and_outside_drift(self):
        self.assertTrue(all(name in globals() for name in ('_NATIVE_OS_PATHS', '_NATIVE_OS_EXPECTED_U', '_NATIVE_OS_REGIONS', '_restore_native_os_layer', '_native_os_sources_before_native34')), 'native OS source preinverse API missing')
        # Explicit UNIT algorithm seam only: never read a production image or
        # authorize native execution with these small independent literals.
        from unittest.mock import patch
        paths = (
            'tools/ibsw_upgrade_driver.py', 'tools/ibsw_upgrade_executor.py',
            'tools/ibsw_upgrade_component.py',
            'infiniband/bringup/xdr-upgrade/upgrade-component.sh',
        )
        old = b'left\nOLD-A\nmid\nOLD-B\nright\n'
        new = b'left\nNEW-A-X\nmid\nNEW-B-X\nright\n'
        regions = (
            (1, 5, 5, b'OLD-A\n', b'NEW-A-X\n', 0),
            (2, 15, 17, b'OLD-B\n', b'NEW-B-X\n', 0),
        )
        pins = {p: hashlib.sha256(old).hexdigest() for p in paths}
        with patch.dict(_NATIVE_OS_REGIONS, {p: regions for p in paths}, clear=True), \
                patch.dict(_NATIVE_OS_EXPECTED_U, pins, clear=True):
            integrated = {p: new for p in paths}
            originals = {p: old for p in paths}
            self.assertEqual(originals, _restore_native_os_layer(integrated))
            self.assertEqual(originals, _native_os_sources_before_native34(integrated))
            self.assertEqual(originals, _native_os_sources_before_native34(originals))
            with self.assertRaises(AssertionError):
                _restore_native_os_layer(originals)
            bad_vectors = {
                'missing-path': {p: new for p in paths[:-1]},
                'foreign-path': dict(integrated, **{'tools/foreign.py': new}),
                'partial-cohort': dict(integrated, **{paths[1]: old}),
            }
            for label, vector in bad_vectors.items():
                with self.subTest(vector=label), self.assertRaises(AssertionError):
                    _native_os_sources_before_native34(vector)
            bad_bytes = {
                'missing-hunk': new.replace(b'NEW-A-X\n', b'', 1),
                'truncated-hunk': new.replace(b'NEW-A-X\n', b'NEW-A-X', 1),
                'duplicate-hunk': new + b'NEW-A-X\n',
                'extra-old': new + b'OLD-A\n',
                'reordered': b'left\nNEW-B-X\nmid\nNEW-A-X\nright\n',
                'outside-prefix': b'!' + new[1:],
                'outside-middle': new.replace(b'mid\n', b'Mid\n', 1),
                'outside-suffix': new[:-1] + b'!',
            }
            for label, payload in bad_bytes.items():
                vector = dict(integrated, **{paths[0]: payload})
                with self.subTest(mutation=label), self.assertRaises(AssertionError):
                    _native_os_sources_before_native34(vector)
