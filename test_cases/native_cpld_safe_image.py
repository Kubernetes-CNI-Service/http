"""UNRUN test-only cold image preparation and mandatory executable IO gate.

No production import, discovery, grant, source search or child launch here.
Ordinary canonical isolation must prepare this fixed cohort before cold import.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import tempfile

from test_cases.native_cpld_physical_io import lower_fixed_io_images
from test_cases.native_cpld_stub_sources import executable_sources

PROVIDER = 'tools/ibsw_upgrade_scp.py'
TEMPLATE = 'infiniband/bringup/xdr-upgrade/upgrade-component.sh'
PROVIDER_PREIMAGE = '685cae25a02fae9cb447528c7a5e57abd3dc459f3247f9b5c5015662af7536d1'
TEMPLATE_PREIMAGE = 'a2bde38c42ff14cc73ed5c5cbd3859701e93a8193eb78ae67f2bd5575393b502'
COPY_FILES = (
    'tools/_package_common.py', 'tools/project_contract.py',
    'tools/ssh_key_preparation.py', 'tools/ib_bringup_runtime_guard.py',
    'tools/ibsw_upgrade_contract.py', 'tools/ibsw_upgrade_inputs.py',
    'tools/ibsw_upgrade_driver.py', 'tools/ibsw_upgrade_schedule.py',
    'tools/ibsw_upgrade_component.py', 'tools/ibsw_upgrade_observer.py',
    'tools/ibsw_upgrade_executor.py', 'tools/ibsw_upgrade_access.py',
    'tools/ibsw_upgrade_pipeline.py', PROVIDER,
    'infiniband/bringup/xdr-upgrade/upgrade.py',
    'infiniband/bringup/xdr-upgrade/upgrade.sh', TEMPLATE,
    'infiniband/bringup/xdr-upgrade/upgrade-owned-runner.sh',
    'infiniband/bringup/xdr-upgrade/requirements.txt',
    'test_cases/__init__.py', 'test_cases/module_loader.py',
    'test_cases/ibsw225_fixture_support/runtime_source_support.py',
    'test_cases/ibsw225_fixture_support/fixed_fixture_registry.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_upgrade_cli.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_known_hosts.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_manual_execution.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_nvos_observations.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_three_component_workflow.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_access_recovery.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_grouped_summary.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_runtime_budgets.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_os_alternatives.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_input_isolation.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_health_upgrade_gate.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_compact_summary.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_os_download_telemetry.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_standalone_links.py',
    'test_cases/fixtures/nvos-25.02.8008-system-version.txt',
    'test_cases/fixtures/nvos-system-health.txt',
    'test_cases/fixtures/nvos-six-cpld-firmware.txt',
    'test_cases/scp_source_cli_fixture.py',
    'test_cases/test_ibsw3_scp_source_cli_prompt_binding.py',
    'test_cases/scp_native_cpld_bridge_fixture.py',
    'test_cases/scp_native_cpld_bridge_isolation.py',
    'test_cases/native_cpld_physical_io.py',
    'test_cases/native_cpld_stub_sources.py',
    'test_cases/native_cpld_safe_image.py',
    'test_cases/test_ibsw3_native_cpld_bridge.py',
)
METADATA = 'native-cpld-safe-image.json'
PREPARED_METADATA = 'native-cpld-io-lowering.json'


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _read(path, *, mode=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or before.st_size > 4 * 1024 * 1024
                or mode is not None and stat.S_IMODE(before.st_mode) != mode):
            raise AssertionError('unsafe fixed image file')
        pieces = []
        while True:
            piece = os.read(fd, 65536)
            if not piece:
                break
            pieces.append(piece)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid,
                            s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if fields(before) != fields(after) or fields(after) != fields(named):
            raise AssertionError('fixed image source changed during read')
        return b''.join(pieces)
    finally:
        os.close(fd)


_OS22_TEMPLATE_REGIONS = (
    (4813, 4813,
(
            b"        temporary=\"\"\n"
            b"        ;;\n"
            b"    scp)\n"
            b"        # No SCP OS installer until genuine SCP-only manager ACK is closed.\n"
            b"        [[ \"$IBSW_COMPONENT\" != os ]] || exit 64\n"
            b"        : \"${scp_source:?bound source path required}\"\n"
            b"        : \"${IBSW_SCP_HELPER_B64:?fixed stdin-only helper required}\"\n"
            b"        read_scp_context\n"
        ),
(
            b"        temporary=\"\"\n"
            b"        ;;\n"
            b"    scp)\n"
            b"        # SCP OS waits for its exact content-bound manager V2 ACK below.\n"
            b"        : \"${scp_source:?bound source path required}\"\n"
            b"        : \"${IBSW_SCP_HELPER_B64:?fixed stdin-only helper required}\"\n"
            b"        read_scp_context\n"
        )),
    (6537, 6485,
(
            b"        done\n"
            b"        [[ -n \"$content\" && -n \"$measurement\" && -s \"$temporary\" ]] || exit 66\n"
            b"        printf '%s\\n' \"$content\" \"$measurement\"\n"
            b"        mv -- \"$temporary\" \"$IBSW_LOCAL_PACKAGE\"\n"
            b"        temporary=\"\"\n"
            b"        ;;\n"
        ),
(
            b"        done\n"
            b"        [[ -n \"$content\" && -n \"$measurement\" && -s \"$temporary\" ]] || exit 66\n"
            b"        printf '%s\\n' \"$content\" \"$measurement\"\n"
            b"        if [[ \"$IBSW_COMPONENT\" == os ]]; then\n"
            b"            # Public content DATA alone cannot release installation. The real\n"
            b"            # manager must finish its original reliable record before V2 ACK.\n"
            b"            printf '%s\\n' 'IBSW_STAGE=WAIT_DOWNLOAD_RECORD'\n"
            b"            local content_digest\n"
            b"            content_digest=$(/usr/bin/python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode(\"ascii\")).hexdigest())' \"$content\") || exit 66\n"
            b"            local ack_path=\"${BASH_SOURCE[0]%/*}/download-ack\"\n"
            b"            local expected=\"IBSW_SCP_DOWNLOAD_ACK_V2|$IBSW_RUN_ID|$content_digest|$measurement\" ack=\"\" waited=0\n"
            b"            while :; do\n"
            b"                if [[ -f \"$ack_path\" && ! -L \"$ack_path\" ]]; then\n"
            b"                    IFS= read -r ack < \"$ack_path\" || exit 66\n"
            b"                    [[ \"$ack\" == \"$expected\" ]] || exit 66\n"
            b"                    break\n"
            b"                fi\n"
            b"                (( waited < 300 )) || exit 75\n"
            b"                sleep 1\n"
            b"                waited=$((waited+1))\n"
            b"            done\n"
            b"        fi\n"
            b"        mv -- \"$temporary\" \"$IBSW_LOCAL_PACKAGE\"\n"
            b"        temporary=\"\"\n"
            b"        ;;\n"
        )),
    (6948, 7914,
(
            b"}\n"
            b"\n"
            b"# IBSW_BODY_OS\n"
            b"[[ \"$IBSW_METHOD\" != scp ]] || exit 64\n"
            b"prepare_package \"$IBSW_LOCAL_PACKAGE\" \"$IBSW_PACKAGE_URL\" \"${IBSW_SCP_PACKAGE_PATH:-}\"\n"
            b"# NVOS IB published FILE fetch, then default-reboot install. The latter can\n"
            b"# disconnect SSH before any final marker returns; do not resend it on timeout.\n"
        ),
(
            b"}\n"
            b"\n"
            b"# IBSW_BODY_OS\n"
            b"prepare_package \"$IBSW_LOCAL_PACKAGE\" \"$IBSW_PACKAGE_URL\" \"${IBSW_SCP_PACKAGE_PATH:-}\"\n"
            b"# NVOS IB published FILE fetch, then default-reboot install. The latter can\n"
            b"# disconnect SSH before any final marker returns; do not resend it on timeout.\n"
        )),
)


def _template_preimage(template):
    """Only verify old template SHA; never return old bytes for execution."""
    if type(template) is not bytes:
        raise AssertionError('fixed template bytes required')
    if _sha(template) == TEMPLATE_PREIMAGE:
        return template
    spans = []
    previous = 0
    for old_offset, new_offset, old, new in _OS22_TEMPLATE_REGIONS:
        if (template.count(new) != 1 or template.count(old) != 0
                or template.find(new) != new_offset or new_offset < previous):
            raise AssertionError('complete unique reviewed OS template layer required')
        spans.append((new_offset, old, new))
        previous = new_offset + len(new)
    original = template
    for offset, old, new in reversed(spans):
        original = original[:offset] + old + original[offset + len(new):]
    if (_sha(original) != TEMPLATE_PREIMAGE
            or any(original[offset:offset + len(old)] != old
                   for offset, _new_offset, old, _new in _OS22_TEMPLATE_REGIONS)):
        raise AssertionError('whole original template preimage inverse failed')
    return original


def _restore(provider, template, old_root):
    """Verify IO1/1/4 then OS3 inverse; keep actual unlowered template bytes."""
    if type(provider) is not bytes or type(template) is not bytes:
        raise AssertionError('fixed original provider/template bytes required')
    if _sha(provider) == PROVIDER_PREIMAGE:
        _template_preimage(template)  # Validation only, never execution source.
        return provider, template
    restored = provider
    for label in ('SSH', 'SCP'):
        old = (label + ' = ' + repr(str(old_root / 'tools/native-cpld-io' /
                                       ('private-' + label.lower())))).encode()
        new = (label + " = '/usr/bin/" + label.lower() + "'").encode()
        if restored.count(old) != 1 or restored.count(new) != 0:
            raise AssertionError('not the exact approved provider IO lowering')
        restored = restored.replace(old, new, 1)
    marker = b'# IBSW_BODY_CPLD\n'
    if template.count(marker) != 1:
        raise AssertionError('fixed CPLD section missing')
    prefix, body = template.split(marker, 1)
    token = ('\n' + shlex.quote(str(old_root / 'tools/native-cpld-io/private-nv')) + ' ').encode()
    if body.count(token) != 4 or b'\nnv ' in body:
        raise AssertionError('not the exact approved template IO lowering')
    result = prefix + marker + body.replace(token, b'\nnv ')
    if _sha(restored) != PROVIDER_PREIMAGE:
        raise AssertionError('full original provider byte inverse failed')
    _template_preimage(result)  # Check old whole SHA, retain actual common bytes.
    return restored, result


def prepare_image(source):
    """Copy only literal cohort, lower only 1+1+4 sites, no production imports."""
    source = Path(source).resolve()
    image = Path(tempfile.mkdtemp(prefix='native-cpld-isolated-', dir='/private/tmp')).resolve()
    originals = {}
    for relative in COPY_FILES:
        path = source / relative
        if path.resolve() != path:
            raise AssertionError('fixed copy source symlink refused')
        originals[relative] = _read(path)
    if _sha(originals[PROVIDER]) != PROVIDER_PREIMAGE:
        raise AssertionError('new image requires exact unlowered reviewed provider')
    _template_preimage(originals[TEMPLATE])  # Validate, do not substitute old bytes.
    provider, template = originals[PROVIDER], originals[TEMPLATE]
    private = image / 'tools/native-cpld-io'
    private.mkdir(parents=True, mode=0o700)
    private.parent.chmod(0o700)
    stub_hashes = {}
    for name, raw in executable_sources().items():
        target = private / name
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(0o700)
        stub_hashes[name] = _sha(raw)
    lowered_p, lowered_t, inverse = lower_fixed_io_images(provider, template,
        private/'private-ssh', private/'private-scp', private/'private-nv')
    originals[PROVIDER], originals[TEMPLATE] = lowered_p, lowered_t
    hashes = {}
    for relative, raw in originals.items():
        target = image / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(0o600)
        hashes[relative] = _sha(raw)
    metadata = dict(schema=1, image=str(image), hashes=hashes,
                    stubs=stub_hashes, io_lowering=inverse)
    with (image / METADATA).open('x') as stream:
        json.dump(metadata, stream, sort_keys=True)
    (image / METADATA).chmod(0o600)
    validate_image(image)
    return image


def select_image(source):
    """Existing evidence must validate; never silently repair/reprepare it."""
    source = Path(source).resolve()
    present = [name for name in (METADATA, PREPARED_METADATA)
               if os.path.lexists(source / name)]
    if present:
        if len(present) != 1:
            raise AssertionError('ambiguous prepared image metadata')
        validate_image(source)
        return source
    return prepare_image(source)


def _validate_prepared(image):
    """Old preparation record binds ONLY immutable IO inverse, not old fixture SHA.

    The historical fixture_sources entries are intentionally NOT adopted as
    current. Current fixed files are read below, and cold imports/audits remain
    normal. Stub bytes come from this independent literal builder, not metadata.
    """
    if (not image.name.startswith('http-scp-native-cpld-bridge-')
            or os.path.lexists(image / METADATA)):
        raise AssertionError('unexpected legacy prepared image')
    meta = json.loads(_read(image / PREPARED_METADATA))
    if (set(meta) != {'fixture_sources', 'io_lowering', 'private_image', 'production_modules_imported'}
            or meta['private_image'] != str(image)
            or meta['production_modules_imported'] is not False):
        raise AssertionError('immutable original preparation record required')
    for relative in COPY_FILES:
        path = image / relative
        if path.resolve() != path:
            raise AssertionError('prepared fixed source symlink refused')
        _read(path)
    for name, raw in executable_sources().items():
        path = image / 'tools/native-cpld-io' / name
        if path.resolve() != path or _read(path, mode=0o700) != raw:
            raise AssertionError('prepared executable differs from independent literal stub')
    p, t = _read(image / PROVIDER), _read(image / TEMPLATE)
    original_p, original_t = _restore(p, t, image)
    private = image / 'tools/native-cpld-io'
    expected_p, expected_t, inverse = lower_fixed_io_images(original_p, original_t,
        private/'private-ssh', private/'private-scp', private/'private-nv')
    if (p != expected_p or t != expected_t
            or meta['io_lowering'] != json.loads(json.dumps(inverse))):
        raise AssertionError('prepared immutable source inverse no longer valid')
    return p


def validate_image(image):
    image = Path(image)
    if (image.resolve() != image or image.parent != Path('/private/tmp')
            or stat.S_IMODE(image.stat().st_mode) != 0o700
            or image.stat().st_uid != os.geteuid()):
        raise AssertionError('exclusive test image identity required')
    if os.path.lexists(image / PREPARED_METADATA):
        return _validate_prepared(image)
    if not image.name.startswith('native-cpld-isolated-'):
        raise AssertionError('new private image metadata required')
    metadata = json.loads(_read(image / METADATA, mode=0o600))
    if (set(metadata) != {'schema', 'image', 'hashes', 'stubs', 'io_lowering'}
            or metadata['schema'] != 1 or metadata['image'] != str(image)
            or set(metadata['hashes']) != set(COPY_FILES)):
        raise AssertionError('fixed complete image metadata required before execution')
    for relative in COPY_FILES:
        path = image / relative
        if path.resolve() != path or _sha(_read(path, mode=0o600)) != metadata['hashes'][relative]:
            raise AssertionError('cold image source identity changed')
    stubs = executable_sources()
    if set(metadata['stubs']) != set(stubs):
        raise AssertionError('fixed executable stub roster required')
    for name, raw in stubs.items():
        path = image / 'tools/native-cpld-io' / name
        if (path.resolve() != path or _read(path, mode=0o700) != raw
                or metadata['stubs'][name] != _sha(raw)):
            raise AssertionError('independent literal private executable mismatch')
    p, t = _read(image / PROVIDER), _read(image / TEMPLATE)
    original_p, original_t = _restore(p, t, image)
    private = image / 'tools/native-cpld-io'
    expected_p, expected_t, inverse = lower_fixed_io_images(original_p, original_t,
        private/'private-ssh', private/'private-scp', private/'private-nv')
    # JSON represents tuples as lists; compare through its canonical DATA form.
    if (p != expected_p or t != expected_t
            or metadata['io_lowering'] != json.loads(json.dumps(inverse))):
        raise AssertionError('exact pre-import executable lowering required')
    return p


def require_safe_command(image, words):
    """Before ANY actual channel Popen: no metadata or wrong literal => refuse."""
    provider = validate_image(image)
    constants = {}
    for node in ast.parse(provider).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ('_REMOTE_HELPER', '_STDIN_LAUNCHER'):
                    if target.id in constants or not isinstance(node.value, ast.Constant) or type(node.value.value) is not str:
                        raise AssertionError('unique fixed producer literal required')
                    constants[target.id] = node.value.value
    if set(constants) != {'_REMOTE_HELPER', '_STDIN_LAUNCHER'}:
        raise AssertionError('complete fixed producer literals required')
    if words[:2] != ['/usr/bin/python3', '-c'] or len(words) not in (4, 6):
        raise AssertionError('fixed probe/launcher shape required')
    if len(words) == 4:
        if words[3] != 'probe':
            raise AssertionError('fixed probe role required')
        body = "import os\nos.environ.pop('IBSW_SCP_AUTH',None)\n" + constants['_REMOTE_HELPER']
    else:
        body = constants['_STDIN_LAUNCHER']
        if (not Path(words[3]).is_absolute() or Path(words[3]).name != 'step.sh'
                or any(len(s) != 64 or any(c not in '0123456789abcdef' for c in s) for s in words[4:])):
            raise AssertionError('fixed launch arguments required')
    expected = 'import base64;exec(base64.b64decode(' + repr(base64.b64encode(body.encode()).decode()) + '))'
    if words[2] != expected:
        raise AssertionError('only exact lowered fixed producer expressions may execute')
