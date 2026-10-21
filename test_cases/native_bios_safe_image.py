"""UNRUN test-only cold image preparation and mandatory executable IO gate.

No production import, discovery, grant, source search or child launch here.
Ordinary canonical isolation must prepare this fixed cohort before cold import.
"""
import ast
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import stat
import tempfile

from test_cases.native_bios_physical_io import lower_fixed_io_images, _sections
from test_cases.native_bios_stub_sources import executable_sources
from test_cases.native_os_safe_image import (
    _native_os_reviewed_source_bytes as _previous_source_vector, PRODUCTION_PINS)

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
    'test_cases/native_bios_physical_io.py',
    'test_cases/native_bios_safe_image.py',
    'test_cases/native_bios_stub_sources.py',
    'test_cases/native_bios_isolation.py',
    'test_cases/native_bios_flow.py',
    'test_cases/test_ibsw3_native_bios_bridge.py',
    'test_cases/native_os_safe_image.py',
    'test_cases/native_os_stub_sources.py',
)
METADATA = 'native-bios-safe-image.json'
PREPARED_METADATA = 'native-bios-io-lowering.json'


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
    """Exact BIOS IO1/1/2 inverse then original whole template OS3 inverse."""
    if type(provider) is not bytes or type(template) is not bytes:
        raise AssertionError('fixed original provider/template bytes required')
    if _sha(provider) == PROVIDER_PREIMAGE:
        _template_preimage(template)
        return provider, template
    restored = provider
    for label in ('SSH', 'SCP'):
        old = (label + ' = ' + repr(str(old_root / 'tools/native-bios-io' /
                                       ('private-' + label.lower())))).encode()
        new = (label + " = '/usr/bin/" + label.lower() + "'").encode()
        if restored.count(old) != 1 or new in restored:
            raise AssertionError('exact BIOS source IO lowering required')
        restored = restored.replace(old, new, 1)
    common, os_body, bios_body, cpld_body = _sections(template)
    token = ('\n' + shlex.quote(str(old_root / 'tools/native-bios-io/private-nv')) + ' ').encode()
    if (bios_body.count(token) != 2 or b'\nnv ' in bios_body
            or token in common or token in os_body or token in cpld_body):
        raise AssertionError('only exact BIOS2 sites may be lowered')
    result = (common + b'# IBSW_BODY_OS\n' + os_body + b'# IBSW_BODY_BIOS\n' +
              bios_body.replace(token, b'\nnv ') + b'# IBSW_BODY_CPLD\n' + cpld_body)
    if _sha(restored) != PROVIDER_PREIMAGE:
        raise AssertionError('whole original source provider inverse differs')
    _template_preimage(result)
    return restored, result



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
        if _sha(original) != _BIOS_TARGETS[path]:
            raise AssertionError('whole previous OS22 source differs after BIOS inverse')
        restored[path] = original
    return restored

def _verified_source_vector(files):
    """Validate only; never substitute inverse old bytes into execution image."""
    vector = dict(files)
    if not all(type(vector.get(p)) is bytes and _sha(vector[p]) == digest
               for p, digest in _BIOS_TARGETS.items()):
        vector.update(_restore_bios_layer({p: vector[p] for p in _BIOS_TARGETS}))
    # Original display2/OS22 -> all19 unchanged U whole pins.
    return _previous_source_vector(vector)


def prepare_image(source):
    """Copy only literal cohort, lower only 1+1+2 BIOS sites, no production imports."""
    source = Path(source).resolve()
    originals = {}
    for relative in COPY_FILES:
        path = source / relative
        if path.resolve() != path:
            raise AssertionError('fixed copy source symlink refused')
        originals[relative] = _read(path)
    if _sha(originals[PROVIDER]) != PROVIDER_PREIMAGE:
        raise AssertionError('new image requires exact unlowered reviewed provider')
    _template_preimage(originals[TEMPLATE])  # Validate, do not substitute old bytes.
    _verified_source_vector(originals)
    image = Path(tempfile.mkdtemp(prefix='native-bios-isolated-', dir='/private/tmp')).resolve()
    print('IBSW_BIOS_PREPARED_IMAGE=' + str(image), flush=True)
    provider, template = originals[PROVIDER], originals[TEMPLATE]
    private = image / 'tools/native-bios-io'
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


def validate_image(image):
    image = Path(image)
    if (image.resolve() != image or image.parent != Path('/private/tmp')
            or stat.S_IMODE(image.stat().st_mode) != 0o700
            or image.stat().st_uid != os.geteuid()):
        raise AssertionError('exclusive test image identity required')
    if os.path.lexists(image / PREPARED_METADATA):
        raise AssertionError('legacy prepared images are not BIOS input')
    if not image.name.startswith('native-bios-isolated-'):
        raise AssertionError('new private image metadata required')
    metadata = json.loads(_read(image / METADATA, mode=0o600))
    if (set(metadata) != {'schema', 'image', 'hashes', 'stubs', 'io_lowering'}
            or metadata['schema'] != 1 or metadata['image'] != str(image)
            or set(metadata['hashes']) != set(COPY_FILES)):
        raise AssertionError('fixed complete image metadata required before execution')
    files = {}
    for relative in COPY_FILES:
        path = image / relative
        raw = _read(path, mode=0o600)
        if path.resolve() != path or _sha(raw) != metadata['hashes'][relative]:
            raise AssertionError('cold image source identity changed')
        files[relative] = raw
    stubs = executable_sources()
    if set(metadata['stubs']) != set(stubs):
        raise AssertionError('fixed executable stub roster required')
    for name, raw in stubs.items():
        path = image / 'tools/native-bios-io' / name
        if (path.resolve() != path or _read(path, mode=0o700) != raw
                or metadata['stubs'][name] != _sha(raw)):
            raise AssertionError('independent literal private executable mismatch')
    p, t = _read(image / PROVIDER), _read(image / TEMPLATE)
    original_p, original_t = _restore(p, t, image)
    private = image / 'tools/native-bios-io'
    expected_p, expected_t, inverse = lower_fixed_io_images(original_p, original_t,
        private/'private-ssh', private/'private-scp', private/'private-nv')
    files[PROVIDER], files[TEMPLATE] = original_p, original_t
    _verified_source_vector(files)
    # JSON represents tuples as lists; compare through its canonical DATA form.
    if (p != expected_p or t != expected_t
            or metadata['io_lowering'] != json.loads(json.dumps(inverse))):
        raise AssertionError('exact pre-import executable lowering required')
    return p


def _assignments(raw, names, banner):
    if not raw.startswith(banner):
        raise AssertionError('exact original generated source header required')
    lines = raw[len(banner):].decode('ascii').splitlines()
    if len(lines) != len(names):
        raise AssertionError('extra/missing shell assignments refused')
    result = {}
    for line, name in zip(lines, names):
        tokens = shlex.split(line)
        if len(tokens) != 1 or not tokens[0].startswith(name + '='):
            raise AssertionError('literal canonical shell assignment required')
        value = tokens[0][len(name) + 1:]
        if line != name + '=' + shlex.quote(value):
            raise AssertionError('noncanonical shell source refused')
        result[name] = value
    return result


def require_safe_command(image, words, root):
    """Test exec safety only; never replaces live production graph validation."""
    validate_image(image)
    original_runner = _read(image / 'infiniband/bringup/xdr-upgrade/upgrade-owned-runner.sh')
    lowered_provider = _read(image / PROVIDER)
    constants = {}
    for node in ast.parse(lowered_provider).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ('_REMOTE_HELPER', '_STDIN_LAUNCHER'):
                    if target.id in constants or not isinstance(node.value, ast.Constant) or type(node.value.value) is not str:
                        raise AssertionError('unique fixed producer literal required')
                    constants[target.id] = node.value.value
    if set(constants) != {'_REMOTE_HELPER', '_STDIN_LAUNCHER'}:
        raise AssertionError('fixed producer literals missing')
    if words[:2] != ['/usr/bin/python3', '-c'] or len(words) not in (4, 6):
        raise AssertionError('only fixed probe or original stdin launcher')
    body = ("import os\nos.environ.pop('IBSW_SCP_AUTH',None)\n" + constants['_REMOTE_HELPER']
            if len(words) == 4 else constants['_STDIN_LAUNCHER'])
    expected = 'import base64;exec(base64.b64decode(' + repr(base64.b64encode(body.encode()).decode()) + '))'
    if words[2] != expected or len(words) == 4 and words[3] != 'probe':
        raise AssertionError('exact fixed expression required')
    if len(words) == 4:
        return 'probe'
    root = Path(root); switch = root / 'switch'
    remote = Path(words[3]); directory = remote.parent
    if (remote.name != 'step.sh' or directory.parent != switch or directory.resolve() != directory
            or not re.fullmatch(r'\.ibsw-[A-Za-z0-9][A-Za-z0-9_-]{0,95}-ew-spine0[12]\.example-bios-[0-9a-f]{32}', directory.name)):
        raise AssertionError('fixed actual BIOS remote request namespace required')
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
        raise AssertionError('actual private generated directory required')
    step = _read(remote, mode=0o600); runner = _read(directory / 'runner.sh', mode=0o600)
    if [_sha(runner), _sha(step)] != words[4:]:
        raise AssertionError('actual original uploaded bytes must match fixed command')
    # Use LOWERED reviewed template body, not the inverse's unlowered NV sites.
    common, _os_body, bios_body, _cpld = _sections(_read(image / TEMPLATE))
    step_body = common + bios_body
    if not step.endswith(step_body):
        raise AssertionError('whole original generated BIOS body required')
    names = ('IBSW_RUN_ID', 'IBSW_COMPONENT', 'IBSW_METHOD', 'IBSW_PACKAGE_FILE',
        'IBSW_PACKAGE_URL', 'IBSW_SWITCH_DIR', 'IBSW_LOCAL_PACKAGE', 'IBSW_BINDING_JSON',
        'IBSW_EXPECTED_EFFECT', 'IBSW_SCP_HELPER_B64', 'IBSW_SCP_PACKAGE_PATH')
    values = _assignments(step[:-len(step_body)], names,
        b'#!/bin/bash\n# Generated IB NVOS component plan artifact; not execution permission.\n')
    package = '0ACQF.cab'
    binding = json.loads(values['IBSW_BINDING_JSON'])
    if (type(binding) is not list or len(binding) != 6 or binding[1] not in
            ('ew-spine01.example', 'ew-spine02.example')):
        raise AssertionError('fixed fixture node tuple required')
    number = int(binding[1][8:10])
    if (binding != [values['IBSW_RUN_ID'], binding[1], '192.0.2.' + str(number),
                    '02:00:00:00:00:0' + str(number), 'bios', '0ACQF_06.01.009']
            or values['IBSW_BINDING_JSON'] != json.dumps(binding, ensure_ascii=True, separators=(',', ':'))
            or values['IBSW_COMPONENT'] != 'bios' or values['IBSW_METHOD'] != 'scp'
            or values['IBSW_PACKAGE_FILE'] != package or values['IBSW_PACKAGE_URL'] != ''
            or values['IBSW_SWITCH_DIR'] != str(switch)
            or values['IBSW_LOCAL_PACKAGE'] != str(switch / package)
            or values['IBSW_EXPECTED_EFFECT'] != 'REBOOT_EXPECTED'
            or values['IBSW_SCP_PACKAGE_PATH'] != str(root / 'packages/firmware' / package)
            or values['IBSW_SCP_HELPER_B64'] != base64.b64encode(
                ("import os\nos.environ.pop('IBSW_SCP_AUTH',None)\n" + constants['_REMOTE_HELPER']).encode()).decode()):
        raise AssertionError('fixed original BIOS generated header differs')
    run_id = values['IBSW_RUN_ID']
    prefix = '.ibsw-' + run_id + '-' + binding[1] + '-bios-'
    if not directory.name.startswith(prefix) or not re.fullmatch('[0-9a-f]{32}', directory.name[len(prefix):]):
        raise AssertionError('remote namespace differs from original header')
    runner_body = original_runner
    if not runner.endswith(runner_body):
        raise AssertionError('original owned runner whole body required')
    keys = ('IBSW_RUN_ID', 'IBSW_NODE', 'IBSW_COMPONENT', 'IBSW_STAGE',
            'IBSW_SCRIPT_SHA256', 'IBSW_ORIGINAL_STEP', 'IBSW_EXIT_RECORD')
    rv = _assignments(runner[:-len(runner_body)], keys, b'#!/bin/bash\n')
    if rv != dict(zip(keys, (run_id, binding[1], 'bios', 'bios', _sha(step),
                            str(remote), str(directory / 'owned-exit.record')))):
        raise AssertionError('original owned runner header binding differs')
    for name in ('execution.stdout', 'execution.stderr'):
        if _read(directory / name, mode=0o600):
            raise AssertionError('fresh precreated original output required')
    return 'native-bios-launcher'
