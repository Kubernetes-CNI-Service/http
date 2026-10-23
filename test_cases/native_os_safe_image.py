"""NOTRUN finite native OS test image / execution IO safety, never authority."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile

from test_cases.native_cpld_safe_image import COPY_FILES as BASE_FILES, _read
from test_cases.native_os_stub_sources import executable_sources

PROVIDER = 'tools/ibsw_upgrade_scp.py'
TEMPLATE = 'infiniband/bringup/xdr-upgrade/upgrade-component.sh'
RUNNER = 'infiniband/bringup/xdr-upgrade/upgrade-owned-runner.sh'
METADATA = 'native-os-safe-image.json'
EXTRA_FILES = tuple('test_cases/' + name for name in (
    'native_os_stub_sources.py', 'native_os_safe_image.py', 'native_os_dual_channel.py',
    'native_os_physical_bridge.py', 'native_os_test_isolation.py',
    'scp_native_os_manager_fixture.py', 'test_ibsw3_native_os_manager_workflow.py'))
COPY_FILES = BASE_FILES + EXTRA_FILES
# Baseline only. Root must independently review candidate implementation inverse
# before extending this exact source roster; no adopt-current-hash fallback.
# 2026-10-23: tools/_package_common.py and tools/project_contract.py re-pinned to the reviewed UFM/F01
# integration (owner-approved setup links, reference-only subtree, server_ufm/server_mgmt types; was the
# 7c44779 bytes). Both are compared whole only; no inverse layer covers them.
PRODUCTION_PINS = {
    'tools/_package_common.py': 'a3c55bfe13a831d75e01516cbb238c44eb756166005a49c78adf76705b73e2ef',
    'tools/project_contract.py': 'cff03898c923d83989ebb3677b079392f68e1e7559b00afdbf79ea3f700febb6',
    'tools/ssh_key_preparation.py': '16a383dfff78cfb9410db50d63ae4b25ad885021445ce8567c9a6d95f2a36352',
    'tools/ib_bringup_runtime_guard.py': 'f8f7815ec8438d21749d1a0bda3bf3ae47d485cf40e81e98ddcf594fc447f594',
    'tools/ibsw_upgrade_contract.py': 'e9163ecf5363db5401377d1e044cc36750b0045168d119a9f40bf5dd9d1f616b',
    'tools/ibsw_upgrade_inputs.py': '75c700e576b9fb6bd8ce5a117aa2f0c0f6e7ea96f9a1a12bc973ef814a13cbae',
    'tools/ibsw_upgrade_driver.py': '887a3faf2808cfd2107849825cea2a14fe041f9468987249c5bba07c39030f01',
    'tools/ibsw_upgrade_schedule.py': '547f957b99e7df2c8d1dfe682e501a37c31cf03e601f86564135d9bc3a287fb2',
    'tools/ibsw_upgrade_component.py': '1ab3b4b6bb75f11a01816f35ef788b701df2e16489e4c8054709502fd8f2f2d1',
    'tools/ibsw_upgrade_observer.py': '46614501ad84e3d0d6b98fa83c9671df55431ee64e3e31901159152e5e67ece9',
    'tools/ibsw_upgrade_executor.py': '1736c076376873e2de2a2ce14639cde357bf15f058f0e486fcbf176b5ef02f51',
    'tools/ibsw_upgrade_access.py': '67eb3f6f30ab347e2860905dc1ac42e34acb8929074ce64975781b8f5e295858',
    'tools/ibsw_upgrade_pipeline.py': '38196135304c47b07e89325b4427549170fbc2d364151fbae7fbab0c2ad0f5cb',
    PROVIDER: '685cae25a02fae9cb447528c7a5e57abd3dc459f3247f9b5c5015662af7536d1',
    'infiniband/bringup/xdr-upgrade/upgrade.py': '95f325fadff8d294b3917e23efbdf5540413c12b0d0571911dc268b89a94596f',
    'infiniband/bringup/xdr-upgrade/upgrade.sh': '0ddbbf01f920bb3f4d6dcd9406083c8ca407d8edba94aad49669b8bb36899e65',
    TEMPLATE: 'a2bde38c42ff14cc73ed5c5cbd3859701e93a8193eb78ae67f2bd5575393b502',
    RUNNER: 'cb9cc7d68fda9e24972e6335e58e5c6fa196e8d685532d949b78e290e654e1e2',
    'infiniband/bringup/xdr-upgrade/requirements.txt': 'c423e2d749ccb1ca7e5434c36f465a3906a874e3fe46f5e1abd9649861eb17e7',
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


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
        if _sha(original) != PRODUCTION_PINS[path]:
            raise AssertionError('whole original U source SHA differs after finite native OS inverse')
        restored[path] = original
    return restored


# Display-only pre-layer; reviewed diff4238f0, not a new whole-hash allowance.
_NATIVE_DISPLAY_ENTRY = 'infiniband/bringup/xdr-upgrade/upgrade.py'
# (U offset, candidate offset, old complete hunk literal, new complete literal)
_NATIVE_DISPLAY_REGIONS = (
    # display1: old583B/b9679900bfb5a955819be72dcc665391f3cba50ac958f739db852c5a9038992c; new743B/84d4d2a84738d6b5b597f395428db25107a4e7b1c6f4ed7d21b71d4a9d13c14c; retained-old0.
    (60975, 60975,
(
            b'            except queue.Empty: break\n'
            b'            row=record[\'measurement\']\n'
            b'            if not quiet:\n'
            b'                sys.stderr.write(f"[OS DOWNLOAD] {record[\'hostname\']} {record[\'stage\']} attempt={row[\'attempt\']} "\n'
            b'                    f"bytes={row[\'bytes_downloaded\']} elapsed={row[\'elapsed_seconds\']:.3f}s "\n'
            b'                    f"avg={row[\'average_bytes_per_second\']/1000000:.2f}MB/s "\n'
            b'                    f"http={row[\'http_status\']} curl-exit={row[\'curl_exit\']}\\n")\n'
            b'        while True:\n'
            b'            try:\n'
            b'                hostname, component, stage, stamp = self.queue.get_nowait()\n'
        ),
(
            b'            except queue.Empty: break\n'
            b'            row=record[\'measurement\']\n'
            b'            if not quiet:\n'
            b'                transport=(f"scp-exit={row[\'scp_exit\']} reserved-status={row[\'reserved_status\']}"\n'
            b'                    if \'scp_exit\' in row else f"http={row[\'http_status\']} curl-exit={row[\'curl_exit\']}")\n'
            b'                sys.stderr.write(f"[OS DOWNLOAD] {record[\'hostname\']} {record[\'stage\']} attempt={row[\'attempt\']} "\n'
            b'                    f"bytes={row[\'bytes_downloaded\']} elapsed={row[\'elapsed_seconds\']:.3f}s "\n'
            b'                    f"avg={row[\'average_bytes_per_second\']/1000000:.2f}MB/s "\n'
            b'                    f"{transport}\\n")\n'
            b'        while True:\n'
            b'            try:\n'
            b'                hostname, component, stage, stamp = self.queue.get_nowait()\n'
        )),
    # display2: old1027B/80a8982430db3cf32027f17bee84b0d7bc665232847b42beb9353be6ea8b7b00; new1337B/20c8e6ee045fd4978251b8622e3f0bb9fde1bc07a5f396dbc0059ddcddf1274e; retained-old0.
    (103439, 103599,
(
            b'            measurements=summary[\'os_downloads\']\n'
            b'            add(\'  OS image download measurements (not installation results):\')\n'
            b'            add(\'    Attempts=\'+str(len(measurements))+\' successful-transfers=\'+str(sum(\n'
            b'                r[\'measurement\'][\'curl_exit\']==0 and r[\'measurement\'][\'http_status\']==200 for r in measurements)))\n'
            b'            for record in sorted(measurements,key=lambda r:(r[\'hostname\'].casefold(),r[\'stage\'],r[\'measurement\'][\'attempt\'])):\n'
            b'                row=record[\'measurement\']\n'
            b'                detail(\'    \'+device_name(record[\'hostname\'],\'os\')+\' \'+record[\'stage\']+\': \',\n'
            b'                    f"attempt={row[\'attempt\']} {row[\'bytes_downloaded\']/1000000:.1f}MB "\n'
            b'                    f"{row[\'elapsed_seconds\']:.3f}s avg={row[\'average_bytes_per_second\']/1000000:.2f}MB/s "\n'
            b'                    f"HTTP={row[\'http_status\']} curl-exit={row[\'curl_exit\']}")\n'
            b'    if summary.get(\'ssd_checks\') and not any(p[\'component\']==\'os\' for p in view[\'component_groups\']):\n'
            b'        ssd_results()\n'
            b'    section(\'04 HEALTH CHECKS\')\n'
        ),
(
            b'            measurements=summary[\'os_downloads\']\n'
            b'            add(\'  OS image download measurements (not installation results):\')\n'
            b'            add(\'    Attempts=\'+str(len(measurements))+\' successful-transfers=\'+str(sum(\n'
            b'                (r[\'measurement\'][\'scp_exit\']==0 and r[\'measurement\'][\'reserved_status\']==0\n'
            b'                 if \'scp_exit\' in r[\'measurement\'] else\n'
            b'                 r[\'measurement\'][\'curl_exit\']==0 and r[\'measurement\'][\'http_status\']==200) for r in measurements)))\n'
            b'            for record in sorted(measurements,key=lambda r:(r[\'hostname\'].casefold(),r[\'stage\'],r[\'measurement\'][\'attempt\'])):\n'
            b'                row=record[\'measurement\']\n'
            b'                transport=(f"SCP-exit={row[\'scp_exit\']} reserved-status={row[\'reserved_status\']}"\n'
            b'                    if \'scp_exit\' in row else f"HTTP={row[\'http_status\']} curl-exit={row[\'curl_exit\']}")\n'
            b'                detail(\'    \'+device_name(record[\'hostname\'],\'os\')+\' \'+record[\'stage\']+\': \',\n'
            b'                    f"attempt={row[\'attempt\']} {row[\'bytes_downloaded\']/1000000:.1f}MB "\n'
            b'                    f"{row[\'elapsed_seconds\']:.3f}s avg={row[\'average_bytes_per_second\']/1000000:.2f}MB/s "\n'
            b'                    f"{transport}")\n'
            b'    if summary.get(\'ssd_checks\') and not any(p[\'component\']==\'os\' for p in view[\'component_groups\']):\n'
            b'        ssd_results()\n'
            b'    section(\'04 HEALTH CHECKS\')\n'
        )),
)


def _restore_native_display_layer(payload):
    """Reverse only exact display2; unchanged/partial/foreign bytes refuse."""
    if type(payload) is not bytes:
        raise AssertionError('original entry source bytes required')
    spans, previous_new_end, previous_old_end, difference = [], 0, 0, 0
    for old_offset, new_offset, old, new in _NATIVE_DISPLAY_REGIONS:
        if (payload.count(new) != 1 or payload.find(new) != new_offset
                or payload.count(old) != 0 or new_offset < previous_new_end
                or old_offset < previous_old_end or new_offset + difference != old_offset):
            raise AssertionError('missing/duplicate/old/reordered display literal region')
        spans.append((new_offset, new, old))
        previous_new_end, previous_old_end = new_offset + len(new), old_offset + len(old)
        difference += len(old) - len(new)
    pieces, cursor = [], 0
    for offset, new, old in spans:
        pieces.extend((payload[cursor:offset], old))
        cursor = offset + len(new)
    pieces.append(payload[cursor:])
    original = b''.join(pieces)
    if _sha(original) != PRODUCTION_PINS[_NATIVE_DISPLAY_ENTRY]:
        raise AssertionError('whole original entry SHA differs after display2 inverse')
    return original



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


_NATIVE_TRANSFER_WORDING_REGIONS = (
    (6210, 6210,
     b'                "Same-source input symlinks are supported; load/setup is not required. HTTP only. "\n',
     b'                "Same-source input symlinks are supported; load/setup is not required. "\n'
     b'                "HTTP is the default transfer; SCP requires explicit selection. "\n'
     b'                "HTTPS is unsupported; no automatic transport fallback. "\n'),
    (30250, 30395,
     b'    "project HTTP is not enabled": ("HTTP_POLICY", "HTTP is disabled in global; enable the approved project HTTP configuration before continuing. This entry supports HTTP only; HTTPS, SCP and local are not fallback transports."),\n',
     b'    "project HTTP is not enabled": ("HTTP_POLICY", "HTTP is disabled in global; enable the approved project HTTP configuration before continuing. HTTP mode does not fall back to SCP, HTTPS or local transport."),\n'),
)


def _restore_native_transfer_wording_layer(payload):
    """Reverse two reviewed wording literals to W; not a new source grant."""
    if type(payload) is not bytes:
        raise AssertionError('original entry source bytes required')
    spans, previous_new_end, previous_old_end, difference = [], 0, 0, 0
    for old_offset, new_offset, old, new in _NATIVE_TRANSFER_WORDING_REGIONS:
        if (payload.count(new) != 1 or payload.find(new) != new_offset
                or payload.count(old) != 0 or new_offset < previous_new_end
                or old_offset < previous_old_end or new_offset + difference != old_offset):
            raise AssertionError('missing/duplicate/old/reordered wording literal region')
        spans.append((new_offset, new, old))
        previous_new_end, previous_old_end = new_offset + len(new), old_offset + len(old)
        difference += len(old) - len(new)
    pieces, cursor = [], 0
    for offset, new, old in spans:
        pieces.extend((payload[cursor:offset], old))
        cursor = offset + len(new)
    pieces.append(payload[cursor:])
    original = b''.join(pieces)
    if _sha(original) != '5fc48f933cdeaa4defd4414941c5e29d2f7e4836095dae4bb97b31ed29232efe':
        raise AssertionError('whole previous entry SHA differs after wording2 inverse')
    return original


# Operator-usability pre-layer above wording2 (fixed SSH-runtime venv switch,
# in-process open-file soft limit, post-inspection upgrade offer): the reviewed
# diff from the previous entry (020fe60 bytes), not a new whole-hash allowance.
# Literals between the markers are generated from that diff by a script that
# refuses unless the previous entry restores through wording2/display2 to the
# unchanged U pin; never edit them by hand.
# BEGIN GENERATED NATIVE USABILITY LAYER
# Generated from the diff HEAD -> working tree of infiniband/bringup/xdr-upgrade/upgrade.py;
# context=3 lines, 11 hunks. Never edit by hand.
# (previous offset, candidate offset, old complete hunk literal, new complete literal)
_NATIVE_USABILITY_BEFORE_SHA256 = 'a09290b10ec18886fe61bce831739f51642f1a702e76511be88cff23c120b358'
_NATIVE_USABILITY_REGIONS = (
    # usability1: old961B/2fcd7f5d910ef61ab63f768d3795b6bbf3b6bfb6b0d352a6a5128a9f1fa48e62; new1396B/9f62144891b4ca38708891646ab10be821b2a00d8db1aec40efd8711927b1dc5; retained-old0.
    (6637, 6637,
     (
        b'                "Do not use another server or configuration writer against these switches at the same time. "\n'
        b'                "Alternatively use --project /var/www/html/DAY0-Prepare/PROJECT. "\n'
        b'                "Upgrade workers U=min(32,ceil(ready_devices/2)); verification workers V=min(8,ceil(U/4)). "\n'
        b'                "Startup preflight is also parallel: min(32,ceil(candidate_devices/2)), limited by half-soft FD headroom. "\n'
        b'                "Each component\'s upgrade canary must pass; after reboot require nvued running AND a usable version query, at most 5 rounds 60 seconds apart. "\n'
        b'                "--devices is a case-insensitive full-hostname glob selector, not a regex. "\n'
        b'                "Quote patterns such as \'ew-spine00[1-9]*\' or \'ib-pod[a-d]-leaf*\'. "\n'
        b'                "Real upgrades still require --upgrade --yes; inspection never upgrades devices."),\n'
        b'        allow_abbrev=False,\n'
        b'    )\n'
        b'    parser.add_argument("--inspect-only", action="store_true",\n'
     ),
     (
        b'                "Do not use another server or configuration writer against these switches at the same time. "\n'
        b'                "Alternatively use --project /var/www/html/DAY0-Prepare/PROJECT. "\n'
        b'                "Upgrade workers U=min(32,ceil(ready_devices/2)); verification workers V=min(8,ceil(U/4)). "\n'
        b'                "Startup preflight is also parallel: min(32,ceil(candidate_devices/2)), limited by half-soft FD headroom; "\n'
        b'                "the process first raises only its own open-file soft limit toward the hard limit. "\n'
        b'                "--parallel-limit lowers both preflight and upgrade concurrency. "\n'
        b'                "Each component\'s upgrade canary must pass; after reboot require nvued running AND a usable version query, at most 5 rounds 60 seconds apart. "\n'
        b'                "--devices is a case-insensitive full-hostname glob selector, not a regex. "\n'
        b'                "Quote patterns such as \'ew-spine00[1-9]*\' or \'ib-pod[a-d]-leaf*\'. "\n'
        b'                "Without an active venv, ~/.venvs/http/ibsw-upgrade (then ~/.venv-upgrade) is used once if it carries requirements.txt. "\n'
        b'                "Real upgrades require --upgrade --yes, or typing yes when an interactive default inspection "\n'
        b'                "offers its READY/UPGRADE_REQUIRED devices; the inspection never upgrades devices."),\n'
        b'        allow_abbrev=False,\n'
        b'    )\n'
        b'    parser.add_argument("--inspect-only", action="store_true",\n'
     )),
    # usability2: old347B/0677aa8aa0ab2134fd0729376ebe0a8b1114899e5765829ef4285e4e16fe5343; new9523B/a0ae6566a59c072af2fa0e104a5a92ad0b6f012a7b6998d7e202197932d91354; retained-old0.
    (25216, 25651,
     (
        b'            problems.append(f"{name} expected={expected} installed={visible}")\n'
        b'    if problems:\n'
        b'        raise _InspectionHold("SSH runtime mismatch: " + "; ".join(problems)\n'
        b'                              + ". Use the matching virtual environment or install requirements.txt there; nothing was installed automatically")\n'
        b'\n'
        b'\n'
        b'def _resolve_auth(parsed):\n'
     ),
     (
        b'            problems.append(f"{name} expected={expected} installed={visible}")\n'
        b'    if problems:\n'
        b'        raise _InspectionHold("SSH runtime mismatch: " + "; ".join(problems)\n'
        b'                              + ". Use the matching virtual environment or install requirements.txt there; nothing was installed automatically. "\n'
        b'                              + _runtime_venv_hint())\n'
        b'\n'
        b'\n'
        b'# SSH runtime environment switch. This block is the single replaceable place\n'
        b'# for the candidate paths and their acceptance rules (README: "SSH runtime\n'
        b'# environment"); a project dependency table may later supply the fixed path.\n'
        b'# Owner ruling 2026-10-23: the first path is the designated environment and\n'
        b'# the creation target; ~/.venv-upgrade is accepted for compatibility only.\n'
        b"_RUNTIME_VENV_PATHS = ('~/.venvs/http/ibsw-upgrade', '~/.venv-upgrade')\n"
        b"_RUNTIME_VENV_MARKER = 'IBSW_UPGRADE_VENV_REEXEC'  # loop guard only; never a secret\n"
        b"_REQUIREMENT_LINE = re.compile(r'([A-Za-z0-9][A-Za-z0-9._-]{0,79})(?:==([A-Za-z0-9][A-Za-z0-9.+!_-]{0,79}))?')\n"
        b'\n'
        b'\n'
        b'def _runtime_venv_candidates():\n'
        b'    """Fixed ordered venvs from _RUNTIME_VENV_PATHS, expanded with os.path.expanduser.\n'
        b'\n'
        b'    Never derived from argv, input files or the entry directory.\n'
        b'    """\n'
        b'    return tuple(Path(os.path.expanduser(path)) for path in _RUNTIME_VENV_PATHS)\n'
        b'\n'
        b'\n'
        b'def _runtime_requirements():\n'
        b'    """Sibling requirements.txt as ((name, exact-version-or-None), ...); None if unusable."""\n'
        b'    try:\n'
        b"        with open(_ENTRY_DIRECTORY / 'requirements.txt', encoding='utf-8') as handle:\n"
        b'            text = handle.read(65536)\n'
        b'    except (OSError, UnicodeDecodeError):\n'
        b'        return None\n'
        b'    entries = []\n'
        b'    for raw in text.splitlines():\n'
        b'        line = raw.strip()\n'
        b"        if not line or line.startswith('#'):\n"
        b'            continue\n'
        b'        match = _REQUIREMENT_LINE.fullmatch(line)\n'
        b'        if match is None:\n'
        b'            return None\n'
        b'        entries.append((match.group(1), match.group(2)))\n'
        b'    return tuple(entries) or None\n'
        b'\n'
        b'\n'
        b'def _requirement_problems(requirements, version):\n'
        b'    problems = []\n'
        b'    for name, expected in requirements:\n'
        b'        try:\n'
        b'            installed = version(name)\n'
        b'        except metadata.PackageNotFoundError:\n'
        b'            installed = None\n'
        b'        if installed is None or (expected is not None and installed != expected):\n'
        b"            visible = ('missing' if installed is None else installed\n"
        b"                       if re.fullmatch(r'[A-Za-z0-9.+_-]{1,80}', str(installed)) else 'unsupported')\n"
        b"            problems.append(name + ' expected=' + (expected or 'present') + ' installed=' + visible)\n"
        b'    return problems\n'
        b'\n'
        b'\n'
        b'def _audited_runtime_venv(venv):\n'
        b'    """(python, reason). Bounded audit, not a whole-tree audit.\n'
        b'\n'
        b"    The venv's parents inside the home directory, the venv root, bin, lib, its\n"
        b'    single lib/python3.*/site-packages, pyvenv.cfg and bin/python3 (followed)\n'
        b'    must be real, owned by this account or root and not writable by others\n'
        b'    (group only for a private user group); the site-packages metadata must\n'
        b'    satisfy every requirements.txt entry.\n'
        b'    """\n'
        b'    import grp\n'
        b'    import pwd\n'
        b'    euid = os.geteuid()\n'
        b'    account = pwd.getpwuid(euid)\n'
        b'\n'
        b'    def unsafe(info):\n'
        b'        if info.st_uid not in (0, euid):\n'
        b"            return 'owned by another account'\n"
        b'        if info.st_mode & stat.S_IWOTH:\n'
        b"            return 'writable by others'\n"
        b'        if info.st_mode & stat.S_IWGRP:\n'
        b'            try:\n'
        b'                group = grp.getgrgid(info.st_gid)\n'
        b'            except KeyError:\n'
        b"                return 'group-writable'\n"
        b'            if not (info.st_gid == account.pw_gid and group.gr_name == account.pw_name\n'
        b'                    and all(member == account.pw_name for member in group.gr_mem)):\n'
        b"                return 'group-writable'\n"
        b'        return None\n'
        b'    requirements = _runtime_requirements()\n'
        b'    if requirements is None:\n'
        b"        return None, 'requirements.txt unreadable'\n"
        b'    venv = Path(venv)\n'
        b'    try:\n'
        b'        if not venv.is_absolute():\n'
        b"            return None, 'not absolute'\n"
        b"        home = Path(os.path.expanduser('~'))\n"
        b'        parents = [parent for parent in venv.parents if parent != home and parent.is_relative_to(home)]\n'
        b'        for parent in parents:\n'
        b'            info = os.lstat(parent)\n'
        b'            if not stat.S_ISDIR(info.st_mode):\n'
        b"                return None, str(parent) + ' is not a real directory'\n"
        b'            problem = unsafe(info)\n'
        b'            if problem:\n'
        b"                return None, str(parent) + ' ' + problem\n"
        b"        for path, label in ((venv, 'directory'), (venv / 'bin', 'bin'), (venv / 'lib', 'lib'),\n"
        b"                            (venv / 'pyvenv.cfg', 'pyvenv.cfg')):\n"
        b'            info = os.lstat(path)\n'
        b"            if not (stat.S_ISREG(info.st_mode) if label == 'pyvenv.cfg' else stat.S_ISDIR(info.st_mode)):\n"
        b"                return None, label + ' is not a real ' + ('file' if label == 'pyvenv.cfg' else 'directory')\n"
        b'            problem = unsafe(info)\n'
        b'            if problem:\n'
        b"                return None, label + ' ' + problem\n"
        b"        sites = sorted((venv / 'lib').glob('python3.*/site-packages'))\n"
        b'        if len(sites) != 1:\n'
        b"            return None, 'needs exactly one lib/python3.*/site-packages'\n"
        b'        for path in (sites[0].parent, sites[0]):\n'
        b'            info = os.lstat(path)\n'
        b'            if not stat.S_ISDIR(info.st_mode):\n'
        b"                return None, 'site-packages is not a real directory'\n"
        b'            problem = unsafe(info)\n'
        b'            if problem:\n'
        b"                return None, 'site-packages ' + problem\n"
        b"        python = venv / 'bin' / 'python3'\n"
        b'        info = os.stat(python)\n'
        b'        if not stat.S_ISREG(info.st_mode) or not os.access(python, os.X_OK):\n'
        b"            return None, 'bin/python3 is not executable'\n"
        b'        problem = unsafe(info)\n'
        b'        if problem:\n'
        b"            return None, 'bin/python3 ' + problem\n"
        b'    except FileNotFoundError:\n'
        b"        return None, 'missing'\n"
        b'    except OSError as error:\n'
        b"        return None, 'unreadable (' + errno.errorcode.get(error.errno, 'OSError') + ')'\n"
        b'\n'
        b'    def installed(name):\n'
        b'        found = [item.version for item in metadata.distributions(name=name, path=[str(sites[0])])]\n'
        b'        if len(found) != 1:\n'
        b'            raise metadata.PackageNotFoundError(name)\n'
        b'        return found[0]\n'
        b'    try:\n'
        b'        problems = _requirement_problems(requirements, installed)\n'
        b'    except (OSError, ValueError, UnicodeDecodeError):\n'
        b"        return None, 'site-packages metadata unreadable'\n"
        b'    if problems:\n'
        b"        return None, 'requirements not met: ' + '; '.join(problems)\n"
        b"    return str(python), 'usable'\n"
        b'\n'
        b'\n'
        b'def _runtime_venv_hint():\n'
        b'    """Fixed guidance naming both candidates; the owner-designated first one is created."""\n'
        b'    candidates = _runtime_venv_candidates()\n'
        b"    checked = ', '.join(str(venv) + ' (' + _audited_runtime_venv(venv)[1] + ')' for venv in candidates)\n"
        b'    target = candidates[0]  # under the home directory, outside any deployed or packaged tree\n'
        b"    current = (' This interpreter already runs from ' + sys.prefix + '; it was not switched again.'\n"
        b"               if any(Path(sys.prefix) == venv for venv in candidates) else '')\n"
        b"    return ('Fixed venv candidates: ' + checked + '.' + current\n"
        b"            + ' Create the fixed environment once, then rerun: python3 -m venv ' + str(target)\n"
        b"            + ' && ' + str(target / 'bin' / 'python') + ' -m pip install -r '\n"
        b"            + str(_ENTRY_DIRECTORY / 'requirements.txt'))\n"
        b'\n'
        b'\n'
        b'def _reexec_in_runtime_venv(argv=None):\n'
        b'    """Switch once to the first audited fixed venv before the guard or any prompt.\n'
        b'\n'
        b'    Runs only from the script entry. Arguments are passed unchanged; the\n'
        b'    environment gains only the loop marker. No password or other secret has\n'
        b'    been read at this point. Otherwise returns and the SSH_RUNTIME hold applies.\n'
        b'    """\n'
        b'    if os.environ.pop(_RUNTIME_VENV_MARKER, None) is not None:\n'
        b"        return 'ALREADY_SWITCHED'\n"
        b'    args = tuple(sys.argv[1:] if argv is None else argv)\n'
        b"    if any(arg in ('-h', '--help', '--version') for arg in args):\n"
        b"        return 'NOT_NEEDED'\n"
        b'    try:\n'
        b'        parsed = _parse_cli(args)\n'
        b'    except Exception:\n'
        b"        return 'NOT_NEEDED'  # main() reports the argument error unchanged\n"
        b'    if parsed.scripts_only or parsed.diagnose_inputs:\n'
        b"        return 'NOT_NEEDED'\n"
        b'    try:\n'
        b'        requirements = _runtime_requirements()\n'
        b'        problems = _requirement_problems(requirements, metadata.version) if requirements else ()\n'
        b'        candidates = [(venv, _audited_runtime_venv(venv)[0]) for venv in _runtime_venv_candidates()] if problems else ()\n'
        b'    except Exception:\n'
        b"        return 'NOT_NEEDED'  # never fail before the guard; the SSH_RUNTIME hold reports it\n"
        b'    if not problems:\n'
        b"        return 'NOT_NEEDED'\n"
        b'    for venv, python in candidates:\n'
        b'        if python is None:\n'
        b'            continue\n'
        b"        # Forward -B only: -I/-E/-S/-s would hide the venv's own site-packages.\n"
        b"        options = ['-B'] if sys.flags.dont_write_bytecode else []\n"
        b'        environment = dict(os.environ)\n'
        b"        environment[_RUNTIME_VENV_MARKER] = '1'\n"
        b"        sys.stderr.write('[RUNTIME] ' + sys.executable + ' lacks the pinned SSH runtime ('\n"
        b"                         + '; '.join(problems) + '). Re-running once with fixed venv ' + str(venv)\n"
        b"                         + ' (' + python + '); arguments unchanged, no secret has been read.\\n')\n"
        b'        sys.stderr.flush()\n'
        b'        try:\n'
        b'            os.execve(python, [python, *options, sys.argv[0], *args], environment)\n'
        b'        except OSError as error:\n'
        b"            sys.stderr.write('[RUNTIME] Could not start ' + python + ' ('\n"
        b"                             + errno.errorcode.get(error.errno, 'OSError') + '); trying the next fixed candidate.\\n')\n"
        b"    return 'NO_CANDIDATE'\n"
        b'\n'
        b'\n'
        b'def _resolve_auth(parsed):\n'
     )),
    # usability3: old205B/71f6f4f97763c34942a28cd7dc5812b7277ebc35b3946726c3dcfc09703e4468; new3047B/1da30ad6218d8545a8fd7024573ec0d1659394c6f4ce0d60f31fe53959c7b223; retained-old0.
    (37270, 46881,
     (
        b'def _upgrade_worker_count(ready_count,cap=None):\n'
        b'    workers=min(32,(ready_count+1)//2)\n'
        b'    return min(workers,cap) if cap is not None else workers\n'
        b'\n'
        b'\n'
        b'def _print_ready_device(index, total, hostname, rows):\n'
     ),
     (
        b'def _upgrade_worker_count(ready_count,cap=None):\n'
        b'    workers=min(32,(ready_count+1)//2)\n'
        b'    return min(workers,cap) if cap is not None else workers\n'
        b'\n'
        b'\n'
        b'_FD_RETAINED_PER_DEVICE = 16  # conservative startup evidence kept open per adopted device\n'
        b'\n'
        b'\n'
        b'def _descriptor_soft_target(candidates, startup_workers, *, upgrade, os_hops=1):\n'
        b'    """Soft RLIMIT_NOFILE whose half (the pipeline budget) admits full concurrency.\n'
        b'\n'
        b'    Current use + 64 reserve + retained startup evidence per device + the larger\n'
        b'    of 64 per startup scope and, for upgrades, (128 + 64 x OS hops) per\n'
        b"    in-flight device: the pipeline's own preflight/upgrade reservations.\n"
        b'    """\n'
        b'    from ibsw_upgrade_pipeline import _open_descriptor_count\n'
        b'    in_flight = 64 * startup_workers\n'
        b'    if upgrade:\n'
        b'        in_flight = max(in_flight, _upgrade_worker_count(candidates) * (128 + 64 * max(1, os_hops)))\n'
        b'    return 2 * (_open_descriptor_count() + 64 + _FD_RETAINED_PER_DEVICE * candidates + in_flight)\n'
        b'\n'
        b'\n'
        b'def _planned_os_hops(scope):\n'
        b'    """Upper bound before routes are frozen: the declared OS stages."""\n'
        b"    if 'os' not in scope.parsed.selected:\n"
        b'        return 1\n'
        b'    policy = scope.policy\n'
        b"    return max(1, len(getattr(policy, 'os_stages', ()) or getattr(policy, 'os', ())))\n"
        b'\n'
        b'\n'
        b'def _raise_descriptor_soft_limit(required):\n'
        b'    """Raise only this process\'s open-file soft limit toward min(hard, required).\n'
        b'\n'
        b'    rlimits belong to a process: the invoking shell keeps its own values and\n'
        b'    only children started later inherit this one, so nothing is restored. The\n'
        b'    hard limit is never changed; when it is too low the original FD_BUDGET\n'
        b'    refusal still applies.\n'
        b'    """\n'
        b'    import resource\n'
        b'    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)\n'
        b'    record = dict(soft_before=soft, soft_after=soft, hard=hard, required=required)\n'
        b'    if soft == resource.RLIM_INFINITY or soft >= required:\n'
        b'        return record\n'
        b'    target = required if hard == resource.RLIM_INFINITY else min(hard, required)\n'
        b'\n'
        b'    def shown(value):\n'
        b"        return 'unlimited' if value == resource.RLIM_INFINITY else str(value)\n"
        b'    if target > soft:\n'
        b'        try:\n'
        b'            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))\n'
        b'        except (ValueError, OSError):\n'
        b'            sys.stderr.write(f"[FD] Could not raise this process\'s open-file soft limit {soft} -> {target} "\n'
        b'                             f"(hard={shown(hard)}); keeping {soft}.\\n")\n'
        b'            return record\n'
        b"        record['soft_after'] = target\n"
        b'        sys.stderr.write(f"[FD] Raised this process\'s open-file soft limit {soft} -> {target} "\n'
        b'                         f"(hard={shown(hard)}, estimated need={required}); the invoking shell is unchanged.\\n")\n'
        b'    if target < required:\n'
        b'        sys.stderr.write(f"[FD] Open-file hard limit {shown(hard)} is below the estimated need {required}; "\n'
        b'                         "if startup still reports FD_BUDGET_INSUFFICIENT, select a smaller --devices batch "\n'
        b'                         "or have the administrator raise the hard limit.\\n")\n'
        b'    return record\n'
        b'\n'
        b'\n'
        b'def _print_ready_device(index, total, hostname, rows):\n'
     )),
    # usability4: old527B/867a279b7686bd17134ed0e8a7e86a4f2f591bc78098919bd02341c3633d13c0; new716B/9b06910826ca551896a66554198cd5b9f486ca4e0958ea4bf9bda04a34727057; retained-old0.
    (51345, 63798,
     (
        b'    completed, pending = {}, {}\n'
        b'    cursor = publish = 0\n'
        b"    nominal = _upgrade_worker_count(len(nodes),getattr(parsed,'parallel_limit',None))\n"
        b'    scope._readiness_scheduler = dict(workers=nominal, max_pending=0, completed=0,\n'
        b'        descriptor_budget=_soft_descriptor_limit()//2, per_pending_reserved=64)\n'
        b'    if not nodes: return (), []\n'
        b"    sys.stderr.write(f'[PREFLIGHT] candidates={len(nodes)} workers={nominal} '\n"
        b'                     f\'fd-budget={scope._readiness_scheduler["descriptor_budget"]} rule=min(32,ceil(N/2))\\n\')\n'
     ),
     (
        b'    completed, pending = {}, {}\n'
        b'    cursor = publish = 0\n'
        b"    nominal = _upgrade_worker_count(len(nodes),getattr(parsed,'parallel_limit',None))\n"
        b'    soft_limit = _raise_descriptor_soft_limit(_descriptor_soft_target(\n'
        b'        len(nodes), nominal, upgrade=scope._access_required, os_hops=_planned_os_hops(scope)))\n'
        b'    scope._readiness_scheduler = dict(workers=nominal, max_pending=0, completed=0,\n'
        b'        descriptor_budget=_soft_descriptor_limit()//2, per_pending_reserved=64, soft_limit=soft_limit)\n'
        b'    if not nodes: return (), []\n'
        b"    sys.stderr.write(f'[PREFLIGHT] candidates={len(nodes)} workers={nominal} '\n"
        b'                     f\'fd-budget={scope._readiness_scheduler["descriptor_budget"]} rule=min(32,ceil(N/2))\\n\')\n'
     )),
    # usability5: old348B/6c5ad6517a5725eb17cf7f259922a00066defaab7ebb834748602f6e84031a68; new6929B/c23e9e3309ffc76767961536c1c9c7e947a5de838c52b53797924eed3b4852ac; retained-old0.
    (109306, 121948,
     (
        b'    sys.stderr.flush()\n'
        b'\n'
        b'\n'
        b'def _input_diagnostic_document(parsed, prepare, entry, cwd, stage, error=None, selected=(), blocked=()):\n'
        b'    document = {"revision": _DESKTOP_REVISION, "state": "INPUT_PREFLIGHT_FAILED" if error else "INPUT_PREFLIGHT_PASSED",\n'
        b'        "diagnostic_data_only": True, "execution_state": "NOT_EXECUTED", "ssh_attempted": False,\n'
     ),
     (
        b'    sys.stderr.flush()\n'
        b'\n'
        b'\n'
        b'# Post-inspection offer: default interactive inspection only. The confirmed\n'
        b'# set is DATA that can only narrow the following upgrade run; every device\n'
        b"# still passes that run's own fresh preflight and per-component gates.\n"
        b'_UPGRADE_CONFIRMATION_SECONDS = 300\n'
        b"_EXPLICIT_MODE_OPTIONS = frozenset(('--inspect-only', '--dry-run', '--verify-only',\n"
        b"                                    '--scripts-only', '--upgrade', '--diagnose-inputs'))\n"
        b'\n'
        b'\n'
        b'def _upgrade_handoff_plan(summary):\n'
        b'    """READY devices with a selected UPGRADE_REQUIRED component, startup health\n'
        b'    PASS and no review item, in inspection order. Display/selection DATA only."""\n'
        b"    skipped = {row['hostname'] for row in summary.get('skipped_devices', [])}\n"
        b"    selected = set(summary.get('selected_components') or ())\n"
        b"    review = {row['hostname'] for row in summary.get('component_precheck_issues', [])}\n"
        b'    health = _health_check_summary(summary)\n'
        b"    healthy = set(health['groups']['PASS']) - set(health['abnormal_devices'])\n"
        b'    rows = {}\n'
        b"    for row in summary.get('version_plan', []):\n"
        b"        if row['component'] in selected:\n"
        b"            rows.setdefault(row['hostname'], []).append(row)\n"
        b"    devices, components = [], {component: [] for component in ('os', 'bios', 'cpld')}\n"
        b'    excluded = dict(health_not_pass=[], review_required=[])\n'
        b"    for target in summary.get('targets', []):\n"
        b"        host = target['hostname']\n"
        b'        actions = rows.get(host, [])\n'
        b"        if host in skipped or not any(row['action'] == 'UPGRADE_REQUIRED' for row in actions):\n"
        b'            continue\n'
        b"        if host in review or any(row['action'] not in ('UPGRADE_REQUIRED', 'AT_TARGET_NO_FLASH') for row in actions):\n"
        b"            excluded['review_required'].append(host)\n"
        b'        elif host not in healthy:\n'
        b"            excluded['health_not_pass'].append(host)\n"
        b'        else:\n'
        b'            devices.append(host)\n'
        b'            for row in actions:\n'
        b"                if row['action'] == 'UPGRADE_REQUIRED':\n"
        b"                    components[row['component']].append(host)\n"
        b"    return dict(inspection_run_directory=summary.get('run_directory'), devices=tuple(devices),\n"
        b'                components={name: tuple(hosts) for name, hosts in components.items()},\n'
        b'                excluded={name: tuple(hosts) for name, hosts in excluded.items()},\n'
        b'                preflight_skipped=len(skipped))\n'
        b'\n'
        b'\n'
        b'def _upgrade_handoff_terminal():\n'
        b'    try:\n'
        b'        return all(stream is not None and stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr))\n'
        b'    except (AttributeError, ValueError, OSError):\n'
        b'        return False\n'
        b'\n'
        b'\n'
        b'def _read_upgrade_confirmation(timeout):\n'
        b'    """One answer line after discarding type-ahead; None on EOF or timeout."""\n'
        b'    try:\n'
        b'        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)\n'
        b'    except (OSError, ValueError, AttributeError, termios.error):\n'
        b'        pass\n'
        b'    readable, _, _ = select.select([sys.stdin], [], [], timeout)\n'
        b'    if not readable:\n'
        b"        sys.stderr.write('\\n[UPGRADE OFFER] No answer within ' + str(timeout) + ' seconds.\\n')\n"
        b'        return None\n'
        b'    line = sys.stdin.readline(64)\n'
        b'    return line.strip() if line else None\n'
        b'\n'
        b'\n'
        b'def _offer_upgrade_handoff(argv, parsed, summary):\n'
        b'    """Ask once after the saved default inspection; return the confirmed plan or None."""\n'
        b'    if (_EXPLICIT_MODE_OPTIONS.intersection(argv) or not parsed.inspect_only or parsed.verify_only\n'
        b'            or parsed.output_json or not _upgrade_handoff_terminal()):\n'
        b'        return None\n'
        b'    plan = _upgrade_handoff_plan(summary)\n'
        b"    if not plan['devices']:\n"
        b'        return None\n'
        b"    count = len(plan['devices'])\n"
        b'\n'
        b'    def names(hosts):\n'
        b'        for start in range(0, len(hosts), 4):\n'
        b"            sys.stderr.write(re.sub(r'[\\x00-\\x1f\\x7f]', '?', '    - ' + ', '.join(hosts[start:start + 4])) + '\\n')\n"
        b"    sys.stderr.write(f'\\n[UPGRADE OFFER] {count} device(s) are READY with UPGRADE_REQUIRED and passed the startup health check:\\n')\n"
        b"    for component in ('os', 'bios', 'cpld'):\n"
        b"        if plan['components'][component]:\n"
        b'            sys.stderr.write(f"  {component.upper()}: {len(plan[\'components\'][component])} device(s)\\n")\n'
        b"    names(plan['devices'])\n"
        b"    for key, label in (('health_not_pass', 'startup health not PASS'), ('review_required', 'observation requires review')):\n"
        b"        if plan['excluded'][key]:\n"
        b'            sys.stderr.write(f"  Not offered, {label}: {len(plan[\'excluded\'][key])} device(s)\\n")\n'
        b"            names(plan['excluded'][key])\n"
        b"    if plan['preflight_skipped']:\n"
        b'        sys.stderr.write(f"  Not offered, preflight-skipped: {plan[\'preflight_skipped\']} device(s)\\n")\n'
        b"    sys.stderr.write('  yes = real upgrade now, in this process and a new run, of exactly these device(s); '\n"
        b"                     'equivalent to --upgrade --yes limited to them'\n"
        b"                     + (' with --skip-canary.\\n' if parsed.skip_canary else '; component canaries apply.\\n'))\n"
        b"    sys.stderr.write('  The switch password is then requested once. The upgrade repeats its own fresh preflight '\n"
        b"                     'on each device (host key, identity, versions, startup health gate, key AND password login, '\n"
        b"                     'authorized_keys backup) and keeps configuration backup and post-reboot verification.\\n')\n"
        b"    sys.stderr.write(f'Type yes to upgrade these {count} device(s) now; anything else keeps the inspection only '\n"
        b"                     f'[{_UPGRADE_CONFIRMATION_SECONDS}s = no]: ')\n"
        b'    sys.stderr.flush()\n'
        b"    if _read_upgrade_confirmation(_UPGRADE_CONFIRMATION_SECONDS) != 'yes':\n"
        b"        sys.stderr.write('[UPGRADE OFFER] Not confirmed; inspection only, no upgrade was started.\\n')\n"
        b'        return None\n'
        b'    sys.stderr.write(f"[UPGRADE OFFER] Confirmed for {count} device(s); inspection evidence retained at "\n'
        b'                     f"{plan[\'inspection_run_directory\']}.\\n")\n'
        b'    return plan\n'
        b'\n'
        b'\n'
        b'def _upgrade_handoff_argv(argv):\n'
        b'    """Original public arguments (including a frozen --method) plus explicit confirmation."""\n'
        b'    argv = tuple(argv)\n'
        b"    return argv + ('--upgrade',) + (() if ('--yes' in argv or '-y' in argv) else ('--yes',))\n"
        b'\n'
        b'\n'
        b'def _restrict_to_handoff(devices, blocked, handoff):\n'
        b'    """Narrow, never widen: every confirmed device must still be selected."""\n'
        b"    confirmed = tuple(handoff['devices'])\n"
        b'    kept = tuple(node for node in devices if node.hostname in confirmed)\n'
        b'    if len(kept) != len(confirmed) or {node.hostname for node in kept} != set(confirmed):\n'
        b"        raise _InspectionHold('INSPECTION_HANDOFF: the current inputs no longer select every device confirmed '\n"
        b"                              'after the inspection; no upgrade was started. Run the inspection again')\n"
        b'    return kept, tuple(item for item in blocked if item.hostname in confirmed)\n'
        b'\n'
        b'\n'
        b'def _input_diagnostic_document(parsed, prepare, entry, cwd, stage, error=None, selected=(), blocked=()):\n'
        b'    document = {"revision": _DESKTOP_REVISION, "state": "INPUT_PREFLIGHT_FAILED" if error else "INPUT_PREFLIGHT_PASSED",\n'
        b'        "diagnostic_data_only": True, "execution_state": "NOT_EXECUTED", "ssh_attempted": False,\n'
     )),
    # usability6: old380B/57343328d6b8ca3f7d1166073fb9f73534f57042f2e467a2ea9c80a8176a9c01; new394B/dd61f0dcf9b64731bada0324d31b8f094ec1244527340d43e4793d1c14fec726; retained-old0.
    (116255, 135478,
     (
        b'    return stage, ("Validation refused (" + type(error).__name__ + "). See Location below or run --diagnose-inputs for source/path diagnostics; raw exception text is withheld to protect credentials")\n'
        b'\n'
        b'\n'
        b'def main(argv=None,*,_password_attempt=1,_password_history=()):\n'
        b'    is_upgrade = False\n'
        b'    stage = "ARGUMENTS"\n'
        b'    parsed, prepare_arguments, entry, cwd = None, None, None, None\n'
     ),
     (
        b'    return stage, ("Validation refused (" + type(error).__name__ + "). See Location below or run --diagnose-inputs for source/path diagnostics; raw exception text is withheld to protect credentials")\n'
        b'\n'
        b'\n'
        b'def main(argv=None,*,_password_attempt=1,_password_history=(),_handoff=None):\n'
        b'    is_upgrade = False\n'
        b'    stage = "ARGUMENTS"\n'
        b'    parsed, prepare_arguments, entry, cwd = None, None, None, None\n'
     )),
    # usability7: old491B/3c97b940b55f8cf90ad4707fbc06fe4fe1e254ed35549f0f65add6eb14403804; new647B/9e4809574144b90a2dd1082493e18c492089d21cfae868511289f20c0acd7399; retained-old0.
    (117953, 137190,
     (
        b'        # and verifies the full CSV; this snapshot never becomes permission.\n'
        b'        selection = driver.preflight_inventory_selection(entry, cwd, parsed.prepare_args)\n'
        b'        selected, blocked = selection.devices, selection.blocked_devices\n'
        b'        if parsed.diagnose_inputs:\n'
        b'            document = _input_diagnostic_document(parsed, prepare_arguments, entry, cwd, stage, selected=selected, blocked=blocked)\n'
        b'            sys.stdout.write(json.dumps(document, sort_keys=True, indent=2) + "\\n")\n'
     ),
     (
        b'        # and verifies the full CSV; this snapshot never becomes permission.\n'
        b'        selection = driver.preflight_inventory_selection(entry, cwd, parsed.prepare_args)\n'
        b'        selected, blocked = selection.devices, selection.blocked_devices\n'
        b'        if _handoff is not None:\n'
        b'            stage = "INSPECTION_HANDOFF"\n'
        b'            selected, blocked = _restrict_to_handoff(selected, blocked, _handoff)\n'
        b'        if parsed.diagnose_inputs:\n'
        b'            document = _input_diagnostic_document(parsed, prepare_arguments, entry, cwd, stage, selected=selected, blocked=blocked)\n'
        b'            sys.stdout.write(json.dumps(document, sort_keys=True, indent=2) + "\\n")\n'
     )),
    # usability8: old372B/13578c01632f75d076c6fef799a5ae2356350e842f848898dbb365a84234e007; new534B/3cab175b041d0a6e212d446788d012446dbc6d3b6e97d16250abf11c1139f0ed; retained-old0.
    (120910, 140303,
     (
        b'                                      prepared["run_directory"]) as scope:\n'
        b'            live_selection = driver.select_inventory_devices(scope.session.inventory(), parsed.devices)\n'
        b'            nodes, blocked = live_selection.devices, live_selection.blocked_devices\n'
        b'            ready = nodes\n'
        b'            if not parsed.scripts_only:\n'
        b'                stage = "TARGET_READINESS"\n'
     ),
     (
        b'                                      prepared["run_directory"]) as scope:\n'
        b'            live_selection = driver.select_inventory_devices(scope.session.inventory(), parsed.devices)\n'
        b'            nodes, blocked = live_selection.devices, live_selection.blocked_devices\n'
        b'            if _handoff is not None:\n'
        b'                stage = "INSPECTION_HANDOFF"\n'
        b'                nodes, blocked = _restrict_to_handoff(nodes, blocked, _handoff)\n'
        b'            ready = nodes\n'
        b'            if not parsed.scripts_only:\n'
        b'                stage = "TARGET_READINESS"\n'
     )),
    # usability9: old408B/800ca2d4639258ff48461e0ba62e5e96115b1fd96ec9b5661ef64ecd7cfe1479; new794B/c46f39d216c2be453b1e04bc02a3f4e947c1dcfb03481358c439f0b46eca0b39; retained-old0.
    (125527, 145082,
     (
        b'        if parsed.upgrade:\n'
        b"            summary['password_attempt']=_password_attempt\n"
        b"            summary['previous_password_attempt_runs']=list(_password_history)\n"
        b'        summary.update(input_eligible_ib_count=len(nodes), ready_ib_count=len(ready), eligible_ib_count=len(ready))\n'
        b'        summary["run_directory"] = prepared["run_directory"]\n'
        b"        summary['version_plan'] = getattr(scope,'_version_plan',[])\n"
     ),
     (
        b'        if parsed.upgrade:\n'
        b"            summary['password_attempt']=_password_attempt\n"
        b"            summary['previous_password_attempt_runs']=list(_password_history)\n"
        b'        if _handoff is not None:\n'
        b"            summary['inspection_handoff']=dict(inspection_run_directory=_handoff['inspection_run_directory'],\n"
        b"                devices=list(_handoff['devices']),\n"
        b"                components={name: list(hosts) for name, hosts in _handoff['components'].items()},\n"
        b"                excluded={name: list(hosts) for name, hosts in _handoff['excluded'].items()})\n"
        b'        summary.update(input_eligible_ib_count=len(nodes), ready_ib_count=len(ready), eligible_ib_count=len(ready))\n'
        b'        summary["run_directory"] = prepared["run_directory"]\n'
        b"        summary['version_plan'] = getattr(scope,'_version_plan',[])\n"
     )),
    # usability10: old724B/4f36e953db0c1367589ec163a391ca90c262a38640c5a1cf2bd5b423154cf6d0; new1093B/b64892e8a280dde54026fa559ca3e2241d4f26afef8c09ab3f04b13b30f172ad; retained-old0.
    (130664, 150605,
     (
        b'            final_scope.write_run_report(summary)\n'
        b'        _emit_report_json(summary,force=parsed.output_json)\n'
        b'        _print_upgrade_summary(summary)\n'
        b'        return 3 if incomplete else 0\n'
        b'    except _PasswordReentry as retry:\n'
        b"        sys.stderr.write(f'[AUTH] Existing password was explicitly rejected before any key or installer write. '\n"
        b"            f'Attempt {_password_attempt+1}/3; previous evidence retained at {retry.directory}\\n')\n"
        b'        return main(argv,_password_attempt=_password_attempt+1,\n'
        b'                    _password_history=(*_password_history,retry.directory))\n'
        b'    except _InvalidParallelLimit:\n'
        b'        sys.stderr.write("HOLD: Invalid --parallel-limit: expected a non-negative integer.\\n")\n'
        b'        return 1\n'
     ),
     (
        b'            final_scope.write_run_report(summary)\n'
        b'        _emit_report_json(summary,force=parsed.output_json)\n'
        b'        _print_upgrade_summary(summary)\n'
        b'        if _handoff is None and not parsed.upgrade:\n'
        b'            # The inspection run is saved and closed; the runtime guard stays held.\n'
        b'            stage = "UPGRADE_OFFER"\n'
        b'            handoff = _offer_upgrade_handoff(argv, parsed, summary)\n'
        b'            if handoff is not None:\n'
        b'                return main(_upgrade_handoff_argv(argv), _handoff=handoff)\n'
        b'        return 3 if incomplete else 0\n'
        b'    except _PasswordReentry as retry:\n'
        b"        sys.stderr.write(f'[AUTH] Existing password was explicitly rejected before any key or installer write. '\n"
        b"            f'Attempt {_password_attempt+1}/3; previous evidence retained at {retry.directory}\\n')\n"
        b'        return main(argv,_password_attempt=_password_attempt+1,\n'
        b'                    _password_history=(*_password_history,retry.directory),_handoff=_handoff)\n'
        b'    except _InvalidParallelLimit:\n'
        b'        sys.stderr.write("HOLD: Invalid --parallel-limit: expected a non-negative integer.\\n")\n'
        b'        return 1\n'
     )),
    # usability11: old168B/15bdbed4b0411d04f00bb8a65b6f28186ebd6e34e7d3eccff55257f1d6cb9c9c; new202B/1ad90429c9772a1a77a8d0729c1344a6557fcc834a11945a86a2ed3a84c9297f; retained-old0.
    (132250, 152560,
     (
        b'\n'
        b'if __name__ == "__main__":\n'
        b'    try:\n'
        b'        raise SystemExit(_guarded_main())\n'
        b'    except KeyboardInterrupt:\n'
        b'        sys.stderr.write("HOLD: inspection interrupted\\n")\n'
     ),
     (
        b'\n'
        b'if __name__ == "__main__":\n'
        b'    try:\n'
        b'        _reexec_in_runtime_venv()\n'
        b'        raise SystemExit(_guarded_main())\n'
        b'    except KeyboardInterrupt:\n'
        b'        sys.stderr.write("HOLD: inspection interrupted\\n")\n'
     )),
)
# END GENERATED NATIVE USABILITY LAYER


def _restore_native_usability_layer(payload):
    """Reverse every reviewed usability hunk to the previous entry; else refuse."""
    if type(payload) is not bytes:
        raise AssertionError('original entry source bytes required')
    if not _NATIVE_USABILITY_REGIONS:
        raise AssertionError('reviewed usability layer missing')
    spans, previous_new_end, previous_old_end, difference = [], 0, 0, 0
    for old_offset, new_offset, old, new in _NATIVE_USABILITY_REGIONS:
        if (payload.count(new) != 1 or payload.find(new) != new_offset
                or payload.count(old) != 0 or new_offset < previous_new_end
                or old_offset < previous_old_end or new_offset + difference != old_offset):
            raise AssertionError('missing/duplicate/old/reordered usability literal region')
        spans.append((new_offset, new, old))
        previous_new_end, previous_old_end = new_offset + len(new), old_offset + len(old)
        difference += len(old) - len(new)
    # One pass over the candidate; inserted old bytes are never re-scanned.
    pieces, cursor = [], 0
    for offset, new, old in spans:
        pieces.extend((payload[cursor:offset], old))
        cursor = offset + len(new)
    pieces.append(payload[cursor:])
    original = b''.join(pieces)
    if _sha(original) != _NATIVE_USABILITY_BEFORE_SHA256:
        raise AssertionError('whole previous entry SHA differs after usability inverse')
    return original


def _native_os_reviewed_source_bytes(files):
    """Preserve baseline19 pins; accept only whole baseline OR exact new layer."""
    if type(files) is not dict or any(path not in files for path in PRODUCTION_PINS):
        raise AssertionError('complete reviewed production source vector required')
    original = dict(files)
    original.update(_strip_bios_source_layer({p: original[p] for p in _BIOS_TARGETS}))
    if _sha(original[_NATIVE_DISPLAY_ENTRY]) != PRODUCTION_PINS[_NATIVE_DISPLAY_ENTRY]:
        if any(new in original[_NATIVE_DISPLAY_ENTRY]
               for _, _, _, new in _NATIVE_USABILITY_REGIONS):
            original[_NATIVE_DISPLAY_ENTRY] = _restore_native_usability_layer(original[_NATIVE_DISPLAY_ENTRY])
        if any(new in original[_NATIVE_DISPLAY_ENTRY]
               for _, _, _, new in _NATIVE_TRANSFER_WORDING_REGIONS):
            original[_NATIVE_DISPLAY_ENTRY] = _restore_native_transfer_wording_layer(original[_NATIVE_DISPLAY_ENTRY])
        original[_NATIVE_DISPLAY_ENTRY] = _restore_native_display_layer(original[_NATIVE_DISPLAY_ENTRY])
    # A mixed old/new four-file layer is not supported. The strict inverse
    # rejects unchanged/missing hunks; baseline admission remains the old19 pins.
    if not all(_sha(original[path]) == PRODUCTION_PINS[path] for path in _NATIVE_OS_PATHS):
        layer = _restore_native_os_layer({path: original[path] for path in _NATIVE_OS_PATHS})
        original.update(layer)
    if any(_sha(original[name]) != pin for name, pin in PRODUCTION_PINS.items()):
        raise AssertionError('whole reviewed production source inverse differs')
    return original


def _sections(template):
    markers = [b'# IBSW_BODY_' + name + b'\n' for name in (b'OS', b'BIOS', b'CPLD')]
    if any(template.count(marker) != 1 for marker in markers):
        raise AssertionError('unique original component sections required')
    common, rest = template.split(markers[0], 1)
    os_body, rest = rest.split(markers[1], 1)
    bios_body, cpld_body = rest.split(markers[2], 1)
    return common, os_body, bios_body, cpld_body


def lower_fixed_images(provider, template, image, *, reverse=False):
    """Exactly SSH1/SCP1/OS2/CPLD4, whole byte inverse; BIOS untouched."""
    p = provider
    for label in ('SSH', 'SCP'):
        original = (label + " = '/usr/bin/" + label.lower() + "'").encode()
        private = (label + ' = ' + repr(str(image / 'tools/native-os-io' /
                                           ('private-' + label.lower())))).encode()
        old, new = (private, original) if reverse else (original, private)
        if p.count(old) != 1 or p.count(new) != 0:
            raise AssertionError('unique fixed source executable literal required')
        p = p.replace(old, new, 1)
    common, os_body, bios_body, cpld_body = _sections(template)
    token = ('\n' + shlex.quote(str(image / 'tools/native-os-io/private-nv')) + ' ').encode()
    old, new = (token, b'\nnv ') if reverse else (b'\nnv ', token)
    if (os_body.count(old) != 2 or cpld_body.count(old) != 4
            or new in os_body or new in cpld_body or token in common or token in bios_body):
        raise AssertionError('only exact OS2/CPLD4 NV sites may be lowered')
    result = (common + b'# IBSW_BODY_OS\n' + os_body.replace(old, new)
              + b'# IBSW_BODY_BIOS\n' + bios_body
              + b'# IBSW_BODY_CPLD\n' + cpld_body.replace(old, new))
    return p, result


def prepare_image(source):
    source = Path(source).resolve()
    original = {name: _read(source / name) for name in COPY_FILES}
    _native_os_reviewed_source_bytes(original)  # Validate; copy actual candidate bytes unchanged.
    image = Path(tempfile.mkdtemp(prefix='native-os-isolated-', dir='/private/tmp')).resolve()
    private = image / 'tools/native-os-io'
    private.mkdir(parents=True, mode=0o700); private.parent.chmod(0o700)
    stub_hashes = {}
    for name, raw in executable_sources().items():
        path = private / name
        with path.open('xb') as stream: stream.write(raw)
        path.chmod(0o700); stub_hashes[name] = _sha(raw)
    p, t = lower_fixed_images(original[PROVIDER], original[TEMPLATE], image)
    restored_p, restored_t = lower_fixed_images(p, t, image, reverse=True)
    if (restored_p, restored_t) != (original[PROVIDER], original[TEMPLATE]):
        raise AssertionError('whole source IO inverse mismatch')
    original[PROVIDER], original[TEMPLATE] = p, t
    hashes = {}
    for name, raw in original.items():
        path = image / name; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(raw)
        path.chmod(0o600); hashes[name] = _sha(raw)
    meta = dict(schema=1, image=str(image), hashes=hashes, stubs=stub_hashes,
                lowering=[1, 1, 2, 4])
    with (image / METADATA).open('x') as stream: json.dump(meta, stream, sort_keys=True)
    (image / METADATA).chmod(0o600)
    validate_image(image)
    return image


def select_image(source):
    source = Path(source).resolve()
    if os.path.lexists(source / METADATA):
        validate_image(source)
        return source
    # Existing other images/metadata are never repaired or reinterpreted.
    if any(os.path.lexists(source / name) for name in
           ('native-cpld-safe-image.json', 'native-cpld-io-lowering.json')):
        raise AssertionError('do not adopt another carrier image')
    return prepare_image(source)


def validate_image(image):
    image = Path(image)
    info = image.lstat()
    if (image.resolve() != image or image.parent != Path('/private/tmp')
            or not image.name.startswith('native-os-isolated-')
            or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()):
        raise AssertionError('exact new private native OS image required')
    meta = json.loads(_read(image / METADATA, mode=0o600))
    if (set(meta) != {'schema', 'image', 'hashes', 'stubs', 'lowering'}
            or meta['schema'] != 1 or meta['image'] != str(image)
            or set(meta['hashes']) != set(COPY_FILES) or meta['lowering'] != [1, 1, 2, 4]):
        raise AssertionError('fixed native OS metadata required')
    files = {}
    for name in COPY_FILES:
        path = image / name
        if path.resolve() != path:
            raise AssertionError('image source symlink refused')
        raw = _read(path, mode=0o600)
        if _sha(raw) != meta['hashes'][name]:
            raise AssertionError('fixed image source changed')
        files[name] = raw
    expected = executable_sources()
    if set(meta['stubs']) != set(expected):
        raise AssertionError('exact private executable roster required')
    for name, raw in expected.items():
        path = image / 'tools/native-os-io' / name
        if (path.resolve() != path or _read(path, mode=0o700) != raw
                or meta['stubs'][name] != _sha(raw)):
            raise AssertionError('independent literal executable mismatch')
    p, t = lower_fixed_images(files[PROVIDER], files[TEMPLATE], image, reverse=True)
    files[PROVIDER], files[TEMPLATE] = p, t
    return _native_os_reviewed_source_bytes(files)


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
    original = validate_image(image)
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
            or not re.fullmatch(r'\.ibsw-[A-Za-z0-9][A-Za-z0-9_-]{0,95}-ew-spine0[12]\.example-os-0001-[0-9a-f]{32}', directory.name)):
        raise AssertionError('fixed actual OS remote request namespace required')
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
        raise AssertionError('actual private generated directory required')
    step = _read(remote, mode=0o600); runner = _read(directory / 'runner.sh', mode=0o600)
    if [_sha(runner), _sha(step)] != words[4:]:
        raise AssertionError('actual original uploaded bytes must match fixed command')
    # Use LOWERED reviewed template body, not the inverse's unlowered NV sites.
    common, os_body, _bios, _cpld = _sections(_read(image / TEMPLATE))
    step_body = common + os_body
    if not step.endswith(step_body):
        raise AssertionError('whole original generated OS body required')
    names = ('IBSW_RUN_ID', 'IBSW_COMPONENT', 'IBSW_METHOD', 'IBSW_PACKAGE_FILE',
        'IBSW_PACKAGE_URL', 'IBSW_SWITCH_DIR', 'IBSW_LOCAL_PACKAGE', 'IBSW_BINDING_JSON',
        'IBSW_EXPECTED_EFFECT', 'IBSW_SCP_HELPER_B64', 'IBSW_SCP_PACKAGE_PATH')
    values = _assignments(step[:-len(step_body)], names,
        b'#!/bin/bash\n# Generated IB NVOS component plan artifact; not execution permission.\n')
    package = 'nvos-amd64-25.03.1010.bin'
    binding = json.loads(values['IBSW_BINDING_JSON'])
    if (type(binding) is not list or len(binding) != 6 or binding[1] not in
            ('ew-spine01.example', 'ew-spine02.example')):
        raise AssertionError('fixed fixture node tuple required')
    number = int(binding[1][8:10])
    if (binding != [values['IBSW_RUN_ID'], binding[1], '192.0.2.' + str(number),
                    '02:00:00:00:00:0' + str(number), 'os', '25.03.1010']
            or values['IBSW_BINDING_JSON'] != json.dumps(binding, ensure_ascii=True, separators=(',', ':'))
            or values['IBSW_COMPONENT'] != 'os' or values['IBSW_METHOD'] != 'scp'
            or values['IBSW_PACKAGE_FILE'] != package or values['IBSW_PACKAGE_URL'] != ''
            or values['IBSW_SWITCH_DIR'] != str(switch)
            or values['IBSW_LOCAL_PACKAGE'] != str(switch / package)
            or values['IBSW_EXPECTED_EFFECT'] != 'REBOOT_EXPECTED'
            or values['IBSW_SCP_PACKAGE_PATH'] != str(root / 'packages/image' / package)
            or values['IBSW_SCP_HELPER_B64'] != base64.b64encode(
                ("import os\nos.environ.pop('IBSW_SCP_AUTH',None)\n" + constants['_REMOTE_HELPER']).encode()).decode()):
        raise AssertionError('fixed original OS generated header differs')
    run_id = values['IBSW_RUN_ID']
    prefix = '.ibsw-' + run_id + '-' + binding[1] + '-os-0001-'
    if not directory.name.startswith(prefix) or not re.fullmatch('[0-9a-f]{32}', directory.name[len(prefix):]):
        raise AssertionError('remote namespace differs from original header')
    runner_body = original[RUNNER]
    if not runner.endswith(runner_body):
        raise AssertionError('original owned runner whole body required')
    keys = ('IBSW_RUN_ID', 'IBSW_NODE', 'IBSW_COMPONENT', 'IBSW_STAGE',
            'IBSW_SCRIPT_SHA256', 'IBSW_ORIGINAL_STEP', 'IBSW_EXIT_RECORD')
    rv = _assignments(runner[:-len(runner_body)], keys, b'#!/bin/bash\n')
    if rv != dict(zip(keys, (run_id, binding[1], 'os', 'os-0001', _sha(step),
                            str(remote), str(directory / 'owned-exit.record')))):
        raise AssertionError('original owned runner header binding differs')
    for name in ('execution.stdout', 'execution.stderr'):
        if _read(directory / name, mode=0o600):
            raise AssertionError('fresh precreated original output required')
    return 'native-os-launcher'
