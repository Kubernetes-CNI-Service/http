#!/usr/bin/env python3
"""Clean-clone workflow for the final Q01 publication phase on v2."""

from pathlib import Path
import ast
import base64
import contextlib
import errno
import fcntl
import hashlib
import inspect
import io
import json
import os
import platform
import re
import secrets
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unicodedata
import unittest
import zlib
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SYSTEM_EXECUTABLE_PATH = os.confstr("CS_PATH") or "/usr/bin:/bin"
_SYSTEM_GIT = shutil.which("git", path=SYSTEM_EXECUTABLE_PATH)
if not _SYSTEM_GIT:
    raise RuntimeError("trusted system Git executable is unavailable")
GIT_BINARY = str(Path(_SYSTEM_GIT).resolve())
RAW_OBJECT_TIMEOUT_SECONDS = 1
S_COMMIT = "991a64476cfe1de2a0ab45bca8b7b6d75d5e9149"
P_MANIFEST_SHA256 = (
    "b3bd5315bce55679e9aae86336cee77a86af8d97de9fde9088557719e528a964"
)
P_MANIFEST_SIZE = 53298
S_HTML_SHA256 = (
    "516c73b23bc5d74f332c7d649cf99a60fd52585f57db467e97ad53237411ca39"
)
P_HTML_STATIC_SEED_SHA256 = (
    "31926c7c07dbcfa0a4f2ea7ff1a31568747572f4a85e4452f04889c013efe5b4"
)
P_HTML_FINAL_SIZE = 718686
P_HTML_FINAL_SHA256 = (
    "392c8fb10c62d1926385cfc0fde4eb37300130dc9bd051c300653f210f31e0f9"
)
P_TREE_PATH_COUNT = 332
P_TREE_PATH_DIGEST = (
    "45fe20a8ae9d0765b042703ade90105c7a7a48a1017b1df93410629d79ed6b64"
)
P_TREE_RECORD_DIGEST = (
    "e72fe6f8634e960727346bed51710c111bf05222caffdfceec6e87d66357110f"
)
P_PHASE_RECORD_DIGEST = (
    "5e4a5eef1aaea27871f5c57978194341f932adafaba30a5253f4121230bd3d07"
)
P_PRELEDGER_PATH_DIGEST = (
    "3115344d0c0f8b59172834392f1d3c70ec518cfa9f093ec9007d6705455efd68"
)
P_FINAL_PATH_DIGEST = (
    "fa27f04baa6b59b94f94746faa4b2c2c0addd0377fab20f93230e3603f9f6ddb"
)
Q01_PUBLIC_DOCUMENT_PATHS = (
    "docs/README.md",
    "docs/architecture/README.md",
    "docs/deployment/BUNDLE_WORKFLOWS.md",
    "docs/deployment/README.md",
    "docs/operations/README.md",
    "docs/reference/README.md",
    "docs/validation/README.md",
    "infra/docker/README.md",
)
Q05_V2_FORBIDDEN_LIFECYCLE_PATHS = (
    "docs/v3/finished-project-lifecycle/ARCHITECTURE.md",
    "docs/v3/finished-project-lifecycle/OPEN_QUESTIONS.md",
    "docs/v3/finished-project-lifecycle/OVERVIEW.md",
    "docs/v3/finished-project-lifecycle/REQUIREMENTS.md",
    "docs/v3/finished-project-lifecycle/TEST_PLAN.md",
    "docs/v3/finished-project-lifecycle/USER_GUIDE.md",
    "docs/v3/finished-project-lifecycle/WORKFLOWS.md",
)
P_V2_FORBIDDEN_REFERENCE_PATHS = (
    "Finished-projects/.gitignore", "Finished-projects/README.txt",
    "v3-requirements.md",
    "monitor/cabletracker-main/.env.example",
    "monitor/cabletracker-main/.gitignore",
    "monitor/cabletracker-main/.gitlab-ci.yml",
    "monitor/cabletracker-main/Dockerfile",
    "monitor/cabletracker-main/README.md",
    "monitor/cabletracker-main/cabletracker_runner.py",
    "monitor/cabletracker-main/docker-compose.yaml",
    "monitor/cabletracker-main/mapping_v4.json",
    "monitor/cabletracker-main/refresh_cvt_sum.py",
    "monitor/cabletracker-main/requirements.txt",
    "monitor/cabletracker-main/tests/fixtures/cvt_offline_sample.json",
    "monitor/cabletracker-main/tests/test_cvt_sum.py",
    "monitor/cabletracker-main/tests/test_offline_workflow.py",
    "monitor/cabletracker-main/tmp.json",
)
P_V2_FORBIDDEN_ROOTS = (
    "docs/v3/finished-project-lifecycle", "Finished-projects",
    "monitor/cabletracker-main",
)
P_PHASE_PRELEDGER_PATHS = (
    ".github/README.md",
    "PUBLIC_REPOSITORY.md",
    *Q01_PUBLIC_DOCUMENT_PATHS,
    "test_cases/README.md",
    "test_cases/REAL_ENVIRONMENT.md",
    "test_cases/script_test_manifest.json",
    "test_cases/test_change_aware_test_runner.py",
    "test_cases/test_public_project_fixture_workflow.py",
    "test_cases/test_documentation_catalog.py",
    "test_cases/test_monitor_authority_semantic_workflow.py",
    "test_cases/test_predeploy_test_gate.py",
    "test_cases/test_public_repository_contract.py",
    "test_cases/test_public_publication_contract.py",
    "test_cases/test_public_publication_workflow.py",
    "test_cases/test_public_s_phase_contract.py",
    "test_cases/test_public_s_phase_workflow.py",
    "test_cases/test_ztp_container_runtime.py",
    "test_cases/test_ztp_release_core_review.py",
    "user-manual.html",
)
P_LEDGER_PATH = "test_cases/script_test_approved_hashes.json"
P_SELF_RECORD_PATH = "test_cases/test_public_publication_workflow.py"
P_FULL_TEST_COUNT = 2124
P_FORMAL_SUITE_TIMEOUT_SECONDS = 1500
P_FULL_SKIP_REASONS = (
    "real byte-exact deploy/hostlock/helper/11-load workflow requires Linux EUID0",
    "root-entrypoint-workflow: NOT COVERED (requires Linux EUID 0 private namespace)",
    "the macOS workspace sandbox forbids filesystem AF_UNIX binds",
    "private documentation tier absent in public checkout",
)
P_REPOSITORY_SUITE_TEST_COUNT = 144
P_REPOSITORY_SKIP_REASONS = (
    "private documentation tier absent in public checkout",
)
P_STAGED_OVERLAY_FQN = (
    "test_cases.test_public_publication_workflow."
    "PublicPublicationWorkflowTests."
    "test_p_staged_overlay_uses_held_index_blobs_and_rejects_rebinding"
)
P_FAST_EXACT_COMMIT_FQN = (
    "test_cases.test_public_publication_workflow."
    "PublicPublicationWorkflowTests."
    "test_p_phase_exact_commit_runs_catalog_in_private_free_clone"
)
P_REENTRANT_OUTER_PROBE_FQN = (
    "test_cases.test_public_publication_workflow."
    "PublicPublicationWorkflowTests._bootstrap_reentry_outer_probe"
)
P_REENTRANT_FAST_TARGET_FQN = (
    "test_cases.test_public_publication_workflow."
    "PublicPublicationWorkflowTests._bootstrap_reentry_fast_commit_target"
)
P_REENTRANT_TEST_PROBE_ARGUMENTS = (
    "-B", "-m", "unittest", "-v", P_REENTRANT_OUTER_PROBE_FQN,
)
P_REENTRANT_RUNNER_ARGUMENTS = (
    ("-B", "test_cases/run_related_tests.py", "--all", "-v"),
    (
        "-B", "test_cases/run_related_tests.py", "--suite",
        "repository-governance", "-v",
    ),
    ("-B", "test_cases/run_related_tests.py", "--all", "--no-approve", "-v"),
    P_REENTRANT_TEST_PROBE_ARGUMENTS,
)
P_REENTRANT_ENV_KEYS = {
    "marker": "HTTP_P_DEPENDENCY_REENTRANT",
    "snapshot": "HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT",
    "snapshot_identity": "HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_IDENTITY",
    "snapshot_fd": "HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_FD",
    "python_home": "HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME",
    "python_home_identity": "HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_IDENTITY",
    "python_home_fds": "HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_FDS",
}
P_CAPSULE_RECORDS_SHA256 = (
    "ecfc714f73eb7e0c5c623bbdd8187b83ce982cf711d68252682fcf073faa56b9"
)
P_CAPSULE_FILE_COUNT = 4055
P_CAPSULE_TOTAL_BYTES = 64164026
P_CAPSULE_MODE_COUNTS = {"0644": 3986, "0755": 69}
P_CAPSULE_NATIVE_COUNT = 65
P_CAPSULE_SIX_SHA256 = "53867fcafe77e16e423728d8f62f15d4e5d8d928c09f2f32d8be6f0cb8614e13"
P_CAPSULE_SOURCE_MAPPING_SHA256 = "5fb3999e611ec59755e70d2e1c9c290184501ce1ea98f9dc476aaebec21f7433"
P_CAPSULE_SOURCE_MAPPING_SIZE = 625454
P_CAPSULE_EXCLUDED_MAPPING_SHA256 = "c1272f7edb9ef89813d263707076278edc47db00a73841fda1c565af83b6266f"
P_CAPSULE_EXCLUDED_MAPPING_SIZE = 198
P_CAPSULE_LOGICAL_MAPPING_SHA256 = "9ea27a2f962493dda35a22aafa1531e77d54622025a7bc7e359f58231195c94b"
P_CAPSULE_LOGICAL_MAPPING_SIZE = 426329
P_CAPSULE_LOGICAL_EXCLUDED_MAPPING_SHA256 = (
    "281722980d55ad3c177813d26b1872c0175cc5626c5f92e44bd43dd5d56c98b8"
)
P_CAPSULE_LOGICAL_EXCLUDED_MAPPING_SIZE = 149
P_CAPSULE_EXCLUDED_TARGET = "numpy/distutils/__pycache__/conv_template.cpython-39.pyc"
P_CAPSULE_ARCHIVE_SIZE = 67287040
P_CAPSULE_ARCHIVE_SHA256 = (
    "476c24d7320be00379236313fe7e919aca86dcb0a5bd15877255e012a073eedd"
)
P_CAPSULE_SANDBOX_EXECUTABLE = "/usr/bin/sandbox-exec"
P_CAPSULE_FD_ENV = "HTTP_P_DEPENDENCY_ARCHIVE_FD"
P_CAPSULE_IDENTITY_ENV = "HTTP_P_DEPENDENCY_ARCHIVE_IDENTITY"
P_FORMAL_LOOPBACK_SSHD_ENV = "HTTP_P_FORMAL_LOOPBACK_SSHD"
P_FORMAL_LOOPBACK_SSHD_RELATIVE = "formal-loopback-sshd"
P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV = "HTTP_P_FORMAL_LOOPBACK_SSHD"
P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE = "formal-loopback-sshd"
P_EXPECTED_FORMAL_LOOPBACK_MUTATION_PROBE = r"""
import errno, json, os, pathlib, sys
state = pathlib.Path(sys.argv[1]).resolve().parent
root = state / 'formal-loopback-sshd'
manifest = root / 'authority.json'
observed = {}
operations = (
    ('open', lambda: os.open(manifest, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)),
    ('chmod', lambda: os.chmod(root, 0o755)),
    ('unlink', lambda: os.unlink(manifest)),
    ('rename', lambda: os.rename(manifest, root / 'authority.moved')),
)
for name, operation in operations:
    try:
        operation()
    except OSError as error:
        observed[name] = error.errno
    else:
        observed[name] = 0
state_fd = os.open(
    state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    | os.O_NONBLOCK | os.O_CLOEXEC,
)
try:
    try:
        descriptor = os.open(
            'hostile-child', os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=state_fd,
        )
    except OSError as error:
        observed['state-openat'] = error.errno
    else:
        os.close(descriptor)
        observed['state-openat'] = 0
finally:
    os.close(state_fd)
print(json.dumps(observed, sort_keys=True))
raise SystemExit(0 if observed == {
    'chmod': errno.EPERM, 'open': errno.EPERM, 'rename': errno.EPERM,
    'state-openat': errno.EPERM, 'unlink': errno.EPERM,
} else 93)
"""
P_REENTRANT_UNITTEST_BOOTSTRAP = """import fcntl, hashlib, json, os, pathlib, runpy, stat, sys
repository = pathlib.Path(sys.argv[1]).resolve()
arguments = json.loads(sys.argv[2])
if not isinstance(arguments, list) or not all(isinstance(value, str) for value in arguments):
    raise SystemExit('malformed reviewed unittest arguments')
if len(arguments) < 2 or arguments[0] != 'unittest':
    raise SystemExit('unreviewed unittest child target')
protocol_keys = (
    'HTTP_P_DEPENDENCY_ARCHIVE_FD', 'HTTP_P_DEPENDENCY_ARCHIVE_IDENTITY',
    'HTTP_P_DEPENDENCY_REENTRANT', 'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT',
    'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_IDENTITY',
    'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_FD',
    'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME',
    'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_IDENTITY',
    'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_FDS',
)
loopback_routing_key = 'HTTP_P_FORMAL_LOOPBACK_SSHD'
if any(key not in os.environ for key in protocol_keys):
    raise SystemExit('partial unittest dependency protocol')
archive_fd = int(os.environ[protocol_keys[0]])
snapshot_fd = int(os.environ[protocol_keys[5]])
python_home_fds = tuple(
    int(value) for value in os.environ[protocol_keys[8]].split(',') if value
)
descriptors = (archive_fd, snapshot_fd, *python_home_fds)
if len(descriptors) != 7 or len(set(descriptors)) != 7:
    raise SystemExit('aliased unittest dependency descriptors')
for descriptor in descriptors:
    os.set_inheritable(descriptor, False)
archive_identity = os.environ[protocol_keys[1]].split(':')
if len(archive_identity) != 4:
    raise SystemExit('malformed unittest archive identity')
archive_stat = os.fstat(archive_fd)
if (
    not stat.S_ISREG(archive_stat.st_mode)
    or stat.S_IMODE(archive_stat.st_mode) != 0o400
    or archive_stat.st_nlink != 0
    or fcntl.fcntl(archive_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
    or (str(archive_stat.st_dev), str(archive_stat.st_ino), str(archive_stat.st_size))
    != tuple(archive_identity[:3])
    or archive_identity[3]
    != '476c24d7320be00379236313fe7e919aca86dcb0a5bd15877255e012a073eedd'
):
    raise SystemExit('unsafe unittest dependency archive')
archive_digest = hashlib.sha256()
offset = 0
while offset < archive_stat.st_size:
    payload = os.pread(archive_fd, min(1024 * 1024, archive_stat.st_size - offset), offset)
    if not payload:
        raise SystemExit('truncated unittest dependency archive')
    archive_digest.update(payload)
    offset += len(payload)
if archive_digest.hexdigest() != archive_identity[3]:
    raise SystemExit('unittest dependency archive digest mismatch')
snapshot = pathlib.Path(os.environ[protocol_keys[3]]).resolve()
snapshot_identity = os.environ[protocol_keys[4]].split(':')
snapshot_stat = os.fstat(snapshot_fd)
snapshot_path_stat = snapshot.lstat()
if (
    len(snapshot_identity) != 3
    or not stat.S_ISDIR(snapshot_stat.st_mode)
    or fcntl.fcntl(snapshot_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
    or (snapshot_stat.st_dev, snapshot_stat.st_ino)
    != (snapshot_path_stat.st_dev, snapshot_path_stat.st_ino)
    or (str(snapshot_stat.st_dev), str(snapshot_stat.st_ino))
    != tuple(snapshot_identity[:2])
    or snapshot_identity[2]
    != 'ecfc714f73eb7e0c5c623bbdd8187b83ce982cf711d68252682fcf073faa56b9'
):
    raise SystemExit('unsafe unittest dependency snapshot')
python_home = pathlib.Path(os.environ[protocol_keys[6]]).resolve()
try:
    python_home_identity = json.loads(os.environ[protocol_keys[7]])
except (TypeError, ValueError):
    raise SystemExit('malformed unittest Python home identity')
if not isinstance(python_home_identity, list) or len(python_home_identity) != 5:
    raise SystemExit('malformed unittest Python home components')
for descriptor, expected in zip(python_home_fds, python_home_identity):
    if not isinstance(expected, dict) or set(expected) != {'dev', 'ino', 'mode', 'path'}:
        raise SystemExit('malformed unittest Python home component')
    metadata = os.fstat(descriptor)
    component = pathlib.Path(expected['path']).resolve()
    path_metadata = component.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        or (metadata.st_dev, metadata.st_ino, f'{stat.S_IMODE(metadata.st_mode):04o}')
        != (expected['dev'], expected['ino'], expected['mode'])
        or (metadata.st_dev, metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        raise SystemExit('unsafe unittest Python home component')
if pathlib.Path(python_home_identity[1]['path']).resolve() != python_home:
    raise SystemExit('unittest Python home path mismatch')
stdlib = pathlib.Path('/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9').resolve()
expected_pythonpath = os.pathsep.join((str(snapshot), str(stdlib), str(stdlib / 'lib-dynload')))
if (
    os.environ.get('HTTP_P_DEPENDENCY_REENTRANT') != '1'
    or pathlib.Path(os.environ.get('PYTHONHOME', '')).resolve() != python_home
    or os.environ.get('PYTHONPATH') != expected_pythonpath
    or os.environ.get('PYTHONNOUSERSITE') != '1'
    or os.environ.get('PYTHONDONTWRITEBYTECODE') != '1'
):
    raise SystemExit('unsafe unittest Python environment')
if any(key.startswith(('LD_', 'DYLD_', 'GIT_')) for key in os.environ):
    raise SystemExit('unsafe unittest ambient environment')
sys.path[:] = [str(snapshot), str(repository), str(stdlib), str(stdlib / 'lib-dynload')]
sys.argv = arguments
runpy.run_module('unittest', run_name='__main__', alter_sys=True)
"""
P_CAPSULE_BOOTSTRAP = """import fcntl, json, pathlib, runpy, subprocess, sys
import os
snapshot = pathlib.Path(sys.argv[1]).resolve()
repository = pathlib.Path(sys.argv[2]).resolve()
arguments = json.loads(sys.argv[3])
reviewed_unittest_bootstrap = __P_REENTRANT_UNITTEST_BOOTSTRAP__
reviewed_arguments = tuple(arguments)
protocol_keys = (
    'HTTP_P_DEPENDENCY_ARCHIVE_FD', 'HTTP_P_DEPENDENCY_ARCHIVE_IDENTITY',
    'HTTP_P_DEPENDENCY_REENTRANT', 'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT',
    'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_IDENTITY',
    'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_FD',
    'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME',
    'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_IDENTITY',
    'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_FDS',
)
loopback_routing_key = 'HTTP_P_FORMAL_LOOPBACK_SSHD'
reentry_keys = protocol_keys[2:]
allowed_reentry = (
    ('-B', 'test_cases/run_related_tests.py', '--all', '-v'),
    ('-B', 'test_cases/run_related_tests.py', '--suite', 'repository-governance', '-v'),
    ('-B', 'test_cases/run_related_tests.py', '--all', '--no-approve', '-v'),
    ('-B', '-m', 'unittest', '-v', 'test_cases.test_public_publication_workflow.PublicPublicationWorkflowTests._bootstrap_reentry_outer_probe'),
)
active = any(key in os.environ for key in reentry_keys)
if active and any(key not in os.environ for key in protocol_keys):
    raise SystemExit('partial dependency reentry protocol')
retain_reentry = active and tuple(arguments) in allowed_reentry
if retain_reentry:
    descriptor_words = [
        os.environ['HTTP_P_DEPENDENCY_ARCHIVE_FD'],
        os.environ['HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_FD'],
        *os.environ['HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_FDS'].split(','),
    ]
    for word in descriptor_words:
        os.set_inheritable(int(word), False)
else:
    descriptor_words = []
    for key in ('HTTP_P_DEPENDENCY_ARCHIVE_FD', 'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_FD'):
        if key in os.environ:
            descriptor_words.append(os.environ[key])
    if 'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_FDS' in os.environ:
        descriptor_words.extend(os.environ['HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_FDS'].split(','))
    closed = set()
    for word in descriptor_words:
        descriptor = int(word)
        if descriptor not in closed:
            os.set_inheritable(descriptor, False)
            os.close(descriptor)
            closed.add(descriptor)
    for key in protocol_keys:
        os.environ.pop(key, None)
    os.environ.pop(loopback_routing_key, None)
for key in tuple(os.environ):
    if key.startswith(('PYTHON', 'LD_', 'DYLD_', 'GIT_')):
        os.environ.pop(key, None)
stdlib_root = pathlib.Path('/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9').resolve()
python_home = pathlib.Path(
    os.environ['HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME']
    if retain_reentry else snapshot.parent / 'python-home'
).resolve()
os.environ.update({
    'PYTHONHOME': str(python_home),
    'PYTHONPATH': os.pathsep.join((str(snapshot), str(stdlib_root), str(stdlib_root/'lib-dynload'))),
    'PYTHONNOUSERSITE': '1',
    'PYTHONDONTWRITEBYTECODE': '1',
})
trusted = []
trusted_roots = {stdlib_root, (stdlib_root / 'lib-dynload').resolve()}
for entry in tuple(sys.path):
    if not entry:
        continue
    resolved = pathlib.Path(entry).resolve()
    if resolved in trusted_roots:
        trusted.append(str(resolved))
sys.path[:] = [str(snapshot), str(repository), *trusted]
reviewed_runner = retain_reentry and reviewed_arguments in allowed_reentry[:3]
expected_unittest_child = None
if reviewed_runner:
    if reviewed_arguments == allowed_reentry[1]:
        manifest = json.loads(
            (repository / 'test_cases/script_test_manifest.json').read_text(encoding='utf-8')
        )
        suites = [
            suite for suite in manifest['test_suites']
            if suite['id'] == 'repository-governance'
        ]
        if len(suites) != 1:
            raise SystemExit('reviewed repository suite is ambiguous')
        expected_unittest_child = (
            sys.executable, '-B', '-m', 'unittest', '-b', '-v',
            *sorted(suites[0]['tests']),
        )
    else:
        expected_unittest_child = (
            sys.executable, '-B', '-m', 'unittest', 'discover', '-b',
            '-s', 'test_cases', '-t', '.', '-p', 'test_*.py', '-v',
        )
    reviewed_descriptors = tuple(int(word) for word in descriptor_words)
    if len(reviewed_descriptors) != 7 or len(set(reviewed_descriptors)) != 7:
        raise SystemExit('invalid reviewed runner descriptor set')
    original_subprocess_run = subprocess.run
    unittest_child_count = [0]
    def reviewed_runner_subprocess(command, *positional, **keywords):
        command_tuple = tuple(command)
        exact_keywords = {'cwd', 'env', 'stdin', 'check'}
        exact_child = (
            command_tuple == expected_unittest_child
            and not positional
            and set(keywords) == exact_keywords
            and pathlib.Path(keywords['cwd']).resolve() == repository
            and isinstance(keywords['env'], dict)
            and keywords['stdin'] is subprocess.DEVNULL
            and keywords['check'] is False
        )
        if not exact_child:
            delegated = dict(keywords)
            delegated.pop('pass_fds', None)
            source_environment = delegated.get('env')
            delegated_environment = dict(
                os.environ if source_environment is None else source_environment
            )
            for key in (*protocol_keys, loopback_routing_key):
                delegated_environment.pop(key, None)
            delegated['env'] = delegated_environment
            return original_subprocess_run(command, *positional, **delegated)
        if unittest_child_count[0] != 0:
            raise SystemExit('multiple reviewed unittest children')
        unittest_child_count[0] += 1
        duplicates = []
        try:
            for descriptor in reviewed_descriptors:
                duplicates.append(fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 0))
            child_environment = dict(keywords['env'])
            child_environment['HTTP_P_DEPENDENCY_ARCHIVE_FD'] = str(duplicates[0])
            child_environment['HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_FD'] = str(duplicates[1])
            child_environment['HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_FDS'] = ','.join(
                str(descriptor) for descriptor in duplicates[2:]
            )
            for key in tuple(child_environment):
                if key.startswith(('LD_', 'DYLD_', 'GIT_')):
                    child_environment.pop(key, None)
            child_command = (
                str(pathlib.Path(sys.executable).resolve()), '-I', '-S', '-B', '-c',
                reviewed_unittest_bootstrap, str(repository),
                json.dumps(list(command_tuple[3:]), separators=(',', ':')),
            )
            child_keywords = dict(keywords)
            child_keywords['env'] = child_environment
            child_keywords['pass_fds'] = tuple(duplicates)
            return original_subprocess_run(child_command, **child_keywords)
        finally:
            for descriptor in duplicates:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
if arguments and arguments[0] == '-B':
    arguments.pop(0)
if not arguments:
    raise SystemExit('missing reviewed Python target')
sys.argv = arguments[1:]
if arguments[0] == '-m':
    sys.argv = arguments[1:]
    runpy.run_module(arguments[1], run_name='__main__', alter_sys=True)
elif arguments[0] == '-c':
    sys.argv = ['-c', *arguments[2:]]
    exec(compile(arguments[1], '<string>', 'exec'), {'__name__': '__main__'})
else:
    sys.argv = arguments
    if reviewed_runner:
        subprocess.run = reviewed_runner_subprocess
        terminal_exit = None
        try:
            try:
                runpy.run_path(arguments[0], run_name='__main__')
            except SystemExit as error:
                terminal_exit = error
        finally:
            subprocess.run = original_subprocess_run
        if unittest_child_count[0] != 1:
            raise SystemExit('reviewed runner did not execute exactly one unittest child')
        if terminal_exit is not None:
            raise terminal_exit
    else:
        runpy.run_path(arguments[0], run_name='__main__')
"""
P_CAPSULE_BOOTSTRAP = P_CAPSULE_BOOTSTRAP.replace(
    "__P_REENTRANT_UNITTEST_BOOTSTRAP__", repr(P_REENTRANT_UNITTEST_BOOTSTRAP),
)
P_FORMAL_HARNESS_BOOTSTRAP = """import fcntl, hashlib, importlib, os, pathlib, stat, sys, unittest
repository = pathlib.Path(sys.argv[1]).resolve()
test_name = sys.argv[2]
archive_fd = int(os.environ['HTTP_P_DEPENDENCY_ARCHIVE_FD'])
identity_fields = os.environ['HTTP_P_DEPENDENCY_ARCHIVE_IDENTITY'].split(':')
if len(identity_fields) != 4:
    raise SystemExit('malformed dependency archive identity')
archive_stat = os.fstat(archive_fd)
if not stat.S_ISREG(archive_stat.st_mode) or stat.S_IMODE(archive_stat.st_mode) != 0o400 or archive_stat.st_nlink != 0:
    raise SystemExit('unsafe inherited dependency archive')
if (str(archive_stat.st_dev), str(archive_stat.st_ino), str(archive_stat.st_size)) != tuple(identity_fields[:3]):
    raise SystemExit('inherited dependency archive identity mismatch')
if fcntl.fcntl(archive_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
    raise SystemExit('inherited dependency archive is writable')
if identity_fields[3] != '476c24d7320be00379236313fe7e919aca86dcb0a5bd15877255e012a073eedd':
    raise SystemExit('unreviewed dependency archive digest')
archive_digest = hashlib.sha256()
archive_offset = 0
while archive_offset < archive_stat.st_size:
    archive_chunk = os.pread(archive_fd, min(1024 * 1024, archive_stat.st_size - archive_offset), archive_offset)
    if not archive_chunk:
        raise SystemExit('truncated inherited dependency archive')
    archive_digest.update(archive_chunk)
    archive_offset += len(archive_chunk)
if archive_digest.hexdigest() != identity_fields[3]:
    raise SystemExit('inherited dependency archive digest mismatch')
os.set_inheritable(archive_fd, False)
if os.environ.get('HTTP_P_DEPENDENCY_REENTRANT') == '1':
    active_fds = [
        os.environ['HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_FD'],
        *os.environ['HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_FDS'].split(','),
    ]
    for active_fd in active_fds:
        os.set_inheritable(int(active_fd), False)
stdlib_root = pathlib.Path('/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9').resolve()
trusted = []
for entry in tuple(sys.path):
    if not entry:
        continue
    resolved = pathlib.Path(entry).resolve()
    if resolved == stdlib_root or stdlib_root in resolved.parents:
        trusted.append(str(resolved))
sys.path[:] = [str(repository), *trusted]
target_module = importlib.import_module(test_name.rsplit('.', 2)[0])
adopt_calls = []
real_adopt = target_module._adopt_dependency_archive_from_environment
def counted_adopt(*args, **kwargs):
    adopt_calls.append(True)
    return real_adopt(*args, **kwargs)
def forbidden_build(*args, **kwargs):
    raise AssertionError('nested formal rebuilt dependency archive')
target_module._adopt_dependency_archive_from_environment = counted_adopt
target_module._build_dependency_archive = forbidden_build
suite = unittest.defaultTestLoader.loadTestsFromName(test_name)
result = unittest.TextTestRunner(verbosity=2).run(suite)
if len(adopt_calls) != 1 or not result.wasSuccessful():
    raise SystemExit(1)
"""
P_CAPSULE_PYTHON_IDENTITY = {
    "executable": (
        "/Library/Developer/CommandLineTools/Library/Frameworks/"
        "Python3.framework/Versions/3.9/bin/python3.9"
    ),
    "implementation": "CPython",
    "version": (3, 9, 6),
    "cache_tag": "cpython-39",
    "platform": "darwin",
    "machine": "arm64",
}
P_CAPSULE_STDLIB_ROOT = (
    "/Library/Developer/CommandLineTools/Library/Frameworks/"
    "Python3.framework/Versions/3.9/lib/python3.9"
)
P_CAPSULE_PACKAGE_VERSIONS = {
    "Jinja2": "3.1.6", "PyYAML": "6.0.3", "pandas": "2.3.3",
    "openpyxl": "3.1.5", "XlsxWriter": "3.2.9",
    "MarkupSafe": "3.0.3", "numpy": "2.0.2",
    "python-dateutil": "2.9.0.post0", "pytz": "2026.2",
    "tzdata": "2026.2", "et_xmlfile": "2.0.0", "six": "1.15.0",
}
P_CAPSULE_ROOTS = (
    "jinja2", "jinja2-3.1.6.dist-info", "yaml", "pyyaml-6.0.3.dist-info",
    "pandas", "pandas-2.3.3.dist-info", "openpyxl",
    "openpyxl-3.1.5.dist-info", "xlsxwriter", "xlsxwriter-3.2.9.dist-info",
    "markupsafe", "markupsafe-3.0.3.dist-info", "numpy",
    "numpy-2.0.2.dist-info", "dateutil", "python_dateutil-2.9.0.post0.dist-info",
    "pytz", "pytz-2026.2.dist-info", "tzdata", "tzdata-2026.2.dist-info",
    "et_xmlfile", "et_xmlfile-2.0.0.dist-info", "six.py",
    "six-1.15.0.dist-info",
)
P_PHASE_FINAL_PATHS = (*P_PHASE_PRELEDGER_PATHS, P_LEDGER_PATH)
P_STATIC_TARGET_SHA256 = {
    ".github/README.md": "d6ef8e75f5e745c1991bea9c97d41b0f21ceb7653c0e9112faa84bf513dda35a",
    "PUBLIC_REPOSITORY.md": "dd5541aa172c431290bc9060905927773c668d7fea907b9d82ddb24d252e8a60",
    "docs/README.md": "e646ad967d9bd418451f152fd2c48f41fe3415dc7acea55e434ae610ff1b57fd",
    "docs/architecture/README.md": "153837bcd62f49edf8591ceec8b1b6ccefe9a3b5638a91bed6452ac87264a0e4",
    "docs/deployment/BUNDLE_WORKFLOWS.md": "adab10445e130f3335113c5b35072b81b5d7e10d28d3d1214ace45e120199a1b",
    "docs/deployment/README.md": "f1914024ab82546239f9424abaca44380f22d6c4331c76e3e6ede218333a036e",
    "docs/operations/README.md": "da1fb0570f8277d7304c1446ab49d7ae49dcf52a320c86b90babdf15e4a6dd05",
    "docs/reference/README.md": "717f023b3016420b61e8889493fd0e2ab9d0106388483025f8d66dee75c75039",
    "docs/validation/README.md": "2a2ee457e01074db1994363a2f8ed62029a9febb14d7c4ea92243b93ec61d98f",
    "infra/docker/README.md": "8355b6cf2bea57f072a689da6a4c3e4979cfd3da26c87f585a728c42972fb996",
    "test_cases/README.md": "670466172c97db3092db21345414b048b1acad1ed69898566132925b52c900cb",
    "test_cases/REAL_ENVIRONMENT.md": "cbf4d5b5623a117f13e06b154ebd0147243a585bcb4084e2476d17d68ff38676",
}


def _literal_dependency_capsule_records(capsule: Path):
    root_metadata = capsule.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_IMODE(root_metadata.st_mode) != 0o700:
        raise AssertionError("P dependency capsule root is not a private real directory")
    records = []
    native = []
    mode_counts = {"0644": 0, "0755": 0}
    for path in sorted(capsule.rglob("*"), key=lambda item: item.relative_to(capsule).as_posix()):
        relative = path.relative_to(capsule).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o755 or metadata.st_nlink < 2:
                raise AssertionError(f"unsafe P capsule directory: {relative}")
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AssertionError(f"unsafe P capsule file: {relative}")
        mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if mode not in mode_counts:
            raise AssertionError(f"unreviewed P capsule mode: {relative}")
        payload = path.read_bytes()
        if len(payload) != metadata.st_size:
            raise AssertionError(f"unstable P capsule file: {relative}")
        if (
            relative.endswith((".pth", ".pyc", ".pyo"))
            or Path(relative).name in {"sitecustomize.py", "usercustomize.py"}
            or "__pycache__" in Path(relative).parts
        ):
            raise AssertionError(f"P capsule contains injection/cache file: {relative}")
        if relative.endswith(".so"):
            if not relative.endswith(".cpython-39-darwin.so"):
                raise AssertionError(f"wrong P capsule native cache tag: {relative}")
            if payload[:4] != b"\xcf\xfa\xed\xfe":
                raise AssertionError(f"wrong P capsule Mach-O magic: {relative}")
            if int.from_bytes(payload[4:8], "little") != 0x0100000C:
                raise AssertionError(f"wrong P capsule native architecture: {relative}")
            native.append(relative)
        mode_counts[mode] += 1
        records.append({
            "mode": mode, "path": relative,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload), "type": "regular",
        })
    serialized = b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for record in records
    )
    return records, serialized, mode_counts, tuple(native)


def _independent_ustar(entries):
    """Build small hostile fixtures without using the production archive code."""
    blocks = []
    for name, mode, payload, typeflag in entries:
        encoded = name.encode("utf-8")
        if len(encoded) > 100:
            raise AssertionError("test USTAR fixture name is too long")
        header = bytearray(512)
        header[:len(encoded)] = encoded
        header[100:108] = f"{mode:07o}\0".encode("ascii")
        header[108:116] = b"0000000\0"
        header[116:124] = b"0000000\0"
        header[124:136] = f"{len(payload):011o}\0".encode("ascii")
        header[136:148] = b"00000000000\0"
        header[148:156] = b"        "
        header[156:157] = typeflag
        header[257:263] = b"ustar\0"
        header[263:265] = b"00"
        checksum = sum(header)
        header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
        blocks.extend((bytes(header), payload, b"\0" * (-len(payload) % 512)))
    stream = b"".join(blocks) + b"\0" * 1024
    return stream + b"\0" * (-len(stream) % 10240)


def _dependency_archive_observer(event, **authority):
    """Test-only boundary observer; production helpers call it without trusting it."""


def _formal_loopback_sshd_observer(event, **authority):
    """Test boundary for parent-owned loopback sshd lifecycle transitions."""


class _DependencyArchiveAuthority:
    def __init__(self, descriptor, metadata, digest):
        self.fd = descriptor
        self.dev = metadata.st_dev
        self.ino = metadata.st_ino
        self.size = metadata.st_size
        self.sha256 = digest

    def close(self):
        descriptor, self.fd = self.fd, -1
        if descriptor >= 0:
            os.close(descriptor)


def _resolve_dependency_sources(roots):
    resolved = {}
    search = tuple(Path(entry).resolve() for entry in sys.path if entry)
    for root in roots:
        matches = []
        for base in search:
            candidate = base / root
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                continue
            if candidate.is_symlink() or not (
                stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
            ):
                raise AssertionError(f"unsafe dependency source root: {root}")
            matches.append(candidate)
        if not matches:
            raise AssertionError(f"missing dependency source root: {root}")
        # sys.path order is part of the bound CPython environment.
        resolved[root] = matches[0]
    if len({path.resolve() for path in resolved.values()}) != len(resolved):
        raise AssertionError("dependency source roots overlap")
    return resolved


def _stable_metadata_tuple(metadata):
    return (
        metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode), metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _read_stable_dependency_source(path):
    path = Path(path)
    descriptor = None
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        first = os.fstat(descriptor)
        if (
            not stat.S_ISREG(first.st_mode) or first.st_nlink != 1
            or stat.S_IMODE(first.st_mode) not in {0o644, 0o755}
        ):
            raise AssertionError(f"unsafe dependency source: {path}")
        payload = os.pread(descriptor, first.st_size + 1, 0)
        middle = os.fstat(descriptor)
        repeated = os.pread(descriptor, middle.st_size + 1, 0)
        final = os.fstat(descriptor)
        if (
            len(payload) != first.st_size or payload != repeated
            or _stable_metadata_tuple(first) != _stable_metadata_tuple(middle)
            or _stable_metadata_tuple(middle) != _stable_metadata_tuple(final)
        ):
            raise AssertionError(f"unstable dependency source: {path}")
        return payload, stat.S_IMODE(first.st_mode)
    except OSError as error:
        raise AssertionError(f"cannot safely read dependency source: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _canonical_dependency_logical_mapping(records, roots):
    if not isinstance(roots, (tuple, list)) or not roots:
        raise AssertionError("dependency logical roots are missing")
    canonical_roots = tuple(roots)
    folded_roots = set()
    for root in canonical_roots:
        if (
            not isinstance(root, str) or not root
            or root != unicodedata.normalize("NFC", root)
            or root.startswith("/") or root.endswith("/") or "\\" in root
            or "//" in root or any(part in {"", ".", ".."} for part in root.split("/"))
        ):
            raise AssertionError("dependency logical root is noncanonical")
        folded = root.casefold()
        if folded in folded_roots:
            raise AssertionError("dependency logical roots collide")
        folded_roots.add(folded)
    for left in canonical_roots:
        for right in canonical_roots:
            if left != right and (left.startswith(right + "/") or right.startswith(left + "/")):
                raise AssertionError("dependency logical roots are ambiguous")
    reviewed = []
    folded_targets = set()
    previous = None
    for record in records:
        if not isinstance(record, dict) or set(record) != {"relative", "root", "target"}:
            raise AssertionError("dependency logical record shape changed")
        relative, root, target = (
            record["relative"], record["root"], record["target"],
        )
        if root not in canonical_roots:
            raise AssertionError("dependency logical record has unknown root")
        for value in (relative, target):
            if not isinstance(value, str) or value != unicodedata.normalize("NFC", value):
                raise AssertionError("dependency logical path is not NFC")
            if (
                not value or value.startswith("/") or value.endswith("/")
                or "\\" in value or "//" in value
                or any(part in {"", ".."} for part in value.split("/"))
            ):
                raise AssertionError("dependency logical path is noncanonical")
        if relative != "." and "." in relative.split("/"):
            raise AssertionError("dependency logical relative path is noncanonical")
        expected_target = root if relative == "." else f"{root}/{relative}"
        if target != expected_target:
            raise AssertionError("dependency logical target cannot be reconstructed")
        encoded = target.encode("utf-8")
        if previous is not None and encoded <= previous:
            raise AssertionError("dependency logical records are not strictly sorted")
        previous = encoded
        folded = target.casefold()
        if folded in folded_targets:
            raise AssertionError("dependency logical targets collide")
        folded_targets.add(folded)
        reviewed.append({"relative": relative, "root": root, "target": target})
    return b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for record in reviewed
    )


def _logical_dependency_records(targets):
    records = []
    for target in targets:
        matches = [
            root for root in P_CAPSULE_ROOTS
            if target == root or target.startswith(root + "/")
        ]
        if len(matches) != 1:
            raise AssertionError(f"dependency target has ambiguous root: {target}")
        root = matches[0]
        relative = "." if target == root else target[len(root) + 1:]
        records.append({"relative": relative, "root": root, "target": target})
    return tuple(records)


def _capsule_source_entries():
    active = None
    if _dependency_reentry_protocol_present():
        source_fd = _parse_exact_descriptor(
            os.environ[P_CAPSULE_FD_ENV], "archive",
        )
        source_metadata = os.fstat(source_fd)
        identity_fields = os.environ[P_CAPSULE_IDENTITY_ENV].split(":")
        borrowed_archive = _DependencyArchiveAuthority(
            source_fd, source_metadata,
            identity_fields[3] if len(identity_fields) == 4 else "",
        )
        active = _active_dependency_authority(borrowed_archive)
        if active is None:
            raise AssertionError("active dependency source authority is unavailable")
        snapshot = Path(active.snapshot)
        resolved = {root: snapshot / root for root in P_CAPSULE_ROOTS}
        for root, source_root in resolved.items():
            try:
                metadata = source_root.lstat()
            except OSError as error:
                raise AssertionError(
                    f"active dependency source root is unavailable: {root}"
                ) from error
            if source_root.is_symlink() or not (
                stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
            ):
                raise AssertionError(f"unsafe active dependency source root: {root}")
        expected_summary = {
            "records_sha256": P_CAPSULE_RECORDS_SHA256,
            "file_count": P_CAPSULE_FILE_COUNT,
            "total_bytes": P_CAPSULE_TOTAL_BYTES,
            "mode_counts": P_CAPSULE_MODE_COUNTS,
        }
        if active.snapshot_summary != expected_summary:
            raise AssertionError("active dependency snapshot summary changed")
        if (
            _DEPENDENCY_RECORD_AUTHORITY is None
            or len(_DEPENDENCY_RECORD_AUTHORITY) != P_CAPSULE_FILE_COUNT
        ):
            raise AssertionError("active dependency archive records are unavailable")
    else:
        resolved = _resolve_dependency_sources(P_CAPSULE_ROOTS)
    source_candidates = []
    for root in P_CAPSULE_ROOTS:
        source_root = Path(resolved[root])
        if source_root.is_file():
            candidates = (source_root,)
        else:
            candidates = tuple(sorted(
                (path for path in source_root.rglob("*") if not path.is_dir()),
                key=lambda path: path.relative_to(source_root).as_posix().encode("utf-8"),
            ))
        for source in candidates:
            relative_source = Path() if source == source_root else source.relative_to(source_root)
            target = root if source == source_root else (Path(root) / relative_source).as_posix()
            source_candidates.append((target, source))
    if active is not None:
        source_candidates.sort(key=lambda item: item[0].encode("utf-8"))
    entries = []
    excluded = []
    for target, source in source_candidates:
            if source.is_symlink():
                raise AssertionError(f"symlink dependency source: {source}")
            suffix = source.suffix
            parts = Path(target).parts
            if (
                suffix in {".pyc", ".pyo", ".pth"}
                or source.name in {"sitecustomize.py", "usercustomize.py"}
                or "__pycache__" in parts
            ):
                excluded.append(target)
                continue
            payload, mode = _read_stable_dependency_source(source)
            if active is not None:
                expected = _DEPENDENCY_RECORD_AUTHORITY.get(target)
                observed = {
                    "mode": f"{mode:04o}", "path": target,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload), "type": "regular",
                }
                if expected != observed:
                    raise AssertionError(
                        f"active dependency source differs from archive: {target}"
                    )
            entries.append((target, mode, payload))
    entries.sort(key=lambda entry: entry[0].encode("utf-8"))
    if len(entries) != P_CAPSULE_FILE_COUNT or len({entry[0] for entry in entries}) != len(entries):
        raise AssertionError("dependency source inventory differs from reviewed capsule")
    logical = _canonical_dependency_logical_mapping(
        _logical_dependency_records(entry[0] for entry in entries), P_CAPSULE_ROOTS,
    )
    excluded_logical = _canonical_dependency_logical_mapping(
        _logical_dependency_records(sorted(excluded, key=lambda value: value.encode("utf-8"))),
        P_CAPSULE_ROOTS,
    )
    if (
        len(logical) != P_CAPSULE_LOGICAL_MAPPING_SIZE
        or hashlib.sha256(logical).hexdigest() != P_CAPSULE_LOGICAL_MAPPING_SHA256
        or (
            active is None and (
                len(excluded) != 1
                or excluded[0] != P_CAPSULE_EXCLUDED_TARGET
                or len(excluded_logical) != P_CAPSULE_LOGICAL_EXCLUDED_MAPPING_SIZE
                or hashlib.sha256(excluded_logical).hexdigest()
                != P_CAPSULE_LOGICAL_EXCLUDED_MAPPING_SHA256
            )
        )
        or (active is not None and (excluded or excluded_logical != b""))
    ):
        raise AssertionError("dependency logical source mapping differs from authority")
    return tuple(entries)


def _canonical_ustar_header(name, mode, size):
    encoded = name.encode("utf-8")
    if not encoded or len(encoded) > 100 or b"\0" in encoded:
        raise AssertionError(f"unsupported dependency archive path: {name!r}")
    header = bytearray(512)
    header[:len(encoded)] = encoded
    header[100:108] = f"{mode:07o}\0".encode("ascii")
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = f"{size:011o}\0".encode("ascii")
    header[136:148] = b"00000000000\0"
    header[148:156] = b"        "
    header[156:157] = tarfile.REGTYPE
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    return bytes(header)


def _write_all(descriptor, payload):
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise AssertionError("short dependency archive write")
        view = view[written:]


def _pread_all(descriptor, size):
    chunks = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise AssertionError("truncated dependency archive")
        chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise AssertionError("dependency archive grew during read")
    return b"".join(chunks)


def _register_dependency_archive_path(
    name, exact_names, descendant_prefixes,
):
    prefixes = tuple(
        name[:index] for index, character in enumerate(name)
        if character == "/"
    )
    if (
        name in descendant_prefixes
        or any(prefix in exact_names for prefix in prefixes)
    ):
        raise AssertionError("file/directory USTAR prefix conflict")
    exact_names.add(name)
    descendant_prefixes.update(prefixes)


def _parse_dependency_archive(payload, *, expected_records=None):
    if not isinstance(payload, bytes) or not payload or len(payload) % 10240:
        raise AssertionError("dependency archive has noncanonical length")
    records = []
    names = []
    normalized = set()
    exact_names = set()
    descendant_prefixes = set()
    offset = 0
    zero_start = None
    while offset + 512 <= len(payload):
        header = payload[offset:offset + 512]
        if header == b"\0" * 512:
            zero_start = offset
            break
        checksum_field = header[148:156]
        if not re.fullmatch(rb"[0-7]{6}\0 ", checksum_field):
            raise AssertionError("noncanonical USTAR checksum")
        checked = bytearray(header)
        checked[148:156] = b"        "
        if int(checksum_field[:6], 8) != sum(checked):
            raise AssertionError("invalid USTAR checksum")
        name_field = header[:100]
        name_bytes = name_field.split(b"\0", 1)[0]
        if not name_bytes or b"\0" not in name_field[len(name_bytes):]:
            raise AssertionError("invalid USTAR name")
        try:
            name = name_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise AssertionError("invalid UTF-8 USTAR name") from error
        if (
            name.startswith("/") or name.endswith("/") or "\\" in name
            or "//" in name or any(part in {"", ".", ".."} for part in name.split("/"))
        ):
            raise AssertionError(f"unsafe USTAR name: {name!r}")
        if header[100:108] not in {b"0000644\0", b"0000755\0"}:
            raise AssertionError("unreviewed USTAR mode")
        if header[108:116] != b"0000000\0" or header[116:124] != b"0000000\0":
            raise AssertionError("nonzero USTAR owner")
        size_field = header[124:136]
        if not re.fullmatch(rb"[0-7]{11}\0", size_field):
            raise AssertionError("noncanonical USTAR size")
        size = int(size_field[:11], 8)
        if header[136:148] != b"00000000000\0":
            raise AssertionError("nonzero USTAR mtime")
        if header[156:157] != tarfile.REGTYPE:
            raise AssertionError("non-regular USTAR member")
        if header[157:257].strip(b"\0") or header[265:329].strip(b"\0"):
            raise AssertionError("USTAR links or owner names are forbidden")
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            raise AssertionError("noncanonical USTAR format")
        if header[329:500].strip(b"\0") or header[500:512].strip(b"\0"):
            raise AssertionError("unsupported USTAR extension fields")
        data_start = offset + 512
        data_end = data_start + size
        padded_end = data_start + ((size + 511) // 512) * 512
        if padded_end > len(payload) or any(payload[data_end:padded_end]):
            raise AssertionError("invalid USTAR payload or padding")
        member_payload = payload[data_start:data_end]
        canonical = unicodedata.normalize("NFC", name).casefold()
        if canonical in normalized:
            raise AssertionError("colliding USTAR member names")
        _register_dependency_archive_path(
            name, exact_names, descendant_prefixes,
        )
        normalized.add(canonical)
        names.append(name)
        mode = int(header[100:107], 8)
        records.append({
            "mode": f"{mode:04o}", "path": name,
            "sha256": hashlib.sha256(member_payload).hexdigest(),
            "size": size, "type": "regular",
        })
        offset = padded_end
    if zero_start is None or len(payload) - zero_start < 1024 or any(payload[zero_start:]):
        raise AssertionError("invalid USTAR end padding")
    if names != sorted(names, key=lambda name: name.encode("utf-8")):
        raise AssertionError("noncanonical USTAR member order")
    result = tuple(records)
    if expected_records is not None and result != tuple(expected_records):
        raise AssertionError("dependency archive records differ from authority")
    return result


def _archive_summary(payload):
    records = _parse_dependency_archive(payload)
    serialized = b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for record in records
    )
    mode_counts = {"0644": 0, "0755": 0}
    native = []
    for record in records:
        mode_counts[record["mode"]] += 1
        if record["path"].endswith(".so"):
            native.append(record["path"])
    record_paths = {record["path"] for record in records}
    roots = tuple(
        root for root in P_CAPSULE_ROOTS
        if root in record_paths or any(path.startswith(root + "/") for path in record_paths)
    )
    return {
        "records": records,
        "records_sha256": hashlib.sha256(serialized).hexdigest(),
        "file_count": len(records),
        "total_bytes": sum(record["size"] for record in records),
        "mode_counts": mode_counts,
        "native_count": len(native),
        "archive_sha256": hashlib.sha256(payload).hexdigest(),
        "archive_size": len(payload),
        "roots": roots,
    }


def _verify_dependency_archive(archive):
    descriptor = archive.fd
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_nlink != 0 or metadata.st_size != P_CAPSULE_ARCHIVE_SIZE
        or (metadata.st_dev, metadata.st_ino) != (archive.dev, archive.ino)
        or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        or not fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
    ):
        raise AssertionError("dependency archive descriptor authority changed")
    payload = _pread_all(descriptor, metadata.st_size)
    summary = _archive_summary(payload)
    logical = _canonical_dependency_logical_mapping(
        _logical_dependency_records(record["path"] for record in summary["records"]),
        P_CAPSULE_ROOTS,
    )
    if (
        len(logical) != P_CAPSULE_LOGICAL_MAPPING_SIZE
        or hashlib.sha256(logical).hexdigest() != P_CAPSULE_LOGICAL_MAPPING_SHA256
    ):
        raise AssertionError("dependency archive logical mapping changed")
    if (
        summary["archive_sha256"] != P_CAPSULE_ARCHIVE_SHA256
        or summary["records_sha256"] != P_CAPSULE_RECORDS_SHA256
        or summary["file_count"] != P_CAPSULE_FILE_COUNT
        or summary["total_bytes"] != P_CAPSULE_TOTAL_BYTES
        or summary["mode_counts"] != P_CAPSULE_MODE_COUNTS
        or summary["native_count"] != P_CAPSULE_NATIVE_COUNT
        or summary["roots"] != tuple(P_CAPSULE_ROOTS)
    ):
        raise AssertionError("dependency archive differs from reviewed authority")
    if summary["archive_sha256"] != archive.sha256 or archive.size != metadata.st_size:
        raise AssertionError("dependency archive handle metadata changed")
    _remember_dependency_records(summary)
    return summary


def _build_dependency_archive(state_root):
    state_root = Path(state_root)
    root_metadata = state_root.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or any(state_root.iterdir())
    ):
        raise AssertionError("dependency archive state root must be fresh mode 0700")
    parent_fd = writer_fd = reader_fd = None
    name = f".dependency-{secrets.token_hex(16)}.ustar"
    try:
        parent_fd = os.open(
            state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        held_parent = os.fstat(parent_fd)
        writer_fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent_fd,
        )
        _dependency_archive_observer("writer-opened", fd=writer_fd, parent_fd=parent_fd, name=name)
        total = 0
        for relative, mode, payload in _capsule_source_entries():
            header = _canonical_ustar_header(relative, mode, len(payload))
            _write_all(writer_fd, header)
            _write_all(writer_fd, payload)
            padding = (-len(payload)) % 512
            if padding:
                _write_all(writer_fd, b"\0" * padding)
            total += 512 + len(payload) + padding
        _write_all(writer_fd, b"\0" * 1024)
        total += 1024
        blocking = (-total) % 10240
        if blocking:
            _write_all(writer_fd, b"\0" * blocking)
        os.fchmod(writer_fd, 0o400)
        os.fsync(writer_fd)
        _dependency_archive_observer("writer-fsync", fd=writer_fd, parent_fd=parent_fd, name=name)
        os.close(writer_fd)
        closed_writer = writer_fd
        writer_fd = None
        _dependency_archive_observer("writer-closed", fd=closed_writer, parent_fd=parent_fd, name=name)
        _dependency_archive_observer("before-reader-open", parent_fd=parent_fd, name=name)
        reader_fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        reader_metadata = os.fstat(reader_fd)
        named_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(reader_metadata.st_mode) or reader_metadata.st_nlink != 1
            or stat.S_IMODE(reader_metadata.st_mode) != 0o400
            or _stable_metadata_tuple(reader_metadata) != _stable_metadata_tuple(named_metadata)
        ):
            raise AssertionError("dependency archive name rebound")
        _dependency_archive_observer("reader-opened", fd=reader_fd, parent_fd=parent_fd, name=name)
        payload = _pread_all(reader_fd, reader_metadata.st_size)
        digest = hashlib.sha256(payload).hexdigest()
        if reader_metadata.st_size != P_CAPSULE_ARCHIVE_SIZE or digest != P_CAPSULE_ARCHIVE_SHA256:
            raise AssertionError("built dependency archive differs from reviewed bytes")
        _dependency_archive_observer("before-unlink", parent_fd=parent_fd, name=name)
        visible_parent = state_root.lstat()
        named_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(visible_parent.st_mode)
            or (visible_parent.st_dev, visible_parent.st_ino) != (held_parent.st_dev, held_parent.st_ino)
            or (named_metadata.st_dev, named_metadata.st_ino) != (reader_metadata.st_dev, reader_metadata.st_ino)
        ):
            raise AssertionError("dependency archive parent or name rebound")
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        _dependency_archive_observer("after-unlink", parent_fd=parent_fd, name=name)
        anonymous_metadata = os.fstat(reader_fd)
        if anonymous_metadata.st_nlink != 0:
            raise AssertionError("dependency archive is not anonymous")
        archive = _DependencyArchiveAuthority(reader_fd, anonymous_metadata, digest)
        _verify_dependency_archive(archive)
        reader_fd = None
        return archive
    except OSError as error:
        raise AssertionError("failed to build dependency archive") from error
    finally:
        if writer_fd is not None:
            os.close(writer_fd)
        if parent_fd is not None:
            try:
                os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass
        if reader_fd is not None:
            os.close(reader_fd)
        if parent_fd is not None:
            os.close(parent_fd)


_DEPENDENCY_RECORD_AUTHORITY = None


def _archive_member_payloads(payload):
    _parse_dependency_archive(payload)
    members = []
    offset = 0
    while payload[offset:offset + 512] != b"\0" * 512:
        header = payload[offset:offset + 512]
        name = header[:100].split(b"\0", 1)[0].decode("utf-8")
        size = int(header[124:135], 8)
        mode = int(header[100:107], 8)
        start = offset + 512
        members.append((name, mode, payload[start:start + size]))
        offset = start + ((size + 511) // 512) * 512
    return tuple(members)


def _remember_dependency_records(summary):
    global _DEPENDENCY_RECORD_AUTHORITY
    _DEPENDENCY_RECORD_AUTHORITY = {
        record["path"]: dict(record) for record in summary["records"]
    }


def _open_snapshot_directory(root_fd, parts):
    descriptor = fcntl.fcntl(root_fd, fcntl.F_DUPFD_CLOEXEC, 0)
    try:
        for part in parts:
            if not part or "/" in part or part in {".", ".."}:
                raise AssertionError("unsafe snapshot directory component")
            try:
                os.mkdir(part, 0o755, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            metadata = os.fstat(child)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o755:
                os.close(child)
                raise AssertionError("unsafe snapshot directory")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _extract_dependency_snapshot(archive, state_root):
    state_root = Path(state_root)
    state_metadata = state_root.lstat()
    if not stat.S_ISDIR(state_metadata.st_mode) or stat.S_IMODE(state_metadata.st_mode) != 0o700:
        raise AssertionError("dependency snapshot state root must be mode 0700")
    summary = _verify_dependency_archive(archive)
    _remember_dependency_records(summary)
    archive_payload = _pread_all(archive.fd, archive.size)
    members = _archive_member_payloads(archive_payload)
    state_fd = snapshot_fd = None
    snapshot = state_root / "snapshot"
    created = False
    try:
        state_fd = os.open(
            state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        os.mkdir("snapshot", 0o700, dir_fd=state_fd)
        created = True
        snapshot_fd = os.open(
            "snapshot", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=state_fd,
        )
        for relative, mode, member_payload in members:
            parts = Path(relative).parts
            parent_fd = _open_snapshot_directory(snapshot_fd, parts[:-1])
            output_fd = None
            try:
                _dependency_archive_observer(
                    "before-snapshot-leaf-open", snapshot=snapshot,
                    relative=relative, parent_fd=parent_fd,
                )
                output_fd = os.open(
                    parts[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    mode, dir_fd=parent_fd,
                )
                _write_all(output_fd, member_payload)
                os.fchmod(output_fd, mode)
                os.fsync(output_fd)
                output_metadata = os.fstat(output_fd)
                if (
                    not stat.S_ISREG(output_metadata.st_mode) or output_metadata.st_nlink != 1
                    or stat.S_IMODE(output_metadata.st_mode) != mode
                    or output_metadata.st_size != len(member_payload)
                ):
                    raise AssertionError("unstable extracted dependency file")
            finally:
                if output_fd is not None:
                    os.close(output_fd)
                os.close(parent_fd)
        result = _verify_dependency_snapshot(snapshot)
        _dependency_archive_observer("snapshot-ready", snapshot=snapshot, summary=result)
        return snapshot
    except OSError as error:
        raise AssertionError("failed to extract dependency snapshot") from error
    finally:
        if snapshot_fd is not None:
            os.close(snapshot_fd)
        if state_fd is not None:
            os.close(state_fd)
        if sys.exc_info()[0] is not None and created and os.path.lexists(snapshot):
            if snapshot.is_symlink():
                snapshot.unlink()
            else:
                shutil.rmtree(snapshot)


def _verify_dependency_snapshot(snapshot):
    snapshot = Path(snapshot)
    try:
        root = snapshot.lstat()
    except OSError as error:
        raise AssertionError("dependency snapshot root is unavailable") from error
    if not stat.S_ISDIR(root.st_mode) or stat.S_IMODE(root.st_mode) != 0o700:
        raise AssertionError("dependency snapshot root is not private")
    if _DEPENDENCY_RECORD_AUTHORITY is None:
        raise AssertionError("dependency snapshot has no reviewed archive authority")
    observed = {}
    directories = []
    for path in sorted(snapshot.rglob("*"), key=lambda item: item.relative_to(snapshot).as_posix()):
        relative = path.relative_to(snapshot).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o755:
                raise AssertionError(f"unsafe dependency snapshot directory: {relative}")
            directories.append(relative)
            continue
        payload, mode = _read_stable_dependency_source(path)
        observed[relative] = {
            "mode": f"{mode:04o}", "path": relative,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload), "type": "regular",
        }
    if observed != _DEPENDENCY_RECORD_AUTHORITY:
        raise AssertionError("dependency snapshot differs from reviewed archive")
    serialized = b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for record in (observed[path] for path in sorted(observed))
    )
    if hashlib.sha256(serialized).hexdigest() != P_CAPSULE_RECORDS_SHA256:
        raise AssertionError("dependency snapshot record digest changed")
    logical = _canonical_dependency_logical_mapping(
        _logical_dependency_records(sorted(observed)), P_CAPSULE_ROOTS,
    )
    if (
        len(logical) != P_CAPSULE_LOGICAL_MAPPING_SIZE
        or hashlib.sha256(logical).hexdigest() != P_CAPSULE_LOGICAL_MAPPING_SHA256
    ):
        raise AssertionError("dependency snapshot logical mapping changed")
    return {
        "records_sha256": P_CAPSULE_RECORDS_SHA256,
        "file_count": len(observed),
        "total_bytes": sum(record["size"] for record in observed.values()),
        "mode_counts": {
            mode: sum(record["mode"] == mode for record in observed.values())
            for mode in ("0644", "0755")
        },
    }


def _canonical_capsule_python_environment(state_root, capsule, *, ambient=None):
    state_root = Path(state_root)
    source = dict(os.environ)
    if ambient:
        source.update(ambient)
    protocol_keys = {
        P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
        *P_REENTRANT_ENV_KEYS.values(),
        P_FORMAL_LOOPBACK_SSHD_ENV,
    }
    for key in tuple(source):
        if (
            key in protocol_keys or key == "HOME" or key == "PATH"
            or key.startswith(("PYTHON", "LD_", "DYLD_", "GIT_"))
        ):
            source.pop(key, None)
    home = state_root / "home"
    cache = state_root / "pycache"
    home.mkdir(mode=0o700, exist_ok=True)
    cache.mkdir(mode=0o700, exist_ok=True)
    source.update({"HOME": str(home), "PATH": SYSTEM_EXECUTABLE_PATH})
    return source


def _private_python_home_open_flags():
    return (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        | os.O_CLOEXEC
    )


def _create_private_python_home(state_root):
    state_root = Path(state_root).resolve()
    state_metadata = state_root.lstat()
    if (
        not stat.S_ISDIR(state_metadata.st_mode)
        or stat.S_IMODE(state_metadata.st_mode) != 0o700
    ):
        raise AssertionError("dependency child state root is not a private directory")
    flags = _private_python_home_open_flags()
    opened = []
    try:
        state_fd = os.open(state_root, flags)
        opened.append(state_fd)
        opened_state = os.fstat(state_fd)
        if (opened_state.st_dev, opened_state.st_ino) != (
            state_metadata.st_dev, state_metadata.st_ino,
        ):
            raise AssertionError("dependency child state root changed while opening")
        parent_fd = state_fd
        components = []
        parent_path = state_root
        for name, mode in (
            ("python-home", 0o700), ("lib", 0o755),
            ("python3.9", 0o755), ("site-packages", 0o755),
        ):
            os.mkdir(name, mode, dir_fd=parent_fd)
            child_fd = os.open(name, flags, dir_fd=parent_fd)
            opened.append(child_fd)
            os.fchmod(child_fd, mode)
            metadata = os.fstat(child_fd)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != mode
            ):
                raise AssertionError("unsafe private PYTHONHOME component")
            child_path = parent_path / name
            components.append((child_path, child_fd, mode, metadata.st_dev, metadata.st_ino))
            parent_path = child_path
            parent_fd = child_fd
        authority = SimpleNamespace(
            state_path=state_root,
            state_fd=state_fd,
            state_identity=(opened_state.st_dev, opened_state.st_ino),
            components=tuple(components),
            closed=False,
        )
        _verify_private_python_home(authority)
        return authority
    except BaseException:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _verify_private_python_home(authority):
    if authority.closed:
        raise AssertionError("private PYTHONHOME authority is closed")
    expected_children = (("lib",), ("python3.9",), ("site-packages",), ())
    state_fd_metadata = os.fstat(authority.state_fd)
    state_path_metadata = authority.state_path.lstat()
    if (
        not stat.S_ISDIR(state_fd_metadata.st_mode)
        or not stat.S_ISDIR(state_path_metadata.st_mode)
        or (state_fd_metadata.st_dev, state_fd_metadata.st_ino)
        != authority.state_identity
        or (state_path_metadata.st_dev, state_path_metadata.st_ino)
        != authority.state_identity
    ):
        raise AssertionError("private PYTHONHOME state identity changed")
    identities = []
    for component, children in zip(authority.components, expected_children):
        path, descriptor, expected_mode, expected_dev, expected_ino = component
        fd_metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
        identity = (expected_dev, expected_ino)
        if (
            not stat.S_ISDIR(fd_metadata.st_mode)
            or not stat.S_ISDIR(path_metadata.st_mode)
            or stat.S_IMODE(fd_metadata.st_mode) != expected_mode
            or stat.S_IMODE(path_metadata.st_mode) != expected_mode
            or (fd_metadata.st_dev, fd_metadata.st_ino) != identity
            or (path_metadata.st_dev, path_metadata.st_ino) != identity
        ):
            raise AssertionError(f"private PYTHONHOME component changed: {path.name}")
        if tuple(sorted(os.listdir(descriptor))) != children:
            raise AssertionError(f"private PYTHONHOME layout changed: {path.name}")
        identities.append(identity)
    if len(identities) != len(set(identities)):
        raise AssertionError("private PYTHONHOME components alias each other")


def _close_private_python_home(authority):
    if authority is None or authority.closed:
        return
    authority.closed = True
    for _path, descriptor, _mode, _dev, _ino in reversed(authority.components):
        os.close(descriptor)
    os.close(authority.state_fd)


def _run_bounded_process(command, *, cwd, environment, pass_fds, timeout):
    process = subprocess.Popen(
        list(command), cwd=cwd, env=environment,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True, pass_fds=tuple(pass_fds),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=1)
        raise
    return subprocess.CompletedProcess(list(command), process.returncode, stdout, stderr)


def _run_capsule_sandbox(command, *, cwd, environment, pass_fds, timeout):
    result = _run_bounded_process(
        command, cwd=cwd, environment=environment,
        pass_fds=pass_fds, timeout=timeout,
    )
    if result.returncode == 71:
        raise AssertionError("dependency sandbox is unavailable")
    return result


def _run_formal_harness_process(command, *, cwd, environment, pass_fds, timeout):
    return _run_bounded_process(
        command, cwd=cwd, environment=environment,
        pass_fds=pass_fds, timeout=timeout,
    )


def _archive_identity_environment(archive):
    return {
        P_CAPSULE_FD_ENV: str(archive.fd),
        P_CAPSULE_IDENTITY_ENV: ":".join((
            str(archive.dev), str(archive.ino), str(archive.size), P_CAPSULE_ARCHIVE_SHA256,
        )),
    }


P_REENTRANT_WRITE_PROBE = textwrap.dedent("""
    import errno, json, os, pathlib, sys
    target = pathlib.Path(sys.argv[1])
    safe_site = pathlib.Path(sys.argv[2])
    observed = {}
    for name, operation in (
        ('open', lambda: os.open(target, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)),
        ('chmod', lambda: os.chmod(target, 0o600)),
    ):
        try:
            operation()
        except OSError as error:
            observed[name] = error.errno
        else:
            observed[name] = 0
    safe_site_fd = os.open(
        safe_site,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | os.O_NONBLOCK | os.O_CLOEXEC,
    )
    try:
        try:
            os.open(
                'hostile.pth',
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                0o600, dir_fd=safe_site_fd,
            )
        except OSError as error:
            observed['site-open'] = error.errno
        else:
            observed['site-open'] = 0
    finally:
        os.close(safe_site_fd)
    observed['site-residue'] = (safe_site / 'hostile.pth').exists()
    print(json.dumps(observed, sort_keys=True))
    raise SystemExit(0 if observed == {
        'chmod': errno.EPERM, 'open': errno.EPERM,
        'site-open': errno.EPERM, 'site-residue': False,
    } else 9)
""")


def _dependency_reentry_protocol_present(environment=None):
    environment = os.environ if environment is None else environment
    keys = (P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV, *P_REENTRANT_ENV_KEYS.values())
    present = tuple(key in environment for key in keys)
    if any(present) and not all(present):
        raise AssertionError("partial dependency reentrant authority protocol")
    return all(present)


def _parse_exact_descriptor(word, label):
    if not isinstance(word, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", word):
        raise AssertionError(f"malformed reentrant {label} descriptor")
    return int(word)


def _active_dependency_authority(dependency_archive):
    if not _dependency_reentry_protocol_present():
        return None
    if os.environ[P_REENTRANT_ENV_KEYS["marker"]] != "1":
        raise AssertionError("invalid dependency reentrant marker")
    _verify_dependency_archive(dependency_archive)

    archive_fd = _parse_exact_descriptor(
        os.environ[P_CAPSULE_FD_ENV], "archive",
    )
    archive_fields = os.environ[P_CAPSULE_IDENTITY_ENV].split(":")
    if (
        len(archive_fields) != 4
        or not all(re.fullmatch(r"(?:0|[1-9][0-9]*)", value) for value in archive_fields[:3])
        or archive_fields[3] != P_CAPSULE_ARCHIVE_SHA256
    ):
        raise AssertionError("malformed inherited reentrant archive authority")
    archive_metadata = os.fstat(archive_fd)
    archive_identity = tuple(map(int, archive_fields[:3]))
    if (
        not stat.S_ISREG(archive_metadata.st_mode)
        or stat.S_IMODE(archive_metadata.st_mode) != 0o400
        or archive_metadata.st_nlink != 0
        or fcntl.fcntl(archive_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        or not fcntl.fcntl(archive_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        or (archive_metadata.st_dev, archive_metadata.st_ino, archive_metadata.st_size)
        != archive_identity
        or archive_identity != (
            dependency_archive.dev, dependency_archive.ino, dependency_archive.size,
        )
    ):
        raise AssertionError("inherited reentrant archive authority changed")
    inherited_archive = _DependencyArchiveAuthority(
        archive_fd, archive_metadata, archive_fields[3],
    )
    _verify_dependency_archive(inherited_archive)

    snapshot_word = os.environ[P_REENTRANT_ENV_KEYS["snapshot"]]
    snapshot = Path(snapshot_word).resolve()
    if str(snapshot) != snapshot_word:
        raise AssertionError("reentrant snapshot path is noncanonical")
    snapshot_fd = _parse_exact_descriptor(
        os.environ[P_REENTRANT_ENV_KEYS["snapshot_fd"]], "snapshot",
    )
    snapshot_fields = os.environ[P_REENTRANT_ENV_KEYS["snapshot_identity"]].split(":")
    if (
        len(snapshot_fields) != 3
        or not all(re.fullmatch(r"(?:0|[1-9][0-9]*)", value) for value in snapshot_fields[:2])
        or snapshot_fields[2] != P_CAPSULE_RECORDS_SHA256
    ):
        raise AssertionError("malformed inherited reentrant snapshot authority")
    snapshot_metadata = os.fstat(snapshot_fd)
    snapshot_named = snapshot.lstat()
    snapshot_identity = tuple(map(int, snapshot_fields[:2]))
    snapshot_flags = fcntl.fcntl(snapshot_fd, fcntl.F_GETFL)
    if (
        not stat.S_ISDIR(snapshot_metadata.st_mode)
        or stat.S_IMODE(snapshot_metadata.st_mode) != 0o700
        or snapshot_flags & os.O_ACCMODE != os.O_RDONLY
        or not fcntl.fcntl(snapshot_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        or (snapshot_metadata.st_dev, snapshot_metadata.st_ino) != snapshot_identity
        or (snapshot_named.st_dev, snapshot_named.st_ino) != snapshot_identity
    ):
        raise AssertionError("inherited reentrant snapshot authority changed")
    snapshot_summary = _verify_dependency_snapshot(snapshot)

    try:
        python_rows = json.loads(
            os.environ[P_REENTRANT_ENV_KEYS["python_home_identity"]]
        )
    except (TypeError, ValueError) as error:
        raise AssertionError("malformed inherited reentrant PYTHONHOME authority") from error
    if (
        not isinstance(python_rows, list) or len(python_rows) != 5
        or any(not isinstance(row, dict) or set(row) != {"dev", "ino", "mode", "path"}
               for row in python_rows)
    ):
        raise AssertionError("malformed inherited reentrant PYTHONHOME authority")
    python_words = os.environ[P_REENTRANT_ENV_KEYS["python_home_fds"]].split(",")
    if len(python_words) != 5:
        raise AssertionError("malformed inherited reentrant PYTHONHOME descriptors")
    python_fds = tuple(
        _parse_exact_descriptor(word, "PYTHONHOME") for word in python_words
    )
    python_paths = []
    python_components = []
    identities = []
    for index, (row, descriptor) in enumerate(zip(python_rows, python_fds)):
        if (
            not isinstance(row["dev"], int) or not isinstance(row["ino"], int)
            or row["mode"] not in ({"0700"} if index == 0 else {"0700", "0755"})
            or not isinstance(row["path"], str)
        ):
            raise AssertionError("malformed inherited reentrant PYTHONHOME row")
        path = Path(row["path"]).resolve()
        if str(path) != row["path"]:
            raise AssertionError("reentrant PYTHONHOME path is noncanonical")
        metadata = os.fstat(descriptor)
        named = path.lstat()
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        identity = (row["dev"], row["ino"])
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != int(row["mode"], 8)
            or flags & os.O_ACCMODE != os.O_RDONLY
            or not fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
            or (metadata.st_dev, metadata.st_ino) != identity
            or (named.st_dev, named.st_ino) != identity
        ):
            raise AssertionError("inherited reentrant PYTHONHOME authority changed")
        python_paths.append(path)
        identities.append(identity)
    descriptor_identities = (
        (archive_metadata.st_dev, archive_metadata.st_ino), snapshot_identity, *identities,
    )
    if len(set(descriptor_identities)) != len(descriptor_identities):
        raise AssertionError("reentrant authority descriptors alias each other")
    expected_paths = (
        snapshot.parent,
        snapshot.parent / "python-home",
        snapshot.parent / "python-home/lib",
        snapshot.parent / "python-home/lib/python3.9",
        snapshot.parent / "python-home/lib/python3.9/site-packages",
    )
    if tuple(python_paths) != tuple(path.resolve() for path in expected_paths):
        raise AssertionError("inherited reentrant PYTHONHOME layout changed")
    python_home_word = os.environ[P_REENTRANT_ENV_KEYS["python_home"]]
    if python_home_word != str(python_paths[1]):
        raise AssertionError("inherited reentrant PYTHONHOME path changed")
    python_authority = SimpleNamespace(
        state_path=python_paths[0], state_fd=python_fds[0],
        state_identity=identities[0],
        components=tuple(
            (python_paths[index], python_fds[index], int(python_rows[index]["mode"], 8),
             *identities[index])
            for index in range(1, 5)
        ),
        closed=False,
    )
    _verify_private_python_home(python_authority)
    return SimpleNamespace(
        archive_fd=archive_fd, snapshot=snapshot, snapshot_fd=snapshot_fd,
        snapshot_summary=snapshot_summary, python_home=python_authority,
        source_fds=(archive_fd, snapshot_fd, *python_fds),
    )


def _duplicate_reentrant_authority(authority):
    duplicates = []
    try:
        for descriptor in authority.source_fds:
            duplicates.append(fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 0))
        return tuple(duplicates)
    except BaseException as error:
        for descriptor in reversed(duplicates):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if isinstance(error, OSError):
            raise AssertionError("failed to duplicate reentrant authority descriptors") from error
        raise


def _close_descriptors(descriptors):
    for descriptor in reversed(tuple(descriptors)):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _reentrant_child_environment(authority, duplicates, ambient=None):
    state_root = authority.snapshot.parent
    environment = _canonical_capsule_python_environment(
        state_root, None, ambient=ambient,
    )
    environment.update({
        P_CAPSULE_FD_ENV: str(duplicates[0]),
        P_CAPSULE_IDENTITY_ENV: os.environ[P_CAPSULE_IDENTITY_ENV],
        P_REENTRANT_ENV_KEYS["marker"]: "1",
        P_REENTRANT_ENV_KEYS["snapshot"]: str(authority.snapshot),
        P_REENTRANT_ENV_KEYS["snapshot_identity"]: os.environ[
            P_REENTRANT_ENV_KEYS["snapshot_identity"]
        ],
        P_REENTRANT_ENV_KEYS["snapshot_fd"]: str(duplicates[1]),
        P_REENTRANT_ENV_KEYS["python_home"]: os.environ[
            P_REENTRANT_ENV_KEYS["python_home"]
        ],
        P_REENTRANT_ENV_KEYS["python_home_identity"]: os.environ[
            P_REENTRANT_ENV_KEYS["python_home_identity"]
        ],
        P_REENTRANT_ENV_KEYS["python_home_fds"]: ",".join(
            str(descriptor) for descriptor in duplicates[2:]
        ),
    })
    return environment


def _adopt_dependency_archive_from_environment():
    raw_fd = os.environ.get(P_CAPSULE_FD_ENV)
    raw_identity = os.environ.get(P_CAPSULE_IDENTITY_ENV)
    if raw_fd is None or raw_identity is None or not re.fullmatch(r"[0-9]+", raw_fd):
        raise AssertionError("missing inherited dependency archive")
    fields = raw_identity.split(":")
    if len(fields) != 4 or not all(re.fullmatch(r"[0-9]+", field) for field in fields[:3]):
        raise AssertionError("malformed inherited dependency archive identity")
    expected = (int(fields[0]), int(fields[1]), int(fields[2]))
    if fields[3] != P_CAPSULE_ARCHIVE_SHA256:
        raise AssertionError("unreviewed inherited dependency archive digest")
    source_fd = int(raw_fd)
    try:
        source_metadata = os.fstat(source_fd)
        source_flags = fcntl.fcntl(source_fd, fcntl.F_GETFL)
    except OSError as error:
        raise AssertionError("unavailable inherited dependency archive") from error
    if (
        not stat.S_ISREG(source_metadata.st_mode)
        or stat.S_IMODE(source_metadata.st_mode) != 0o400
        or source_metadata.st_nlink != 0
        or source_flags & os.O_ACCMODE != os.O_RDONLY
        or (source_metadata.st_dev, source_metadata.st_ino, source_metadata.st_size) != expected
    ):
        raise AssertionError("unsafe inherited dependency archive")
    descriptor = fcntl.fcntl(source_fd, fcntl.F_DUPFD_CLOEXEC, 0)
    archive = None
    try:
        metadata = os.fstat(descriptor)
        archive = _DependencyArchiveAuthority(descriptor, metadata, fields[3])
        _verify_dependency_archive(archive)
        return archive
    except BaseException:
        if archive is not None:
            archive.close()
        else:
            os.close(descriptor)
        raise


@contextlib.contextmanager
def _formal_dependency_archive_scope(state_root):
    state_root = Path(state_root)
    archive = None
    owns_state = False
    try:
        if P_CAPSULE_FD_ENV in os.environ or P_CAPSULE_IDENTITY_ENV in os.environ:
            archive = _adopt_dependency_archive_from_environment()
        else:
            state_root.mkdir(mode=0o700)
            owns_state = True
            archive = _build_dependency_archive(state_root)
        yield archive
        _verify_dependency_archive(archive)
    finally:
        if archive is not None:
            archive.close()
        if owns_state and os.path.lexists(state_root):
            shutil.rmtree(state_root)


def _formal_test_harness_run(repository, test_name, *, timeout, dependency_archive, ambient=None):
    active = _active_dependency_authority(dependency_archive)
    if active is not None:
        if test_name != P_REENTRANT_FAST_TARGET_FQN:
            raise AssertionError("unreviewed active reentrant formal harness target")
        duplicates = _duplicate_reentrant_authority(active)
        try:
            environment = _reentrant_child_environment(active, duplicates, ambient=ambient)
            command = (
                str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                P_FORMAL_HARNESS_BOOTSTRAP, str(Path(repository).resolve()), test_name,
            )
            result = _run_formal_harness_process(
                command, cwd=Path(repository).resolve(), environment=environment,
                pass_fds=duplicates, timeout=timeout,
            )
            _verify_dependency_archive(dependency_archive)
            _verify_dependency_snapshot(active.snapshot)
            _verify_private_python_home(active.python_home)
            return result
        finally:
            _close_descriptors(duplicates)
    _verify_dependency_archive(dependency_archive)
    with tempfile.TemporaryDirectory(prefix="http-p-formal-harness-") as directory:
        state = Path(directory)
        environment = _canonical_capsule_python_environment(state, None, ambient=ambient)
        environment.update(_archive_identity_environment(dependency_archive))
        command = (
            str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
            P_FORMAL_HARNESS_BOOTSTRAP, str(Path(repository).resolve()), test_name,
        )
        result = _run_formal_harness_process(
            command, cwd=Path(repository).resolve(), environment=environment,
            pass_fds=(dependency_archive.fd,), timeout=timeout,
        )
        _verify_dependency_archive(dependency_archive)
        return result


def _expected_capsule_sandbox_profile(snapshot: Path) -> str:
    snapshot = snapshot.resolve()
    parent = snapshot.parent.resolve()
    python_home = (parent / "python-home").resolve()
    loopback = (parent / P_FORMAL_LOOPBACK_SSHD_RELATIVE).resolve()
    profile = (
        "(version 1)\n"
        "(allow default)\n"
        f'(deny file-write* (subpath {json.dumps(str(snapshot))}))\n'
        f'(deny file-write* (literal {json.dumps(str(snapshot))}))\n'
        f'(deny file-write* (literal {json.dumps(str(parent))}))\n'
        f'(deny file-write* (subpath {json.dumps(str(python_home))}))\n'
        f'(deny file-write* (literal {json.dumps(str(python_home))}))\n'
    )
    if os.path.lexists(loopback):
        profile += (
            f'(deny file-write* (subpath {json.dumps(str(parent))}))\n'
            f'(deny file-write* (subpath {json.dumps(str(loopback))}))\n'
            f'(deny file-write* (literal {json.dumps(str(loopback))}))\n'
        )
    return profile


def _canonical_git_environment(extra=None, *, source_environment=None):
    environment = dict(source_environment or os.environ)
    for key in tuple(environment):
        if key.startswith("GIT_"):
            environment.pop(key, None)
    environment.update({
        "GIT_CONFIG": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    if extra:
        environment.update(extra)
    return environment


def _canonical_python_environment(state_root: Path, *, ambient=None):
    source_environment = os.environ.copy()
    if ambient:
        source_environment.update(ambient)
    environment = _canonical_git_environment(source_environment=source_environment)
    for key in tuple(environment):
        if (
            key == "HOME" or key == "PATH" or key.startswith("PYTHON")
            or key == P_FORMAL_LOOPBACK_SSHD_ENV
            or key.startswith(("LD_", "DYLD_"))
        ):
            environment.pop(key, None)
    home = state_root / "home"
    home.mkdir(mode=0o700)
    environment.update({
        "HOME": str(home),
        "PATH": SYSTEM_EXECUTABLE_PATH,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPYCACHEPREFIX": str(state_root / "pycache"),
    })
    return environment


def _formal_loopback_stable_metadata(metadata):
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _formal_loopback_read_held(descriptor, expected_size=None):
    metadata = os.fstat(descriptor)
    size = metadata.st_size if expected_size is None else expected_size
    payload = os.pread(descriptor, size + 1, 0)
    if len(payload) != size:
        raise AssertionError("formal loopback held file changed size")
    return payload, metadata


def _verify_formal_loopback_sshd_authority(authority):
    expected_paths = tuple(authority.held_paths)
    expected_modes = (0o700, 0o600, 0o644, 0o600, 0o644, 0o600, 0o400, 0o600)
    expected_types = (stat.S_IFDIR,) + (stat.S_IFREG,) * 7
    expected_children = {
        "authority.json", "host-ed25519", "host-ed25519.pub", "host-rsa",
        "host-rsa.pub", "sshd.pid", "sshd.stderr", "sshd_config",
    }
    expected_nlinks = (2 + len(expected_children), 1, 1, 1, 1, 1, 1, 1)
    if (
        len(expected_paths) != 8
        or len(authority.held_fds) != 8
        or len(authority.held_identities) != 8
        or len(set(authority.held_identities)) != 8
    ):
        raise AssertionError("formal loopback held authority set changed")
    if set(os.listdir(authority.held_fds[0])) != expected_children:
        raise AssertionError("formal loopback directory entries changed")
    for index, (path, descriptor, identity, expected_mode, expected_type,
                expected_nlink) in enumerate(zip(
                    expected_paths, authority.held_fds, authority.held_identities,
                    expected_modes, expected_types, expected_nlinks,
                )):
        metadata = os.fstat(descriptor)
        named = path.lstat()
        if (
            (metadata.st_dev, metadata.st_ino) != identity
            or (named.st_dev, named.st_ino) != identity
            or stat.S_IFMT(metadata.st_mode) != expected_type
            or stat.S_IFMT(named.st_mode) != expected_type
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or stat.S_IMODE(named.st_mode) != expected_mode
            or metadata.st_nlink != expected_nlink
            or named.st_nlink != expected_nlink
            or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
            or not fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        ):
            raise AssertionError("formal loopback held authority changed")
        if index:
            payload, after = _formal_loopback_read_held(
                descriptor, len(authority.held_payloads[path]),
            )
            if (
                payload != authority.held_payloads[path]
                or _formal_loopback_stable_metadata(metadata)
                != _formal_loopback_stable_metadata(after)
            ):
                raise AssertionError("formal loopback held content changed")
    pid_fd = os.open(
        "sshd.pid",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=authority.held_fds[0],
    )
    try:
        before = os.fstat(pid_fd)
        named = os.stat(
            "sshd.pid", dir_fd=authority.held_fds[0], follow_symlinks=False,
        )
        first, middle = _formal_loopback_read_held(pid_fd, before.st_size)
        second, after = _formal_loopback_read_held(pid_fd, middle.st_size)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o644
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
            or first != f"{authority.daemon_pid}\n".encode("ascii")
            or second != first
            or _formal_loopback_stable_metadata(before)
            != _formal_loopback_stable_metadata(middle)
            or _formal_loopback_stable_metadata(before)
            != _formal_loopback_stable_metadata(after)
        ):
            raise AssertionError("formal loopback pid authority changed")
    finally:
        os.close(pid_fd)
    if authority.process.poll() is not None:
        raise AssertionError("formal loopback sshd exited")


def _formal_loopback_remove(path):
    if not os.path.lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)


@contextlib.contextmanager
def _formal_loopback_sshd_scope(state_root):
    state_root = Path(state_root).resolve()
    root = state_root / P_FORMAL_LOOPBACK_SSHD_RELATIVE
    expected_sshd = Path("/usr/sbin/sshd")
    keygen = Path("/usr/bin/ssh-keygen")
    keyscan = Path("/usr/bin/ssh-keyscan")
    environment = _canonical_capsule_python_environment(state_root, None)
    held_fds = []
    process = None
    log_stream = None
    authority = None
    try:
        sshd_metadata = expected_sshd.lstat()
        if (
            not stat.S_ISREG(sshd_metadata.st_mode)
            or sshd_metadata.st_uid != 0
            or stat.S_IMODE(sshd_metadata.st_mode) & 0o022
        ):
            raise AssertionError("unsafe formal loopback sshd executable")
        root.mkdir(mode=0o700)
        for algorithm, name in (("ed25519", "host-ed25519"), ("rsa", "host-rsa")):
            result = subprocess.run(
                (
                    str(keygen), "-q", "-t", algorithm, "-N", "", "-f",
                    str(root / name),
                ),
                text=True, capture_output=True, timeout=10, check=False,
                env=environment,
            )
            if result.returncode != 0 or result.stderr != "":
                raise AssertionError("formal loopback key generation failed")
            (root / name).chmod(0o600)
            public_path = root / (name + ".pub")
            public_words = public_path.read_text(encoding="utf-8").split()
            if len(public_words) < 2:
                raise AssertionError("formal loopback generated malformed public key")
            public_payload = (" ".join(public_words[:2]) + "\n").encode("utf-8")
            public_fd = os.open(
                public_path,
                os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                if os.write(public_fd, public_payload) != len(public_payload):
                    raise AssertionError("short formal loopback public key write")
                os.fsync(public_fd)
            finally:
                os.close(public_fd)
            public_path.chmod(0o644)
        _formal_loopback_sshd_observer("after-keygen", root=root)

        public_keys = {
            "ed25519": (root / "host-ed25519.pub").read_text(encoding="utf-8"),
            "rsa": (root / "host-rsa.pub").read_text(encoding="utf-8"),
        }
        fingerprints = {}
        for algorithm, name in (("ed25519", "host-ed25519"), ("rsa", "host-rsa")):
            result = subprocess.run(
                (str(keygen), "-lf", str(root / (name + ".pub")), "-E", "sha256"),
                text=True, capture_output=True, timeout=10, check=False,
                env=environment,
            )
            fields = result.stdout.strip().split()
            if (
                result.returncode != 0 or result.stderr != "" or len(fields) < 4
                or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fields[1])
            ):
                raise AssertionError("formal loopback fingerprint generation failed")
            fingerprints[algorithm] = fields[1]

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = root / "sshd_config"
        config_payload = (
            f"Port {port}\n"
            "ListenAddress 127.0.0.1\n"
            f"HostKey {root / 'host-ed25519'}\n"
            f"PidFile {root / 'sshd.pid'}\n"
            "AuthorizedKeysFile none\n"
            "PasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\n"
            "UsePAM no\n"
            "PermitRootLogin no\n"
            "StrictModes no\n"
            "MaxStartups 100\n"
            "PerSourcePenalties no\n"
            "LogLevel ERROR\n"
        ).encode("utf-8")
        config_fd = os.open(
            config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            if os.write(config_fd, config_payload) != len(config_payload):
                raise AssertionError("short formal loopback config write")
            os.fsync(config_fd)
        finally:
            os.close(config_fd)
        daemon_log = root / "sshd.stderr"
        log_fd = os.open(
            daemon_log,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        log_stream = os.fdopen(log_fd, "w", encoding="utf-8")
        process = subprocess.Popen(
            (str(expected_sshd), "-D", "-e", "-f", str(config)),
            cwd=root, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=log_stream, text=True,
            start_new_session=True, close_fds=True, pass_fds=(),
        )
        log_stream.close()

        manifest = root / "authority.json"
        manifest_value = {
            "daemon_log": "sshd.stderr",
            "fingerprints": fingerprints,
            "pid": process.pid,
            "port": port,
            "public_keys": {
                algorithm: {
                    "name": "host-" + algorithm + ".pub",
                    "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                    "value": payload,
                }
                for algorithm, payload in public_keys.items()
            },
            "schema": "http-p-formal-loopback-sshd-v1",
        }
        manifest_payload = (
            json.dumps(manifest_value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        manifest_fd = os.open(
            manifest,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
        )
        try:
            if os.write(manifest_fd, manifest_payload) != len(manifest_payload):
                raise AssertionError("short formal loopback manifest write")
            os.fsync(manifest_fd)
        finally:
            os.close(manifest_fd)

        held_paths = (
            root, root / "host-ed25519", root / "host-ed25519.pub",
            root / "host-rsa", root / "host-rsa.pub", config, manifest, daemon_log,
        )
        for index, path in enumerate(held_paths):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if index == 0:
                flags |= os.O_DIRECTORY
            held_fds.append(os.open(path, flags))
        held_identities = tuple(
            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
            for descriptor in held_fds
        )
        held_payloads = {}
        for path, descriptor in zip(held_paths[1:], held_fds[1:]):
            payload, _metadata = _formal_loopback_read_held(descriptor)
            held_payloads[path] = payload
        authority = SimpleNamespace(
            root=root, port=port, daemon_pid=process.pid, process=process,
            manifest=manifest, daemon_log=daemon_log, public_keys=public_keys,
            fingerprints=fingerprints, held_paths=held_paths,
            held_fds=tuple(held_fds), held_identities=held_identities,
            held_payloads=held_payloads,
        )
        event_authority = {
            "root": root, "daemon_pid": process.pid,
            "daemon_pgid": os.getpgid(process.pid),
            "held_fds": tuple(held_fds),
        }
        _formal_loopback_sshd_observer("after-popen", **event_authority)
        deadline = time.monotonic() + 8
        ready = False
        host = f"[127.0.0.1]:{port}"
        for attempt in range(3):
            if process.poll() is not None:
                raise AssertionError("formal loopback sshd exited before readiness")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            result = subprocess.run(
                (
                    str(keyscan), "-T", "2", "-p", str(port), "-t",
                    "ed25519", "127.0.0.1",
                ),
                text=True, capture_output=True, timeout=min(4, remaining),
                check=False, env=environment,
            )
            _formal_loopback_sshd_observer(
                "readiness-attempt", **event_authority,
                attempt=attempt, deadline=deadline, remaining=remaining,
            )
            lines = tuple(
                line for line in result.stdout.splitlines()
                if line and not line.startswith("#")
            )
            expected_fields = public_keys["ed25519"].split()[:2]
            if result.returncode == 0 and len(lines) == 1:
                fields = lines[0].split()
                if fields == [host, *expected_fields]:
                    digest = "SHA256:" + base64.b64encode(
                        hashlib.sha256(base64.b64decode(fields[2])).digest()
                    ).rstrip(b"=").decode("ascii")
                    if digest == fingerprints["ed25519"]:
                        ready = True
                        break
            time.sleep(0.05)
        if not ready:
            raise AssertionError("formal loopback sshd readiness failed")
        _formal_loopback_sshd_observer("after-readiness", **event_authority)
        _verify_formal_loopback_sshd_authority(authority)
        yield authority
        _verify_formal_loopback_sshd_authority(authority)
    finally:
        try:
            if log_stream is not None and not log_stream.closed:
                log_stream.close()
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1)
        finally:
            try:
                for descriptor in reversed(held_fds):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            finally:
                try:
                    _formal_loopback_remove(root)
                finally:
                    _formal_loopback_remove(root.with_name(root.name + ".held"))


def _formal_loopback_sshd_authority_from_environment():
    marker = os.environ.get(P_FORMAL_LOOPBACK_SSHD_ENV)
    if marker is None:
        return None
    if marker != "1" or not _dependency_reentry_protocol_present():
        raise AssertionError("invalid formal loopback sshd routing authority")
    archive_fd = _parse_exact_descriptor(os.environ[P_CAPSULE_FD_ENV], "archive")
    fields = os.environ[P_CAPSULE_IDENTITY_ENV].split(":")
    if len(fields) != 4:
        raise AssertionError("malformed formal loopback archive authority")
    borrowed = _DependencyArchiveAuthority(
        archive_fd, os.fstat(archive_fd), fields[3],
    )
    active = _active_dependency_authority(borrowed)
    if active is None:
        raise AssertionError("formal loopback requires active dependency authority")
    root = active.snapshot.parent / P_FORMAL_LOOPBACK_SSHD_RELATIVE
    names_modes = {
        "host-ed25519": 0o600, "host-ed25519.pub": 0o644,
        "host-rsa": 0o600, "host-rsa.pub": 0o644,
        "sshd_config": 0o600, "authority.json": 0o400,
        "sshd.stderr": 0o600, "sshd.pid": 0o644,
    }
    payloads = {}
    identities = []
    root_fd = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        | os.O_CLOEXEC,
    )
    try:
        root_metadata = os.fstat(root_fd)
        root_named = root.lstat()
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
            or root_metadata.st_nlink != 2 + len(names_modes)
            or (root_metadata.st_dev, root_metadata.st_ino)
            != (root_named.st_dev, root_named.st_ino)
            or set(os.listdir(root_fd)) != set(names_modes)
        ):
            raise AssertionError("unsafe formal loopback root")
        for name, expected_mode in names_modes.items():
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            try:
                before = os.fstat(descriptor)
                named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                first, middle = _formal_loopback_read_held(
                    descriptor, before.st_size,
                )
                second, after = _formal_loopback_read_held(
                    descriptor, middle.st_size,
                )
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_IMODE(before.st_mode) != expected_mode
                    or before.st_nlink != 1
                    or (before.st_dev, before.st_ino)
                    != (named.st_dev, named.st_ino)
                    or first != second
                    or _formal_loopback_stable_metadata(before)
                    != _formal_loopback_stable_metadata(middle)
                    or _formal_loopback_stable_metadata(before)
                    != _formal_loopback_stable_metadata(after)
                ):
                    raise AssertionError("formal loopback input changed")
                payloads[name] = first
                identities.append((before.st_dev, before.st_ino))
            finally:
                os.close(descriptor)
    finally:
        os.close(root_fd)
    if len(set(identities)) != len(identities):
        raise AssertionError("formal loopback inputs alias")
    try:
        manifest = json.loads(payloads["authority.json"])
    except (TypeError, ValueError) as error:
        raise AssertionError("malformed formal loopback manifest") from error
    public_keys = {
        "ed25519": payloads["host-ed25519.pub"].decode("utf-8"),
        "rsa": payloads["host-rsa.pub"].decode("utf-8"),
    }
    fingerprints = {}
    for algorithm, payload in public_keys.items():
        words = payload.split()
        if len(words) < 2:
            raise AssertionError("malformed formal loopback public key")
        fingerprints[algorithm] = "SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(words[1])).digest()
        ).rstrip(b"=").decode("ascii")
    expected_manifest = {
        "daemon_log": "sshd.stderr",
        "fingerprints": fingerprints,
        "pid": manifest.get("pid"),
        "port": manifest.get("port"),
        "public_keys": {
            algorithm: {
                "name": "host-" + algorithm + ".pub",
                "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                "value": payload,
            }
            for algorithm, payload in public_keys.items()
        },
        "schema": "http-p-formal-loopback-sshd-v1",
    }
    if (
        manifest != expected_manifest
        or payloads["authority.json"] != (
            json.dumps(expected_manifest, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        or not isinstance(manifest.get("pid"), int) or manifest["pid"] <= 0
        or not isinstance(manifest.get("port"), int)
        or not 0 < manifest["port"] < 65536
    ):
        raise AssertionError("formal loopback manifest changed")
    if payloads["sshd.pid"] != f"{manifest['pid']}\n".encode("ascii"):
        raise AssertionError("formal loopback pid changed")
    try:
        os.kill(manifest["pid"], 0)
    except OSError as error:
        raise AssertionError("formal loopback daemon is unavailable") from error
    return SimpleNamespace(
        root=root, manifest=root / "authority.json", daemon_log=root / "sshd.stderr",
        port=manifest["port"], daemon_pid=manifest["pid"],
        public_keys=public_keys, fingerprints=fingerprints,
        source_fds=active.source_fds,
    )


def _python_run(
    repository: Path, arguments, *, timeout, dependency_archive, ambient=None,
):
    repository = Path(repository).resolve()
    _verify_dependency_archive(dependency_archive)
    active = _active_dependency_authority(dependency_archive)
    if active is not None:
        formal_loopback = tuple(arguments) in P_REENTRANT_RUNNER_ARGUMENTS[:3]
        if formal_loopback:
            inherited_loopback = _formal_loopback_sshd_authority_from_environment()
            if inherited_loopback is None:
                raise AssertionError("formal runner is missing loopback authority")
        duplicates = _duplicate_reentrant_authority(active)
        try:
            proof_environment = _canonical_capsule_python_environment(
                active.snapshot.parent, None, ambient=ambient,
            )
            for key in (
                P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
                *P_REENTRANT_ENV_KEYS.values(),
            ):
                proof_environment.pop(key, None)
            nested = _run_bounded_process(
                (
                    P_CAPSULE_SANDBOX_EXECUTABLE, "-p",
                    "(version 1)\n(allow default)\n", "/usr/bin/true",
                ),
                cwd=repository, environment=proof_environment,
                pass_fds=(), timeout=timeout,
            )
            nested_result = (nested.returncode, nested.stdout, nested.stderr)
            if nested_result not in (
                (71, "", ""),
                (
                    71, "",
                    "sandbox-exec: sandbox_apply: Operation not permitted\n",
                ),
            ):
                raise AssertionError(
                    "nested dependency sandbox authority was not rejected: "
                    f"returncode={nested.returncode!r} stdout={nested.stdout!r} "
                    f"stderr={nested.stderr!r}"
                )
            write = _run_bounded_process(
                (
                    str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                    P_REENTRANT_WRITE_PROBE, str(active.snapshot / "six.py"),
                    str(active.python_home.components[-1][0]),
                ),
                cwd=repository, environment=proof_environment,
                pass_fds=(), timeout=timeout,
            )
            expected_write = {
                "chmod": errno.EPERM, "open": errno.EPERM,
                "site-open": errno.EPERM, "site-residue": False,
            }
            try:
                write_report = json.loads(write.stdout)
            except (TypeError, ValueError) as error:
                raise AssertionError("malformed reentrant kernel write proof") from error
            if (
                write.returncode != 0 or write.stderr != ""
                or write.stdout != json.dumps(expected_write, sort_keys=True) + "\n"
                or write_report != expected_write
            ):
                raise AssertionError("reentrant kernel write proof failed")

            allowed = tuple(arguments) in P_REENTRANT_RUNNER_ARGUMENTS
            child_environment = _reentrant_child_environment(
                active, duplicates, ambient=ambient,
            )
            if formal_loopback:
                child_environment[P_FORMAL_LOOPBACK_SSHD_ENV] = "1"
            else:
                child_environment.pop(P_FORMAL_LOOPBACK_SSHD_ENV, None)
            if allowed:
                pass_fds = duplicates
            else:
                for key in P_REENTRANT_ENV_KEYS.values():
                    child_environment.pop(key, None)
                pass_fds = (duplicates[0],)
            command = (
                str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                P_CAPSULE_BOOTSTRAP, str(active.snapshot), str(repository),
                json.dumps(list(arguments), separators=(",", ":")),
            )
            result = _run_bounded_process(
                command, cwd=repository, environment=child_environment,
                pass_fds=pass_fds, timeout=timeout,
            )
            _verify_dependency_archive(dependency_archive)
            _verify_dependency_snapshot(active.snapshot)
            _verify_private_python_home(active.python_home)
            return result
        finally:
            _close_descriptors(duplicates)
    state = Path(tempfile.mkdtemp(prefix="http-p-python-")).resolve()
    state.chmod(0o700)
    snapshot = state / "snapshot"
    python_home_authority = None
    snapshot_authority_fd = None
    snapshot_authority_identity = None
    loopback_stack = contextlib.ExitStack()
    loopback_authority = None
    try:
        snapshot = _extract_dependency_snapshot(dependency_archive, state)
        python_home_authority = _create_private_python_home(state)
        _verify_dependency_snapshot(snapshot)
        _verify_private_python_home(python_home_authority)
        retain_reentry = tuple(arguments) in P_REENTRANT_RUNNER_ARGUMENTS
        if retain_reentry:
            snapshot_authority_fd = os.open(
                snapshot, _private_python_home_open_flags(),
            )
            snapshot_metadata = os.fstat(snapshot_authority_fd)
            snapshot_named = snapshot.lstat()
            snapshot_authority_identity = (
                snapshot_metadata.st_dev, snapshot_metadata.st_ino,
            )
            snapshot_flags = fcntl.fcntl(snapshot_authority_fd, fcntl.F_GETFL)
            if (
                not stat.S_ISDIR(snapshot_metadata.st_mode)
                or stat.S_IMODE(snapshot_metadata.st_mode) != 0o700
                or snapshot_flags & os.O_ACCMODE != os.O_RDONLY
                or not fcntl.fcntl(snapshot_authority_fd, fcntl.F_GETFD)
                & fcntl.FD_CLOEXEC
                or (snapshot_named.st_dev, snapshot_named.st_ino)
                != snapshot_authority_identity
            ):
                raise AssertionError("failed to hold dependency snapshot authority")
        formal_loopback = tuple(arguments) in P_REENTRANT_RUNNER_ARGUMENTS[:3]
        if formal_loopback:
            loopback_authority = loopback_stack.enter_context(
                _formal_loopback_sshd_scope(state)
            )
        _dependency_archive_observer(
            "before-sandbox", snapshot=snapshot, state_root=state,
        )
        _verify_dependency_snapshot(snapshot)
        _verify_private_python_home(python_home_authority)
        if loopback_authority is not None:
            _verify_formal_loopback_sshd_authority(loopback_authority)
        if snapshot_authority_fd is not None:
            snapshot_metadata = os.fstat(snapshot_authority_fd)
            snapshot_named = snapshot.lstat()
            if (
                (snapshot_metadata.st_dev, snapshot_metadata.st_ino)
                != snapshot_authority_identity
                or (snapshot_named.st_dev, snapshot_named.st_ino)
                != snapshot_authority_identity
            ):
                raise AssertionError("dependency snapshot authority changed before sandbox")
        environment = _canonical_capsule_python_environment(
            state, snapshot, ambient=ambient,
        )
        environment.update(_archive_identity_environment(dependency_archive))
        if formal_loopback:
            environment[P_FORMAL_LOOPBACK_SSHD_ENV] = "1"
        pass_fds = (dependency_archive.fd,)
        if retain_reentry:
            python_home_rows = (
                (
                    python_home_authority.state_path,
                    python_home_authority.state_fd,
                    0o700,
                    *python_home_authority.state_identity,
                ),
                *python_home_authority.components,
            )
            authority_identities = (
                (dependency_archive.dev, dependency_archive.ino),
                snapshot_authority_identity,
                *((row[3], row[4]) for row in python_home_rows),
            )
            if len(authority_identities) != len(set(authority_identities)):
                raise AssertionError("standalone reentrant authority descriptors alias")
            environment.update({
                P_REENTRANT_ENV_KEYS["marker"]: "1",
                P_REENTRANT_ENV_KEYS["snapshot"]: str(snapshot),
                P_REENTRANT_ENV_KEYS["snapshot_identity"]: ":".join((
                    str(snapshot_authority_identity[0]),
                    str(snapshot_authority_identity[1]),
                    P_CAPSULE_RECORDS_SHA256,
                )),
                P_REENTRANT_ENV_KEYS["snapshot_fd"]: str(snapshot_authority_fd),
                P_REENTRANT_ENV_KEYS["python_home"]: str(
                    python_home_authority.components[0][0]
                ),
                P_REENTRANT_ENV_KEYS["python_home_identity"]: json.dumps([
                    {
                        "dev": row[3], "ino": row[4],
                        "mode": f"{row[2]:04o}", "path": str(row[0]),
                    }
                    for row in python_home_rows
                ], sort_keys=True, separators=(",", ":")),
                P_REENTRANT_ENV_KEYS["python_home_fds"]: ",".join(
                    str(row[1]) for row in python_home_rows
                ),
            })
            pass_fds = (
                dependency_archive.fd, snapshot_authority_fd,
                *(row[1] for row in python_home_rows),
            )
        command = (
            P_CAPSULE_SANDBOX_EXECUTABLE, "-p",
            _expected_capsule_sandbox_profile(snapshot),
            str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
            P_CAPSULE_BOOTSTRAP, str(snapshot), str(repository),
            json.dumps(list(arguments), separators=(",", ":")),
        )
        result = _run_capsule_sandbox(
            command, cwd=repository, environment=environment,
            pass_fds=pass_fds, timeout=timeout,
        )
        _dependency_archive_observer(
            "after-child", snapshot=snapshot, state_root=state, result=result,
        )
        _verify_dependency_snapshot(snapshot)
        _verify_private_python_home(python_home_authority)
        _verify_dependency_archive(dependency_archive)
        if snapshot_authority_fd is not None:
            snapshot_metadata = os.fstat(snapshot_authority_fd)
            snapshot_named = snapshot.lstat()
            if (
                (snapshot_metadata.st_dev, snapshot_metadata.st_ino)
                != snapshot_authority_identity
                or (snapshot_named.st_dev, snapshot_named.st_ino)
                != snapshot_authority_identity
            ):
                raise AssertionError("dependency snapshot authority changed after child")
        if result.returncode == 71:
            raise AssertionError("dependency sandbox is unavailable")
        return result
    finally:
        try:
            loopback_stack.close()
        finally:
            if snapshot_authority_fd is not None:
                os.close(snapshot_authority_fd)
            _close_private_python_home(python_home_authority)
            for owned in (state, state.with_name(state.name + ".held")):
                if os.path.lexists(owned):
                    if owned.is_symlink():
                        owned.unlink()
                    else:
                        shutil.rmtree(owned)


def _git_run(repository: Path, arguments, *, text=False, check=False):
    if "commit" in arguments and arguments.index("commit") % 2 == 0:
        commit_index = arguments.index("commit")
        prefix = arguments[:commit_index]
        if any(prefix[index] != "-c" for index in range(0, len(prefix), 2)):
            raise AssertionError("P canonical commit options are not reviewed")
        config = {
            prefix[index + 1].split("=", 1)[0]: prefix[index + 1].split("=", 1)[1]
            for index in range(0, len(prefix), 2)
            if "=" in prefix[index + 1]
        }
        tail = arguments[commit_index + 1:]
        if "-m" not in tail:
            raise AssertionError("P canonical commit requires a literal message")
        message = tail[tail.index("-m") + 1]
        environment = _canonical_git_environment()
        environment.update({
            "GIT_AUTHOR_NAME": config.get("user.name", "P Proof"),
            "GIT_AUTHOR_EMAIL": config.get("user.email", "p-proof@example.invalid"),
            "GIT_COMMITTER_NAME": config.get("user.name", "P Proof"),
            "GIT_COMMITTER_EMAIL": config.get("user.email", "p-proof@example.invalid"),
        })
        base_command = [
            GIT_BINARY, "--no-replace-objects", "-c",
            f"core.hooksPath={os.devnull}", "-C", str(repository),
        ]
        tree = subprocess.run(
            [*base_command, "write-tree"], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if tree.returncode:
            result = tree
        else:
            parent = subprocess.run(
                [*base_command, "rev-parse", "--verify", "HEAD"],
                env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False,
            )
            commit_command = [
                *base_command, "commit-tree", tree.stdout.decode("ascii").strip(),
            ]
            if parent.returncode == 0:
                commit_command.extend(["-p", parent.stdout.decode("ascii").strip()])
            created = subprocess.run(
                commit_command, env=environment,
                input=(message + "\n").encode("utf-8"),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            if created.returncode:
                result = created
            else:
                object_id = created.stdout.decode("ascii").strip()
                update = [*base_command, "update-ref", "HEAD", object_id]
                if parent.returncode == 0:
                    update.append(parent.stdout.decode("ascii").strip())
                result = subprocess.run(
                    update, env=environment, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=False,
                )
        if result.returncode and check:
            raise subprocess.CalledProcessError(
                result.returncode, result.args, output=result.stdout,
                stderr=result.stderr,
            )
        if text:
            return subprocess.CompletedProcess(
                result.args, result.returncode,
                result.stdout.decode("utf-8", "replace"),
                result.stderr.decode("utf-8", "replace"),
            )
        return result
    if arguments and arguments[0] == "add" and "--" in arguments:
        separator = arguments.index("--")
        if separator != 1:
            raise AssertionError("P canonical add accepts only literal paths")
        environment = _canonical_git_environment()
        for relative in arguments[separator + 1:]:
            path = repository / relative
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                command = [
                    GIT_BINARY, "--no-replace-objects", "-c",
                    f"core.hooksPath={os.devnull}", "-C", str(repository),
                    "update-index", "--remove", "--", relative,
                ]
                result = subprocess.run(
                    command, env=environment, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=text, check=False,
                )
            else:
                if stat.S_ISLNK(metadata.st_mode):
                    payload = os.readlink(path).encode("utf-8")
                    hashed = subprocess.run(
                        [GIT_BINARY, "--no-replace-objects", "-c",
                         f"core.hooksPath={os.devnull}", "-C", str(repository),
                         "hash-object", "-w", "--stdin"],
                        env=environment, input=payload, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, check=False,
                    )
                    mode = "120000"
                elif stat.S_ISREG(metadata.st_mode):
                    hashed = subprocess.run(
                        [GIT_BINARY, "--no-replace-objects", "-c",
                         f"core.hooksPath={os.devnull}", "-C", str(repository),
                         "hash-object", "-w", "--no-filters", "--", relative],
                        env=environment, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, check=False,
                    )
                    mode = "100755" if metadata.st_mode & 0o111 else "100644"
                else:
                    raise AssertionError(f"P canonical add path is not regular: {relative}")
                if hashed.returncode:
                    result = hashed
                else:
                    object_id = hashed.stdout.decode("ascii").strip()
                    result = subprocess.run(
                        [GIT_BINARY, "--no-replace-objects", "-c",
                         f"core.hooksPath={os.devnull}", "-C", str(repository),
                         "update-index", "--add", "--cacheinfo",
                         f"{mode},{object_id},{relative}"],
                        env=environment, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=text, check=False,
                    )
            if result.returncode:
                if check:
                    raise subprocess.CalledProcessError(
                        result.returncode, result.args, output=result.stdout,
                        stderr=result.stderr,
                    )
                return result
        return subprocess.CompletedProcess(
            [GIT_BINARY, "add", "--", *arguments[separator + 1:]],
            0, "" if text else b"", "" if text else b"",
        )
    return subprocess.run(
        [GIT_BINARY, "--no-replace-objects", "-c", f"core.hooksPath={os.devnull}",
         "-C", str(repository), *arguments],
        env=_canonical_git_environment(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=text, check=check,
    )


def _git_run_with_review_hook(repository: Path, arguments, *, text=False):
    return subprocess.run(
        [GIT_BINARY, "--no-replace-objects", "-C", str(repository), *arguments],
        env=_canonical_git_environment(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=text, check=False,
    )


def _tracked_paths() -> set[str]:
    result = _git_run(ROOT, ["ls-files", "-z"])
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", "replace"))
    return {
        item.decode("utf-8") for item in result.stdout.split(b"\0") if item
    }


def _path_digest(paths) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.encode("utf-8") + b"\0")
    return digest.hexdigest()


def _nul_paths(payload: bytes, *, source: str) -> set[str]:
    fields = payload.split(b"\0")
    if not fields or fields[-1] != b"":
        raise AssertionError(f"{source} is not NUL terminated")
    paths = set()
    for raw in fields[:-1]:
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AssertionError(f"non-UTF-8 path in {source}") from error
        if (
            not relative or relative.startswith("/") or "\0" in relative
            or relative == "." or relative == ".."
            or relative.startswith("../") or "/../" in relative
        ):
            raise AssertionError(f"unsafe path in {source}: {relative!r}")
        if relative in paths:
            raise AssertionError(f"duplicate path in {source}: {relative}")
        paths.add(relative)
    return paths


def _forbidden_v2_paths(paths) -> set[str]:
    exact = (*Q05_V2_FORBIDDEN_LIFECYCLE_PATHS, *P_V2_FORBIDDEN_REFERENCE_PATHS)
    return {
        path for path in paths
        if any(path == item or path.startswith(item + "/") for item in exact)
        or any(
            path == root or path.startswith(root + "/")
            for root in P_V2_FORBIDDEN_ROOTS
        )
    }


def _materialization_observer(event: str, path: Path, **authority) -> None:
    """Test-only race hook; production proof never replaces this no-op."""


def _object_tree_snapshot(root: Path) -> dict:
    """Capture one object tree without following any symlink component."""
    snapshot = {}

    def visit(path: Path, relative: str) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            snapshot[relative] = ("absent", b"")
            return
        mode = stat.S_IFMT(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            payload = path.read_bytes()
        elif stat.S_ISLNK(metadata.st_mode):
            payload = os.readlink(path).encode("utf-8")
        else:
            payload = b""
        snapshot[relative] = (
            metadata.st_dev, metadata.st_ino, metadata.st_nlink,
            metadata.st_mode, metadata.st_uid, metadata.st_gid,
            metadata.st_size, metadata.st_mtime_ns, mode, payload,
        )
        if stat.S_ISDIR(metadata.st_mode):
            with os.scandir(path) as entries:
                names = sorted(entry.name for entry in entries)
            for name in names:
                visit(path / name, name if relative == "." else f"{relative}/{name}")

    visit(root, ".")
    return snapshot


def _directory_snapshot(root: Path) -> dict:
    return _object_tree_snapshot(root)


def _assert_canonical_history_metadata(repository: Path) -> None:
    git_path = repository / ".git"
    try:
        metadata = git_path.lstat()
    except OSError as error:
        raise AssertionError("P canonical Git directory is missing") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise AssertionError("P proof Git directory is not a real directory")
    if os.path.lexists(git_path / "commondir"):
        raise AssertionError("P proof rejects Git commondir metadata")
    for alternate in (
        git_path / "objects/info/alternates",
        git_path / "objects/info/http-alternates",
    ):
        if os.path.lexists(alternate):
            raise AssertionError("P proof rejects alternate object metadata")
    shallow = _git_run(
        repository, ["rev-parse", "--is-shallow-repository"], text=True,
    )
    if shallow.returncode or shallow.stdout != "false\n":
        raise AssertionError("P proof rejects shallow repository metadata")
    grafts = git_path / "info/grafts"
    if os.path.lexists(grafts):
        raise AssertionError("P proof rejects legacy graft metadata")


def _history_observer(event: str, repository: Path, **authority) -> None:
    """Test-only history race hook; the formal proof keeps this as a no-op."""


def _clean_state_observer(event: str, repository: Path, **authority) -> None:
    """Test-only clean-state race hook; the formal proof keeps this as a no-op."""


def _raw_commit_parents(repository: Path, object_id: str) -> tuple[str, ...]:
    _echoed, _kind, _size, payload = _read_raw_git_object(
        repository, object_id, "commit",
    )
    headers, separator, _body = payload.partition(b"\n\n")
    if not separator:
        raise AssertionError("P commit object has no header/body separator")
    lines = headers.split(b"\n")
    if not lines or not re.fullmatch(rb"tree [0-9a-f]{40}", lines[0]):
        raise AssertionError("P commit tree header is not exact and first")
    if any(line.startswith(b"tree") for line in lines[1:]):
        raise AssertionError("P commit has a duplicate/misplaced tree header")
    parents = []
    for line in lines[1:]:
        if line.startswith(b"parent "):
            try:
                parent = line[7:].decode("ascii", "strict")
            except UnicodeError as error:
                raise AssertionError("P parent object id is not ASCII") from error
            if not re.fullmatch(r"[0-9a-f]{40}", parent):
                raise AssertionError(f"invalid P parent object id: {parent!r}")
            parents.append(parent)
    return tuple(parents)


def _read_raw_git_object(
    repository: Path, object_id: str, expected_kind: str,
) -> tuple[str, str, int, bytes]:
    if not re.fullmatch(r"[0-9a-f]{40}", object_id):
        raise AssertionError(f"invalid P object id: {object_id!r}")
    if expected_kind not in {"blob", "tree", "commit"}:
        raise AssertionError(f"invalid P expected object kind: {expected_kind!r}")
    environment = _canonical_git_environment()
    for key in tuple(environment):
        if key.startswith(("LD_", "DYLD_")):
            environment.pop(key, None)
    environment["PATH"] = SYSTEM_EXECUTABLE_PATH
    command = (
        GIT_BINARY, "--no-replace-objects", "-c",
        f"core.hooksPath={os.devnull}", "-C", str(repository),
        "cat-file", "--batch",
    )
    try:
        result = subprocess.run(
            command, env=environment, input=(object_id + "\n").encode("ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            check=False, timeout=RAW_OBJECT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AssertionError("P raw object authority read failed") from error
    if result.returncode != 0 or result.stderr != b"":
        raise AssertionError("P raw object authority process failed")
    header, separator, remainder = result.stdout.partition(b"\n")
    if not separator:
        raise AssertionError("P raw object response has no header")
    fields = header.split(b" ")
    if len(fields) != 3:
        raise AssertionError("P raw object response header is malformed")
    try:
        echoed = fields[0].decode("ascii")
        kind = fields[1].decode("ascii")
        raw_size = fields[2].decode("ascii")
    except UnicodeError as error:
        raise AssertionError("P raw object response header is not ASCII") from error
    if echoed != object_id or kind != expected_kind:
        raise AssertionError("P raw object response identity/type mismatch")
    if not re.fullmatch(r"0|[1-9][0-9]*", raw_size):
        raise AssertionError("P raw object response size is noncanonical")
    size = int(raw_size)
    if len(remainder) != size + 1 or remainder[-1:] != b"\n":
        raise AssertionError("P raw object response length/delimiter mismatch")
    payload = remainder[:-1]
    canonical = (
        kind.encode("ascii") + b" " + str(len(payload)).encode("ascii")
        + b"\0" + payload
    )
    if hashlib.sha1(canonical).hexdigest() != object_id:
        raise AssertionError("P raw object payload does not match its object id")
    return echoed, kind, size, payload


def _verified_commit_records(
    repository: Path, object_id: str,
) -> dict[str, tuple[str, str, str, bytes]]:
    if not re.fullmatch(r"[0-9a-f]{40}", object_id):
        raise AssertionError(f"invalid P commit object id: {object_id!r}")
    git_directory = repository / ".git"
    try:
        git_metadata = git_directory.lstat()
    except OSError as error:
        raise AssertionError("P Git directory is missing") from error
    if not stat.S_ISDIR(git_metadata.st_mode):
        raise AssertionError("P Git directory is not a real directory")
    for forbidden in (
        git_directory / "commondir",
        git_directory / "objects/info/alternates",
        git_directory / "objects/info/http-alternates",
    ):
        if os.path.lexists(forbidden):
            raise AssertionError(f"P Git object authority is redirected: {forbidden}")
    _echoed, _kind, _size, commit = _read_raw_git_object(
        repository, object_id, "commit",
    )
    headers, separator, _body = commit.partition(b"\n\n")
    if not separator:
        raise AssertionError("P commit object has no header/body separator")
    lines = headers.split(b"\n")
    if not lines or not re.fullmatch(rb"tree [0-9a-f]{40}", lines[0]):
        raise AssertionError("P commit tree header is not exact and first")
    if any(line.startswith(b"tree") for line in lines[1:]):
        raise AssertionError("P commit has a duplicate/misplaced tree header")
    root_tree = lines[0][5:].decode("ascii")
    records = {}

    def walk(tree_id: str, prefix: str, ancestors: tuple[str, ...]) -> None:
        if tree_id in ancestors:
            raise AssertionError("P tree graph contains a cycle")
        _oid, _tree_kind, _tree_size, payload = _read_raw_git_object(
            repository, tree_id, "tree",
        )
        offset = 0
        previous_key = None
        logical_names = set()
        entries = []
        while offset < len(payload):
            space = payload.find(b" ", offset)
            nul = payload.find(b"\0", space + 1 if space >= 0 else offset)
            if space <= offset or nul < 0 or nul + 21 > len(payload):
                raise AssertionError("P tree object has a truncated entry")
            raw_mode = payload[offset:space]
            raw_name = payload[space + 1:nul]
            raw_oid = payload[nul + 1:nul + 21]
            offset = nul + 21
            if raw_mode not in {b"100644", b"100755", b"120000", b"40000"}:
                raise AssertionError("P tree object has a noncanonical mode")
            if not raw_name or raw_name in {b".", b".."} or b"/" in raw_name:
                raise AssertionError("P tree object has an unsafe name")
            try:
                name = raw_name.decode("utf-8")
            except UnicodeError as error:
                raise AssertionError("P tree object name is not UTF-8") from error
            if name in logical_names:
                raise AssertionError("P tree object has a duplicate logical name")
            logical_names.add(name)
            is_tree = raw_mode == b"40000"
            order_key = raw_name + (b"/" if is_tree else b"")
            if previous_key is not None and order_key <= previous_key:
                raise AssertionError("P tree object order is noncanonical")
            previous_key = order_key
            entries.append((raw_mode.decode("ascii"), name, raw_oid.hex(), is_tree))
        if offset != len(payload):
            raise AssertionError("P tree object has trailing bytes")
        for mode, name, child_oid, is_tree in entries:
            relative = f"{prefix}/{name}" if prefix else name
            if is_tree:
                walk(child_oid, relative, (*ancestors, tree_id))
                continue
            _blob_oid, kind, _blob_size, blob = _read_raw_git_object(
                repository, child_oid, "blob",
            )
            if relative in records:
                raise AssertionError(f"duplicate P tree path: {relative}")
            records[relative] = (mode, kind, child_oid, blob)

    walk(root_tree, "", ())
    return records


def _raw_p_lineage_distance(repository: Path, head: str) -> int:
    current = head
    for distance in range(4):
        if current == S_COMMIT:
            return distance
        parents = _raw_commit_parents(repository, current)
        if len(parents) != 1:
            raise AssertionError(
                f"P lineage must have exactly one raw parent: {current} {parents!r}"
            )
        current = parents[0]
    raise AssertionError("P lineage is more than two commits beyond S")


def _write_loose_object_fixture(
    repository: Path, claimed_object_id: str, kind: str, payload: bytes,
) -> Path:
    """Write a test-only loose object, allowing an intentionally false filename."""
    self_describing = (
        kind.encode("ascii") + b" " + str(len(payload)).encode("ascii")
        + b"\0" + payload
    )
    loose = (
        repository / ".git/objects" / claimed_object_id[:2]
        / claimed_object_id[2:]
    )
    loose.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(loose):
        loose.chmod(0o600)
    loose.write_bytes(zlib.compress(self_describing))
    return loose


def _materialize_staged_overlay(destination: Path, expected_paths) -> dict:
    from test_cases import test_public_project_fixture_workflow as fixture

    expected = set(expected_paths)
    preliminary, _records = fixture._index_snapshot(ROOT)
    with fixture._held_canonical_index(ROOT):
        snapshot, records = fixture._index_snapshot(ROOT)
        if snapshot != preliminary:
            raise AssertionError("P index changed before authority lock")
        staged_result = fixture._run_canonical_git(
            ROOT, ["diff", "--cached", "--name-only", "-z", "--"],
        )
        if staged_result.returncode:
            raise AssertionError(staged_result.stderr.decode("utf-8", "replace"))
        staged = _nul_paths(staged_result.stdout, source="P staged paths")
        if staged != expected:
            raise AssertionError(
                f"P staged paths differ: missing={sorted(expected - staged)!r} "
                f"extra={sorted(staged - expected)!r}"
            )
        materialized = {}
        for relative in sorted(expected):
            mode, object_id = records[relative]
            if mode != "100644":
                raise AssertionError(f"P phase path is not 100644: {relative}")
            payload = fixture._index_blob(ROOT, object_id)
            materialized[relative] = (mode, "blob", object_id, payload)
        confirmed, _records = fixture._index_snapshot(ROOT)
        if confirmed != snapshot:
            raise AssertionError("P index changed during materialization")
        for relative, (mode, _kind, _object_id, payload) in materialized.items():
            _write_materialized_entry(destination, relative, payload, mode)
        final, _records = fixture._index_snapshot(ROOT)
        if final != snapshot:
            raise AssertionError("P index changed at overlay publish boundary")
    return materialized


def _directory_fd_identity(descriptor: int):
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino, value.st_mode


def _write_materialized_entry(
    destination: Path, relative: str, payload: bytes, mode: str,
) -> None:
    parts = relative.split("/")
    if (
        not parts or any(not part or part in {".", ".."} for part in parts)
        or mode not in {"100644", "100755"}
    ):
        raise AssertionError(f"unsafe P materialized path: {relative!r}")
    target = destination / relative
    _materialization_observer("before-entry", target)
    if not os.path.lexists(destination):
        try:
            destination.mkdir(mode=0o755)
        except OSError as error:
            raise AssertionError("P materialization root cannot be created") from error
    root_flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        root_flags |= getattr(os, name, 0)
    descriptors = []
    temporary = None
    recovery = None
    recovery_descriptor = None
    prior_payload = None
    leaf_descriptor = None
    output = None
    publication_attempted = False
    publication_completed = False
    published_identity = None
    try:
        try:
            root_fd = os.open(destination, root_flags)
            root_held = os.fstat(root_fd)
        except OSError as error:
            raise AssertionError("P materialization root is unsafe") from error
        descriptors.append((destination, root_fd, root_held))
        if not stat.S_ISDIR(root_held.st_mode):
            raise AssertionError("P materialization root is not a directory")
        _materialization_observer(
            "root-held", target, root_fd=root_fd, root_flags=root_flags,
        )
        current_fd = root_fd
        current_path = destination
        for index, component in enumerate(parts[:-1]):
            try:
                child_fd = os.open(component, root_flags, dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o755, dir_fd=current_fd)
                    child_fd = os.open(component, root_flags, dir_fd=current_fd)
                except OSError as error:
                    raise AssertionError(
                        f"P materialization parent is unsafe: {relative}"
                    ) from error
            except OSError as error:
                raise AssertionError(
                    f"P materialization parent is unsafe: {relative}"
                ) from error
            try:
                child_held = os.fstat(child_fd)
            except BaseException:
                os.close(child_fd)
                raise
            current_path = current_path / component
            descriptors.append((current_path, child_fd, child_held))
            current_fd = child_fd
            if not stat.S_ISDIR(child_held.st_mode):
                raise AssertionError(f"P materialization parent is not a directory: {relative}")
            if index == len(parts[:-1]) - 1:
                _materialization_observer(
                    "parent-held", target, parent_fd=current_fd,
                    parent_flags=root_flags,
                    component="/".join(parts[:-1]),
                )

        leaf = parts[-1]
        read_flags = os.O_RDONLY
        for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
            read_flags |= getattr(os, name, 0)
        prior = None
        try:
            leaf_descriptor = os.open(leaf, read_flags, dir_fd=current_fd)
        except FileNotFoundError:
            leaf_descriptor = None
        except OSError as error:
            raise AssertionError(f"P materialization leaf is unsafe: {relative}") from error
        if leaf_descriptor is not None:
            prior = os.fstat(leaf_descriptor)
            if not stat.S_ISREG(prior.st_mode) or prior.st_nlink != 1:
                raise AssertionError(f"P materialization leaf is not replaceable: {relative}")
            _materialization_observer(
                "leaf-opened", target, leaf_fd=leaf_descriptor,
                leaf_flags=read_flags,
            )

        for visible_path, descriptor, held in descriptors:
            try:
                visible = visible_path.lstat()
                current = os.fstat(descriptor)
            except OSError as error:
                raise AssertionError(f"P materialization authority changed: {relative}") from error
            if (
                not stat.S_ISDIR(visible.st_mode)
                or (visible.st_dev, visible.st_ino) != (held.st_dev, held.st_ino)
                or _directory_fd_identity(descriptor)
                != (held.st_dev, held.st_ino, held.st_mode)
            ):
                raise AssertionError(f"P materialization authority changed: {relative}")
        if prior is not None:
            try:
                visible_leaf = os.stat(
                    leaf, dir_fd=current_fd, follow_symlinks=False,
                )
                current_leaf = os.fstat(leaf_descriptor)
            except OSError as error:
                raise AssertionError(f"P materialization leaf changed: {relative}") from error
            if (
                (visible_leaf.st_dev, visible_leaf.st_ino, visible_leaf.st_nlink,
                 visible_leaf.st_mode, visible_leaf.st_size, visible_leaf.st_mtime_ns,
                 visible_leaf.st_ctime_ns)
                != (prior.st_dev, prior.st_ino, prior.st_nlink, prior.st_mode,
                    prior.st_size, prior.st_mtime_ns, prior.st_ctime_ns)
                or (current_leaf.st_dev, current_leaf.st_ino, current_leaf.st_nlink,
                    current_leaf.st_mode, current_leaf.st_size,
                    current_leaf.st_mtime_ns, current_leaf.st_ctime_ns)
                != (prior.st_dev, prior.st_ino, prior.st_nlink, prior.st_mode,
                    prior.st_size, prior.st_mtime_ns, prior.st_ctime_ns)
            ):
                raise AssertionError(f"P materialization leaf changed: {relative}")

        temporary = f".{leaf}.materializing-{secrets.token_hex(16)}"
        write_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            write_flags |= getattr(os, name, 0)
        try:
            output = os.open(temporary, write_flags, 0o600, dir_fd=current_fd)
        except OSError as error:
            raise AssertionError(f"P materialization temporary cannot be created: {relative}") from error
        view = memoryview(payload)
        while view:
            written = os.write(output, view)
            if written <= 0:
                raise AssertionError("P materialization made no write progress")
            view = view[written:]
        os.fchmod(output, 0o755 if mode == "100755" else 0o644)
        os.fsync(output)
        expected_mode = 0o755 if mode == "100755" else 0o644
        held_temporary = os.fstat(output)
        visible_temporary = os.stat(
            temporary, dir_fd=current_fd, follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(held_temporary.st_mode)
            or held_temporary.st_nlink != 1
            or stat.S_IMODE(held_temporary.st_mode) != expected_mode
            or held_temporary.st_size != len(payload)
            or (visible_temporary.st_dev, visible_temporary.st_ino,
                visible_temporary.st_mode, visible_temporary.st_nlink,
                visible_temporary.st_size)
            != (held_temporary.st_dev, held_temporary.st_ino,
                held_temporary.st_mode, held_temporary.st_nlink,
                held_temporary.st_size)
        ):
            raise AssertionError(f"P materialization temporary changed: {relative}")
        for visible_path, descriptor, held in descriptors:
            visible = visible_path.lstat()
            current = os.fstat(descriptor)
            if (
                (visible.st_dev, visible.st_ino) != (held.st_dev, held.st_ino)
                or (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)
            ):
                raise AssertionError(f"P materialization authority changed: {relative}")

        if prior is not None:
            recovery = f".{leaf}.rollback-{secrets.token_hex(16)}"
            try:
                os.link(
                    leaf, recovery, src_dir_fd=current_fd, dst_dir_fd=current_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise AssertionError(
                    f"P materialization rollback authority cannot be created: {relative}"
                ) from error
            visible_prior = os.stat(
                leaf, dir_fd=current_fd, follow_symlinks=False,
            )
            visible_recovery = os.stat(
                recovery, dir_fd=current_fd, follow_symlinks=False,
            )
            current_prior = os.fstat(leaf_descriptor)
            if (
                not stat.S_ISREG(visible_recovery.st_mode)
                or (visible_prior.st_dev, visible_prior.st_ino)
                != (prior.st_dev, prior.st_ino)
                or (visible_recovery.st_dev, visible_recovery.st_ino)
                != (prior.st_dev, prior.st_ino)
                or (current_prior.st_dev, current_prior.st_ino)
                != (prior.st_dev, prior.st_ino)
                or visible_prior.st_nlink != 2
                or visible_recovery.st_nlink != 2
                or current_prior.st_nlink != 2
            ):
                raise AssertionError(
                    f"P materialization rollback authority changed: {relative}"
                )
            recovery_flags = os.O_RDWR
            for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
                recovery_flags |= getattr(os, name, 0)
            try:
                recovery_descriptor = os.open(
                    recovery, recovery_flags, dir_fd=current_fd,
                )
            except OSError as error:
                raise AssertionError(
                    f"P materialization rollback descriptor cannot be held: {relative}"
                ) from error
            held_recovery = os.fstat(recovery_descriptor)
            if (
                not stat.S_ISREG(held_recovery.st_mode)
                or (held_recovery.st_dev, held_recovery.st_ino)
                != (prior.st_dev, prior.st_ino)
                or held_recovery.st_nlink != 2
                or held_recovery.st_mode != prior.st_mode
                or held_recovery.st_size != prior.st_size
            ):
                raise AssertionError(
                    f"P materialization rollback descriptor changed: {relative}"
                )
            snapshot_before = os.fstat(leaf_descriptor)
            first_snapshot = os.pread(leaf_descriptor, prior.st_size, 0)
            snapshot_between = os.fstat(leaf_descriptor)
            second_snapshot = os.pread(
                recovery_descriptor, prior.st_size, 0,
            )
            snapshot_after = os.fstat(recovery_descriptor)
            stable_fields = lambda value: (
                value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns,
            )
            expected_snapshot = (
                prior.st_dev, prior.st_ino, prior.st_mode, 2,
                prior.st_size, snapshot_before.st_mtime_ns,
                snapshot_before.st_ctime_ns,
            )
            if (
                len(first_snapshot) != prior.st_size
                or len(second_snapshot) != prior.st_size
                or first_snapshot != second_snapshot
                or stable_fields(snapshot_before) != expected_snapshot
                or stable_fields(snapshot_between) != expected_snapshot
                or stable_fields(snapshot_after) != expected_snapshot
            ):
                if len(first_snapshot) == prior.st_size:
                    os.ftruncate(recovery_descriptor, len(first_snapshot))
                    offset = 0
                    while offset < len(first_snapshot):
                        written = os.pwrite(
                            recovery_descriptor, first_snapshot[offset:], offset,
                        )
                        if written <= 0:
                            break
                        offset += written
                    os.fchmod(recovery_descriptor, stat.S_IMODE(prior.st_mode))
                    os.fsync(recovery_descriptor)
                raise AssertionError(
                    f"P materialization prior snapshot changed: {relative}"
                )
            prior_payload = first_snapshot

        publication_attempted = True
        os.replace(temporary, leaf, src_dir_fd=current_fd, dst_dir_fd=current_fd)
        publication_completed = True
        published = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
        published_identity = (
            published.st_dev, published.st_ino, published.st_mode,
            published.st_nlink, published.st_size,
        )
        _materialization_observer("after-entry", target)
        published = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
        held_published = os.fstat(output)
        if (
            not stat.S_ISREG(published.st_mode)
            or not stat.S_ISREG(held_published.st_mode)
            or published.st_nlink != 1 or held_published.st_nlink != 1
            or stat.S_IMODE(published.st_mode) != expected_mode
            or stat.S_IMODE(held_published.st_mode) != expected_mode
            or published.st_size != len(payload)
            or held_published.st_size != len(payload)
            or (published.st_dev, published.st_ino)
            != (held_published.st_dev, held_published.st_ino)
            or os.pread(output, len(payload), 0) != payload
        ):
            raise AssertionError(f"P materialization publication changed: {relative}")
        temporary = None
        if recovery is not None:
            os.unlink(recovery, dir_fd=current_fd)
            recovery = None
        final_visible = os.stat(
            leaf, dir_fd=current_fd, follow_symlinks=False,
        )
        final_held = os.fstat(output)
        if (
            not stat.S_ISREG(final_visible.st_mode)
            or not stat.S_ISREG(final_held.st_mode)
            or (final_visible.st_dev, final_visible.st_ino)
            != (final_held.st_dev, final_held.st_ino)
        ):
            raise AssertionError(
                f"P materialization final identity changed: {relative}"
            )
        final_payload = os.pread(output, len(payload), 0)
        if (
            final_visible.st_nlink != 1 or final_held.st_nlink != 1
            or stat.S_IMODE(final_visible.st_mode) != expected_mode
            or stat.S_IMODE(final_held.st_mode) != expected_mode
            or final_visible.st_size != len(payload)
            or final_held.st_size != len(payload)
            or final_payload != payload
        ):
            os.ftruncate(output, len(payload))
            offset = 0
            while offset < len(payload):
                written = os.pwrite(output, payload[offset:], offset)
                if written <= 0:
                    raise AssertionError(
                        f"P materialization final repair made no write progress: {relative}"
                    )
                offset += written
            os.fchmod(output, expected_mode)
            os.fsync(output)
            repaired_visible = os.stat(
                leaf, dir_fd=current_fd, follow_symlinks=False,
            )
            repaired_held = os.fstat(output)
            if (
                (repaired_visible.st_dev, repaired_visible.st_ino,
                 repaired_visible.st_mode, repaired_visible.st_nlink,
                 repaired_visible.st_size)
                != (repaired_held.st_dev, repaired_held.st_ino,
                    repaired_held.st_mode, repaired_held.st_nlink,
                    repaired_held.st_size)
                or stat.S_IMODE(repaired_held.st_mode) != expected_mode
                or repaired_held.st_size != len(payload)
                or os.pread(output, len(payload), 0) != payload
            ):
                raise AssertionError(
                    f"P materialization final repair failed: {relative}"
                )
            raise AssertionError(
                f"P materialization changed during final verification: {relative}"
            )
    except BaseException as error:
        rollback_error = None
        if publication_attempted:
            try:
                try:
                    current_published = os.stat(
                        leaf, dir_fd=descriptors[-1][1], follow_symlinks=False,
                    )
                except FileNotFoundError:
                    current_published = None
                if publication_completed:
                    current_identity = None if current_published is None else (
                        current_published.st_dev, current_published.st_ino,
                        current_published.st_mode, current_published.st_nlink,
                        current_published.st_size,
                    )
                    if published_identity is not None and current_identity != published_identity:
                        raise AssertionError(
                            f"P materialization published object changed: {relative}"
                        )
                if prior is None:
                    if current_published is not None:
                        held_output = os.fstat(output)
                        current_identity = (
                            current_published.st_dev, current_published.st_ino,
                            current_published.st_mode, current_published.st_nlink,
                            current_published.st_size,
                        )
                        if current_identity != published_identity and (
                            current_published.st_dev, current_published.st_ino
                        ) != (held_output.st_dev, held_output.st_ino):
                            raise AssertionError(
                                f"P materialization cannot identify failed publication: {relative}"
                            )
                        os.unlink(leaf, dir_fd=descriptors[-1][1])
                elif current_published is not None and (
                    current_published.st_dev, current_published.st_ino
                ) == (prior.st_dev, prior.st_ino):
                    pass
                else:
                    if recovery is None:
                        raise AssertionError(
                            f"P materialization rollback authority is missing: {relative}"
                        )
                    if recovery_descriptor is None or prior_payload is None:
                        raise AssertionError(
                            f"P materialization rollback descriptor is missing: {relative}"
                        )
                    visible_recovery = os.stat(
                        recovery, dir_fd=descriptors[-1][1],
                        follow_symlinks=False,
                    )
                    held_recovery = os.fstat(recovery_descriptor)
                    if (
                        not stat.S_ISREG(visible_recovery.st_mode)
                        or not stat.S_ISREG(held_recovery.st_mode)
                        or (visible_recovery.st_dev, visible_recovery.st_ino)
                        != (prior.st_dev, prior.st_ino)
                        or (held_recovery.st_dev, held_recovery.st_ino)
                        != (prior.st_dev, prior.st_ino)
                        or visible_recovery.st_nlink != 1
                        or held_recovery.st_nlink != 1
                    ):
                        raise AssertionError(
                            f"P materialization rollback descriptor changed: {relative}"
                        )
                    if (
                        held_recovery.st_mode != prior.st_mode
                        or held_recovery.st_size != len(prior_payload)
                        or os.pread(
                            recovery_descriptor, held_recovery.st_size, 0,
                        ) != prior_payload
                    ):
                        os.ftruncate(recovery_descriptor, len(prior_payload))
                        offset = 0
                        while offset < len(prior_payload):
                            written = os.pwrite(
                                recovery_descriptor, prior_payload[offset:], offset,
                            )
                            if written <= 0:
                                raise AssertionError(
                                    f"P materialization rollback made no write progress: {relative}"
                                )
                            offset += written
                        os.fchmod(recovery_descriptor, stat.S_IMODE(prior.st_mode))
                        os.fsync(recovery_descriptor)
                    restored_authority = os.fstat(recovery_descriptor)
                    if (
                        restored_authority.st_mode != prior.st_mode
                        or restored_authority.st_size != len(prior_payload)
                        or os.pread(
                            recovery_descriptor, len(prior_payload), 0,
                        ) != prior_payload
                    ):
                        raise AssertionError(
                            f"P materialization rollback content cannot be restored: {relative}"
                        )
                    os.replace(
                        recovery, leaf,
                        src_dir_fd=descriptors[-1][1],
                        dst_dir_fd=descriptors[-1][1],
                    )
                    recovery = None
                    postrollback = os.stat(
                        leaf, dir_fd=descriptors[-1][1],
                        follow_symlinks=False,
                    )
                    postrollback_fd = os.fstat(recovery_descriptor)
                    postrollback_payload = os.pread(
                        recovery_descriptor, len(prior_payload), 0,
                    )
                    if (
                        (postrollback.st_dev, postrollback.st_ino)
                        != (postrollback_fd.st_dev, postrollback_fd.st_ino)
                    ):
                        raise AssertionError(
                            f"P materialization post-rollback identity changed: {relative}"
                        )
                    if (
                        postrollback_fd.st_mode != prior.st_mode
                        or postrollback_fd.st_size != len(prior_payload)
                        or postrollback_payload != prior_payload
                    ):
                        os.ftruncate(recovery_descriptor, len(prior_payload))
                        offset = 0
                        while offset < len(prior_payload):
                            written = os.pwrite(
                                recovery_descriptor, prior_payload[offset:], offset,
                            )
                            if written <= 0:
                                raise AssertionError(
                                    f"P materialization post-rollback made no write progress: {relative}"
                                )
                            offset += written
                        os.fchmod(recovery_descriptor, stat.S_IMODE(prior.st_mode))
                        os.fsync(recovery_descriptor)
                    postrollback = os.stat(
                        leaf, dir_fd=descriptors[-1][1],
                        follow_symlinks=False,
                    )
                    postrollback_fd = os.fstat(recovery_descriptor)
                    if (
                        (postrollback.st_dev, postrollback.st_ino,
                         postrollback.st_mode, postrollback.st_nlink)
                        != (prior.st_dev, prior.st_ino, prior.st_mode, 1)
                        or (postrollback_fd.st_dev, postrollback_fd.st_ino,
                            postrollback_fd.st_mode, postrollback_fd.st_nlink)
                        != (prior.st_dev, prior.st_ino, prior.st_mode, 1)
                        or os.pread(
                            recovery_descriptor, len(prior_payload), 0,
                        ) != prior_payload
                    ):
                        raise AssertionError(
                            f"P materialization post-rollback content changed: {relative}"
                        )
                if prior is not None:
                    restored = os.stat(
                        leaf, dir_fd=descriptors[-1][1], follow_symlinks=False,
                    )
                    restored_fd = os.fstat(leaf_descriptor)
                    if (
                        (restored.st_dev, restored.st_ino, restored.st_mode,
                         restored.st_nlink)
                        != (prior.st_dev, prior.st_ino, prior.st_mode, 1)
                        or (restored_fd.st_dev, restored_fd.st_ino,
                            restored_fd.st_mode, restored_fd.st_nlink)
                        != (prior.st_dev, prior.st_ino, prior.st_mode, 1)
                    ):
                        raise AssertionError(
                            f"P materialization rollback did not restore prior object: {relative}"
                        )
            except BaseException as rollback_failure:
                rollback_error = rollback_failure
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=descriptors[-1][1])
            except OSError:
                pass
        if recovery is not None:
            try:
                os.unlink(recovery, dir_fd=descriptors[-1][1])
            except OSError:
                pass
        if rollback_error is not None:
            raise AssertionError(f"P materialization rollback failed: {relative}") from rollback_error
        if isinstance(error, AssertionError):
            raise
        if isinstance(error, OSError):
            raise AssertionError(f"P materialization failed: {relative}") from error
        raise
    finally:
        if recovery_descriptor is not None:
            os.close(recovery_descriptor)
        if output is not None:
            os.close(output)
        if leaf_descriptor is not None:
            os.close(leaf_descriptor)
        for _path, descriptor, _held in reversed(descriptors):
            os.close(descriptor)


def _tree_modes(repository: Path, revision="HEAD") -> dict[str, str]:
    return {
        path: record[0]
        for path, record in _tree_records(repository, revision).items()
    }


def _tree_records(
    repository: Path, revision="HEAD",
) -> dict[str, tuple[str, str, str, bytes]]:
    if revision == "HEAD":
        revision = _head(repository)
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise AssertionError(f"P tree revision is not an exact commit: {revision!r}")
    return _verified_commit_records(repository, revision)


def _record_digest(records) -> str:
    digest = hashlib.sha256()
    for path in sorted(records):
        mode, kind, object_id, payload = records[path]
        digest.update(path.encode("utf-8") + b"\0")
        digest.update(mode.encode("ascii") + b"\0")
        digest.update(kind.encode("ascii") + b"\0")
        if path == P_LEDGER_PATH:
            digest.update(b"<runner-owned-ledger-object>\0")
            digest.update(b"<runner-owned-ledger-content>\0")
        elif path == P_SELF_RECORD_PATH:
            pattern = (
                rb'P_(?:TREE|PHASE)_RECORD_DIGEST = \(\n'
                rb'    "[0-9a-f]{64}"\n\)'
            )
            if len(re.findall(pattern, payload)) != 2:
                raise AssertionError("P workflow self-record tokens are ambiguous")
            normalized = re.sub(
                pattern,
                b'P_<SELF>_RECORD_DIGEST = (\n    "<self-record-digest>"\n)',
                payload,
            )
            digest.update(b"<self-record-object>\0")
            digest.update(hashlib.sha256(normalized).hexdigest().encode("ascii") + b"\0")
        else:
            digest.update(object_id.encode("ascii") + b"\0")
            digest.update(hashlib.sha256(payload).hexdigest().encode("ascii") + b"\0")
        if mode == "120000":
            target = payload.decode("utf-8")
            if not target or target.startswith("/") or "\0" in target:
                raise AssertionError(f"unsafe P symlink target: {path}")
            digest.update(target.encode("utf-8") + b"\0")
    return digest.hexdigest()


def _assert_committed_phase_records(
    phase_records, committed_records, expected_paths=P_PHASE_PRELEDGER_PATHS,
) -> None:
    committed_phase = {
        path: committed_records[path] for path in expected_paths
    }
    if phase_records != committed_phase:
        raise AssertionError(
            "the committed P phase blobs differ from the held index snapshot"
        )


def _staged_blob_record(repository: Path, relative: str):
    result = _git_run(
        repository, ["ls-files", "--stage", "-z", "--", relative],
    )
    if result.returncode or not result.stdout.endswith(b"\0"):
        raise AssertionError(f"cannot resolve staged blob: {relative}")
    fields = result.stdout[:-1].split(b"\0")
    if len(fields) != 1:
        raise AssertionError(f"ambiguous staged blob: {relative}")
    metadata, raw_path = fields[0].split(b"\t", 1)
    mode, object_id, stage = metadata.decode("ascii").split(" ")
    if raw_path.decode("utf-8") != relative or stage != "0" or mode != "100644":
        raise AssertionError(f"unsafe staged blob: {relative}")
    payload = _git_run(repository, ["cat-file", "blob", object_id])
    if payload.returncode:
        raise AssertionError(payload.stderr.decode("utf-8", "replace"))
    return mode, "blob", object_id, payload.stdout


def _assert_committed_ledger_record(staged_record, committed_records) -> None:
    if committed_records.get(P_LEDGER_PATH) != staged_record:
        raise AssertionError("committed P ledger differs from the staged attestation")


def _head(repository: Path) -> str:
    result = _git_run(repository, ["rev-parse", "HEAD"], text=True)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def _assert_clean_and_ledger(
    repository: Path, ledger: bytes, captured_head: str,
) -> None:
    index_path = repository / ".git/index"
    try:
        index_before = index_path.read_bytes()
        index_metadata = index_path.lstat()
    except OSError as error:
        raise AssertionError("P clean-state index authority is unavailable") from error
    _clean_state_observer(
        "before-clean-comparison", repository, captured_head=captured_head,
    )
    try:
        staged = _git_run(
            repository, ["diff-index", "--quiet", captured_head, "--"],
        )
        worktree = _git_run(repository, ["diff-files", "--quiet", "--"])
        untracked = _git_run(
            repository, ["ls-files", "--others", "--exclude-standard", "-z"],
        )
    finally:
        _clean_state_observer(
            "after-clean-comparison", repository, captured_head=captured_head,
        )
    if _head(repository) != captured_head:
        raise AssertionError("P final checkout HEAD changed during clean comparison")
    try:
        index_after = index_path.read_bytes()
        after_metadata = index_path.lstat()
    except OSError as error:
        raise AssertionError("P clean-state index authority changed") from error
    if (
        index_before != index_after
        or (index_metadata.st_dev, index_metadata.st_ino, index_metadata.st_mode)
        != (after_metadata.st_dev, after_metadata.st_ino, after_metadata.st_mode)
    ):
        raise AssertionError("P clean-state index authority changed")
    if (
        staged.returncode != 0 or worktree.returncode != 0
        or untracked.returncode != 0 or untracked.stdout
    ):
        raise AssertionError("P clean checkout has changed or untracked content")
    if (repository / P_LEDGER_PATH).read_bytes() != ledger:
        raise AssertionError("P runner command changed approved ledger")


def _ran_summary(stderr: str) -> tuple[int, int]:
    matches = re.findall(r"^Ran (\d+) tests?", stderr, re.M)
    if len(matches) != 1 or int(matches[0]) <= 0:
        raise AssertionError("P runner did not execute one positive unittest set")
    skipped = re.findall(r"\bskipped=(\d+)\b", stderr)
    if len(skipped) > 1:
        raise AssertionError("P runner emitted ambiguous skipped-test summary")
    return int(matches[0]), int(skipped[0]) if skipped else 0


def _assert_run_summary(stderr: str, count: int, reasons) -> None:
    actual_count, actual_skips = _ran_summary(stderr)
    if (actual_count, actual_skips) != (count, len(reasons)):
        raise AssertionError(
            f"unexpected P test summary: {(actual_count, actual_skips)!r}"
        )
    for reason in reasons:
        if stderr.count(f"skipped '{reason}'") != 1:
            raise AssertionError(f"missing/duplicate P skip reason: {reason}")


def _full_selection_stdout(manifest: dict, approval_path) -> str:
    lines = ["mode: full-suite", "changed paths:"]
    lines.extend(f"  - {path}" for path in sorted(manifest["scripts"]))
    lines.extend((
        "tests:", "  - unittest discovery: test_cases/test_*.py",
        "reasons:", "  - explicit --all",
        "root-entrypoint-workflow: NOT COVERED (requires Linux EUID 0 private namespace)",
    ))
    if approval_path is not None:
        lines.append(f"approved hashes updated atomically: {approval_path}")
    return "\n".join(lines) + "\n"


class PublicPublicationWorkflowTests(unittest.TestCase):
    def test_p_staged_overlay_uses_held_index_blobs_and_rejects_rebinding(self):
        from test_cases import test_public_project_fixture_workflow as fixture

        module = sys.modules[__name__]
        active_fixture = None
        active_fixture_fds = ()
        active_fixture_identities = ()
        active_fixture_offset = None
        if _dependency_reentry_protocol_present():
            active_archive_fd = int(os.environ[P_CAPSULE_FD_ENV])
            active_archive_metadata = os.fstat(active_archive_fd)
            active_archive_fields = os.environ[P_CAPSULE_IDENTITY_ENV].split(":")
            borrowed_archive = _DependencyArchiveAuthority(
                active_archive_fd, active_archive_metadata,
                active_archive_fields[3] if len(active_archive_fields) == 4 else "",
            )
            active_helper = _active_dependency_authority
            with mock.patch.object(
                module, "_active_dependency_authority", wraps=active_helper,
            ) as authenticated_active_helper:
                active_fixture = authenticated_active_helper(borrowed_archive)
            authenticated_active_helper.assert_called_once_with(borrowed_archive)
            self.assertIsNotNone(active_fixture)
            active_fixture_fds = (
                int(os.environ[P_CAPSULE_FD_ENV]),
                int(os.environ[P_REENTRANT_ENV_KEYS["snapshot_fd"]]),
                *map(int, os.environ[
                    P_REENTRANT_ENV_KEYS["python_home_fds"]
                ].split(",")),
            )
            self.assertEqual(active_fixture_fds, active_fixture.source_fds)
            active_fixture_identities = tuple(
                (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                for descriptor in active_fixture_fds
            )
            active_fixture_offset = os.lseek(
                active_archive_fd, 0, os.SEEK_CUR,
            )
        active_fixture_flags = (
            tuple(
                (
                    fcntl.fcntl(descriptor, fcntl.F_GETFL),
                    fcntl.fcntl(descriptor, fcntl.F_GETFD),
                )
                for descriptor in active_fixture_fds
            )
            if active_fixture is not None else ()
        )

        orchestrator_source = inspect.getsource(
            self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone
        )
        self.assertNotRegex(
            orchestrator_source, r"\bos\.(?:environ|getenv)\b",
            "P phase selection must not have an environment-controlled bypass",
        )
        parsed_orchestrator = ast.parse(textwrap.dedent(orchestrator_source))
        raw_python_children = [
            node for node in ast.walk(parsed_orchestrator)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr == "run"
            and "sys.executable" in ast.unparse(node)
        ]
        self.assertEqual(
            [], raw_python_children,
            "every formal Python child must use the sanitized fresh-cache runner",
        )
        self.assertEqual(
            2, orchestrator_source.count("_assert_committed_phase_records("),
            "the formal P commit must use the same exact-record validator",
        )
        self.assertIn(
            "_assert_committed_phase_records(phase_records, records)",
            orchestrator_source,
        )
        self.assertEqual(
            2, orchestrator_source.count("_assert_committed_ledger_record("),
            "the formal P ledger commit must use the exact staged-record validator",
        )
        self.assertIn(
            "_assert_committed_ledger_record(staged_ledger_record, final_records)",
            orchestrator_source,
        )
        self.assertIn(
            "_assert_canonical_history_metadata(ROOT)", orchestrator_source,
            "the formal P proof must reject repository-local shallow/graft metadata",
        )
        self.assertIn("_tree_records(ROOT, head)", orchestrator_source)
        self.assertIn(
            'self.assertEqual(head, _head(ROOT), "P HEAD changed during formal proof")',
            orchestrator_source,
        )
        from test_cases import test_public_publication_contract as direct
        with self.subTest(verified_reader_routing="workflow"):
            self.assertIn(
                "_verified_commit_records", inspect.getsource(_tree_records),
            )
        with self.subTest(verified_reader_routing="direct"):
            self.assertIn(
                "_verified_commit_records", inspect.getsource(direct._tree_blob_records),
            )

        sentinel_records = {
            "sentinel/reviewed.sh": (
                "100755", "blob", "1" * 40, b"#!/bin/sh\nexit 7\n",
            ),
            "sentinel/target": (
                "120000", "blob", "2" * 40, b"reviewed.sh",
            ),
        }
        with tempfile.TemporaryDirectory(prefix="http-p-consumer-binding-") as directory:
            binding_repository = Path(directory)
            workflow_verifier = mock.Mock(return_value=sentinel_records)
            with self.subTest(consumer_binding="workflow"), mock.patch.object(
                sys.modules[__name__], "_verified_commit_records",
                workflow_verifier, create=True,
            ), mock.patch.object(
                sys.modules[__name__], "_git_run",
                side_effect=AssertionError("secondary Git authority read is forbidden"),
            ):
                self.assertEqual(
                    sentinel_records,
                    _tree_records(binding_repository, "3" * 40),
                )
            with self.subTest(consumer_binding_workflow_call=True):
                workflow_verifier.assert_called_once_with(
                    binding_repository, "3" * 40,
                )
            direct_verifier = mock.Mock(return_value=sentinel_records)
            with self.subTest(consumer_binding="direct"), mock.patch.object(direct, "ROOT", binding_repository), mock.patch.object(
                direct, "_verified_commit_records", direct_verifier, create=True,
            ), mock.patch.object(
                direct, "_canonical_git",
                side_effect=AssertionError("secondary Git authority read is forbidden"),
            ):
                self.assertEqual(
                    {
                        path: (mode, payload)
                        for path, (mode, _kind, _oid, payload)
                        in sentinel_records.items()
                    },
                    direct._tree_blob_records(),
                )
            with self.subTest(consumer_binding_direct_call=True):
                direct_verifier.assert_called_once_with(binding_repository, "HEAD")

        with tempfile.TemporaryDirectory(prefix="http-p-index-overlay-") as directory:
            repository = Path(directory) / "repository"
            destination = Path(directory) / "candidate"
            repository.mkdir()
            _git_run(repository, ["init", "--quiet"], check=True)
            relative = "nested/reviewed.txt"
            source = repository / relative
            source.parent.mkdir(parents=True)
            source.write_bytes(b"base\n")
            _git_run(repository, ["add", "--", relative], check=True)
            _git_run(
                repository,
                ["-c", "user.name=P Test", "-c", "user.email=p@test.invalid",
                 "commit", "--quiet", "-m", "base"], check=True,
            )
            source.write_bytes(b"reviewed-index\n")
            _git_run(repository, ["add", "--", relative], check=True)
            source.write_bytes(b"hostile-worktree\n")
            with mock.patch.object(sys.modules[__name__], "ROOT", repository):
                records = _materialize_staged_overlay(destination, (relative,))
            self.assertEqual(b"reviewed-index\n", (destination / relative).read_bytes())
            self.assertEqual(b"reviewed-index\n", records[relative][3])

            alternate_repository = Path(directory) / "alternate-repository"
            alternate_repository.mkdir()
            _git_run(alternate_repository, ["init", "--quiet"], check=True)
            alternate_file = alternate_repository / relative
            alternate_file.parent.mkdir(parents=True)
            alternate_file.write_bytes(b"attacker-repository\n")
            _git_run(alternate_repository, ["add", "--", relative], check=True)
            _git_run(
                alternate_repository,
                ["-c", "user.name=Attacker", "-c", "user.email=a@test.invalid",
                 "commit", "--quiet", "-m", "alternate"], check=True,
            )
            canonical_head = _head(repository)
            canonical_payload = _tree_records(repository)[relative][3]
            hostile_environment = {
                "GIT_DIR": str(alternate_repository / ".git"),
                "GIT_WORK_TREE": str(alternate_repository),
                "GIT_INDEX_FILE": str(alternate_repository / ".git/index"),
                "GIT_OBJECT_DIRECTORY": str(alternate_repository / ".git/objects"),
                "GIT_EXEC_PATH": str(alternate_repository),
                "GIT_TEMPLATE_DIR": str(alternate_repository),
                "GIT_SHALLOW_FILE": str(alternate_repository / ".git/shallow"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.repositoryformatversion",
                "GIT_CONFIG_VALUE_0": "0",
                "PYTHONHOME": str(alternate_repository),
                "PYTHONPATH": str(alternate_repository),
                "PYTHONPYCACHEPREFIX": str(alternate_repository / "pycache"),
                "HOME": str(alternate_repository),
            }
            with mock.patch.dict(os.environ, hostile_environment, clear=False):
                before_environment = dict(os.environ)
                with mock.patch.object(sys.modules[__name__], "ROOT", repository), mock.patch.object(
                    direct, "ROOT", repository,
                ):
                    self.assertEqual(canonical_head, _head(repository))
                    self.assertEqual(canonical_payload, _tree_records(repository)[relative][3])
                    self.assertEqual(canonical_head, direct._git("rev-parse", "HEAD").stdout.strip())
                    self.assertEqual(canonical_payload, direct._tree_blob_records()[relative][1])
                    python_state = Path(directory) / "python-state"
                    python_state.mkdir()
                    child_environment = _canonical_python_environment(python_state)
                    self.assertEqual(SYSTEM_EXECUTABLE_PATH, child_environment["PATH"])
                    self.assertEqual(str(python_state / "home"), child_environment["HOME"])
                    self.assertEqual(
                        str(python_state / "pycache"),
                        child_environment["PYTHONPYCACHEPREFIX"],
                    )
                    self.assertNotIn("PYTHONHOME", child_environment)
                    self.assertNotIn("PYTHONPATH", child_environment)
                    for loader_key in (
                        "LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_FRAMEWORK_PATH",
                        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
                    ):
                        self.assertNotIn(loader_key, child_environment)
                    for key in hostile_environment:
                        if key.startswith("GIT_"):
                            self.assertNotIn(key, child_environment)
                self.assertEqual(before_environment, dict(os.environ))

            hostile_site = Path(directory) / "hostile-site"
            hostile_site.mkdir()
            site_marker = Path(directory) / "sitecustomize-ran"
            (hostile_site / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(site_marker)!r}).write_text('hostile', encoding='utf-8')\n",
                encoding="utf-8",
            )
            probe_root = Path(directory) / "python-probe"
            probe_root.mkdir()
            probe_module = probe_root / "probe_module.py"
            probe_module.write_text("value = 'stale'\n", encoding="utf-8")
            stale_cache = Path(directory) / "stale-pycache"
            stale_environment = os.environ.copy()
            stale_environment["PYTHONPYCACHEPREFIX"] = str(stale_cache)
            seeded = subprocess.run(
                [sys.executable, "-c", "import probe_module"], cwd=probe_root,
                env=stale_environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(0, seeded.returncode, seeded.stderr)
            source_stat = probe_module.stat()
            probe_module.write_text("value = 'fresh'\n", encoding="utf-8")
            os.utime(
                probe_module,
                ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns),
            )
            hostile_python = {
                "PYTHONHOME": str(hostile_site),
                "PYTHONPATH": str(hostile_site),
                "PYTHONPYCACHEPREFIX": str(stale_cache),
                "LD_LIBRARY_PATH": str(hostile_site),
                "LD_PRELOAD": str(hostile_site / "hostile.so"),
                "LD_AUDIT": str(hostile_site / "hostile-audit.so"),
                "DYLD_FRAMEWORK_PATH": str(hostile_site),
                "DYLD_INSERT_LIBRARIES": str(hostile_site / "hostile.dylib"),
                "DYLD_LIBRARY_PATH": str(hostile_site),
            }
            hostile_python_state = Path(directory) / "hostile-python-state"
            hostile_python_state.mkdir()
            sanitized_hostile_python = _canonical_python_environment(
                hostile_python_state, ambient=hostile_python,
            )
            for key in hostile_python:
                if key.startswith(("LD_", "DYLD_")):
                    self.assertNotIn(key, sanitized_hostile_python)
            probe_archive_state = Path(directory) / "hostile-python-archive-state"
            probe_archive_fd = None
            probe_archive_build = _build_dependency_archive
            probe_archive_adopt = _adopt_dependency_archive_from_environment
            with mock.patch.object(
                sys.modules[__name__], "_build_dependency_archive",
                wraps=probe_archive_build,
            ) as build_probe_archive, mock.patch.object(
                sys.modules[__name__],
                "_adopt_dependency_archive_from_environment",
                wraps=probe_archive_adopt,
            ) as adopt_probe_archive:
                with _formal_dependency_archive_scope(probe_archive_state) as probe_archive:
                    probe_archive_fd = probe_archive.fd
                    probe_archive_before = _verify_dependency_archive(probe_archive)
                    with mock.patch.dict(os.environ, hostile_python, clear=False):
                        hostile_before = dict(os.environ)
                        probe = _python_run(
                            probe_root,
                            ["-B", "-c", "import probe_module; print(probe_module.value)"],
                            timeout=30, dependency_archive=probe_archive,
                        )
                        self.assertEqual(hostile_before, dict(os.environ))
                    self.assertEqual(
                        probe_archive_before,
                        _verify_dependency_archive(probe_archive),
                    )
            if active_fixture is None:
                build_probe_archive.assert_called_once_with(probe_archive_state)
                adopt_probe_archive.assert_not_called()
            else:
                build_probe_archive.assert_not_called()
                adopt_probe_archive.assert_called_once_with()
                self.assertNotIn(probe_archive_fd, active_fixture_fds)
            self.assertFalse(os.path.lexists(probe_archive_state))
            self.assertIsNotNone(probe_archive_fd)
            with self.assertRaises(OSError):
                os.fstat(probe_archive_fd)
            if active_fixture is not None:
                self.assertEqual(
                    active_fixture_identities,
                    tuple(
                        (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                        for descriptor in active_fixture_fds
                    ),
                )
                self.assertEqual(
                    active_fixture_flags,
                    tuple(
                        (
                            fcntl.fcntl(descriptor, fcntl.F_GETFL),
                            fcntl.fcntl(descriptor, fcntl.F_GETFD),
                        )
                        for descriptor in active_fixture_fds
                    ),
                )
                self.assertEqual(
                    active_fixture_offset,
                    os.lseek(active_fixture.archive_fd, 0, os.SEEK_CUR),
                )
                _verify_dependency_archive(_DependencyArchiveAuthority(
                    active_fixture.archive_fd,
                    os.fstat(active_fixture.archive_fd),
                    P_CAPSULE_ARCHIVE_SHA256,
                ))
                _verify_dependency_snapshot(active_fixture.snapshot)
                _verify_private_python_home(active_fixture.python_home)
            self.assertEqual(0, probe.returncode, probe.stdout + probe.stderr)
            self.assertEqual("fresh\n", probe.stdout)
            self.assertFalse(site_marker.exists())

            hostile_home = Path(directory) / "hostile-home"
            hostile_home.mkdir()
            hostile_hooks = Path(directory) / "hostile-hooks"
            hostile_hooks.mkdir()
            git_hook_marker = Path(directory) / "ambient-git-hook-ran"
            git_filter_marker = Path(directory) / "ambient-git-filter-ran"
            hook = hostile_hooks / "pre-commit"
            hook.write_text(
                "#!/bin/sh\n" + f"printf hostile > {str(git_hook_marker)!r}\n",
                encoding="utf-8",
            )
            hook.chmod(0o755)
            filter_command = f"sh -c 'printf filter > {git_filter_marker!s}; cat'"
            (hostile_home / ".gitconfig").write_text(
                "[init]\n\ttemplateDir = " + str(hostile_hooks.parent) + "\n"
                "[core]\n\thooksPath = " + str(hostile_hooks) + "\n"
                "[filter \"hostile\"]\n\tclean = " + filter_command + "\n"
                "\trequired = true\n",
                encoding="utf-8",
            )
            formal_repository = Path(directory) / "formal-git-config"
            formal_repository.mkdir()
            with mock.patch.dict(os.environ, {"HOME": str(hostile_home)}, clear=False):
                self.assertEqual(
                    0, _git_run(formal_repository, ["init", "--quiet"]).returncode,
                )
                local_config_environment = _canonical_git_environment()
                for key in ("GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"):
                    local_config_environment.pop(key, None)
                for key, value in (
                    ("core.hooksPath", str(hostile_hooks)),
                    ("filter.hostile.clean", filter_command),
                    ("filter.hostile.required", "true"),
                ):
                    configured = subprocess.run(
                        [GIT_BINARY, "--no-replace-objects", "-C", str(formal_repository),
                         "config", "--local", key, value],
                        env=local_config_environment, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, check=False,
                    )
                    self.assertEqual(0, configured.returncode, configured.stderr)
                (formal_repository / ".gitattributes").write_text(
                    "*.txt filter=hostile\n", encoding="utf-8",
                )
                (formal_repository / "reviewed.txt").write_text(
                    "reviewed\n", encoding="utf-8",
                )
                self.assertEqual(
                    0,
                    _git_run(
                        formal_repository,
                        ["add", "--", ".gitattributes", "reviewed.txt"],
                    ).returncode,
                )
                committed = _git_run(
                    formal_repository,
                    ["-c", "user.name=Formal", "-c", "user.email=formal@example.invalid",
                     "commit", "--quiet", "-m", "formal"],
                )
                self.assertEqual(0, committed.returncode, committed.stderr)
            with self.subTest(ambient_git_config=True):
                self.assertFalse(git_hook_marker.exists())
                self.assertFalse(git_filter_marker.exists())

            fake_bin = Path(directory) / "fake-bin"
            fake_bin.mkdir()
            fake_git = fake_bin / "git"
            fake_git.write_text("#!/bin/sh\nexit 91\n", encoding="utf-8")
            fake_git.chmod(0o755)
            path_environment = {
                "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            }
            path_destination = Path(directory) / "path-authority-candidate"
            with self.subTest(git_path_authority=True):
                with mock.patch.dict(os.environ, path_environment, clear=False), mock.patch.object(
                    sys.modules[__name__], "ROOT", repository,
                ):
                    before_environment = dict(os.environ)
                    records = _materialize_staged_overlay(path_destination, (relative,))
                    self.assertEqual(before_environment, dict(os.environ))
                self.assertEqual(b"reviewed-index\n", records[relative][3])
                self.assertEqual(
                    b"reviewed-index\n", (path_destination / relative).read_bytes(),
                )

            replacement = repository / "replacement.txt"
            replacement.write_bytes(b"replacement-object\n")
            replacement_oid = _git_run(
                repository, ["hash-object", "-w", "--", str(replacement)], text=True,
            ).stdout.strip()
            source_oid = _git_run(
                repository, ["rev-parse", f"HEAD:{relative}"], text=True,
            ).stdout.strip()
            _git_run(
                repository,
                ["-c", "user.name=Attacker", "-c", "user.email=a@test.invalid",
                 "tag", "-a", "replacement-tag", replacement_oid,
                 "-m", "annotated replacement"], check=True,
            )
            tag_oid = _git_run(
                repository, ["rev-parse", "refs/tags/replacement-tag^{tag}"], text=True,
            ).stdout.strip()
            _git_run(
                repository, ["update-ref", f"refs/replace/{source_oid}", tag_oid],
                check=True,
            )
            raw_environment = _canonical_git_environment()
            raw_environment.pop("GIT_NO_REPLACE_OBJECTS", None)
            raw = subprocess.run(
                [GIT_BINARY, "-C", str(repository), "cat-file", "blob", source_oid],
                env=raw_environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False,
            )
            self.assertTrue(raw.returncode != 0 or raw.stdout != canonical_payload)
            self.assertEqual(canonical_payload, _tree_records(repository)[relative][3])
            with mock.patch.object(direct, "ROOT", repository):
                self.assertEqual(canonical_payload, direct._tree_blob_records()[relative][1])

            alternate_index = Path(directory) / "alternate-index"
            alternate_env = _canonical_git_environment({
                "GIT_INDEX_FILE": str(alternate_index),
            })
            subprocess.run(
                [GIT_BINARY, "--no-replace-objects", "-C", str(repository),
                 "read-tree", "HEAD"], env=alternate_env, check=True,
            )
            source.write_bytes(b"rebound-index\n")
            subprocess.run(
                [GIT_BINARY, "--no-replace-objects", "-C", str(repository),
                 "add", "--", relative], env=alternate_env, check=True,
            )
            real_blob = fixture._index_blob
            fired = []

            def mutate_after_blob(candidate_repository, object_id):
                payload = real_blob(candidate_repository, object_id)
                if not fired:
                    os.replace(alternate_index, repository / ".git/index")
                    fired.append(True)
                return payload

            rejected = Path(directory) / "rejected"
            with mock.patch.object(sys.modules[__name__], "ROOT", repository), mock.patch.object(
                fixture, "_index_blob", side_effect=mutate_after_blob,
            ), self.assertRaisesRegex(AssertionError, "index changed"):
                _materialize_staged_overlay(rejected, (relative,))
            self.assertEqual([True], fired)
            self.assertFalse(rejected.exists())

            object_repository = Path(directory) / "object-integrity-repository"
            object_repository.mkdir()
            _git_run(object_repository, ["init", "--quiet"], check=True)
            nested_file = object_repository / "nested/reviewed.txt"
            nested_file.parent.mkdir(parents=True)
            nested_file.write_bytes(b"canonical nested payload\n")
            _git_run(object_repository, ["add", "--", "nested/reviewed.txt"], check=True)
            _git_run(
                object_repository,
                ["-c", "user.name=Object Integrity",
                 "-c", "user.email=object-integrity@example.invalid",
                 "commit", "--quiet", "-m", "object integrity base"], check=True,
            )
            object_head = _head(object_repository)
            nested_blob_oid = _git_run(
                object_repository, ["rev-parse", "HEAD:nested/reviewed.txt"],
                text=True, check=True,
            ).stdout.strip()
            nested_blob = _git_run(
                object_repository, ["cat-file", "blob", nested_blob_oid], check=True,
            ).stdout
            corrupted_blob = b"h" + nested_blob[1:]
            self.assertEqual(len(nested_blob), len(corrupted_blob))
            _write_loose_object_fixture(
                object_repository, nested_blob_oid, "blob", corrupted_blob,
            )
            self.assertEqual(
                corrupted_blob,
                _git_run(
                    object_repository, ["cat-file", "blob", nested_blob_oid],
                    check=True,
                ).stdout,
                "Git itself must demonstrate the false-filename loose blob bypass",
            )
            for reader in ("workflow", "direct"):
                with self.subTest(corrupt_loose_blob=True, reader=reader), self.assertRaisesRegex(
                    AssertionError, "object id",
                ):
                    if reader == "workflow":
                        _tree_records(object_repository, object_head)
                    else:
                        with mock.patch.object(direct, "ROOT", object_repository):
                            direct._tree_blob_records()

            tree_repository = Path(directory) / "tree-integrity-repository"
            tree_repository.mkdir()
            _git_run(tree_repository, ["init", "--quiet"], check=True)
            tree_nested_file = tree_repository / "nested/reviewed.txt"
            tree_nested_file.parent.mkdir(parents=True)
            tree_nested_file.write_bytes(b"canonical nested payload\n")
            _git_run(tree_repository, ["add", "--", "nested/reviewed.txt"], check=True)
            _git_run(
                tree_repository,
                ["-c", "user.name=Tree Integrity",
                 "-c", "user.email=tree-integrity@example.invalid",
                 "commit", "--quiet", "-m", "tree integrity base"], check=True,
            )
            tree_head = _head(tree_repository)
            nested_tree_oid = _git_run(
                tree_repository, ["rev-parse", "HEAD:nested"], text=True, check=True,
            ).stdout.strip()
            nested_tree = _git_run(
                tree_repository, ["cat-file", "tree", nested_tree_oid], check=True,
            ).stdout
            canonical_blob_oid = _git_run(
                tree_repository, ["rev-parse", "HEAD:nested/reviewed.txt"],
                text=True, check=True,
            ).stdout.strip()
            alternate_blob = b"alternate nested payload\n"
            alternate_blob_oid = hashlib.sha1(
                b"blob " + str(len(alternate_blob)).encode("ascii") + b"\0"
                + alternate_blob
            ).hexdigest()
            _write_loose_object_fixture(
                tree_repository, alternate_blob_oid, "blob", alternate_blob,
            )
            tree_entry = b"100644 reviewed.txt\0" + bytes.fromhex(canonical_blob_oid)
            self.assertEqual(1, nested_tree.count(tree_entry))
            corrupted_tree = nested_tree.replace(
                tree_entry,
                b"100644 reviewed.txt\0" + bytes.fromhex(alternate_blob_oid),
                1,
            )
            self.assertEqual(len(nested_tree), len(corrupted_tree))
            _write_loose_object_fixture(
                tree_repository, nested_tree_oid, "tree", corrupted_tree,
            )
            with self.subTest(corrupt_nested_tree_git_bypass=True):
                self.assertEqual(
                    alternate_blob_oid,
                    _git_run(
                        tree_repository,
                        ["rev-parse", "HEAD:nested/reviewed.txt"],
                        text=True, check=True,
                    ).stdout.strip(),
                    "Git itself must expose the false-filename nested-tree bypass",
                )
            for reader in ("workflow", "direct"):
                with self.subTest(corrupt_nested_tree=True, reader=reader), self.assertRaisesRegex(
                    AssertionError, "object id",
                ):
                    if reader == "workflow":
                        _tree_records(tree_repository, tree_head)
                    else:
                        with mock.patch.object(direct, "ROOT", tree_repository):
                            direct._tree_blob_records()

            parser_repository = Path(directory) / "strict-parser-repository"
            parser_repository.mkdir()
            _git_run(parser_repository, ["init", "--quiet"], check=True)

            def store_literal_object(kind, object_id, payload):
                canonical = (
                    kind.encode("ascii") + b" " + str(len(payload)).encode("ascii")
                    + b"\0" + payload
                )
                self.assertEqual(
                    object_id, hashlib.sha1(canonical).hexdigest(),
                    f"independent {kind} fixture OID drift",
                )
                _write_loose_object_fixture(
                    parser_repository, object_id, kind, payload,
                )

            blob_literals = {
                "f52515160081df27fbe0548e58ee74c8c73d91a7": b"regular\n",
                "039e4d0069c5c26909f86c505b9de66182e6d1f3": b"#!/bin/sh\nexit 0\n",
                "fe9e3b0b83597ce07de3bef40ee7cd0fcb08f143": b"nested/regular.txt",
                "bf1a1fdefa3c7f4b0180a75a951e9574662a8bc8": b"top\n",
            }
            for object_id, payload in blob_literals.items():
                store_literal_object("blob", object_id, payload)
            subtree_payload = bytes.fromhex(
                "3130303735352065786563757461626c652e736800"
                "039e4d0069c5c26909f86c505b9de66182e6d1f3"
                "31303036343420726567756c61722e74787400"
                "f52515160081df27fbe0548e58ee74c8c73d91a7"
            )
            root_tree_payload = bytes.fromhex(
                "31303036343420666f6f2e62617200bf1a1fdefa3c7f4b0180a75a951e9574662a8bc8"
                "343030303020666f6f007079da8acc8c93d6ee749d1891051301c49c94a8"
                "313230303030206c696e6b00fe9e3b0b83597ce07de3bef40ee7cd0fcb08f143"
                "3430303030206e6573746564007079da8acc8c93d6ee749d1891051301c49c94a8"
                "31303036343420746f702e74787400bf1a1fdefa3c7f4b0180a75a951e9574662a8bc8"
            )
            positive_commit_payload = bytes.fromhex(
                "7472656520656437326163323263356437333935316432343062333935343135346361343437626662613364610a"
                "617574686f7220502046697874757265203c70406578616d706c652e696e76616c69643e2030202b303030300a"
                "636f6d6d697474657220502046697874757265203c70406578616d706c652e696e76616c69643e2030202b303030300a0a"
                "666978747572650a"
            )
            store_literal_object(
                "tree", "7079da8acc8c93d6ee749d1891051301c49c94a8", subtree_payload,
            )
            store_literal_object(
                "tree", "ed72ac22c5d73951d240b3954154ca447bfba3da", root_tree_payload,
            )
            store_literal_object(
                "commit", "fbd95dea0fd3b6799c1ff6a5a3ec7fe54f5982b1",
                positive_commit_payload,
            )
            expected_positive_records = {
                "foo.bar": (
                    "100644", "blob", "bf1a1fdefa3c7f4b0180a75a951e9574662a8bc8",
                    b"top\n",
                ),
                "foo/executable.sh": (
                    "100755", "blob", "039e4d0069c5c26909f86c505b9de66182e6d1f3",
                    b"#!/bin/sh\nexit 0\n",
                ),
                "foo/regular.txt": (
                    "100644", "blob", "f52515160081df27fbe0548e58ee74c8c73d91a7",
                    b"regular\n",
                ),
                "link": (
                    "120000", "blob", "fe9e3b0b83597ce07de3bef40ee7cd0fcb08f143",
                    b"nested/regular.txt",
                ),
                "nested/executable.sh": (
                    "100755", "blob", "039e4d0069c5c26909f86c505b9de66182e6d1f3",
                    b"#!/bin/sh\nexit 0\n",
                ),
                "nested/regular.txt": (
                    "100644", "blob", "f52515160081df27fbe0548e58ee74c8c73d91a7",
                    b"regular\n",
                ),
                "top.txt": (
                    "100644", "blob", "bf1a1fdefa3c7f4b0180a75a951e9574662a8bc8",
                    b"top\n",
                ),
            }

            bad_commit_literals = {
                "missing-tree": (
                    "b30f4b5f7de61a4bb97959d6d13e66c480eb96ec",
                    bytes.fromhex(
                        "617574686f722050203c7040783e2030202b303030300a"
                        "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
                    ),
                ),
                "duplicate-tree": (
                    "b72f4271f6237932495a96f869130d155496c9aa",
                    bytes.fromhex(
                        "7472656520643566666631613730386535616535313733343137353338313433666335333433373833636164310a"
                        "7472656520643566666631613730386535616535313733343137353338313433666335333433373833636164310a"
                        "617574686f722050203c7040783e2030202b303030300a"
                        "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
                    ),
                ),
                "invalid-tree": (
                    "03d6452d0d773f4a6fbbd63e86bbec166d128d6a",
                    b"tree " + b"z" * 40
                    + b"\nauthor P <p@x> 0 +0000\n"
                    + b"committer P <p@x> 0 +0000\n\nx\n",
                ),
                "uppercase-tree": (
                    "1d24931c6d6318c607693c13e3dfe64e63e11fb7",
                    bytes.fromhex(
                        "7472656520454437324143323243354437333935314432343042333935343135344341343437424642413344410a"
                        "617574686f722050203c7040783e2030202b303030300a"
                        "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
                    ),
                ),
                "short-tree-oid": (
                    "fb50adeaa73798bd02cb62476fe64af3bec240ef",
                    bytes.fromhex(
                        "74726565206564373261633232633564373339353164323430623339353431353463613434376266626133640a"
                        "617574686f722050203c7040783e2030202b303030300a"
                        "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
                    ),
                ),
                "long-tree-oid": (
                    "ac6d49acca886ccfab07170c65a79fbb3ebb823e",
                    bytes.fromhex(
                        "747265652065643732616332326335643733393531643234306233393534313534636134343762666261336461610a"
                        "617574686f722050203c7040783e2030202b303030300a"
                        "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
                    ),
                ),
                "tree-not-first-header": (
                    "c731fb900dcddfebbff9750db6c3c4313324f30e",
                    bytes.fromhex(
                        "617574686f722050203c7040783e2030202b303030300a"
                        "7472656520656437326163323263356437333935316432343062333935343135346361343437626662613364610a"
                        "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
                    ),
                ),
                "tree-header-trailing-space": (
                    "4aee7121ef639bb3aaf20188f7a44e1597f612e7",
                    bytes.fromhex(
                        "747265652065643732616332326335643733393531643234306233393534313534636134343762666261336461200a"
                        "617574686f722050203c7040783e2030202b303030300a"
                        "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
                    ),
                ),
                "tree-header-trailing-tab": (
                    "807f146321b639fb2b8c0cfaed0e1faa5392577e",
                    bytes.fromhex(
                        "747265652065643732616332326335643733393531643234306233393534313534636134343762666261336461090a"
                        "617574686f722050203c7040783e2030202b303030300a"
                        "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
                    ),
                ),
            }
            for _name, (object_id, payload) in bad_commit_literals.items():
                store_literal_object("commit", object_id, payload)

            bad_tree_literals = {
                "missing-nul": ("835e2391e1201959adb98d6ce7a337a8f0bdc816", "d271a8a11cc3a51193532236e2445ecf808e940d", "3130303634342078f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "truncated-oid": ("c603986bc6d4889c1a6d475845c2672244e3d5fc", "7a142859a42d49c038745c0652ca18ab26bbaad1", "313030363434207800f52515160081df27fbe0548e58ee74c8c73d91"),
                "illegal-mode": ("80b7e7327d30ff4434f02f729fba65f858f9306f", "18f67ce11239db0b554146ee3fac4d1e7e7599a6", "313630303030207800f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "blob-as-tree": ("a27d5fc9d624892c6e665e8ca24cb9ec82ba611b", "00ece05ac1968a00f01cebfe1c4a94b34d57f6d7", "3430303030207800f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "tree-as-blob": ("2ccc68e23dc0edbf8eac485d19bc8c571d7b1ea2", "b6c6fb4a84260c870eec70c8f7f1d68247acd01a", "3130303634342078007079da8acc8c93d6ee749d1891051301c49c94a8"),
                "duplicate": ("1152afdc3b4af06f7ba05acdc69663ed3a7719e3", "beea7a7e9f1dbbf01c0ad638ceede64d84756d12", "313030363434207800f52515160081df27fbe0548e58ee74c8c73d91a7313030363434207800f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "noncanonical-order": ("11ecc3ff08540cc31731343bd6c852b78ee62875", "139bd0b3aec7a534a53a396c0bb273524e2f7e25", "313030363434207a00f52515160081df27fbe0548e58ee74c8c73d91a7313030363434206100f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "empty-name": ("fce03a9979ec18caa51b1e772ae8ba5d64d46ef5", "ea473b5d4c2d3d99fc6bb8a5b561b59f45862af2", "3130303634342000f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "dot-name": ("a13263a9319552423de92fdf8bb72c905c35c31a", "14997f0ba7b7732fc2cca499bf0376058b996bf7", "313030363434202e00f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "dotdot-name": ("ea8e8b46da9efef595b6adc2847c5a99e41261aa", "6ec7166df0c9527b10a6cfd7d1ef0da5b5abea3d", "313030363434202e2e00f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "slash-name": ("ea729bbe9a5e4a361492fb2405ad5ac327761cde", "cf64c69e0d5e9a446afb9ddc57d13768f43665c9", "31303036343420612f6200f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "nonutf8-name": ("968c539d8ea21bf498e81b7015a6c622149c1c58", "bf80e8e7d03e4af5f60b83b08e795e9f160e708a", "31303036343420ff00f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "reversed-git-order": ("df9c53c35b6ff0e3a39d84b9f9cfd709191be2f3", "e99ec718c7b2183082e4dcd92949bd91d0899668", "343030303020666f6f007079da8acc8c93d6ee749d1891051301c49c94a831303036343420666f6f2e62617200bf1a1fdefa3c7f4b0180a75a951e9574662a8bc8"),
                "cross-mode-duplicate": ("b06aec02f444b02dd2034978cfbb689a215b1f74", "f5e178c366d2480d31e1415d6bf851246da4237c", "31303036343420666f6f00bf1a1fdefa3c7f4b0180a75a951e9574662a8bc8343030303020666f6f007079da8acc8c93d6ee749d1891051301c49c94a8"),
                "noncanonical-100664": ("4f5a55262ef25ed16d1a4f1c0da688fb0dea9ff9", "46cb07c3498e8b3cc31541a1d3a237c5e052ac11", "313030363634207800f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "noncanonical-0100644": ("ffa9497f4c3823d5b6f349d907c616f910b39404", "c4cc6ee7f96f840044a9eea7dd81317f29647d53", "30313030363434207800f52515160081df27fbe0548e58ee74c8c73d91a7"),
                "noncanonical-040000": ("86be107ccffe439f4459d1d12a8577bb8904d2bf", "8702bd05d51fbdb155723deb8987f351208d120b", "3034303030302078007079da8acc8c93d6ee749d1891051301c49c94a8"),
                "gitlink-to-valid-commit": ("4d8afb9b5b8cbe37e3f407b40fba57ae640147ab", "4b8af3d1b7e23a47eb6fae5c70cdc6e83f7a6b6a", "313630303030207800fbd95dea0fd3b6799c1ff6a5a3ec7fe54f5982b1"),
            }
            commit_template = (
                "tree {tree}\nauthor P Fixture <p@example.invalid> 0 +0000\n"
                "committer P Fixture <p@example.invalid> 0 +0000\n\nfixture\n"
            )
            for _name, (tree_oid, commit_oid, raw_hex) in bad_tree_literals.items():
                tree_payload = bytes.fromhex(raw_hex)
                commit_payload = commit_template.format(tree=tree_oid).encode("ascii")
                store_literal_object("tree", tree_oid, tree_payload)
                store_literal_object("commit", commit_oid, commit_payload)

            verifier_modules = (
                ("workflow", sys.modules[__name__]), ("direct", direct),
            )
            for reader, module in verifier_modules:
                with self.subTest(strict_graph_positive=reader):
                    verifier = getattr(module, "_verified_commit_records", None)
                    self.assertTrue(callable(verifier), "missing verified object-graph reader")
                    self.assertEqual(
                        expected_positive_records,
                        verifier(parser_repository, "fbd95dea0fd3b6799c1ff6a5a3ec7fe54f5982b1"),
                    )
                for attack, (object_id, _payload) in bad_commit_literals.items():
                    with self.subTest(strict_commit=attack, reader=reader):
                        verifier = getattr(module, "_verified_commit_records", None)
                        self.assertTrue(callable(verifier), "missing verified object-graph reader")
                        with self.assertRaises(AssertionError):
                            verifier(parser_repository, object_id)
                for attack, (_tree_oid, commit_oid, _raw_hex) in bad_tree_literals.items():
                    with self.subTest(strict_tree=attack, reader=reader):
                        verifier = getattr(module, "_verified_commit_records", None)
                        self.assertTrue(callable(verifier), "missing verified object-graph reader")
                        with self.assertRaises(AssertionError):
                            verifier(parser_repository, commit_oid)

            positive_oid = "fbd95dea0fd3b6799c1ff6a5a3ec7fe54f5982b1"
            with self.subTest(real_tree_records_positive=True):
                self.assertEqual(
                    expected_positive_records,
                    _tree_records(parser_repository, positive_oid),
                )
            _git_run(
                parser_repository, ["update-ref", "HEAD", positive_oid], check=True,
            )
            with self.subTest(real_direct_tree_records_positive=True), mock.patch.object(
                direct, "ROOT", parser_repository,
            ):
                self.assertEqual(
                    {
                        path: (mode, payload)
                        for path, (mode, _kind, _oid, payload)
                        in expected_positive_records.items()
                    },
                    direct._tree_blob_records(),
                )
            malformed_commits = {
                object_id for object_id, _payload in bad_commit_literals.values()
            } | {
                commit_oid for _tree_oid, commit_oid, _raw_hex
                in bad_tree_literals.values()
            }
            def assert_fail_closed_reader(callback):
                try:
                    callback()
                except AssertionError:
                    return
                except Exception as error:
                    self.fail(
                        f"reader leaked {type(error).__name__} instead of failing closed: {error}"
                    )
                self.fail("malformed object graph was accepted")

            for malformed_oid in sorted(malformed_commits):
                with self.subTest(real_tree_records_malformed=malformed_oid):
                    assert_fail_closed_reader(
                        lambda: _tree_records(parser_repository, malformed_oid)
                    )
                (parser_repository / ".git/HEAD").write_text(
                    malformed_oid + "\n", encoding="ascii",
                )
                with self.subTest(
                    real_direct_tree_records_malformed=malformed_oid,
                ), mock.patch.object(direct, "ROOT", parser_repository):
                    assert_fail_closed_reader(direct._tree_blob_records)

            for spoof_name, spoof_kind, spoof_oid, spoof_payload in (
                ("tree-declared-blob", "blob",
                 "ed72ac22c5d73951d240b3954154ca447bfba3da", root_tree_payload),
                ("blob-declared-tree", "tree",
                 "f52515160081df27fbe0548e58ee74c8c73d91a7", b"regular\n"),
                ("commit-declared-blob", "blob", positive_oid,
                 positive_commit_payload),
            ):
                with self.subTest(raw_storage_header_spoof=spoof_name):
                    spoof_repository = Path(directory) / f"header-spoof-{spoof_name}"
                    spoof_repository.mkdir()
                    _git_run(spoof_repository, ["init", "--quiet"], check=True)
                    for object_id, payload in blob_literals.items():
                        _write_loose_object_fixture(
                            spoof_repository, object_id, "blob", payload,
                        )
                    _write_loose_object_fixture(
                        spoof_repository,
                        "7079da8acc8c93d6ee749d1891051301c49c94a8",
                        "tree", subtree_payload,
                    )
                    _write_loose_object_fixture(
                        spoof_repository,
                        "ed72ac22c5d73951d240b3954154ca447bfba3da",
                        "tree", root_tree_payload,
                    )
                    _write_loose_object_fixture(
                        spoof_repository, positive_oid, "commit",
                        positive_commit_payload,
                    )
                    _write_loose_object_fixture(
                        spoof_repository, spoof_oid, spoof_kind, spoof_payload,
                    )
                    exposed_kind = _git_run(
                        spoof_repository, ["cat-file", "-t", spoof_oid],
                        text=True, check=True,
                    ).stdout.strip()
                    self.assertEqual(spoof_kind, exposed_kind)
                    if spoof_name == "commit-declared-blob":
                        with self.assertRaises(AssertionError):
                            _raw_commit_parents(spoof_repository, positive_oid)
                        with self.assertRaises(AssertionError):
                            _tree_records(spoof_repository, positive_oid)
                        (spoof_repository / ".git/HEAD").write_text(
                            positive_oid + "\n", encoding="ascii",
                        )
                        with mock.patch.object(
                            direct, "ROOT", spoof_repository,
                        ), self.assertRaises(AssertionError):
                            direct._tree_blob_records()
                        continue
                    with self.assertRaises(AssertionError):
                        _tree_records(spoof_repository, positive_oid)
                    _git_run(
                        spoof_repository, ["update-ref", "HEAD", positive_oid],
                        check=True,
                    )
                    with mock.patch.object(
                        direct, "ROOT", spoof_repository,
                    ), self.assertRaises(AssertionError):
                        direct._tree_blob_records()

            primitive_oid = "587be6b4c3f93f93c489c0111bba5596147a26cb"
            primitive_payload = b"x\n"
            primitive_stdout = (
                primitive_oid.encode("ascii") + b" blob 2\n" + primitive_payload + b"\n"
            )
            primitive_tree_oid = "ab69b4abf3bb84d4e268bd42d84e4a9a5e242bd3"
            primitive_tree_payload = bytes.fromhex(
                "313030363434207800587be6b4c3f93f93c489c0111bba5596147a26cb"
            )
            primitive_commit_oid = "8a6a1b7b253fc72da72c8b74d5c32423b813beaa"
            primitive_commit_payload = bytes.fromhex(
                "7472656520616236396234616266336262383464346532363862643432643834653461396135653234326264330a"
                "617574686f722050203c7040783e2030202b303030300a"
                "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
            )
            primitive_cases = (
                (primitive_oid, "blob", primitive_payload),
                (primitive_tree_oid, "tree", primitive_tree_payload),
                (primitive_commit_oid, "commit", primitive_commit_payload),
            )
            parseable_tree_blob_oid = "dd92b71e97daba66f2f0b11ecc49958211f1faf8"
            parseable_commit_blob_oid = "e02a8243aabe3a0c1f684e931f68614ab6a25233"
            parseable_blob_tree_commit_oid = (
                "86b520dbdf4d17e7a2cacc81db493a146b5025b2"
            )
            parseable_blob_tree_commit_payload = bytes.fromhex(
                "7472656520646439326237316539376461626136366632663062313165636334393935383231316631666166380a"
                "617574686f7220502046697874757265203c70406578616d706c652e696e76616c69643e2030202b303030300a"
                "636f6d6d697474657220502046697874757265203c70406578616d706c652e696e76616c69643e2030202b303030300a0a"
                "666978747572650a"
            )
            cross_kind_cases = (
                (parseable_tree_blob_oid, "blob", "tree", primitive_tree_payload),
                (parseable_commit_blob_oid, "blob", "commit", primitive_commit_payload),
                (primitive_tree_oid, "tree", "blob", primitive_tree_payload),
                (primitive_commit_oid, "commit", "blob", primitive_commit_payload),
            )
            self.assertEqual(1, RAW_OBJECT_TIMEOUT_SECONDS)
            malformed_responses = (
                b"", b"missing\n", primitive_stdout + b"trailing",
                primitive_stdout + primitive_stdout,
                primitive_oid.encode("ascii") + b" blob 02\n" + primitive_payload + b"\n",
                primitive_oid.encode("ascii") + b" blob 1\n" + primitive_payload + b"\n",
                primitive_oid.encode("ascii") + b" blob 3\n" + primitive_payload + b"\n",
                primitive_oid.encode("ascii") + b" tree 2\n" + primitive_payload + b"\n",
                primitive_oid.encode("ascii") + b" blob 2\ny\n\n",
                b"0" * 40 + b" blob 2\n" + primitive_payload + b"\n",
            )
            for reader, module in verifier_modules:
                primitive = getattr(module, "_read_raw_git_object", None)
                with self.subTest(raw_object_primitive=reader):
                    self.assertTrue(callable(primitive), "missing raw-object primitive")
                    loader_markers = {
                        key: Path(directory) / f"{reader}-{key}-executed"
                        for key in (
                            "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH",
                            "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
                            "DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
                        )
                    }
                    hostile_loader_environment = {
                        key: str(path) for key, path in loader_markers.items()
                    }
                    run = mock.Mock(return_value=subprocess.CompletedProcess(
                        (), 0, primitive_stdout, b"",
                    ))
                    with mock.patch.object(subprocess, "run", run), mock.patch.object(
                        subprocess, "Popen",
                        side_effect=AssertionError("persistent/split object read forbidden"),
                    ), mock.patch.dict(
                        os.environ, hostile_loader_environment, clear=False,
                    ):
                        self.assertEqual(
                            (primitive_oid, "blob", 2, primitive_payload),
                            primitive(parser_repository, primitive_oid, "blob"),
                        )
                    self.assertEqual(1, run.call_count)
                    command = tuple(os.fspath(value) for value in run.call_args.args[0])
                    self.assertEqual(
                        (GIT_BINARY, "--no-replace-objects", "-c",
                         f"core.hooksPath={os.devnull}", "-C",
                         str(parser_repository), "cat-file", "--batch"),
                        command,
                    )
                    self.assertEqual(
                        (primitive_oid + "\n").encode("ascii"),
                        run.call_args.kwargs.get("input"),
                    )
                    self.assertEqual(
                        {"env", "input", "stdout", "stderr", "text", "check",
                         "timeout"},
                        set(run.call_args.kwargs),
                    )
                    self.assertEqual(subprocess.PIPE, run.call_args.kwargs["stdout"])
                    self.assertEqual(subprocess.PIPE, run.call_args.kwargs["stderr"])
                    self.assertFalse(run.call_args.kwargs["text"])
                    self.assertFalse(run.call_args.kwargs["check"])
                    self.assertEqual(1, run.call_args.kwargs["timeout"])
                    primitive_environment = run.call_args.kwargs.get("env")
                    self.assertIsInstance(primitive_environment, dict)
                    self.assertEqual(
                        SYSTEM_EXECUTABLE_PATH, primitive_environment.get("PATH"),
                    )
                    self.assertFalse(any(
                        key.startswith(("LD_", "DYLD_"))
                        for key in primitive_environment
                    ))
                    self.assertTrue(all(
                        not marker.exists() for marker in loader_markers.values()
                    ))
                    self.assertEqual(
                        {
                            "GIT_CONFIG": os.devnull,
                            "GIT_CONFIG_GLOBAL": os.devnull,
                            "GIT_CONFIG_NOSYSTEM": "1",
                            "GIT_NO_REPLACE_OBJECTS": "1",
                        },
                        {
                            key: value for key, value in primitive_environment.items()
                            if key.startswith("GIT_")
                        },
                    )
                    hostile_bin = Path(directory) / f"hostile-git-{reader}"
                    hostile_bin.mkdir()
                    hostile_marker = hostile_bin / "executed"
                    fake_git = hostile_bin / "git"
                    fake_git.write_text(
                        "#!/bin/sh\ntouch " + str(hostile_marker) + "\nexit 99\n",
                        encoding="utf-8",
                    )
                    fake_git.chmod(0o755)
                    _write_loose_object_fixture(
                        parser_repository, primitive_oid, "blob", primitive_payload,
                    )
                    with mock.patch.dict(
                        os.environ,
                        {
                            "PATH": str(hostile_bin), "GIT_DIR": str(hostile_bin),
                            **hostile_loader_environment,
                        },
                        clear=False,
                    ):
                        self.assertEqual(
                            (primitive_oid, "blob", 2, primitive_payload),
                            primitive(parser_repository, primitive_oid, "blob"),
                        )
                    self.assertFalse(hostile_marker.exists())
                    self.assertTrue(all(
                        not marker.exists() for marker in loader_markers.values()
                    ))
                for case_oid, case_kind, case_payload in primitive_cases:
                    with self.subTest(
                        raw_object_expected_kind=case_kind, reader=reader,
                    ):
                        if callable(primitive):
                            case_stdout = (
                                case_oid.encode("ascii") + b" "
                                + case_kind.encode("ascii") + b" "
                                + str(len(case_payload)).encode("ascii") + b"\n"
                                + case_payload + b"\n"
                            )
                            run = mock.Mock(return_value=subprocess.CompletedProcess(
                                (), 0, case_stdout, b"",
                            ))
                            with mock.patch.object(subprocess, "run", run), mock.patch.object(
                                subprocess, "Popen",
                                side_effect=AssertionError("persistent object read forbidden"),
                            ):
                                self.assertEqual(
                                    (case_oid, case_kind, len(case_payload), case_payload),
                                    primitive(
                                        parser_repository, case_oid, case_kind,
                                    ),
                                )
                            self.assertEqual(1, run.call_count)
                            self.assertEqual(
                                (GIT_BINARY, "--no-replace-objects", "-c",
                                 f"core.hooksPath={os.devnull}", "-C",
                                 str(parser_repository), "cat-file", "--batch"),
                                tuple(os.fspath(value) for value in run.call_args.args[0]),
                            )
                            self.assertEqual(
                                (case_oid + "\n").encode("ascii"),
                                run.call_args.kwargs["input"],
                            )
                            self.assertEqual(
                                {"env", "input", "stdout", "stderr", "text",
                                 "check", "timeout"},
                                set(run.call_args.kwargs),
                            )
                            self.assertEqual(
                                subprocess.PIPE, run.call_args.kwargs["stdout"],
                            )
                            self.assertEqual(
                                subprocess.PIPE, run.call_args.kwargs["stderr"],
                            )
                            self.assertFalse(run.call_args.kwargs["text"])
                            self.assertFalse(run.call_args.kwargs["check"])
                            self.assertEqual(1, run.call_args.kwargs["timeout"])
                            case_environment = run.call_args.kwargs["env"]
                            self.assertEqual(SYSTEM_EXECUTABLE_PATH, case_environment["PATH"])
                            self.assertEqual(
                                {
                                    "GIT_CONFIG": os.devnull,
                                    "GIT_CONFIG_GLOBAL": os.devnull,
                                    "GIT_CONFIG_NOSYSTEM": "1",
                                    "GIT_NO_REPLACE_OBJECTS": "1",
                                },
                                {
                                    key: value for key, value in case_environment.items()
                                    if key.startswith("GIT_")
                                },
                            )
                            self.assertEqual(0, sum(
                                key.startswith(("LD_", "DYLD_"))
                                for key in case_environment
                            ))
                for actual_oid, actual_kind, expected_kind, payload in cross_kind_cases:
                    with self.subTest(
                        raw_object_actual_kind=actual_kind,
                        raw_object_expected_kind=expected_kind,
                        reader=reader,
                    ):
                        if callable(primitive):
                            response = (
                                actual_oid.encode("ascii") + b" "
                                + actual_kind.encode("ascii") + b" "
                                + str(len(payload)).encode("ascii") + b"\n"
                                + payload + b"\n"
                            )
                            with mock.patch.object(
                                subprocess, "run",
                                return_value=subprocess.CompletedProcess(
                                    (), 0, response, b"",
                                ),
                            ), self.assertRaises(AssertionError):
                                primitive(
                                    parser_repository, actual_oid, expected_kind,
                                )
                for suffix in ("A" * 40, primitive_oid[:39], primitive_oid + "0",
                               primitive_oid + "^{blob}", primitive_oid[:12]):
                    with self.subTest(raw_object_id_rejected=suffix, reader=reader):
                        if callable(primitive):
                            with self.assertRaises(AssertionError):
                                primitive(parser_repository, suffix, "blob")
                for malformed in malformed_responses:
                    with self.subTest(raw_object_response=malformed[:20], reader=reader):
                        if callable(primitive):
                            with mock.patch.object(
                                subprocess, "run", return_value=subprocess.CompletedProcess(
                                    (), 0, malformed, b"",
                                ),
                            ), self.assertRaises(AssertionError):
                                primitive(parser_repository, primitive_oid, "blob")
                for case_oid, case_kind, case_payload in primitive_cases:
                    case_stdout = (
                        case_oid.encode("ascii") + b" " + case_kind.encode("ascii")
                        + b" " + str(len(case_payload)).encode("ascii") + b"\n"
                        + case_payload + b"\n"
                    )
                    for returncode in (1, -9):
                        for process_stderr in (b"", b"fatal\n"):
                            with self.subTest(
                                raw_object_process_status=returncode,
                                process_stderr=process_stderr,
                                expected_kind=case_kind, reader=reader,
                            ):
                                if callable(primitive):
                                    with mock.patch.object(
                                        subprocess, "run",
                                        return_value=subprocess.CompletedProcess(
                                            (), returncode, case_stdout, process_stderr,
                                        ),
                                    ), self.assertRaises(AssertionError):
                                        primitive(parser_repository, case_oid, case_kind)
                    for process_error in (
                        subprocess.TimeoutExpired((GIT_BINARY, "cat-file"), 1),
                        OSError("raw object process unavailable"),
                    ):
                        with self.subTest(
                            raw_object_process_exception=type(process_error).__name__,
                            expected_kind=case_kind, reader=reader,
                        ):
                            if callable(primitive):
                                with mock.patch.object(
                                    subprocess, "run", side_effect=process_error,
                                ), self.assertRaises(AssertionError):
                                    primitive(parser_repository, case_oid, case_kind)
                    with self.subTest(
                        raw_object_fifo_is_bounded=reader, expected_kind=case_kind,
                    ):
                        if callable(primitive) and hasattr(os, "mkfifo"):
                            positive_parser_head = (
                                "fbd95dea0fd3b6799c1ff6a5a3ec7fe54f5982b1"
                            )
                            _git_run(
                                parser_repository,
                                ["reset", "--hard", positive_parser_head],
                                check=True,
                            )
                            self.assertEqual(
                                positive_parser_head, _head(parser_repository),
                            )
                            clean_parser = _git_run(
                                parser_repository, ["status", "--porcelain=v1"],
                            )
                            self.assertEqual(0, clean_parser.returncode)
                            self.assertEqual(b"", clean_parser.stdout)
                            _write_loose_object_fixture(
                                parser_repository, case_oid, case_kind, case_payload,
                            )
                            loose_path = (
                                parser_repository / ".git/objects"
                                / case_oid[:2] / case_oid[2:]
                            )
                            loose_bytes = loose_path.read_bytes()
                            loose_mode = stat.S_IMODE(loose_path.stat().st_mode)
                            head_before = (parser_repository / ".git/HEAD").read_bytes()
                            status_before = _git_run(
                                parser_repository, ["status", "--porcelain=v1"],
                                check=True,
                            ).stdout
                            loose_path.unlink()
                            os.mkfifo(loose_path, 0o600)
                            started = time.monotonic()
                            try:
                                with self.assertRaises(AssertionError):
                                    primitive(parser_repository, case_oid, case_kind)
                                self.assertLess(time.monotonic() - started, 3)
                                self.assertTrue(
                                    stat.S_ISFIFO(loose_path.lstat().st_mode)
                                )
                                self.assertEqual(
                                    head_before,
                                    (parser_repository / ".git/HEAD").read_bytes(),
                                )
                                self.assertEqual(
                                    status_before,
                                    _git_run(
                                        parser_repository,
                                        ["status", "--porcelain=v1"], check=True,
                                    ).stdout,
                                )
                            finally:
                                if os.path.lexists(loose_path):
                                    loose_path.unlink()
                                loose_path.write_bytes(loose_bytes)
                                loose_path.chmod(loose_mode)
                with self.subTest(raw_object_stderr_on_success=reader):
                    if callable(primitive):
                        with mock.patch.object(
                            subprocess, "run", return_value=subprocess.CompletedProcess(
                                (), 0, primitive_stdout, b"warning\n",
                            ),
                        ), self.assertRaises(AssertionError):
                            primitive(parser_repository, primitive_oid, "blob")

            _write_loose_object_fixture(
                parser_repository, parseable_tree_blob_oid, "blob",
                primitive_tree_payload,
            )
            _write_loose_object_fixture(
                parser_repository, parseable_commit_blob_oid, "blob",
                primitive_commit_payload,
            )
            _write_loose_object_fixture(
                parser_repository, parseable_blob_tree_commit_oid, "commit",
                parseable_blob_tree_commit_payload,
            )
            for attack, head_oid in (
                ("hash-valid-blob-as-tree", parseable_blob_tree_commit_oid),
                ("hash-valid-blob-as-commit", parseable_commit_blob_oid),
            ):
                with self.subTest(actual_reader_cross_kind=attack):
                    with self.assertRaises(AssertionError):
                        _tree_records(parser_repository, head_oid)
                    (parser_repository / ".git/HEAD").write_text(
                        head_oid + "\n", encoding="ascii",
                    )
                    with mock.patch.object(
                        direct, "ROOT", parser_repository,
                    ), self.assertRaises(AssertionError):
                        direct._tree_blob_records()

            graph_blob_oid = "587be6b4c3f93f93c489c0111bba5596147a26cb"
            graph_tree_oid = "ab69b4abf3bb84d4e268bd42d84e4a9a5e242bd3"
            graph_commit_oid = "8a6a1b7b253fc72da72c8b74d5c32423b813beaa"
            graph_objects = {
                graph_commit_oid: ("commit", bytes.fromhex(
                    "7472656520616236396234616266336262383464346532363862643432643834653461396135653234326264330a"
                    "617574686f722050203c7040783e2030202b303030300a"
                    "636f6d6d69747465722050203c7040783e2030202b303030300a0a780a"
                )),
                graph_tree_oid: ("tree", bytes.fromhex(
                    "313030363434207800587be6b4c3f93f93c489c0111bba5596147a26cb"
                )),
                graph_blob_oid: ("blob", b"x\n"),
            }
            expected_graph = {
                "x": ("100644", "blob", graph_blob_oid, b"x\n"),
            }
            graph_repository = Path(directory) / "primitive-graph"
            graph_repository.mkdir()
            (graph_repository / ".git").mkdir()
            (graph_repository / ".git/HEAD").write_text(
                graph_commit_oid + "\n", encoding="ascii",
            )
            for reader, module in verifier_modules:
                calls = []

                def raw_object(repository, object_id, expected_kind):
                    self.assertEqual(graph_repository, repository)
                    kind, payload = graph_objects[object_id]
                    self.assertEqual(expected_kind, kind)
                    calls.append((object_id, expected_kind))
                    return object_id, kind, len(payload), payload

                with self.subTest(raw_object_consumer=reader), mock.patch.object(
                    module, "_read_raw_git_object", side_effect=raw_object, create=True,
                ), mock.patch.object(
                    subprocess, "run", side_effect=AssertionError("secondary Git read forbidden"),
                ), mock.patch.object(
                    subprocess, "Popen", side_effect=AssertionError("secondary Git read forbidden"),
                ):
                    if reader == "workflow":
                        self.assertEqual(
                            expected_graph,
                            _tree_records(graph_repository, graph_commit_oid),
                        )
                    else:
                        with mock.patch.object(direct, "ROOT", graph_repository):
                            self.assertEqual(
                                {"x": ("100644", b"x\n")},
                                direct._tree_blob_records(),
                            )
                with self.subTest(raw_object_exact_calls=reader):
                    self.assertEqual(
                        [(graph_commit_oid, "commit"), (graph_tree_oid, "tree"),
                         (graph_blob_oid, "blob")],
                        calls,
                    )

            authority_repository = Path(directory) / "authority-base-repository"
            authority_repository.mkdir()
            _git_run(authority_repository, ["init", "--quiet"], check=True)
            authority_file = authority_repository / "reviewed.txt"
            authority_file.write_bytes(b"reviewed authority\n")
            _git_run(authority_repository, ["add", "--", "reviewed.txt"], check=True)
            _git_run(
                authority_repository,
                ["-c", "user.name=Authority",
                 "-c", "user.email=authority@example.invalid",
                 "commit", "--quiet", "-m", "authority base"], check=True,
            )
            git_symlink_repository = Path(directory) / "git-symlink-repository"
            _git_run(
                authority_repository,
                ["clone", "--quiet", "--no-local", str(authority_repository),
                 str(git_symlink_repository)], check=True,
            )
            real_git_directory = Path(directory) / "detached-git-directory"
            (git_symlink_repository / ".git").rename(real_git_directory)
            (git_symlink_repository / ".git").symlink_to(
                real_git_directory, target_is_directory=True,
            )
            for reader in ("workflow", "direct"):
                with self.subTest(
                    git_directory_symlink=True, reader=reader,
                ), self.assertRaisesRegex(AssertionError, "Git directory"):
                    if reader == "workflow":
                        _assert_canonical_history_metadata(git_symlink_repository)
                    else:
                        with mock.patch.object(direct, "ROOT", git_symlink_repository):
                            direct._tree_blob_records()

            for metadata_name in ("alternates", "http-alternates"):
                for metadata_kind in ("regular", "symlink", "directory"):
                    with self.subTest(
                        object_alternate=metadata_name, kind=metadata_kind,
                    ):
                        alternate_repository = Path(directory) / (
                            f"alternate-{metadata_name}-{metadata_kind}"
                        )
                        _git_run(
                            authority_repository,
                            ["clone", "--quiet", "--no-local", str(authority_repository),
                             str(alternate_repository)], check=True,
                        )
                        alternate_path = (
                            alternate_repository / ".git/objects/info" / metadata_name
                        )
                        if metadata_kind == "regular":
                            alternate_path.write_text("/untrusted/objects\n", encoding="utf-8")
                        elif metadata_kind == "symlink":
                            alternate_path.symlink_to(authority_repository / ".git/objects")
                        else:
                            alternate_path.mkdir()
                        for reader in ("workflow", "direct"):
                            with self.subTest(reader=reader), self.assertRaisesRegex(
                                AssertionError, "alternate",
                            ):
                                if reader == "workflow":
                                    _assert_canonical_history_metadata(alternate_repository)
                                else:
                                    with mock.patch.object(
                                        direct, "ROOT", alternate_repository,
                                    ):
                                        direct._tree_blob_records()

            for metadata_kind in ("regular", "symlink", "directory"):
                commondir_repository = Path(directory) / f"commondir-{metadata_kind}"
                _git_run(
                    authority_repository,
                    ["clone", "--quiet", "--no-local", str(authority_repository),
                     str(commondir_repository)], check=True,
                )
                commondir = commondir_repository / ".git/commondir"
                if metadata_kind == "regular":
                    commondir.write_text("../untrusted-common\n", encoding="utf-8")
                elif metadata_kind == "symlink":
                    commondir.symlink_to(authority_repository / ".git")
                else:
                    commondir.mkdir()
                for reader in ("workflow", "direct"):
                    with self.subTest(
                        commondir=metadata_kind, reader=reader,
                    ), self.assertRaisesRegex(AssertionError, "commondir"):
                        if reader == "workflow":
                            _assert_canonical_history_metadata(commondir_repository)
                        else:
                            with mock.patch.object(direct, "ROOT", commondir_repository):
                                direct._tree_blob_records()

        for attack in (
            "root-symlink", "parent-symlink", "intermediate-parent-symlink",
            "leaf-symlink", "leaf-hardlink", "leaf-fifo", "leaf-directory",
        ):
            with self.subTest(destination_attack=attack), tempfile.TemporaryDirectory(
                prefix="http-p-destination-"
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                outside = base / "outside"
                repository.mkdir()
                outside.mkdir()
                if attack == "root-symlink":
                    destination.symlink_to(outside, target_is_directory=True)
                else:
                    destination.mkdir()
                _git_run(repository, ["init", "--quiet"], check=True)
                relative = (
                    "one/two/reviewed.txt"
                    if attack == "intermediate-parent-symlink"
                    else "nested/reviewed.txt"
                )
                source = repository / relative
                source.parent.mkdir(parents=True)
                source.write_bytes(b"base\n")
                _git_run(repository, ["add", "--", relative], check=True)
                _git_run(
                    repository,
                    ["-c", "user.name=P Test", "-c", "user.email=p@test.invalid",
                     "commit", "--quiet", "-m", "base"], check=True,
                )
                source.write_bytes(b"reviewed-index\n")
                _git_run(repository, ["add", "--", relative], check=True)
                outside_leaf = outside / (
                    "two/reviewed.txt"
                    if attack == "intermediate-parent-symlink"
                    else "reviewed.txt"
                )
                outside_leaf.parent.mkdir(parents=True, exist_ok=True)
                outside_leaf.write_bytes(b"outside-sentinel\n")
                if attack == "root-symlink":
                    pass
                elif attack == "parent-symlink":
                    (destination / "nested").symlink_to(outside, target_is_directory=True)
                elif attack == "intermediate-parent-symlink":
                    (destination / "one").symlink_to(outside, target_is_directory=True)
                else:
                    (destination / relative).parent.mkdir(parents=True)
                    leaf = destination / relative
                    if attack == "leaf-symlink":
                        leaf.symlink_to(outside_leaf)
                    elif attack == "leaf-hardlink":
                        os.link(outside_leaf, leaf)
                    elif attack == "leaf-fifo":
                        os.mkfifo(leaf)
                    else:
                        leaf.mkdir()
                outside_before = _directory_snapshot(outside)
                destination_before = _object_tree_snapshot(destination)
                dangerous_write = []
                real_write = Path.write_bytes
                real_open = os.open
                opened_descriptors = []

                def observed_write(path, payload):
                    if path == destination / relative:
                        mode = path.lstat().st_mode
                        if stat.S_ISFIFO(mode):
                            dangerous_write.append(True)
                            raise AssertionError("unsafe FIFO write attempted")
                    return real_write(path, payload)

                def observed_open(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    opened_descriptors.append(descriptor)
                    return descriptor

                failure = None
                try:
                    with mock.patch.object(sys.modules[__name__], "ROOT", repository), mock.patch.object(
                        Path, "write_bytes", observed_write,
                    ), mock.patch.object(
                        os, "open", side_effect=observed_open,
                    ):
                        _materialize_staged_overlay(destination, (relative,))
                except BaseException as error:
                    failure = error
                self.assertEqual(
                    destination_before, _object_tree_snapshot(destination),
                    "a rejected static destination must remain byte-for-byte unchanged",
                )
                self.assertEqual(outside_before, _directory_snapshot(outside))
                self.assertIsInstance(failure, AssertionError)
                self.assertEqual([], dangerous_write)
                self.assertEqual(b"outside-sentinel\n", outside_leaf.read_bytes())
                self.assertEqual([], [
                    path.relative_to(base).as_posix() for path in base.rglob("*")
                    if ".material" in path.name
                ])
                for descriptor in opened_descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

            if attack != "leaf-directory":
                continue
            base.mkdir(parents=True)
            with self.subTest(implicit_status_head_and_index_aba_is_rejected=True):
                status_repository = base / "implicit-status-aba"
                status_repository.mkdir()
                _git_run(status_repository, ["init", "--quiet"], check=True)
                tracked = status_repository / "tracked.txt"
                ledger = status_repository / P_LEDGER_PATH
                ledger.parent.mkdir(parents=True)
                tracked.write_bytes(b"captured-A\n")
                ledger.write_bytes(b"ledger-authority\n")
                _git_run(status_repository, ["add", "--", "tracked.txt", P_LEDGER_PATH], check=True)
                _git_run(
                    status_repository,
                    ["-c", "user.name=P", "-c", "user.email=p@example.invalid",
                     "commit", "--quiet", "-m", "captured A"], check=True,
                )
                captured_head = _head(status_repository)
                captured_index = (status_repository / ".git/index").read_bytes()
                tracked.write_bytes(b"transient-B\n")
                _git_run(status_repository, ["add", "--", "tracked.txt"], check=True)
                _git_run(
                    status_repository,
                    ["-c", "user.name=P", "-c", "user.email=p@example.invalid",
                     "commit", "--quiet", "-m", "transient B"], check=True,
                )
                transient_head = _head(status_repository)
                transient_index = (status_repository / ".git/index").read_bytes()
                transient_payload = tracked.read_bytes()
                _git_run(status_repository, ["reset", "--hard", captured_head], check=True)
                (status_repository / ".git/index").write_bytes(captured_index)
                self.assertEqual(captured_index, (status_repository / ".git/index").read_bytes())
                fired = []

                def swap_status_authority(event, repository, **authority):
                    self.assertEqual(status_repository, repository)
                    self.assertEqual(captured_head, authority["captured_head"])
                    if event == "before-clean-comparison":
                        _git_run(repository, ["update-ref", "HEAD", transient_head], check=True)
                        (repository / ".git/index").write_bytes(transient_index)
                        tracked.write_bytes(transient_payload)
                        fired.append("B")
                    elif event == "after-clean-comparison":
                        _git_run(repository, ["update-ref", "HEAD", captured_head], check=True)
                        (repository / ".git/index").write_bytes(captured_index)
                        tracked.write_bytes(b"captured-A\n")
                        fired.append("A")

                with mock.patch.object(
                    sys.modules[__name__], "_clean_state_observer",
                    side_effect=swap_status_authority,
                ), self.assertRaisesRegex(AssertionError, "clean|index|HEAD|authority"):
                    _assert_clean_and_ledger(
                        status_repository, ledger.read_bytes(), captured_head,
                    )
                self.assertEqual(["B", "A"], fired)
                self.assertEqual(captured_head, _head(status_repository))
                self.assertEqual(captured_index, (status_repository / ".git/index").read_bytes())
                self.assertEqual(b"captured-A\n", tracked.read_bytes())
                self.assertEqual(
                    "", _git_run(
                        status_repository, ["status", "--porcelain=v1"],
                        text=True, check=True,
                    ).stdout,
                )
                untracked = status_repository / "operator-untracked.txt"
                untracked.write_bytes(b"must remain untouched\n")
                with self.assertRaisesRegex(AssertionError, "changed|untracked|clean"):
                    _assert_clean_and_ledger(
                        status_repository, ledger.read_bytes(), captured_head,
                    )
                self.assertEqual(b"must remain untouched\n", untracked.read_bytes())
                self.assertTrue(os.path.lexists(untracked))
            shutil.rmtree(base)

        for attack in (
            "root-swap", "root-held-first-parent-swap", "parent-swap",
            "second-parent-swap", "post-open-rebind",
        ):
            with self.subTest(destination_race=attack), tempfile.TemporaryDirectory(
                prefix="http-p-destination-race-"
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                outside = base / "outside"
                repository.mkdir()
                destination.mkdir()
                outside.mkdir()
                _git_run(repository, ["init", "--quiet"], check=True)
                relative = (
                    "one/two/reviewed.txt"
                    if attack in {"root-held-first-parent-swap", "second-parent-swap"}
                    else "nested/reviewed.txt"
                )
                source = repository / relative
                source.parent.mkdir(parents=True)
                source.write_bytes(b"base\n")
                _git_run(repository, ["add", "--", relative], check=True)
                _git_run(
                    repository,
                    ["-c", "user.name=P Test", "-c", "user.email=p@test.invalid",
                     "commit", "--quiet", "-m", "base"], check=True,
                )
                source.write_bytes(b"reviewed-index\n")
                _git_run(repository, ["add", "--", relative], check=True)
                outside_leaf = outside / (
                    "two/reviewed.txt"
                    if attack == "root-held-first-parent-swap"
                    else "reviewed.txt"
                )
                outside_leaf.parent.mkdir(parents=True, exist_ok=True)
                outside_leaf.write_bytes(b"outside-sentinel\n")
                outside_before = _directory_snapshot(outside)
                parent = (destination / relative).parent
                parent.mkdir(parents=True)
                prior_leaf = parent / "reviewed.txt"
                prior_leaf.write_bytes(b"prior-reviewed-object\n")
                root_prior = destination / "root-prior.txt"
                root_prior.write_bytes(b"root-prior-object\n")
                fired = []
                real_open = os.open
                opened_descriptors = []
                post_hold_opens = []
                post_hold_attempts = []
                held_parent_descriptor = []
                expected_destination = []
                expected_held_root = []

                def observed_open(*args, **kwargs):
                    if fired:
                        post_hold_attempts.append((args, dict(kwargs)))
                    descriptor = real_open(*args, **kwargs)
                    opened_descriptors.append(descriptor)
                    if fired:
                        post_hold_opens.append((args, dict(kwargs), descriptor))
                    return descriptor

                def inject_rebind(event, path, **authority):
                    if path != destination / relative or fired:
                        return
                    if attack == "root-swap" and event == "root-held":
                        descriptor = authority.get("root_fd")
                        flags = authority.get("root_flags")
                        self.assertIsInstance(descriptor, int)
                        self.assertIsInstance(flags, int)
                        self.assertTrue(stat.S_ISDIR(os.fstat(descriptor).st_mode))
                        self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
                        for required in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
                            if hasattr(os, required):
                                self.assertTrue(flags & getattr(os, required), required)
                        held_parent_descriptor.append(descriptor)
                        destination.rename(base / "held-root")
                        destination.symlink_to(outside, target_is_directory=True)
                        fired.append(True)
                        expected_destination.append(_object_tree_snapshot(destination))
                        expected_held_root.append(
                            _object_tree_snapshot(base / "held-root")
                        )
                    elif attack == "root-held-first-parent-swap" and event == "root-held":
                        descriptor = authority.get("root_fd")
                        flags = authority.get("root_flags")
                        self.assertIsInstance(descriptor, int)
                        self.assertIsInstance(flags, int)
                        visible_root = destination.lstat()
                        held_root = os.fstat(descriptor)
                        self.assertEqual(
                            (visible_root.st_dev, visible_root.st_ino),
                            (held_root.st_dev, held_root.st_ino),
                        )
                        for required in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
                            if hasattr(os, required):
                                self.assertTrue(flags & getattr(os, required), required)
                        held_parent_descriptor.append(descriptor)
                        first_parent = destination / "one"
                        first_parent.rename(destination / "held-one")
                        first_parent.symlink_to(outside, target_is_directory=True)
                        fired.append(True)
                        expected_destination.append(_object_tree_snapshot(destination))
                    elif attack in {"parent-swap", "second-parent-swap"} and event == "parent-held":
                        descriptor = authority.get("parent_fd")
                        flags = authority.get("parent_flags")
                        self.assertIsInstance(descriptor, int)
                        self.assertIsInstance(flags, int)
                        self.assertTrue(stat.S_ISDIR(os.fstat(descriptor).st_mode))
                        self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
                        for required in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
                            if hasattr(os, required):
                                self.assertTrue(flags & getattr(os, required), required)
                        self.assertEqual(
                            parent.relative_to(destination).as_posix(),
                            authority.get("component"),
                        )
                        visible_parent = parent.lstat()
                        held_parent = os.fstat(descriptor)
                        self.assertEqual(
                            (visible_parent.st_dev, visible_parent.st_ino),
                            (held_parent.st_dev, held_parent.st_ino),
                        )
                        held_parent_descriptor.append(descriptor)
                        held_parent = (
                            destination / "one/held-two"
                            if attack == "second-parent-swap"
                            else destination / "held-parent"
                        )
                        parent.rename(held_parent)
                        parent.symlink_to(outside, target_is_directory=True)
                        fired.append(True)
                        expected_destination.append(_object_tree_snapshot(destination))
                    elif attack == "post-open-rebind" and event == "leaf-opened":
                        descriptor = authority.get("leaf_fd")
                        self.assertIsInstance(descriptor, int)
                        self.assertTrue(stat.S_ISREG(os.fstat(descriptor).st_mode))
                        path.rename(destination / "held-leaf")
                        path.symlink_to(outside_leaf)
                        fired.append(True)
                        expected_destination.append(_object_tree_snapshot(destination))
                failure = None
                try:
                    with mock.patch.object(sys.modules[__name__], "ROOT", repository), mock.patch.object(
                        sys.modules[__name__], "_materialization_observer",
                        side_effect=inject_rebind,
                    ), mock.patch.object(
                        os, "open", side_effect=observed_open,
                    ):
                        _materialize_staged_overlay(destination, (relative,))
                except BaseException as error:
                    failure = error
                self.assertEqual(outside_before, _directory_snapshot(outside))
                self.assertEqual([True], fired)
                self.assertIsInstance(failure, AssertionError)
                self.assertEqual(
                    expected_destination, [_object_tree_snapshot(destination)],
                    "rejected publication must add no entry after the reviewed rebind",
                )
                self.assertEqual(b"outside-sentinel\n", outside_leaf.read_bytes())
                if attack == "root-swap":
                    self.assertEqual(
                        expected_held_root,
                        [_object_tree_snapshot(base / "held-root")],
                    )
                    self.assertEqual(
                        b"root-prior-object\n", (base / "held-root/root-prior.txt").read_bytes(),
                    )
                    self.assertTrue(any(
                        kwargs.get("dir_fd") == held_parent_descriptor[0]
                        for _args, kwargs, _descriptor in post_hold_opens
                    ))
                elif attack == "root-held-first-parent-swap":
                    self.assertEqual(
                        b"prior-reviewed-object\n",
                        (destination / "held-one/two/reviewed.txt").read_bytes(),
                    )
                    descendant_opens = [
                        (args, kwargs) for args, kwargs in post_hold_attempts
                        if kwargs.get("dir_fd") == held_parent_descriptor[0]
                        and args and os.fspath(args[0]) == "one"
                    ]
                    self.assertTrue(descendant_opens)
                    for args, kwargs in descendant_opens:
                        self.assertEqual("one", os.fspath(args[0]))
                        flags = args[1] if len(args) > 1 else kwargs.get("flags", 0)
                        self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
                        for required in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
                            if hasattr(os, required):
                                self.assertTrue(flags & getattr(os, required), required)
                        for forbidden in (
                            "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND",
                            "O_EXCL",
                        ):
                            if hasattr(os, forbidden):
                                self.assertFalse(flags & getattr(os, forbidden), forbidden)
                elif attack in {"parent-swap", "second-parent-swap"}:
                    held_parent = (
                        destination / "one/held-two"
                        if attack == "second-parent-swap"
                        else destination / "held-parent"
                    )
                    self.assertEqual(
                        b"prior-reviewed-object\n",
                        (held_parent / "reviewed.txt").read_bytes(),
                    )
                    self.assertTrue(any(
                        kwargs.get("dir_fd") == held_parent_descriptor[0]
                        for _args, kwargs, _descriptor in post_hold_opens
                    ))
                else:
                    self.assertEqual(
                        b"prior-reviewed-object\n",
                        (destination / "held-leaf").read_bytes(),
                    )
                residue = [
                    path.relative_to(base).as_posix() for path in base.rglob("*")
                    if ".material" in path.name
                ]
                self.assertEqual([], residue)
                for descriptor in opened_descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

        trusted_payload = b"reviewed-bytes\n"
        hostile_payload = b"hostile-bytes!\n"
        self.assertEqual(len(trusted_payload), len(hostile_payload))
        for prior_state in ("absent", "existing"):
            for temporary_attack in (
                "baseline", "regular-rebind", "symlink-rebind",
                "same-inode-overwrite",
            ):
                with self.subTest(
                    prior_state=prior_state,
                    temporary_attack=temporary_attack,
                ), tempfile.TemporaryDirectory(
                    prefix="http-p-temporary-rebind-",
                ) as directory:
                    base = Path(directory)
                    destination = base / "candidate"
                    parent = destination / "nested"
                    parent.mkdir(parents=True)
                    target = parent / "reviewed.txt"
                    outside = base / "outside.txt"
                    outside.write_bytes(hostile_payload)
                    if prior_state == "existing":
                        target.write_bytes(b"prior-publication\n")
                    prior_metadata = target.lstat() if target.exists() else None
                    prior_payload = target.read_bytes() if target.exists() else None
                    real_open = os.open
                    real_fstat = os.fstat
                    real_stat = os.stat
                    real_os_lstat = os.lstat
                    real_lstat = Path.lstat
                    real_read = os.read
                    real_pread = getattr(os, "pread", None)
                    real_lseek = os.lseek
                    real_replace = os.replace
                    opened_descriptors = []
                    temporary_descriptors = []
                    replace_events = []
                    held_at_replace = []
                    held_after_publish = []
                    post_publish_reads = []
                    original_temporary_metadata = []
                    attack_complete = []
                    publication_returned = []

                    def observed_open(*args, **kwargs):
                        descriptor = real_open(*args, **kwargs)
                        opened_descriptors.append(descriptor)
                        name = os.fspath(args[0]) if args else ""
                        flags = args[1] if len(args) > 1 else kwargs.get("flags", 0)
                        if (
                            name.startswith(".reviewed.txt.materializing-")
                            and flags & os.O_CREAT and flags & os.O_EXCL
                        ):
                            temporary_descriptors.append(descriptor)
                        return descriptor

                    def masked_metadata(actual):
                        reviewed = mock.Mock()
                        for attribute in (
                            "st_mode", "st_ino", "st_dev", "st_nlink",
                            "st_uid", "st_gid", "st_size", "st_atime",
                            "st_mtime", "st_ctime", "st_atime_ns",
                            "st_mtime_ns", "st_ctime_ns",
                        ):
                            setattr(reviewed, attribute, getattr(actual, attribute))
                        authority = original_temporary_metadata[0]
                        reviewed.st_mtime = authority.st_mtime
                        reviewed.st_ctime = authority.st_ctime
                        reviewed.st_mtime_ns = authority.st_mtime_ns
                        reviewed.st_ctime_ns = authority.st_ctime_ns
                        return reviewed

                    def observed_fstat(descriptor):
                        current = real_fstat(descriptor)
                        if (
                            temporary_attack == "same-inode-overwrite"
                            and attack_complete
                            and temporary_descriptors
                            and descriptor == temporary_descriptors[0]
                        ):
                            return masked_metadata(current)
                        return current

                    def observed_stat(path, *args, **kwargs):
                        current = real_stat(path, *args, **kwargs)
                        name = os.fspath(path)
                        if (
                            temporary_attack == "same-inode-overwrite"
                            and attack_complete
                            and (
                                name.startswith(".reviewed.txt.materializing-")
                                or name == "reviewed.txt"
                                or Path(name) == target
                            )
                        ):
                            return masked_metadata(current)
                        return current

                    def observed_lstat(path):
                        current = real_lstat(path)
                        if (
                            temporary_attack == "same-inode-overwrite"
                            and attack_complete and path == target
                        ):
                            return masked_metadata(current)
                        return current

                    def observed_os_lstat(path, *args, **kwargs):
                        current = real_os_lstat(path, *args, **kwargs)
                        name = os.fspath(path)
                        if (
                            temporary_attack == "same-inode-overwrite"
                            and attack_complete
                            and (
                                name.startswith(".reviewed.txt.materializing-")
                                or name == "reviewed.txt"
                                or Path(name) == target
                            )
                        ):
                            return masked_metadata(current)
                        return current

                    def observed_read(descriptor, size):
                        offset = real_lseek(descriptor, 0, os.SEEK_CUR)
                        payload = real_read(descriptor, size)
                        if (
                            publication_returned and temporary_descriptors
                            and descriptor == temporary_descriptors[0]
                        ):
                            post_publish_reads.append((offset, payload))
                        return payload

                    def observed_pread(descriptor, size, offset):
                        payload = real_pread(descriptor, size, offset)
                        if (
                            publication_returned and temporary_descriptors
                            and descriptor == temporary_descriptors[0]
                        ):
                            post_publish_reads.append((offset, payload))
                        return payload

                    def observed_materialization(event, path, **authority):
                        if event != "after-entry" or path != target:
                            return
                        descriptor = temporary_descriptors[0]
                        try:
                            held = real_fstat(descriptor)
                            visible = real_lstat(target)
                        except OSError:
                            held_after_publish.append(False)
                        else:
                            held_after_publish.append(
                                stat.S_ISREG(held.st_mode)
                                and (held.st_dev, held.st_ino)
                                == (visible.st_dev, visible.st_ino)
                            )

                    def attacked_replace(source, destination_name, *args, **kwargs):
                        source_name = os.fspath(source)
                        destination_leaf = os.fspath(destination_name)
                        source_fd = kwargs.get("src_dir_fd")
                        destination_fd = kwargs.get("dst_dir_fd")
                        is_target_publication = (
                            destination_leaf == "reviewed.txt"
                            and source_name.startswith(".reviewed.txt.materializing-")
                        )
                        if is_target_publication and not replace_events:
                            self.assertIsInstance(source_fd, int)
                            self.assertEqual(source_fd, destination_fd)
                            self.assertTrue(stat.S_ISDIR(real_fstat(source_fd).st_mode))
                            self.assertEqual(1, len(temporary_descriptors))
                            source_metadata = real_stat(
                                source_name, dir_fd=source_fd,
                                follow_symlinks=False,
                            )
                            original_temporary_metadata.append(source_metadata)
                            try:
                                held_metadata = real_fstat(temporary_descriptors[0])
                            except OSError:
                                held_at_replace.append(False)
                            else:
                                held_at_replace.append(
                                    stat.S_ISREG(held_metadata.st_mode)
                                    and (held_metadata.st_dev, held_metadata.st_ino)
                                    == (source_metadata.st_dev, source_metadata.st_ino)
                                )
                            replace_events.append(temporary_attack)
                            if temporary_attack == "regular-rebind":
                                os.unlink(source_name, dir_fd=source_fd)
                                attack_fd = real_open(
                                    source_name,
                                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                    | getattr(os, "O_NOFOLLOW", 0),
                                    0o644,
                                    dir_fd=source_fd,
                                )
                                try:
                                    self.assertEqual(
                                        len(hostile_payload),
                                        os.write(attack_fd, hostile_payload),
                                    )
                                finally:
                                    os.close(attack_fd)
                            elif temporary_attack == "symlink-rebind":
                                os.unlink(source_name, dir_fd=source_fd)
                                os.symlink(
                                    os.fspath(outside), source_name,
                                    dir_fd=source_fd,
                                )
                            elif temporary_attack == "same-inode-overwrite":
                                before = real_stat(
                                    source_name, dir_fd=source_fd,
                                    follow_symlinks=False,
                                )
                                attack_fd = real_open(
                                    source_name,
                                    os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                                    dir_fd=source_fd,
                                )
                                try:
                                    self.assertEqual(0, os.lseek(attack_fd, 0, os.SEEK_SET))
                                    self.assertEqual(
                                        len(hostile_payload),
                                        os.write(attack_fd, hostile_payload),
                                    )
                                    os.fsync(attack_fd)
                                finally:
                                    os.close(attack_fd)
                                os.utime(
                                    source_name,
                                    ns=(before.st_atime_ns, before.st_mtime_ns),
                                    dir_fd=source_fd,
                                    follow_symlinks=False,
                                )
                                after = real_stat(
                                    source_name, dir_fd=source_fd,
                                    follow_symlinks=False,
                                )
                                self.assertEqual(
                                    (before.st_dev, before.st_ino, before.st_size,
                                     before.st_mtime_ns),
                                    (after.st_dev, after.st_ino, after.st_size,
                                     after.st_mtime_ns),
                                )
                            attack_complete.append(True)
                        result = real_replace(source, destination_name, *args, **kwargs)
                        if is_target_publication:
                            publication_returned.append(True)
                        return result

                    failure = None
                    try:
                        with mock.patch.object(
                            os, "open", side_effect=observed_open,
                        ), mock.patch.object(
                            os, "fstat", side_effect=observed_fstat,
                        ), mock.patch.object(
                            os, "stat", side_effect=observed_stat,
                        ), mock.patch.object(
                            os, "lstat", side_effect=observed_os_lstat,
                        ), mock.patch.object(
                            Path, "lstat", autospec=True,
                            side_effect=observed_lstat,
                        ), mock.patch.object(
                            os, "read", side_effect=observed_read,
                        ), mock.patch.object(
                            os, "pread", side_effect=observed_pread,
                        ), mock.patch.object(
                            os, "replace", side_effect=attacked_replace,
                        ), mock.patch.object(
                            sys.modules[__name__], "_materialization_observer",
                            side_effect=observed_materialization,
                        ):
                            _write_materialized_entry(
                                destination, "nested/reviewed.txt",
                                trusted_payload, "100644",
                            )
                    except BaseException as error:
                        failure = error
                    self.assertEqual([temporary_attack], replace_events)
                    self.assertEqual([True], publication_returned)

                    def reviewed_post_publish_payload(expected):
                        reviewed = {}
                        for offset, chunk in post_publish_reads:
                            self.assertGreaterEqual(offset, 0)
                            self.assertLessEqual(offset + len(chunk), len(expected))
                            for index, value in enumerate(chunk, start=offset):
                                if index in reviewed:
                                    self.assertEqual(reviewed[index], value)
                                reviewed[index] = value
                        self.assertEqual(set(range(len(expected))), set(reviewed))
                        return bytes(reviewed[index] for index in range(len(expected)))

                    if temporary_attack == "baseline":
                        self.assertIsNone(failure)
                        self.assertEqual(trusted_payload, target.read_bytes())
                        self.assertTrue(stat.S_ISREG(target.lstat().st_mode))
                        self.assertEqual(0o644, stat.S_IMODE(target.lstat().st_mode))
                        self.assertEqual([True], held_after_publish)
                        self.assertEqual(
                            trusted_payload,
                            reviewed_post_publish_payload(trusted_payload),
                        )
                    else:
                        self.assertIsInstance(failure, AssertionError)
                        self.assertEqual(
                            [temporary_attack == "same-inode-overwrite"],
                            held_after_publish,
                        )
                        if prior_metadata is None:
                            self.assertFalse(os.path.lexists(target))
                        else:
                            restored = target.lstat()
                            self.assertEqual(
                                (prior_metadata.st_dev, prior_metadata.st_ino,
                                 prior_metadata.st_mode, prior_metadata.st_nlink),
                                (restored.st_dev, restored.st_ino,
                                 restored.st_mode, restored.st_nlink),
                            )
                            self.assertEqual(prior_payload, target.read_bytes())
                        if os.path.lexists(target) and target.is_file():
                            self.assertNotIn(
                                target.read_bytes(),
                                {trusted_payload, hostile_payload},
                            )
                        if temporary_attack == "same-inode-overwrite":
                            self.assertEqual(
                                hostile_payload,
                                reviewed_post_publish_payload(hostile_payload),
                            )
                    self.assertEqual([True], held_at_replace)
                    self.assertEqual(hostile_payload, outside.read_bytes())
                    self.assertEqual([], [
                        path.relative_to(base).as_posix()
                        for path in base.rglob("*")
                        if ".materializing-" in path.name
                        or ".recovery" in path.name
                        or ".rollback" in path.name
                    ])
                    for descriptor in opened_descriptors:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)

        for prior_state in ("absent", "existing"):
            for late_attack in (
                "same-inode-return", "raise-known", "unknown-replacement",
            ):
                with self.subTest(
                    prior_state=prior_state, late_attack=late_attack,
                ), tempfile.TemporaryDirectory(
                    prefix="http-p-after-entry-race-",
                ) as directory:
                    base = Path(directory)
                    destination = base / "candidate"
                    parent = destination / "nested"
                    parent.mkdir(parents=True)
                    target = parent / "reviewed.txt"
                    if prior_state == "existing":
                        target.write_bytes(b"prior-publication\n")
                    prior_metadata = target.lstat() if target.exists() else None
                    prior_payload = target.read_bytes() if target.exists() else None
                    real_open = os.open
                    real_fstat = os.fstat
                    real_stat = os.stat
                    real_os_lstat = os.lstat
                    real_path_lstat = Path.lstat
                    real_replace = os.replace
                    real_pread = os.pread
                    real_read = os.read
                    real_lseek = os.lseek
                    opened_descriptors = []
                    temporary_descriptors = []
                    events = []
                    attack_complete = []
                    post_attack_reads = []
                    unknown_authority = []
                    original_published_metadata = []

                    def observed_open(*args, **kwargs):
                        descriptor = real_open(*args, **kwargs)
                        opened_descriptors.append(descriptor)
                        name = os.fspath(args[0]) if args else ""
                        flags = args[1] if len(args) > 1 else kwargs.get("flags", 0)
                        if (
                            name.startswith(".reviewed.txt.materializing-")
                            and flags & os.O_CREAT and flags & os.O_EXCL
                        ):
                            temporary_descriptors.append(descriptor)
                        return descriptor

                    def observed_replace(source, destination_name, *args, **kwargs):
                        result = real_replace(source, destination_name, *args, **kwargs)
                        if (
                            os.fspath(source).startswith(
                                ".reviewed.txt.materializing-"
                            )
                            and os.fspath(destination_name) == "reviewed.txt"
                            and not events
                        ):
                            self.assertEqual(1, len(temporary_descriptors))
                            held = real_fstat(temporary_descriptors[0])
                            visible = real_path_lstat(target)
                            self.assertEqual(
                                (held.st_dev, held.st_ino),
                                (visible.st_dev, visible.st_ino),
                            )
                            events.append("replace-return")
                        return result

                    def masked_published_metadata(actual):
                        reviewed = mock.Mock()
                        for attribute in (
                            "st_mode", "st_ino", "st_dev", "st_nlink",
                            "st_uid", "st_gid", "st_size", "st_atime",
                            "st_mtime", "st_ctime", "st_atime_ns",
                            "st_mtime_ns", "st_ctime_ns",
                        ):
                            setattr(reviewed, attribute, getattr(actual, attribute))
                        authority = original_published_metadata[0]
                        reviewed.st_mtime = authority.st_mtime
                        reviewed.st_ctime = authority.st_ctime
                        reviewed.st_mtime_ns = authority.st_mtime_ns
                        reviewed.st_ctime_ns = authority.st_ctime_ns
                        return reviewed

                    def late_fstat(descriptor):
                        current = real_fstat(descriptor)
                        if (
                            late_attack == "same-inode-return" and attack_complete
                            and temporary_descriptors
                            and descriptor == temporary_descriptors[0]
                        ):
                            return masked_published_metadata(current)
                        return current

                    def late_stat(path, *args, **kwargs):
                        current = real_stat(path, *args, **kwargs)
                        name = os.fspath(path)
                        if (
                            late_attack == "same-inode-return" and attack_complete
                            and (name == "reviewed.txt" or Path(name) == target)
                        ):
                            return masked_published_metadata(current)
                        return current

                    def late_os_lstat(path, *args, **kwargs):
                        current = real_os_lstat(path, *args, **kwargs)
                        name = os.fspath(path)
                        if (
                            late_attack == "same-inode-return" and attack_complete
                            and (name == "reviewed.txt" or Path(name) == target)
                        ):
                            return masked_published_metadata(current)
                        return current

                    def late_path_lstat(path):
                        current = real_path_lstat(path)
                        if (
                            late_attack == "same-inode-return" and attack_complete
                            and path == target
                        ):
                            return masked_published_metadata(current)
                        return current

                    def observed_pread(descriptor, size, offset):
                        payload = real_pread(descriptor, size, offset)
                        if (
                            attack_complete and temporary_descriptors
                            and descriptor == temporary_descriptors[0]
                        ):
                            if not any(event == "post-attack-read" for event in events):
                                events.append("post-attack-read")
                            post_attack_reads.append((offset, payload))
                        return payload

                    def observed_read(descriptor, size):
                        offset = real_lseek(descriptor, 0, os.SEEK_CUR)
                        payload = real_read(descriptor, size)
                        if (
                            attack_complete and temporary_descriptors
                            and descriptor == temporary_descriptors[0]
                        ):
                            if not any(event == "post-attack-read" for event in events):
                                events.append("post-attack-read")
                            post_attack_reads.append((offset, payload))
                        return payload

                    def late_observer(event, path, **authority):
                        if event != "after-entry" or path != target:
                            return
                        self.assertEqual(["replace-return"], events)
                        held = real_fstat(temporary_descriptors[0])
                        visible = real_path_lstat(target)
                        original_published_metadata.append(held)
                        self.assertEqual(
                            (held.st_dev, held.st_ino),
                            (visible.st_dev, visible.st_ino),
                        )
                        if late_attack == "unknown-replacement":
                            unknown_name = ".reviewed.txt.concurrent"
                            unknown_fd = real_open(
                                unknown_name,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                | getattr(os, "O_NOFOLLOW", 0),
                                0o644, dir_fd=authority.get("parent_fd", None),
                            ) if authority.get("parent_fd") is not None else real_open(
                                parent / unknown_name,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                | getattr(os, "O_NOFOLLOW", 0), 0o644,
                            )
                            try:
                                os.write(unknown_fd, b"concurrent-authority\n")
                                os.fsync(unknown_fd)
                            finally:
                                os.close(unknown_fd)
                            real_replace(parent / unknown_name, target)
                            unknown = target.lstat()
                            unknown_authority.append(
                                (unknown.st_dev, unknown.st_ino, unknown.st_mode,
                                 unknown.st_nlink, target.read_bytes())
                            )
                            events.append("after-entry-unknown")
                            raise KeyboardInterrupt("concurrent publication")
                        attack_fd = real_open(
                            target,
                            os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                        )
                        before = target.lstat()
                        try:
                            os.lseek(attack_fd, 0, os.SEEK_SET)
                            self.assertEqual(
                                len(hostile_payload),
                                os.write(attack_fd, hostile_payload),
                            )
                            os.fsync(attack_fd)
                        finally:
                            os.close(attack_fd)
                        os.utime(
                            target,
                            ns=(before.st_atime_ns, before.st_mtime_ns),
                            follow_symlinks=False,
                        )
                        attack_complete.append(True)
                        events.append(
                            "after-entry-attack" if late_attack == "same-inode-return"
                            else "after-entry-raise"
                        )
                        if late_attack == "raise-known":
                            raise KeyboardInterrupt("known publication")

                    failure = None
                    try:
                        with mock.patch.object(
                            os, "open", side_effect=observed_open,
                        ), mock.patch.object(
                            os, "fstat", side_effect=late_fstat,
                        ), mock.patch.object(
                            os, "stat", side_effect=late_stat,
                        ), mock.patch.object(
                            os, "lstat", side_effect=late_os_lstat,
                        ), mock.patch.object(
                            Path, "lstat", autospec=True,
                            side_effect=late_path_lstat,
                        ), mock.patch.object(
                            os, "replace", side_effect=observed_replace,
                        ), mock.patch.object(
                            os, "pread", side_effect=observed_pread,
                        ), mock.patch.object(
                            os, "read", side_effect=observed_read,
                        ), mock.patch.object(
                            sys.modules[__name__], "_materialization_observer",
                            side_effect=late_observer,
                        ):
                            _write_materialized_entry(
                                destination, "nested/reviewed.txt",
                                trusted_payload, "100644",
                            )
                    except BaseException as error:
                        failure = error

                    if late_attack == "same-inode-return":
                        self.assertIsInstance(failure, AssertionError)
                        self.assertEqual(
                            ["replace-return", "after-entry-attack", "post-attack-read"],
                            events,
                        )
                        reviewed = {}
                        for offset, chunk in post_attack_reads:
                            for index, value in enumerate(chunk, start=offset):
                                reviewed[index] = value
                        self.assertEqual(
                            hostile_payload,
                            bytes(reviewed[index] for index in range(len(hostile_payload))),
                        )
                    elif late_attack == "raise-known":
                        self.assertIsInstance(failure, KeyboardInterrupt)
                        self.assertEqual(
                            ["replace-return", "after-entry-raise"], events,
                        )
                    else:
                        self.assertIsInstance(failure, AssertionError)
                        self.assertRegex(str(failure), "rollback")
                        self.assertEqual(
                            ["replace-return", "after-entry-unknown"], events,
                        )
                        self.assertEqual(1, len(unknown_authority))
                        current = target.lstat()
                        self.assertEqual(
                            unknown_authority[0],
                            (current.st_dev, current.st_ino, current.st_mode,
                             current.st_nlink, target.read_bytes()),
                        )
                    if late_attack != "unknown-replacement":
                        if prior_metadata is None:
                            self.assertFalse(os.path.lexists(target))
                        else:
                            restored = target.lstat()
                            self.assertEqual(
                                (prior_metadata.st_dev, prior_metadata.st_ino,
                                 prior_metadata.st_mode, prior_metadata.st_nlink,
                                 prior_payload),
                                (restored.st_dev, restored.st_ino,
                                 restored.st_mode, restored.st_nlink,
                                 target.read_bytes()),
                            )
                    self.assertEqual([], [
                        path.relative_to(base).as_posix()
                        for path in base.rglob("*")
                        if ".materializing-" in path.name
                        or ".recovery" in path.name
                        or ".rollback" in path.name
                    ])
                    for descriptor in opened_descriptors:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)

        with self.subTest(
            rollback_content_authority=True,
        ), tempfile.TemporaryDirectory(
            prefix="http-p-rollback-content-",
        ) as directory:
            base = Path(directory)
            destination = base / "candidate"
            parent = destination / "nested"
            parent.mkdir(parents=True)
            target = parent / "reviewed.txt"
            prior_payload = b"prior-authority\n"
            poisoned_prior = b"hostile-prior!!\n"
            self.assertEqual(len(prior_payload), len(poisoned_prior))
            target.write_bytes(prior_payload)
            prior_metadata = target.lstat()
            real_open = os.open
            real_replace = os.replace
            opened_descriptors = []
            prior_descriptors = []
            prior_open_flags = []
            writable_prior_descriptors = []
            writable_held_at_publication = []
            temporary_descriptors = []
            opened_descriptors = []
            attack_events = []

            def authority_open(*args, **kwargs):
                name = os.fspath(args[0]) if args else ""
                flags = args[1] if len(args) > 1 else kwargs.get("flags", 0)
                descriptor = real_open(*args, **kwargs)
                opened_descriptors.append(descriptor)
                if name == "reviewed.txt" and not prior_descriptors:
                    prior_descriptors.append(descriptor)
                    prior_open_flags.append(flags)
                if (
                    name.startswith(".reviewed.txt.materializing-")
                    and flags & os.O_CREAT and flags & os.O_EXCL
                ):
                    temporary_descriptors.append(descriptor)
                elif flags & os.O_ACCMODE in {os.O_WRONLY, os.O_RDWR}:
                    held = os.fstat(descriptor)
                    if (held.st_dev, held.st_ino) == (
                        prior_metadata.st_dev, prior_metadata.st_ino,
                    ):
                        writable_prior_descriptors.append((descriptor, flags))
                return descriptor

            def poison_both_authorities(source, destination_name, *args, **kwargs):
                if (
                    os.fspath(source).startswith(".reviewed.txt.materializing-")
                    and os.fspath(destination_name) == "reviewed.txt"
                    and not attack_events
                ):
                    self.assertEqual(1, len(prior_descriptors))
                    self.assertEqual(1, len(temporary_descriptors))
                    eligible_writable = []
                    for descriptor, flags in writable_prior_descriptors:
                        try:
                            held = os.fstat(descriptor)
                        except OSError:
                            continue
                        if (
                            (held.st_dev, held.st_ino)
                            == (prior_metadata.st_dev, prior_metadata.st_ino)
                            and flags & os.O_ACCMODE in {os.O_WRONLY, os.O_RDWR}
                            and (
                                not hasattr(os, "O_NOFOLLOW")
                                or flags & os.O_NOFOLLOW
                            )
                            and (
                                not hasattr(os, "O_CLOEXEC")
                                or flags & os.O_CLOEXEC
                            )
                            and (
                                not hasattr(os, "O_NONBLOCK")
                                or flags & os.O_NONBLOCK
                            )
                            and all(
                                not hasattr(os, forbidden)
                                or not flags & getattr(os, forbidden)
                                for forbidden in (
                                    "O_TRUNC", "O_APPEND", "O_CREAT", "O_EXCL",
                                )
                            )
                        ):
                            eligible_writable.append(descriptor)
                    writable_held_at_publication.append(len(eligible_writable) == 1)
                    parent_fd = kwargs.get("src_dir_fd")
                    self.assertIsInstance(parent_fd, int)
                    prior_name = "reviewed.txt"
                    try:
                        visible_prior = os.stat(
                            prior_name, dir_fd=parent_fd, follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        prior_name = next(
                            name for name in os.listdir(parent)
                            if name != os.fspath(source)
                            and (lambda value: (
                                value.st_dev, value.st_ino
                            ) == (prior_metadata.st_dev, prior_metadata.st_ino))(
                                os.stat(
                                    name, dir_fd=parent_fd,
                                    follow_symlinks=False,
                                )
                            )
                        )
                    else:
                        self.assertEqual(
                            (prior_metadata.st_dev, prior_metadata.st_ino),
                            (visible_prior.st_dev, visible_prior.st_ino),
                        )
                    attack_prior = real_open(
                        prior_name,
                        os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=parent_fd,
                    )
                    attack_temporary = real_open(
                        source,
                        os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=parent_fd,
                    )
                    prior_before = os.fstat(attack_prior)
                    temporary_before = os.fstat(attack_temporary)
                    try:
                        self.assertEqual(
                            len(poisoned_prior),
                            os.write(attack_prior, poisoned_prior),
                        )
                        self.assertEqual(
                            len(hostile_payload),
                            os.write(attack_temporary, hostile_payload),
                        )
                        os.fsync(attack_prior)
                        os.fsync(attack_temporary)
                    finally:
                        os.close(attack_temporary)
                        os.close(attack_prior)
                    os.utime(
                        prior_name,
                        ns=(prior_before.st_atime_ns, prior_before.st_mtime_ns),
                        dir_fd=parent_fd, follow_symlinks=False,
                    )
                    os.utime(
                        source,
                        ns=(temporary_before.st_atime_ns,
                            temporary_before.st_mtime_ns),
                        dir_fd=parent_fd, follow_symlinks=False,
                    )
                    attack_events.append("prior-and-temporary-poisoned")
                return real_replace(source, destination_name, *args, **kwargs)

            failure = None
            try:
                with mock.patch.object(
                    os, "open", side_effect=authority_open,
                ), mock.patch.object(
                    os, "replace", side_effect=poison_both_authorities,
                ):
                    _write_materialized_entry(
                        destination, "nested/reviewed.txt",
                        trusted_payload, "100644",
                    )
            except BaseException as error:
                failure = error
            self.assertEqual(["prior-and-temporary-poisoned"], attack_events)
            self.assertEqual([True], writable_held_at_publication)
            self.assertEqual(1, len(prior_open_flags))
            self.assertEqual(os.O_RDONLY, prior_open_flags[0] & os.O_ACCMODE)
            for required in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
                if hasattr(os, required):
                    self.assertTrue(prior_open_flags[0] & getattr(os, required))
            self.assertIsInstance(failure, AssertionError)
            restored = target.lstat()
            self.assertEqual(
                (prior_metadata.st_dev, prior_metadata.st_ino,
                 prior_metadata.st_mode, prior_metadata.st_nlink, prior_payload),
                (restored.st_dev, restored.st_ino,
                 restored.st_mode, restored.st_nlink, target.read_bytes()),
            )
            self.assertNotIn(target.read_bytes(), {hostile_payload, poisoned_prior})
            self.assertEqual([], [
                path.relative_to(base).as_posix()
                for path in base.rglob("*")
                if ".materializing-" in path.name
                or ".recovery" in path.name
                or ".rollback" in path.name
            ])
            for descriptor in opened_descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

        with self.subTest(
            prior_snapshot_stability=True,
        ), tempfile.TemporaryDirectory(
            prefix="http-p-prior-snapshot-",
        ) as directory:
            base = Path(directory)
            destination = base / "candidate"
            parent = destination / "nested"
            parent.mkdir(parents=True)
            target = parent / "reviewed.txt"
            prior_payload = b"prior-authority\n"
            poisoned_prior = b"hostile-prior!!\n"
            target.write_bytes(prior_payload)
            prior_metadata = target.lstat()
            real_open = os.open
            real_fstat = os.fstat
            real_pread = os.pread
            real_replace = os.replace
            opened_descriptors = []
            prior_authority_descriptors = []
            prior_reads = []
            snapshot_events = []
            snapshot_attack = []
            publish_calls = []

            def snapshot_open(*args, **kwargs):
                descriptor = real_open(*args, **kwargs)
                opened_descriptors.append(descriptor)
                name = os.fspath(args[0]) if args else ""
                if name == "reviewed.txt" or ".rollback-" in name:
                    prior_authority_descriptors.append(descriptor)
                return descriptor

            def snapshot_fstat(descriptor):
                metadata = real_fstat(descriptor)
                if (metadata.st_dev, metadata.st_ino) == (
                    prior_metadata.st_dev, prior_metadata.st_ino,
                ):
                    snapshot_events.append("fstat")
                return metadata

            def snapshot_pread(descriptor, size, offset):
                payload = real_pread(descriptor, size, offset)
                if descriptor in prior_authority_descriptors:
                    snapshot_events.append("read")
                    prior_reads.append(payload)
                    if not snapshot_attack:
                        attack_fd = real_open(
                            target,
                            os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
                            | getattr(os, "O_CLOEXEC", 0),
                        )
                        before = target.lstat()
                        try:
                            os.write(attack_fd, poisoned_prior)
                            os.fsync(attack_fd)
                        finally:
                            os.close(attack_fd)
                        os.utime(
                            target,
                            ns=(before.st_atime_ns, before.st_mtime_ns),
                            follow_symlinks=False,
                        )
                        snapshot_attack.append(True)
                return payload

            def reject_snapshot_publication(source, destination_name, *args, **kwargs):
                if (
                    os.fspath(source).startswith(".reviewed.txt.materializing-")
                    and os.fspath(destination_name) == "reviewed.txt"
                ):
                    publish_calls.append(True)
                    raise AssertionError("unstable prior snapshot reached publication")
                return real_replace(source, destination_name, *args, **kwargs)

            failure = None
            try:
                with mock.patch.object(
                    os, "open", side_effect=snapshot_open,
                ), mock.patch.object(
                    os, "fstat", side_effect=snapshot_fstat,
                ), mock.patch.object(
                    os, "pread", side_effect=snapshot_pread,
                ), mock.patch.object(
                    os, "replace", side_effect=reject_snapshot_publication,
                ):
                    _write_materialized_entry(
                        destination, "nested/reviewed.txt",
                        trusted_payload, "100644",
                    )
            except BaseException as error:
                failure = error
            self.assertEqual([True], snapshot_attack)
            self.assertEqual([], publish_calls)
            self.assertIsInstance(failure, AssertionError)
            self.assertGreaterEqual(len(prior_reads), 2)
            self.assertEqual(prior_payload, prior_reads[0])
            self.assertIn(poisoned_prior, prior_reads[1:])
            read_positions = [
                index for index, event in enumerate(snapshot_events)
                if event == "read"
            ]
            self.assertGreaterEqual(len(read_positions), 2)
            first_read, second_read = read_positions[:2]
            self.assertIn("fstat", snapshot_events[:first_read])
            self.assertIn("fstat", snapshot_events[first_read + 1:second_read])
            self.assertIn("fstat", snapshot_events[second_read + 1:])
            restored = target.lstat()
            self.assertEqual(
                (prior_metadata.st_dev, prior_metadata.st_ino,
                 prior_metadata.st_mode, prior_metadata.st_nlink, prior_payload),
                (restored.st_dev, restored.st_ino,
                 restored.st_mode, restored.st_nlink, target.read_bytes()),
            )
            for descriptor in opened_descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

        with self.subTest(
            rollback_replace_boundary=True,
        ), tempfile.TemporaryDirectory(
            prefix="http-p-rollback-replace-",
        ) as directory:
            base = Path(directory)
            destination = base / "candidate"
            parent = destination / "nested"
            parent.mkdir(parents=True)
            target = parent / "reviewed.txt"
            prior_payload = b"prior-authority\n"
            poisoned_prior = b"hostile-prior!!\n"
            target.write_bytes(prior_payload)
            prior_metadata = target.lstat()
            real_open = os.open
            real_pread = os.pread
            real_replace = os.replace
            recovery_descriptors = []
            opened_descriptors = []
            rollback_returned = []
            postrollback_reads = []
            postrollback_identity = []
            attack_events = []

            def rollback_open(*args, **kwargs):
                descriptor = real_open(*args, **kwargs)
                opened_descriptors.append(descriptor)
                name = os.fspath(args[0]) if args else ""
                flags = args[1] if len(args) > 1 else kwargs.get("flags", 0)
                if ".rollback-" in name and flags & os.O_ACCMODE in {
                    os.O_WRONLY, os.O_RDWR,
                }:
                    recovery_descriptors.append(descriptor)
                return descriptor

            def rollback_pread(descriptor, size, offset):
                payload = real_pread(descriptor, size, offset)
                if rollback_returned and descriptor in recovery_descriptors:
                    postrollback_reads.append(payload)
                    held = os.fstat(descriptor)
                    visible = target.lstat()
                    postrollback_identity.append(
                        (held.st_dev, held.st_ino)
                        == (visible.st_dev, visible.st_ino)
                    )
                return payload

            def poison_rollback_replace(source, destination_name, *args, **kwargs):
                source_name = os.fspath(source)
                destination_leaf = os.fspath(destination_name)
                if (
                    ".rollback-" in source_name
                    and destination_leaf == "reviewed.txt"
                    and not attack_events
                ):
                    attack_fd = real_open(
                        source,
                        os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=kwargs["src_dir_fd"],
                    )
                    before = os.fstat(attack_fd)
                    try:
                        os.write(attack_fd, poisoned_prior)
                        os.fsync(attack_fd)
                    finally:
                        os.close(attack_fd)
                    os.utime(
                        source,
                        ns=(before.st_atime_ns, before.st_mtime_ns),
                        dir_fd=kwargs["src_dir_fd"], follow_symlinks=False,
                    )
                    attack_events.append("rollback-poisoned")
                result = real_replace(source, destination_name, *args, **kwargs)
                if ".rollback-" in source_name and destination_leaf == "reviewed.txt":
                    rollback_returned.append(True)
                return result

            def force_known_rollback(event, path, **authority):
                if event == "after-entry" and path == target:
                    raise KeyboardInterrupt("force verified rollback")

            failure = None
            try:
                with mock.patch.object(
                    os, "open", side_effect=rollback_open,
                ), mock.patch.object(
                    os, "pread", side_effect=rollback_pread,
                ), mock.patch.object(
                    os, "replace", side_effect=poison_rollback_replace,
                ), mock.patch.object(
                    sys.modules[__name__], "_materialization_observer",
                    side_effect=force_known_rollback,
                ):
                    _write_materialized_entry(
                        destination, "nested/reviewed.txt",
                        trusted_payload, "100644",
                    )
            except BaseException as error:
                failure = error
            self.assertEqual(["rollback-poisoned"], attack_events)
            self.assertEqual([True], rollback_returned)
            self.assertIsInstance(failure, KeyboardInterrupt)
            self.assertGreaterEqual(len(postrollback_reads), 2)
            self.assertEqual(poisoned_prior, postrollback_reads[0])
            self.assertEqual(prior_payload, postrollback_reads[-1])
            self.assertTrue(all(postrollback_identity))
            restored = target.lstat()
            self.assertEqual(
                (prior_metadata.st_dev, prior_metadata.st_ino,
                 prior_metadata.st_mode, prior_metadata.st_nlink, prior_payload),
                (restored.st_dev, restored.st_ino,
                 restored.st_mode, restored.st_nlink, target.read_bytes()),
            )
            self.assertEqual([], [
                path.relative_to(base).as_posix()
                for path in base.rglob("*")
                if ".materializing-" in path.name
                or ".recovery" in path.name
                or ".rollback" in path.name
            ])
            for descriptor in opened_descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

        with self.subTest(
            recovery_cleanup_precedes_final_verification=True,
        ), tempfile.TemporaryDirectory(
            prefix="http-p-recovery-cleanup-",
        ) as directory:
            base = Path(directory)
            destination = base / "candidate"
            parent = destination / "nested"
            parent.mkdir(parents=True)
            target = parent / "reviewed.txt"
            target.write_bytes(b"prior-publication\n")
            real_open = os.open
            real_unlink = os.unlink
            real_pread = os.pread
            temporary_descriptors = []
            opened_descriptors = []
            cleanup_attack = []
            final_reads = []
            final_read_identity = []
            events = []

            def cleanup_open(*args, **kwargs):
                descriptor = real_open(*args, **kwargs)
                opened_descriptors.append(descriptor)
                name = os.fspath(args[0]) if args else ""
                flags = args[1] if len(args) > 1 else kwargs.get("flags", 0)
                if (
                    name.startswith(".reviewed.txt.materializing-")
                    and flags & os.O_CREAT and flags & os.O_EXCL
                ):
                    temporary_descriptors.append(descriptor)
                return descriptor

            def attack_cleanup(path, *args, **kwargs):
                if ".rollback-" in os.fspath(path) and not cleanup_attack:
                    attack_fd = real_open(
                        "reviewed.txt",
                        os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=kwargs["dir_fd"],
                    )
                    try:
                        os.write(attack_fd, hostile_payload)
                        os.fsync(attack_fd)
                    finally:
                        os.close(attack_fd)
                    cleanup_attack.append(True)
                    events.append("cleanup-attack")
                return real_unlink(path, *args, **kwargs)

            def cleanup_observer(event, path, **authority):
                if event == "after-entry" and path == target:
                    events.append("after-entry")

            def cleanup_pread(descriptor, size, offset):
                payload = real_pread(descriptor, size, offset)
                if descriptor in temporary_descriptors:
                    if (
                        "after-entry" in events and not cleanup_attack
                        and "precleanup-read" not in events
                    ):
                        events.append("precleanup-read")
                    elif cleanup_attack:
                        final_reads.append(payload)
                        held = os.fstat(descriptor)
                        visible = target.lstat()
                        final_read_identity.append(
                            (held.st_dev, held.st_ino)
                            == (visible.st_dev, visible.st_ino)
                        )
                        if "final-read" not in events:
                            events.append("final-read")
                return payload

            failure = None
            try:
                with mock.patch.object(
                    os, "open", side_effect=cleanup_open,
                ), mock.patch.object(
                    os, "unlink", side_effect=attack_cleanup,
                ), mock.patch.object(
                    os, "pread", side_effect=cleanup_pread,
                ), mock.patch.object(
                    sys.modules[__name__], "_materialization_observer",
                    side_effect=cleanup_observer,
                ):
                    _write_materialized_entry(
                        destination, "nested/reviewed.txt",
                        trusted_payload, "100644",
                    )
            except BaseException as error:
                failure = error
            self.assertEqual([True], cleanup_attack)
            self.assertIsInstance(failure, AssertionError)
            self.assertEqual(
                ["after-entry", "precleanup-read", "cleanup-attack", "final-read"],
                events,
            )
            self.assertGreaterEqual(len(final_reads), 2)
            self.assertEqual(hostile_payload, final_reads[0])
            self.assertEqual(trusted_payload, final_reads[-1])
            self.assertTrue(all(final_read_identity))
            self.assertEqual(trusted_payload, target.read_bytes())
            self.assertTrue(stat.S_ISREG(target.lstat().st_mode))
            self.assertEqual([], [
                path.relative_to(base).as_posix()
                for path in base.rglob("*")
                if ".materializing-" in path.name
                or ".recovery" in path.name
                or ".rollback" in path.name
            ])
            for descriptor in opened_descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def _legacy_directory_dependency_capsule_contract(self):
        module = sys.modules[__name__]
        read_source = getattr(module, "_read_stable_dependency_source")
        build = getattr(module, "_build_dependency_capsule")
        verify = getattr(module, "_verify_dependency_capsule")
        self.assertEqual(24, len(P_CAPSULE_SOURCE_ENTRIES))
        self.assertEqual(24, len(set(P_CAPSULE_SOURCE_ENTRIES)))
        self.assertEqual(4055, P_CAPSULE_FILE_COUNT)
        self.assertEqual(64164026, P_CAPSULE_TOTAL_BYTES)
        self.assertEqual({"0644": 3986, "0755": 69}, P_CAPSULE_MODE_COUNTS)
        self.assertEqual(65, P_CAPSULE_NATIVE_COUNT)
        self.assertEqual("cpython-39", P_CAPSULE_PYTHON_IDENTITY["cache_tag"])
        self.assertEqual("darwin", P_CAPSULE_PYTHON_IDENTITY["platform"])
        self.assertEqual("arm64", P_CAPSULE_PYTHON_IDENTITY["machine"])
        self.assertEqual((3, 9, 6), P_CAPSULE_PYTHON_IDENTITY["version"])
        self.assertEqual(
            P_CAPSULE_PYTHON_IDENTITY["executable"],
            str(Path(sys.executable).resolve()),
        )
        self.assertEqual(
            P_CAPSULE_PYTHON_IDENTITY["implementation"],
            platform.python_implementation(),
        )
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["version"], sys.version_info[:3])
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["cache_tag"], sys.implementation.cache_tag)
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["platform"], sys.platform)
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["machine"], platform.machine())

        with tempfile.TemporaryDirectory(prefix="http-p-capsule-source-") as directory:
            source_root = Path(directory)
            source = source_root / "reviewed.py"
            reviewed = b"value = 'reviewed'\n"
            source.write_bytes(reviewed)
            source.chmod(0o644)
            opened = []
            real_open = os.open

            def observed_open(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                if Path(path).name == source.name:
                    opened.append((descriptor, flags))
                return descriptor

            with mock.patch.object(os, "open", side_effect=observed_open):
                self.assertEqual((reviewed, "0644"), read_source(source))
            self.assertEqual(1, len(opened))
            descriptor, flags = opened[0]
            self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
            for required in (os.O_NOFOLLOW, os.O_CLOEXEC, os.O_NONBLOCK):
                self.assertEqual(required, flags & required)
            for forbidden in (os.O_WRONLY, os.O_RDWR, os.O_CREAT, os.O_TRUNC, os.O_APPEND):
                self.assertFalse(flags & forbidden)
            with self.assertRaises(OSError):
                os.fstat(descriptor)

            alias = source_root / "alias.py"
            alias.symlink_to(source.name)
            with self.assertRaises(AssertionError):
                read_source(alias)
            fifo = source_root / "source.fifo"
            os.mkfifo(fifo)
            started = time.monotonic()
            with self.assertRaises(AssertionError):
                read_source(fifo)
            self.assertLess(time.monotonic() - started, 3)

            original = source.stat()
            hostile = b"value = 'hostile'\n"
            self.assertEqual(len(reviewed), len(hostile))
            real_pread = os.pread
            reads = []

            def unstable_pread(fd, size, offset):
                payload = real_pread(fd, size, offset)
                if fd == opened_descriptor[0] and not reads:
                    reads.append(payload)
                    writer = os.open(source, os.O_WRONLY | os.O_CLOEXEC)
                    try:
                        os.pwrite(writer, hostile, 0)
                        os.fsync(writer)
                    finally:
                        os.close(writer)
                    os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
                return payload

            opened_descriptor = []

            def capture_unstable(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                if Path(path).name == source.name and (flags & os.O_ACCMODE) == os.O_RDONLY:
                    opened_descriptor[:] = [descriptor]
                return descriptor

            try:
                with mock.patch.object(os, "open", side_effect=capture_unstable), \
                        mock.patch.object(os, "pread", side_effect=unstable_pread):
                    with self.assertRaises(AssertionError):
                        read_source(source)
                self.assertEqual([reviewed], reads)
            finally:
                source.write_bytes(reviewed)
                source.chmod(0o644)

        with tempfile.TemporaryDirectory(prefix="http-p-capsule-build-") as directory:
            state_root = Path(directory) / "state"
            state_root.mkdir(mode=0o700)
            stable_calls = []

            def observed_source(path):
                result = read_source(path)
                stable_calls.append(Path(path).resolve())
                return result

            with mock.patch.object(
                module, "_read_stable_dependency_source", side_effect=observed_source,
            ):
                capsule = build(state_root)
            self.assertEqual(state_root / "capsule", capsule)
            self.assertEqual(0o700, stat.S_IMODE(state_root.lstat().st_mode))
            self.assertEqual(P_CAPSULE_FILE_COUNT, len(stable_calls))
            self.assertEqual(P_CAPSULE_FILE_COUNT, len(set(stable_calls)))
            reviewed_roots = tuple(
                (Path(source).resolve(), target)
                for source, target in P_CAPSULE_SOURCE_ENTRIES
            )
            used_roots = set()
            for source_path in stable_calls:
                matches = [
                    (source_root, target)
                    for source_root, target in reviewed_roots
                    if source_path == source_root or source_root in source_path.parents
                ]
                self.assertEqual(1, len(matches), source_path)
                used_roots.add(matches[0])
            self.assertEqual(set(reviewed_roots), used_roots)
            records, serialized, mode_counts, native = _literal_dependency_capsule_records(
                capsule
            )
            expected_source_mapping = {}
            for record in records:
                relative = Path(record["path"])
                matches = []
                for source, target in P_CAPSULE_SOURCE_ENTRIES:
                    target_path = Path(target)
                    if relative == target_path:
                        matches.append(Path(source).resolve())
                    elif target_path in relative.parents:
                        matches.append(
                            (Path(source) / relative.relative_to(target_path)).resolve()
                        )
                self.assertEqual(1, len(matches), record["path"])
                expected_source_mapping[matches[0]] = record["path"]
            self.assertEqual(P_CAPSULE_FILE_COUNT, len(expected_source_mapping))
            self.assertEqual(set(expected_source_mapping), set(stable_calls))
            self.assertEqual(P_CAPSULE_FILE_COUNT, len(records))
            self.assertEqual(P_CAPSULE_TOTAL_BYTES, sum(record["size"] for record in records))
            self.assertEqual(P_CAPSULE_MODE_COUNTS, mode_counts)
            self.assertEqual(P_CAPSULE_NATIVE_COUNT, len(native))
            self.assertEqual(
                P_CAPSULE_RECORDS_SHA256, hashlib.sha256(serialized).hexdigest(),
            )
            verify(capsule)

            authority_file = capsule / "six.py"
            authority_payload = authority_file.read_bytes()
            authority_mode = stat.S_IMODE(authority_file.lstat().st_mode)
            root_identity = (capsule.lstat().st_dev, capsule.lstat().st_ino)

            def observe_verify(attack=None):
                real_open = os.open
                real_fstat = os.fstat
                real_pread = os.pread
                attempts = []
                opened_fds = []
                authority_fd = []
                root_fds = set()
                root_flags = []
                events = []
                attacked = []

                def observed_open(path, flags, *args, **kwargs):
                    attempts.append((path, flags, kwargs.get("dir_fd")))
                    descriptor = real_open(path, flags, *args, **kwargs)
                    opened_fds.append(descriptor)
                    metadata = real_fstat(descriptor)
                    identity = (metadata.st_dev, metadata.st_ino)
                    if stat.S_ISDIR(metadata.st_mode) and identity == root_identity:
                        root_fds.add(descriptor)
                        root_flags.append(flags)
                    if stat.S_ISREG(metadata.st_mode) and identity == (
                        authority_file.lstat().st_dev, authority_file.lstat().st_ino
                    ):
                        authority_fd[:] = [descriptor]
                    return descriptor

                def observed_fstat(descriptor):
                    metadata = real_fstat(descriptor)
                    if authority_fd and descriptor == authority_fd[0]:
                        events.append("fstat")
                    return metadata

                def observed_pread(descriptor, size, offset):
                    payload = real_pread(descriptor, size, offset)
                    if authority_fd and descriptor == authority_fd[0]:
                        events.append("read")
                        if attack and not attacked:
                            attacked.append(True)
                            attack()
                    return payload

                failure = None
                started = time.monotonic()
                try:
                    with mock.patch.object(os, "open", side_effect=observed_open), \
                            mock.patch.object(os, "fstat", side_effect=observed_fstat), \
                            mock.patch.object(os, "pread", side_effect=observed_pread):
                        verify(capsule)
                except BaseException as error:
                    failure = error
                elapsed = time.monotonic() - started
                return (
                    failure, elapsed, attempts, opened_fds, authority_fd,
                    root_fds, events, attacked, root_flags,
                )

            baseline = observe_verify()
            self.assertIsNone(baseline[0])
            self.assertTrue(baseline[4])
            self.assertTrue(baseline[5])
            self.assertEqual(1, len(baseline[8]))
            self.assertEqual(os.O_RDONLY, baseline[8][0] & os.O_ACCMODE)
            for required in (os.O_DIRECTORY, os.O_NOFOLLOW, os.O_CLOEXEC):
                self.assertEqual(required, baseline[8][0] & required)
            self.assertEqual(
                ["fstat", "read", "fstat", "read", "fstat"],
                baseline[6],
            )
            leaf_attempts = [
                (flags, dir_fd) for path, flags, dir_fd in baseline[2]
                if path == "six.py" and dir_fd in baseline[5]
            ]
            self.assertEqual(1, len(leaf_attempts))
            leaf_flags, _ = leaf_attempts[0]
            self.assertEqual(os.O_RDONLY, leaf_flags & os.O_ACCMODE)
            for required in (os.O_NOFOLLOW, os.O_CLOEXEC, os.O_NONBLOCK):
                self.assertEqual(required, leaf_flags & required)
            for descriptor in baseline[3]:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

            original_metadata = authority_file.lstat()

            def replace_with_symlink():
                authority_file.unlink()
                authority_file.symlink_to("yaml/__init__.py")

            def replace_with_fifo():
                authority_file.unlink()
                os.mkfifo(authority_file)

            def overwrite_same_inode():
                hostile = bytes([authority_payload[0] ^ 1]) + authority_payload[1:]
                writer = os.open(
                    authority_file,
                    os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                )
                try:
                    os.pwrite(writer, hostile, 0)
                    os.fsync(writer)
                finally:
                    os.close(writer)
                os.utime(
                    authority_file,
                    ns=(original_metadata.st_atime_ns, original_metadata.st_mtime_ns),
                )

            for label, attack in (
                ("symlink-rebind", replace_with_symlink),
                ("fifo-rebind", replace_with_fifo),
                ("same-inode-overwrite", overwrite_same_inode),
            ):
                try:
                    outcome = observe_verify(attack)
                    with self.subTest(attack=label):
                        self.assertEqual([True], outcome[7])
                        self.assertIsInstance(outcome[0], AssertionError)
                        self.assertLess(outcome[1], 3)
                        self.assertGreaterEqual(outcome[6].count("read"), 1)
                        for descriptor in outcome[3]:
                            with self.assertRaises(OSError):
                                os.fstat(descriptor)
                finally:
                    if os.path.lexists(authority_file):
                        authority_file.unlink()
                    authority_file.write_bytes(authority_payload)
                    authority_file.chmod(authority_mode)
                verify(capsule)
            with self.assertRaises(AssertionError):
                build(state_root)

            ordinary = capsule / "six.py"
            ordinary_payload = ordinary.read_bytes()
            ordinary_mode = stat.S_IMODE(ordinary.lstat().st_mode)
            native_path = capsule / native[0]
            native_payload = native_path.read_bytes()
            native_mode = stat.S_IMODE(native_path.lstat().st_mode)

            def restore_regular(path, payload, mode):
                if os.path.lexists(path):
                    if path.is_dir() and not path.is_symlink():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                path.chmod(mode)

            mutations = []
            ordinary.unlink()
            mutations.append(("missing", ordinary, ordinary_payload, ordinary_mode))
            for label, path, payload, mode in mutations:
                with self.subTest(mutation=label):
                    with self.assertRaises(AssertionError):
                        verify(capsule)
                    restore_regular(path, payload, mode)
                    verify(capsule)

            hostile = bytes([ordinary_payload[0] ^ 1]) + ordinary_payload[1:]
            ordinary.write_bytes(hostile)
            ordinary.chmod(ordinary_mode)
            with self.assertRaises(AssertionError):
                verify(capsule)
            restore_regular(ordinary, ordinary_payload, ordinary_mode)

            for injected in (
                capsule / "unexpected.py", capsule / "hostile.pth",
                capsule / "sitecustomize.py", capsule / "usercustomize.py",
                capsule / "__pycache__/hostile.cpython-39.pyc",
            ):
                with self.subTest(injected=injected.relative_to(capsule).as_posix()):
                    injected.parent.mkdir(parents=True, exist_ok=True)
                    injected.write_bytes(b"hostile\n")
                    with self.assertRaises(AssertionError):
                        verify(capsule)
                    injected.unlink()
                    if injected.parent.name == "__pycache__":
                        injected.parent.rmdir()
                    verify(capsule)

            ordinary.unlink()
            ordinary.symlink_to("yaml/__init__.py")
            with self.assertRaises(AssertionError):
                verify(capsule)
            restore_regular(ordinary, ordinary_payload, ordinary_mode)
            ordinary.unlink()
            os.mkfifo(ordinary)
            started = time.monotonic()
            with self.assertRaises(AssertionError):
                verify(capsule)
            self.assertLess(time.monotonic() - started, 3)
            restore_regular(ordinary, ordinary_payload, ordinary_mode)

            native_path.write_bytes(b"hostile!" + native_payload[8:])
            native_path.chmod(native_mode)
            with self.assertRaises(AssertionError):
                verify(capsule)
            restore_regular(native_path, native_payload, native_mode)
            verify(capsule)

        with tempfile.TemporaryDirectory(prefix="http-p-capsule-fail-") as directory:
            state_root = Path(directory) / "state"
            state_root.mkdir(mode=0o700)
            failures = []

            def fail_build(path):
                failures.append(Path(path))
                if len(failures) == 2:
                    raise KeyboardInterrupt("capsule source changed")
                return read_source(path)

            with mock.patch.object(
                module, "_read_stable_dependency_source", side_effect=fail_build,
            ), self.assertRaisesRegex(KeyboardInterrupt, "capsule source changed"):
                build(state_root)
            self.assertEqual(2, len(failures))
            self.assertEqual([], list(state_root.iterdir()))

    def _legacy_directory_dependency_capsule_wiring(self):
        module = sys.modules[__name__]
        formal_source = inspect.getsource(
            PublicPublicationWorkflowTests.
            test_p_phase_exact_commit_runs_catalog_in_private_free_clone
        )
        formal_tree = ast.parse(textwrap.dedent(formal_source))
        self.assertEqual((
            "-B", "-m", "unittest", "-v", P_REENTRANT_OUTER_PROBE_FQN,
        ), P_REENTRANT_TEST_PROBE_ARGUMENTS)
        module_tree = ast.parse(Path(__file__).read_bytes(), filename=__file__)
        probe_assignments = [
            node for node in module_tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "P_REENTRANT_TEST_PROBE_ARGUMENTS"
                for target in node.targets
            )
        ]
        self.assertEqual(1, len(probe_assignments))
        self.assertIsInstance(probe_assignments[0].value, ast.Tuple)
        self.assertEqual(5, len(probe_assignments[0].value.elts))
        for hidden_fqn, hidden_name in (
            (P_REENTRANT_OUTER_PROBE_FQN, "_bootstrap_reentry_outer_probe"),
            (P_REENTRANT_FAST_TARGET_FQN, "_bootstrap_reentry_fast_commit_target"),
        ):
            hidden_suite = unittest.defaultTestLoader.loadTestsFromName(hidden_fqn)
            self.assertEqual(1, hidden_suite.countTestCases(), hidden_fqn)
            hidden_tests = list(hidden_suite)
            self.assertEqual(1, len(hidden_tests), hidden_fqn)
            self.assertIsInstance(hidden_tests[0], PublicPublicationWorkflowTests)
            self.assertEqual(hidden_name, hidden_tests[0]._testMethodName)
            self.assertNotIn("_FailedTest", type(hidden_tests[0]).__name__)
        discovered_names = unittest.defaultTestLoader.getTestCaseNames(
            PublicPublicationWorkflowTests
        )
        self.assertEqual(4, len(discovered_names))
        self.assertNotIn("_bootstrap_reentry_outer_probe", discovered_names)
        self.assertNotIn("_bootstrap_reentry_fast_commit_target", discovered_names)
        child_calls = [
            node for node in ast.walk(formal_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_python_run"
        ]
        self.assertEqual(16, len(child_calls))
        for call in child_calls:
            capsule_keywords = [
                keyword.value for keyword in call.keywords
                if keyword.arg == "dependency_capsule"
            ]
            self.assertEqual(1, len(capsule_keywords))
            self.assertIsInstance(capsule_keywords[0], ast.Name)
            self.assertEqual("dependency_capsule", capsule_keywords[0].id)
        builders = [
            node for node in ast.walk(formal_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_build_dependency_capsule"
        ]
        self.assertEqual(1, len(builders))
        self.assertGreaterEqual(
            formal_source.count("_verify_dependency_capsule(dependency_capsule)"),
            2,
        )
        build = getattr(module, "_build_dependency_capsule")
        verify = getattr(module, "_verify_dependency_capsule")
        canonical_env = getattr(module, "_canonical_capsule_python_environment")
        signature = inspect.signature(_python_run)
        self.assertIn("dependency_capsule", signature.parameters)
        self.assertIs(
            inspect.Parameter.empty,
            signature.parameters["dependency_capsule"].default,
        )
        state_parent = tempfile.TemporaryDirectory(prefix="http-p-formal-capsule-")
        state_parent_path = Path(state_parent.name)
        rebuild_guard = None
        forbidden_rebuild = None
        try:
            state_root = state_parent_path / "state"
            state_root.mkdir(mode=0o700)
            capsule = build(state_root)
            rebuild_guard = mock.patch.object(
                module, "_build_dependency_capsule",
                side_effect=AssertionError("formal chain rebuilt its capsule"),
            )
            forbidden_rebuild = rebuild_guard.start()
            verify(capsule)
            hostile = {
                "HOME": "/hostile/home", "PATH": "/hostile/bin",
                "PYTHONHOME": "/hostile/python", "PYTHONPATH": "/hostile/site",
                "PYTHONPYCACHEPREFIX": "/hostile/cache", "PYTHONSTARTUP": "/hostile/start",
                "PYTHONHASHSEED": "hostile", "PYTHONINSPECT": "1",
                "LD_PRELOAD": "/hostile/preload", "LD_AUDIT": "/hostile/audit",
                "LD_HOSTILE_FUTURE": "/hostile/ld-future",
                "DYLD_INSERT_LIBRARIES": "/hostile/dylib",
                "DYLD_HOSTILE_FUTURE": "/hostile/dyld-future",
                "GIT_DIR": "/hostile/git", "GIT_INDEX_FILE": "/hostile/index",
                "GIT_EXEC_PATH": "/hostile/git-exec",
            }
            call_state = state_parent_path / "call-state"
            call_state.mkdir(mode=0o700)
            environment = canonical_env(call_state, capsule, ambient=hostile)
            self.assertEqual(str(capsule), environment["PYTHONPATH"])
            self.assertEqual(str(call_state / "home"), environment["HOME"])
            self.assertEqual(str(call_state / "pycache"), environment["PYTHONPYCACHEPREFIX"])
            self.assertEqual("1", environment["PYTHONNOUSERSITE"])
            self.assertEqual("1", environment["PYTHONDONTWRITEBYTECODE"])
            self.assertEqual(SYSTEM_EXECUTABLE_PATH, environment["PATH"])
            expected_environment_authority = {
                "PYTHONPATH": str(capsule),
                "PYTHONPYCACHEPREFIX": str(call_state / "pycache"),
                "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                "GIT_CONFIG": os.devnull, "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1",
            }
            for key, value in expected_environment_authority.items():
                self.assertEqual(value, environment.get(key))
            for key in hostile:
                if key in expected_environment_authority:
                    self.assertEqual(expected_environment_authority[key], environment[key])
                elif key.startswith(("PYTHON", "LD_", "DYLD_", "GIT_")):
                    self.assertNotIn(key, environment)
            self.assertTrue(all(not key.startswith(("LD_", "DYLD_")) for key in environment))

            capsule_records, _, _, capsule_native = _literal_dependency_capsule_records(
                capsule
            )
            self.assertEqual(P_CAPSULE_FILE_COUNT, len(capsule_records))
            prechild_targets = (capsule / "six.py", capsule / capsule_native[0])
            for target in prechild_targets:
                reviewed_payload = target.read_bytes()
                reviewed_mode = stat.S_IMODE(target.lstat().st_mode)
                hostile_payload = bytes([reviewed_payload[0] ^ 1]) + reviewed_payload[1:]
                target.write_bytes(hostile_payload)
                target.chmod(reviewed_mode)
                child_calls_during_invalid_snapshot = []

                def forbidden_child(*args, **kwargs):
                    child_calls_during_invalid_snapshot.append((args, kwargs))
                    raise AssertionError("child ran with invalid dependency capsule")

                try:
                    with mock.patch.object(subprocess, "run", side_effect=forbidden_child), \
                            self.assertRaises(AssertionError):
                        _python_run(
                            ROOT, ["-B", "-c", "raise SystemExit('unreachable')"],
                            timeout=30, dependency_capsule=capsule,
                        )
                    self.assertEqual([], child_calls_during_invalid_snapshot)
                finally:
                    target.write_bytes(reviewed_payload)
                    target.chmod(reviewed_mode)
                verify(capsule)

            probe = textwrap.dedent("""
                import importlib.metadata as metadata
                import json
                import jinja2, yaml, pandas, openpyxl, xlsxwriter
                import markupsafe, numpy, dateutil, pytz, tzdata, et_xmlfile, six
                modules = {
                    'Jinja2': jinja2, 'PyYAML': yaml, 'pandas': pandas,
                    'openpyxl': openpyxl, 'XlsxWriter': xlsxwriter,
                    'MarkupSafe': markupsafe, 'numpy': numpy,
                    'python-dateutil': dateutil, 'pytz': pytz, 'tzdata': tzdata,
                    'et_xmlfile': et_xmlfile, 'six': six,
                }
                print(json.dumps({
                    name: {'version': metadata.version(name), 'origin': mod.__file__}
                    for name, mod in modules.items()
                }, sort_keys=True))
                print(yaml.safe_load('a: [1, true]'))
                print(pandas.DataFrame({'a': [1]}).to_dict())
            """)
            calls = []
            real_run = subprocess.run

            def observed_run(command, *args, **kwargs):
                if command and command[0] == sys.executable:
                    calls.append((tuple(command), dict(kwargs)))
                return real_run(command, *args, **kwargs)

            with mock.patch.object(subprocess, "run", side_effect=observed_run):
                result = _python_run(
                    ROOT, ["-B", "-c", probe], timeout=60,
                    ambient=hostile, dependency_capsule=capsule,
                )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual("", result.stderr)
            self.assertEqual(1, len(calls))
            command, kwargs = calls[0]
            self.assertEqual((sys.executable, "-S", "-B", "-c", probe), command)
            self.assertEqual(str(capsule), kwargs["env"]["PYTHONPATH"])
            self.assertEqual(subprocess.DEVNULL, kwargs["stdin"])
            self.assertEqual(subprocess.PIPE, kwargs["stdout"])
            self.assertEqual(subprocess.PIPE, kwargs["stderr"])
            self.assertEqual(60, kwargs["timeout"])
            report = json.loads(result.stdout.splitlines()[0])
            self.assertEqual(P_CAPSULE_PACKAGE_VERSIONS, {
                name: value["version"] for name, value in report.items()
            })
            for value in report.values():
                self.assertTrue(Path(value["origin"]).resolve().is_relative_to(capsule))
            self.assertEqual("{'a': [1, True]}", result.stdout.splitlines()[1])
            self.assertEqual("{'a': {0: 1}}", result.stdout.splitlines()[2])

            aba_target = capsule / "six.py"
            aba_reviewed = aba_target.read_bytes()
            aba_hostile = bytes([aba_reviewed[0] ^ 1]) + aba_reviewed[1:]
            aba_events = []

            def mutate_consume_restore(command, *args, **kwargs):
                if command and command[0] == sys.executable and not aba_events:
                    aba_target.write_bytes(aba_hostile)
                    aba_events.append("mutate")
                    try:
                        completed = real_run(command, *args, **kwargs)
                        aba_events.append("consume")
                        return completed
                    finally:
                        aba_target.write_bytes(aba_reviewed)
                        aba_target.chmod(0o644)
                        aba_events.append("restore")
                return real_run(command, *args, **kwargs)

            aba_probe = (
                "import hashlib, pathlib, six, sys; "
                f"expected={hashlib.sha256(aba_reviewed).hexdigest()!r}; "
                "origin=pathlib.Path(six.__file__).resolve(); "
                "actual=hashlib.sha256(origin.read_bytes()).hexdigest(); "
                "raise SystemExit(0 if actual == expected and "
                f"origin.is_relative_to(pathlib.Path({str(capsule)!r})) else 9)"
            )
            aba_failure = None
            aba_result = None
            try:
                with mock.patch.object(
                    subprocess, "run", side_effect=mutate_consume_restore,
                ):
                    aba_result = _python_run(
                        ROOT, ["-B", "-c", aba_probe], timeout=30,
                        dependency_capsule=capsule,
                    )
            except AssertionError as error:
                aba_failure = error
            self.assertEqual(["mutate", "consume", "restore"], aba_events)
            if aba_failure is None:
                self.assertIsNotNone(aba_result)
                self.assertNotEqual(0, aba_result.returncode)
            verify(capsule)

            historical = _python_run(
                ROOT,
                ["-B", "-m", "unittest", "-v", (
                    "test_cases.test_public_s_phase_contract.PublicSPhaseDirectTests."
                    "test_s_manifest_has_exact_forward_and_reverse_closure"
                )],
                timeout=240, dependency_capsule=capsule,
            )
            self.assertEqual(0, historical.returncode, historical.stdout + historical.stderr)
            self.assertEqual(1, historical.stderr.count("Ran 1 test in"))

            with tempfile.TemporaryDirectory(prefix="http-p-capsule-distance2-") as directory:
                repository = Path(directory) / "repository"
                _git_run(ROOT, ["clone", "--quiet", "--no-local", ROOT, repository], check=True)
                (repository / P_LEDGER_PATH).write_bytes(b'{"unapproved":"distance2"}\n')
                _git_run(repository, ["add", "--", P_LEDGER_PATH], check=True)
                _git_run(
                    repository,
                    ["-c", "user.name=P Test", "-c", "user.email=p@test.invalid",
                     "commit", "--quiet", "-m", "unapproved distance2 ledger"],
                    check=True,
                )
                checked = _python_run(
                    repository,
                    ["-B", "test_cases/run_related_tests.py", "--check", "--require-full"],
                    timeout=120, dependency_capsule=capsule,
                )
                self.assertEqual(4, checked.returncode)
                self.assertIn("unapproved source/test state detected", checked.stderr)
                self.assertNotIn("ModuleNotFoundError", checked.stderr)

            mutation_target = capsule / "six.py"
            reviewed = mutation_target.read_bytes()
            mutated = bytes([reviewed[0] ^ 1]) + reviewed[1:]
            mutated_once = []

            def mutate_after_child(command, *args, **kwargs):
                completed = real_run(command, *args, **kwargs)
                if command and command[0] == sys.executable and not mutated_once:
                    mutation_target.write_bytes(mutated)
                    mutated_once.append(True)
                return completed

            try:
                with mock.patch.object(subprocess, "run", side_effect=mutate_after_child), \
                        self.assertRaises(AssertionError):
                    _python_run(
                        ROOT, ["-B", "-c", "print('reviewed child')"], timeout=30,
                        dependency_capsule=capsule,
                    )
                self.assertEqual([True], mutated_once)
            finally:
                mutation_target.write_bytes(reviewed)
                mutation_target.chmod(0o644)
            verify(capsule)
        finally:
            if rebuild_guard is not None:
                rebuild_guard.stop()
            if forbidden_rebuild is not None:
                forbidden_rebuild.assert_not_called()
            capsule_path = state_parent_path / "state/capsule"
            state_parent.cleanup()
        self.assertFalse(os.path.lexists(capsule_path))

    def _bootstrap_reentry_authority_snapshot(self):
        self.assertEqual(
            "1", os.environ.get(P_REENTRANT_ENV_KEYS["marker"]),
            "hidden reentry probes require the authenticated outer protocol",
        )
        required_keys = (
            P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
            *P_REENTRANT_ENV_KEYS.values(),
        )
        self.assertEqual([], [key for key in required_keys if key not in os.environ])
        archive_fd = int(os.environ[P_CAPSULE_FD_ENV])
        archive_fields = os.environ[P_CAPSULE_IDENTITY_ENV].split(":")
        self.assertEqual(4, len(archive_fields))
        archive_metadata = os.fstat(archive_fd)
        self.assertEqual(
            tuple(map(int, archive_fields[:3])),
            (archive_metadata.st_dev, archive_metadata.st_ino, archive_metadata.st_size),
        )
        self.assertEqual(P_CAPSULE_ARCHIVE_SHA256, archive_fields[3])
        self.assertEqual(os.O_RDONLY, fcntl.fcntl(archive_fd, fcntl.F_GETFL) & os.O_ACCMODE)
        self.assertEqual(0, archive_metadata.st_nlink)
        archive_authority = _DependencyArchiveAuthority(
            archive_fd, archive_metadata, archive_fields[3],
        )
        archive_summary = _verify_dependency_archive(archive_authority)

        snapshot = Path(os.environ[P_REENTRANT_ENV_KEYS["snapshot"]]).resolve()
        snapshot_fd = int(os.environ[P_REENTRANT_ENV_KEYS["snapshot_fd"]])
        snapshot_fields = os.environ[P_REENTRANT_ENV_KEYS["snapshot_identity"]].split(":")
        self.assertEqual(3, len(snapshot_fields))
        snapshot_metadata = os.fstat(snapshot_fd)
        snapshot_path_metadata = snapshot.lstat()
        self.assertEqual(
            tuple(map(int, snapshot_fields[:2])),
            (snapshot_metadata.st_dev, snapshot_metadata.st_ino),
        )
        self.assertEqual(
            (snapshot_metadata.st_dev, snapshot_metadata.st_ino),
            (snapshot_path_metadata.st_dev, snapshot_path_metadata.st_ino),
        )
        self.assertEqual(P_CAPSULE_RECORDS_SHA256, snapshot_fields[2])
        snapshot_summary = _verify_dependency_snapshot(snapshot)

        component_rows = json.loads(
            os.environ[P_REENTRANT_ENV_KEYS["python_home_identity"]]
        )
        component_fds = tuple(map(
            int, os.environ[P_REENTRANT_ENV_KEYS["python_home_fds"]].split(","),
        ))
        self.assertEqual(5, len(component_rows))
        self.assertEqual(len(component_rows), len(component_fds))
        for row, descriptor in zip(component_rows, component_fds):
            metadata = os.fstat(descriptor)
            path = Path(row["path"]).resolve()
            path_metadata = path.lstat()
            self.assertEqual(
                (row["dev"], row["ino"]),
                (metadata.st_dev, metadata.st_ino),
            )
            self.assertEqual(
                (metadata.st_dev, metadata.st_ino),
                (path_metadata.st_dev, path_metadata.st_ino),
            )
            self.assertEqual(int(row["mode"], 8), stat.S_IMODE(metadata.st_mode))
            self.assertEqual(os.O_RDONLY, fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE)
        python_home = Path(os.environ[P_REENTRANT_ENV_KEYS["python_home"]]).resolve()
        self.assertEqual(Path(component_rows[1]["path"]).resolve(), python_home)
        python_home_authority = SimpleNamespace(
            state_path=Path(component_rows[0]["path"]).resolve(),
            state_fd=component_fds[0],
            state_identity=(component_rows[0]["dev"], component_rows[0]["ino"]),
            components=tuple(
                (
                    Path(row["path"]).resolve(), descriptor,
                    int(row["mode"], 8), row["dev"], row["ino"],
                )
                for row, descriptor in zip(component_rows[1:], component_fds[1:])
            ),
            closed=False,
        )
        _verify_private_python_home(python_home_authority)
        return {
            "archive_fd": archive_fd,
            "archive_offset": os.lseek(archive_fd, 0, os.SEEK_CUR),
            "archive_summary": archive_summary,
            "snapshot": snapshot,
            "snapshot_fd": snapshot_fd,
            "snapshot_summary": snapshot_summary,
            "python_home": python_home_authority,
            "fds": (archive_fd, snapshot_fd, *component_fds),
            "identities": tuple(
                (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                for descriptor in (archive_fd, snapshot_fd, *component_fds)
            ),
        }

    def _bootstrap_reentry_fast_commit_target(self):
        authority = self._bootstrap_reentry_authority_snapshot()
        head = _head(ROOT)
        self.assertEqual(1, _raw_p_lineage_distance(ROOT, head))
        index_payload = (ROOT / ".git/index").read_bytes()
        ledger_payload = (ROOT / P_LEDGER_PATH).read_bytes()
        module = sys.modules[__name__]
        with mock.patch.object(
            module, "_build_dependency_archive",
            side_effect=AssertionError("reentrant fast target rebuilt archive"),
        ) as forbidden_build, mock.patch.object(
            module, "_extract_dependency_snapshot",
            side_effect=AssertionError("reentrant fast target extracted snapshot"),
        ) as forbidden_extract, mock.patch.object(
            module, "_run_capsule_sandbox",
            side_effect=AssertionError("reentrant fast target nested sandbox"),
        ) as forbidden_sandbox, mock.patch.object(
            module, "_close_private_python_home",
            side_effect=AssertionError("reentrant fast target cleaned inherited PYTHONHOME"),
        ) as forbidden_python_home_cleanup:
            self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
        forbidden_build.assert_not_called()
        forbidden_extract.assert_not_called()
        forbidden_sandbox.assert_not_called()
        forbidden_python_home_cleanup.assert_not_called()
        self.assertEqual(head, _head(ROOT))
        self.assertEqual(index_payload, (ROOT / ".git/index").read_bytes())
        self.assertEqual(ledger_payload, (ROOT / P_LEDGER_PATH).read_bytes())
        self.assertEqual("", _git_run(
            ROOT, ["status", "--porcelain=v1", "--untracked-files=all"],
            text=True, check=True,
        ).stdout)
        self.assertEqual(authority["snapshot_summary"], _verify_dependency_snapshot(authority["snapshot"]))
        _verify_private_python_home(authority["python_home"])
        self.assertEqual(authority["archive_summary"]["archive_sha256"], P_CAPSULE_ARCHIVE_SHA256)
        self.assertEqual(
            authority["archive_offset"],
            os.lseek(authority["archive_fd"], 0, os.SEEK_CUR),
        )
        self.assertEqual(
            authority["identities"],
            tuple(
                (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                for descriptor in authority["fds"]
            ),
        )

    def _bootstrap_reentry_outer_probe(self):
        authority = self._bootstrap_reentry_authority_snapshot()
        head = _head(ROOT)
        self.assertEqual(S_COMMIT, head)
        staged = _git_run(
            ROOT, ["diff", "--cached", "--name-only"], text=True, check=True,
        ).stdout.splitlines()
        self.assertEqual(set(P_PHASE_PRELEDGER_PATHS), set(staged))
        self.assertEqual(P_PRELEDGER_PATH_DIGEST, _path_digest(staged))
        index_payload = (ROOT / ".git/index").read_bytes()
        ledger_payload = (ROOT / P_LEDGER_PATH).read_bytes()
        module = sys.modules[__name__]
        state = authority["snapshot"].parent / "hidden-formal-state"
        with tempfile.TemporaryDirectory(prefix="http-p-reentrant-hidden-") as directory:
            base = Path(directory).resolve()
            overlay = base / "overlay"
            fast_candidate = base / "candidate"
            records = _materialize_staged_overlay(
                overlay, P_PHASE_PRELEDGER_PATHS,
            )
            self.assertEqual(set(P_PHASE_PRELEDGER_PATHS), set(records))
            _git_run(
                ROOT, ["clone", "--quiet", "--no-local", str(ROOT), str(fast_candidate)],
                check=True,
            )
            self.assertEqual(S_COMMIT, _head(fast_candidate))
            for relative, (mode, _kind, _object_id, payload) in records.items():
                _write_materialized_entry(fast_candidate, relative, payload, mode)
            _git_run(fast_candidate, ["add", "--", *P_PHASE_PRELEDGER_PATHS], check=True)
            _git_run(
                fast_candidate,
                ["-c", "user.name=P Reentry", "-c", "user.email=p-reentry@example.invalid",
                 "commit", "--quiet", "-m", "P reentrant fast candidate"],
                check=True,
            )
            self.assertEqual(1, _raw_p_lineage_distance(fast_candidate, _head(fast_candidate)))
            self.assertEqual("", _git_run(
                fast_candidate, ["status", "--porcelain=v1", "--untracked-files=all"],
                text=True, check=True,
            ).stdout)
            with mock.patch.object(
                module, "_build_dependency_archive",
                side_effect=AssertionError("hidden outer rebuilt archive"),
            ) as forbidden_build, mock.patch.object(
                module, "_extract_dependency_snapshot",
                side_effect=AssertionError("hidden outer extracted snapshot"),
            ) as forbidden_extract, mock.patch.object(
                module, "_run_capsule_sandbox",
                side_effect=AssertionError("hidden outer nested sandbox"),
            ) as forbidden_sandbox:
                with _formal_dependency_archive_scope(state) as inherited_archive:
                    result = _formal_test_harness_run(
                        fast_candidate, P_REENTRANT_FAST_TARGET_FQN, timeout=240,
                        dependency_archive=inherited_archive,
                    )
        forbidden_build.assert_not_called()
        forbidden_extract.assert_not_called()
        forbidden_sandbox.assert_not_called()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(1, result.stderr.count("Ran 1 test in"), result.stderr)
        self.assertIn("OK", result.stderr)
        self.assertFalse(os.path.lexists(state))
        self.assertEqual(head, _head(ROOT))
        self.assertEqual(index_payload, (ROOT / ".git/index").read_bytes())
        self.assertEqual(ledger_payload, (ROOT / P_LEDGER_PATH).read_bytes())
        self.assertEqual(authority["snapshot_summary"], _verify_dependency_snapshot(authority["snapshot"]))
        _verify_private_python_home(authority["python_home"])
        self.assertEqual(
            authority["archive_offset"],
            os.lseek(authority["archive_fd"], 0, os.SEEK_CUR),
        )
        self.assertEqual(
            authority["identities"],
            tuple(
                (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                for descriptor in authority["fds"]
            ),
        )

    def test_formal_python_dependency_capsule_is_literal_and_fail_closed(self):
        module = sys.modules[__name__]
        active_fixture = None
        active_fixture_fds = ()
        active_fixture_identities = ()
        active_fixture_offset = None
        if _dependency_reentry_protocol_present():
            active_archive_fd = int(os.environ[P_CAPSULE_FD_ENV])
            active_archive_metadata = os.fstat(active_archive_fd)
            active_archive_fields = os.environ[P_CAPSULE_IDENTITY_ENV].split(":")
            borrowed_archive = _DependencyArchiveAuthority(
                active_archive_fd, active_archive_metadata,
                active_archive_fields[3] if len(active_archive_fields) == 4 else "",
            )
            active_helper = _active_dependency_authority
            with mock.patch.object(
                module, "_active_dependency_authority", wraps=active_helper,
            ) as authenticated_active_helper:
                active_fixture = authenticated_active_helper(borrowed_archive)
            authenticated_active_helper.assert_called_once_with(borrowed_archive)
            self.assertIsNotNone(active_fixture)
            active_fixture_fds = (
                int(os.environ[P_CAPSULE_FD_ENV]),
                int(os.environ[P_REENTRANT_ENV_KEYS["snapshot_fd"]]),
                *map(int, os.environ[
                    P_REENTRANT_ENV_KEYS["python_home_fds"]
                ].split(",")),
            )
            self.assertEqual(active_fixture_fds, active_fixture.source_fds)
            active_fixture_identities = tuple(
                (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                for descriptor in active_fixture_fds
            )
            active_fixture_offset = os.lseek(
                active_archive_fd, 0, os.SEEK_CUR,
            )
        active_fixture_flags = (
            tuple(
                (
                    fcntl.fcntl(descriptor, fcntl.F_GETFL),
                    fcntl.fcntl(descriptor, fcntl.F_GETFD),
                )
                for descriptor in active_fixture_fds
            )
            if active_fixture is not None else ()
        )
        self.assertEqual(24, len(P_CAPSULE_ROOTS))
        self.assertEqual(24, len(set(P_CAPSULE_ROOTS)))
        self.assertEqual(4055, P_CAPSULE_FILE_COUNT)
        self.assertEqual(64164026, P_CAPSULE_TOTAL_BYTES)
        self.assertEqual({"0644": 3986, "0755": 69}, P_CAPSULE_MODE_COUNTS)
        self.assertEqual(65, P_CAPSULE_NATIVE_COUNT)
        self.assertEqual(67287040, P_CAPSULE_ARCHIVE_SIZE)
        self.assertEqual(
            "476c24d7320be00379236313fe7e919aca86dcb0a5bd15877255e012a073eedd",
            P_CAPSULE_ARCHIVE_SHA256,
        )
        self.assertEqual(
            "ecfc714f73eb7e0c5c623bbdd8187b83ce982cf711d68252682fcf073faa56b9",
            P_CAPSULE_RECORDS_SHA256,
        )
        self.assertEqual(426329, P_CAPSULE_LOGICAL_MAPPING_SIZE)
        self.assertEqual(
            "9ea27a2f962493dda35a22aafa1531e77d54622025a7bc7e359f58231195c94b",
            P_CAPSULE_LOGICAL_MAPPING_SHA256,
        )
        self.assertEqual(149, P_CAPSULE_LOGICAL_EXCLUDED_MAPPING_SIZE)
        self.assertEqual(
            "281722980d55ad3c177813d26b1872c0175cc5626c5f92e44bd43dd5d56c98b8",
            P_CAPSULE_LOGICAL_EXCLUDED_MAPPING_SHA256,
        )
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["executable"], str(Path(sys.executable).resolve()))
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["implementation"], platform.python_implementation())
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["version"], sys.version_info[:3])
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["cache_tag"], sys.implementation.cache_tag)
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["platform"], sys.platform)
        self.assertEqual(P_CAPSULE_PYTHON_IDENTITY["machine"], platform.machine())

        resolve_sources = getattr(module, "_resolve_dependency_sources")
        read_source = getattr(module, "_read_stable_dependency_source")
        build = getattr(module, "_build_dependency_archive")
        verify = getattr(module, "_verify_dependency_archive")
        parse = getattr(module, "_parse_dependency_archive")
        register_archive_path = getattr(
            module, "_register_dependency_archive_path",
        )
        logical_mapping = getattr(module, "_canonical_dependency_logical_mapping")
        with tempfile.TemporaryDirectory(prefix="http-p-source-authority-") as directory:
            source = Path(directory) / "reviewed.py"
            reviewed = b"value = 'reviewed'\n"
            hostile = b"value = 'hostile!'\n"
            self.assertEqual(len(reviewed), len(hostile))
            source.write_bytes(reviewed)
            source.chmod(0o644)
            real_open, real_fstat, real_pread = os.open, os.fstat, os.pread
            opened, events, attacked = [], [], []
            source_authority = source.lstat()
            source_identity = (source_authority.st_dev, source_authority.st_ino)
            def source_open(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                opened.append((descriptor, flags))
                return descriptor
            def source_fstat(descriptor):
                result = real_fstat(descriptor)
                if opened and descriptor == opened[0][0]:
                    events.append("fstat")
                    if attacked:
                        result = SimpleNamespace(
                            st_dev=result.st_dev, st_ino=result.st_ino,
                            st_mode=result.st_mode, st_nlink=result.st_nlink,
                            st_size=result.st_size,
                            st_mtime_ns=source_authority.st_mtime_ns,
                            st_ctime_ns=source_authority.st_ctime_ns,
                        )
                return result
            def source_pread(descriptor, size, offset):
                result = real_pread(descriptor, size, offset)
                if opened and descriptor == opened[0][0]:
                    events.append("read")
                    if not attacked:
                        attacked.append(True)
                        before = source.lstat()
                        writer = real_open(
                            source, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        )
                        try:
                            os.pwrite(writer, hostile, 0)
                            os.fsync(writer)
                        finally:
                            os.close(writer)
                        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
                return result
            try:
                with mock.patch.object(os, "open", side_effect=source_open), \
                        mock.patch.object(os, "fstat", side_effect=source_fstat), \
                        mock.patch.object(os, "pread", side_effect=source_pread), \
                        self.assertRaises(AssertionError):
                    read_source(source)
                self.assertEqual([True], attacked)
                self.assertEqual(["fstat", "read", "fstat", "read", "fstat"], events)
                descriptor, flags = opened[0]
                self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
                for required in (os.O_NOFOLLOW, os.O_NONBLOCK, os.O_CLOEXEC):
                    self.assertEqual(required, flags & required)
                self.assertEqual(source_identity, (source.lstat().st_dev, source.lstat().st_ino))
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            finally:
                source.unlink()
                source.write_bytes(reviewed)
                source.chmod(0o644)
            for kind in ("symlink", "fifo"):
                source.unlink()
                if kind == "symlink":
                    source.symlink_to("outside")
                else:
                    os.mkfifo(source)
                started = time.monotonic()
                with self.subTest(source_kind=kind), self.assertRaises(AssertionError):
                    read_source(source)
                self.assertLess(time.monotonic() - started, 3)
        resolved = resolve_sources(P_CAPSULE_ROOTS)
        self.assertEqual(set(P_CAPSULE_ROOTS), set(resolved))
        self.assertEqual(24, len({Path(path).resolve() for path in resolved.values()}))
        for root, source in resolved.items():
            metadata = Path(source).lstat()
            self.assertFalse(Path(source).is_symlink(), root)
            self.assertTrue(stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode), root)

        stable_calls = []
        def observed_source(path):
            payload, mode = read_source(path)
            stable_calls.append((Path(path).resolve(), mode, len(payload), hashlib.sha256(payload).hexdigest()))
            return payload, mode

        with tempfile.TemporaryDirectory(prefix="http-p-anonymous-archive-") as directory:
            state_root = Path(directory) / "state"
            state_root.mkdir(mode=0o700)
            real_open = os.open
            real_fsync = os.fsync
            real_unlink = os.unlink
            build_opens = []
            build_fsyncs = []
            archive_events = []
            archive_timeline = []
            writer_closed_checks = []
            parent_identity_checks = []
            def observed_archive_open(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                build_opens.append((os.fspath(path), flags, descriptor, kwargs.get("dir_fd")))
                return descriptor
            def observed_archive_event(event, **authority):
                archive_events.append((event, dict(authority)))
                archive_timeline.append((event, authority.get("fd") or authority.get("parent_fd")))
                if event == "writer-closed":
                    actual_writer = next(
                        item[2] for item in build_opens
                        if ".ustar" in Path(item[0]).name
                        and item[1] & os.O_ACCMODE == os.O_WRONLY
                    )
                    self.assertEqual(actual_writer, authority["fd"])
                    try:
                        os.fstat(authority["fd"])
                    except OSError:
                        writer_closed_checks.append("EBADF")
                if event == "before-unlink":
                    held = os.fstat(authority["parent_fd"])
                    visible = state_root.lstat()
                    parent_identity_checks.append(
                        (held.st_dev, held.st_ino) == (visible.st_dev, visible.st_ino)
                    )
            def observed_archive_fsync(descriptor):
                build_fsyncs.append(descriptor)
                archive_timeline.append(("fsync", descriptor))
                return real_fsync(descriptor)
            def observed_archive_unlink(path, *args, **kwargs):
                archive_timeline.append(("unlink", kwargs.get("dir_fd")))
                return real_unlink(path, *args, **kwargs)
            with mock.patch.object(module, "_read_stable_dependency_source", side_effect=observed_source), \
                    mock.patch.object(
                        module, "_canonical_dependency_logical_mapping",
                        wraps=logical_mapping,
                    ) as build_logical_mapping, \
                    mock.patch.object(os, "open", side_effect=observed_archive_open), \
                    mock.patch.object(os, "fsync", side_effect=observed_archive_fsync), \
                    mock.patch.object(os, "unlink", side_effect=observed_archive_unlink), \
                    mock.patch.object(module, "_dependency_archive_observer", side_effect=observed_archive_event):
                archive = build(state_root)
            self.assertEqual(
                3 if active_fixture is None else 6,
                build_logical_mapping.call_count,
            )
            self.assertEqual(
                ["writer-opened", "writer-fsync", "writer-closed", "before-reader-open", "reader-opened", "before-unlink", "after-unlink"],
                [event for event, _ in archive_events],
            )
            self.assertEqual(["EBADF"], writer_closed_checks)
            self.assertEqual([True], parent_identity_checks)
            expected_stable_passes = 1 if active_fixture is None else 2
            self.assertEqual(
                P_CAPSULE_FILE_COUNT * expected_stable_passes,
                len(stable_calls),
            )
            stable_passes = tuple(
                tuple(stable_calls[
                    index * P_CAPSULE_FILE_COUNT:
                    (index + 1) * P_CAPSULE_FILE_COUNT
                ])
                for index in range(expected_stable_passes)
            )
            self.assertEqual(expected_stable_passes, len(stable_passes))
            self.assertTrue(all(
                stable_pass == stable_passes[0]
                for stable_pass in stable_passes
            ))
            builder_stable_calls = stable_passes[-1]
            self.assertEqual(
                P_CAPSULE_FILE_COUNT,
                len({call[0] for call in builder_stable_calls}),
            )
            source_roots = (
                {root: Path(source).resolve() for root, source in resolved.items()}
                if active_fixture is None else {
                    root: (active_fixture.snapshot / root).resolve()
                    for root in P_CAPSULE_ROOTS
                }
            )
            self.assertEqual(set(P_CAPSULE_ROOTS), set(source_roots))
            used_roots = set()
            source_mapping = []
            source_authority = {}
            for source_path, mode, size, digest in builder_stable_calls:
                matches = [
                    root for root, source in source_roots.items()
                    if source_path == source or source in source_path.parents
                ]
                self.assertEqual(1, len(matches), source_path)
                self.assertIn(mode, (0o644, 0o755))
                root = matches[0]
                used_roots.add(root)
                source_root = source_roots[root]
                target = root if source_path == source_root else (
                    Path(root) / source_path.relative_to(source_root)
                ).as_posix()
                source_mapping.append({"source": str(source_path), "target": target})
                source_authority[target] = {
                    "mode": f"{mode:04o}", "path": target, "sha256": digest,
                    "size": size, "type": "regular",
                }
            self.assertEqual(set(P_CAPSULE_ROOTS), used_roots)
            mapping_bytes = b"".join(
                (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                for record in sorted(source_mapping, key=lambda record: record["target"])
            )
            if active_fixture is None:
                self.assertEqual(625454, len(mapping_bytes))
                self.assertEqual(P_CAPSULE_SOURCE_MAPPING_SIZE, len(mapping_bytes))
                self.assertEqual(
                    P_CAPSULE_SOURCE_MAPPING_SHA256,
                    hashlib.sha256(mapping_bytes).hexdigest(),
                )
            else:
                self.assertEqual(
                    [str(active_fixture.snapshot / record["target"])
                     for record in sorted(source_mapping, key=lambda item: item["target"])],
                    [record["source"]
                     for record in sorted(source_mapping, key=lambda item: item["target"])],
                )
            def independent_logical_record(target, roots=P_CAPSULE_ROOTS):
                matches = [
                    root for root in roots
                    if target == root or target.startswith(root + "/")
                ]
                self.assertEqual(1, len(matches), target)
                root = matches[0]
                relative = "." if target == root else target[len(root) + 1:]
                self.assertEqual(
                    target,
                    root if relative == "." else f"{root}/{relative}",
                )
                return {"relative": relative, "root": root, "target": target}
            logical_records = tuple(
                independent_logical_record(record["target"])
                for record in sorted(source_mapping, key=lambda record: record["target"])
            )
            logical_bytes = b"".join(
                (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                for record in logical_records
            )
            self.assertEqual(P_CAPSULE_LOGICAL_MAPPING_SIZE, len(logical_bytes))
            self.assertEqual(
                P_CAPSULE_LOGICAL_MAPPING_SHA256,
                hashlib.sha256(logical_bytes).hexdigest(),
            )
            self.assertEqual(
                logical_bytes,
                logical_mapping(logical_records, P_CAPSULE_ROOTS),
            )
            if active_fixture is None:
                excluded = ({
                    "source": str(
                        Path(resolved["numpy"]).resolve()
                        / "distutils/__pycache__/conv_template.cpython-39.pyc"
                    ),
                    "target": P_CAPSULE_EXCLUDED_TARGET,
                },)
                self.assertEqual(1, len(excluded))
                excluded_bytes = b"".join(
                    (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                    for record in excluded
                )
                self.assertEqual(198, len(excluded_bytes))
                self.assertEqual(P_CAPSULE_EXCLUDED_MAPPING_SIZE, len(excluded_bytes))
                self.assertEqual(P_CAPSULE_EXCLUDED_MAPPING_SHA256, hashlib.sha256(excluded_bytes).hexdigest())
                logical_excluded = (
                    independent_logical_record(P_CAPSULE_EXCLUDED_TARGET),
                )
                logical_excluded_bytes = (
                    json.dumps(
                        logical_excluded[0], sort_keys=True, separators=(",", ":"),
                    ) + "\n"
                ).encode("utf-8")
                self.assertEqual(
                    P_CAPSULE_LOGICAL_EXCLUDED_MAPPING_SIZE,
                    len(logical_excluded_bytes),
                )
                self.assertEqual(
                    P_CAPSULE_LOGICAL_EXCLUDED_MAPPING_SHA256,
                    hashlib.sha256(logical_excluded_bytes).hexdigest(),
                )
                self.assertEqual(
                    logical_excluded_bytes,
                    logical_mapping(logical_excluded, P_CAPSULE_ROOTS),
                )
                expected_build_logical_calls = [
                    mock.call(logical_records, P_CAPSULE_ROOTS),
                    mock.call(logical_excluded, P_CAPSULE_ROOTS),
                    mock.call(logical_records, P_CAPSULE_ROOTS),
                ]
            else:
                self.assertFalse(os.path.lexists(
                    active_fixture.snapshot / P_CAPSULE_EXCLUDED_TARGET,
                ))
                expected_build_logical_calls = [
                    mock.call(logical_records, P_CAPSULE_ROOTS),
                    mock.call(logical_records, P_CAPSULE_ROOTS),
                    mock.call(logical_records, P_CAPSULE_ROOTS),
                    mock.call(logical_records, P_CAPSULE_ROOTS),
                    mock.call((), P_CAPSULE_ROOTS),
                    mock.call(logical_records, P_CAPSULE_ROOTS),
                ]
            self.assertEqual(
                expected_build_logical_calls,
                build_logical_mapping.call_args_list,
            )
            if active_fixture is not None:
                self.assertEqual(
                    active_fixture_identities,
                    tuple(
                        (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                        for descriptor in active_fixture_fds
                    ),
                )
                self.assertEqual(
                    active_fixture_flags,
                    tuple(
                        (
                            fcntl.fcntl(descriptor, fcntl.F_GETFL),
                            fcntl.fcntl(descriptor, fcntl.F_GETFD),
                        )
                        for descriptor in active_fixture_fds
                    ),
                )
                self.assertEqual(
                    active_fixture_offset,
                    os.lseek(active_fixture.archive_fd, 0, os.SEEK_CUR),
                )
            logical_hostiles = {
                "duplicate": (*logical_records, logical_records[-1]),
                "unsorted": tuple(reversed(logical_records)),
                "mixed-physical": (
                    {**logical_records[0], "source": "/hostile"},
                ),
                "unknown-root": (
                    {"relative": "x", "root": "unknown", "target": "unknown/x"},
                ),
                "noncanonical-relative": (
                    {"relative": "./x", "root": "numpy", "target": "numpy/x"},
                ),
                "empty-relative-trailing-target": (
                    {"relative": "", "root": "numpy", "target": "numpy/"},
                ),
                "relative-double-separator": (
                    {"relative": "x//y", "root": "numpy", "target": "numpy/x//y"},
                ),
                "relative-dot-component": (
                    {"relative": "x/./y", "root": "numpy", "target": "numpy/x/./y"},
                ),
                "single-non-nfc": (
                    {
                        "relative": unicodedata.normalize("NFD", "caf\u00e9"),
                        "root": "numpy",
                        "target": "numpy/" + unicodedata.normalize("NFD", "caf\u00e9"),
                    },
                ),
                "reconstruct-mismatch": (
                    {"relative": "x", "root": "numpy", "target": "six.py"},
                ),
                "absolute": (
                    {"relative": "x", "root": "numpy", "target": "/x"},
                ),
                "double-separator": (
                    {"relative": "/x", "root": "numpy", "target": "numpy//x"},
                ),
                "dotdot": (
                    {"relative": "../x", "root": "numpy", "target": "numpy/../x"},
                ),
                "backslash": (
                    {"relative": "x\\y", "root": "numpy", "target": "numpy/x\\y"},
                ),
            }
            for label, hostile_records in logical_hostiles.items():
                with self.subTest(logical_mapping=label), self.assertRaises(AssertionError):
                    logical_mapping(hostile_records, P_CAPSULE_ROOTS)
            with self.subTest(logical_mapping="ambiguous-roots"), self.assertRaises(AssertionError):
                logical_mapping(
                    ({"relative": "c", "root": "a/b", "target": "a/b/c"},),
                    ("a", "a/b"),
                )
            for label, collision in (
                ("casefold", ("a/A", "a/a")),
                ("nfc", (
                    "a/caf\u00e9", "a/" + unicodedata.normalize("NFD", "caf\u00e9"),
                )),
            ):
                collision_records = tuple(
                    {"relative": target[2:], "root": "a", "target": target}
                    for target in sorted(collision, key=lambda value: value.encode("utf-8"))
                )
                with self.subTest(logical_mapping=label), self.assertRaises(AssertionError):
                    logical_mapping(collision_records, ("a",))
            self.assertNotIn(P_CAPSULE_EXCLUDED_TARGET, {record["target"] for record in source_mapping})
            poison_state = Path(directory) / "poison-logical-state"
            poison_state.mkdir(mode=0o700)
            def poisoned_logical_mapping(records, roots):
                canonical_mapping = logical_mapping(records, roots)
                if len(records) == P_CAPSULE_FILE_COUNT:
                    return bytes([canonical_mapping[0] ^ 1]) + canonical_mapping[1:]
                return canonical_mapping
            with mock.patch.object(
                module, "_canonical_dependency_logical_mapping",
                side_effect=poisoned_logical_mapping,
            ) as poisoned_builder_mapping, self.assertRaisesRegex(
                AssertionError, "mapping|logical|source",
            ):
                build(poison_state)
            self.assertGreaterEqual(poisoned_builder_mapping.call_count, 1)
            self.assertEqual([], list(poison_state.iterdir()))
            poison_state.rmdir()
            self.assertEqual([], list(state_root.iterdir()))
            descriptor = archive.fd
            metadata = os.fstat(descriptor)
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
            self.assertEqual(os.O_NONBLOCK, flags & os.O_NONBLOCK)
            self.assertEqual(fcntl.FD_CLOEXEC, fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            archive_name_opens = [item for item in build_opens if ".ustar" in Path(item[0]).name]
            self.assertEqual(2, len(archive_name_opens))
            writer_name, writer_flags, writer_fd, writer_parent = archive_name_opens[0]
            reader_name, reader_flags, reader_fd, reader_parent = archive_name_opens[1]
            self.assertEqual(writer_name, reader_name)
            self.assertEqual(writer_parent, reader_parent)
            self.assertIsNotNone(writer_parent)
            parent_open = next(item for item in build_opens if item[2] == writer_parent)
            self.assertEqual(os.O_RDONLY, parent_open[1] & os.O_ACCMODE)
            for required in (os.O_DIRECTORY, os.O_NOFOLLOW, os.O_CLOEXEC):
                self.assertEqual(required, parent_open[1] & required)
            self.assertEqual(os.O_WRONLY, writer_flags & os.O_ACCMODE)
            for required in (os.O_CREAT, os.O_EXCL, os.O_NOFOLLOW, os.O_CLOEXEC):
                self.assertEqual(required, writer_flags & required)
            self.assertEqual(os.O_RDONLY, reader_flags & os.O_ACCMODE)
            for required in (os.O_NOFOLLOW, os.O_NONBLOCK, os.O_CLOEXEC):
                self.assertEqual(required, reader_flags & required)
            self.assertEqual(descriptor, reader_fd)
            self.assertIn(writer_fd, build_fsyncs)
            self.assertIn(writer_parent, build_fsyncs)
            self.assertLess(
                archive_timeline.index(("writer-opened", writer_fd)),
                archive_timeline.index(("fsync", writer_fd)),
            )
            self.assertLess(
                archive_timeline.index(("fsync", writer_fd)),
                archive_timeline.index(("writer-closed", writer_fd)),
            )
            self.assertLess(
                archive_timeline.index(("before-unlink", writer_parent)),
                archive_timeline.index(("unlink", writer_parent)),
            )
            self.assertLess(
                archive_timeline.index(("unlink", writer_parent)),
                archive_timeline.index(("fsync", writer_parent)),
            )
            self.assertLess(
                archive_timeline.index(("fsync", writer_parent)),
                archive_timeline.index(("after-unlink", writer_parent)),
            )
            with self.assertRaises(OSError):
                os.fstat(writer_parent)
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(0o400, stat.S_IMODE(metadata.st_mode))
            self.assertEqual(0, metadata.st_nlink)
            self.assertEqual(P_CAPSULE_ARCHIVE_SIZE, metadata.st_size)
            self.assertEqual((metadata.st_dev, metadata.st_ino), (archive.dev, archive.ino))
            self.assertEqual(P_CAPSULE_ARCHIVE_SHA256, archive.sha256)
            os.lseek(descriptor, 8192, os.SEEK_SET)
            summary = verify(archive)
            self.assertEqual(8192, os.lseek(descriptor, 0, os.SEEK_CUR))
            self.assertEqual(P_CAPSULE_RECORDS_SHA256, summary["records_sha256"])
            self.assertEqual(P_CAPSULE_FILE_COUNT, summary["file_count"])
            self.assertEqual(P_CAPSULE_TOTAL_BYTES, summary["total_bytes"])
            self.assertEqual(P_CAPSULE_MODE_COUNTS, summary["mode_counts"])
            self.assertEqual(P_CAPSULE_NATIVE_COUNT, summary["native_count"])
            self.assertEqual(P_CAPSULE_ARCHIVE_SHA256, summary["archive_sha256"])
            self.assertEqual(P_CAPSULE_ARCHIVE_SIZE, summary["archive_size"])
            self.assertEqual(tuple(P_CAPSULE_ROOTS), summary["roots"])
            self.assertEqual(source_authority, {
                record["path"]: record for record in summary["records"]
            })
            snapshot_logical_records = tuple(
                independent_logical_record(record["path"])
                for record in summary["records"]
            )
            self.assertEqual(logical_records, snapshot_logical_records)
            self.assertEqual(
                logical_bytes,
                logical_mapping(snapshot_logical_records, P_CAPSULE_ROOTS),
            )
            with mock.patch.object(
                module, "_canonical_dependency_logical_mapping",
                return_value=bytes([logical_bytes[0] ^ 1]) + logical_bytes[1:],
            ) as poisoned_archive_mapping, self.assertRaisesRegex(
                AssertionError, "mapping|logical|source",
            ):
                verify(archive)
            poisoned_archive_mapping.assert_called_once()
            with mock.patch.object(
                os, "read", side_effect=AssertionError("archive read must use pread"),
            ) as forbidden_read, mock.patch.object(
                os, "lseek", side_effect=AssertionError("archive read must not move OFD offset"),
            ) as forbidden_seek:
                self.assertEqual(summary, verify(archive))
            forbidden_read.assert_not_called()
            forbidden_seek.assert_not_called()
            verify(archive)
            self.assertEqual(8192, os.lseek(descriptor, 0, os.SEEK_CUR))
            archive.close()
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertEqual([], list(state_root.iterdir()))

        canonical = _independent_ustar((("a.py", 0o644, b"a = 1\n", tarfile.REGTYPE),))
        expected = ({
            "mode": "0644", "path": "a.py", "sha256": hashlib.sha256(b"a = 1\n").hexdigest(),
            "size": 6, "type": "regular",
        },)
        self.assertEqual(expected, parse(canonical, expected_records=expected))

        parse_source = inspect.getsource(parse)
        parse_tree = ast.parse(textwrap.dedent(parse_source))
        history_scans = [
            node for node in ast.walk(parse_tree)
            if isinstance(node, (ast.For, ast.comprehension))
            and isinstance(node.iter, ast.Name) and node.iter.id == "names"
        ]
        self.assertEqual([], history_scans)
        register_calls = [
            node for node in ast.walk(parse_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_register_dependency_archive_path"
        ]
        self.assertEqual(1, len(register_calls))
        final_order_checks = [
            node for node in ast.walk(parse_tree)
            if isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name) and node.left.id == "names"
            and len(node.ops) == 1 and isinstance(node.ops[0], ast.NotEq)
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Call)
            and isinstance(node.comparators[0].func, ast.Name)
            and node.comparators[0].func.id == "sorted"
            and node.comparators[0].args
            and isinstance(node.comparators[0].args[0], ast.Name)
            and node.comparators[0].args[0].id == "names"
        ]
        self.assertEqual(1, len(final_order_checks))

        def assert_registration_failure(accepted, rejected):
            exact_names = set()
            descendant_prefixes = set()
            for name in accepted:
                register_archive_path(
                    name, exact_names, descendant_prefixes,
                )
            before = (exact_names.copy(), descendant_prefixes.copy())
            with self.assertRaisesRegex(
                AssertionError,
                r"\Afile/directory USTAR prefix conflict\Z",
            ):
                register_archive_path(
                    rejected, exact_names, descendant_prefixes,
                )
            self.assertEqual(before[0], exact_names)
            self.assertEqual(before[1], descendant_prefixes)

        assert_registration_failure(("a",), "a/b")
        assert_registration_failure(("a/b",), "a")
        assert_registration_failure(("a", "a-bridge"), "a/b")
        valid_archive_names = ("a/b", "a/c", "x/leaf", "y/leaf")
        valid_exact_names = set()
        valid_descendant_prefixes = set()
        for name in valid_archive_names:
            register_archive_path(
                name, valid_exact_names, valid_descendant_prefixes,
            )
        self.assertEqual(set(valid_archive_names), valid_exact_names)
        self.assertEqual({"a", "x", "y"}, valid_descendant_prefixes)

        class CountingNoIterSet(set):
            def __init__(self):
                super().__init__()
                self.probes = 0
                self.add_calls = 0
                self.update_calls = 0
                self.update_items = 0
                self.iterations = 0
            def __contains__(self, value):
                self.probes += 1
                return super().__contains__(value)
            def __iter__(self):
                self.iterations += 1
                raise AssertionError("archive path set was scanned")
            def add(self, value):
                self.add_calls += 1
                return super().add(value)
            def update(self, values):
                values = tuple(values)
                self.update_calls += 1
                self.update_items += len(values)
                return super().update(values)

        counted_exact_names = CountingNoIterSet()
        counted_descendant_prefixes = CountingNoIterSet()
        for index in range(P_CAPSULE_FILE_COUNT):
            register_archive_path(
                f"package-{index:04d}/leaf.py",
                counted_exact_names, counted_descendant_prefixes,
            )
        self.assertEqual(P_CAPSULE_FILE_COUNT, len(counted_exact_names))
        self.assertEqual(P_CAPSULE_FILE_COUNT, len(counted_descendant_prefixes))
        self.assertEqual(P_CAPSULE_FILE_COUNT, counted_exact_names.probes)
        self.assertEqual(P_CAPSULE_FILE_COUNT, counted_descendant_prefixes.probes)
        self.assertEqual(P_CAPSULE_FILE_COUNT, counted_exact_names.add_calls)
        self.assertEqual(0, counted_exact_names.update_calls)
        self.assertEqual(P_CAPSULE_FILE_COUNT, counted_descendant_prefixes.update_calls)
        self.assertEqual(P_CAPSULE_FILE_COUNT, counted_descendant_prefixes.update_items)
        self.assertEqual(0, counted_exact_names.iterations)
        self.assertEqual(0, counted_descendant_prefixes.iterations)

        valid_archive = _independent_ustar(tuple(
            (name, 0o644, name.encode("ascii"), tarfile.REGTYPE)
            for name in valid_archive_names
        ))
        observed_registered_names = []
        def observe_registered_name(name, exact_names, descendant_prefixes):
            observed_registered_names.append(name)
            return register_archive_path(
                name, exact_names, descendant_prefixes,
            )
        with mock.patch.object(
            module, "_register_dependency_archive_path",
            side_effect=observe_registered_name,
        ) as observed_register:
            parsed_valid_archive = parse(valid_archive)
        self.assertEqual(valid_archive_names, tuple(observed_registered_names))
        self.assertEqual(len(valid_archive_names), observed_register.call_count)
        self.assertEqual(
            valid_archive_names,
            tuple(record["path"] for record in parsed_valid_archive),
        )

        normalized_duplicate = _independent_ustar((
            ("A.py", 0o644, b"a", tarfile.REGTYPE),
            ("a.py", 0o644, b"b", tarfile.REGTYPE),
        ))
        with mock.patch.object(
            module, "_register_dependency_archive_path",
            wraps=register_archive_path,
        ) as collision_register, self.assertRaisesRegex(
            AssertionError, r"\Acolliding USTAR member names\Z",
        ):
            parse(normalized_duplicate)
        self.assertEqual(1, collision_register.call_count)

        def mutate_header(stream, offset, replacement):
            result = bytearray(stream)
            result[offset:offset + len(replacement)] = replacement
            result[148:156] = b"        "
            result[148:156] = f"{sum(result[:512]):06o}\0 ".encode("ascii")
            return bytes(result)

        malformed = {
            "checksum": bytes([canonical[0] ^ 1]) + canonical[1:],
            "truncated": canonical[:-1],
            "trailing": canonical + b"x",
            "noncanonical-mode": mutate_header(canonical, 100, b"0000644 "),
            "noncanonical-size": mutate_header(canonical, 124, b"00000000006 "),
            "overflow-size": mutate_header(canonical, 124, b"77777777777\0"),
            "duplicate": _independent_ustar((
                ("a.py", 0o644, b"a = 1\n", tarfile.REGTYPE),
                ("a.py", 0o644, b"a = 1\n", tarfile.REGTYPE),
            )),
            "prefix-conflict": _independent_ustar((
                ("a", 0o644, b"x", tarfile.REGTYPE),
                ("a/b", 0o644, b"y", tarfile.REGTYPE),
            )),
            "nonadjacent-prefix-conflict": _independent_ustar((
                ("a", 0o644, b"x", tarfile.REGTYPE),
                ("a-bridge", 0o644, b"z", tarfile.REGTYPE),
                ("a/b", 0o644, b"y", tarfile.REGTYPE),
            )),
            "reverse-prefix-conflict": _independent_ustar((
                ("a/b", 0o644, b"y", tarfile.REGTYPE),
                ("a", 0o644, b"x", tarfile.REGTYPE),
            )),
            "unsorted": _independent_ustar((
                ("z.py", 0o644, b"z", tarfile.REGTYPE),
                ("a.py", 0o644, b"a", tarfile.REGTYPE),
            )),
            "casefold": _independent_ustar((
                ("A.py", 0o644, b"x", tarfile.REGTYPE),
                ("a.py", 0o644, b"y", tarfile.REGTYPE),
            )),
            "nfc": _independent_ustar((
                ("caf\u00e9", 0o644, b"x", tarfile.REGTYPE),
                (unicodedata.normalize("NFD", "caf\u00e9"), 0o644, b"y", tarfile.REGTYPE),
            )),
        }
        for name in ("", ".", "..", "/absolute", "a/../b", "a\\b"):
            malformed[f"path-{name!r}"] = _independent_ustar(((name, 0o644, b"x", tarfile.REGTYPE),))
        for label, kind in (
            ("directory", tarfile.DIRTYPE), ("hardlink", tarfile.LNKTYPE),
            ("symlink", tarfile.SYMTYPE), ("character", tarfile.CHRTYPE),
            ("block", tarfile.BLKTYPE), ("fifo", tarfile.FIFOTYPE),
            ("pax", tarfile.XHDTYPE), ("gnu-longname", tarfile.GNUTYPE_LONGNAME),
            ("gnu-sparse", tarfile.GNUTYPE_SPARSE),
        ):
            malformed[label] = _independent_ustar((("a.py", 0o644, b"x", kind),))
        malformed["nul-name"] = mutate_header(canonical, 1, b"\0hostile")
        malformed["invalid-utf8"] = mutate_header(canonical, 0, b"\xff.py\0")
        malformed["uid"] = mutate_header(canonical, 108, b"0000001\0")
        malformed["gid"] = mutate_header(canonical, 116, b"0000001\0")
        malformed["mtime"] = mutate_header(canonical, 136, b"00000000001\0")
        malformed["uname"] = mutate_header(canonical, 265, b"owner\0")
        malformed["gname"] = mutate_header(canonical, 297, b"group\0")
        malformed["linkname"] = mutate_header(canonical, 157, b"target\0")
        malformed["devmajor"] = mutate_header(canonical, 329, b"0000001\0")
        malformed["devminor"] = mutate_header(canonical, 337, b"0000001\0")
        malformed["prefix"] = mutate_header(canonical, 345, b"prefix\0")
        malformed["magic"] = mutate_header(canonical, 257, b"ustar ")
        malformed["version"] = mutate_header(canonical, 263, b"01")
        malformed["wrong-supported-mode"] = mutate_header(canonical, 100, b"0000755\0")
        for hostile_path in ("./a.py", "a//b.py", "a.py/"):
            malformed[f"separator-{hostile_path}"] = _independent_ustar((
                (hostile_path, 0o644, b"x", tarfile.REGTYPE),
            ))
        malformed["payload-padding"] = canonical[:518] + b"X" + canonical[519:]
        malformed["end-padding"] = canonical[:-1] + b"X"
        for label, payload in malformed.items():
            with self.subTest(malformed_archive=label), self.assertRaises(AssertionError):
                parse(payload, expected_records=expected)

        with tempfile.TemporaryDirectory(prefix="http-p-archive-fail-") as directory:
            state_root = Path(directory) / "state"
            state_root.mkdir(mode=0o700)
            for event in (
                "writer-opened", "writer-fsync", "writer-closed", "reader-opened",
                "before-reader-open", "before-unlink", "after-unlink",
            ):
                reached = []
                failed_fds = []
                def fail_boundary(observed, **authority):
                    if observed == event:
                        reached.append(observed)
                        raise KeyboardInterrupt(event)
                def capture_failed_open(path, flags, *args, **kwargs):
                    descriptor = real_open(path, flags, *args, **kwargs)
                    failed_fds.append(descriptor)
                    return descriptor
                with self.subTest(archive_boundary=event), mock.patch.object(
                    module, "_dependency_archive_observer", side_effect=fail_boundary,
                ), mock.patch.object(
                    os, "open", side_effect=capture_failed_open,
                ), self.assertRaisesRegex(KeyboardInterrupt, event):
                    build(state_root)
                self.assertEqual([event], reached)
                self.assertEqual([], list(state_root.iterdir()))
                for descriptor in failed_fds:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
            for replacement in ("regular", "symlink", "fifo"):
                attacked = []
                attack_fds = []
                attack_started = []
                def rebind_named_archive(event, **authority):
                    if event != "before-reader-open" or attacked:
                        return
                    name = authority["name"]
                    parent_fd = authority["parent_fd"]
                    os.unlink(name, dir_fd=parent_fd)
                    if replacement == "regular":
                        hostile_fd = real_open(
                            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                            0o400, dir_fd=parent_fd,
                        )
                        os.ftruncate(hostile_fd, P_CAPSULE_ARCHIVE_SIZE)
                        os.close(hostile_fd)
                    elif replacement == "symlink":
                        os.symlink("outside", name, dir_fd=parent_fd)
                    else:
                        os.mkfifo(state_root / name)
                    attacked.append((name, parent_fd))
                    attack_started.append(time.monotonic())
                def capture_attack_fd(path, flags, *args, **kwargs):
                    descriptor = real_open(path, flags, *args, **kwargs)
                    attack_fds.append(descriptor)
                    return descriptor
                with self.subTest(archive_rebind=replacement), mock.patch.object(
                    module, "_dependency_archive_observer", side_effect=rebind_named_archive,
                ), mock.patch.object(
                    os, "open", side_effect=capture_attack_fd,
                ), self.assertRaises(AssertionError):
                    build(state_root)
                self.assertEqual(1, len(attacked))
                self.assertEqual(1, len(attack_started))
                self.assertLess(time.monotonic() - attack_started[0], 3)
                self.assertEqual([], list(state_root.iterdir()))
                for descriptor in attack_fds:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
            archive_outside = Path(directory) / "outside"
            archive_outside.mkdir(mode=0o700)
            (archive_outside / "sentinel").write_bytes(b"outside-trusted\n")
            outside_snapshot = (archive_outside / "sentinel").read_bytes()
            parent_rebound = []
            held_state = state_root.with_name("state-held")
            def rebind_archive_parent(event, **authority):
                if event == "before-unlink" and not parent_rebound:
                    state_root.rename(held_state)
                    state_root.symlink_to(archive_outside, target_is_directory=True)
                    parent_rebound.append(True)
            with mock.patch.object(
                module, "_dependency_archive_observer", side_effect=rebind_archive_parent,
            ), self.assertRaises(AssertionError):
                build(state_root)
            self.assertEqual([True], parent_rebound)
            self.assertEqual(outside_snapshot, (archive_outside / "sentinel").read_bytes())
            self.assertTrue(state_root.is_symlink())
            self.assertTrue(held_state.is_dir())
            self.assertEqual([], list(held_state.iterdir()))
            state_root.unlink()
            held_state.rmdir()
            archive_outside.joinpath("sentinel").unlink()
            archive_outside.rmdir()

    def test_formal_children_share_one_isolated_dependency_capsule(self):
        module = sys.modules[__name__]
        loopback_scope = getattr(module, "_formal_loopback_sshd_scope")
        loopback_consumer = getattr(
            module, "_formal_loopback_sshd_authority_from_environment",
        )
        loopback_observer = getattr(module, "_formal_loopback_sshd_observer")
        active_fixture = None
        active_fixture_fds = ()
        active_fixture_identities = ()
        active_fixture_offset = None
        active_fixture_environment = None
        active_fixture_loopback_marker = None
        active_inherited_loopback_identity = None
        active_inherited_loopback_value = None
        active_inherited_loopback_pgid = None
        borrowed_archive = None
        if _dependency_reentry_protocol_present():
            active_protocol_keys = (
                P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
                *P_REENTRANT_ENV_KEYS.values(),
            )
            self.assertEqual(9, len(active_protocol_keys))
            active_fixture_environment = {
                key: os.environ[key] for key in active_protocol_keys
            }
            active_fixture_loopback_marker = os.environ[
                P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV
            ]
            self.assertEqual("1", active_fixture_loopback_marker)
            active_archive_fd = int(os.environ[P_CAPSULE_FD_ENV])
            active_archive_metadata = os.fstat(active_archive_fd)
            active_archive_fields = os.environ[P_CAPSULE_IDENTITY_ENV].split(":")
            borrowed_archive = _DependencyArchiveAuthority(
                active_archive_fd, active_archive_metadata,
                active_archive_fields[3] if len(active_archive_fields) == 4 else "",
            )
            active_helper = _active_dependency_authority
            with mock.patch.object(
                module, "_active_dependency_authority", wraps=active_helper,
            ) as authenticated_active_helper:
                active_fixture = authenticated_active_helper(borrowed_archive)
            authenticated_active_helper.assert_called_once_with(borrowed_archive)
            self.assertIsNotNone(active_fixture)
            active_fixture_fds = (
                int(os.environ[P_CAPSULE_FD_ENV]),
                int(os.environ[P_REENTRANT_ENV_KEYS["snapshot_fd"]]),
                *map(int, os.environ[
                    P_REENTRANT_ENV_KEYS["python_home_fds"]
                ].split(",")),
            )
            self.assertEqual(active_fixture_fds, active_fixture.source_fds)
            active_fixture_identities = tuple(
                (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                for descriptor in active_fixture_fds
            )
            active_fixture_offset = os.lseek(
                active_archive_fd, 0, os.SEEK_CUR,
            )
            with mock.patch.dict(os.environ, {
                P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "1",
            }, clear=False), mock.patch.object(
                module, "_active_dependency_authority", wraps=active_helper,
            ) as authenticated_loopback_helper:
                inherited_loopback = loopback_consumer()
            authenticated_loopback_helper.assert_called_once()
            self.assertEqual(
                active_fixture.snapshot.parent
                / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE,
                inherited_loopback.root,
            )
            self.assertEqual(active_fixture.source_fds, inherited_loopback.source_fds)
            active_inherited_loopback_identity = (
                inherited_loopback.root.lstat().st_dev,
                inherited_loopback.root.lstat().st_ino,
            )
            active_inherited_loopback_value = (
                inherited_loopback.root, inherited_loopback.port,
                inherited_loopback.daemon_pid,
                dict(inherited_loopback.public_keys),
                dict(inherited_loopback.fingerprints),
                inherited_loopback.source_fds,
            )
            active_inherited_loopback_pgid = os.getpgid(
                inherited_loopback.daemon_pid,
            )
        active_fixture_flags = (
            tuple(
                (
                    fcntl.fcntl(descriptor, fcntl.F_GETFL),
                    fcntl.fcntl(descriptor, fcntl.F_GETFD),
                )
                for descriptor in active_fixture_fds
            )
            if active_fixture is not None else ()
        )
        build = getattr(module, "_build_dependency_archive")
        verify_archive = getattr(module, "_verify_dependency_archive")
        extract = getattr(module, "_extract_dependency_snapshot")
        verify_snapshot = getattr(module, "_verify_dependency_snapshot")
        create_python_home = getattr(module, "_create_private_python_home")
        verify_python_home = getattr(module, "_verify_private_python_home")
        close_python_home = getattr(module, "_close_private_python_home")
        canonical_env = getattr(module, "_canonical_capsule_python_environment")
        canonical_plain_env = getattr(module, "_canonical_python_environment")
        formal_scope = getattr(module, "_formal_dependency_archive_scope")
        adopt = getattr(module, "_adopt_dependency_archive_from_environment")
        formal_harness = getattr(module, "_formal_test_harness_run")
        run_sandbox = getattr(module, "_run_capsule_sandbox")
        run_harness_process = getattr(module, "_run_formal_harness_process")
        run_bounded = getattr(module, "_run_bounded_process")
        read_source = getattr(module, "_read_stable_dependency_source")
        resolved = getattr(module, "_resolve_dependency_sources")(P_CAPSULE_ROOTS)
        logical_mapping = getattr(module, "_canonical_dependency_logical_mapping")
        formal_source = inspect.getsource(
            PublicPublicationWorkflowTests.test_p_phase_exact_commit_runs_catalog_in_private_free_clone
        )
        formal_tree = ast.parse(textwrap.dedent(formal_source))
        self.assertEqual((
            "-B", "-m", "unittest", "-v", P_REENTRANT_OUTER_PROBE_FQN,
        ), P_REENTRANT_TEST_PROBE_ARGUMENTS)
        module_tree = ast.parse(Path(__file__).read_bytes(), filename=__file__)
        probe_assignments = [
            node for node in module_tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "P_REENTRANT_TEST_PROBE_ARGUMENTS"
                for target in node.targets
            )
        ]
        self.assertEqual(1, len(probe_assignments))
        self.assertIsInstance(probe_assignments[0].value, ast.Tuple)
        self.assertEqual(5, len(probe_assignments[0].value.elts))
        for hidden_fqn, hidden_name in (
            (P_REENTRANT_OUTER_PROBE_FQN, "_bootstrap_reentry_outer_probe"),
            (P_REENTRANT_FAST_TARGET_FQN, "_bootstrap_reentry_fast_commit_target"),
        ):
            hidden_suite = unittest.defaultTestLoader.loadTestsFromName(hidden_fqn)
            self.assertEqual(1, hidden_suite.countTestCases(), hidden_fqn)
            hidden_tests = list(hidden_suite)
            self.assertEqual(1, len(hidden_tests), hidden_fqn)
            self.assertIsInstance(hidden_tests[0], PublicPublicationWorkflowTests)
            self.assertEqual(hidden_name, hidden_tests[0]._testMethodName)
            self.assertNotIn("_FailedTest", type(hidden_tests[0]).__name__)
        discovered_names = unittest.defaultTestLoader.getTestCaseNames(
            PublicPublicationWorkflowTests
        )
        self.assertEqual(4, len(discovered_names))
        self.assertNotIn("_bootstrap_reentry_outer_probe", discovered_names)
        self.assertNotIn("_bootstrap_reentry_fast_commit_target", discovered_names)
        scopes = [
            node for node in ast.walk(formal_tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_formal_dependency_archive_scope"
        ]
        self.assertEqual(1, len(scopes))
        self.assertEqual([], [
            node for node in ast.walk(formal_tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "_build_dependency_archive"
        ])
        child_calls = [
            node for node in ast.walk(formal_tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "_python_run"
        ]
        self.assertEqual(16, len(child_calls))
        for call in child_calls:
            values = [keyword.value for keyword in call.keywords if keyword.arg == "dependency_archive"]
            self.assertEqual(1, len(values))
            self.assertIsInstance(values[0], ast.Name)
            self.assertEqual("dependency_archive", values[0].id)
        actual_runner_argument_nodes = [
            ast.dump(call.args[1], include_attributes=False)
            for call in child_calls if len(call.args) >= 2
        ]
        self.assertEqual(1500, P_FORMAL_SUITE_TIMEOUT_SECONDS)
        reviewed_formal_suite_expressions = (
            "[*runner, '--all', '-v']",
            "[*final_runner, '--suite', repository_suite['id'], '-v']",
            "[*final_runner, '--all', '--no-approve', '-v']",
        )
        reviewed_formal_suite_nodes = []
        for reviewed_expression in reviewed_formal_suite_expressions:
            reviewed_node = ast.parse(reviewed_expression, mode="eval").body
            reviewed_dump = ast.dump(reviewed_node, include_attributes=False)
            reviewed_formal_suite_nodes.append(reviewed_dump)
            self.assertEqual(
                1,
                actual_runner_argument_nodes.count(reviewed_dump),
                reviewed_expression,
            )
        reviewed_formal_suite_calls = [
            call for call in child_calls if len(call.args) >= 2
            and ast.dump(call.args[1], include_attributes=False)
            in reviewed_formal_suite_nodes
        ]
        self.assertEqual(3, len(reviewed_formal_suite_calls))
        for call in reviewed_formal_suite_calls:
            timeout_values = [
                keyword.value for keyword in call.keywords
                if keyword.arg == "timeout"
            ]
            self.assertEqual(1, len(timeout_values))
            self.assertIsInstance(timeout_values[0], ast.Name)
            self.assertEqual(
                "P_FORMAL_SUITE_TIMEOUT_SECONDS", timeout_values[0].id,
            )
        signature = inspect.signature(_python_run)
        self.assertIn("dependency_archive", signature.parameters)
        self.assertIs(inspect.Parameter.empty, signature.parameters["dependency_archive"].default)
        self.assertNotIn("os.system", inspect.getsource(_python_run))
        with_nodes = [node for node in ast.walk(formal_tree) if isinstance(node, ast.With)]
        self.assertTrue(any(
            any(
                isinstance(item.context_expr, ast.Call)
                and isinstance(item.context_expr.func, ast.Name)
                and item.context_expr.func.id == "_formal_dependency_archive_scope"
                for item in node.items
            )
            for node in with_nodes
        ))

        # A formal runner may not start sshd inside the Darwin seatbelt.  The
        # parent owns one fixed-location loopback fixture and the child merely
        # authenticates it through the already-reviewed dependency authority.
        # The marker is routing only: it is useless without the complete active
        # nine-key protocol and the held snapshot/PYHOME/archive descriptors.
        hostile_loopback = {
            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "/hostile/fixture",
        }
        with tempfile.TemporaryDirectory(
            prefix="http-p-loopback-contract-",
        ) as loopback_directory:
            loopback_state = Path(loopback_directory).resolve() / "state"
            loopback_state.mkdir(mode=0o700)
            scrubbed = canonical_env(
                loopback_state, None, ambient=hostile_loopback,
            )
            self.assertNotIn(P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV, scrubbed)
            plain_state = Path(loopback_directory).resolve() / "plain-state"
            plain_state.mkdir(mode=0o700)
            plain_scrubbed = canonical_plain_env(
                plain_state, ambient=hostile_loopback,
            )
            self.assertNotIn(
                P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV, plain_scrubbed,
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertIsNone(loopback_consumer())
            for hostile_marker in ("", "0", "true", "/hostile/fixture"):
                with self.subTest(loopback_marker=hostile_marker), \
                        mock.patch.dict(os.environ, {
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: hostile_marker,
                        }, clear=True), self.assertRaises(AssertionError):
                    loopback_consumer()
            for partial_name, partial_key in P_REENTRANT_ENV_KEYS.items():
                with self.subTest(loopback_partial_protocol=partial_name), \
                        mock.patch.dict(os.environ, {
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "1",
                            partial_key: "hostile-partial",
                        }, clear=True), self.assertRaises(AssertionError):
                    loopback_consumer()

            def assert_loopback_authority(loopback, expected_state):
                self.assertEqual(
                    expected_state / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE,
                    loopback.root,
                )
                root_metadata = loopback.root.lstat()
                self.assertTrue(stat.S_ISDIR(root_metadata.st_mode))
                self.assertEqual(0o700, stat.S_IMODE(root_metadata.st_mode))
                self.assertEqual(10, root_metadata.st_nlink)
                self.assertIsInstance(loopback.port, int)
                self.assertGreater(loopback.port, 0)
                self.assertLess(loopback.port, 65536)
                self.assertGreater(loopback.daemon_pid, 0)
                self.assertEqual(
                    loopback.root / "authority.json", loopback.manifest,
                )
                self.assertEqual(loopback.root / "sshd.stderr", loopback.daemon_log)
                self.assertEqual(
                    {"ed25519", "rsa"}, set(loopback.public_keys),
                )
                self.assertEqual(
                    {"ed25519", "rsa"}, set(loopback.fingerprints),
                )
                self.assertEqual(
                    "ssh-ed25519", loopback.public_keys["ed25519"].split()[0],
                )
                self.assertEqual(
                    "ssh-rsa", loopback.public_keys["rsa"].split()[0],
                )
                for fingerprint in loopback.fingerprints.values():
                    self.assertRegex(
                        fingerprint, r"\ASHA256:[A-Za-z0-9+/]{43}\Z",
                    )
                expected_held_paths = (
                    loopback.root,
                    loopback.root / "host-ed25519",
                    loopback.root / "host-ed25519.pub",
                    loopback.root / "host-rsa",
                    loopback.root / "host-rsa.pub",
                    loopback.root / "sshd_config",
                    loopback.root / "authority.json",
                    loopback.root / "sshd.stderr",
                )
                expected_held_modes = (
                    0o700, 0o600, 0o644, 0o600, 0o644, 0o600, 0o400, 0o600,
                )
                expected_held_types = (
                    stat.S_IFDIR,
                    *(stat.S_IFREG for _path in expected_held_paths[1:]),
                )
                expected_children = {
                    "authority.json", "host-ed25519", "host-ed25519.pub",
                    "host-rsa", "host-rsa.pub", "sshd.pid", "sshd.stderr",
                    "sshd_config",
                }
                self.assertEqual(
                    expected_children, set(os.listdir(loopback.held_fds[0])),
                )
                expected_held_nlinks = (10, 1, 1, 1, 1, 1, 1, 1)
                self.assertEqual(
                    2 + len(expected_children), expected_held_nlinks[0],
                )
                self.assertEqual(expected_held_paths, tuple(loopback.held_paths))
                self.assertEqual(8, len(loopback.held_fds))
                self.assertEqual(
                    len(loopback.held_fds), len(set(loopback.held_fds)),
                )
                self.assertEqual(
                    len(loopback.held_fds), len(loopback.held_identities),
                )
                self.assertEqual(
                    len(loopback.held_identities),
                    len(set(loopback.held_identities)),
                )
                def stable_metadata(metadata):
                    return (
                        metadata.st_dev, metadata.st_ino, metadata.st_mode,
                        metadata.st_nlink, metadata.st_size,
                        metadata.st_mtime_ns, metadata.st_ctime_ns,
                    )
                for path, descriptor, identity, expected_mode, expected_type, \
                        expected_nlink in zip(
                    loopback.held_paths, loopback.held_fds,
                    loopback.held_identities, expected_held_modes,
                    expected_held_types, expected_held_nlinks,
                ):
                    metadata = os.fstat(descriptor)
                    named = path.lstat()
                    self.assertEqual(
                        (metadata.st_dev, metadata.st_ino), identity,
                    )
                    self.assertEqual(
                        identity, (named.st_dev, named.st_ino),
                    )
                    self.assertEqual(expected_type, stat.S_IFMT(metadata.st_mode))
                    self.assertEqual(expected_type, stat.S_IFMT(named.st_mode))
                    self.assertEqual(expected_mode, stat.S_IMODE(metadata.st_mode))
                    self.assertEqual(expected_nlink, metadata.st_nlink)
                    self.assertEqual(expected_nlink, named.st_nlink)
                    self.assertEqual(
                        os.O_RDONLY,
                        fcntl.fcntl(descriptor, fcntl.F_GETFL)
                        & os.O_ACCMODE,
                    )
                    self.assertTrue(
                        fcntl.fcntl(descriptor, fcntl.F_GETFD)
                        & fcntl.FD_CLOEXEC,
                    )
                pid_fd = os.open(
                    "sshd.pid",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=loopback.held_fds[0],
                )
                try:
                    pid_before = os.fstat(pid_fd)
                    pid_named = (loopback.root / "sshd.pid").lstat()
                    pid_first = os.pread(pid_fd, pid_before.st_size + 1, 0)
                    pid_middle = os.fstat(pid_fd)
                    pid_second = os.pread(pid_fd, pid_middle.st_size + 1, 0)
                    pid_after = os.fstat(pid_fd)
                    self.assertTrue(stat.S_ISREG(pid_before.st_mode))
                    self.assertEqual(0o644, stat.S_IMODE(pid_before.st_mode))
                    self.assertEqual(1, pid_before.st_nlink)
                    self.assertEqual(
                        (pid_before.st_dev, pid_before.st_ino),
                        (pid_named.st_dev, pid_named.st_ino),
                    )
                    self.assertEqual(
                        f"{loopback.daemon_pid}\n".encode("ascii"), pid_first,
                    )
                    self.assertEqual(pid_first, pid_second)
                    self.assertEqual(
                        stable_metadata(pid_before), stable_metadata(pid_middle),
                    )
                    self.assertEqual(
                        stable_metadata(pid_before), stable_metadata(pid_after),
                    )
                finally:
                    os.close(pid_fd)
                root_before = stable_metadata(os.fstat(loopback.held_fds[0]))
                self.assertEqual(
                    root_before,
                    stable_metadata(loopback.held_paths[0].lstat()),
                )
                held_payloads = {}
                for path, descriptor in zip(
                    loopback.held_paths[1:8], loopback.held_fds[1:8],
                ):
                    before = os.fstat(descriptor)
                    first = os.pread(descriptor, before.st_size + 1, 0)
                    middle = os.fstat(descriptor)
                    second = os.pread(descriptor, middle.st_size + 1, 0)
                    after = os.fstat(descriptor)
                    self.assertEqual(before.st_size, len(first), str(path))
                    self.assertEqual(first, second, str(path))
                    held_payloads[path] = first
                    self.assertEqual(
                        stable_metadata(before), stable_metadata(middle), str(path),
                    )
                    self.assertEqual(
                        stable_metadata(before), stable_metadata(after), str(path),
                    )
                    self.assertEqual(
                        stable_metadata(after),
                        stable_metadata(path.lstat()),
                        str(path),
                    )
                self.assertEqual(
                    loopback.public_keys["ed25519"].encode("utf-8"),
                    held_payloads[loopback.root / "host-ed25519.pub"],
                )
                self.assertEqual(
                    loopback.public_keys["rsa"].encode("utf-8"),
                    held_payloads[loopback.root / "host-rsa.pub"],
                )
                for key_name, public_name in (
                    ("ed25519", "host-ed25519.pub"),
                    ("rsa", "host-rsa.pub"),
                ):
                    public_fields = held_payloads[
                        loopback.root / public_name
                    ].split()
                    self.assertGreaterEqual(len(public_fields), 2)
                    independent_fingerprint = "SHA256:" + base64.b64encode(
                        hashlib.sha256(
                            base64.b64decode(public_fields[1])
                        ).digest()
                    ).rstrip(b"=").decode("ascii")
                    self.assertEqual(
                        loopback.fingerprints[key_name], independent_fingerprint,
                    )
                manifest_index = expected_held_paths.index(loopback.manifest)
                manifest_fd = loopback.held_fds[manifest_index]
                manifest_before = os.fstat(manifest_fd)
                manifest_bytes = held_payloads[loopback.manifest]
                self.assertEqual(
                    manifest_bytes,
                    os.pread(manifest_fd, manifest_before.st_size + 1, 0),
                )
                self.assertEqual(manifest_before, os.fstat(manifest_fd))
                manifest = json.loads(manifest_bytes)
                self.assertEqual(
                    manifest_bytes,
                    json.dumps(
                        manifest, sort_keys=True, separators=(",", ":"),
                    ).encode("utf-8") + b"\n",
                )
                expected_manifest = {
                    "daemon_log": "sshd.stderr",
                    "fingerprints": dict(loopback.fingerprints),
                    "pid": loopback.daemon_pid,
                    "port": loopback.port,
                    "public_keys": {
                        "ed25519": {
                            "name": "host-ed25519.pub",
                            "sha256": hashlib.sha256(
                                loopback.public_keys["ed25519"].encode("utf-8")
                            ).hexdigest(),
                            "value": loopback.public_keys["ed25519"],
                        },
                        "rsa": {
                            "name": "host-rsa.pub",
                            "sha256": hashlib.sha256(
                                loopback.public_keys["rsa"].encode("utf-8")
                            ).hexdigest(),
                            "value": loopback.public_keys["rsa"],
                        },
                    },
                    "schema": "http-p-formal-loopback-sshd-v1",
                }
                self.assertEqual(expected_manifest, manifest)
                held_fds = tuple(loopback.held_fds)
                held_pid = loopback.daemon_pid
                held_root = loopback.root
                profile = _expected_capsule_sandbox_profile(
                    expected_state / "snapshot",
                )
                quoted_root = json.dumps(str(loopback.root))
                self.assertIn(
                    f"(deny file-write* (subpath {quoted_root}))", profile,
                )
                self.assertIn(
                    f"(deny file-write* (literal {quoted_root}))", profile,
                )
                return held_fds, held_pid, held_root

            if active_fixture is None:
                loopback_runs = []
                loopback_popens = []
                loopback_processes = []
                loopback_signals = []
                loopback_writer_authority = []
                real_subprocess_run = subprocess.run
                real_subprocess_popen = subprocess.Popen
                real_killpg = os.killpg
                expected_loopback_daemon_command = (
                    "/usr/sbin/sshd", "-D", "-e", "-f",
                    str(
                        loopback_state
                        / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE
                        / "sshd_config"
                    ),
                )
                def observe_loopback_run(command, *args, **kwargs):
                    loopback_runs.append((tuple(command), args, dict(kwargs)))
                    return real_subprocess_run(command, *args, **kwargs)
                def observe_loopback_popen(command, *args, **kwargs):
                    observed_command = tuple(command)
                    if observed_command != expected_loopback_daemon_command:
                        return real_subprocess_popen(command, *args, **kwargs)
                    loopback_popens.append((observed_command, args, dict(kwargs)))
                    self.assertIn("stderr", kwargs)
                    self.assertTrue(hasattr(kwargs["stderr"], "fileno"))
                    self.assertFalse(kwargs["stderr"].closed)
                    writer_fd = kwargs["stderr"].fileno()
                    writer_metadata = os.fstat(writer_fd)
                    loopback_writer_authority.append((
                        writer_fd,
                        (writer_metadata.st_dev, writer_metadata.st_ino),
                        fcntl.fcntl(writer_fd, fcntl.F_GETFL),
                        fcntl.fcntl(writer_fd, fcntl.F_GETFD),
                    ))
                    process = real_subprocess_popen(command, *args, **kwargs)
                    loopback_processes.append(process)
                    return process
                def observe_loopback_killpg(process_group, signal_number):
                    loopback_signals.append((process_group, signal_number))
                    return real_killpg(process_group, signal_number)
                scope_ambient = {
                    "P_LOOPBACK_SAFE_SENTINEL": "preserved",
                    P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "/hostile/fixture",
                    "PYTHONPATH": "/hostile/python",
                    "GIT_DIR": "/hostile/git",
                    "LD_PRELOAD": "/hostile/loader",
                    "DYLD_INSERT_LIBRARIES": "/hostile/dyld",
                }
                expected_scope_environment = {
                    "HOME": str(loopback_state / "home"),
                    "PATH": SYSTEM_EXECUTABLE_PATH,
                    "P_LOOPBACK_SAFE_SENTINEL": "preserved",
                }
                scope_started = time.monotonic()
                with mock.patch.object(
                    subprocess, "run", side_effect=observe_loopback_run,
                ), mock.patch.object(
                    subprocess, "Popen", side_effect=observe_loopback_popen,
                ), mock.patch.object(
                    os, "killpg", side_effect=observe_loopback_killpg,
                ), mock.patch.dict(os.environ, scope_ambient, clear=True):
                    with loopback_scope(loopback_state) as loopback:
                        held_fds, held_pid, held_root = assert_loopback_authority(
                            loopback, loopback_state,
                        )
                        held_port = loopback.port
                        held_pgid = os.getpgid(held_pid)
                        with mock.patch.dict(os.environ, {
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "1",
                        }, clear=True), self.assertRaises(AssertionError):
                            loopback_consumer()
                        independent_scan = real_subprocess_run(
                            (
                                "/usr/bin/ssh-keyscan", "-T", "2", "-p",
                                str(loopback.port), "-t", "ed25519", "127.0.0.1",
                            ),
                            text=True, capture_output=True, timeout=4, check=False,
                        )
                        independent_lines = tuple(
                            line for line in independent_scan.stdout.splitlines()
                            if line and not line.startswith("#")
                        )
                        self.assertEqual(0, independent_scan.returncode)
                        self.assertEqual(1, len(independent_lines))
                        fields = independent_lines[0].split()
                        self.assertEqual(
                            (
                                f"[127.0.0.1]:{loopback.port}",
                                *loopback.public_keys["ed25519"].split()[:2],
                            ),
                            tuple(fields),
                        )
                        independent_fingerprint = "SHA256:" + base64.b64encode(
                            hashlib.sha256(base64.b64decode(fields[2])).digest()
                        ).rstrip(b"=").decode("ascii")
                        self.assertEqual(
                            loopback.fingerprints["ed25519"],
                            independent_fingerprint,
                        )
                        self.assertNotEqual(
                            (loopback.root / "host-ed25519").read_bytes(),
                            (loopback.root / "host-rsa").read_bytes(),
                        )
                        self.assertEqual(1, len(loopback_popens))
                        self.assertTrue(loopback_popens[0][2]["stderr"].closed)
                        self.assertEqual(1, len(loopback_writer_authority))
                        writer_fd, writer_identity, writer_flags, writer_fd_flags = (
                            loopback_writer_authority[0]
                        )
                        self.assertEqual(
                            loopback.held_identities[7], writer_identity,
                        )
                        self.assertEqual(
                            os.O_WRONLY, writer_flags & os.O_ACCMODE,
                        )
                        self.assertTrue(writer_fd_flags & fcntl.FD_CLOEXEC)
                self.assertLess(time.monotonic() - scope_started, 8)
                expected_keygen = "/usr/bin/ssh-keygen"
                expected_keyscan = "/usr/bin/ssh-keyscan"
                keygen_calls = [
                    row for row in loopback_runs if row[0][0] == expected_keygen
                ]
                keyscan_calls = [
                    row for row in loopback_runs if row[0][0] == expected_keyscan
                ]
                self.assertEqual(4, len(keygen_calls))
                self.assertGreaterEqual(len(keyscan_calls), 1)
                self.assertLessEqual(len(keyscan_calls), 3)
                fixture_root = (
                    loopback_state / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE
                )
                self.assertEqual(
                    (
                        (
                            expected_keygen, "-q", "-t", "ed25519", "-N", "",
                            "-f", str(fixture_root / "host-ed25519"),
                        ),
                        (
                            expected_keygen, "-q", "-t", "rsa", "-N", "",
                            "-f", str(fixture_root / "host-rsa"),
                        ),
                        (
                            expected_keygen, "-lf",
                            str(fixture_root / "host-ed25519.pub"),
                            "-E", "sha256",
                        ),
                        (
                            expected_keygen, "-lf",
                            str(fixture_root / "host-rsa.pub"),
                            "-E", "sha256",
                        ),
                    ),
                    tuple(command for command, _args, _kwargs in keygen_calls),
                )
                self.assertEqual(
                    {
                        (
                            expected_keyscan, "-T", "2", "-p", str(held_port),
                            "-t", "ed25519", "127.0.0.1",
                        )
                    },
                    {command for command, _args, _kwargs in keyscan_calls},
                )
                readiness_timeouts = tuple(
                    kwargs["timeout"] for _command, _args, kwargs in keyscan_calls
                )
                self.assertTrue(all(0 < value <= 4 for value in readiness_timeouts))
                self.assertEqual(
                    tuple(sorted(readiness_timeouts, reverse=True)),
                    readiness_timeouts,
                )
                for command, positional, kwargs in loopback_runs:
                    self.assertEqual((), positional)
                    self.assertTrue(Path(command[0]).is_absolute())
                    self.assertEqual(
                        {"capture_output", "check", "env", "text", "timeout"},
                        set(kwargs),
                    )
                    self.assertIsInstance(kwargs["env"], dict)
                    self.assertEqual(expected_scope_environment, kwargs["env"])
                self.assertEqual(1, len(loopback_popens))
                daemon_command, daemon_positional, daemon_kwargs = loopback_popens[0]
                self.assertEqual((), daemon_positional)
                expected_sshd = Path("/usr/sbin/sshd")
                expected_sshd_metadata = expected_sshd.lstat()
                self.assertTrue(stat.S_ISREG(expected_sshd_metadata.st_mode))
                self.assertEqual(0, expected_sshd_metadata.st_uid)
                self.assertEqual(
                    0, stat.S_IMODE(expected_sshd_metadata.st_mode) & 0o022,
                )
                self.assertEqual(
                    (
                        str(expected_sshd), "-D", "-e", "-f",
                        str(
                            loopback_state
                            / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE
                            / "sshd_config"
                        ),
                    ),
                    daemon_command,
                )
                self.assertEqual(
                    {
                        "close_fds", "cwd", "env", "start_new_session", "stderr",
                        "stdin", "stdout", "text", "pass_fds",
                    },
                    set(daemon_kwargs),
                )
                self.assertIs(subprocess.DEVNULL, daemon_kwargs["stdin"])
                self.assertIs(subprocess.DEVNULL, daemon_kwargs["stdout"])
                self.assertIs(True, daemon_kwargs["close_fds"])
                self.assertIs(True, daemon_kwargs["start_new_session"])
                self.assertEqual((), daemon_kwargs["pass_fds"])
                self.assertEqual(loopback_state / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE,
                                 Path(daemon_kwargs["cwd"]))
                self.assertEqual(expected_scope_environment, daemon_kwargs["env"])
                self.assertEqual(1, len(loopback_processes))
                self.assertEqual(loopback_processes[0].pid, held_pid)
                self.assertEqual(loopback_processes[0].pid, held_pgid)
                self.assertTrue(loopback_signals)
                self.assertEqual((held_pid, signal.SIGTERM), loopback_signals[0])
                self.assertTrue(all(
                    process_group == held_pid for process_group, _signal in loopback_signals
                ))
                self.assertFalse(os.path.lexists(held_root))
                for descriptor in held_fds:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                with self.assertRaises(ProcessLookupError):
                    os.kill(held_pid, 0)

                for boundary, failure in (
                    ("after-keygen", RuntimeError("key generation boundary")),
                    ("after-popen", KeyboardInterrupt("daemon spawn boundary")),
                    (
                        "readiness-attempt",
                        subprocess.TimeoutExpired(("ssh-keyscan",), 2),
                    ),
                    ("after-readiness", RuntimeError("readiness boundary")),
                ):
                    observed_boundaries = []
                    observed_authority = {}
                    def fail_loopback_boundary(event, **authority):
                        observed_boundaries.append(event)
                        if event == boundary:
                            observed_authority.update(authority)
                            raise failure
                        return loopback_observer(event, **authority)
                    started = time.monotonic()
                    with self.subTest(loopback_failure_boundary=boundary), \
                            mock.patch.object(
                                module, "_formal_loopback_sshd_observer",
                                side_effect=fail_loopback_boundary,
                            ):
                        try:
                            with loopback_scope(loopback_state):
                                self.fail("failed loopback scope yielded authority")
                        except BaseException as error:
                            self.assertIs(failure, error)
                        else:
                            self.fail("loopback boundary failure was swallowed")
                    self.assertLess(time.monotonic() - started, 8)
                    self.assertIn(boundary, observed_boundaries)
                    self.assertEqual("after-keygen", observed_boundaries[0])
                    if boundary != "after-keygen":
                        self.assertEqual("after-popen", observed_boundaries[1])
                    if boundary == "readiness-attempt":
                        self.assertEqual(
                            ("after-keygen", "after-popen", "readiness-attempt"),
                            tuple(observed_boundaries),
                        )
                    if boundary == "after-readiness":
                        self.assertEqual("after-readiness", observed_boundaries[-1])
                        self.assertGreaterEqual(
                            observed_boundaries.count("readiness-attempt"), 1,
                        )
                        self.assertLessEqual(
                            observed_boundaries.count("readiness-attempt"), 3,
                        )
                    expected_authority_keys = (
                        {"root"} if boundary == "after-keygen" else {
                            "daemon_pgid", "daemon_pid", "held_fds", "root",
                        } | ({
                                "attempt", "deadline", "remaining",
                            } if boundary == "readiness-attempt" else set())
                    )
                    self.assertEqual(
                        expected_authority_keys, set(observed_authority),
                    )
                    self.assertEqual(
                        loopback_state / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE,
                        observed_authority["root"],
                    )
                    if boundary != "after-keygen":
                        self.assertEqual(
                            observed_authority["daemon_pid"],
                            observed_authority["daemon_pgid"],
                        )
                        self.assertEqual(8, len(observed_authority["held_fds"]))
                    self.assertFalse(os.path.lexists(
                        loopback_state / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE
                    ))
                    for descriptor in observed_authority.get("held_fds", ()):
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    daemon_pid = observed_authority.get("daemon_pid")
                    if daemon_pid is not None:
                        with self.assertRaises(ProcessLookupError):
                            os.kill(daemon_pid, 0)

                interrupted_fds = ()
                interrupted_pid = None
                interrupted_root = None
                interrupted_signals = []
                def observe_interrupted_killpg(process_group, signal_number):
                    interrupted_signals.append((process_group, signal_number))
                    return real_killpg(process_group, signal_number)
                try:
                    with mock.patch.object(
                        os, "killpg", side_effect=observe_interrupted_killpg,
                    ):
                        with loopback_scope(loopback_state) as loopback:
                            interrupted_fds = tuple(loopback.held_fds)
                            interrupted_pid = loopback.daemon_pid
                            interrupted_root = loopback.root
                            raise KeyboardInterrupt(
                                "formal loopback parent interrupted"
                            )
                except KeyboardInterrupt as error:
                    self.assertEqual(
                        "formal loopback parent interrupted", str(error),
                    )
                else:
                    self.fail("loopback scope swallowed BaseException")
                self.assertFalse(os.path.lexists(interrupted_root))
                for descriptor in interrupted_fds:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                with self.assertRaises(ProcessLookupError):
                    os.kill(interrupted_pid, 0)
                self.assertTrue(interrupted_signals)
                self.assertEqual(
                    (interrupted_pid, signal.SIGTERM), interrupted_signals[0],
                )
                self.assertTrue(all(
                    process_group == interrupted_pid
                    for process_group, _signal in interrupted_signals
                ))
                with self.assertRaises(ProcessLookupError):
                    os.killpg(interrupted_pid, 0)

                fallback_signals = []
                fallback_waits = []
                fallback_targeted_popens = []
                fallback_pid = None
                def stubborn_loopback_popen(command, *args, **kwargs):
                    if tuple(command) != expected_loopback_daemon_command:
                        return real_subprocess_popen(command, *args, **kwargs)
                    fallback_targeted_popens.append(tuple(command))
                    process = real_subprocess_popen(command, *args, **kwargs)
                    real_wait = process.wait
                    wait_count = [0]
                    def bounded_wait(timeout):
                        fallback_waits.append(timeout)
                        wait_count[0] += 1
                        if wait_count[0] == 1:
                            raise subprocess.TimeoutExpired(command, timeout)
                        return real_wait(timeout=timeout)
                    process.wait = bounded_wait
                    return process
                def fallback_killpg(process_group, signal_number):
                    fallback_signals.append((process_group, signal_number))
                    return real_killpg(process_group, signal_number)
                try:
                    with mock.patch.object(
                        subprocess, "Popen", side_effect=stubborn_loopback_popen,
                    ), mock.patch.object(
                        os, "killpg", side_effect=fallback_killpg,
                    ):
                        with loopback_scope(loopback_state) as loopback:
                            fallback_pid = loopback.daemon_pid
                            raise RuntimeError("force bounded daemon reap")
                except RuntimeError as error:
                    self.assertEqual("force bounded daemon reap", str(error))
                else:
                    self.fail("bounded daemon cleanup failure was swallowed")
                self.assertEqual(
                    (expected_loopback_daemon_command,),
                    tuple(fallback_targeted_popens),
                )
                self.assertEqual(
                    (
                        (fallback_pid, signal.SIGTERM),
                        (fallback_pid, signal.SIGKILL),
                    ),
                    tuple(fallback_signals),
                )
                self.assertEqual(2, len(fallback_waits))
                self.assertTrue(all(0 < timeout <= 2 for timeout in fallback_waits))
                with self.assertRaises(ProcessLookupError):
                    os.killpg(fallback_pid, 0)
                self.assertFalse(os.path.lexists(
                    loopback_state / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE
                ))
            else:
                inherited_held_paths = (
                    inherited_loopback.root,
                    inherited_loopback.root / "host-ed25519",
                    inherited_loopback.root / "host-ed25519.pub",
                    inherited_loopback.root / "host-rsa",
                    inherited_loopback.root / "host-rsa.pub",
                    inherited_loopback.root / "sshd_config",
                    inherited_loopback.root / "authority.json",
                    inherited_loopback.root / "sshd.stderr",
                )
                inherited_held_fds = []
                try:
                    for index, path in enumerate(inherited_held_paths):
                        flags = (
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                            | os.O_CLOEXEC
                        )
                        if index == 0:
                            flags |= os.O_DIRECTORY
                        inherited_held_fds.append(os.open(path, flags))
                    inherited_held_authority = SimpleNamespace(
                        **vars(inherited_loopback),
                        held_paths=inherited_held_paths,
                        held_fds=tuple(inherited_held_fds),
                        held_identities=tuple(
                            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                            for descriptor in inherited_held_fds
                        ),
                    )
                    assert_loopback_authority(
                        inherited_held_authority, active_fixture.snapshot.parent,
                    )
                finally:
                    for descriptor in reversed(inherited_held_fds):
                        os.close(descriptor)
                for descriptor in inherited_held_fds:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

        with tempfile.TemporaryDirectory(prefix="http-p-formal-archive-") as directory:
            formal_root = (Path(directory) / "formal").resolve()
            formal_root.mkdir(mode=0o700)
            dependency_archive = build(formal_root)
            archive_fd = dependency_archive.fd
            archive_identity = (dependency_archive.dev, dependency_archive.ino)
            os.lseek(archive_fd, 16384, os.SEEK_SET)
            inherited_environment = {
                P_CAPSULE_FD_ENV: str(archive_fd),
                P_CAPSULE_IDENTITY_ENV: ":".join((
                    str(dependency_archive.dev), str(dependency_archive.ino),
                    str(P_CAPSULE_ARCHIVE_SIZE), P_CAPSULE_ARCHIVE_SHA256,
                )),
            }
            with mock.patch.dict(os.environ, inherited_environment, clear=False), \
                    mock.patch.object(
                        module, "_build_dependency_archive",
                        side_effect=AssertionError("nested formal rebuilt dependency archive"),
                    ) as nested_rebuild:
                with formal_scope(formal_root / "nested-state") as inherited:
                    inherited_fd = inherited.fd
                    self.assertNotEqual(archive_fd, inherited_fd)
                    inherited_metadata = os.fstat(inherited_fd)
                    self.assertEqual(archive_identity, (inherited_metadata.st_dev, inherited_metadata.st_ino))
                    self.assertEqual(0, inherited_metadata.st_nlink)
                    self.assertEqual(os.O_RDONLY, fcntl.fcntl(inherited_fd, fcntl.F_GETFL) & os.O_ACCMODE)
                    verify_archive(inherited)
                    self.assertEqual(16384, os.lseek(inherited_fd, 0, os.SEEK_CUR))
                with self.assertRaises(OSError):
                    os.fstat(inherited_fd)
                nested_rebuild.assert_not_called()
                adopted = adopt()
                adopted_fd = adopted.fd
                self.assertEqual(archive_identity, (adopted.dev, adopted.ino))
                adopted.close()
                with self.assertRaises(OSError):
                    os.fstat(adopted_fd)
            with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(AssertionError):
                adopt()
            for hostile_identity in (
                "malformed", "0:0:0:" + P_CAPSULE_ARCHIVE_SHA256,
                f"{dependency_archive.dev}:{dependency_archive.ino}:{P_CAPSULE_ARCHIVE_SIZE + 1}:{P_CAPSULE_ARCHIVE_SHA256}",
            ):
                with self.subTest(inherited_identity=hostile_identity), mock.patch.dict(
                    os.environ, {
                        P_CAPSULE_FD_ENV: str(archive_fd),
                        P_CAPSULE_IDENTITY_ENV: hostile_identity,
                    }, clear=True,
                ), self.assertRaises(AssertionError):
                    adopt()
            predup_calls = []
            real_predup = os.dup
            real_prefcntl = fcntl.fcntl
            def observed_predup(descriptor):
                duplicated = real_predup(descriptor)
                if descriptor == archive_fd:
                    predup_calls.append(duplicated)
                return duplicated
            def observed_prefcntl(descriptor, command, *args):
                result = real_prefcntl(descriptor, command, *args)
                if command == getattr(fcntl, "F_DUPFD_CLOEXEC", object()) and descriptor == archive_fd:
                    predup_calls.append(result)
                return result
            with mock.patch.dict(os.environ, {
                P_CAPSULE_FD_ENV: str(archive_fd),
                P_CAPSULE_IDENTITY_ENV: (
                    f"{dependency_archive.dev}:{dependency_archive.ino}:"
                    f"{P_CAPSULE_ARCHIVE_SIZE}:" + "00" * 32
                ),
            }, clear=True), mock.patch.object(
                os, "dup", side_effect=observed_predup,
            ), mock.patch.object(
                fcntl, "fcntl", side_effect=observed_prefcntl,
            ), self.assertRaises(AssertionError):
                adopt()
            try:
                self.assertEqual([], predup_calls)
            finally:
                for predup_fd in predup_calls:
                    try:
                        os.close(predup_fd)
                    except OSError:
                        pass
            closed_fd = os.dup(archive_fd)
            os.close(closed_fd)
            with mock.patch.dict(os.environ, {
                P_CAPSULE_FD_ENV: str(closed_fd),
                P_CAPSULE_IDENTITY_ENV: inherited_environment[P_CAPSULE_IDENTITY_ENV],
            }, clear=True), self.assertRaises(AssertionError):
                adopt()
            hostile_path = formal_root / "linked-or-writable.archive"
            hostile_path.write_bytes(b"hostile")
            for hostile_flags in (os.O_RDONLY, os.O_RDWR):
                hostile_fd = os.open(hostile_path, hostile_flags | os.O_CLOEXEC)
                hostile_metadata = os.fstat(hostile_fd)
                hostile_env = {
                    P_CAPSULE_FD_ENV: str(hostile_fd),
                    P_CAPSULE_IDENTITY_ENV: (
                        f"{hostile_metadata.st_dev}:{hostile_metadata.st_ino}:"
                        f"{hostile_metadata.st_size}:{hashlib.sha256(b'hostile').hexdigest()}"
                    ),
                }
                try:
                    with self.subTest(inherited_flags=hostile_flags), mock.patch.dict(
                        os.environ, hostile_env, clear=True,
                    ), self.assertRaises(AssertionError):
                        adopt()
                finally:
                    os.close(hostile_fd)
            hostile_path.unlink()
            hostile_digest_path = formal_root / "wrong-digest-anonymous.archive"
            hostile_digest_writer = os.open(
                hostile_digest_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
            )
            try:
                os.ftruncate(hostile_digest_writer, P_CAPSULE_ARCHIVE_SIZE)
                os.fchmod(hostile_digest_writer, 0o400)
                os.fsync(hostile_digest_writer)
            finally:
                os.close(hostile_digest_writer)
            hostile_digest_fd = os.open(
                hostile_digest_path,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            )
            hostile_digest_metadata = os.fstat(hostile_digest_fd)
            hostile_digest_path.unlink()
            hostile_digest_hasher = hashlib.sha256()
            hostile_digest_offset = 0
            while hostile_digest_offset < hostile_digest_metadata.st_size:
                hostile_digest_chunk = os.pread(
                    hostile_digest_fd,
                    min(1024 * 1024, hostile_digest_metadata.st_size - hostile_digest_offset),
                    hostile_digest_offset,
                )
                self.assertTrue(hostile_digest_chunk)
                hostile_digest_hasher.update(hostile_digest_chunk)
                hostile_digest_offset += len(hostile_digest_chunk)
            hostile_digest_sha256 = hostile_digest_hasher.hexdigest()
            self.assertNotEqual(P_CAPSULE_ARCHIVE_SHA256, hostile_digest_sha256)
            hostile_digest_env = {
                P_CAPSULE_FD_ENV: str(hostile_digest_fd),
                P_CAPSULE_IDENTITY_ENV: ":".join((
                    str(hostile_digest_metadata.st_dev),
                    str(hostile_digest_metadata.st_ino),
                    str(hostile_digest_metadata.st_size),
                    P_CAPSULE_ARCHIVE_SHA256,
                )),
            }
            internal_adopt_fds = []
            real_dup = os.dup
            real_fcntl_call = fcntl.fcntl
            def observed_adopt_dup(descriptor):
                duplicated = real_dup(descriptor)
                if descriptor == hostile_digest_fd:
                    internal_adopt_fds.append(duplicated)
                return duplicated
            def observed_adopt_fcntl(descriptor, command, *args):
                result = real_fcntl_call(descriptor, command, *args)
                if command == getattr(fcntl, "F_DUPFD_CLOEXEC", object()) and descriptor == hostile_digest_fd:
                    internal_adopt_fds.append(result)
                return result
            try:
                with mock.patch.dict(
                    os.environ, hostile_digest_env, clear=True,
                ), mock.patch.object(
                    os, "dup", side_effect=observed_adopt_dup,
                ), mock.patch.object(
                    fcntl, "fcntl", side_effect=observed_adopt_fcntl,
                ), self.assertRaises(AssertionError):
                    adopt()
                self.assertEqual(1, len(internal_adopt_fds))
                for internal_adopt_fd in internal_adopt_fds:
                    with self.assertRaises(OSError):
                        os.fstat(internal_adopt_fd)
                self.assertEqual(
                    (hostile_digest_metadata.st_dev, hostile_digest_metadata.st_ino),
                    (os.fstat(hostile_digest_fd).st_dev, os.fstat(hostile_digest_fd).st_ino),
                )
            finally:
                os.close(hostile_digest_fd)
            self.assertEqual(archive_identity, (os.fstat(archive_fd).st_dev, os.fstat(archive_fd).st_ino))
            self.assertEqual(16384, os.lseek(archive_fd, 0, os.SEEK_CUR))

            for exit_kind in ("normal", "error", "interrupt"):
                owning_state = formal_root / f"owning-{exit_kind}"
                owned_fds = []
                failure = None
                try:
                    with mock.patch.object(
                        module, "_build_dependency_archive", wraps=build,
                    ) as owning_build, mock.patch.object(
                        module, "_adopt_dependency_archive_from_environment",
                        wraps=adopt,
                    ) as owning_adopt:
                        with formal_scope(owning_state) as owned:
                            owned_fds.append(owned.fd)
                            verify_archive(owned)
                            if exit_kind == "error":
                                raise AssertionError("formal archive owner failed")
                            if exit_kind == "interrupt":
                                raise KeyboardInterrupt("formal archive owner interrupted")
                except BaseException as error:
                    failure = error
                if active_fixture is None:
                    owning_build.assert_called_once_with(owning_state)
                    owning_adopt.assert_not_called()
                else:
                    owning_build.assert_not_called()
                    owning_adopt.assert_called_once_with()
                    self.assertNotIn(owned_fds[0], active_fixture_fds)
                if exit_kind == "normal":
                    self.assertIsNone(failure)
                elif exit_kind == "error":
                    self.assertIsInstance(failure, AssertionError)
                else:
                    self.assertIsInstance(failure, KeyboardInterrupt)
                self.assertEqual(1, len(owned_fds))
                with self.assertRaises(OSError):
                    os.fstat(owned_fds[0])
                self.assertFalse(os.path.lexists(owning_state))
                if active_fixture is not None:
                    self.assertEqual(
                        active_fixture_identities,
                        tuple(
                            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                            for descriptor in active_fixture_fds
                        ),
                    )
                    self.assertEqual(
                        active_fixture_flags,
                        tuple(
                            (
                                fcntl.fcntl(descriptor, fcntl.F_GETFL),
                                fcntl.fcntl(descriptor, fcntl.F_GETFD),
                            )
                            for descriptor in active_fixture_fds
                        ),
                    )
                    self.assertEqual(
                        active_fixture_offset,
                        os.lseek(active_fixture.archive_fd, 0, os.SEEK_CUR),
                    )
                    verify_archive(_DependencyArchiveAuthority(
                        active_fixture.archive_fd,
                        os.fstat(active_fixture.archive_fd),
                        P_CAPSULE_ARCHIVE_SHA256,
                    ))
                    verify_snapshot(active_fixture.snapshot)
                    verify_python_home(active_fixture.python_home)
            with mock.patch.object(
                module, "_build_dependency_archive",
                side_effect=AssertionError("formal process tree rebuilt dependency archive"),
            ) as rebuild:
                verify_archive(dependency_archive)
                snapshots = []
                real_observer = _dependency_archive_observer
                def observed(event, **authority):
                    if event == "snapshot-ready":
                        snapshot = Path(authority["snapshot"])
                        metadata = snapshot.lstat()
                        snapshots.append((snapshot, metadata.st_dev, metadata.st_ino))
                    return real_observer(event, **authority)

                hostile = {
                    "HOME": "/hostile/home", "PATH": "/hostile/bin",
                    "PYTHONPATH": "/hostile/python", "PYTHONHOME": "/hostile/home-python",
                    "PYTHONSTARTUP": "/hostile/start", "PYTHONINSPECT": "1",
                    "PYTHON_CAPSULE_HOSTILE_MARKER": "must-not-reach-child",
                    "LD_PRELOAD": "/hostile/preload", "LD_AUDIT": "/hostile/audit",
                    "DYLD_INSERT_LIBRARIES": "/hostile/dyld", "DYLD_FUTURE": "hostile",
                    "GIT_DIR": "/hostile/git", "GIT_INDEX_FILE": "/hostile/index",
                }
                hostile.update({
                    P_CAPSULE_FD_ENV: "1",
                    P_CAPSULE_IDENTITY_ENV: "hostile-archive-identity",
                    **{
                        key: f"hostile-{name}"
                        for name, key in P_REENTRANT_ENV_KEYS.items()
                    },
                })
                hostile[P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV] = "/hostile/fixture"
                outside = formal_root / "outside"
                outside.mkdir(mode=0o700)
                hostile["CAPSULE_ATTACK_OUTSIDE"] = str(outside)
                real_open = os.open

                # The four exact runner argument vectors are the only standalone
                # producers of the complete reentrant authority.  Exercise the
                # real producer up to its sandbox boundary; mocks below observe,
                # rather than synthesize, every owned descriptor and identity.
                producer_offset = os.lseek(archive_fd, 0, os.SEEK_CUR)
                producer_result = subprocess.CompletedProcess(
                    ["reentrant-producer"], 0, "producer\n", "",
                )
                reviewed_reentrant_runner_arguments = (
                    ("-B", "test_cases/run_related_tests.py", "--all", "-v"),
                    (
                        "-B", "test_cases/run_related_tests.py", "--suite",
                        "repository-governance", "-v",
                    ),
                    (
                        "-B", "test_cases/run_related_tests.py", "--all",
                        "--no-approve", "-v",
                    ),
                    (
                        "-B", "-m", "unittest", "-v",
                        "test_cases.test_public_publication_workflow."
                        "PublicPublicationWorkflowTests."
                        "_bootstrap_reentry_outer_probe",
                    ),
                )
                self.assertEqual(
                    reviewed_reentrant_runner_arguments,
                    P_REENTRANT_RUNNER_ARGUMENTS,
                )
                producer_boundaries = []
                loopback_scope_calls = []
                loopback_scope_authorities = []
                @contextlib.contextmanager
                def observed_loopback_scope(state_path):
                    fixture_root = None
                    try:
                        with loopback_scope(state_path) as authority:
                            fixture_root = authority.root
                            held = tuple(authority.held_fds)
                            daemon_pid = authority.daemon_pid
                            daemon_pgid = os.getpgid(daemon_pid)
                            loopback_scope_authorities.append((
                                fixture_root, held, daemon_pid, daemon_pgid,
                            ))
                            loopback_scope_calls.append(("enter", fixture_root))
                            yield authority
                    finally:
                        if fixture_root is not None:
                            loopback_scope_calls.append(("exit", fixture_root))
                def observe_reentrant_producer(command, **kwargs):
                    environment = kwargs["environment"]
                    passed = tuple(kwargs["pass_fds"])
                    arguments = json.loads(command[-1])
                    snapshot_path = Path(command[-3])
                    state_path = snapshot_path.parent
                    self.assertEqual(7, len(passed))
                    self.assertEqual(7, len(set(passed)))
                    self.assertEqual(archive_fd, passed[0])
                    self.assertEqual(str(passed[0]), environment[P_CAPSULE_FD_ENV])
                    self.assertEqual(
                        inherited_environment[P_CAPSULE_IDENTITY_ENV],
                        environment[P_CAPSULE_IDENTITY_ENV],
                    )
                    self.assertEqual(
                        set(P_REENTRANT_ENV_KEYS.values()),
                        set(P_REENTRANT_ENV_KEYS.values()).intersection(environment),
                    )
                    self.assertEqual("1", environment[P_REENTRANT_ENV_KEYS["marker"]])
                    self.assertEqual(
                        str(snapshot_path), environment[P_REENTRANT_ENV_KEYS["snapshot"]],
                    )
                    self.assertEqual(
                        str(passed[1]), environment[P_REENTRANT_ENV_KEYS["snapshot_fd"]],
                    )
                    snapshot_metadata = os.fstat(passed[1])
                    snapshot_named = snapshot_path.lstat()
                    self.assertTrue(stat.S_ISDIR(snapshot_metadata.st_mode))
                    self.assertEqual(0o700, stat.S_IMODE(snapshot_metadata.st_mode))
                    self.assertEqual(
                        (snapshot_metadata.st_dev, snapshot_metadata.st_ino),
                        (snapshot_named.st_dev, snapshot_named.st_ino),
                    )
                    self.assertEqual(
                        ":".join((
                            str(snapshot_metadata.st_dev), str(snapshot_metadata.st_ino),
                            P_CAPSULE_RECORDS_SHA256,
                        )),
                        environment[P_REENTRANT_ENV_KEYS["snapshot_identity"]],
                    )
                    identity_rows = json.loads(
                        environment[P_REENTRANT_ENV_KEYS["python_home_identity"]]
                    )
                    self.assertEqual(
                        ",".join(str(descriptor) for descriptor in passed[2:]),
                        environment[P_REENTRANT_ENV_KEYS["python_home_fds"]],
                    )
                    self.assertEqual(5, len(identity_rows))
                    self.assertEqual(
                        ({"dev", "ino", "mode", "path"},) * 5,
                        tuple(set(row) for row in identity_rows),
                    )
                    expected_paths = (
                        state_path, state_path / "python-home",
                        state_path / "python-home/lib",
                        state_path / "python-home/lib/python3.9",
                        state_path / "python-home/lib/python3.9/site-packages",
                    )
                    for descriptor, row, expected_path, expected_mode in zip(
                        passed[2:], identity_rows, expected_paths,
                        (0o700, 0o700, 0o755, 0o755, 0o755),
                    ):
                        metadata = os.fstat(descriptor)
                        named = expected_path.lstat()
                        self.assertTrue(stat.S_ISDIR(metadata.st_mode))
                        self.assertEqual(expected_mode, stat.S_IMODE(metadata.st_mode))
                        self.assertEqual(
                            (metadata.st_dev, metadata.st_ino),
                            (named.st_dev, named.st_ino),
                        )
                        self.assertEqual({
                            "dev": metadata.st_dev, "ino": metadata.st_ino,
                            "mode": f"{expected_mode:04o}", "path": str(expected_path),
                        }, row)
                    for descriptor in passed:
                        os.fstat(descriptor)
                        self.assertFalse(os.get_inheritable(descriptor))
                    self.assertEqual(
                        (
                            P_CAPSULE_SANDBOX_EXECUTABLE, "-p",
                            _expected_capsule_sandbox_profile(snapshot_path),
                            str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                            P_CAPSULE_BOOTSTRAP, str(snapshot_path), str(ROOT),
                            json.dumps(arguments, separators=(",", ":")),
                        ),
                        tuple(command),
                    )
                    fixture_root = (
                        state_path / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE
                    )
                    is_formal_runner = tuple(arguments) in (
                        reviewed_reentrant_runner_arguments[:3]
                    )
                    if is_formal_runner:
                        self.assertEqual(
                            "1",
                            environment[P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV],
                        )
                        quoted_fixture = json.dumps(str(fixture_root))
                        self.assertIn(
                            f"(deny file-write* (subpath {quoted_fixture}))",
                            command[2],
                        )
                        self.assertIn(
                            f"(deny file-write* (literal {quoted_fixture}))",
                            command[2],
                        )
                    else:
                        self.assertNotIn(
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV, environment,
                        )
                    producer_boundaries.append((state_path, passed))
                    return producer_result

                def assert_reused_active_loopback(authority):
                    self.assertIsNotNone(active_fixture)
                    self.assertEqual(
                        active_inherited_loopback_value,
                        (
                            authority.root, authority.port, authority.daemon_pid,
                            dict(authority.public_keys),
                            dict(authority.fingerprints), authority.source_fds,
                        ),
                    )
                    self.assertEqual(active_fixture_fds, authority.source_fds)
                    self.assertEqual(
                        active_inherited_loopback_identity,
                        (
                            authority.root.lstat().st_dev,
                            authority.root.lstat().st_ino,
                        ),
                    )
                    os.kill(authority.daemon_pid, 0)
                    self.assertEqual(
                        active_inherited_loopback_pgid,
                        os.getpgid(authority.daemon_pid),
                    )
                    self.assertEqual(
                        active_fixture_identities,
                        tuple(
                            (os.fstat(descriptor).st_dev,
                             os.fstat(descriptor).st_ino)
                            for descriptor in active_fixture_fds
                        ),
                    )
                    self.assertEqual(
                        active_fixture_flags,
                        tuple(
                            (
                                fcntl.fcntl(descriptor, fcntl.F_GETFL),
                                fcntl.fcntl(descriptor, fcntl.F_GETFD),
                            )
                            for descriptor in active_fixture_fds
                        ),
                    )
                    self.assertEqual(
                        active_fixture_offset,
                        os.lseek(active_fixture.archive_fd, 0, os.SEEK_CUR),
                    )

                for producer_index, producer_arguments in enumerate(
                    reviewed_reentrant_runner_arguments
                ):
                    with self.subTest(reentrant_producer=producer_arguments):
                        producer_boundaries.clear()
                        loopback_scope_calls.clear()
                        loopback_scope_authorities.clear()
                        if active_fixture is None:
                            with mock.patch.dict(os.environ, {}, clear=True), \
                                    mock.patch.object(
                                        module, "_run_capsule_sandbox",
                                        side_effect=observe_reentrant_producer,
                                    ) as producer_sandbox, mock.patch.object(
                                        module, "_formal_loopback_sshd_scope",
                                        side_effect=observed_loopback_scope,
                                    ) as parent_sshd_scope:
                                produced = _python_run(
                                    ROOT, list(producer_arguments), timeout=91,
                                    dependency_archive=dependency_archive,
                                    ambient=hostile,
                                )
                            self.assertIs(producer_result, produced)
                            producer_sandbox.assert_called_once()
                            self.assertEqual(
                                1 if producer_index < 3 else 0,
                                parent_sshd_scope.call_count,
                            )
                            self.assertEqual(
                                1 if producer_index < 3 else 0,
                                len(loopback_scope_authorities),
                            )
                            self.assertEqual(
                                (
                                    ("enter", producer_boundaries[0][0]
                                     / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE),
                                    ("exit", producer_boundaries[0][0]
                                     / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE),
                                ) if producer_index < 3 else (),
                                tuple(loopback_scope_calls),
                            )
                            if producer_index < 3:
                                observed_root, observed_fds, observed_pid, \
                                        observed_pgid = loopback_scope_authorities[0]
                                self.assertEqual(
                                    producer_boundaries[0][0]
                                    / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE,
                                    observed_root,
                                )
                                self.assertFalse(os.path.lexists(observed_root))
                                for descriptor in observed_fds:
                                    with self.assertRaises(OSError):
                                        os.fstat(descriptor)
                                with self.assertRaises(ProcessLookupError):
                                    os.kill(observed_pid, 0)
                                with self.assertRaises(ProcessLookupError):
                                    os.killpg(observed_pgid, 0)
                            self.assertEqual(1, len(producer_boundaries))
                            producer_state, producer_fds = producer_boundaries[0]
                            self.assertFalse(os.path.lexists(producer_state))
                            for descriptor in producer_fds[1:]:
                                with self.assertRaises(OSError):
                                    os.fstat(descriptor)
                            os.fstat(archive_fd)
                            self.assertEqual(
                                producer_offset,
                                os.lseek(archive_fd, 0, os.SEEK_CUR),
                            )
                            continue

                        active_process_calls = []
                        active_owned_fds = []
                        active_consumed_loopbacks = []
                        expected_active_write = {
                            "chmod": errno.EPERM, "open": errno.EPERM,
                            "site-open": errno.EPERM, "site-residue": False,
                        }
                        def observe_active_producer_process(command, **kwargs):
                            active_process_calls.append((tuple(command), dict(kwargs)))
                            self.assertEqual(
                                {"cwd", "environment", "pass_fds", "timeout"},
                                set(kwargs),
                            )
                            self.assertEqual(ROOT.resolve(), Path(kwargs["cwd"]).resolve())
                            self.assertEqual(91, kwargs["timeout"])
                            if len(active_process_calls) == 1:
                                self.assertEqual((
                                    P_CAPSULE_SANDBOX_EXECUTABLE, "-p",
                                    "(version 1)\n(allow default)\n", "/usr/bin/true",
                                ), tuple(command))
                                self.assertEqual((), tuple(kwargs["pass_fds"]))
                                self.assertEqual(set(), {
                                    P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                                    P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
                                    *P_REENTRANT_ENV_KEYS.values(),
                                }.intersection(kwargs["environment"]))
                                return subprocess.CompletedProcess(
                                    list(command), 71, "", "",
                                )
                            if len(active_process_calls) == 2:
                                self.assertEqual((
                                    str(Path(sys.executable).resolve()),
                                    "-I", "-S", "-B", "-c", P_REENTRANT_WRITE_PROBE,
                                    str(active_fixture.snapshot / "six.py"),
                                    str(active_fixture.python_home.components[-1][0]),
                                ), tuple(command))
                                self.assertEqual((), tuple(kwargs["pass_fds"]))
                                self.assertEqual(set(), {
                                    P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                                    P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
                                    *P_REENTRANT_ENV_KEYS.values(),
                                }.intersection(kwargs["environment"]))
                                return subprocess.CompletedProcess(
                                    list(command), 0,
                                    json.dumps(expected_active_write, sort_keys=True) + "\n",
                                    "",
                                )
                            self.assertEqual(3, len(active_process_calls))
                            passed = tuple(kwargs["pass_fds"])
                            active_owned_fds.extend(passed)
                            self.assertEqual(7, len(passed))
                            self.assertEqual(7, len(set(passed)))
                            self.assertEqual(set(), set(passed).intersection(active_fixture_fds))
                            self.assertEqual(
                                active_fixture_identities,
                                tuple(
                                    (os.fstat(descriptor).st_dev,
                                     os.fstat(descriptor).st_ino)
                                    for descriptor in passed
                                ),
                            )
                            for descriptor in passed:
                                self.assertFalse(os.get_inheritable(descriptor))
                            environment = kwargs["environment"]
                            self.assertEqual(
                                set(active_fixture_environment),
                                set(active_fixture_environment).intersection(environment),
                            )
                            self.assertEqual(str(passed[0]), environment[P_CAPSULE_FD_ENV])
                            self.assertEqual(
                                str(passed[1]),
                                environment[P_REENTRANT_ENV_KEYS["snapshot_fd"]],
                            )
                            self.assertEqual(
                                ",".join(str(descriptor) for descriptor in passed[2:]),
                                environment[P_REENTRANT_ENV_KEYS["python_home_fds"]],
                            )
                            for protocol_key in set(active_fixture_environment) - {
                                P_CAPSULE_FD_ENV,
                                P_REENTRANT_ENV_KEYS["snapshot_fd"],
                                P_REENTRANT_ENV_KEYS["python_home_fds"],
                            }:
                                self.assertEqual(
                                    active_fixture_environment[protocol_key],
                                    environment[protocol_key],
                                )
                            if producer_index < 3:
                                self.assertEqual(
                                    "1",
                                    environment[P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV],
                                )
                            else:
                                self.assertNotIn(
                                    P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV, environment,
                                )
                            self.assertEqual((
                                str(Path(sys.executable).resolve()),
                                "-I", "-S", "-B", "-c", P_CAPSULE_BOOTSTRAP,
                                str(active_fixture.snapshot), str(ROOT.resolve()),
                                json.dumps(list(producer_arguments), separators=(",", ":")),
                            ), tuple(command))
                            return producer_result

                        def observe_active_loopback_consumer():
                            authority = loopback_consumer()
                            active_consumed_loopbacks.append(authority)
                            return authority

                        active_loopback_identity = (
                            inherited_loopback.root.lstat().st_dev,
                            inherited_loopback.root.lstat().st_ino,
                        )
                        active_loopback_pgid = os.getpgid(
                            inherited_loopback.daemon_pid,
                        )
                        with mock.patch.dict(
                            os.environ, {
                                **active_fixture_environment,
                                P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV:
                                    active_fixture_loopback_marker,
                            }, clear=True,
                        ), mock.patch.object(
                            module, "_run_bounded_process",
                            side_effect=observe_active_producer_process,
                        ) as active_bounded, mock.patch.object(
                            module, "_formal_loopback_sshd_authority_from_environment",
                            side_effect=observe_active_loopback_consumer,
                        ) as active_loopback_consumer, mock.patch.object(
                            module, "_formal_loopback_sshd_scope",
                            side_effect=AssertionError(
                                "active producer attempted nested loopback scope"
                            ),
                        ) as forbidden_active_scope:
                            produced = _python_run(
                                ROOT, list(producer_arguments), timeout=91,
                                dependency_archive=borrowed_archive,
                                ambient=hostile,
                            )
                        self.assertIs(producer_result, produced)
                        self.assertEqual(3, active_bounded.call_count)
                        forbidden_active_scope.assert_not_called()
                        self.assertEqual(
                            1 if producer_index < 3 else 0,
                            active_loopback_consumer.call_count,
                        )
                        self.assertEqual(
                            1 if producer_index < 3 else 0,
                            len(active_consumed_loopbacks),
                        )
                        for consumed_loopback in active_consumed_loopbacks:
                            assert_reused_active_loopback(consumed_loopback)
                            self.assertEqual(
                                (
                                    inherited_loopback.root,
                                    inherited_loopback.port,
                                    inherited_loopback.daemon_pid,
                                    dict(inherited_loopback.public_keys),
                                    dict(inherited_loopback.fingerprints),
                                    active_fixture_fds,
                                ),
                                (
                                    consumed_loopback.root,
                                    consumed_loopback.port,
                                    consumed_loopback.daemon_pid,
                                    dict(consumed_loopback.public_keys),
                                    dict(consumed_loopback.fingerprints),
                                    consumed_loopback.source_fds,
                                ),
                            )
                        self.assertEqual(7, len(active_owned_fds))
                        for descriptor in active_owned_fds:
                            with self.assertRaises(OSError):
                                os.fstat(descriptor)
                        self.assertEqual(
                            active_fixture_identities,
                            tuple(
                                (os.fstat(descriptor).st_dev,
                                 os.fstat(descriptor).st_ino)
                                for descriptor in active_fixture_fds
                            ),
                        )
                        self.assertEqual(
                            active_fixture_flags,
                            tuple(
                                (
                                    fcntl.fcntl(descriptor, fcntl.F_GETFL),
                                    fcntl.fcntl(descriptor, fcntl.F_GETFD),
                                )
                                for descriptor in active_fixture_fds
                            ),
                        )
                        self.assertEqual(
                            active_fixture_offset,
                            os.lseek(active_fixture.archive_fd, 0, os.SEEK_CUR),
                        )
                        self.assertEqual(
                            active_loopback_identity,
                            (
                                inherited_loopback.root.lstat().st_dev,
                                inherited_loopback.root.lstat().st_ino,
                            ),
                        )
                        os.kill(inherited_loopback.daemon_pid, 0)
                        self.assertEqual(
                            active_loopback_pgid,
                            os.getpgid(inherited_loopback.daemon_pid),
                        )

                # Exercise the real Darwin sandbox once.  The child receives
                # the existing seven dependency descriptors only; the parent
                # fixture is protected by pathname policy and parent-held FDs.
                expected_mutation_report = {
                    "chmod": errno.EPERM,
                    "open": errno.EPERM,
                    "rename": errno.EPERM,
                    "state-openat": errno.EPERM,
                    "unlink": errno.EPERM,
                }
                mutation_owned_fds = []
                mutation_consumers = []
                def observe_active_mutation_process(command, **kwargs):
                    if kwargs["pass_fds"]:
                        mutation_owned_fds.extend(kwargs["pass_fds"])
                    return run_bounded(command, **kwargs)
                def observe_mutation_consumer():
                    authority = loopback_consumer()
                    mutation_consumers.append(authority)
                    return authority
                mutation_environment = (
                    {} if active_fixture is None else {
                        **active_fixture_environment,
                        P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV:
                            active_fixture_loopback_marker,
                    }
                )
                mutation_archive = (
                    dependency_archive
                    if active_fixture is None else borrowed_archive
                )
                with mock.patch.object(
                    module, "P_CAPSULE_BOOTSTRAP",
                    P_EXPECTED_FORMAL_LOOPBACK_MUTATION_PROBE,
                ), mock.patch.dict(
                    os.environ, mutation_environment, clear=True,
                ), mock.patch.object(
                    module, "_run_bounded_process",
                    side_effect=(
                        observe_active_mutation_process
                        if active_fixture is not None else run_bounded
                    ),
                ) as mutation_bounded, mock.patch.object(
                    module, "_formal_loopback_sshd_authority_from_environment",
                    side_effect=observe_mutation_consumer,
                ) as mutation_consumer, mock.patch.object(
                    module, "_formal_loopback_sshd_scope",
                    wraps=loopback_scope,
                ) as mutation_scope:
                    mutation_result = _python_run(
                        ROOT, list(reviewed_reentrant_runner_arguments[0]),
                        timeout=30, dependency_archive=mutation_archive,
                        ambient=hostile,
                    )
                self.assertEqual(0, mutation_result.returncode, mutation_result.stderr)
                self.assertEqual("", mutation_result.stderr)
                self.assertEqual(
                    json.dumps(expected_mutation_report, sort_keys=True) + "\n",
                    mutation_result.stdout,
                )
                if active_fixture is None:
                    mutation_consumer.assert_not_called()
                    mutation_scope.assert_called_once()
                    self.assertFalse(any(
                        path.name in {"authority.moved", "hostile-child"}
                        for path in formal_root.rglob("*")
                    ))
                    os.fstat(archive_fd)
                    self.assertEqual(
                        producer_offset, os.lseek(archive_fd, 0, os.SEEK_CUR),
                    )
                else:
                    mutation_consumer.assert_called_once()
                    mutation_scope.assert_not_called()
                    self.assertEqual(3, mutation_bounded.call_count)
                    self.assertEqual(1, len(mutation_consumers))
                    assert_reused_active_loopback(mutation_consumers[0])
                    self.assertEqual(7, len(mutation_owned_fds))
                    for descriptor in mutation_owned_fds:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    self.assertFalse(os.path.lexists(
                        inherited_loopback.root / "authority.moved"
                    ))
                    self.assertFalse(os.path.lexists(
                        active_fixture.snapshot.parent / "hostile-child"
                    ))

                # A dedicated non-recursive probe runs the real ZTP FQN under
                # the actual sandbox and reviewed exact-seven unittest
                # bootstrap.  This proves that the child consumes the parent
                # daemon while retaining every fake and live KEX assertion.
                ztp_fqn = (
                    "test_cases.test_ztp_release_core_review."
                    "BackupAuthenticationContractTests."
                    "test_stock_openssh_known_hosts_command_is_strict_on_loopback"
                )
                ztp_verbose_line = (
                    "test_stock_openssh_known_hosts_command_is_strict_on_loopback "
                    "(test_cases.test_ztp_release_core_review."
                    "BackupAuthenticationContractTests) ... ok"
                )
                real_capsule_sandbox = run_sandbox
                active_ztp_boundaries = []
                def run_active_ztp_probe(command, **kwargs):
                    environment = dict(kwargs["environment"])
                    passed = tuple(kwargs["pass_fds"])
                    self.assertEqual(7, len(passed))
                    self.assertEqual(7, len(set(passed)))
                    self.assertEqual(
                        "1", environment[P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV],
                    )
                    snapshot_path = Path(
                        environment[P_REENTRANT_ENV_KEYS["snapshot"]]
                    ).resolve()
                    python_home = Path(
                        environment[P_REENTRANT_ENV_KEYS["python_home"]]
                    ).resolve()
                    stdlib = Path(P_CAPSULE_STDLIB_ROOT).resolve()
                    environment.update({
                        "PYTHONHOME": str(python_home),
                        "PYTHONPATH": os.pathsep.join((
                            str(snapshot_path), str(stdlib),
                            str(stdlib / "lib-dynload"),
                        )),
                        "PYTHONNOUSERSITE": "1",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    })
                    probe_command = (
                        *tuple(command[:8]), P_REENTRANT_UNITTEST_BOOTSTRAP,
                        str(ROOT.resolve()),
                        json.dumps(["unittest", "-v", ztp_fqn], separators=(",", ":")),
                    )
                    active_ztp_boundaries.append((probe_command, passed))
                    return real_capsule_sandbox(
                        probe_command, cwd=kwargs["cwd"], environment=environment,
                        pass_fds=passed, timeout=kwargs["timeout"],
                    )
                active_ztp_owned_fds = []
                active_ztp_consumers = []
                def run_inherited_ztp_probe(command, **kwargs):
                    passed = tuple(kwargs["pass_fds"])
                    if not passed:
                        return run_bounded(command, **kwargs)
                    self.assertEqual(7, len(passed))
                    self.assertEqual(7, len(set(passed)))
                    active_ztp_owned_fds.extend(passed)
                    environment = dict(kwargs["environment"])
                    self.assertEqual(
                        "1", environment[P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV],
                    )
                    self.assertEqual(
                        set(),
                        {key for key in environment if key.startswith("PYTHON")},
                    )
                    active_snapshot = active_fixture.snapshot.resolve()
                    active_python_home = (
                        active_fixture.python_home.components[0][0].resolve()
                    )
                    active_stdlib = Path(P_CAPSULE_STDLIB_ROOT).resolve()
                    expected_active_python_environment = {
                        "PYTHONHOME": str(active_python_home),
                        "PYTHONPATH": os.pathsep.join((
                            str(active_snapshot), str(active_stdlib),
                            str(active_stdlib / "lib-dynload"),
                        )),
                        "PYTHONNOUSERSITE": "1",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    }
                    environment.update(expected_active_python_environment)
                    self.assertEqual(
                        expected_active_python_environment,
                        {
                            key: environment[key]
                            for key in expected_active_python_environment
                        },
                    )
                    probe_command = (
                        *tuple(command[:5]), P_REENTRANT_UNITTEST_BOOTSTRAP,
                        str(ROOT.resolve()),
                        json.dumps(
                            ["unittest", "-v", ztp_fqn], separators=(",", ":"),
                        ),
                    )
                    active_ztp_boundaries.append((probe_command, passed))
                    return run_bounded(
                        probe_command, cwd=kwargs["cwd"], environment=environment,
                        pass_fds=passed, timeout=kwargs["timeout"],
                    )
                def observe_active_ztp_consumer():
                    authority = loopback_consumer()
                    active_ztp_consumers.append(authority)
                    return authority
                ztp_environment = (
                    {} if active_fixture is None else {
                        **active_fixture_environment,
                        P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV:
                            active_fixture_loopback_marker,
                    }
                )
                ztp_archive = (
                    dependency_archive
                    if active_fixture is None else borrowed_archive
                )
                with mock.patch.object(
                    module, "_run_capsule_sandbox",
                    side_effect=run_active_ztp_probe,
                ), mock.patch.object(
                    module, "_run_bounded_process",
                    side_effect=(
                        run_inherited_ztp_probe
                        if active_fixture is not None else run_bounded
                    ),
                ) as ztp_bounded, mock.patch.object(
                    module, "_formal_loopback_sshd_authority_from_environment",
                    side_effect=observe_active_ztp_consumer,
                ) as ztp_consumer, mock.patch.object(
                    module, "_formal_loopback_sshd_scope", wraps=loopback_scope,
                ) as ztp_scope, mock.patch.dict(
                    os.environ, ztp_environment, clear=True,
                ):
                    ztp_result = _python_run(
                        ROOT, list(reviewed_reentrant_runner_arguments[0]),
                        timeout=45, dependency_archive=ztp_archive,
                        ambient=hostile,
                    )
                self.assertEqual(0, ztp_result.returncode, ztp_result.stderr)
                self.assertEqual(1, len(active_ztp_boundaries))
                self.assertEqual(
                    1, ztp_result.stderr.splitlines().count(ztp_verbose_line),
                    ztp_result.stderr,
                )
                self.assertIn("Ran 1 test", ztp_result.stderr)
                self.assertIn("OK", ztp_result.stderr)
                if active_fixture is None:
                    ztp_consumer.assert_not_called()
                    ztp_scope.assert_called_once()
                    os.fstat(archive_fd)
                    self.assertEqual(
                        producer_offset, os.lseek(archive_fd, 0, os.SEEK_CUR),
                    )
                else:
                    ztp_consumer.assert_called_once()
                    ztp_scope.assert_not_called()
                    self.assertEqual(3, ztp_bounded.call_count)
                    self.assertEqual(1, len(active_ztp_consumers))
                    assert_reused_active_loopback(active_ztp_consumers[0])
                    self.assertEqual(7, len(active_ztp_owned_fds))
                    for descriptor in active_ztp_owned_fds:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)

                near_miss_arguments = (
                    (
                        "-B", "test_cases/run_related_tests.py", "--all", "-v",
                        "extra",
                    ),
                    (
                        "-B", "test_cases/run_related_tests.py", "-v", "--all",
                    ),
                    ("-B", "-c", "print('ordinary child')"),
                )
                for near_arguments in near_miss_arguments:
                    near_boundaries = []
                    near_archive = (
                        dependency_archive
                        if active_fixture is None else borrowed_archive
                    )
                    def observe_near_miss(command, **kwargs):
                        environment = kwargs["environment"]
                        passed = tuple(kwargs["pass_fds"])
                        self.assertEqual((near_archive.fd,), passed)
                        self.assertEqual(
                            set(), set(P_REENTRANT_ENV_KEYS.values()).intersection(environment),
                        )
                        self.assertNotIn(
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV, environment,
                        )
                        self.assertEqual(
                            str(near_archive.fd), environment[P_CAPSULE_FD_ENV],
                        )
                        self.assertEqual(list(near_arguments), json.loads(command[-1]))
                        near_boundaries.append(Path(command[-3]).parent)
                        return producer_result
                    near_environment = (
                        {} if active_fixture is None else {
                            **active_fixture_environment,
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV:
                                active_fixture_loopback_marker,
                        }
                    )
                    with self.subTest(reentrant_near_miss=near_arguments):
                        if active_fixture is None:
                            with mock.patch.dict(
                                os.environ, near_environment, clear=True,
                            ), mock.patch.object(
                                module, "_run_capsule_sandbox",
                                side_effect=observe_near_miss,
                            ) as near_sandbox, mock.patch.object(
                                module, "_formal_loopback_sshd_scope",
                            ) as near_parent_sshd, mock.patch.object(
                                module,
                                "_formal_loopback_sshd_authority_from_environment",
                                wraps=loopback_consumer,
                            ) as near_loopback_consumer:
                                near_returned = _python_run(
                                    ROOT, list(near_arguments), timeout=91,
                                    dependency_archive=near_archive,
                                    ambient=hostile,
                                )
                        else:
                            near_process_calls = []
                            near_owned_fds = []
                            duplicate_authority = getattr(
                                module, "_duplicate_reentrant_authority",
                            )
                            def observe_near_duplicate(authority):
                                duplicated = duplicate_authority(authority)
                                near_owned_fds.extend(duplicated)
                                return duplicated
                            def observe_active_near_process(command, **kwargs):
                                near_process_calls.append((tuple(command), dict(kwargs)))
                                if len(near_process_calls) == 1:
                                    return subprocess.CompletedProcess(
                                        list(command), 71, "", "",
                                    )
                                if len(near_process_calls) == 2:
                                    return subprocess.CompletedProcess(
                                        list(command), 0,
                                        json.dumps(expected_active_write, sort_keys=True)
                                        + "\n", "",
                                    )
                                self.assertEqual(3, len(near_process_calls))
                                environment = kwargs["environment"]
                                passed = tuple(kwargs["pass_fds"])
                                self.assertEqual((near_owned_fds[0],), passed)
                                self.assertEqual(
                                    set(),
                                    set(P_REENTRANT_ENV_KEYS.values()).intersection(
                                        environment
                                    ),
                                )
                                self.assertNotIn(
                                    P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                                    environment,
                                )
                                self.assertEqual(
                                    str(passed[0]), environment[P_CAPSULE_FD_ENV],
                                )
                                self.assertEqual(
                                    list(near_arguments), json.loads(command[-1]),
                                )
                                return producer_result
                            with mock.patch.dict(
                                os.environ, near_environment, clear=True,
                            ), mock.patch.object(
                                module, "_run_bounded_process",
                                side_effect=observe_active_near_process,
                            ) as near_bounded, mock.patch.object(
                                module, "_duplicate_reentrant_authority",
                                side_effect=observe_near_duplicate,
                            ) as near_duplicate, mock.patch.object(
                                module, "_formal_loopback_sshd_scope",
                            ) as near_parent_sshd, mock.patch.object(
                                module,
                                "_formal_loopback_sshd_authority_from_environment",
                                wraps=loopback_consumer,
                            ) as near_loopback_consumer:
                                near_returned = _python_run(
                                    ROOT, list(near_arguments), timeout=91,
                                    dependency_archive=near_archive,
                                    ambient=hostile,
                                )
                            near_sandbox = None
                            self.assertEqual(3, near_bounded.call_count)
                            near_duplicate.assert_called_once()
                            self.assertEqual(7, len(near_owned_fds))
                            for descriptor in near_owned_fds:
                                with self.assertRaises(OSError):
                                    os.fstat(descriptor)
                    self.assertIs(producer_result, near_returned)
                    if near_sandbox is not None:
                        near_sandbox.assert_called_once()
                    near_parent_sshd.assert_not_called()
                    near_loopback_consumer.assert_not_called()
                    if active_fixture is None:
                        self.assertEqual(1, len(near_boundaries))
                        self.assertFalse(os.path.lexists(near_boundaries[0]))
                        os.fstat(archive_fd)
                        self.assertEqual(
                            producer_offset,
                            os.lseek(archive_fd, 0, os.SEEK_CUR),
                        )
                    else:
                        assert_reused_active_loopback(loopback_consumer())

                class ProducerBoundaryFailure(BaseException):
                    pass
                producer_failure = ProducerBoundaryFailure("producer sandbox interrupted")
                producer_failure_archive = (
                    dependency_archive
                    if active_fixture is None else borrowed_archive
                )
                producer_archive_summary = verify_archive(producer_failure_archive)
                producer_repository_head = _head(ROOT)
                producer_repository_status = _git_run(
                    ROOT, ["status", "--porcelain=v1", "-z"], text=True, check=True,
                ).stdout
                producer_index_path = Path(_git_run(
                    ROOT, ["rev-parse", "--git-path", "index"], text=True, check=True,
                ).stdout.strip())
                if not producer_index_path.is_absolute():
                    producer_index_path = ROOT / producer_index_path
                producer_index = producer_index_path.read_bytes()
                producer_ledger = (ROOT / P_LEDGER_PATH).read_bytes()
                failed_boundary = []
                def fail_reentrant_producer(command, **kwargs):
                    observe_reentrant_producer(command, **kwargs)
                    failed_boundary[:] = producer_boundaries
                    raise producer_failure
                producer_boundaries.clear()
                loopback_scope_calls.clear()
                loopback_scope_authorities.clear()
                if active_fixture is None:
                    with mock.patch.object(
                        module, "_run_capsule_sandbox",
                        side_effect=fail_reentrant_producer,
                    ) as failed_sandbox, mock.patch.object(
                        module, "_formal_loopback_sshd_scope",
                        side_effect=observed_loopback_scope,
                    ) as failed_parent_sshd, mock.patch.dict(
                        os.environ, {}, clear=True,
                    ):
                        try:
                            _python_run(
                                ROOT, list(reviewed_reentrant_runner_arguments[0]),
                                timeout=91, dependency_archive=dependency_archive,
                                ambient=hostile,
                            )
                        except BaseException as observed_failure:
                            self.assertIs(producer_failure, observed_failure)
                        else:
                            self.fail("producer sandbox BaseException was swallowed")
                    failed_sandbox.assert_called_once()
                    failed_parent_sshd.assert_called_once()
                    self.assertEqual(1, len(loopback_scope_authorities))
                    self.assertEqual(("enter", "exit"), tuple(
                        event for event, _path in loopback_scope_calls
                    ))
                    failed_loopback_root, failed_loopback_fds, \
                            failed_loopback_pid, failed_loopback_pgid = (
                                loopback_scope_authorities[0]
                            )
                    self.assertFalse(os.path.lexists(failed_loopback_root))
                    for descriptor in failed_loopback_fds:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(failed_loopback_pid, 0)
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(failed_loopback_pgid, 0)
                    self.assertEqual(1, len(failed_boundary))
                    failed_state, failed_fds = failed_boundary[0]
                    self.assertFalse(os.path.lexists(failed_state))
                    for descriptor in failed_fds[1:]:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    os.fstat(archive_fd)
                    self.assertEqual(
                        producer_offset, os.lseek(archive_fd, 0, os.SEEK_CUR),
                    )
                else:
                    failed_active_calls = []
                    failed_active_owned = []
                    failed_active_consumers = []
                    failed_loopback_identity = (
                        inherited_loopback.root.lstat().st_dev,
                        inherited_loopback.root.lstat().st_ino,
                    )
                    failed_loopback_pgid = os.getpgid(
                        inherited_loopback.daemon_pid,
                    )
                    def fail_active_producer_process(command, **kwargs):
                        failed_active_calls.append((tuple(command), dict(kwargs)))
                        if len(failed_active_calls) == 1:
                            return subprocess.CompletedProcess(
                                list(command), 71, "", "",
                            )
                        if len(failed_active_calls) == 2:
                            return subprocess.CompletedProcess(
                                list(command), 0,
                                json.dumps(expected_active_write, sort_keys=True) + "\n",
                                "",
                            )
                        self.assertEqual(3, len(failed_active_calls))
                        failed_active_owned.extend(kwargs["pass_fds"])
                        self.assertEqual(
                            active_fixture_identities,
                            tuple(
                                (os.fstat(descriptor).st_dev,
                                 os.fstat(descriptor).st_ino)
                                for descriptor in kwargs["pass_fds"]
                            ),
                        )
                        raise producer_failure
                    def observe_failed_active_consumer():
                        authority = loopback_consumer()
                        failed_active_consumers.append(authority)
                        return authority
                    with mock.patch.dict(
                        os.environ, {
                            **active_fixture_environment,
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV:
                                active_fixture_loopback_marker,
                        }, clear=True,
                    ), mock.patch.object(
                        module, "_run_bounded_process",
                        side_effect=fail_active_producer_process,
                    ) as failed_active_process, mock.patch.object(
                        module, "_formal_loopback_sshd_authority_from_environment",
                        side_effect=observe_failed_active_consumer,
                    ) as failed_active_consumer, mock.patch.object(
                        module, "_formal_loopback_sshd_scope",
                        side_effect=AssertionError(
                            "active failure attempted nested loopback scope"
                        ),
                    ) as failed_active_scope:
                        try:
                            _python_run(
                                ROOT, list(reviewed_reentrant_runner_arguments[0]),
                                timeout=91, dependency_archive=borrowed_archive,
                                ambient=hostile,
                            )
                        except BaseException as observed_failure:
                            self.assertIs(producer_failure, observed_failure)
                        else:
                            self.fail("active producer BaseException was swallowed")
                    self.assertEqual(3, failed_active_process.call_count)
                    failed_active_consumer.assert_called_once()
                    failed_active_scope.assert_not_called()
                    self.assertEqual(1, len(failed_active_consumers))
                    failed_consumer = failed_active_consumers[0]
                    assert_reused_active_loopback(failed_consumer)
                    self.assertEqual(
                        (
                            inherited_loopback.root,
                            inherited_loopback.port,
                            inherited_loopback.daemon_pid,
                            dict(inherited_loopback.public_keys),
                            dict(inherited_loopback.fingerprints),
                            active_fixture_fds,
                        ),
                        (
                            failed_consumer.root,
                            failed_consumer.port,
                            failed_consumer.daemon_pid,
                            dict(failed_consumer.public_keys),
                            dict(failed_consumer.fingerprints),
                            failed_consumer.source_fds,
                        ),
                    )
                    self.assertEqual(7, len(failed_active_owned))
                    for descriptor in failed_active_owned:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    self.assertEqual(
                        active_fixture_identities,
                        tuple(
                            (os.fstat(descriptor).st_dev,
                             os.fstat(descriptor).st_ino)
                            for descriptor in active_fixture_fds
                        ),
                    )
                    self.assertEqual(
                        active_fixture_flags,
                        tuple(
                            (
                                fcntl.fcntl(descriptor, fcntl.F_GETFL),
                                fcntl.fcntl(descriptor, fcntl.F_GETFD),
                            )
                            for descriptor in active_fixture_fds
                        ),
                    )
                    self.assertEqual(
                        active_fixture_offset,
                        os.lseek(active_fixture.archive_fd, 0, os.SEEK_CUR),
                    )
                    self.assertEqual(
                        failed_loopback_identity,
                        (
                            inherited_loopback.root.lstat().st_dev,
                            inherited_loopback.root.lstat().st_ino,
                        ),
                    )
                    os.kill(inherited_loopback.daemon_pid, 0)
                    self.assertEqual(
                        failed_loopback_pgid,
                        os.getpgid(inherited_loopback.daemon_pid),
                    )
                self.assertEqual(
                    producer_archive_summary,
                    verify_archive(producer_failure_archive),
                )
                self.assertEqual(producer_repository_head, _head(ROOT))
                self.assertEqual(producer_index, producer_index_path.read_bytes())
                self.assertEqual(producer_ledger, (ROOT / P_LEDGER_PATH).read_bytes())
                self.assertEqual(
                    producer_repository_status,
                    _git_run(
                        ROOT, ["status", "--porcelain=v1", "-z"],
                        text=True, check=True,
                    ).stdout,
                )

                # Equal-length writes preserve the inode, size, and restored
                # mtime.  Post-child verification therefore has to compare
                # the held bytes, not merely pathname metadata.
                for poison_name, poison_mode in (
                    ("authority.json", 0o400),
                    ("host-ed25519.pub", 0o644),
                ):
                    if active_fixture is not None:
                        active_poison_target = (
                            inherited_loopback.root / poison_name
                        )
                        active_poison_before = loopback_consumer()
                        assert_reused_active_loopback(active_poison_before)
                        active_poison_flags = (
                            os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                            | os.O_CLOEXEC
                        )
                        with self.subTest(
                            active_loopback_write_denial=poison_name,
                        ), mock.patch.object(
                            module, "_formal_loopback_sshd_scope",
                        ) as active_poison_scope:
                            try:
                                unexpected_writer = os.open(
                                    active_poison_target, active_poison_flags,
                                )
                            except OSError as error:
                                self.assertEqual(errno.EPERM, error.errno)
                            else:
                                os.close(unexpected_writer)
                                self.fail(
                                    "outer sandbox allowed formal loopback write"
                                )
                        active_poison_scope.assert_not_called()
                        active_poison_after = loopback_consumer()
                        assert_reused_active_loopback(active_poison_after)
                        self.assertEqual(
                            active_inherited_loopback_value,
                            (
                                active_poison_before.root,
                                active_poison_before.port,
                                active_poison_before.daemon_pid,
                                dict(active_poison_before.public_keys),
                                dict(active_poison_before.fingerprints),
                                active_poison_before.source_fds,
                            ),
                        )
                        self.assertEqual(
                            active_inherited_loopback_value,
                            (
                                active_poison_after.root,
                                active_poison_after.port,
                                active_poison_after.daemon_pid,
                                dict(active_poison_after.public_keys),
                                dict(active_poison_after.fingerprints),
                                active_poison_after.source_fds,
                            ),
                        )
                        continue
                    poison_events = []
                    poison_fds = []
                    real_dependency_observer = _dependency_archive_observer
                    def poison_held_loopback_file(event, **authority):
                        if event == "after-child" and not poison_events:
                            state_path = Path(authority["state_root"])
                            target = (
                                state_path / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE
                                / poison_name
                            )
                            held_flags = (
                                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                                | os.O_CLOEXEC
                            )
                            held = os.open(target, held_flags)
                            poison_fds.append(held)
                            try:
                                before = os.fstat(held)
                                named_before = target.lstat()
                                self.assertTrue(stat.S_ISREG(before.st_mode))
                                self.assertEqual(
                                    poison_mode, stat.S_IMODE(before.st_mode),
                                )
                                self.assertEqual(1, before.st_nlink)
                                self.assertEqual(
                                    (before.st_dev, before.st_ino),
                                    (named_before.st_dev, named_before.st_ino),
                                )
                                self.assertEqual(
                                    os.O_RDONLY,
                                    fcntl.fcntl(held, fcntl.F_GETFL)
                                    & os.O_ACCMODE,
                                )
                                self.assertTrue(
                                    fcntl.fcntl(held, fcntl.F_GETFD)
                                    & fcntl.FD_CLOEXEC,
                                )
                                original = os.pread(held, before.st_size + 1, 0)
                                self.assertEqual(before.st_size, len(original))
                                hostile_bytes = bytes(
                                    byte ^ 0x01 for byte in original
                                )
                                os.fchmod(held, poison_mode | stat.S_IWUSR)
                                writer = None
                                try:
                                    writer_flags = (
                                        os.O_WRONLY | os.O_NOFOLLOW
                                        | os.O_NONBLOCK | os.O_CLOEXEC
                                    )
                                    writer = os.open(target, writer_flags)
                                    poison_fds.append(writer)
                                    writer_metadata = os.fstat(writer)
                                    self.assertTrue(
                                        stat.S_ISREG(writer_metadata.st_mode),
                                    )
                                    self.assertEqual(1, writer_metadata.st_nlink)
                                    self.assertEqual(
                                        (before.st_dev, before.st_ino),
                                        (writer_metadata.st_dev,
                                         writer_metadata.st_ino),
                                    )
                                    opened_flags = fcntl.fcntl(
                                        writer, fcntl.F_GETFL,
                                    )
                                    self.assertEqual(
                                        os.O_WRONLY, opened_flags & os.O_ACCMODE,
                                    )
                                    self.assertEqual(
                                        0,
                                        opened_flags & (
                                            os.O_CREAT | os.O_EXCL | os.O_TRUNC
                                            | os.O_APPEND
                                        ),
                                    )
                                    self.assertTrue(
                                        fcntl.fcntl(writer, fcntl.F_GETFD)
                                        & fcntl.FD_CLOEXEC,
                                    )
                                    self.assertEqual(
                                        len(hostile_bytes),
                                        os.pwrite(writer, hostile_bytes, 0),
                                    )
                                    os.fsync(writer)
                                finally:
                                    if writer is not None:
                                        os.close(writer)
                                    os.fchmod(held, poison_mode)
                                    os.utime(
                                        held,
                                        ns=(before.st_atime_ns,
                                            before.st_mtime_ns),
                                    )
                                after = os.fstat(held)
                                named_after = target.lstat()
                                stable_before = (
                                    before.st_dev, before.st_ino, before.st_mode,
                                    before.st_nlink, before.st_size,
                                    before.st_mtime_ns,
                                )
                                self.assertEqual(
                                    stable_before,
                                    (
                                        after.st_dev, after.st_ino,
                                        after.st_mode, after.st_nlink,
                                        after.st_size, after.st_mtime_ns,
                                    ),
                                )
                                self.assertEqual(
                                    stable_before,
                                    (
                                        named_after.st_dev, named_after.st_ino,
                                        named_after.st_mode, named_after.st_nlink,
                                        named_after.st_size,
                                        named_after.st_mtime_ns,
                                    ),
                                )
                                self.assertEqual(
                                    hostile_bytes,
                                    os.pread(held, after.st_size + 1, 0),
                                )
                                self.assertNotEqual(original, hostile_bytes)
                                poison_events.append(target)
                            finally:
                                os.close(held)
                        return real_dependency_observer(event, **authority)
                    with self.subTest(loopback_equal_size_poison=poison_name), \
                            mock.patch.object(
                                module, "_dependency_archive_observer",
                                side_effect=poison_held_loopback_file,
                            ), mock.patch.object(
                                module, "_run_capsule_sandbox",
                                return_value=producer_result,
                            ) as poison_sandbox, mock.patch.dict(
                                os.environ, {}, clear=True,
                            ), self.assertRaisesRegex(
                                AssertionError,
                                r"\Aformal loopback held content changed\Z",
                            ):
                        _python_run(
                            ROOT,
                            list(reviewed_reentrant_runner_arguments[0]),
                            timeout=30,
                            dependency_archive=dependency_archive,
                            ambient=hostile,
                        )
                    poison_sandbox.assert_called_once()
                    self.assertEqual(1, len(poison_events))
                    self.assertEqual(2, len(poison_fds))
                    for descriptor in poison_fds:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    self.assertFalse(os.path.lexists(poison_events[0].parents[1]))
                    os.fstat(archive_fd)
                    self.assertEqual(
                        producer_offset, os.lseek(archive_fd, 0, os.SEEK_CUR),
                    )

                # The parent fixture root is also held across both observer
                # boundaries.  A symlink or a content-valid directory swap is
                # rejected before publication can continue.
                for fixture_phase in ("before-sandbox", "after-child"):
                    for fixture_replacement in ("symlink", "same-shape-directory"):
                        if active_fixture is not None:
                            active_rebind_leaf = inherited_loopback.root / (
                                "hostile-" + fixture_phase + "-"
                                + fixture_replacement
                            )
                            self.assertFalse(os.path.lexists(active_rebind_leaf))
                            active_rebind_events = []
                            active_rebind_before = loopback_consumer()
                            assert_reused_active_loopback(active_rebind_before)
                            def attempt_active_rebind():
                                active_rebind_events.append("attack")
                                try:
                                    if fixture_replacement == "symlink":
                                        os.symlink(
                                            "outside-hostile-target",
                                            active_rebind_leaf,
                                        )
                                    else:
                                        os.mkdir(active_rebind_leaf, 0o700)
                                except OSError as error:
                                    self.assertEqual(errno.EPERM, error.errno)
                                else:
                                    if fixture_replacement == "symlink":
                                        os.unlink(active_rebind_leaf)
                                    else:
                                        os.rmdir(active_rebind_leaf)
                                    self.fail(
                                        "outer sandbox allowed formal loopback "
                                        "fixture rebind"
                                    )
                            def run_active_rebind_boundary():
                                active_rebind_events.append("child")
                                result = run_bounded(
                                    ("/usr/bin/true",), cwd=ROOT,
                                    environment={}, pass_fds=(), timeout=5,
                                )
                                self.assertEqual(0, result.returncode, result.stderr)
                                self.assertEqual("", result.stdout)
                                self.assertEqual("", result.stderr)
                            with self.subTest(
                                active_fixture_rebind_phase=fixture_phase,
                                active_fixture_replacement=fixture_replacement,
                            ), mock.patch.object(
                                module, "_formal_loopback_sshd_scope",
                            ) as active_rebind_scope:
                                if fixture_phase == "before-sandbox":
                                    attempt_active_rebind()
                                    run_active_rebind_boundary()
                                else:
                                    run_active_rebind_boundary()
                                    attempt_active_rebind()
                            active_rebind_scope.assert_not_called()
                            self.assertEqual(
                                (
                                    ("attack", "child")
                                    if fixture_phase == "before-sandbox"
                                    else ("child", "attack")
                                ),
                                tuple(active_rebind_events),
                            )
                            self.assertFalse(os.path.lexists(active_rebind_leaf))
                            active_rebind_after = loopback_consumer()
                            assert_reused_active_loopback(active_rebind_after)
                            self.assertEqual(
                                active_inherited_loopback_value,
                                (
                                    active_rebind_before.root,
                                    active_rebind_before.port,
                                    active_rebind_before.daemon_pid,
                                    dict(active_rebind_before.public_keys),
                                    dict(active_rebind_before.fingerprints),
                                    active_rebind_before.source_fds,
                                ),
                            )
                            self.assertEqual(
                                active_inherited_loopback_value,
                                (
                                    active_rebind_after.root,
                                    active_rebind_after.port,
                                    active_rebind_after.daemon_pid,
                                    dict(active_rebind_after.public_keys),
                                    dict(active_rebind_after.fingerprints),
                                    active_rebind_after.source_fds,
                                ),
                            )
                            continue
                        fixture_attacks = []
                        outside_fixture = formal_root / (
                            "outside-loopback-" + fixture_phase + "-"
                            + fixture_replacement
                        )
                        outside_fixture.mkdir(mode=0o700)
                        outside_sentinel = outside_fixture / "sentinel"
                        outside_sentinel.write_bytes(b"outside-loopback-sentinel\n")
                        outside_before = outside_sentinel.read_bytes()
                        real_dependency_observer = _dependency_archive_observer
                        def rebind_parent_fixture(event, **authority):
                            if event == fixture_phase and not fixture_attacks:
                                state_path = Path(authority["state_root"])
                                fixture = (
                                    state_path
                                    / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE
                                )
                                held = fixture.with_name(fixture.name + ".held")
                                fixture.rename(held)
                                if fixture_replacement == "symlink":
                                    fixture.symlink_to(
                                        outside_fixture, target_is_directory=True,
                                    )
                                else:
                                    shutil.copytree(held, fixture)
                                fixture_attacks.append((fixture, held))
                            return real_dependency_observer(event, **authority)
                        with self.subTest(
                            fixture_rebind_phase=fixture_phase,
                            fixture_replacement=fixture_replacement,
                        ), mock.patch.object(
                            module, "_dependency_archive_observer",
                            side_effect=rebind_parent_fixture,
                        ), mock.patch.object(
                            module, "_run_capsule_sandbox",
                            return_value=producer_result,
                        ) as rebind_sandbox, mock.patch.dict(
                            os.environ, {}, clear=True,
                        ), self.assertRaises(AssertionError):
                            _python_run(
                                ROOT,
                                list(reviewed_reentrant_runner_arguments[0]),
                                timeout=30,
                                dependency_archive=dependency_archive,
                                ambient=hostile,
                            )
                        self.assertEqual(1, len(fixture_attacks))
                        self.assertEqual(
                            0 if fixture_phase == "before-sandbox" else 1,
                            rebind_sandbox.call_count,
                        )
                        self.assertEqual(outside_before, outside_sentinel.read_bytes())
                        shutil.rmtree(outside_fixture)
                        os.fstat(archive_fd)
                        self.assertEqual(
                            producer_offset,
                            os.lseek(archive_fd, 0, os.SEEK_CUR),
                        )

                # A content-valid replacement must still fail the held root
                # identity check.  Use a second fully extracted and verified
                # snapshot so neither row can pass merely because a symlink,
                # empty directory, or malformed payload was rejected first.
                for rebind_phase in ("before-sandbox", "after-child"):
                    twin_state = formal_root / (
                        "verified-snapshot-twin-" + rebind_phase
                    )
                    twin_state.mkdir(mode=0o700)
                    twin_snapshot = extract(dependency_archive, twin_state)
                    verify_snapshot(twin_snapshot)
                    rebind_events = []
                    rebind_target = {}
                    rebind_fds = []
                    sandbox_calls = []
                    def capture_rebind_open(path, flags, *args, **kwargs):
                        descriptor = real_open(path, flags, *args, **kwargs)
                        current = rebind_target.get("snapshot")
                        try:
                            opened = Path(os.fspath(path))
                        except TypeError:
                            opened = None
                        if current is not None and opened == current:
                            rebind_fds.append(descriptor)
                            rebind_events.append(("open", descriptor))
                        return descriptor
                    def swap_verified_snapshot(dynamic_snapshot):
                        live_roots = []
                        named = dynamic_snapshot.lstat()
                        for descriptor in rebind_fds:
                            try:
                                metadata = os.fstat(descriptor)
                            except OSError:
                                continue
                            if (
                                stat.S_ISDIR(metadata.st_mode)
                                and (metadata.st_dev, metadata.st_ino)
                                == (named.st_dev, named.st_ino)
                            ):
                                live_roots.append(descriptor)
                        self.assertEqual(1, len(live_roots))
                        held = dynamic_snapshot.with_name(
                            dynamic_snapshot.name + ".authority-held"
                        )
                        dynamic_snapshot.rename(held)
                        twin_snapshot.rename(dynamic_snapshot)
                        verify_snapshot(dynamic_snapshot)
                        replacement = dynamic_snapshot.lstat()
                        held_metadata = os.fstat(live_roots[0])
                        self.assertNotEqual(
                            (held_metadata.st_dev, held_metadata.st_ino),
                            (replacement.st_dev, replacement.st_ino),
                        )
                        rebind_events.append(("attack", rebind_phase))
                    def observe_verified_rebind(event, **authority):
                        if event == "snapshot-ready":
                            dynamic_snapshot = Path(authority["snapshot"])
                            rebind_target["snapshot"] = dynamic_snapshot
                            rebind_target["state"] = dynamic_snapshot.parent
                            rebind_events.append(("snapshot-ready", dynamic_snapshot))
                        elif event == rebind_phase:
                            swap_verified_snapshot(Path(authority["snapshot"]))
                    def observe_rebind_sandbox(command, **kwargs):
                        sandbox_calls.append((tuple(command), dict(kwargs)))
                        rebind_events.append(("sandbox", tuple(command)))
                        return producer_result
                    expected_error = (
                        "dependency snapshot authority changed before sandbox"
                        if rebind_phase == "before-sandbox"
                        else "dependency snapshot authority changed after child"
                    )
                    with self.subTest(verified_snapshot_root_rebind=rebind_phase), \
                            mock.patch.dict(os.environ, {}, clear=True), \
                            mock.patch.object(
                                module, "_dependency_archive_observer",
                                side_effect=observe_verified_rebind,
                            ), mock.patch.object(
                                module, "_run_capsule_sandbox",
                                side_effect=observe_rebind_sandbox,
                            ), mock.patch.object(
                                os, "open", side_effect=capture_rebind_open,
                            ), self.assertRaisesRegex(
                                AssertionError, expected_error,
                            ):
                        _python_run(
                            ROOT, list(P_REENTRANT_TEST_PROBE_ARGUMENTS), timeout=91,
                            dependency_archive=dependency_archive, ambient=hostile,
                        )
                    self.assertEqual(
                        0 if rebind_phase == "before-sandbox" else 1,
                        len(sandbox_calls),
                    )
                    event_names = [event[0] for event in rebind_events]
                    self.assertLess(
                        event_names.index("open"), event_names.index("attack"),
                    )
                    if rebind_phase == "after-child":
                        self.assertLess(
                            event_names.index("sandbox"), event_names.index("attack"),
                        )
                    self.assertFalse(os.path.lexists(rebind_target["state"]))
                    for descriptor in rebind_fds:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    self.assertEqual([], list(twin_state.iterdir()))
                    twin_state.rmdir()
                    os.fstat(archive_fd)
                    self.assertEqual(
                        producer_offset, os.lseek(archive_fd, 0, os.SEEK_CUR),
                    )

                call_state = formal_root / "call-state"
                call_state.mkdir(mode=0o700)
                real_open = os.open
                extract_opens = []
                def observed_extract_open(path, flags, *args, **kwargs):
                    descriptor = real_open(path, flags, *args, **kwargs)
                    extract_opens.append((os.fspath(path), flags, descriptor, kwargs.get("dir_fd")))
                    return descriptor
                with mock.patch.object(
                    tarfile.TarFile, "extract",
                    side_effect=AssertionError("unsafe TarFile.extract used"),
                ), mock.patch.object(
                    tarfile.TarFile, "extractall",
                    side_effect=AssertionError("unsafe TarFile.extractall used"),
                ), mock.patch.object(os, "open", side_effect=observed_extract_open), \
                        mock.patch.object(
                            os, "read", side_effect=AssertionError("extract must use archive pread"),
                        ) as extract_read, mock.patch.object(
                            os, "lseek", side_effect=AssertionError("extract must not move archive OFD"),
                        ) as extract_seek:
                    snapshot = extract(dependency_archive, call_state)
                extract_read.assert_not_called()
                extract_seek.assert_not_called()
                self.assertEqual(16384, os.lseek(archive_fd, 0, os.SEEK_CUR))
                self.assertEqual(0o700, stat.S_IMODE(snapshot.lstat().st_mode))
                leaf_opens = [item for item in extract_opens if item[1] & os.O_CREAT]
                self.assertEqual(P_CAPSULE_FILE_COUNT, len(leaf_opens))
                for name, flags, descriptor, parent_fd in leaf_opens:
                    self.assertNotIn("/", name)
                    self.assertIsNotNone(parent_fd)
                    self.assertEqual(os.O_WRONLY, flags & os.O_ACCMODE)
                    for required in (os.O_CREAT, os.O_EXCL, os.O_NOFOLLOW, os.O_CLOEXEC):
                        self.assertEqual(required, flags & required)
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                directory_opens = [
                    item for item in extract_opens
                    if item[1] & os.O_DIRECTORY and item[3] is not None
                ]
                self.assertTrue(directory_opens)
                for name, flags, descriptor, _ in directory_opens:
                    self.assertNotIn("/", name)
                    self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
                    for required in (os.O_DIRECTORY, os.O_NOFOLLOW, os.O_CLOEXEC):
                        self.assertEqual(required, flags & required)
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                verify_snapshot(snapshot)
                snapshot_authority = snapshot / "six.py"
                snapshot_payload = snapshot_authority.read_bytes()
                snapshot_metadata = snapshot_authority.lstat()
                verifier_opened, verifier_events, verifier_attacked, authority_fd = [], [], [], []
                real_fstat, real_pread = os.fstat, os.pread
                def verifier_open(path, flags, *args, **kwargs):
                    descriptor = real_open(path, flags, *args, **kwargs)
                    verifier_opened.append((descriptor, flags))
                    opened_metadata = real_fstat(descriptor)
                    if (opened_metadata.st_dev, opened_metadata.st_ino) == (
                        snapshot_metadata.st_dev, snapshot_metadata.st_ino,
                    ):
                        authority_fd[:] = [descriptor]
                    return descriptor
                def verifier_fstat(descriptor):
                    result = real_fstat(descriptor)
                    if authority_fd and descriptor == authority_fd[0]:
                        verifier_events.append("fstat")
                        if verifier_attacked:
                            result = SimpleNamespace(
                                st_dev=result.st_dev, st_ino=result.st_ino,
                                st_mode=result.st_mode, st_nlink=result.st_nlink,
                                st_size=result.st_size,
                                st_mtime_ns=snapshot_metadata.st_mtime_ns,
                                st_ctime_ns=snapshot_metadata.st_ctime_ns,
                            )
                    return result
                def verifier_pread(descriptor, size, offset):
                    payload = real_pread(descriptor, size, offset)
                    if authority_fd and descriptor == authority_fd[0]:
                        verifier_events.append("read")
                        if not verifier_attacked:
                            verifier_attacked.append(True)
                            hostile_payload = bytes([snapshot_payload[0] ^ 1]) + snapshot_payload[1:]
                            writer = real_open(
                                snapshot_authority,
                                os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            )
                            try:
                                os.pwrite(writer, hostile_payload, 0)
                                os.fsync(writer)
                            finally:
                                os.close(writer)
                            os.utime(
                                snapshot_authority,
                                ns=(snapshot_metadata.st_atime_ns, snapshot_metadata.st_mtime_ns),
                            )
                    return payload
                try:
                    with mock.patch.object(os, "open", side_effect=verifier_open), \
                            mock.patch.object(os, "fstat", side_effect=verifier_fstat), \
                            mock.patch.object(os, "pread", side_effect=verifier_pread), \
                            self.assertRaises(AssertionError):
                        verify_snapshot(snapshot)
                    self.assertEqual([True], verifier_attacked)
                    self.assertEqual(
                        ["fstat", "read", "fstat", "read", "fstat"],
                        verifier_events,
                    )
                    self.assertTrue(authority_fd)
                    verifier_fd = authority_fd[0]
                    verifier_flags = next(flags for fd, flags in verifier_opened if fd == verifier_fd)
                    self.assertEqual(os.O_RDONLY, verifier_flags & os.O_ACCMODE)
                    for required in (os.O_NOFOLLOW, os.O_NONBLOCK, os.O_CLOEXEC):
                        self.assertEqual(required, verifier_flags & required)
                    with self.assertRaises(OSError):
                        os.fstat(verifier_fd)
                finally:
                    snapshot_authority.write_bytes(snapshot_payload)
                    snapshot_authority.chmod(0o644)
                verify_snapshot(snapshot)
                for hostile_kind in ("symlink", "fifo"):
                    snapshot_authority.unlink()
                    if hostile_kind == "symlink":
                        snapshot_authority.symlink_to(snapshot / "yaml/__init__.py")
                    else:
                        os.mkfifo(snapshot_authority)
                    started = time.monotonic()
                    with self.subTest(snapshot_entry=hostile_kind), self.assertRaises(AssertionError):
                        verify_snapshot(snapshot)
                    self.assertLess(time.monotonic() - started, 3)
                    snapshot_authority.unlink()
                    snapshot_authority.write_bytes(snapshot_payload)
                    snapshot_authority.chmod(0o644)
                    verify_snapshot(snapshot)
                ordinary = snapshot / "numpy/tests/test_public_api.py"
                native = snapshot / "markupsafe/_speedups.cpython-39-darwin.so"
                for target in (ordinary, native):
                    reviewed_payload = target.read_bytes()
                    reviewed_mode = stat.S_IMODE(target.lstat().st_mode)
                    for mutation in ("missing", "content", "mode", "symlink", "fifo"):
                        try:
                            if mutation == "missing":
                                target.unlink()
                            elif mutation == "content":
                                target.write_bytes(bytes([reviewed_payload[0] ^ 1]) + reviewed_payload[1:])
                            elif mutation == "mode":
                                target.chmod(0o600)
                            elif mutation == "symlink":
                                target.unlink()
                                target.symlink_to(snapshot / "six.py")
                            else:
                                target.unlink()
                                os.mkfifo(target)
                            started = time.monotonic()
                            with self.subTest(snapshot_mutation=(target.relative_to(snapshot).as_posix(), mutation)), \
                                    self.assertRaises(AssertionError):
                                verify_snapshot(snapshot)
                            self.assertLess(time.monotonic() - started, 3)
                        finally:
                            if os.path.lexists(target):
                                target.unlink()
                            target.write_bytes(reviewed_payload)
                            target.chmod(reviewed_mode)
                        verify_snapshot(snapshot)
                extra = snapshot / "unexpected.py"
                extra.write_bytes(b"hostile\n")
                with self.assertRaises(AssertionError):
                    verify_snapshot(snapshot)
                extra.unlink()
                verify_snapshot(snapshot)
                environment = canonical_env(call_state, snapshot, ambient=hostile)
                self.assertNotIn("PYTHONPATH", environment)
                self.assertEqual(SYSTEM_EXECUTABLE_PATH, environment["PATH"])
                self.assertEqual(str(call_state / "home"), environment["HOME"])
                for key in hostile:
                    if key.startswith(("PYTHON", "LD_", "DYLD_", "GIT_")):
                        self.assertNotIn(key, environment)
                self.assertTrue(all(
                    not key.startswith(("LD_", "DYLD_", "GIT_", "PYTHON"))
                    for key in environment
                ))
                self.assertTrue(all(
                    key not in environment
                    for key in (
                        P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
                        *P_REENTRANT_ENV_KEYS.values(),
                    )
                ))
                shutil.rmtree(snapshot)

                static_state = formal_root / "extract-static-root"
                static_state.mkdir(mode=0o700)
                static_outside = formal_root / "extract-static-outside"
                static_outside.mkdir(mode=0o700)
                (static_state / "snapshot").symlink_to(static_outside, target_is_directory=True)
                with self.assertRaises(AssertionError):
                    extract(dependency_archive, static_state)
                self.assertEqual([], list(static_outside.iterdir()))
                self.assertTrue((static_state / "snapshot").is_symlink())
                (static_state / "snapshot").unlink()
                static_state.rmdir()
                static_outside.rmdir()

                for attack_kind in ("symlink-leaf", "fifo-leaf", "parent-rebind"):
                    attack_state = formal_root / f"extract-{attack_kind}"
                    attack_state.mkdir(mode=0o700)
                    outside_tree = formal_root / f"outside-{attack_kind}"
                    outside_tree.mkdir(mode=0o700)
                    outside_before = tuple(outside_tree.iterdir())
                    fired = []
                    def attack_extract(event, **authority):
                        if event != "before-snapshot-leaf-open" or fired:
                            return
                        relative = Path(authority["relative"])
                        snapshot_path = Path(authority["snapshot"])
                        leaf = snapshot_path / relative
                        if attack_kind == "parent-rebind" and len(relative.parts) < 2:
                            return
                        leaf.parent.mkdir(parents=True, exist_ok=True)
                        if attack_kind == "symlink-leaf":
                            leaf.symlink_to(outside_tree / "sentinel")
                        elif attack_kind == "fifo-leaf":
                            os.mkfifo(leaf)
                        else:
                            original_parent = leaf.parent.with_name(leaf.parent.name + ".held")
                            leaf.parent.rename(original_parent)
                            leaf.parent.symlink_to(outside_tree, target_is_directory=True)
                        fired.append((relative.as_posix(), authority["parent_fd"]))
                    opened_during_attack = []
                    def capture_attack_open(path, flags, *args, **kwargs):
                        descriptor = real_open(path, flags, *args, **kwargs)
                        opened_during_attack.append(descriptor)
                        return descriptor
                    started = time.monotonic()
                    try:
                        with mock.patch.object(
                            module, "_dependency_archive_observer", side_effect=attack_extract,
                        ), mock.patch.object(os, "open", side_effect=capture_attack_open), \
                                self.assertRaises(AssertionError):
                            extract(dependency_archive, attack_state)
                        self.assertEqual(1, len(fired))
                        self.assertLess(time.monotonic() - started, 3)
                        self.assertEqual(outside_before, tuple(outside_tree.iterdir()))
                        self.assertEqual([], list(attack_state.iterdir()))
                        for descriptor in opened_during_attack:
                            with self.assertRaises(OSError):
                                os.fstat(descriptor)
                    finally:
                        if os.path.lexists(attack_state / "snapshot"):
                            candidate = attack_state / "snapshot"
                            if candidate.is_dir() and not candidate.is_symlink():
                                shutil.rmtree(candidate)
                            else:
                                candidate.unlink()
                        for held in attack_state.rglob("*.held"):
                            if held.is_dir():
                                shutil.rmtree(held)
                        shutil.rmtree(attack_state)
                        shutil.rmtree(outside_tree)

                for rebind_kind in (
                    "leaf", "nested-parent", "same-inode-content",
                    "snapshot-root", "state-root",
                ):
                    fired, child_attempts, attacked_paths = [], [], []
                    same_inode_authority = []
                    real_stat, real_lstat, real_fstat = os.stat, os.lstat, os.fstat
                    def mask_same_inode(result):
                        if not same_inode_authority or (result.st_dev, result.st_ino) != same_inode_authority[0][:2]:
                            return result
                        return SimpleNamespace(
                            st_dev=result.st_dev, st_ino=result.st_ino,
                            st_mode=result.st_mode, st_nlink=result.st_nlink,
                            st_size=result.st_size,
                            st_mtime_ns=same_inode_authority[0][2],
                            st_ctime_ns=same_inode_authority[0][3],
                        )
                    def masked_stat(*args, **kwargs):
                        return mask_same_inode(real_stat(*args, **kwargs))
                    def masked_lstat(*args, **kwargs):
                        return mask_same_inode(real_lstat(*args, **kwargs))
                    def masked_fstat(*args, **kwargs):
                        return mask_same_inode(real_fstat(*args, **kwargs))
                    outside_sentinel = outside / f"{rebind_kind}.sentinel"
                    outside_sentinel.write_bytes(b"outside-trusted\n")
                    outside_before = outside_sentinel.read_bytes()
                    verification_timeline = []
                    def observed_full_verify(path):
                        verification_timeline.append("verify-start")
                        result = verify_snapshot(path)
                        verification_timeline.append("verify-end")
                        return result
                    def attack_before_sandbox(event, **authority):
                        if event != "before-sandbox" or fired:
                            return
                        dynamic_snapshot = Path(authority["snapshot"])
                        if rebind_kind == "leaf":
                            target = dynamic_snapshot / "six.py"
                            target.unlink()
                            target.symlink_to(outside_sentinel)
                            attacked_paths.append(target)
                        elif rebind_kind == "nested-parent":
                            target = dynamic_snapshot / "numpy/tests/test_public_api.py"
                            held = target.parent.with_name(target.parent.name + ".held")
                            target.parent.rename(held)
                            target.parent.symlink_to(outside, target_is_directory=True)
                            attacked_paths.extend((target.parent, held))
                        elif rebind_kind == "same-inode-content":
                            target = dynamic_snapshot / "six.py"
                            payload = target.read_bytes()
                            before = target.lstat()
                            same_inode_authority.append((
                                before.st_dev, before.st_ino,
                                before.st_mtime_ns, before.st_ctime_ns,
                            ))
                            writer = os.open(
                                target,
                                os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            )
                            try:
                                os.pwrite(writer, bytes([payload[0] ^ 1]) + payload[1:], 0)
                                os.fsync(writer)
                            finally:
                                os.close(writer)
                            os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
                            attacked_paths.append(target)
                        elif rebind_kind == "snapshot-root":
                            held = dynamic_snapshot.with_name(dynamic_snapshot.name + ".held")
                            dynamic_snapshot.rename(held)
                            dynamic_snapshot.symlink_to(outside, target_is_directory=True)
                            attacked_paths.extend((dynamic_snapshot, held))
                        else:
                            dynamic_state = dynamic_snapshot.parent
                            held = dynamic_state.with_name(dynamic_state.name + ".held")
                            dynamic_state.rename(held)
                            dynamic_state.symlink_to(outside, target_is_directory=True)
                            attacked_paths.extend((dynamic_state, held))
                        verification_timeline.append("attack")
                        fired.append(rebind_kind)
                    def forbidden_sandbox(*args, **kwargs):
                        child_attempts.append((args, kwargs))
                        raise AssertionError("sandbox started after snapshot authority rebind")
                    with self.subTest(pre_sandbox_rebind=rebind_kind), \
                            mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                        module, "_dependency_archive_observer", side_effect=attack_before_sandbox,
                    ), mock.patch.object(
                        module, "_run_capsule_sandbox", side_effect=forbidden_sandbox,
                    ), mock.patch.object(
                        module, "_verify_dependency_snapshot", side_effect=observed_full_verify,
                    ) as full_verifies, mock.patch.object(
                        os, "stat", side_effect=masked_stat,
                    ), mock.patch.object(
                        os, "lstat", side_effect=masked_lstat,
                    ), mock.patch.object(
                        os, "fstat", side_effect=masked_fstat,
                    ), self.assertRaises(AssertionError):
                        _python_run(
                            ROOT, ["-B", "-c", "raise SystemExit('unreachable')"],
                            timeout=30, dependency_archive=dependency_archive,
                        )
                    self.assertEqual([rebind_kind], fired)
                    self.assertEqual([], child_attempts)
                    self.assertGreaterEqual(full_verifies.call_count, 2)
                    self.assertLess(verification_timeline.index("verify-end"), verification_timeline.index("attack"))
                    self.assertIn("verify-start", verification_timeline[verification_timeline.index("attack") + 1:])
                    self.assertEqual(outside_before, outside_sentinel.read_bytes())
                    self.assertTrue(all(not os.path.lexists(path) for path in attacked_paths))
                    outside_sentinel.unlink()

                for python_home_attack in (
                    "root-symlink", "root-rebind", "lib-symlink",
                    "version-rebind", "lib-file", "version-fifo",
                    "site-symlink", "site-rebind", "site-file", "site-fifo",
                    "sitecustomize", "usercustomize", "hostile-pth",
                ):
                    fired, child_attempts, attack_states = [], [], []
                    helper_open_attempts, helper_opened = [], []
                    attack_active, component_authority = [], []
                    def capture_python_home_open(path, flags, *args, **kwargs):
                        if attack_active:
                            return real_open(path, flags, *args, **kwargs)
                        parent_fd = kwargs.get("dir_fd")
                        parent_identity = None
                        if parent_fd is not None:
                            try:
                                parent_metadata = os.fstat(parent_fd)
                                parent_identity = (
                                    parent_metadata.st_dev, parent_metadata.st_ino,
                                )
                            except OSError:
                                pass
                        attempt = {
                            "name": os.fspath(path), "flags": flags,
                            "parent_fd": parent_fd,
                            "parent_identity": parent_identity,
                            "fd": None, "identity": None, "error": None,
                        }
                        helper_open_attempts.append(attempt)
                        try:
                            descriptor = real_open(path, flags, *args, **kwargs)
                        except OSError as error:
                            attempt["error"] = error.errno
                            raise
                        opened_metadata = os.fstat(descriptor)
                        attempt["fd"] = descriptor
                        attempt["identity"] = (
                            opened_metadata.st_dev, opened_metadata.st_ino,
                        )
                        helper_opened.append(attempt)
                        return descriptor
                    python_home_outside = outside / f"python-home-{python_home_attack}"
                    python_home_outside.mkdir(mode=0o700)
                    outside_shape = python_home_outside / "shape"
                    outside_site = outside_shape / "lib/python3.9/site-packages"
                    outside_site.mkdir(parents=True, mode=0o755)
                    (outside_shape / "lib").chmod(0o755)
                    (outside_shape / "lib/python3.9").chmod(0o755)
                    outside_shape.chmod(0o700)
                    outside_sentinel = python_home_outside / "sentinel"
                    outside_sentinel.write_bytes(b"outside-trusted\n")
                    customizer_marker = python_home_outside / "customizer-loaded"
                    outside_before = _object_tree_snapshot(python_home_outside)
                    def attack_python_home(event, **authority):
                        if event == "snapshot-ready":
                            attack_states.append(Path(authority["snapshot"]).parent)
                        if event != "before-sandbox" or fired:
                            return
                        state_path = Path(authority["state_root"])
                        python_home = state_path / "python-home"
                        python_lib = python_home / "lib"
                        python_version = python_lib / "python3.9"
                        safe_site = python_version / "site-packages"
                        if python_home_attack.startswith("root-"):
                            attacked_component = python_home
                        elif python_home_attack.startswith("lib-"):
                            attacked_component = python_lib
                        elif python_home_attack.startswith("version-"):
                            attacked_component = python_version
                        elif python_home_attack == "sitecustomize":
                            attacked_component = python_version
                        else:
                            attacked_component = safe_site
                        attacked_metadata = attacked_component.lstat()
                        attacked_parent_metadata = attacked_component.parent.lstat()
                        held_before = []
                        for opened in helper_opened:
                            if opened["identity"] != (
                                attacked_metadata.st_dev, attacked_metadata.st_ino,
                            ):
                                continue
                            try:
                                os.fstat(opened["fd"])
                            except OSError:
                                continue
                            held_before.append(opened)
                        component_authority.append({
                            "name": attacked_component.name,
                            "parent_identity": (
                                attacked_parent_metadata.st_dev,
                                attacked_parent_metadata.st_ino,
                            ),
                            "attempt_count": len(helper_open_attempts),
                            "held_before": held_before,
                        })
                        attack_active.append(True)
                        if python_home_attack == "root-symlink":
                            shutil.rmtree(python_home)
                            python_home.symlink_to(outside_shape, target_is_directory=True)
                        elif python_home_attack == "root-rebind":
                            held = python_home.with_name("python-home.held")
                            python_home.rename(held)
                            python_home.symlink_to(outside_shape, target_is_directory=True)
                        elif python_home_attack == "lib-symlink":
                            shutil.rmtree(python_lib)
                            python_lib.symlink_to(
                                outside_shape / "lib", target_is_directory=True,
                            )
                        elif python_home_attack == "version-rebind":
                            held = python_version.with_name("python3.9.held")
                            python_version.rename(held)
                            python_version.symlink_to(
                                outside_shape / "lib/python3.9", target_is_directory=True,
                            )
                        elif python_home_attack == "lib-file":
                            shutil.rmtree(python_lib)
                            python_lib.write_bytes(b"hostile-middle-component\n")
                        elif python_home_attack == "version-fifo":
                            shutil.rmtree(python_version)
                            os.mkfifo(python_version, 0o600)
                        elif python_home_attack == "site-symlink":
                            safe_site.rmdir()
                            safe_site.symlink_to(outside_site, target_is_directory=True)
                        elif python_home_attack == "site-rebind":
                            held = safe_site.with_name("site-packages.held")
                            safe_site.rename(held)
                            safe_site.symlink_to(outside_site, target_is_directory=True)
                        elif python_home_attack == "site-file":
                            safe_site.rmdir()
                            safe_site.write_bytes(b"hostile-site-leaf\n")
                        elif python_home_attack == "site-fifo":
                            safe_site.rmdir()
                            os.mkfifo(safe_site, 0o600)
                        elif python_home_attack == "sitecustomize":
                            (python_version / "sitecustomize.py").write_bytes(
                                (
                                    "from pathlib import Path\n"
                                    f"Path({str(customizer_marker)!r}).write_text('loaded')\n"
                                ).encode("utf-8")
                            )
                        elif python_home_attack == "usercustomize":
                            (safe_site / "usercustomize.py").write_bytes(
                                (
                                    "from pathlib import Path\n"
                                    f"Path({str(customizer_marker)!r}).write_text('loaded')\n"
                                ).encode("utf-8")
                            )
                        else:
                            (safe_site / "hostile.pth").write_bytes(
                                (
                                    "import pathlib; "
                                    f"pathlib.Path({str(customizer_marker)!r}).write_text('loaded')\n"
                                ).encode("utf-8")
                            )
                        attack_active.clear()
                        fired.append(python_home_attack)
                    small_state = formal_root / f"python-home-direct-{python_home_attack}"
                    small_state.mkdir(mode=0o700)
                    python_home_authority = None
                    try:
                        with self.subTest(python_home_attack=python_home_attack), \
                                mock.patch.object(
                                    os, "open", side_effect=capture_python_home_open,
                                ):
                            python_home_authority = create_python_home(small_state)
                            attack_python_home(
                                "snapshot-ready", snapshot=small_state / "snapshot",
                            )
                            attack_python_home(
                                "before-sandbox", snapshot=small_state / "snapshot",
                                state_root=small_state,
                            )
                            with self.assertRaises(AssertionError):
                                verify_python_home(python_home_authority)
                    finally:
                        close_python_home(python_home_authority)
                        if os.path.lexists(small_state):
                            shutil.rmtree(small_state)
                    self.assertEqual([python_home_attack], fired)
                    self.assertEqual([], child_attempts)
                    self.assertEqual(1, len(component_authority))
                    authority = component_authority[0]
                    def assert_safe_component_open(opened):
                        self.assertEqual(authority["name"], opened["name"])
                        self.assertEqual(
                            authority["parent_identity"], opened["parent_identity"],
                        )
                        self.assertEqual(os.O_RDONLY, opened["flags"] & os.O_ACCMODE)
                        for required in (os.O_DIRECTORY, os.O_NOFOLLOW, os.O_CLOEXEC):
                            self.assertEqual(required, opened["flags"] & required)
                        if hasattr(os, "O_NONBLOCK"):
                            self.assertEqual(
                                os.O_NONBLOCK, opened["flags"] & os.O_NONBLOCK,
                            )
                        for forbidden in (
                            os.O_CREAT, os.O_EXCL, os.O_TRUNC, os.O_APPEND,
                        ):
                            self.assertEqual(0, opened["flags"] & forbidden)
                    if authority["held_before"]:
                        for held_open in authority["held_before"]:
                            assert_safe_component_open(held_open)
                    else:
                        later_attempts = [
                            attempt for attempt in helper_open_attempts[
                                authority["attempt_count"]:
                            ]
                            if attempt["name"] == authority["name"]
                            and attempt["parent_identity"]
                            == authority["parent_identity"]
                        ]
                        self.assertTrue(later_attempts)
                        assert_safe_component_open(later_attempts[0])
                    self.assertTrue(attack_states)
                    self.assertTrue(all(not os.path.lexists(path) for path in attack_states))
                    self.assertFalse(os.path.lexists(customizer_marker))
                    self.assertEqual(
                        outside_before, _object_tree_snapshot(python_home_outside),
                    )
                    for opened in helper_opened:
                        with self.assertRaises(OSError):
                            os.fstat(opened["fd"])
                    shutil.rmtree(python_home_outside)

                pyhome_e2e_outside = outside / "python-home-e2e-pre"
                pyhome_e2e_site = pyhome_e2e_outside / "lib/python3.9/site-packages"
                pyhome_e2e_site.mkdir(parents=True, mode=0o755)
                (pyhome_e2e_outside / "lib").chmod(0o755)
                (pyhome_e2e_outside / "lib/python3.9").chmod(0o755)
                pyhome_e2e_outside.chmod(0o700)
                pyhome_e2e_before = _object_tree_snapshot(pyhome_e2e_outside)
                pyhome_e2e_events, pyhome_e2e_children, pyhome_e2e_states = [], [], []
                def rebind_python_home_before_sandbox(event, **authority):
                    if event == "snapshot-ready":
                        pyhome_e2e_states.append(Path(authority["snapshot"]).parent)
                    if event != "before-sandbox" or pyhome_e2e_events:
                        return
                    state_path = Path(authority["state_root"])
                    python_home = state_path / "python-home"
                    held = python_home.with_name("python-home.held")
                    python_home.rename(held)
                    python_home.symlink_to(pyhome_e2e_outside, target_is_directory=True)
                    pyhome_e2e_events.append("rebound")
                def reject_pyhome_e2e_child(*args, **kwargs):
                    pyhome_e2e_children.append((args, kwargs))
                    raise AssertionError("sandbox started after PYTHONHOME root rebind")
                with mock.patch.object(
                    module, "_dependency_archive_observer",
                    side_effect=rebind_python_home_before_sandbox,
                ), mock.patch.object(
                    module, "_run_capsule_sandbox",
                    side_effect=reject_pyhome_e2e_child,
                ), mock.patch.dict(
                    os.environ, {}, clear=True,
                ), self.assertRaises(AssertionError):
                    _python_run(
                        ROOT, ["-B", "-c", "raise SystemExit('unreachable')"],
                        timeout=30, dependency_archive=dependency_archive,
                    )
                self.assertEqual(["rebound"], pyhome_e2e_events)
                self.assertEqual([], pyhome_e2e_children)
                self.assertTrue(pyhome_e2e_states)
                self.assertTrue(all(
                    not os.path.lexists(path) for path in pyhome_e2e_states
                ))
                self.assertEqual(
                    pyhome_e2e_before, _object_tree_snapshot(pyhome_e2e_outside),
                )
                shutil.rmtree(pyhome_e2e_outside)

                pyhome_postchild_events, pyhome_postchild_states = [], []
                pyhome_child_sentinel = subprocess.CompletedProcess([], 0, "trusted\n", "")
                def mutate_python_home_after_child(event, **authority):
                    if event == "snapshot-ready":
                        pyhome_postchild_states.append(Path(authority["snapshot"]).parent)
                    if event == "after-child" and not pyhome_postchild_events:
                        state_path = Path(authority["state_root"])
                        hostile_path = (
                            state_path / "python-home/lib/python3.9/site-packages/hostile.pth"
                        )
                        hostile_path.write_bytes(b"import hostile_postchild\n")
                        pyhome_postchild_events.append("mutated")
                with mock.patch.object(
                    module, "_dependency_archive_observer",
                    side_effect=mutate_python_home_after_child,
                ), mock.patch.object(
                    module, "_run_capsule_sandbox",
                    return_value=pyhome_child_sentinel,
                ) as pyhome_child, mock.patch.dict(
                    os.environ, {}, clear=True,
                ), self.assertRaises(AssertionError):
                    _python_run(
                        ROOT, ["-B", "-c", "print('trusted')"], timeout=30,
                        dependency_archive=dependency_archive,
                    )
                pyhome_child.assert_called_once()
                self.assertEqual(["mutated"], pyhome_postchild_events)
                self.assertTrue(pyhome_postchild_states)
                self.assertTrue(all(
                    not os.path.lexists(path) for path in pyhome_postchild_states
                ))

                postchild_events, postchild_snapshots = [], []
                def mutate_after_child(event, **authority):
                    if event == "snapshot-ready":
                        postchild_snapshots.append(Path(authority["snapshot"]))
                    if event == "after-child" and not postchild_events:
                        target = Path(authority["snapshot"]) / "six.py"
                        payload = target.read_bytes()
                        before = target.lstat()
                        writer = os.open(
                            target, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        )
                        try:
                            os.pwrite(writer, bytes([payload[0] ^ 1]) + payload[1:], 0)
                            os.fsync(writer)
                        finally:
                            os.close(writer)
                        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
                        postchild_events.append("mutated")
                successful_child = subprocess.CompletedProcess([], 0, "", "")
                with mock.patch.object(
                    module, "_dependency_archive_observer", side_effect=mutate_after_child,
                ), mock.patch.object(
                    module, "_run_capsule_sandbox", return_value=successful_child,
                ), mock.patch.dict(
                    os.environ, {}, clear=True,
                ), self.assertRaises(AssertionError):
                    _python_run(
                        ROOT, ["-B", "-c", "print('unreachable')"], timeout=30,
                        dependency_archive=dependency_archive,
                    )
                self.assertEqual(["mutated"], postchild_events)
                self.assertTrue(postchild_snapshots)
                self.assertTrue(all(not os.path.lexists(path) for path in postchild_snapshots))

                probe = textwrap.dedent("""
                    import importlib.metadata as md, json, os, pathlib, subprocess, sys
                    import jinja2, yaml, pandas, openpyxl, xlsxwriter
                    import markupsafe, numpy, dateutil, pytz, tzdata, et_xmlfile, six
                    modules = {'Jinja2': jinja2, 'PyYAML': yaml, 'pandas': pandas,
                      'openpyxl': openpyxl, 'XlsxWriter': xlsxwriter,
                      'MarkupSafe': markupsafe, 'numpy': numpy,
                      'python-dateutil': dateutil, 'pytz': pytz, 'tzdata': tzdata,
                      'et_xmlfile': et_xmlfile, 'six': six}
                    ordinary_leaf_code = "import json,os,site,sys,yaml; import markupsafe._speedups as native; print(json.dumps({'prefix':sys.prefix,'exec_prefix':sys.exec_prefix,'path':sys.path,'sitepackages':site.getsitepackages(),'no_user':site.ENABLE_USER_SITE is False,'pythonhome':os.environ.get('PYTHONHOME'),'pythonpath':os.environ.get('PYTHONPATH'),'dontwrite':os.environ.get('PYTHONDONTWRITEBYTECODE'),'ambient_marker':os.environ.get('PYTHON_CAPSULE_HOSTILE_MARKER'),'sitecustomize_loaded':'sitecustomize' in sys.modules,'usercustomize_loaded':'usercustomize' in sys.modules,'yaml':yaml.__file__,'native':native.__file__},sort_keys=True))"
                    ordinary_code = "import json,os,pathlib,site,subprocess,sys,yaml; import markupsafe._speedups as native; leaf=" + repr(ordinary_leaf_code) + "; grandchild=subprocess.run([sys.executable,'-B','-c',leaf],capture_output=True,text=True); report={'prefix':sys.prefix,'exec_prefix':sys.exec_prefix,'path':sys.path,'sitepackages':site.getsitepackages(),'no_user':site.ENABLE_USER_SITE is False,'pythonhome':os.environ.get('PYTHONHOME'),'pythonpath':os.environ.get('PYTHONPATH'),'dontwrite':os.environ.get('PYTHONDONTWRITEBYTECODE'),'ambient_marker':os.environ.get('PYTHON_CAPSULE_HOSTILE_MARKER'),'sitecustomize_loaded':'sitecustomize' in sys.modules,'usercustomize_loaded':'usercustomize' in sys.modules,'yaml':yaml.__file__,'native':native.__file__,'grandchild_rc':grandchild.returncode,'grandchild_stderr':grandchild.stderr,'grandchild':json.loads(grandchild.stdout) if grandchild.returncode==0 else None}; print(json.dumps(report,sort_keys=True))"
                    ordinary = subprocess.run([sys.executable, '-B', '-c', ordinary_code], capture_output=True, text=True)
                    print(json.dumps({'versions': {k: md.version(k) for k in modules},
                      'origins': {k: v.__file__ for k, v in modules.items()},
                      'path': sys.path, 'ordinary_rc': ordinary.returncode,
                      'ordinary_stderr': ordinary.stderr,
                      'ordinary': json.loads(ordinary.stdout) if ordinary.returncode == 0 else None}, sort_keys=True))
                    print(yaml.safe_load('a: [1, true]'))
                    print(pandas.DataFrame({'a': [1]}).to_dict())
                """)
                calls = []
                normal_fds = []
                normal_state_authority = []
                def capture_normal_fd(path, flags, *args, **kwargs):
                    descriptor = real_open(path, flags, *args, **kwargs)
                    normal_fds.append((os.fspath(path), flags, descriptor, kwargs.get("dir_fd")))
                    return descriptor
                def observed_normal_sandbox(command, **kwargs):
                    self.assertTrue(snapshots)
                    snapshot_path = snapshots[-1][0]
                    home_path = Path(kwargs["environment"]["HOME"])
                    state_path = home_path.parent
                    python_home = state_path / "python-home"
                    python_lib = python_home / "lib"
                    python_version = python_lib / "python3.9"
                    safe_site = python_version / "site-packages"
                    home_metadata = home_path.lstat()
                    state_metadata = state_path.lstat()
                    python_home_metadata = python_home.lstat()
                    python_lib_metadata = python_lib.lstat()
                    python_version_metadata = python_version.lstat()
                    safe_site_metadata = safe_site.lstat()
                    self.assertFalse(home_path.is_symlink())
                    self.assertFalse(state_path.is_symlink())
                    self.assertTrue(stat.S_ISDIR(home_metadata.st_mode))
                    self.assertTrue(stat.S_ISDIR(state_metadata.st_mode))
                    self.assertTrue(stat.S_ISDIR(python_home_metadata.st_mode))
                    self.assertTrue(stat.S_ISDIR(python_lib_metadata.st_mode))
                    self.assertTrue(stat.S_ISDIR(python_version_metadata.st_mode))
                    self.assertTrue(stat.S_ISDIR(safe_site_metadata.st_mode))
                    self.assertEqual(0o700, stat.S_IMODE(home_metadata.st_mode))
                    self.assertEqual(0o700, stat.S_IMODE(state_metadata.st_mode))
                    self.assertEqual(0o700, stat.S_IMODE(python_home_metadata.st_mode))
                    self.assertEqual(0o755, stat.S_IMODE(python_lib_metadata.st_mode))
                    self.assertEqual(0o755, stat.S_IMODE(python_version_metadata.st_mode))
                    self.assertEqual(0o755, stat.S_IMODE(safe_site_metadata.st_mode))
                    self.assertEqual(["lib"], [entry.name for entry in python_home.iterdir()])
                    self.assertEqual(["python3.9"], [entry.name for entry in python_lib.iterdir()])
                    self.assertEqual(["site-packages"], [entry.name for entry in python_version.iterdir()])
                    self.assertEqual([], list(safe_site.iterdir()))
                    python_home_components = (
                        python_home, python_lib, python_version, safe_site,
                    )
                    component_identities = tuple(
                        (component.lstat().st_dev, component.lstat().st_ino)
                        for component in python_home_components
                    )
                    self.assertEqual(len(component_identities), len(set(component_identities)))
                    for component in python_home_components:
                        self.assertFalse(component.is_symlink())
                        self.assertEqual(component, component.resolve())
                        self.assertTrue(component.is_relative_to(state_path))
                    held_component_fds = []
                    for component, identity in zip(
                        python_home_components, component_identities,
                    ):
                        parent_identity = (
                            component.parent.lstat().st_dev,
                            component.parent.lstat().st_ino,
                        )
                        matching = []
                        for opened_name, opened_flags, opened_fd, parent_fd in normal_fds:
                            if opened_name != component.name or parent_fd is None:
                                continue
                            try:
                                opened_metadata = os.fstat(opened_fd)
                                parent_metadata = os.fstat(parent_fd)
                            except OSError:
                                continue
                            if (opened_metadata.st_dev, opened_metadata.st_ino) != identity:
                                continue
                            if (parent_metadata.st_dev, parent_metadata.st_ino) != parent_identity:
                                continue
                            self.assertEqual(os.O_RDONLY, opened_flags & os.O_ACCMODE)
                            for required in (os.O_DIRECTORY, os.O_NOFOLLOW, os.O_CLOEXEC):
                                self.assertEqual(required, opened_flags & required)
                            if hasattr(os, "O_NONBLOCK"):
                                self.assertEqual(os.O_NONBLOCK, opened_flags & os.O_NONBLOCK)
                            for forbidden in (
                                os.O_CREAT, os.O_EXCL, os.O_TRUNC, os.O_APPEND,
                            ):
                                self.assertEqual(0, opened_flags & forbidden)
                            matching.append(opened_fd)
                        self.assertEqual(1, len(matching), component)
                        held_component_fds.append(matching[0])
                    self.assertEqual(state_path, snapshot_path.parent)
                    expected_profile = (
                        "(version 1)\n(allow default)\n"
                        f'(deny file-write* (subpath {json.dumps(str(snapshot_path.resolve()))}))\n'
                        f'(deny file-write* (literal {json.dumps(str(snapshot_path.resolve()))}))\n'
                        f'(deny file-write* (literal {json.dumps(str(state_path.resolve()))}))\n'
                        f'(deny file-write* (subpath {json.dumps(str(python_home.resolve()))}))\n'
                        f'(deny file-write* (literal {json.dumps(str(python_home.resolve()))}))\n'
                    )
                    self.assertEqual(expected_profile, command[2])
                    normal_state_authority.append((
                        home_path, state_path, python_home,
                        (home_metadata.st_dev, home_metadata.st_ino),
                        (state_metadata.st_dev, state_metadata.st_ino),
                    ))
                    sandbox_result = run_sandbox(command, **kwargs)
                    for component_fd, identity in zip(
                        held_component_fds, component_identities,
                    ):
                        component_metadata = os.fstat(component_fd)
                        self.assertEqual(
                            identity,
                            (component_metadata.st_dev, component_metadata.st_ino),
                        )
                    self.assertEqual(
                        component_identities,
                        tuple(
                            (component.lstat().st_dev, component.lstat().st_ino)
                            for component in python_home_components
                        ),
                    )
                    self.assertEqual(["lib"], [entry.name for entry in python_home.iterdir()])
                    self.assertEqual(["python3.9"], [entry.name for entry in python_lib.iterdir()])
                    self.assertEqual(["site-packages"], [entry.name for entry in python_version.iterdir()])
                    self.assertEqual([], list(safe_site.iterdir()))
                    return sandbox_result
                active_normal_owned_fds = []
                active_normal_calls = []
                normal_arguments = ["-B", "-c", probe]
                duplicate_authority = getattr(
                    module, "_duplicate_reentrant_authority",
                )
                def observe_active_normal_duplicate(authority):
                    duplicated = duplicate_authority(authority)
                    active_normal_owned_fds.extend(duplicated)
                    return duplicated
                def observe_active_normal_process(command, **kwargs):
                    active_normal_calls.append((tuple(command), dict(kwargs)))
                    if len(active_normal_calls) == 3:
                        environment = kwargs["environment"]
                        passed = tuple(kwargs["pass_fds"])
                        self.assertEqual((active_normal_owned_fds[0],), passed)
                        self.assertEqual(
                            str(passed[0]), environment[P_CAPSULE_FD_ENV],
                        )
                        self.assertEqual(
                            set(),
                            set(P_REENTRANT_ENV_KEYS.values()).intersection(
                                environment
                            ),
                        )
                        self.assertNotIn(
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV, environment,
                        )
                        self.assertEqual(normal_arguments, json.loads(command[-1]))
                    return run_bounded(command, **kwargs)
                if active_fixture is None:
                    with mock.patch.object(
                        module, "_dependency_archive_observer", side_effect=observed,
                    ), mock.patch.object(
                        module, "_run_capsule_sandbox",
                        side_effect=observed_normal_sandbox,
                    ) as observed_run, mock.patch.object(
                        module, "_run_bounded_process", wraps=run_bounded,
                    ) as bounded_sandbox, mock.patch.object(
                        os, "open", side_effect=capture_normal_fd,
                    ):
                        result = _python_run(
                            ROOT, normal_arguments, timeout=60, ambient=hostile,
                            dependency_archive=dependency_archive,
                        )
                else:
                    with mock.patch.dict(
                        os.environ, active_fixture_environment, clear=True,
                    ), mock.patch.object(
                        module, "_run_bounded_process",
                        side_effect=observe_active_normal_process,
                    ) as bounded_sandbox, mock.patch.object(
                        module, "_duplicate_reentrant_authority",
                        side_effect=observe_active_normal_duplicate,
                    ) as active_normal_duplicate, mock.patch.object(
                        module, "_run_capsule_sandbox",
                    ) as observed_run, mock.patch.object(
                        module, "_formal_loopback_sshd_scope",
                    ) as active_normal_scope, mock.patch.object(
                        module,
                        "_formal_loopback_sshd_authority_from_environment",
                        wraps=loopback_consumer,
                    ) as active_normal_consumer:
                        result = _python_run(
                            ROOT, normal_arguments, timeout=60, ambient=hostile,
                            dependency_archive=borrowed_archive,
                        )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertEqual("", result.stderr)
                if active_fixture is None:
                    self.assertEqual(1, observed_run.call_count)
                    self.assertEqual(1, bounded_sandbox.call_count)
                    self.assertEqual(1, len(snapshots))
                    self.assertEqual(1, len(normal_state_authority))
                    first_snapshot = snapshots[0]
                    command = tuple(observed_run.call_args.args[0])
                    kwargs = observed_run.call_args.kwargs
                    self.assertEqual((
                        P_CAPSULE_SANDBOX_EXECUTABLE, "-p",
                        _expected_capsule_sandbox_profile(first_snapshot[0]),
                        str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                        P_CAPSULE_BOOTSTRAP, str(first_snapshot[0]), str(ROOT),
                        json.dumps(normal_arguments, separators=(",", ":")),
                    ), command)
                    self.assertEqual((archive_fd,), kwargs["pass_fds"])
                    self.assertEqual(
                        {"cwd", "environment", "timeout", "pass_fds"},
                        set(kwargs),
                    )
                    self.assertEqual(ROOT, Path(kwargs["cwd"]).resolve())
                    self.assertEqual(60, kwargs["timeout"])
                    self.assertEqual(
                        str(archive_fd), kwargs["environment"][P_CAPSULE_FD_ENV],
                    )
                    self.assertEqual(
                        inherited_environment[P_CAPSULE_IDENTITY_ENV],
                        kwargs["environment"][P_CAPSULE_IDENTITY_ENV],
                    )
                    self.assertEqual(
                        SYSTEM_EXECUTABLE_PATH, kwargs["environment"]["PATH"],
                    )
                    self.assertNotIn("PYTHONPATH", kwargs["environment"])
                    self.assertTrue(all(
                        not key.startswith(("LD_", "DYLD_", "GIT_", "PYTHON"))
                        for key in kwargs["environment"]
                    ))
                    self.assertTrue(all(
                        key not in kwargs["environment"]
                        for key in P_REENTRANT_ENV_KEYS.values()
                    ))
                    normal_home, normal_state, normal_python_home, \
                            _home_identity, _state_identity = normal_state_authority[0]
                else:
                    observed_run.assert_not_called()
                    active_normal_scope.assert_not_called()
                    active_normal_consumer.assert_not_called()
                    active_normal_duplicate.assert_called_once()
                    self.assertEqual(3, bounded_sandbox.call_count)
                    self.assertEqual(7, len(active_normal_owned_fds))
                    for descriptor in active_normal_owned_fds:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    assert_reused_active_loopback(loopback_consumer())
                    first_snapshot = (
                        active_fixture.snapshot,
                        active_fixture.snapshot.lstat().st_dev,
                        active_fixture.snapshot.lstat().st_ino,
                    )
                    normal_state = active_fixture.snapshot.parent
                    normal_home = normal_state / "home"
                    normal_python_home = (
                        active_fixture.python_home.components[0][0]
                    )
                report = json.loads(result.stdout.splitlines()[0])
                self.assertEqual(P_CAPSULE_PACKAGE_VERSIONS, report["versions"])
                self.assertEqual("{'a': [1, True]}", result.stdout.splitlines()[1])
                self.assertEqual("{'a': {0: 1}}", result.stdout.splitlines()[2])
                for origin in report["origins"].values():
                    self.assertTrue(Path(origin).resolve().is_relative_to(first_snapshot[0]))
                ordinary = report["ordinary"]
                self.assertEqual(0, report["ordinary_rc"], report["ordinary_stderr"])
                self.assertEqual(str(normal_python_home), ordinary["prefix"])
                self.assertEqual(str(normal_python_home), ordinary["exec_prefix"])
                self.assertTrue(ordinary["no_user"])
                self.assertEqual("1", ordinary["dontwrite"])
                self.assertEqual(str(normal_python_home), ordinary["pythonhome"])
                self.assertIsNone(ordinary["ambient_marker"])
                self.assertFalse(ordinary["sitecustomize_loaded"])
                self.assertFalse(ordinary["usercustomize_loaded"])
                self.assertEqual(
                    os.pathsep.join((
                        str(first_snapshot[0]), P_CAPSULE_STDLIB_ROOT,
                        P_CAPSULE_STDLIB_ROOT + "/lib-dynload",
                    )),
                    ordinary["pythonpath"],
                )
                safe_site = normal_python_home / "lib/python3.9/site-packages"
                stdlib_root = Path(P_CAPSULE_STDLIB_ROOT).resolve()
                lib_dynload = (stdlib_root / "lib-dynload").resolve()
                allowed_ordinary_roots = (first_snapshot[0], normal_python_home)
                self.assertTrue(all(
                    not entry or any(
                        Path(entry).resolve() == root.resolve()
                        or Path(entry).resolve().is_relative_to(root.resolve())
                        for root in allowed_ordinary_roots
                    )
                    or Path(entry).resolve() in (stdlib_root, lib_dynload)
                    for entry in ordinary["path"]
                ))
                self.assertEqual([str(safe_site)], ordinary["sitepackages"])
                self.assertTrue(all(
                    "site-packages" not in Path(entry).parts
                    or Path(entry).resolve() == safe_site.resolve()
                    or Path(entry).resolve().is_relative_to(first_snapshot[0])
                    for entry in ordinary["path"] if entry
                ))
                self.assertTrue(Path(ordinary["yaml"]).resolve().is_relative_to(first_snapshot[0]))
                self.assertTrue(Path(ordinary["native"]).resolve().is_relative_to(first_snapshot[0]))
                self.assertEqual(0, ordinary["grandchild_rc"], ordinary["grandchild_stderr"])
                ordinary_grandchild = ordinary["grandchild"]
                self.assertEqual(str(normal_python_home), ordinary_grandchild["prefix"])
                self.assertEqual(str(normal_python_home), ordinary_grandchild["exec_prefix"])
                self.assertTrue(ordinary_grandchild["no_user"])
                self.assertEqual("1", ordinary_grandchild["dontwrite"])
                self.assertEqual(str(normal_python_home), ordinary_grandchild["pythonhome"])
                self.assertEqual(ordinary["pythonpath"], ordinary_grandchild["pythonpath"])
                self.assertIsNone(ordinary_grandchild["ambient_marker"])
                self.assertFalse(ordinary_grandchild["sitecustomize_loaded"])
                self.assertFalse(ordinary_grandchild["usercustomize_loaded"])
                self.assertTrue(all(
                    not entry or any(
                        Path(entry).resolve() == root.resolve()
                        or Path(entry).resolve().is_relative_to(root.resolve())
                        for root in allowed_ordinary_roots
                    )
                    or Path(entry).resolve() in (stdlib_root, lib_dynload)
                    for entry in ordinary_grandchild["path"]
                ))
                self.assertEqual([str(safe_site)], ordinary_grandchild["sitepackages"])
                self.assertTrue(all(
                    "site-packages" not in Path(entry).parts
                    or Path(entry).resolve() == safe_site.resolve()
                    or Path(entry).resolve().is_relative_to(first_snapshot[0])
                    for entry in ordinary_grandchild["path"] if entry
                ))
                self.assertTrue(
                    Path(ordinary_grandchild["yaml"]).resolve().is_relative_to(first_snapshot[0])
                )
                self.assertTrue(
                    Path(ordinary_grandchild["native"]).resolve().is_relative_to(first_snapshot[0])
                )
                self.assertEqual(first_snapshot[0], Path(report["path"][0]).resolve())
                self.assertEqual(ROOT, Path(report["path"][1]).resolve())
                if active_fixture is None:
                    self.assertFalse(os.path.lexists(first_snapshot[0]))
                    self.assertFalse(os.path.lexists(normal_home))
                    self.assertFalse(os.path.lexists(normal_state))
                    for _name, _flags, opened_fd, _parent_fd in normal_fds:
                        with self.assertRaises(OSError):
                            os.fstat(opened_fd)
                else:
                    verify_snapshot(active_fixture.snapshot)
                    verify_python_home(active_fixture.python_home)
                    self.assertEqual(
                        active_fixture_identities,
                        tuple(
                            (os.fstat(descriptor).st_dev,
                             os.fstat(descriptor).st_ino)
                            for descriptor in active_fixture_fds
                        ),
                    )
                    self.assertEqual(
                        active_fixture_flags,
                        tuple(
                            (
                                fcntl.fcntl(descriptor, fcntl.F_GETFL),
                                fcntl.fcntl(descriptor, fcntl.F_GETFD),
                            )
                            for descriptor in active_fixture_fds
                        ),
                    )
                    self.assertEqual(
                        active_fixture_offset,
                        os.lseek(active_fixture.archive_fd, 0, os.SEEK_CUR),
                    )

                # A formal full runner is itself the one top-level sandboxed child.
                # Its exact runner descendants must authenticate and reuse this held
                # authority without attempting a nested sandbox or owning its cleanup.
                active_state = formal_root / "authenticated-reentry"
                active_state.mkdir(mode=0o700)
                active_snapshot = extract(dependency_archive, active_state)
                with mock.patch.object(
                    module, "_canonical_dependency_logical_mapping",
                    return_value=b"hostile logical snapshot mapping\n",
                ) as poisoned_snapshot_mapping, self.assertRaisesRegex(
                    AssertionError, "mapping|logical|record|snapshot",
                ):
                    verify_snapshot(active_snapshot)
                poisoned_snapshot_mapping.assert_called_once()
                verify_snapshot(active_snapshot)
                active_python_home = create_python_home(active_state)
                active_runtime_environment = canonical_env(
                    active_state, None, ambient={
                        "PYTHONPATH": "/hostile/active-python",
                        "LD_PRELOAD": "/hostile/active-loader",
                        "DYLD_INSERT_LIBRARIES": "/hostile/active-dyld",
                        "GIT_DIR": "/hostile/active-git",
                    },
                )
                self.assertEqual(str(active_state / "home"), active_runtime_environment["HOME"])
                self.assertEqual(SYSTEM_EXECUTABLE_PATH, active_runtime_environment["PATH"])
                self.assertTrue(all(
                    not key.startswith(("PYTHON", "LD_", "DYLD_", "GIT_"))
                    for key in active_runtime_environment
                ))
                active_runtime_paths = (active_state / "home", active_state / "pycache")
                active_runtime_identities = []
                for runtime_path in active_runtime_paths:
                    runtime_metadata = runtime_path.lstat()
                    self.assertTrue(stat.S_ISDIR(runtime_metadata.st_mode))
                    self.assertEqual(0o700, stat.S_IMODE(runtime_metadata.st_mode))
                    active_runtime_identities.append((
                        runtime_metadata.st_dev, runtime_metadata.st_ino,
                        stat.S_IMODE(runtime_metadata.st_mode),
                    ))
                self.assertEqual(
                    ("home", "pycache", "python-home", "snapshot"),
                    tuple(sorted(path.name for path in active_state.iterdir())),
                )
                def assert_active_runtime_unchanged():
                    self.assertEqual(
                        ("home", "pycache", "python-home", "snapshot"),
                        tuple(sorted(path.name for path in active_state.iterdir())),
                    )
                    for runtime_path, expected_identity in zip(
                        active_runtime_paths, active_runtime_identities,
                    ):
                        runtime_metadata = runtime_path.lstat()
                        self.assertTrue(stat.S_ISDIR(runtime_metadata.st_mode))
                        self.assertEqual(expected_identity, (
                            runtime_metadata.st_dev, runtime_metadata.st_ino,
                            stat.S_IMODE(runtime_metadata.st_mode),
                        ))
                active_snapshot_fd = os.open(
                    active_snapshot,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    | os.O_NONBLOCK | os.O_CLOEXEC,
                )
                active_snapshot_metadata = os.fstat(active_snapshot_fd)
                active_components = (
                    (
                        active_python_home.state_path,
                        active_python_home.state_fd, 0o700,
                        *active_python_home.state_identity,
                    ),
                    *active_python_home.components,
                )
                active_fds = (
                    archive_fd, active_snapshot_fd,
                    *(component[1] for component in active_components),
                )
                self.assertEqual(len(active_fds), len(set(active_fds)))
                for active_fd in active_fds:
                    self.assertEqual(
                        fcntl.FD_CLOEXEC,
                        fcntl.fcntl(active_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                    )
                reentry_keys = dict(P_REENTRANT_ENV_KEYS)
                active_environment = {
                    P_CAPSULE_FD_ENV: str(archive_fd),
                    P_CAPSULE_IDENTITY_ENV: inherited_environment[P_CAPSULE_IDENTITY_ENV],
                    reentry_keys["marker"]: "1",
                    reentry_keys["snapshot"]: str(active_snapshot),
                    reentry_keys["snapshot_identity"]: ":".join((
                        str(active_snapshot_metadata.st_dev),
                        str(active_snapshot_metadata.st_ino),
                        P_CAPSULE_RECORDS_SHA256,
                    )),
                    reentry_keys["snapshot_fd"]: str(active_snapshot_fd),
                    reentry_keys["python_home"]: str(active_python_home.components[0][0]),
                    reentry_keys["python_home_identity"]: json.dumps([
                        {
                            "dev": component[3], "ino": component[4],
                            "mode": f"{component[2]:04o}",
                            "path": str(component[0]),
                        }
                        for component in active_components
                    ], sort_keys=True, separators=(",", ":")),
                    reentry_keys["python_home_fds"]: ",".join(
                        str(component[1]) for component in active_components
                    ),
                }
                reentry_write_probe = textwrap.dedent("""
                    import errno, json, os, pathlib, sys
                    target = pathlib.Path(sys.argv[1])
                    safe_site = pathlib.Path(sys.argv[2])
                    observed = {}
                    for name, operation in (
                        ('open', lambda: os.open(target, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)),
                        ('chmod', lambda: os.chmod(target, 0o600)),
                    ):
                        try:
                            operation()
                        except OSError as error:
                            observed[name] = error.errno
                        else:
                            observed[name] = 0
                    safe_site_fd = os.open(
                        safe_site,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                        | os.O_NONBLOCK | os.O_CLOEXEC,
                    )
                    try:
                        try:
                            os.open(
                                'hostile.pth',
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                0o600, dir_fd=safe_site_fd,
                            )
                        except OSError as error:
                            observed['site-open'] = error.errno
                        else:
                            observed['site-open'] = 0
                    finally:
                        os.close(safe_site_fd)
                    observed['site-residue'] = (safe_site / 'hostile.pth').exists()
                    print(json.dumps(observed, sort_keys=True))
                    raise SystemExit(0 if observed == {
                        'chmod': errno.EPERM, 'open': errno.EPERM,
                        'site-open': errno.EPERM, 'site-residue': False,
                    } else 9)
                """)
                allowed_reentrant_runners = (
                    ("-B", "test_cases/run_related_tests.py", "--all", "-v"),
                    (
                        "-B", "test_cases/run_related_tests.py", "--suite",
                        "repository-governance", "-v",
                    ),
                    (
                        "-B", "test_cases/run_related_tests.py", "--all",
                        "--no-approve", "-v",
                    ),
                    P_REENTRANT_TEST_PROBE_ARGUMENTS,
                )
                active_snapshot_payload = (active_snapshot / "six.py").read_bytes()
                # An authenticated full-runner rebuild has a different source
                # provenance from the standalone, machine-bound build above.  It
                # must consume the already verified snapshot exclusively: the
                # reviewed archive intentionally excludes the one physical .pyc,
                # so the authenticated logical exclusion set is exactly empty.
                active_archive_summary = verify_archive(dependency_archive)
                active_record_authority = {
                    record["path"]: dict(record)
                    for record in active_archive_summary["records"]
                }
                active_targets = tuple(sorted(active_record_authority))
                self.assertEqual(P_CAPSULE_FILE_COUNT, len(active_targets))
                self.assertNotIn(P_CAPSULE_EXCLUDED_TARGET, active_record_authority)
                self.assertFalse(
                    os.path.lexists(active_snapshot / P_CAPSULE_EXCLUDED_TARGET)
                )
                active_logical_rows = []
                active_used_roots = set()
                for target in active_targets:
                    matching_roots = [
                        root for root in P_CAPSULE_ROOTS
                        if target == root or target.startswith(root + "/")
                    ]
                    self.assertEqual(1, len(matching_roots), target)
                    root = matching_roots[0]
                    active_used_roots.add(root)
                    relative = "." if target == root else target[len(root) + 1:]
                    active_logical_rows.append({
                        "relative": relative, "root": root, "target": target,
                    })
                self.assertEqual(set(P_CAPSULE_ROOTS), active_used_roots)
                active_logical_bytes = b"".join(
                    (
                        json.dumps(row, sort_keys=True, separators=(",", ":"))
                        + "\n"
                    ).encode("utf-8")
                    for row in active_logical_rows
                )
                self.assertEqual(
                    P_CAPSULE_LOGICAL_MAPPING_SIZE, len(active_logical_bytes),
                )
                self.assertEqual(
                    P_CAPSULE_LOGICAL_MAPPING_SHA256,
                    hashlib.sha256(active_logical_bytes).hexdigest(),
                )
                self.assertEqual(b"", logical_mapping((), P_CAPSULE_ROOTS))

                caller_archive_metadata = os.fstat(archive_fd)
                caller_archive_identity = (
                    caller_archive_metadata.st_dev,
                    caller_archive_metadata.st_ino,
                    caller_archive_metadata.st_size,
                )
                caller_archive_offset = os.lseek(archive_fd, 0, os.SEEK_CUR)
                active_authority_helper = getattr(
                    module, "_active_dependency_authority",
                )
                sentinel_state = formal_root / "authenticated-source-sentinel"
                sentinel_state.mkdir(mode=0o700)
                sentinel_snapshot = extract(dependency_archive, sentinel_state)
                sentinel_summary = verify_snapshot(sentinel_snapshot)
                self.assertNotEqual(
                    (active_snapshot.lstat().st_dev, active_snapshot.lstat().st_ino),
                    (sentinel_snapshot.lstat().st_dev, sentinel_snapshot.lstat().st_ino),
                )
                active_reads = []
                active_headers = []
                active_authority_arguments = []
                caller_archive_closes = []
                caller_archive_duplicates = []
                real_header = getattr(module, "_canonical_ustar_header")
                real_close = os.close
                real_dup = os.dup
                real_fcntl = fcntl.fcntl
                def observed_active_source(path):
                    payload, mode = read_source(path)
                    source_path = Path(path).resolve()
                    self.assertTrue(source_path.is_relative_to(sentinel_snapshot))
                    target = source_path.relative_to(sentinel_snapshot).as_posix()
                    record = active_record_authority[target]
                    self.assertEqual(int(record["mode"], 8), mode)
                    self.assertEqual(record["size"], len(payload))
                    self.assertEqual(
                        record["sha256"], hashlib.sha256(payload).hexdigest(),
                    )
                    active_reads.append(target)
                    return payload, mode
                def observed_active_header(name, mode, size):
                    active_headers.append((name, mode, size))
                    return real_header(name, mode, size)
                def observed_active_authority(nonowning_archive):
                    self.assertIsInstance(
                        nonowning_archive, _DependencyArchiveAuthority,
                    )
                    self.assertEqual(archive_fd, nonowning_archive.fd)
                    self.assertEqual(
                        caller_archive_identity,
                        (
                            nonowning_archive.dev, nonowning_archive.ino,
                            nonowning_archive.size,
                        ),
                    )
                    self.assertEqual(
                        P_CAPSULE_ARCHIVE_SHA256, nonowning_archive.sha256,
                    )
                    active_authority_arguments.append(nonowning_archive)
                    with mock.patch.object(
                        module, "_read_stable_dependency_source",
                        side_effect=read_source,
                    ):
                        authority = active_authority_helper(nonowning_archive)
                    return SimpleNamespace(
                        **{
                            **vars(authority),
                            "snapshot": sentinel_snapshot,
                            "snapshot_summary": sentinel_summary,
                        }
                    )
                def observed_active_close(descriptor):
                    if descriptor == archive_fd:
                        caller_archive_closes.append(descriptor)
                    return real_close(descriptor)
                def observed_active_dup(descriptor):
                    if descriptor == archive_fd:
                        caller_archive_duplicates.append(("os.dup",))
                    return real_dup(descriptor)
                def observed_active_fcntl(descriptor, operation, *args):
                    if (
                        descriptor == archive_fd
                        and operation == getattr(fcntl, "F_DUPFD_CLOEXEC", -1)
                    ):
                        caller_archive_duplicates.append(args)
                    return real_fcntl(descriptor, operation, *args)

                active_build_state = formal_root / "authenticated-source-build"
                active_build_state.mkdir(mode=0o700)
                with mock.patch.dict(
                    os.environ, active_environment, clear=False,
                ), mock.patch.object(
                    module, "_resolve_dependency_sources",
                    side_effect=AssertionError(
                        "authenticated snapshot attempted external source fallback"
                    ),
                ) as forbidden_external_sources, mock.patch.object(
                    module, "_read_stable_dependency_source",
                    side_effect=observed_active_source,
                ), mock.patch.object(
                    module, "_canonical_ustar_header",
                    side_effect=observed_active_header,
                ), mock.patch.object(
                    module, "_canonical_dependency_logical_mapping",
                    wraps=logical_mapping,
                ) as active_logical_mapping:
                    with mock.patch.object(
                        module, "_active_dependency_authority",
                        side_effect=observed_active_authority,
                    ) as consumed_active_authority, mock.patch.object(
                        os, "close", side_effect=observed_active_close,
                    ), mock.patch.object(
                        os, "dup", side_effect=observed_active_dup,
                    ), mock.patch.object(
                        fcntl, "fcntl", side_effect=observed_active_fcntl,
                    ):
                        rebuilt_active_archive = build(active_build_state)
                forbidden_external_sources.assert_not_called()
                self.assertEqual(1, consumed_active_authority.call_count)
                self.assertEqual(1, len(active_authority_arguments))
                self.assertEqual([], caller_archive_closes)
                self.assertEqual([], caller_archive_duplicates)
                self.assertEqual(list(active_targets), active_reads)
                self.assertTrue(all(
                    target != P_CAPSULE_EXCLUDED_TARGET for target in active_reads
                ))
                self.assertEqual(
                    [
                        (
                            target,
                            int(active_record_authority[target]["mode"], 8),
                            active_record_authority[target]["size"],
                        )
                        for target in active_targets
                    ],
                    active_headers,
                )
                self.assertIn(
                    mock.call(tuple(active_logical_rows), P_CAPSULE_ROOTS),
                    active_logical_mapping.call_args_list,
                )
                self.assertIn(
                    mock.call((), P_CAPSULE_ROOTS),
                    active_logical_mapping.call_args_list,
                )
                rebuilt_metadata = os.fstat(rebuilt_active_archive.fd)
                self.assertEqual(0, rebuilt_metadata.st_nlink)
                self.assertEqual(0o400, stat.S_IMODE(rebuilt_metadata.st_mode))
                self.assertEqual(os.O_RDONLY, (
                    fcntl.fcntl(rebuilt_active_archive.fd, fcntl.F_GETFL)
                    & os.O_ACCMODE
                ))
                self.assertNotEqual(
                    (caller_archive_metadata.st_dev, caller_archive_metadata.st_ino),
                    (rebuilt_metadata.st_dev, rebuilt_metadata.st_ino),
                )
                rebuilt_summary = verify_archive(rebuilt_active_archive)
                self.assertEqual(P_CAPSULE_ARCHIVE_SHA256, rebuilt_summary["archive_sha256"])
                self.assertEqual(P_CAPSULE_RECORDS_SHA256, rebuilt_summary["records_sha256"])
                rebuilt_active_fd = rebuilt_active_archive.fd
                rebuilt_active_archive.close()
                with self.assertRaises(OSError):
                    os.fstat(rebuilt_active_fd)
                self.assertEqual([], list(active_build_state.iterdir()))
                active_build_state.rmdir()
                self.assertEqual(
                    caller_archive_identity,
                    (
                        os.fstat(archive_fd).st_dev, os.fstat(archive_fd).st_ino,
                        os.fstat(archive_fd).st_size,
                    ),
                )
                self.assertEqual(
                    caller_archive_offset, os.lseek(archive_fd, 0, os.SEEK_CUR),
                )
                self.assertEqual(
                    P_CAPSULE_ARCHIVE_SHA256,
                    verify_archive(dependency_archive)["archive_sha256"],
                )
                sentinel_snapshot_fd = os.open(
                    sentinel_snapshot,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    | os.O_NONBLOCK | os.O_CLOEXEC,
                )
                sentinel_identity = os.fstat(sentinel_snapshot_fd)
                self.assertEqual(
                    (sentinel_identity.st_dev, sentinel_identity.st_ino),
                    (
                        sentinel_snapshot.lstat().st_dev,
                        sentinel_snapshot.lstat().st_ino,
                    ),
                )
                os.close(sentinel_snapshot_fd)
                shutil.rmtree(sentinel_snapshot)
                sentinel_state.rmdir()

                early_state = formal_root / "active-source-early-rejection"
                early_state.mkdir(mode=0o700)
                early_reads = []
                early_headers = []
                forged_marker = {
                    **active_environment, reentry_keys["marker"]: "0",
                }
                with mock.patch.dict(
                    os.environ, forged_marker, clear=True,
                ), mock.patch.object(
                    module, "_active_dependency_authority",
                    wraps=active_authority_helper,
                ) as rejecting_active_authority, mock.patch.object(
                    module, "_resolve_dependency_sources",
                    side_effect=AssertionError("early rejection used external roots"),
                ) as forbidden_early_resolver, mock.patch.object(
                    module, "_read_stable_dependency_source",
                    side_effect=lambda path: early_reads.append(Path(path)) or read_source(path),
                ), mock.patch.object(
                    module, "_canonical_ustar_header",
                    side_effect=lambda *args: early_headers.append(args) or real_header(*args),
                ), self.assertRaises(AssertionError):
                    build(early_state)
                self.assertEqual(1, rejecting_active_authority.call_count)
                forbidden_early_resolver.assert_not_called()
                self.assertEqual([], early_reads)
                self.assertEqual([], early_headers)
                self.assertEqual([], list(early_state.iterdir()))
                early_state.rmdir()

                def assert_active_source_rejected(label, environment):
                    hostile_state = formal_root / ("active-source-hostile-" + label)
                    hostile_state.mkdir(mode=0o700)
                    try:
                        with mock.patch.dict(
                            os.environ, environment, clear=True,
                        ), mock.patch.object(
                            module, "_resolve_dependency_sources",
                            side_effect=AssertionError(
                                "authenticated snapshot used mixed external roots"
                            ),
                        ) as forbidden_mixed_sources, self.assertRaises(AssertionError):
                            build(hostile_state)
                        forbidden_mixed_sources.assert_not_called()
                        self.assertEqual([], list(hostile_state.iterdir()))
                    finally:
                        if os.path.lexists(hostile_state):
                            shutil.rmtree(hostile_state)

                protocol_keys = (
                    P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
                    *reentry_keys.values(),
                )
                self.assertEqual(9, len(protocol_keys))
                for missing_key in protocol_keys:
                    incomplete = dict(active_environment)
                    incomplete.pop(missing_key)
                    with self.subTest(active_source_missing_key=missing_key):
                        assert_active_source_rejected(
                            "missing-" + missing_key.lower().replace("_", "-"),
                            incomplete,
                        )
                forged_environments = {
                    "snapshot-identity": {
                        **active_environment,
                        reentry_keys["snapshot_identity"]: ":".join((
                            str(active_snapshot_metadata.st_dev),
                            str(active_snapshot_metadata.st_ino), "00" * 32,
                        )),
                    },
                    "mixed-snapshot-path": {
                        **active_environment,
                        reentry_keys["snapshot"]: str(
                            Path(resolved["numpy"]).resolve().parent
                        ),
                    },
                }
                for label, forged_environment in forged_environments.items():
                    with self.subTest(active_source_forgery=label):
                        assert_active_source_rejected(label, forged_environment)

                six_path = active_snapshot / "six.py"
                six_payload = six_path.read_bytes()
                six_mode = stat.S_IMODE(six_path.lstat().st_mode)
                outside_six = formal_root / "outside-six.py"
                outside_six.write_bytes(six_payload)
                outside_six.chmod(six_mode)
                for mutation in ("missing", "symlink", "extra", "drift"):
                    hostile_state = formal_root / ("active-source-" + mutation)
                    hostile_state.mkdir(mode=0o700)
                    extra_path = active_snapshot / "hostile-extra.py"
                    try:
                        if mutation == "missing":
                            six_path.unlink()
                        elif mutation == "symlink":
                            six_path.unlink()
                            six_path.symlink_to(outside_six)
                        elif mutation == "extra":
                            extra_path.write_bytes(b"hostile active source\n")
                            extra_path.chmod(0o644)
                        else:
                            self.assertGreater(len(six_payload), 1)
                            drifted = bytes([six_payload[0] ^ 1]) + six_payload[1:]
                            six_path.write_bytes(drifted)
                            six_path.chmod(six_mode)
                        with self.subTest(active_source_mutation=mutation), \
                                mock.patch.dict(
                                    os.environ, active_environment, clear=False,
                                ), mock.patch.object(
                                    module, "_resolve_dependency_sources",
                                    side_effect=AssertionError(
                                        "mutated active source used external fallback"
                                    ),
                                ) as forbidden_mutation_fallback, \
                                self.assertRaises(AssertionError):
                            build(hostile_state)
                        forbidden_mutation_fallback.assert_not_called()
                        self.assertEqual([], list(hostile_state.iterdir()))
                    finally:
                        if six_path.is_symlink() or not six_path.exists():
                            if os.path.lexists(six_path):
                                six_path.unlink()
                            six_path.write_bytes(six_payload)
                            six_path.chmod(six_mode)
                        elif mutation == "drift":
                            six_path.write_bytes(six_payload)
                            six_path.chmod(six_mode)
                        if os.path.lexists(extra_path):
                            extra_path.unlink()
                        if os.path.lexists(hostile_state):
                            shutil.rmtree(hostile_state)
                    self.assertEqual(
                        active_snapshot_payload, six_path.read_bytes(), mutation,
                    )
                    self.assertEqual(
                        P_CAPSULE_RECORDS_SHA256,
                        verify_snapshot(active_snapshot)["records_sha256"],
                    )
                outside_six.unlink()

                held_snapshot = active_state / "snapshot-held-for-source-rebind"
                active_snapshot.rename(held_snapshot)
                rebound_snapshot = extract(dependency_archive, active_state)
                self.assertEqual(active_snapshot, rebound_snapshot)
                self.assertNotEqual(
                    (os.fstat(active_snapshot_fd).st_dev, os.fstat(active_snapshot_fd).st_ino),
                    (rebound_snapshot.lstat().st_dev, rebound_snapshot.lstat().st_ino),
                )
                rebind_state = formal_root / "active-source-root-rebind"
                rebind_state.mkdir(mode=0o700)
                try:
                    self.assertEqual(
                        P_CAPSULE_RECORDS_SHA256,
                        verify_snapshot(rebound_snapshot)["records_sha256"],
                    )
                    with mock.patch.dict(
                        os.environ, active_environment, clear=False,
                    ), mock.patch.object(
                        module, "_resolve_dependency_sources",
                        side_effect=AssertionError(
                            "rebound active source used external fallback"
                        ),
                    ) as forbidden_rebind_fallback, self.assertRaises(AssertionError):
                        build(rebind_state)
                    forbidden_rebind_fallback.assert_not_called()
                    self.assertEqual([], list(rebind_state.iterdir()))
                finally:
                    if os.path.lexists(rebound_snapshot):
                        shutil.rmtree(rebound_snapshot)
                    held_snapshot.rename(active_snapshot)
                    if os.path.lexists(rebind_state):
                        shutil.rmtree(rebind_state)
                self.assertEqual(
                    (os.fstat(active_snapshot_fd).st_dev, os.fstat(active_snapshot_fd).st_ino),
                    (active_snapshot.lstat().st_dev, active_snapshot.lstat().st_ino),
                )
                self.assertEqual(
                    P_CAPSULE_RECORDS_SHA256,
                    verify_snapshot(active_snapshot)["records_sha256"],
                )
                self.assertEqual(
                    caller_archive_offset, os.lseek(archive_fd, 0, os.SEEK_CUR),
                )
                if active_fixture is None:
                    runner_archive = dependency_archive
                    runner_snapshot = active_snapshot
                    runner_python_home = active_python_home
                    runner_fds = active_fds
                    runner_environment = active_environment
                else:
                    runner_archive = borrowed_archive
                    runner_snapshot = active_fixture.snapshot
                    runner_python_home = active_fixture.python_home
                    runner_fds = active_fixture.source_fds
                    runner_environment = active_fixture_environment
                runner_components = (
                    (
                        runner_python_home.state_path,
                        runner_python_home.state_fd, 0o700,
                        *runner_python_home.state_identity,
                    ),
                    *runner_python_home.components,
                )
                self.assertEqual(
                    runner_fds,
                    (
                        int(runner_environment[P_CAPSULE_FD_ENV]),
                        int(runner_environment[reentry_keys["snapshot_fd"]]),
                        *map(int, runner_environment[
                            reentry_keys["python_home_fds"]
                        ].split(",")),
                    ),
                )
                runner_identities = tuple(
                    (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                    for descriptor in runner_fds
                )
                runner_flags = tuple(
                    (
                        fcntl.fcntl(descriptor, fcntl.F_GETFL),
                        fcntl.fcntl(descriptor, fcntl.F_GETFD),
                    )
                    for descriptor in runner_fds
                )
                runner_archive_offset = os.lseek(runner_fds[0], 0, os.SEEK_CUR)
                runner_formal_environment = {
                    **runner_environment,
                    P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: (
                        active_fixture_loopback_marker
                        if active_fixture is not None else "1"
                    ),
                }
                runner_state = runner_snapshot.parent
                runner_snapshot_payload = (runner_snapshot / "six.py").read_bytes()
                runner_runtime_paths = (
                    runner_state / "home", runner_state / "pycache",
                )
                runner_runtime_identities = tuple(
                    (
                        path.lstat().st_dev, path.lstat().st_ino,
                        stat.S_IMODE(path.lstat().st_mode),
                    )
                    for path in runner_runtime_paths
                )
                def assert_runner_runtime_unchanged():
                    self.assertEqual(
                        (
                            "formal-loopback-sshd", "home", "pycache",
                            "python-home", "snapshot",
                        ),
                        tuple(sorted(path.name for path in runner_state.iterdir())),
                    )
                    for runtime_path, expected_identity in zip(
                        runner_runtime_paths, runner_runtime_identities,
                    ):
                        metadata = runtime_path.lstat()
                        self.assertTrue(stat.S_ISDIR(metadata.st_mode))
                        self.assertEqual(expected_identity, (
                            metadata.st_dev, metadata.st_ino,
                            stat.S_IMODE(metadata.st_mode),
                        ))

                runner_loopback_stack = contextlib.ExitStack()
                owned_runner_loopback = active_fixture is None
                def assert_synthetic_runtime_during_runner_scope():
                    expected_children = (
                        (
                            "formal-loopback-sshd", "home", "pycache",
                            "python-home", "snapshot",
                        )
                        if owned_runner_loopback else
                        ("home", "pycache", "python-home", "snapshot")
                    )
                    self.assertEqual(
                        expected_children,
                        tuple(sorted(path.name for path in active_state.iterdir())),
                    )
                    for runtime_path, expected_identity in zip(
                        active_runtime_paths, active_runtime_identities,
                    ):
                        metadata = runtime_path.lstat()
                        self.assertEqual(expected_identity, (
                            metadata.st_dev, metadata.st_ino,
                            stat.S_IMODE(metadata.st_mode),
                        ))
                runner_loopback_held_fds = ()
                runner_loopback_pid = None
                runner_loopback_pgid = None
                runner_loopback_root = None
                runner_loopback_ready = False
                try:
                    if owned_runner_loopback:
                        runner_loopback = runner_loopback_stack.enter_context(
                            loopback_scope(runner_state)
                        )
                        (
                            runner_loopback_held_fds,
                            runner_loopback_pid,
                            runner_loopback_root,
                        ) = assert_loopback_authority(
                            runner_loopback, runner_state,
                        )
                        runner_loopback_pgid = os.getpgid(runner_loopback_pid)
                    else:
                        with mock.patch.dict(
                            os.environ,
                            {
                                **runner_environment,
                                P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "1",
                            },
                            clear=True,
                        ), mock.patch.object(
                            module, "_active_dependency_authority",
                            wraps=active_helper,
                        ) as inherited_runner_helper:
                            runner_loopback = loopback_consumer()
                        inherited_runner_helper.assert_called_once()
                        self.assertEqual(runner_fds, runner_loopback.source_fds)
                        runner_loopback_root = runner_loopback.root
                        runner_loopback_pid = runner_loopback.daemon_pid
                        runner_loopback_pgid = os.getpgid(runner_loopback_pid)
                    self.assertEqual(
                        runner_loopback_pid, runner_loopback_pgid,
                    )
                    self.assertEqual(
                        runner_state / P_EXPECTED_FORMAL_LOOPBACK_SSHD_RELATIVE,
                        runner_loopback_root,
                    )
                    runner_loopback_identity = (
                        runner_loopback_root.lstat().st_dev,
                        runner_loopback_root.lstat().st_ino,
                    )
                    runner_loopback_value = (
                        runner_loopback.root, runner_loopback.port,
                        runner_loopback.daemon_pid,
                        dict(runner_loopback.public_keys),
                        dict(runner_loopback.fingerprints),
                    )
                    assert_runner_runtime_unchanged()
                    assert_synthetic_runtime_during_runner_scope()
                    active_python_home_layout = tuple(
                        tuple(sorted(os.listdir(component[1])))
                        for component in active_components
                    )
                    runner_python_home_layout = tuple(
                        tuple(sorted(os.listdir(component[1])))
                        for component in runner_components
                    )
                    runner_loopback_ready = True
                    import runpy
                    class BootstrapDispatchObserved(BaseException):
                        pass
                    bootstrap_protocol_keys = (
                        P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
                        *reentry_keys.values(),
                    )
                    bootstrap_routing_keys = (
                        *bootstrap_protocol_keys,
                        P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                    )
                    capsule_bootstrap_tree = ast.parse(P_CAPSULE_BOOTSTRAP)
                    loopback_routing_assignments = [
                        node for node in capsule_bootstrap_tree.body
                        if isinstance(node, ast.Assign)
                        and any(
                            isinstance(target, ast.Name)
                            and target.id == "loopback_routing_key"
                            for target in node.targets
                        )
                    ]
                    self.assertEqual(1, len(loopback_routing_assignments))
                    self.assertIsInstance(
                        loopback_routing_assignments[0].value, ast.Constant,
                    )
                    self.assertEqual(
                        P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                        loopback_routing_assignments[0].value.value,
                    )
                    production_runner_arguments = allowed_reentrant_runners[:3]
                    for bootstrap_arguments in production_runner_arguments:
                        bootstrap_fds = tuple(
                            fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 0)
                            for descriptor in active_fds
                        )
                        bootstrap_environment = {
                            **active_environment,
                            P_CAPSULE_FD_ENV: str(bootstrap_fds[0]),
                            reentry_keys["snapshot_fd"]: str(bootstrap_fds[1]),
                            reentry_keys["python_home_fds"]: ",".join(
                                str(descriptor) for descriptor in bootstrap_fds[2:]
                            ),
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "1",
                        }
                        bootstrap_dispatch = []
                        def observe_bootstrap_dispatch(path, *, run_name):
                            self.assertEqual("test_cases/run_related_tests.py", path)
                            self.assertEqual("__main__", run_name)
                            self.assertEqual(list(bootstrap_arguments[1:]), sys.argv)
                            self.assertEqual(
                                set(bootstrap_routing_keys),
                                set(bootstrap_routing_keys).intersection(os.environ),
                            )
                            self.assertEqual(
                                str(bootstrap_fds[0]), os.environ[P_CAPSULE_FD_ENV],
                            )
                            self.assertEqual(
                                str(bootstrap_fds[1]),
                                os.environ[reentry_keys["snapshot_fd"]],
                            )
                            self.assertEqual(
                                ",".join(str(descriptor) for descriptor in bootstrap_fds[2:]),
                                os.environ[reentry_keys["python_home_fds"]],
                            )
                            for descriptor in bootstrap_fds:
                                os.fstat(descriptor)
                                self.assertFalse(os.get_inheritable(descriptor))
                            self.assertEqual(
                                active_environment[reentry_keys["python_home"]],
                                os.environ["PYTHONHOME"],
                            )
                            self.assertEqual(
                                os.pathsep.join((
                                    str(active_snapshot.resolve()), P_CAPSULE_STDLIB_ROOT,
                                    P_CAPSULE_STDLIB_ROOT + "/lib-dynload",
                                )),
                                os.environ["PYTHONPATH"],
                            )
                            self.assertEqual("1", os.environ["PYTHONNOUSERSITE"])
                            self.assertEqual("1", os.environ["PYTHONDONTWRITEBYTECODE"])
                            stdlib_root = Path(P_CAPSULE_STDLIB_ROOT).resolve()
                            trusted_roots = {
                                stdlib_root,
                                (stdlib_root / "lib-dynload").resolve(),
                            }
                            expected_trusted = [
                                str(resolved) for entry in original_path if entry
                                for resolved in (Path(entry).resolve(),)
                                if resolved in trusted_roots
                            ]
                            self.assertEqual(
                                [str(active_snapshot.resolve()), str(ROOT.resolve()), *expected_trusted],
                                sys.path,
                            )
                            self.assertTrue(all(
                                Path(entry).resolve() == stdlib_root
                                or Path(entry).resolve().is_relative_to(stdlib_root)
                                for entry in sys.path[2:]
                            ))
                            self.assertTrue(all(
                                "site-packages" not in Path(entry).parts
                                for entry in sys.path[2:]
                            ))
                            import importlib
                            yaml_module = importlib.import_module("yaml")
                            self.assertTrue(
                                Path(yaml_module.__file__).resolve().is_relative_to(
                                    active_snapshot
                                )
                            )
                            bootstrap_dispatch.append(tuple(sys.argv))
                            raise BootstrapDispatchObserved
                        original_argv = sys.argv
                        original_path = list(sys.path)
                        prior_yaml_modules = {
                            name: value for name, value in sys.modules.items()
                            if name == "yaml" or name.startswith("yaml.")
                        }
                        for name in prior_yaml_modules:
                            sys.modules.pop(name, None)
                        try:
                            with self.subTest(bootstrap_reentry=bootstrap_arguments), \
                                    mock.patch.dict(
                                        os.environ, bootstrap_environment, clear=True,
                                    ), mock.patch.object(
                                        runpy, "run_path", side_effect=observe_bootstrap_dispatch,
                                    ), self.assertRaises(BootstrapDispatchObserved):
                                sys.argv = [
                                    "-c", str(active_snapshot), str(ROOT),
                                    json.dumps(list(bootstrap_arguments), separators=(",", ":")),
                                ]
                                exec(compile(
                                    P_CAPSULE_BOOTSTRAP, "<reviewed capsule bootstrap>", "exec",
                                ), {"__name__": "__main__"})
                            self.assertEqual([tuple(bootstrap_arguments[1:])], bootstrap_dispatch)
                        finally:
                            sys.argv = original_argv
                            sys.path[:] = original_path
                            for name in tuple(sys.modules):
                                if name == "yaml" or name.startswith("yaml."):
                                    sys.modules.pop(name, None)
                            sys.modules.update(prior_yaml_modules)
                            for descriptor in bootstrap_fds:
                                try:
                                    os.close(descriptor)
                                except OSError:
                                    pass

                    expected_reentrant_unittest_bootstrap = """import fcntl, hashlib, json, os, pathlib, runpy, stat, sys
repository = pathlib.Path(sys.argv[1]).resolve()
arguments = json.loads(sys.argv[2])
if not isinstance(arguments, list) or not all(isinstance(value, str) for value in arguments):
    raise SystemExit('malformed reviewed unittest arguments')
if len(arguments) < 2 or arguments[0] != 'unittest':
    raise SystemExit('unreviewed unittest child target')
protocol_keys = (
    'HTTP_P_DEPENDENCY_ARCHIVE_FD', 'HTTP_P_DEPENDENCY_ARCHIVE_IDENTITY',
    'HTTP_P_DEPENDENCY_REENTRANT', 'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT',
    'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_IDENTITY',
    'HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT_FD',
    'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME',
    'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_IDENTITY',
    'HTTP_P_DEPENDENCY_ACTIVE_PYTHONHOME_FDS',
)
loopback_routing_key = 'HTTP_P_FORMAL_LOOPBACK_SSHD'
if any(key not in os.environ for key in protocol_keys):
    raise SystemExit('partial unittest dependency protocol')
archive_fd = int(os.environ[protocol_keys[0]])
snapshot_fd = int(os.environ[protocol_keys[5]])
python_home_fds = tuple(
    int(value) for value in os.environ[protocol_keys[8]].split(',') if value
)
descriptors = (archive_fd, snapshot_fd, *python_home_fds)
if len(descriptors) != 7 or len(set(descriptors)) != 7:
    raise SystemExit('aliased unittest dependency descriptors')
for descriptor in descriptors:
    os.set_inheritable(descriptor, False)
archive_identity = os.environ[protocol_keys[1]].split(':')
if len(archive_identity) != 4:
    raise SystemExit('malformed unittest archive identity')
archive_stat = os.fstat(archive_fd)
if (
    not stat.S_ISREG(archive_stat.st_mode)
    or stat.S_IMODE(archive_stat.st_mode) != 0o400
    or archive_stat.st_nlink != 0
    or fcntl.fcntl(archive_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
    or (str(archive_stat.st_dev), str(archive_stat.st_ino), str(archive_stat.st_size))
    != tuple(archive_identity[:3])
    or archive_identity[3]
    != '476c24d7320be00379236313fe7e919aca86dcb0a5bd15877255e012a073eedd'
):
    raise SystemExit('unsafe unittest dependency archive')
archive_digest = hashlib.sha256()
offset = 0
while offset < archive_stat.st_size:
    payload = os.pread(archive_fd, min(1024 * 1024, archive_stat.st_size - offset), offset)
    if not payload:
        raise SystemExit('truncated unittest dependency archive')
    archive_digest.update(payload)
    offset += len(payload)
if archive_digest.hexdigest() != archive_identity[3]:
    raise SystemExit('unittest dependency archive digest mismatch')
snapshot = pathlib.Path(os.environ[protocol_keys[3]]).resolve()
snapshot_identity = os.environ[protocol_keys[4]].split(':')
snapshot_stat = os.fstat(snapshot_fd)
snapshot_path_stat = snapshot.lstat()
if (
    len(snapshot_identity) != 3
    or not stat.S_ISDIR(snapshot_stat.st_mode)
    or fcntl.fcntl(snapshot_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
    or (snapshot_stat.st_dev, snapshot_stat.st_ino)
    != (snapshot_path_stat.st_dev, snapshot_path_stat.st_ino)
    or (str(snapshot_stat.st_dev), str(snapshot_stat.st_ino))
    != tuple(snapshot_identity[:2])
    or snapshot_identity[2]
    != 'ecfc714f73eb7e0c5c623bbdd8187b83ce982cf711d68252682fcf073faa56b9'
):
    raise SystemExit('unsafe unittest dependency snapshot')
python_home = pathlib.Path(os.environ[protocol_keys[6]]).resolve()
try:
    python_home_identity = json.loads(os.environ[protocol_keys[7]])
except (TypeError, ValueError):
    raise SystemExit('malformed unittest Python home identity')
if not isinstance(python_home_identity, list) or len(python_home_identity) != 5:
    raise SystemExit('malformed unittest Python home components')
for descriptor, expected in zip(python_home_fds, python_home_identity):
    if not isinstance(expected, dict) or set(expected) != {'dev', 'ino', 'mode', 'path'}:
        raise SystemExit('malformed unittest Python home component')
    metadata = os.fstat(descriptor)
    component = pathlib.Path(expected['path']).resolve()
    path_metadata = component.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        or (metadata.st_dev, metadata.st_ino, f'{stat.S_IMODE(metadata.st_mode):04o}')
        != (expected['dev'], expected['ino'], expected['mode'])
        or (metadata.st_dev, metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        raise SystemExit('unsafe unittest Python home component')
if pathlib.Path(python_home_identity[1]['path']).resolve() != python_home:
    raise SystemExit('unittest Python home path mismatch')
stdlib = pathlib.Path('/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9').resolve()
expected_pythonpath = os.pathsep.join((str(snapshot), str(stdlib), str(stdlib / 'lib-dynload')))
if (
    os.environ.get('HTTP_P_DEPENDENCY_REENTRANT') != '1'
    or pathlib.Path(os.environ.get('PYTHONHOME', '')).resolve() != python_home
    or os.environ.get('PYTHONPATH') != expected_pythonpath
    or os.environ.get('PYTHONNOUSERSITE') != '1'
    or os.environ.get('PYTHONDONTWRITEBYTECODE') != '1'
):
    raise SystemExit('unsafe unittest Python environment')
if any(key.startswith(('LD_', 'DYLD_', 'GIT_')) for key in os.environ):
    raise SystemExit('unsafe unittest ambient environment')
sys.path[:] = [str(snapshot), str(repository), str(stdlib), str(stdlib / 'lib-dynload')]
sys.argv = arguments
runpy.run_module('unittest', run_name='__main__', alter_sys=True)
"""
                    reviewed_unittest_bootstrap = globals().get(
                        "P_REENTRANT_UNITTEST_BOOTSTRAP"
                    )
                    self.assertEqual(
                        expected_reentrant_unittest_bootstrap,
                        reviewed_unittest_bootstrap,
                        "the runner child must use the independently reviewed bootstrap literal",
                    )

                    class UnittestChildDispatchObserved(BaseException):
                        pass

                    def exercise_runner_unittest_boundary(
                        bootstrap_arguments, *, child_attack=None, child_count=1,
                        terminal_exit=None,
                    ):
                        bootstrap_fds = tuple(
                            fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 0)
                            for descriptor in active_fds
                        )
                        bootstrap_environment = {
                            **active_environment,
                            P_CAPSULE_FD_ENV: str(bootstrap_fds[0]),
                            reentry_keys["snapshot_fd"]: str(bootstrap_fds[1]),
                            reentry_keys["python_home_fds"]: ",".join(
                                str(descriptor) for descriptor in bootstrap_fds[2:]
                            ),
                            "P_TEST_AMBIENT_SENTINEL": "preserved",
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "1",
                        }
                        if "--suite" in bootstrap_arguments:
                            runner_manifest = json.loads(
                                (ROOT / "test_cases/script_test_manifest.json").read_text(
                                    encoding="utf-8"
                                )
                            )
                            runner_suite = next(
                                suite for suite in runner_manifest["test_suites"]
                                if suite["id"] == "repository-governance"
                            )
                            runner_child = [
                                sys.executable, "-B", "-m", "unittest", "-b", "-v",
                                *sorted(runner_suite["tests"]),
                            ]
                        else:
                            runner_child = [
                                sys.executable, "-B", "-m", "unittest", "discover", "-b",
                                "-s", "test_cases", "-t", ".", "-p", "test_*.py", "-v",
                            ]
                        near_runner_children = (
                            (
                                sys.executable, "-B", "-m", "unittest", "-b", "-v",
                                P_STAGED_OVERLAY_FQN, P_FAST_EXACT_COMMIT_FQN,
                            ),
                            (
                                sys.executable, "-B", "-m", "unittest", "-b", "-v",
                                "--locals", P_STAGED_OVERLAY_FQN,
                            ),
                            (
                                sys.executable, "-B", "-m", "unittest", "-v", "-b",
                                P_STAGED_OVERLAY_FQN,
                            ),
                        )
                        delegated_git = []
                        delegated_near = []
                        child_calls = []
                        child_dispatches = []
                        duplicated = []
                        real_boundary_fcntl = fcntl.fcntl

                        def observe_boundary_fcntl(descriptor, operation, *values):
                            result = real_boundary_fcntl(descriptor, operation, *values)
                            if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in bootstrap_fds:
                                duplicated.append((descriptor, result))
                            return result

                        def observe_child_dispatch(module_name, *, run_name, alter_sys):
                            self.assertEqual("unittest", module_name)
                            self.assertEqual("__main__", run_name)
                            self.assertTrue(alter_sys)
                            child_environment = os.environ
                            child_fds = tuple(
                                int(child_environment[key])
                                for key in (
                                    P_CAPSULE_FD_ENV, reentry_keys["snapshot_fd"],
                                )
                            ) + tuple(
                                int(value) for value in child_environment[
                                    reentry_keys["python_home_fds"]
                                ].split(",")
                            )
                            self.assertEqual(7, len(child_fds))
                            self.assertEqual(7, len(set(child_fds)))
                            for descriptor in child_fds:
                                os.fstat(descriptor)
                                self.assertEqual(
                                    fcntl.FD_CLOEXEC,
                                    real_boundary_fcntl(descriptor, fcntl.F_GETFD)
                                    & fcntl.FD_CLOEXEC,
                                )
                            self.assertEqual(
                                active_environment[P_CAPSULE_IDENTITY_ENV],
                                child_environment[P_CAPSULE_IDENTITY_ENV],
                            )
                            self.assertEqual(
                                "1",
                                child_environment[
                                    P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV
                                ],
                            )
                            self.assertEqual(
                                [
                                    str(active_snapshot.resolve()), str(ROOT.resolve()),
                                    str(Path(P_CAPSULE_STDLIB_ROOT).resolve()),
                                    str((Path(P_CAPSULE_STDLIB_ROOT) / "lib-dynload").resolve()),
                                ],
                                sys.path,
                            )
                            self.assertEqual(
                                active_environment[reentry_keys["python_home"]],
                                child_environment["PYTHONHOME"],
                            )
                            self.assertEqual(runner_child[3:], sys.argv)
                            child_dispatches.append(tuple(sys.argv))
                            raise UnittestChildDispatchObserved

                        def fake_process(command, *args, **kwargs):
                            command_tuple = tuple(command)
                            if command_tuple and command_tuple[0] == GIT_BINARY:
                                delegated_git.append((command_tuple, args, kwargs))
                                return subprocess.CompletedProcess(command, 0, b"git version reviewed\n", b"")
                            if command_tuple in near_runner_children:
                                delegated_near.append((command_tuple, args, kwargs))
                                self.assertEqual((), args)
                                self.assertEqual(
                                    {"cwd", "env", "stdin", "check"}, set(kwargs),
                                )
                                self.assertNotIn("pass_fds", kwargs)
                                self.assertNotIn("shell", kwargs)
                                self.assertNotIn("preexec_fn", kwargs)
                                self.assertEqual(
                                    set(),
                                    set(bootstrap_routing_keys).intersection(kwargs["env"]),
                                )
                                return subprocess.CompletedProcess(command, 0, b"", b"")
                            child_calls.append((command_tuple, args, kwargs))
                            expected_duplicates = tuple(
                                duplicate for _source, duplicate in duplicated
                            )
                            self.assertEqual(7, len(expected_duplicates))
                            self.assertEqual(expected_duplicates, tuple(kwargs["pass_fds"]))
                            self.assertEqual((), args)
                            self.assertEqual(
                                {"cwd", "env", "stdin", "check", "pass_fds"},
                                set(kwargs),
                            )
                            self.assertNotIn("shell", kwargs)
                            self.assertNotIn("preexec_fn", kwargs)
                            self.assertNotIn("close_fds", kwargs)
                            self.assertNotIn("start_new_session", kwargs)
                            self.assertEqual(str(ROOT.resolve()), os.fspath(kwargs["cwd"]))
                            self.assertIs(subprocess.DEVNULL, kwargs["stdin"])
                            self.assertFalse(kwargs["check"])
                            self.assertEqual(
                                (
                                    str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                                    reviewed_unittest_bootstrap, str(ROOT.resolve()),
                                    json.dumps(runner_child[3:], separators=(",", ":")),
                                ),
                                command_tuple,
                            )
                            child_environment = dict(kwargs["env"])
                            self.assertTrue(all(
                                not key.startswith(("LD_", "DYLD_", "GIT_"))
                                for key in child_environment
                            ))
                            self.assertEqual(
                                "1",
                                child_environment[
                                    P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV
                                ],
                            )
                            if child_attack == "process-baseexception":
                                raise BootstrapDispatchObserved
                            if child_attack == "partial":
                                child_environment.pop(reentry_keys["snapshot_fd"])
                            elif child_attack == "alias":
                                child_environment[reentry_keys["snapshot_fd"]] = child_environment[
                                    P_CAPSULE_FD_ENV
                                ]
                            elif child_attack == "wrong-identity":
                                child_environment[reentry_keys["snapshot_identity"]] = "0:0:" + (
                                    "0" * 64
                                )
                            original_argv = sys.argv
                            original_path = list(sys.path)
                            try:
                                for descriptor in expected_duplicates:
                                    os.set_inheritable(descriptor, True)
                                with mock.patch.dict(
                                    os.environ, child_environment, clear=True,
                                ), mock.patch.object(
                                    runpy, "run_module", side_effect=observe_child_dispatch,
                                ):
                                    sys.argv = list(command_tuple[5:])
                                    if child_attack == "writable":
                                        def writable_fcntl(descriptor, operation, *values):
                                            result = real_boundary_fcntl(
                                                descriptor, operation, *values
                                            )
                                            if (
                                                operation == fcntl.F_GETFL
                                                and descriptor == expected_duplicates[0]
                                            ):
                                                return (result & ~os.O_ACCMODE) | os.O_RDWR
                                            return result
                                        with mock.patch.object(
                                            fcntl, "fcntl", side_effect=writable_fcntl,
                                        ), self.assertRaises(SystemExit):
                                            exec(compile(
                                                reviewed_unittest_bootstrap,
                                                "<reviewed unittest bootstrap>", "exec",
                                            ), {"__name__": "__main__"})
                                    elif child_attack in {
                                        "partial", "alias", "wrong-identity",
                                    }:
                                        with self.assertRaises(SystemExit):
                                            exec(compile(
                                                reviewed_unittest_bootstrap,
                                                "<reviewed unittest bootstrap>", "exec",
                                            ), {"__name__": "__main__"})
                                    else:
                                        with self.assertRaises(UnittestChildDispatchObserved):
                                            exec(compile(
                                                reviewed_unittest_bootstrap,
                                                "<reviewed unittest bootstrap>", "exec",
                                            ), {"__name__": "__main__"})
                            finally:
                                sys.argv = original_argv
                                sys.path[:] = original_path
                            return subprocess.CompletedProcess(
                                command,
                                73 if child_attack in {
                                    "partial", "alias", "writable", "wrong-identity",
                                } else 0,
                                b"", b"",
                            )

                        def fake_runner(path, *, run_name):
                            self.assertEqual("test_cases/run_related_tests.py", path)
                            self.assertEqual("__main__", run_name)
                            if child_attack == "runpath-baseexception":
                                raise BootstrapDispatchObserved
                            git_environment = {"P_TEST_GIT_SENTINEL": "preserved"}
                            git_result = subprocess.run(
                                [GIT_BINARY, "--version"], env=git_environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False,
                            )
                            self.assertEqual(0, git_result.returncode)
                            no_environment_git = subprocess.run(
                                [GIT_BINARY, "rev-parse", "--show-toplevel"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False,
                            )
                            self.assertEqual(0, no_environment_git.returncode)
                            none_environment_git = subprocess.run(
                                [GIT_BINARY, "status", "--porcelain=v1"], env=None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False,
                            )
                            self.assertEqual(0, none_environment_git.returncode)
                            selected_children = (
                                near_runner_children
                                if child_attack == "near" else (tuple(runner_child),) * child_count
                            )
                            for selected_child in selected_children:
                                child_result = subprocess.run(
                                    selected_child,
                                    cwd=ROOT, env=os.environ.copy(),
                                    stdin=subprocess.DEVNULL, check=False,
                                )
                                if child_result.returncode:
                                    raise SystemExit("reviewed unittest child failed")
                            if terminal_exit is not None:
                                raise terminal_exit

                        original_argv = sys.argv
                        original_path = list(sys.path)
                        try:
                            with mock.patch.dict(
                                os.environ, bootstrap_environment, clear=True,
                            ), mock.patch.object(
                                runpy, "run_path", side_effect=fake_runner,
                            ), mock.patch.object(
                                subprocess, "run", side_effect=fake_process,
                            ) as boundary_process, mock.patch.object(
                                fcntl, "fcntl", side_effect=observe_boundary_fcntl,
                            ):
                                sys.argv = [
                                    "-c", str(active_snapshot), str(ROOT),
                                    json.dumps(list(bootstrap_arguments), separators=(",", ":")),
                                ]
                                if terminal_exit is not None:
                                    with self.assertRaises(SystemExit) as terminal_result:
                                        exec(compile(
                                            P_CAPSULE_BOOTSTRAP,
                                            "<reviewed capsule bootstrap>", "exec",
                                        ), {"__name__": "__main__"})
                                    if child_count == 1:
                                        self.assertIs(terminal_exit, terminal_result.exception)
                                    else:
                                        self.assertIsNot(terminal_exit, terminal_result.exception)
                                        self.assertRegex(
                                            str(terminal_result.exception),
                                            "exactly one|multiple reviewed",
                                        )
                                elif child_attack in {
                                    "process-baseexception", "runpath-baseexception",
                                }:
                                    with self.assertRaises(BootstrapDispatchObserved):
                                        exec(compile(
                                            P_CAPSULE_BOOTSTRAP,
                                            "<reviewed capsule bootstrap>", "exec",
                                        ), {"__name__": "__main__"})
                                elif child_attack in {
                                    "partial", "alias", "writable", "wrong-identity", "near",
                                }:
                                    with self.assertRaises(SystemExit):
                                        exec(compile(
                                            P_CAPSULE_BOOTSTRAP,
                                            "<reviewed capsule bootstrap>", "exec",
                                        ), {"__name__": "__main__"})
                                elif child_count != 1:
                                    with self.assertRaises(SystemExit):
                                        exec(compile(
                                            P_CAPSULE_BOOTSTRAP,
                                            "<reviewed capsule bootstrap>", "exec",
                                        ), {"__name__": "__main__"})
                                else:
                                    exec(compile(
                                        P_CAPSULE_BOOTSTRAP,
                                        "<reviewed capsule bootstrap>", "exec",
                                    ), {"__name__": "__main__"})
                                self.assertIs(
                                    boundary_process, subprocess.run,
                                    "runner interception must restore subprocess.run on every exit",
                                )
                        finally:
                            sys.argv = original_argv
                            sys.path[:] = original_path
                            for descriptor in bootstrap_fds:
                                try:
                                    os.close(descriptor)
                                except OSError:
                                    pass
                        self.assertEqual(
                            0 if child_attack == "runpath-baseexception" else 3,
                            len(delegated_git),
                        )
                        if delegated_git:
                            self.assertEqual([
                                (GIT_BINARY, "--version"),
                                (GIT_BINARY, "rev-parse", "--show-toplevel"),
                                (GIT_BINARY, "status", "--porcelain=v1"),
                            ], [command for command, _args, _kwargs in delegated_git])
                            for git_index, (_command, git_args, git_kwargs) in enumerate(
                                delegated_git
                            ):
                                self.assertEqual((), git_args)
                                self.assertEqual(
                                    {"env", "stdout", "stderr", "check"},
                                    set(git_kwargs),
                                )
                                self.assertNotIn("pass_fds", git_kwargs)
                                self.assertNotIn("shell", git_kwargs)
                                self.assertNotIn("preexec_fn", git_kwargs)
                                self.assertEqual(
                                    set(),
                                    set(bootstrap_routing_keys).intersection(
                                        git_kwargs["env"]
                                    ),
                                )
                                if git_index == 0:
                                    self.assertEqual(
                                        {"P_TEST_GIT_SENTINEL": "preserved"},
                                        git_kwargs["env"],
                                    )
                                else:
                                    self.assertEqual(
                                        "preserved",
                                        git_kwargs["env"]["P_TEST_AMBIENT_SENTINEL"],
                                    )
                                self.assertIs(subprocess.PIPE, git_kwargs["stdout"])
                                self.assertIs(subprocess.PIPE, git_kwargs["stderr"])
                                self.assertFalse(git_kwargs["check"])
                        expected_reviewed_calls = (
                            min(child_count, 1) if child_attack is None else 1
                        )
                        if child_attack in {
                            None, "partial", "alias", "writable", "wrong-identity",
                        }:
                            self.assertEqual(
                                expected_reviewed_calls, len(child_calls),
                            )
                        if child_attack == "near":
                            self.assertEqual(list(near_runner_children), [
                                command for command, _args, _kwargs in delegated_near
                            ])
                            self.assertEqual([], child_calls)
                        if child_attack is None:
                            self.assertEqual(
                                [tuple(runner_child[3:])] * expected_reviewed_calls,
                                child_dispatches,
                            )
                        if child_attack == "runpath-baseexception":
                            self.assertEqual([], duplicated)
                        for _source, descriptor in duplicated:
                            with self.assertRaises(OSError):
                                os.fstat(descriptor)
                        for descriptor in active_fds:
                            os.fstat(descriptor)

                    for bootstrap_arguments in production_runner_arguments:
                        with self.subTest(runner_unittest_handoff=bootstrap_arguments):
                            exercise_runner_unittest_boundary(bootstrap_arguments)
                    for child_attack in (
                        "near", "partial", "alias", "writable", "wrong-identity",
                        "process-baseexception", "runpath-baseexception",
                    ):
                        with self.subTest(runner_unittest_attack=child_attack):
                            exercise_runner_unittest_boundary(
                                production_runner_arguments[0], child_attack=child_attack,
                            )
                    for child_count in (0, 2):
                        with self.subTest(runner_unittest_child_count=child_count):
                            exercise_runner_unittest_boundary(
                                production_runner_arguments[0], child_count=child_count,
                            )
                    for child_count in (0, 1, 2):
                        with self.subTest(
                            runner_terminal_system_exit_child_count=child_count,
                        ):
                            exercise_runner_unittest_boundary(
                                production_runner_arguments[0], child_count=child_count,
                                terminal_exit=SystemExit(37),
                            )

                    bootstrap_near_arguments = (
                        "-B", "test_cases/run_related_tests.py", "--all", "-v", "--extra",
                    )
                    near_bootstrap_fds = tuple(
                        fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 0)
                        for descriptor in active_fds
                    )
                    near_bootstrap_environment = {
                        **active_environment,
                        P_CAPSULE_FD_ENV: str(near_bootstrap_fds[0]),
                        reentry_keys["snapshot_fd"]: str(near_bootstrap_fds[1]),
                        reentry_keys["python_home_fds"]: ",".join(
                            str(descriptor) for descriptor in near_bootstrap_fds[2:]
                        ),
                        P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "hostile-near-marker",
                    }
                    near_bootstrap_dispatch = []
                    def observe_near_bootstrap_dispatch(path, *, run_name):
                        self.assertEqual("test_cases/run_related_tests.py", path)
                        self.assertEqual("__main__", run_name)
                        self.assertEqual(list(bootstrap_near_arguments[1:]), sys.argv)
                        self.assertEqual(
                            set(), set(bootstrap_routing_keys).intersection(os.environ),
                        )
                        for descriptor in near_bootstrap_fds:
                            with self.assertRaises(OSError):
                                os.fstat(descriptor)
                        near_bootstrap_dispatch.append(tuple(sys.argv))
                        raise BootstrapDispatchObserved
                    original_argv = sys.argv
                    original_path = list(sys.path)
                    try:
                        with mock.patch.dict(
                            os.environ, near_bootstrap_environment, clear=True,
                        ), mock.patch.object(
                            runpy, "run_path", side_effect=observe_near_bootstrap_dispatch,
                        ), self.assertRaises(BootstrapDispatchObserved):
                            sys.argv = [
                                "-c", str(active_snapshot), str(ROOT),
                                json.dumps(list(bootstrap_near_arguments), separators=(",", ":")),
                            ]
                            exec(compile(
                                P_CAPSULE_BOOTSTRAP, "<reviewed capsule bootstrap>", "exec",
                            ), {"__name__": "__main__"})
                        self.assertEqual(
                            [tuple(bootstrap_near_arguments[1:])], near_bootstrap_dispatch,
                        )
                    finally:
                        sys.argv = original_argv
                        sys.path[:] = original_path
                        for descriptor in near_bootstrap_fds:
                            try:
                                os.close(descriptor)
                            except OSError:
                                pass

                    for runner_index, runner_arguments in enumerate(
                        allowed_reentrant_runners
                    ):
                        with self.subTest(authenticated_reentry=runner_arguments):
                            formal_runner = runner_index < 3
                            case_archive = (
                                runner_archive if formal_runner else dependency_archive
                            )
                            case_snapshot = (
                                runner_snapshot if formal_runner else active_snapshot
                            )
                            case_python_home = (
                                runner_python_home if formal_runner else active_python_home
                            )
                            case_components = (
                                runner_components if formal_runner else active_components
                            )
                            case_fds = runner_fds if formal_runner else active_fds
                            case_environment = (
                                runner_environment if formal_runner else active_environment
                            )
                            case_snapshot_payload = (
                                runner_snapshot_payload
                                if formal_runner else active_snapshot_payload
                            )
                            case_python_home_layout = (
                                runner_python_home_layout
                                if formal_runner else active_python_home_layout
                            )
                            reentry_duplications = []
                            real_reentry_fcntl = fcntl.fcntl
                            def observed_reentry_fcntl(descriptor, operation, *values):
                                result = real_reentry_fcntl(descriptor, operation, *values)
                                if (
                                    operation == fcntl.F_DUPFD_CLOEXEC
                                    and descriptor in case_fds
                                ):
                                    reentry_duplications.append((descriptor, result))
                                return result
                            reentrant_result = subprocess.CompletedProcess(
                                ["reentrant-direct"], 0, "trusted reentrant\n", "",
                            )
                            bounded_results = iter((
                                subprocess.CompletedProcess(
                                    ["nested-sandbox-proof"], 71, "",
                                    (
                                        "sandbox-exec: sandbox_apply: "
                                        "Operation not permitted\n"
                                        if runner_index % 2 else ""
                                    ),
                                ),
                                subprocess.CompletedProcess(
                                    ["snapshot-write-proof"], 0,
                                    '{"chmod": 1, "open": 1, "site-open": 1, "site-residue": false}\n', "",
                                ),
                                reentrant_result,
                            ))
                            runner_ambient = {
                                **case_environment,
                                P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: (
                                    "1" if formal_runner else "hostile-hidden-marker"
                                ),
                                "PYTHONPATH": "/hostile/reentry-python",
                                "PYTHONHOME": "/hostile/reentry-home",
                                "LD_PRELOAD": "/hostile/reentry-loader",
                                "DYLD_INSERT_LIBRARIES": "/hostile/reentry-dyld",
                                "GIT_DIR": "/hostile/reentry-git",
                            }
                            with mock.patch.dict(
                                os.environ, runner_ambient, clear=True,
                            ), mock.patch.object(
                                module, "_extract_dependency_snapshot",
                                side_effect=AssertionError("FORBIDDEN REENTRY EXTRACT"),
                            ) as reentry_extract, mock.patch.object(
                                module, "_build_dependency_archive",
                                side_effect=AssertionError("FORBIDDEN REENTRY BUILD"),
                            ) as reentry_build, mock.patch.object(
                                module, "_run_capsule_sandbox",
                                side_effect=AssertionError("FORBIDDEN NESTED SANDBOX"),
                            ) as nested_sandbox, mock.patch.object(
                                module, "_run_bounded_process",
                                side_effect=lambda *args, **kwargs: next(bounded_results),
                            ) as reentry_bounded, mock.patch.object(
                                fcntl, "fcntl", side_effect=observed_reentry_fcntl,
                            ):
                                observed_reentrant = _python_run(
                                    ROOT, list(runner_arguments), timeout=91,
                                    dependency_archive=case_archive,
                                )
                            self.assertIs(reentrant_result, observed_reentrant)
                            reentry_extract.assert_not_called()
                            reentry_build.assert_not_called()
                            nested_sandbox.assert_not_called()
                            self.assertEqual(3, reentry_bounded.call_count)
                            nested_call, write_call, direct_call = reentry_bounded.call_args_list
                            self.assertEqual((
                                P_CAPSULE_SANDBOX_EXECUTABLE, "-p",
                                "(version 1)\n(allow default)\n", "/usr/bin/true",
                            ), tuple(nested_call.args[0]))
                            self.assertEqual((
                                str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                                reentry_write_probe, str(case_snapshot / "six.py"),
                                str(case_python_home.components[-1][0]),
                            ), tuple(write_call.args[0]))
                            self.assertEqual(91, nested_call.kwargs["timeout"])
                            self.assertEqual(91, write_call.kwargs["timeout"])
                            self.assertEqual((), tuple(nested_call.kwargs["pass_fds"]))
                            self.assertEqual((), tuple(write_call.kwargs["pass_fds"]))
                            self.assertEqual((
                                str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                                P_CAPSULE_BOOTSTRAP, str(case_snapshot), str(ROOT),
                                json.dumps(list(runner_arguments), separators=(",", ":")),
                            ), tuple(direct_call.args[0]))
                            self.assertEqual(
                                case_fds,
                                tuple(source for source, _duplicate in reentry_duplications),
                            )
                            duplicated_fds = tuple(
                                duplicate for _source, duplicate in reentry_duplications
                            )
                            self.assertEqual(len(duplicated_fds), len(set(duplicated_fds)))
                            self.assertEqual(
                                duplicated_fds,
                                tuple(direct_call.kwargs["pass_fds"]),
                            )
                            self.assertEqual(91, direct_call.kwargs["timeout"])
                            direct_environment = direct_call.kwargs["environment"]
                            self.assertEqual(
                                str(duplicated_fds[0]),
                                direct_environment[P_CAPSULE_FD_ENV],
                            )
                            self.assertEqual(
                                case_environment[P_CAPSULE_IDENTITY_ENV],
                                direct_environment[P_CAPSULE_IDENTITY_ENV],
                            )
                            self.assertEqual(
                                str(duplicated_fds[1]),
                                direct_environment[reentry_keys["snapshot_fd"]],
                            )
                            self.assertEqual(
                                ",".join(str(descriptor) for descriptor in duplicated_fds[2:]),
                                direct_environment[reentry_keys["python_home_fds"]],
                            )
                            for key in (
                                reentry_keys["marker"], reentry_keys["snapshot"],
                                reentry_keys["snapshot_identity"],
                                reentry_keys["python_home"],
                                reentry_keys["python_home_identity"],
                            ):
                                self.assertEqual(
                                    case_environment[key], direct_environment[key],
                                )
                            if formal_runner:
                                self.assertEqual(
                                    "1", direct_environment[
                                        P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV
                                    ],
                                )
                            else:
                                self.assertNotIn(
                                    P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                                    direct_environment,
                                )
                            self.assertTrue(all(
                                not key.startswith(("PYTHON", "LD_", "DYLD_", "GIT_"))
                                for key in direct_environment
                            ))
                            for duplicated_fd in duplicated_fds:
                                with self.assertRaises(OSError):
                                    os.fstat(duplicated_fd)
                            for original_fd in case_fds:
                                os.fstat(original_fd)
                            self.assertEqual(
                                case_snapshot_payload,
                                (case_snapshot / "six.py").read_bytes(),
                            )
                            verify_snapshot(case_snapshot)
                            verify_python_home(case_python_home)
                            verify_archive(case_archive)
                            if formal_runner:
                                assert_runner_runtime_unchanged()
                            else:
                                assert_synthetic_runtime_during_runner_scope()
                            self.assertEqual(
                                case_python_home_layout,
                                tuple(
                                    tuple(sorted(os.listdir(component[1])))
                                    for component in case_components
                                ),
                            )

                    active_harness_result = subprocess.CompletedProcess(
                        ["active-formal-harness"], 0, "hidden trusted\n", "",
                    )
                    active_harness_duplications = []
                    real_active_harness_fcntl = fcntl.fcntl
                    def observed_active_harness_fcntl(descriptor, operation, *values):
                        result = real_active_harness_fcntl(descriptor, operation, *values)
                        if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in active_fds:
                            active_harness_duplications.append((descriptor, result))
                        return result
                    with mock.patch.dict(
                        os.environ, {
                            **active_environment,
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "hostile-harness-marker",
                            "PYTHONPATH": "/hostile/harness",
                            "PYTHONHOME": "/hostile/reentry-home",
                            "LD_PRELOAD": "/hostile/reentry-loader",
                            "DYLD_INSERT_LIBRARIES": "/hostile/reentry-dyld",
                            "GIT_DIR": "/hostile/reentry-git",
                        }, clear=True,
                    ), mock.patch.object(
                        module, "_run_formal_harness_process",
                        return_value=active_harness_result,
                    ) as active_harness_process, mock.patch.object(
                        module, "_build_dependency_archive",
                        side_effect=AssertionError("active harness rebuilt archive"),
                    ) as active_harness_build, mock.patch.object(
                        module, "_extract_dependency_snapshot",
                        side_effect=AssertionError("active harness extracted snapshot"),
                    ) as active_harness_extract, mock.patch.object(
                        module, "_run_capsule_sandbox",
                        side_effect=AssertionError("active harness nested sandbox"),
                    ) as active_harness_sandbox, mock.patch.object(
                        fcntl, "fcntl", side_effect=observed_active_harness_fcntl,
                    ):
                        observed_active_harness = formal_harness(
                            ROOT, P_REENTRANT_FAST_TARGET_FQN, timeout=113,
                            dependency_archive=dependency_archive,
                            ambient={"PYTHONPATH": "/hostile/harness"},
                        )
                    self.assertIs(active_harness_result, observed_active_harness)
                    active_harness_build.assert_not_called()
                    active_harness_extract.assert_not_called()
                    active_harness_sandbox.assert_not_called()
                    active_harness_process.assert_called_once()
                    self.assertEqual(
                        active_fds,
                        tuple(source for source, _duplicate in active_harness_duplications),
                    )
                    active_harness_duplicates = tuple(
                        duplicate for _source, duplicate in active_harness_duplications
                    )
                    active_harness_command = tuple(
                        active_harness_process.call_args.args[0]
                    )
                    active_harness_kwargs = active_harness_process.call_args.kwargs
                    self.assertEqual((
                        str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                        P_FORMAL_HARNESS_BOOTSTRAP, str(ROOT.resolve()),
                        P_REENTRANT_FAST_TARGET_FQN,
                    ), active_harness_command)
                    self.assertEqual(
                        active_harness_duplicates,
                        tuple(active_harness_kwargs["pass_fds"]),
                    )
                    self.assertEqual(113, active_harness_kwargs["timeout"])
                    active_harness_environment = active_harness_kwargs["environment"]
                    self.assertEqual(
                        str(active_harness_duplicates[0]),
                        active_harness_environment[P_CAPSULE_FD_ENV],
                    )
                    self.assertEqual(
                        str(active_harness_duplicates[1]),
                        active_harness_environment[reentry_keys["snapshot_fd"]],
                    )
                    self.assertEqual(
                        ",".join(
                            str(descriptor) for descriptor in active_harness_duplicates[2:]
                        ),
                        active_harness_environment[reentry_keys["python_home_fds"]],
                    )
                    for key in (
                        P_CAPSULE_IDENTITY_ENV, reentry_keys["marker"],
                        reentry_keys["snapshot"], reentry_keys["snapshot_identity"],
                        reentry_keys["python_home"],
                        reentry_keys["python_home_identity"],
                    ):
                        self.assertEqual(
                            active_environment[key], active_harness_environment[key],
                        )
                    self.assertNotIn("PYTHONPATH", active_harness_environment)
                    for duplicate in active_harness_duplicates:
                        with self.assertRaises(OSError):
                            os.fstat(duplicate)
                    self.assertNotIn(
                        P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                        active_harness_environment,
                    )
                    for original_fd in active_fds:
                        os.fstat(original_fd)
                    verify_archive(dependency_archive)
                    verify_snapshot(active_snapshot)
                    verify_python_home(active_python_home)
                    assert_synthetic_runtime_during_runner_scope()

                    for hostile_harness_target in (
                        P_REENTRANT_OUTER_PROBE_FQN,
                        P_FAST_EXACT_COMMIT_FQN,
                        P_REENTRANT_FAST_TARGET_FQN + ".extra",
                    ):
                        with self.subTest(active_harness_target=hostile_harness_target), \
                                mock.patch.dict(
                                    os.environ, active_environment, clear=True,
                                ), mock.patch.object(
                                    module, "_run_formal_harness_process",
                                    side_effect=AssertionError("hostile harness target reached child"),
                                ) as hostile_harness_child, self.assertRaisesRegex(
                                    AssertionError, "harness|reentrant|target|authority",
                                ):
                            formal_harness(
                                ROOT, hostile_harness_target, timeout=113,
                                dependency_archive=dependency_archive,
                            )
                        hostile_harness_child.assert_not_called()

                    harness_dup_owned = []
                    harness_dup_calls = []
                    real_harness_failure_fcntl = fcntl.fcntl
                    def fail_active_harness_dup(descriptor, operation, *values):
                        if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in active_fds:
                            harness_dup_calls.append(descriptor)
                            if len(harness_dup_calls) == 3:
                                raise OSError(errno.EMFILE, "active harness dup failure")
                        result = real_harness_failure_fcntl(descriptor, operation, *values)
                        if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in active_fds:
                            harness_dup_owned.append(result)
                        return result
                    with mock.patch.dict(
                        os.environ, active_environment, clear=True,
                    ), mock.patch.object(
                        fcntl, "fcntl", side_effect=fail_active_harness_dup,
                    ), mock.patch.object(
                        module, "_run_formal_harness_process",
                        side_effect=AssertionError("failed harness dup reached child"),
                    ) as failed_harness_child, self.assertRaisesRegex(
                        AssertionError, "duplicate|descriptor|harness|authority",
                    ):
                        formal_harness(
                            ROOT, P_REENTRANT_FAST_TARGET_FQN, timeout=113,
                            dependency_archive=dependency_archive,
                        )
                    self.assertEqual(active_fds[:3], tuple(harness_dup_calls))
                    self.assertEqual(2, len(harness_dup_owned))
                    failed_harness_child.assert_not_called()
                    for owned_fd in harness_dup_owned:
                        with self.assertRaises(OSError):
                            os.fstat(owned_fd)
                    for original_fd in active_fds:
                        os.fstat(original_fd)

                    for harness_failure in (
                        KeyboardInterrupt("active harness interrupted"),
                        OSError(errno.EIO, "active harness process failed"),
                        subprocess.TimeoutExpired(["active-formal-harness"], 113),
                    ):
                        failed_harness_owned = []
                        real_failed_harness_fcntl = fcntl.fcntl
                        def observed_failed_harness_fcntl(descriptor, operation, *values):
                            result = real_failed_harness_fcntl(descriptor, operation, *values)
                            if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in active_fds:
                                failed_harness_owned.append(result)
                            return result
                        with self.subTest(active_harness_failure=type(harness_failure).__name__), \
                                mock.patch.dict(
                                    os.environ, active_environment, clear=True,
                                ), mock.patch.object(
                                    module, "_run_formal_harness_process",
                                    side_effect=harness_failure,
                                ) as failed_harness_process, mock.patch.object(
                                    fcntl, "fcntl", side_effect=observed_failed_harness_fcntl,
                                ):
                            try:
                                formal_harness(
                                    ROOT, P_REENTRANT_FAST_TARGET_FQN, timeout=113,
                                    dependency_archive=dependency_archive,
                                )
                            except BaseException as observed_failure:
                                self.assertIs(harness_failure, observed_failure)
                            else:
                                self.fail("active formal harness swallowed process failure")
                        failed_harness_process.assert_called_once()
                        self.assertEqual(len(active_fds), len(failed_harness_owned))
                        for owned_fd in failed_harness_owned:
                            with self.assertRaises(OSError):
                                os.fstat(owned_fd)
                        for original_fd in active_fds:
                            os.fstat(original_fd)
                        self.assertEqual(
                            active_snapshot_payload,
                            (active_snapshot / "six.py").read_bytes(),
                        )
                        self.assertEqual(
                            active_python_home_layout,
                            tuple(
                                tuple(sorted(os.listdir(component[1])))
                                for component in active_components
                            ),
                        )
                        verify_archive(dependency_archive)
                        verify_snapshot(active_snapshot)
                        verify_python_home(active_python_home)
                        assert_synthetic_runtime_during_runner_scope()

                    probe_failures = {
                        "nested-sandbox-not-71": (
                            subprocess.CompletedProcess([], 0, "", ""),
                        ),
                        "nested-sandbox-other-error": (
                            subprocess.CompletedProcess([], 72, "", ""),
                        ),
                        "nested-sandbox-signal": (
                            subprocess.CompletedProcess([], -9, "", ""),
                        ),
                        "nested-sandbox-71-with-stderr": (
                            subprocess.CompletedProcess([], 71, "", "unexpected nested stderr\n"),
                        ),
                        "nested-sandbox-71-with-stdout": (
                            subprocess.CompletedProcess([], 71, "unexpected nested stdout\n", ""),
                        ),
                        "kernel-write-probe-nonzero": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess([], 9, "", ""),
                        ),
                        "kernel-write-probe-signal": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess([], -9, "", ""),
                        ),
                        "kernel-write-probe-not-eperm": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 13, "open": 13, "site-open": 13, "site-residue": false}\n',
                                "",
                            ),
                        ),
                        "kernel-write-probe-bad-open": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 1, "open": 13, "site-open": 1, "site-residue": false}\n',
                                "",
                            ),
                        ),
                        "kernel-write-probe-bad-chmod": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 13, "open": 1, "site-open": 1, "site-residue": false}\n',
                                "",
                            ),
                        ),
                        "kernel-write-probe-bad-site-open": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 1, "open": 1, "site-open": 13, "site-residue": false}\n',
                                "",
                            ),
                        ),
                        "kernel-write-probe-residue": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 1, "open": 1, "site-open": 1, "site-residue": true}\n',
                                "",
                            ),
                        ),
                        "kernel-write-probe-missing-field": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 1, "open": 1, "site-open": 1}\n', "",
                            ),
                        ),
                        "kernel-write-probe-extra-field": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 1, "extra": 1, "open": 1, "site-open": 1, "site-residue": false}\n',
                                "",
                            ),
                        ),
                        "kernel-write-probe-malformed": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess([], 0, "not-json\n", ""),
                        ),
                        "kernel-write-probe-trailing": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 1, "open": 1, "site-open": 1, "site-residue": false}\ntrailing\n',
                                "",
                            ),
                        ),
                        "kernel-write-probe-stderr": (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 1, "open": 1, "site-open": 1, "site-residue": false}\n',
                                "unexpected kernel stderr\n",
                            ),
                        ),
                    }
                    for label, probe_results in probe_failures.items():
                        with self.subTest(reentry_kernel_proof=label):
                            results = iter(probe_results)
                            with mock.patch.dict(
                                os.environ, runner_formal_environment, clear=True,
                            ), mock.patch.object(
                                module, "_extract_dependency_snapshot",
                                side_effect=AssertionError("FORBIDDEN REENTRY EXTRACT"),
                            ), mock.patch.object(
                                module, "_run_capsule_sandbox",
                                side_effect=AssertionError("FORBIDDEN NESTED SANDBOX"),
                            ), mock.patch.object(
                                module, "_run_bounded_process",
                                side_effect=lambda *args, **kwargs: next(results),
                            ) as failed_probe, self.assertRaisesRegex(
                                AssertionError, "sandbox|kernel|write|reentrant|authority",
                            ):
                                _python_run(
                                    ROOT, list(allowed_reentrant_runners[0]),
                                    timeout=91, dependency_archive=runner_archive,
                                )
                            self.assertEqual(len(probe_results), failed_probe.call_count)

                    for failing_stage, injected_failure in enumerate((
                        KeyboardInterrupt("nested proof interrupted"),
                        OSError(errno.EIO, "kernel proof failed"),
                        subprocess.TimeoutExpired(["reentrant-direct"], 91),
                    )):
                        stage_prefix = (
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 1, "open": 1, "site-open": 1, "site-residue": false}\n',
                                "",
                            ),
                        )
                        stage_calls = []
                        stage_owned_fds = []
                        real_stage_fcntl = fcntl.fcntl
                        def observed_stage_fcntl(descriptor, operation, *values):
                            result = real_stage_fcntl(descriptor, operation, *values)
                            if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in active_fds:
                                stage_owned_fds.append(result)
                            return result
                        def fail_reentry_stage(*args, **kwargs):
                            index = len(stage_calls)
                            stage_calls.append((args, kwargs))
                            if index == failing_stage:
                                raise injected_failure
                            return stage_prefix[index]
                        with self.subTest(reentry_baseexception_stage=failing_stage), \
                                mock.patch.dict(
                                    os.environ, active_environment, clear=True,
                                ), mock.patch.object(
                                    module, "_extract_dependency_snapshot",
                                    side_effect=AssertionError("FORBIDDEN REENTRY EXTRACT"),
                                ), mock.patch.object(
                                    module, "_run_capsule_sandbox",
                                    side_effect=AssertionError("FORBIDDEN NESTED SANDBOX"),
                                ), mock.patch.object(
                                    module, "_run_bounded_process",
                                    side_effect=fail_reentry_stage,
                                ), mock.patch.object(
                                    fcntl, "fcntl", side_effect=observed_stage_fcntl,
                                ):
                            try:
                                _python_run(
                                    ROOT, list(P_REENTRANT_TEST_PROBE_ARGUMENTS),
                                    timeout=91, dependency_archive=dependency_archive,
                                )
                            except BaseException as observed_failure:
                                self.assertIs(injected_failure, observed_failure)
                            else:
                                self.fail("reentrant bounded-process failure was swallowed")
                        self.assertEqual(failing_stage + 1, len(stage_calls))
                        for _arguments, stage_kwargs in stage_calls:
                            self.assertNotIn(
                                P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                                stage_kwargs["environment"],
                            )
                        for owned_fd in stage_owned_fds:
                            with self.assertRaises(OSError):
                                os.fstat(owned_fd)
                        for original_fd in active_fds:
                            os.fstat(original_fd)
                        self.assertEqual(
                            active_snapshot_payload,
                            (active_snapshot / "six.py").read_bytes(),
                        )
                        self.assertEqual(
                            active_python_home_layout,
                            tuple(
                                tuple(sorted(os.listdir(component[1])))
                                for component in active_components
                            ),
                        )
                        verify_archive(dependency_archive)
                        verify_snapshot(active_snapshot)
                        verify_python_home(active_python_home)
                        assert_synthetic_runtime_during_runner_scope()

                    forged_probe_results = []
                    forged_probe_calls = []
                    forged_duplications = []
                    real_forged_fcntl = fcntl.fcntl
                    def observed_forged_fcntl(descriptor, operation, *values):
                        result = real_forged_fcntl(descriptor, operation, *values)
                        if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in active_fds:
                            forged_duplications.append((descriptor, result))
                        return result
                    def run_forged_kernel_proof(command, **kwargs):
                        forged_probe_calls.append((tuple(command), dict(kwargs)))
                        if len(forged_probe_calls) == 1:
                            return subprocess.CompletedProcess(list(command), 71, "", "")
                        result = run_bounded(command, **kwargs)
                        forged_probe_results.append(result)
                        return result
                    forged_six_mode = stat.S_IMODE((active_snapshot / "six.py").lstat().st_mode)
                    forged_site_residue = active_python_home.components[-1][0] / "hostile.pth"
                    try:
                        with self.subTest(reentry_kernel_proof="forged-marker-unsandboxed"), \
                                mock.patch.dict(
                                    os.environ, active_environment, clear=True,
                                ), mock.patch.object(
                                    module, "_extract_dependency_snapshot",
                                    side_effect=AssertionError("FORBIDDEN REENTRY EXTRACT"),
                                ), mock.patch.object(
                                    module, "_run_capsule_sandbox",
                                    side_effect=AssertionError("FORBIDDEN NESTED SANDBOX"),
                                ), mock.patch.object(
                                    module, "_run_bounded_process",
                                    side_effect=run_forged_kernel_proof,
                                ), mock.patch.object(
                                    fcntl, "fcntl", side_effect=observed_forged_fcntl,
                                ), self.assertRaisesRegex(
                                    AssertionError, "kernel|write|sandbox|reentrant|authority",
                                ):
                            _python_run(
                                ROOT, list(P_REENTRANT_TEST_PROBE_ARGUMENTS), timeout=91,
                                dependency_archive=dependency_archive,
                            )
                        self.assertEqual(2, len(forged_probe_calls))
                        self.assertEqual(1, len(forged_probe_results))
                        self.assertEqual(9, forged_probe_results[0].returncode)
                        forged_report = json.loads(forged_probe_results[0].stdout)
                        self.assertEqual(0, forged_report["open"])
                        self.assertEqual(0, forged_report["chmod"])
                        self.assertEqual(0, forged_report["site-open"])
                        self.assertTrue(forged_report["site-residue"])
                    finally:
                        os.chmod(active_snapshot / "six.py", forged_six_mode)
                        if os.path.lexists(forged_site_residue):
                            forged_site_residue.unlink()
                    self.assertEqual(
                        active_snapshot_payload, (active_snapshot / "six.py").read_bytes(),
                    )
                    self.assertEqual([], list(active_python_home.components[-1][0].iterdir()))
                    for _source, duplicate in forged_duplications:
                        with self.assertRaises(OSError):
                            os.fstat(duplicate)
                    for original_fd in active_fds:
                        os.fstat(original_fd)

                    ordinary_arguments = ("-B", "-c", "print('ordinary reentry')")
                    ordinary_result = subprocess.CompletedProcess(
                        ["reentrant-ordinary"], 0, "ordinary reentry\n", "",
                    )
                    ordinary_results = iter((
                        subprocess.CompletedProcess([], 71, "", ""),
                        subprocess.CompletedProcess(
                            [], 0,
                            '{"chmod": 1, "open": 1, "site-open": 1, "site-residue": false}\n',
                            "",
                        ),
                        ordinary_result,
                    ))
                    ordinary_duplications = []
                    real_ordinary_fcntl = fcntl.fcntl
                    def observed_ordinary_fcntl(descriptor, operation, *values):
                        result = real_ordinary_fcntl(descriptor, operation, *values)
                        if (
                            operation == fcntl.F_DUPFD_CLOEXEC
                            and descriptor in active_fds
                        ):
                            ordinary_duplications.append((descriptor, result))
                        return result
                    with mock.patch.dict(
                        os.environ, {
                            **active_environment,
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "hostile-ordinary-marker",
                            "PYTHONPATH": "/hostile/reentry-python",
                            "PYTHONHOME": "/hostile/reentry-home",
                            "LD_PRELOAD": "/hostile/reentry-loader",
                            "DYLD_INSERT_LIBRARIES": "/hostile/reentry-dyld",
                            "GIT_DIR": "/hostile/reentry-git",
                        }, clear=True,
                    ), mock.patch.object(
                        module, "_extract_dependency_snapshot",
                        side_effect=AssertionError("FORBIDDEN REENTRY EXTRACT"),
                    ), mock.patch.object(
                        module, "_run_capsule_sandbox",
                        side_effect=AssertionError("FORBIDDEN NESTED SANDBOX"),
                    ), mock.patch.object(
                        module, "_run_bounded_process",
                        side_effect=lambda *args, **kwargs: next(ordinary_results),
                    ) as ordinary_bounded, mock.patch.object(
                        fcntl, "fcntl", side_effect=observed_ordinary_fcntl,
                    ):
                        observed_ordinary = _python_run(
                            ROOT, list(ordinary_arguments), timeout=91,
                            dependency_archive=dependency_archive,
                        )
                    self.assertIs(ordinary_result, observed_ordinary)
                    self.assertEqual(3, ordinary_bounded.call_count)
                    ordinary_child = ordinary_bounded.call_args_list[-1]
                    self.assertEqual(
                        active_fds,
                        tuple(source for source, _duplicate in ordinary_duplications),
                    )
                    ordinary_duplicates = tuple(
                        duplicate for _source, duplicate in ordinary_duplications
                    )
                    self.assertEqual(len(ordinary_duplicates), len(set(ordinary_duplicates)))
                    self.assertEqual(
                        (ordinary_duplicates[0],),
                        tuple(ordinary_child.kwargs["pass_fds"]),
                    )
                    self.assertEqual(
                        str(ordinary_duplicates[0]),
                        ordinary_child.kwargs["environment"][P_CAPSULE_FD_ENV],
                    )
                    self.assertEqual(
                        set(),
                        set(reentry_keys.values()).intersection(
                            ordinary_child.kwargs["environment"],
                        ),
                    )
                    self.assertNotIn(
                        P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                        ordinary_child.kwargs["environment"],
                    )
                    self.assertEqual(
                        inherited_environment[P_CAPSULE_IDENTITY_ENV],
                        ordinary_child.kwargs["environment"][P_CAPSULE_IDENTITY_ENV],
                    )
                    self.assertTrue(all(
                        not key.startswith(("PYTHON", "LD_", "DYLD_", "GIT_"))
                        for key in ordinary_child.kwargs["environment"]
                    ))
                    for duplicate in ordinary_duplicates:
                        with self.assertRaises(OSError):
                            os.fstat(duplicate)
                    for original_fd in active_fds:
                        os.fstat(original_fd)

                    near_miss_runners = (
                        ("-B", "test_cases/run_related_tests.py", "--all", "-v", "--extra"),
                        ("-B", "test_cases/run_related_tests.py", "-v", "--all"),
                        ("-B", "test_cases/run_related_tests.py", "--watch", "-v"),
                        ("-B", "test_cases/run_related_tests.py", "--suite", "repository-governance-extra", "-v"),
                        ("-B", "test_cases/../test_cases/run_related_tests.py", "--all", "-v"),
                        (*P_REENTRANT_TEST_PROBE_ARGUMENTS, "extra"),
                        (
                            "-B", "-m", "unittest", P_REENTRANT_OUTER_PROBE_FQN,
                            "-v",
                        ),
                        (
                            "-B", "-m", "unittest", "-v",
                            P_REENTRANT_FAST_TARGET_FQN,
                        ),
                        (
                            "-B", "-m", "unittest", "-v",
                            "./" + P_REENTRANT_OUTER_PROBE_FQN,
                        ),
                        ("-B", "-m", "unittest", "--watch", P_REENTRANT_OUTER_PROBE_FQN),
                    )
                    for near_arguments in near_miss_runners:
                        near_result = subprocess.CompletedProcess(
                            ["ordinary-near-miss"], 0, "ordinary near miss\n", "",
                        )
                        near_results = iter((
                            subprocess.CompletedProcess([], 71, "", ""),
                            subprocess.CompletedProcess(
                                [], 0,
                                '{"chmod": 1, "open": 1, "site-open": 1, "site-residue": false}\n',
                                "",
                            ),
                            near_result,
                        ))
                        near_duplications = []
                        real_near_fcntl = fcntl.fcntl
                        def observed_near_fcntl(descriptor, operation, *values):
                            result = real_near_fcntl(descriptor, operation, *values)
                            if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in active_fds:
                                near_duplications.append((descriptor, result))
                            return result
                        with self.subTest(reentry_near_miss=near_arguments), mock.patch.dict(
                            os.environ, {
                                **active_environment,
                                P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV: "hostile-near-marker",
                                "PYTHONPATH": "/hostile/reentry-python",
                                "PYTHONHOME": "/hostile/reentry-home",
                                "LD_PRELOAD": "/hostile/reentry-loader",
                                "DYLD_INSERT_LIBRARIES": "/hostile/reentry-dyld",
                                "GIT_DIR": "/hostile/reentry-git",
                            }, clear=True,
                        ), mock.patch.object(
                            module, "_extract_dependency_snapshot",
                            side_effect=AssertionError("FORBIDDEN REENTRY EXTRACT"),
                        ), mock.patch.object(
                            module, "_run_capsule_sandbox",
                            side_effect=AssertionError("FORBIDDEN NESTED SANDBOX"),
                        ), mock.patch.object(
                            module, "_run_bounded_process",
                            side_effect=lambda *args, **kwargs: next(near_results),
                        ) as near_bounded, mock.patch.object(
                            fcntl, "fcntl", side_effect=observed_near_fcntl,
                        ):
                            observed_near = _python_run(
                                ROOT, list(near_arguments), timeout=91,
                                dependency_archive=dependency_archive,
                            )
                        self.assertIs(near_result, observed_near)
                        self.assertEqual(3, near_bounded.call_count)
                        self.assertEqual(
                            active_fds,
                            tuple(source for source, _duplicate in near_duplications),
                        )
                        near_duplicates = tuple(
                            duplicate for _source, duplicate in near_duplications
                        )
                        near_child = near_bounded.call_args_list[-1]
                        self.assertEqual(
                            (near_duplicates[0],), tuple(near_child.kwargs["pass_fds"]),
                        )
                        self.assertEqual(
                            json.dumps(list(near_arguments), separators=(",", ":")),
                            near_child.args[0][-1],
                        )
                        self.assertEqual(
                            set(),
                            set(reentry_keys.values()).intersection(
                                near_child.kwargs["environment"],
                            ),
                        )
                        self.assertNotIn(
                            P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                            near_child.kwargs["environment"],
                        )
                        for duplicate in near_duplicates:
                            with self.assertRaises(OSError):
                                os.fstat(duplicate)
                        for original_fd in active_fds:
                            os.fstat(original_fd)

                    hostile_protocols = {
                        "mixed-marker": {reentry_keys["marker"]: "0"},
                        "bad-snapshot-fd": {reentry_keys["snapshot_fd"]: "-1"},
                        "bad-snapshot-identity": {
                            reentry_keys["snapshot_identity"]: "0:0:" + P_CAPSULE_RECORDS_SHA256,
                        },
                        "bad-python-home-identity": {
                            reentry_keys["python_home_identity"]: "[]",
                        },
                        "bad-python-home-fds": {reentry_keys["python_home_fds"]: "-1"},
                        "mixed-snapshot-path": {
                            reentry_keys["snapshot"]: str(active_state),
                            reentry_keys["snapshot_identity"]: ":".join((
                                str(active_state.lstat().st_dev),
                                str(active_state.lstat().st_ino),
                                P_CAPSULE_RECORDS_SHA256,
                            )),
                        },
                        "mixed-python-home-path": {
                            reentry_keys["python_home"]: str(
                                active_python_home.components[-1][0]
                            ),
                        },
                        "snapshot-fd-is-state-fd": {
                            reentry_keys["snapshot_fd"]: str(active_python_home.state_fd),
                        },
                        "python-home-fds-cross-swapped": {
                            reentry_keys["python_home_fds"]: ",".join(
                                str(descriptor) for descriptor in reversed(
                                    [component[1] for component in active_components]
                                )
                            ),
                        },
                        "python-home-fds-alias": {
                            reentry_keys["python_home_fds"]: ",".join(
                                str(active_components[0][1]) for _component in active_components
                            ),
                        },
                        "snapshot-is-state": {
                            reentry_keys["snapshot"]: str(active_python_home.state_path),
                            reentry_keys["snapshot_fd"]: str(active_python_home.state_fd),
                            reentry_keys["snapshot_identity"]: ":".join((
                                str(active_python_home.state_identity[0]),
                                str(active_python_home.state_identity[1]),
                                P_CAPSULE_RECORDS_SHA256,
                            )),
                        },
                    }
                    for label, mutation in hostile_protocols.items():
                        hostile_environment = {**active_environment, **mutation}
                        hostile_owned_fds = []
                        real_hostile_fcntl = fcntl.fcntl
                        def observed_hostile_fcntl(descriptor, operation, *values):
                            result = real_hostile_fcntl(descriptor, operation, *values)
                            if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in active_fds:
                                hostile_owned_fds.append(result)
                            return result
                        with self.subTest(reentry_authority=label), mock.patch.dict(
                            os.environ, hostile_environment, clear=False,
                        ), mock.patch.object(
                            module, "_build_dependency_archive",
                            side_effect=AssertionError("FORBIDDEN REENTRY BUILD"),
                        ) as hostile_build, mock.patch.object(
                            module, "_run_bounded_process",
                            side_effect=AssertionError("runner reached with hostile reentry authority"),
                        ) as hostile_bounded, mock.patch.object(
                            fcntl, "fcntl", side_effect=observed_hostile_fcntl,
                        ), self.assertRaisesRegex(
                            AssertionError, "reentrant|inherited|snapshot|PYTHONHOME|authority",
                        ):
                            _python_run(
                                ROOT, list(P_REENTRANT_TEST_PROBE_ARGUMENTS), timeout=91,
                                dependency_archive=dependency_archive,
                            )
                        hostile_build.assert_not_called()
                        hostile_bounded.assert_not_called()
                        for owned_fd in hostile_owned_fds:
                            with self.assertRaises(OSError):
                                os.fstat(owned_fd)
                        for original_fd in active_fds:
                            os.fstat(original_fd)

                    complete_protocol_keys = (
                        P_CAPSULE_FD_ENV, P_CAPSULE_IDENTITY_ENV,
                        *reentry_keys.values(),
                    )
                    for missing_key in complete_protocol_keys:
                        missing_environment = {
                            key: value for key, value in active_environment.items()
                            if key != missing_key
                        }
                        missing_duplications = []
                        real_missing_fcntl = fcntl.fcntl
                        def observed_missing_fcntl(descriptor, operation, *values):
                            result = real_missing_fcntl(descriptor, operation, *values)
                            if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in active_fds:
                                missing_duplications.append(result)
                            return result
                        with self.subTest(reentry_missing=missing_key), mock.patch.dict(
                            os.environ, missing_environment, clear=True,
                        ), mock.patch.object(
                            module, "_build_dependency_archive",
                            side_effect=AssertionError("FORBIDDEN PARTIAL REENTRY BUILD"),
                        ) as missing_build, mock.patch.object(
                            module, "_run_bounded_process",
                            side_effect=AssertionError("partial reentry reached child"),
                        ) as missing_bounded, mock.patch.object(
                            fcntl, "fcntl", side_effect=observed_missing_fcntl,
                        ), self.assertRaisesRegex(
                            AssertionError, "reentrant|inherited|protocol|authority",
                        ):
                            _python_run(
                                ROOT, list(P_REENTRANT_TEST_PROBE_ARGUMENTS), timeout=91,
                                dependency_archive=dependency_archive,
                            )
                        missing_build.assert_not_called()
                        missing_bounded.assert_not_called()
                        self.assertEqual([], missing_duplications)

                    duplicate_failure_owned = []
                    duplicate_failure_calls = []
                    real_duplicate_failure_fcntl = fcntl.fcntl
                    def fail_during_reentry_duplication(descriptor, operation, *values):
                        if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in runner_fds:
                            duplicate_failure_calls.append(descriptor)
                            if len(duplicate_failure_calls) == 4:
                                raise OSError(errno.EMFILE, "injected reentry duplication failure")
                        result = real_duplicate_failure_fcntl(descriptor, operation, *values)
                        if operation == fcntl.F_DUPFD_CLOEXEC and descriptor in runner_fds:
                            duplicate_failure_owned.append(result)
                        return result
                    with self.subTest(reentry_authority="duplicate-mid-failure"), \
                            mock.patch.dict(
                                os.environ, runner_formal_environment, clear=True,
                            ), mock.patch.object(
                                fcntl, "fcntl", side_effect=fail_during_reentry_duplication,
                            ), mock.patch.object(
                                module, "_run_bounded_process",
                                side_effect=AssertionError("duplication failure reached child"),
                            ) as duplicate_failure_child, self.assertRaisesRegex(
                                AssertionError, "duplicate|descriptor|reentrant|authority",
                            ):
                        _python_run(
                            ROOT, list(allowed_reentrant_runners[0]), timeout=91,
                            dependency_archive=runner_archive,
                        )
                    self.assertEqual(runner_fds[:4], tuple(duplicate_failure_calls))
                    self.assertEqual(3, len(duplicate_failure_owned))
                    duplicate_failure_child.assert_not_called()
                    for owned_fd in duplicate_failure_owned:
                        with self.assertRaises(OSError):
                            os.fstat(owned_fd)
                    for original_fd in runner_fds:
                        os.fstat(original_fd)

                    cross_state = formal_root / "cross-authority-archive"
                    cross_state.mkdir(mode=0o700)
                    cross_archive = build(cross_state)
                    cross_archive_fd = cross_archive.fd
                    try:
                        self.assertNotEqual(
                            (dependency_archive.dev, dependency_archive.ino),
                            (cross_archive.dev, cross_archive.ino),
                        )
                        with self.subTest(reentry_authority="environment-A-argument-B"), \
                                mock.patch.dict(
                                    os.environ, active_environment, clear=True,
                                ), mock.patch.object(
                                    module, "_build_dependency_archive",
                                    side_effect=AssertionError("FORBIDDEN CROSS-AUTHORITY BUILD"),
                                ) as cross_build, mock.patch.object(
                                    module, "_run_bounded_process",
                                    side_effect=AssertionError("cross authority reached child"),
                                ) as cross_child, self.assertRaisesRegex(
                                    AssertionError, "archive|inherited|reentrant|authority",
                                ):
                            _python_run(
                                ROOT, list(P_REENTRANT_TEST_PROBE_ARGUMENTS), timeout=91,
                                dependency_archive=cross_archive,
                            )
                        cross_build.assert_not_called()
                        cross_child.assert_not_called()
                    finally:
                        cross_archive.close()
                        shutil.rmtree(cross_state)
                    with self.assertRaises(OSError):
                        os.fstat(cross_archive_fd)

                    six_path = active_snapshot / "six.py"
                    six_metadata = six_path.lstat()
                    six_hostile = bytes([active_snapshot_payload[0] ^ 1]) + active_snapshot_payload[1:]
                    six_writer = os.open(
                        six_path,
                        os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    )
                    try:
                        os.pwrite(six_writer, six_hostile, 0)
                        os.fsync(six_writer)
                    finally:
                        os.close(six_writer)
                    os.utime(
                        six_path,
                        ns=(six_metadata.st_atime_ns, six_metadata.st_mtime_ns),
                    )
                    try:
                        with self.subTest(reentry_authority="snapshot-content"), \
                                mock.patch.dict(
                                    os.environ, active_environment, clear=False,
                                ), mock.patch.object(
                                    module, "_run_bounded_process",
                                    side_effect=AssertionError("runner consumed hostile snapshot"),
                                ) as hostile_bounded, self.assertRaisesRegex(
                                    AssertionError, "snapshot|authority|record|digest",
                                ):
                            _python_run(
                                ROOT, list(P_REENTRANT_TEST_PROBE_ARGUMENTS), timeout=91,
                                dependency_archive=dependency_archive,
                            )
                        hostile_bounded.assert_not_called()
                    finally:
                        restore_writer = os.open(
                            six_path,
                            os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        )
                        try:
                            os.pwrite(restore_writer, active_snapshot_payload, 0)
                            os.fsync(restore_writer)
                        finally:
                            os.close(restore_writer)
                        os.utime(
                            six_path,
                            ns=(six_metadata.st_atime_ns, six_metadata.st_mtime_ns),
                        )
                    hostile_pth = active_python_home.components[-1][0] / "hostile.pth"
                    hostile_pth.write_bytes(b"import hostile_reentry\n")
                    try:
                        with self.subTest(reentry_authority="python-home-content"), \
                                mock.patch.dict(
                                    os.environ, active_environment, clear=False,
                                ), mock.patch.object(
                                    module, "_run_bounded_process",
                                    side_effect=AssertionError("runner consumed hostile PYTHONHOME"),
                                ) as hostile_bounded, self.assertRaisesRegex(
                                    AssertionError, "PYTHONHOME|layout|authority",
                                ):
                            _python_run(
                                ROOT, list(P_REENTRANT_TEST_PROBE_ARGUMENTS), timeout=91,
                                dependency_archive=dependency_archive,
                            )
                        hostile_bounded.assert_not_called()
                    finally:
                        hostile_pth.unlink()
                    verify_snapshot(active_snapshot)
                    verify_python_home(active_python_home)
                finally:
                    try:
                        try:
                            if runner_loopback_ready:
                                assert_runner_runtime_unchanged()
                            if runner_loopback_ready and not owned_runner_loopback:
                                with mock.patch.dict(
                                    os.environ, runner_formal_environment, clear=True,
                                ), mock.patch.object(
                                    module, "_active_dependency_authority",
                                    wraps=active_helper,
                                ) as final_runner_helper:
                                    final_runner_loopback = loopback_consumer()
                                final_runner_helper.assert_called_once()
                                self.assertEqual(
                                    runner_loopback_value,
                                    (
                                        final_runner_loopback.root,
                                        final_runner_loopback.port,
                                        final_runner_loopback.daemon_pid,
                                        dict(final_runner_loopback.public_keys),
                                        dict(final_runner_loopback.fingerprints),
                                    ),
                                )
                                self.assertEqual(
                                    runner_fds, final_runner_loopback.source_fds,
                                )
                        finally:
                            runner_loopback_stack.close()
                        if runner_loopback_ready and owned_runner_loopback:
                            self.assertFalse(os.path.lexists(runner_loopback_root))
                            for descriptor in runner_loopback_held_fds:
                                with self.assertRaises(OSError):
                                    os.fstat(descriptor)
                            with self.assertRaises(ProcessLookupError):
                                os.kill(runner_loopback_pid, 0)
                            with self.assertRaises(ProcessLookupError):
                                os.killpg(runner_loopback_pgid, 0)
                            assert_active_runtime_unchanged()
                        elif runner_loopback_ready:
                            self.assertEqual(
                                runner_loopback_identity,
                                (
                                    runner_loopback_root.lstat().st_dev,
                                    runner_loopback_root.lstat().st_ino,
                                ),
                            )
                            os.kill(runner_loopback_pid, 0)
                            os.killpg(runner_loopback_pgid, 0)
                            assert_runner_runtime_unchanged()
                        self.assertEqual(
                            runner_identities,
                            tuple(
                                (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                                for descriptor in runner_fds
                            ),
                        )
                        self.assertEqual(
                            runner_flags,
                            tuple(
                                (
                                    fcntl.fcntl(descriptor, fcntl.F_GETFL),
                                    fcntl.fcntl(descriptor, fcntl.F_GETFD),
                                )
                                for descriptor in runner_fds
                            ),
                        )
                        self.assertEqual(
                            runner_archive_offset,
                            os.lseek(runner_fds[0], 0, os.SEEK_CUR),
                        )
                    finally:
                        os.close(active_snapshot_fd)
                        close_python_home(active_python_home)
                        shutil.rmtree(active_state)
                self.assertFalse(os.path.lexists(active_state))
                for active_fd in active_fds[1:]:
                    with self.assertRaises(OSError):
                        os.fstat(active_fd)
                self.assertEqual(
                    archive_identity,
                    (os.fstat(archive_fd).st_dev, os.fstat(archive_fd).st_ino),
                )
                if active_fixture is not None:
                    self.assertEqual(
                        runner_identities,
                        tuple(
                            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                            for descriptor in runner_fds
                        ),
                    )

                def run_active_direct_child(
                    repository, arguments, *, timeout, ambient=None,
                    transform_final=None, final_started=None,
                    final_finished=None, final_failures=None,
                ):
                    self.assertIsNotNone(active_fixture)
                    active_direct_calls = []
                    active_direct_owned = []
                    duplicate_authority = getattr(
                        module, "_duplicate_reentrant_authority",
                    )
                    def observe_active_direct_duplicate(authority):
                        self.assertEqual(active_fixture_fds, authority.source_fds)
                        duplicated = duplicate_authority(authority)
                        self.assertEqual(7, len(duplicated))
                        self.assertEqual(7, len(set(duplicated)))
                        self.assertTrue(
                            set(duplicated).isdisjoint(active_fixture_fds)
                        )
                        for source, descriptor, identity, flags in zip(
                            active_fixture_fds, duplicated,
                            active_fixture_identities, active_fixture_flags,
                        ):
                            metadata = os.fstat(descriptor)
                            self.assertEqual(
                                identity, (metadata.st_dev, metadata.st_ino),
                            )
                            self.assertEqual(
                                flags[0], fcntl.fcntl(descriptor, fcntl.F_GETFL),
                            )
                            self.assertEqual(
                                flags[1], fcntl.fcntl(descriptor, fcntl.F_GETFD),
                            )
                            self.assertFalse(os.get_inheritable(descriptor))
                            self.assertTrue(
                                fcntl.fcntl(descriptor, fcntl.F_GETFD)
                                & fcntl.FD_CLOEXEC
                            )
                            os.fstat(source)
                        active_direct_owned.extend(duplicated)
                        return duplicated
                    def observe_active_direct_process(command, **kwargs):
                        active_direct_calls.append((tuple(command), dict(kwargs)))
                        call_index = len(active_direct_calls)
                        self.assertEqual(
                            {"cwd", "environment", "pass_fds", "timeout"},
                            set(kwargs),
                        )
                        self.assertEqual(
                            Path(repository).resolve(), Path(kwargs["cwd"]).resolve(),
                        )
                        self.assertEqual(timeout, kwargs["timeout"])
                        if call_index < 3:
                            self.assertEqual((), tuple(kwargs["pass_fds"]))
                        if call_index == 1:
                            self.assertEqual((
                                P_CAPSULE_SANDBOX_EXECUTABLE, "-p",
                                "(version 1)\n(allow default)\n",
                                "/usr/bin/true",
                            ), tuple(command))
                        elif call_index == 2:
                            self.assertEqual((
                                str(Path(sys.executable).resolve()),
                                "-I", "-S", "-B", "-c",
                                P_REENTRANT_WRITE_PROBE,
                                str(active_fixture.snapshot / "six.py"),
                                str(active_fixture.python_home.components[-1][0]),
                            ), tuple(command))
                            self.assertEqual(
                                active_direct_calls[0][1]["environment"],
                                kwargs["environment"],
                            )
                        elif call_index == 3:
                            if final_started is not None:
                                final_started.append(time.monotonic())
                            environment = kwargs["environment"]
                            passed = tuple(kwargs["pass_fds"])
                            retains = tuple(arguments) in P_REENTRANT_RUNNER_ARGUMENTS
                            self.assertEqual(
                                tuple(active_direct_owned if retains
                                      else active_direct_owned[:1]),
                                passed,
                            )
                            self.assertEqual(
                                str(active_direct_owned[0]),
                                environment[P_CAPSULE_FD_ENV],
                            )
                            self.assertEqual(
                                active_fixture_environment[P_CAPSULE_IDENTITY_ENV],
                                environment[P_CAPSULE_IDENTITY_ENV],
                            )
                            archive_metadata = os.fstat(active_direct_owned[0])
                            self.assertEqual(
                                (
                                    str(archive_metadata.st_dev),
                                    str(archive_metadata.st_ino),
                                    str(archive_metadata.st_size),
                                    P_CAPSULE_ARCHIVE_SHA256,
                                ),
                                tuple(environment[P_CAPSULE_IDENTITY_ENV].split(":")),
                            )
                            self.assertNotIn(
                                P_EXPECTED_FORMAL_LOOPBACK_SSHD_ENV,
                                environment,
                            )
                            if retains:
                                self.assertEqual(
                                    set(P_REENTRANT_ENV_KEYS.values()),
                                    set(P_REENTRANT_ENV_KEYS.values()).intersection(
                                        environment
                                    ),
                                )
                                self.assertEqual(
                                    str(active_direct_owned[1]),
                                    environment[P_REENTRANT_ENV_KEYS["snapshot_fd"]],
                                )
                                snapshot_metadata = os.fstat(
                                    active_direct_owned[1]
                                )
                                self.assertEqual(
                                    (
                                        str(snapshot_metadata.st_dev),
                                        str(snapshot_metadata.st_ino),
                                        P_CAPSULE_RECORDS_SHA256,
                                    ),
                                    tuple(environment[
                                        P_REENTRANT_ENV_KEYS["snapshot_identity"]
                                    ].split(":")),
                                )
                                self.assertEqual(
                                    ",".join(
                                        str(descriptor)
                                        for descriptor in active_direct_owned[2:]
                                    ),
                                    environment[
                                        P_REENTRANT_ENV_KEYS["python_home_fds"]
                                    ],
                                )
                                python_home_rows = json.loads(environment[
                                    P_REENTRANT_ENV_KEYS["python_home_identity"]
                                ])
                                self.assertEqual(5, len(python_home_rows))
                                for descriptor, row in zip(
                                    active_direct_owned[2:], python_home_rows,
                                ):
                                    metadata = os.fstat(descriptor)
                                    self.assertEqual(
                                        (metadata.st_dev, metadata.st_ino),
                                        (row["dev"], row["ino"]),
                                    )
                                for name in (
                                    "marker", "snapshot", "snapshot_identity",
                                    "python_home", "python_home_identity",
                                ):
                                    key = P_REENTRANT_ENV_KEYS[name]
                                    self.assertEqual(
                                        active_fixture_environment[key],
                                        environment[key],
                                    )
                            else:
                                self.assertEqual(
                                    set(),
                                    set(P_REENTRANT_ENV_KEYS.values()).intersection(
                                        environment
                                    ),
                                )
                            self.assertEqual((
                                str(Path(sys.executable).resolve()),
                                "-I", "-S", "-B", "-c", P_CAPSULE_BOOTSTRAP,
                                str(active_fixture.snapshot),
                                str(Path(repository).resolve()),
                                json.dumps(list(arguments), separators=(",", ":")),
                            ), tuple(command))
                            if transform_final is not None:
                                command = transform_final(
                                    tuple(command), passed, environment,
                                )
                        else:
                            self.fail("active direct child ran an extra process")
                        try:
                            return run_bounded(command, **kwargs)
                        except subprocess.TimeoutExpired as error:
                            if call_index == 3 and final_finished is not None:
                                final_finished.append(time.monotonic())
                            if call_index == 3 and final_failures is not None:
                                final_failures.append(error)
                            raise
                    try:
                        with mock.patch.dict(
                            os.environ, active_fixture_environment, clear=True,
                        ), mock.patch.object(
                            module, "_run_bounded_process",
                            side_effect=observe_active_direct_process,
                        ) as active_direct_bounded, mock.patch.object(
                            module, "_duplicate_reentrant_authority",
                            side_effect=observe_active_direct_duplicate,
                        ) as active_direct_duplicate, mock.patch.object(
                            module, "_run_capsule_sandbox",
                        ) as active_direct_sandbox, mock.patch.object(
                            module, "_formal_loopback_sshd_scope",
                        ) as active_direct_scope, mock.patch.object(
                            module,
                            "_formal_loopback_sshd_authority_from_environment",
                            wraps=loopback_consumer,
                        ) as active_direct_consumer:
                            return _python_run(
                                repository, list(arguments), timeout=timeout,
                                dependency_archive=borrowed_archive,
                                ambient=ambient,
                            )
                    finally:
                        self.assertEqual(3, len(active_direct_calls))
                        active_direct_bounded.assert_called()
                        active_direct_duplicate.assert_called_once()
                        active_direct_sandbox.assert_not_called()
                        active_direct_scope.assert_not_called()
                        active_direct_consumer.assert_not_called()
                        self.assertEqual(7, len(active_direct_owned))
                        for descriptor in active_direct_owned:
                            with self.assertRaises(OSError):
                                os.fstat(descriptor)
                        verify_archive(borrowed_archive)
                        verify_snapshot(active_fixture.snapshot)
                        verify_python_home(active_fixture.python_home)
                        assert_reused_active_loopback(loopback_consumer())
                        self.assertEqual(
                            active_fixture_identities,
                            tuple(
                                (os.fstat(descriptor).st_dev,
                                 os.fstat(descriptor).st_ino)
                                for descriptor in active_fixture_fds
                            ),
                        )
                        self.assertEqual(
                            active_fixture_flags,
                            tuple(
                                (
                                    fcntl.fcntl(descriptor, fcntl.F_GETFL),
                                    fcntl.fcntl(descriptor, fcntl.F_GETFD),
                                )
                                for descriptor in active_fixture_fds
                            ),
                        )
                        self.assertEqual(
                            active_fixture_offset,
                            os.lseek(active_fixture.archive_fd, 0, os.SEEK_CUR),
                        )

                attack_program = textwrap.dedent("""
                    import errno, hashlib, json, mmap, os, pathlib, subprocess, sys
                    root = pathlib.Path(sys.path[0]); target = root/'six.py'
                    outside = pathlib.Path(os.environ['CAPSULE_ATTACK_OUTSIDE'])
                    native = next(root.rglob('*.so'))
                    safe_prefix = root.parent/'python-home'
                    safe_site = safe_prefix/'lib/python3.9/site-packages'
                    probes = {}
                    reviewed_six = '53867fcafe77e16e423728d8f62f15d4e5d8d928c09f2f32d8be6f0cb8614e13'
                    def sandbox_denied(name, fn):
                        try: fn(); probes[name] = False
                        except OSError as error: probes[name] = error.errno in (errno.EPERM, errno.EACCES)
                    def readonly_denied(name, fn, allowed):
                        try: fn(); probes[name] = False
                        except OSError as error: probes[name] = error.errno in allowed
                    sandbox_denied('direct', lambda: target.write_bytes(b'hostile'))
                    fd = os.open(root, os.O_RDONLY); sandbox_denied('dirfd', lambda: os.open('six.py', os.O_WRONLY, dir_fd=fd)); os.close(fd)
                    alias = outside/'alias'; alias.symlink_to(target); sandbox_denied('symlink', lambda: alias.write_bytes(b'hostile'))
                    def hardlink_alias():
                        os.link(target, outside/'hard')
                    sandbox_denied('hardlink', hardlink_alias)
                    sandbox_denied('chmod', lambda: target.chmod(0o600)); sandbox_denied('unlink', target.unlink)
                    sandbox_denied('rename', lambda: target.rename(outside/'moved'))
                    sandbox_denied('pwrite', lambda: os.pwrite(os.open(target, os.O_WRONLY), b'X', 0))
                    sandbox_denied('mmap', lambda: mmap.mmap(os.open(native, os.O_RDWR), 1, access=mmap.ACCESS_WRITE))
                    sandbox_denied('rename-root', lambda: root.rename(outside/'snapshot'))
                    sandbox_denied('rename-parent', lambda: root.parent.rename(outside/'parent'))
                    sandbox_denied('python-home-mkdir', lambda: (safe_prefix/'hostile').mkdir())
                    safe_site_fd = os.open(safe_site, os.O_RDONLY)
                    try:
                        sandbox_denied('python-home-openat', lambda: os.open('sitecustomize.py', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600, dir_fd=safe_site_fd))
                    finally:
                        os.close(safe_site_fd)
                    sandbox_denied('python-home-symlink', lambda: os.symlink(target, safe_site/'sitecustomize.py'))
                    sandbox_denied('python-home-chmod', lambda: safe_prefix.chmod(0o755))
                    sandbox_denied('python-home-rename', lambda: safe_prefix.rename(outside/'python-home'))
                    grandchild_code = "import errno,hashlib,json,os,pathlib,sys; p=pathlib.Path(sys.argv[1]); ok=False; err=None; fd_closed=False;\\ntry: p.write_bytes(b'hostile')\\nexcept OSError as e: err=e.errno; ok=e.errno in (errno.EPERM,errno.EACCES)\\ntry: os.fstat(int(sys.argv[3]))\\nexcept OSError as e: fd_closed=e.errno==errno.EBADF\\nprint(json.dumps({'denied':ok,'errno':err,'trusted':hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[2],'archive_closed':fd_closed})); raise SystemExit(0 if ok and fd_closed else 9)"
                    child = subprocess.run([sys.executable, '-I', '-S', '-c', grandchild_code, str(target), reviewed_six, '__ARCHIVE_FD__'], capture_output=True, text=True)
                    child_report = json.loads(child.stdout)
                    probes['grandchild'] = child.returncode == 0 and child_report == {'denied': True, 'errno': child_report['errno'], 'trusted': True, 'archive_closed': True} and child_report['errno'] in (errno.EPERM, errno.EACCES)
                    relaxed = subprocess.run(['/usr/bin/sandbox-exec', '-p', '(version 1)(allow default)', '/usr/bin/true'], capture_output=True)
                    probes['nested-sandbox'] = relaxed.returncode == 71
                    inherited = __ARCHIVE_FD__
                    readonly_denied('archive-write', lambda: os.write(inherited,b'X'), (errno.EBADF,))
                    readonly_denied('archive-truncate', lambda: os.ftruncate(inherited,0), (errno.EINVAL, errno.EBADF))
                    readonly_denied('archive-seek', lambda: os.lseek(inherited,0,os.SEEK_SET), (errno.EBADF,))
                    readonly_denied('archive-reopen', lambda: open('/dev/fd/%d'%inherited,'wb'), (errno.EBADF, errno.EACCES, errno.EPERM))
                    probes['trusted-payload'] = hashlib.sha256(target.read_bytes()).hexdigest() == reviewed_six
                    probes['python-home-empty'] = not any(safe_site.iterdir())
                    print(json.dumps(probes, sort_keys=True)); raise SystemExit(0 if all(probes.values()) else 9)
                """)
                if active_fixture is None:
                    attack_program = attack_program.replace(
                        "__ARCHIVE_FD__", str(archive_fd),
                    )
                    attacked = _python_run(
                        ROOT, ["-B", "-c", attack_program], timeout=60,
                        dependency_archive=dependency_archive,
                        ambient={"CAPSULE_ATTACK_OUTSIDE": str(outside)},
                    )
                else:
                    def bind_active_attack_archive(
                        command, passed, environment,
                    ):
                        child_arguments = json.loads(command[-1])
                        self.assertEqual(["-B", "-c", attack_program], child_arguments)
                        child_arguments[2] = child_arguments[2].replace(
                            "__ARCHIVE_FD__", str(passed[0]),
                        )
                        return (
                            *command[:-1],
                            json.dumps(child_arguments, separators=(",", ":")),
                        )
                    attacked = run_active_direct_child(
                        ROOT, ("-B", "-c", attack_program), timeout=60,
                        ambient={"CAPSULE_ATTACK_OUTSIDE": str(outside)},
                        transform_final=bind_active_attack_archive,
                    )
                self.assertEqual(0, attacked.returncode, attacked.stdout + attacked.stderr)
                self.assertTrue(all(json.loads(attacked.stdout.splitlines()[-1]).values()))
                self.assertTrue((outside / "alias").is_symlink())
                (outside / "alias").unlink()
                self.assertFalse(os.path.lexists(outside / "hard"))
                self.assertEqual([], list(outside.iterdir()))
                verify_archive(dependency_archive)
                self.assertEqual(archive_identity, (dependency_archive.dev, dependency_archive.ino))
                preserved_archive_offset = os.lseek(
                    archive_fd, 4096, os.SEEK_SET,
                )
                self.assertEqual(4096, preserved_archive_offset)
                verify_archive(dependency_archive)
                self.assertEqual(
                    preserved_archive_offset,
                    os.lseek(archive_fd, 0, os.SEEK_CUR),
                )

                historical_arguments = ("-B", "-m", "unittest", "-v", (
                    "test_cases.test_public_s_phase_contract.PublicSPhaseDirectTests."
                    "test_s_manifest_has_exact_forward_and_reverse_closure"
                ))
                historical = (
                    _python_run(
                        ROOT, list(historical_arguments), timeout=240,
                        dependency_archive=dependency_archive,
                    )
                    if active_fixture is None else run_active_direct_child(
                        ROOT, historical_arguments, timeout=240,
                    )
                )
                self.assertEqual(0, historical.returncode, historical.stdout + historical.stderr)
                self.assertEqual(1, historical.stderr.count("Ran 1 test in"))

                harness_sentinel = subprocess.CompletedProcess(
                    ["bounded-harness-sentinel"], 0, "trusted stdout", "",
                )
                harness_semantic_command = (
                    str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                    P_FORMAL_HARNESS_BOOTSTRAP, str(ROOT),
                    "test_cases.test_public_publication_workflow."
                    "PublicPublicationWorkflowTests."
                    "test_p_phase_exact_commit_runs_catalog_in_private_free_clone",
                )
                harness_semantic_environment = {
                    "PATH": SYSTEM_EXECUTABLE_PATH,
                    P_CAPSULE_FD_ENV: str(archive_fd),
                    P_CAPSULE_IDENTITY_ENV: inherited_environment[P_CAPSULE_IDENTITY_ENV],
                }
                with mock.patch.object(
                    module, "_run_bounded_process", return_value=harness_sentinel,
                ) as semantic_bounded, mock.patch.object(
                    subprocess, "run", side_effect=AssertionError("secondary subprocess.run")
                ), mock.patch.object(
                    subprocess, "Popen", side_effect=AssertionError("secondary subprocess.Popen")
                ):
                    harness_forwarded = run_harness_process(
                        harness_semantic_command, cwd=ROOT,
                        environment=harness_semantic_environment,
                        pass_fds=(archive_fd,), timeout=37,
                    )
                self.assertIs(harness_sentinel, harness_forwarded)
                semantic_bounded.assert_called_once_with(
                    harness_semantic_command, cwd=ROOT,
                    environment=harness_semantic_environment,
                    pass_fds=(archive_fd,), timeout=37,
                )

                with tempfile.TemporaryDirectory(
                    prefix="http-p-capsule-harness-digest-",
                ) as harness_probe_dir:
                    harness_probe_root = Path(harness_probe_dir).resolve()
                    harness_probe_marker = harness_probe_root / "imported.marker"
                    (harness_probe_root / "harness_probe.py").write_text(
                        "import pathlib, unittest\n"
                        f"pathlib.Path({str(harness_probe_marker)!r}).write_text('imported')\n"
                        "def _adopt_dependency_archive_from_environment():\n"
                        "    return object()\n"
                        "def _build_dependency_archive(*args, **kwargs):\n"
                        "    raise AssertionError('unexpected rebuild')\n"
                        "class Probe(unittest.TestCase):\n"
                        "    def test_ok(self):\n"
                        "        self.assertTrue(True)\n",
                        encoding="utf-8",
                    )
                    wrong_digest_identity = ":".join((
                        str(dependency_archive.dev), str(dependency_archive.ino),
                        str(P_CAPSULE_ARCHIVE_SIZE), "00" * 32,
                    ))
                    wrong_digest_environment = {
                        "PATH": SYSTEM_EXECUTABLE_PATH,
                        P_CAPSULE_FD_ENV: str(archive_fd),
                        P_CAPSULE_IDENTITY_ENV: wrong_digest_identity,
                    }
                    wrong_digest_command = (
                        str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                        P_FORMAL_HARNESS_BOOTSTRAP, str(harness_probe_root),
                        "harness_probe.Probe.test_ok",
                    )
                    wrong_digest_result = run_harness_process(
                        wrong_digest_command, cwd=harness_probe_root,
                        environment=wrong_digest_environment,
                        pass_fds=(archive_fd,), timeout=30,
                    )
                    self.assertNotEqual(0, wrong_digest_result.returncode)
                    self.assertFalse(harness_probe_marker.exists())
                    self.assertEqual(
                        archive_identity,
                        (os.fstat(archive_fd).st_dev, os.fstat(archive_fd).st_ino),
                    )
                    self.assertEqual(
                        preserved_archive_offset,
                        os.lseek(archive_fd, 0, os.SEEK_CUR),
                    )

                    harness_hostile_path = harness_probe_root / "hostile.archive"
                    harness_hostile_writer = os.open(
                        harness_hostile_path,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                    )
                    try:
                        os.ftruncate(harness_hostile_writer, P_CAPSULE_ARCHIVE_SIZE)
                        os.fchmod(harness_hostile_writer, 0o400)
                        os.fsync(harness_hostile_writer)
                    finally:
                        os.close(harness_hostile_writer)
                    harness_hostile_fd = os.open(
                        harness_hostile_path,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    )
                    harness_hostile_metadata = os.fstat(harness_hostile_fd)
                    harness_hostile_path.unlink()
                    harness_hostile_hasher = hashlib.sha256()
                    harness_hostile_offset = 0
                    while harness_hostile_offset < harness_hostile_metadata.st_size:
                        harness_hostile_chunk = os.pread(
                            harness_hostile_fd,
                            min(1024 * 1024, harness_hostile_metadata.st_size - harness_hostile_offset),
                            harness_hostile_offset,
                        )
                        self.assertTrue(harness_hostile_chunk)
                        harness_hostile_hasher.update(harness_hostile_chunk)
                        harness_hostile_offset += len(harness_hostile_chunk)
                    harness_hostile_sha256 = harness_hostile_hasher.hexdigest()
                    self.assertNotEqual(P_CAPSULE_ARCHIVE_SHA256, harness_hostile_sha256)
                    harness_hostile_identity = ":".join((
                        str(harness_hostile_metadata.st_dev),
                        str(harness_hostile_metadata.st_ino),
                        str(harness_hostile_metadata.st_size),
                        harness_hostile_sha256,
                    ))
                    harness_hostile_environment = {
                        "PATH": SYSTEM_EXECUTABLE_PATH,
                        P_CAPSULE_FD_ENV: str(harness_hostile_fd),
                        P_CAPSULE_IDENTITY_ENV: harness_hostile_identity,
                    }
                    try:
                        harness_hostile_result = run_harness_process(
                            wrong_digest_command, cwd=harness_probe_root,
                            environment=harness_hostile_environment,
                            pass_fds=(harness_hostile_fd,), timeout=30,
                        )
                        self.assertNotEqual(0, harness_hostile_result.returncode)
                        self.assertFalse(harness_probe_marker.exists())
                        self.assertEqual(
                            0, os.lseek(harness_hostile_fd, 0, os.SEEK_CUR),
                        )
                    finally:
                        os.close(harness_hostile_fd)

                current_head = _head(ROOT)
                self.assertNotEqual(
                    S_COMMIT, current_head,
                    "capsule formal-state oracle must run in the P candidate/final checkout",
                )
                current_distance = _raw_p_lineage_distance(ROOT, current_head)
                self.assertIn(current_distance, {1, 2})
                phase_commit = current_head
                if current_distance == 2:
                    current_parents = _raw_commit_parents(ROOT, current_head)
                    self.assertEqual(1, len(current_parents))
                    phase_commit = current_parents[0]
                    self.assertEqual(1, _raw_p_lineage_distance(ROOT, phase_commit))
                    ledger_only = _git_run(
                        ROOT,
                        ["diff-tree", "--no-commit-id", "--name-only", "-r",
                         phase_commit, current_head],
                        text=True, check=True,
                    ).stdout
                    self.assertEqual(P_LEDGER_PATH + "\n", ledger_only)
                with tempfile.TemporaryDirectory(prefix="http-p-capsule-formal-state-") as clone_dir:
                    formal_clone = (Path(clone_dir) / "repository").resolve()
                    _git_run(
                        ROOT, ["clone", "--quiet", "--no-local", ROOT, formal_clone],
                        check=True,
                    )
                    _git_run(
                        formal_clone, ["checkout", "--quiet", "--detach", phase_commit],
                        check=True,
                    )
                    _git_run(formal_clone, ["reset", "--soft", S_COMMIT], check=True)
                    self.assertEqual(S_COMMIT, _head(formal_clone))
                    staged_source_paths = _git_run(
                        formal_clone, ["diff", "--cached", "--name-only"],
                        text=True, check=True,
                    ).stdout.splitlines()
                    self.assertEqual(set(P_PHASE_PRELEDGER_PATHS), set(staged_source_paths))
                    self.assertEqual(P_PRELEDGER_PATH_DIGEST, _path_digest(staged_source_paths))
                    self.assertEqual("", _git_run(
                        formal_clone, ["diff", "--name-only"], text=True, check=True,
                    ).stdout)
                    harness_hostile = {
                        "PATH": "/hostile/bin", "PYTHONPATH": "/hostile/python",
                        "PYTHONHOME": "/hostile/home", "LD_PRELOAD": "/hostile/preload",
                        "DYLD_INSERT_LIBRARIES": "/hostile/dyld", "GIT_DIR": "/hostile/git",
                    }
                    harness_hostile.update({
                        P_CAPSULE_FD_ENV: "1",
                        P_CAPSULE_IDENTITY_ENV: "hostile-archive-identity",
                        **{
                            key: f"hostile-{name}"
                            for name, key in P_REENTRANT_ENV_KEYS.items()
                        },
                    })
                    e2e_snapshots = []
                    e2e_fds = []
                    e2e_sandbox_calls = []
                    def observe_e2e(event, **authority):
                        if event == "snapshot-ready":
                            e2e_snapshots.append(Path(authority["snapshot"]))
                    def capture_e2e_fd(path, flags, *args, **kwargs):
                        descriptor = real_open(path, flags, *args, **kwargs)
                        e2e_fds.append(descriptor)
                        return descriptor
                    def observe_e2e_sandbox(command, **kwargs):
                        environment = kwargs["environment"]
                        passed = tuple(kwargs["pass_fds"])
                        self.assertEqual(7, len(passed))
                        self.assertEqual(7, len(set(passed)))
                        self.assertEqual(str(passed[0]), environment[P_CAPSULE_FD_ENV])
                        self.assertEqual(str(passed[1]), environment[P_REENTRANT_ENV_KEYS["snapshot_fd"]])
                        self.assertEqual(
                            ",".join(str(descriptor) for descriptor in passed[2:]),
                            environment[P_REENTRANT_ENV_KEYS["python_home_fds"]],
                        )
                        self.assertEqual("1", environment[P_REENTRANT_ENV_KEYS["marker"]])
                        self.assertEqual(
                            set(P_REENTRANT_ENV_KEYS.values()),
                            set(P_REENTRANT_ENV_KEYS.values()) & set(environment),
                        )
                        for descriptor in passed:
                            os.fstat(descriptor)
                            self.assertFalse(os.get_inheritable(descriptor))
                        e2e_sandbox_calls.append((tuple(command), passed))
                        return run_sandbox(command, **kwargs)
                    formal_index = (formal_clone / ".git/index").read_bytes()
                    formal_ledger = (formal_clone / P_LEDGER_PATH).read_bytes()
                    if active_fixture is None:
                        with mock.patch.object(
                            module, "_dependency_archive_observer",
                            side_effect=observe_e2e,
                        ), mock.patch.object(
                            module, "_run_capsule_sandbox",
                            side_effect=observe_e2e_sandbox,
                        ), mock.patch.object(
                            os, "open", side_effect=capture_e2e_fd,
                        ):
                            nested = _python_run(
                                formal_clone,
                                list(P_REENTRANT_TEST_PROBE_ARGUMENTS),
                                timeout=600,
                                dependency_archive=dependency_archive,
                                ambient=harness_hostile,
                            )
                    else:
                        nested = run_active_direct_child(
                            formal_clone, P_REENTRANT_TEST_PROBE_ARGUMENTS,
                            timeout=600, ambient=harness_hostile,
                        )
                    self.assertEqual(0, nested.returncode, nested.stdout + nested.stderr)
                    self.assertEqual(
                        1 if active_fixture is None else 0,
                        len(e2e_sandbox_calls),
                    )
                    self.assertEqual(1, nested.stderr.count("Ran 1 test in"), nested.stderr)
                    self.assertIn("OK", nested.stderr)
                    self.assertEqual(
                        1 if active_fixture is None else 0,
                        len(e2e_snapshots),
                    )
                    if e2e_snapshots:
                        self.assertFalse(os.path.lexists(e2e_snapshots[0]))
                    for descriptor in e2e_fds:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                    self.assertEqual(S_COMMIT, _head(formal_clone))
                    self.assertEqual(formal_index, (formal_clone / ".git/index").read_bytes())
                    self.assertEqual(formal_ledger, (formal_clone / P_LEDGER_PATH).read_bytes())
                    self.assertEqual(
                        set(P_PHASE_PRELEDGER_PATHS),
                        set(_git_run(
                            formal_clone, ["diff", "--cached", "--name-only"],
                            text=True, check=True,
                        ).stdout.splitlines()),
                    )
                    self.assertEqual("", _git_run(
                        formal_clone, ["diff", "--name-only"], text=True, check=True,
                    ).stdout)
                    verify_archive(dependency_archive)
                    self.assertEqual(
                        preserved_archive_offset,
                        os.lseek(archive_fd, 0, os.SEEK_CUR),
                    )

                for returncode in (-9, 1, 4):
                    before = verify_archive(dependency_archive)
                    completed = subprocess.CompletedProcess([], returncode, "", "child failed")
                    outcome_snapshots = []
                    outcome_fds = []
                    def observe_outcome(event, **authority):
                        if event == "snapshot-ready":
                            outcome_snapshots.append(Path(authority["snapshot"]))
                    def capture_outcome_fd(path, flags, *args, **kwargs):
                        descriptor = real_open(path, flags, *args, **kwargs)
                        outcome_fds.append(descriptor)
                        return descriptor
                    with self.subTest(child_returncode=returncode), mock.patch.object(
                        module, "_run_capsule_sandbox", return_value=completed,
                    ) as ordinary_run, mock.patch.object(
                        module, "_dependency_archive_observer", side_effect=observe_outcome,
                    ), mock.patch.object(
                        os, "open", side_effect=capture_outcome_fd,
                    ), mock.patch.dict(os.environ, {}, clear=True):
                        returned = _python_run(
                            ROOT, ["-B", "-c", "print('unreachable')"], timeout=1,
                            dependency_archive=dependency_archive,
                        )
                    ordinary_run.assert_called_once()
                    self.assertIs(completed, returned)
                    self.assertEqual(before, verify_archive(dependency_archive))
                    self.assertTrue(outcome_snapshots)
                    self.assertTrue(all(not os.path.lexists(path) for path in outcome_snapshots))
                    for opened_fd in outcome_fds:
                        with self.assertRaises(OSError):
                            os.fstat(opened_fd)
                sandbox_failed = subprocess.CompletedProcess(
                    [], 71, "", "sandbox initialization failed",
                )
                sandbox_snapshots = []
                sandbox_fds = []
                def observe_sandbox_failure(event, **authority):
                    if event == "snapshot-ready":
                        sandbox_snapshots.append(Path(authority["snapshot"]))
                def capture_sandbox_fd(path, flags, *args, **kwargs):
                    descriptor = real_open(path, flags, *args, **kwargs)
                    sandbox_fds.append(descriptor)
                    return descriptor
                with mock.patch.object(module, "_run_capsule_sandbox", return_value=sandbox_failed) as sandbox_run, \
                        mock.patch.object(
                            module, "_dependency_archive_observer", side_effect=observe_sandbox_failure,
                        ), mock.patch.object(os, "open", side_effect=capture_sandbox_fd), \
                        mock.patch.dict(os.environ, {}, clear=True), \
                        self.assertRaises(AssertionError):
                    _python_run(
                        ROOT, ["-B", "-c", "print('unreachable')"], timeout=1,
                        dependency_archive=dependency_archive,
                    )
                sandbox_run.assert_called_once()
                self.assertTrue(sandbox_snapshots)
                self.assertTrue(all(not os.path.lexists(path) for path in sandbox_snapshots))
                for opened_fd in sandbox_fds:
                    with self.assertRaises(OSError):
                        os.fstat(opened_fd)
                for outcome in (
                    subprocess.TimeoutExpired([], 1), OSError("sandbox unavailable"),
                    KeyboardInterrupt("formal interrupted"),
                ):
                    before = verify_archive(dependency_archive)
                    exception_snapshots = []
                    exception_fds = []
                    def observe_exception(event, **authority):
                        if event == "snapshot-ready":
                            exception_snapshots.append(Path(authority["snapshot"]))
                    def capture_exception_fd(path, flags, *args, **kwargs):
                        descriptor = real_open(path, flags, *args, **kwargs)
                        exception_fds.append(descriptor)
                        return descriptor
                    exception_started = []
                    def fail_at_sandbox_boundary(*args, **kwargs):
                        exception_started.append(time.monotonic())
                        raise outcome
                    with self.subTest(child_exception=type(outcome).__name__), mock.patch.object(
                        module, "_run_capsule_sandbox", side_effect=fail_at_sandbox_boundary,
                    ) as failed_run, mock.patch.object(
                        module, "_dependency_archive_observer", side_effect=observe_exception,
                    ), mock.patch.object(
                        os, "open", side_effect=capture_exception_fd,
                    ), mock.patch.dict(
                        os.environ, {}, clear=True,
                    ), self.assertRaises(type(outcome)):
                        _python_run(
                            ROOT, ["-B", "-c", "print('unreachable')"], timeout=1,
                            dependency_archive=dependency_archive,
                        )
                    failed_run.assert_called_once()
                    self.assertEqual(1, len(exception_started))
                    self.assertLess(time.monotonic() - exception_started[0], 3)
                    self.assertEqual(before, verify_archive(dependency_archive))
                    self.assertTrue(exception_snapshots)
                    self.assertTrue(all(not os.path.lexists(path) for path in exception_snapshots))
                    for opened_fd in exception_fds:
                        with self.assertRaises(OSError):
                            os.fstat(opened_fd)
                class HostileProcess:
                    pid = 43127
                    returncode = None
                    def __init__(self, first):
                        self.first = first
                        self.calls = 0
                    def communicate(self, *args, **kwargs):
                        self.calls += 1
                        if self.calls == 1:
                            raise self.first
                        if self.calls == 2:
                            raise subprocess.TimeoutExpired(["hostile"], 1)
                        self.returncode = -signal.SIGKILL
                        return "", ""
                sandbox_command = [P_CAPSULE_SANDBOX_EXECUTABLE, "-p", "(version 1)\n(allow default)\n", "/usr/bin/true"]
                sandbox_environment = {"PATH": SYSTEM_EXECUTABLE_PATH}
                for first_failure in (
                    subprocess.TimeoutExpired(sandbox_command, 1),
                    KeyboardInterrupt("sandbox wait interrupted"),
                    OSError("sandbox communicate failed"),
                ):
                    hostile_process = HostileProcess(first_failure)
                    with self.subTest(process_cleanup=type(first_failure).__name__), \
                            mock.patch.object(subprocess, "Popen", return_value=hostile_process) as popen, \
                            mock.patch.object(os, "killpg") as killpg, \
                            self.assertRaises(type(first_failure)):
                        run_sandbox(
                            sandbox_command, cwd=ROOT,
                            environment=sandbox_environment, pass_fds=(archive_fd,), timeout=1,
                        )
                    popen.assert_called_once_with(
                        sandbox_command, cwd=ROOT, env=sandbox_environment,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, start_new_session=True,
                        pass_fds=(archive_fd,),
                    )
                    self.assertEqual(
                        [mock.call(hostile_process.pid, signal.SIGTERM),
                         mock.call(hostile_process.pid, signal.SIGKILL)],
                        killpg.call_args_list,
                    )
                    self.assertEqual(3, hostile_process.calls)
                with mock.patch.object(
                    subprocess, "Popen", side_effect=OSError("sandbox spawn failed"),
                ) as failed_spawn, self.assertRaisesRegex(OSError, "sandbox spawn failed"):
                    run_sandbox(
                        sandbox_command, cwd=ROOT,
                        environment=sandbox_environment, pass_fds=(archive_fd,), timeout=1,
                    )
                failed_spawn.assert_called_once()
                timeout_marker = outside / "grandchild-survived"
                timeout_snapshots = []
                timeout_fds = []
                def observe_timeout(event, **authority):
                    if event == "snapshot-ready":
                        timeout_snapshots.append(Path(authority["snapshot"]))
                def capture_timeout_fd(path, flags, *args, **kwargs):
                    descriptor = real_open(path, flags, *args, **kwargs)
                    timeout_fds.append(descriptor)
                    return descriptor
                timeout_program = (
                    "import signal,subprocess,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                    "subprocess.Popen([sys.executable,'-I','-S','-c',"
                    "'import pathlib,signal,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(2); pathlib.Path(sys.argv[1]).write_text(\"survived\")',"
                    f"{str(timeout_marker)!r}]); time.sleep(30)"
                )
                timeout_started = []
                timeout_finished = []
                timeout_failures = []
                def timed_real_sandbox(*args, **kwargs):
                    timeout_started.append(time.monotonic())
                    try:
                        return run_sandbox(*args, **kwargs)
                    except subprocess.TimeoutExpired as error:
                        timeout_finished.append(time.monotonic())
                        timeout_failures.append(error)
                        raise
                if active_fixture is None:
                    with mock.patch.object(
                        module, "_dependency_archive_observer",
                        side_effect=observe_timeout,
                    ), mock.patch.object(
                        os, "open", side_effect=capture_timeout_fd,
                    ), mock.patch.object(
                        module, "_run_capsule_sandbox",
                        side_effect=timed_real_sandbox,
                    ), self.assertRaises(
                        subprocess.TimeoutExpired,
                    ) as observed_timeout:
                        _python_run(
                            ROOT, ["-B", "-c", timeout_program], timeout=1,
                            dependency_archive=dependency_archive,
                        )
                else:
                    with self.assertRaises(
                        subprocess.TimeoutExpired,
                    ) as observed_timeout:
                        run_active_direct_child(
                            ROOT, ("-B", "-c", timeout_program), timeout=1,
                            final_started=timeout_started,
                            final_finished=timeout_finished,
                            final_failures=timeout_failures,
                        )
                self.assertEqual(1, len(timeout_started))
                self.assertEqual(1, len(timeout_finished))
                self.assertEqual(1, len(timeout_failures))
                self.assertIs(observed_timeout.exception, timeout_failures[0])
                self.assertLess(timeout_finished[0] - timeout_started[0], 5)
                time.sleep(2.5)
                self.assertFalse(timeout_marker.exists())
                self.assertEqual(
                    1 if active_fixture is None else 0,
                    len(timeout_snapshots),
                )
                self.assertTrue(all(
                    not os.path.lexists(path) for path in timeout_snapshots
                ))
                for opened_fd in timeout_fds:
                    with self.assertRaises(OSError):
                        os.fstat(opened_fd)
                rebuild.assert_not_called()
            shutil.rmtree(call_state)
            outside.rmdir()
            verify_archive(dependency_archive)
            self.assertEqual(
                preserved_archive_offset,
                os.lseek(archive_fd, 0, os.SEEK_CUR),
            )
            dependency_archive.close()
            with self.assertRaises(OSError):
                os.fstat(archive_fd)
            self.assertEqual([], list(formal_root.iterdir()))

    def test_p_phase_exact_commit_runs_catalog_in_private_free_clone(self):
        formal_archive_owner = tempfile.TemporaryDirectory(
            prefix="http-p-formal-archive-owner-",
        )
        self.addCleanup(formal_archive_owner.cleanup)
        formal_archive_state = Path(formal_archive_owner.name) / "state"
        with _formal_dependency_archive_scope(formal_archive_state) as scoped_archive:
            formal_archive_fd = fcntl.fcntl(
                scoped_archive.fd, fcntl.F_DUPFD_CLOEXEC, 0,
            )
            formal_archive_metadata = os.fstat(formal_archive_fd)
            dependency_archive = _DependencyArchiveAuthority(
                formal_archive_fd, formal_archive_metadata, scoped_archive.sha256,
            )
            _verify_dependency_archive(dependency_archive)
        self.addCleanup(dependency_archive.close)
        self.assertEqual(26, len(P_PHASE_PRELEDGER_PATHS))
        self.assertEqual(27, len(P_PHASE_FINAL_PATHS))
        self.assertEqual(P_PRELEDGER_PATH_DIGEST, _path_digest(P_PHASE_PRELEDGER_PATHS))
        self.assertEqual(P_FINAL_PATH_DIGEST, _path_digest(P_PHASE_FINAL_PATHS))
        self.assertEqual(len(P_PHASE_PRELEDGER_PATHS), len(set(P_PHASE_PRELEDGER_PATHS)))
        git_directory = ROOT / ".git"
        try:
            git_metadata = git_directory.lstat()
        except OSError as error:
            raise AssertionError("P canonical Git directory is missing") from error
        if not stat.S_ISDIR(git_metadata.st_mode):
            raise AssertionError("P proof Git directory is not a real directory")
        git_directory_identity = (
            git_metadata.st_dev, git_metadata.st_ino, git_metadata.st_mode,
        )
        _assert_canonical_history_metadata(ROOT)
        _history_observer("after-metadata-check", ROOT)
        try:
            rebound_git_metadata = git_directory.lstat()
        except OSError as error:
            raise AssertionError("P Git directory identity changed") from error
        if (
            not stat.S_ISDIR(rebound_git_metadata.st_mode)
            or (
                rebound_git_metadata.st_dev, rebound_git_metadata.st_ino,
                rebound_git_metadata.st_mode,
            ) != git_directory_identity
        ):
            raise AssertionError("P Git directory identity changed")
        head = _head(ROOT)
        if head != S_COMMIT:
            try:
                distance = _raw_p_lineage_distance(ROOT, head)
            finally:
                _history_observer("after-raw-lineage", ROOT, head=head)
            self.assertIn(distance, {1, 2})
            records = _tree_records(ROOT, head)
            self.assertEqual(P_TREE_PATH_COUNT, len(records))
            self.assertEqual(P_TREE_PATH_DIGEST, _path_digest(records))
            self.assertEqual(set(), _forbidden_v2_paths(records))
            self.assertEqual(P_TREE_RECORD_DIGEST, _record_digest(records))
            formal_ledger = (ROOT / P_LEDGER_PATH).read_bytes()
            _assert_clean_and_ledger(ROOT, formal_ledger, head)
            if distance == 1:
                s_records = _tree_records(ROOT, S_COMMIT)
                self.assertEqual(
                    s_records[P_LEDGER_PATH], records[P_LEDGER_PATH],
                )
            else:
                head_parents = _raw_commit_parents(ROOT, head)
                self.assertEqual(1, len(head_parents))
                raw_parent = head_parents[0]
                self.assertEqual(1, _raw_p_lineage_distance(ROOT, raw_parent))
                _history_observer(
                    "before-distance-two-diff", ROOT,
                    head=head, raw_parent=raw_parent,
                )
                changed = _git_run(
                    ROOT, ["diff-tree", "--no-commit-id", "--name-only", "-r",
                           raw_parent, head], text=True,
                )
                _history_observer(
                    "after-distance-two-diff", ROOT,
                    head=head, raw_parent=raw_parent,
                )
                self.assertEqual(0, changed.returncode, changed.stderr)
                self.assertEqual(P_LEDGER_PATH + "\n", changed.stdout)
                ledger_before = (ROOT / P_LEDGER_PATH).read_bytes()
                _assert_clean_and_ledger(ROOT, ledger_before, head)
                checked = _python_run(
                    ROOT, ["-B", "test_cases/run_related_tests.py",
                           "--check", "--require-full"], timeout=180,
                    dependency_archive=dependency_archive,
                )
                self.assertEqual(0, checked.returncode, checked.stdout + checked.stderr)
                _assert_clean_and_ledger(ROOT, ledger_before, head)
            generated = _python_run(
                ROOT, ["-B", "tools/update-user-manual.py", "--check"], timeout=180,
                dependency_archive=dependency_archive,
            )
            self.assertEqual(0, generated.returncode, generated.stdout + generated.stderr)
            self.assertEqual(head, _head(ROOT), "P HEAD changed during formal proof")
            _assert_clean_and_ledger(
                ROOT, (ROOT / P_LEDGER_PATH).read_bytes(), head,
            )
            final_records = _tree_records(ROOT, head)
            if final_records != records:
                raise AssertionError("P committed tree records changed after verification")
            self.assertEqual(P_TREE_PATH_COUNT, len(final_records))
            self.assertEqual(P_TREE_PATH_DIGEST, _path_digest(final_records))
            self.assertEqual(set(), _forbidden_v2_paths(final_records))
            self.assertEqual(P_TREE_RECORD_DIGEST, _record_digest(final_records))
            return

        for relative in Q05_V2_FORBIDDEN_LIFECYCLE_PATHS:
            with self.subTest(forbidden=relative):
                self.assertFalse(os.path.lexists(ROOT / relative), relative)
                self.assertNotIn(relative, _tracked_paths())
        for relative, digest in P_STATIC_TARGET_SHA256.items():
            with self.subTest(target=relative):
                self.assertEqual(
                    digest, hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                )
        manifest_payload = (ROOT / "test_cases/script_test_manifest.json").read_bytes()
        self.assertEqual(P_MANIFEST_SIZE, len(manifest_payload))
        self.assertEqual(P_MANIFEST_SHA256, hashlib.sha256(manifest_payload).hexdigest())
        html_payload = (ROOT / "user-manual.html").read_bytes()
        self.assertEqual(P_HTML_FINAL_SIZE, len(html_payload))
        self.assertEqual(P_HTML_FINAL_SHA256, hashlib.sha256(html_payload).hexdigest())
        with tempfile.TemporaryDirectory(prefix="http-public-p-checkout-") as directory:
            base = Path(directory)
            candidate = base / "candidate"
            proof = base / "proof"
            final_checkout = base / "final"

            def make_clone_loose_only(repository: Path, label: str) -> None:
                pack_directory = repository / ".git/objects/pack"
                packed = sorted(pack_directory.glob("*.pack"))
                self.assertTrue(packed)
                held_packs = base / f"held-packs-{label}"
                self.assertFalse(os.path.lexists(held_packs))
                pack_directory.rename(held_packs)
                pack_directory.mkdir(mode=0o755)
                for packed_path in packed:
                    unpacked = subprocess.run(
                        [
                            GIT_BINARY, "--no-replace-objects", "-c",
                            f"core.hooksPath={os.devnull}", "-C", str(repository),
                            "unpack-objects", "-r",
                        ],
                        input=(held_packs / packed_path.name).read_bytes(),
                        env=_canonical_git_environment(),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                    )
                    self.assertEqual(0, unpacked.returncode, unpacked.stderr)
                    self.assertEqual(b"", unpacked.stdout)
                    self.assertEqual(b"", unpacked.stderr)
                shutil.rmtree(held_packs)
                self.assertEqual([], list(pack_directory.iterdir()))
                for alternate_name in ("alternates", "http-alternates"):
                    self.assertFalse(os.path.lexists(
                        repository / ".git/objects/info" / alternate_name,
                    ))
                checked = _git_run(
                    repository, ["fsck", "--strict", "--no-dangling"],
                )
                self.assertEqual(0, checked.returncode, checked.stderr)
                self.assertEqual(b"", checked.stdout)
                self.assertEqual(b"", checked.stderr)

            _git_run(ROOT, ["clone", "--quiet", "--no-local", str(ROOT), str(candidate)], check=True)
            _git_run(candidate, ["checkout", "--quiet", "--detach", S_COMMIT], check=True)
            phase_records = _materialize_staged_overlay(
                candidate, P_PHASE_PRELEDGER_PATHS,
            )
            self.assertEqual(P_PHASE_RECORD_DIGEST, _record_digest(phase_records))
            generated = _python_run(
                candidate, ["-B", "tools/update-user-manual.py", "--check"],
                timeout=60, dependency_archive=dependency_archive,
            )
            self.assertEqual(0, generated.returncode, generated.stdout + generated.stderr)
            _git_run(candidate, ["add", "--", *P_PHASE_PRELEDGER_PATHS], check=True)
            staged = _git_run(candidate, ["diff", "--cached", "--name-only"], text=True, check=True)
            self.assertEqual(
                set(P_PHASE_PRELEDGER_PATHS), set(staged.stdout.splitlines()),
            )
            _git_run(
                candidate, [
                    "-c", "user.name=Public Contract",
                    "-c", "user.email=public-contract@example.invalid",
                    "commit", "--quiet", "-m", "public P candidate",
                ],
                check=True,
            )
            candidate_head = _head(candidate)
            with self.subTest(formal_distance_one_status_aba_is_rejected=True):
                aba_path = candidate / "AGENTS.md"
                captured_payload = aba_path.read_bytes()
                captured_index = (candidate / ".git/index").read_bytes()
                captured_ledger = (candidate / P_LEDGER_PATH).read_bytes()
                aba_path.write_bytes(b"# transient status authority\n")
                _git_run(candidate, ["add", "--", "AGENTS.md"], check=True)
                _git_run(
                    candidate,
                    ["-c", "user.name=P", "-c", "user.email=p@example.invalid",
                     "commit", "--quiet", "-m", "transient status B"], check=True,
                )
                transient_head = _head(candidate)
                transient_index = (candidate / ".git/index").read_bytes()
                transient_payload = aba_path.read_bytes()
                _git_run(candidate, ["reset", "--hard", candidate_head], check=True)
                (candidate / ".git/index").write_bytes(captured_index)
                events = []
                python_calls = []

                def transient_clean_authority(event, repository, **authority):
                    self.assertEqual(candidate, repository)
                    self.assertEqual(candidate_head, authority["captured_head"])
                    if event == "before-clean-comparison":
                        _git_run(repository, ["update-ref", "HEAD", transient_head], check=True)
                        (repository / ".git/index").write_bytes(transient_index)
                        aba_path.write_bytes(transient_payload)
                        events.append("B")
                    elif event == "after-clean-comparison":
                        _git_run(repository, ["update-ref", "HEAD", candidate_head], check=True)
                        (repository / ".git/index").write_bytes(captured_index)
                        aba_path.write_bytes(captured_payload)
                        events.append("A")

                def reject_python_after_status_aba(*args, **kwargs):
                    python_calls.append((args, kwargs))
                    raise AssertionError("runner reached after status authority ABA")

                with mock.patch.object(
                    sys.modules[__name__], "ROOT", candidate,
                ), mock.patch.object(
                    sys.modules[__name__], "_clean_state_observer",
                    side_effect=transient_clean_authority,
                ), mock.patch.object(
                    sys.modules[__name__], "_python_run",
                    side_effect=reject_python_after_status_aba,
                ), self.assertRaisesRegex(AssertionError, "clean|index|HEAD|authority"):
                    self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
                self.assertEqual(["B", "A"], events)
                self.assertEqual([], python_calls)
                self.assertEqual(candidate_head, _head(candidate))
                self.assertEqual(captured_index, (candidate / ".git/index").read_bytes())
                self.assertEqual(captured_payload, aba_path.read_bytes())
                self.assertEqual(captured_ledger, (candidate / P_LEDGER_PATH).read_bytes())
            modes = _tree_modes(candidate, candidate_head)
            self.assertEqual(P_TREE_PATH_COUNT, len(modes))
            self.assertEqual(P_TREE_PATH_DIGEST, _path_digest(modes))
            self.assertEqual(
                {relative: "100644" for relative in Q01_PUBLIC_DOCUMENT_PATHS},
                {relative: modes[relative] for relative in Q01_PUBLIC_DOCUMENT_PATHS},
            )
            self.assertEqual(
                set(), set(modes).intersection(Q05_V2_FORBIDDEN_LIFECYCLE_PATHS),
            )
            records = _tree_records(candidate, candidate_head)
            _assert_committed_phase_records(phase_records, records)
            hostile_phase = dict(phase_records)
            mode, kind, object_id, payload = hostile_phase[P_SELF_RECORD_PATH]
            token = re.compile(
                rb'(P_PHASE_RECORD_DIGEST = \(\n    ")[0-9a-f]{64}("\n\))'
            )
            self.assertEqual(1, len(token.findall(payload)))
            hostile_payload = token.sub(rb'\g<1>' + b"0" * 64 + rb'\g<2>', payload)
            hostile_phase[P_SELF_RECORD_PATH] = (
                mode, kind, "d" * 40, hostile_payload,
            )
            self.assertEqual(
                _record_digest(phase_records), _record_digest(hostile_phase),
                "the normalized self token must exercise the exact-record backstop",
            )
            self.assertNotEqual(
                phase_records, hostile_phase,
                "commit-hook mutation of a normalized token must still be rejected",
            )
            self.assertEqual(set(), _forbidden_v2_paths(records))
            self.assertEqual(P_TREE_RECORD_DIGEST, _record_digest(records))
            for gitdir_attack in ("directory-inode", "symlink"):
                with self.subTest(git_directory_rebind=gitdir_attack):
                    gitdir_race = base / f"gitdir-rebind-{gitdir_attack}"
                    _git_run(
                        candidate,
                        ["clone", "--quiet", "--no-local", str(candidate),
                         str(gitdir_race)], check=True,
                    )
                    race_head = _head(gitdir_race)
                    original_git = gitdir_race / ".git"
                    held_git = base / f"gitdir-held-{gitdir_attack}"
                    before_git = original_git.stat()
                    ledger_before = (gitdir_race / P_LEDGER_PATH).read_bytes()
                    worktree_before = {
                        path: (
                            os.readlink(gitdir_race / path).encode("utf-8")
                            if mode == "120000" else (gitdir_race / path).read_bytes()
                        )
                        for path, (mode, _kind, _oid, _payload) in records.items()
                    }
                    fired = []
                    python_calls = []

                    def rebind_git_directory(event, repository, **_authority):
                        if event != "after-metadata-check" or fired:
                            return
                        self.assertEqual(gitdir_race, repository)
                        original_git.rename(held_git)
                        if gitdir_attack == "symlink":
                            original_git.symlink_to(held_git)
                        else:
                            shutil.copytree(held_git, original_git, symlinks=True)
                        fired.append(True)

                    def reject_python_after_gitdir_rebind(*args, **kwargs):
                        python_calls.append((args, kwargs))
                        raise AssertionError("Python child reached after Git directory rebind")

                    try:
                        with mock.patch.object(
                            sys.modules[__name__], "ROOT", gitdir_race,
                        ), mock.patch.object(
                            sys.modules[__name__], "_history_observer",
                            side_effect=rebind_git_directory,
                        ), mock.patch.object(
                            sys.modules[__name__], "_python_run",
                            side_effect=reject_python_after_gitdir_rebind,
                        ), self.assertRaisesRegex(AssertionError, "Git directory|identity"):
                            self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
                    finally:
                        if os.path.lexists(original_git):
                            attacker = base / f"gitdir-attacker-{gitdir_attack}"
                            original_git.rename(attacker)
                        if held_git.exists():
                            held_git.rename(original_git)
                    self.assertEqual([True], fired)
                    self.assertEqual([], python_calls)
                    restored_git = original_git.stat()
                    self.assertEqual(
                        (before_git.st_dev, before_git.st_ino, stat.S_IFMT(before_git.st_mode)),
                        (restored_git.st_dev, restored_git.st_ino,
                         stat.S_IFMT(restored_git.st_mode)),
                    )
                    self.assertEqual(race_head, _head(gitdir_race))
                    self.assertEqual(
                        "", _git_run(
                            gitdir_race, ["status", "--porcelain=v1"],
                            text=True, check=True,
                        ).stdout,
                    )
                    self.assertEqual(
                        ledger_before, (gitdir_race / P_LEDGER_PATH).read_bytes(),
                    )
                    self.assertEqual(
                        worktree_before,
                        {
                            path: (
                                os.readlink(gitdir_race / path).encode("utf-8")
                                if mode == "120000" else (gitdir_race / path).read_bytes()
                            )
                            for path, (mode, _kind, _oid, _payload) in records.items()
                        },
                    )
            hostile = dict(records)
            changed_path = "test_cases/test_public_publication_contract.py"
            mode, kind, object_id, payload = hostile[changed_path]
            hostile[changed_path] = (
                mode, kind, "f" * 40, payload + b"hostile nonconstant byte\n",
            )
            self.assertNotEqual(P_TREE_RECORD_DIGEST, _record_digest(hostile))
            hostile_self = dict(records)
            mode, kind, object_id, payload = hostile_self[P_SELF_RECORD_PATH]
            hostile_self[P_SELF_RECORD_PATH] = (
                mode, kind, "e" * 40, payload + b"hostile nonconstant self byte\n",
            )
            self.assertNotEqual(P_TREE_RECORD_DIGEST, _record_digest(hostile_self))
            with self.subTest(postcommit_head_rebind_is_rejected=True):
                candidate_tree = _git_run(
                    candidate, ["rev-parse", f"{candidate_head}^{{tree}}"],
                    text=True, check=True,
                ).stdout.strip()
                alternate_head = _git_run(
                    candidate,
                    ["-c", "user.name=Ref Race",
                     "-c", "user.email=ref-race@example.invalid",
                     "commit-tree", candidate_tree, "-p", candidate_head,
                     "-m", "hostile same-tree head"], text=True, check=True,
                ).stdout.strip()
                ledger_before = (candidate / P_LEDGER_PATH).read_bytes()
                worktree_before = {
                    path: (
                        os.readlink(candidate / path).encode("utf-8")
                        if mode == "120000" else (candidate / path).read_bytes()
                    )
                    for path, (mode, _kind, _oid, _payload) in records.items()
                }
                real_tree_records = _tree_records
                fired = []

                def rebind_after_tree(candidate_repository, revision="HEAD"):
                    resolved = real_tree_records(candidate_repository, revision)
                    if (
                        candidate_repository == candidate
                        and revision == candidate_head and not fired
                    ):
                        _git_run(
                            candidate, ["update-ref", "HEAD", alternate_head],
                            check=True,
                        )
                        fired.append(True)
                    return resolved

                with mock.patch.object(
                    sys.modules[__name__], "ROOT", candidate,
                ), mock.patch.object(
                    sys.modules[__name__], "_tree_records",
                    side_effect=rebind_after_tree,
                ), self.assertRaisesRegex(AssertionError, "HEAD changed"):
                    self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
                self.assertEqual([True], fired)
                self.assertEqual(alternate_head, _head(candidate))
                self.assertEqual("", _git_run(
                    candidate, ["status", "--porcelain=v1"], text=True, check=True,
                ).stdout)
                self.assertEqual(ledger_before, (candidate / P_LEDGER_PATH).read_bytes())
                self.assertEqual(
                    worktree_before,
                    {
                        path: (
                            os.readlink(candidate / path).encode("utf-8")
                            if mode == "120000" else (candidate / path).read_bytes()
                        )
                        for path, (mode, _kind, _oid, _payload) in records.items()
                    },
                )
                _git_run(
                    candidate, ["update-ref", "HEAD", candidate_head], check=True,
                )
            for object_attack, object_spec in (
                ("ordinary-blob", "AGENTS.md"),
                ("ledger-blob", P_LEDGER_PATH),
                ("nested-tree", "test_cases"),
            ):
              with self.subTest(postverification_object_rebind=object_attack):
                object_race = base / f"postverification-{object_attack}"
                _git_run(
                    candidate,
                    ["clone", "--quiet", "--no-local", str(candidate),
                     str(object_race)], check=True,
                )
                make_clone_loose_only(
                    object_race, f"postverification-{object_attack}",
                )
                pack_directory = object_race / ".git/objects/pack"
                race_head = _head(object_race)
                claimed_oid = _git_run(
                    object_race, ["rev-parse", f"{race_head}:{object_spec}"],
                    text=True, check=True,
                ).stdout.strip()
                object_kind = "tree" if object_attack == "nested-tree" else "blob"
                canonical_payload = _git_run(
                    object_race, ["cat-file", object_kind, claimed_oid], check=True,
                ).stdout
                self.assertEqual([], list((object_race / ".git/objects/pack").glob("*.pack")))
                claimed_loose = (
                    object_race / ".git/objects" / claimed_oid[:2] / claimed_oid[2:]
                )
                self.assertTrue(claimed_loose.is_file(), claimed_loose)
                hostile_payload = (
                    (b"1" if canonical_payload[:1] != b"1" else b"0")
                    + canonical_payload[1:]
                )
                ledger_before = (object_race / P_LEDGER_PATH).read_bytes()
                status_before = _git_run(
                    object_race, ["status", "--porcelain=v1"], text=True,
                    check=True,
                ).stdout
                real_tree_records = _tree_records
                real_raw_object = _read_raw_git_object
                real_git_run = _git_run
                fired = []
                postattack_claimed_reads = []
                forbidden_ledger_fallbacks = []

                def observe_postattack_raw_object(
                    repository, object_id, expected_kind,
                ):
                    if (
                        fired and repository == object_race
                        and object_id == claimed_oid
                        and expected_kind == object_kind
                    ):
                        postattack_claimed_reads.append(
                            (object_id, expected_kind),
                        )
                    return real_raw_object(
                        repository, object_id, expected_kind,
                    )

                def reject_postattack_ledger_fallback(
                    repository, args, *positional, **keywords,
                ):
                    if (
                        fired and repository == object_race
                        and tuple(args) == (
                            "show", f"{S_COMMIT}:{P_LEDGER_PATH}",
                        )
                    ):
                        forbidden_ledger_fallbacks.append(tuple(args))
                        raise AssertionError(
                            "postattack ledger authority used git show fallback"
                        )
                    return real_git_run(
                        repository, args, *positional, **keywords,
                    )

                def corrupt_after_verified_records(repository, revision="HEAD"):
                    trusted = real_tree_records(repository, revision)
                    if repository == object_race and revision == race_head and not fired:
                        _write_loose_object_fixture(
                            object_race, claimed_oid, object_kind, hostile_payload,
                        )
                        fired.append(True)
                        self.assertEqual(
                            hostile_payload,
                            _git_run(
                                object_race,
                                ["cat-file", object_kind, claimed_oid], check=True,
                            ).stdout,
                            "stock Git must consume the hostile loose object before formal rejection",
                        )
                        self.assertEqual(race_head, _head(object_race))
                        self.assertEqual(
                            status_before,
                            _git_run(
                                object_race, ["status", "--porcelain=v1"],
                                text=True, check=True,
                            ).stdout,
                        )
                    return trusted

                with mock.patch.object(
                    sys.modules[__name__], "ROOT", object_race,
                ), mock.patch.object(
                    sys.modules[__name__], "_tree_records",
                    side_effect=corrupt_after_verified_records,
                ), mock.patch.object(
                    sys.modules[__name__], "_read_raw_git_object",
                    side_effect=observe_postattack_raw_object,
                ), mock.patch.object(
                    sys.modules[__name__], "_git_run",
                    side_effect=reject_postattack_ledger_fallback,
                ), self.assertRaisesRegex(AssertionError, "object id"):
                    self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
                self.assertEqual([True], fired)
                self.assertEqual(
                    [(claimed_oid, object_kind)], postattack_claimed_reads,
                )
                self.assertEqual([], forbidden_ledger_fallbacks)
                self.assertEqual(
                    hostile_payload,
                    _git_run(
                        object_race, ["cat-file", object_kind, claimed_oid], check=True,
                    ).stdout,
                )
                self.assertEqual(race_head, _head(object_race))
                self.assertEqual(
                    status_before,
                    _git_run(
                        object_race, ["status", "--porcelain=v1"], text=True,
                        check=True,
                    ).stdout,
                )
                self.assertEqual(
                    ledger_before, (object_race / P_LEDGER_PATH).read_bytes(),
                )
            with self.subTest(commit_hook_rebinds_normalized_phase_token=True):
                hook_repository = base / "commit-hook-repository"
                hook_repository.mkdir()
                _git_run(hook_repository, ["init", "--quiet"], check=True)
                hook_path = hook_repository / P_SELF_RECORD_PATH
                hook_path.parent.mkdir(parents=True)
                hook_path.write_bytes(
                    b'P_TREE_RECORD_DIGEST = (\n    "' + b"1" * 64 + b'"\n)\n'
                    b'P_PHASE_RECORD_DIGEST = (\n    "' + b"2" * 64 + b'"\n)\n'
                )
                _git_run(hook_repository, ["add", "--", P_SELF_RECORD_PATH], check=True)
                staged_result = _git_run(
                    hook_repository,
                    ["ls-files", "--stage", "-z", "--", P_SELF_RECORD_PATH],
                )
                metadata, _raw_path = staged_result.stdout[:-1].split(b"\t", 1)
                hook_mode, hook_oid, hook_stage = metadata.decode("ascii").split(" ")
                self.assertEqual("0", hook_stage)
                staged_records = {
                    P_SELF_RECORD_PATH: (
                        hook_mode, "blob", hook_oid,
                        _git_run(hook_repository, ["cat-file", "blob", hook_oid]).stdout,
                    ),
                }
                hook_program = hook_repository / ".git/hooks/pre-commit"
                hook_program.write_text(
                    "#!/bin/sh\n"
                    "python3 -c 'from pathlib import Path; p=Path(\""
                    + P_SELF_RECORD_PATH
                    + "\"); b=p.read_bytes(); p.write_bytes(b.replace(b\"22222222\", b\"33333333\", 1))'\n"
                    + GIT_BINARY + " --no-replace-objects add -- "
                    + P_SELF_RECORD_PATH + "\n",
                    encoding="utf-8",
                )
                hook_program.chmod(0o755)
                committed = _git_run_with_review_hook(
                    hook_repository,
                    ["-c", "user.name=P Hook", "-c", "user.email=p-hook@example.invalid",
                     "commit", "--quiet", "-m", "hook mutation"],
                )
                self.assertEqual(0, committed.returncode, committed.stderr)
                committed_records = _tree_records(hook_repository)
                self.assertEqual(
                    _record_digest(staged_records), _record_digest(committed_records),
                )
                self.assertNotEqual(staged_records, committed_records)
                with self.assertRaisesRegex(
                    AssertionError, "committed P phase blobs differ",
                ):
                    _assert_committed_phase_records(
                        staged_records, committed_records, (P_SELF_RECORD_PATH,),
                    )
                ledger_path = hook_repository / P_LEDGER_PATH
                ledger_path.parent.mkdir(parents=True, exist_ok=True)
                ledger_path.write_text(
                    '{"schema_version": 1, "status": "reviewed"}\n',
                    encoding="utf-8",
                )
                _git_run(hook_repository, ["add", "--", P_LEDGER_PATH], check=True)
                staged_ledger = _staged_blob_record(hook_repository, P_LEDGER_PATH)
                hook_program.write_text(
                    f"#!{sys.executable}\n"
                    "import json, subprocess\n"
                    f"path = {P_LEDGER_PATH!r}\n"
                    "data = json.load(open(path, encoding='utf-8'))\n"
                    "data['hostile_unknown_authority'] = True\n"
                    "open(path, 'w', encoding='utf-8').write(json.dumps(data, sort_keys=True) + '\\n')\n"
                    f"subprocess.run([{GIT_BINARY!r}, '--no-replace-objects', 'add', '--', path], check=True)\n",
                    encoding="utf-8",
                )
                hook_program.chmod(0o755)
                committed = _git_run_with_review_hook(
                    hook_repository,
                    ["-c", "user.name=P Hook", "-c", "user.email=p-hook@example.invalid",
                     "commit", "--quiet", "-m", "ledger hook mutation"],
                )
                self.assertEqual(0, committed.returncode, committed.stderr)
                with self.assertRaisesRegex(
                    AssertionError, "committed P ledger differs",
                ):
                    _assert_committed_ledger_record(
                        staged_ledger, _tree_records(hook_repository),
                    )
            _git_run(candidate, ["clone", "--quiet", "--no-local", str(candidate), str(proof)], check=True)
            command = [
                "-B", "-m", "unittest", "-v",
                "test_cases.test_public_publication_contract",
                "test_cases.test_documentation_catalog",
                "test_cases.test_private_documentation_contract."
                "PrivateDocumentationContractTests",
            ]
            result = _python_run(
                proof, command, timeout=120, dependency_archive=dependency_archive,
            )
            combined = result.stdout + result.stderr
            skip_line = "skipped 'private documentation tier absent in public checkout'"
            self.assertEqual(1, combined.count(skip_line), combined)
            self.assertRegex(combined, r"\bskipped=1\b")
            self.assertNotIn("FileNotFoundError", combined)
            self.assertEqual(0, result.returncode, combined)
            audit = _python_run(
                proof, ["-B", "test_cases/audit_public_tree.py"], timeout=120,
                dependency_archive=dependency_archive,
            )
            self.assertEqual(0, audit.returncode, audit.stdout + audit.stderr)
            runner = ["-B", "test_cases/run_related_tests.py"]
            proof_manifest = json.loads(
                (proof / "test_cases/script_test_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            full = _python_run(
                proof, [*runner, "--all", "-v"],
                timeout=P_FORMAL_SUITE_TIMEOUT_SECONDS,
                dependency_archive=dependency_archive,
            )
            self.assertEqual(0, full.returncode, full.stdout + full.stderr)
            _assert_run_summary(full.stderr, P_FULL_TEST_COUNT, P_FULL_SKIP_REASONS)
            full_count, _full_skips = _ran_summary(full.stderr)
            self.assertEqual(
                _full_selection_stdout(
                    proof_manifest, (proof / P_LEDGER_PATH).resolve(),
                ),
                full.stdout,
            )
            changed = _git_run(proof, ["status", "--porcelain=v1"], text=True, check=True)
            self.assertEqual(f" M {P_LEDGER_PATH}\n", changed.stdout)
            _git_run(proof, ["add", "--", P_LEDGER_PATH], check=True)
            staged_ledger_record = _staged_blob_record(proof, P_LEDGER_PATH)
            staged_ledger = _git_run(
                proof, ["diff", "--cached", "--name-only"], text=True, check=True,
            )
            self.assertEqual(P_LEDGER_PATH + "\n", staged_ledger.stdout)
            _git_run(
                proof, ["-c", "user.name=Public Contract",
                 "-c", "user.email=public-contract@example.invalid",
                 "commit", "--quiet", "-m", "P full-suite attestation"],
                check=True,
            )
            with self.subTest(formal_distance_two_status_aba_is_rejected=True):
                distance_two_head = _head(proof)
                aba_path = proof / "AGENTS.md"
                captured_payload = aba_path.read_bytes()
                captured_index = (proof / ".git/index").read_bytes()
                captured_ledger = (proof / P_LEDGER_PATH).read_bytes()
                aba_path.write_bytes(b"# transient distance-two authority\n")
                _git_run(proof, ["add", "--", "AGENTS.md"], check=True)
                _git_run(
                    proof,
                    ["-c", "user.name=P", "-c", "user.email=p@example.invalid",
                     "commit", "--quiet", "-m", "transient distance three"],
                    check=True,
                )
                transient_head = _head(proof)
                transient_index = (proof / ".git/index").read_bytes()
                transient_payload = aba_path.read_bytes()
                _git_run(proof, ["reset", "--hard", distance_two_head], check=True)
                (proof / ".git/index").write_bytes(captured_index)
                events = []
                python_calls = []

                def distance_two_aba(event, repository, **authority):
                    self.assertEqual(proof, repository)
                    self.assertEqual(distance_two_head, authority["captured_head"])
                    if event == "before-clean-comparison":
                        _git_run(repository, ["update-ref", "HEAD", transient_head], check=True)
                        (repository / ".git/index").write_bytes(transient_index)
                        aba_path.write_bytes(transient_payload)
                        events.append("B")
                    elif event == "after-clean-comparison":
                        _git_run(repository, ["update-ref", "HEAD", distance_two_head], check=True)
                        (repository / ".git/index").write_bytes(captured_index)
                        aba_path.write_bytes(captured_payload)
                        events.append("A")

                def reject_python_after_distance_two_aba(*args, **kwargs):
                    python_calls.append((args, kwargs))
                    raise AssertionError("runner reached after distance-two status ABA")

                with mock.patch.object(
                    sys.modules[__name__], "ROOT", proof,
                ), mock.patch.object(
                    sys.modules[__name__], "_clean_state_observer",
                    side_effect=distance_two_aba,
                ), mock.patch.object(
                    sys.modules[__name__], "_python_run",
                    side_effect=reject_python_after_distance_two_aba,
                ), self.assertRaisesRegex(AssertionError, "clean|index|HEAD|authority"):
                    self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
                self.assertEqual(["B", "A"], events)
                self.assertEqual([], python_calls)
                self.assertEqual(distance_two_head, _head(proof))
                self.assertEqual(captured_index, (proof / ".git/index").read_bytes())
                self.assertEqual(captured_payload, aba_path.read_bytes())
                self.assertEqual(captured_ledger, (proof / P_LEDGER_PATH).read_bytes())
            _git_run(proof, ["clone", "--quiet", "--no-local", str(proof), str(final_checkout)], check=True)
            ledger_payload = (final_checkout / P_LEDGER_PATH).read_bytes()
            final_head = _head(final_checkout)
            final_records = _tree_records(final_checkout)
            _assert_committed_ledger_record(staged_ledger_record, final_records)
            self.assertEqual(P_TREE_RECORD_DIGEST, _record_digest(final_records))
            final_runner = ["-B", "test_cases/run_related_tests.py"]
            manifest = json.loads(
                (final_checkout / "test_cases/script_test_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            suite_modules = {
                test for suite in manifest["test_suites"] for test in suite["tests"]
            }
            self.assertEqual(77, len(suite_modules))

            first_check = _python_run(
                final_checkout, [*final_runner, "--check", "--require-full"],
                timeout=180, dependency_archive=dependency_archive,
            )
            self.assertEqual(0, first_check.returncode, first_check.stdout + first_check.stderr)
            _assert_clean_and_ledger(final_checkout, ledger_payload, final_head)

            listed = _python_run(
                final_checkout, [*final_runner, "--all", "--list"], timeout=180,
                dependency_archive=dependency_archive,
            )
            self.assertEqual(0, listed.returncode, listed.stdout + listed.stderr)
            self.assertEqual("", listed.stderr)
            expected_list = ["mode: full-suite", "changed paths:"]
            expected_list.extend(f"  - {path}" for path in sorted(manifest["scripts"]))
            expected_list.extend((
                "tests:", "  - unittest discovery: test_cases/test_*.py",
                "reasons:", "  - explicit --all",
            ))
            self.assertEqual("\n".join(expected_list) + "\n", listed.stdout)
            _assert_clean_and_ledger(final_checkout, ledger_payload, final_head)

            catalog = _python_run(
                final_checkout, [*final_runner, "--list-suites"], timeout=180,
                dependency_archive=dependency_archive,
            )
            self.assertEqual(0, catalog.returncode, catalog.stdout + catalog.stderr)
            self.assertEqual("", catalog.stderr)
            expected_catalog = ["test suites:"]
            for suite in manifest["test_suites"]:
                expected_catalog.append(f"  {suite['id']} ({len(suite['tests'])} modules)")
                expected_catalog.append(f"    {suite['description']}")
                expected_catalog.extend(f"    - {test}" for test in suite["tests"])
            self.assertEqual("\n".join(expected_catalog) + "\n", catalog.stdout)
            self.assertEqual(77, catalog.stdout.count("    - test_cases."))
            _assert_clean_and_ledger(final_checkout, ledger_payload, final_head)

            repository_suite = next(
                suite for suite in manifest["test_suites"]
                if suite["id"] == "repository-governance"
            )
            selected = _python_run(
                final_checkout,
                [*final_runner, "--suite", repository_suite["id"], "-v"],
                timeout=P_FORMAL_SUITE_TIMEOUT_SECONDS,
                dependency_archive=dependency_archive,
            )
            self.assertEqual(0, selected.returncode, selected.stdout + selected.stderr)
            _assert_run_summary(
                selected.stderr,
                P_REPOSITORY_SUITE_TEST_COUNT,
                P_REPOSITORY_SKIP_REASONS,
            )
            for test in repository_suite["tests"]:
                self.assertIn(f"  - {test}\n", selected.stdout)
            for test in suite_modules - set(repository_suite["tests"]):
                self.assertNotIn(f"  - {test}\n", selected.stdout)
            _assert_clean_and_ledger(final_checkout, ledger_payload, final_head)

            no_approve = _python_run(
                final_checkout, [*final_runner, "--all", "--no-approve", "-v"],
                timeout=P_FORMAL_SUITE_TIMEOUT_SECONDS,
                dependency_archive=dependency_archive,
            )
            self.assertEqual(0, no_approve.returncode, no_approve.stdout + no_approve.stderr)
            _assert_run_summary(
                no_approve.stderr, P_FULL_TEST_COUNT, P_FULL_SKIP_REASONS,
            )
            self.assertEqual(full_count, _ran_summary(no_approve.stderr)[0])
            self.assertEqual(_full_selection_stdout(manifest, None), no_approve.stdout)
            _assert_clean_and_ledger(final_checkout, ledger_payload, final_head)

            final_check = _python_run(
                final_checkout, [*final_runner, "--check", "--require-full"],
                timeout=180, dependency_archive=dependency_archive,
            )
            self.assertEqual(0, final_check.returncode, final_check.stdout + final_check.stderr)
            self.assertEqual(
                (first_check.stdout, first_check.stderr),
                (final_check.stdout, final_check.stderr),
                "the two full-proof checks must have byte-identical output",
            )
            first_check_digest = hashlib.sha256(
                first_check.stdout.encode("utf-8") + b"\0"
                + first_check.stderr.encode("utf-8")
            ).hexdigest()
            self.assertEqual(
                first_check_digest,
                hashlib.sha256(
                    final_check.stdout.encode("utf-8") + b"\0"
                    + final_check.stderr.encode("utf-8")
                ).hexdigest(),
            )
            _assert_clean_and_ledger(final_checkout, ledger_payload, final_head)

            for corrupt_kind in ("ledger-blob", "nested-tree"):
                with self.subTest(corrupt_committed_object=corrupt_kind):
                    corrupt_checkout = base / f"corrupt-{corrupt_kind}"
                    _git_run(
                        final_checkout,
                        ["clone", "--quiet", "--no-local", str(final_checkout),
                         str(corrupt_checkout)], check=True,
                    )
                    make_clone_loose_only(
                        corrupt_checkout, f"committed-{corrupt_kind}",
                    )
                    corrupt_head = _head(corrupt_checkout)
                    if corrupt_kind == "ledger-blob":
                        claimed_oid = _git_run(
                            corrupt_checkout,
                            ["rev-parse", f"HEAD:{P_LEDGER_PATH}"],
                            text=True, check=True,
                        ).stdout.strip()
                        canonical_payload = _git_run(
                            corrupt_checkout, ["cat-file", "blob", claimed_oid],
                            check=True,
                        ).stdout
                        claimed_loose = (
                            corrupt_checkout / ".git/objects" / claimed_oid[:2]
                            / claimed_oid[2:]
                        )
                        claimed_metadata = claimed_loose.lstat()
                        self.assertTrue(stat.S_ISREG(claimed_metadata.st_mode))
                        self.assertEqual(1, claimed_metadata.st_nlink)
                        corrupt_payload = (
                            (b"[" if canonical_payload[:1] != b"[" else b"{")
                            + canonical_payload[1:]
                        )
                        _write_loose_object_fixture(
                            corrupt_checkout, claimed_oid, "blob", corrupt_payload,
                        )
                        replaced_metadata = claimed_loose.lstat()
                        self.assertEqual(
                            (claimed_metadata.st_dev, claimed_metadata.st_ino),
                            (replaced_metadata.st_dev, replaced_metadata.st_ino),
                        )
                        self.assertTrue(stat.S_ISREG(replaced_metadata.st_mode))
                        self.assertEqual(1, replaced_metadata.st_nlink)
                        self.assertEqual(
                            corrupt_payload,
                            _git_run(
                                corrupt_checkout, ["cat-file", "blob", claimed_oid],
                                check=True,
                            ).stdout,
                        )
                    else:
                        claimed_oid = _git_run(
                            corrupt_checkout, ["rev-parse", "HEAD:test_cases"],
                            text=True, check=True,
                        ).stdout.strip()
                        canonical_payload = _git_run(
                            corrupt_checkout, ["cat-file", "tree", claimed_oid],
                            check=True,
                        ).stdout
                        claimed_loose = (
                            corrupt_checkout / ".git/objects" / claimed_oid[:2]
                            / claimed_oid[2:]
                        )
                        claimed_metadata = claimed_loose.lstat()
                        self.assertTrue(stat.S_ISREG(claimed_metadata.st_mode))
                        self.assertEqual(1, claimed_metadata.st_nlink)
                        self_oid = _git_run(
                            corrupt_checkout,
                            ["rev-parse", f"HEAD:{P_SELF_RECORD_PATH}"],
                            text=True, check=True,
                        ).stdout.strip()
                        self_payload = _git_run(
                            corrupt_checkout, ["cat-file", "blob", self_oid],
                            check=True,
                        ).stdout
                        token = re.compile(
                            rb'(P_PHASE_RECORD_DIGEST = \(\n    ")[0-9a-f]{64}("\n\))'
                        )
                        self.assertEqual(1, len(token.findall(self_payload)))
                        hostile_self_payload = token.sub(
                            rb'\g<1>' + b"9" * 64 + rb'\g<2>', self_payload,
                        )
                        hostile_self_oid = hashlib.sha1(
                            b"blob " + str(len(hostile_self_payload)).encode("ascii")
                            + b"\0" + hostile_self_payload
                        ).hexdigest()
                        _write_loose_object_fixture(
                            corrupt_checkout, hostile_self_oid, "blob",
                            hostile_self_payload,
                        )
                        entry = (
                            b"100644 test_public_publication_workflow.py\0"
                            + bytes.fromhex(self_oid)
                        )
                        self.assertEqual(1, canonical_payload.count(entry))
                        corrupt_payload = canonical_payload.replace(
                            entry,
                            b"100644 test_public_publication_workflow.py\0"
                            + bytes.fromhex(hostile_self_oid),
                            1,
                        )
                        _write_loose_object_fixture(
                            corrupt_checkout, claimed_oid, "tree", corrupt_payload,
                        )
                        replaced_metadata = claimed_loose.lstat()
                        self.assertEqual(
                            (claimed_metadata.st_dev, claimed_metadata.st_ino),
                            (replaced_metadata.st_dev, replaced_metadata.st_ino),
                        )
                        self.assertTrue(stat.S_ISREG(replaced_metadata.st_mode))
                        self.assertEqual(1, replaced_metadata.st_nlink)
                        self.assertEqual(
                            hostile_self_oid,
                            _git_run(
                                corrupt_checkout,
                                ["rev-parse", f"HEAD:{P_SELF_RECORD_PATH}"],
                                text=True, check=True,
                            ).stdout.strip(),
                        )
                    status_before = _git_run(
                        corrupt_checkout, ["status", "--porcelain=v1"],
                        text=True, check=True,
                    ).stdout
                    ledger_before = (corrupt_checkout / P_LEDGER_PATH).read_bytes()
                    runner_calls = []

                    def reject_runner_after_corruption(*_args, **_kwargs):
                        runner_calls.append(True)
                        raise AssertionError("runner reached corrupt Git object")

                    with mock.patch.object(
                        sys.modules[__name__], "ROOT", corrupt_checkout,
                    ), mock.patch.object(
                        sys.modules[__name__], "_python_run",
                        side_effect=reject_runner_after_corruption,
                    ), self.assertRaisesRegex(AssertionError, "object id"):
                        self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
                    self.assertEqual([], runner_calls)
                    self.assertEqual(
                        status_before,
                        _git_run(
                            corrupt_checkout, ["status", "--porcelain=v1"],
                            text=True, check=True,
                        ).stdout,
                    )
                    self.assertEqual(
                        ledger_before, (corrupt_checkout / P_LEDGER_PATH).read_bytes(),
                    )

            for attack in (
                "garbage", "stale-snapshot", "wrong-platform", "unknown-field",
            ):
                with self.subTest(distance_two_ledger=attack):
                    hostile_checkout = base / f"distance-two-{attack}"
                    _git_run(
                        candidate,
                        ["clone", "--quiet", "--no-local", str(candidate),
                         str(hostile_checkout)],
                        check=True,
                    )
                    ledger_path = hostile_checkout / P_LEDGER_PATH
                    if attack == "garbage":
                        ledger_path.write_bytes(b"not-json\n")
                    else:
                        hostile_ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
                        def poison_field(value, field, replacement):
                            if isinstance(value, dict):
                                for key, child in value.items():
                                    if key == field:
                                        value[key] = replacement
                                        return True
                                    if poison_field(child, field, replacement):
                                        return True
                            elif isinstance(value, list):
                                for child in value:
                                    if poison_field(child, field, replacement):
                                        return True
                            return False
                        if attack == "stale-snapshot":
                            self.assertTrue(poison_field(
                                hostile_ledger, "snapshot_sha256", "0" * 64,
                            ))
                        elif attack == "wrong-platform":
                            self.assertTrue(poison_field(
                                hostile_ledger, "platform", "hostile-platform",
                            ))
                        else:
                            hostile_ledger["hostile_unknown_authority"] = True
                        ledger_path.write_text(
                            json.dumps(hostile_ledger, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8",
                        )
                    _git_run(hostile_checkout, ["add", "--", P_LEDGER_PATH], check=True)
                    _git_run(
                        hostile_checkout,
                        ["-c", "user.name=Hostile Ledger",
                         "-c", "user.email=hostile-ledger@example.invalid",
                         "commit", "--quiet", "-m", f"hostile {attack}"],
                        check=True,
                    )
                    before_ledger = ledger_path.read_bytes()
                    before_status = _git_run(
                        hostile_checkout, ["status", "--porcelain=v1"], text=True,
                        check=True,
                    ).stdout
                    rejected = _python_run(
                        hostile_checkout,
                        ["-B", "-m", "unittest", "-v",
                         "test_cases.test_public_publication_workflow."
                         "PublicPublicationWorkflowTests."
                         "test_p_phase_exact_commit_runs_catalog_in_private_free_clone"],
                        timeout=240, dependency_archive=dependency_archive,
                    )
                    self.assertNotEqual(0, rejected.returncode)
                    self.assertEqual(before_ledger, ledger_path.read_bytes())
                    self.assertEqual(
                        before_status,
                        _git_run(
                            hostile_checkout, ["status", "--porcelain=v1"],
                            text=True, check=True,
                        ).stdout,
                    )

            with self.subTest(transient_graft_cannot_hide_raw_parent_changes=True):
                hostile_history = base / "distance-two-raw-parent-hostile"
                candidate_head = _head(candidate)
                _git_run(
                    final_checkout,
                    ["clone", "--quiet", "--no-local", str(final_checkout),
                     str(hostile_history)], check=True,
                )
                _git_run(
                    hostile_history,
                    ["checkout", "--quiet", "--detach", candidate_head], check=True,
                )
                hostile_source = hostile_history / "PUBLIC_REPOSITORY.md"
                canonical_public = hostile_source.read_bytes()
                candidate_ledger_payload = (
                    hostile_history / P_LEDGER_PATH
                ).read_bytes()
                candidate_tree = _git_run(
                    hostile_history, ["rev-parse", f"{candidate_head}^{{tree}}"],
                    text=True, check=True,
                ).stdout.strip()
                hostile_source.write_bytes(
                    canonical_public + b"\nhostile raw-parent byte\n"
                )
                _git_run(
                    hostile_history, ["add", "--", "PUBLIC_REPOSITORY.md"],
                    check=True,
                )
                self.assertEqual(
                    "M  PUBLIC_REPOSITORY.md\n",
                    _git_run(
                        hostile_history, ["status", "--porcelain=v1"],
                        text=True, check=True,
                    ).stdout,
                )
                malicious_tree = _git_run(
                    hostile_history, ["write-tree"], text=True, check=True,
                ).stdout.strip()
                malicious_parent = _git_run(
                    hostile_history,
                    ["-c", "user.name=Raw Parent",
                     "-c", "user.email=raw-parent@example.invalid",
                     "commit-tree", malicious_tree, "-p", S_COMMIT,
                     "-m", "malicious raw parent"], text=True, check=True,
                ).stdout.strip()
                _git_run(
                    hostile_history, ["reset", "--hard", candidate_head],
                    check=True,
                )
                self.assertEqual(candidate_head, _head(hostile_history))
                self.assertEqual(
                    candidate_tree,
                    _git_run(
                        hostile_history, ["rev-parse", "HEAD^{tree}"],
                        text=True, check=True,
                    ).stdout.strip(),
                )
                self.assertEqual(
                    "",
                    _git_run(
                        hostile_history, ["status", "--porcelain=v1"],
                        text=True, check=True,
                    ).stdout,
                )
                self.assertEqual(canonical_public, hostile_source.read_bytes())
                self.assertEqual(
                    candidate_ledger_payload,
                    (hostile_history / P_LEDGER_PATH).read_bytes(),
                )
                self.assertEqual(
                    (S_COMMIT,),
                    _raw_commit_parents(hostile_history, malicious_parent),
                )
                self.assertEqual(
                    malicious_tree,
                    _git_run(
                        hostile_history,
                        ["rev-parse", f"{malicious_parent}^{{tree}}"],
                        text=True, check=True,
                    ).stdout.strip(),
                )
                final_tree = _git_run(
                    final_checkout, ["rev-parse", "HEAD^{tree}"],
                    text=True, check=True,
                ).stdout.strip()
                self.assertEqual(
                    _git_run(
                        final_checkout, ["cat-file", "tree", final_tree], check=True,
                    ).stdout,
                    _git_run(
                        hostile_history, ["cat-file", "tree", final_tree], check=True,
                    ).stdout,
                )
                hostile_head = _git_run(
                    hostile_history,
                    ["-c", "user.name=Raw Parent",
                     "-c", "user.email=raw-parent@example.invalid",
                     "commit-tree", final_tree, "-p", malicious_parent,
                     "-m", "apparently valid final ledger"], text=True, check=True,
                ).stdout.strip()
                _git_run(
                    hostile_history, ["checkout", "--quiet", "--detach", hostile_head],
                    check=True,
                )
                self.assertEqual(hostile_head, _head(hostile_history))
                self.assertEqual(
                    final_tree,
                    _git_run(
                        hostile_history, ["rev-parse", "HEAD^{tree}"],
                        text=True, check=True,
                    ).stdout.strip(),
                )
                self.assertEqual(
                    "",
                    _git_run(
                        hostile_history, ["status", "--porcelain=v1"],
                        text=True, check=True,
                    ).stdout,
                )
                self.assertEqual(canonical_public, hostile_source.read_bytes())
                self.assertEqual(
                    ledger_payload,
                    (hostile_history / P_LEDGER_PATH).read_bytes(),
                )
                self.assertEqual(
                    2, _raw_p_lineage_distance(hostile_history, hostile_head),
                )
                raw_change = _git_run(
                    hostile_history,
                    ["diff-tree", "--no-commit-id", "--name-only", "-r",
                     malicious_parent, hostile_head], text=True, check=True,
                )
                self.assertEqual(
                    "PUBLIC_REPOSITORY.md\n" + P_LEDGER_PATH + "\n",
                    raw_change.stdout,
                )
                grafts = hostile_history / ".git/info/grafts"
                graft_payload = f"{hostile_head} {candidate_head}\n"
                grafts.parent.mkdir(parents=True, exist_ok=True)
                grafts.write_text(graft_payload, encoding="ascii")
                forged_change = _git_run(
                    hostile_history,
                    ["diff-tree", "--no-commit-id", "--name-only", "-r",
                     "HEAD^", "HEAD"], text=True, check=True,
                )
                self.assertEqual(P_LEDGER_PATH + "\n", forged_change.stdout)
                grafts.unlink()
                events = []

                def inject_diff_graft(event, repository, **authority):
                    self.assertEqual(hostile_history, repository)
                    if event == "before-distance-two-diff":
                        self.assertEqual(hostile_head, authority.get("head"))
                        self.assertEqual(
                            malicious_parent, authority.get("raw_parent"),
                        )
                        grafts.write_text(graft_payload, encoding="ascii")
                        events.append("injected")
                    elif event == "after-distance-two-diff":
                        self.assertTrue(os.path.lexists(grafts))
                        grafts.unlink()
                        events.append("removed")

                with mock.patch.object(
                    sys.modules[__name__], "ROOT", hostile_history,
                ), mock.patch.object(
                    sys.modules[__name__], "_history_observer",
                    side_effect=inject_diff_graft,
                ), self.assertRaises(AssertionError):
                    self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
                self.assertEqual(["injected", "removed"], events)
                self.assertFalse(os.path.lexists(grafts))

            distance_three = base / "distance-three-history-forgery"
            _git_run(
                candidate,
                ["clone", "--quiet", "--no-local", str(candidate),
                 str(distance_three)], check=True,
            )
            _git_run(
                distance_three,
                ["-c", "user.name=Shallow Hostile",
                 "-c", "user.email=shallow@example.invalid", "commit", "--quiet",
                 "--allow-empty", "-m", "empty distance two"],
                check=True,
            )
            (distance_three / P_LEDGER_PATH).write_bytes(ledger_payload)
            _git_run(distance_three, ["add", "--", P_LEDGER_PATH], check=True)
            _git_run(
                distance_three,
                ["-c", "user.name=Shallow Hostile",
                 "-c", "user.email=shallow@example.invalid", "commit", "--quiet",
                 "-m", "valid ledger distance three"], check=True,
            )
            valid_distance_three = _python_run(
                distance_three,
                ["-B", "test_cases/run_related_tests.py", "--check", "--require-full"],
                timeout=180, dependency_archive=dependency_archive,
            )
            self.assertEqual(
                0, valid_distance_three.returncode,
                valid_distance_three.stdout + valid_distance_three.stderr,
            )
            forged_boundary = _git_run(
                distance_three, ["rev-parse", "HEAD^"], text=True, check=True,
            ).stdout.strip()
            shallow_file = base / "hostile-shallow"
            shallow_file.write_text(forged_boundary + "\n", encoding="ascii")
            hostile_shallow_environment = _canonical_git_environment(
                {"GIT_SHALLOW_FILE": str(shallow_file)},
            )
            forged_count = subprocess.run(
                [GIT_BINARY, "--no-replace-objects", "-C", str(distance_three),
                 "rev-list", "--count", f"{S_COMMIT}..HEAD"],
                env=hostile_shallow_environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(0, forged_count.returncode, forged_count.stderr)
            self.assertEqual("2", forged_count.stdout.strip())
            rejected = _python_run(
                distance_three,
                ["-B", "-m", "unittest", "-v",
                 "test_cases.test_public_publication_workflow."
                 "PublicPublicationWorkflowTests."
                 "test_p_phase_exact_commit_runs_catalog_in_private_free_clone"],
                timeout=240,
                ambient={"GIT_SHALLOW_FILE": str(shallow_file)},
                dependency_archive=dependency_archive,
            )
            self.assertNotEqual(0, rejected.returncode)

            local_metadata_cases = {
                "shallow": (distance_three / ".git/shallow", forged_boundary + "\n"),
                "grafts": (
                    distance_three / ".git/info/grafts",
                    _git_run(
                        distance_three, ["rev-parse", "HEAD^"],
                        text=True, check=True,
                    ).stdout.strip() + " " + S_COMMIT + "\n",
                ),
            }
            for metadata_kind, (metadata_path, metadata_payload) in local_metadata_cases.items():
                with self.subTest(local_history_metadata=metadata_kind):
                    metadata_path.parent.mkdir(parents=True, exist_ok=True)
                    metadata_path.write_text(metadata_payload, encoding="ascii")
                    try:
                        with self.assertRaisesRegex(
                            AssertionError, "shallow|graft",
                        ):
                            _assert_canonical_history_metadata(distance_three)
                        raw_count = _git_run(
                            distance_three,
                            ["rev-list", "--count", f"{S_COMMIT}..HEAD"],
                            text=True,
                        )
                        self.assertEqual(0, raw_count.returncode, raw_count.stderr)
                        self.assertEqual("2", raw_count.stdout.strip())
                        last_change = _git_run(
                            distance_three,
                            ["diff-tree", "--no-commit-id", "--name-only", "-r",
                             "HEAD^", "HEAD"], text=True, check=True,
                        )
                        self.assertEqual(P_LEDGER_PATH + "\n", last_change.stdout)
                        before_status = _git_run(
                            distance_three, ["status", "--porcelain=v1"],
                            text=True, check=True,
                        ).stdout
                        before_ledger = (
                            distance_three / P_LEDGER_PATH
                        ).read_bytes()
                        rejected = _python_run(
                            distance_three,
                            ["-B", "-m", "unittest", "-v",
                             "test_cases.test_public_publication_workflow."
                             "PublicPublicationWorkflowTests."
                             "test_p_phase_exact_commit_runs_catalog_in_private_free_clone"],
                            timeout=240, dependency_archive=dependency_archive,
                        )
                        self.assertNotEqual(0, rejected.returncode)
                        self.assertEqual(
                            before_status,
                            _git_run(
                                distance_three, ["status", "--porcelain=v1"],
                                text=True, check=True,
                            ).stdout,
                        )
                        self.assertEqual(
                            before_ledger,
                            (distance_three / P_LEDGER_PATH).read_bytes(),
                        )
                    finally:
                        metadata_path.unlink(missing_ok=True)

            for metadata_kind, (metadata_path, metadata_payload) in local_metadata_cases.items():
                with self.subTest(transient_history_metadata=metadata_kind):
                    events = []

                    def inject_history_metadata(event, repository, **_authority):
                        self.assertEqual(distance_three, repository)
                        if event == "after-metadata-check":
                            metadata_path.parent.mkdir(parents=True, exist_ok=True)
                            metadata_path.write_text(metadata_payload, encoding="ascii")
                            events.append("injected")
                            self.assertEqual(
                                3,
                                _raw_p_lineage_distance(
                                    distance_three,
                                    _head(distance_three),
                                ),
                                "raw commit parent headers must ignore shallow/graft metadata",
                            )
                        elif event == "after-raw-lineage":
                            self.assertTrue(os.path.lexists(metadata_path))
                            metadata_path.unlink()
                            events.append("removed")

                    with mock.patch.object(
                        sys.modules[__name__], "ROOT", distance_three,
                    ), mock.patch.object(
                        sys.modules[__name__], "_history_observer",
                        side_effect=inject_history_metadata,
                    ), self.assertRaises(AssertionError):
                        self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
                    self.assertEqual(["injected", "removed"], events)
                    self.assertFalse(os.path.lexists(metadata_path))

            with self.subTest(corrupt_loose_commit_object_is_rejected=True):
                corrupt_history = base / "corrupt-loose-commit"
                _git_run(
                    distance_three,
                    ["clone", "--quiet", "--no-local", str(distance_three),
                     str(corrupt_history)], check=True,
                )
                make_clone_loose_only(corrupt_history, "corrupt-commit")
                corrupt_head = _head(corrupt_history)
                original_commit = _git_run(
                    corrupt_history, ["cat-file", "commit", corrupt_head], check=True,
                ).stdout
                parent_match = re.search(rb"(?m)^parent ([0-9a-f]{40})$", original_commit)
                self.assertIsNotNone(parent_match)
                old_parent = parent_match.group(1)
                replacement_digit = b"0" if old_parent[:1] != b"0" else b"1"
                corrupt_commit = original_commit.replace(
                    b"parent " + old_parent,
                    b"parent " + replacement_digit + old_parent[1:],
                    1,
                )
                self.assertEqual(len(original_commit), len(corrupt_commit))
                loose_object = (
                    corrupt_history / ".git/objects" / corrupt_head[:2] / corrupt_head[2:]
                )
                loose_metadata = loose_object.lstat()
                self.assertTrue(stat.S_ISREG(loose_metadata.st_mode))
                self.assertEqual(1, loose_metadata.st_nlink)
                _write_loose_object_fixture(
                    corrupt_history, corrupt_head, "commit", corrupt_commit,
                )
                replaced_metadata = loose_object.lstat()
                self.assertEqual(
                    (loose_metadata.st_dev, loose_metadata.st_ino),
                    (replaced_metadata.st_dev, replaced_metadata.st_ino),
                )
                self.assertTrue(stat.S_ISREG(replaced_metadata.st_mode))
                self.assertEqual(1, replaced_metadata.st_nlink)
                permissive = _git_run(
                    corrupt_history, ["cat-file", "commit", corrupt_head],
                )
                self.assertEqual(0, permissive.returncode, permissive.stderr)
                self.assertEqual(corrupt_commit, permissive.stdout)
                with self.assertRaisesRegex(AssertionError, "object id"):
                    _raw_commit_parents(corrupt_history, corrupt_head)
                ledger_before = (corrupt_history / P_LEDGER_PATH).read_bytes()
                status_before = _git_run(
                    corrupt_history, ["status", "--porcelain=v1"], text=True,
                ).stdout
                runner_calls = []

                def reject_runner_after_commit_corruption(*_args, **_kwargs):
                    runner_calls.append(True)
                    raise AssertionError("runner reached corrupt commit object")

                with mock.patch.object(
                    sys.modules[__name__], "ROOT", corrupt_history,
                ), mock.patch.object(
                    sys.modules[__name__], "_python_run",
                    side_effect=reject_runner_after_commit_corruption,
                ), self.assertRaisesRegex(AssertionError, "object id"):
                    self.test_p_phase_exact_commit_runs_catalog_in_private_free_clone()
                self.assertEqual([], runner_calls)
                self.assertEqual(
                    status_before,
                    _git_run(
                        corrupt_history, ["status", "--porcelain=v1"], text=True,
                    ).stdout,
                )
                self.assertEqual(
                    ledger_before, (corrupt_history / P_LEDGER_PATH).read_bytes(),
                )


if __name__ == "__main__":
    unittest.main()
