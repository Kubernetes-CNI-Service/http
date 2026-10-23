#!/usr/bin/env python3
"""Direct and workflow contracts for the optional one-project Docker image."""

from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import tracemalloc
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

from test_cases.project_image_owned_guard_outer import (
    HeldGuardInputs, borrowed_snapshot_path, parent_launch_boundary,
)


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
PROJECT_IMAGE_PATH = TOOLS / "package-project-image.py"
UPLOAD_PATH = TOOLS / "tar-for-upload.py"
UPLOAD_INSTALLER_PATH = TOOLS / "deploy-upload-archive.py"
GUARD_PATH = TOOLS / "deployment_prewrite_guard.py"
SHARED_PACKAGER_PATH = TOOLS / "package-shared-artifacts.py"
SHARED_INSTALLER_PATH = TOOLS / "deploy-shared-artifacts.py"
LOAD_PATH = ROOT / "DAY0-Prepare/11-load.py"
BOOTSTRAP_TOOLS = {
    "package-project-image.py": PROJECT_IMAGE_PATH,
    "deploy-upload-archive.py": UPLOAD_INSTALLER_PATH,
    "deploy-shared-artifacts.py": SHARED_INSTALLER_PATH,
}
BOOTSTRAP_LABELS = {
    "package-project-image.py": (
        "com.nvidia.http-ztp.project-bootstrap-package-sha256"
    ),
    "deploy-upload-archive.py": (
        "com.nvidia.http-ztp.project-bootstrap-upload-sha256"
    ),
    "deploy-shared-artifacts.py": (
        "com.nvidia.http-ztp.project-bootstrap-shared-sha256"
    ),
}


def create_public_bootstrap_directory_fixture(path: Path) -> None:
    """Make a public positive premise before any deliberate metadata attack."""
    path.mkdir(mode=0o755)
    path.chmod(0o755)


def bootstrap_tool_hashes() -> dict[str, str]:
    return {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in BOOTSTRAP_TOOLS.items()
    }


SHARED_GLOBAL = b"""\
schema_version: 1
common:
  mgmt:
    dhcp-server: {status: enabled, package: isc-dhcp-server}
    http: {status: enabled, address: 192.0.2.10, package: apache2, http_root: /var/www/html}
    ztp: {status: enabled, ztp_url_prefix: /ztp}
  switch:
    system: {dns: [], ntp: [], date-time: {}}
switches:
  - eth: {version: 5.18.1}
  - ib: {version: 25.03.1010}
  - nvl: {version: 25.02.4282}
"""
SHARED_DEVICES = (
    b"hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
    b"eth1_ip,netmask,eth1_gw,eth1_mac\n"
    b"AIR-leaf01,air,oob,192.0.2.14,255.255.255.0,192.0.2.1,"
    b"02:00:00:00:00:14,,,,\n"
)


def load_module(name: str, path: Path):
    if not path.is_file():
        raise AssertionError(f"required production script is missing: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def add_bytes(archive: tarfile.TarFile, name: str, payload: bytes, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = mode
    archive.addfile(info, io.BytesIO(payload))


def write_upload_archive(
    path: Path, project="customer", *,
    global_payload: bytes = b"schema_version: 2\n",
    devices_payload: bytes = b"hostname,type\nleaf01,eth\n",
) -> bytes:
    installer = UPLOAD_INSTALLER_PATH.read_bytes()
    guard = GUARD_PATH.read_bytes()
    records = [
        {
            "path": "tools/deploy-upload-archive.py", "type": "file",
            "target": None, "sha256": hashlib.sha256(installer).hexdigest(),
        },
        {
            "path": "tools/deployment_prewrite_guard.py", "type": "file",
            "target": None, "sha256": hashlib.sha256(guard).hexdigest(),
        },
    ]
    manifest = (json.dumps(
        {"schema_version": 1, "files": records}, sort_keys=True,
    ) + "\n").encode("ascii")
    members = {
        "./tools/deploy-upload-archive.py": installer,
        "./tools/deployment_prewrite_guard.py": guard,
        "./infra/docker/deployment-source-manifest.json": manifest,
        f"./DAY0-Prepare/{project}/01-global.yaml": global_payload,
        f"./DAY0-Prepare/{project}/02-devices_config.csv": devices_payload,
        f"./DAY0-Prepare/{project}/02-dhcp-subnet_config.csv": b"subnet,netmask\n192.0.2.0,255.255.255.0\n",
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in members.items():
            add_bytes(
                archive, name, payload,
                0o500 if name.endswith("deploy-upload-archive.py") else 0o644,
            )
    path.chmod(0o600)
    return manifest


def write_upload_bundle(
    base: Path, project="customer", *,
    global_payload: bytes = b"schema_version: 2\n",
    devices_payload: bytes = b"hostname,type\nleaf01,eth\n",
) -> tuple[Path, bytes]:
    upload = load_module("project_image_upload_builder", UPLOAD_PATH)
    archive = base / "source.tar.gz"
    manifest = write_upload_archive(
        archive, project,
        global_payload=global_payload, devices_payload=devices_payload,
    )
    destination = base / "upload-release"
    upload.publish_relay_bundle(
        destination,
        archive,
        project_name=project,
        runtime="docker",
        expected_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        installer_path=UPLOAD_INSTALLER_PATH,
    )
    return destination.resolve(), manifest


def write_shared_bundle(
    base: Path, *, project="customer",
    global_payload: bytes = SHARED_GLOBAL,
    devices_payload: bytes = SHARED_DEVICES,
    no_upgrade: bool = False,
):
    packager = load_module("project_image_shared_packager", SHARED_PACKAGER_PATH)
    repository = base / "shared-repository"
    project_path = repository / "DAY0-Prepare" / project
    project_path.mkdir(parents=True)
    (repository / "image").mkdir()
    (repository / "apps").mkdir()
    (repository / "firmware").mkdir()
    (project_path / "01-global.yaml").write_bytes(global_payload)
    (project_path / "02-devices_config.csv").write_bytes(devices_payload)
    image = repository / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
    image.write_bytes(b"#!/bin/sh\n" + b"x" * (1024 * 1024))
    image.chmod(0o644)
    firmware = ()
    if no_upgrade:
        firmware_path = repository / "firmware/card/fw.bin"
        firmware_path.parent.mkdir(parents=True)
        firmware_path.write_bytes(b"firmware\n")
        firmware_path.chmod(0o644)
        firmware = (Path("firmware/card/fw.bin"),)
    return packager.build_bundle(
        project,
        output=repository / "outputs/artifacts/shared",
        repository_root=repository,
        deployment_scope="air",
        no_upgrade=no_upgrade,
        firmware=firmware,
        installer_path=SHARED_INSTALLER_PATH,
        load_script_path=LOAD_PATH,
    )


def write_bundled_payload(
    base: Path, upload_bundle: Path, *, shared_bundle: Path | None = None,
    upgrade_policy: str = "enabled",
) -> Path:
    """Materialize the exact payload shape copied into a project image."""
    base.mkdir(parents=True, exist_ok=True)
    bundled = base / "bundled-project"
    bundled.mkdir(mode=0o700)
    for name, source_bundle in (
        ("upload", upload_bundle), ("shared", shared_bundle),
    ):
        if source_bundle is None:
            continue
        destination_bundle = bundled / name
        destination_bundle.mkdir(mode=0o700)
        for source in source_bundle.iterdir():
            destination = destination_bundle / source.name
            destination.write_bytes(source.read_bytes())
            destination.chmod(stat.S_IMODE(source.stat().st_mode))
    if shared_bundle is not None:
        upgrade_policy = json.loads(
            (shared_bundle / "artifact-metadata.json").read_text(encoding="ascii"),
        )["upgrade_policy"]
    payload = {
        "artifact_type": "http-ztp-project-image-payload",
        "schema_version": 1,
        "image_contract": "3",
        "project": "customer",
        "upload_bundle": "upload",
        "shared_bundle": "shared" if shared_bundle is not None else None,
        "upgrade_policy": upgrade_policy,
        "bootstrap_tools": bootstrap_tool_hashes(),
    }
    (bundled / "project-payload.json").write_text(
        json.dumps(payload, sort_keys=True) + "\n", encoding="ascii",
    )
    (bundled / "project-payload.json").chmod(0o600)
    return bundled


# 2026-10-23 owner load->collection: the guard's monitor flag allow-list gained --request-collection-on-complete (guard was 46af60b5b4ed…, bootstrap cd1802da5725…).
OWNED_NATIVE_GUARD_BOOTSTRAP_SHA256 = '79f0c06d882ae3d337a26b27f944566731c3f6964ccad80e028a03e74202802d'
OWNED_NATIVE_GUARD_SOURCE_SHA256 = '0b293410b466ce5fd41d63faa51b9843b7adec42b1379eca292fc17a0171ad33'
OWNED_NATIVE_GUARD_BOOTSTRAP_SOURCE = r'''# SOURCE-ONLY TEST BOOTSTRAP. NOT INSTALLED, IMPORTED OR EXECUTED.
# The parent test supplies a separately frozen literal bootstrap SHA.
import builtins
import hashlib
import importlib.abc
import importlib.util
import inspect
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

GUARD_SHA256 = '0b293410b466ce5fd41d63faa51b9843b7adec42b1379eca292fc17a0171ad33'
MODULE_NAME = '_test_owned_complete_verified_guard'
FILE_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
               'st_size', 'st_mtime_ns', 'st_ctime_ns')
RAW_CLOSE = os.close
FACTS = dict(main_calls=0, archive_calls=0, archive_delegates=0,
             quiesce_calls=0, quiesce_delegates=0, stop_calls=0, stop_delegates=0,
             state_owned=[], proc_owned=[], quiesce_results=[], stop_empty=[],
             forbidden=[], closed=[], cleanup_errors=[], restored=[],
             initial_guard_main_reached=False, original_domain_argv=False)

class IsolationHold(RuntimeError):
    pass

def require(value, label):
    if not value:
        raise IsolationHold(label)

def directory_key(value):
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode),
            value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode))

def file_key(value):
    return tuple(str(getattr(value, name)) for name in FILE_FIELDS)

class HeldFixture:
    # Only these fixed fixture sources/parents are owned; never the archive FD.
    def __init__(self):
        self.directories = {}
        self.files = []
        self.order = []
    def directory(self, path, mode=None):
        path = Path(path)
        require(path.is_absolute() and '..' not in path.parts and len(path.parts) < 64,
                'fixture directory spelling')
        if path not in self.directories:
            parent = None if path == Path('/') else self.directory(path.parent)
            before = os.lstat(path) if parent is None else os.stat(
                path.name, dir_fd=parent['fd'], follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode), 'fixture directory type')
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            fd = os.open(str(path) if parent is None else path.name, flags,
                         **({} if parent is None else {'dir_fd': parent['fd']}))
            record = dict(fd=fd, path=path, key=directory_key(before), parent=parent,
                          kind='directory', closed=False)
            self.order.append(record)  # acquisition registered before post-open fstat
            require(directory_key(os.fstat(fd)) == record['key'], 'fixture directory FD')
            self.directories[path] = record
        record = self.directories[path]
        if mode is not None:
            require(record['key'][3] == os.geteuid() and record['key'][5] == mode,
                    'fixture directory owner/mode')
        return record
    def file(self, path, expected_sha):
        path = Path(path);parent = self.directory(path.parent, 0o700)
        before = os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600
                and 0 < before.st_size <= 524288, 'fixed fixture file metadata')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent['fd'])
        record = dict(fd=fd, path=path, key=file_key(before), parent=parent,
                      kind='file', closed=False)
        self.order.append(record)
        require(file_key(os.fstat(fd)) == record['key'], 'fixed fixture file FD')
        raw = os.pread(fd, 524289, 0)
        require(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == expected_sha,
                'fixed fixture source pin')
        record['raw'] = raw;self.files.append(record)
        self.verify()
        return record
    def verify(self):
        for record in self.order:
            current = os.fstat(record['fd'])
            parent = record['parent']
            named = os.lstat(record['path']) if parent is None else os.stat(
                record['path'].name, dir_fd=parent['fd'], follow_symlinks=False)
            key = directory_key if record['kind'] == 'directory' else file_key
            require(key(current) == record['key'] == key(named), 'held original changed')
            if record['kind'] == 'file':
                require(os.pread(record['fd'], 524289, 0) == record['raw'], 'held source bytes')
    def close(self):
        errors = []
        for record in reversed(self.order):
            try:
                key = directory_key if record['kind'] == 'directory' else file_key
                require(key(os.fstat(record['fd'])) == record['key'], 'cleanup original UNKNOWN')
                RAW_CLOSE(record['fd']);record['closed'] = True
                FACTS['closed'].append(record['kind'])
            except BaseException as error:
                errors.append(error)  # UNKNOWN slot is never adopted or blindly closed
        return errors

def select_primary(primary, errors):
    if primary is not None and not isinstance(primary, Exception):
        return primary
    return next((error for error in errors if not isinstance(error, Exception)),
                primary if primary is not None else (errors[0] if errors else None))

def run():
    held = HeldFixture();primary = None;cleanup = [];patches = []
    result = 2;binding = None
    def patch(obj, name, replacement):
        original = getattr(obj, name)
        patches.append((obj, name, original));setattr(obj, name, replacement)
        return original
    def deny(label):
        def reject(*args, **kwargs):
            FACTS['forbidden'].append(label)
            raise IsolationHold('test child forbidden ' + label)
        return reject
    try:
        binding = json.loads(os.environ['HTTP_TEST_GUARD_BINDING'])
        require(set(binding) == {'parent', 'root', 'directory', 'bootstrap_sha256',
                'guard_sha256', 'archive_key', 'domain_argv', 'phase'}, 'fixed binding fields')
        require(binding['phase'] in ('OBSERVE_DEFAULTS', 'OWNED_PARAMETERS'), 'fixed phase')
        require(binding['guard_sha256'] == GUARD_SHA256, 'fixed original guard pin')
        parent = Path(binding['parent']);root = Path(binding['root'])
        directory = Path(binding['directory'])
        require(root == parent/'live' and directory.parent == parent
                and directory.name.startswith('owned-native-guard.'), 'fixed local namespace')
        require(sys.argv[0] == '-c', 'fixed literal bootstrap activation')
        held.directory(parent, 0o700);held.directory(root, 0o755)
        held.directory(directory, 0o700)
        state, proc, temporary, emptybin = (directory/name for name in ('state', 'proc', 'tmp', 'bin'))
        for path in (state, proc, temporary, emptybin):
            held.directory(path, 0o700)
            require(list(path.iterdir()) == [], 'fixture directory must start empty')
        held.file(directory/'bootstrap.py', binding['bootstrap_sha256'])
        guard = held.file(directory/'verified-guard.py', GUARD_SHA256)
        domain = tuple(sys.argv[1:])
        require(list(domain) == binding['domain_argv'], 'original domain argv changed')
        FACTS['original_domain_argv'] = True
        for flag in ('--root', '--lock', '--runtime', '--archive-fd',
                     '--archive-sha256', '--source-manifest-sha256'):
            require(domain.count(flag) == 1, 'fixed original argv multiplicity')
        value = lambda flag: domain[domain.index(flag)+1]
        require(Path(value('--root')) == root and Path(value('--lock')) == root/'.deployment.lock'
                and value('--runtime') == 'native' and '--archive' not in domain, 'fixed original argv')
        archive_fd = int(value('--archive-fd'));first = os.fstat(archive_fd)
        require(file_key(first) == tuple(binding['archive_key']) and stat.S_ISREG(first.st_mode)
                and first.st_uid == os.geteuid() and first.st_nlink == 1
                and stat.S_IMODE(first.st_mode) == 0o600, 'original inherited snapshot identity')
        digest = hashlib.sha256();offset = 0
        while offset < first.st_size:
            block = os.pread(archive_fd, min(65536, first.st_size-offset), offset)
            require(bool(block), 'original snapshot truncated');digest.update(block);offset += len(block)
        require(digest.hexdigest() == value('--archive-sha256')
                and file_key(os.fstat(archive_fd)) == tuple(binding['archive_key']),
                'original snapshot digest')
        require(Path(tempfile.gettempdir()) == temporary, 'owned child tempfile selection')
        def audit(event, args):
            if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system',
                    'os.posix_spawn', 'os.posix_spawnp', 'os.fork', 'os.forkpty',
                    'os.kill', 'os.killpg', 'os.chown', 'os.fchown'):
                deny(event)()
        sys.addaudithook(audit)
        for obj, name in ((os, 'kill'), (os, 'waitpid'), (os, 'system'),
                          (os, 'chown'), (os, 'fchown'),
                          (subprocess, 'Popen'), (subprocess, 'run'),
                          (threading.Thread, '__init__'), (threading.Thread, 'start')):
            patch(obj, name, deny(name))
        def outside_system(path):
            if isinstance(path, (str, bytes, os.PathLike)):
                parts = Path(os.fsdecode(path)).parts
                return (parts[:2] == ('/', 'proc')
                        or parts[:4] == ('/', 'var', 'lib', 'http-ztp-container')
                        or parts[:5] == ('/', 'private', 'var', 'lib', 'http-ztp-container'))
            return False
        for name in ('open', 'stat', 'lstat', 'listdir', 'scandir', 'access'):
            original = getattr(os, name)
            def wrapped(path, *args, _original=original, **kwargs):
                if outside_system(path):deny('system-state-or-proc')()
                return _original(path, *args, **kwargs)
            patch(os, name, wrapped)
        original_builtin_open = builtins.open
        def safe_open(path, *args, **kwargs):
            if outside_system(path):deny('system-state-or-proc')()
            return original_builtin_open(path, *args, **kwargs)
        patch(builtins, 'open', safe_open)
        class WholeHeldGuardLoader(importlib.abc.SourceLoader):
            def get_filename(self, fullname):
                require(fullname == MODULE_NAME, 'fixed guard module');return str(guard['path'])
            def get_data(self, path):
                require(path == str(guard['path']), 'no alternate module/cache source')
                held.verify();return guard['raw']
        loader = WholeHeldGuardLoader()
        spec = importlib.util.spec_from_loader(MODULE_NAME, loader)
        module = importlib.util.module_from_spec(spec);loader.exec_module(module)
        original_main = module.main
        original_archive = module.run_locked_archive
        original_quiesce = module.quiesce_for_source_update
        original_stop = module.stop_native_ztp_monitors
        def archive(*args, **kwargs):
            FACTS['archive_calls'] += 1
            parameters = inspect.signature(original_archive).bind(*args, **kwargs)
            parameters.apply_defaults()
            require(parameters.arguments['http_root'] == root
                    and parameters.arguments['_archive_fd'] == archive_fd
                    and parameters.arguments['_ownership_target'] == (0, 0), 'original archive arguments')
            if binding['phase'] == 'OWNED_PARAMETERS':kwargs['state_root'] = state
            FACTS['archive_delegates'] += 1
            return original_archive(*args, **kwargs)
        def quiesce(*args, **kwargs):
            FACTS['quiesce_calls'] += 1
            parameters = inspect.signature(original_quiesce).bind(*args, **kwargs)
            parameters.apply_defaults();owned = parameters.arguments['state_root'] == state
            FACTS['state_owned'].append(owned)
            if not owned:raise module.GuardError('test isolation refused nonowned state before IO')
            require(parameters.arguments['http_root'] == root
                    and parameters.arguments['native_requested'] is True
                    and parameters.arguments['docker_requested'] is False, 'original quiesce arguments')
            held.verify();kwargs['runner'] = deny('Docker-runner')
            kwargs['which'] = lambda name: shutil.which(name, path=str(emptybin))
            FACTS['quiesce_delegates'] += 1
            result = original_quiesce(*args, **kwargs)
            FACTS['quiesce_results'].append(result);require(result is False, 'unexpected managed Docker state')
            return result
        def stop(http_root):
            FACTS['stop_calls'] += 1;require(http_root == root, 'original monitor root')
            FACTS['proc_owned'].append(True);held.verify();FACTS['stop_delegates'] += 1
            result = original_stop(http_root, proc_root=proc, kill=deny('monitor-kill'))
            FACTS['stop_empty'].append(result == ());require(result == (), 'unexpected fixture monitor')
            return result
        patch(module, 'run_locked_archive', archive)
        patch(module, 'quiesce_for_source_update', quiesce)
        patch(module, 'stop_native_ztp_monitors', stop)
        held.verify();FACTS['initial_guard_main_reached'] = True;FACTS['main_calls'] += 1
        result = original_main(list(domain))  # original parser/main/domain argv, not a fake status
        require(type(result) is int, 'original main status unknown')
        held.verify()
        require(file_key(os.fstat(archive_fd)) == tuple(binding['archive_key']), 'snapshot after guard')
    except BaseException as error:
        primary = error
    finally:
        for obj, name, original in reversed(patches):
            try:
                setattr(obj, name, original);FACTS['restored'].append(getattr(obj, name) is original)
            except BaseException as error:cleanup.append(error)
        cleanup.extend(held.close())
        FACTS['cleanup_errors'] = [type(error).__name__ for error in cleanup]
        FACTS['main_returncode'] = result
        FACTS['owned_originals'] = len(held.order)
        FACTS['all_owned_closed'] = all(record['closed'] for record in held.order)
        FACTS['primary_type'] = type(primary).__name__ if primary is not None else None
        try:
            print('OWNED_GUARD_FACTS ' + json.dumps(FACTS, sort_keys=True), flush=True)
        except BaseException as error:
            cleanup.append(error)  # no log failure may cover an original NI
    selected = select_primary(primary, cleanup)
    if selected is not None:
        if selected is not primary and primary is not None and selected.__cause__ is None:
            raise selected from primary
        raise selected
    return result if not cleanup else 2

if __name__ == '__main__':
    raise SystemExit(run())
'''

def trusted_installer_loader_for_workflow(
    tool, *, owned_parent: Path, fail_upload_guard_times: int = 0,
    isolation_phase: str = 'OWNED_PARAMETERS',
):
    """Test-only full guard child, exact held source, owned state/proc only."""
    original_loader = tool._load_module
    owned_parent = Path(owned_parent)
    parent = owned_parent.lstat()
    if (owned_parent.resolve(strict=True) != owned_parent or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700):
        raise AssertionError('explicit owned fixture parent required')
    if isolation_phase not in ('OBSERVE_DEFAULTS', 'OWNED_PARAMETERS'):
        raise AssertionError('unknown fixed test phase')
    if hashlib.sha256(OWNED_NATIVE_GUARD_BOOTSTRAP_SOURCE.encode()).hexdigest() != OWNED_NATIVE_GUARD_BOOTSTRAP_SHA256:
        raise AssertionError('bootstrap differs from independently frozen literal pin')
    state = dict(upload_guard_calls=0, shared_staging_parents=[], upload_staging_parents=[],
                 upload_guard_environments=[], actual_child_receipts=[])
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    file_key = lambda value: tuple(str(getattr(value, field)) for field in fields)
    physical = lambda value: (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_uid, value.st_gid)
    def choose(primary, errors):
        if primary is not None and not isinstance(primary, Exception):return primary
        return next((error for error in errors if not isinstance(error, Exception)),
                    primary if primary is not None else (errors[0] if errors else None))
    def loader(name, path, **kwargs):
        module = original_loader(name, path, **kwargs)
        canonical = Path(path).resolve()
        if canonical == SHARED_INSTALLER_PATH.resolve():
            original_deploy = module.deploy_archive
            def deploy_shared(*args, **kwargs):
                state['shared_staging_parents'].append(kwargs.get('staging_parent'))
                return original_deploy(*args, **kwargs)
            module.deploy_archive = deploy_shared
        elif canonical == UPLOAD_INSTALLER_PATH.resolve():
            original_deploy = module.deploy_archive;original_guard = module.run_guard
            original_snapshot = module._private_archive_snapshot
            @contextmanager
            def held_original_snapshot(*args, **keywords):
                manager = original_snapshot(*args, **keywords)
                with manager as descriptor:
                    archive_path = borrowed_snapshot_path(
                        manager, original_snapshot, descriptor, owned_parent)
                    if state.get('borrowed_snapshot') is not None:
                        raise AssertionError('overlapping original snapshot context')
                    record = (descriptor, archive_path)
                    state['borrowed_snapshot'] = record
                    primary = None;errors = []
                    try:
                        yield descriptor
                    except BaseException as error:
                        primary = error
                    finally:
                        if state.get('borrowed_snapshot') is record:
                            state.pop('borrowed_snapshot')
                        else:
                            errors.append(AssertionError('original snapshot registration changed'))
                    selected = choose(primary, errors)
                    if selected is not None:
                        raise selected  # Preserve original object/cause; original context owns cleanup.
            module._private_archive_snapshot = held_original_snapshot
            def deploy_upload(*args, **kwargs):
                state['upload_staging_parents'].append(kwargs.get('staging_parent'))
                state['upload_guard_environments'].append(kwargs.get('guard_environment'))
                return original_deploy(*args, **kwargs)
            def run_native_guard(command, **kwargs):
                state['upload_guard_calls'] += 1
                if state['upload_guard_calls'] <= fail_upload_guard_times:
                    # Retain the existing explicit fault lane, not a fake success.
                    return SimpleNamespace(returncode=74, stdout=b'', stderr=b'injected upload failure')
                if set(kwargs) - {'env', 'archive_fd', 'timeout'}:
                    raise AssertionError('unknown original guard keyword')
                command = list(command)
                if command[:2] != [sys.executable, '-c']:
                    raise AssertionError('original fixed interpreter activation differs')
                guard_source = command[2].encode('utf-8')
                if hashlib.sha256(guard_source).hexdigest() != OWNED_NATIVE_GUARD_SOURCE_SHA256:
                    raise AssertionError('embedded source differs from frozen original guard')
                command[command.index('--runtime')+1] = 'native'  # existing test premise
                domain = command[3:]
                root = Path(domain[domain.index('--root')+1])
                if root != owned_parent/'live' or root.resolve(strict=True) != root:
                    raise AssertionError('guard root is not this explicit local fixture')
                if stat.S_IMODE(root.lstat().st_mode) != 0o755:
                    raise AssertionError('public root0755 premise not satisfied')
                archive_fd = module._guard_archive_fd(command, kwargs.get('archive_fd'))
                if type(archive_fd) is not int:
                    raise AssertionError('original inherited snapshot FD absent')
                archive_before = os.fstat(archive_fd)
                directory = Path(tempfile.mkdtemp(prefix='owned-native-guard.', dir=owned_parent))
                directory_before = directory.lstat();directory_fd = None
                primary = None;errors = [];result = None;source_records = []
                try:
                    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    if physical(os.fstat(directory_fd)) != physical(directory_before):
                        raise AssertionError('owned bootstrap directory identity')
                    for label in ('state', 'proc', 'tmp', 'bin'):
                        (directory/label).mkdir(mode=0o700)
                    def write_original(name, raw):
                        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=directory_fd)
                        key = None;body = None;cleanup = []
                        try:
                            value = os.fstat(fd);key = physical(value)
                            view = memoryview(raw)
                            while view:
                                count = os.write(fd, view)
                                if count <= 0:raise OSError('fixture source write made no progress')
                                view = view[count:]
                            os.fsync(fd)
                        except BaseException as error:body = error
                        finally:
                            try:
                                if key is None or physical(os.fstat(fd)) != key:
                                    raise AssertionError('source cleanup original FD UNKNOWN')
                                os.close(fd)
                            except BaseException as error:cleanup.append(error)
                        selected = choose(body, cleanup)
                        if selected is not None:
                            if selected is not body and body is not None and selected.__cause__ is None:
                                raise selected from body
                            raise selected
                    write_original('bootstrap.py', OWNED_NATIVE_GUARD_BOOTSTRAP_SOURCE.encode())
                    write_original('verified-guard.py', guard_source)
                    os.fsync(directory_fd)
                    for name, expected in (('bootstrap.py', OWNED_NATIVE_GUARD_BOOTSTRAP_SHA256),
                            ('verified-guard.py', OWNED_NATIVE_GUARD_SOURCE_SHA256)):
                        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                        row = dict(fd=fd, name=name, key=file_key(before), expected=expected)
                        source_records.append(row)
                        if (file_key(os.fstat(fd)) != row['key'] or hashlib.sha256(
                                os.pread(fd, 524289, 0)).hexdigest() != expected):
                            raise AssertionError('parent held source differs from literal pin')
                    binding = dict(parent=str(owned_parent), root=str(root), directory=str(directory),
                        bootstrap_sha256=OWNED_NATIVE_GUARD_BOOTSTRAP_SHA256,
                        guard_sha256=OWNED_NATIVE_GUARD_SOURCE_SHA256,
                        archive_key=list(file_key(archive_before)), domain_argv=domain,
                        phase=isolation_phase)
                    environment = {'PATH':str(directory/'bin'), 'TMPDIR':str(directory/'tmp'),
                        'PYTHONDONTWRITEBYTECODE':'1',
                        'HTTP_TEST_GUARD_BINDING':json.dumps(binding, sort_keys=True)}
                    # Execute the parent's fixed literal, not a raceable named source.
                    # The -c program changes; the original guard-domain argv is intact.
                    activated = [command[0], '-I', '-S', '-B', '-c', OWNED_NATIVE_GUARD_BOOTSTRAP_SOURCE, *domain]
                    if 'timeout' in kwargs and kwargs['timeout'] != 5:
                        raise AssertionError('fixed original guard API timeout5 required')
                    snapshot = state.get('borrowed_snapshot')
                    if (type(snapshot) is not tuple or len(snapshot) != 2
                            or snapshot[0] != archive_fd):
                        raise AssertionError('original staged snapshot yield not retained')
                    authority = HeldGuardInputs(parent=owned_parent, directory=directory,
                        directory_fd=directory_fd, archive=snapshot[1], archive_fd=archive_fd)
                    with parent_launch_boundary(authority) as activate:
                        activate.bind_helper(run_native_guard.__code__)
                        result = activate(original_guard, activated,
                            env=environment, archive_fd=archive_fd, timeout=5)
                    # No fabricated CompletedProcess/returncode: this is the original Popen result.
                    lines = [line.partition(b'OWNED_GUARD_FACTS ')[2] for line in result.stdout.splitlines()
                             if line.startswith(b'OWNED_GUARD_FACTS ')]
                    if len(lines) != 1:raise AssertionError('original child final receipt absent')
                    facts = json.loads(lines[0]);state['actual_child_receipts'].append(facts)
                    if (not facts['initial_guard_main_reached'] or not facts['original_domain_argv']
                            or facts['main_calls'] != 1 or facts['archive_delegates'] != 1
                            or facts['forbidden'] or facts['cleanup_errors']
                            or not facts['all_owned_closed'] or not facts['restored']
                            or not all(facts['restored'])):
                        raise AssertionError('original child isolation/cleanup not proved')
                    if result.returncode == 0 and (facts['main_returncode'] != 0
                            or facts['primary_type'] is not None):
                        raise AssertionError('child success is not original main success')
                    if isolation_phase == 'OWNED_PARAMETERS' and (
                            facts['state_owned'] != [True] or facts['proc_owned'] != [True]
                            or facts['quiesce_results'] != [False] or facts['stop_empty'] != [True]
                            or facts['quiesce_delegates'] != 1 or facts['stop_delegates'] != 1):
                        raise AssertionError('original quiesce/stop owned delegation absent')
                    if file_key(os.fstat(archive_fd)) != file_key(archive_before):
                        raise AssertionError('original parent snapshot changed')
                    for row in source_records:
                        if (file_key(os.fstat(row['fd'])) != row['key']
                                or file_key(os.stat(row['name'], dir_fd=directory_fd,
                                    follow_symlinks=False)) != row['key']
                                or hashlib.sha256(os.pread(row['fd'], 524289, 0)).hexdigest() != row['expected']):
                            raise AssertionError('parent held source changed during actual guard')
                except BaseException as error:primary = error
                finally:
                    for row in reversed(source_records):
                        try:
                            if file_key(os.fstat(row['fd'])) != row['key']:
                                raise AssertionError('parent source FD cleanup UNKNOWN')
                            os.close(row['fd'])
                        except BaseException as error:errors.append(error)
                    if directory_fd is not None:
                        try:
                            if physical(os.fstat(directory_fd)) != physical(directory_before):
                                raise AssertionError('bootstrap directory FD cleanup UNKNOWN')
                            os.close(directory_fd)
                        except BaseException as error:errors.append(error)
                    try:
                        if physical(directory.lstat()) != physical(directory_before):
                            raise AssertionError('bootstrap directory cleanup UNKNOWN')
                        shutil.rmtree(directory)
                    except BaseException as error:errors.append(error)
                selected = choose(primary, errors)
                if selected is not None:
                    if selected is not primary and primary is not None and selected.__cause__ is None:
                        raise selected from primary
                    raise selected
                return result
            module.run_guard = run_native_guard;module.deploy_archive = deploy_upload
        return module
    return loader, state


class ProjectImageBundleTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_module("project_image_bundle_contract", PROJECT_IMAGE_PATH)

    def test_public_bootstrap_fixture_modes_are_explicit_under_private_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "live"
            previous = os.umask(0o077)
            try:
                create_public_bootstrap_directory_fixture(root)
                for name in ("image", "apps", "firmware"):
                    create_public_bootstrap_directory_fixture(root / name)
                for path in (root, root / "image", root / "apps", root / "firmware"):
                    with self.subTest(path=path.name):
                        self.assertEqual(0o755, stat.S_IMODE(path.stat().st_mode))
            finally:
                os.umask(previous)

    def test_cli_separates_host_build_from_in_image_install(self):
        base_id = "sha256:" + "a" * 64
        build = self.tool.parser().parse_args([
            "build", "/root/customer-upload", "--base-image", base_id,
            "--output", "/root/customer-project-image",
        ])
        self.assertEqual("build", build.action)
        self.assertEqual(Path("/root/customer-upload"), build.upload_bundle)
        self.assertEqual(base_id, build.base_image)
        self.assertIsNone(build.shared_bundle)
        self.assertFalse(build.no_upgrade)
        no_upgrade = self.tool.parser().parse_args([
            "build", "/root/customer-upload", "--base-image", base_id,
            "--output", "/root/customer-project-image", "--no-upgrade",
        ])
        self.assertTrue(no_upgrade.no_upgrade)
        install = self.tool.parser().parse_args(["install", "--verify-only"])
        self.assertEqual("install", install.action)
        self.assertEqual(Path("/var/www/html"), install.root)
        self.assertTrue(install.verify_only)
        help_text = self.tool.parser().format_help()
        self.assertNotIn("--skip-verify", help_text)
        self.assertNotIn("--force", help_text)

    def test_public_build_and_install_options_explain_artifacts_and_effects(self):
        parser = self.tool.parser()
        subparsers = next(action for action in parser._actions if action.dest == "action")
        build = {action.dest: action for action in subparsers.choices["build"]._actions}
        install = {action.dest: action for action in subparsers.choices["install"]._actions}
        for destination, phrase in {
            "upload_bundle": "upload bundle",
            "base_image": "base image",
            "output": "export directory",
            "shared_bundle": "shared-artifact bundle",
        }.items():
            with self.subTest(action="build", destination=destination):
                self.assertIn(phrase, build[destination].help or "")
        for destination, phrase in {
            "root": "installation root",
            "verify_only": "without installing",
        }.items():
            with self.subTest(action="install", destination=destination):
                self.assertIn(phrase, install[destination].help or "")

    def test_shared_upgrade_policy_drives_the_only_supported_deploy_command(self):
        image_id = "sha256:" + "c" * 64
        for policy, expected_suffix in (
            ("enabled", image_id),
            ("disabled", image_id + " --no-upgrade"),
        ):
            result = self.tool.BuildResult(
                Path("/root/output"), "customer", image_id, "d" * 64,
                deployment_scope="air", switch_scope="eth", mini=True,
                upgrade_policy=policy,
            )
            stdout = io.StringIO()
            options = [
                "build", "/root/upload", "--base-image", "sha256:" + "b" * 64,
                "--shared-bundle", "/root/shared", "--output", "/root/output",
            ]
            if policy == "disabled":
                options.append("--no-upgrade")
            with self.subTest(policy=policy), \
                    mock.patch.object(os, "geteuid", return_value=0), \
                    mock.patch.object(
                        self.tool, "build_project_image", return_value=result,
                    ) as build_mock, redirect_stdout(stdout):
                self.assertEqual(0, self.tool.main(options))
            self.assertIs(policy == "disabled", build_mock.call_args.kwargs["no_upgrade"])
            deployment = next(
                line.strip() for line in stdout.getvalue().splitlines()
                if "deploy-project-preloaded" in line
            )
            self.assertTrue(deployment.endswith(expected_suffix), deployment)

    def test_machine_payload_exposes_all_label_bound_authorities(self):
        bootstrap = {
            "package-project-image.py": "a" * 64,
            "deploy-upload-archive.py": "b" * 64,
            "deploy-shared-artifacts.py": "c" * 64,
        }
        installed = self.tool.InstallResult(
            project="customer",
            upload_archive_sha256="d" * 64,
            source_manifest_sha256="e" * 64,
            shared_archive_sha256="f" * 64,
            bootstrap_tools=bootstrap,
            verify_only=True,
            upgrade_policy="disabled",
        )
        stdout = io.StringIO()
        with mock.patch.object(os, "geteuid", return_value=0), mock.patch.object(
            self.tool, "install_bundled_project", return_value=installed,
        ), redirect_stdout(stdout):
            self.assertEqual(0, self.tool.main([
                "install", "--verify-only", "--machine-readable",
            ]))
        self.assertEqual({
            "bootstrap_tools": bootstrap,
            "image_contract": "3",
            "project": "customer",
            "shared_archive_sha256": "f" * 64,
            "source_manifest_sha256": "e" * 64,
            "upload_archive_sha256": "d" * 64,
            "upgrade_policy": "disabled",
            "verified": True,
        }, json.loads(stdout.getvalue()))

    def test_build_policy_defaults_enabled_and_conflicts_with_shared_fail_closed(self):
        enabled = SimpleNamespace(metadata_value={"upgrade_policy": "enabled"})
        disabled = SimpleNamespace(metadata_value={"upgrade_policy": "disabled"})
        self.assertEqual("enabled", self.tool.resolve_upgrade_policy(None, False))
        self.assertEqual("disabled", self.tool.resolve_upgrade_policy(None, True))
        self.assertEqual("enabled", self.tool.resolve_upgrade_policy(enabled, False))
        self.assertEqual("disabled", self.tool.resolve_upgrade_policy(disabled, True))
        for shared, no_upgrade in ((enabled, True), (disabled, False)):
            with self.subTest(shared=shared.metadata_value, no_upgrade=no_upgrade), \
                    self.assertRaisesRegex(
                        self.tool.ProjectImageError, "upgrade policy.*shared",
                    ):
                self.tool.resolve_upgrade_policy(shared, no_upgrade)

    def test_upload_release_authority_drives_offline_project_dockerfile(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, manifest = write_upload_bundle(base)
            authority = self.tool.verify_upload_bundle(
                bundle, required_uid=os.getuid(),
            )
            self.assertEqual("customer", authority.project)
            self.assertEqual(
                hashlib.sha256(manifest).hexdigest(),
                authority.source_manifest_sha256,
            )
            base_id = "sha256:" + "b" * 64
            dockerfile = self.tool.render_project_dockerfile(
                base_id, authority, shared=None,
                upgrade_policy="enabled",
                bootstrap_tools=bootstrap_tool_hashes(),
            )
            self.assertIn(f"FROM {base_id}", dockerfile)
            self.assertIn('image-flavor="project"', dockerfile)
            self.assertIn('com.nvidia.http-ztp.image-contract="3"', dockerfile)
            self.assertIn('project="customer"', dockerfile)
            self.assertIn(authority.archive_sha256, dockerfile)
            self.assertIn(authority.source_manifest_sha256, dockerfile)
            self.assertIn('com.nvidia.http-ztp.upgrade-policy="enabled"', dockerfile)
            for name, digest in bootstrap_tool_hashes().items():
                self.assertIn(f'{BOOTSTRAP_LABELS[name]}="{digest}"', dockerfile)
            self.assertIn(
                "COPY bootstrap-tools/ /opt/http-ztp/project-bootstrap/tools/",
                dockerfile,
            )
            self.assertNotIn("/opt/http-ztp/source-tree/tools/", dockerfile)
            self.assertIn("COPY upload/ /opt/http-ztp/bundled-project/upload/", dockerfile)
            self.assertEqual(
                1,
                dockerfile.count(
                    "COPY upload/ /opt/http-ztp/bundled-project/upload/"
                ),
            )
            self.assertNotIn("apt-get", dockerfile)
            self.assertNotIn("curl", dockerfile)
            self.assertNotIn("ADD http", dockerfile)

    def test_private_authority_writer_publishes_the_payload_exactly_once(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "authority.json"
            payload = b'{"schema_version":1}\n'

            self.tool._private_write(target, payload)

            self.assertEqual(payload, target.read_bytes())
            self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))

    def test_bundle_directory_and_bootstrap_root_reject_symlink_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, _manifest = write_upload_bundle(base)
            bundle_alias = base / "upload-alias"
            bundle_alias.symlink_to(bundle, target_is_directory=True)
            with self.assertRaisesRegex(
                self.tool.ProjectImageError, "bundle directory",
            ):
                self.tool.verify_upload_bundle(
                    bundle_alias, required_uid=os.getuid(),
                )

            live = base / "live"
            live.mkdir(mode=0o755)
            live_alias = base / "live-alias"
            live_alias.symlink_to(live, target_is_directory=True)
            with self.assertRaisesRegex(
                self.tool.ProjectImageError, "bootstrap root",
            ):
                self.tool._fresh_bootstrap_root(
                    live_alias,
                )

    def test_every_authority_path_rejects_a_symlink_in_any_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            real = base / "real"
            real.mkdir(mode=0o700)
            upload, _manifest = write_upload_bundle(real)
            shared = write_shared_bundle(real / "shared-source")
            output_parent = real / "outputs"
            output_parent.mkdir(mode=0o700)
            live = real / "live"
            live.mkdir(mode=0o755)
            bundled = write_bundled_payload(real / "payload-source", upload)
            alias = base / "ancestor-alias"
            alias.symlink_to(real, target_is_directory=True)

            cases = {
                "upload bundle": lambda: self.tool.verify_upload_bundle(
                    alias / upload.relative_to(real), required_uid=os.getuid(),
                ),
                "shared bundle": lambda: self.tool.verify_shared_bundle(
                    alias / shared.output.relative_to(real), required_uid=os.getuid(),
                ),
                "output parent": lambda: self.tool._open_output_authority(
                    alias / "outputs/project-image", required_uid=os.getuid(),
                ),
                "live root": lambda: self.tool._safe_live_root(
                    alias / "live", required_uid=os.getuid(), require_fresh=True,
                ),
                "payload root": lambda: self.tool._safe_bundled_root(
                    alias / bundled.relative_to(real), required_uid=os.getuid(),
                ),
            }
            for label, operation in cases.items():
                with self.subTest(label=label), self.assertRaisesRegex(
                    self.tool.ProjectImageError, "symlink ancestor",
                ):
                    operation()

    def test_fresh_root_allowlist_has_strict_type_mode_owner_and_link_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "live"
            create_public_bootstrap_directory_fixture(root)
            for name in ("image", "apps", "firmware"):
                create_public_bootstrap_directory_fixture(root / name)
            lock = root / ".deployment.lock"
            lock.write_bytes(b"")
            lock.chmod(0o600)
            self.assertEqual(
                root,
                self.tool._safe_live_root(
                    root, required_uid=os.getuid(), require_fresh=True,
                ),
            )
            lock.chmod(0o644)
            self.assertEqual(
                root,
                self.tool._safe_live_root(
                    root, required_uid=os.getuid(), require_fresh=True,
                ),
            )
            lock.chmod(0o600)

            mutations = (
                ("image is a symlink", "image", "symlink"),
                ("apps is a regular file", "apps", "file"),
                ("firmware is group writable", "firmware", "mode"),
                ("lock is group writable", ".deployment.lock", "mode"),
                ("lock has a second hard link", ".deployment.lock", "hardlink"),
            )
            for label, name, mutation in mutations:
                with self.subTest(label=label):
                    candidate = base / ("case-" + mutation + "-" + name.strip("."))
                    create_public_bootstrap_directory_fixture(candidate)
                    for directory_name in ("image", "apps", "firmware"):
                        create_public_bootstrap_directory_fixture(candidate / directory_name)
                    candidate_lock = candidate / ".deployment.lock"
                    candidate_lock.write_bytes(b"")
                    candidate_lock.chmod(0o600)
                    target = candidate / name
                    if mutation == "symlink":
                        target.rmdir()
                        target.symlink_to(root / name, target_is_directory=True)
                    elif mutation == "file":
                        target.rmdir()
                        target.write_bytes(b"not a directory")
                        target.chmod(0o644)
                    elif mutation == "mode":
                        target.chmod(0o775 if target.is_dir() else 0o660)
                    else:
                        os.link(target, base / (candidate.name + "-second-lock-link"))
                    with self.assertRaisesRegex(
                        self.tool.ProjectImageError,
                        "fresh bootstrap member|deployment lock",
                    ):
                        self.tool._safe_live_root(
                            candidate,
                            required_uid=os.getuid(), require_fresh=True,
                        )

            path_type = type(root)
            original_lstat = path_type.lstat

            def wrong_owner(path):
                metadata = original_lstat(path)
                if path == root / "apps":
                    values = list(metadata)
                    values[4] = os.getuid() + 1
                    return os.stat_result(values)
                return metadata

            with mock.patch.object(path_type, "lstat", new=wrong_owner), \
                    self.assertRaisesRegex(
                        self.tool.ProjectImageError, "fresh bootstrap member",
                    ):
                self.tool._safe_live_root(
                    root, required_uid=os.getuid(), require_fresh=True,
                )

    def test_large_bundle_members_are_copied_with_bounded_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            source = base / "source"
            destination = base / "destination"
            source.mkdir(mode=0o700)
            large = source / "large-upload.tar.gz"
            with large.open("wb") as stream:
                stream.truncate(24 * 1024 * 1024)
            large.chmod(0o600)

            tracemalloc.start()
            try:
                self.tool._copy_bundle(
                    source,
                    destination,
                    required_uid=os.getuid(),
                )
                _current, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertLess(peak, 12 * 1024 * 1024)
            self.assertEqual(large.stat().st_size, (destination / large.name).stat().st_size)

    def test_upload_verifier_never_executes_an_untrusted_bundle_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, _manifest = write_upload_bundle(base)
            marker = base / "untrusted-installer-executed"
            installer = bundle / "deploy-upload-archive.py"
            installer.chmod(0o600)
            installer.write_text(
                "from pathlib import Path\n"
                f"Path({os.fspath(marker)!r}).write_text('executed')\n"
                "def verify_inputs(*args, **kwargs):\n"
                "    raise RuntimeError('untrusted installer ran')\n",
                encoding="ascii",
            )
            installer.chmod(0o500)
            metadata_path = bundle / "upload-metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata["installer"]["size"] = installer.stat().st_size
            metadata["installer"]["sha256"] = hashlib.sha256(
                installer.read_bytes(),
            ).hexdigest()
            metadata_path.write_text(
                json.dumps(metadata, sort_keys=True, indent=2) + "\n",
                encoding="ascii",
            )
            metadata_path.chmod(0o600)
            sums = {}
            for item in bundle.iterdir():
                if item.name != "SHA256SUMS":
                    sums[item.name] = hashlib.sha256(item.read_bytes()).hexdigest()
            (bundle / "SHA256SUMS").write_text(
                "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())),
                encoding="ascii",
            )
            (bundle / "SHA256SUMS").chmod(0o600)

            with self.assertRaises(self.tool.ProjectImageError):
                self.tool.verify_upload_bundle(bundle, required_uid=os.getuid())
            self.assertFalse(marker.exists())

    def test_trusted_installer_is_rehashed_immediately_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, _manifest = write_upload_bundle(base)
            trusted = base / "trusted-deploy-upload-archive.py"
            trusted.write_bytes(UPLOAD_INSTALLER_PATH.read_bytes())
            trusted.chmod(0o500)
            marker = base / "raced-installer-executed"
            original_hash = self.tool.sha256_file
            changed = []

            def replace_after_hash(path, **kwargs):
                digest = original_hash(path, **kwargs)
                if Path(path) == trusted and not changed:
                    trusted.chmod(0o600)
                    trusted.write_text(
                        "from pathlib import Path\n"
                        f"Path({os.fspath(marker)!r}).write_text('executed')\n",
                        encoding="ascii",
                    )
                    trusted.chmod(0o500)
                    changed.append(True)
                return digest

            with mock.patch.object(self.tool, "UPLOAD_INSTALLER", trusted), \
                    mock.patch.object(
                        self.tool, "sha256_file", side_effect=replace_after_hash,
                    ), self.assertRaises(self.tool.ProjectImageError):
                self.tool.verify_upload_bundle(bundle, required_uid=os.getuid())
            self.assertEqual([True], changed)
            self.assertFalse(
                marker.exists(),
                "installer bytes changed after trust check must never execute",
            )

    def test_project_image_rejects_symlink_output_parent_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, manifest = write_upload_bundle(base)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            real_parent = base / "real-output-parent"
            real_parent.mkdir(mode=0o700)
            alias = base / "output-parent-alias"
            alias.symlink_to(real_parent, target_is_directory=True)
            base_id = "sha256:" + "b" * 64

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    return SimpleNamespace(returncode=0, stdout=base_id + "\n", stderr="")
                self.fail(f"Docker build reached through unsafe output parent: {command}")

            with self.assertRaisesRegex(
                self.tool.ProjectImageError, "output parent",
            ):
                self.tool.build_project_image(
                    bundle,
                    base_image=base_id,
                    output=alias / "project-image",
                    shared_bundle=None,
                    source_manifest=source_manifest,
                    expected_architecture="amd64",
                    required_uid=os.getuid(),
                    runner=runner,
                )

    def test_project_image_reverifies_the_copied_upload_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, manifest = write_upload_bundle(base)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            output_parent = base / "outputs"
            output_parent.mkdir(mode=0o700)
            base_id = "sha256:" + "b" * 64
            original_copy = self.tool._copy_bundle

            def replaced_after_copy(source, destination, **kwargs):
                original_copy(source, destination, **kwargs)
                if destination.name == "upload":
                    archive = next(destination.glob("*-upload.tar.gz"))
                    archive.write_bytes(archive.read_bytes() + b"substituted\n")

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    return SimpleNamespace(returncode=0, stdout=base_id + "\n", stderr="")
                self.fail(f"Docker build reached with substituted upload bytes: {command}")

            with mock.patch.object(
                self.tool, "_copy_bundle", side_effect=replaced_after_copy,
            ):
                with self.assertRaisesRegex(
                    self.tool.ProjectImageError, "copied upload",
                ):
                    self.tool.build_project_image(
                        bundle,
                        base_image=base_id,
                        output=output_parent / "project-image",
                        shared_bundle=None,
                        source_manifest=source_manifest,
                        expected_architecture="amd64",
                        required_uid=os.getuid(),
                        runner=runner,
                    )

    def test_shared_bundle_checksum_and_upload_input_identity_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            upload, manifest = write_upload_bundle(
                base, global_payload=SHARED_GLOBAL,
                devices_payload=SHARED_DEVICES,
            )
            shared = write_shared_bundle(base)
            authority = self.tool.verify_shared_bundle(
                shared.output, required_uid=os.getuid(),
            )
            self.tool.validate_shared_upload_binding(
                self.tool.verify_upload_bundle(upload, required_uid=os.getuid()),
                authority,
                required_uid=os.getuid(),
            )

            sums = shared.output / "SHA256SUMS"
            original_sums = sums.read_bytes()
            sums.write_text("0" * 64 + "  shared-artifacts.tar.gz\n", encoding="ascii")
            sums.chmod(0o600)
            with self.assertRaisesRegex(
                self.tool.ProjectImageError, "SHA256SUMS|checksum|exact bundle",
            ):
                self.tool.verify_shared_bundle(
                    shared.output, required_uid=os.getuid(),
                )
            sums.write_bytes(original_sums)
            sums.chmod(0o600)

            mismatched_base = base / "mismatched-upload"
            mismatched_base.mkdir()
            mismatched, mismatched_manifest = write_upload_bundle(
                mismatched_base,
                global_payload=SHARED_GLOBAL.replace(b"5.18.1", b"5.17.0"),
                devices_payload=SHARED_DEVICES,
            )
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(mismatched_manifest)
            source_manifest.chmod(0o600)
            output_parent = base / "outputs"
            output_parent.mkdir(mode=0o700)

            def runner(command, **_kwargs):
                self.fail(f"Docker reached with mismatched project inputs: {command}")

            with self.assertRaisesRegex(
                self.tool.ProjectImageError, "shared.*input|project input",
            ):
                self.tool.build_project_image(
                    mismatched,
                    base_image="sha256:" + "b" * 64,
                    output=output_parent / "project-image",
                    shared_bundle=shared.output,
                    source_manifest=source_manifest,
                    expected_architecture="amd64",
                    required_uid=os.getuid(),
                    runner=runner,
                )

    def test_build_cli_bootstrap_exposes_only_http_root_and_runtime_state(self):
        result = self.tool.BuildResult(
            Path("/root/output"), "customer", "sha256:" + "c" * 64,
            "d" * 64,
        )
        stdout = io.StringIO()
        with mock.patch.object(os, "geteuid", return_value=0), \
             mock.patch.object(self.tool, "build_project_image", return_value=result), \
             redirect_stdout(stdout):
            self.assertEqual(0, self.tool.main([
                "build", "/root/upload", "--base-image", "sha256:" + "b" * 64,
                "--output", "/root/output",
            ]))
        text = stdout.getvalue()
        self.assertIn(
            "src=/var/lib/http-ztp-container/runtime,"
            "dst=/var/lib/http-ztp-container/runtime",
            text,
        )
        self.assertNotIn(
            "src=/var/lib/http-ztp-container,dst=/var/lib/http-ztp-container",
            text,
        )
        self.assertIn(
            "/opt/http-ztp/project-bootstrap/tools/package-project-image.py install",
            text,
        )
        self.assertNotIn(
            "/opt/http-ztp/source-tree/tools/package-project-image.py install",
            text,
        )
        self.assertNotIn("--scope air --switch eth", text)

    def test_project_image_build_is_offline_and_exports_only_image_authorities(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, manifest = write_upload_bundle(base)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            output = base / "project-image-output"
            base_id = "sha256:" + "b" * 64
            final_id = "sha256:" + "c" * 64
            commands = []

            def runner(command, **kwargs):
                command = [os.fspath(item) for item in command]
                commands.append((command, kwargs))
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    self.assertIn("--expected-image-flavor", command)
                    flavor = command[command.index("--expected-image-flavor") + 1]
                    if flavor == "generic":
                        return SimpleNamespace(returncode=0, stdout=base_id + "\n", stderr="")
                    self.assertEqual("project", flavor)
                    self.assertEqual(
                        "customer", command[command.index("--expected-project") + 1],
                    )
                    return SimpleNamespace(returncode=0, stdout=final_id + "\n", stderr="")
                if command[:2] == ["docker", "build"]:
                    self.assertIn("--network", command)
                    self.assertEqual("none", command[command.index("--network") + 1])
                    self.assertIn("--iidfile", command)
                    iidfile = Path(command[command.index("--iidfile") + 1])
                    iidfile.write_text(final_id + "\n", encoding="ascii")
                    iidfile.chmod(0o600)
                    context = Path(command[-1])
                    text = (context / "Dockerfile").read_text(encoding="ascii")
                    self.assertIn(f"FROM {base_id}", text)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:3] == ["docker", "image", "inspect"]:
                    self.fail("project build must verify the immutable iid, not a mutable tag")
                if command[:2] == ["docker", "save"]:
                    archive = Path(command[command.index("--output") + 1])
                    archive.write_bytes(b"project OCI archive\n")
                    archive.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected command: {command}")

            result = self.tool.build_project_image(
                bundle,
                base_image=base_id,
                output=output,
                shared_bundle=None,
                source_manifest=source_manifest,
                expected_architecture="amd64",
                required_uid=os.getuid(),
                runner=runner,
            )
            self.assertEqual(output.resolve(), result.output)
            self.assertEqual(final_id, result.image_id)
            self.assertEqual(
                {
                    "http-ztp-project-customer.tar",
                    "project-image-metadata.json",
                    "SHA256SUMS",
                },
                {item.name for item in output.iterdir()},
            )
            metadata = json.loads(
                (output / "project-image-metadata.json").read_text(encoding="ascii"),
            )
            self.assertEqual("http-ztp-project-image", metadata["artifact_type"])
            self.assertEqual("3", metadata["image_contract"])
            self.assertEqual("customer", metadata["project"])
            self.assertEqual(base_id, metadata["base_image_id"])
            self.assertEqual(final_id, metadata["image_id"])
            self.assertIsNone(metadata["shared_artifacts"])
            self.assertEqual("enabled", metadata["upgrade_policy"])
            self.assertEqual("enabled", result.upgrade_policy)
            self.assertEqual(bootstrap_tool_hashes(), metadata["bootstrap_tools"])
            self.assertFalse(any(
                command[:2] in (["docker", "pull"], ["docker", "load"])
                for command, _kwargs in commands
            ))
            self.assertFalse(any(
                command[:3] == ["docker", "image", "inspect"]
                for command, _kwargs in commands
            ))
            lifecycle = {
                tuple(command[:2]): kwargs
                for command, kwargs in commands
                if command[:2] in (["docker", "build"], ["docker", "save"])
            }
            self.assertFalse(lifecycle[("docker", "build")]["capture_output"])
            self.assertEqual(7200, lifecycle[("docker", "build")]["timeout"])
            self.assertFalse(lifecycle[("docker", "save")]["capture_output"])
            self.assertEqual(3600, lifecycle[("docker", "save")]["timeout"])

    def test_real_upload_packager_excludes_mixed_case_ssh_secret_before_image_context(self):
        """Bind one planted private sentinel through packager, relay, and image build."""
        sentinel = b"DOCKER_MGMT_IMAGE_SECRET_92f79da03d704fd9\n"
        with tempfile.TemporaryDirectory(prefix="http-image-secret-boundary-") as directory:
            base = Path(directory).resolve()
            workspace = base / "workspace"
            workspace.mkdir(mode=0o700)

            activate = load_module(
                "project_image_secret_activate", ROOT / "infra/docker/activate.py",
            )
            selected = set(activate.image_source_paths(ROOT))
            selected.add(".dockerignore")
            for relative_name in sorted(selected):
                source = ROOT / relative_name
                destination = workspace / relative_name
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.is_symlink():
                    destination.symlink_to(os.readlink(source))
                else:
                    shutil.copy2(source, destination)

            project = workspace / "DAY0-Prepare/customer"
            project.mkdir(parents=True, exist_ok=True)
            (project / "01-global.yaml").write_bytes(SHARED_GLOBAL)
            (project / "02-devices_config.csv").write_bytes(SHARED_DEVICES)
            (project / "02-dhcp-subnet_config.csv").write_bytes(
                (ROOT / "examples/public-project/02-dhcp-subnet_config.csv.example")
                .read_bytes()
            )
            with zipfile.ZipFile(
                project / "Customer P2P.xlsx", "w", compression=zipfile.ZIP_DEFLATED,
            ) as workbook:
                workbook.writestr("[Content_Types].xml", "<Types/>")
                workbook.writestr(
                    "xl/workbook.xml", "<workbook><keep>cells</keep></workbook>",
                )
            (project / "p2p.xlsx").symlink_to("Customer P2P.xlsx")
            private = workspace / "infra/.Ssh/id_ed25519"
            private.parent.mkdir()
            private.write_bytes(sentinel)

            if os.fspath(TOOLS) not in sys.path:
                sys.path.insert(0, os.fspath(TOOLS))
            package_core = __import__("_package_common")
            upload_tool = load_module(
                "project_image_secret_upload", ROOT / "tools/tar-for-upload.py",
            )
            archive = base / "customer-upload.tar.gz"
            args = argparse.Namespace(
                project=os.fspath(project), output=archive, force=False,
                max_file_size_mib=50, include_images=False, include_apps=False,
                apps_platform=None, apps_platforms=set(), include_firmware=False,
                exclude_project_images=True,
            )
            with mock.patch.multiple(
                package_core,
                ROOT=workspace,
                DAY0=workspace / "DAY0-Prepare",
                TOOLS_DIR=workspace / "tools",
                MANIFEST=workspace / "ztp/.setup_manifest",
                DEPLOYMENT_PREWRITE_GUARD=(
                    workspace / "tools/deployment_prewrite_guard.py"
                ),
                DEPLOYMENT_SOURCE_MANIFEST_BUILDER=(
                    workspace / "infra/docker/activate.py"
                ),
            ):
                package_core.create_package(
                    args, day0_all=False, artifact_kind="upload",
                )

            with tarfile.open(archive, "r:gz") as stream:
                names = stream.getnames()
                self.assertFalse(any(
                    part.casefold() == ".ssh"
                    for name in names for part in Path(name).parts
                ))
                payload = b"".join(
                    stream.extractfile(member).read()
                    for member in stream.getmembers() if member.isfile()
                )
                manifest_stream = stream.extractfile(
                    "./infra/docker/deployment-source-manifest.json"
                )
                self.assertIsNotNone(manifest_stream)
                source_manifest_bytes = manifest_stream.read()
            self.assertNotIn(sentinel, payload)

            relay = upload_tool.publish_relay_bundle(
                base / "upload-release",
                archive,
                project_name="customer",
                runtime="docker",
                expected_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                installer_path=workspace / "tools/deploy-upload-archive.py",
            )
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(source_manifest_bytes)
            source_manifest.chmod(0o600)
            base_id = "sha256:" + "d" * 64
            final_id = "sha256:" + "e" * 64
            observed_contexts = []

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    flavor = command[command.index("--expected-image-flavor") + 1]
                    return SimpleNamespace(
                        returncode=0,
                        stdout=(base_id if flavor == "generic" else final_id) + "\n",
                        stderr="",
                    )
                if command[:2] == ["docker", "build"]:
                    context = Path(command[-1]).resolve()
                    observed_contexts.append(context)
                    context_payload = bytearray()
                    for item in context.rglob("*"):
                        relative = item.relative_to(context)
                        self.assertNotIn(
                            ".ssh", {part.casefold() for part in relative.parts},
                        )
                        if not item.is_file():
                            continue
                        data = item.read_bytes()
                        context_payload.extend(data)
                        if item.name.endswith(".tar.gz"):
                            with tarfile.open(item, "r:gz") as nested:
                                self.assertFalse(any(
                                    part.casefold() == ".ssh"
                                    for name in nested.getnames()
                                    for part in Path(name).parts
                                ))
                                for member in nested.getmembers():
                                    if member.isfile():
                                        context_payload.extend(
                                            nested.extractfile(member).read()
                                        )
                    self.assertNotIn(sentinel, bytes(context_payload))
                    iidfile = Path(command[command.index("--iidfile") + 1])
                    iidfile.write_text(final_id + "\n", encoding="ascii")
                    iidfile.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:2] == ["docker", "save"]:
                    output = Path(command[command.index("--output") + 1])
                    output.write_bytes(b"safe project image archive\n")
                    output.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected command: {command}")

            result = self.tool.build_project_image(
                relay,
                base_image=base_id,
                output=base / "project-image",
                shared_bundle=None,
                source_manifest=source_manifest,
                expected_architecture="amd64",
                required_uid=os.getuid(),
                runner=runner,
            )
            self.assertEqual(final_id, result.image_id)
            self.assertEqual(1, len(observed_contexts))
            self.assertFalse(observed_contexts[0].exists())

    def test_build_context_and_save_use_only_the_held_output_filesystem(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, manifest = write_upload_bundle(base)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            output_parent = base / "large-output-filesystem"
            output_parent.mkdir(mode=0o700)
            output = output_parent / "project-image-output"
            ambient_tmp = base / "ambient-tmpfs-only-1g"
            ambient_tmp.mkdir(mode=0o700)
            base_id = "sha256:" + "b" * 64
            final_id = "sha256:" + "c" * 64
            docker_paths = {}
            ambient_allocations = []

            def ambient_mkdtemp(*, prefix, dir=None):
                self.assertIsNone(dir)
                target = ambient_tmp / (prefix + "forced")
                target.mkdir(mode=0o700)
                ambient_allocations.append(target)
                return os.fspath(target)

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    flavor = command[command.index("--expected-image-flavor") + 1]
                    return SimpleNamespace(
                        returncode=0,
                        stdout=(base_id if flavor == "generic" else final_id) + "\n",
                        stderr="",
                    )
                if command[:2] == ["docker", "build"]:
                    context = Path(command[-1]).resolve()
                    docker_paths["context"] = context
                    iidfile = Path(command[command.index("--iidfile") + 1])
                    iidfile.write_text(final_id + "\n", encoding="ascii")
                    iidfile.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:2] == ["docker", "save"]:
                    archive = Path(command[command.index("--output") + 1]).resolve()
                    docker_paths["save"] = archive
                    archive.write_bytes(b"project OCI archive\n")
                    archive.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected command: {command}")

            with mock.patch.dict(
                os.environ, {"TMPDIR": os.fspath(ambient_tmp)}, clear=False,
            ), mock.patch.object(
                tempfile, "mkdtemp", side_effect=ambient_mkdtemp,
            ):
                result = self.tool.build_project_image(
                    bundle,
                    base_image=base_id,
                    output=output,
                    shared_bundle=None,
                    source_manifest=source_manifest,
                    expected_architecture="amd64",
                    required_uid=os.getuid(),
                    runner=runner,
                )

            self.assertEqual(output, result.output)
            self.assertEqual([], ambient_allocations)
            self.assertEqual({"context", "save"}, set(docker_paths))
            for path in docker_paths.values():
                self.assertIn(output_parent, path.parents)
                self.assertNotIn(ambient_tmp, path.parents)
            self.assertFalse(docker_paths["context"].exists())
            self.assertFalse(docker_paths["save"].exists())
            self.assertEqual({output.name}, {item.name for item in output_parent.iterdir()})
            self.assertTrue(
                (output / "http-ztp-project-customer.tar").is_file(),
            )

    def test_project_image_output_publish_is_atomic_no_clobber_under_race(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, manifest = write_upload_bundle(base)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            output_parent = base / "outputs"
            output_parent.mkdir(mode=0o700)
            output = output_parent / "project-image-output"
            base_id = "sha256:" + "b" * 64
            final_id = "sha256:" + "c" * 64
            raced_inode = []

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    flavor = command[command.index("--expected-image-flavor") + 1]
                    identity = base_id if flavor == "generic" else final_id
                    return SimpleNamespace(returncode=0, stdout=identity + "\n", stderr="")
                if command[:2] == ["docker", "build"]:
                    context = Path(command[-1])
                    payload = json.loads(
                        (context / "project-payload.json").read_text(encoding="ascii"),
                    )
                    self.assertEqual("3", payload["image_contract"])
                    iidfile = Path(command[command.index("--iidfile") + 1])
                    context = Path(command[-1])
                    payload = json.loads(
                        (context / "project-payload.json").read_text(encoding="ascii"),
                    )
                    self.assertEqual("3", payload["image_contract"])
                    self.assertEqual("enabled", payload["upgrade_policy"])
                    self.assertEqual(
                        bootstrap_tool_hashes(), payload["bootstrap_tools"],
                    )
                    trusted = context / "bootstrap-tools"
                    self.assertEqual(
                        PROJECT_IMAGE_PATH.read_bytes(),
                        (trusted / "package-project-image.py").read_bytes(),
                    )
                    self.assertEqual(
                        UPLOAD_INSTALLER_PATH.read_bytes(),
                        (trusted / "deploy-upload-archive.py").read_bytes(),
                    )
                    self.assertEqual(
                        SHARED_INSTALLER_PATH.read_bytes(),
                        (trusted / "deploy-shared-artifacts.py").read_bytes(),
                    )
                    dockerfile = (context / "Dockerfile").read_text(encoding="ascii")
                    self.assertIn(
                        "COPY bootstrap-tools/ /opt/http-ztp/project-bootstrap/tools/",
                        dockerfile,
                    )
                    iidfile.write_text(final_id + "\n", encoding="ascii")
                    iidfile.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:2] == ["docker", "save"]:
                    archive = Path(command[command.index("--output") + 1])
                    archive.write_bytes(b"project OCI archive\n")
                    archive.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected command: {command}")

            def race():
                output.mkdir(mode=0o700)
                raced_inode.append(output.lstat().st_ino)

            with mock.patch.object(
                self.tool, "_TEST_BEFORE_OUTPUT_PUBLISH", race, create=True,
            ), self.assertRaisesRegex(
                self.tool.ProjectImageError, "output.*changed|no-clobber|publish",
            ):
                self.tool.build_project_image(
                    bundle,
                    base_image=base_id,
                    output=output,
                    shared_bundle=None,
                    source_manifest=source_manifest,
                    expected_architecture="amd64",
                    required_uid=os.getuid(),
                    runner=runner,
                )
            self.assertEqual(1, len(raced_inode), "race hook was not reached")
            self.assertTrue(output.is_dir())
            self.assertEqual(raced_inode[0], output.lstat().st_ino)
            self.assertEqual([], list(output.iterdir()))

    def test_publish_rolls_back_a_stage_name_replacement_before_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            parent = base / "outputs"
            parent.mkdir(mode=0o700)
            output = parent / "project-image"
            output, parent_fd, parent_identity = self.tool._open_output_authority(
                output, required_uid=os.getuid(),
            )
            stage_name, stage_fd, stage_identity = self.tool._create_output_stage(
                parent_fd, ".project.tmp.", required_uid=os.getuid(),
            )
            self.tool._private_write_at(stage_fd, "trusted", b"trusted\n")
            preserved_name = stage_name + ".preserved"
            real_rename = self.tool._rename_directory_noreplace
            fired = []

            def racing_rename(source, destination, *, directory_fd=None):
                if (
                    not fired
                    and Path(source).name == stage_name
                    and Path(destination).name == output.name
                ):
                    os.rename(
                        stage_name, preserved_name,
                        src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                    )
                    os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
                    replacement_fd = os.open(
                        stage_name,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                        dir_fd=parent_fd,
                    )
                    try:
                        self.tool._private_write_at(
                            replacement_fd, "attacker", b"attacker\n",
                        )
                    finally:
                        os.close(replacement_fd)
                    fired.append(True)
                return real_rename(
                    source, destination, directory_fd=directory_fd,
                )

            try:
                with mock.patch.object(
                    self.tool, "_rename_directory_noreplace",
                    side_effect=racing_rename,
                ), self.assertRaisesRegex(
                    self.tool.ProjectImageError, "identity|publish",
                ):
                    self.tool._publish_held_output(
                        output=output,
                        parent_descriptor=parent_fd,
                        parent_identity=parent_identity,
                        stage_name=stage_name,
                        stage_descriptor=stage_fd,
                        stage_identity=stage_identity,
                        required_uid=os.getuid(),
                    )
            finally:
                os.close(stage_fd)
                os.close(parent_fd)
            self.assertEqual([True], fired)
            self.assertFalse(
                os.path.lexists(output),
                "an unverified replacement must never remain at the final output",
            )
            self.assertEqual(
                b"attacker\n", (parent / stage_name / "attacker").read_bytes(),
            )
            self.assertEqual(
                b"trusted\n", (parent / preserved_name / "trusted").read_bytes(),
            )

    def test_build_rejects_output_parent_swap_before_any_stage_is_redirected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, manifest = write_upload_bundle(base)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            parent = base / "outputs"
            parent.mkdir(mode=0o700)
            output = parent / "project-image"
            moved_parent = base / "moved-outputs"
            attacker = base / "attacker"
            attacker.mkdir(mode=0o700)
            base_id = "sha256:" + "b" * 64
            final_id = "sha256:" + "c" * 64
            swaps = []

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    flavor = command[command.index("--expected-image-flavor") + 1]
                    return SimpleNamespace(
                        returncode=0,
                        stdout=(base_id if flavor == "generic" else final_id) + "\n",
                        stderr="",
                    )
                if command[:2] == ["docker", "build"]:
                    iidfile = Path(command[command.index("--iidfile") + 1])
                    iidfile.write_text(final_id + "\n", encoding="ascii")
                    iidfile.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:2] == ["docker", "save"]:
                    archive = Path(command[command.index("--output") + 1])
                    archive.write_bytes(b"project OCI archive\n")
                    archive.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected command: {command}")

            def swap_parent():
                parent.rename(moved_parent)
                parent.symlink_to(attacker, target_is_directory=True)
                swaps.append(True)

            with mock.patch.object(
                self.tool, "_TEST_AFTER_OUTPUT_PARENT_OPEN", swap_parent, create=True,
            ), self.assertRaisesRegex(
                self.tool.ProjectImageError, "output parent.*changed|parent identity",
            ):
                self.tool.build_project_image(
                    bundle,
                    base_image=base_id,
                    output=output,
                    shared_bundle=None,
                    source_manifest=source_manifest,
                    expected_architecture="amd64",
                    required_uid=os.getuid(),
                    runner=runner,
                )
            self.assertEqual([True], swaps)
            self.assertEqual([], list(attacker.iterdir()))
            self.assertEqual([], list(moved_parent.iterdir()))

    def test_failed_build_cleanup_preserves_same_name_stage_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            bundle, manifest = write_upload_bundle(base)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            parent = base / "outputs"
            parent.mkdir(mode=0o700)
            output = parent / "project-image"
            base_id = "sha256:" + "b" * 64
            cleanup_events = []
            replacement = []

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    return SimpleNamespace(returncode=0, stdout=base_id + "\n", stderr="")
                if command[:2] == ["docker", "build"]:
                    return SimpleNamespace(returncode=17, stdout="", stderr="injected")
                self.fail(f"unexpected command: {command}")

            def replace_stage(_parent_fd, stage_name, _stage_identity):
                original = parent / stage_name
                preserved = parent / (stage_name + ".preserved")
                original.rename(preserved)
                original.mkdir(mode=0o700)
                sentinel = original / "do-not-delete"
                sentinel.write_bytes(b"replacement\n")
                cleanup_events.append(True)
                replacement.append(sentinel)

            with mock.patch.object(
                self.tool, "_TEST_BEFORE_OUTPUT_STAGE_CLEANUP", replace_stage,
                create=True,
            ), self.assertRaisesRegex(
                self.tool.ProjectImageError, "build|staging.*changed|cleanup",
            ):
                self.tool.build_project_image(
                    bundle,
                    base_image=base_id,
                    output=output,
                    shared_bundle=None,
                    source_manifest=source_manifest,
                    expected_architecture="amd64",
                    required_uid=os.getuid(),
                    runner=runner,
                )
            self.assertEqual([True], cleanup_events)
            self.assertEqual(1, len(replacement))
            self.assertEqual(b"replacement\n", replacement[0].read_bytes())
            self.assertFalse(any(
                ".context." in item.name for item in parent.iterdir()
            ))

    def test_context_cleanup_never_rmdirs_a_same_name_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            parent_fd = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            context_name, context_fd, context_identity = (
                self.tool._create_output_stage(
                    parent_fd, ".project.context.", required_uid=os.getuid(),
                )
            )
            self.tool._private_write_at(context_fd, "large-payload", b"payload\n")
            preserved_name = context_name + ".preserved"
            real_rename = self.tool._rename_directory_noreplace
            fired = []
            replacement_inode = []

            def racing_rename(source, destination, *, directory_fd=None):
                if (
                    not fired
                    and directory_fd == parent_fd
                    and Path(source).name == context_name
                ):
                    os.rename(
                        context_name, preserved_name,
                        src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                    )
                    os.mkdir(context_name, 0o700, dir_fd=parent_fd)
                    replacement_inode.append(
                        os.stat(
                            context_name, dir_fd=parent_fd,
                            follow_symlinks=False,
                        ).st_ino
                    )
                    replacement_fd = os.open(
                        context_name,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                        dir_fd=parent_fd,
                    )
                    try:
                        self.tool._private_write_at(
                            replacement_fd, "attacker", b"replacement\n",
                        )
                    finally:
                        os.close(replacement_fd)
                    fired.append(True)
                return real_rename(
                    source, destination, directory_fd=directory_fd,
                )

            try:
                with mock.patch.object(
                    self.tool, "_rename_directory_noreplace",
                    side_effect=racing_rename,
                ), self.assertRaisesRegex(
                    self.tool.ProjectImageError, "source changed|replacement",
                ):
                    self.tool._cleanup_private_context(
                        parent_fd, context_name, context_fd, context_identity,
                        required_uid=os.getuid(),
                    )
            finally:
                os.close(context_fd)
                os.close(parent_fd)
            self.assertEqual([True], fired)
            self.assertTrue((parent / context_name).is_dir())
            self.assertEqual(
                replacement_inode[0], (parent / context_name).stat().st_ino,
            )
            self.assertEqual(
                b"replacement\n",
                (parent / context_name / "attacker").read_bytes(),
            )
            self.assertEqual([], list((parent / preserved_name).iterdir()))

    def test_regular_cleanup_never_unlinks_a_same_name_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            parent_fd = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            context_name, context_fd, context_identity = (
                self.tool._create_output_stage(
                    parent_fd, ".project.context.", required_uid=os.getuid(),
                )
            )
            self.tool._private_write_at(
                context_fd, "large-payload", b"original-large-payload\n",
            )
            real_unlink = os.unlink
            fired = []
            replacement_inode = []

            def racing_unlink(path, *args, **kwargs):
                if (
                    not fired
                    and path == "large-payload"
                    and kwargs.get("dir_fd") == context_fd
                ):
                    os.rename(
                        "large-payload", "large-payload.preserved",
                        src_dir_fd=context_fd, dst_dir_fd=context_fd,
                    )
                    self.tool._private_write_at(
                        context_fd, "large-payload", b"replacement\n",
                    )
                    replacement_inode.append(
                        os.stat(
                            "large-payload", dir_fd=context_fd,
                            follow_symlinks=False,
                        ).st_ino
                    )
                    fired.append(True)
                return real_unlink(path, *args, **kwargs)

            error = None
            try:
                with mock.patch.object(
                    self.tool.os, "unlink", side_effect=racing_unlink,
                ):
                    try:
                        self.tool._cleanup_private_context(
                            parent_fd, context_name, context_fd, context_identity,
                            required_uid=os.getuid(),
                        )
                    except self.tool.ProjectImageError as exc:
                        error = exc
            finally:
                os.close(context_fd)
                os.close(parent_fd)
            if fired:
                context = parent / context_name
                self.assertIsNotNone(error)
                self.assertTrue(
                    (context / "large-payload").is_file(),
                    "regular cleanup removed a concurrent same-name replacement",
                )
                self.assertEqual(
                    replacement_inode[0], (context / "large-payload").stat().st_ino,
                )
                self.assertEqual(
                    b"", (context / "large-payload.preserved").read_bytes(),
                    "the held original inode retained a potentially huge payload",
                )
            else:
                self.assertIsNone(error)
                self.assertFalse((parent / context_name).exists())

    def test_regular_cleanup_restores_a_replacement_moved_by_detach(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            parent_fd = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            context_name, context_fd, context_identity = (
                self.tool._create_output_stage(
                    parent_fd, ".project.context.", required_uid=os.getuid(),
                )
            )
            self.tool._private_write_at(
                context_fd, "large-payload", b"original-large-payload\n",
            )
            real_rename = self.tool._rename_directory_noreplace
            fired = []
            replacement_inode = []

            def racing_rename(source, destination, *, directory_fd=None):
                if (
                    not fired
                    and directory_fd == context_fd
                    and Path(source).name == "large-payload"
                ):
                    os.rename(
                        "large-payload", "large-payload.preserved",
                        src_dir_fd=context_fd, dst_dir_fd=context_fd,
                    )
                    self.tool._private_write_at(
                        context_fd, "large-payload", b"replacement\n",
                    )
                    replacement_inode.append(
                        os.stat(
                            "large-payload", dir_fd=context_fd,
                            follow_symlinks=False,
                        ).st_ino
                    )
                    fired.append(True)
                return real_rename(
                    source, destination, directory_fd=directory_fd,
                )

            error = None
            try:
                with mock.patch.object(
                    self.tool, "_rename_directory_noreplace",
                    side_effect=racing_rename,
                ):
                    try:
                        self.tool._cleanup_private_context(
                            parent_fd, context_name, context_fd, context_identity,
                            required_uid=os.getuid(),
                        )
                    except self.tool.ProjectImageError as exc:
                        error = exc
            finally:
                os.close(context_fd)
                os.close(parent_fd)
            self.assertEqual([True], fired)
            self.assertIsNotNone(error)
            context = parent / context_name
            self.assertEqual(
                replacement_inode[0], (context / "large-payload").stat().st_ino,
            )
            self.assertEqual(
                b"replacement\n", (context / "large-payload").read_bytes(),
            )
            self.assertEqual(
                b"", (context / "large-payload.preserved").read_bytes(),
                "the held original inode retained a potentially huge payload",
            )

    def test_nested_context_cleanup_never_rmdirs_a_same_name_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            parent_fd = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            context_name, context_fd, context_identity = (
                self.tool._create_output_stage(
                    parent_fd, ".project.context.", required_uid=os.getuid(),
                )
            )
            os.mkdir("nested", 0o700, dir_fd=context_fd)
            nested_fd = os.open(
                "nested", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                dir_fd=context_fd,
            )
            try:
                self.tool._private_write_at(nested_fd, "large-payload", b"payload\n")
            finally:
                os.close(nested_fd)
            real_rename = self.tool._rename_directory_noreplace
            fired = []
            replacement_inode = []

            def racing_rename(source, destination, *, directory_fd=None):
                if (
                    not fired
                    and directory_fd == context_fd
                    and Path(source).name == "nested"
                ):
                    os.rename(
                        "nested", "nested.preserved",
                        src_dir_fd=context_fd, dst_dir_fd=context_fd,
                    )
                    os.mkdir("nested", 0o700, dir_fd=context_fd)
                    replacement_inode.append(
                        os.stat(
                            "nested", dir_fd=context_fd,
                            follow_symlinks=False,
                        ).st_ino
                    )
                    replacement_fd = os.open(
                        "nested",
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                        dir_fd=context_fd,
                    )
                    try:
                        self.tool._private_write_at(
                            replacement_fd, "attacker", b"replacement\n",
                        )
                    finally:
                        os.close(replacement_fd)
                    fired.append(True)
                return real_rename(
                    source, destination, directory_fd=directory_fd,
                )

            try:
                with mock.patch.object(
                    self.tool, "_rename_directory_noreplace",
                    side_effect=racing_rename,
                ), self.assertRaisesRegex(
                    self.tool.ProjectImageError, "source changed|replacement",
                ):
                    self.tool._cleanup_private_context(
                        parent_fd, context_name, context_fd, context_identity,
                        required_uid=os.getuid(),
                    )
            finally:
                os.close(context_fd)
                os.close(parent_fd)
            self.assertEqual([True], fired)
            context = parent / context_name
            self.assertTrue(context.is_dir())
            self.assertEqual(
                replacement_inode[0], (context / "nested").stat().st_ino,
            )
            self.assertEqual(
                b"replacement\n", (context / "nested/attacker").read_bytes(),
            )
            self.assertEqual([], list((context / "nested.preserved").iterdir()))

    def test_output_stage_cleanup_never_rmdirs_a_same_name_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            parent_fd = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            stage_name, stage_fd, stage_identity = self.tool._create_output_stage(
                parent_fd, ".project.tmp.", required_uid=os.getuid(),
            )
            self.tool._private_write_at(stage_fd, "image.tar", b"payload\n")
            preserved_name = stage_name + ".preserved"
            real_rename = self.tool._rename_directory_noreplace
            fired = []
            replacement_inode = []

            def racing_rename(source, destination, *, directory_fd=None):
                if (
                    not fired
                    and directory_fd == parent_fd
                    and Path(source).name == stage_name
                ):
                    os.rename(
                        stage_name, preserved_name,
                        src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                    )
                    os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
                    replacement_inode.append(
                        os.stat(
                            stage_name, dir_fd=parent_fd,
                            follow_symlinks=False,
                        ).st_ino
                    )
                    replacement_fd = os.open(
                        stage_name,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                        dir_fd=parent_fd,
                    )
                    try:
                        self.tool._private_write_at(
                            replacement_fd, "attacker", b"replacement\n",
                        )
                    finally:
                        os.close(replacement_fd)
                    fired.append(True)
                return real_rename(
                    source, destination, directory_fd=directory_fd,
                )

            try:
                with mock.patch.object(
                    self.tool, "_rename_directory_noreplace",
                    side_effect=racing_rename,
                ), self.assertRaisesRegex(
                    self.tool.ProjectImageError, "source changed|replacement",
                ):
                    self.tool._cleanup_output_stage(
                        parent_fd, stage_name, stage_identity,
                        required_uid=os.getuid(), stage_descriptor=stage_fd,
                    )
            finally:
                os.close(stage_fd)
                os.close(parent_fd)
            self.assertEqual([True], fired)
            self.assertTrue((parent / stage_name).is_dir())
            self.assertEqual(
                replacement_inode[0], (parent / stage_name).stat().st_ino,
            )
            self.assertEqual(
                b"replacement\n",
                (parent / stage_name / "attacker").read_bytes(),
            )
            self.assertEqual([], list((parent / preserved_name).iterdir()))

    def test_working_directory_is_restored_when_fchdir_switch_then_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            original_fd = os.open(".", flags)
            target_fd = os.open(target, flags)
            original_identity = os.fstat(original_fd)
            real_fchdir = os.fchdir
            fired = []

            def switch_then_raise(descriptor):
                real_fchdir(descriptor)
                if not fired:
                    fired.append(True)
                    raise KeyboardInterrupt("injected after directory switch")

            try:
                with mock.patch.object(
                    self.tool.os, "fchdir", side_effect=switch_then_raise,
                ), self.assertRaisesRegex(KeyboardInterrupt, "injected"):
                    with self.tool._working_directory(target_fd):
                        self.fail("the injected switch must not yield")
                current = os.stat(".", follow_symlinks=False)
                self.assertEqual([True], fired)
                self.assertEqual(
                    (original_identity.st_dev, original_identity.st_ino),
                    (current.st_dev, current.st_ino),
                )
            finally:
                real_fchdir(original_fd)
                os.close(target_fd)
                os.close(original_fd)

    def test_project_image_publish_rejects_a_concurrent_parent_symlink_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            parent = base / "output-parent"
            parent.mkdir(mode=0o700)
            output = parent / "project-image"
            output, parent_fd, parent_identity = self.tool._open_output_authority(
                output, required_uid=os.getuid(),
            )
            stage_name, stage_fd, stage_identity = self.tool._create_output_stage(
                parent_fd, ".project.tmp.", required_uid=os.getuid(),
            )
            stage = parent / stage_name
            self.tool._private_write_at(stage_fd, "authority", b"trusted\n")
            moved_parent = base / "moved-output-parent"
            attacker = base / "attacker"
            attacker.mkdir(mode=0o700)

            def race():
                parent.rename(moved_parent)
                parent.symlink_to(attacker, target_is_directory=True)
                fake_stage = attacker / stage.name
                fake_stage.mkdir(mode=0o700)
                (fake_stage / "authority").write_bytes(b"attacker\n")

            try:
                with mock.patch.object(
                    self.tool, "_TEST_BEFORE_OUTPUT_PUBLISH", race,
                ), self.assertRaisesRegex(
                    self.tool.ProjectImageError, "output parent|publish",
                ):
                    self.tool._publish_held_output(
                        output=output,
                        parent_descriptor=parent_fd,
                        parent_identity=parent_identity,
                        stage_name=stage_name,
                        stage_descriptor=stage_fd,
                        stage_identity=stage_identity,
                        required_uid=os.getuid(),
                    )
            finally:
                os.close(stage_fd)
                os.close(parent_fd)
            self.assertFalse(os.path.lexists(output))
            self.assertTrue((attacker / stage.name).is_dir())
            self.assertEqual(
                b"trusted\n", (moved_parent / stage.name / "authority").read_bytes(),
            )

    def test_shared_project_build_and_real_two_installer_bootstrap_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            upload, manifest = write_upload_bundle(
                base, global_payload=SHARED_GLOBAL,
                devices_payload=SHARED_DEVICES,
            )
            shared = write_shared_bundle(base)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            output_parent = base / "outputs"
            output_parent.mkdir(mode=0o700, exist_ok=True)
            output = output_parent / "project-image-output"
            base_id = "sha256:" + "b" * 64
            final_id = "sha256:" + "c" * 64

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    flavor = command[command.index("--expected-image-flavor") + 1]
                    identity = base_id if flavor == "generic" else final_id
                    return SimpleNamespace(returncode=0, stdout=identity + "\n", stderr="")
                if command[:2] == ["docker", "build"]:
                    context = Path(command[-1])
                    payload = json.loads(
                        (context / "project-payload.json").read_text(encoding="ascii"),
                    )
                    self.assertEqual("enabled", payload["upgrade_policy"])
                    self.assertEqual(
                        bootstrap_tool_hashes(), payload["bootstrap_tools"],
                    )
                    trusted = context / "bootstrap-tools"
                    for name, source in BOOTSTRAP_TOOLS.items():
                        self.assertEqual(
                            source.read_bytes(), (trusted / name).read_bytes(),
                        )
                        self.assertEqual(
                            0o500, stat.S_IMODE((trusted / name).stat().st_mode),
                        )
                    dockerfile = (context / "Dockerfile").read_text(encoding="ascii")
                    self.assertIn(
                        "COPY bootstrap-tools/ /opt/http-ztp/project-bootstrap/tools/",
                        dockerfile,
                    )
                    iidfile = Path(command[command.index("--iidfile") + 1])
                    iidfile.write_text(final_id + "\n", encoding="ascii")
                    iidfile.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:2] == ["docker", "save"]:
                    archive = Path(command[command.index("--output") + 1])
                    archive.write_bytes(b"project OCI archive\n")
                    archive.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected command: {command}")

            built = self.tool.build_project_image(
                upload,
                base_image=base_id,
                output=output,
                shared_bundle=shared.output,
                source_manifest=source_manifest,
                expected_architecture="amd64",
                required_uid=os.getuid(),
                runner=runner,
            )
            metadata = json.loads(
                (output / "project-image-metadata.json").read_text(encoding="ascii"),
            )
            self.assertEqual(final_id, built.image_id)
            self.assertEqual(
                hashlib.sha256(shared.archive.read_bytes()).hexdigest(),
                metadata["shared_artifacts"]["archive_sha256"],
            )
            self.assertEqual(
                "enabled", metadata["shared_artifacts"]["upgrade_policy"],
            )
            self.assertEqual("enabled", built.upgrade_policy)

            bundled = write_bundled_payload(
                base / "embedded", upload, shared_bundle=shared.output,
            )
            live = base / "live"
            create_public_bootstrap_directory_fixture(live)
            self.assertEqual(0o755, stat.S_IMODE(live.lstat().st_mode))
            loader, state = trusted_installer_loader_for_workflow(self.tool, owned_parent=base)
            with mock.patch.object(self.tool, "_load_module", side_effect=loader):
                installed = self.tool.install_bundled_project(
                    bundled_root=bundled,
                    root=live,
                    verify_only=False,
                    required_uid=os.getuid(),
                )
            self.assertEqual("customer", installed.project)
            self.assertEqual("enabled", installed.upgrade_policy)
            self.assertEqual(1, state["upload_guard_calls"])
            self.assertEqual([live], state["shared_staging_parents"])
            self.assertEqual([live], state["upload_staging_parents"])
            self.assertEqual(
                [{
                    "PATH": (
                        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                    ),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "TMPDIR": os.fspath(live),
                }],
                state["upload_guard_environments"],
            )
            self.assertTrue((live / "image/cumulus-linux-5.18.1-mlx-amd64.bin").is_file())
            self.assertTrue((live / ".shared-artifact-receipts").is_dir())
            self.assertEqual(
                SHARED_GLOBAL,
                (live / "DAY0-Prepare/customer/01-global.yaml").read_bytes(),
            )

    def test_no_upgrade_shared_policy_is_bound_through_the_project_image(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            upload, manifest = write_upload_bundle(
                base, global_payload=SHARED_GLOBAL,
                devices_payload=SHARED_DEVICES,
            )
            shared = write_shared_bundle(base, no_upgrade=True)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            output_parent = base / "outputs"
            output_parent.mkdir(mode=0o700)
            output = output_parent / "project-image-output"
            base_id = "sha256:" + "b" * 64
            final_id = "sha256:" + "c" * 64

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    flavor = command[command.index("--expected-image-flavor") + 1]
                    identity = base_id if flavor == "generic" else final_id
                    return SimpleNamespace(returncode=0, stdout=identity + "\n", stderr="")
                if command[:2] == ["docker", "build"]:
                    context = Path(command[-1])
                    payload = json.loads(
                        (context / "project-payload.json").read_text(encoding="ascii"),
                    )
                    self.assertEqual("disabled", payload["upgrade_policy"])
                    dockerfile = (context / "Dockerfile").read_text(encoding="ascii")
                    self.assertIn(
                        'com.nvidia.http-ztp.upgrade-policy="disabled"',
                        dockerfile,
                    )
                    iidfile = Path(command[command.index("--iidfile") + 1])
                    iidfile.write_text(final_id + "\n", encoding="ascii")
                    iidfile.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:2] == ["docker", "save"]:
                    archive = Path(command[command.index("--output") + 1])
                    archive.write_bytes(b"project OCI archive\n")
                    archive.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected command: {command}")

            result = self.tool.build_project_image(
                upload,
                base_image=base_id,
                output=output,
                shared_bundle=shared.output,
                no_upgrade=True,
                source_manifest=source_manifest,
                expected_architecture="amd64",
                required_uid=os.getuid(),
                runner=runner,
            )
            self.assertEqual("disabled", result.upgrade_policy)
            metadata = json.loads(
                (output / "project-image-metadata.json").read_text(encoding="ascii"),
            )
            self.assertEqual(
                "disabled", metadata["shared_artifacts"]["upgrade_policy"],
            )

    def test_no_shared_no_upgrade_project_image_still_binds_disabled_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            upload, manifest = write_upload_bundle(base)
            source_manifest = base / "deployment-source-manifest.json"
            source_manifest.write_bytes(manifest)
            source_manifest.chmod(0o600)
            output = base / "project-image-output"
            base_id = "sha256:" + "b" * 64
            final_id = "sha256:" + "c" * 64

            def runner(command, **_kwargs):
                command = [os.fspath(item) for item in command]
                if command[0] == sys.executable and "hostlock.py" in command[1]:
                    flavor = command[command.index("--expected-image-flavor") + 1]
                    if flavor == "project":
                        self.assertEqual(
                            "disabled",
                            command[command.index("--expected-upgrade-policy") + 1],
                        )
                    return SimpleNamespace(
                        returncode=0,
                        stdout=(base_id if flavor == "generic" else final_id) + "\n",
                        stderr="",
                    )
                if command[:2] == ["docker", "build"]:
                    context = Path(command[-1])
                    payload = json.loads(
                        (context / "project-payload.json").read_text(encoding="ascii"),
                    )
                    self.assertEqual("disabled", payload["upgrade_policy"])
                    dockerfile = (context / "Dockerfile").read_text(encoding="ascii")
                    self.assertIn(
                        'com.nvidia.http-ztp.upgrade-policy="disabled"', dockerfile,
                    )
                    iidfile = Path(command[command.index("--iidfile") + 1])
                    iidfile.write_text(final_id + "\n", encoding="ascii")
                    iidfile.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:2] == ["docker", "save"]:
                    archive = Path(command[command.index("--output") + 1])
                    archive.write_bytes(b"project OCI archive\n")
                    archive.chmod(0o600)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected command: {command}")

            result = self.tool.build_project_image(
                upload,
                base_image=base_id,
                output=output,
                shared_bundle=None,
                no_upgrade=True,
                source_manifest=source_manifest,
                expected_architecture="amd64",
                required_uid=os.getuid(),
                runner=runner,
            )
            metadata = json.loads(
                (output / "project-image-metadata.json").read_text(encoding="ascii"),
            )
            self.assertIsNone(metadata["shared_artifacts"])
            self.assertEqual("disabled", metadata["upgrade_policy"])
            self.assertEqual("disabled", result.upgrade_policy)

    def test_shared_success_then_upload_failure_is_safely_retryable(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            upload, _manifest = write_upload_bundle(
                base, global_payload=SHARED_GLOBAL,
                devices_payload=SHARED_DEVICES,
            )
            shared = write_shared_bundle(base)
            bundled = write_bundled_payload(
                base / "embedded", upload, shared_bundle=shared.output,
            )
            live = base / "live"
            create_public_bootstrap_directory_fixture(live)
            self.assertEqual(0o755, stat.S_IMODE(live.lstat().st_mode))
            loader, state = trusted_installer_loader_for_workflow(
                self.tool, owned_parent=base, fail_upload_guard_times=1,
            )
            with mock.patch.object(self.tool, "_load_module", side_effect=loader):
                with self.assertRaisesRegex(
                    self.tool.ProjectImageError, "embedded upload release install failed",
                ):
                    self.tool.install_bundled_project(
                        bundled_root=bundled,
                        root=live,
                        verify_only=False,
                        required_uid=os.getuid(),
                    )
                image = live / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
                receipt_directory = live / ".shared-artifact-receipts"
                self.assertTrue(image.is_file())
                self.assertEqual(1, len(tuple(receipt_directory.iterdir())))

                receipt = next(receipt_directory.iterdir())
                receipt_bytes = receipt.read_bytes()
                receipt.write_bytes(receipt_bytes + b"tampered\n")
                receipt.chmod(0o600)
                with self.assertRaisesRegex(
                    self.tool.ProjectImageError, "shared-artifact install failed",
                ):
                    self.tool.install_bundled_project(
                        bundled_root=bundled,
                        root=live,
                        verify_only=False,
                        required_uid=os.getuid(),
                    )
                self.assertEqual(1, state["upload_guard_calls"])
                receipt.write_bytes(receipt_bytes)
                receipt.chmod(0o600)

                image_bytes = image.read_bytes()
                image.write_bytes(image_bytes + b"tampered\n")
                image.chmod(0o644)
                with self.assertRaisesRegex(
                    self.tool.ProjectImageError, "shared-artifact install failed",
                ):
                    self.tool.install_bundled_project(
                        bundled_root=bundled,
                        root=live,
                        verify_only=False,
                        required_uid=os.getuid(),
                    )
                self.assertEqual(1, state["upload_guard_calls"])
                image.write_bytes(image_bytes)
                image.chmod(0o644)

                result = self.tool.install_bundled_project(
                    bundled_root=bundled,
                    root=live,
                    verify_only=False,
                    required_uid=os.getuid(),
                )
            self.assertEqual("customer", result.project)
            self.assertEqual(2, state["upload_guard_calls"])
            self.assertTrue(image.is_file())
            self.assertEqual(
                SHARED_GLOBAL,
                (live / "DAY0-Prepare/customer/01-global.yaml").read_bytes(),
            )

    def test_bundled_upload_verify_only_uses_real_matching_installer_without_live_write(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            upload_bundle, _manifest = write_upload_bundle(base)
            bundled = base / "bundled-project"
            bundled.mkdir(mode=0o700)
            target_upload = bundled / "upload"
            target_upload.mkdir(mode=0o700)
            for source in upload_bundle.iterdir():
                destination = target_upload / source.name
                destination.write_bytes(source.read_bytes())
                destination.chmod(stat.S_IMODE(source.stat().st_mode))
            metadata = {
                "artifact_type": "http-ztp-project-image-payload",
                "schema_version": 1,
                "image_contract": "3",
                "project": "customer",
                "upload_bundle": "upload",
                "shared_bundle": None,
                "upgrade_policy": "enabled",
                "bootstrap_tools": bootstrap_tool_hashes(),
            }
            (bundled / "project-payload.json").write_text(
                json.dumps(metadata, sort_keys=True) + "\n", encoding="ascii",
            )
            (bundled / "project-payload.json").chmod(0o600)
            live = base / "live"
            create_public_bootstrap_directory_fixture(live)
            before = list(live.iterdir())
            result = self.tool.install_bundled_project(
                bundled_root=bundled,
                root=live,
                verify_only=True,
                required_uid=os.getuid(),
            )
            self.assertEqual("customer", result.project)
            self.assertEqual(before, list(live.iterdir()))

    def test_embedded_payload_root_is_exact_and_cannot_be_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            upload_bundle, _manifest = write_upload_bundle(base)
            bundled = base / "bundled-project"
            bundled.mkdir(mode=0o700)
            target_upload = bundled / "upload"
            target_upload.mkdir(mode=0o700)
            for source in upload_bundle.iterdir():
                destination = target_upload / source.name
                destination.write_bytes(source.read_bytes())
                destination.chmod(stat.S_IMODE(source.stat().st_mode))
            (bundled / "project-payload.json").write_text(
                json.dumps({
                    "artifact_type": "http-ztp-project-image-payload",
                    "schema_version": 1,
                    "image_contract": "3",
                    "project": "customer",
                    "upload_bundle": "upload",
                    "shared_bundle": None,
                    "upgrade_policy": "enabled",
                    "bootstrap_tools": bootstrap_tool_hashes(),
                }, sort_keys=True) + "\n",
                encoding="ascii",
            )
            (bundled / "project-payload.json").chmod(0o600)
            live = base / "live"
            live.mkdir(mode=0o755)

            unexpected = bundled / "shared"
            unexpected.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                self.tool.ProjectImageError, "payload root|members",
            ):
                self.tool.install_bundled_project(
                    bundled_root=bundled,
                    root=live,
                    verify_only=True,
                    required_uid=os.getuid(),
                )
            unexpected.rmdir()

            alias = base / "bundled-project-alias"
            alias.symlink_to(bundled, target_is_directory=True)
            with self.assertRaisesRegex(
                self.tool.ProjectImageError, "payload root",
            ):
                self.tool.install_bundled_project(
                    bundled_root=alias,
                    root=live,
                    verify_only=True,
                    required_uid=os.getuid(),
                )

    def test_bundled_install_rejects_a_symlink_live_root_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            upload_bundle, _manifest = write_upload_bundle(base)
            bundled = base / "bundled-project"
            bundled.mkdir(mode=0o700)
            target_upload = bundled / "upload"
            target_upload.mkdir(mode=0o700)
            for source in upload_bundle.iterdir():
                destination = target_upload / source.name
                destination.write_bytes(source.read_bytes())
                destination.chmod(stat.S_IMODE(source.stat().st_mode))
            (bundled / "project-payload.json").write_text(
                json.dumps({
                    "artifact_type": "http-ztp-project-image-payload",
                    "schema_version": 1,
                    "image_contract": "3",
                    "project": "customer",
                    "upload_bundle": "upload",
                    "shared_bundle": None,
                    "upgrade_policy": "enabled",
                    "bootstrap_tools": bootstrap_tool_hashes(),
                }, sort_keys=True) + "\n",
                encoding="ascii",
            )
            (bundled / "project-payload.json").chmod(0o600)
            live = base / "live"
            live.mkdir(mode=0o755)
            live_alias = base / "live-alias"
            live_alias.symlink_to(live, target_is_directory=True)

            with self.assertRaisesRegex(
                self.tool.ProjectImageError, "bootstrap root",
            ):
                self.tool.install_bundled_project(
                    bundled_root=bundled,
                    root=live_alias,
                    verify_only=False,
                    required_uid=os.getuid(),
                )
            self.assertEqual([], list(live.iterdir()))

    def test_deploy_wrapper_has_a_separate_project_preloaded_lifecycle(self):
        deploy = (ROOT / "infra/docker/deploy.sh").read_text(encoding="utf-8")
        usage = deploy.split("usage() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("deploy-project-preloaded IMAGE_ID", usage)
        branch = deploy.rsplit("  deploy-project-preloaded)", 1)[1].split("    ;;", 1)[0]
        self.assertIn(
            'verify_preloaded_image "$2" project "$HTTP_ZTP_PROJECT" '
            '"$project_upgrade_policy"', branch,
        )
        self.assertIn("project_upgrade_policy=enabled", branch)
        self.assertIn("project_upgrade_policy=disabled", branch)
        self.assertIn("start_inactive_container", branch)
        self.assertIn("run_load", branch)
        self.assertNotIn("build_image", branch)

    def test_embedded_policy_and_bootstrap_tool_hashes_fail_closed_before_deploy(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            upload_bundle, _manifest = write_upload_bundle(base)
            bundled = write_bundled_payload(base / "embedded", upload_bundle)
            payload_path = bundled / "project-payload.json"
            live = base / "live"
            live.mkdir(mode=0o755)

            original = json.loads(payload_path.read_text(encoding="ascii"))
            for label, mutate, message in (
                (
                    "legacy image contract",
                    lambda value: value.update(image_contract="2"),
                    "image contract",
                ),
                (
                    "invalid policy",
                    lambda value: value.update(upgrade_policy="invalid"),
                    "upgrade policy",
                ),
                (
                    "bootstrap tool digest drift",
                    lambda value: value["bootstrap_tools"].update(
                        {"package-project-image.py": "0" * 64},
                    ),
                    "bootstrap tool",
                ),
            ):
                changed = json.loads(json.dumps(original))
                mutate(changed)
                payload_path.write_text(
                    json.dumps(changed, sort_keys=True) + "\n", encoding="ascii",
                )
                payload_path.chmod(0o600)
                with self.subTest(label=label), self.assertRaisesRegex(
                    self.tool.ProjectImageError, message,
                ):
                    self.tool.install_bundled_project(
                        bundled_root=bundled,
                        root=live,
                        verify_only=False,
                        required_uid=os.getuid(),
                    )
                self.assertEqual([], list(live.iterdir()))


if __name__ == "__main__":
    unittest.main()
