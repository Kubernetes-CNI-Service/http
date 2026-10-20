"""SOURCE-only provider source-close poison test, isolated in an owned child.

Only the actual fixed sibling _HeldFile close gets one ordinary EIO. It does
NOT call raw close for that original. Its uncertain descriptor is never retried
or rescued; the child exits with the private tree retained. Other closes really
delegate. No numeric-FD census, device, package factory substitution, or source
permission DTO is involved. The child uses the same normal Python/dependencies
as the root runner (not -I, which would remove its known PyYAML dependency).

This is a fixture/source lifecycle test. Audited write attempts are a limited
passive witness, not a generic native sandbox or an after-UNKNOWN bytes scan.
"""
import contextlib
import errno
import importlib
import inspect
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

# A fresh child gets the SAME actual coherent source root, not fake module
# metadata. No subject source or test assertion is generated from an outcome.
if __name__ == '__main__' and len(sys.argv) == 3 and sys.argv[1] == '--close-probe':
    _bundle = Path(sys.argv[2]).absolute()
    sys.path[:0] = [str(_bundle), str(_bundle / 'tools')]

from test_cases import test_ibsw3_scp_provider_source as original_fixture

RETAINED = []


def _close_probe():
    subject = original_fixture.SUBJECT
    inputs = importlib.import_module('ibsw_upgrade_inputs')
    source = importlib.import_module('ibsw_upgrade_scp')
    source_path = Path(subject.__file__).absolute().parent / 'ibsw_upgrade_scp.py'
    named = source_path.lstat()
    source_key = (named.st_dev, named.st_ino, stat.S_IFMT(named.st_mode))
    fixture = original_fixture.manual.ManualTests()
    root = Path(tempfile.mkdtemp(prefix='ib-provider-close-unknown-')).resolve()
    # No TemporaryDirectory/finalizer can silently clean this uncertain tree.
    project, _home, _known, _logs = fixture.fixture(root)
    packages = root / 'packages'; packages.mkdir(mode=0o700)
    package = packages / 'nvos-amd64-25.03.1010.bin'
    package.write_bytes(b'abc'); package.chmod(0o600)
    args = (*fixture.arguments(project), '--package-dir', str(packages))
    raw_close, raw_open = os.close, os.open
    raw_profile = sys.getprofile()
    if raw_profile is not None:
        raise RuntimeError('cannot replace another profile owner')
    counts = {'fault': 0, 'source_audit': 0, 'source_closes': 0,
              'target_close_retry': 0, 'factory': 0, 'package_open': 0}
    errors, snapshots = {}, {}
    target_fd = None
    fault_held = None
    tail = OSError(errno.EIO, 'independent original provider source close failure')
    audit_enabled = False
    write_attempts = []
    package_literals = (str(package), package.name,
                        os.fsencode(str(package)), os.fsencode(package.name))
    audit_code = subject._fixed_package_source_api.__code__
    held_close_code = inputs._HeldFile.close.__code__
    conditional_code = inputs._CandidateDescriptor.conditional_close.__code__

    def audited(event, values):
        # Passive only. No getframe/repr/locals, no exception, no changed result.
        if not audit_enabled:
            return
        if event == 'open' and len(values) == 3:
            path, _mode, flags = values
            if isinstance(path, (str, bytes)) and isinstance(flags, int):
                absolute = os.fsdecode(path)
                if absolute.startswith(str(root) + '/') and flags & (
                        os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                    write_attempts.append('open-write')
        elif event in ('os.remove', 'os.rename', 'os.rmdir', 'os.mkdir', 'os.link', 'os.symlink'):
            if any(isinstance(value, (str, bytes)) and
                   os.fsdecode(value).startswith(str(root) + '/') for value in values):
                write_attempts.append(event)

    def opened(path, *pargs, **kwargs):
        if isinstance(path, (str, bytes, os.PathLike)) and os.fspath(path) in package_literals:
            counts['package_open'] += 1
        return raw_open(path, *pargs, **kwargs)

    def closed(fd):
        nonlocal target_fd, fault_held
        caller = inspect.currentframe().f_back
        try:
            # Exact original close chain. Merely sharing a numeric FD or inode
            # in another caller is not permission to inject or adopt its owner.
            chain = (caller, caller.f_back, caller.f_back.f_back)
            selected = (
                chain[0].f_code is conditional_code and chain[0].f_globals is vars(inputs)
                and chain[1].f_code is held_close_code and chain[1].f_globals is vars(inputs)
                and chain[2].f_code is audit_code and chain[2].f_globals is vars(subject)
                and chain[2].f_locals.get('scope') is parent)
            if selected:
                info = os.fstat(fd)
                key = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
                held = chain[1].f_locals.get('self')
                if (key == source_key and type(held) is inputs._HeldFile
                        and held.name == 'ibsw_upgrade_scp.py' and held.fd == fd
                        and held.directory.path == source_path.parent):
                    counts['source_closes'] += 1
                    if target_fd is None:
                        target_fd = fd
                        fault_held = held
                        RETAINED.append(held)
                        counts['fault'] += 1
                        raise tail  # Deliberately do not raw-close this original.
                    if fd == target_fd:
                        counts['target_close_retry'] += 1
                        raise tail  # No numeric rescue/retry even if caller is wrong.
            return raw_close(fd)
        finally:
            del caller

    def profiled(frame, event, value):
        if event == 'call':
            if frame.f_code is audit_code and frame.f_globals is vars(subject):
                counts['source_audit'] += 1
            if (frame.f_code is source.package_content_owner.__code__
                    and frame.f_globals is vars(source)):
                counts['factory'] += 1

    def attempt(label, callback):
        try:
            callback()
        except Exception as error:
            errors[label] = error
        else:
            errors[label] = None
        snapshots[label] = dict(counts)

    with fixture.no_deployment_or_filesystem_locks(), \
         mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('no nested process')), \
         mock.patch.object(socket, 'create_connection', side_effect=AssertionError('no network')):
        prepared = subject.prepare_manual_run(original_fixture.APP.__file__, str(project), args)
        parent = subject.open_manual_run(original_fixture.APP.__file__, str(project), args,
                                         prepared['run_directory'])
        parent.__enter__()  # Actual original input/run scope; no mocked verify.
        RETAINED.extend((parent, root, tail, errors))
        # All preparation is complete before this narrowly selected fault.
        sys.addaudithook(audited)
        audit_enabled = True
        with mock.patch.object(os, 'open', new=opened), \
             mock.patch.object(os, 'close', new=closed):
            sys.setprofile(profiled)
            try:
                attempt('freeze', lambda: parent.freeze_package_sources((('os', 1),),
                    deadline=time.monotonic() + 4, max_fds=64))
                cleanup_registered = bool(parent.cleanup_issues)
                original_tail_retained = (fault_held is not None and
                    any(issue is tail for issue in fault_held.cleanup_issues))
                no_owner = parent._package_source_owner is None
                attempt('verify', parent.verify)
                attempt('refreeze', lambda: parent.freeze_package_sources((('os', 1),),
                    deadline=time.monotonic() + 4, max_fds=64))
                attempt('first_close', parent.close)
                attempt('repeat_close', parent.close)
            finally:
                sys.setprofile(raw_profile)
                audit_enabled = False
    # Do not invoke parent.__exit__, clean the private root, probe the unknown
    # FD, or turn a failed close into a best-effort rescue. JSON is memory-only.
    return {'child_pid': os.getpid(), 'retained_tree': str(root),
            'counts': counts, 'snapshots': snapshots,
            'cleanup_registered': cleanup_registered,
            'original_tail_retained': original_tail_retained, 'no_owner': no_owner,
            'write_attempts': write_attempts,
            'error_types': {label: None if value is None else type(value).__name__
                            for label, value in errors.items()},
            'freeze_typed': type(errors['freeze']) is subject.SharedUpgradeHold,
            'all_rejected': {label: isinstance(value, Exception) for label, value in errors.items()}}


class LazyScpSourceCloseTests(unittest.TestCase):
    def test_provider_critical_close_poison_survives_verify_refreeze_and_repeat_close(self):
        bundle = Path(original_fixture.SUBJECT.__file__).absolute().parent.parent
        command = [sys.executable, '-B', str(Path(__file__).absolute()), '--close-probe', str(bundle)]
        # Diagnostic-only outer bound; original admission deadline remains 4s.
        # subprocess.run owns/reaps only this newly returned child and its pipes.
        result = subprocess.run(command, cwd=tempfile.gettempdir(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(1, len(lines), 'child must return one pure memory result')
        facts = json.loads(lines[0])
        self.assertNotEqual(os.getpid(), facts['child_pid'])
        self.assertEqual(1, facts['counts']['fault'], 'ACTUAL_ORIGINAL_SOURCE_CLOSE_FAULT_MUST_FIRE')
        self.assertIs(facts['cleanup_registered'], True)
        self.assertIs(facts['no_owner'], True)
        self.assertIs(facts['freeze_typed'], True)
        self.assertIs(facts['original_tail_retained'], True)
        self.assertEqual(0, facts['counts']['factory'])
        self.assertEqual(0, facts['counts']['package_open'])
        self.assertEqual(0, facts['counts']['target_close_retry'])
        self.assertEqual([], facts['write_attempts'])
        initial = facts['snapshots']['freeze']
        self.assertEqual(1, initial['source_audit'])
        self.assertEqual(1, initial['source_closes'])
        for label in ('verify', 'refreeze', 'first_close', 'repeat_close'):
            self.assertIs(facts['all_rejected'][label], True, label + '_MUST_REMAIN_HOLD')
            self.assertEqual(initial, facts['snapshots'][label],
                             label + '_MUST_NOT_REAUDIT_OR_RETRY_THE_SOURCE')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--close-probe':
        print(json.dumps(_close_probe(), sort_keys=True))
    else:
        unittest.main()
