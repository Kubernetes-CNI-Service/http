"""UNRUN: real holder constructor failure before parent registration.

LOCAL declaration scope only. No fake factory return, SCP launch or ACK.
Root runs each exact whole in its own owned bounded child as before.
"""
import errno
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from test_cases import test_ibsw3_scp_stage_scope as BASE
driver = BASE.driver
import ibsw_upgrade_scp as scp


from test_cases.ibsw3_scp_test_isolation import isolated_whole

class StageConstructorBoundaryTests(unittest.TestCase):
    def exercise(self, failing):
        fixture = BASE.StagePackageSourceBoundaryV3Tests()
        fixture.capabilities()
        state = dict(calls=0, fired=False, opened=[], bytes=[], errors={})
        try:
            with fixture.owned_tree() as name:
                root = Path(name)
                state['root'] = str(root)
                manual = BASE.manual.ManualTests()
                project, home, known, logs = manual.fixture(root)
                packages = root/'packages'
                packages.mkdir(mode=0o700)
                package = packages/'nvos-amd64-25.03.1010.bin'
                package.write_bytes(b'abc')
                package.chmod(0o600)
                original = package.stat()
                key = (original.st_dev, original.st_ino, stat.S_IFMT(original.st_mode))
                args = (*manual.arguments(project), '--package-dir', str(packages))
                with manual.no_deployment_or_filesystem_locks(), \
                     patch.object(subprocess, 'Popen', side_effect=AssertionError('no native process')), \
                     patch.object(socket, 'create_connection', side_effect=AssertionError('no network')):
                    prepared = driver.prepare_manual_run(BASE.app.__file__, str(project), args)
                    with driver.open_manual_run(BASE.app.__file__, str(project), args, prepared['run_directory']) as parent:
                        original_files = dict(parent.files)
                        real_factory = scp.package_content_owner
                        real_open, real_read, real_fstat = os.open, os.read, os.fstat
                        active = []
                        profile_errors = []
                        factory_code = real_factory.__code__
                        factory_globals = real_factory.__globals__
                        def observe_factory(frame, event, arg):
                            # Passive events only for the original factory's
                            # exact code AND globals. Never replaces a provider.
                            if frame.f_code is not factory_code or frame.f_globals is not factory_globals:
                                return
                            if event == 'call':
                                state['calls'] += 1
                                active.append(frame)
                            elif event == 'return':
                                if not active or active[-1] is not frame:
                                    profile_errors.append('factory profile return mismatch')
                                else:
                                    active.pop()
                        def opening(*args, **kwargs):
                            fd = real_open(*args, **kwargs)
                            if active:
                                state['opened'].append(fd)
                            return fd
                        def reading(fd, count):
                            if active:
                                row = real_fstat(fd)
                                if (row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode)) == key:
                                    if failing and not state['fired']:
                                        state['fired'] = True
                                        raise OSError(errno.EIO, 'literal real package read failure')
                                    data = real_read(fd, count)
                                    state['bytes'].append(data)
                                    return data
                            return real_read(fd, count)
                        def freeze():
                            return parent.freeze_package_sources((('os', 1),),
                                deadline=time.monotonic()+4, max_fds=64)
                        prior_profile = sys.getprofile()
                        if prior_profile is not None:
                            raise AssertionError('refuse preexisting profile; no provider or profile takeover')
                        with patch.object(scp.os, 'open', opening), \
                             patch.object(scp.os, 'read', reading):
                            sys.setprofile(observe_factory)
                            try:
                                try:
                                    owner = freeze()
                                    state['owner'] = owner
                                except Exception as error:
                                    state['errors']['construct'] = error
                                if failing:
                                    # Immediately after REAL constructor cleanup,
                                    # before any later open could reuse these slots.
                                    closed = []
                                    for fd in state['opened']:
                                        try:
                                            real_fstat(fd)
                                        except OSError as error:
                                            closed.append(error.errno == errno.EBADF)
                                        else:
                                            closed.append(False)
                                    state['first_constructor_closed'] = bool(closed) and all(closed)
                                    for label, operation in (('verify', parent.verify), ('refreeze', freeze),
                                            ('new-stage', lambda: parent.prepare_requested_step(BASE.HOST, 'os', 1))):
                                        try:
                                            operation()
                                        except Exception as error:
                                            state['errors'][label] = error
                                    sibling = None
                                    try:
                                        sibling = parent.fork_readiness_scope(BASE.HOST)
                                    except Exception as error:
                                        state['errors']['sibling'] = error
                                    finally:
                                        if sibling is not None:
                                            sibling.close()
                                    state['same_originals'] = set(parent.files) == set(original_files) and all(
                                        parent.files[name] is obj for name, obj in original_files.items())
                                    state['no_stage'] = not (parent.run_directory/BASE.HOST/'os-0001').exists()
                                else:
                                    parent.verify()
                                    state['same_owner'] = parent._package_source_owner is owner
                                    with parent.fork_readiness_scope(BASE.HOST) as child:
                                        child.verify()
                                        state['same_borrow'] = child._package_source_owner is owner
                                    owner.verify()
                                    state['no_borrowers'] = not parent._package_source_borrowers
                            finally:
                                intact = sys.getprofile() is observe_factory
                                sys.setprofile(prior_profile)
                            if not intact or active or profile_errors:
                                raise AssertionError('original factory profile lifecycle changed')
                        state['package_unchanged'] = package.read_bytes() == b'abc' and package.stat().st_ino == original.st_ino
        except Exception as error:
            state['cleanup_error'] = error
        return state

    @isolated_whole
    def test_real_constructor_read_failure_revokes_parent_and_blocks_refreeze_or_new_scope(self):
        state = self.exercise(True)
        self.assertTrue(state['fired'], 'actual original package read must fail inside real constructor')
        self.assertIsInstance(state['errors'].get('construct'), scp.ContentHold)
        self.assertTrue(state['first_constructor_closed'])
        for role in ('verify', 'refreeze', 'new-stage', 'sibling'):
            self.assertIsNotNone(state['errors'].get(role), role+' must HOLD after failed acquisition')
        self.assertEqual(1, state['calls'], 'failed source acquisition is not silently retried')
        self.assertEqual([], state['bytes'], 'no later fresh baseline read after failed acquisition')
        self.assertTrue(state['same_originals'])
        self.assertTrue(state['no_stage'])
        self.assertTrue(state['package_unchanged'])
        self.assertIsNotNone(state.get('cleanup_error'), 'shared failure remains visible after real scope cleanup')
        self.assertIn(state['root'], BASE.RETAINED_TREES)

    @isolated_whole
    def test_same_real_constructor_healthy_source_is_borrowed_and_naturally_closed(self):
        state = self.exercise(False)
        self.assertEqual({}, state['errors'])
        self.assertNotIn('cleanup_error', state)
        self.assertFalse(state['fired'])
        self.assertEqual(1, state['calls'])
        self.assertEqual(b'abc', b''.join(state['bytes']))
        self.assertTrue(state['same_owner'])
        self.assertTrue(state['same_borrow'])
        self.assertTrue(state['no_borrowers'])
        self.assertTrue(state['package_unchanged'])
        with self.assertRaises(scp.ContentHold):
            state['owner'].verify()
