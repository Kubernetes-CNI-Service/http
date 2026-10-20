"""UNRUN independent failure contracts. LOCAL DATA only, no native SCP or ACK.

Run each whole in its own root-owned bounded interpreter. Critical close faults
may retain an original FD; no saved numeric FD is rescued/retried by this test.
"""
import errno
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

from test_cases import test_ibsw3_scp_stage_scope as BASE
driver = BASE.driver


from test_cases.ibsw3_scp_test_isolation import isolated_whole

class StageDurabilityBoundaryTests(unittest.TestCase):
    def exercise(self, mode):
        fixture = BASE.StagePackageSourceBoundaryV3Tests()
        fixture.capabilities()
        state = dict(events=[], writers=[], writes=0, links=0, fired=False, errors={})
        cleanup_error = None
        def after_close():
            state['cold'] = state['record_path'].read_bytes()
        try:
            with fixture.original_graph(after_close=after_close) as (parent, child, leaf, owner, package, stage, held):
                state['record_path'] = stage.path/'package-source.json'
                state['root'] = str(package.parent.parent)
                originals = dict(held)
                original_payloads = {name: obj.payload for name, obj in held.items()}
                init = driver._JournalWriter.__init__
                finish = driver._JournalWriter.finish
                fsync, close, write, link = os.fsync, os.close, os.write, os.link
                active_finish = []
                fault = OSError(errno.EIO, 'literal critical source companion failure')
                def initialize(writer, scope, directory):
                    init(writer, scope, directory)
                    if scope is child and directory is stage:
                        state['writers'].append(writer)
                def is_writer_fd(fd):
                    return any(any(owned.fd == fd for owned in writer.owners) for writer in state['writers'])
                def fail(label):
                    state['fired'] = True
                    state['events'].append(label)
                    state['at_fault'] = (state['writes'], state['links'], len(state['writers']))
                    raise fault
                def syncing(fd):
                    if is_writer_fd(fd):
                        state['events'].append('file-fsync')
                        if mode == 'file-fsync' and not state['fired']:
                            fail('file-fsync-refused')
                    elif fd == stage.fd:
                        state['events'].append('directory-fsync')
                        if mode == 'directory-fsync' and not state['fired']:
                            fail('directory-fsync-refused')
                    return fsync(fd)
                def writing(fd, data):
                    result = write(fd, data)
                    if is_writer_fd(fd):
                        state['writes'] += 1
                    return result
                def linking(source, target, *args, **kwargs):
                    result = link(source, target, *args, **kwargs)
                    if (target == 'package-source.json' and kwargs.get('dst_dir_fd') == stage.fd):
                        state['links'] += 1
                        state['events'].append('exclusive-link')
                    return result
                def finishing(writer):
                    if any(writer is original for original in state['writers']):
                        active_finish.append(writer)
                    try:
                        return finish(writer)
                    finally:
                        if active_finish and active_finish[-1] is writer:
                            active_finish.pop()
                def closing(fd):
                    if active_finish and any(owned.fd == fd for owned in active_finish[-1].owners):
                        # Original writer object+current descriptor generation;
                        # no unrelated FD or filename-only match is injected.
                        owned = next(owned for owned in active_finish[-1].owners if owned.fd == fd)
                        actual = os.fstat(fd)
                        if owned.owner.key != (actual.st_dev, actual.st_ino, stat.S_IFMT(actual.st_mode)):
                            raise AssertionError('fixture lost original writer generation')
                        state['events'].append('writer-finish-close')
                        if mode == 'writer-finish-close' and not state['fired']:
                            fail('writer-finish-close-refused')
                    return close(fd)
                with patch.object(driver._JournalWriter, '__init__', initialize), \
                     patch.object(driver._JournalWriter, 'finish', finishing), \
                     patch.object(driver.os, 'fsync', syncing), \
                     patch.object(driver.os, 'close', closing), \
                     patch.object(driver.os, 'write', writing), \
                     patch.object(driver.os, 'link', linking):
                    try:
                        with child._request_namespace_lease():
                            child._capture_package_source_data_locked(leaf, 'os', 1)
                        state['returned'] = True
                    except Exception as error:
                        state['errors']['capture'] = error
                    if mode is not None:
                        for label, operation in (('parent', parent.verify), ('child', child.verify)):
                            try:
                                operation()
                            except Exception as error:
                                state['errors'][label] = error
                        try:
                            with child._request_namespace_lease():
                                child._capture_package_source_data_locked(leaf, 'os', 1)
                        except Exception as error:
                            state['errors']['retry'] = error
                        # A sibling acquisition must be rejected by the parent
                        # gate. If baseline permits it, close that exact scope,
                        # never saved FD numbers, and record the negative fact.
                        sibling = None
                        try:
                            sibling = parent.fork_readiness_scope(BASE.HOST)
                        except Exception as error:
                            state['errors']['sibling'] = error
                        finally:
                            if sibling is not None:
                                sibling.close()
                        state['after_checks'] = (state['writes'], state['links'], len(state['writers']))
                    else:
                        state['record'] = child._hold(stage, 'package-source.json').payload
                        state['events'].append('capture-returned')
                state['same_objects'] = all(child.files[(str(stage.path), name)] is original for name, original in originals.items())
                state['same_payloads'] = all(original.payload == original_payloads[name] for name, original in originals.items())
                state['no_dispatch'] = not (stage.path/'component-dispatch.json').exists()
                state['no_ack'] = not (stage.path/'download-ack').exists()
        except Exception as error:
            cleanup_error = error
        state['cleanup_error'] = cleanup_error
        return state

    def check_failure(self, mode):
        state = self.exercise(mode)
        self.assertTrue(state['fired'], 'fault must reach the actual selected critical boundary')
        self.assertNotIn('returned', state)
        self.assertIsNotNone(state['errors'].get('capture'))
        for role in ('parent', 'child', 'retry', 'sibling'):
            self.assertIsNotNone(state['errors'].get(role), role+' must HOLD after uncertain persistence')
        self.assertEqual(state['at_fault'], state['after_checks'], 'no retry writer/link or record refresh')
        self.assertTrue(state['same_objects'])
        self.assertTrue(state['same_payloads'])
        self.assertTrue(state['no_dispatch'])
        self.assertTrue(state['no_ack'])
        self.assertIsNotNone(state['cleanup_error'], 'shared poison stays visible through real final verify')
        self.assertIn(state['root'], BASE.RETAINED_TREES)

    @isolated_whole
    def test_file_fsync_failure_poison_parent_child_and_sibling_without_retry(self):
        self.check_failure('file-fsync')

    @isolated_whole
    def test_directory_fsync_failure_visible_record_does_not_become_committed_by_retry(self):
        self.check_failure('directory-fsync')

    @isolated_whole
    def test_critical_writer_finish_close_failure_keeps_shared_hold(self):
        self.check_failure('writer-finish-close')

    @isolated_whole
    def test_healthy_companion_returns_only_after_real_sync_and_writer_finish(self):
        state = self.exercise(None)
        self.assertEqual({}, state['errors'])
        self.assertIsNone(state['cleanup_error'])
        self.assertTrue(state['returned'])
        self.assertFalse(state['fired'])
        self.assertEqual(1, len(state['writers']))
        for before, after in (('file-fsync', 'exclusive-link'),
                              ('exclusive-link', 'directory-fsync'),
                              ('directory-fsync', 'writer-finish-close'),
                              ('writer-finish-close', 'capture-returned')):
            self.assertLess(state['events'].index(before), state['events'].index(after))
        self.assertEqual(state['record'], state['cold'])
        self.assertEqual('PACKAGE_SOURCE_PRELAUNCH_DATA_ONLY', json.loads(state['cold'])['state'])
        self.assertTrue(state['no_dispatch'])
        self.assertTrue(state['no_ack'])

    @isolated_whole
    def test_scope_repeated_close_preserves_real_holder_close_uncertainty(self):
        fixture = BASE.StagePackageSourceBoundaryV3Tests()
        fixture.capabilities()
        state = {}
        outer_error = None
        def after_child(parent, child, owner):
            # No live borrow: this tests real holder.close propagation, not the
            # separate premature-parent-close lifecycle branch.
            state['no_borrowers'] = not parent._package_source_borrowers
            state['no_lifecycle_marker'] = parent._package_source_lifecycle_failure is None
            path, row = next(iter(owner._files.items()))
            target = row[0]
            key = (row[3][0], row[3][1], stat.S_IFMT(row[3][2]))
            close = os.close
            attempts = []
            def closing(fd):
                if fd == target:
                    metadata = os.fstat(fd)
                    if (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)) != key:
                        raise AssertionError('fixture lost exact original package FD')
                    attempts.append(fd)
                    raise OSError(errno.EIO, 'literal original holder close failure')
                return close(fd)
            with patch.object(driver.os, 'close', closing):
                try:
                    parent.close()
                except Exception as error:
                    state['first'] = error
                count = len(attempts)
                try:
                    parent.close()
                except Exception as error:
                    state['second'] = error
                state['no_retry'] = len(attempts) == count == 1
                state['scope_issues'] = bool(parent.cleanup_issues)
                state['holder_issues'] = bool(owner.cleanup_issues)
            # Re-propagate the ACTUAL first cleanup error to retain this graph.
            # No FD cleanup, slot rescue, or synthetic success is supplied.
            if 'first' in state:
                raise state['first']
        try:
            with fixture.original_graph(after_child_close=after_child) as values:
                state['root'] = str(values[4].parent.parent)
        except Exception as error:
            outer_error = error
        self.assertTrue(state['no_borrowers'])
        self.assertTrue(state['no_lifecycle_marker'])
        self.assertIsNotNone(state.get('first'))
        self.assertIsNotNone(state.get('second'), 'scope must not convert unknown holder close into clean success')
        self.assertTrue(state['no_retry'])
        self.assertTrue(state['scope_issues'])
        self.assertTrue(state['holder_issues'])
        self.assertIs(state['first'], outer_error)
        self.assertIn(state['root'], BASE.RETAINED_TREES)
