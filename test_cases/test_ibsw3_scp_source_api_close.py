"""UNRUN source audit cleanup direct, real LOCAL original graph, not native."""
import errno
import os
import sys
import threading
import unittest
from unittest.mock import patch

from test_cases import test_ibsw3_scp_stage_scope as BASE


class ScpSourceApiCloseTests(unittest.TestCase):
    def test_actual_provider_image_close_failure_is_sticky_and_first_ni_keeps_cause(self):
        driver = BASE.driver
        function = getattr(driver, '_fixed_scp_source_api', None)
        self.assertTrue(callable(function), 'fixed original-source API capability required')
        inputs = sys.modules['ibsw_upgrade_inputs']
        conditional = inputs._CandidateDescriptor.conditional_close
        constructor = inputs._HeldFile.__init__
        read_original = inputs._HeldFile._read_original
        read_primitive = os.pread
        raw_open, raw_fstat = os.open, os.fstat
        for interrupt in (False, True):
            with self.subTest(interrupt=interrupt):
                observations = dict(api_frame=None, selected=None, selected_owner=None,
                    selected_fd=None, selected_directory=None, close_calls=0, ebadf=False,
                    eio_fired=False, ni_fired=False, second_opens=0, body_completed=False,
                    failure=None, repeat_error=None, verify_error=None, cleanup=(), marker=None)
                primary = KeyboardInterrupt('synthetic original body interruption')
                cause = RuntimeError('preexisting interruption cause')
                primary.__cause__ = cause
                eio = OSError(errno.EIO, 'synthetic critical source-image close report')
                outer_error = None
                parent = None
                self.assertIsNone(sys.getprofile())
                # threading.getprofile()/gettrace() are 3.10+; on 3.9 they are read from the hooks threading.setprofile()/settrace() store.
                self.assertIsNone(getattr(threading, 'getprofile', lambda: threading._profile_hook)())

                def observe(frame, event, argument):
                    if frame.f_code is function.__code__ and frame.f_globals is function.__globals__:
                        if event == 'call': observations['api_frame'] = frame
                        elif event == 'return': observations['api_frame'] = None
                    elif (event == 'return' and frame.f_code is constructor.__code__
                            and frame.f_globals is constructor.__globals__):
                        audit = observations['api_frame']
                        original = frame.f_locals.get('self')
                        if (audit is not None and observations['selected'] is None
                                and type(original) is inputs._HeldFile
                                and original.fd is not None
                                and original.directory is audit.f_locals.get('directory')
                                and original.name == 'ibsw_upgrade_scp.py'):
                            # Direct actual constructor/actual API frame joint;
                            # neither pathname nor descriptor number grants authority.
                            observations['selected'] = original
                            observations['selected_owner'] = original._owner
                            observations['selected_fd'] = original.fd
                            observations['selected_directory'] = original.directory

                def close_once(owner):
                    if owner is not observations['selected_owner']:
                        return conditional(owner)
                    observations['close_calls'] += 1
                    issue = conditional(owner)  # Actual key/fstat/close, once.
                    if issue is not None:
                        return issue
                    try:
                        raw_fstat(observations['selected_fd'])
                    except OSError as error:
                        observations['ebadf'] = error.errno == errno.EBADF
                    observations['eio_fired'] = True
                    return eio

                def final_read(fd, length, offset):
                    value = read_primitive(fd, length, offset)
                    caller = sys._getframe(1)
                    original = observations['selected']
                    if (interrupt and not observations['ni_fired'] and original is not None
                            and observations['api_frame'] is not None
                            and caller.f_code is read_original.__code__
                            and caller.f_globals is read_original.__globals__
                            and caller.f_locals.get('self') is original
                            and fd == original.fd and length == 1
                            and offset == original.identity[4] and value == b''):
                        # The real EOF pread completed; no fabricated verification.
                        observations['ni_fired'] = True
                        raise primary
                    return value

                def count_second_open(*args, **kwargs):
                    observations['second_opens'] += 1
                    return raw_open(*args, **kwargs)

                try:
                    with BASE.StagePackageSourceBoundaryV3Tests().original_graph() as graph:
                        parent = graph[0]
                        healthy = function(parent)
                        if not (type(healthy) is tuple and len(healthy) == 19):
                            raise AssertionError('genuine source API healthy control must reach actual return')
                        try:
                            sys.setprofile(observe)
                            with patch.object(inputs._CandidateDescriptor, 'conditional_close', close_once), \
                                 patch.object(os, 'pread', final_read):
                                try:
                                    function(parent)
                                except BaseException as failure:
                                    observations['failure'] = failure
                        finally:
                            sys.setprofile(None)
                        observations['cleanup'] = tuple(parent.cleanup_issues)
                        observations['marker'] = parent._package_source_lifecycle_failure
                        try:
                            parent.verify()
                        except BaseException as failure:
                            observations['verify_error'] = failure
                        with patch.object(os, 'open', count_second_open):
                            try:
                                function(parent)
                            except BaseException as failure:
                                observations['repeat_error'] = failure
                        observations['body_completed'] = True
                except BaseException as failure:
                    outer_error = failure
                finally:
                    # Original profile was checked None. No test-owned FD rescue.
                    sys.setprofile(None)
                # All literal assertions are outside original graph ownership:
                # expected cleanup HOLD cannot consume a unittest AssertionError.
                self.assertTrue(observations['body_completed'], 'must reach the entire audit body')
                self.assertIsNotNone(observations['selected'])
                self.assertIs(observations['selected_owner'], observations['selected']._owner)
                self.assertIs(observations['selected_directory'], observations['selected'].directory)
                self.assertEqual(1, observations['close_calls'])
                self.assertTrue(observations['ebadf'], 'original close must actually finish before injected EIO')
                self.assertTrue(observations['eio_fired'])
                self.assertTrue(any(issue is eio for issue in observations['selected'].cleanup_issues))
                self.assertIsNone(observations['selected'].fd)
                self.assertTrue(observations['selected_owner'].attempted)
                self.assertTrue(any(issue is not None for issue in observations['cleanup']))
                self.assertIsInstance(observations['marker'], driver.SharedUpgradeHold)
                self.assertIsInstance(observations['verify_error'], ValueError)
                self.assertIsInstance(observations['repeat_error'], ValueError)
                self.assertIn('HOLD', str(observations['repeat_error']))
                self.assertEqual(0, observations['second_opens'], 'sticky refusal before reopening audit images')
                self.assertIsInstance(outer_error, Exception, 'original graph must report cleanup HOLD')
                if interrupt:
                    self.assertTrue(observations['ni_fired'])
                    self.assertIs(primary, observations['failure'])
                    self.assertIs(cause, observations['failure'].__cause__)
                else:
                    self.assertFalse(observations['ni_fired'])
                    self.assertIsInstance(observations['failure'], driver.SharedUpgradeHold)
