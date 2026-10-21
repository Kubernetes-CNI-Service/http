"""NOT RUN: one owned-cold-child lease-close UNIT whole, no native/send grant.

Run this whole ALONE in a newly owned cold unittest interpreter with no other
Python threads. Only after genuine existing-only lease/Reader replay succeeds,
temporarily delegate shared os.close and fault the one witnessed lease LOCK:
the original close succeeds once, then EIO is raised. No retry/rescue/FD scan.
All private fixture roots and their original evidence are retained.
"""
from contextlib import ExitStack, contextmanager
import errno
from hashlib import sha256
import os
import sys
import threading
from types import FunctionType
import unittest
from unittest import mock

from monitor.issue_tracker_cycle_source import (
    _hold_completed_cycle_replay, read_completed_cycle_evidence,
)
from test_cases import completed_collection_source_read_fixture as fixture


def _literal_completed_cycle(case, observed):
    """Independent UNIT record semantics, not an IB qualification oracle."""
    return (type(observed) is tuple and len(observed) == 1
        and observed[0].sequence == 1 and observed[0].scope == 'prod'
        and observed[0].project_key == sha256(str(case.project).encode()).hexdigest()
        and observed[0].cycle_id == case.start['cycle_id']
        and observed[0].source_slots == ('ethernet/prod', 'infiniband/prod', 'nvlink/prod')
        and observed[0].qualifying is True
        and observed[0].summary_sha256 == case.summary_sha
        and observed[0].completion_sha256 == case.completion_sha)


@contextmanager
def _observe_actual_lease_opens(opening):
    """Observe original code+globals returns; no registry or supplied FD grant."""
    prior = sys.getprofile()
    if prior is not None:
        raise AssertionError('cannot replace an existing profile observer')
    rows = []
    def observe(frame, event, value):
        if (event == 'return' and frame.f_code is opening.__code__
                and frame.f_globals is opening.__globals__
                and type(value) is tuple and len(value) == 2
                and type(value[0]) is int):
            fd = value[0]
            try:
                info = os.fstat(fd)
            except OSError as error:
                rows.append((frame.f_locals.get('name'), fd, None, error))
            else:
                rows.append((frame.f_locals.get('name'), fd,
                             (info.st_dev, info.st_ino), None))
    try:
        sys.setprofile(observe)
        yield rows
    finally:
        sys.setprofile(prior)


class CompletedSourceReadLeaseCloseTests(unittest.TestCase):
    def _exercise_owned_child_actual_lock_close_then_eio_preserves_body_interrupt_and_cause(self):
        acquire, Reader, hold = fixture.api(self)
        opening = getattr(fixture.GATE, '_completed_read_open', None)
        self.assertTrue(type(opening) is FunctionType
            and opening.__globals__ is vars(fixture.GATE),
            'MISSING_ORIGINAL_COMPLETED_READ_OPEN_OBSERVER')
        self.assertEqual([threading.current_thread()], threading.enumerate(),
            'root must run this whole alone in its own fresh cold unittest child')
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted):
                case = fixture.make_completed_unit()
                before = fixture.snapshot(case.root)
                facts = {'healthy': None, 'healthy_ok': False, 'witness_ready': False,
                    'body_complete': False, 'target_calls': 0, 'faults': 0,
                    'closed_slot_retries': 0, 'opened': (), 'target_fd': None,
                    'target_key': None, 'busy': None, 'caught': None}
                cause = ValueError('independent completed-read body cause')
                interrupt = KeyboardInterrupt('independent completed-read body interrupt')
                interrupt.__cause__ = cause
                patches = ExitStack()
                observations = []
                try:
                    with _observe_actual_lease_opens(opening) as observations:
                        with acquire(str(case.project), status_dir=case.status) as lease:
                            lease.verify()
                            reader = Reader(lease=lease)
                            with _hold_completed_cycle_replay(reader) as verify:
                                facts['healthy'] = read_completed_cycle_evidence(reader)
                                verify()
                            facts['healthy_ok'] = _literal_completed_cycle(case, facts['healthy'])
                            facts['opened'] = tuple(observations)
                            lock_rows = [row for row in observations
                                if row[0] == '.switch-collection-cooldown.lock']
                            if facts['healthy_ok'] and len(lock_rows) == 1:
                                _name, fd, key, error = lock_rows[0]
                                named = case.lock.lstat()
                                current = os.fstat(fd)
                                facts['target_fd'] = fd
                                facts['target_key'] = key
                                facts['witness_ready'] = (
                                    error is None and key == (named.st_dev, named.st_ino)
                                    and key == (current.st_dev, current.st_ino)
                                    and fd == lease._lock_fd
                                    and len({row[1] for row in observations}) == len(observations)
                                    and all(row[2] is not None and row[3] is None
                                            for row in observations))
                            if facts['witness_ready']:
                                facts['busy'] = fixture.raw_contender(case.lock)
                            # A failed healthy/witness precondition NEVER injects
                            # a fault or earns close-negative coverage.
                            if facts['witness_ready'] and facts['busy'] == b'BUSY\n':
                                native_close = os.close
                                fd, key = facts['target_fd'], facts['target_key']
                                def closing(selected_fd):
                                    if selected_fd == fd:
                                        try:
                                            info = os.fstat(fd)
                                        except OSError as error:
                                            if facts['faults'] and error.errno == errno.EBADF:
                                                facts['closed_slot_retries'] += 1
                                            return native_close(selected_fd)
                                        if (info.st_dev, info.st_ino) == key:
                                            facts['target_calls'] += 1
                                            if facts['faults'] == 0:
                                                native_close(fd)
                                                facts['faults'] += 1
                                                raise OSError(errno.EIO,
                                                    'independent after actual lease LOCK close')
                                        elif facts['faults'] == 0:
                                            raise AssertionError('witnessed lease LOCK FD changed')
                                    # Every other close, including a genuinely
                                    # different later object, is delegated.
                                    return native_close(selected_fd)
                                patches.enter_context(mock.patch.object(os, 'close', side_effect=closing))
                                facts['body_complete'] = True
                                if interrupted:
                                    raise interrupt
                except BaseException as error:
                    facts['caught'] = error
                finally:
                    patches.close()  # Restore shared function; never rescue any FD.
                facts['opened'] = tuple(observations)
                # No new opens before these original numeric slots are observed.
                target = facts['target_fd']
                facts['target_closed'] = target is not None and fixture.fd_closed(target)
                facts['captured_originals_closed'] = tuple(
                    fixture.fd_closed(row[1]) for row in facts['opened'])
                after = fixture.snapshot(case.root)
                available = (fixture.raw_contender(case.lock)
                             if facts['witness_ready'] else None)
                final = fixture.snapshot(case.root)
                # ALL assertions below are outside lease, replay, profile,
                # shared-close patch and their finalizers.
                self.assertEqual([threading.current_thread()], threading.enumerate())
                self.assertEqual((False, 'cooldown'), case.cooldown)
                self.assertTrue(_literal_completed_cycle(case, facts['healthy']))
                self.assertTrue(facts['healthy_ok'])
                self.assertTrue(facts['witness_ready'])
                self.assertEqual(b'BUSY\n', facts['busy'])
                self.assertTrue(facts['body_complete'], 'fault NOT_REACHED without healthy replay')
                self.assertEqual(1, facts['target_calls'])
                self.assertEqual(1, facts['faults'])
                self.assertEqual(0, facts['closed_slot_retries'])
                self.assertTrue(facts['target_closed'])
                self.assertTrue(facts['opened'])
                self.assertEqual((True,) * len(facts['opened']),
                                 facts['captured_originals_closed'])
                if interrupted:
                    self.assertIs(interrupt, facts['caught'])
                    self.assertIs(cause, facts['caught'].__cause__)
                else:
                    self.assertIsInstance(facts['caught'], hold)
                self.assertEqual(b'ACQUIRED\n', available)
                self.assertEqual(before, after)
                self.assertEqual(before, final)


    def test_owned_child_actual_lock_close_then_eio_preserves_body_interrupt_and_cause(self):
        from test_cases.completed_read_close_isolation import run_close_whole
        run_close_whole(self)


if __name__ == '__main__':
    unittest.main()
