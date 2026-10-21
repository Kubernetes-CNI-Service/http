"""NOT RUN: completed-evidence serialization/reader DATA contracts, not IB authority."""
import copy
from hashlib import sha256
import os
from pathlib import Path
import unittest

from monitor.issue_tracker_cycle_source import (
    CycleSourceHoldError, _hold_completed_cycle_replay, read_completed_cycle_evidence,
)
from test_cases import completed_collection_source_read_fixture as fixture


def expected_cycle(case, observed):
    return (type(observed) is tuple and len(observed) == 1
        and observed[0].sequence == 1 and observed[0].scope == 'prod'
        and observed[0].project_key == sha256(str(case.project).encode()).hexdigest()
        and observed[0].cycle_id == case.start['cycle_id']
        and observed[0].source_slots == ('ethernet/prod', 'infiniband/prod', 'nvlink/prod')
        and observed[0].qualifying is True
        and observed[0].summary_sha256 == case.summary_sha
        and observed[0].completion_sha256 == case.completion_sha)


class CompletedSourceReadLeaseDirectTests(unittest.TestCase):
    def test_real_read_lease_preserves_parent_cooldown_and_has_no_collection_surface(self):
        acquire, Reader, _hold = fixture.api(self)
        case = fixture.make_completed_unit()
        before = fixture.snapshot(case.root)
        facts = {}
        with acquire(str(case.project), status_dir=case.status) as lease:
            facts['lease_is_collecting_gate'] = isinstance(lease, fixture.WORKER.CollectionGate)
            facts['has_decision'] = hasattr(lease, 'decision')
            facts['has_mark_success'] = hasattr(lease, 'mark_success')
            lease.verify()
            reader = Reader(lease=lease)
            facts['reader_type'] = type(reader)
            facts['subclasses_writer'] = issubclass(Reader, fixture.WORKER.CollectionCycleStore)
            facts['reader_gate'] = reader.gate is lease
            facts['reader_binding'] = (
                reader.project_identity, reader.project_key, reader.scope, reader.source,
                Path(reader.root_status_dir), Path(reader.records_dir), Path(reader.witness_path))
            facts['lease_binding'] = (lease.project, lease.scope, Path(lease.status_dir), lease.lane,
                tuple(lease.collection_keys), lease.state_name, lease.lock_name)
            facts['mutation_surfaces'] = [name for name in (
                'allocate_start', 'publish_launch', 'publish_completion', '_write_witness',
                '_publish_start', '_publish_crashed_completion', '_scan_and_reconcile', 'mark_success')
                if hasattr(reader, name)]
            try:
                fixture.WORKER.CollectionCycleStore(gate=lease)
            except BaseException as error:
                facts['writer_rejected'] = error
            else:
                facts['writer_rejected'] = None
            lock_fd = lease._lock_fd  # Passive observation of the actual acquired FD.
            info = os.fstat(lock_fd)
            facts['held_lock_matches_name'] = (info.st_dev, info.st_ino) == (
                case.lock.lstat().st_dev, case.lock.lstat().st_ino)
            with _hold_completed_cycle_replay(reader) as verify:
                facts['cycles'] = read_completed_cycle_evidence(reader)
                verify()
                facts['cycles_again'] = read_completed_cycle_evidence(reader)
            copied = copy.copy(lease)
            facts['copy_is_distinct'] = copied is not lease
            try:
                Reader(lease=copied)
            except BaseException as error:
                facts['live_copy_rejected'] = error
            else:
                facts['live_copy_rejected'] = None
            facts['busy'] = fixture.raw_contender(case.lock)
            lease.verify()
        # Observe immediately, before opening anything that could reuse this slot.
        facts['original_lock_closed'] = fixture.fd_closed(lock_fd)
        after = fixture.snapshot(case.root)
        facts['available_after_exit'] = fixture.raw_contender(case.lock)
        for name, action in (
            ('released_lease', lease.verify),
            ('released_reader', lambda: read_completed_cycle_evidence(reader)),
            ('old_parent_store', lambda: read_completed_cycle_evidence(case.store)),
            ('copied_lease', lambda: Reader(lease=copy.copy(lease))),
            ('foreign_lease', lambda: Reader(lease=object())),
        ):
            try:
                action()
            except BaseException as error:
                facts[name] = error
            else:
                facts[name] = None
        final = fixture.snapshot(case.root)
        self.assertEqual((False, 'cooldown'), case.cooldown)
        self.assertFalse(facts['lease_is_collecting_gate'])
        self.assertFalse(facts['has_decision'])
        self.assertFalse(facts['has_mark_success'])
        self.assertIs(Reader, facts['reader_type'])
        self.assertFalse(facts['subclasses_writer'])
        self.assertTrue(facts['reader_gate'])
        self.assertEqual((str(case.project), sha256(str(case.project).encode()).hexdigest(),
            'prod', 'switch_collection', case.status, case.store.records_dir, case.store.witness_path),
            facts['reader_binding'])
        self.assertEqual((str(case.project), 'prod', case.status, 'completed-source-read',
            ('prod-ethernet', 'prod-infiniband', 'prod-nvlink'),
            '.switch-collection-cooldown.json', '.switch-collection-cooldown.lock'), facts['lease_binding'])
        self.assertEqual([], facts['mutation_surfaces'])
        self.assertIsInstance(facts['writer_rejected'], fixture.WORKER.CollectionCycleHoldError)
        self.assertTrue(facts['held_lock_matches_name'])
        self.assertTrue(expected_cycle(case, facts['cycles']))
        self.assertTrue(expected_cycle(case, facts['cycles_again']))
        self.assertTrue(facts['copy_is_distinct'])
        self.assertIsInstance(facts['live_copy_rejected'], fixture.WORKER.CollectionCycleHoldError)
        self.assertEqual(b'BUSY\n', facts['busy'])
        self.assertEqual(b'ACQUIRED\n', facts['available_after_exit'])
        self.assertTrue(facts['original_lock_closed'])
        self.assertEqual(before, after)
        self.assertEqual(before, final)
        self.assertIsInstance(facts['released_lease'], _hold)
        self.assertIsInstance(facts['released_reader'], CycleSourceHoldError)
        self.assertIsInstance(facts['old_parent_store'], CycleSourceHoldError)
        self.assertIsInstance(facts['copied_lease'], fixture.WORKER.CollectionCycleHoldError)
        self.assertIsInstance(facts['foreign_lease'], fixture.WORKER.CollectionCycleHoldError)

    def test_contention_missing_linked_or_rebound_originals_never_create_or_adopt(self):
        acquire, Reader, hold = fixture.api(self)
        for fault in ('busy', 'missing-status', 'missing-lock', 'linked-lock',
                      'missing-state', 'linked-state', 'lock-rebind', 'state-rebind',
                      'witness-rebind', 'completion-rebind'):
            with self.subTest(fault=fault):
                case = fixture.make_completed_unit()
                # Mandatory genuine healthy native-lock/read semantic precondition.
                with acquire(str(case.project), status_dir=case.status) as lease:
                    reader = Reader(lease=lease)
                    with _hold_completed_cycle_replay(reader):
                        healthy = read_completed_cycle_evidence(reader)
                self.assertEqual((False, 'cooldown'), case.cooldown)
                self.assertTrue(expected_cycle(case, healthy))
                if fault.endswith('-rebind'):
                    facts = {'inner': None, 'returned': None, 'body_complete': False}
                    tail = None
                    try:
                        with acquire(str(case.project), status_dir=case.status) as lease:
                            reader = Reader(lease=lease)
                            with _hold_completed_cycle_replay(reader):
                                current = read_completed_cycle_evidence(reader)
                                if not expected_cycle(case, current):
                                    facts['unexpected_healthy'] = current
                                else:
                                    selected = {'lock-rebind': case.lock, 'state-rebind': case.state,
                                        'witness-rebind': case.store.witness_path,
                                        'completion-rebind': case.completion}[fault]
                                    old, new, raw, retained = fixture.rebind(selected)
                                    facts['new_inode'] = old != new
                                    facts['same_bytes'] = raw == selected.read_bytes() == retained.read_bytes()
                                    after_fault = fixture.snapshot(case.root)
                                    try:
                                        facts['returned'] = read_completed_cycle_evidence(reader)
                                    except BaseException as error:
                                        facts['inner'] = error
                                    if fault in ('lock-rebind', 'state-rebind'):
                                        try:
                                            lease.verify()
                                        except BaseException as error:
                                            facts['lease_rejected'] = error
                                        else:
                                            facts['lease_rejected'] = None
                                    facts['body_complete'] = True
                    except BaseException as error:
                        tail = error  # Tail-only rejection is never the inner oracle.
                    after = fixture.snapshot(case.root)
                    self.assertTrue(facts['body_complete'], 'fault NOT REACHED without healthy read')
                    self.assertTrue(facts['new_inode'])
                    self.assertTrue(facts['same_bytes'])
                    self.assertIsInstance(facts['inner'], CycleSourceHoldError)
                    self.assertIsNone(facts['returned'])
                    self.assertEqual(after_fault, after)
                    if fault in ('lock-rebind', 'state-rebind'):
                        self.assertIsInstance(facts['lease_rejected'], hold)
                    if tail is not None:
                        self.assertIsInstance(tail, (hold, CycleSourceHoldError))
                    continue
                if fault != 'busy':
                    selected = {'missing-status': case.status, 'missing-lock': case.lock,
                        'linked-lock': case.lock, 'missing-state': case.state,
                        'linked-state': case.state}[fault]
                    retained = selected.with_name(selected.name + '.test-retained-original')
                    selected.rename(retained)
                    if fault.startswith('linked-'):
                        selected.symlink_to(retained.name)
                before = fixture.snapshot(case.root)
                caught = None
                yielded = False
                if fault == 'busy':
                    with fixture.raw_holder(case.lock):
                        try:
                            with acquire(str(case.project), status_dir=case.status):
                                yielded = True
                        except BaseException as error:
                            caught = error
                else:
                    try:
                        with acquire(str(case.project), status_dir=case.status):
                            yielded = True
                    except BaseException as error:
                        caught = error
                after = fixture.snapshot(case.root)
                available = (fixture.raw_contender(case.lock)
                             if fault in ('busy', 'missing-state', 'linked-state') else None)
                self.assertFalse(yielded)
                self.assertIsInstance(caught, hold)
                self.assertEqual(before, after)
                if available is not None:
                    self.assertEqual(b'ACQUIRED\n', available)
