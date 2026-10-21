"""NOT RUN: real private C6 -> parent gate exit -> read lease -> actual C5.

Not A integration, native root deployment, SDK, sender, Cloud or deadline proof.
"""
from hashlib import sha256
import json
import os
import socket
import subprocess
from types import FunctionType
import unittest
from unittest import mock

from monitor.issue_tracker_cycle_source import (
    CycleSourceHoldError, _hold_completed_cycle_replay, read_completed_cycle_evidence,
)
from test_cases import completed_collection_source_read_fixture as fixture


class CompletedSourceReadLeaseWorkflowTests(unittest.TestCase):
    def test_protected_c6_parent_gate_exit_then_read_lease_replays_real_three_panel_c5(self):
        acquire, Reader, _hold = fixture.api(self)
        facts = {}
        def body(case, committed, _artifacts, parent, events):
            from monitor import collection_ib_producer as producer
            from monitor.issue_tracker_collected_source import collected_changes
            from monitor.issue_tracker_source_model import TrackerChanges
            from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
            from monitor.issue_tracker_state_owner import current_k, tracker_writer
            from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
            from test_cases import issue_tracker_cable_post_c6_fixture as original
            facts['parent_default'] = parent.enforce_cooldown
            facts['parent_closed'] = parent._lock_fd == -1
            facts['parent_events'] = tuple(row[0] for row in events)
            facts['parent_close_confirmed'] = bool(events and events[-1][0] == 'exit_return'
                                                    and events[-1][2] is True)
            before_local = original.local_evidence(case, committed)
            local_stats = {path: fixture.stat9(path.lstat()) for path in before_local}
            facts['old_store_rejected'] = None
            try:
                read_completed_cycle_evidence(case.store)
            except BaseException as error:
                facts['old_store_rejected'] = error
            status = case.root / 'monitor/status'
            with fixture.WORKER.CollectionGate(str(case.project), 'prod', status_dir=status) as control:
                facts['cooldown'] = (control.decision.allowed, control.decision.reason)
            # The ordinary control above legitimately fchmods LOCK; no such
            # contender is used during this new lease's immutability witness.
            before_status = fixture.snapshot(status)
            project_key = sha256(str(case.project).encode()).hexdigest()
            authority_path = (case.root / 'var/lib/http-ztp-container/ib-producer-authority'
                              / (project_key + '.json'))
            authority_raw = authority_path.read_bytes()
            facts['authority_sha'] = sha256(authority_raw).hexdigest()
            facts['authority_mode'] = authority_path.lstat().st_mode & 0o777
            facts['protected_reader_types'] = tuple(type(value) for value in (
                producer.load_ib_producer_authority, producer.recheck_ib_producer_authority,
                producer._open_protected_attestation_dir))
            authority = producer.load_ib_producer_authority(project_key=project_key,
                                                            project_root=case.project)
            producer.recheck_ib_producer_authority(authority)
            facts['actual_authority_sha'] = authority.sha256
            with mock.patch.object(socket, 'socket', side_effect=AssertionError('NETWORK_FORBIDDEN')) as network, \
                 mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('CHILD_FORBIDDEN_AFTER_C6')) as children:
                with acquire(str(case.project), status_dir=status) as lease:
                    lease.verify()
                    reader = Reader(lease=lease)
                    facts['actual_reader_type'] = type(reader)
                    facts['separate_lease'] = reader.gate is lease and lease is not parent
                    lock_fd = lease._lock_fd
                    with tracker_writer(case.project, case.publication) as token:
                        settings = current_k(token)
                        whitelist = read_whitelist_workbook(case.template)
                        with _hold_completed_cycle_replay(reader) as verify:
                            qualified = qualify_prod_stage_l(reader, http_root=case.root,
                                settings=settings, whitelist_snapshot=whitelist,
                                whitelist_path=case.template, writer_token=token)
                            facts['qualified'] = qualified.qualified
                            changes = collected_changes(qualified.candidates)
                            facts['changes_type'] = type(changes)
                            facts['expected_type'] = TrackerChanges
                            facts['counts'] = (len(changes.cabling), len(changes.switch))
                            facts['keys'] = {item.activity_key for item in (*changes.cabling, *changes.switch)}
                            facts['families'] = {item.activity_key[0] for item in (*changes.cabling, *changes.switch)}
                            facts['endpoints'] = {item.activity_key: (item.expected_endpoints, item.actual_endpoints)
                                                 for item in changes.cabling}
                            cycles = read_completed_cycle_evidence(reader)
                            facts['cycle_count'] = len(cycles)
                            facts['cycle_slots'] = cycles[-1].source_slots
                            facts['completion_sha'] = cycles[-1].completion_sha256
                            facts['actual_completion_sha'] = sha256(case.store.completion_path(1).read_bytes()).hexdigest()
                            verify()
                        lease.verify()
                facts['read_lease_closed'] = fixture.fd_closed(lock_fd)
                facts['network_count'] = network.call_count
                facts['children_count'] = children.call_count
            facts['status_unchanged'] = before_status == fixture.snapshot(status)
            facts['local_unchanged'] = before_local == original.local_evidence(case, committed)
            facts['local_stat9_unchanged'] = local_stats == {
                path: fixture.stat9(path.lstat()) for path in before_local}
            cycle_id = cycles[-1].cycle_id
            attestation_path = (case.root / 'var/lib/http-ztp-container/ib-producer-attestations'
                                / project_key / (cycle_id + '.json'))
            attestation_raw = producer._read_protected_attestation(project_key, cycle_id)
            facts['attestation_exact'] = attestation_path.read_bytes() == attestation_raw
            attestation = json.loads(attestation_raw)
            facts['attestation_binding'] = (attestation['project_key'], attestation['cycle_id'],
                                            attestation['authority_sha256'])
            facts['expected_attestation_binding'] = (project_key, cycle_id, facts['authority_sha'])
            generation = case.project / '.tracker/generations' / committed.receipt.generation_id
            facts['manifest_sha'] = sha256((generation / 'MANIFEST').read_bytes()).hexdigest()
            facts['receipt_manifest_sha'] = committed.receipt.manifest_id
            facts['workbook_sha'] = sha256((case.publication /
                (committed.receipt.generation_id + '.xlsx')).read_bytes()).hexdigest()
            facts['prepared_sha'] = sha256(committed.prepared.xlsx_bytes).hexdigest()
            facts['receipt_published_sha'] = committed.receipt.published_sha256
        fixture.run_protected_after_parent_exit(self, body)
        # No assertions below can be normalized/swallowed by a live owner.
        self.assertIs(True, facts['parent_default'])
        self.assertTrue(facts['parent_closed'])
        self.assertEqual(('mark_success_return', 'exit_call', 'exit_return'), facts['parent_events'])
        self.assertTrue(facts['parent_close_confirmed'])
        self.assertEqual((False, 'cooldown'), facts['cooldown'])
        self.assertIsInstance(facts['old_store_rejected'], CycleSourceHoldError)
        self.assertIs(Reader, facts['actual_reader_type'])
        self.assertTrue(facts['separate_lease'])
        self.assertTrue(facts['qualified'])
        self.assertEqual((FunctionType, FunctionType, FunctionType), facts['protected_reader_types'])
        self.assertEqual(0o600, facts['authority_mode'])
        self.assertEqual(facts['authority_sha'], facts['actual_authority_sha'])
        self.assertTrue(facts['attestation_exact'])
        self.assertEqual(facts['expected_attestation_binding'], facts['attestation_binding'])
        self.assertIs(facts['expected_type'], facts['changes_type'])
        self.assertEqual((2, 2), facts['counts'])
        self.assertEqual({'eth_cabling', 'ib_cabling', 'switch'}, facts['families'])
        self.assertEqual({
            ('eth_cabling', 'leaf-a', 'swp1', 'Mis-wiring'),
            ('ib_cabling', 'leaf01', 'sw1p1', 'Mis-wiring'),
            ('switch', 'leaf-a', 'fan', 'PSU1/FAN1'),
            ('switch', 'nvsw01', 'asic_temp', 'ASIC1'),
        }, facts['keys'])
        self.assertEqual({
            ('eth_cabling', 'leaf-a', 'swp1', 'Mis-wiring'): (
                ('leaf-a', 'swp1', 'leaf-z', 'swp2'), ('foreign-z', 'swp9', 'leaf-a', 'swp1')),
            ('ib_cabling', 'leaf01', 'sw1p1', 'Mis-wiring'): (
                ('leaf01', 'sw1p1', 'server01', 'mlx5_0'), ('leaf01', 'sw1p1', 'server02', 'mlx5_1')),
        }, facts['endpoints'])
        self.assertEqual(1, facts['cycle_count'])
        self.assertEqual(('ethernet/prod', 'infiniband/prod', 'nvlink/prod'), facts['cycle_slots'])
        self.assertEqual(facts['actual_completion_sha'], facts['completion_sha'])
        self.assertEqual(facts['receipt_manifest_sha'], facts['manifest_sha'])
        self.assertEqual(facts['receipt_published_sha'], facts['workbook_sha'])
        self.assertEqual(facts['receipt_published_sha'], facts['prepared_sha'])
        self.assertTrue(facts['read_lease_closed'])
        self.assertTrue(facts['status_unchanged'])
        self.assertTrue(facts['local_unchanged'])
        self.assertTrue(facts['local_stat9_unchanged'])
        self.assertEqual((0, 0), (facts['network_count'], facts['children_count']))
