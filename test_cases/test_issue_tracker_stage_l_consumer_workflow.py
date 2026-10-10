"""Real protected Stage-L source, C5/C6 and fail-closed workflow contracts."""

from __future__ import annotations

from dataclasses import asdict, replace
from contextlib import ExitStack, contextmanager
import datetime as dt
import hashlib
import json
from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock
import zipfile

import xlsxwriter

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_ib_runtime import IbBoundCycleReport, IbReportLink
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_issue_tracker_local_workbook import fake_workbook
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx

from test_cases.test_issue_tracker_stage_l_consumer import ProdStageLFixture


class ProdStageLConsumerWorkflowTests(ProdStageLFixture):
    def _original_business_read_acquisition_probe(self, mode):
        from monitor import issue_tracker_history_preread_journal as preread
        self.assertTrue(callable(getattr(preread, '_hold_owned_original_business_history_reads', None)),
            'actual protected source needs fixed original business/History fresh reads')
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, receipted_intent_probe=True,
            native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True, native_catalog_launch_probe=(mode, observed))
        suffix = {'business-originals': 'fresh-read-only',
                  'business-originals-rebind': 'original-rebind-hold'}[mode]
        self.assertEqual(['ETH Cabling:' + suffix, 'IB Cabling:' + suffix], observed)

    def test_actual_protected_business_and_history_fixed_acquisition_preserves_original_count(self):
        self._original_business_read_acquisition_probe('business-originals')

    def test_actual_business_original_rebound_during_last_native_read_refuses_without_count(self):
        self._original_business_read_acquisition_probe('business-originals-rebind')

    def _default_source_read_preparation_probe(self, mode):
        from monitor import issue_tracker_remote_history_match as remote
        self.assertTrue(callable(getattr(remote,'_prepare_current_project_online_observation',None)),
            'default coordinator must prepare actual current source and fresh project reads')
        observed=[]
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True,receipted_intent_probe=True,
            native_catalog_probe=True,native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True,native_catalog_launch_probe=(mode,observed))
        suffix={'prepare':'visible-only-no-count',
            'prepare-mixed-accounting':'mixed-original-visible-only-no-count',
            'prepare-quota-rebind':'original-rebind-hold-no-count',
            'prepare-finalizer-expiry':'post-finalizer-expiry-hold-no-count'}[mode]
        self.assertEqual(['ETH Cabling:'+suffix,'IB Cabling:'+suffix],observed)

    def test_default_preparation_replays_actual_source_then_fresh_project_gate_reads_without_count(self):
        self._default_source_read_preparation_probe('prepare')

    def test_default_preparation_actual_protected_pending_uses_mixed_original_quota_without_count(self):
        self._default_source_read_preparation_probe('prepare-mixed-accounting')

    def test_default_preparation_original_quota_rebind_during_actual_last_read_refuses_without_count(self):
        self._default_source_read_preparation_probe('prepare-quota-rebind')

    def test_default_preparation_actual_read_expiry_after_last_original_finalizer_refuses_without_count(self):
        self._default_source_read_preparation_probe('prepare-finalizer-expiry')

    def _protected_shared_counter_route(self, *, launch=False, retry=False):
        from test_cases import test_req7_global_attempt_journal as fixtures
        actual_load = fixtures.load; routed = []; results = []
        with ExitStack() as patches:
            def load_and_observe():
                module = actual_load(); counter = module.record_global_attempt_intent
                def count(owner,bound,unit):
                    routed.append(unit.unit_id)
                    result = counter(owner,bound,unit)
                    results.append((result.attempt_count,result.outcome))
                    return result
                patches.enter_context(mock.patch.object(module,'record_global_attempt_intent',side_effect=count))
                return module
            patches.enter_context(mock.patch.object(fixtures,'load',side_effect=load_and_observe))
            if retry:
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True,business_preread_probe=True,
                    original_reserved_probe=True,receipted_intent_probe=True,
                    owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='normal')
            else:
                marks = []
                options = dict(native_catalog_launch_probe=('normal',marks)) if launch else dict(
                    native_catalog_receipted_count_probe=marks)
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True,receipted_intent_probe=True,
                    native_catalog_probe=True,native_catalog_c6_origin_probe=True,
                    native_catalog_retained_probe=True,**options)
                self.assertEqual(2,len(marks))
        # Outside all sanitized production contexts: actual protected C5/C6,
        # and where selected, fresh reads/CLAIM/TLS must reach this boundary.
        self.assertEqual([(1,'UNKNOWN'),(2 if retry else 1,'UNKNOWN')],results,
            'every actual protected count, including identical retry, must reach the shared counter exactly once')
        self.assertEqual(2,len(routed))
        self.assertEqual(retry,routed[0]==routed[1],
            'retry binds one original unit; native ETH/IB source panels bind distinct units')

    def test_actual_protected_native_receipted_count_joins_shared_catalog_counter(self):
        self._protected_shared_counter_route()

    def test_actual_protected_native_fixed_request_joins_shared_catalog_counter(self):
        self._protected_shared_counter_route(launch=True)

    def test_actual_original_shared_retry_joins_the_same_catalog_counter(self):
        self._protected_shared_counter_route(retry=True)

    def test_original_unknown_unit_retries_after_a_new_real_cycle_without_recompile(self):
        self._exercise_original_unknown_retry()

    def test_same_byte_original_c6_replacement_after_old_retry_count_keeps_unpaired_intent(self):
        self._exercise_original_unknown_retry(replace_c6_after_count=True)

    def test_same_byte_current_high_water_replacement_after_old_retry_count_keeps_unpaired_intent(self):
        self._exercise_original_unknown_retry(replace_input_after_count='high_water')

    def test_same_byte_policy_replacement_after_old_retry_count_keeps_unpaired_intent(self):
        self._exercise_original_unknown_retry(replace_input_after_count='policy')

    def test_same_byte_w1_replacement_after_old_retry_count_keeps_unpaired_intent(self):
        self._exercise_original_unknown_retry(replace_input_after_count='w1')

    def _exercise_original_unknown_retry(self, *, replace_c6_after_count=False, replace_input_after_count=None):
        from test_cases import test_req7_global_attempt_journal as journal_fixture
        from monitor.collection_ib_producer import produce_worker_ib_analysis
        from tools.project_contract import build_collection_cycle_identity
        from test_cases.test_collection_cycle_persistence import TOKEN_2
        from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence

        native_load = journal_fixture.load
        advanced = []
        faults = []
        class OwnedRetryFaultObserved(Exception):
            pass

        def with_original_count_boundary():
            module = native_load()
            first = module.record_continuous_owned_attempt_intent
            retry = module.record_shared_retry_continuous_owned_attempt_intent

            def first_then_new_cycle(*args, **kwargs):
                result = first(*args, **kwargs)
                self.assertEqual((1, 'UNKNOWN'), (result.attempt_count, result.outcome))
                before = read_completed_cycle_evidence(self.store)
                self.assertEqual(1, len(before))
                identity = build_collection_cycle_identity(str(self.project), 'prod', 2, TOKEN_2)
                ib = produce_worker_ib_analysis(identity, project_root=self.project,
                    http_root=self.root,
                    clock=lambda: dt.datetime(2026, 9, 26, 4, 31, tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail('transport must remain the owned fixture'))
                cycle, _ = self._cycle(activity=True, derivation=True, ib_analysis=ib,
                    observed_peer='newer-not-original-peer', additional_eth_activity=True,
                    fabric_templates={'ethernet/prod': 'tan-leaf', 'nvlink/prod': 'border-leaf'})
                self.assertEqual(identity['cycle_id'], cycle['cycle_id'])
                self.assertNotEqual(before[-1].cycle_id, cycle['cycle_id'])
                advanced.append(True)
                return result

            def check_original_retry(*args, **kwargs):
                unit = args[2]
                wire, action = unit.wire_bytes, unit.action_preimage
                image = {p.relative_to(self.project).as_posix(): p.read_bytes()
                         for p in (self.project / '.tracker/generations').rglob('*') if p.is_file()}
                if not replace_c6_after_count and replace_input_after_count is None:
                    from monitor.issue_tracker_remote_history_match import observe_owned_unit_read_gates
                    gates = observe_owned_unit_read_gates(kwargs['writer_token'], args[0], args[1], unit,
                        whitelist_snapshot=kwargs['whitelist_snapshot'].whitelist,
                        identity_response=kwargs['identity_response'], headers_response=kwargs['headers_response'],
                        whitelist_response=kwargs['whitelist_response'], metadata_response=kwargs['metadata_response'])
                    ordinary = {key:kwargs[key] for key in ('qualified_source','store','writer_token',
                        'settings','whitelist_snapshot','expected_template_sha256','http_root','whitelist_path')}
                    with self.assertRaises(module.GlobalAttemptHold):
                        module.record_receipted_original_attempt_intent(
                            args[0], args[1], gates.identity, unit, **ordinary)
                    retained = module.inspect_global_unit(*args[:3])
                    self.assertEqual((1, 'UNKNOWN'), (retained.attempt_count, retained.outcome))
                    self.assertEqual([], list((self.project / '.tracker/admissions').glob('retry-*-intent.json')))
                if replace_c6_after_count or replace_input_after_count is not None:
                    manifest = self.project / '.tracker/generations' / json.loads(action)['identity']['generation_id'] / 'MANIFEST'
                    if replace_input_after_count is not None:
                        manifest = {'high_water':self.store.witness_path,
                                    'policy':self.project/'01-global.yaml', 'w1':self.template}[replace_input_after_count]
                    raw, inode = manifest.read_bytes(), manifest.stat().st_ino
                    mode = manifest.stat().st_mode & 0o777
                    preserved = self.project / 'owned-original-old-retry-manifest'
                    observe = module._observe
                    def replace_after_count(*values, **options):
                        result = observe(*values, **options)
                        if values[3]:
                            self.assertEqual((2, 'UNKNOWN'), (result.attempt_count, result.outcome))
                            manifest.rename(preserved)
                            manifest.write_bytes(raw); manifest.chmod(mode)
                            faults.append(True)
                        return result
                    with mock.patch.object(module, '_observe', side_effect=replace_after_count):
                        with self.assertRaises(module.GlobalAttemptHold):
                            retry(*args, **kwargs)
                    self.assertEqual([True], faults, 'reach the actual original durable second count')
                    retained = module.inspect_global_unit(*args[:3])
                    self.assertEqual((2, 'UNKNOWN'), (retained.attempt_count, retained.outcome))
                    self.assertEqual((wire, action), (unit.wire_bytes, unit.action_preimage))
                    self.assertEqual(raw, manifest.read_bytes()); self.assertEqual(raw, preserved.read_bytes())
                    self.assertNotEqual(inode, manifest.stat().st_ino)
                    self.assertTrue(list((self.project / '.tracker/admissions').glob('retry-*-intent.json')))
                    self.assertEqual([], list((self.project / '.tracker/admissions').glob('retry-*-count.json')))
                    self.assertEqual(image, {p.relative_to(self.project).as_posix(): p.read_bytes()
                        for p in (self.project / '.tracker/generations').rglob('*') if p.is_file()})
                    self.assertFalse(hasattr(retained, 'send_authority'))
                    raise OwnedRetryFaultObserved()
                result = retry(*args, **kwargs)
                self.assertEqual((2, 'UNKNOWN'), (result.attempt_count, result.outcome))
                self.assertEqual((wire, action), (unit.wire_bytes, unit.action_preimage))
                self.assertEqual(image, {p.relative_to(self.project).as_posix(): p.read_bytes()
                    for p in (self.project / '.tracker/generations').rglob('*') if p.is_file()})
                self.assertFalse(hasattr(result, 'send_authority'))
                return result

            module.record_continuous_owned_attempt_intent = first_then_new_cycle
            module.record_shared_retry_continuous_owned_attempt_intent = check_original_retry
            return module

        with mock.patch.object(journal_fixture, 'load', side_effect=with_original_count_boundary):
            def exercise():
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True, business_preread_probe=True,
                    original_reserved_probe=True, receipted_intent_probe=True,
                    owned_read_gates_probe=True, owned_continuity_probe=True, shared_retry_probe=True)
            if replace_c6_after_count or replace_input_after_count is not None:
                with self.assertRaises(OwnedRetryFaultObserved):
                    exercise()
            else:
                exercise()
        self.assertEqual([True], advanced)


    def _exercise_timed_out_boot_probe(self, **options):
        from test_cases.test_collection_cycle_persistence import WORKER

        original_run = subprocess.run
        original_is_file = Path.is_file
        timed_out_probes = []

        def bounded_probe(command, *args, **kwargs):
            if command == ["/usr/sbin/sysctl", "-n", "kern.boottime"]:
                timed_out_probes.append(command)
                raise subprocess.TimeoutExpired(command, 2)
            return original_run(command, *args, **kwargs)

        def no_linux_boot_file(path):
            return False if str(path) == "/proc/sys/kernel/random/boot_id" \
                else original_is_file(path)

        with mock.patch.object(WORKER.subprocess, "run", side_effect=bounded_probe), \
                mock.patch.object(WORKER.Path, "is_file", autospec=True,
                                  side_effect=no_linux_boot_file):
            self._exercise_real_protected_three_panel_fixture(
                skip_history=False, **options,
            )
        self.assertTrue(timed_out_probes, "the workflow must execute the injected fault")

    def test_boot_probe_timeout_does_not_admit_n_two_local_c6(self):
        self._exercise_timed_out_boot_probe(
            automatic_first=True, automatic_not_due=True,
        )

    def test_boot_probe_timeout_does_not_auto_readmit_manual_receipt(self):
        self._exercise_timed_out_boot_probe(replayed_auto=True)

    def test_real_nine_role_ib_and_eth_fourth_role_qualify_and_c5_reject_drift(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False)

    def test_real_protected_three_panel_sources_compile_literal_units_and_refuse_invented_values(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, source_unit_probe=True)

    def test_actual_protected_workbook_receipt_admission_bind_all_source_units_and_reject_drift(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, receipted_source_probe=True)

    def test_actual_receipt_source_and_full_row_images_derive_all_update_coordinates_and_preread(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_source_probe=True)

    def test_actual_source_receipt_global_owner_and_original_enrollment_derive_switch_inserts(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_switch_insert_probe=True)

    def test_actual_source_receipt_and_original_two_sheet_nv_derive_mixed_cabling_units(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True)

    def test_actual_protected_c6_source_compiles_native_nv_and_reads_same_original_catalog_unit(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True)

    def test_actual_protected_c6_native_nv_registers_unique_catalog_and_original_project_origin(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True, native_catalog_c6_origin_probe=True)

    def test_actual_protected_c6_native_nv_origin_global_and_retained_originals_stay_read_only(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True)

    def test_actual_protected_c6_native_nv_creator_receive_fault_holds_before_compile_and_closes_owned_fd(self):
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True,
            native_catalog_creator_first_stat_probe=observed)
        self.assertEqual(['ETH Cabling:actual-first-stat-fault:owned-fd-closed',
                          'IB Cabling:actual-first-stat-fault:owned-fd-closed'], observed)

    def test_actual_protected_native_nv_origin_history_quota_and_receipted_first_count_preserve_unknown(self):
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, receipted_intent_probe=True,
            native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True, native_catalog_receipted_count_probe=observed)
        self.assertEqual(['ETH Cabling:actual-receipted-count:unknown',
            'IB Cabling:actual-receipted-count:unknown'], observed)

    def _native_original_launch_probe(self, mode):
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, receipted_intent_probe=True,
            native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True, native_catalog_launch_probe=(mode, observed))
        self.assertEqual(['ETH Cabling:native-launch:' + mode,
            'IB Cabling:native-launch:' + mode], observed)

    def test_native_original_fresh_reads_count_claim_and_one_fixed_local_request(self):
        self._native_original_launch_probe('normal')

    def test_native_original_receipt_rebind_after_count_refuses_fixed_local_request(self):
        self._native_original_launch_probe('receipt-rebind')

    def test_native_original_issued_read_expiry_after_count_refuses_fixed_local_request(self):
        self._native_original_launch_probe('read-expiry')

    def _exercise_native_original_counted_launch(self, *, mode, observed, global_root, private_context,
            writer_token, spreadsheet_token, binding, credential, unit, identity, quota_raw, history_raw,
            reads, sheet, qualified, settings, committed, state, owner_module, global_journal):
        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests, load as load_read_gates
        from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests, load as load_mutation
        from test_cases.test_req7_sheets_read_decode import header_response, identity_response, response
        from test_cases.test_req7_online_whitelist_read import document as whitelist_document
        from monitor import issue_tracker_history_read_launcher as fixed_reads, issue_tracker_local_commit as local
        from contextlib import ExitStack
        import xml.etree.ElementTree as ET
        import socket
        load_read_gates()
        native = Req7OwnedHistoryMatchWorkflowTests()
        native.root = global_root; native.path = global_root/'etc/ssl/certs/ca-certificates.crt'
        native.path.parent.mkdir(parents=True); native.addCleanup = self.addCleanup
        namespace = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
        with zipfile.ZipFile(self.template) as archive:
            original_sheet = ET.fromstring(archive.read('xl/worksheets/sheet13.xml'))
        rows = []
        for original_row in original_sheet.find(namespace+'sheetData'):
            cells = [None]*6
            for cell in original_row:
                self.assertEqual('inlineStr', cell.get('t')); self.assertIsNone(cell.find(namespace+'f'))
                column = ord(cell.get('r')[0])-ord('A'); self.assertTrue(0 <= column < 6)
                cells[column] = ''.join(cell.itertext())
            rows.append(tuple(cells))
        whitelist_doc = whitelist_document(())
        whitelist_doc['sheets'][0]['properties']['sheetId'] = dict(identity.sheet_ids)['Whitelist']
        whitelist_doc['sheets'][0]['data'][0]['rowData'] = [
            {'values': [{} if value is None else {'userEnteredValue': {'stringValue': value}}
                for value in row]} for row in rows]
        def owned(kind, raw, **options):
            return native.read_owned(private_context, writer_token, spreadsheet_token,
                binding, credential, kind, json.loads(raw), raw_body=raw, **options)
        if mode in ('business-originals', 'business-originals-rebind'):
            from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests
            from monitor import issue_tracker_history_preread_journal as preread
            from monitor import issue_tracker_mutation_launcher as mutation
            before = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            actual, _credential, _raw = Req7HistoryReadLauncherWorkflowTests.project_auth(
                native, private_context, owner_module, spreadsheet_token, binding)
            documents = {'template_identity': response(identity_response()).data,
                'history_tail': history_raw.data, 'activity': reads[0]['discovery_response'].data,
                'insertion': reads[0]['occupancy_response'].data,
                'row': next(item['row_response'].data for item in reads if item['row_response'] is not None)}
            real_read = fixed_reads.OwnedProjectSheetsReadUnit.read_once
            issued = []; substituted = []; entered = []; refused = []
            def read(reader):
                body = documents[reader._kind]
                reply = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body
                with native.server(reply, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), ExitStack() as launched:
                    port = socket.getaddrinfo('sheets.googleapis.com', 443)[0][4][1]
                    calls, children = native.intercept(launched, native.child_fixture(port), writer_token, spreadsheet_token, binding)
                    value = real_read(reader)
                issued.append((reader._kind, len(records), len(calls), tuple(errors), children[0].returncode))
                if mode == 'business-originals-rebind' and reader._kind == 'row':
                    path = next(path for path in state.rglob('BUSINESS-RAW'))
                    raw = path.read_bytes(); inode = path.stat().st_ino
                    path.rename(global_root / 'preserved-business-read-original')
                    path.write_bytes(raw); path.chmod(0o600)
                    substituted.append((str(path.relative_to(state)), inode, path.stat().st_ino))
                return value
            with mock.patch.object(fixed_reads.OwnedProjectSheetsReadUnit, 'read_once', autospec=True, side_effect=read), \
                    mock.patch.object(global_journal, 'record_global_attempt_intent', wraps=global_journal.record_global_attempt_intent) as no_count, \
                    mock.patch.object(mutation, '_send_counted_original_once') as no_mutation:
                identity_raw = fixed_reads.OwnedProjectSheetsReadUnit(writer_token, spreadsheet_token,
                    binding, actual, read_kind='template_identity').read_once()
                def observe():
                    with preread._hold_owned_original_business_history_reads(writer_token,
                            spreadsheet_token, binding, unit, actual, identity_response=identity_raw) as (result, verify):
                        entered.append(True)
                        self.assertEqual((2, 0), (result.operations_retained, result.noop_operations))
                        verify()
                if mode == 'business-originals':
                    observe()
                else:
                    with self.assertRaises(preread.HistoryPrereadHold): observe()
                    refused.append(True)
            # Facts outside every exception sanitizer; no synthetic read permit.
            self.assertEqual([(kind, 1, 1, (), 0) for kind in
                ('template_identity', 'history_tail', 'activity', 'insertion', 'row')], issued)
            self.assertEqual([True] if mode == 'business-originals' else [], entered)
            self.assertEqual([] if mode == 'business-originals' else [True], refused)
            no_count.assert_not_called(); no_mutation.assert_not_called()
            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
            self.assertFalse(list(state.rglob('ATTEMPT-*'))); self.assertFalse(list(state.rglob('CLAIM-*')))
            after = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            if mode == 'business-originals': self.assertEqual(before, after)
            else:
                self.assertEqual(1, len(substituted)); name, old, new = substituted[0]
                self.assertNotEqual(old, new); self.assertEqual(before[name][1], after[name][1])
                self.assertEqual({k: v for k, v in before.items() if k != name},
                                 {k: v for k, v in after.items() if k != name})
            observed.append(sheet + (':fresh-read-only' if mode == 'business-originals' else ':original-rebind-hold'))
            return
        if mode in ('prepare','prepare-mixed-accounting','prepare-quota-rebind','prepare-finalizer-expiry'):
            from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests
            from monitor import issue_tracker_token_launcher as tokens
            from monitor import issue_tracker_remote_history_match as remote
            from monitor import issue_tracker_stage_l_consumer as source
            from monitor import issue_tracker_mutation_launcher as mutation
            from monitor import issue_tracker_unit_catalog as catalog
            from monitor import issue_tracker_metadata_reservation as quota
            before={str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            actual, _credential, _raw=Req7HistoryReadLauncherWorkflowTests.project_auth(
                native,private_context,owner_module,spreadsheet_token,binding)
            native.certificates('sheets.googleapis.com')
            documents={'template_identity':identity_response(),'template_headers':header_response(),
                'whitelist':whitelist_doc,'metadata':json.loads(quota_raw.data)}
            real_read=fixed_reads.OwnedProjectSheetsReadUnit.read_once
            real_source=source.qualify_prod_stage_l
            issued=[]; projections=[]; replaced=[]; refused=[]
            closed=[]; first_holder=[]; mixed_observations=[]
            real_hold=catalog.hold_pending_project_c6_units
            real_mixed_quota=quota._hold_owned_project_mixed_metadata_capacity
            real_clock=fixed_reads._monotonic
            @contextmanager
            def held_catalog(*args,**options):
                first = not first_holder
                first_holder.append(True)
                with real_hold(*args,**options) as actual_rows:
                    yield actual_rows
                # First acquired holder is last released. Its actual verifier
                # and cleanup run before the original read deadlines expire.
                if first: closed.append(True)
            @contextmanager
            def mixed_quota(*args,**options):
                with real_mixed_quota(*args,**options) as actual_budget:
                    budget,_verify=actual_budget
                    mixed_observations.append((budget.outcome,budget.outstanding_reservations))
                    yield actual_budget
            def post_finalizer_clock():
                return real_clock()+(31 if closed else 0)
            def qualify(*args,**options):
                value=real_source(*args,**options)
                projections.append(value); return value
            def read(reader):
                self.assertTrue(projections,'actual source must precede actual project reads')
                body=response(documents[reader._kind]).data
                reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
                with native.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as launched:
                    port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                    calls,children=native.intercept(launched,native.child_fixture(port),writer_token,spreadsheet_token,binding)
                    value=real_read(reader)
                issued.append((reader._kind,len(records),len(calls),tuple(errors),children[0].returncode))
                if mode=='prepare-quota-rebind' and reader._kind=='metadata':
                    path=next(path for path in state.rglob('RESERVATION') if path.parent.name.endswith('.metadata'))
                    raw=path.read_bytes(); inode=path.stat().st_ino
                    path.rename(global_root/'preserved-preparation-quota')
                    path.write_bytes(raw); path.chmod(0o600)
                    replaced.append((str(path.relative_to(state)),inode,path.stat().st_ino))
                return value
            with ExitStack() as preparation_boundary, \
                    mock.patch.object(source,'qualify_prod_stage_l',side_effect=qualify), \
                    mock.patch.object(fixed_reads.OwnedProjectSheetsReadUnit,'read_once',autospec=True,side_effect=read), \
                    mock.patch.object(tokens,'OwnedProjectTokenRefreshUnit') as no_second_oauth, \
                    mock.patch.object(global_journal,'record_global_attempt_intent',wraps=global_journal.record_global_attempt_intent) as no_count, \
                    mock.patch.object(mutation,'_send_counted_original_once') as no_mutation:
                if mode=='prepare-finalizer-expiry':
                    preparation_boundary.enter_context(mock.patch.object(catalog,
                        'hold_pending_project_c6_units',side_effect=held_catalog))
                    preparation_boundary.enter_context(mock.patch.object(fixed_reads,
                        '_monotonic',side_effect=post_finalizer_clock))
                if mode=='prepare-mixed-accounting':
                    preparation_boundary.enter_context(mock.patch.object(quota,
                        '_hold_owned_project_mixed_metadata_capacity',side_effect=mixed_quota))
                if mode in ('prepare','prepare-mixed-accounting'):
                    result=remote._prepare_current_project_online_observation(writer_token,spreadsheet_token,
                        binding,actual,_store=self.store,http_root=self.root)
                    self.assertEqual('VISIBLE_ONLY_UNPROVED',result)
                else:
                    with self.assertRaises(remote.RemoteHistoryHold):
                        remote._prepare_current_project_online_observation(writer_token,spreadsheet_token,
                            binding,actual,_store=self.store,http_root=self.root)
                    refused.append(True)
                no_second_oauth.assert_not_called(); no_count.assert_not_called(); no_mutation.assert_not_called()
            # Independent facts outside every implementation sanitizer.
            self.assertEqual([(kind,1,1,(),0) for kind in
                ('template_identity','template_headers','whitelist','metadata')],issued)
            positive = mode in ('prepare','prepare-mixed-accounting')
            self.assertGreaterEqual(len(projections),2 if positive else 1)
            self.assertEqual([] if positive else [True],refused)
            if mode=='prepare-mixed-accounting':
                self.assertEqual([('VISIBLE_ONLY_UNPROVED',1)],mixed_observations)
            if mode=='prepare-finalizer-expiry': self.assertEqual([True],closed)
            self.assertEqual(0,global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count)
            self.assertFalse(list(state.rglob('ATTEMPT-*'))); self.assertFalse(list(state.rglob('CLAIM-*')))
            after={str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            if mode!='prepare-quota-rebind': self.assertEqual(before,after)
            else:
                self.assertEqual(1,len(replaced)); name,old,new=replaced[0]
                self.assertNotEqual(old,new); self.assertEqual(before[name][1],after[name][1])
                self.assertEqual({k:v for k,v in before.items() if k!=name},{k:v for k,v in after.items() if k!=name})
            observed.append(sheet+{'prepare':':visible-only-no-count',
                'prepare-mixed-accounting':':mixed-original-visible-only-no-count',
                'prepare-quota-rebind':':original-rebind-hold-no-count',
                'prepare-finalizer-expiry':':post-finalizer-expiry-hold-no-count'}[mode])
            return
        bundle = {name:owned(kind, response(doc).data) for name,kind,doc in (
            ('identity_response','template_identity',identity_response()),
            ('headers_response','template_headers',header_response()),
            ('whitelist_response','whitelist',whitelist_doc),
            ('metadata_response','metadata',json.loads(quota_raw.data)))}
        bundle['history_response'] = owned('history_tail', history_raw.data)
        current = {role+'_response':owned(kind, reads[0][role+'_response'].data, sheet=sheet)
            for role,kind in (('discovery','activity'),('occupancy','insertion'))}
        bundle['business_reads'] = tuple({'operation_id':reading['operation_id'], **current,
            'row_response':None if reading['row_response'] is None else owned('row',
                reading['row_response'].data, sheet=sheet, row=3)} for reading in reads)
        mutation_fixture = Req7MutationLauncherWorkflowTests()
        mutation_fixture.root = global_root; mutation_fixture.path = native.path
        mutation_fixture.addCleanup = self.addCleanup; mutation = load_mutation()
        before = {str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
            for path in state.rglob('*') if path.is_file()}
        wire_response = b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        calls = []; children = []; reached = []; rejected = []
        with mutation_fixture.server(wire_response, hostname='sheets.googleapis.com',
                destination='sheets.googleapis.com') as (requests, errors), ExitStack() as transport:
            port = socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            def exercise():
                nonlocal calls, children
                with global_journal._hold_continuous_owned_attempt_wire(spreadsheet_token,binding,unit,
                        writer_token=writer_token,qualified_source=qualified,store=self.store,
                        settings=settings,whitelist_snapshot=self.snapshot,
                        expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                        whitelist_path=self.template,**bundle) as image:
                    reached.append('original-count-and-claim'); self.assertEqual(1,image.attempt_count)
                    calls,children = mutation_fixture.intercept(transport,local,owner_module,
                        writer_token,spreadsheet_token,binding,image,port)
                    if mode == 'receipt-rebind':
                        path = Path(self.store.project_identity)/'.tracker/generations'/committed.receipt.generation_id/'RECEIPT'
                        raw = path.read_bytes(); inode = path.stat().st_ino
                        path.rename(global_root/'owned-prelaunch-original-receipt')
                        path.write_bytes(raw); path.chmod(0o600)
                        self.assertNotEqual(inode,path.stat().st_ino); self.assertEqual(raw,path.read_bytes())
                    if mode == 'normal':
                        result = mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                        self.assertEqual((1,401,'UNKNOWN'),(result.attempt_count,result.status,result.outcome))
                        self.assertTrue(result.termination_confirmed)
                        with self.assertRaises(mutation.MutationLauncherHold):
                            mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                    else:
                        if mode == 'read-expiry':
                            clock = fixed_reads._monotonic
                            transport.enter_context(mock.patch.object(fixed_reads,'_monotonic',side_effect=lambda:clock()+31))
                        with self.assertRaises(mutation.MutationLauncherHold) as caught:
                            mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                        self.assertFalse(caught.exception.termination_confirmed); rejected.append('before-child')
            if mode == 'normal': exercise()
            else:
                with self.assertRaises(global_journal.GlobalAttemptHold): exercise()
            self.assertEqual(['original-count-and-claim'],reached)
            self.assertEqual([] if mode == 'normal' else ['before-child'],rejected)
            self.assertEqual(1 if mode == 'normal' else 0,len(calls))
            self.assertEqual(1 if mode == 'normal' else 0,len(children))
            self.assertEqual(1 if mode == 'normal' else 0,len(requests)); self.assertEqual([],errors)
            if requests: self.assertEqual(unit.wire_bytes,requests[0][2])
        retained = global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
        self.assertEqual((1,'UNKNOWN'),(retained.attempt_count,retained.outcome))
        after = {str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
            for path in state.rglob('*') if path.is_file()}
        for name,image in before.items():
            if '.journal/' not in name: self.assertEqual(image,after[name],name)
        observed.append(sheet + ':native-launch:' + mode)

    def test_actual_protected_native_nv_all_project_c6_fifo_keeps_originals_and_issues_no_send_permission(self):
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True, native_catalog_all_c6_fifo_probe=observed)
        self.assertEqual(['ETH Cabling:actual-all-project-c6:no-applied', 'ETH Cabling:actual-fifo:read-only',
                          'IB Cabling:actual-all-project-c6:no-applied', 'IB Cabling:actual-fifo:read-only'], observed)

    def test_native_compiler_holds_nv_original_drift_during_final_real_receipt_read(self):
        self._exercise_native_compiler_return_fault('same_byte_replace')

    def test_native_compiler_holds_nv_same_inode_rewrite_during_final_real_receipt_read(self):
        self._exercise_native_compiler_return_fault('same_inode_rewrite')

    def _exercise_native_compiler_return_fault(self, mode):
        marks = []; error = None
        try:
            self._exercise_real_protected_three_panel_fixture(skip_history=False,
                observed_cabling_insert_probe=True, native_catalog_probe=True,
                native_catalog_return_fault=(mode, marks))
        except Exception as exc:
            error = exc
        # Each method gets a fresh actual project/cycle fixture. Outer scope
        # HOLD must not mask a compiler that already returned a frozen unit.
        self.assertEqual([('injected', mode), ('compiler', 'HOLD'), ('catalog_written', False)], marks)
        self.assertIs(type(error), sys.modules['monitor.issue_tracker_nv_reservation'].NvReservationHold)

    def test_actual_receipted_cabling_unit_retains_original_business_images_across_unknown(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True, business_preread_probe=True)

    def test_actual_receipted_cabling_original_chain_dominates_reserved_count(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True, business_preread_probe=True, original_reserved_probe=True)

    def test_actual_original_c6_receipt_dominates_every_business_count_and_post_count_drift_holds(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True, business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True)

    def test_same_byte_original_c6_admission_replacement_after_count_is_hold_not_success(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            receipt_admission_rebind_probe=True)

    def test_same_byte_original_quota_replacement_during_protected_count_is_hold(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            quota_namespace_rebind_probe=True)

    def test_actual_c25_allocation_dominates_original_c6_counts_and_unknown_retains_audits(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
            business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True, settings_audit_probe=True)

    def test_actual_c25_assignment_original_survives_the_entire_durable_count(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
            business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True,
            settings_audit_probe=True, allocation_original_identity_probe=True)

    def test_actual_c25_assignment_replacement_after_shared_retry_keeps_terminal_unknown(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
            business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True,
            settings_audit_probe=True, owned_read_gates_probe=True, owned_continuity_probe=True,
            shared_retry_probe=True, allocation_retry_identity_probe=True)

    def test_same_byte_quota_replacement_after_shared_retry_keeps_unpaired_intent_and_unknown(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            settings_audit_probe=True,owned_read_gates_probe=True,owned_continuity_probe=True,
            shared_retry_probe=True,quota_retry_identity_probe=True)

    def test_each_independent_c25_sheet_fixture_acquires_a_fresh_synthetic_credential(self):
        # Separate fixtures must not inherit an earlier fixture's expired
        # token. Preserve the production expiry contract and its 3600s TTL.
        clock=[time.time()]
        def starting(sheet):
            if sheet=='IB Cabling': clock[0]+=7200
        with mock.patch('monitor.issue_tracker_sheets_read_plan.time.time',side_effect=lambda:clock[0]):
            self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
                business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True,
                settings_audit_probe=True, before_cabling_fixture=starting)

    def test_actual_native_read_gates_dominate_original_c6_count_and_expiry_retains_unknown(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal, 'record_owned_receipted_attempt_intent'),
                        'actual issued W1/template/nonces must dominate original protected C6 count')
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
            business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True,
            owned_read_gates_probe=True)

    def test_actual_live_all_business_and_history_continuity_dominate_original_c6_count(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'record_continuous_owned_attempt_intent'),
                        'actual fixed ALL-business/History observations must gate original C6 count')
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True)

    def test_actual_continuous_count_scope_reaches_one_fixed_native_original_request(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_continuous_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,continuous_launch_probe='normal')

    def test_shared_retry_held_originals_reach_one_identical_native_request(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_shared_retry_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='normal')

    def test_shared_retry_after_new_real_cycle_sends_only_the_original_unknown_wire(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal, '_hold_shared_retry_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='old-cycle')

    def test_old_receipted_private_window_replays_semantics_once_per_actual_qualification(self):
        from monitor import issue_tracker_cycle_source as source
        from monitor import issue_tracker_stage_l_consumer as consumer
        actual_replay = consumer.replay_original_receipted_prod_source
        actual_read = source._read_completed_cycle_evidence
        reached = []
        observed = []

        def replay(*args, **kwargs):
            windows = {}
            def read(store):
                if store is not self.store:
                    item = windows.setdefault(id(store), [store, 0])
                    item[1] += 1
                return actual_read(store)
            with mock.patch.object(source, '_read_completed_cycle_evidence', side_effect=read):
                result = actual_replay(*args, **kwargs)
            observed.append((len(windows), tuple(item[1] for item in windows.values())))
            reached.append(result)
            return result

        try:
            with mock.patch.object(consumer, 'replay_original_receipted_prod_source', side_effect=replay):
                self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
                    business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
                    owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='old-cycle')
        finally:
            # Keep the independent assertion outside production's sanitized
            # HOLD scopes; their exception cleanup must not mask its RED.
            self.assertTrue(reached, 'the original admitted window must actually be requalified')
            self.assertEqual([(1, (1,))] * len(observed), observed,
                             'held original worker bytes need one semantic replay per private window')

    def test_shared_retry_original_receipt_rebind_stops_before_second_native_launch(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_shared_retry_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='receipt-rebind')

    def test_shared_retry_original_read_expiry_stops_before_second_native_launch(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_shared_retry_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='read-expiry')

    def test_native_qualification_bounds_recursive_source_replays_without_shortening_final_checks(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='bounded')

    def test_real_protected_three_domains_keep_start_end_reads_without_recursive_bound_walks(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='composed-legs')

    def test_real_composed_switch_families_keep_two_fresh_windows_per_domain_leg(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        self.assertTrue(callable(getattr(consumer, '_observe_prod_stage_l_switch_sources', None)),
                        'actual composition must retain fresh source families without nested standalone walks')
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='switch-families')

    def test_real_w1_drift_after_first_eth_observation_is_hold_at_composed_end(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='composed-w1-drift')

    def test_real_ethernet_archive_drift_after_eth_observation_is_hold(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='composed-ethernet-archive-drift')

    def test_real_nvlink_archive_drift_after_eth_observation_is_hold(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='composed-nvlink-archive-drift')

    def test_native_qualification_still_rejects_whitelist_drift_at_final_projection_boundary(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='whitelist-drift')

    def test_original_receipt_rebind_after_continuous_count_stops_before_native_launch(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_continuous_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,continuous_launch_probe='receipt-rebind')

    def test_issued_read_expiry_after_continuous_count_stops_before_native_launch(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_continuous_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,continuous_launch_probe='read-expiry')

    def test_actual_protected_sources_native_reads_and_c6_share_retry_admission_without_new_publication(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,shared_retry_probe=True)

    def test_two_real_cycles_keep_keys_and_commit_latest_business_values(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, two_cycle_changed_latest=True,
        )

    def test_authenticated_k_relay_persists_replays_and_invalidates_real_preview(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, settings_channel_probe=True,
        )

    def test_k_relay_interrupted_commit_retains_unknown_claim_not_success_or_retry(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, settings_channel_fault=True,
        )

    def _verify_authenticated_settings_channel(self, project, *, fault=False):
        from monitor.issue_tracker_manual_channel import DurableManualQueue, ManualQueueWorker
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        from monitor.issue_tracker_state_owner import current_k, tracker_writer
        from test_cases.test_issue_tracker_manual_channel import cgi, valid_env

        root = project / ".tracker/manual-k-fixture"
        root.mkdir(mode=0o700)
        queue = DurableManualQueue(root, boot_id="settings-fixture")
        broker = make_protected_stage_l_broker(
            self.store, http_root=self.root, project=project,
            publication=self.publication, template_path=self.template,
            boot_id="settings-fixture", clock=lambda: 1000.0,
        )
        worker = ManualQueueWorker(queue, broker)
        jobs = []

        def submit(request):
            job = queue.enqueue(request)
            jobs.append(job)
            claimed, result = worker.process_job(job)
            self.assertEqual(job, claimed)
            self.assertEqual("done", queue.status(job)["state"])
            return result

        body = b"action=settings&panel=Switch+Status"
        status, initial = cgi.handle(valid_env(body), body, submit=submit)
        self.assertEqual("200 OK", status)
        self.assertEqual((1, 1), (initial["revision"], initial["k"]))
        preview = broker.preview("nvis", "Switch Status")
        generations = tuple((project / ".tracker/generations").iterdir())
        template = self.template.read_bytes()
        change = (b"action=set_k&panel=Eth+Link+Validation&new_k=5000"
                  b"&expected_revision=1&request_id=" + b"d" * 32)
        if fault:
            # Failure after immutable event/outbox installation, before the
            # current-pointer barrier: preserve the tail and this claimed job.
            with mock.patch("monitor.issue_tracker_k_store._replace_current",
                            side_effect=OSError("injected pointer barrier failure")):
                status, result = cgi.handle(valid_env(change), change, submit=submit)
            self.assertEqual(("503 Service Unavailable", {"error": "manual_worker_unavailable"}),
                             (status, result))
            self.assertEqual("unknown_after_claim", queue.status(jobs[-1])["state"])
            self.assertTrue((project / ".tracker/settings/events/2.json").is_file())
            self.assertTrue((project / ".tracker/settings/outbox/2.json").is_file())
            status, result = cgi.handle(valid_env(body), body, submit=submit)
            self.assertEqual("503 Service Unavailable", status)
            self.assertEqual("unknown_after_claim", queue.status(jobs[-1])["state"])
            self.assertEqual(generations, tuple((project / ".tracker/generations").iterdir()))
            self.assertEqual(template, self.template.read_bytes())
            return
        status, result = cgi.handle(valid_env(change), change, submit=submit)
        self.assertEqual("200 OK", status)
        self.assertEqual(("committed", 2, 5000, False),
                         (result["settings"], result["revision"], result["k"], result["replay"]))
        event_path = project / ".tracker/settings/events/2.json"
        event = json.loads(event_path.read_bytes())
        self.assertEqual(("operator:nvis", 1, 5000, "d" * 32),
                         (event["actor"], event["old_k"], event["new_k"], event["request_id"]))
        self.assertEqual(hashlib.sha256(event_path.read_bytes()).hexdigest(), result["event_sha256"])
        self.assertTrue((project / ".tracker/settings/outbox/2.json").is_file())
        restart = make_protected_stage_l_broker(
            self.store, http_root=self.root, project=project,
            publication=self.publication, template_path=self.template,
            boot_id="new-worker", clock=lambda: 1000.0,
        )
        self.assertEqual((2, 5000), (restart.settings("cumulus", "IB Link Validation")["revision"],
                                     restart.settings("cumulus", "IB Link Validation")["k"]))
        status, replay = cgi.handle(valid_env(change), change, submit=submit)
        self.assertEqual("200 OK", status)
        self.assertEqual({**result, "replay": True}, replay)
        for altered, environment in (
            (change.replace(b"new_k=5000", b"new_k=6"), None),
            (change.replace(b"d" * 32, b"e" * 32), None),
            (change, {**valid_env(change), "REMOTE_USER": "cumulus"}),
        ):
            status, refused = cgi.handle(environment or valid_env(altered), altered, submit=submit)
            self.assertEqual(("409 Conflict", {"error": "manual_hold"}), (status, refused))
        with tracker_writer(project, self.publication) as token:
            self.assertEqual((2, 5000), (current_k(token).revision, current_k(token).k))
        from monitor.issue_tracker_publish_runtime import inspect_stage_l
        status = inspect_stage_l(self.store, http_root=self.root, project=project,
                                 publication=self.publication, template_path=self.template)
        self.assertEqual((2, 5000), (status["k_revision"], status["k"]))
        self.assertEqual("pending", status["state"])
        self.assertEqual("disabled_no_send_authority", status["online"])
        from monitor.issue_tracker_manual_preview import ManualPreviewHold
        with self.assertRaises(ManualPreviewHold):
            broker.confirm("nvis", "Switch Status", preview["token"], confirmation="publish_local")
        self.assertEqual(generations, tuple((project / ".tracker/generations").iterdir()))
        self.assertEqual(template, self.template.read_bytes())


    def test_real_protected_eth_and_switch_skips_have_local_audit_history(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=True)

    def test_real_protected_first_due_cycle_auto_commits_local_receipt(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True,
        )

    def test_real_protected_second_due_cycle_auto_commits_distinct_local_receipt(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, automatic_second_due=True,
        )

    def test_manual_c6_cannot_bypass_prior_automatic_shared_admission(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, manual_second_probe=True,
        )

    def test_automatic_c6_then_manual_c6_uses_one_shared_admission_chain(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, manual_second_admit=True,
        )

    def test_invalid_auto_clock_refuses_before_local_c6_receipt(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, invalid_auto_clock=True,
        )

    def test_one_completed_cycle_cannot_admit_n_two_local_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, automatic_not_due=True,
        )

    def test_replayed_completion_after_manual_receipt_cannot_auto_readmit(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, replayed_auto=True,
        )

    def test_first_manual_c6_records_shared_admission_for_later_automatic_lane(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, require_first_manual_admission=True,
        )

    def test_manual_c6_then_manual_c6_does_not_inherit_automatic_n(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, require_first_manual_admission=True,
            manual_after_manual=True,
        )

    def test_crash_after_c6_receipt_before_admission_is_terminal_visible_hold(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, terminal_orphan_probe=True,
        )

    def test_manual_switch_only_c5_to_c6_receipt_preserves_other_sheet_bytes(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, selected_manual_panel="Switch Status",
        )

    def test_manual_empty_switch_panel_creates_no_receipt_or_workbook_change(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, selected_manual_panel="Switch Status",
            selected_panel_empty=True,
        )

    def test_manual_queue_broker_requalifies_selected_panel_before_real_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, selected_manual_panel="Switch Status",
            manual_channel_bridge=True,
        )

    def test_real_three_panel_source_paths_times_hashes_reopen_or_hold(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, source_identity_probe=True,
        )

    def test_real_protected_three_panel_preview_classifies_workbook_without_committing(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, panel_counts_probe=True,
        )

    def test_complete_manual_preview_binds_source_files_and_workbook_before_real_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, complete_preview_probe=True,
        )

    def test_complete_manual_preview_source_stat_race_before_c6_never_receipts(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, complete_preview_probe=True, complete_preview_source_race=True,
        )

    def test_complete_manual_browser_confirm_crosses_real_cgi_queue_and_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, complete_preview_probe=True, complete_preview_cgi=True,
        )

    def _verify_manual_queue_protected_commit(
        self, project, original_template, before_generations, qualified,
    ):
        from monitor.issue_tracker_manual_channel import (
            DurableManualQueue, ManualChannelHold, ManualQueueWorker,
        )
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        from monitor.issue_tracker_manifest import selected_panel_decision_sha256
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, commit_qualified_prod_local,
        )
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook

        queue_root = project / ".tracker/manual-fixture"
        queue_root.mkdir(mode=0o700)
        queue = DurableManualQueue(queue_root, boot_id="synthetic-boot")
        broker = make_protected_stage_l_broker(
            self.store, http_root=self.root, project=project,
            publication=self.publication, template_path=self.template,
            boot_id="synthetic-boot", monotonic_ns=time.monotonic_ns,
            clock=lambda: 1000.0,
        )
        worker = ManualQueueWorker(queue, broker)
        preview_request = {"action": "preview", "panel": "Switch Status",
                           "principal": "nvis"}

        def preview():
            job = queue.enqueue(preview_request)
            completed, result = worker.process_job(job)
            self.assertEqual(job, completed)
            self.assertEqual("done", queue.status(job)["state"])
            self.assertEqual(
                selected_panel_decision_sha256(qualified, "Switch Status"),
                result["selected_decision_sha256"],
            )
            return result["token"]

        def confirm(token, *, principal="nvis"):
            return queue.enqueue({
                "action": "confirm", "panel": "Switch Status",
                "principal": principal, "token": token,
                "confirmation": "publish_local",
            })

        generation_root = project / ".tracker/generations"

        def no_receipt():
            self.assertEqual(before_generations,
                             tuple(sorted(generation_root.iterdir())))
            self.assertFalse(any(generation_root.glob("*/RECEIPT")))

        token = preview()
        with self.assertRaises(ManualChannelHold):
            queue.enqueue({**preview_request, "principal": ""})
        wrong_job = confirm(token, principal="cumulus")
        self.assertEqual({"error": "manual_hold"}, worker.process_job(wrong_job)[1])
        self.assertEqual("done", queue.status(wrong_job)["state"])
        no_receipt()

        # The same preview is consumed before a failed source refresh.
        self.template.write_bytes(b"corrupt-source")
        drift_job = confirm(token)
        with self.assertRaises(StageLHold):
            worker.process_job(drift_job)
        self.assertEqual("unknown_after_claim", queue.status(drift_job)["state"])
        self.assertTrue((queue_root / f"claimed-{drift_job}.json").is_file())
        no_receipt()
        self.template.write_bytes(original_template)
        replay_job = confirm(token)
        self.assertEqual({"error": "manual_hold"}, worker.process_job(replay_job)[1])
        no_receipt()

        # A fresh status is valid, but a different selected C5 decision is
        # injected only when the protected writer requalifies under LK-P.
        token = preview()
        real_commit = commit_qualified_prod_local

        def changed_decision(*args, **kwargs):
            with mock.patch(
                "monitor.issue_tracker_publish_runtime.selected_panel_decision_sha256",
                return_value="0" * 64,
            ):
                return real_commit(*args, **kwargs)

        changed_job = confirm(token)
        with mock.patch(
            "monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
            side_effect=changed_decision,
        ), self.assertRaises(StageLHold):
            worker.process_job(changed_job)
        self.assertEqual("unknown_after_claim", queue.status(changed_job)["state"])
        no_receipt()

        token = preview()
        error_job = confirm(token)
        with mock.patch(
            "monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
            side_effect=RuntimeError("synthetic worker exception"),
        ), self.assertRaises(RuntimeError):
            worker.process_job(error_job)
        self.assertEqual("unknown_after_claim", queue.status(error_job)["state"])
        no_receipt()

        token = preview()
        real_results = []

        def capture_commit(*args, **kwargs):
            result = real_commit(*args, **kwargs)
            real_results.append(result)
            return result

        success_job = confirm(token)
        with mock.patch(
            "monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
            side_effect=capture_commit,
        ):
            completed, public = worker.process_job(success_job)
        self.assertEqual(success_job, completed)
        self.assertEqual("done", queue.status(success_job)["state"])
        self.assertEqual(1, len(real_results))
        committed = real_results[0]
        self.assertIsInstance(committed, CommittedProdWorkbook)
        self.assertEqual("committed", public["local"])
        self.assertEqual(committed.receipt.manifest_id, public["manifest_id"])
        self.assertEqual(committed.generation.generation_id,
                         public["generation_id"])
        self.assertIs(public["local_applied"], True)
        self.assertEqual("disabled_no_send_authority", public["online"])
        generation = generation_root / public["generation_id"]
        persisted = json.loads((generation / "MANIFEST").read_bytes())
        self.assertEqual("Switch Status",
                         persisted["qualified_source"]["selected_panel"])
        self.assertTrue((generation / "RECEIPT").is_file())
        with zipfile.ZipFile(BytesIO(original_template)) as before, \
             zipfile.ZipFile(BytesIO(committed.prepared.xlsx_bytes)) as after:
            for other in ("sheet3.xml", "sheet4.xml"):
                path = "xl/worksheets/" + other
                self.assertEqual(before.read(path), after.read(path), other)
        retry_job = confirm(token)
        self.assertEqual({"error": "manual_hold"}, worker.process_job(retry_job)[1])
        self.assertEqual(1, len(real_results))

    def _exercise_real_protected_three_panel_fixture(
        self, *, skip_history, automatic_first=False, replayed_auto=False,
        invalid_auto_clock=False, automatic_not_due=False,
        automatic_second_due=False, manual_second_probe=False,
        manual_second_admit=False,
        require_first_manual_admission=False, manual_after_manual=False,
        terminal_orphan_probe=False, selected_manual_panel=None,
        selected_panel_empty=False, manual_channel_bridge=False,
        source_identity_probe=False, two_cycle_changed_latest=False,
        settings_channel_probe=False, settings_channel_fault=False,
        panel_counts_probe=False, source_unit_probe=False, receipted_source_probe=False, observed_source_probe=False,
        observed_switch_insert_probe=False, observed_cabling_insert_probe=False, business_preread_probe=False, original_reserved_probe=False, receipted_intent_probe=False,
        settings_audit_probe=False, owned_read_gates_probe=False, owned_continuity_probe=False, complete_preview_probe=False,
        shared_retry_probe=False, allocation_original_identity_probe=False, allocation_retry_identity_probe=False,
        receipt_admission_rebind_probe=False,quota_namespace_rebind_probe=False,quota_retry_identity_probe=False,
        before_cabling_fixture=None, native_catalog_probe=False, native_catalog_return_fault=None,
        native_catalog_c6_origin_probe=False,
        native_catalog_retained_probe=False,
        native_catalog_creator_first_stat_probe=None,
        native_catalog_all_c6_fifo_probe=None,
        native_catalog_receipted_count_probe=None,
        native_catalog_launch_probe=None,
        continuous_launch_probe=None,
        retry_launch_probe=None,
        qualification_replay_probe=None,
        complete_preview_source_race=False,
        complete_preview_cgi=False,
    ):
        from monitor.collection_ib_producer import (
            IbProducerAuthoritySnapshot, parse_ib_producer_authority,
            produce_worker_ib_analysis,
        )
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, commit_qualified_prod_local, inspect_stage_l,
            local_publish_interval,
            read_auto_local_admission,
        )
        from monitor.issue_tracker_ib_runtime import read_prod_ib_k_window
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, ProdWorkbookNoop,
            commit_prod_stage_l_workbook,
        )
        from monitor.issue_tracker_local_commit import LocalCommitHold
        from monitor.issue_tracker_local_workbook import _read_bound_source
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, qualify_prod_stage_l,
        )
        from monitor.issue_tracker_state_owner import (
            current_k, initialize_tracker_state, set_k, tracker_writer,
        )
        from test_cases.test_collection_cycle_persistence import WORKER, TOKEN_1, TOKEN_2
        from test_cases.test_collection_ib_producer import _record
        from test_cases.test_issue_tracker_ib_runtime_workflow import ROOT
        from tools.project_contract import (
            MIN_CONTINUOUS_INTERVAL_MINUTES, build_collection_cycle_identity,
        )
        from tools.ufm_collection_contract import publish_local_archive
        from tools.ufm_remote_producer import (
            RemoteCollectionObservation, VerifiedRetrievedObservation,
        )

        project = self.root / "DAY0-Prepare/fabric-a"
        project.mkdir(parents=True)
        self.gate.__exit__(None, None, None)
        protected_gate = WORKER.CollectionGate(
            str(project), "prod", status_dir=self.root / "monitor/status",
            enforce_cooldown=False, lane="collection",
        )
        held_gate = protected_gate.__enter__()
        self.addCleanup(lambda: protected_gate.__exit__(None, None, None))
        self.store = WORKER.CollectionCycleStore(gate=held_gate)
        self.project = project
        setup = self.root / "ztp/config/nvos/template/P2P"
        setup.mkdir(parents=True)
        selected = project / "fabric-blue.xlsx"
        with xlsxwriter.Workbook(str(selected)) as book:
            sheet = book.add_worksheet("CL links")
            for col, item in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, col, item)
            for col, item in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, col, item)
            if observed_cabling_insert_probe:
                for col, item in enumerate(("leaf01", "sw1p2", "server03", "mlx5_2")):
                    sheet.write(2, col, item)
        (project / "p2p.xlsx").symlink_to(selected.name)
        (setup / "p2p.xlsx").symlink_to(
            "../../../../../DAY0-Prepare/fabric-a/p2p.xlsx")
        for name, body in (("01-inventory.log", "[ib-sw]\n*leaf*\n\n[server]\n*server*\n"),
                           ("02-port-mapping.log", ""), ("03-splitter.log", "")):
            (setup / name).write_text(body, encoding="utf-8")
        output = setup / "output-p2p"
        output.mkdir()
        cvt = output / "fabric-blue-cvt.xlsx"
        converted = subprocess.run(
            [sys.executable, "-B", str(ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"),
             "--output", str(cvt), "--inventory", str(setup / "01-inventory.log"),
             "--port-map", str(setup / "02-port-mapping.log"),
             "--splitter", str(setup / "03-splitter.log")],
            cwd=setup, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                            "XLSX_TO_CSV_BASE_DIR": str(setup)},
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(0, converted.returncode, converted.stdout + converted.stderr)
        incoming = project / "99-output-ufm/incoming"
        incoming.mkdir(parents=True)
        identity = build_collection_cycle_identity(str(project), "prod", 1, TOKEN_1)
        record = _record()
        record.update({
            "project_key": identity["project_key"], "project_root": str(project),
            "retrieval_dir": str(incoming),
            "p2p_sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
            "cvt_sha256": hashlib.sha256(cvt.read_bytes()).hexdigest(),
            "cvt_provenance_sha256": hashlib.sha256(
                Path(f"{cvt}.provenance.json").read_bytes()).hexdigest(),
        })
        authority = IbProducerAuthoritySnapshot(
            parse_ib_producer_authority(
                record, project_key=identity["project_key"], project_root=project),
            "b" * 64, (1, 2, 3),
        )
        vendor = self.root / "vendor-iblinkinfo.txt"
        vendor.write_text(
            "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
            ' 1 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
            '20 1[  ] "server02 mlx5_1"\n' + (
                ' 1 2[  ] ==( 4X 200 Gbps Active / LinkUp )==> 21 2[  ] "server04 mlx5_3"\n'
                if observed_cabling_insert_probe else ''), encoding="utf-8",
        )
        protected = self.root / "synthetic-root-attestation"
        protected.mkdir(mode=0o700)

        def retrieved(plan, **_kwargs):
            archive = publish_local_archive(plan, vendor, incoming)
            sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            return VerifiedRetrievedObservation(
                RemoteCollectionObservation("EXAMPLE-UFM01", plan.run_id,
                                            "iblinkinfo", plan.ufm_remote_path, sha),
                archive, sha, sha, sha, "b" * 64, "b" * 64,
            )

        with mock.patch("monitor.collection_ib_producer._ROOT_UID", os.getuid()), \
             mock.patch("monitor.collection_ib_producer._open_protected_attestation_dir",
                        side_effect=lambda _key: os.open(protected, os.O_RDONLY)), \
             mock.patch("monitor.collection_ib_producer.load_ib_producer_authority",
                        return_value=authority), \
             mock.patch("monitor.collection_ib_producer.recheck_ib_producer_authority"), \
             mock.patch("monitor.collection_ib_producer.observe_and_retrieve_remote_producer",
                        side_effect=retrieved):
            binding = produce_worker_ib_analysis(
                identity, project_root=project, http_root=self.root,
                clock=lambda: dt.datetime(2026, 9, 26, 4, 20,
                                          tzinfo=dt.timezone.utc),
                runner=lambda _argv: self.fail("transport is supplied by fixture"),
            )
            if selected_panel_empty:
                from test_cases.test_issue_tracker_switch_info_source import (
                    _info as healthy_info, _nvl_info as healthy_nvl_info,
                )
                switch_inputs = (
                    mock.patch(
                        "test_cases.test_issue_tracker_switch_runtime_workflow._info",
                        side_effect=lambda host, **_kwargs: healthy_info(
                            host, fan_state="ok"),
                    ),
                    mock.patch(
                        "test_cases.test_issue_tracker_switch_runtime_workflow._nvl_info",
                        side_effect=lambda host, **_kwargs: healthy_nvl_info(
                            host, asic_current="30"),
                    ),
                )
                with switch_inputs[0], switch_inputs[1]:
                    cycle, artifacts = self._cycle(
                        activity=True, derivation=True, ib_analysis=binding,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"},
                    )
            else:
                cycle, artifacts = self._cycle(
                    activity=True, derivation=True, ib_analysis=binding,
                    fabric_templates={"ethernet/prod": "tan-leaf",
                                      "nvlink/prod": "border-leaf"},
                    additional_eth_activity=observed_cabling_insert_probe,
                )
            self.assertEqual(identity["cycle_id"], cycle["cycle_id"])
            self.publication = project / "99-output-monitor"
            self.publication.mkdir()
            initialize_tracker_state(
                project, self.publication, initialized_at="2026-09-25T00:00:00Z",
                acquisition_id="req7-three-panel-protected-fixture",
            )
            self.template = self.publication / "local.xlsx"
            self.template.write_bytes(fake_workbook(reserved_switch_rows=4))
            default_preparation = (native_catalog_launch_probe is not None
                and native_catalog_launch_probe[0] in ('prepare','prepare-mixed-accounting','prepare-quota-rebind','prepare-finalizer-expiry'))
            if manual_channel_bridge or complete_preview_probe or default_preparation:
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(self.template.read_bytes())
                self.template = root_template
            self.snapshot = read_whitelist_workbook(self.template)
            with tracker_writer(project, self.publication) as token:
                set_k(token, new_k=2 if two_cycle_changed_latest else 1,
                      actor="operator:fixture",
                      recorded_at="2026-09-25T00:01:00Z",
                      request_id=("req7-three-panel-k2" if two_cycle_changed_latest
                                  else "req7-three-panel-k1"), expected_revision=0)
                self.settings = current_k(token)
            args = {"http_root": self.root, "settings": self.settings,
                    "whitelist_snapshot": self.snapshot,
                    "whitelist_path": self.template}
            if skip_history:
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n",
                    encoding="utf-8",
                )
                self._verify_protected_skip_commit(project, args)
                return
            if two_cycle_changed_latest:
                second_identity = build_collection_cycle_identity(
                    str(project), "prod", 2, TOKEN_2,
                )
                vendor.write_text(
                    "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                    ' 1 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                    '20 1[  ] "server03 mlx5_1"\n', encoding="utf-8",
                )
                second_binding = produce_worker_ib_analysis(
                    second_identity, project_root=project, http_root=self.root,
                    clock=lambda: dt.datetime(2026, 9, 26, 4, 31,
                                              tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail("transport is supplied by fixture"),
                )
                from test_cases.test_issue_tracker_switch_info_source import _nvl_info
                with mock.patch(
                    "test_cases.test_issue_tracker_switch_runtime_workflow._nvl_info",
                    side_effect=lambda host, **_kwargs: _nvl_info(host, asic_current="81"),
                ):
                    second_cycle, _ = self._cycle(
                        activity=True, derivation=True,
                        ib_analysis=second_binding, observed_peer="changed-peer",
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"},
                    )
                self.assertEqual(second_identity["cycle_id"], second_cycle["cycle_id"])
                self._verify_two_cycle_latest_local_commit(
                    project, args, (cycle["cycle_id"], second_cycle["cycle_id"]),
                )
                return
            if qualification_replay_probe is not None:
                from monitor import issue_tracker_stage_l_consumer as consumer
                if qualification_replay_probe in (
                        'composed-ethernet-archive-drift',
                        'composed-nvlink-archive-drift'):
                    slot = ('ethernet/prod' if qualification_replay_probe ==
                            'composed-ethernet-archive-drift' else 'nvlink/prod')
                    path = artifacts[slot]['info']
                    original_archive = path.read_bytes()
                    actual_read = consumer.read_prod_eth_activity_k_window
                    reached = []
                    def drift_after_eth(*values, **keywords):
                        result = actual_read(*values, **keywords)
                        reached.append(True)
                        if len(reached) == 1:
                            path.write_bytes(original_archive + b'changed Switch archive after ETH')
                        return result
                    try:
                        with mock.patch.object(consumer, 'read_prod_eth_activity_k_window',
                                               side_effect=drift_after_eth):
                            with self.assertRaises(consumer.StageLConsumerHold):
                                consumer.inspect_prod_stage_l_composed_sources(self.store, **args)
                        self.assertEqual([True], reached)
                        self.assertEqual((), tuple(self.publication.glob('Issue_Tracker*')))
                    finally:
                        path.write_bytes(original_archive)
                    return
                if qualification_replay_probe == 'switch-families':
                    actual_observe = consumer._observe_prod_stage_l_switch_sources
                    actual_window = consumer.read_prod_switch_k_window
                    legs = []
                    def observe(*values, **keywords):
                        with mock.patch.object(consumer, 'read_prod_switch_k_window',
                                               wraps=actual_window) as windows:
                            result = actual_observe(*values, **keywords)
                        legs.append(tuple(call.kwargs['source_slot'] for call in windows.call_args_list))
                        return result
                    with mock.patch.object(consumer, '_observe_prod_stage_l_switch_sources', side_effect=observe):
                        qualified = qualify_prod_stage_l(self.store, **args)
                    self.assertEqual([('ethernet/prod', 'nvlink/prod')] * 4, legs,
                                     'each actual composed start/end leg rereads both real Switch families once')
                    self.assertTrue(qualified.qualified)
                    self.assertEqual({'Switch Status', 'Eth Link Validation', 'IB Link Validation'},
                                     {item.panel for item in qualified.candidates})
                    self.assertEqual(4, len(qualified.candidates))
                    self.assertEqual((), tuple(self.publication.glob('Issue_Tracker*')))
                    return
                if qualification_replay_probe == 'composed-w1-drift':
                    actual_read = consumer.read_prod_eth_activity_k_window
                    original_template = self.template.read_bytes()
                    reached = []
                    def drift_after_read(*values, **keywords):
                        result = actual_read(*values, **keywords)
                        reached.append(True)
                        if len(reached) == 1:
                            self.template.write_bytes(b'changed W1 after actual ETH observation')
                        return result
                    try:
                        with mock.patch.object(consumer, 'read_prod_eth_activity_k_window',
                                               side_effect=drift_after_read):
                            with self.assertRaises(consumer.StageLConsumerHold):
                                consumer.inspect_prod_stage_l_composed_sources(self.store, **args)
                        self.assertEqual([True], reached)
                        self.assertEqual((), tuple(self.publication.glob('Issue_Tracker*')))
                    finally:
                        self.template.write_bytes(original_template)
                    return
                if qualification_replay_probe == 'composed-legs':
                    with mock.patch.object(consumer, 'read_whitelisted_ib_k_window',
                            wraps=consumer.read_whitelisted_ib_k_window) as ib_reads, \
                            mock.patch.object(consumer, '_observe_prod_stage_l_switch_sources',
                            wraps=consumer._observe_prod_stage_l_switch_sources) as switch_reads, \
                            mock.patch.object(consumer, 'inspect_prod_stage_l_composed_sources',
                            wraps=consumer.inspect_prod_stage_l_composed_sources) as composed_reads:
                        qualified = qualify_prod_stage_l(self.store, **args)
                    self.assertEqual(2, composed_reads.call_count)
                    self.assertEqual(4, ib_reads.call_count,
                        'actual IB start/end for both native qualification walks, not nested duplicate legs')
                    self.assertEqual(4, switch_reads.call_count)
                    self.assertTrue(qualified.qualified)
                    self.assertEqual({'Switch Status', 'Eth Link Validation', 'IB Link Validation'},
                                     {item.panel for item in qualified.candidates})
                    self.assertEqual(4, len(qualified.candidates))
                    self.assertEqual((), tuple(self.publication.glob('Issue_Tracker*')))
                    return
                if qualification_replay_probe == 'whitelist-drift':
                    real_final = consumer.validate_prod_stage_l_source_projection
                    reached = []
                    original_template = self.template.read_bytes()
                    def drift(*values, **keywords):
                        reached.append(True)
                        self.template.write_bytes(b'changed W1 at final projection boundary')
                        return real_final(*values, **keywords)
                    try:
                        with mock.patch.object(consumer,'validate_prod_stage_l_source_projection',side_effect=drift):
                            with self.assertRaises(consumer.StageLConsumerHold):
                                qualify_prod_stage_l(self.store,**args)
                        self.assertEqual([True],reached)
                    finally:
                        self.template.write_bytes(original_template)
                    return
                self.assertEqual('bounded',qualification_replay_probe)
                with mock.patch.object(consumer,'inspect_prod_stage_l_composed_sources',
                                       wraps=consumer.inspect_prod_stage_l_composed_sources) as replay:
                    qualified = qualify_prod_stage_l(self.store,**args)
                self.assertEqual(2,replay.call_count,
                    'one native qualification needs complete start/end source walks, not a third recursive walk')
                self.assertTrue(qualified.qualified)
                self.assertEqual({'Switch Status','Eth Link Validation','IB Link Validation'},
                                 {item.panel for item in qualified.candidates})
                self.assertEqual(4,len(qualified.candidates))
                return
            qualified = qualify_prod_stage_l(self.store, **args)
            self.assertTrue(qualified.qualified)
            self.assertEqual("prod-runtime-protected-v1", qualified.mode)
            self.assertEqual((cycle["cycle_id"],), qualified.cycle_ids)
            expected_panels = ({"Eth Link Validation", "IB Link Validation"}
                               if selected_panel_empty else
                               {"Switch Status", "Eth Link Validation",
                                "IB Link Validation"})
            expected_count = 2 if selected_panel_empty else (6 if observed_cabling_insert_probe else 4)
            self.assertEqual(expected_panels,
                             {item.panel for item in qualified.candidates})
            self.assertEqual(expected_count, len(qualified.candidates))
            if complete_preview_probe:
                from monitor import issue_tracker_manual_preview as manual
                from test_cases.test_issue_tracker_manual_ui import browser_settings_script
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n", encoding="utf-8")
                broker = manual.make_complete_protected_stage_l_broker(
                    self.store, http_root=self.root, project=project,
                    publication=self.publication, template_path=self.template,
                    boot_id="complete-preview-fixture", monotonic_ns=time.monotonic_ns,
                    clock=lambda: 1000.0,
                )
                generated_confirm = {}
                if complete_preview_cgi:
                    from urllib.parse import urlencode
                    from monitor.issue_tracker_manual_channel import DurableManualQueue, ManualQueueWorker
                    from test_cases.test_issue_tracker_manual_ui_workflow import CGI, environ
                    queue_root = project / ".tracker/complete-preview-queue"
                    queue_root.mkdir(mode=0o700)
                    queue = DurableManualQueue(queue_root, boot_id="complete-preview-fixture")
                    worker = ManualQueueWorker(queue, broker)
                    def cgi(body):
                        def submit(request):
                            job = queue.enqueue(request)
                            done, result = worker.process_job(job)
                            self.assertEqual(job, done)
                            self.assertEqual("done", queue.status(job)["state"])
                            return result
                        return CGI.handle(environ(body), body, submit=submit)
                previews = {}
                for panel, count, files in (("Switch Status", 2, 2),
                                            ("Eth Link Validation", 1, 1),
                                            ("IB Link Validation", 1, 1)):
                    if complete_preview_cgi:
                        body = urlencode({"action": "preview", "panel": panel}).encode("ascii")
                        status, preview = cgi(body)
                        self.assertEqual("200 OK", status)
                    else:
                        preview = broker.preview("nvis", panel)
                    previews[panel] = preview
                    self.assertEqual((count, count, 0, 0), tuple(preview[key] for key in (
                        "qualified_operation_count", "new_count", "update_count", "skip_count")))
                    self.assertEqual(files, len(preview["source_files"]))
                    self.assertEqual(count, len(preview["row_digests"]))
                    for item in preview["source_files"]:
                        self.assertEqual(hashlib.sha256((self.root / item["path"]).read_bytes()).hexdigest(),
                                         item["sha256"])
                    browser = browser_settings_script(
                        "console.log(JSON.stringify({valid:validIssueTrackerPreview(" +
                        json.dumps(preview) + "," + json.dumps(panel) + ")}));")
                    self.assertEqual({"valid": True}, browser)
                    if complete_preview_cgi:
                        browser = browser_settings_script(
                            "replies.push(" + json.dumps(preview) + ");\n"
                            "await issueTrackerManualPreview(" + json.dumps(panel) + ");\n"
                            "replies.push({local_applied:false});\n"
                            "await issueTrackerManualConfirm();\n"
                            "console.log(JSON.stringify({calls}));")
                        self.assertEqual(body.decode("ascii"), browser["calls"][0]["body"])
                        generated_confirm[panel] = browser["calls"][1]["body"].encode("ascii")
                if complete_preview_source_race:
                    real_commit = broker._commit_local
                    def change_after_confirm_read(panel, fingerprint):
                        path = artifacts["ethernet/prod"]["info"]
                        stamp = path.stat().st_mtime_ns
                        os.utime(path, ns=(stamp + 2_000_000_000, stamp + 2_000_000_000))
                        return real_commit(panel, fingerprint)
                    broker._commit_local = change_after_confirm_read
                    with self.assertRaises(StageLHold):
                        broker.confirm("nvis", "Switch Status", previews["Switch Status"]["token"],
                                       confirmation="publish_local")
                    self.assertFalse(any((project / ".tracker/generations").glob("*/RECEIPT")))
                    with self.assertRaises(manual.ManualPreviewHold):
                        broker.confirm("nvis", "Switch Status", previews["Switch Status"]["token"],
                                       confirmation="publish_local")
                    return
                if complete_preview_cgi:
                    status, committed = cgi(generated_confirm["Switch Status"])
                    self.assertEqual("200 OK", status)
                else:
                    committed = broker.confirm("nvis", "Switch Status", previews["Switch Status"]["token"],
                                               confirmation="publish_local")
                self.assertTrue(committed["local_applied"])
                receipts = tuple((project / ".tracker/generations").glob("*/RECEIPT"))
                self.assertEqual(1, len(receipts))
                # Even an untouched ETH source cannot reuse counts computed
                # against the pre-Switch local workbook image.
                if complete_preview_cgi:
                    status, held = cgi(generated_confirm["Eth Link Validation"])
                    self.assertEqual(("409 Conflict", {"error": "manual_hold"}), (status, held))
                else:
                    with self.assertRaises(manual.ManualPreviewHold):
                        broker.confirm("nvis", "Eth Link Validation",
                                       previews["Eth Link Validation"]["token"],
                                       confirmation="publish_local")
                self.assertEqual(receipts, tuple((project / ".tracker/generations").glob("*/RECEIPT")))
                return
            if panel_counts_probe:
                from monitor.issue_tracker_local_workbook_commit import (
                    project_manual_panel_image, project_manual_panel_preview,
                )
                source = self.template.read_bytes()
                generation_root = project / ".tracker/generations"
                before_generations = tuple(generation_root.iterdir())
                for panel, count in (("Switch Status", 2),
                                     ("Eth Link Validation", 1),
                                     ("IB Link Validation", 1)):
                    _, manifest_id = freeze_prod_stage_l_manifest(
                        qualified, self.store, metadata={
                            "project_id": str(project), "schema_version": 1,
                            "producer_version": "stage-l-runtime-v1",
                            "template_contract_version": "local-xlsx-v1",
                            "template_sha256": self.snapshot.workbook_sha256,
                        }, expected_template_sha256=self.snapshot.workbook_sha256,
                        selected_panel=panel, **args,
                    )
                    preview = project_manual_panel_preview(source, qualified, panel, manifest_id)
                    self.assertEqual((count, count, 0, 0), tuple(preview[key] for key in (
                        "qualified_operation_count", "new_count", "update_count", "skip_count")))
                    self.assertEqual(count, len(preview["row_digests"]))
                    image = project_manual_panel_image(source, qualified, panel, manifest_id)
                    noop = project_manual_panel_preview(image, qualified, panel, manifest_id)
                    self.assertEqual((0, 0, count), tuple(noop[key] for key in (
                        "new_count", "update_count", "skip_count")))
                self.assertEqual(source, self.template.read_bytes())
                self.assertEqual(before_generations, tuple(generation_root.iterdir()))
                return
            if source_identity_probe:
                from monitor.issue_tracker_stage_l_consumer import (
                    read_prod_stage_l_panel_source_files,
                    validate_prod_stage_l_panel_source_files,
                )
                expected = {
                    "Switch Status": {
                        artifacts["ethernet/prod"]["info"],
                        artifacts["nvlink/prod"]["info"],
                    },
                    "Eth Link Validation": {
                        artifacts["ethernet/prod"]["activity"],
                    },
                    "IB Link Validation": {
                        project / "99-output-ufm/runs" / binding["run_id"] /
                        "EXAMPLE-UFM01" /
                        f"iblinkinfo_{binding['run_id']}-topology-validation.xlsx",
                    },
                }
                witnessed_by_panel = {}
                for panel, source_paths in expected.items():
                    witnessed = read_prod_stage_l_panel_source_files(
                        qualified, self.store, panel=panel, **args,
                    )
                    witnessed_by_panel[panel] = witnessed
                    self.assertEqual(
                        {str(path.relative_to(self.root)) for path in source_paths},
                        {item.path for item in witnessed},
                    )
                    self.assertTrue(all(item.recorded_at_utc and
                                        item.sha256 == hashlib.sha256(
                                            (self.root / item.path).read_bytes()
                                        ).hexdigest() for item in witnessed))
                    self.assertEqual(witnessed,
                        validate_prod_stage_l_panel_source_files(
                            witnessed, qualified, self.store, panel=panel,
                            **args,
                        ))
                altered = artifacts["ethernet/prod"]["info"]
                prior_ns = altered.stat().st_mtime_ns
                os.utime(altered, ns=(prior_ns + 2_000_000_000,
                                      prior_ns + 2_000_000_000))
                with self.assertRaises(StageLConsumerHold):
                    validate_prod_stage_l_panel_source_files(
                        witnessed_by_panel["Switch Status"], qualified, self.store,
                        panel="Switch Status", **args,
                    )
                altered.write_bytes(b"changed after protected preview")
                with self.assertRaises(StageLConsumerHold):
                    validate_prod_stage_l_panel_source_files(
                        witnessed_by_panel["Switch Status"], qualified, self.store,
                        panel="Switch Status", **args,
                    )
                return
            stage_status = inspect_stage_l(
                self.store, http_root=self.root, project=project,
                publication=self.publication, template_path=self.template,
            )
            self.assertEqual("qualified", stage_status["state"])
            self.assertEqual(expected_count, stage_status["qualified_operation_count"])
            self.assertEqual(0, stage_status["whitelist_skip_count"])
            self.assertEqual("disabled_no_send_authority", stage_status["online"])
            self.assertNotIn("receipt", stage_status)
            if settings_channel_probe or settings_channel_fault:
                self._verify_authenticated_settings_channel(project, fault=settings_channel_fault)
                return
            protected_time = read_prod_ib_k_window(self.store, **args).recorded_at_utc
            self.assertTrue(protected_time)
            self.assertEqual(protected_time, qualified.recorded_at_utc)
            self.assertEqual({protected_time},
                             {item.recorded_at_utc for item in qualified.candidates})
            observations = json.dumps({
                "candidates": [asdict(item) for item in qualified.candidates],
                "whitelist_skips": [asdict(item) for item in qualified.whitelist_skips],
                "hostname_fallback_count": sum(
                    item.fabric_source == "hostname-fallback"
                    for item in qualified.candidates
                ),
                "recorded_at_utc": protected_time,
            }, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode("utf-8") + b"\n"
            self.assertEqual(hashlib.sha256(observations).hexdigest(),
                             qualified.observations_sha256)
            with tracker_writer(project, self.publication) as token:
                self.assertEqual(
                    qualified,
                    qualify_prod_stage_l(self.store, writer_token=token, **args),
                )
            metadata = {
                "project_id": str(project), "schema_version": 1,
                "producer_version": "req7-test-producer",
                "template_contract_version": "v1",
                "template_sha256": self.snapshot.workbook_sha256,
            }
            before_publication = tuple(sorted(self.publication.iterdir()))
            body, digest = freeze_prod_stage_l_manifest(
                qualified, self.store, metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                **args,
            )
            self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
            self.assertEqual(
                protected_time,
                json.loads(body)["qualified_source"]["recorded_at_utc"],
            )
            self.assertEqual(before_publication,
                             tuple(sorted(self.publication.iterdir())))
            generation_root = project / ".tracker/generations"
            before_generations = tuple(sorted(generation_root.iterdir()))
            original_template = self.template.read_bytes()
            if source_unit_probe:
                from monitor.issue_tracker_send_unit import freeze_prod_source_unit, SendUnitHold
                for sheet, family, sid in (('ETH&IB Switch', 'switch', 101), ('ETH Cabling', 'eth_cabling', 102),
                                           ('IB Cabling', 'ib_cabling', 103)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    self.assertTrue(candidates, 'all three real protected families must be exercised')
                    placements = tuple({'operation_id': item.operation_id, 'action': 'update' if family == 'switch' else 'insert',
                        'row_index': index + 2 if family == 'switch' else None, 'observed_values': {'L': {}} if family == 'switch' else None,
                        'reserved_id': None if family == 'switch' else 'NV%05d' % (41001 + index)}
                        for index, item in enumerate(candidates))
                    options = dict(generation_id='a' * 64, publish_id='b' * 64,
                        spreadsheet_id='synthetic_spreadsheet_id_0001', sheet=sheet, sheet_id=sid, history_sheet_id=105,
                        target_nonce='c' * 64, history_nonce='d' * 64, preread_sha256='e' * 64,
                        audits=(), occupied_metadata_ids=())
                    with tracker_writer(project, self.publication) as token:
                        value = freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                            expected_template_sha256=self.snapshot.workbook_sha256, placements=placements, writer_token=token,
                            **args, **options)
                        image = json.loads(value.action_preimage)
                        self.assertEqual(digest, image['manifest_id'])
                        self.assertEqual([item.operation_id for item in candidates], [item['operation_id'] for item in image['business']])
                        self.assertEqual([list(item.activity_key) for item in candidates], [item['activity_key'] for item in image['business']])
                        self.assertEqual([item.recorded_at_utc for item in candidates], [item['recorded_at_utc'] for item in image['business']])
                        for item, candidate in zip(image['business'], candidates):
                            if family == 'switch':
                                self.assertEqual({'stringValue': '[MONITOR][%s][%s] [fabric_source=%s] %s' %
                                    (candidate.activity_key[2], candidate.activity_key[3], candidate.fabric_source, candidate.evidence_description)},
                                    item['requests'][0]['updateCells']['rows'][0]['values'][0]['userEnteredValue'])
                            else:
                                cells = item['requests'][0]['appendCells']['rows'][0]['values']
                                self.assertEqual({'stringValue': 'ETH' if family == 'eth_cabling' else 'IB'}, cells[4]['userEnteredValue'])
                                self.assertEqual({'stringValue': 'New'}, cells[20]['userEnteredValue'])
                                self.assertEqual({'stringValue': candidate.activity_key[3]}, cells[5]['userEnteredValue'])
                        invented = tuple({**item, 'values': {'L': 'caller invented text'}} for item in placements)
                        with self.assertRaises(SendUnitHold):
                            freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=invented, writer_token=token, **args, **options)
                        altered = replace(qualified, candidates=tuple(replace(item, evidence_description='caller invented text')
                                                                      for item in qualified.candidates))
                        with self.assertRaises(SendUnitHold):
                            freeze_prod_source_unit(altered, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=placements, writer_token=token, **args, **options)
                        if family == 'switch':
                            noop_placements = tuple({**placement, 'observed_values': {'L': {
                                'stringValue': '[MONITOR][%s][%s] [fabric_source=%s] %s' %
                                    (candidate.activity_key[2], candidate.activity_key[3], candidate.fabric_source,
                                     candidate.evidence_description)}}}
                                for placement, candidate in zip(placements, candidates))
                            noop = freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=noop_placements,
                                writer_token=token, **args, **options)
                            self.assertEqual('NO_SEND', noop.outcome)
                            self.assertEqual(b'', noop.wire_bytes)
                            self.assertEqual(0, noop.history_rows_expected)
                            source_path = artifacts['ethernet/prod']['info']
                            source_before = source_path.read_bytes()
                            from monitor.issue_tracker_online_cells import source_tool_values as real_values
                            def drift_after_source_values(*values_args, **values_kwargs):
                                result = real_values(*values_args, **values_kwargs)
                                source_path.write_bytes(source_before + b'\nchanged during source compilation\n')
                                return result
                            try:
                                with mock.patch('monitor.issue_tracker_online_cells.source_tool_values',
                                                side_effect=drift_after_source_values), self.assertRaises(SendUnitHold):
                                    freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                                        expected_template_sha256=self.snapshot.workbook_sha256, placements=placements,
                                        writer_token=token, **args, **options)
                            finally:
                                source_path.write_bytes(source_before)
                    self.assertEqual(before_publication, tuple(sorted(self.publication.iterdir())))
                    self.assertEqual(before_generations, tuple(sorted(generation_root.iterdir())))
                    self.assertEqual(original_template, self.template.read_bytes())
                return
            if selected_manual_panel is not None:
                selected_body, selected_id = freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    selected_panel=selected_manual_panel, **args,
                )
                scoped = json.loads(selected_body)
                self.assertEqual("Switch Status",
                                 scoped["qualified_source"]["selected_panel"])
                if selected_panel_empty:
                    self.assertEqual([], scoped["operations"])
                    self.assertEqual([], scoped["qualified_source"]["whitelist_skips"])
                    evaluations = scoped["qualified_source"]["panel_evaluation"]
                    self.assertEqual(
                        {"state": "evaluated", "whitelist_skips": "no-skips"},
                        evaluations["Switch Status"],
                    )
                    for other in ("Eth Link Validation", "IB Link Validation"):
                        self.assertEqual(
                            {"state": "not-evaluated-in-this-manifest"},
                            evaluations[other],
                        )
                    self.assertEqual(
                        qualified.source_authority_sha256,
                        scoped["qualified_source"]["source_authority_sha256"],
                    )
                    self.assertEqual(
                        qualified.observations_sha256,
                        scoped["qualified_source"]["observations_sha256"],
                    )
                self.assertEqual(set() if selected_panel_empty else {"Switch Status"},
                                 {item.panel for item in qualified.candidates
                                  if item.operation_id in {operation["operation_id"]
                                      for operation in scoped["operations"]}})
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n",
                    encoding="utf-8",
                )
                if manual_channel_bridge:
                    self._verify_manual_queue_protected_commit(
                        project, original_template, before_generations,
                        qualified,
                    )
                    return
                interval, policy_sha = local_publish_interval(project)
                witness = (policy_sha, interval, "fixture-boot", time.monotonic_ns())
                with tracker_writer(project, self.publication) as token:
                    committed = commit_prod_stage_l_workbook(
                        token, qualified, self.store,
                        template_path=self.template, metadata=metadata,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        manual_admission=witness,
                        selected_panel=selected_manual_panel, **args,
                    )
                if selected_panel_empty:
                    self.assertIsInstance(committed, ProdWorkbookNoop)
                    self.assertEqual("no_candidates", committed.status)
                    self.assertEqual(selected_id, committed.manifest_id)
                    self.assertEqual(before_generations,
                                     tuple(sorted(generation_root.iterdir())))
                    self.assertFalse(any(generation_root.glob("*/RECEIPT")))
                    self.assertEqual(original_template, self.template.read_bytes())
                    with zipfile.ZipFile(BytesIO(original_template)) as before, \
                         zipfile.ZipFile(BytesIO(self.template.read_bytes())) as after:
                        for other in ("sheet3.xml", "sheet4.xml"):
                            path = "xl/worksheets/" + other
                            self.assertEqual(before.read(path), after.read(path))
                    return
                self.assertIsInstance(committed, CommittedProdWorkbook)
                self.assertEqual(3, committed.prepared.source_family_count)
                self.assertEqual(selected_id, committed.receipt.manifest_id)
                generation = (project / ".tracker/generations" /
                              committed.generation.generation_id)
                self.assertEqual(selected_body, (generation / "MANIFEST").read_bytes())
                self.assertTrue((generation / "RECEIPT").is_file())
                persisted_manifest = json.loads((generation / "MANIFEST").read_bytes())
                self.assertEqual(selected_manual_panel,
                                 persisted_manifest["qualified_source"]["selected_panel"])
                evaluations = persisted_manifest["qualified_source"]["panel_evaluation"]
                self.assertEqual({"state": "evaluated", "whitelist_skips": "no-skips"},
                                 evaluations["Switch Status"])
                for other in ("Eth Link Validation", "IB Link Validation"):
                    self.assertEqual({"state": "not-evaluated-in-this-manifest"},
                                     evaluations[other])
                persisted_receipt = json.loads((generation / "RECEIPT").read_bytes())
                self.assertEqual(selected_id, persisted_receipt["manifest_id"])
                self.assertEqual(1 + len(before_generations),
                                 len(tuple(generation_root.iterdir())))
                with zipfile.ZipFile(BytesIO(original_template)) as before, \
                     zipfile.ZipFile(BytesIO(committed.prepared.xlsx_bytes)) as after:
                    for other in ("sheet3.xml", "sheet4.xml"):
                        path = "xl/worksheets/" + other
                        self.assertEqual(before.read(path), after.read(path), other)
                    self.assertNotEqual(before.read("xl/worksheets/sheet2.xml"),
                                        after.read("xl/worksheets/sheet2.xml"))
                    self.assertNotEqual(before.read("xl/worksheets/sheet6.xml"),
                                        after.read("xl/worksheets/sheet6.xml"))
                return
            if automatic_first:
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(original_template)
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n"
                    + ("      publish_every_cycles: 2\n"
                       if automatic_not_due else ""),
                    encoding="utf-8",
                )
                stage_status_path = (
                    self.root / "monitor/status/issue-tracker-stage-l.status.json"
                )
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value="" if invalid_auto_clock
                                        else WORKER._current_boot_identity())):
                    result = WORKER._publish_stage_l_local_after_completion(self.store)
                if automatic_not_due:
                    self.assertIsNone(result)
                    self.assertEqual("qualified", json.loads(
                        stage_status_path.read_bytes())["state"])
                    self.assertEqual("not_due", json.loads(
                        stage_status_path.read_bytes())["local"])
                    self.assertEqual(before_generations,
                                     tuple(sorted(generation_root.iterdir())))
                    self.assertFalse((project / ".tracker/admissions").exists())
                    return
                if invalid_auto_clock:
                    self.assertIsNone(result)
                    self.assertEqual("hold", json.loads(
                        stage_status_path.read_bytes())["state"])
                    self.assertEqual(before_generations,
                                     tuple(sorted(generation_root.iterdir())))
                    self.assertFalse((project / ".tracker/admissions").exists())
                    return
                self.assertIsInstance(result, CommittedProdWorkbook)
                self.assertEqual("local_applied", json.loads(
                    stage_status_path.read_bytes())["state"])
                self.assertEqual("disabled_no_send_authority", json.loads(
                    stage_status_path.read_bytes())["online"])
                self.assertEqual(
                    hashlib.sha256(result.prepared.xlsx_bytes).hexdigest(),
                    result.receipt.published_sha256,
                )
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                admission_files = tuple(sorted((project / ".tracker/admissions").iterdir()))
                self.assertEqual(1, len(admission_files))
                admission = json.loads(admission_files[0].read_bytes())
                self.assertEqual(result.receipt.generation_id,
                                 admission["generation_id"])
                self.assertEqual(result.receipt.published_sha256,
                                 admission["published_sha256"])
                self.assertEqual(self.store.project_key, admission["project_key"])
                self.assertEqual("prod", admission["scope"])
                self.assertEqual(1, admission["schema_version"])
                with tracker_writer(project, self.publication) as token:
                    self.assertEqual(admission, read_auto_local_admission(
                        token, self.store, self.snapshot.workbook_sha256,
                    ))
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value=admission["boot_id"])):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                self.assertEqual("qualified", json.loads(
                    stage_status_path.read_bytes())["state"])
                self.assertEqual("not_due", json.loads(
                    stage_status_path.read_bytes())["local"])
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                if automatic_second_due or manual_second_probe or manual_second_admit:
                    second_identity = build_collection_cycle_identity(
                        str(project), "prod", 2, TOKEN_2,
                    )
                    second_binding = produce_worker_ib_analysis(
                        second_identity, project_root=project, http_root=self.root,
                        clock=lambda: dt.datetime(2026, 9, 26, 4, 31,
                                                  tzinfo=dt.timezone.utc),
                        runner=lambda _argv: self.fail(
                            "transport is supplied by fixture"),
                    )
                    second_cycle, _ = self._cycle(
                        activity=True, derivation=True,
                        observed_peer="changed-peer", ib_analysis=second_binding,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"},
                    )
                    self.assertEqual(second_identity["cycle_id"],
                                     second_cycle["cycle_id"])
                    if manual_second_probe:
                        with self.assertRaises(StageLHold):
                            commit_qualified_prod_local(
                                self.store, http_root=self.root,
                                project=project, publication=self.publication,
                                template_path=self.root /
                                "monitor/Issue_Tracker_Template_v1.xlsx",
                            )
                        # The lower C6 helper is also callable with a real
                        # qualified set. It must not mint a second generation
                        # without the same shared admission proof.
                        with tracker_writer(project, self.publication) as token:
                            second_qualified = qualify_prod_stage_l(
                                self.store, writer_token=token, **args,
                            )
                            with self.assertRaisesRegex(
                                LocalCommitHold, "shared admission",
                            ):
                                commit_prod_stage_l_workbook(
                                    token, second_qualified, self.store,
                                    template_path=self.template,
                                    metadata=metadata,
                                    expected_template_sha256=(
                                        self.snapshot.workbook_sha256),
                                    **args,
                                )
                        self.assertEqual(1, len(tuple(
                            (project / ".tracker/admissions").iterdir())))
                        self.assertEqual(len(before_generations) + 1,
                                         len(tuple(generation_root.iterdir())))
                        return
                    later_ns = (admission["monotonic_ns"]
                                + MIN_CONTINUOUS_INTERVAL_MINUTES * 60
                                * 1_000_000_000 + 1)
                    if manual_second_admit:
                        manual_witness = (
                            admission["policy_sha256"],
                            admission["publish_every_cycles"],
                            admission["boot_id"], later_ns,
                        )
                        with mock.patch.object(WORKER.time, "monotonic_ns",
                                               return_value=later_ns):
                            manual_result = commit_qualified_prod_local(
                                self.store, http_root=self.root, project=project,
                                publication=self.publication,
                                template_path=root_template,
                                manual_admission=manual_witness,
                            )
                        self.assertIsInstance(manual_result, CommittedProdWorkbook)
                        with tracker_writer(project, self.publication) as token:
                            manual_event = read_auto_local_admission(
                                token, self.store, self.snapshot.workbook_sha256)
                        self.assertEqual("manual", manual_event["lane"])
                        self.assertEqual(second_cycle["cycle_id"],
                                         manual_event["cycle_id"])
                        self.assertEqual(manual_result.receipt.generation_id,
                                         manual_event["generation_id"])
                        self.assertEqual(2, len(tuple(
                            (project / ".tracker/admissions").iterdir())))
                        self.assertEqual(len(before_generations) + 2,
                                         len(tuple(generation_root.iterdir())))
                        with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                              mock.patch.object(WORKER, "STATUS_DIR",
                                                stage_status_path.parent),
                              mock.patch.object(WORKER,
                                                "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                                stage_status_path),
                              mock.patch.object(WORKER, "_current_boot_identity",
                                                return_value=admission["boot_id"]),
                              mock.patch.object(WORKER.time, "monotonic_ns",
                                                return_value=later_ns)):
                            self.assertIsNone(
                                WORKER._publish_stage_l_local_after_completion(
                                    self.store))
                        held_status = json.loads(stage_status_path.read_bytes())
                        self.assertEqual("not_due", held_status.get("local"),
                                         held_status)
                        self.assertEqual(len(before_generations) + 2,
                                         len(tuple(generation_root.iterdir())))
                        return
                    with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                          mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                          mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                            stage_status_path),
                          mock.patch.object(WORKER, "_current_boot_identity",
                                            return_value=admission["boot_id"]),
                          mock.patch.object(WORKER.time, "monotonic_ns",
                                            return_value=later_ns)):
                        second_result = WORKER._publish_stage_l_local_after_completion(
                            self.store)
                    self.assertIsInstance(second_result, CommittedProdWorkbook)
                    self.assertNotEqual(result.receipt.generation_id,
                                        second_result.receipt.generation_id)
                    self.assertEqual("local_applied", json.loads(
                        stage_status_path.read_bytes())["state"])
                    second_admissions = tuple(sorted(
                        (project / ".tracker/admissions").iterdir()))
                    self.assertEqual(2, len(second_admissions))
                    self.assertEqual(len(before_generations) + 2,
                                     len(tuple(generation_root.iterdir())))
                    with tracker_writer(project, self.publication) as token:
                        latest_admission = read_auto_local_admission(
                            token, self.store, self.snapshot.workbook_sha256)
                    self.assertEqual(second_cycle["cycle_id"],
                                     latest_admission["cycle_id"])
                    self.assertEqual(second_result.receipt.generation_id,
                                     latest_admission["generation_id"])
                    tampered = json.loads(second_admissions[1].read_bytes())
                    tampered["monotonic_ns"] = admission["monotonic_ns"] + 1
                    second_admissions[1].write_bytes(
                        json.dumps(tampered, sort_keys=True,
                                   separators=(",", ":")).encode() + b"\n"
                    )
                    with tracker_writer(project, self.publication) as token:
                        with self.assertRaises(StageLHold):
                            read_auto_local_admission(
                                token, self.store,
                                self.snapshot.workbook_sha256,
                            )
                    return
                # A new boot has no proved elapsed interval from this event.
                # It must remain a visible HOLD, not infer the time floor from
                # completed-cycle count or replay the first C6 image.
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value="fixture-new-boot")):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                self.assertEqual("hold", json.loads(
                    stage_status_path.read_bytes())["state"])
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                admission_files[0].write_bytes(b"{}\n")
                with tracker_writer(project, self.publication) as token:
                    with self.assertRaises(StageLHold):
                        read_auto_local_admission(
                            token, self.store, self.snapshot.workbook_sha256,
                        )
                return

            def drift_after_bound_read(path, snapshot):
                source_bytes = _read_bound_source(path, snapshot)
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("leaf-z",), reserved_switch_rows=4,
                ))
                return source_bytes

            try:
                with tracker_writer(project, self.publication) as token, \
                     mock.patch(
                         "monitor.issue_tracker_local_workbook_commit._read_bound_source",
                         side_effect=drift_after_bound_read,
                     ):
                    with self.assertRaisesRegex(
                        LocalCommitHold,
                        "C-6 workbook source changed before generation",
                    ):
                        commit_prod_stage_l_workbook(
                            token, qualified, self.store,
                            template_path=self.template, metadata=metadata,
                            expected_template_sha256=self.snapshot.workbook_sha256,
                            **args,
                        )
            finally:
                self.template.write_bytes(original_template)
            self.assertEqual(before_generations,
                             tuple(sorted(generation_root.iterdir())))
            (project / "01-global.yaml").write_text(
                "schema_version: 2\ncommon:\n  mgmt:\n"
                "    issue-tracker:\n" + ("      status: enabled\n      spreadsheet_id: synthetic_spreadsheet_id_0001\n"
                    if receipted_intent_probe else "      status: disabled\n")
                + ("      publish_every_cycles: 3\n"
                   if manual_after_manual else ""),
                encoding="utf-8",
            )
            interval, policy_sha = local_publish_interval(project)
            manual_witness = (policy_sha, interval, "fixture-boot",
                              time.monotonic_ns())
            with tracker_writer(project, self.publication) as token:
                if terminal_orphan_probe:
                    with (mock.patch("monitor.issue_tracker_admission._mkdir",
                                     side_effect=OSError(
                                         "injected post-receipt admission failure")),
                          self.assertRaisesRegex(
                              OSError, "injected post-receipt admission failure")):
                        commit_prod_stage_l_workbook(
                            token, qualified, self.store, template_path=self.template,
                            metadata=metadata,
                            expected_template_sha256=self.snapshot.workbook_sha256,
                            manual_admission=manual_witness,
                            **args,
                        )
                else:
                    committed = commit_prod_stage_l_workbook(
                        token, qualified, self.store, template_path=self.template,
                        metadata=metadata,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        manual_admission=manual_witness,
                        **args,
                    )
            if terminal_orphan_probe:
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                self.assertTrue(any((generation / "RECEIPT").is_file()
                                    for generation in generation_root.iterdir()))
                self.assertFalse((project / ".tracker/admissions").exists())
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(self.template.read_bytes())
                stage_status_path = (
                    self.root / "monitor/status/issue-tracker-stage-l.status.json"
                )
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value="fixture-boot")):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                terminal_status = json.loads(stage_status_path.read_bytes())
                self.assertEqual("hold", terminal_status["state"])
                self.assertEqual("local_c6_terminal_admission_state",
                                 terminal_status["reason"])
                self.assertEqual("C6 RECEIPT has no admission evidence",
                                 terminal_status["terminal_detail"])
                self.assertEqual("disabled_no_send_authority",
                                 terminal_status["online"])
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                return
            self.assertIsInstance(committed, CommittedProdWorkbook)
            self.assertEqual(digest, committed.receipt.manifest_id)
            self.assertEqual(hashlib.sha256(committed.prepared.xlsx_bytes).hexdigest(),
                             committed.receipt.published_sha256)
            if observed_cabling_insert_probe:
                import tempfile
                import monitor.issue_tracker_send_unit as compiler
                from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read, prepare_insertion_sheet_read, prepare_sheets_read, prepare_history_tail_read, prepare_template_identity_read
                from monitor.issue_tracker_sheets_read_decode import decode_template_identity
                from monitor.issue_tracker_online_target import OnlineTargetBinding
                from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                from test_cases.test_req7_activity_discovery import sheet_document, insertion_document, exact_row_document, cabling_row, literal
                from test_cases.test_req7_sheets_read_decode import identity_response, response
                from test_cases.test_req7_spreadsheet_owner import load as load_owner, scoped_fixture
                from test_cases.test_req7_enrollment_journal import load as load_enrollment
                from test_cases.test_req7_nv_reservation import load as load_nv
                self.assertTrue(hasattr(compiler, 'freeze_observed_receipted_cabling_unit'), 'Cabling compiler must bind original source/receipt and durable IDs')
                binding = OnlineTargetBinding('synthetic_spreadsheet_id_0001', 'a'*64, 'b'*64)
                if receipted_intent_probe:
                    from monitor import issue_tracker_credential_shape as private_inputs, issue_tracker_online_target as current_target
                    from tools.project_contract import safe_load_global_yaml
                    allowlist_bytes = b'["synthetic_spreadsheet_id_0001"]\n'
                    binding = current_target.bind_online_target(safe_load_global_yaml((project/'01-global.yaml').read_text()),
                        current_target.freeze_target_allowlist(allowlist_bytes))
                for sheet, family, sid, other_sheet, other_sid in (('ETH Cabling', 'eth_cabling', 102, 'IB Cabling', 103),
                                                                  ('IB Cabling', 'ib_cabling', 103, 'ETH Cabling', 102)):
                    if before_cabling_fixture is not None: before_cabling_fixture(sheet)
                    # Each sheet below owns a separate native fixture/lock
                    # period. Acquire its synthetic credential/read plans here,
                    # never extend or ignore an earlier period's token expiry.
                    credential = AuthenticatedToken('synthetic.private-token', time.time()+3600)
                    identity = decode_template_identity(prepare_template_identity_read(binding, credential), response(identity_response()))
                    history_plan = prepare_history_tail_read(binding, credential)
                    history_raw = response({'spreadsheetId': binding.spreadsheet_id, 'sheets': [{'properties': {'sheetId': 105,
                        'title': 'Update_History', 'sheetType': 'GRID', 'gridProperties': {'rowCount': 100, 'columnCount': 5}},
                        'data': [{'startRow': 2, 'startColumn': 0}]}]})
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    self.assertGreater(len(candidates), 1)
                    row = cabling_row('NV30016'); key = candidates[0].activity_key
                    row.update({column: literal(value) for column, value in zip(('K', 'L', 'F'), key[1:])})
                    closed = cabling_row('NV30017', 'Closed'); key = candidates[-1].activity_key
                    closed.update({column: literal(value) for column, value in zip(('K', 'L', 'F'), key[1:])})
                    rows = [row, closed, {'V': {'boolValue': False}}]
                    discovery = sheet_document(sheet, rows, 100); discovery['sheets'][0]['properties']['sheetId'] = sid
                    occupancy = insertion_document(sheet, rows, 100); occupancy['sheets'][0]['properties']['sheetId'] = sid
                    other = cabling_row('NV39999', 'Closed'); other['K'] = literal('unrelated-original-seed')
                    other_raw = sheet_document(other_sheet, [other], 100); other_raw['sheets'][0]['properties']['sheetId'] = other_sid
                    try:
                        discovery_plan = prepare_activity_sheet_read(binding, credential, sheet=sheet)
                        occupancy_plan = prepare_insertion_sheet_read(binding, credential, sheet=sheet)
                        other_plan = prepare_activity_sheet_read(binding, credential, sheet=other_sheet)
                    except Exception as exc:
                        # Safe phase facts only; no credential/header/body/ID.
                        print('CABLING_FIXTURE_PLAN_ERROR',sheet,type(exc).__name__,{
                            'binding_class_current':type(binding) is sys.modules['monitor.issue_tracker_online_target'].OnlineTargetBinding,
                            'token_class_current':type(credential) is sys.modules['monitor.issue_tracker_sdk_authentication'].AuthenticatedToken,
                            'expires_in_seconds':credential.expires_at-time.time()},flush=True)
                        raise
                    original_read = response(discovery); other_read = response(other_raw)
                    reads = []
                    for offset, candidate in enumerate(candidates):
                        exact = exact_row_document(sheet, rows[0], 2); exact['sheets'][0]['properties']['sheetId'] = sid
                        reads.append({'operation_id': candidate.operation_id, 'discovery_plan': discovery_plan,
                            'discovery_response': original_read, 'occupancy_plan': occupancy_plan, 'occupancy_response': response(occupancy),
                            'row_plan': prepare_sheets_read(binding, credential, mode='row_rectangle', sheet=sheet, first_row=3) if offset == 0 else None,
                            'row_response': response(exact) if offset == 0 else None})
                    requested = tuple(item.activity_key for item in candidates[1:])
                    expected = tuple((key, 'NV%05d' % (40000+index)) for index, key in enumerate(sorted(requested)))
                    with tempfile.TemporaryDirectory(prefix='req7-real-cabling-unit-') as directory:
                        global_root = Path(directory).resolve(); state = global_root/'var/lib/http-ztp-container/issue-tracker'
                        state.mkdir(parents=True, mode=0o700); owner_module = load_owner(); enrollment_module = load_enrollment(); nv_module = load_nv()
                        from contextlib import ExitStack
                        with tracker_writer(project, self.publication) as writer_token, scoped_fixture(global_root, owner_module), owner_module.spreadsheet_owner(binding) as spreadsheet_token, ExitStack() as private_context, ExitStack() as native_count_context:
                            if receipted_intent_probe:
                                private_directory = global_root/'var/lib/http-ztp-container/service-account'
                                private_directory.mkdir(mode=0o700)
                                private_allowlist = private_directory/'issue-tracker-spreadsheet-whitelist.json'
                                private_allowlist.write_bytes(allowlist_bytes); private_allowlist.chmod(0o600)
                                private_context.enter_context(scoped_fixture(global_root, private_inputs))
                                private_context.enter_context(scoped_fixture(global_root, current_target))
                            original = enrollment_module.prepare_enrollment_journal(spreadsheet_token, binding, identity)
                            nv_args = dict(generation_id=committed.receipt.generation_id, publish_id=committed.receipt.published_sha256,
                                sheet=sheet, requested_keys=requested)
                            pair = (discovery_plan, original_read, other_plan, other_read) if sheet == 'ETH Cabling' else (other_plan, other_read, discovery_plan, original_read)
                            prepared = None
                            if native_catalog_probe:
                                from test_cases.test_req7_global_attempt_journal import load as load_global
                                load_global(); nv_module = load_nv()
                                from test_cases.test_req7_unit_catalog import load as load_catalog
                                catalog = load_catalog(reset_dependencies=False)
                                self.assertIs(catalog.ownership, owner_module, 'native catalog must use this actual fixture owner registry')
                                if native_catalog_creator_first_stat_probe is not None:
                                    from test_cases.test_req7_nv_reservation import native_creator_first_stat_fault
                                    with native_creator_first_stat_fault(nv_module, global_root) as (created, marks, _foreign, real_fstat):
                                        with self.assertRaises(nv_module.NvReservationHold):
                                            with nv_module.hold_catalog_nv_preparation(spreadsheet_token, binding, identity, *pair, **nv_args):
                                                self.fail('actual protected C6 fault reached compiler handoff')
                                        self.assertEqual(['actual-first-stat-fault'], marks)
                                        self.assertEqual(1, len(created))
                                        with self.assertRaises(OSError, msg='actual protected C6 NV creator leaked owned FD'):
                                            real_fstat(created[0][0])
                                        self.assertFalse(any(path.name.endswith('.units') or path.name.endswith('.project-origin')
                                            or '.journal' in path.name for path in state.iterdir()))
                                        self.assertEqual(1, len(tuple(state.glob('*.nv-started'))))
                                        native_catalog_creator_first_stat_probe.append(sheet + ':actual-first-stat-fault:owned-fd-closed')
                                    continue
                                preparation_context = (native_count_context if native_catalog_receipted_count_probe is not None or native_catalog_launch_probe is not None else private_context)
                                prepared = preparation_context.enter_context(nv_module.hold_catalog_nv_preparation(
                                    spreadsheet_token, binding, identity, *pair, **nv_args))
                                reservation = prepared.observation
                            else:
                                reservation = nv_module.prepare_nv_reservation(spreadsheet_token, binding, identity, *pair, **nv_args)
                            self.assertEqual(expected, reservation.reservations)
                            def compile_cabling(**changes):
                                options = dict(local_generation_id=committed.receipt.generation_id, sheet=sheet, business_reads=tuple(reads),
                                    history_plan=history_plan, history_response=history_raw, spreadsheet_token=spreadsheet_token, binding=binding, identity=identity)
                                if prepared is not None: options['_nv_preparation'] = prepared
                                if settings_audit_probe and sheet == 'ETH Cabling':
                                    from monitor.issue_tracker_settings_audit_allocation import pending_settings_audits
                                    options['audits'] = pending_settings_audits(writer_token)
                                    self.assertTrue(options['audits'])
                                options.update(changes)
                                return compiler.freeze_observed_receipted_cabling_unit(qualified, self.store, metadata=metadata,
                                    expected_template_sha256=self.snapshot.workbook_sha256, writer_token=writer_token, **args, **options)
                            nv_suffix = '.nv' if prepared is None else '.unit-' + reservation.unit_id + '.nv'
                            before = {path.name: path.read_bytes() for path in (state/(hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+nv_suffix)).iterdir()}
                            if native_catalog_return_fault is not None:
                                mode, marks = native_catalog_return_fault
                                original_freeze = compiler.freeze_receipted_prod_source_unit
                                original_receipt = compiler._original_receipt_identity
                                compiled_stage = []
                                raw_path = state/(hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+nv_suffix)/'ETH-RAW'
                                def retain_real_frozen_unit(*arguments, **keywords):
                                    result = original_freeze(*arguments, **keywords)
                                    compiled_stage.append(True)
                                    return result
                                def drift_after_real_final_receipt(*arguments, **keywords):
                                    result = original_receipt(*arguments, **keywords)
                                    if compiled_stage and not marks:
                                        raw, old_stat = raw_path.read_bytes(), raw_path.stat()
                                        if mode == 'same_byte_replace':
                                            replacement = raw_path.with_name('owned-fault-replacement')
                                            replacement.write_bytes(raw); replacement.chmod(0o600)
                                            os.replace(replacement, raw_path)
                                            self.assertNotEqual(old_stat.st_ino, raw_path.stat().st_ino)
                                        else:
                                            raw_path.write_bytes(raw)
                                            os.utime(raw_path, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns+1000000))
                                            self.assertEqual(old_stat.st_ino, raw_path.stat().st_ino)
                                        marks.append(('injected', mode))
                                    return result
                                with mock.patch.object(compiler, 'freeze_receipted_prod_source_unit', side_effect=retain_real_frozen_unit), \
                                     mock.patch.object(compiler, '_original_receipt_identity', side_effect=drift_after_real_final_receipt):
                                    try: compile_cabling()
                                    except compiler.SendUnitHold: marks.append(('compiler', 'HOLD'))
                                    else: marks.append(('compiler', 'RETURNED'))
                                marks.append(('catalog_written', any(path.name.endswith('.units') for path in state.iterdir())))
                                raise RuntimeError('owned native compiler fault fixture complete; preserve original HOLD')
                            if native_catalog_probe:
                                try: unit = compile_cabling()
                                except compiler.SendUnitHold:
                                    print('NATIVE_C6_COMPILE_REJECTED_BEFORE_HANDOFF', sheet, flush=True)
                                    raise
                            else:
                                unit = compile_cabling()
                            action = json.loads(unit.action_preimage)
                            self.assertEqual(['update']+['insert']*(len(candidates)-1), [item['action'] for item in action['business']])
                            self.assertEqual(committed.receipt.generation_id, action['identity']['generation_id'])
                            self.assertEqual(committed.receipt.published_sha256, action['identity']['publish_id'])
                            nonces = {title: nonce for title, _sid, nonce in original.nonces}
                            self.assertEqual(nonces[sheet], action['target_nonce']); self.assertEqual(nonces['Update_History'], action['history_nonce'])
                            independent_read_image = {'schema_version': 1, 'spreadsheet_id': binding.spreadsheet_id, 'sheet': sheet,
                                'sheet_id': sid, 'history_sheet_id': 105, 'history_path': history_plan.path,
                                'history_sha256': hashlib.sha256(history_raw.data).hexdigest(), 'nv_journal_sha256': reservation.journal_sha256,
                                'business': [{'operation_id': candidate.operation_id, 'discovery_path': discovery_plan.path,
                                    'discovery_sha256': hashlib.sha256(original_read.data).hexdigest(), 'occupancy_path': occupancy_plan.path,
                                    'occupancy_sha256': hashlib.sha256(reads[index]['occupancy_response'].data).hexdigest(),
                                    'row_path': reads[index]['row_plan'].path if index == 0 else None,
                                    'row_sha256': hashlib.sha256(reads[index]['row_response'].data).hexdigest() if index == 0 else None,
                                    'append_start_row_index': None if index == 0 else 5}
                                    for index, candidate in enumerate(candidates)]}
                            self.assertEqual(hashlib.sha256((json.dumps(independent_read_image, ensure_ascii=False, sort_keys=True,
                                separators=(',', ':'))+'\n').encode()).hexdigest(), action['preread_sha256'])
                            requests = json.loads(unit.wire_bytes)['requests']
                            appends = [item['appendCells'] for item in requests if 'appendCells' in item and item['appendCells']['sheetId'] == sid]
                            self.assertEqual(len(candidates)-1, len(appends))
                            self.assertEqual([dict(expected)[item.activity_key] for item in candidates[1:]],
                                [item['rows'][0]['values'][0]['userEnteredValue']['stringValue'] for item in appends])
                            for item in appends:
                                self.assertEqual({'sheetId', 'rows', 'fields'}, set(item))
                                for index in (7, 8, 9, 14, 15): self.assertEqual({}, item['rows'][0]['values'][index])
                            for item in requests:
                                if 'updateCells' in item:
                                    self.assertEqual(2, item['updateCells']['start']['rowIndex']); self.assertNotEqual(0, item['updateCells']['start']['columnIndex'])
                            if prepared is not None:
                                self.assertEqual(reservation, nv_module._catalog_nv_compiled_observation(prepared, spreadsheet_token, binding, unit))
                                for changes in ({'_nv_preparation': replace(prepared)}, {'reserved_ids': ('NV99999',)},
                                                {'placements': ()}, {'target_nonce': 'c'*64}, {'business_reads': tuple(reads[:-1])}):
                                    with self.assertRaises(compiler.SendUnitHold): compile_cabling(**changes)
                                from monitor import issue_tracker_unit_catalog as catalog
                                if native_catalog_c6_origin_probe:
                                    actual_append = catalog.register_pending_unit; appended = []
                                    def append_once(*arguments, **keywords):
                                        appended.append(arguments[2].unit_id)
                                        return actual_append(*arguments, **keywords)
                                    with mock.patch.object(catalog, 'register_pending_unit', side_effect=append_once):
                                        catalog.register_pending_c6_unit(writer_token, spreadsheet_token, binding, unit,
                                            _nv_preparation=prepared)
                                    self.assertEqual([unit.unit_id], appended, 'one genuine C6 registration cannot double append')
                                    with catalog.hold_pending_project_c6_units(spreadsheet_token, binding) as (rows, verify_projects):
                                        self.assertEqual((unit,), tuple(row.unit for row in rows)); verify_projects()
                                else:
                                    nv_module.register_catalog_nv_unit(prepared, unit)
                                with catalog.hold_pending_c6_units(writer_token, spreadsheet_token, binding) as (units, verify_c6):
                                    self.assertEqual((unit,), units); verify_c6()
                                self.assertEqual(reservation, nv_module.require_unit_nv_reservation(spreadsheet_token, binding, identity, unit))
                                self.assertEqual(before, {path.name: path.read_bytes() for path in
                                    (state/(hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+nv_suffix)).iterdir()})
                                origins = tuple(path for path in state.iterdir() if path.name.endswith('.project-origin'))
                                if native_catalog_c6_origin_probe:
                                    self.assertEqual(1, len(origins))
                                    self.assertEqual({'STARTED', 'ORIGIN', 'WITNESS'}, set(os.listdir(origins[0])))
                                else:
                                    self.assertFalse(origins, 'C6 original reader is not the separate project-origin writer')
                                if native_catalog_retained_probe:
                                    # Close the actual preparation before the genuine GLOBAL
                                    # writer adds its fixed journal; old namespace proof is
                                    # not silently refreshed to permit a foreign append.
                                    if native_catalog_receipted_count_probe is not None or native_catalog_launch_probe is not None:
                                        # Close only the completed native preparation. The
                                        # actual fixed credential/allowlist roots must stay
                                        # bound through protected source replay and count.
                                        native_count_context.close()
                                    else:
                                        private_context.close()
                                    from monitor import issue_tracker_global_attempt_journal as global_journal
                                    # This fixture creates canonical owner registries per
                                    # scenario. Bind the real consumer after that setup,
                                    # as the existing native inventory fixtures do; a
                                    # preimported prior scenario cannot own this token.
                                    from test_cases.test_req7_retained_global_inventory import load as inventory_load
                                    inventory = inventory_load(reset_support=False)
                                    global_journal.prepare_global_unit(spreadsheet_token, binding, unit)
                                    original_files = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                        for path in state.rglob('*') if path.is_file()}
                                    with inventory._hold_catalog_retained_inventory(spreadsheet_token, binding) as (rows, verify):
                                        self.assertEqual((unit,), tuple(row.unit for row in rows))
                                        self.assertEqual((0,), tuple(row.attempt_count for row in rows))
                                        self.assertIn('nv-started', rows[0].families)
                                        self.assertTrue(any(name.endswith('.nv/PRIOR') for name, _stat, _sha in rows[0].originals))
                                        self.assertFalse(any(hasattr(rows[0], name) for name in ('permit', 'applied', 'fresh', 'new')))
                                        verify()
                                    if native_catalog_all_c6_fifo_probe is not None:
                                        with inventory._hold_all_project_applied_keys(spreadsheet_token, binding) as (rows, verify):
                                            self.assertEqual((unit,), tuple(row.unit for row in rows))
                                            self.assertEqual((0,), tuple(row.attempt_count for row in rows))
                                            self.assertEqual(((),), tuple(row.key_watermarks for row in rows))
                                            verify()
                                            native_catalog_all_c6_fifo_probe.append(sheet + ':actual-all-project-c6:no-applied')
                                        with inventory._hold_all_project_fifo_frontier(spreadsheet_token, binding) as (frontier, verify):
                                            self.assertEqual((unit.unit_id,), frontier.frontier)
                                            self.assertEqual((), frontier.blocked)
                                            self.assertEqual((), frontier.applied); self.assertEqual((), frontier.superseded)
                                            self.assertFalse(any(hasattr(frontier, name) for name in ('permit', 'fresh', 'new', 'writer_token')))
                                            verify()
                                            native_catalog_all_c6_fifo_probe.append(sheet + ':actual-fifo:read-only')
                                    self.assertEqual(original_files, {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                        for path in state.rglob('*') if path.is_file()})
                                if native_catalog_receipted_count_probe is not None or native_catalog_launch_probe is not None:
                                    from test_cases.test_req7_history_preread_journal import load as load_preread
                                    from test_cases.test_req7_metadata_reservation import load as load_quota
                                    from monitor.issue_tracker_metadata_capacity import prepare_metadata_capacity_read
                                    preread = load_preread(); quota_module = load_quota()
                                    preread.prepare_history_preread(spreadsheet_token, binding, unit, history_plan, history_raw)
                                    preread.prepare_business_preread(spreadsheet_token, binding, identity, unit,
                                        manifest=body, business_reads=tuple(reads))
                                    quota_raw = response({'matchedDeveloperMetadata': [
                                        {'developerMetadata': {'metadataId': index+1, 'metadataKey': 'http-ztp-enrollment-v1',
                                            'metadataValue': nonce, 'visibility': 'DOCUMENT',
                                            'location': {'locationType': 'SHEET', 'sheetId': sheet_id}}}
                                        for index, (_title, sheet_id, nonce) in enumerate(original.nonces)]})
                                    quota_module.prepare_metadata_reservation(spreadsheet_token, binding, identity, unit,
                                        prepare_metadata_capacity_read(binding, credential), quota_raw)
                                    frozen_images = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                        for path in state.rglob('*') if path.is_file()}
                                    if native_catalog_launch_probe is not None:
                                        mode,observed = native_catalog_launch_probe
                                        self._exercise_native_original_counted_launch(mode=mode,observed=observed,
                                            global_root=global_root,private_context=private_context,
                                            writer_token=writer_token,spreadsheet_token=spreadsheet_token,
                                            binding=binding,credential=credential,unit=unit,identity=identity,
                                            quota_raw=quota_raw,history_raw=history_raw,reads=reads,sheet=sheet,
                                            qualified=qualified,settings=args['settings'],committed=committed,
                                            state=state,owner_module=owner_module,global_journal=global_journal)
                                        continue
                                    counted = global_journal.record_receipted_original_attempt_intent(
                                        spreadsheet_token, binding, identity, unit, qualified_source=qualified,
                                        store=self.store, writer_token=writer_token, settings=args['settings'],
                                        whitelist_snapshot=self.snapshot, expected_template_sha256=self.snapshot.workbook_sha256,
                                        http_root=self.root, whitelist_path=self.template)
                                    self.assertEqual((1, 'UNKNOWN'), (counted.attempt_count, counted.outcome))
                                    self.assertFalse(any(hasattr(counted, name) for name in ('permit', 'send_once', 'complete', 'applied')))
                                    self.assertEqual(expected, nv_module.require_unit_nv_reservation(
                                        spreadsheet_token, binding, identity, unit).reservations)
                                    after = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                        for path in state.rglob('*') if path.is_file()}
                                    for name, image in frozen_images.items():
                                        if '.journal/' not in name:
                                            self.assertEqual(image, after[name], name)
                                    native_catalog_receipted_count_probe.append(sheet + ':actual-receipted-count:unknown')
                                continue
                            self.assertEqual(reservation, nv_module.require_unit_nv_reservation(spreadsheet_token, binding, identity, unit))
                            for claims in ({'reserved_ids': ('NV99999',)}, {'placements': ()}, {'target_nonce': 'c'*64}, {'business_reads': tuple(reads[:-1])}, {'sheet': 'ETH&IB Switch'}):
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling(**claims)
                            saved = reads[-1]['discovery_response']; changed = json.loads(saved.data)
                            changed['sheets'][0]['data'][0]['rowData'][0]['values'][0] = {'userEnteredValue': literal('Closed')}
                            reads[-1]['discovery_response'] = response(changed)
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally: reads[-1]['discovery_response'] = saved
                            saved_occupancy = tuple(reading['occupancy_response'] for reading in reads)
                            full = json.loads(saved_occupancy[0].data)
                            for grid in full['sheets'][0]['data']:
                                if grid['startColumn'] == 21:
                                    grid['rowData'] = [{}, {}, {'values': [{'userEnteredValue': {'boolValue': False}}]}] + [{}]*94 + [
                                        {'values': [{'userEnteredValue': literal('operator at capacity boundary')}]}]
                            for reading in reads: reading['occupancy_response'] = response(full)
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally:
                                for reading, original_response in zip(reads, saved_occupancy): reading['occupancy_response'] = original_response
                            real_freeze = compiler.freeze_receipted_prod_source_unit
                            drift = json.loads(saved_occupancy[-1].data)
                            for grid in drift['sheets'][0]['data']:
                                if grid['startColumn'] == 21: grid['rowData'][2]['values'][0] = {'userEnteredValue': literal('changed during compile')}
                            def change_occupancy_during_freeze(*freeze_args, **freeze_kwargs):
                                result = real_freeze(*freeze_args, **freeze_kwargs)
                                reads[-1]['occupancy_response'] = response(drift)
                                return result
                            try:
                                with mock.patch.object(compiler, 'freeze_receipted_prod_source_unit', side_effect=change_occupancy_during_freeze):
                                    with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally: reads[-1]['occupancy_response'] = saved_occupancy[-1]
                            stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                            ids_path = state/(stem+'.nv')/'RESERVATIONS'; saved_ids = ids_path.read_bytes()
                            ids_path.write_bytes(saved_ids.replace(b'NV40000', b'NV99999'))
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally: ids_path.write_bytes(saved_ids)
                            stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                            if business_preread_probe:
                                from test_cases.test_req7_global_attempt_journal import load as load_global
                                from test_cases.test_req7_history_preread_journal import load as load_preread
                                # Mirror canonical imports after this fixture's
                                # owner reload; never relax real owner registries.
                                global_journal = load_global(); preread = load_preread()
                                self.assertIs(global_journal.ownership, owner_module)
                                self.assertIs(preread.ownership, owner_module)
                                self.assertTrue(hasattr(preread, 'prepare_business_preread'), 'original C5/C6 business images must survive cold/UNKNOWN')
                                global_journal.prepare_global_unit(spreadsheet_token, binding, unit)
                                preread.prepare_history_preread(spreadsheet_token, binding, unit, history_plan, history_raw)
                                preread.prepare_business_preread(spreadsheet_token, binding, identity, unit, manifest=body, business_reads=tuple(reads))
                                seen = preread.inspect_business_preread(spreadsheet_token, binding, identity, unit)
                                self.assertEqual((len(candidates), 0, action['preread_sha256']), (seen.operations_retained, seen.noop_operations, seen.preread_sha256))
                                retained = {path.name: path.read_bytes() for path in (state/(stem+'.business')).iterdir()}
                                if original_reserved_probe:
                                    from test_cases.test_req7_metadata_reservation import load as load_quota
                                    from monitor.issue_tracker_metadata_capacity import prepare_metadata_capacity_read
                                    quota_module = load_quota()
                                    quota_raw = response({'matchedDeveloperMetadata': [
                                        {'developerMetadata': {'metadataId': index+1, 'metadataKey': 'http-ztp-enrollment-v1',
                                            'metadataValue': nonce, 'visibility': 'DOCUMENT',
                                            'location': {'locationType': 'SHEET', 'sheetId': sheet_id}}}
                                        for index, (_title, sheet_id, nonce) in enumerate(original.nonces)]})
                                    quota = quota_module.prepare_metadata_reservation(spreadsheet_token, binding, identity, unit,
                                        prepare_metadata_capacity_read(binding, credential), quota_raw)
                                    self.assertTrue(hasattr(global_journal, 'record_original_business_reserved_attempt_intent'), 'complete original chain must dominate counted intent')
                                    record = lambda: global_journal.record_original_business_reserved_attempt_intent(spreadsheet_token, binding, identity, unit)
                                    if receipted_intent_probe:
                                        self.assertTrue(hasattr(global_journal, 'record_receipted_original_attempt_intent'), 'protected original C6 chain must dominate each counted intent')
                                        self.assertTrue(hasattr(preread, 'inspect_business_source_projection'), 'replayed C5 source values must bind ALL original wire and NOOP decisions')
                                        from monitor.issue_tracker_local_workbook_commit import _source_rows
                                        cabling_source, switch_source = _source_rows(qualified)
                                        source_rows = (*cabling_source, *switch_source)
                                        self.assertEqual(seen, preread.inspect_business_source_projection(spreadsheet_token, binding, identity, unit, source_rows))
                                        changed_rows = tuple(replace(row, evidence_description='caller invented original values') for row in source_rows)
                                        with self.assertRaises(preread.HistoryPrereadHold):
                                            preread.inspect_business_source_projection(spreadsheet_token, binding, identity, unit, changed_rows)
                                        self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                        def record(**changes):
                                            options = dict(qualified_source=qualified, store=self.store, writer_token=writer_token,
                                                settings=args['settings'], whitelist_snapshot=self.snapshot,
                                                expected_template_sha256=self.snapshot.workbook_sha256,
                                                http_root=self.root, whitelist_path=self.template)
                                            options.update(changes)
                                            return global_journal.record_receipted_original_attempt_intent(spreadsheet_token, binding, identity, unit, **options)
                                        if settings_audit_probe and sheet == 'ETH Cabling':
                                            from test_cases.test_req7_settings_audit_allocation import load as load_allocation
                                            allocation_module = load_allocation()
                                            self.assertTrue(action['audits'])
                                            # Existing coherent unit + C5/C6 + all reservations still
                                            # cannot count without ORIGINAL durable C25 assignments.
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            allocation_module.prepare_settings_audit_allocation(writer_token, spreadsheet_token, binding, unit)
                                            allocation_path = project/'.tracker/settings-audit-allocation'
                                            allocation_image = {p.name: p.read_bytes() for p in allocation_path.iterdir()}
                                            assignments_path = allocation_path/'ASSIGNMENTS'
                                            assignments_path.write_bytes(b'foreign original allocation')
                                            try:
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                                self.assertEqual(b'foreign original allocation', assignments_path.read_bytes())
                                            finally: assignments_path.write_bytes(allocation_image['ASSIGNMENTS'])
                                        private_allowlist.write_bytes(b'[]\n')
                                        try:
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(b'[]\n', private_allowlist.read_bytes())
                                        finally: private_allowlist.write_bytes(allowlist_bytes)
                                        for changes in ({'writer_token': None}, {'qualified_source': replace(qualified, observations_sha256='f'*64)},
                                                        {'expected_template_sha256': 'f'*64}):
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record(**changes)
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                        generation_path = project/'.tracker/generations'/committed.receipt.generation_id
                                        c6_original = {name: (generation_path/name).read_bytes() for name in ('STATE', 'MANIFEST', 'INTENT', 'RECEIPT')}
                                        for name, raw in c6_original.items():
                                            path = generation_path/name; path.write_bytes(b'foreign C6 original')
                                            try:
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                                self.assertEqual(b'foreign C6 original', path.read_bytes())
                                            finally: path.write_bytes(raw)  # undo this owned fixture fault only
                                        source_path = artifacts['ethernet/prod']['info']
                                        source_before = source_path.read_bytes()
                                        source_path.write_bytes(source_before+b'\nchanged original producer source\n')
                                        try:
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(source_before+b'\nchanged original producer source\n', source_path.read_bytes())
                                        finally: source_path.write_bytes(source_before)  # owned producer fault only
                                        actual_business_inspect = preread.inspect_business_preread
                                        def change_source_after_business(*inspect_args, **inspect_kwargs):
                                            result = actual_business_inspect(*inspect_args, **inspect_kwargs)
                                            source_path.write_bytes(source_before+b'\nchanged during original barrier\n')
                                            return result
                                        try:
                                            with mock.patch.object(preread, 'inspect_business_preread', side_effect=change_source_after_business):
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(source_before+b'\nchanged during original barrier\n', source_path.read_bytes())
                                        finally: source_path.write_bytes(source_before)  # owned fixture only
                                        actual_source_projection = preread.inspect_business_source_projection
                                        def revoke_during_business(*inspect_args, **inspect_kwargs):
                                            result = actual_source_projection(*inspect_args, **inspect_kwargs)
                                            private_allowlist.write_bytes(b'[]\n'); return result
                                        try:
                                            with mock.patch.object(preread, 'inspect_business_source_projection', side_effect=revoke_during_business):
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(b'[]\n', private_allowlist.read_bytes())
                                        finally: private_allowlist.write_bytes(allowlist_bytes)  # owned fault only
                                    if owned_read_gates_probe:
                                        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests, load as load_read_gates
                                        from test_cases.test_req7_sheets_read_decode import header_response
                                        from test_cases.test_req7_online_whitelist_read import document as whitelist_document
                                        from monitor import issue_tracker_history_read_launcher as fixed_reads
                                        read_gates = load_read_gates()
                                        self.assertIs(read_gates.global_journal, global_journal)
                                        self.assertIs(read_gates.enrollment, sys.modules['monitor.issue_tracker_enrollment_journal'])
                                        self.assertIs(read_gates.ownership, owner_module)
                                        import xml.etree.ElementTree as ET
                                        native_fixture = Req7OwnedHistoryMatchWorkflowTests()
                                        # The read child still uses the real fixed CA reader.
                                        # Its owned TLS root must not replace the CA/leaf
                                        # of an already prepared mutation endpoint.
                                        native_fixture.root = global_root/'owned-read-tls-root'
                                        native_fixture.path = native_fixture.root/'etc/ssl/certs/ca-certificates.crt'
                                        native_fixture.path.parent.mkdir(parents=True)
                                        native_fixture.addCleanup = self.addCleanup
                                        # Read actual fixture cells, not a whitelist generated
                                        # from the implementation's normalized digest/rules.
                                        namespace = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
                                        with zipfile.ZipFile(self.template) as archive:
                                            original_sheet = ET.fromstring(archive.read('xl/worksheets/sheet13.xml'))
                                        literal_rows = []
                                        for original_row in original_sheet.find(namespace+'sheetData'):
                                            cells = [None]*6
                                            for cell in original_row:
                                                self.assertEqual('inlineStr',cell.get('t'))
                                                self.assertIsNone(cell.find(namespace+'f'))
                                                column = ord(cell.get('r')[0])-ord('A')
                                                self.assertTrue(0 <= column < 6)
                                                cells[column] = ''.join(cell.itertext())
                                            literal_rows.append(tuple(cells))
                                        whitelist_doc = whitelist_document(())
                                        whitelist_doc['sheets'][0]['properties']['sheetId'] = dict(identity.sheet_ids)['Whitelist']
                                        whitelist_doc['sheets'][0]['data'][0]['rowData'] = [
                                            {'values': [{} if value is None else {'userEnteredValue': {'stringValue': value}}
                                                        for value in row[:6]]} for row in literal_rows]
                                        def fresh_bundle():
                                            bundle = {name:native_fixture.read_owned(private_context,writer_token,spreadsheet_token,
                                                binding,credential,kind,doc,raw_body=response(doc).data) for name,kind,doc in (
                                                    ('identity_response','template_identity',identity_response()),
                                                    ('headers_response','template_headers',header_response()),
                                                    ('whitelist_response','whitelist',whitelist_doc),
                                                    ('metadata_response','metadata',json.loads(quota_raw.data)))}
                                            if owned_continuity_probe:
                                                bundle['history_response'] = native_fixture.read_owned(private_context,writer_token,spreadsheet_token,
                                                    binding,credential,'history_tail',json.loads(history_raw.data),raw_body=history_raw.data)
                                                current = {}
                                                for role,kind in (('discovery','activity'),('occupancy','insertion')):
                                                    raw = reads[0][role+'_response'].data
                                                    current[role+'_response'] = native_fixture.read_owned(private_context,writer_token,spreadsheet_token,
                                                        binding,credential,kind,json.loads(raw),raw_body=raw,sheet=sheet)
                                                bundle['business_reads'] = tuple({'operation_id':reading['operation_id'],**current,
                                                    'row_response':None if reading['row_response'] is None else native_fixture.read_owned(
                                                        private_context,writer_token,spreadsheet_token,binding,credential,'row',
                                                        json.loads(reading['row_response'].data),raw_body=reading['row_response'].data,sheet=sheet,row=3)}
                                                    for reading in reads)
                                            return bundle
                                        def record_owned(bundle):
                                            counting = (global_journal.record_continuous_owned_attempt_intent if owned_continuity_probe
                                                        else global_journal.record_owned_receipted_attempt_intent)
                                            return counting(
                                                spreadsheet_token,binding,unit,qualified_source=qualified,store=self.store,
                                                writer_token=writer_token,settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                whitelist_path=self.template,**bundle)
                                        original_bundle = fresh_bundle()
                                        for name in original_bundle:
                                            if name == 'business_reads': continue  # completions inside tuple are checked below
                                            with self.subTest(copied_read=name),self.assertRaises(global_journal.GlobalAttemptHold):
                                                record_owned({**original_bundle,name:replace(original_bundle[name])})
                                            self.assertEqual(0,global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count)
                                        if owned_continuity_probe:
                                            with self.assertRaises(global_journal.GlobalAttemptHold):
                                                record_owned({**original_bundle,'business_reads':original_bundle['business_reads'][1:]})
                                            changed = [dict(item) for item in original_bundle['business_reads']]
                                            changed[0]['discovery_response'] = replace(changed[0]['discovery_response'])
                                            with self.assertRaises(global_journal.GlobalAttemptHold):
                                                record_owned({**original_bundle,'business_reads':tuple(changed)})
                                            self.assertEqual(0,global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count)
                                    if retry_launch_probe is not None:
                                        from types import SimpleNamespace
                                        from monitor import issue_tracker_admission as admission
                                        from monitor import issue_tracker_local_commit as local
                                        from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests, load as load_mutation
                                        from tools.project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES
                                        import socket
                                        native_mutation=Req7MutationLauncherWorkflowTests()
                                        native_mutation.root=global_root
                                        native_mutation.path=global_root/'etc/ssl/certs/ca-certificates.crt'
                                        native_mutation.path.parent.mkdir(parents=True,exist_ok=True)
                                        native_mutation.addCleanup=self.addCleanup
                                        mutation=load_mutation(); original_wire=unit.wire_bytes; all_requests=[]; rejected=[]
                                        response_bytes=b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
                                        expected_requests = 2 if retry_launch_probe in ('normal', 'old-cycle') else 1
                                        for count in (1,2):
                                            scope=global_journal._hold_continuous_owned_attempt_wire if count==1 else global_journal._hold_shared_retry_owned_attempt_wire
                                            with native_mutation.server(response_bytes,hostname='sheets.googleapis.com',
                                                    destination='sheets.googleapis.com') as (requests,errors), ExitStack() as transport:
                                                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                                                # Prepare the endpoint before issuing real
                                                # bounded reads; keep their original deadline.
                                                bundle=fresh_bundle()
                                                options=dict(qualified_source=qualified,store=self.store,writer_token=writer_token,
                                                    settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                    expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                    whitelist_path=self.template,**bundle)
                                                if count==2:
                                                    prior=admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)
                                                    now=prior['monotonic_ns']+MIN_CONTINUOUS_INTERVAL_MINUTES*60*1_000_000_000
                                                    options.update(boot_id=prior['boot_id'],monotonic_ns=now)
                                                    # Fixture clock supplies the admitted interval; production
                                                    # still derives and validates the original shared floor.
                                                    transport.enter_context(mock.patch.object(admission,'time',SimpleNamespace(monotonic_ns=lambda:now)))
                                                calls=[]; children=[]
                                                def exercise():
                                                    nonlocal calls,children
                                                    with scope(spreadsheet_token,binding,unit,**options) as image:
                                                        self.assertEqual(count,image.attempt_count)
                                                        self.assertEqual(original_wire,os.pread(image.fd,len(original_wire)+1,0))
                                                        calls,children=native_mutation.intercept(transport,local,owner_module,
                                                            writer_token,spreadsheet_token,binding,image,port)
                                                        if count==2 and retry_launch_probe=='receipt-rebind':
                                                            path=generation_path/'RECEIPT'; raw=path.read_bytes(); inode=path.stat().st_ino
                                                            path.rename(project/'owned-retry-prelaunch-receipt'); path.write_bytes(raw); path.chmod(0o600)
                                                            self.assertNotEqual(inode,path.stat().st_ino)
                                                        if count==2 and retry_launch_probe=='read-expiry':
                                                            clock=fixed_reads._monotonic
                                                            transport.enter_context(mock.patch.object(fixed_reads,'_monotonic',side_effect=lambda:clock()+31))
                                                        if count==1 or retry_launch_probe in ('normal', 'old-cycle'):
                                                            result=mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                            self.assertEqual((count,401,'UNKNOWN'),(result.attempt_count,result.status,result.outcome))
                                                            self.assertTrue(result.termination_confirmed)
                                                            self.assertEqual(1,len(calls)); self.assertEqual(1,len(children))
                                                            with self.assertRaises(mutation.MutationLauncherHold):
                                                                mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                            self.assertEqual(1,len(calls))
                                                        else:
                                                            with self.assertRaises(mutation.MutationLauncherHold):
                                                                mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                            self.assertEqual([],calls); self.assertEqual([],children); rejected.append(True)
                                                if count==1 or retry_launch_probe in ('normal', 'old-cycle'): exercise()
                                                else:
                                                    with self.assertRaises(global_journal.GlobalAttemptHold): exercise()
                                                    self.assertEqual([True],rejected)
                                            self.assertEqual([],errors)
                                            self.assertEqual(1 if count==1 or retry_launch_probe in ('normal', 'old-cycle') else 0,len(requests))
                                            if requests: self.assertEqual(original_wire,requests[0][2])
                                            all_requests.extend(requests)
                                            if count == 1 and retry_launch_probe == 'old-cycle':
                                                from monitor.collection_ib_producer import produce_worker_ib_analysis
                                                from tools.project_contract import build_collection_cycle_identity
                                                from test_cases.test_collection_cycle_persistence import TOKEN_2
                                                old_cycles = read_completed_cycle_evidence(self.store)
                                                self.assertEqual(1, len(old_cycles))
                                                identity_new = build_collection_cycle_identity(str(self.project), 'prod', 2, TOKEN_2)
                                                ib_new = produce_worker_ib_analysis(identity_new, project_root=self.project,
                                                    http_root=self.root,
                                                    clock=lambda: dt.datetime(2026,9,26,4,31,tzinfo=dt.timezone.utc),
                                                    runner=lambda _argv: self.fail('no external collection transport'))
                                                latest, _ = self._cycle(activity=True, derivation=True, ib_analysis=ib_new,
                                                    observed_peer='newer-not-original-peer', additional_eth_activity=True,
                                                    fabric_templates={'ethernet/prod':'tan-leaf', 'nvlink/prod':'border-leaf'})
                                                self.assertEqual(identity_new['cycle_id'], latest['cycle_id'])
                                                self.assertNotEqual(qualified.cycle_ids[-1], latest['cycle_id'])
                                                self.assertEqual(original_wire, unit.wire_bytes)
                                                self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                                self.assertEqual((1, 'UNKNOWN'),
                                                    (global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count,
                                                     global_journal.inspect_global_unit(spreadsheet_token,binding,unit).outcome))
                                        self.assertEqual(expected_requests,len(all_requests))
                                        retained=global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                        self.assertEqual((2,'UNKNOWN'),(retained.attempt_count,retained.outcome))
                                        self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                        self.assertEqual(quota,quota_module.inspect_metadata_reservation(spreadsheet_token,binding,identity,unit))
                                        state_path=state/(hashlib.sha256(binding.spreadsheet_id.encode('ascii')).hexdigest()+'.journal')
                                        self.assertFalse((state_path/'ATTEMPT-3').exists())
                                        shared=admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)
                                        self.assertEqual('retry',shared['lane'])
                                        return
                                    if continuous_launch_probe is not None:
                                        from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests, load as load_mutation
                                        from monitor import issue_tracker_local_commit as local
                                        native_mutation=Req7MutationLauncherWorkflowTests()
                                        native_mutation.root=global_root
                                        native_mutation.path=global_root/'etc/ssl/certs/ca-certificates.crt'
                                        native_mutation.path.parent.mkdir(parents=True,exist_ok=True)
                                        native_mutation.addCleanup=self.addCleanup
                                        mutation=load_mutation(); rejected=[]; calls=[]; children=[]
                                        import socket
                                        wire_response=b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
                                        with native_mutation.server(wire_response,hostname='sheets.googleapis.com',
                                                destination='sheets.googleapis.com') as (requests,errors), ExitStack() as transport:
                                            port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                                            bundle=fresh_bundle()
                                            def exercise():
                                                with global_journal._hold_continuous_owned_attempt_wire(
                                                        spreadsheet_token,binding,unit,qualified_source=qualified,store=self.store,
                                                        writer_token=writer_token,settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                        expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                        whitelist_path=self.template,**bundle) as image:
                                                    nonlocal calls,children
                                                    self.assertEqual(1,image.attempt_count)
                                                    calls,children=native_mutation.intercept(transport,local,owner_module,
                                                        writer_token,spreadsheet_token,binding,image,port)
                                                    if continuous_launch_probe=='receipt-rebind':
                                                        original=generation_path/'RECEIPT'; raw=original.read_bytes(); inode=original.stat().st_ino
                                                        original.rename(project/'owned-prelaunch-c6-receipt')
                                                        original.write_bytes(raw); original.chmod(0o600)
                                                        self.assertNotEqual(inode,original.stat().st_ino)
                                                        self.assertEqual(raw,original.read_bytes())
                                                    if continuous_launch_probe=='normal':
                                                        result=mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                        self.assertEqual((1,401,'UNKNOWN'),(result.attempt_count,result.status,result.outcome))
                                                        self.assertTrue(result.termination_confirmed)
                                                        self.assertEqual(1,len(calls)); self.assertEqual(1,len(children))
                                                    else:
                                                        with ExitStack() as fault:
                                                            if continuous_launch_probe=='read-expiry':
                                                                original_clock=fixed_reads._monotonic
                                                                transport.enter_context(mock.patch.object(fixed_reads,'_monotonic',
                                                                    side_effect=lambda:original_clock()+31))
                                                            with self.assertRaises(mutation.MutationLauncherHold) as caught:
                                                                mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                            self.assertFalse(caught.exception.termination_confirmed)
                                                            self.assertEqual([],calls); self.assertEqual([],children)
                                                            rejected.append(True)
                                            if continuous_launch_probe=='normal': exercise()
                                            else:
                                                with self.assertRaises(global_journal.GlobalAttemptHold): exercise()
                                                self.assertEqual([True],rejected)
                                            retained=global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                            self.assertEqual((1,'UNKNOWN'),(retained.attempt_count,retained.outcome))
                                            self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                            self.assertEqual(quota,quota_module.inspect_metadata_reservation(spreadsheet_token,binding,identity,unit))
                                            self.assertFalse((state/(hashlib.sha256(binding.spreadsheet_id.encode('ascii')).hexdigest()+'.journal')/'ATTEMPT-2').exists())
                                        self.assertEqual([],errors)
                                        self.assertEqual(1 if continuous_launch_probe=='normal' else 0,len(requests))
                                        if requests: self.assertEqual(unit.wire_bytes,requests[0][2])
                                        return
                                    if shared_retry_probe:
                                        from types import SimpleNamespace
                                        from monitor import issue_tracker_admission as admission
                                        from monitor.issue_tracker_receipt_snapshot import read_current_cycle_local_receipts
                                        from tools.project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES
                                        self.assertEqual(1,record_owned(fresh_bundle()).attempt_count)
                                        prior=admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)
                                        now=prior['monotonic_ns']+MIN_CONTINUOUS_INTERVAL_MINUTES*60*1_000_000_000
                                        original_receipts=read_current_cycle_local_receipts(writer_token,self.store,
                                            expected_template_sha256=self.snapshot.workbook_sha256,settings=args['settings'],
                                            whitelist_sha256=self.snapshot.whitelist.sha256,qualified_source=qualified)
                                        bundle=fresh_bundle()
                                        if allocation_retry_identity_probe or quota_retry_identity_probe:
                                            original_observe=global_journal._observe
                                            quota_path=state/(hashlib.sha256(binding.spreadsheet_id.encode('ascii')).hexdigest()+'.metadata')
                                            quota_image={p.name:p.read_bytes() for p in quota_path.iterdir()}
                                            fault_path=quota_path/'HEADER' if quota_retry_identity_probe else assignments_path
                                            raw=fault_path.read_bytes(); inode=fault_path.stat().st_ino
                                            preserved=(project/'owned-original-retry-quota-header' if quota_retry_identity_probe
                                                else allocation_path.parent/'owned-original-retry-assignments')
                                            injected=[]
                                            def replace_after_retry(*values,**options):
                                                result=original_observe(*values,**options)
                                                if values[3]:
                                                    fault_path.rename(preserved)
                                                    fault_path.write_bytes(raw); fault_path.chmod(0o600)
                                                    injected.append(result.attempt_count)
                                                return result
                                            with mock.patch.object(admission,'time',SimpleNamespace(monotonic_ns=lambda:now)), \
                                                    mock.patch.object(global_journal,'_observe',side_effect=replace_after_retry):
                                                with self.assertRaises(global_journal.GlobalAttemptHold):
                                                    global_journal.record_shared_retry_continuous_owned_attempt_intent(
                                                        spreadsheet_token,binding,unit,qualified_source=qualified,store=self.store,
                                                        writer_token=writer_token,settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                        expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                        whitelist_path=self.template,boot_id=prior['boot_id'],monotonic_ns=now,**bundle)
                                            self.assertEqual([2],injected)
                                            self.assertNotEqual(inode,fault_path.stat().st_ino)
                                            self.assertEqual(raw,preserved.read_bytes()); self.assertEqual(raw,fault_path.read_bytes())
                                            intent=global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                            self.assertEqual((2,'UNKNOWN'),(intent.attempt_count,intent.outcome))
                                            self.assertEqual(allocation_image,{p.name:p.read_bytes() for p in allocation_path.iterdir()})
                                            self.assertEqual(quota_image,{p.name:p.read_bytes() for p in quota_path.iterdir()})
                                            self.assertTrue(list((project/'.tracker/settings/outbox').iterdir()))
                                            admissions=project/'.tracker/admissions'
                                            self.assertTrue(list(admissions.glob('retry-*-intent.json')))
                                            self.assertEqual([],list(admissions.glob('retry-*-count.json')))
                                            retained={p.name:p.read_bytes() for p in admissions.iterdir()}
                                            with self.assertRaises(admission.AdmissionHold):
                                                admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)
                                            self.assertEqual(retained,{p.name:p.read_bytes() for p in admissions.iterdir()})
                                            self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                            return
                                        from monitor import issue_tracker_history_preread_journal as continuity_module
                                        from monitor import issue_tracker_remote_history_match as gates_module
                                        phases=[]
                                        def traced(phase, original):
                                            def call(*values, **options):
                                                observed_phase=(phase+('_write' if values[3] else '_read')
                                                    if phase=='_observe' else phase)
                                                phases.append((observed_phase,'begin'))
                                                try: result=original(*values, **options)
                                                except Exception as exc:
                                                    frames=[]; trace=exc.__traceback__
                                                    while trace is not None:
                                                        frames.append((Path(trace.tb_frame.f_code.co_filename).name,
                                                            trace.tb_lineno,trace.tb_frame.f_code.co_name))
                                                        trace=trace.tb_next
                                                    print('SHARED_RETRY_PHASE_ERROR',observed_phase,type(exc).__name__,frames,flush=True)
                                                    raise
                                                phases.append((observed_phase,'complete'))
                                                return result
                                            return call
                                        with ExitStack() as diagnostics:
                                            diagnostics.enter_context(mock.patch.object(admission,'time',SimpleNamespace(monotonic_ns=lambda:now)))
                                            for module,name in ((global_journal,'_receipted_original_facts'),
                                                    (global_journal,'_observe'),
                                                    (continuity_module,'observe_owned_business_continuity'),
                                                    (gates_module,'observe_owned_unit_read_gates')):
                                                diagnostics.enter_context(mock.patch.object(module,name,
                                                    side_effect=traced(name,getattr(module,name))))
                                            result=global_journal.record_shared_retry_continuous_owned_attempt_intent(
                                                spreadsheet_token,binding,unit,qualified_source=qualified,store=self.store,
                                                writer_token=writer_token,settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                whitelist_path=self.template,boot_id=prior['boot_id'],monotonic_ns=now,**bundle)
                                        self.assertEqual(2,sum(phase==('_receipted_original_facts','complete') for phase in phases))
                                        self.assertEqual(1,sum(phase==('_observe_write','complete') for phase in phases))
                                        self.assertEqual((2,'UNKNOWN'),(result.attempt_count,result.outcome))
                                        self.assertEqual('retry',admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)['lane'])
                                        self.assertEqual(original_receipts,read_current_cycle_local_receipts(writer_token,self.store,
                                            expected_template_sha256=self.snapshot.workbook_sha256,settings=args['settings'],
                                            whitelist_sha256=self.snapshot.whitelist.sha256,qualified_source=qualified))
                                        self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                        return  # this new scenario asserts one complete protected ETH retry, not the fault loop below
                                    for count in range(1, 7):
                                        allocation_fault = settings_audit_probe and sheet == 'ETH Cabling' and count == 6
                                        if (receipt_admission_rebind_probe or quota_namespace_rebind_probe) and count==1:
                                            target=(state/(hashlib.sha256(binding.spreadsheet_id.encode('ascii')).hexdigest()+'.metadata')/'HEADER'
                                                if quota_namespace_rebind_probe else
                                                project/'.tracker/admissions/admission-00000000000000000001.json')
                                            raw=target.read_bytes(); inode=target.stat().st_ino
                                            preserved=project/('owned-original-quota-header' if quota_namespace_rebind_probe else 'owned-original-c6-admission'); injected=[]
                                            original_observe=global_journal._observe
                                            def replace_after_count(*values,**options):
                                                result=original_observe(*values,**options)
                                                if values[3]:
                                                    target.rename(preserved); target.write_bytes(raw); target.chmod(0o600)
                                                    injected.append(result.attempt_count)
                                                return result
                                            with mock.patch.object(global_journal,'_observe',side_effect=replace_after_count):
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual([1],injected)
                                            self.assertNotEqual(inode,target.stat().st_ino)
                                            self.assertEqual(raw,target.read_bytes()); self.assertEqual(raw,preserved.read_bytes())
                                            intent=global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                            self.assertEqual((1,'UNKNOWN'),(intent.attempt_count,intent.outcome))
                                            self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                            self.assertEqual(seen,preread.inspect_business_preread(spreadsheet_token,binding,identity,unit))
                                            self.assertEqual(quota,quota_module.inspect_metadata_reservation(spreadsheet_token,binding,identity,unit))
                                            self.assertTrue(list((project/'.tracker/settings/outbox').iterdir()))
                                            return  # this independent fault keeps its retained originals; no fixture repair/retry
                                        elif allocation_original_identity_probe and sheet == 'ETH Cabling' and count == 1:
                                            original_observe = global_journal._observe
                                            original_bytes = assignments_path.read_bytes()
                                            original_inode = assignments_path.stat().st_ino
                                            preserved = allocation_path.parent/'owned-original-assignments'
                                            replaced = allocation_path.parent/'owned-replaced-assignments'
                                            injected = []
                                            def replace_after_count(*observe_args, **observe_kwargs):
                                                result = original_observe(*observe_args, **observe_kwargs)
                                                if observe_args[3]:
                                                    assignments_path.rename(preserved)
                                                    assignments_path.write_bytes(original_bytes)
                                                    assignments_path.chmod(0o600)
                                                    injected.append(result.attempt_count)
                                                return result
                                            try:
                                                with mock.patch.object(global_journal, '_observe', side_effect=replace_after_count):
                                                    with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual([1], injected)
                                                self.assertNotEqual(original_inode, assignments_path.stat().st_ino)
                                                self.assertEqual(original_bytes, assignments_path.read_bytes())
                                                self.assertEqual(original_bytes, preserved.read_bytes())
                                                intent = global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
                                                self.assertEqual((1, 'UNKNOWN'), (intent.attempt_count, intent.outcome))
                                                self.assertEqual(allocation_image, {p.name: p.read_bytes() for p in allocation_path.iterdir()})
                                                self.assertTrue(list((project/'.tracker/settings/outbox').iterdir()))
                                            finally:
                                                if preserved.exists():
                                                    assignments_path.rename(replaced)
                                                    preserved.rename(assignments_path)  # owned fixture only; no production repair
                                        elif owned_read_gates_probe and count == 6:
                                            bundle = fresh_bundle(); expired = [False]
                                            original_counter = global_journal.record_receipted_original_attempt_intent
                                            def finish_after_read_deadline(*counter_args,**counter_kwargs):
                                                result = original_counter(*counter_args,**counter_kwargs)
                                                expired[0] = True; return result
                                            with mock.patch.object(global_journal,'record_receipted_original_attempt_intent',side_effect=finish_after_read_deadline), \
                                                    mock.patch.object(fixed_reads,'_monotonic',side_effect=lambda:time.monotonic()+(31 if expired[0] else 0)):
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record_owned(bundle)
                                            intent = global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                        elif receipted_intent_probe and (count in (2, 3, 4, 5) or allocation_fault):
                                            original_observe = global_journal._observe
                                            fault_path = assignments_path if allocation_fault else {2: private_allowlist, 3: generation_path/'RECEIPT',
                                                4: source_path, 5: project/'01-global.yaml'}[count]
                                            original_bytes = fault_path.read_bytes()
                                            def change_after_count(*observe_args, **observe_kwargs):
                                                result = original_observe(*observe_args, **observe_kwargs)
                                                if observe_args[3]: fault_path.write_bytes(b'changed after durable count')
                                                return result
                                            try:
                                                with mock.patch.object(global_journal, '_observe', side_effect=change_after_count):
                                                    with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                intent = global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
                                                self.assertEqual(b'changed after durable count', fault_path.read_bytes())
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual(count, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            finally: fault_path.write_bytes(original_bytes)  # fault fixture only, no production recovery
                                        else: intent = record_owned(fresh_bundle()) if owned_read_gates_probe else record()
                                        self.assertEqual((count, 'UNKNOWN'), (intent.attempt_count, intent.outcome))
                                        self.assertFalse(hasattr(intent, 'permit')); self.assertFalse(hasattr(intent, 'complete'))
                                        self.assertEqual(seen, preread.inspect_business_preread(spreadsheet_token, binding, identity, unit))
                                        self.assertEqual(quota, quota_module.inspect_metadata_reservation(spreadsheet_token, binding, identity, unit))
                                    with self.assertRaises(global_journal.GlobalAttemptHold):
                                        record()
                                    if receipted_intent_probe:
                                        self.assertEqual(c6_original, {name: (generation_path/name).read_bytes() for name in c6_original})
                                    if settings_audit_probe and sheet == 'ETH Cabling':
                                        self.assertEqual(allocation_image, {p.name: p.read_bytes() for p in allocation_path.iterdir()})
                                        self.assertTrue(list((project/'.tracker/settings/outbox').iterdir()))
                                else:
                                    global_journal.record_global_attempt_intent(spreadsheet_token, binding, unit)
                                self.assertEqual(seen, preread.inspect_business_preread(spreadsheet_token, binding, identity, unit))
                                with self.assertRaises(preread.HistoryPrereadHold):
                                    preread.prepare_business_preread(spreadsheet_token, binding, identity, unit, manifest=body, business_reads=tuple(reads))
                                self.assertEqual(retained, {path.name: path.read_bytes() for path in (state/(stem+'.business')).iterdir()})
                                self.assertEqual(before, {path.name: path.read_bytes() for path in (state/(stem+'.nv')).iterdir()})
                                continue
                            blocked = state/(stem+'.journal'); blocked.mkdir(mode=0o700)
                            with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            self.assertEqual([], list(blocked.iterdir()))
                            self.assertEqual(before, {path.name: path.read_bytes() for path in (state/(stem+'.nv')).iterdir()})
                self.assertEqual(original_template, self.template.read_bytes())
                self.assertFalse((project/'.tracker/remote-actions').exists()); self.assertFalse((project/'.tracker/remote-attempts').exists())
                return
            if observed_switch_insert_probe:
                import tempfile
                import monitor.issue_tracker_send_unit as compiler
                from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read, prepare_insertion_sheet_read, prepare_sheets_read, prepare_history_tail_read, prepare_template_identity_read
                from monitor.issue_tracker_sheets_read_decode import decode_template_identity
                from monitor.issue_tracker_online_target import OnlineTargetBinding
                from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                from test_cases.test_req7_activity_discovery import sheet_document, insertion_document, exact_row_document, reserved_switch_row, literal
                from test_cases.test_req7_sheets_read_decode import response, identity_response
                from test_cases.test_req7_spreadsheet_owner import load as load_owner, scoped_fixture
                from test_cases.test_req7_enrollment_journal import load as load_enrollment
                self.assertTrue(hasattr(compiler,'freeze_observed_receipted_switch_unit'),'original receipt, owner and enrollment must derive Switch inserts')
                binding = OnlineTargetBinding('synthetic_spreadsheet_id_0001','a'*64,'b'*64)
                credential = AuthenticatedToken('synthetic.private-token',time.time()+3600)
                identity = decode_template_identity(prepare_template_identity_read(binding,credential),response(identity_response()))
                candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == 'switch')
                self.assertGreater(len(candidates),1)
                rows = [reserved_switch_row(index) for index in range(2,len(candidates)+5)]
                rows[0]['M'] = {'boolValue':False}
                key = candidates[0].activity_key
                rows[1].update({'F':literal(key[1]),'L':literal('[MONITOR][%s][%s] old evidence'%key[2:]),'N':literal('New')})
                source = sheet_document('ETH&IB Switch',rows,len(rows)+2); source['sheets'][0]['properties']['sheetId'] = 101
                occupancy = insertion_document('ETH&IB Switch',rows,len(rows)+2); occupancy['sheets'][0]['properties']['sheetId'] = 101
                discovery_plan = prepare_activity_sheet_read(binding,credential,sheet='ETH&IB Switch')
                occupancy_plan = prepare_insertion_sheet_read(binding,credential,sheet='ETH&IB Switch')
                reads = []
                for offset,candidate in enumerate(candidates):
                    index = offset+3
                    exact = exact_row_document('ETH&IB Switch',rows[index-2],index); exact['sheets'][0]['properties']['sheetId'] = 101
                    reads.append({'operation_id':candidate.operation_id,'discovery_plan':discovery_plan,'discovery_response':response(source),
                        'occupancy_plan':occupancy_plan,'occupancy_response':response(occupancy),
                        'row_plan':prepare_sheets_read(binding,credential,mode='row_rectangle',sheet='ETH&IB Switch',first_row=index+1),
                        'row_response':response(exact)})
                history_plan = prepare_history_tail_read(binding,credential)
                history_response = response({'spreadsheetId':binding.spreadsheet_id,'sheets':[{'properties':{'sheetId':105,'title':'Update_History',
                    'sheetType':'GRID','gridProperties':{'rowCount':100,'columnCount':5}},'data':[{'startRow':2,'startColumn':0}]}]})
                with tempfile.TemporaryDirectory(prefix='req7-real-switch-insert-') as directory:
                    global_root = Path(directory).resolve(); state = global_root/'var/lib/http-ztp-container/issue-tracker'
                    state.mkdir(parents=True,mode=0o700); owner_module = load_owner(); enrollment_module = load_enrollment()
                    with tracker_writer(project,self.publication) as writer_token, scoped_fixture(global_root,owner_module), owner_module.spreadsheet_owner(binding) as spreadsheet_token:
                        original = enrollment_module.prepare_enrollment_journal(spreadsheet_token,binding,identity)
                        def compile_switch(**changes):
                            options = dict(local_generation_id=committed.receipt.generation_id,business_reads=tuple(reads),history_plan=history_plan,
                                history_response=history_response,spreadsheet_token=spreadsheet_token,binding=binding,identity=identity,audits=(),occupied_metadata_ids=())
                            options.update(changes)
                            return compiler.freeze_observed_receipted_switch_unit(qualified,self.store,metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256,writer_token=writer_token,**args,**options)
                        unit = compile_switch(); action = json.loads(unit.action_preimage)
                        self.assertEqual(committed.receipt.generation_id,action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256,action['identity']['publish_id'])
                        nonces = {title:nonce for title,sid,nonce in original.nonces}
                        self.assertEqual(nonces['ETH&IB Switch'],action['target_nonce']); self.assertEqual(nonces['Update_History'],action['history_nonce'])
                        self.assertEqual(['update']+['insert']*(len(candidates)-1),[item['action'] for item in action['business']])
                        updates = [item['updateCells'] for item in json.loads(unit.wire_bytes)['requests'] if 'updateCells' in item]
                        self.assertEqual(set(range(3,len(candidates)+3)),{item['start']['rowIndex'] for item in updates})
                        for item in updates:
                            self.assertEqual(101,item['start']['sheetId']); self.assertNotIn(item['start']['columnIndex'],(0,3,4,6,7,8,12,14,15,16,17,18,19,20))
                        for claim in ({'target_nonce':'c'*64},{'placements':()},{'sheet_id':101},{'preread_sha256':'e'*64},{'business_reads':tuple(reads[:-1])}):
                            with self.assertRaises(compiler.SendUnitHold): compile_switch(**claim)
                        with self.assertRaises(compiler.SendUnitHold): compile_switch(spreadsheet_token=object())
                        changed_identity = replace(identity,sheet_ids=tuple((title,150 if title=='ETH&IB Switch' else sid) for title,sid in identity.sheet_ids))
                        with self.assertRaises(compiler.SendUnitHold): compile_switch(identity=changed_identity)
                        saved = reads[1]['row_response']; drift = json.loads(saved.data)
                        drift['sheets'][0]['data'][0]['rowData'][0]['values'][12] = {'userEnteredValue':literal('operator drift')}
                        reads[1]['row_response'] = response(drift)
                        try:
                            with self.assertRaises(compiler.SendUnitHold): compile_switch()
                        finally: reads[1]['row_response'] = saved
                        real_freeze = compiler.freeze_receipted_prod_source_unit
                        def change_row_during_compilation(*freeze_args,**freeze_kwargs):
                            result = real_freeze(*freeze_args,**freeze_kwargs)
                            reads[1]['row_response'] = response(drift)
                            return result
                        try:
                            with mock.patch.object(compiler,'freeze_receipted_prod_source_unit',side_effect=change_row_during_compilation):
                                with self.assertRaises(compiler.SendUnitHold): compile_switch()
                        finally: reads[1]['row_response'] = saved
                        stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                        blocked = state/(stem+'.journal'); blocked.mkdir(mode=0o700)
                        with self.assertRaises(compiler.SendUnitHold): compile_switch()
                        self.assertEqual([],list(blocked.iterdir()))
                        self.assertEqual({stem+'.lock',stem+'.enrollment',stem+'.journal'},{path.name for path in state.iterdir()})
                self.assertEqual(original_template,self.template.read_bytes())
                self.assertFalse((project/'.tracker/remote-actions').exists()); self.assertFalse((project/'.tracker/remote-attempts').exists())
                return
            if observed_source_probe:
                import monitor.issue_tracker_send_unit as compiler
                from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read, prepare_sheets_read, prepare_history_tail_read
                from monitor.issue_tracker_online_target import OnlineTargetBinding
                from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                from test_cases.test_req7_activity_discovery import sheet_document, exact_row_document, switch_row, cabling_row, literal
                from test_cases.test_req7_sheets_read_decode import response
                self.assertTrue(hasattr(compiler, 'freeze_observed_receipted_source_updates'), 'protected receipt/source must derive rows from original read images')
                binding = OnlineTargetBinding('synthetic_spreadsheet_id_0001', 'a' * 64, 'b' * 64)
                credential = AuthenticatedToken('synthetic.private-token', time.time() + 3600)
                history_plan = prepare_history_tail_read(binding, credential)
                history_raw = response({'spreadsheetId': binding.spreadsheet_id, 'sheets': [{
                    'properties': {'sheetId': 105, 'title': 'Update_History', 'sheetType': 'GRID',
                        'gridProperties': {'rowCount': 100, 'columnCount': 5}},
                    'data': [{'startRow': 2, 'startColumn': 0}]}]})
                before_generations_observed = tuple(sorted(generation_root.iterdir()))
                for sheet, family, sid in (('ETH&IB Switch', 'switch', 101), ('ETH Cabling', 'eth_cabling', 102), ('IB Cabling', 'ib_cabling', 103)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    rows = []
                    for index, candidate in enumerate(candidates):
                        key = candidate.activity_key
                        row = switch_row('NV%05d' % (43001 + index)) if family == 'switch' else cabling_row('NV%05d' % (43001 + index))
                        if family == 'switch':
                            row['F'] = literal(key[1]); row['L'] = literal('[MONITOR][%s][%s] old independent evidence' % key[2:])
                        else:
                            for column, value in zip(('K', 'L', 'F'), key[1:]): row[column] = literal(value)
                        rows.append(row)
                    source = sheet_document(sheet, rows, row_count=len(rows) + 4)
                    source['sheets'][0]['properties']['sheetId'] = sid
                    discovery_plan = prepare_activity_sheet_read(binding, credential, sheet=sheet)
                    raw_discovery = response(source)
                    reads = []
                    for index, candidate in enumerate(candidates):
                        exact = exact_row_document(sheet, rows[index], index + 2)
                        exact['sheets'][0]['properties']['sheetId'] = sid
                        reads.append({'operation_id': candidate.operation_id, 'discovery_plan': discovery_plan,
                            'discovery_response': raw_discovery, 'row_plan': prepare_sheets_read(binding, credential,
                                mode='row_rectangle', sheet=sheet, first_row=index + 3), 'row_response': response(exact)})
                    options = dict(local_generation_id=committed.receipt.generation_id, spreadsheet_id=binding.spreadsheet_id,
                        sheet=sheet, sheet_id=sid, history_sheet_id=105, target_nonce='c' * 64, history_nonce='d' * 64,
                        audits=(), occupied_metadata_ids=())
                    with tracker_writer(project, self.publication) as token:
                        def compile_observed(**changes):
                            return compiler.freeze_observed_receipted_source_updates(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, writer_token=token, **args,
                                **{**options, 'business_reads': tuple(reads), 'history_plan': history_plan, 'history_response': history_raw, **changes})
                        unit = compile_observed()
                        action = json.loads(unit.action_preimage)
                        self.assertEqual(committed.receipt.generation_id, action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256, action['identity']['publish_id'])
                        self.assertNotEqual('e' * 64, action['preread_sha256'])
                        requests = json.loads(unit.wire_bytes)['requests']
                        updates = [item['updateCells'] for item in requests if 'updateCells' in item]
                        self.assertEqual(set(range(2, len(rows) + 2)), {item['start']['rowIndex'] for item in updates})
                        for item in updates:
                            self.assertEqual(sid, item['start']['sheetId'])
                            self.assertEqual('userEnteredValue', item['fields'])
                            self.assertNotEqual(0, item['start']['columnIndex'])
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(preread_sha256='e' * 64)
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(placements=())
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(business_reads=tuple(reads[:-1]))
                        foreign_history = json.loads(history_raw.data)
                        foreign_history['spreadsheetId'] = 'foreign_spreadsheet_id_0002'
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(history_response=response(foreign_history))
                        full_history = json.loads(history_raw.data)
                        full_history['sheets'][0]['properties']['gridProperties']['rowCount'] = 3
                        full_history['sheets'][0]['data'][0]['rowData'] = [{'values': [{'userEnteredValue': literal('occupied original tail')}]}]
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(history_response=response(full_history))
                        original_row = reads[0]['row_response']
                        drift = json.loads(original_row.data)
                        drift['sheets'][0]['data'][0]['rowData'][0]['values'][0] = {'userEnteredValue': literal('NV99999')}
                        reads[0]['row_response'] = response(drift)
                        try:
                            with self.assertRaises(compiler.SendUnitHold): compile_observed()
                        finally: reads[0]['row_response'] = original_row
                        def change_row_during_freeze(*freeze_args, **freeze_kwargs):
                            result = real_freeze(*freeze_args, **freeze_kwargs)
                            reads[0]['row_response'] = response(drift)
                            return result
                        real_freeze = compiler.freeze_receipted_prod_source_unit
                        try:
                            with mock.patch.object(compiler, 'freeze_receipted_prod_source_unit', side_effect=change_row_during_freeze):
                                with self.assertRaises(compiler.SendUnitHold): compile_observed()
                        finally: reads[0]['row_response'] = original_row
                self.assertEqual(before_generations_observed, tuple(sorted(generation_root.iterdir())))
                self.assertEqual(original_template, self.template.read_bytes())
                self.assertFalse((project / '.tracker/remote-actions').exists())
                self.assertFalse((project / '.tracker/remote-attempts').exists())
                return
            if receipted_source_probe:
                import monitor.issue_tracker_send_unit as compiler
                generation_id = committed.receipt.generation_id
                original_publications = tuple(sorted(self.publication.iterdir()))
                original_generations = tuple(sorted(generation_root.iterdir()))
                receipt_path = generation_root / generation_id / 'RECEIPT'
                receipt_bytes = receipt_path.read_bytes()
                publication_path = self.publication / (generation_id + '.xlsx')
                published_bytes = publication_path.read_bytes()
                for sheet, family, sid in (('ETH&IB Switch', 'switch', 101), ('ETH Cabling', 'eth_cabling', 102),
                                           ('IB Cabling', 'ib_cabling', 103)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    self.assertTrue(candidates)
                    placements = tuple({'operation_id': item.operation_id, 'action': 'update' if family == 'switch' else 'insert',
                        'row_index': index + 2 if family == 'switch' else None, 'observed_values': {'L': {}} if family == 'switch' else None,
                        'reserved_id': None if family == 'switch' else 'NV%05d' % (42001 + index)}
                        for index, item in enumerate(candidates))
                    options = dict(local_generation_id=generation_id,
                        spreadsheet_id='synthetic_spreadsheet_id_0001', sheet=sheet, sheet_id=sid, history_sheet_id=105,
                        target_nonce='c' * 64, history_nonce='d' * 64, preread_sha256='e' * 64,
                        audits=(), occupied_metadata_ids=())
                    with tracker_writer(project, self.publication) as token:
                        def compile_unit(**changes):
                            return compiler.freeze_receipted_prod_source_unit(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=placements,
                                writer_token=token, **args, **{**options, **changes})
                        unit = compile_unit()
                        action = json.loads(unit.action_preimage)
                        self.assertEqual(generation_id, action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256, action['identity']['publish_id'])
                        self.assertEqual(committed.receipt.manifest_id, action['manifest_id'])
                        with self.assertRaises(compiler.SendUnitHold): compile_unit(publish_id='f' * 64)
                        with self.assertRaises(compiler.SendUnitHold):
                            compile_unit(local_generation_id='gen-00000000000000000002-' + '1' * 32)
                        if family == 'switch':
                            forged = json.loads(receipt_bytes); forged['sequence'] = True
                            receipt_path.write_bytes(json.dumps(forged).encode())
                            bad_receipt = receipt_path.read_bytes()
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertEqual(bad_receipt, receipt_path.read_bytes())
                            finally:
                                receipt_path.write_bytes(receipt_bytes)
                            admission_path = next((project / '.tracker/admissions').iterdir())
                            admission_bytes = admission_path.read_bytes()
                            try:
                                admission_path.write_bytes(b'{}\n')
                                with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertEqual(b'{}\n', admission_path.read_bytes())
                            finally:
                                admission_path.write_bytes(admission_bytes)
                            real_compile = compiler.freeze_prod_source_unit
                            def change_publication_after_freeze(*freeze_args, **freeze_options):
                                result = real_compile(*freeze_args, **freeze_options)
                                publication_path.write_bytes(b'changed after source unit freeze')
                                return result
                            try:
                                with mock.patch.object(compiler, 'freeze_prod_source_unit', side_effect=change_publication_after_freeze):
                                    with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertEqual(b'changed after source unit freeze', publication_path.read_bytes())
                            finally:
                                publication_path.write_bytes(published_bytes)
                            preserved_receipt = project / 'preserved-original-receipt'
                            def replace_receipt_inode_after_freeze(*freeze_args, **freeze_options):
                                result = real_compile(*freeze_args, **freeze_options)
                                receipt_path.rename(preserved_receipt)
                                receipt_path.write_bytes(receipt_bytes)
                                receipt_path.chmod(0o600)
                                return result
                            try:
                                with mock.patch.object(compiler, 'freeze_prod_source_unit', side_effect=replace_receipt_inode_after_freeze):
                                    with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertNotEqual(preserved_receipt.stat().st_ino, receipt_path.stat().st_ino)
                                self.assertEqual(receipt_bytes, receipt_path.read_bytes())
                            finally:
                                if preserved_receipt.exists():
                                    receipt_path.unlink()
                                    preserved_receipt.rename(receipt_path)
                self.assertEqual(original_publications, tuple(sorted(self.publication.iterdir())))
                self.assertEqual(original_generations, tuple(sorted(generation_root.iterdir())))
                self.assertEqual(original_template, self.template.read_bytes())
                self.assertEqual(receipt_bytes, receipt_path.read_bytes())
                self.assertEqual(published_bytes, publication_path.read_bytes())
                self.assertFalse((project / '.tracker/remote-actions').exists())
                self.assertFalse((project / '.tracker/remote-attempts').exists())
                return
            if require_first_manual_admission:
                self.assertTrue((project / ".tracker/admissions").is_dir())
                admission_files = tuple(sorted(
                    (project / ".tracker/admissions").iterdir()))
                self.assertEqual(1, len(admission_files))
                with tracker_writer(project, self.publication) as token:
                    shared = read_auto_local_admission(
                        token, self.store, self.snapshot.workbook_sha256)
                self.assertEqual(committed.receipt.generation_id,
                                 shared["generation_id"])
                self.assertEqual(committed.receipt.published_sha256,
                                 shared["published_sha256"])
                self.assertEqual("manual", shared["lane"])
                self.assertEqual(cycle["cycle_id"], shared["cycle_id"])
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(self.template.read_bytes())
                stage_status_path = (
                    self.root / "monitor/status/issue-tracker-stage-l.status.json"
                )
                before_second_cycle = tuple(sorted(generation_root.iterdir()))
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value=shared["boot_id"])):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                self.assertEqual(before_second_cycle,
                                 tuple(sorted(generation_root.iterdir())))
                self.assertEqual("not_due", json.loads(
                    stage_status_path.read_bytes())["local"])
                second_identity = build_collection_cycle_identity(
                    str(project), "prod", 2, TOKEN_2,
                )
                second_binding = produce_worker_ib_analysis(
                    second_identity, project_root=project, http_root=self.root,
                    clock=lambda: dt.datetime(2026, 9, 26, 4, 31,
                                              tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail(
                        "transport is supplied by fixture"),
                )
                second_cycle, _ = self._cycle(
                    activity=True, derivation=True,
                    observed_peer="changed-peer", ib_analysis=second_binding,
                    fabric_templates={"ethernet/prod": "tan-leaf",
                                      "nvlink/prod": "border-leaf"},
                )
                self.assertEqual(second_identity["cycle_id"],
                                 second_cycle["cycle_id"])
                later_ns = (shared["monotonic_ns"]
                            + MIN_CONTINUOUS_INTERVAL_MINUTES * 60
                            * 1_000_000_000 + 1)
                if manual_after_manual:
                    second_witness = (
                        shared["policy_sha256"],
                        shared["publish_every_cycles"],
                        shared["boot_id"], later_ns,
                    )
                    with mock.patch.object(WORKER.time, "monotonic_ns",
                                           return_value=later_ns):
                        second_result = commit_qualified_prod_local(
                            self.store, http_root=self.root, project=project,
                            publication=self.publication,
                            template_path=root_template,
                            manual_admission=second_witness,
                        )
                    self.assertIsInstance(second_result, CommittedProdWorkbook)
                    self.assertNotEqual(committed.receipt.generation_id,
                                        second_result.receipt.generation_id)
                    with tracker_writer(project, self.publication) as token:
                        latest = read_auto_local_admission(
                            token, self.store, self.snapshot.workbook_sha256)
                    self.assertEqual("manual", latest["lane"])
                    self.assertEqual(3, latest["publish_every_cycles"])
                    self.assertEqual(second_cycle["cycle_id"], latest["cycle_id"])
                    self.assertEqual(second_result.receipt.generation_id,
                                     latest["generation_id"])
                    self.assertEqual(2, len(tuple(
                        (project / ".tracker/admissions").iterdir())))
                    with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                          mock.patch.object(WORKER, "STATUS_DIR",
                                            stage_status_path.parent),
                          mock.patch.object(WORKER,
                                            "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                            stage_status_path),
                          mock.patch.object(WORKER, "_current_boot_identity",
                                            return_value=shared["boot_id"]),
                          mock.patch.object(WORKER.time, "monotonic_ns",
                                            return_value=later_ns)):
                        self.assertIsNone(
                            WORKER._publish_stage_l_local_after_completion(
                                self.store))
                    self.assertEqual("not_due", json.loads(
                        stage_status_path.read_bytes())["local"])
                    self.assertEqual(2, len(tuple(
                        (project / ".tracker/generations").iterdir())))
                    return
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value=shared["boot_id"]),
                      mock.patch.object(WORKER.time, "monotonic_ns",
                                        return_value=later_ns)):
                    second_result = WORKER._publish_stage_l_local_after_completion(
                        self.store)
                self.assertIsInstance(second_result, CommittedProdWorkbook)
                self.assertNotEqual(committed.receipt.generation_id,
                                    second_result.receipt.generation_id)
                with tracker_writer(project, self.publication) as token:
                    latest = read_auto_local_admission(
                        token, self.store, self.snapshot.workbook_sha256)
                self.assertEqual("automatic", latest["lane"])
                self.assertEqual(second_cycle["cycle_id"], latest["cycle_id"])
                self.assertEqual(second_result.receipt.generation_id,
                                 latest["generation_id"])
                self.assertEqual(2, len(tuple(
                    (project / ".tracker/admissions").iterdir())))
                return
            root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
            root_template.parent.mkdir(parents=True, exist_ok=True)
            root_template.write_bytes(self.template.read_bytes())
            before_runtime_entry = tuple(sorted(generation_root.iterdir()))
            runtime_noop = commit_qualified_prod_local(
                self.store, http_root=self.root, project=project,
                publication=self.publication, template_path=root_template,
                manual_admission=manual_witness,
            )
            self.assertIsInstance(runtime_noop, ProdWorkbookNoop)
            self.assertEqual("no_change", runtime_noop.status)
            self.assertEqual(before_runtime_entry,
                             tuple(sorted(generation_root.iterdir())))
            stage_status_path = self.root / "monitor/status/issue-tracker-stage-l.status.json"
            with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                  mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                  mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                    stage_status_path)):
                lane_result = WORKER._publish_stage_l_local_after_completion(self.store)
            if replayed_auto:
                self.assertIsNone(lane_result)
                self.assertEqual("hold", json.loads(stage_status_path.read_bytes())["state"])
                self.assertEqual(before_runtime_entry,
                                 tuple(sorted(generation_root.iterdir())))
                return
            # Direct C6 image replay remains a no-op above; an automatic lane
            # must not treat that prior manual RECEIPT as a new admission.
            self.assertIsNone(lane_result)
            self.assertEqual("hold", json.loads(stage_status_path.read_bytes())["state"])
            self.assertEqual(before_runtime_entry,
                             tuple(sorted(generation_root.iterdir())))
            try:
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("leaf-z",), reserved_switch_rows=4,
                ))
                skipped_snapshot = read_whitelist_workbook(self.template)
                skipped_args = {**args, "whitelist_snapshot": skipped_snapshot}
                eth_skipped = qualify_prod_stage_l(self.store, **skipped_args)
                self.assertEqual(protected_time, eth_skipped.recorded_at_utc)
                self.assertEqual(
                    (("eth_cabling", ("leaf-a", "swp1", "leaf-z", "swp2"),
                      "leaf-z"),),
                    tuple((skip.source, skip.endpoints, skip.matched_rule)
                          for skip in eth_skipped.whitelist_skips),
                )
                self.assertTrue(all(skip.activity_key is None
                                    and skip.record_id is None
                                    for skip in eth_skipped.whitelist_skips))
                eth_metadata = {
                    **metadata,
                    "template_sha256": skipped_snapshot.workbook_sha256,
                }
                eth_body, eth_digest = freeze_prod_stage_l_manifest(
                    eth_skipped, self.store, metadata=eth_metadata,
                    expected_template_sha256=skipped_snapshot.workbook_sha256,
                    **skipped_args,
                )
                self.assertEqual(hashlib.sha256(eth_body).hexdigest(), eth_digest)
                self.assertEqual([{
                    "source": "eth_cabling",
                    "endpoints": ["leaf-a", "swp1", "leaf-z", "swp2"],
                    "matched_rule": "leaf-z",
                }], json.loads(eth_body)["qualified_source"]["whitelist_skips"])
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("leaf-a",), reserved_switch_rows=4,
                ))
                switch_snapshot = read_whitelist_workbook(self.template)
                switch_args = {**args, "whitelist_snapshot": switch_snapshot}
                switch_skipped = qualify_prod_stage_l(self.store, **switch_args)
                self.assertEqual(protected_time, switch_skipped.recorded_at_utc)
                self.assertEqual({
                    ("switch", "switch:leaf-a", None, "leaf-a"),
                    ("eth_cabling", None,
                     ("leaf-a", "swp1", "leaf-z", "swp2"), "leaf-a"),
                }, {
                    (skip.source, skip.record_id, skip.endpoints,
                     skip.matched_rule)
                    for skip in switch_skipped.whitelist_skips
                })
                self.assertTrue(all(skip.activity_key is None
                                    for skip in switch_skipped.whitelist_skips))
                with self.assertRaises((StageLConsumerHold, ValueError)):
                    freeze_prod_stage_l_manifest(
                        eth_skipped, self.store, metadata=eth_metadata,
                        expected_template_sha256=skipped_snapshot.workbook_sha256,
                        **skipped_args,
                    )
                switch_metadata = {
                    **metadata,
                    "template_sha256": switch_snapshot.workbook_sha256,
                }
                switch_body, switch_digest = freeze_prod_stage_l_manifest(
                    switch_skipped, self.store, metadata=switch_metadata,
                    expected_template_sha256=switch_snapshot.workbook_sha256,
                    **switch_args,
                )
                self.assertEqual(hashlib.sha256(switch_body).hexdigest(),
                                 switch_digest)
                self.assertEqual({
                    ("eth_cabling", "leaf-a", None),
                    ("switch", "leaf-a", "switch:leaf-a"),
                }, {
                    (item["source"], item["matched_rule"],
                     item.get("record_id"))
                    for item in json.loads(switch_body)["qualified_source"]
                    ["whitelist_skips"]
                })
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("re:^leaf-a$",), reserved_switch_rows=4,
                ))
                regex_snapshot = read_whitelist_workbook(self.template)
                regex_args = {**args, "whitelist_snapshot": regex_snapshot}
                regex_skipped = qualify_prod_stage_l(self.store, **regex_args)
                self.assertEqual(
                    {(skip.source, skip.record_id, skip.endpoints)
                     for skip in switch_skipped.whitelist_skips},
                    {(skip.source, skip.record_id, skip.endpoints)
                     for skip in regex_skipped.whitelist_skips},
                )
                self.assertEqual({"re:^leaf-a$"},
                                 {skip.matched_rule for skip in
                                  regex_skipped.whitelist_skips})
                with self.assertRaises((StageLConsumerHold, ValueError)):
                    freeze_prod_stage_l_manifest(
                        switch_skipped, self.store, metadata=switch_metadata,
                        expected_template_sha256=switch_snapshot.workbook_sha256,
                        **switch_args,
                    )
            finally:
                self.template.write_bytes(original_template)
            self.template.write_bytes(fake_workbook(
                whitelist_rules=("leaf-z",), reserved_switch_rows=4,
            ))
            with self.assertRaises((StageLConsumerHold, ValueError)):
                freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    **args,
                )
            self.template.write_bytes(fake_workbook(reserved_switch_rows=4))
            latest = artifacts["ethernet/prod"]["info"]
            original = latest.read_bytes()
            latest.write_bytes(original + b"late byte drift")
            with self.assertRaises((StageLConsumerHold, ValueError)):
                freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    **args,
                )
            latest.write_bytes(original)
            with tracker_writer(project, self.publication) as token:
                set_k(token, new_k=2, actor="operator:fixture",
                      recorded_at="2026-09-25T00:02:00Z",
                      request_id="req7-three-panel-k2", expected_revision=1)
            with self.assertRaises((StageLConsumerHold, ValueError)):
                freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    **args,
                )

    def _verify_protected_skip_commit(self, project, args):
        from monitor.issue_tracker_publish_runtime import local_publish_interval
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, ProdWorkbookNoop,
            commit_prod_stage_l_workbook,
        )
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
        from monitor.issue_tracker_state_owner import tracker_writer

        self.template.write_bytes(fake_workbook(
            whitelist_rules=("leaf-a",), reserved_switch_rows=4,
        ))
        self.snapshot = read_whitelist_workbook(self.template)
        args = {**args, "whitelist_snapshot": self.snapshot}
        qualified = qualify_prod_stage_l(self.store, **args)
        self.assertEqual({"eth_cabling", "switch"},
                         {skip.source for skip in qualified.whitelist_skips})
        metadata = {
            "project_id": str(project), "schema_version": 1,
            "producer_version": "req7-test-producer",
            "template_contract_version": "v1",
            "template_sha256": self.snapshot.workbook_sha256,
        }
        body, manifest_id = freeze_prod_stage_l_manifest(
            qualified, self.store, metadata=metadata,
            expected_template_sha256=self.snapshot.workbook_sha256,
            **args,
        )
        self.assertEqual(hashlib.sha256(body).hexdigest(), manifest_id)
        interval, policy_sha = local_publish_interval(project)
        manual_witness = (policy_sha, interval, "fixture-boot",
                          time.monotonic_ns())
        with tracker_writer(project, self.publication) as token:
            committed = commit_prod_stage_l_workbook(
                token, qualified, self.store, template_path=self.template,
                metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                manual_admission=manual_witness,
                **args,
            )
        self.assertIsInstance(committed, CommittedProdWorkbook)
        self.assertEqual(manifest_id, committed.receipt.manifest_id)
        with zipfile.ZipFile(BytesIO(self.template.read_bytes())) as before, \
             zipfile.ZipFile(BytesIO(committed.prepared.xlsx_bytes)) as after:
            history = after.read("xl/worksheets/sheet6.xml")
            self.assertIn(b"Whitelist Skip", history)
            self.assertIn(manifest_id.encode("ascii"), history)
            self.assertIn(qualified.recorded_at_utc.encode("ascii"), history)
            self.assertIn(b"switch:leaf-a", history)
            self.assertIn(b"leaf-z", history)
            self.assertIn(b"matched_rule=leaf-a", history)
            self.assertEqual(before.read("xl/worksheets/sheet3.xml"),
                             after.read("xl/worksheets/sheet3.xml"))
            self.assertNotIn(b"leaf-a", after.read("xl/worksheets/sheet2.xml"))
        with tracker_writer(project, self.publication) as token:
            no_op = commit_prod_stage_l_workbook(
                token, qualified, self.store, template_path=self.template,
                metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                **args,
            )
        self.assertIsInstance(no_op, ProdWorkbookNoop)
        self.assertEqual("no_change", no_op.status)

    def _verify_two_cycle_latest_local_commit(self, project, args, cycle_ids):
        from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, commit_prod_stage_l_workbook,
        )
        from monitor.issue_tracker_publish_runtime import local_publish_interval
        from monitor.issue_tracker_state_owner import tracker_writer
        import xml.etree.ElementTree as ET

        qualified = qualify_prod_stage_l(self.store, **args)
        self.assertTrue(qualified.qualified)
        self.assertEqual(cycle_ids, qualified.cycle_ids)
        self.assertEqual(2, self.settings.k)
        self.assertEqual(4, len(qualified.candidates))
        by_key = {item.activity_key: item for item in qualified.candidates}
        self.assertEqual({
            ("eth_cabling", "leaf-a", "swp1", "Mis-wiring"),
            ("ib_cabling", "leaf01", "sw1p1", "Mis-wiring"),
            ("switch", "leaf-a", "fan", "PSU1/FAN1"),
            ("switch", "nvsw01", "asic_temp", "ASIC1"),
        }, set(by_key))
        eth = by_key[("eth_cabling", "leaf-a", "swp1", "Mis-wiring")]
        ib = by_key[("ib_cabling", "leaf01", "sw1p1", "Mis-wiring")]
        self.assertEqual(("leaf-a", "swp1", "leaf-z", "swp2"), eth.expected_endpoints)
        self.assertEqual(("changed-peer", "swp9", "leaf-a", "swp1"), eth.actual_endpoints)
        # Match the literal planned P2P switch port, not the raw vendor ordinal.
        self.assertEqual(("leaf01", "sw1p1", "server01", "mlx5_0"), ib.expected_endpoints)
        self.assertEqual(("leaf01", "sw1p1", "server03", "mlx5_1"), ib.actual_endpoints)
        asic = by_key[("switch", "nvsw01", "asic_temp", "ASIC1")]
        self.assertIn("81", asic.evidence_description)
        self.assertNotIn("75", asic.evidence_description)
        original_template = self.template.read_bytes()
        metadata = {
            "project_id": str(project), "schema_version": 1,
            "producer_version": "req7-test-producer",
            "template_contract_version": "v1",
            "template_sha256": self.snapshot.workbook_sha256,
        }
        before = tuple(sorted(self.publication.iterdir()))
        body, digest = freeze_prod_stage_l_manifest(
            qualified, self.store, metadata=metadata,
            expected_template_sha256=self.snapshot.workbook_sha256, **args,
        )
        self.assertEqual(before, tuple(sorted(self.publication.iterdir())))
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        (project / "01-global.yaml").write_text(
            "schema_version: 2\ncommon:\n  mgmt:\n"
            "    issue-tracker:\n      status: disabled\n", encoding="utf-8",
        )
        interval, policy_sha = local_publish_interval(project)
        witness = (policy_sha, interval, "fixture-boot", time.monotonic_ns())
        with tracker_writer(project, self.publication) as token:
            committed = commit_prod_stage_l_workbook(
                token, qualified, self.store, template_path=self.template,
                metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                manual_admission=witness, **args,
            )
        self.assertIsInstance(committed, CommittedProdWorkbook)
        self.assertEqual(3, committed.prepared.source_family_count)
        self.assertEqual(digest, committed.receipt.manifest_id)
        self.assertEqual(hashlib.sha256(committed.prepared.xlsx_bytes).hexdigest(),
                         committed.receipt.published_sha256)
        generation = project / ".tracker/generations" / committed.generation.generation_id
        self.assertEqual(body, (generation / "MANIFEST").read_bytes())
        receipt = json.loads((generation / "RECEIPT").read_bytes())
        self.assertEqual(digest, receipt["manifest_id"])
        self.assertEqual(committed.receipt.published_sha256, receipt["published_sha256"])
        published_bytes = (self.publication / receipt["published"]).read_bytes()
        self.assertEqual(committed.prepared.xlsx_bytes, published_bytes)
        self.assertEqual(hashlib.sha256(published_bytes).hexdigest(),
                         committed.receipt.published_sha256)
        self.assertEqual(original_template, self.template.read_bytes())
        ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

        def cells(archive, sheet):
            root = ET.fromstring(archive.read("xl/worksheets/" + sheet))
            return {node.attrib["r"]: node for node in root.findall(".//s:c", ns)}

        def text_value(node):
            return "".join(node.itertext())

        with zipfile.ZipFile(BytesIO(original_template)) as template, \
             zipfile.ZipFile(BytesIO(published_bytes)) as published:
            for sheet, expected in (
                ("sheet3.xml", {"M3": "changed-peer", "N3": "swp9",
                                "S3": "leaf-a", "T3": "swp1"}),
                ("sheet4.xml", {"M3": "leaf01", "N3": "sw1p1",
                                "S3": "server03", "T3": "mlx5_1"}),
            ):
                actual_cells = cells(published, sheet)
                for address, expected_value in expected.items():
                    self.assertEqual(expected_value, text_value(actual_cells[address]), address)
            old_switch, new_switch = cells(template, "sheet2.xml"), cells(published, "sheet2.xml")
            for address in ("D3", "E3", "G3", "H3", "I3", "O3", "U3"):
                self.assertEqual(ET.tostring(old_switch[address]),
                                 ET.tostring(new_switch[address]), address)
            for row in range(4, 8):
                for column in "DEGH":
                    address = f"{column}{row}"
                    self.assertEqual(ET.tostring(old_switch[address]),
                                     ET.tostring(new_switch[address]), address)
            asic_rows = [address[1:] for address, node in new_switch.items()
                         if address.startswith("F") and text_value(node) == "nvsw01"]
            self.assertEqual(1, len(asic_rows))
            description = text_value(new_switch["L" + asic_rows[0]])
            self.assertIn("81", description)
            self.assertNotIn("75", description)

    def test_frozen_template_fabric_is_projected_with_strict_type_precedence(self):
        from monitor.issue_tracker_stage_l_consumer import (
            inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
        )

        self.two_cycles(activity=True, derivation=True,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"})
        cycles = read_completed_cycle_evidence(self.store)
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        fabrics = {(item.activity_key[1], item.fabric, item.fabric_source)
                   for item in projection.candidates
                   if item.panel == "Switch Status"}
        self.assertEqual({("leaf-a", "Inband", "template"),
                          ("nvsw01", "Compute", "type")}, fabrics)
        self.assertEqual("qualification_not_implemented", projection.reason)
        self.assertEqual(0, projection.hostname_fallback_count)
        self.assertFalse(projection.qualified)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_source_projection_displays_eth_w1_skip_without_issue_or_permit(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_source_projection,
        )

        self.template.write_bytes(literal_xlsx(rules=("leaf-z",)))
        self.snapshot = read_whitelist_workbook(self.template)
        self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertFalse(projection.qualified)
        self.assertEqual("hold", projection.state)
        self.assertFalse(any(item.panel == "Eth Link Validation"
                             for item in projection.candidates))
        self.assertEqual(1, len(projection.whitelist_skips))
        self.assertEqual(("eth_cabling", ("leaf-a", "swp1", "leaf-z", "swp2")),
                         (projection.whitelist_skips[0].source,
                          projection.whitelist_skips[0].endpoints))
        self.assertEqual("leaf-z", projection.whitelist_skips[0].matched_rule)
        self.template.write_bytes(literal_xlsx(rules=("leaf-a",)))
        changed_snapshot = read_whitelist_workbook(self.template)
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            with self.assertRaisesRegex(
                StageLConsumerHold, "changed|disagree|unsafe",
            ):
                validate_prod_stage_l_source_projection(
                    projection, source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=changed_snapshot,
                    whitelist_path=self.template,
                )
            changed_source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=changed_snapshot,
                whitelist_path=self.template,
            )
            changed = project_prod_stage_l_source_candidates(
                changed_source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=changed_snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual(projection.whitelist_skips[0].endpoints,
                         changed.whitelist_skips[0].endpoints)
        self.assertEqual("leaf-a", changed.whitelist_skips[0].matched_rule)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_source_projection_reopens_w1_and_latest_completed_source_bytes(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_source_projection,
        )

        _, _, artifacts = self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        row = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (row,),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
            self.assertFalse(projection.qualified)
            self.template.write_bytes(literal_xlsx(rules=("leaf-z",)))
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            with self.assertRaises(StageLConsumerHold):
                validate_prod_stage_l_source_projection(
                    projection, source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            self.template.write_bytes(literal_xlsx())
            latest = artifacts["ethernet/prod"]["info"]
            latest.write_bytes(latest.read_bytes() + b"late byte drift")
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_source_projection_preserves_switch_device_level_w1_record_id(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_source_projection,
        )

        self.template.write_bytes(literal_xlsx(rules=("leaf-a",)))
        self.snapshot = read_whitelist_workbook(self.template)
        self.two_cycles(activity=True, derivation=True,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"})
        cycles = read_completed_cycle_evidence(self.store)
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
            switch_skips = tuple(skip for skip in projection.whitelist_skips
                                 if skip.source == "switch")
            self.assertEqual(1, len(switch_skips))
            self.assertEqual(("switch:leaf-a", "leaf-a", None),
                             (switch_skips[0].record_id,
                              switch_skips[0].matched_rule,
                              switch_skips[0].endpoints))
            self.assertFalse(projection.qualified)
            self.template.write_bytes(literal_xlsx(rules=("re:^leaf-a$",)))
            changed_snapshot = read_whitelist_workbook(self.template)
            with self.assertRaises(StageLConsumerHold):
                validate_prod_stage_l_source_projection(
                    projection, source, self.store, http_root=self.root,
                    settings=self.settings,
                    whitelist_snapshot=changed_snapshot,
                    whitelist_path=self.template,
                )

    def test_prod_three_source_domains_join_exact_k_without_qualification(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold,
            inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_composed_sources,
            validate_prod_stage_l_source_projection,
        )

        self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        row = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (row,),
            ) for cycle in cycles
        }
        # Only the protected IB report decoder is substituted. This tests
        # composition, not true nine-role IB provenance or Stage-L acceptance.
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            self.assertEqual(tuple(cycle.cycle_id for cycle in cycles),
                             source.eth_link_source.cycle_ids)
            self.assertEqual(source.switch_ib_source.switch_source.cycle_ids,
                             source.eth_link_source.cycle_ids)
            self.assertEqual("WRONG_PEER",
                             source.eth_link_source.persistent_links[0].status)
            self.assertEqual(("Miswired_Links", "Mis-wiring"),
                             (source.eth_issue_rows[0].source_sheet,
                              source.eth_issue_rows[0].issue_type))
            self.assertFalse(source.eth_issue_rows[0].qualified)
            self.assertEqual((row,), source.switch_ib_source.ib_source.kept_rows)
            self.assertFalse(source.qualified)
            self.assertEqual("hold", source.state)
            self.assertEqual("qualification_not_implemented", source.reason)
            self.assertEqual(source, validate_prod_stage_l_composed_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            ))
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
            self.assertFalse(projection.qualified)
            self.assertEqual("hold", projection.state)
            self.assertEqual("fabric_identity_unresolved", projection.reason)
            self.assertEqual({"Switch Status", "Eth Link Validation",
                              "IB Link Validation"},
                             {item.panel for item in projection.candidates})
            eth = [item for item in projection.candidates
                   if item.panel == "Eth Link Validation"]
            self.assertEqual(1, len(eth))
            self.assertEqual(("leaf-a", "swp1", "leaf-z", "swp2"),
                             eth[0].expected_endpoints)
            self.assertEqual(("foreign-z", "swp9", "leaf-a", "swp1"),
                             eth[0].actual_endpoints)
            self.assertEqual(("Miswired_Links", "Mis-wiring"),
                             (eth[0].source_sheet, eth[0].issue_type))
            self.assertEqual(
                "stl-" + hashlib.sha256(
                    b'["eth_cabling","leaf-a","swp1","Mis-wiring"]'
                ).hexdigest(),
                eth[0].operation_id,
            )
            self.assertFalse(any(item.qualified for item in projection.candidates))
            fabrics = {(item.activity_key[1], item.fabric, item.fabric_source)
                       for item in projection.candidates
                       if item.panel == "Switch Status"}
            self.assertIn(("nvsw01", "Compute", "type"), fabrics)
            self.assertIn(("leaf-a", None, None), fabrics)
            self.assertEqual(projection, validate_prod_stage_l_source_projection(
                projection, source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            ))
            with self.assertRaises(StageLConsumerHold):
                validate_prod_stage_l_source_projection(
                    replace(projection, qualified=True), source, self.store,
                    http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    replace(source, qualified=True), self.store,
                    http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    replace(source, eth_link_source=replace(
                        source.eth_link_source,
                        cycle_ids=("foreign-cycle", *source.eth_link_source.cycle_ids[1:]),
                    )), self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_real_cycles_and_durable_k_combine_switch_families_and_ib_only(self):
        from monitor.issue_tracker_stage_l_consumer import (
            inspect_prod_stage_l_bound_sources,
            validate_prod_stage_l_bound_sources,
        )

        self.two_cycles()
        cycles = read_completed_cycle_evidence(self.store)
        first = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        latest = IbReportLink(
            "Mis-wiring", first.expected_endpoints,
            ("server03", "mlx5_2"), "Miswired_Links", 3,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64,
                (first if index == 0 else latest,),
            ) for index, cycle in enumerate(cycles)
        }
        # This composition seam replaces protected IB report replay only;
        # it cannot be counted as real report-role or Stage-L acceptance.
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_bound_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            self.assertEqual(tuple(cycle.cycle_id for cycle in cycles),
                             source.switch_source.cycle_ids)
            self.assertEqual((latest,), source.ib_source.kept_rows)
            self.assertFalse(source.qualified)
            self.assertEqual("hold", source.state)
            self.assertEqual("qualification_not_implemented", source.reason)
            self.assertEqual(source, validate_prod_stage_l_bound_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            ))
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_real_prod_worker_emitter_cycles_with_unbound_ib_stay_read_only(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_sources,
            require_complete_stage_l_sources,
        )

        first, second, _artifacts = self.two_cycles()
        source = inspect_prod_stage_l_sources(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.snapshot, whitelist_path=self.template,
        )
        self.assertEqual((first["cycle_id"], second["cycle_id"]), source.cycle_ids)
        self.assertEqual("hold", source.state)
        self.assertEqual("ib_report_not_bound_to_completed_cycle", source.reason)
        self.assertFalse(source.qualified)
        self.assertEqual({"ethernet/prod", "nvlink/prod"},
                         {row.source_slot for row in source.switch_rows})
        with self.assertRaisesRegex(StageLConsumerHold,
                                    "IB report.*completed cycle"):
            require_complete_stage_l_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))


if __name__ == "__main__":
    unittest.main()
