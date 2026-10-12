"""Independent all-business/all-audit reconciliation and original APPLIED evidence."""
from copy import deepcopy
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

import test_cases
ROOT = Path(test_cases.__file__).resolve().parents[1]
from test_cases.test_req7_spreadsheet_owner import load as load_owner, fixture, binding, TARGET, scoped_fixture
from test_cases.test_req7_global_attempt_journal import load as load_global
from test_cases.test_req7_history_preread_journal import load as load_before
from test_cases.test_req7_enrollment_journal import load as load_enrollment
from test_cases.test_req7_history_read import load as load_read, inputs as read_inputs, response, tail_document
from test_cases.test_req7_send_unit import inputs as send_inputs
from test_cases.test_req7_sheets_read_decode import identity_response


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()


def load():
    path = ROOT / 'monitor/issue_tracker_remote_history_match.py'
    if not path.is_file(): raise AssertionError('journal/nonce/fence/all-History matcher missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_remote_history_match', path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    monitor.issue_tracker_remote_history_match = module
    return module


class Req7RemoteHistoryMatchDirectTests(unittest.TestCase):
    def test_fixed_current_native_switch_preparation_creator_accepts_no_caller_generation_or_unit(self):
        import inspect
        module=load();create=getattr(module,'_prepare_current_cycle_native_switch_unit',None)
        self.assertTrue(callable(create),'runtime must derive the actual current C6 before native preparation creation')
        self.assertFalse({'generation_id','publish_id','unit','keys','qualified','compiler','callback','plan'}
            & set(inspect.signature(create).parameters))
        with self.assertRaises(module.RemoteHistoryHold):
            create(object(),object(),binding(),object(),_store=object(),http_root=ROOT)

    def test_current_native_receipt_locator_context_keeps_originals_live_without_caller_guards(self):
        import inspect
        module=load();hold=getattr(module,'_hold_current_cycle_native_receipt_locators',None)
        self.assertTrue(callable(hold),'NEW preparation requires original C5/C6/K holders live beyond locator discovery')
        self.assertEqual(('writer_token','_store','http_root'),tuple(inspect.signature(hold).parameters))
        entered=[]
        with self.assertRaises(module.RemoteHistoryHold):
            with hold(object(),_store=object(),http_root=ROOT):entered.append(True)
        self.assertEqual([],entered)

    def test_current_native_receipt_locator_discovery_has_no_caller_source_or_admission_callback(self):
        import inspect
        module=load();discover=getattr(module,'_read_current_cycle_native_receipt_locators',None)
        self.assertTrue(callable(discover),'default native preparation needs fixed actual current C6 discovery')
        self.assertEqual(('writer_token','_store','http_root'),tuple(inspect.signature(discover).parameters))
        with mock.patch('monitor.issue_tracker_state_owner.current_k') as settings:
            with self.assertRaises(module.RemoteHistoryHold):discover(object(),_store=object(),http_root=ROOT)
        settings.assert_not_called()

    def test_native_nv_issued_columns_match_both_retained_originals_without_new_read_or_capacity_authority(self):
        module=load();verify=getattr(module,'_verify_native_issued_nv_columns',None)
        self.assertTrue(callable(verify),'both original issued columns need a fixed precompiler check')
        from monitor import issue_tracker_nv_reservation as native,issue_tracker_history_read_launcher as reads,issue_tracker_token_launcher as tokens
        eth=SimpleNamespace(data=b'original ETH column image');ib=SimpleNamespace(data=b'original IB column image')
        observation=SimpleNamespace(eth_source_sha256=hashlib.sha256(eth.data).hexdigest(),
            ib_source_sha256=hashlib.sha256(ib.data).hexdigest())
        prepared=native._CatalogNvPreparation(observation);writer=object();token=object();auth=object();target=binding()
        record={'token':token,'binding':target}
        with mock.patch.object(native,'_verify_catalog_preparation',return_value=record), \
                mock.patch.object(reads,'require_current_owned_project_read') as guard, \
                mock.patch.object(tokens,'require_current_owned_project_token') as authenticate, \
                mock.patch.object(reads.OwnedProjectSheetsReadUnit,'read_once') as acquire:
            self.assertIsNone(verify(prepared,writer,token,target,auth,eth,ib))
            self.assertEqual([mock.call(writer,token,target,eth,auth,read_kind='activity',sheet='ETH Cabling'),
                mock.call(writer,token,target,ib,auth,read_kind='activity',sheet='IB Cabling')],guard.call_args_list)
            self.assertEqual(2,authenticate.call_count);acquire.assert_not_called()
            for first,second in ((SimpleNamespace(data=b'changed ETH column image'),ib),
                                 (eth,SimpleNamespace(data=b'changed IB column image')),(ib,eth)):
                with self.subTest(pair=(first.data,second.data)),self.assertRaises(module.RemoteHistoryHold):
                    verify(prepared,writer,token,target,auth,first,second)

    def test_native_nv_cabling_issued_compiler_refuses_unissued_preparation_without_caller_source_plans(self):
        import inspect
        module=load();entry=getattr(module,'_hold_native_current_cycle_observed_nv_cabling_unit',None)
        self.assertTrue(callable(entry),'actual two-original-column NV compiler receiver is missing')
        self.assertFalse({'sheet','keys','rows','plans','qualified','unit','compiler','eth_plan','ib_plan'}
            & set(inspect.signature(entry).parameters))
        from monitor import issue_tracker_history_read_launcher as reads,issue_tracker_token_launcher as tokens
        entered=[]
        with mock.patch.object(reads.OwnedProjectSheetsReadUnit,'read_once') as acquire, \
                mock.patch.object(tokens,'require_current_owned_project_token') as auth:
            with self.assertRaises(module.RemoteHistoryHold):
                with entry(object(),object(),object(),binding(),object(),_store=object(),http_root=self.root):
                    entered.append(True)
        self.assertEqual([],entered);acquire.assert_not_called();auth.assert_not_called()

    def test_native_cabling_issued_compiler_derives_family_and_refuses_unissued_preparation_before_reads(self):
        import inspect
        module=load();entry=getattr(module,'_hold_native_current_cycle_observed_cabling_unit',None)
        self.assertTrue(callable(entry),'Cabling needs a fixed actual issuer factory, not caller row/read plans')
        self.assertFalse({'sheet','keys','rows','plans','qualified','unit','compiler'} & set(inspect.signature(entry).parameters))
        from monitor import issue_tracker_history_read_launcher as reads,issue_tracker_token_launcher as tokens
        entered=[]
        with mock.patch.object(reads.OwnedProjectSheetsReadUnit,'read_once') as acquire, \
                mock.patch.object(tokens,'require_current_owned_project_token') as auth:
            with self.assertRaises(module.RemoteHistoryHold):
                with entry(object(),object(),object(),binding(),object(),_store=object(),http_root=self.root):
                    entered.append(True)
        self.assertEqual([],entered,'sanitized caller assertion is not rejection before entry')
        acquire.assert_not_called();auth.assert_not_called()

    def test_native_switch_issued_compiler_refuses_unissued_preparation_before_auth_or_reads(self):
        module=load();entry=getattr(module,'_hold_native_current_cycle_observed_switch_unit',None)
        self.assertTrue(callable(entry),'fixed actual issued-read Switch compiler is missing')
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_token_launcher as tokens
        with mock.patch.object(reads.OwnedProjectSheetsReadUnit,'read_once') as acquire, \
                mock.patch.object(tokens,'require_current_owned_project_token') as auth:
            with self.assertRaises(module.RemoteHistoryHold):
                with entry(object(),object(),object(),binding(),object(),_store=object(),http_root=self.root):
                    self.fail('unissued native preparation reached an authenticated read')
        acquire.assert_not_called();auth.assert_not_called()

    def test_native_current_cycle_compiler_inputs_refuse_unissued_preparation_before_acquisition(self):
        module=load();entry=getattr(module,'_hold_native_current_cycle_compiler_inputs',None)
        self.assertTrue(callable(entry),'fixed native source/receipt reception is missing')
        from monitor import issue_tracker_nv_reservation as native
        from monitor import issue_tracker_stage_l_consumer as source
        with mock.patch.object(source,'_hold_original_replay_inputs') as acquire:
            with self.assertRaises((module.RemoteHistoryHold,native.NvReservationHold)):
                with entry(object(),object(),object(),binding(),_store=object(),http_root=self.root):
                    self.fail('unissued preparation reached source/receipt reception')
        acquire.assert_not_called()

    def setUp(self):
        self.owner = load_owner(); self.global_journal = load_global()
        self.planner = load_read('issue_tracker_sheets_read_plan'); self.decoder = load_read('issue_tracker_sheets_read_decode')
        self.enrollment = load_enrollment(); self.before = load_before()
        self.capacity = load_read('issue_tracker_metadata_capacity'); self.decoder = sys.modules['monitor.issue_tracker_sheets_read_decode']
        self.binding, self.token_value = read_inputs()
        self.identity = self.decoder.decode_template_identity(self.planner.prepare_template_identity_read(self.binding, self.token_value), response(identity_response()))
        self.meta_plan = self.capacity.prepare_metadata_capacity_read(self.binding, self.token_value)
        self.plan = self.planner.prepare_history_tail_read(self.binding, self.token_value)
        self.temp = tempfile.TemporaryDirectory(prefix='req7-remote-match-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.state = self.root / 'var/lib/http-ztp-container/issue-tracker'
        self.state.mkdir(parents=True, mode=0o700)
        args = send_inputs(); args.update(sheet_id=101, history_sheet_id=105, target_nonce='a' * 64, history_nonce='d' * 64)
        # First business op is NOOP; only op 1 and ALL assigned audits travel.
        args['business'][0]['observed_values'] = {'L': {'stringValue': 'down'}}
        args['audits'] = ({'event_id': 'settings:001', 'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': 'K=3'},)
        from monitor.issue_tracker_send_unit import freeze_send_unit
        self.unit = freeze_send_unit(**args)
        self.empty = tail_document(12); self.empty['sheets'][0]['properties']['sheetId'] = 105
        self.empty['sheets'][0]['data'][0]['rowData'] = []
        common = {'schema_version': 1, 'unit_id': self.unit.unit_id, 'manifest_id': args['manifest_id'],
                  'generation_id': 'a' * 64, 'publish_id': 'b' * 64, 'action_digest': self.unit.action_digest,
                  'outcome_mapping_sha256': self.unit.outcome_mapping_sha256, 'target_nonce': 'a' * 64,
                  'history_nonce': 'd' * 64, 'preread_sha256': 'e' * 64}
        intended = hashlib.sha256(canonical({'sheet': 'ETH&IB Switch', 'sheet_id': 101, 'action': 'update',
                                            'row_index': 3, 'values': {'L': {'stringValue': 'down'}}})).hexdigest()
        self.rows = [('2026-10-08T10:00:00Z', 'ETH&IB Switch', 'update', 'switch:0001',
                      canonical({**common, 'operation_id': 'switch:0001', 'intended_sha256': intended}).decode().rstrip('\n')),
                     ('2026-10-08T10:00:00Z', 'ETH&IB Switch', 'settings-audit', 'settings:001',
                      canonical({**common, 'event_id': 'settings:001', 'event_details': 'K=3'}).decode().rstrip('\n'))]
        self.post = deepcopy(self.empty)
        self.post['sheets'][0]['data'][0]['rowData'] = [{'values': [{'userEnteredValue': {'stringValue': text}} for text in row]} for row in self.rows]
        self.metadata = {'matchedDeveloperMetadata': [
            {'developerMetadata': {'metadataId': 1, 'metadataKey': 'http-ztp-enrollment-v1', 'metadataValue': 'a' * 64,
                                   'visibility': 'DOCUMENT', 'location': {'locationType': 'SHEET', 'sheetId': 101}}},
            {'developerMetadata': {'metadataId': 2, 'metadataKey': 'http-ztp-enrollment-v1', 'metadataValue': 'd' * 64,
                                   'visibility': 'DOCUMENT', 'location': {'locationType': 'SHEET', 'sheetId': 105}}},
            {'developerMetadata': {'metadataId': self.unit.fence_metadata_id, 'metadataKey': 'z', 'metadataValue': '1',
                                   'visibility': 'DOCUMENT', 'location': {'locationType': 'SHEET', 'sheetId': 101}}}]}

    def prepare(self, token, *, attempt=True, before=None):
        with mock.patch('secrets.token_hex', side_effect=['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]):
            self.enrollment.prepare_enrollment_journal(token, binding(), self.identity)
        self.global_journal.prepare_global_unit(token, binding(), self.unit)
        self.before.prepare_history_preread(token, binding(), self.unit, self.plan, response(self.empty if before is None else before))
        if attempt: self.global_journal.record_global_attempt_intent(token, binding(), self.unit)

    def observe(self, module, token, *, post=None, metadata=None):
        return module.observe_remote_history_unit(token, binding(), self.unit, self.identity,
            self.meta_plan, response(self.metadata if metadata is None else metadata),
            self.plan, response(self.post if post is None else post))

    def test_unissued_owner_cannot_write_key_watermark_or_alter_original_journal(self):
        module = load()
        self.assertTrue(callable(getattr(module, 'record_owned_applied_key_watermarks', None)),
                        'C6/C19 require original-proof-bound key high-water, not an APPLIED flag')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            original = {p: (p.stat().st_ino, p.read_bytes())
                        for p in self.root.rglob('*') if p.is_file()}
            with self.assertRaises(module.RemoteHistoryHold) as caught:
                module.record_owned_applied_key_watermarks(
                    object(), token, binding(), self.unit,
                    generation=SimpleNamespace(generation_id='a' * 64, sequence=1, state='APPLIED'),
                )
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(original, {p: (p.stat().st_ino, p.read_bytes())
                                        for p in self.root.rglob('*') if p.is_file()})

    def test_actual_journals_and_both_nonces_fence_all_sent_and_audit_match_without_clearing_unknown(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            seen = self.observe(module, token)
            self.assertEqual(('MATCHED_OBSERVATION', 2, 2, 1), (seen.state, seen.history_rows_expected, seen.history_rows_matched, seen.attempt_count))
            self.assertTrue(seen.fence_present); self.assertTrue(seen.target_nonce_valid); self.assertTrue(seen.history_nonce_valid)
            self.assertFalse(hasattr(seen, 'permit')); self.assertFalse(hasattr(seen, 'applied'))
            self.assertEqual((1, 'UNKNOWN'), (self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count,
                                             self.global_journal.inspect_global_unit(token, binding(), self.unit).outcome))

    def test_fence_alone_missing_audit_duplicate_wrong_digest_or_typed_formula_conflict(self):
        module = load()
        cases = []
        item = deepcopy(self.empty); cases.append(item)
        item = deepcopy(self.post); item['sheets'][0]['data'][0]['rowData'].pop(); cases.append(item)
        item = deepcopy(self.post); item['sheets'][0]['data'][0]['rowData'].append(deepcopy(item['sheets'][0]['data'][0]['rowData'][0])); cases.append(item)
        for column, value in ((3, 'switch:0000'), (4, 'wrong digest')):
            item = deepcopy(self.post); item['sheets'][0]['data'][0]['rowData'][0]['values'][column]['userEnteredValue']['stringValue'] = value; cases.append(item)
        item = deepcopy(self.post); item['sheets'][0]['data'][0]['rowData'][0]['values'][0]['userEnteredValue'] = {'formulaValue': '=literal'}; cases.append(item)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            for item in cases: self.assertEqual('CONFLICT', self.observe(module, token, post=item).state)
            self.assertEqual(1, self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count)

    def test_absent_fence_and_exact_unchanged_history_remain_unresolved_not_complete_or_conflict(self):
        module = load()
        absent = deepcopy(self.metadata); absent['matchedDeveloperMetadata'].pop()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            seen = self.observe(module, token, post=deepcopy(self.empty), metadata=absent)
            self.assertEqual(('UNKNOWN', 1, False, 2, 0),
                (seen.state, seen.attempt_count, seen.fence_present,
                 seen.history_rows_expected, seen.history_rows_matched))
            self.assertEqual((1, 'UNKNOWN'),
                (self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count,
                 self.global_journal.inspect_global_unit(token, binding(), self.unit).outcome))
            self.assertFalse(hasattr(seen, 'permit'))
            # A partial append is not the unchanged pre-send state, and even
            # an empty tail conflicts when the actual fence is present.
            partial = deepcopy(self.post); partial['sheets'][0]['data'][0]['rowData'].pop()
            self.assertEqual('CONFLICT', self.observe(module, token, post=partial, metadata=absent).state)
            self.assertEqual('CONFLICT', self.observe(module, token, post=deepcopy(self.empty)).state)

    def test_absent_fence_is_unknown_foreign_fence_or_bad_nonce_cannot_match(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            item = deepcopy(self.metadata); item['matchedDeveloperMetadata'].pop()
            self.assertEqual('UNKNOWN', self.observe(module, token, metadata=item).state)
            for field, value in (('metadataKey', 'foreign'), ('metadataValue', '2'), ('visibility', 'PROJECT')):
                item = deepcopy(self.metadata); item['matchedDeveloperMetadata'][-1]['developerMetadata'][field] = value
                self.assertEqual('CONFLICT', self.observe(module, token, metadata=item).state)
            item = deepcopy(self.metadata); item['matchedDeveloperMetadata'][0]['developerMetadata']['metadataValue'] = 'f' * 64
            with self.assertRaises(module.RemoteHistoryHold): self.observe(module, token, metadata=item)

    def test_unattempted_unit_never_matches(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token, attempt=False)
            with self.assertRaises(module.RemoteHistoryHold): self.observe(module, token)

    def test_unissued_response_objects_cannot_write_durable_completion_evidence(self):
        module=load()
        self.assertTrue(hasattr(module,'record_owned_completion_evidence'),
                        'C19 needs retained evidence from the actual owned read bridge, not a caller MATCHED flag')
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            retained={str(p.relative_to(self.state)):p.read_bytes() for p in self.state.rglob('*') if p.is_file()}
            with self.assertRaises(module.RemoteHistoryHold) as caught:
                module.record_owned_completion_evidence(object(),token,binding(),self.unit,
                    identity_response=response(identity_response()),headers_response=response({}),
                    metadata_response=response(self.metadata),history_response=response(self.post))
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(retained,{str(p.relative_to(self.state)):p.read_bytes() for p in self.state.rglob('*') if p.is_file()})

    def test_applied_transition_rejects_caller_generation_without_original_local_owner(self):
        """C6/C19: a caller's generation or COMPLETE claim grants no settlement."""
        module=load()
        self.assertTrue(callable(getattr(module,'record_owned_applied_evidence',None)),
                        'REQ7 needs a separate original-C6-bound APPLIED transition')
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            retained={str(p.relative_to(self.state)):p.read_bytes()
                      for p in self.state.rglob('*') if p.is_file()}
            with self.assertRaises(module.RemoteHistoryHold) as caught:
                module.record_owned_applied_evidence(object(),token,binding(),self.unit,
                    generation=SimpleNamespace(generation_id='a'*64,sequence=1,
                                               manifest_id='c'*64,state='COMPLETE'))
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(retained,{str(p.relative_to(self.state)):p.read_bytes()
                                     for p in self.state.rglob('*') if p.is_file()})
            seen=self.global_journal.inspect_global_unit(token,binding(),self.unit)
            self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome))

    def test_cold_completion_initial_header_read_cannot_adopt_rewritten_header_and_marker(self):
        """A self-consistent later pair is not the original pair held at entry."""
        import os
        from dataclasses import asdict
        from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as original_io
        from test_cases.test_req7_sheets_read_decode import header_response
        module=load()
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            observed=self.observe(module,token)
            with module._hold_match_originals(token,binding(),self.unit) as (_verify,originals):
                _owner,_parent,name,base=self.global_journal._inputs(token,binding(),self.unit)
                start=self.state/(name[:-len('.journal')]+'.completion-started')
                start.write_bytes(local._canonical({'schema_version':1,'unit_id':self.unit.unit_id,'binding':base,
                    'originals_sha256':hashlib.sha256(local._canonical(originals)).hexdigest(),
                    'state':'COMPLETION-STARTED-NOT-APPLIED'})); start.chmod(0o600)
                proof=self.state/(name[:-len('.journal')]+'.completion'); proof.mkdir(mode=0o700)
                paths={
                    'IDENTITY-RAW':self.planner.prepare_template_identity_read(self.binding,self.token_value).path,
                    'HEADERS-RAW':self.planner.prepare_template_header_read(self.binding,self.token_value).path,
                    'METADATA-RAW':self.meta_plan.path,'HISTORY-RAW':self.plan.path,
                }
                images={'IDENTITY-RAW':response(identity_response()).data,
                        'HEADERS-RAW':response(header_response()).data,
                        'METADATA-RAW':response(self.metadata).data,'HISTORY-RAW':response(self.post).data}
                files={}
                for name,raw in images.items():
                    path=proof/name; path.write_bytes(raw); path.chmod(0o600)
                    files[name]={'identity':list(original_io._identity(os.stat(path))),
                                 'sha256':hashlib.sha256(raw).hexdigest(),
                                 'request_path_sha256':hashlib.sha256(paths[name].encode()).hexdigest()}
                header=local._canonical({'schema_version':1,'unit_id':self.unit.unit_id,'binding':base,
                    'start_witness_identity':list(original_io._identity(os.stat(start))),
                    'originals':originals,'folder_identity':list(original_io._identity(os.stat(proof))[:2]),
                    'matched':asdict(observed),'responses':files})
                path=proof/'HEADER'; path.write_bytes(header); path.chmod(0o600)
                marker={'schema_version':1,'unit_id':self.unit.unit_id,
                    'header_sha256':hashlib.sha256(header).hexdigest(),
                    'header_identity':list(original_io._identity(os.stat(path))),
                    'state':'COMPLETE-PRESENT-NOT-APPLIED'}
                (proof/'COMPLETE').write_bytes(local._canonical(marker)); (proof/'COMPLETE').chmod(0o600)
            self.assertEqual('COMPLETE-PRESENT-NOT-APPLIED',module.inspect_completion_evidence(token,binding(),self.unit).state)
            reading=original_io._read; changed=[]; original_stat=path.stat()
            def read_then_rewrite(folder,name,limit):
                raw=reading(folder,name,limit)
                if name=='HEADER' and os.fstat(folder).st_ino==proof.stat().st_ino and not changed:
                    with path.open('r+b') as held:
                        held.write(header); held.flush(); os.fsync(held.fileno())
                    os.utime(path,ns=(original_stat.st_atime_ns,original_stat.st_mtime_ns+1_000_000))
                    marker['header_identity']=list(original_io._identity(os.stat(path)))
                    (proof/'COMPLETE').write_bytes(local._canonical(marker))
                    changed.append(True)
                return raw
            with mock.patch.object(original_io,'_read',side_effect=read_then_rewrite):
                with self.assertRaises(module.RemoteHistoryHold): module.inspect_completion_evidence(token,binding(),self.unit)
            self.assertEqual([True],changed)
            self.assertEqual((header,original_stat.st_ino),(path.read_bytes(),path.stat().st_ino))
            self.assertNotEqual(original_stat.st_mtime_ns,path.stat().st_mtime_ns)
            self.assertEqual((1,'UNKNOWN'),(self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count,
                                           self.global_journal.inspect_global_unit(token,binding(),self.unit).outcome))

    def test_original_count_changed_during_post_read_cannot_escape_as_matched_observation(self):
        module=load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            decode_tail=module.decode.decode_history_tail; changed=[]
            def decoding(plan,raw,**options):
                result=decode_tail(plan,raw,**options)
                if raw.data==response(self.post).data and not changed:
                    self.global_journal.record_global_attempt_intent(token,binding(),self.unit)
                    changed.append(True)
                return result
            with mock.patch.object(module.decode,'decode_history_tail',side_effect=decoding):
                with self.assertRaises(module.RemoteHistoryHold): self.observe(module,token)
            self.assertEqual([True],changed)
            self.assertEqual((2,'UNKNOWN'),(self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count,
                                           self.global_journal.inspect_global_unit(token,binding(),self.unit).outcome))

    def test_byte_identical_original_wire_replacement_during_match_is_not_adopted(self):
        self._identical_original_replacement('.journal','WIRE')

    def test_byte_identical_original_history_replacement_during_match_is_not_adopted(self):
        self._identical_original_replacement('.history','HISTORY-RAW')

    def test_byte_identical_original_nonce_replacement_during_match_is_not_adopted(self):
        self._identical_original_replacement('.enrollment','NONCES')

    def test_original_wire_replaced_during_initial_pin_read_is_not_adopted(self):
        module=load()
        from monitor import issue_tracker_attempt_journal as original_io
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            path=self.state/(hashlib.sha256(TARGET.encode()).hexdigest()+'.journal')/'WIRE'
            raw=path.read_bytes(); preserved=self.root/'preserved-wire-at-initial-pin'
            reading=original_io._read; changed=[]
            def read_then_replace(folder,name,limit):
                result=reading(folder,name,limit)
                if name=='WIRE' and not changed:
                    path.rename(preserved); path.write_bytes(raw); path.chmod(0o600)
                    changed.append(True)
                return result
            with mock.patch.object(original_io,'_read',side_effect=read_then_replace):
                with self.assertRaises(module.RemoteHistoryHold): self.observe(module,token)
            self.assertEqual([True],changed)
            self.assertEqual(raw,path.read_bytes()); self.assertEqual(raw,preserved.read_bytes())
            self.assertEqual(1,self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count)

    def test_original_wire_same_inode_rewrite_during_initial_pin_read_is_not_adopted(self):
        module=load()
        from monitor import issue_tracker_attempt_journal as original_io
        import os
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            path=self.state/(hashlib.sha256(TARGET.encode()).hexdigest()+'.journal')/'WIRE'
            raw=path.read_bytes(); original=path.stat()
            reading=original_io._read; changed=[]
            def read_then_rewrite(folder,name,limit):
                result=reading(folder,name,limit)
                if name=='WIRE' and not changed:
                    with path.open('r+b') as held:
                        held.write(raw); held.flush(); os.fsync(held.fileno())
                    os.utime(path,ns=(original.st_atime_ns,original.st_mtime_ns+1_000_000))
                    changed.append(True)
                return result
            with mock.patch.object(original_io,'_read',side_effect=read_then_rewrite):
                with self.assertRaises(module.RemoteHistoryHold): self.observe(module,token)
            self.assertEqual([True],changed)
            self.assertEqual((raw,original.st_ino),(path.read_bytes(),path.stat().st_ino))
            self.assertEqual(1,self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count)

    def _identical_original_replacement(self,suffix,name):
        module=load()
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            path=self.state/(hashlib.sha256(TARGET.encode()).hexdigest()+suffix)/name
            original=path.read_bytes(); preserved=self.root/('preserved-original-'+name)
            decode_tail=module.decode.decode_history_tail; changed=[]
            def decoding(plan,raw,**options):
                result=decode_tail(plan,raw,**options)
                if raw.data==response(self.post).data and not changed:
                    path.rename(preserved); path.write_bytes(original); path.chmod(0o600)
                    changed.append(True)
                return result
            with mock.patch.object(module.decode,'decode_history_tail',side_effect=decoding):
                with self.assertRaises(module.RemoteHistoryHold): self.observe(module,token)
            self.assertEqual([True],changed)
            self.assertEqual(original,preserved.read_bytes()); self.assertEqual(original,path.read_bytes())
            self.assertEqual((1,'UNKNOWN'),(self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count,
                                           self.global_journal.inspect_global_unit(token,binding(),self.unit).outcome))

    def test_counted_unit_without_original_preread_cannot_match_or_create_preread(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            with mock.patch('secrets.token_hex', side_effect=['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]):
                self.enrollment.prepare_enrollment_journal(token, binding(), self.identity)
            self.global_journal.prepare_global_unit(token, binding(), self.unit)
            self.global_journal.record_global_attempt_intent(token, binding(), self.unit)
            with self.assertRaises(module.RemoteHistoryHold): self.observe(module, token)
            self.assertFalse((self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.history')).exists())
            self.assertEqual('UNKNOWN', self.global_journal.inspect_global_unit(token, binding(), self.unit).outcome)

    def test_original_typed_prefix_gaps_and_capacity_must_be_preserved_before_exact_append(self):
        module = load()
        original = deepcopy(self.empty)
        old_rows = [{'values': [{'userEnteredValue': {'boolValue': False}}]}, {},
                    {'values': [{}, {}, {}, {}, {'userEnteredValue': {'stringValue': ' old '}}]}]
        original['sheets'][0]['data'][0]['rowData'] = old_rows
        post = deepcopy(self.post)
        post['sheets'][0]['data'][0]['rowData'] = deepcopy(old_rows) + post['sheets'][0]['data'][0]['rowData']
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token, before=original)
            seen = self.observe(module, token, post=post)
            self.assertEqual(('MATCHED_OBSERVATION', 4, 6), (seen.state, seen.history_last_row_before_send, seen.history_last_row_after_read))
            cases = []
            changed = deepcopy(post); changed['sheets'][0]['data'][0]['rowData'][0]['values'][0]['userEnteredValue'] = {'numberValue': 0}; cases.append(changed)
            changed = deepcopy(post); changed['sheets'][0]['data'][0]['rowData'][1] = {'values': [{'userEnteredValue': {'stringValue': ''}}]}; cases.append(changed)
            changed = deepcopy(post); changed['sheets'][0]['data'][0]['rowData'][2]['values'][4]['userEnteredValue']['stringValue'] = 'old'; cases.append(changed)
            changed = deepcopy(post); changed['sheets'][0]['properties']['gridProperties']['rowCount'] = 8; cases.append(changed)
            for changed in cases:
                with self.subTest(changed=changed): self.assertEqual('CONFLICT', self.observe(module, token, post=changed).state)

    def test_new_row_order_gap_extra_foreign_append_and_alternate_fence_id_never_match(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            cases = []
            changed = deepcopy(self.post); changed['sheets'][0]['data'][0]['rowData'].reverse(); cases.append(changed)
            changed = deepcopy(self.post); changed['sheets'][0]['data'][0]['rowData'].insert(0, {}); cases.append(changed)
            changed = deepcopy(self.post); changed['sheets'][0]['data'][0]['rowData'].append({'values': [{'userEnteredValue': {'stringValue': 'foreign append'}}]}); cases.append(changed)
            for changed in cases: self.assertEqual('CONFLICT', self.observe(module, token, post=changed).state)
            changed = deepcopy(self.metadata); changed['matchedDeveloperMetadata'][-1]['developerMetadata']['metadataId'] += 1
            self.assertEqual('UNKNOWN', self.observe(module, token, metadata=changed).state)

    def test_malformed_duplicate_partial_foreign_or_forged_reads_hold_sanitized_without_settlement(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            raw = response(self.post)
            duplicate = deepcopy(self.metadata); duplicate['matchedDeveloperMetadata'].append(deepcopy(duplicate['matchedDeveloperMetadata'][-1]))
            cases = [dict(metadata_response=response(duplicate)),
                     dict(metadata_response=SimpleNamespace(status=200, complete=False, data=response(self.metadata).data)),
                     dict(history_response=SimpleNamespace(status=200, complete=False, data=raw.data)),
                     dict(history_response=SimpleNamespace(status=503, complete=True, data=raw.data)),
                     dict(history_response=SimpleNamespace(status=200, complete=True, data=b'{"sheets":[],"sheets":[]}')),
                     dict(history_plan=replace(self.plan, path=self.plan.path.replace(TARGET, 'foreign_spreadsheet_0002'))),
                     dict(history_plan=replace(self.plan, path=self.plan.path.replace('E5002', 'E7')))]
            args = dict(token=token, binding=binding(), unit=self.unit, identity=self.identity,
                        metadata_plan=self.meta_plan, metadata_response=response(self.metadata),
                        history_plan=self.plan, history_response=raw)
            for changes in cases:
                with self.subTest(changes=changes), self.assertRaises(module.RemoteHistoryHold) as caught:
                    module.observe_remote_history_unit(**{**args, **changes})
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual('req7_remote_history_unproved', str(caught.exception))
            self.assertEqual('UNKNOWN', self.global_journal.inspect_global_unit(token, binding(), self.unit).outcome)

    def test_full_bounded_rectangle_is_grouped_in_one_pass_without_quadratic_rescanning(self):
        module = load()
        class CountedCells:
            iterations = 0
            def __iter__(self):
                self.iterations += 1
                for row in range(2, 5002):
                    for column in 'ABCDE': yield (row, column, ())
        cells = CountedCells()
        rows = module._rows(cells, 2, 5001)
        self.assertEqual(((),) * 5, rows[0]); self.assertEqual(5000, len(rows))
        self.assertEqual(1, cells.iterations, 'fixed 25000-cell input must not be rescanned once per row')


class Req7RemoteHistoryNativeWorkflowTests(unittest.TestCase):
    from test_cases.test_req7_history_read import Req7HistoryReadNativeWorkflowTests as _Fixture
    fixture = _Fixture.fixture; certificates = _Fixture.certificates; server = _Fixture.server

    def setUp(self):
        self.setup = Req7RemoteHistoryMatchDirectTests('test_actual_journals_and_both_nonces_fence_all_sent_and_audit_match_without_clearing_unknown')
        self.setup.setUp(); self.addCleanup(self.setup.doCleanups)
        self._Fixture.setUp(self)

    def read_once(self, unit, payload):
        wire = ('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(payload)).encode() + payload
        with self.server(wire, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), self.fixture():
            raw = unit.send_once()
            with self.assertRaises(ValueError): unit.send_once()
        self.assertEqual([], errors); self.assertEqual(1, len(records))
        return raw, records[0]

    def test_actual_three_native_reads_then_original_journals_and_whole_history_match_without_settlement(self):
        setup = self.setup
        setup.planner = sys.modules['monitor.issue_tracker_sheets_read_plan']
        setup.plan = setup.planner.prepare_history_tail_read(setup.binding, setup.token_value)
        # Separate actual CA/UID validation from the synthetic global-root
        # directory fixture; no arbitrary source path or mocked decoder result.
        before_raw, first = self.read_once(self.tls.NativeHistoryTailReadUnit(setup.binding, setup.token_value), response(setup.empty).data)
        capacity = load_read('issue_tracker_metadata_capacity')
        setup.decoder = sys.modules['monitor.issue_tracker_sheets_read_decode']
        setup.identity = setup.decoder.decode_template_identity(
            setup.planner.prepare_template_identity_read(setup.binding, setup.token_value), response(identity_response()))
        setup.meta_plan = capacity.prepare_metadata_capacity_read(setup.binding, setup.token_value)
        setup.before = load_before()
        with mock.patch.dict(sys.modules, {'monitor.issue_tracker_tls_inputs': self.tls}):
            meta_raw, second = self.read_once(capacity.NativeMetadataCapacityReadUnit(setup.binding, setup.token_value), response(setup.metadata).data)
        after_raw, third = self.read_once(self.tls.NativeHistoryTailReadUnit(setup.binding, setup.token_value), response(setup.post).data)
        module = load()
        with fixture(setup.root), setup.owner.spreadsheet_owner(binding()) as token:
            with mock.patch('secrets.token_hex', side_effect=['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]):
                setup.enrollment.prepare_enrollment_journal(token, binding(), setup.identity)
            setup.global_journal.prepare_global_unit(token, binding(), setup.unit)
            setup.before.prepare_history_preread(token, binding(), setup.unit, setup.plan, before_raw)
            setup.global_journal.record_global_attempt_intent(token, binding(), setup.unit)
            seen = module.observe_remote_history_unit(token, binding(), setup.unit, setup.identity,
                setup.meta_plan, meta_raw, setup.plan, after_raw)
            self.assertEqual(('MATCHED_OBSERVATION', 2, 2), (seen.state, seen.history_rows_expected, seen.history_rows_matched))
            self.assertEqual('UNKNOWN', setup.global_journal.inspect_global_unit(token, binding(), setup.unit).outcome)
        self.assertEqual(('GET ' + setup.plan.path + ' HTTP/1.1\r\n').encode(), first[0])
        self.assertEqual(first[0], third[0]); self.assertEqual(b'', first[2]); self.assertEqual(b'', third[2])
        self.assertEqual(('POST ' + setup.meta_plan.path + ' HTTP/1.1\r\n').encode(), second[0])
        self.assertEqual(setup.meta_plan.body, second[2])


class Req7RemoteFixtureIsolationTests(unittest.TestCase):
    def test_native_fixture_refreshes_retained_consumer_before_first_owner(self):
        from test_cases.test_req7_retained_global_inventory import load as load_inventory
        previous = load_inventory(reset_support=False)
        load_owner()
        case = Req7OwnedHistoryMatchWorkflowTests()
        class StopBeforeOwners(BaseException):
            pass
        original = StopBeforeOwners()
        reached = []
        def stop(*arguments, **options):
            reached.append(True)
            raise original
        with ExitStack() as stack, mock.patch.object(case, 'owners', side_effect=stop):
            with self.assertRaises(StopBeforeOwners) as caught:
                case.native_audit_completed(stack)
        self.assertIs(original, caught.exception)
        self.assertEqual([True], reached)
        from monitor import issue_tracker_retained_inventory as actual
        for alias, name in (
                ('ownership', 'monitor.issue_tracker_spreadsheet_owner'),
                ('global_journal', 'monitor.issue_tracker_global_attempt_journal'),
                ('enrollment', 'monitor.issue_tracker_enrollment_journal'),
                ('history', 'monitor.issue_tracker_history_preread_journal')):
            with self.subTest(alias=alias):
                self.assertIs(getattr(actual, alias), sys.modules[name],
                    'capture current registries before issuing any native owner token')
        self.assertIsNot(previous, actual)

    def test_native_fixture_rebinds_current_registries_before_owner_issuance(self):
        load_owner(); load_global()
        old_enrollment = load_enrollment(); old_history = load_before()
        current_owner = load_owner(); current_global = load_global()
        self.assertIsNot(old_enrollment.ownership, current_owner)
        self.assertIsNot(old_history.ownership, current_owner)
        case = Req7OwnedHistoryMatchWorkflowTests()
        try:
            case.setUp()
            import monitor
            for name in ('issue_tracker_enrollment_journal', 'issue_tracker_history_preread_journal'):
                with self.subTest(dependency=name):
                    self.assertIs(getattr(monitor, name).ownership, current_owner)
            self.assertIs(monitor.issue_tracker_history_preread_journal.global_journal, current_global)
        finally:
            case.doCleanups()


class Req7AppliedC6OriginalDirectTests(unittest.TestCase):
    """Actual committed C6 originals, not source qualification or sending."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='req7-c6-held-replay-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()

    @contextmanager
    def actual_c6(self):
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_send_unit as composer
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        project=self.root/'project';publication=project/'publication'
        project.mkdir(mode=0o700);publication.mkdir(mode=0o700)
        local.create_local_commit_store(project,publication)
        with local.writer_owner(project,publication) as writer:
            args=send_inputs();generation=local.begin_generation(writer,args['manifest'])
            local.record_intent(writer,generation,literal_xlsx(),kind='xlsx')
            receipt=local.commit(writer,generation)
            args.update(generation_id=generation.generation_id,publish_id=receipt.published_sha256)
            unit=composer.freeze_send_unit(**args)
            yield local,composer,writer,generation,unit,publication

    def test_held_c6_replays_original_bytes_and_recovery_barriers_without_recursive_cold_parse(self):
        module=load()
        with self.actual_c6() as (local,composer,writer,generation,unit,publication):
            folder=publication.parent/'.tracker/generations'/generation.generation_id
            expected=[(publication.stat().st_dev,publication.stat().st_ino),
                      (folder.stat().st_dev,folder.stat().st_ino)]
            actual_sync=os.fsync;barriers=[]
            def sync(fd):
                info=os.fstat(fd);actual_sync(fd)
                barriers.append((info.st_dev,info.st_ino))
            with mock.patch.object(composer,'_read_original_generation_identity',
                    wraps=composer._read_original_generation_identity) as cold:
                with module._hold_applied_generation(writer,generation,unit) as (_owner,verify,facts,sent):
                    with mock.patch.object(os,'fsync',side_effect=sync):
                        verify();verify()
                    self.assertEqual(('switch:0000','switch:0001'),sent)
                    self.assertEqual(generation.generation_id,facts['generation_id'])
                calls=cold.call_count
            self.assertEqual(expected*2,barriers,'both actual recovery barriers remain on every live replay')
            self.assertEqual(1,calls,'one cold semantic admission; all later checks use the same held originals')

    def test_held_c6_refuses_each_actual_recovery_barrier_failure_without_mutating_originals(self):
        module=load()
        for boundary in (1,2):
            with self.subTest(boundary=boundary),self.actual_c6() as (
                    local,_composer,writer,generation,unit,publication):
                paths=[p for p in publication.parent.rglob('*') if p.is_file()]
                before={p:(p.stat().st_ino,p.read_bytes()) for p in paths};reached=[];native=os.fsync
                with module._hold_applied_generation(writer,generation,unit) as (_owner,verify,_facts,_sent):
                    def fault(fd):
                        reached.append(fd)
                        if len(reached)==boundary:raise OSError('owned C6 recovery barrier fault')
                        native(fd)
                    with mock.patch.object(os,'fsync',side_effect=fault):
                        with self.assertRaises(ValueError):verify()
                self.assertEqual(boundary,len(reached))
                self.assertEqual(before,{p:(p.stat().st_ino,p.read_bytes()) for p in paths})
            self.temp.cleanup();self.setUp()

    def test_held_c6_refuses_same_bytes_rebound_after_recovery_barrier_before_return(self):
        module=load()
        for selected in ('RECEIPT','XLSX'):
            with self.subTest(selected=selected),self.actual_c6() as (
                    local,_composer,writer,generation,unit,publication):
                folder=publication.parent/'.tracker/generations'/generation.generation_id
                path=(folder/'RECEIPT' if selected=='RECEIPT' else
                      next(p for p in publication.iterdir() if p.suffix=='.xlsx'))
                image=path.read_bytes();inode=path.stat().st_ino;reached=[];native=os.fsync
                with self.assertRaises(ValueError):
                    with module._hold_applied_generation(writer,generation,unit) as (_owner,verify,_facts,_sent):
                        def replace_after_sync(fd):
                            native(fd)
                            if not reached:
                                path.rename(self.root/'owned-displaced-c6-original')
                                path.write_bytes(image);path.chmod(0o600);reached.append(True)
                        with mock.patch.object(os,'fsync',side_effect=replace_after_sync):verify()
                self.assertEqual([True],reached)
                self.assertNotEqual(inode,path.stat().st_ino)
                self.assertEqual(image,path.read_bytes())
                self.assertEqual(inode,(self.root/'owned-displaced-c6-original').stat().st_ino)
            self.temp.cleanup();self.setUp()

    def test_held_c6_cannot_adopt_same_bytes_replacement_between_cold_read_and_capture(self):
        module=load()
        for selected in ('STATE','RECEIPT','MANIFEST','INTENT','XLSX','DIRECTORY'):
            with self.subTest(selected=selected),self.actual_c6() as (
                    local,composer,writer,generation,unit,publication):
                folder=publication.parent/'.tracker/generations'/generation.generation_id
                path=(folder if selected=='DIRECTORY' else
                      next(p for p in publication.iterdir() if p.suffix=='.xlsx')
                      if selected=='XLSX' else folder/selected)
                original=path.stat().st_ino;reached=[];cold=composer._read_original_generation_identity
                def replace_after_cold(*args,**kwargs):
                    result=cold(*args,**kwargs)
                    if not reached:
                        saved=self.root/'owned-displaced-capture-original'
                        path.rename(saved)
                        if selected=='DIRECTORY':
                            path.mkdir(mode=0o700)
                            for old in saved.iterdir():
                                # Preserve child objects; replace only the ancestor.
                                old.rename(path/old.name)
                        else:
                            path.write_bytes(saved.read_bytes());path.chmod(0o600)
                        reached.append(True)
                    return result
                with mock.patch.object(composer,'_read_original_generation_identity',side_effect=replace_after_cold):
                    with self.assertRaises(ValueError):
                        with module._hold_applied_generation(writer,generation,unit):
                            self.fail('substituted C6 must never reach the handoff')
                self.assertEqual([True],reached)
                self.assertNotEqual(original,path.stat().st_ino)
                self.assertEqual(original,(self.root/'owned-displaced-capture-original').stat().st_ino)
            self.temp.cleanup();self.setUp()


class Req7OwnedHistoryMatchWorkflowTests(unittest.TestCase):
    @contextmanager
    def _default_recovery_store(self, project):
        from test_cases.test_collection_cycle_persistence import WORKER
        gate=WORKER.CollectionGate(str(project),'prod',status_dir=self.root/'monitor/status',
                                  enforce_cooldown=False,lane='collection')
        with gate as held:
            self.assertTrue(held.decision.allowed)
            yield WORKER.CollectionCycleStore(gate=held)

    def _default_recovery_args(self, project, publication):
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        template=self.root/'monitor/Issue_Tracker_Template_v1.xlsx'
        template.parent.mkdir(parents=True,exist_ok=True)
        template.write_bytes(literal_xlsx())
        return dict(http_root=self.root,project=project,publication=publication,
                    template_path=template)

    def _default_recovery_images(self, project):
        return {str(p.relative_to(project)):(p.stat().st_ino,hashlib.sha256(p.read_bytes()).hexdigest())
                for p in project.rglob('*') if p.is_file()}

    def test_default_pending_status_reopens_original_delivery_without_online_authority(self):
        from monitor import issue_tracker_publish_runtime as runtime,issue_tracker_spreadsheet_owner as sheet
        project,publication,bound,unit=self.setup_discovered_settings_cleaned()
        args=self._default_recovery_args(project,publication); before=self._default_recovery_images(project)
        with scoped_fixture(self.root,sheet),self._default_recovery_store(project) as store:
            status=runtime.inspect_stage_l(store,**args)
        self.assertEqual(('pending',0,3,0),
                         (status['state'],status['completed_cycles'],status['k'],status['k_revision']))
        self.assertEqual('disabled_no_send_authority',status['online'])
        self.assertEqual([],status['window_cycle_ids'])
        self.assertEqual(0,status['cycle_summary']['published'])
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())
        self.assertEqual((),tuple(publication.iterdir()))

    def test_default_pending_status_uses_newest_k_but_preserves_later_pending_and_old_wire(self):
        from monitor import issue_tracker_publish_runtime as runtime,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_state_owner as state
        project,publication,bound,unit=self.setup_discovered_settings_cleaned()
        args=self._default_recovery_args(project,publication)
        with scoped_fixture(self.root,sheet):
            with state.tracker_settings_writer(project,publication) as token:
                state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-09T00:00:00Z',
                            request_id='default-local-recovery',expected_revision=0)
            before=self._default_recovery_images(project)
            with self._default_recovery_store(project) as store:
                status=runtime.inspect_stage_l(store,**args)
        self.assertEqual(('pending',6,1),(status['state'],status['k'],status['k_revision']))
        self.assertEqual('disabled_no_send_authority',status['online'])
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertTrue((project/'.tracker/settings/outbox/1.json').is_file())
        wire=self.root/'var/lib/http-ztp-container/issue-tracker'/(
            hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')/'WIRE'
        self.assertEqual(unit.wire_bytes,wire.read_bytes())

    def test_real_worker_status_entry_reads_pending_after_legal_projection_archive(self):
        import json
        from test_cases.test_collection_cycle_persistence import WORKER
        from monitor import issue_tracker_spreadsheet_owner as sheet
        project,publication,bound,unit=self.setup_discovered_settings_cleaned()
        self._default_recovery_args(project,publication); before=self._default_recovery_images(project)
        status_path=self.root/'monitor/status/issue-tracker-stage-l.status.json'
        with scoped_fixture(self.root,sheet),self._default_recovery_store(project) as store:
            with mock.patch.object(WORKER,'HTTP_ROOT',self.root), \
                    mock.patch.object(WORKER,'STATUS_DIR',status_path.parent), \
                    mock.patch.object(WORKER,'ISSUE_TRACKER_STAGE_L_STATUS_FILE',status_path):
                WORKER._publish_stage_l_status_after_completion(store)
        status=json.loads(status_path.read_bytes())
        self.assertEqual(('pending',0,3,0),
                         (status['state'],status['completed_cycles'],status['k'],status['k_revision']))
        self.assertEqual('disabled_no_send_authority',status['online'])
        self.assertEqual(0,status['cycle_summary']['published'])
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())

    def test_default_status_missing_delivery_is_hold_without_recreation(self):
        from monitor import issue_tracker_publish_runtime as runtime,issue_tracker_spreadsheet_owner as sheet
        project,publication,bound,unit=self.setup_discovered_settings_cleaned()
        args=self._default_recovery_args(project,publication)
        delivery=project/'.tracker/settings-audit-delivery/DELIVERED'
        saved=delivery.read_bytes(); delivery.rename(self.root/'preserved-default-local-delivery')
        before=self._default_recovery_images(project)
        with scoped_fixture(self.root,sheet),self._default_recovery_store(project) as store:
            with self.assertRaises(runtime.StageLHold): runtime.inspect_stage_l(store,**args)
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertEqual(saved,(self.root/'preserved-default-local-delivery').read_bytes())
        self.assertFalse(delivery.exists())
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())

    def test_native_cold_default_status_needs_no_parent_delivery_context(self):
        import subprocess
        import sys
        from test_cases.test_req7_remote_history_match import ROOT
        project,publication,bound,unit=self.setup_discovered_settings_cleaned()
        self._default_recovery_args(project,publication)
        before=self._default_recovery_images(project)
        program='''from pathlib import Path
import sys
from monitor import issue_tracker_publish_runtime as runtime,issue_tracker_state_owner as state
from monitor import issue_tracker_spreadsheet_owner as sheet
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from test_cases.test_collection_cycle_persistence import WORKER
root=Path(sys.argv[1]); project=root/'project'
assert state._COMPLETED_READ_CONTEXT=={}
assert state._COMPLETED_ORIGINAL_GUARDS=={}
with scoped_fixture(root,sheet),WORKER.CollectionGate(str(project),'prod',
 status_dir=root/'monitor/status',enforce_cooldown=False,lane='collection') as held:
 assert held.decision.allowed
 store=WORKER.CollectionCycleStore(gate=held)
 status=runtime.inspect_stage_l(store,http_root=root,project=project,
  publication=project/'99-output-monitor',template_path=root/'monitor/Issue_Tracker_Template_v1.xlsx')
 print(status['state'],status['completed_cycles'],status['k'],status['k_revision'],status['online'])
assert state._COMPLETED_READ_CONTEXT=={}
assert state._COMPLETED_ORIGINAL_GUARDS=={}
print('context-revoked')
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(self.root)],cwd=ROOT,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'pending 0 3 0 disabled_no_send_authority\ncontext-revoked\n',cold.stdout)
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())

    def test_default_status_same_byte_header_replacement_during_native_panels_cannot_return_success(self):
        from monitor import issue_tracker_publish_runtime as runtime,issue_tracker_spreadsheet_owner as sheet
        project,publication,bound,unit=self.setup_discovered_settings_cleaned()
        args=self._default_recovery_args(project,publication)
        header=project/'.tracker/settings-audit-allocation/HEADER'
        original=header.read_bytes(); reached=[]; native=runtime._stage_l_per_key_panels
        def replace_after_panels(*a,**kw):
            result=native(*a,**kw)
            replacement=self.root/'same-byte-default-local-header'
            replacement.write_bytes(original); replacement.chmod(0o600)
            header.rename(self.root/'preserved-default-local-header'); replacement.rename(header)
            reached.append(True)
            return result
        with scoped_fixture(self.root,sheet),self._default_recovery_store(project) as store:
            with mock.patch.object(runtime,'_stage_l_per_key_panels',side_effect=replace_after_panels):
                with self.assertRaises(runtime.StageLHold): runtime.inspect_stage_l(store,**args)
        self.assertEqual([True],reached)
        self.assertEqual(original,header.read_bytes())
        self.assertEqual(original,(self.root/'preserved-default-local-header').read_bytes())
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())


    # Reuse owned native fixtures, not inherited test methods/discovery.
    from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests as _Fixture
    certificates = _Fixture.certificates; server = _Fixture.server
    def setUp(self):
        self._Fixture.setUp(self)
        # Earlier direct suites may reload the canonical owner and journal.
        # Capture their current registries BEFORE any owner token is issued
        # and before the remote matcher captures these dependency aliases.
        load_enrollment(); load_before()
    owners = _Fixture.owners; intercept = _Fixture.intercept; child_fixture = _Fixture.child_fixture

    def read_owned(self, stack, writer, owner, binding, token, kind, value, *, raw_body=None, sheet=None, row=None):
        from monitor import issue_tracker_history_read_launcher as reads
        import socket
        body = json.dumps(value, separators=(',', ':')).encode() if raw_body is None else raw_body
        self.assertIs(type(body),bytes)
        reply = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body
        records=errors=children=None
        try:
            with self.server(reply, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors):
                port = socket.getaddrinfo('sheets.googleapis.com', 443)[0][4][1]
                from contextlib import ExitStack
                with ExitStack() as launched:
                    calls, children = self.intercept(launched, self.child_fixture(port), writer, owner, binding)
                    result = reads.OwnedSheetsReadUnit(writer, owner, binding, token, read_kind=kind, sheet=sheet, row=row).read_once()
                    self.assertEqual((1, 0, body), (len(calls), children[0].returncode, result.data))
                self.assertEqual([], errors); self.assertEqual(1, len(records))
                method = b'POST ' if kind == 'metadata' else b'GET '
                self.assertTrue(records[0][0].startswith(method + b'/v4/spreadsheets/' + binding.spreadsheet_id.encode()))
        except reads.HistoryReadLauncherHold:
            # Preserve the original ERROR and all strict timing/behavioral
            # checks. Only non-secret phase facts survive owned-fixture cleanup;
            # never print the token, argv, HTTP headers or response body.
            print('OWNED_READ_FAILURE_PHASE',kind,
                  'server_records',None if records is None else len(records),
                  'server_errors',None if errors is None else [type(error).__name__ for error in errors],
                  'child_returncodes',None if children is None else [child.returncode for child in children],flush=True)
            raise
        return result

    def prepare_owned(self, stack, *, settings_audits=None, native_generation=False):
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_global_attempt_journal as journal, issue_tracker_enrollment_journal as enroll
        from monitor import issue_tracker_history_preread_journal as preread, issue_tracker_sheets_read_decode as decode
        from monitor.issue_tracker_send_unit import freeze_send_unit
        from test_cases.test_req7_sheets_read_decode import header_response
        _local, _ownership, writer, owner, bound, auth, config = self.owners(stack)
        identity_doc = identity_response(); identity_doc['spreadsheetId'] = bound.spreadsheet_id
        headers_doc = header_response(); headers_doc['spreadsheetId'] = bound.spreadsheet_id
        arguments = send_inputs()
        arguments.update(spreadsheet_id=bound.spreadsheet_id, sheet_id=101, history_sheet_id=105,
                         target_nonce='a'*64, history_nonce='d'*64)
        arguments['business'][0]['observed_values'] = {'L': {'stringValue': 'down'}}
        arguments['audits'] = (({'event_id': 'settings:001', 'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': 'K=3'},)
                              if settings_audits is None else settings_audits)
        if native_generation:
            from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
            generation=_local.begin_generation(writer,arguments['manifest'])
            _local.record_intent(writer,generation,literal_xlsx(),kind='xlsx')
            receipt=_local.commit(writer,generation)
            self.native_generation=generation
            arguments.update(generation_id=generation.generation_id,
                             publish_id=receipt.published_sha256)
        if settings_audits is not None:
            from monitor import issue_tracker_k_store as settings
            settings.initialize_local_k_store(self.root/'project/.tracker',token=writer,
                initialized_at='2026-10-08T10:00:00Z',acquisition_id='first-use')
        unit = freeze_send_unit(**arguments)
        empty = tail_document(12); empty['spreadsheetId'] = bound.spreadsheet_id
        empty['sheets'][0]['properties']['sheetId'] = 105; empty['sheets'][0]['data'][0]['rowData'] = []
        original_read = self.read_owned(stack, writer, owner, bound, auth, 'history_tail', empty)
        original_plan = reads.require_current_owned_read(writer, owner, bound, original_read, read_kind='history_tail')
        identity_plan = reads._prepare(bound, auth, 'template_identity', None, None)
        identity = decode.decode_template_identity(identity_plan, response(identity_doc))
        with mock.patch('secrets.token_hex', side_effect=['a'*64, 'b'*64, 'c'*64, 'd'*64]):
            enroll.prepare_enrollment_journal(owner, bound, identity)
        journal.prepare_global_unit(owner, bound, unit)
        if settings_audits is not None:
            from test_cases.test_req7_settings_audit_allocation import load as load_allocation
            allocation=load_allocation()
            allocation.prepare_settings_audit_allocation(writer,owner,bound,unit)
        preread.prepare_history_preread(owner, bound, unit, original_plan, original_read)
        journal.record_global_attempt_intent(owner, bound, unit)
        common = {'schema_version': 1, 'unit_id': unit.unit_id, 'manifest_id': arguments['manifest_id'],
                  'generation_id': arguments['generation_id'], 'publish_id': arguments['publish_id'], 'action_digest': unit.action_digest,
                  'outcome_mapping_sha256': unit.outcome_mapping_sha256, 'target_nonce': 'a'*64,
                  'history_nonce': 'd'*64, 'preread_sha256': 'e'*64}
        intended = hashlib.sha256(canonical({'sheet':'ETH&IB Switch','sheet_id':101,'action':'update',
                                             'row_index':3,'values':{'L':{'stringValue':'down'}}})).hexdigest()
        expected_rows = [('2026-10-08T10:00:00Z', 'ETH&IB Switch', 'update', 'switch:0001',
                          canonical({**common, 'operation_id':'switch:0001', 'intended_sha256':intended}).decode().rstrip('\n'))]
        expected_rows += [(audit['recorded_at_utc'],'ETH&IB Switch','settings-audit',audit['event_id'],
            canonical({**common,'event_id':audit['event_id'],'event_details':audit['details']}).decode().rstrip('\n'))
            for audit in arguments['audits']]
        post = deepcopy(empty)
        post['sheets'][0]['data'][0]['rowData'] = [{'values':[{'userEnteredValue':{'stringValue':text}} for text in row]} for row in expected_rows]
        meta = {'matchedDeveloperMetadata':[
            {'developerMetadata':{'metadataId':1,'metadataKey':'http-ztp-enrollment-v1','metadataValue':'a'*64,
                                  'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':101}}},
            {'developerMetadata':{'metadataId':2,'metadataKey':'http-ztp-enrollment-v1','metadataValue':'d'*64,
                                  'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':105}}},
            {'developerMetadata':{'metadataId':unit.fence_metadata_id,'metadataKey':'z','metadataValue':'1',
                                  'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':101}}}]}
        docs = {'identity_response':('template_identity',identity_doc),'headers_response':('template_headers',headers_doc),
                'metadata_response':('metadata',meta),'history_response':('history_tail',post)}
        return writer, owner, bound, auth, config, unit, docs

    def test_canonical_owner_reload_then_actual_audit_allocation_uses_current_registries(self):
        from contextlib import ExitStack
        from test_cases.test_req7_settings_audit_allocation import load as load_allocation
        from test_cases.test_req7_spreadsheet_owner import load as load_owner
        from test_cases.test_req7_global_attempt_journal import load as load_global
        from test_cases.test_req7_enrollment_journal import load as load_enrollment
        from test_cases.test_req7_history_preread_journal import load as load_preread
        import json
        allocation=load_allocation()
        previous=(allocation.ownership,allocation.global_journal)
        current=(load_owner(),load_global())
        load_enrollment(); load_preread()
        self.assertIsNot(previous[0],current[0])
        self.assertIsNot(previous[1],current[1])
        with ExitStack() as stack:
            writer,owner,bound,_auth,_config,unit,_docs=self.prepare_owned(
                stack,settings_audits=(self.settings_audit_oracle(),))
            self.assertIs(allocation.ownership,current[0])
            self.assertIs(allocation.global_journal,current[1])
            self.assertEqual((self.settings_audit_oracle()['event_id'],),
                tuple(row['audit']['event_id'] for row in json.loads(
                    allocation.inspect_settings_audit_allocation(writer,owner,bound,unit))))

    def current_global_state(self,owner,bound,unit):
        # Earlier real workflow fixtures intentionally reload the canonical
        # owner/global modules. An import-time fixture reference
        # must not interrogate a token issued by the newer owner registry.
        from monitor import issue_tracker_global_attempt_journal as current
        return current.inspect_global_unit(owner,bound,unit)

    def completed(self,stack):
        module=load(); audit=self.settings_audit_oracle()
        writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(audit,))
        responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                   for name,(kind,value) in docs.items()}
        module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
        return writer,owner,bound,unit

    def test_original_delivery_directory_loss_cannot_restart_first_use(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        module=load(); audit=self.settings_audit_oracle()
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(audit,))
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            delivery=self.root/'project/.tracker/settings-audit-delivery'
            preserved=self.root/'preserved-original-delivery'
            original={p.name:p.read_bytes() for p in delivery.iterdir()}
            delivery.rename(preserved)
            with self.assertRaises(allocation.SettingsAuditHold):
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertFalse(delivery.exists(),'lost original delivery is never first use again')
            self.assertEqual(original,{p.name:p.read_bytes() for p in preserved.iterdir()})
            self.assertEqual((1,'UNKNOWN'),(self.current_global_state(owner,bound,unit).attempt_count,
                                           self.current_global_state(owner,bound,unit).outcome))

    def test_first_witness_zero_write_retains_stop_name_before_directory(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer,owner,bound,unit=self.completed(stack)
            started=self.root/'project/.tracker/SETTINGS-AUDIT-DELIVERY-STARTED'
            write=os.write
            def failing(fd,image):
                if started.exists() and os.fstat(fd).st_ino==started.stat().st_ino: return 0
                return write(fd,image)
            with mock.patch('os.write',side_effect=failing),self.assertRaises(allocation.SettingsAuditHold):
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual(b'',started.read_bytes())
            self.assertFalse((started.parent/'settings-audit-delivery').exists())
            with self.assertRaises(allocation.SettingsAuditHold):
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)

    def test_original_witness_handoff_precedes_any_delivery_directory(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer,owner,bound,unit=self.completed(stack)
            started=self.root/'project/.tracker/SETTINGS-AUDIT-DELIVERY-STARTED'
            writing=allocation._write_delivery_file; changed=[]
            def write_then_replace(parent,name,image):
                result=writing(parent,name,image)
                if name=='SETTINGS-AUDIT-DELIVERY-STARTED':
                    raw=started.read_bytes(); started.rename(self.root/'preserved-original-start')
                    started.write_bytes(raw); started.chmod(0o600); changed.append(True)
                return result
            with mock.patch.object(allocation,'_write_delivery_file',side_effect=write_then_replace),\
                    self.assertRaises(allocation.SettingsAuditHold):
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual([True],changed)
            self.assertFalse((started.parent/'settings-audit-delivery').exists())

    def test_witness_replacement_after_header_never_commits_delivered(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer,owner,bound,unit=self.completed(stack)
            started=self.root/'project/.tracker/SETTINGS-AUDIT-DELIVERY-STARTED'
            writing=allocation._write_delivery_file; changed=[]
            def write_then_replace(parent,name,image):
                result=writing(parent,name,image)
                if name=='HEADER':
                    raw=started.read_bytes(); started.rename(self.root/'preserved-original-start')
                    started.write_bytes(raw); started.chmod(0o600); changed.append(True)
                return result
            with mock.patch.object(allocation,'_write_delivery_file',side_effect=write_then_replace),\
                    self.assertRaises(allocation.SettingsAuditHold):
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual([True],changed)
            self.assertFalse((started.parent/'settings-audit-delivery/DELIVERED').exists())

    def test_cold_same_byte_witness_is_not_the_recorded_original(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer,owner,bound,unit=self.completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            started=self.root/'project/.tracker/SETTINGS-AUDIT-DELIVERY-STARTED'
            image=started.read_bytes(); started.rename(self.root/'preserved-original-start')
            started.write_bytes(image); started.chmod(0o600)
            for observe in (allocation.inspect_completed_settings_delivery,
                            allocation.pending_settings_audits_after_completed_unit):
                with self.subTest(observer=observe.__name__),self.assertRaises(allocation.SettingsAuditHold):
                    observe(writer,owner,bound,unit)

    def start_barrier_fault(self,boundary):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer,owner,bound,unit=self.completed(stack)
            started=self.root/'project/.tracker/SETTINGS-AUDIT-DELIVERY-STARTED'
            delivery=started.parent/'settings-audit-delivery'
            sync=os.fsync; reached=[]
            def failing(fd):
                if started.exists() and not delivery.exists():
                    info=os.fstat(fd)
                    if any((p.stat().st_dev,p.stat().st_ino)==(info.st_dev,info.st_ino)
                           for p in (started,started.parent)):
                        reached.append(fd)
                        if len(reached)==boundary: raise OSError('owned start witness barrier fault')
                return sync(fd)
            with mock.patch('os.fsync',side_effect=failing),self.assertRaises(allocation.SettingsAuditHold):
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual(boundary,len(reached)); self.assertTrue(started.is_file())
            self.assertFalse(delivery.exists())
            image=started.read_bytes()
            with self.assertRaises(allocation.SettingsAuditHold):
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual(image,started.read_bytes()); self.assertFalse(delivery.exists())

    def test_start_file_first_barrier_failure_retains_stop(self): self.start_barrier_fault(1)
    def test_start_parent_first_barrier_failure_retains_stop(self): self.start_barrier_fault(2)
    def test_start_held_file_barrier_failure_retains_stop(self): self.start_barrier_fault(3)
    def test_start_held_parent_barrier_failure_retains_stop(self): self.start_barrier_fault(4)

    def test_fresh_writer_scope_recovers_k_without_parent_registry_or_resend(self):
        from dataclasses import asdict
        import json
        import subprocess
        bound,_unit,projection=self.original_completed_writer_pair()
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); project=root/'project'; bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
folder=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((folder/'ACTION-PREIMAGE').read_bytes(),(folder/'WIRE').read_bytes())
with scoped_fixture(root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
 value=state.current_k(token); print(value.revision,value.k)
try: state.current_k(token)
except state.TrackerStateHold: print('REVOKED')
else: raise AssertionError('expired owner still reads K')
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'0 3\nREVOKED\n',cold.stdout)
        self.assertFalse(projection.exists()); self.assertTrue((self.root/'preserved-completed-writer-projection').is_file())

    def original_completed_writer_pair(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer,sheet,bound,unit=self.completed(stack)
            allocation.record_completed_settings_delivery(writer,sheet,bound,unit)
            projection=self.root/'project/.tracker/settings/outbox/0.json'
            projection.rename(self.root/'preserved-completed-writer-projection')
        return bound,unit,projection

    def test_scoped_writer_reads_original_k_and_revokes_without_repair(self):
        from monitor import issue_tracker_state_owner as state
        from monitor import issue_tracker_spreadsheet_owner as sheet
        from test_cases.test_req7_spreadsheet_owner import scoped_fixture
        bound,unit,projection=self.original_completed_writer_pair()
        original={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        project=self.root/'project'
        with scoped_fixture(self.root,sheet),state.tracker_writer(project,project/'publication',
                completed_binding=bound,completed_unit=unit) as token:
            # Ordinary current_k inside this qualified scope must perform a
            # fresh proof read; no caller-provided consumed-ID list or snapshot.
            self.assertEqual((0,3),(state.current_k(token).revision,state.current_k(token).k))
            state.require_current_k(token,project,project/'publication',state.current_k(token))
        with self.assertRaises(state.TrackerStateHold): state.current_k(token)
        self.assertEqual(original,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.assertFalse(projection.exists())

    def test_caller_exception_survives_and_final_proof_loss_revokes_scope(self):
        from monitor import issue_tracker_state_owner as state
        from monitor import issue_tracker_spreadsheet_owner as sheet
        from test_cases.test_req7_spreadsheet_owner import scoped_fixture
        bound,unit,_projection=self.original_completed_writer_pair(); project=self.root/'project'
        class CallerFailure(Exception): pass
        with scoped_fixture(self.root,sheet),self.assertRaises(CallerFailure):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                self.assertEqual(3,state.current_k(token).k)
                raise CallerFailure('owned caller body fault')
        with self.assertRaises(state.TrackerStateHold): state.current_k(token)
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                self.assertEqual(3,state.current_k(token).k)
                (project/'.tracker/settings-audit-delivery/DELIVERED').rename(self.root/'preserved-final-writer-delivery')
        with self.assertRaises(state.TrackerStateHold): state.current_k(token)


    def test_current_pointer_replacement_after_qualified_read_never_escapes_as_k(self):
        from contextlib import contextmanager
        from unittest import mock
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_state_owner as state_owner
        with ExitStack() as stack:
            writer, owner, bound, unit = self.completed(stack)
            allocation.record_completed_settings_delivery(writer, owner, bound, unit)
            tracker=self.root/'project/.tracker'
            (tracker/'settings/outbox/0.json').rename(self.root/'preserved-final-k-projection')
            current=tracker/'settings/current'
            replacement=self.root/'replacement-current'; replacement.write_bytes(current.read_bytes())
            replacement.chmod(0o600)
            original=allocation._hold_delivery_files; reached=[]
            @contextmanager
            def after_observation(*args,**options):
                with original(*args,**options) as verify:
                    yield verify
                    # The returned state was already computed, but its outer
                    # original proof/settings scope has not returned yet.
                    current.rename(self.root/'preserved-original-current')
                    replacement.rename(current); reached.append(True)
            with mock.patch.object(allocation,'_hold_delivery_files',side_effect=after_observation), self.assertRaises(state_owner.TrackerStateHold):
                state_owner.current_k(writer, spreadsheet_token=owner, binding=bound, completed_unit=unit)
            self.assertEqual([True],reached)
            self.assertEqual((self.root/'preserved-original-current').read_bytes(),current.read_bytes())

    def test_fresh_dual_owner_process_reads_original_k_after_delivered_projection_loss(self):
        from dataclasses import asdict
        import json
        import subprocess
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer, owner, bound, unit = self.completed(stack)
            allocation.record_completed_settings_delivery(writer, owner, bound, unit)
            projection=self.root/'project/.tracker/settings/outbox/0.json'
            projection.rename(self.root/'preserved-cold-k-projection')
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_state_owner as state
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor import issue_tracker_spreadsheet_owner as owner,issue_tracker_local_commit as local
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
store=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((store/'ACTION-PREIMAGE').read_bytes(),(store/'WIRE').read_bytes())
with local.writer_owner(root/'project',root/'project/publication') as writer,scoped_fixture(root,owner),owner.spreadsheet_owner(bound) as token:
 seen=state.current_k(writer,spreadsheet_token=token,binding=bound,completed_unit=unit)
 print(seen.revision,seen.k)
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'0 3\n',cold.stdout)
        self.assertFalse(projection.exists()); self.assertTrue((self.root/'preserved-cold-k-projection').is_file())

    def test_partial_forged_or_expired_delivery_context_never_returns_k(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_state_owner as state_owner
        with ExitStack() as stack:
            writer, owner, bound, unit = self.completed(stack)
            allocation.record_completed_settings_delivery(writer, owner, bound, unit)
            projection = self.root / 'project/.tracker/settings/outbox/0.json'
            projection.rename(self.root / 'preserved-unqualified-projection')
            for context in ({'spreadsheet_token': owner},
                            {'spreadsheet_token': object(), 'binding': bound, 'completed_unit': unit},
                            {'spreadsheet_token': owner, 'binding': bound, 'completed_unit': object()}):
                with self.subTest(context_keys=tuple(context)), self.assertRaises(state_owner.TrackerStateHold):
                    state_owner.current_k(writer, **context)
        with self.assertRaises(state_owner.TrackerStateHold):
            state_owner.current_k(writer, spreadsheet_token=owner, binding=bound, completed_unit=unit)
        self.assertFalse(projection.exists())

    def test_missing_delivery_never_makes_highest_k_usable(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_state_owner as state_owner
        with ExitStack() as stack:
            writer, owner, bound, unit = self.completed(stack)
            allocation.record_completed_settings_delivery(writer, owner, bound, unit)
            tracker=self.root/'project/.tracker'
            (tracker/'settings-audit-delivery/DELIVERED').rename(self.root/'preserved-k-delivery')
            (tracker/'settings/outbox/0.json').rename(self.root/'preserved-k-projection')
            original={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
            with self.assertRaises(state_owner.TrackerStateHold):
                state_owner.current_k(writer, spreadsheet_token=owner, binding=bound, completed_unit=unit)
            self.assertEqual(original,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_original_pair_reads_highest_k_without_restoring_delivered_projection(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_state_owner as state_owner
        from monitor import issue_tracker_k_store as settings
        with ExitStack() as stack:
            writer, owner, bound, unit = self.completed(stack)
            # Actual immutable revision 1 remains unconsumed. Highest K=4 is
            # independently authored, never derived from the delivery result.
            settings.apply_local_k_change(self.root / 'project/.tracker', token=writer,
                new_k=4, actor='operator:fixture', recorded_at='2026-10-08T10:01:00Z',
                request_id='change-1', expected_revision=0)
            allocation.record_completed_settings_delivery(writer, owner, bound, unit)
            projection = self.root / 'project/.tracker/settings/outbox/0.json'
            projection.rename(self.root / 'preserved-projection-for-k-read')
            original = {str(p.relative_to(self.root)): p.read_bytes()
                        for p in self.root.rglob('*') if p.is_file()}
            with self.assertRaises(state_owner.TrackerStateHold):
                state_owner.current_k(writer)
            seen = state_owner.current_k(writer, spreadsheet_token=owner,
                binding=bound, completed_unit=unit)
            self.assertEqual((1, 4), (seen.revision, seen.k))
            self.assertEqual(original, {str(p.relative_to(self.root)): p.read_bytes()
                        for p in self.root.rglob('*') if p.is_file()})
            self.assertFalse(projection.exists())
            self.assertTrue((projection.parent / '1.json').is_file())
            observed = self.current_global_state(owner, bound, unit)
            self.assertEqual((1, 'UNKNOWN'), (observed.attempt_count, observed.outcome))

    def test_actual_complete_and_delivered_allow_only_their_absent_projection(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer,owner,bound,unit=self.completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            projection=self.root/'project/.tracker/settings/outbox/0.json'
            retained=self.root/'preserved-original-delivered-projection'
            projection.rename(retained)
            # C25 K5-C's literal expectation: an absent delivered projection is
            # valid only with the actual COMPLETE+DELIVERED pair. No cleanup
            # implementation or resending is faked by this owned loss fixture.
            self.assertEqual((),allocation.pending_settings_audits_after_completed_unit(writer,owner,bound,unit))
            self.assertEqual('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',
                allocation.inspect_completed_settings_delivery(writer,owner,bound,unit).state)
            self.assertTrue(retained.is_file()); self.assertFalse(projection.exists())
            self.assertEqual((1,'UNKNOWN'),(self.current_global_state(owner,bound,unit).attempt_count,
                                           self.current_global_state(owner,bound,unit).outcome))

    def test_partial_delivered_projection_pair_never_changes_original_audit_set(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_k_store as settings
        event0=self.settings_audit_oracle()
        payload={'new_k':4,'actor':'operator:fixture','expected_revision':0,'request_id':'change-1'}
        event=canonical({'schema_version':1,'revision':1,'type':'set_k','old_k':3,'new_k':4,
            'actor':'operator:fixture','recorded_at':'2026-10-08T10:01:00Z','request_id':'change-1',
            'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
            'predecessor_sha256':hashlib.sha256((event0['details']+'\n').encode()).hexdigest()})
        event1={'event_id':'settings:1:'+hashlib.sha256(event).hexdigest(),
            'recorded_at_utc':'2026-10-08T10:01:00Z','details':event.decode().rstrip('\n')}
        initialize=settings.initialize_local_k_store
        def initialized_then_change(root,**options):
            receipt=initialize(root,**options)
            settings.apply_local_k_change(root,token=options['token'],new_k=4,
                actor='operator:fixture',recorded_at='2026-10-08T10:01:00Z',
                request_id='change-1',expected_revision=0)
            return receipt
        with ExitStack() as stack:
            with mock.patch.object(settings,'initialize_local_k_store',side_effect=initialized_then_change):
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(event0,event1))
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            load().record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            projection=self.root/'project/.tracker/settings/outbox/0.json'
            projection.rename(self.root/'preserved-original-projection-0')
            observed=allocation.inspect_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual(('DELIVERED-PRESENT-OUTBOX-PARTIAL-VALID',(event0['event_id'],event1['event_id'])),
                (observed.state,observed.event_ids))
            self.assertEqual((),allocation.pending_settings_audits_after_completed_unit(writer,owner,bound,unit))
            self.assertFalse(projection.exists())
            self.assertTrue((projection.parent/'1.json').is_file())
            self.assertEqual((1,'UNKNOWN'),(self.current_global_state(owner,bound,unit).attempt_count,
                                           self.current_global_state(owner,bound,unit).outcome))

    def absence_denied(self,fault):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer,owner,bound,unit=self.completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            tracker=self.root/'project/.tracker'
            projection=tracker/'settings/outbox/0.json'
            if fault=='later-unproved-event':
                from monitor import issue_tracker_k_store as settings
                settings.apply_local_k_change(tracker,token=writer,new_k=4,actor='operator:fixture',
                    recorded_at='2026-10-08T10:01:00Z',request_id='change-1',expected_revision=0)
                projection=tracker/'settings/outbox/1.json'
            elif fault=='missing-delivered':
                (tracker/'settings-audit-delivery/DELIVERED').rename(self.root/'preserved-marker')
            elif fault=='missing-start':
                (tracker/'SETTINGS-AUDIT-DELIVERY-STARTED').rename(self.root/'preserved-start')
            elif fault=='changed-complete':
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                (proof/'HISTORY-RAW').write_bytes(b'{"not":"the matched original History"}')
            else: raise AssertionError('unknown independent fault')
            projection.rename(self.root/'preserved-projection')
            original={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
            for observe in (allocation.inspect_completed_settings_delivery,
                            allocation.pending_settings_audits_after_completed_unit):
                with self.subTest(observer=observe.__name__),self.assertRaises(allocation.SettingsAuditHold):
                    observe(writer,owner,bound,unit)
            self.assertEqual(original,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
            self.assertFalse(projection.exists())

    def test_missing_delivery_never_excuses_absent_projection(self): self.absence_denied('missing-delivered')
    def test_missing_start_never_excuses_absent_projection(self): self.absence_denied('missing-start')
    def test_nonsemantic_complete_never_excuses_absent_projection(self): self.absence_denied('changed-complete')
    def test_later_undelivered_event_still_requires_its_projection(self): self.absence_denied('later-unproved-event')

    def test_actual_cold_pair_retains_missing_delivered_projection_without_resend(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from dataclasses import asdict
        import json
        import subprocess
        with ExitStack() as stack:
            writer,owner,bound,unit=self.completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            projection=self.root/'project/.tracker/settings/outbox/0.json'
            projection.rename(self.root/'preserved-cold-projection')
        # Parent owners are closed before a fresh interpreter acquires its own
        # locks. Native original files, not a copied object or cached registry.
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_settings_audit_allocation as allocation
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor import issue_tracker_spreadsheet_owner as owner,issue_tracker_local_commit as local
from monitor import issue_tracker_global_attempt_journal as journal
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
store=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((store/'ACTION-PREIMAGE').read_bytes(),(store/'WIRE').read_bytes())
with local.writer_owner(root/'project',root/'project/publication') as writer,scoped_fixture(root,owner),owner.spreadsheet_owner(bound) as token:
 seen=allocation.inspect_completed_settings_delivery(writer,token,bound,unit)
 pending=allocation.pending_settings_audits_after_completed_unit(writer,token,bound,unit)
 state=journal.inspect_global_unit(token,bound,unit)
 print(seen.state,len(pending),state.attempt_count,state.outcome)
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],input=json.dumps(asdict(bound)).encode(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'DELIVERED-PRESENT-OUTBOX-ABSENT-VALID 0 1 UNKNOWN\n',cold.stdout)
        self.assertFalse(projection.exists()); self.assertTrue((self.root/'preserved-cold-projection').is_file())

    def settings_audit_oracle(self):
        # Literal original EVENT contract, never derived from allocation/delivery.
        payload={'new_k':3,'actor':'system:default','expected_revision':None,'request_id':'first-use'}
        event=canonical({'schema_version':1,'revision':0,'type':'init','old_k':None,'new_k':3,
            'actor':'system:default','recorded_at':'2026-10-08T10:00:00Z','request_id':'first-use',
            'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),'predecessor_sha256':None})
        return {'event_id':'settings:0:'+hashlib.sha256(event).hexdigest(),
            'recorded_at_utc':'2026-10-08T10:00:00Z','details':event.decode().rstrip('\n')}

    def native_audit_completed(self, stack, *, fixture_facts=None):
        """Actual native C6/NV originals and four child/TLS completion reads.

        Expectations originate in literal cabling/business/event inputs, not
        the matcher, catalog WIRE or a fabricated COMPLETE observation.
        """
        from test_cases.test_req7_unit_catalog import load as load_catalog
        from test_cases.test_req7_nv_reservation import load as load_nv, cabling_inputs, source, KEYS
        from test_cases.test_req7_settings_audit_allocation import load as load_allocation
        from test_cases.test_req7_retained_global_inventory import load as load_inventory
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        from test_cases.test_req7_sheets_read_decode import header_response
        load_global(); load_enrollment(); load_before()
        nv=load_nv(); catalog=load_catalog(reset_dependencies=False)
        allocation=load_allocation(); completion=load()
        # Earlier suites may have captured an obsolete owner/GLOBAL registry.
        # Refresh the actual consumer before issuance, never adopt a token or
        # replace a registry after any original owner has been acquired.
        load_inventory(reset_support=False)
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_sheets_read_decode as decode, issue_tracker_k_store as settings
        from monitor import issue_tracker_enrollment_journal as enrollment, issue_tracker_global_attempt_journal as journal
        from monitor import issue_tracker_history_preread_journal as preread
        local,_ownership,writer,owner,bound,auth,_config=self.owners(stack,target_id=TARGET)
        audit=self.settings_audit_oracle()
        settings.initialize_local_k_store(self.root/'project/.tracker',token=writer,
            initialized_at='2026-10-08T10:00:00Z',acquisition_id='first-use')
        identity_doc=identity_response(); identity_doc['spreadsheetId']=bound.spreadsheet_id
        identity=decode.decode_template_identity(reads._prepare(bound,auth,'template_identity',None,None),response(identity_doc))
        with mock.patch('secrets.token_hex',side_effect=['a'*64,'b'*64,'c'*64,'d'*64]):
            enrolled=enrollment.prepare_enrollment_journal(owner,bound,identity)
        arguments=cabling_inputs(enrolled.nonces); arguments['audits']=(audit,)
        generation=local.begin_generation(writer,arguments['manifest'])
        local.record_intent(writer,generation,literal_xlsx(),kind='xlsx')
        receipt=local.commit(writer,generation)
        arguments.update(generation_id=generation.generation_id,publish_id=receipt.published_sha256)
        unit=catalog.composer.freeze_send_unit(**arguments)
        eth_plan=reads._prepare(bound,auth,'activity','ETH Cabling',None)
        ib_plan=reads._prepare(bound,auth,'activity','IB Cabling',None)
        with nv.hold_catalog_nv_preparation(owner,bound,identity,
                eth_plan,source('ETH Cabling',('NV30016',)),ib_plan,source('IB Cabling',('NV30101',)),
                generation_id=generation.generation_id,publish_id=receipt.published_sha256,
                sheet='ETH Cabling',requested_keys=KEYS) as prepared:
            catalog.register_pending_c6_unit(writer,owner,bound,unit,_nv_preparation=prepared)
        journal.prepare_global_unit(owner,bound,unit)
        stem=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
        allocated=self.root/'var/lib/http-ztp-container/issue-tracker'/(stem+'.unit-'+unit.unit_id+'.settings-audit')
        self.assertEqual({'HEADER','ASSIGNMENTS','INITIALIZED'},{p.name for p in allocated.iterdir()})
        self.assertFalse((self.root/'project/.tracker/settings-audit-allocation').exists())
        self.assertFalse((self.root/'project/.tracker/SETTINGS-AUDIT-ALLOCATED').exists())
        native_images={name:(allocated/name).read_bytes() for name in ('HEADER','ASSIGNMENTS')}
        empty=tail_document(12); empty['spreadsheetId']=bound.spreadsheet_id
        empty['sheets'][0]['properties']['sheetId']=105; empty['sheets'][0]['data'][0]['rowData']=[]
        original=self.read_owned(stack,writer,owner,bound,auth,'history_tail',empty)
        plan=reads.require_current_owned_read(writer,owner,bound,original,read_kind='history_tail')
        preread.prepare_history_preread(owner,bound,unit,plan,original)
        journal.record_global_attempt_intent(owner,bound,unit)
        common={'schema_version':1,'unit_id':unit.unit_id,'manifest_id':arguments['manifest_id'],
            'generation_id':arguments['generation_id'],'publish_id':arguments['publish_id'],
            'action_digest':unit.action_digest,'outcome_mapping_sha256':unit.outcome_mapping_sha256,
            'target_nonce':'b'*64,'history_nonce':'d'*64,'preread_sha256':'e'*64}
        rows=[]
        for item in arguments['business']:
            intended=hashlib.sha256(canonical({'sheet':'ETH Cabling','sheet_id':102,'action':'insert',
                'row_index':None,'values':{column:{'stringValue':value}
                    for column,value in item['values'].items()}})).hexdigest()
            rows.append((item['recorded_at_utc'],'ETH Cabling','insert',item['operation_id'],
                canonical({**common,'operation_id':item['operation_id'],'intended_sha256':intended}).decode().rstrip('\n')))
        rows.append((audit['recorded_at_utc'],'ETH Cabling','settings-audit',audit['event_id'],
            canonical({**common,'event_id':audit['event_id'],'event_details':audit['details']}).decode().rstrip('\n')))
        post=deepcopy(empty)
        post['sheets'][0]['data'][0]['rowData']=[{'values':[{'userEnteredValue':{'stringValue':text}} for text in row]} for row in rows]
        metadata={'matchedDeveloperMetadata':[
            {'developerMetadata':{'metadataId':1,'metadataKey':'http-ztp-enrollment-v1','metadataValue':'b'*64,
                'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':102}}},
            {'developerMetadata':{'metadataId':2,'metadataKey':'http-ztp-enrollment-v1','metadataValue':'d'*64,
                'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':105}}},
            {'developerMetadata':{'metadataId':unit.fence_metadata_id,'metadataKey':'z','metadataValue':'1',
                'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':102}}}]}
        headers=header_response(); headers['spreadsheetId']=bound.spreadsheet_id
        documents={'identity_response':('template_identity',identity_doc),'headers_response':('template_headers',headers),
            'metadata_response':('metadata',metadata),'history_response':('history_tail',post)}
        responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
            for name,(kind,value) in documents.items()}
        completion.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
        self.assertEqual('COMPLETE-PRESENT-NOT-APPLIED',completion.inspect_completion_evidence(owner,bound,unit).state)
        if fixture_facts is not None:
            # Fixture orchestration only: genuine returned generation/auth and
            # independently authored source/History documents, never a permit.
            fixture_facts.update(generation=generation,auth=auth,identity=identity,nonces=enrolled.nonces,
                identity_doc=identity_doc,post=post,metadata=metadata,headers=headers)
        return allocation,writer,owner,bound,unit,allocated,native_images

    def test_native_complete_delivery_header_binds_actual_catalog_audit_originals(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,unit,allocated,images=self.native_audit_completed(stack)
            immutable={str(p.relative_to(self.root)):(p.stat().st_ino,p.read_bytes())
                for p in self.root.rglob('*') if p.is_file()}
            from monitor import issue_tracker_mutation_launcher as mutation
            with mock.patch.object(mutation,'_send_counted_original_once') as send:
                result=allocation.record_completed_settings_delivery(writer,owner,bound,unit)
                header=json.loads((self.root/'project/.tracker/settings-audit-delivery/HEADER').read_bytes())['complete_allocation']
                self.assertEqual(hashlib.sha256(images['HEADER']).hexdigest(),header['allocation_header_sha256'])
                self.assertEqual(hashlib.sha256(images['ASSIGNMENTS']).hexdigest(),header['assignments_sha256'])
                self.assertEqual((self.settings_audit_oracle()['event_id'],),result.event_ids)
                self.assertEqual((),allocation.pending_settings_audits_after_completed_unit(writer,owner,bound,unit))
                send.assert_not_called()
            for name,(inode,raw) in immutable.items():
                path=self.root/name; self.assertEqual((inode,raw),(path.stat().st_ino,path.read_bytes()))
            seen=self.current_global_state(owner,bound,unit)
            self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome))
            self.assertTrue((self.root/'project/.tracker/settings/outbox/0.json').exists())

    def test_native_delivery_same_bytes_allocation_rebind_refuses_before_marker(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,unit,allocated,images=self.native_audit_completed(stack)
            original=allocation._hold_native_catalog_audit_originals; reached=[]
            path=allocated/'ASSIGNMENTS'; saved=self.root/'preserved-native-delivery-assignment'
            journal_path=allocated.parent/(allocated.name[:-len('.settings-audit')]+'.journal')
            retained={name:((journal_path/name).stat().st_ino,(journal_path/name).read_bytes())
                for name in ('ATTEMPT-1','WIRE','ACTION-PREIMAGE','HEADER','INITIALIZED')}
            @contextmanager
            def rebind(*args,**options):
                with original(*args,**options) as held:
                    if held is not None and not reached:
                        before=path.stat().st_ino; path.rename(saved)
                        path.write_bytes(images['ASSIGNMENTS']); path.chmod(0o600)
                        reached.append((before,path.stat().st_ino))
                    yield held
            with mock.patch.object(allocation,'_hold_native_catalog_audit_originals',side_effect=rebind):
                with self.assertRaises(allocation.SettingsAuditHold):
                    allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual(1,len(reached)); self.assertNotEqual(*reached[0])
            self.assertEqual(images['ASSIGNMENTS'],saved.read_bytes()); self.assertEqual(saved.read_bytes(),path.read_bytes())
            self.assertFalse((self.root/'project/.tracker/settings-audit-delivery/DELIVERED').exists())
            self.assertTrue((self.root/'project/.tracker/settings/outbox/0.json').exists())
            self.assertEqual(set(retained),{p.name for p in journal_path.iterdir()})
            self.assertEqual(retained,{name:((journal_path/name).stat().st_ino,(journal_path/name).read_bytes())
                for name in retained})
            from monitor import issue_tracker_global_attempt_journal as journal
            with self.assertRaises(journal.GlobalAttemptHold):
                self.current_global_state(owner,bound,unit)

    def test_native_complete_delivery_archives_only_original_outbox_projection(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,unit,allocated,images=self.native_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            tracker=self.root/'project/.tracker'; projection=(tracker/'settings/outbox/0.json').read_bytes()
            originals={str(p.relative_to(self.root)):(p.stat().st_ino,p.read_bytes())
                for p in self.root.rglob('*') if p.is_file() and p!=tracker/'settings/outbox/0.json'}
            before={p.name for p in (tracker/'quarantine').iterdir()}
            from monitor import issue_tracker_mutation_launcher as mutation
            with mock.patch.object(mutation,'_send_counted_original_once') as send:
                result=allocation.cleanup_completed_settings_outbox(writer,owner,bound,unit)
                self.assertEqual(('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',(self.settings_audit_oracle()['event_id'],)),
                    (result.state,result.event_ids))
                self.assertEqual((),allocation.pending_settings_audits_after_completed_unit(writer,owner,bound,unit))
                send.assert_not_called()
            archived=[p for p in (tracker/'quarantine').iterdir() if p.name not in before]
            self.assertEqual(1,len(archived)); self.assertEqual(projection,archived[0].read_bytes())
            self.assertEqual(0o600,archived[0].stat().st_mode & 0o777)
            self.assertFalse((tracker/'settings/outbox/0.json').exists())
            for name,(inode,raw) in originals.items():
                path=self.root/name; self.assertEqual((inode,raw),(path.stat().st_ino,path.read_bytes()))
            seen=self.current_global_state(owner,bound,unit)
            self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome))

    def test_native_delivery_paired_k_append_and_archive_preserve_original_count_and_events(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,unit,allocated,images=self.native_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            tracker=self.root/'project/.tracker';old=(tracker/'settings/events/0.json').read_bytes()
            payload={'new_k':6,'actor':'operator:fixture','expected_revision':0,'request_id':'native-after-delivery'}
            expected=canonical({'schema_version':1,'revision':1,'type':'set_k','old_k':3,'new_k':6,
                'actor':'operator:fixture','recorded_at':'2026-10-08T10:01:00Z','request_id':'native-after-delivery',
                'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
                'predecessor_sha256':hashlib.sha256(old).hexdigest()})
            options=dict(new_k=6,actor='operator:fixture',recorded_at='2026-10-08T10:01:00Z',
                request_id='native-after-delivery',expected_revision=0)
            receipt=allocation.apply_completed_k_change(writer,owner,bound,unit,**options)
            digest=hashlib.sha256(expected).hexdigest()
            self.assertEqual((1,6,digest,False),(receipt.revision,receipt.k,receipt.event_sha256,receipt.replay))
            self.assertEqual(expected,(tracker/'settings/events/1.json').read_bytes())
            pending=(tracker/'settings/outbox/1.json').read_bytes()
            allocation.cleanup_completed_settings_outbox(writer,owner,bound,unit)
            self.assertEqual(pending,(tracker/'settings/outbox/1.json').read_bytes())
            self.assertEqual(('settings:1:'+digest,),tuple(row['event_id'] for row in
                allocation.pending_settings_audits_after_completed_unit(writer,owner,bound,unit)))
            replay=allocation.apply_completed_k_change(writer,owner,bound,unit,**options)
            self.assertTrue(replay.replay)
            current=allocation.read_current_k_after_completed_unit(writer,owner,bound,unit)
            self.assertEqual((1,6),(current.revision,current.k))
            self.assertEqual(old,(tracker/'settings/events/0.json').read_bytes())
            for name,raw in images.items():self.assertEqual(raw,(allocated/name).read_bytes())
            seen=self.current_global_state(owner,bound,unit)
            self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome))

    def native_delivery_cold_replay(self, *, discovered=False):
        from dataclasses import asdict
        import subprocess
        with ExitStack() as stack:
            allocation,writer,owner,bound,unit,allocated,images=self.native_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            tracker=self.root/'project/.tracker';original=(tracker/'settings/events/0.json').read_bytes()
            projection=(tracker/'settings/outbox/0.json').read_bytes()
        before={p.name for p in (tracker/'quarantine').iterdir()}
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from monitor import issue_tracker_settings_audit_allocation as allocation
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]);project=root/'project';tracker=project/'.tracker'
bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
folder=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.units')/sys.argv[3]
unit=_original_unit((folder/'ACTION-PREIMAGE').read_bytes(),(folder/'WIRE').read_bytes())
with scoped_fixture(root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
 owner=state._COMPLETED_READ_CONTEXT[token][0]
 result=allocation.cleanup_completed_settings_outbox(token,owner,bound,unit)
 current=state.current_k(token);pending=allocation.pending_settings_audits_after_completed_unit(token,owner,bound,unit)
 print(result.state,current.revision,current.k,len(pending))
 before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
 again=allocation.cleanup_completed_settings_outbox(token,owner,bound,unit)
 print(result==again,before=={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
'''
        if discovered:
            # The fresh process is given only project coordinates, not a
            # binding/unit, parent token registry or reconstructed authority.
            start=program.index('bound=OnlineTargetBinding(')
            end=program.index(' result=allocation.cleanup_completed_settings_outbox')
            program=program[:start]+'''assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}
with scoped_fixture(root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
 owner,bound,unit=state._COMPLETED_READ_CONTEXT[token]
'''+program[end:]
            arguments=[sys.executable,'-B','-c',program,str(ROOT),str(self.root)]
            payload=b''
        else:
            arguments=[sys.executable,'-B','-c',program,str(ROOT),str(self.root),unit.unit_id]
            payload=json.dumps(asdict(bound)).encode()
        program+='assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}\n'
        arguments[3]=program
        cold=subprocess.run(arguments,input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'DELIVERED-PRESENT-OUTBOX-ABSENT-VALID 0 3 0\nTrue True\n',cold.stdout)
        self.assertEqual(original,(tracker/'settings/events/0.json').read_bytes())
        self.assertFalse((tracker/'settings/outbox/0.json').exists())
        archives=[p for p in (tracker/'quarantine').iterdir() if p.name not in before]
        self.assertEqual(1,len(archives));self.assertEqual(projection,archives[0].read_bytes())
        for name,raw in images.items():self.assertEqual(raw,(allocated/name).read_bytes())

    def test_native_catalog_audit_delivery_cold_process_archives_and_replays_original_pair(self):
        self.native_delivery_cold_replay()

    def test_native_default_cold_settings_entry_discovers_actual_delivery_without_parent_coordinates(self):
        self.native_delivery_cold_replay(discovered=True)

    def native_default_delivered_fixture(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,unit,allocated,images=self.native_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            allocation.cleanup_completed_settings_outbox(writer,owner,bound,unit)
        return self.root/'project',allocated

    def native_default_refused_without_repair(self, project):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        before=self._default_recovery_images(project);yielded=[]
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,project/'publication'):
                yielded.append(True)
        self.assertEqual([],yielded)
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_native_default_locator_tampered_unit_never_releases_missing_projection(self):
        project,_allocated=self.native_default_delivered_fixture()
        path=project/'.tracker/settings-audit-delivery/HEADER';body=json.loads(path.read_bytes())
        body['complete_allocation']['native_allocation_header']['unit_id']='f'*64
        path.write_bytes(canonical(body));path.chmod(0o600)
        self.native_default_refused_without_repair(project)

    def test_native_default_locator_recomputed_hash_foreign_project_still_refuses(self):
        project,_allocated=self.native_default_delivered_fixture()
        path=project/'.tracker/settings-audit-delivery/HEADER';body=json.loads(path.read_bytes())
        image=body['complete_allocation']['native_allocation_header']
        image['project_identity'][1]+=1
        body['complete_allocation']['allocation_header_sha256']=hashlib.sha256(canonical(image)).hexdigest()
        path.write_bytes(canonical(body));path.chmod(0o600)
        self.native_default_refused_without_repair(project)

    def test_native_default_missing_native_anchor_never_uses_valid_shadow_legacy_allocation(self):
        project,allocated=self.native_default_delivered_fixture()
        tracker=project/'.tracker';shadow=tracker/'settings-audit-allocation';shadow.mkdir(mode=0o700)
        # Even byte-identical local shadows do not replace the actual shared
        # catalog anchor or its original project/C6 provenance.
        for path in allocated.iterdir():
            target=shadow/path.name;target.write_bytes(path.read_bytes());target.chmod(0o600)
        allocated.rename(self.root/'preserved-native-default-allocation')
        self.native_default_refused_without_repair(project)

    def test_native_default_removed_native_locator_never_adopts_legacy_shadow(self):
        project,allocated=self.native_default_delivered_fixture()
        tracker=project/'.tracker';shadow=tracker/'settings-audit-allocation';shadow.mkdir(mode=0o700)
        for path in allocated.iterdir():
            target=shadow/path.name;target.write_bytes(path.read_bytes());target.chmod(0o600)
        path=tracker/'settings-audit-delivery/HEADER';body=json.loads(path.read_bytes())
        body['complete_allocation'].pop('native_allocation_header')
        path.write_bytes(canonical(body));path.chmod(0o600)
        self.native_default_refused_without_repair(project)

    def native_default_original_replacement_refuses(self, *, allocation_header):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        project,allocated=self.native_default_delivered_fixture();tracker=project/'.tracker'
        header=allocated/'HEADER' if allocation_header else tracker/'settings-audit-delivery/HEADER'
        reached=[];reads=[]
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,project/'publication') as token:
                self.assertEqual((0,3),(state.current_k(token).revision,state.current_k(token).k))
                original=(header.stat().st_ino,header.read_bytes())
                header.rename(self.root/'preserved-native-default-header')
                header.write_bytes(original[1]);header.chmod(0o600)
                reached.append((original[0],header.stat().st_ino))
                with self.assertRaises(state.TrackerStateHold):
                    reads.append(state.current_k(token))
                with self.assertRaises(state.TrackerStateHold):
                    state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-09T00:00:00Z',
                        request_id='native-discovery-rebind',expected_revision=0)
        self.assertEqual(1,len(reached));self.assertNotEqual(*reached[0]);self.assertEqual([],reads)
        self.assertFalse((tracker/'settings/events/1.json').exists())
        self.assertFalse((tracker/'settings/outbox/0.json').exists())
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_native_default_held_delivery_header_same_bytes_rebind_stops_read_and_k_commit(self):
        self.native_default_original_replacement_refuses(allocation_header=False)

    def test_native_default_held_allocation_header_same_bytes_rebind_stops_read_and_k_commit(self):
        self.native_default_original_replacement_refuses(allocation_header=True)

    def test_native_default_locator_revalidates_after_actual_pair_last_finalizer(self):
        project,_allocated=self.native_default_delivered_fixture()
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        header=project/'.tracker/settings-audit-delivery/HEADER'
        actual=allocation._hold_completed_k_pair;armed=[];reached=[]
        @contextmanager
        def after_actual_pair(*args,**options):
            with actual(*args,**options) as original:
                yield original
            if armed and not reached:
                prior=(header.stat().st_ino,header.read_bytes())
                header.rename(self.root/'preserved-last-native-locator')
                header.write_bytes(prior[1]);header.chmod(0o600)
                reached.append((prior[0],header.stat().st_ino))
        with scoped_fixture(self.root,sheet),mock.patch.object(allocation,'_hold_completed_k_pair',side_effect=after_actual_pair), \
                self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,project/'publication') as token:
                self.assertEqual((0,3),(state.current_k(token).revision,state.current_k(token).k))
                armed.append(True)
        self.assertEqual(1,len(reached));self.assertNotEqual(*reached[0])
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        self.assertFalse((project/'.tracker/settings/events/1.json').exists())
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())

    def test_native_default_unknown_partial_claim_after_actual_pair_finalizer_refuses(self):
        project,_allocated=self.native_default_delivered_fixture()
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        tracker=project/'.tracker';actual=allocation._hold_completed_k_pair;armed=[];reached=[]
        partial=tracker/('SETTINGS-AUDIT-DELIVERY-STARTED-'+'f'*64)
        @contextmanager
        def after_actual_pair(*args,**options):
            with actual(*args,**options) as original:
                yield original
            if armed and not reached:
                partial.write_bytes(b'literal-incomplete-delivery-claim\n');partial.chmod(0o600)
                reached.append(partial.stat().st_ino)
        with scoped_fixture(self.root,sheet),mock.patch.object(allocation,'_hold_completed_k_pair',side_effect=after_actual_pair), \
                self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,project/'publication') as token:
                self.assertEqual((0,3),(state.current_k(token).revision,state.current_k(token).k))
                armed.append(True)
        self.assertEqual(1,len(reached));self.assertEqual(b'literal-incomplete-delivery-claim\n',partial.read_bytes())
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        self.assertFalse((tracker/'settings/events/1.json').exists())
        self.assertFalse((tracker/'settings/outbox/0.json').exists())

    def native_second_audit_completed(self, stack, *, fixture_facts=None, archive_before_new=False,late_fault=None,
                                     preparation_k_probe=None):
        """Two real same-project native C6 units; first genuinely APPLIED/key.

        Retain outbox0 while constructing the second. This does not pretend
        that ALL historical DELIVERED interpretation is already integrated.
        """
        facts={}
        allocation,writer,owner,bound,first,allocated,images=self.native_audit_completed(stack,fixture_facts=facts)
        from monitor import issue_tracker_unit_catalog as catalog,issue_tracker_nv_reservation as nv
        from monitor import issue_tracker_remote_history_match as completion,issue_tracker_global_attempt_journal as journal
        from monitor import issue_tracker_history_read_launcher as reads,issue_tracker_history_preread_journal as preread
        from test_cases.test_req7_nv_reservation import cabling_inputs,source,KEYS
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        completion.record_owned_applied_evidence(writer,owner,bound,first,generation=facts['generation'])
        completion.record_owned_applied_key_watermarks(writer,owner,bound,first,generation=facts['generation'])
        allocation.record_completed_settings_delivery(writer,owner,bound,first)
        if archive_before_new:
            # Independent physical-order boundary: no second C6/NV/catalog
            # exists when this actual first event is retired. Existing callers
            # retain their original pre-archive second-unit fixture contract.
            tracker=self.root/'project/.tracker'
            original=(tracker/'settings/outbox/0.json').stat().st_ino,(tracker/'settings/outbox/0.json').read_bytes()
            allocation.cleanup_completed_settings_outbox(writer,owner,bound,first)
            self.assertFalse((tracker/'settings/outbox/0.json').exists())
            self.assertEqual(1,sum((p.stat().st_ino,p.read_bytes())==original
                for p in (tracker/'quarantine').iterdir() if p.is_file()))
            actual_prepare=allocation._prepare_native_catalog_allocation
            def diagnose_native_creation(*args,**kwargs):
                if late_fault is not None:
                    original_preparation=nv._verify_catalog_preparation(args[0])
                    fixture_facts['old']=original_preparation['old']
                    fixture_facts['first_journal']=self.root/'var/lib/http-ztp-container/issue-tracker'/(
                        original_preparation['stem']+'.unit-'+first.unit_id+'.journal')
                    fixture_facts['old_count_images']={p.name:(p.stat().st_ino,p.read_bytes())
                        for p in fixture_facts['first_journal'].iterdir() if p.is_file()}
                try:return actual_prepare(*args,**kwargs)
                except BaseException:
                    import traceback
                    traceback.print_exc()
                    raise
            stack.enter_context(mock.patch.object(allocation,'_prepare_native_catalog_allocation',
                side_effect=diagnose_native_creation))
            if late_fault is not None:
                actual_close=catalog._Originals.close
                def last_nv_old_close(original):
                    result=actual_close(original)
                    if original is fixture_facts.get('old') and not fixture_facts.get('reached'):
                        fixture_facts['reached']=True
                        shared=self.root/'var/lib/http-ztp-container/issue-tracker'
                        stem=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                        if late_fault=='delivery-header':
                            path=tracker/'settings-audit-delivery/HEADER';raw=path.read_bytes()
                            fixture_facts['before_inode']=path.stat().st_ino
                            path.rename(self.root/'retained-old-allocation-delivery-header')
                            path.write_bytes(raw);path.chmod(0o600)
                            fixture_facts['path']=path
                        else:
                            path=shared/(stem+'.unissued-tail') if late_fault=='shared-extra' else shared/(stem+'.units/UNISSUED-TAIL')
                            path.write_bytes(b'literal foreign tail preserved\n');path.chmod(0o600)
                            fixture_facts['path']=path
                    return result
                stack.enter_context(mock.patch.object(catalog._Originals,'close',last_nv_old_close))
        allocation.apply_completed_k_change(writer,owner,bound,first,new_k=7,actor='operator:fixture',
            recorded_at='2026-10-08T10:01:00Z',request_id='catalog-later-k',expected_revision=0)
        tracker=self.root/'project/.tracker'
        first_projection=None if archive_before_new else (
            (tracker/'settings/outbox/0.json').stat().st_ino,(tracker/'settings/outbox/0.json').read_bytes())
        first_delivery={p.name:(p.stat().st_ino,p.read_bytes()) for p in (tracker/'settings-audit-delivery').iterdir()}
        audit=self.catalog_later_settings_audit_oracle()
        arguments=cabling_inputs(facts['nonces'],identifiers=('NV30104','NV30105'));arguments['audits']=(audit,)
        arguments['occupied_metadata_ids']=(first.fence_metadata_id,)
        generation=catalog.local.begin_generation(writer,arguments['manifest'])
        catalog.local.record_intent(writer,generation,literal_xlsx(),kind='xlsx')
        receipt=catalog.local.commit(writer,generation)
        self.assertEqual(2,generation.sequence)
        arguments.update(generation_id=generation.generation_id,publish_id=receipt.published_sha256)
        second=catalog.composer.freeze_send_unit(**arguments)
        self.assertNotEqual(first.unit_id,second.unit_id)
        eth_plan=reads._prepare(bound,facts['auth'],'activity','ETH Cabling',None)
        ib_plan=reads._prepare(bound,facts['auth'],'activity','IB Cabling',None)
        preparation_probe_assertion=None
        with nv.hold_catalog_nv_preparation(owner,bound,facts['identity'],
                eth_plan,source('ETH Cabling',('NV30016',)),ib_plan,source('IB Cabling',('NV30101',)),
                generation_id=generation.generation_id,publish_id=receipt.published_sha256,
                sheet='ETH Cabling',requested_keys=KEYS) as prepared:
            self.assertEqual(((KEYS[0],'NV30104'),(KEYS[1],'NV30105')),prepared.observation.reservations)
            if preparation_k_probe is not None:
                # Keep the independent assertion outside production's typed
                # refusal sanitizer; all real registration/finalizers still run.
                try: preparation_k_probe(allocation,writer,owner,bound,prepared,tracker)
                except AssertionError as exc: preparation_probe_assertion=exc
            catalog.register_pending_c6_unit(writer,owner,bound,second,_nv_preparation=prepared)
        if preparation_probe_assertion is not None:raise preparation_probe_assertion
        journal.prepare_global_unit(owner,bound,second)
        original=self.read_owned(stack,writer,owner,bound,facts['auth'],'history_tail',facts['post'])
        plan=reads.require_current_owned_read(writer,owner,bound,original,read_kind='history_tail')
        preread.prepare_history_preread(owner,bound,second,plan,original)
        journal.record_global_attempt_intent(owner,bound,second)
        common={'schema_version':1,'unit_id':second.unit_id,'manifest_id':arguments['manifest_id'],
            'generation_id':arguments['generation_id'],'publish_id':arguments['publish_id'],
            'action_digest':second.action_digest,'outcome_mapping_sha256':second.outcome_mapping_sha256,
            'target_nonce':'b'*64,'history_nonce':'d'*64,'preread_sha256':'e'*64}
        rows=[]
        for item in arguments['business']:
            intended=hashlib.sha256(canonical({'sheet':'ETH Cabling','sheet_id':102,'action':'insert',
                'row_index':None,'values':{column:{'stringValue':value}
                    for column,value in item['values'].items()}})).hexdigest()
            rows.append((item['recorded_at_utc'],'ETH Cabling','insert',item['operation_id'],
                canonical({**common,'operation_id':item['operation_id'],'intended_sha256':intended}).decode().rstrip('\n')))
        rows.append((audit['recorded_at_utc'],'ETH Cabling','settings-audit',audit['event_id'],
            canonical({**common,'event_id':audit['event_id'],'event_details':audit['details']}).decode().rstrip('\n')))
        post=deepcopy(facts['post'])
        post['sheets'][0]['data'][0]['rowData'].extend(
            {'values':[{'userEnteredValue':{'stringValue':text}} for text in row]} for row in rows)
        metadata=deepcopy(facts['metadata'])
        metadata['matchedDeveloperMetadata'].append({'developerMetadata':{'metadataId':second.fence_metadata_id,
            'metadataKey':'z','metadataValue':'1','visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':102}}})
        documents={'identity_response':('template_identity',facts['identity_doc']),
            'headers_response':('template_headers',facts['headers']),
            'metadata_response':('metadata',metadata),'history_response':('history_tail',post)}
        responses={name:self.read_owned(stack,writer,owner,bound,facts['auth'],kind,value)
            for name,(kind,value) in documents.items()}
        completion.record_owned_completion_evidence(writer,owner,bound,second,**responses)
        self.assertEqual('COMPLETE-PRESENT-NOT-APPLIED',completion.inspect_completion_evidence(owner,bound,second).state)
        if fixture_facts is not None:
            fixture_facts.update(facts)
            fixture_facts.update(generation=generation,post=post,metadata=metadata)
        return allocation,writer,owner,bound,first,second,first_projection,first_delivery

    def test_actual_archived_delivery_native_preparation_reads_original_k_without_reacquiring_sheet(self):
        from monitor import issue_tracker_state_owner as state
        reached=[]
        def probe(allocation,writer,sheet,bound,prepared,tracker):
            self.assertFalse((tracker/'settings/outbox/0.json').exists())
            self.assertEqual({},state._COMPLETED_READ_CONTEXT)
            before={str(path.relative_to(tracker)):(path.stat().st_ino,path.read_bytes())
                for path in tracker.rglob('*') if path.is_file()}
            entry=getattr(allocation,'_hold_native_catalog_k_read',None)
            self.assertTrue(callable(entry),'actual old delivery must support K inside native preparation')
            with mock.patch.object(allocation.ownership,'spreadsheet_owner') as reacquire:
                with entry(prepared,writer,sheet,bound):
                    actual=state.current_k(writer)
                    self.assertEqual((1,7),(actual.revision,actual.k))
                    issued=state._NATIVE_CATALOG_K_READ_CONTEXT[writer]
                    # The real archived delivery grants only a read. Even a
                    # removed/rebound public map must not fall back or mutate.
                    with mock.patch.object(allocation,'_hold_completed_k_pair') as mutation_pair:
                        for altered in (None,allocation._NativeCatalogKContext()):
                            if altered is None:state._NATIVE_CATALOG_K_READ_CONTEXT.pop(writer)
                            else:state._NATIVE_CATALOG_K_READ_CONTEXT[writer]=altered
                            try:
                                with self.assertRaises(state.TrackerStateHold):state.current_k(writer)
                                with self.assertRaises(state.TrackerStateHold):
                                    state.set_k(writer,new_k=9,actor='operator:fixture',recorded_at='2026-10-08T10:02:00Z',
                                                request_id='read-only-must-not-write',expected_revision=1)
                                with self.assertRaises(allocation.SettingsAuditHold):
                                    allocation.cleanup_completed_settings_outbox(writer,sheet,bound,object())
                                with self.assertRaises(allocation.SettingsAuditHold):
                                    allocation.apply_completed_k_change(writer,sheet,bound,object(),new_k=9,
                                        actor='operator:fixture',recorded_at='2026-10-08T10:02:00Z',
                                        request_id='read-only-must-not-write',expected_revision=1)
                            finally:state._NATIVE_CATALOG_K_READ_CONTEXT[writer]=issued
                        mutation_pair.assert_not_called()
                    reset=allocation._NATIVE_CATALOG_K_CONTEXT.set(None)
                    try:
                        with self.assertRaises(state.TrackerStateHold):state.current_k(writer)
                    finally:allocation._NATIVE_CATALOG_K_CONTEXT.reset(reset)
                    self.assertEqual((1,7),(state.current_k(writer).revision,state.current_k(writer).k))
                    reached.append('actual-preparation-original-k')
                reacquire.assert_not_called()
            self.assertNotIn(issued,allocation._LIVE_NATIVE_CATALOG_K_CONTEXTS)
            self.assertIsNone(allocation._NATIVE_CATALOG_K_CONTEXT.get())
            state._NATIVE_CATALOG_K_READ_CONTEXT[writer]=issued
            try:
                with self.assertRaises(state.TrackerStateHold):state.current_k(writer)
            finally:state._NATIVE_CATALOG_K_READ_CONTEXT.pop(writer)
            self.assertEqual({},state._COMPLETED_READ_CONTEXT)
            with self.assertRaises(state.TrackerStateHold):state.current_k(writer)
            self.assertEqual(before,{str(path.relative_to(tracker)):(path.stat().st_ino,path.read_bytes())
                for path in tracker.rglob('*') if path.is_file()})
        with ExitStack() as stack:
            self.native_second_audit_completed(stack,archive_before_new=True,preparation_k_probe=probe)
        self.assertEqual(['actual-preparation-original-k'],reached)

    def test_native_preparation_k_read_refuses_equal_prior_replacement_and_graph_tail_budget_failure(self):
        from monitor import issue_tracker_state_owner as state
        reached=[]
        def probe(allocation,writer,sheet,bound,prepared,tracker):
            # The actual fixture reloads NV before issuance. Capture the
            # current registry here, never an earlier module's empty registry.
            from monitor import issue_tracker_nv_reservation as nv
            record=nv._verify_catalog_preparation(prepared)
            prior=next(row for row in record['prior_delivery_events'] if row['writer'] is writer)
            rows=record['prior_delivery_events'];index=rows.index(prior)
            before={str(path.relative_to(tracker)):(path.stat().st_ino,path.read_bytes())
                for path in tracker.rglob('*') if path.is_file()}
            with allocation._hold_native_catalog_k_read(prepared,writer,sheet,bound):
                self.assertEqual((1,7),(state.current_k(writer).revision,state.current_k(writer).k))
                rows[index]=dict(prior)  # Equal contents are not the issued original row.
                try:
                    with self.assertRaises(state.TrackerStateHold):state.current_k(writer)
                    reached.append('equal-prior-refused')
                finally:rows[index]=prior
                budget=record['budget'];original_graph=nv._verify_catalog_preparation
                def graph_then_fail_budget(actual):
                    result=original_graph(actual)
                    if actual is prepared:budget.failed=True
                    return result
                try:
                    with mock.patch.object(nv,'_verify_catalog_preparation',graph_then_fail_budget):
                        with self.assertRaises(state.TrackerStateHold):state.current_k(writer)
                    reached.append('actual-graph-tail-budget-refused')
                finally:budget.failed=False  # Restore only this test's injected flag.
                self.assertEqual((1,7),(state.current_k(writer).revision,state.current_k(writer).k))
            self.assertEqual(before,{str(path.relative_to(tracker)):(path.stat().st_ino,path.read_bytes())
                for path in tracker.rglob('*') if path.is_file()})
        with ExitStack() as stack:
            self.native_second_audit_completed(stack,archive_before_new=True,preparation_k_probe=probe)
        self.assertEqual(['equal-prior-refused','actual-graph-tail-budget-refused'],reached)

    def test_native_preparation_k_read_rechecks_issuer_after_actual_chain_validation(self):
        from monitor import issue_tracker_state_owner as state
        reached=[]
        def probe(allocation,writer,sheet,bound,prepared,tracker):
            refused=False
            with allocation._hold_native_catalog_k_read(prepared,writer,sheet,bound):
                issued=state._NATIVE_CATALOG_K_READ_CONTEXT[writer]
                actual_validate=allocation.chain.validate_k_chain_snapshot
                def validate_then_revoke(*args,**kwargs):
                    result=actual_validate(*args,**kwargs)
                    reached.append('actual-chain-validated-before-revocation')
                    state._NATIVE_CATALOG_K_READ_CONTEXT.pop(writer)
                    return result
                try:
                    with mock.patch.object(allocation.chain,'validate_k_chain_snapshot',validate_then_revoke):
                        try:state.current_k(writer)
                        except state.TrackerStateHold:refused=True
                finally:state._NATIVE_CATALOG_K_READ_CONTEXT[writer]=issued
            self.assertTrue(refused,'this original K read must HOLD before returning after issuer revocation')
        with ExitStack() as stack:
            self.native_second_audit_completed(stack,archive_before_new=True,preparation_k_probe=probe)
        self.assertEqual(['actual-chain-validated-before-revocation'],reached)

    def test_native_preparation_k_read_rejects_foreign_actual_writer_before_settings_acquisition(self):
        reached=[]
        def probe(allocation,writer,sheet,bound,prepared,tracker):
            project=self.root/'foreign-k-project';publication=project/'publication'
            project.mkdir(mode=0o700);publication.mkdir(mode=0o700)
            allocation.local.create_local_commit_store(project,publication)
            with allocation.local.writer_owner(project,publication) as foreign:
                allocation.settings.initialize_local_k_store(project/'.tracker',initialized_at='2026-10-08T10:00:00Z',
                    acquisition_id='foreign-k-initialization',token=foreign)
                original={str(path.relative_to(project)):(path.stat().st_ino,path.read_bytes())
                    for path in project.rglob('*') if path.is_file()}
                refused=False
                with mock.patch.object(allocation,'_hold_settings_originals',wraps=allocation._hold_settings_originals) as images:
                    try:
                        with allocation._hold_native_catalog_k_read(prepared,foreign,sheet,bound):pass
                    except allocation.SettingsAuditHold:refused=True
                reached.append((refused,images.call_count))
                self.assertEqual(original,{str(path.relative_to(project)):(path.stat().st_ino,path.read_bytes())
                    for path in project.rglob('*') if path.is_file()})
            self.assertEqual([(True,0)],reached,'foreign strict K cannot acquire this preparation read identity')
        with ExitStack() as stack:
            self.native_second_audit_completed(stack,archive_before_new=True,preparation_k_probe=probe)
        self.assertEqual([(True,0)],reached)

    def test_native_preparation_k_read_checks_old_raw_after_actual_settings_finalizer_and_revocation(self):
        from monitor import issue_tracker_state_owner as state
        class ProbeFinished(BaseException):pass
        primary=ProbeFinished('actual tail probe finished')
        facts=[];returned=[];retained=[]
        def probe(allocation,writer,sheet,bound,prepared,tracker):
            actual_holder=allocation._hold_settings_originals
            marker=tracker/'settings-audit-delivery/UNISSUED-K-TAIL'
            @contextmanager
            def after_actual_close(*args,**kwargs):
                with actual_holder(*args,**kwargs) as original:
                    yield original
                # Inner semantic validation closes before issuance; select
                # only the outer actual FD holder after the read identity was
                # issued and then genuinely revoked, not a fake verifier.
                if not returned or facts:return
                facts.append((not state._NATIVE_CATALOG_K_READ_CONTEXT,
                    not allocation._LIVE_NATIVE_CATALOG_K_CONTEXTS,
                    allocation._NATIVE_CATALOG_K_CONTEXT.get() is None))
                marker.write_bytes(b'literal unissued old-delivery tail\n');marker.chmod(0o600)
                retained.append(marker)
            refused=False
            with mock.patch.object(allocation,'_hold_settings_originals',after_actual_close):
                try:
                    with allocation._hold_native_catalog_k_read(prepared,writer,sheet,bound):
                        actual=state.current_k(writer)
                        self.assertEqual((1,7),(actual.revision,actual.k))
                        returned.append('actual-original-read')
                except state.TrackerStateHold:refused=True
            facts.append(('factory-return-refused',refused))
            # Preserve the exact operator interruption through the real outer
            # preparation and owners; never register/repair a faulted graph.
            raise primary
        with self.assertRaises(ProbeFinished) as caught:
            with ExitStack() as stack:
                self.native_second_audit_completed(stack,archive_before_new=True,preparation_k_probe=probe)
        self.assertIs(primary,caught.exception)
        self.assertEqual(['actual-original-read'],returned)
        self.assertEqual([(True,True,True),('factory-return-refused',True)],facts)
        self.assertEqual(1,len(retained))
        self.assertEqual(b'literal unissued old-delivery tail\n',retained[0].read_bytes())
        self.assertEqual({},state._NATIVE_CATALOG_K_READ_CONTEXT)

    def test_native_second_allocation_created_after_actual_first_archive_assigns_only_literal_new_event(self):
        from monitor import issue_tracker_mutation_launcher as mutation
        with ExitStack() as stack,mock.patch.object(mutation,'_send_counted_original_once') as no_send:
            allocation,writer,owner,bound,first,second,_projection,old_pair=self.native_second_audit_completed(
                stack,archive_before_new=True)
            tracker=self.root/'project/.tracker'
            from monitor import issue_tracker_global_attempt_journal as journal
            old=journal.inspect_global_unit(owner,bound,first)
            new=journal.inspect_global_unit(owner,bound,second)
            self.assertEqual((1,'UNKNOWN'),(old.attempt_count,old.outcome))
            self.assertEqual((1,'UNKNOWN'),(new.attempt_count,new.outcome))
            # The helper records one diagnostic count for the four real TLS
            # completion reads; it never launches a protected mutation.
            stem=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            allocated=self.root/'var/lib/http-ztp-container/issue-tracker'/(stem+'.unit-'+second.unit_id+'.settings-audit')
            expected=self.catalog_later_settings_audit_oracle()
            assignments=json.loads((allocated/'ASSIGNMENTS').read_bytes())
            self.assertEqual([{'revision':1,'event_sha256':hashlib.sha256((expected['details']+'\n').encode()).hexdigest(),
                'audit':expected}],assignments)
            self.assertFalse((tracker/'settings/outbox/0.json').exists())
            self.assertEqual((expected['details']+'\n').encode(),(tracker/'settings/events/1.json').read_bytes())
            self.assertEqual(old_pair,{p.name:(p.stat().st_ino,p.read_bytes())
                for p in (tracker/'settings-audit-delivery').iterdir()})
            self.assertFalse((tracker/('settings-audit-delivery-'+second.unit_id)).exists())
            no_send.assert_not_called()

    def test_native_counted_foreign_archived_project_retains_real_owner_through_new_allocation_raw_tail(self):
        from test_cases.test_req7_nv_reservation import cabling_inputs, source, KEYS
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        facts = {}
        with ExitStack() as initial:
            allocation, writer, sheet, bound, first, _allocated, _images = self.native_audit_completed(
                initial, fixture_facts=facts)
            from monitor import issue_tracker_remote_history_match as completion
            completion.record_owned_applied_evidence(writer, sheet, bound, first, generation=facts['generation'])
            completion.record_owned_applied_key_watermarks(writer, sheet, bound, first, generation=facts['generation'])
            allocation.record_completed_settings_delivery(writer, sheet, bound, first)
            allocation.cleanup_completed_settings_outbox(writer, sheet, bound, first)
        from monitor import issue_tracker_unit_catalog as catalog, issue_tracker_nv_reservation as nv
        from monitor import issue_tracker_k_store as settings, issue_tracker_state_owner as state
        from monitor import issue_tracker_global_attempt_journal as journal
        from monitor import issue_tracker_history_read_launcher as reads, issue_tracker_mutation_launcher as mutation
        local = catalog.local; ownership = catalog.ownership
        self.assertEqual({}, local._ACTIVE)
        old_project = self.root / 'project'
        original = self._default_recovery_images(old_project)
        shared = self.root / 'var/lib/http-ztp-container/issue-tracker'
        shared_original = {str(p.relative_to(shared)):(p.stat().st_ino,p.read_bytes())
            for p in shared.rglob('*') if p.is_file()}
        project = self.root / 'next-real-project'; project.mkdir(mode=0o700)
        publication = project / 'publication'; publication.mkdir(mode=0o700)
        local.create_local_commit_store(project, publication)
        tail_facts = []; actual_finish = allocation._NativeAllocationPriorOriginals.finish
        def observe_real_raw_tail(raw, *args):
            # Observe only genuine newly acquired foreign owner and revoked
            # semantic registries. Assertions remain outside sanitizers.
            actual_owner = local._ACTIVE.get(raw.writer)
            tail_facts.append((raw.writer, actual_owner,
                None if actual_owner is None else str(actual_owner.project),
                bool(nv._ACTIVE_CATALOG_PREPARATIONS), bool(state._COMPLETED_READ_CONTEXT),
                bool(state._COMPLETED_ORIGINAL_GUARDS), bool(allocation._LIVE_NATIVE_SETTINGS_CONTEXTS)))
            try:
                return actual_finish(raw, *args)
            except BaseException:
                import traceback
                print('ACTUAL_FOREIGN_RAW_TAIL_OWNER_PRESENT', actual_owner is not None)
                traceback.print_exc()
                raise
        with scoped_fixture(self.root, ownership), ownership.spreadsheet_owner(bound) as sheet, \
                local.writer_owner(project, publication) as current, \
                mock.patch.object(mutation, '_send_counted_original_once') as no_send, \
                mock.patch.object(allocation._NativeAllocationPriorOriginals, 'finish', observe_real_raw_tail):
            settings.initialize_local_k_store(project / '.tracker', token=current,
                initialized_at='2026-10-08T10:00:00Z', acquisition_id='first-use')
            audit = self.settings_audit_oracle()
            args = cabling_inputs(facts['nonces'], identifiers=('NV30104','NV30105')); args['audits']=(audit,)
            args['occupied_metadata_ids']=(first.fence_metadata_id,)
            generation = local.begin_generation(current, args['manifest'])
            local.record_intent(current, generation, literal_xlsx(), kind='xlsx')
            receipt = local.commit(current, generation)
            args.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
            second = catalog.composer.freeze_send_unit(**args)
            eth_plan = reads._prepare(bound, facts['auth'], 'activity', 'ETH Cabling', None)
            ib_plan = reads._prepare(bound, facts['auth'], 'activity', 'IB Cabling', None)
            with nv.hold_catalog_nv_preparation(sheet, bound, facts['identity'],
                    eth_plan, source('ETH Cabling', ('NV30016',)),
                    ib_plan, source('IB Cabling', ('NV30101',)),
                    generation_id=generation.generation_id, publish_id=receipt.published_sha256,
                    sheet='ETH Cabling', requested_keys=KEYS) as prepared:
                self.assertEqual(((KEYS[0],'NV30104'),(KEYS[1],'NV30105')), prepared.observation.reservations)
                catalog.register_pending_c6_unit(current, sheet, bound, second, _nv_preparation=prepared)
            self.assertEqual(1, len(tail_facts))
            foreign, actual_owner, path, *registries = tail_facts[0]
            self.assertIsNotNone(actual_owner); self.assertEqual(str(old_project), path)
            self.assertEqual([False]*4, registries)
            self.assertNotIn(foreign, local._ACTIVE)
            self.assertEqual({current}, set(local._ACTIVE))
            count = journal.inspect_global_unit(sheet, bound, first)
            self.assertEqual((1,'UNKNOWN'), (count.attempt_count,count.outcome))
            folder = shared / (hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+
                '.unit-'+second.unit_id+'.settings-audit')
            self.assertEqual([{'revision':0,'event_sha256':audit['event_id'].split(':')[2],'audit':audit}],
                json.loads((folder/'ASSIGNMENTS').read_bytes()))
            self.assertTrue((project/'.tracker/settings/outbox/0.json').is_file())
            self.assertFalse((project/'.tracker/settings-audit-delivery').exists())
            no_send.assert_not_called()
        self.assertEqual({},local._ACTIVE); self.assertEqual({},nv._ACTIVE_CATALOG_PREPARATIONS)
        self.assertEqual(original,self._default_recovery_images(old_project))
        self.assertEqual(shared_original,{name:((shared/name).stat().st_ino,(shared/name).read_bytes())
            for name in shared_original})

    def test_native_after_archive_allocation_last_old_close_delivery_rebind_is_hold(self):
        self._native_after_archive_last_close_fault('delivery-header')

    def test_native_after_archive_allocation_last_old_close_shared_extra_is_hold(self):
        self._native_after_archive_last_close_fault('shared-extra')

    def test_native_after_archive_allocation_last_old_close_catalog_extra_is_hold(self):
        self._native_after_archive_last_close_fault('catalog-extra')

    def _native_after_archive_last_close_fault(self,fault):
        from monitor import issue_tracker_nv_reservation as nv,issue_tracker_state_owner as state
        from monitor import issue_tracker_mutation_launcher as mutation
        facts={}
        with ExitStack() as stack,mock.patch.object(mutation,'_send_counted_original_once') as no_send:
            # The genuine fixture reloads NV before issuing originals. Pin
            # the literal typed-HOLD contract, not a stale imported class.
            with self.assertRaisesRegex(ValueError,'^req7_nv_reservation_unproved$') as caught:
                self.native_second_audit_completed(stack,fixture_facts=facts,archive_before_new=True,late_fault=fault)
            self.assertEqual('NvReservationHold',type(caught.exception).__name__)
            self.assertTrue(facts.get('reached'),'fault must follow actual NV old original cleanup')
            path=facts['path'];self.assertTrue(path.is_file())
            if fault=='delivery-header':
                self.assertNotEqual(facts['before_inode'],path.stat().st_ino)
                self.assertEqual((self.root/'retained-old-allocation-delivery-header').read_bytes(),path.read_bytes())
            else:self.assertEqual(b'literal foreign tail preserved\n',path.read_bytes())
            self.assertEqual(facts['old_count_images'],{p.name:(p.stat().st_ino,p.read_bytes())
                for p in facts['first_journal'].iterdir() if p.is_file()})
            self.assertEqual({},nv._ACTIVE_CATALOG_PREPARATIONS)
            self.assertEqual({},state._COMPLETED_READ_CONTEXT);self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
            no_send.assert_not_called()

    def test_native_new_delivery_after_first_archive_keeps_originals_and_archives_only_new_event(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_remote_history_match as completion
        tracker=self.root/'project/.tracker'
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            # Both genuine native COMPLETEs already exist. Retire event0 by
            # its actual old pair before first creation of the new pair.
            old=allocation.cleanup_completed_settings_outbox(writer,owner,bound,first)
            self.assertEqual(('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',
                (self.settings_audit_oracle()['event_id'],)),(old.state,old.event_ids))
            self.assertFalse((tracker/'settings/outbox/0.json').exists())
            self.assertTrue((tracker/'settings/outbox/1.json').is_file())
            self.assertEqual('COMPLETE-PRESENT-NOT-APPLIED',completion.inspect_completion_evidence(owner,bound,second).state)
            before={str(path):(path.stat().st_ino,path.read_bytes()) for path in self.root.rglob('*') if path.is_file()}
            print('OWNED_NEW_DELIVERY_AFTER_OLD_ARCHIVE',True,flush=True)
            original_settings=allocation._hold_settings_originals
            @contextmanager
            def settings_diagnosis(*args,**kwargs):
                try:
                    with original_settings(*args,**kwargs) as actual:yield actual
                except Exception:
                    import traceback
                    print('OWNED_NEW_DELIVERY_SETTINGS_FAILURE',flush=True)
                    traceback.print_exc()
                    raise
            with mock.patch.object(allocation,'_hold_settings_originals',side_effect=settings_diagnosis):
                result=allocation.record_completed_settings_delivery(writer,owner,bound,second)
            self.assertEqual((self.catalog_later_settings_audit_oracle()['event_id'],),result.event_ids)
            folder=tracker/('settings-audit-delivery-'+second.unit_id)
            self.assertEqual({'HEADER','DELIVERED'},{path.name for path in folder.iterdir()})
            self.assertTrue((tracker/('SETTINGS-AUDIT-DELIVERY-STARTED-'+second.unit_id)).is_file())
            for name,image in before.items():
                path=Path(name);self.assertEqual(image,(path.stat().st_ino,path.read_bytes()),name)
        event=(self.catalog_later_settings_audit_oracle()['details']+'\n').encode()
        expected=canonical({'schema_version':1,'revision':1,'event_sha256':hashlib.sha256(event).hexdigest()})
        projection=(tracker/'settings/outbox/1.json').stat().st_ino,(tracker/'settings/outbox/1.json').read_bytes()
        self.assertEqual(expected,projection[1]);archives={path.name for path in (tracker/'quarantine').iterdir()}
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(self.root/'project',self.root/'project/publication') as token:
            actual=[key for key,value in sheet._ACTIVE.items() if value.pid==os.getpid()]
            self.assertEqual(1,len(actual))
            result=allocation.cleanup_completed_settings_outbox(token,actual[0],bound,second)
            self.assertEqual(('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',
                (self.catalog_later_settings_audit_oracle()['event_id'],)),(result.state,result.event_ids))
            self.assertEqual((1,7),(state.current_k(token).revision,state.current_k(token).k))
            self.assertEqual((),allocation.pending_settings_audits(token))
            self.assertEqual([(1,'UNKNOWN'),(1,'UNKNOWN')],
                [(self.current_global_state(actual[0],bound,unit).attempt_count,
                  self.current_global_state(actual[0],bound,unit).outcome) for unit in (first,second)])
        self.assertEqual([],list((tracker/'settings/outbox').iterdir()))
        added=[path for path in (tracker/'quarantine').iterdir() if path.name not in archives]
        self.assertEqual(1,len(added));self.assertEqual(projection,(added[0].stat().st_ino,added[0].read_bytes()))
        for name,(inode,raw) in first_delivery.items():
            path=tracker/'settings-audit-delivery'/name
            self.assertEqual((inode,raw),(path.stat().st_ino,path.read_bytes()))
        self.assertEqual({},state._COMPLETED_READ_CONTEXT);self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def _assert_new_native_delivery_after_archive_hold(self, fault):
        from monitor import issue_tracker_state_owner as state
        tracker=self.root/'project/.tracker'
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,_projection,first_delivery=self.native_second_audit_completed(stack)
            allocation.cleanup_completed_settings_outbox(writer,owner,bound,first)
            projection=tracker/'settings/outbox/1.json'
            before=projection.stat().st_ino,projection.read_bytes()
            reached=[];creator_calls=[];write=allocation._write_delivery_file;foreign=[]
            primary=KeyboardInterrupt('literal native delivery operator interruption')
            foreign_path=tracker/'literal-foreign-cleanup-evidence'
            foreign_path.write_bytes(b'literal foreign slot remains owned\n');foreign_path.chmod(0o600)
            actual_capture=allocation._DeliveryCreatorOriginals.capture_written
            actual_folder=allocation._DeliveryCreatorOriginals.capture_folder
            actual_close=allocation.local._close_written_original;folder_sources=[]
            def replace_owned_slot(descriptor):
                os.close(descriptor)
                replacement=os.open(foreign_path,os.O_RDONLY)
                if replacement!=descriptor:os.dup2(replacement,descriptor);os.close(replacement)
                os.lseek(descriptor,3,os.SEEK_SET);foreign.append(descriptor);reached.append(True)
            def capture_written(holder,parent,name,descriptor,identity,raw):
                actual_capture(holder,parent,name,descriptor,identity,raw)
                if fault=='writer-foreign' and name=='SETTINGS-AUDIT-DELIVERY-STARTED-'+second.unit_id:
                    replace_owned_slot(descriptor)
            def capture_folder(holder,descriptor):
                actual_folder(holder,descriptor)
                folder_sources.append((descriptor,os.fstat(descriptor).st_dev,os.fstat(descriptor).st_ino))
                if fault=='folder-foreign':replace_owned_slot(descriptor)
            def close_source(descriptor,identity):
                result=actual_close(descriptor,identity)
                if (fault=='folder-last-close' and folder_sources
                        and (descriptor,*identity[:2])==folder_sources[0] and not reached):
                    old=tracker/'settings-audit-delivery/HEADER';image=old.read_bytes()
                    inode=old.stat().st_ino;old.rename(old.with_name('displaced-original-HEADER'))
                    old.write_bytes(image);old.chmod(0o600)
                    self.assertNotEqual(inode,old.stat().st_ino);reached.append(True)
                return result
            def actual_write(parent,name,raw,**kwargs):
                creator_calls.append(name)
                result=write(parent,name,raw,**kwargs)
                if (name=='SETTINGS-AUDIT-DELIVERY-STARTED-'+second.unit_id
                        and fault in ('old-header-rebind','old-header-interrupt')):
                    self.assertEqual({},allocation._LIVE_NATIVE_SETTINGS_CONTEXTS)
                    self.assertEqual({},state._COMPLETED_READ_CONTEXT)
                    self.assertEqual({},state._LOCAL_C6_READ_CONTEXT)
                    old=tracker/'settings-audit-delivery/HEADER'
                    image=old.read_bytes();identity=old.stat().st_ino
                    old.rename(old.with_name('displaced-original-HEADER'))
                    old.write_bytes(image);old.chmod(0o600)
                    self.assertNotEqual(identity,old.stat().st_ino)
                    reached.append(True)
                    if fault=='old-header-interrupt':raise primary
                return result
            if fault=='selected-outbox-missing':
                projection.rename(tracker/'quarantine/fixture-retained-new-projection')
            try:
                with mock.patch.object(allocation,'_write_delivery_file',side_effect=actual_write), \
                        mock.patch.object(allocation._DeliveryCreatorOriginals,'capture_written',capture_written), \
                        mock.patch.object(allocation._DeliveryCreatorOriginals,'capture_folder',capture_folder), \
                        mock.patch.object(allocation.local,'_close_written_original',side_effect=close_source):
                    if fault=='old-header-interrupt':
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            allocation.record_completed_settings_delivery(writer,owner,bound,second)
                        self.assertIs(primary,caught.exception)
                        self.assertIsInstance(caught.exception.__cause__,allocation.SettingsAuditHold)
                    else:
                        with self.assertRaises(allocation.SettingsAuditHold):
                            allocation.record_completed_settings_delivery(writer,owner,bound,second)
                if fault in ('writer-foreign','folder-foreign'):
                    self.assertEqual(1,len(foreign));self.assertEqual([True],reached)
                    self.assertEqual(foreign_path.stat().st_ino,os.fstat(foreign[0]).st_ino)
                    self.assertEqual(3,os.lseek(foreign[0],0,os.SEEK_CUR))
                    self.assertEqual(b'literal foreign slot remains owned\n',os.pread(foreign[0],100,0))
            finally:
                for descriptor in foreign:
                    try:
                        current=os.fstat(descriptor);expected=foreign_path.stat()
                        if (current.st_dev,current.st_ino)==(expected.st_dev,expected.st_ino):os.close(descriptor)
                    except OSError:pass
            if fault=='selected-outbox-missing':
                self.assertEqual([],creator_calls)
                retained=tracker/'quarantine/fixture-retained-new-projection'
                self.assertEqual(before,(retained.stat().st_ino,retained.read_bytes()))
                self.assertEqual([],reached)
            else:
                self.assertEqual([True],reached)
                self.assertEqual(before,(projection.stat().st_ino,projection.read_bytes()))
                marker=tracker/('settings-audit-delivery-'+second.unit_id)/'DELIVERED'
                if fault=='folder-last-close':
                    self.assertTrue(marker.is_file(),'late refusal retains the actually written marker, never ACKs')
                else:self.assertFalse(marker.exists())
            self.assertFalse((tracker/'settings/outbox/0.json').exists())
            self.assertEqual({},state._COMPLETED_READ_CONTEXT)
            self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_native_new_delivery_after_archive_refuses_old_header_rebind_after_real_started(self):
        self._assert_new_native_delivery_after_archive_hold('old-header-rebind')

    def test_native_new_delivery_after_archive_missing_selected_outbox_never_enters_creator(self):
        self._assert_new_native_delivery_after_archive_hold('selected-outbox-missing')

    def test_native_new_delivery_original_tail_refusal_preserves_real_operator_interrupt(self):
        self._assert_new_native_delivery_after_archive_hold('old-header-interrupt')

    def test_native_new_delivery_writer_cleanup_never_closes_a_recycled_foreign_source_slot(self):
        self._assert_new_native_delivery_after_archive_hold('writer-foreign')

    def test_native_new_delivery_folder_cleanup_never_closes_a_recycled_foreign_source_slot(self):
        self._assert_new_native_delivery_after_archive_hold('folder-foreign')

    def test_native_new_delivery_last_actual_folder_close_still_checks_old_originals(self):
        self._assert_new_native_delivery_after_archive_hold('folder-last-close')

    def test_same_project_second_native_audit_complete_delivers_without_overwriting_first_pair(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            tracker=self.root/'project/.tracker'
            actual=allocation._hold_delivery_authority;entered=[]
            @contextmanager
            def actual_authority(*args,**options):
                with actual(*args,**options) as original:
                    entered.append((args[-1].unit_id,(tracker/'settings-audit-delivery').is_dir(),
                        (tracker/'SETTINGS-AUDIT-DELIVERY-STARTED').is_file()))
                    yield original
            error=None
            try:
                with mock.patch.object(allocation,'_hold_delivery_authority',side_effect=actual_authority):
                    delivered=allocation.record_completed_settings_delivery(writer,owner,bound,second)
            except Exception as exc:error=exc
            # Outside sanitizers: prove the actual second COMPLETE/allocation
            # authority was reached before the fixed-name refusal.
            self.assertEqual([(second.unit_id,True,True)],entered)
            if error is not None:raise error
            self.assertEqual((self.catalog_later_settings_audit_oracle()['event_id'],),delivered.event_ids)
            folder=tracker/('settings-audit-delivery-'+second.unit_id)
            started=tracker/('SETTINGS-AUDIT-DELIVERY-STARTED-'+second.unit_id)
            self.assertEqual({'HEADER','DELIVERED'},{path.name for path in folder.iterdir()})
            self.assertTrue(started.is_file())
            saved=json.loads((folder/'HEADER').read_bytes())
            self.assertEqual(second.unit_id,saved['complete_allocation']['native_delivery_unit_id'])
            self.assertEqual(second.unit_id,saved['complete_allocation']['native_allocation_header']['unit_id'])
            for name,(inode,raw) in first_delivery.items():
                path=tracker/'settings-audit-delivery'/name
                self.assertEqual((inode,raw),(path.stat().st_ino,path.read_bytes()))
            allocation.cleanup_completed_settings_outbox(writer,owner,bound,second)
            path=tracker/'settings/outbox/0.json'
            self.assertEqual(projection,(path.stat().st_ino,path.read_bytes()))
            self.assertFalse((tracker/'settings/outbox/1.json').exists())
            self.assertEqual((self.settings_audit_oracle()['details']+'\n').encode(),(tracker/'settings/events/0.json').read_bytes())
            self.assertEqual((self.catalog_later_settings_audit_oracle()['details']+'\n').encode(),(tracker/'settings/events/1.json').read_bytes())
            for unit in (first,second):
                seen=self.current_global_state(owner,bound,unit)
                self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome))

    def test_second_native_delivery_header_same_bytes_rebind_refuses_cleanup_without_consuming_any_event(self):
        from monitor import issue_tracker_state_owner as state
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,second)
            tracker=self.root/'project/.tracker';header=tracker/('settings-audit-delivery-'+second.unit_id)/'HEADER'
            actual=allocation._hold_delivery_files;reached=[]
            before=self._default_recovery_images(self.root/'project')
            @contextmanager
            def replace_after_hold(*args,**options):
                with actual(*args,**options) as verify:
                    old=(header.stat().st_ino,header.read_bytes())
                    header.rename(self.root/'preserved-second-native-delivery-header')
                    header.write_bytes(old[1]);header.chmod(0o600)
                    reached.append((old[0],header.stat().st_ino))
                    yield verify
            with mock.patch.object(allocation,'_hold_delivery_files',side_effect=replace_after_hold), \
                    self.assertRaises(allocation.SettingsAuditHold):
                allocation.cleanup_completed_settings_outbox(writer,owner,bound,second)
            self.assertEqual(1,len(reached));self.assertNotEqual(*reached[0])
            # The owned fault intentionally replaced exactly this inode. All
            # other original images and the replacement's old SHA must remain.
            key=str(header.relative_to(self.root/'project'))
            before[key]=(reached[0][1],before[key][1])
            self.assertEqual(before,self._default_recovery_images(self.root/'project'))
            for name,(inode,raw) in first_delivery.items():
                path=tracker/'settings-audit-delivery'/name
                self.assertEqual((inode,raw),(path.stat().st_ino,path.read_bytes()))
            path=tracker/'settings/outbox/0.json';self.assertEqual(projection,(path.stat().st_ino,path.read_bytes()))
            self.assertTrue((tracker/'settings/outbox/1.json').is_file())
            self.assertEqual({},state._COMPLETED_READ_CONTEXT)
            self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_second_native_delivery_independent_cold_reader_archives_only_original_selected_projection(self):
        from dataclasses import asdict
        import subprocess
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,second)
            tracker=self.root/'project/.tracker';second_projection=(tracker/'settings/outbox/1.json').read_bytes()
        before={path.name for path in (tracker/'quarantine').iterdir()}
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from monitor import issue_tracker_settings_audit_allocation as allocation
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]);project=root/'project';tracker=project/'.tracker'
bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
folder=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.units')/sys.argv[3]
unit=_original_unit((folder/'ACTION-PREIMAGE').read_bytes(),(folder/'WIRE').read_bytes())
assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}
with scoped_fixture(root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
 owner=state._COMPLETED_READ_CONTEXT[token][0]
 result=allocation.cleanup_completed_settings_outbox(token,owner,bound,unit)
 current=state.current_k(token)
 pending=allocation.pending_settings_audits_after_completed_unit(token,owner,bound,unit)
 print(result.state,current.revision,current.k,len(pending))
assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}
'''
        # New two-unit scenario's bounded process budget; no prior deadline or
        # automatic assertion is changed. Independent parent holds no owners.
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root),second.unit_id],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'DELIVERED-PRESENT-OUTBOX-ABSENT-VALID 1 7 1\n',cold.stdout)
        path=tracker/'settings/outbox/0.json';self.assertEqual(projection,(path.stat().st_ino,path.read_bytes()))
        self.assertFalse((tracker/'settings/outbox/1.json').exists())
        archives=[path for path in (tracker/'quarantine').iterdir() if path.name not in before]
        self.assertEqual(1,len(archives));self.assertEqual(second_projection,archives[0].read_bytes())
        for name,(inode,raw) in first_delivery.items():
            path=tracker/'settings-audit-delivery'/name
            self.assertEqual((inode,raw),(path.stat().st_ino,path.read_bytes()))
        # C25 ALL default discovery now proves both historical deliveries.
        # The explicit single-unit reader above still reports event0 pending;
        # its result is not silently widened to a public union observation.
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        before_default=self._default_recovery_images(self.root/'project')
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(self.root/'project',self.root/'project/publication') as token:
            self.assertEqual((1,7),(state.current_k(token).revision,state.current_k(token).k))
            self.assertEqual((),allocation.pending_settings_audits(token))
        self.assertEqual(before_default,self._default_recovery_images(self.root/'project'))
        self.assertEqual({},state._COMPLETED_READ_CONTEXT);self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_native_all_default_archives_second_only_while_both_projections_present(self):
        from test_cases.test_req7_global_attempt_journal import original_read_files
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,second)
        from monitor import issue_tracker_global_attempt_journal as journal
        project=self.root/'project';tracker=project/'.tracker'
        event=(self.catalog_later_settings_audit_oracle()['details']+'\n').encode()
        expected_second=canonical({'schema_version':1,'revision':1,
            'event_sha256':hashlib.sha256(event).hexdigest()})
        self.assertEqual(expected_second,(tracker/'settings/outbox/1.json').read_bytes())
        self.assertTrue((tracker/'settings/outbox/0.json').is_file())
        before=original_read_files(self.root);archives={path.name for path in (tracker/'quarantine').iterdir()}
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
            actual=[key for key,value in sheet._ACTIVE.items() if value.pid==os.getpid()]
            self.assertEqual(1,len(actual))
            result=allocation.cleanup_completed_settings_outbox(token,actual[0],bound,second)
            self.assertEqual(('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',second.unit_id,
                (self.catalog_later_settings_audit_oracle()['event_id'],)),(result.state,result.unit_id,result.event_ids))
            self.assertEqual((1,7),(state.current_k(token).revision,state.current_k(token).k))
            self.assertEqual((),allocation.pending_settings_audits(token))
            self.assertEqual([(1,'UNKNOWN'),(1,'UNKNOWN')],
                [(row.attempt_count,row.outcome) for _unit,row in journal.inspect_catalog_global_units(actual[0],bound)])
        path=tracker/'settings/outbox/0.json'
        self.assertEqual(projection,(path.stat().st_ino,path.read_bytes()))
        self.assertFalse((tracker/'settings/outbox/1.json').exists())
        added=[path for path in (tracker/'quarantine').iterdir() if path.name not in archives]
        self.assertEqual(1,len(added));self.assertEqual(expected_second,added[0].read_bytes())
        self.assertEqual(0o600,added[0].stat().st_mode & 0o777)
        removed=str((tracker/'settings/outbox/1.json').relative_to(self.root))
        after=original_read_files(self.root)
        self.assertEqual({name:row for name,row in before.items() if name!=removed},
            {name:row for name,row in after.items() if name!=str(added[0].relative_to(self.root))})
        self.assertEqual({},state._COMPLETED_READ_CONTEXT);self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        self.assertEqual({},allocation._LIVE_NATIVE_SETTINGS_CONTEXTS)

    def test_native_all_default_incomplete_or_foreign_second_claim_never_grants_union(self):
        from test_cases.test_req7_global_attempt_journal import original_read_files
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        for fault in ('unknown-start','second-delivered-absent','foreign-second-project'):
            with self.subTest(fault=fault):
                case=type(self)('test_native_all_default_settings_reads_whole_delivery_set_and_commits_only_new_event')
                case.setUp()
                try:
                    with ExitStack() as stack:
                        allocation,writer,owner,bound,first,second,projection,first_delivery=case.native_second_audit_completed(stack)
                        allocation.record_completed_settings_delivery(writer,owner,bound,second)
                    tracker=case.root/'project/.tracker';folder=tracker/('settings-audit-delivery-'+second.unit_id)
                    reached=[]
                    if fault=='unknown-start':
                        path=tracker/('SETTINGS-AUDIT-DELIVERY-STARTED-'+'f'*64)
                        path.write_bytes(b'literal-unknown-incomplete-claim\n');path.chmod(0o600)
                        reached.append(path.is_file())
                    elif fault=='second-delivered-absent':
                        (folder/'DELIVERED').rename(case.root/'preserved-second-delivered')
                        reached.append(not (folder/'DELIVERED').exists())
                    else:
                        path=folder/'HEADER';body=json.loads(path.read_bytes())
                        locator=body['complete_allocation']['native_allocation_header']
                        locator['project_identity'][1]+=1
                        body['complete_allocation']['allocation_header_sha256']=hashlib.sha256(canonical(locator)).hexdigest()
                        path.write_bytes(canonical(body));path.chmod(0o600)
                        reached.append(json.loads(path.read_bytes())['complete_allocation']['native_allocation_header']['project_identity']!=
                            [os.stat(tracker.parent).st_dev,os.stat(tracker.parent).st_ino])
                    before=original_read_files(case.root);yielded=[]
                    with scoped_fixture(case.root,sheet),case.assertRaises(state.TrackerStateHold):
                        with state.tracker_settings_writer(tracker.parent,tracker.parent/'publication'):
                            yielded.append(True)
                    case.assertEqual([True],reached);case.assertEqual([],yielded)
                    case.assertEqual(before,original_read_files(case.root))
                    case.assertEqual({},state._COMPLETED_READ_CONTEXT);case.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
                    case.assertEqual({},allocation._LIVE_NATIVE_SETTINGS_CONTEXTS)
                    case.assertIsNone(allocation._NATIVE_SETTINGS_CONTEXT.get())
                finally:case.doCleanups()

    def test_native_all_default_revokes_before_first_semantic_finalizer_with_owners_still_held(self):
        from contextvars import copy_context
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,second)
        project=self.root/'project';before=self._default_recovery_images(project)
        actual=allocation._hold_native_completed_delivery_originals
        saved={};observed=[]
        @contextmanager
        def first_semantic_exit(*args,**options):
            with actual(*args,**options) as originals:
                try:
                    yield originals
                finally:
                    if saved and not observed:
                        token=saved['token'];context=saved['context']
                        facts=[token not in state._COMPLETED_READ_CONTEXT,
                            token not in state._COMPLETED_ORIGINAL_GUARDS,
                            context not in allocation._LIVE_NATIVE_SETTINGS_CONTEXTS,
                            allocation._NATIVE_SETTINGS_CONTEXT.get() is None,
                            allocation.local._owner(token) is saved['owner'],
                            sheet._validated_owner(saved['sheet'],bound) is saved['sheet_owner']]
                        try:saved['copied'].run(allocation._read_native_completed_k,token,context)
                        except allocation.SettingsAuditHold:facts.append(True)
                        else:facts.append(False)
                        observed.append(tuple(facts))
        with scoped_fixture(self.root,sheet), \
                mock.patch.object(allocation,'_hold_native_completed_delivery_originals',side_effect=first_semantic_exit):
            with state.tracker_settings_writer(project,project/'publication') as token:
                context=state._COMPLETED_READ_CONTEXT[token]
                packet=allocation._LIVE_NATIVE_SETTINGS_CONTEXTS[context]
                self.assertEqual((1,7),(state.current_k(token).revision,state.current_k(token).k))
                saved.update(token=token,context=context,owner=allocation.local._owner(token),
                    sheet=packet['sheet'],sheet_owner=packet['sheet_owner'],copied=copy_context())
        # Assert outside all sanitizers: the first actual original holder's
        # finalizer has not run yet, and both original owners remain live.
        self.assertEqual([(True,True,True,True,True,True,True)],observed)
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertEqual({},state._COMPLETED_READ_CONTEXT);self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        self.assertEqual({},allocation._LIVE_NATIVE_SETTINGS_CONTEXTS)
        self.assertIsNone(allocation._NATIVE_SETTINGS_CONTEXT.get())

    def test_native_all_default_settings_reads_whole_delivery_set_and_commits_only_new_event(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,second)
            allocation.cleanup_completed_settings_outbox(writer,owner,bound,second)
        from monitor import issue_tracker_global_attempt_journal as journal
        project=self.root/'project';tracker=project/'.tracker'
        immutable={str(path.relative_to(tracker)):(path.stat().st_ino,path.read_bytes())
            for folder in ('settings-audit-delivery','settings-audit-delivery-'+second.unit_id)
            for path in (tracker/folder).iterdir()}
        old_events={path.name:(path.stat().st_ino,path.read_bytes()) for path in (tracker/'settings/events').iterdir()}
        archives={path.name for path in (tracker/'quarantine').iterdir()}
        saved_context=None
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
            saved_context=state._COMPLETED_READ_CONTEXT[token]
            self.assertEqual((1,7),(state.current_k(token).revision,state.current_k(token).k))
            self.assertEqual((),allocation.pending_settings_audits(token))
            actual_sheets=[key for key,value in sheet._ACTIVE.items() if value.pid==os.getpid()]
            self.assertEqual(1,len(actual_sheets));actual_sheet=actual_sheets[0]
            result=allocation.cleanup_completed_settings_outbox(token,actual_sheet,bound,first)
            self.assertEqual((first.unit_id,), (result.unit_id,))
            self.assertEqual(('settings:0:'+hashlib.sha256(old_events['0.json'][1]).hexdigest(),),result.event_ids)
            self.assertFalse((tracker/'settings/outbox/0.json').exists())
            self.assertFalse((tracker/'settings/outbox/1.json').exists())
            self.assertEqual([(1,'UNKNOWN'),(1,'UNKNOWN')],
                [(row.attempt_count,row.outcome) for _unit,row in journal.inspect_catalog_global_units(actual_sheet,bound)])
            accepted=state.set_k(token,new_k=11,actor='operator:fixture',recorded_at='2026-10-11T00:00:00Z',
                request_id='native-all-next-k',expected_revision=1)
            self.assertEqual((2,11,False),(accepted.revision,accepted.k,accepted.replay))
            self.assertEqual((2,11),(state.current_k(token).revision,state.current_k(token).k))
        expected_payload=canonical({'new_k':11,'actor':'operator:fixture','expected_revision':1,'request_id':'native-all-next-k'})
        expected=canonical({'schema_version':1,'revision':2,'type':'set_k','old_k':7,'new_k':11,
            'actor':'operator:fixture','recorded_at':'2026-10-11T00:00:00Z','request_id':'native-all-next-k',
            'payload_sha256':hashlib.sha256(expected_payload).hexdigest(),
            'predecessor_sha256':hashlib.sha256(old_events['1.json'][1]).hexdigest()})
        self.assertEqual(expected,(tracker/'settings/events/2.json').read_bytes())
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
            self.assertIsNot(saved_context,state._COMPLETED_READ_CONTEXT[token])
            self.assertEqual((2,11),(state.current_k(token).revision,state.current_k(token).k))
            self.assertEqual(({'event_id':'settings:2:'+hashlib.sha256(expected).hexdigest(),
                'recorded_at_utc':'2026-10-11T00:00:00Z','details':expected.decode().rstrip('\n')},),
                allocation.pending_settings_audits(token))
        for name,(inode,raw) in old_events.items():
            path=tracker/'settings/events'/name;self.assertEqual((inode,raw),(path.stat().st_ino,path.read_bytes()))
        for name,(inode,raw) in immutable.items():
            path=tracker/name;self.assertEqual((inode,raw),(path.stat().st_ino,path.read_bytes()))
        additions=[path for path in (tracker/'quarantine').iterdir() if path.name not in archives]
        self.assertEqual(1,len([path for path in additions if path.read_bytes()==projection[1]]))
        self.assertEqual({},state._COMPLETED_READ_CONTEXT);self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_native_all_default_originals_c6_rebind_after_all_holder_finalizer_refuses(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,second)
            allocation.cleanup_completed_settings_outbox(writer,owner,bound,second)
        # This genuine fixture reloads the catalog. Inject into the actual
        # canonical module only AFTER fixture construction, not a stale alias.
        from monitor import issue_tracker_unit_catalog as catalog
        self.assertIs(catalog,sys.modules['monitor.issue_tracker_unit_catalog'])
        project=self.root/'project';tracker=project/'.tracker'
        action=json.loads(second.action_preimage)
        path=tracker/'generations'/action['identity']['generation_id']/'RECEIPT'
        original=(path.stat().st_ino,path.read_bytes());reached=[]
        native=catalog.hold_pending_project_c6_units
        @contextmanager
        def after_actual_all(*args,**kwargs):
            with native(*args,**kwargs) as result:yield result
            reached.append('after-all-c6-finalizer')
            path.rename(self.root/'preserved-all-c6-receipt')
            path.write_bytes(original[1]);path.chmod(0o600)
        entered=[]
        refusal=None
        with scoped_fixture(self.root,sheet),mock.patch.object(catalog,'hold_pending_project_c6_units',side_effect=after_actual_all):
            try:
                with state.tracker_settings_writer(project,project/'publication') as token:
                    entered.append(token);self.assertEqual((1,7),(state.current_k(token).revision,state.current_k(token).k))
            except state.TrackerStateHold as exc:refusal=exc
        self.assertEqual(1,len(entered));self.assertEqual(['after-all-c6-finalizer'],reached)
        self.assertIsNotNone(refusal,'actual ALL last-finalizer rebind was acknowledged')
        self.assertEqual(original[1],path.read_bytes());self.assertNotEqual(original[0],path.stat().st_ino)
        self.assertEqual(projection,((tracker/'settings/outbox/0.json').stat().st_ino,(tracker/'settings/outbox/0.json').read_bytes()))
        self.assertFalse((tracker/'settings/outbox/1.json').exists())
        self.assertEqual({},state._COMPLETED_READ_CONTEXT);self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_native_all_default_live_context_rebinding_and_revocation_never_grant_or_fallback(self):
        import copy
        import threading
        from contextvars import copy_context
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,second)
        project=self.root/'project';before=self._default_recovery_images(project)
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
            context=state._COMPLETED_READ_CONTEXT[token];captured=copy_context()
            self.assertNotIsInstance(context,(tuple,allocation.SettingsDeliveryObservation))
            self.assertFalse(hasattr(context,'event_ids'))
            for forged in (object(),allocation._NativeCompletedSettingsContext(),copy.copy(context)):
                with self.subTest(forged_type=type(forged).__name__):
                    with self.assertRaises(allocation.SettingsAuditHold):allocation._read_native_completed_k(token,forged)
            guard=state._COMPLETED_ORIGINAL_GUARDS[token]
            caller=mock.Mock(side_effect=AssertionError('caller guard must not be invoked'))
            try:
                for replacement in (None,caller):
                    state._COMPLETED_ORIGINAL_GUARDS[token]=replacement
                    with self.assertRaises(state.TrackerStateHold):state.current_k(token)
                    with self.assertRaises(allocation.SettingsAuditHold):allocation.pending_settings_audits(token)
                caller.assert_not_called()
            finally:state._COMPLETED_ORIGINAL_GUARDS[token]=guard
            try:
                state._COMPLETED_READ_CONTEXT.pop(token)
                with self.assertRaises(state.TrackerStateHold):state.current_k(token)
                with self.assertRaises(allocation.SettingsAuditHold):allocation.pending_settings_audits(token)
                with self.assertRaises(state.TrackerStateHold):
                    state.set_k(token,new_k=11,actor='operator:fixture',recorded_at='2026-10-11T00:00:00Z',
                        request_id='rebound-context-must-not-commit',expected_revision=1)
            finally:state._COMPLETED_READ_CONTEXT[token]=context
            reset=allocation._NATIVE_SETTINGS_CONTEXT.set(None)
            try:
                with self.assertRaises(state.TrackerStateHold):state.current_k(token)
            finally:allocation._NATIVE_SETTINGS_CONTEXT.reset(reset)
            errors=[]
            def foreign_thread():
                try:state.current_k(token)
                except Exception as exc:errors.append(type(exc))
            thread=threading.Thread(target=foreign_thread);thread.start();thread.join(timeout=5)
            self.assertFalse(thread.is_alive());self.assertEqual([state.TrackerStateHold],errors)
            self.assertEqual((1,7),(state.current_k(token).revision,state.current_k(token).k))
            self.assertEqual((),allocation.pending_settings_audits(token))
        with self.assertRaises(allocation.SettingsAuditHold):
            captured.run(allocation._read_native_completed_k,token,context)
        self.assertEqual({},allocation._LIVE_NATIVE_SETTINGS_CONTEXTS)
        self.assertEqual({},state._COMPLETED_READ_CONTEXT);self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        self.assertEqual(before,self._default_recovery_images(project))

    def test_native_all_default_independent_cold_process_reads_both_absent_projections_without_parent_coordinates(self):
        self._exercise_native_all_default_cold_process_reads_both_absent_projections()

    def test_native_all_default_independent_cold_process_recovers_after_archive_before_new_allocation(self):
        self._exercise_native_all_default_cold_process_reads_both_absent_projections(archive_before_new=True)

    def _exercise_native_all_default_cold_process_reads_both_absent_projections(self, *, archive_before_new=False):
        import subprocess
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(
                stack,archive_before_new=archive_before_new)
            allocation.record_completed_settings_delivery(writer,owner,bound,second)
            if archive_before_new:
                # The one-unit legacy pair must NOT excuse the other missing
                # projection. This is not the fixed ALL native factory used
                # by the default writer/worker. Keep its refusal and every
                # original unchanged, then leave ALL initial owners below.
                before_legacy=self._default_recovery_images(self.root/'project')
                with self.assertRaises(allocation.SettingsAuditHold):
                    allocation.cleanup_completed_settings_outbox(writer,owner,bound,second)
                self.assertEqual(before_legacy,self._default_recovery_images(self.root/'project'))
            else:
                allocation.cleanup_completed_settings_outbox(writer,owner,bound,second)
        project=self.root/'project'
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
            actual_sheets=[key for key,value in sheet._ACTIVE.items() if value.pid==os.getpid()]
            self.assertEqual(1,len(actual_sheets))
            allocation.cleanup_completed_settings_outbox(token,actual_sheets[0],bound,first)
            if archive_before_new:
                # Fresh actual default writer discovery owns the union. No
                # caller event list or parent permission crosses the process.
                allocation.cleanup_completed_settings_outbox(token,actual_sheets[0],bound,second)
        before=self._default_recovery_images(project)
        program='''import sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from monitor import issue_tracker_settings_audit_allocation as allocation,issue_tracker_global_attempt_journal as journal
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
root=Path(sys.argv[2]);project=root/'project'
assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}
assert allocation._LIVE_NATIVE_SETTINGS_CONTEXTS=={} and allocation._NATIVE_SETTINGS_CONTEXT.get() is None
with scoped_fixture(root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
 current=state.current_k(token);pending=allocation.pending_settings_audits(token)
 actual=list(sheet._ACTIVE.items());assert len(actual)==1
 counts=journal.inspect_catalog_global_units(actual[0][0],actual[0][1].binding)
 print(current.revision,current.k,len(pending),','.join(str(row.attempt_count)+':'+row.outcome for unit,row in counts))
assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}
assert allocation._LIVE_NATIVE_SETTINGS_CONTEXTS=={} and allocation._NATIVE_SETTINGS_CONTEXT.get() is None
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'1 7 0 1:UNKNOWN,1:UNKNOWN\n',cold.stdout)
        self.assertEqual(before,self._default_recovery_images(project))

    def test_native_complete_pair_originals_do_not_read_or_grant_other_missing_projection(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            allocation.record_completed_settings_delivery(writer,owner,bound,second)
            allocation.cleanup_completed_settings_outbox(writer,owner,bound,second)
            before=self._default_recovery_images(self.root/'project')
            with allocation._hold_native_completed_delivery_originals(writer,owner,bound,first) as (actual,events,verify):
                self.assertIs(allocation.local._owner(writer),actual)
                self.assertEqual((self.settings_audit_oracle()['event_id'],),events)
                verify()
                # A held immutable pair is NOT permission for the ordinary
                # reader or a single-unit reader to ignore another event.
                with self.assertRaises(allocation.SettingsAuditHold):
                    allocation.read_current_k_after_completed_unit(writer,owner,bound,first)
            self.assertEqual(before,self._default_recovery_images(self.root/'project'))

    def test_native_complete_pair_originals_same_bytes_delivered_rebind_refuses_last_close(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            tracker=self.root/'project/.tracker';marker=tracker/'settings-audit-delivery/DELIVERED';reached=[]
            with self.assertRaises(allocation.SettingsAuditHold):
                with allocation._hold_native_completed_delivery_originals(writer,owner,bound,first) as (actual,events,verify):
                    self.assertEqual((self.settings_audit_oracle()['event_id'],),events)
                    prior=(marker.stat().st_ino,marker.read_bytes())
                    marker.rename(self.root/'preserved-immutable-first-delivered')
                    marker.write_bytes(prior[1]);marker.chmod(0o600)
                    reached.append((prior[0],marker.stat().st_ino))
            self.assertEqual(1,len(reached));self.assertNotEqual(*reached[0])
            path=tracker/'settings/outbox/0.json';self.assertEqual(projection,(path.stat().st_ino,path.read_bytes()))
            self.assertTrue((tracker/'settings/outbox/1.json').is_file())

    def test_native_complete_pair_originals_history_rebind_after_actual_replay_finalizer_refuses(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            _owner,parent,name,_body=allocation.global_journal._inputs(owner,bound,first)
            history_name=name[:-len('.journal')]+'.history'
            actual=allocation._hold_delivery_catalog_replay;armed=[];reached=[]
            @contextmanager
            def after_actual_replay(*args,**options):
                with actual(*args,**options) as original:
                    yield original
                if armed and not reached:
                    folder=allocation.local._directory(parent,history_name)
                    try:
                        prior=os.stat('HISTORY-RAW',dir_fd=folder,follow_symlinks=False)
                        source=os.open('HISTORY-RAW',os.O_RDONLY,dir_fd=folder)
                        try:raw=os.pread(source,prior.st_size,0)
                        finally:os.close(source)
                        os.rename('HISTORY-RAW','PRESERVED-HISTORY-RAW',src_dir_fd=folder,dst_dir_fd=folder)
                        fd=os.open('HISTORY-RAW',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=folder)
                        try:os.write(fd,raw)
                        finally:os.close(fd)
                        reached.append((prior.st_ino,os.stat('HISTORY-RAW',dir_fd=folder,follow_symlinks=False).st_ino))
                        # Restore the exact name set; preserve the old original
                        # outside its fixed family without deleting evidence.
                        os.rename('PRESERVED-HISTORY-RAW',str(self.root/'preserved-last-immutable-history'),
                            src_dir_fd=folder)
                    finally:os.close(folder)
            with mock.patch.object(allocation,'_hold_delivery_catalog_replay',side_effect=after_actual_replay), \
                    self.assertRaises(allocation.SettingsAuditHold):
                with allocation._hold_native_completed_delivery_originals(writer,owner,bound,first) as (actual_owner,events,verify):
                    self.assertEqual((self.settings_audit_oracle()['event_id'],),events)
                    armed.append(True)
            self.assertEqual(1,len(reached));self.assertNotEqual(*reached[0])
            tracker=self.root/'project/.tracker';path=tracker/'settings/outbox/0.json'
            self.assertEqual(projection,(path.stat().st_ino,path.read_bytes()))
            self.assertTrue((tracker/'settings/outbox/1.json').is_file())

    def test_native_complete_pair_originals_c6_rebind_after_actual_replay_finalizer_refuses(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            action=allocation.local._json(first.action_preimage)
            marker=self.root/'project/.tracker/generations'/action['identity']['generation_id']/'RECEIPT'
            actual=allocation._hold_delivery_catalog_replay;armed=[];reached=[]
            @contextmanager
            def after_actual_replay(*args,**options):
                with actual(*args,**options) as original:
                    yield original
                if armed and not reached:
                    prior=(marker.stat().st_ino,marker.read_bytes())
                    marker.rename(self.root/'preserved-last-immutable-c6-receipt')
                    marker.write_bytes(prior[1]);marker.chmod(0o600)
                    reached.append((prior[0],marker.stat().st_ino))
            with mock.patch.object(allocation,'_hold_delivery_catalog_replay',side_effect=after_actual_replay), \
                    self.assertRaises(allocation.SettingsAuditHold):
                with allocation._hold_native_completed_delivery_originals(writer,owner,bound,first) as (actual_owner,events,verify):
                    self.assertEqual((self.settings_audit_oracle()['event_id'],),events)
                    armed.append(True)
            self.assertEqual(1,len(reached));self.assertNotEqual(*reached[0])
            tracker=self.root/'project/.tracker';path=tracker/'settings/outbox/0.json'
            self.assertEqual(projection,(path.stat().st_ino,path.read_bytes()))
            self.assertTrue((tracker/'settings/outbox/1.json').is_file())

    def test_native_complete_pair_originals_temporary_path_fd_reuse_preserves_interrupt_and_foreign_fd(self):
        with ExitStack() as stack:
            allocation,writer,owner,bound,first,second,projection,first_delivery=self.native_second_audit_completed(stack)
            foreign=self.root/'owned-foreign-path-fd';foreign.write_bytes(b'foreign must survive\n');foreign.chmod(0o600)
            source=os.open(foreign,os.O_RDONLY);duplicate=[];armed=[];reached=[]
            actual_open=allocation.local._open_absolute_directory;actual_stat=os.fstat
            primary=KeyboardInterrupt('original temporary path acquisition interruption')
            def capture(path):
                fd=actual_open(path)
                caller=sys._getframe(1)
                while caller is not None and caller.f_code.co_filename.endswith('/unittest/mock.py'):
                    caller=caller.f_back
                if armed and caller is not None and caller.f_code.co_name=='verify_raw' and not duplicate:
                    duplicate.append(fd)
                return fd
            def displace(fd):
                if duplicate and fd==duplicate[0] and not reached:
                    reached.append(actual_stat(fd).st_ino)
                    os.close(fd);os.dup2(source,fd)
                    raise primary
                return actual_stat(fd)
            try:
                with mock.patch.object(allocation.local,'_open_absolute_directory',side_effect=capture), \
                        mock.patch.object(os,'fstat',side_effect=displace):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        with allocation._hold_native_completed_delivery_originals(writer,owner,bound,first) as (_actual,events,verify):
                            armed.append(True);verify()
                self.assertIs(primary,raised.exception)
                self.assertEqual(1,len(reached))
                self.assertEqual(actual_stat(source).st_ino,actual_stat(duplicate[0]).st_ino)
                self.assertEqual(b'foreign must survive\n',os.pread(duplicate[0],64,0))
            finally:
                if duplicate:
                    try:
                        if actual_stat(duplicate[0]).st_ino==actual_stat(source).st_ino:os.close(duplicate[0])
                    except OSError:pass
                os.close(source)
            tracker=self.root/'project/.tracker';path=tracker/'settings/outbox/0.json'
            self.assertEqual(projection,(path.stat().st_ino,path.read_bytes()))
            self.assertTrue((tracker/'settings/outbox/1.json').is_file())

    def test_actual_tls_c6_allocation_first_writer_replacement_refuses_before_count(self):
        from test_cases.test_req7_settings_audit_allocation import load as load_allocation
        allocation=load_allocation()
        from monitor import issue_tracker_global_attempt_journal as globals_
        native_write=allocation.local._write_new; native_prepare=globals_.prepare_global_unit
        reached=[]; captured=[]; target=self.root/'project/.tracker/settings-audit-allocation/ASSIGNMENTS'
        preserved=self.root/'preserved-real-first-allocation-original'
        def capture(sheet,bound,unit):
            result=native_prepare(sheet,bound,unit); captured.append((sheet,bound,unit)); return result
        def replace_after_writer(parent,name,raw,**options):
            result=native_write(parent,name,raw,**options)
            if name=='ASSIGNMENTS' and not reached:
                original=target.stat(); target.rename(preserved)
                target.write_bytes(raw); target.chmod(0o600)
                reached.append((original.st_ino,target.stat().st_ino))
            return result
        with ExitStack() as scope:
            with mock.patch.object(globals_,'prepare_global_unit',side_effect=capture), \
                    mock.patch.object(allocation.local,'_write_new',side_effect=replace_after_writer):
                with self.assertRaises(allocation.SettingsAuditHold):
                    self.prepare_owned(scope,settings_audits=(self.settings_audit_oracle(),),native_generation=True)
            self.assertEqual(1,len(reached)); self.assertNotEqual(*reached[0]); self.assertEqual(1,len(captured))
            self.assertEqual(preserved.read_bytes(),target.read_bytes())
            self.assertFalse((target.parent/'INITIALIZED').exists())
            sheet,bound,unit=captured[0]; state=globals_.inspect_global_unit(sheet,bound,unit)
            self.assertEqual((0,'UNATTEMPTED_OBSERVATION'),(state.attempt_count,state.outcome))
            self.assertEqual(['0.json'],sorted(p.name for p in (target.parent.parent/'settings/outbox').iterdir()))
            self.assertFalse(any(p.name.endswith('.completion') for p in (self.root/'var/lib/http-ztp-container/issue-tracker').iterdir()))

    def catalog_settings_completed_and_pending(self, *, mirror_foreign_allocation=False):
        """Actual two-C6 catalog, native TLS COMPLETE and original C25 delivery.

        Adapt orchestration only: no substituted owner, C6, journal, read or
        completion observation. The second immutable unit has no audit and
        remains unattempted; it must not be silently ignored by cold discovery.
        """
        from test_cases.test_req7_unit_catalog import load as load_catalog
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        from monitor import issue_tracker_k_store as settings
        from test_cases.test_req7_settings_audit_allocation import load as load_allocation
        catalog=load_catalog(reset_dependencies=False); remote=load()
        from monitor import issue_tracker_global_attempt_journal as globals_
        allocation=load_allocation()
        original_prepare=globals_.prepare_global_unit
        original_owners=self.owners; writers=[]; units=[]; generations=[]; mirror=[]
        original_allocate=allocation.prepare_settings_audit_allocation
        def capture(scope,**kwargs):
            result=original_owners(scope,**kwargs); writers.append(result[2])
            if mirror_foreign_allocation:
                project=self.root/'other-project'; project.mkdir(mode=0o700)
                publication=project/'publication'; publication.mkdir(mode=0o700)
                catalog.local.create_local_commit_store(project,publication)
                other=scope.enter_context(catalog.local.writer_owner(project,publication))
                settings.initialize_local_k_store(project/'.tracker',token=other,
                    initialized_at='2026-10-08T10:00:00Z',acquisition_id='first-use')
                mirror.append(other)
            return result
        def allocate_both(writer,sheet,bound,unit):
            result=original_allocate(writer,sheet,bound,unit)
            if mirror:
                # Construct retained adversarial local evidence with the real
                # old one-unit API, not fake owners/C6/COMPLETE observations.
                original_allocate(mirror[0],sheet,bound,unit)
            return result
        def prepare_both(sheet,bound,first):
            self.assertEqual([],units)
            writer=writers[0]; arguments=send_inputs()
            arguments.update(spreadsheet_id=bound.spreadsheet_id,sheet_id=101,history_sheet_id=105,
                target_nonce='a'*64,history_nonce='d'*64,audits=())
            arguments['business'][0]['observed_values']={'L':{'stringValue':'down'}}
            generation=catalog.local.begin_generation(writer,arguments['manifest'])
            catalog.local.record_intent(writer,generation,literal_xlsx(),kind='xlsx')
            receipt=catalog.local.commit(writer,generation)
            arguments.update(generation_id=generation.generation_id,publish_id=receipt.published_sha256)
            second=catalog.composer.freeze_send_unit(**arguments)
            self.assertEqual(2,generation.sequence); generations.append(generation)
            for unit in (first,second):
                catalog.register_pending_c6_unit(writer,sheet,bound,unit)
                original_prepare(sheet,bound,unit)
            units.extend((first,second))
        with ExitStack() as scope:
            with mock.patch.object(self,'owners',side_effect=capture), \
                    mock.patch.object(globals_,'prepare_global_unit',side_effect=prepare_both), \
                    mock.patch.object(allocation,'prepare_settings_audit_allocation',side_effect=allocate_both):
                writer,sheet,bound,auth,_config,first,docs=self.prepare_owned(
                    scope,settings_audits=(self.settings_audit_oracle(),),native_generation=True)
            responses={name:self.read_owned(scope,writer,sheet,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            remote.record_owned_completion_evidence(writer,sheet,bound,first,**responses)
            # A later independently committed K event is pending, not delivered
            # by the first unit. Its projection and current pointer stay intact.
            settings.apply_local_k_change(self.root/'project/.tracker',token=writer,new_k=7,
                actor='operator:fixture',recorded_at='2026-10-08T10:01:00Z',
                request_id='catalog-later-k',expected_revision=0)
            allocation.record_completed_settings_delivery(writer,sheet,bound,first)
            delivery=allocation.cleanup_completed_settings_outbox(writer,sheet,bound,first)
            if mirror:
                allocation.record_completed_settings_delivery(mirror[0],sheet,bound,first)
                allocation.cleanup_completed_settings_outbox(mirror[0],sheet,bound,first)
            self.assertEqual(('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',
                (self.settings_audit_oracle()['event_id'],)),(delivery.state,delivery.event_ids))
            before=globals_.inspect_catalog_global_units(sheet,bound)
            self.assertEqual(((1,'UNKNOWN'),(0,'UNATTEMPTED_OBSERVATION')),
                tuple((value.attempt_count,value.outcome) for _unit,value in before))
            self.assertEqual(tuple(units),tuple(unit for unit,_value in before))
        return bound,tuple(units),tuple(generations)

    def catalog_later_settings_audit_oracle(self):
        # Independent literal event contract, never decode the production
        # event/outbox or ask the pending reader to construct its expectation.
        canonical=lambda value: (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
        prior=(self.settings_audit_oracle()['details']+'\n').encode()
        payload={'new_k':7,'actor':'operator:fixture','expected_revision':0,'request_id':'catalog-later-k'}
        event=canonical({'schema_version':1,'revision':1,'type':'set_k','old_k':3,'new_k':7,
            'actor':'operator:fixture','recorded_at':'2026-10-08T10:01:00Z','request_id':'catalog-later-k',
            'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
            'predecessor_sha256':hashlib.sha256(prior).hexdigest()})
        return {'event_id':'settings:1:'+hashlib.sha256(event).hexdigest(),
            'recorded_at_utc':'2026-10-08T10:01:00Z','details':event.decode().rstrip('\n')}

    def test_catalog_scoped_pending_reader_returns_only_original_later_event_after_delivery(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        self.catalog_settings_completed_and_pending()
        from monitor import issue_tracker_settings_audit_allocation as allocation
        project=self.root/'project'; before=self._default_recovery_images(project)
        expected=self.catalog_later_settings_audit_oracle(); seen=[]
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
            seen.append(allocation.pending_settings_audits(token))
            self.assertEqual((expected,),seen[0])
            seen[0][0]['details']='caller-local mutation, never frozen evidence'
            self.assertEqual((expected,),allocation.pending_settings_audits(token))
            self.assertEqual((1,7),(state.current_k(token).revision,state.current_k(token).k))
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        with self.assertRaises(allocation.SettingsAuditHold): allocation.pending_settings_audits(token)

    def test_catalog_cold_pending_reader_uses_actual_scoped_pair_without_parent_context(self):
        import subprocess
        self.catalog_settings_completed_and_pending()
        project=self.root/'project'; before=self._default_recovery_images(project)
        program='''from pathlib import Path
import sys,json
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from monitor import issue_tracker_settings_audit_allocation as allocation
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
root=Path(sys.argv[1]); project=root/'project'
assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}
with scoped_fixture(root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
 print(json.dumps(allocation.pending_settings_audits(token),sort_keys=True,separators=(',',':')))
assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}
'''
        child=subprocess.run([sys.executable,'-B','-c',program,str(self.root)],cwd=ROOT,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        self.assertEqual(0,child.returncode,child.stderr)
        self.assertEqual([self.catalog_later_settings_audit_oracle()],json.loads(child.stdout))
        self.assertEqual(before,self._default_recovery_images(project))

    def test_catalog_pending_reader_refuses_context_replacement_after_real_pair_read(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        self.catalog_settings_completed_and_pending()
        from monitor import issue_tracker_settings_audit_allocation as allocation
        project=self.root/'project'; before=self._default_recovery_images(project); reached=[]
        native=allocation.pending_settings_audits_after_completed_unit
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
            context=state._COMPLETED_READ_CONTEXT[token]
            def replaced(*args,**kwargs):
                result=native(*args,**kwargs)
                state._COMPLETED_READ_CONTEXT[token]=tuple(list(context)); reached.append(True)
                return result
            try:
                with mock.patch.object(allocation,'pending_settings_audits_after_completed_unit',side_effect=replaced):
                    with self.assertRaises(allocation.SettingsAuditHold): allocation.pending_settings_audits(token)
                self.assertEqual([True],reached,'must refuse after the real paired read, not before reaching it')
            finally:
                # Restore only this test-owned registry after the fault result
                # assertions so the outer original factory can close normally.
                state._COMPLETED_READ_CONTEXT[token]=context
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_catalog_settings_discovery_rejects_actual_c6_from_a_different_project(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        self.catalog_settings_completed_and_pending(mirror_foreign_allocation=True)
        project=self.root/'other-project'; before=self._default_recovery_images(project)
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,project/'publication'):
                self.fail('foreign original C6 cannot authorize this project settings')
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_cold_settings_discovery_uses_actual_catalog_journal_and_preserves_pending_unit(self):
        import subprocess
        bound,units,_generations=self.catalog_settings_completed_and_pending()
        project=self.root/'project'; before=self._default_recovery_images(project)
        program='''from pathlib import Path
import sys
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
root=Path(sys.argv[1]); project=root/'project'
assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}
with scoped_fixture(root,sheet),state.tracker_settings_writer(project,project/'publication') as token:
 value=state.current_k(token); print(value.revision,value.k)
assert state._COMPLETED_READ_CONTEXT=={} and state._COMPLETED_ORIGINAL_GUARDS=={}
print('original catalog context revoked')
'''
        child=subprocess.run([sys.executable,'-B','-c',program,str(self.root)],cwd=ROOT,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        self.assertEqual(0,child.returncode,child.stderr)
        self.assertEqual(b'1 7\noriginal catalog context revoked\n',child.stdout)
        self.assertEqual(before,self._default_recovery_images(project))
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())
        self.assertTrue((project/'.tracker/settings/outbox/1.json').is_file())
        parent=self.root/'var/lib/http-ztp-container/issue-tracker'
        stem=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
        self.assertFalse((parent/(stem+'.journal')).exists(),'never manufacture a legacy shadow journal')
        self.assertTrue((parent/(stem+'.unit-'+units[1].unit_id+'.journal')).is_dir())

    def test_catalog_settings_discovery_pins_pending_c6_before_returning_completed_k(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        _bound,_units,generations=self.catalog_settings_completed_and_pending()
        # The fixture reloads the actual canonical catalog before issuing its
        # owners. Observe that current module, never a stale pre-fixture alias.
        from monitor import issue_tracker_unit_catalog as catalog
        project=self.root/'project'
        # Keep the first COMPLETE/DELIVERED pair untouched. Replace an original
        # second-unit C6 image with identical bytes, outside any test sanitizer.
        generation=generations[0]
        candidates=[p for p in (project/'.tracker').rglob('*')
                    if p.is_file() and generation.generation_id in str(p)]
        self.assertTrue(candidates,'actual pending generation originals must exist')
        path=next(p for p in candidates if p.name=='MANIFEST')
        image=path.read_bytes()
        native=catalog.hold_pending_project_c6_units; reached=[]; changed=[]
        @contextmanager
        def actual_c6(*args,**kwargs):
            reached.append(True)
            with native(*args,**kwargs) as actual:
                # C6 facts persist the actual generation/content; this holder
                # pins its FD/stat image for the current observation. Inject
                # AFTER that pin, before discovery may return a K context.
                path.rename(self.root/'preserved-catalog-pending-manifest')
                path.write_bytes(image); path.chmod(0o600)
                changed.append(self._default_recovery_images(project))
                yield actual
        with scoped_fixture(self.root,sheet),mock.patch.object(catalog,'hold_pending_project_c6_units',side_effect=actual_c6):
            with self.assertRaises(state.TrackerStateHold):
                with state.tracker_settings_writer(project,project/'publication') as token:
                    state.current_k(token)
        self.assertEqual([True],reached,'rejection must reach actual ALL-C6 validation, not a missing legacy path')
        self.assertEqual(1,len(changed))
        self.assertEqual(changed[0],self._default_recovery_images(project))
        self.assertEqual(image,(self.root/'preserved-catalog-pending-manifest').read_bytes())
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())
        self.assertTrue((project/'.tracker/settings/outbox/1.json').is_file())

    def test_catalog_settings_first_k_interruption_revokes_both_original_registries(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        self.catalog_settings_completed_and_pending()
        project=self.root/'project'; before=self._default_recovery_images(project)
        native=state.current_k; tokens=[]; primary=RuntimeError('catalog initial K interruption')
        def interrupted(token,**kwargs):
            self.assertIn(token,state._COMPLETED_READ_CONTEXT)
            self.assertIn(token,state._COMPLETED_ORIGINAL_GUARDS)
            value=native(token,**kwargs); self.assertEqual((1,7),(value.revision,value.k))
            tokens.append(token)
            raise primary
        try:
            with scoped_fixture(self.root,sheet),mock.patch.object(state,'current_k',side_effect=interrupted):
                with self.assertRaises(RuntimeError) as caught:
                    with state.tracker_settings_writer(project,project/'publication'):
                        self.fail('interrupted first K must not yield a writer')
            self.assertIs(primary,caught.exception)
            self.assertEqual(1,len(tokens))
            self.assertEqual(before,self._default_recovery_images(project))
            with self.assertRaises(state.TrackerStateHold): native(tokens[0])
            self.assertEqual({},state._COMPLETED_READ_CONTEXT)
            self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        finally:
            for token in tokens:
                state._COMPLETED_READ_CONTEXT.pop(token,None)
                state._COMPLETED_ORIGINAL_GUARDS.pop(token,None)

    def test_catalog_settings_scope_keeps_pending_c6_original_through_last_k_read(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        _bound,_units,generations=self.catalog_settings_completed_and_pending()
        project=self.root/'project'; generation=generations[0]; reached=[]; changed=[]
        path=next(p for p in (project/'.tracker').rglob('MANIFEST')
                  if generation.generation_id in str(p))
        image=path.read_bytes()
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,project/'publication') as token:
                value=state.current_k(token)
                self.assertEqual((1,7),(value.revision,value.k))
                path.rename(self.root/'preserved-catalog-last-manifest')
                path.write_bytes(image); path.chmod(0o600); reached.append(True)
                changed.append(self._default_recovery_images(project))
        self.assertEqual([True],reached,'scope must first qualify the real catalog before late substitution')
        self.assertEqual(changed[0],self._default_recovery_images(project))
        self.assertEqual(image,(self.root/'preserved-catalog-last-manifest').read_bytes())
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())
        self.assertTrue((project/'.tracker/settings/outbox/1.json').is_file())

    def test_actual_complete_then_delivered_binds_original_audits_and_preserves_outbox_unknown(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_global_attempt_journal as journal
        module=load(); audit=self.settings_audit_oracle()
        self.assertTrue(hasattr(allocation,'record_completed_settings_delivery'),
            'C25 needs durable DELIVERED only after a validated original COMPLETE proof')
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(audit,))
            original={p:p.read_bytes() for p in (self.root/'project/.tracker/settings').rglob('*') if p.is_file()}
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            seen=allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual(('DELIVERED-PRESENT-OUTBOX-RETAINED',unit.unit_id,(audit['event_id'],)),
                             (seen.state,seen.unit_id,seen.event_ids))
            self.assertFalse(hasattr(seen,'permit'))
            self.assertEqual(original,{p:p.read_bytes() for p in original})
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                           journal.inspect_global_unit(owner,bound,unit).outcome))
            self.assertEqual(seen,allocation.inspect_completed_settings_delivery(writer,owner,bound,unit))
            with self.assertRaises(allocation.SettingsAuditHold):
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)
        # A cold interpreter uses only the retained original unit/allocation/
        # COMPLETE pair and freshly acquired real local locks, no live registry.
        import subprocess
        from dataclasses import asdict
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor import issue_tracker_spreadsheet_owner as owner, issue_tracker_local_commit as local
from monitor import issue_tracker_global_attempt_journal as journal, issue_tracker_settings_audit_allocation as audit
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
path=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((path/'ACTION-PREIMAGE').read_bytes(),(path/'WIRE').read_bytes())
with local.writer_owner(root/'project',root/'project/publication') as writer, scoped_fixture(root,owner),owner.spreadsheet_owner(bound) as token:
 seen=audit.inspect_completed_settings_delivery(writer,token,bound,unit)
 state=journal.inspect_global_unit(token,bound,unit)
 print(seen.state,len(seen.event_ids),state.attempt_count,state.outcome)
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'DELIVERED-PRESENT-OUTBOX-RETAINED 1 1 UNKNOWN\n',cold.stdout)

    def test_settings_delivery_missing_or_nonsemantic_complete_never_consumes_event(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        module=load(); audit=self.settings_audit_oracle()
        self.assertTrue(hasattr(allocation,'record_completed_settings_delivery'),
            'C25 must reject unproved COMPLETE before writing any delivery record')
        for fault in ('missing','corrupt-history'):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(audit,))
                if fault=='corrupt-history':
                    responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                               for name,(kind,value) in docs.items()}
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                    proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                    (proof/'HISTORY-RAW').write_bytes(b'{"not":"the original full History"}')
                original={p:p.read_bytes() for p in (self.root/'project/.tracker').rglob('*') if p.is_file()}
                with self.assertRaises(allocation.SettingsAuditHold):
                    allocation.record_completed_settings_delivery(writer,owner,bound,unit)
                self.assertEqual(original,{p:p.read_bytes() for p in original})
                self.assertFalse((self.root/'project/.tracker/settings-audit-delivery').exists())
                self.assertEqual((audit,),allocation.pending_settings_audits(writer))
            if fault=='missing': self.doCleanups(); self.setUp()

    def test_delivery_header_original_cannot_change_before_delivered_commit(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        module=load(); audit=self.settings_audit_oracle()
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(audit,))
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            delivery=self.root/'project/.tracker/settings-audit-delivery'
            writing=allocation._write_delivery_file; changed=[]
            def written_then_rebound(parent,name,raw):
                result=writing(parent,name,raw)
                if name=='HEADER' and not changed:
                    path=delivery/'HEADER'; image=path.read_bytes()
                    path.rename(self.root/'preserved-delivery-header')
                    path.write_bytes(image); path.chmod(0o600); changed.append(True)
                return result
            with mock.patch.object(allocation,'_write_delivery_file',side_effect=written_then_rebound), \
                    self.assertRaises(allocation.SettingsAuditHold):
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual([True],changed)
            self.assertFalse((delivery/'DELIVERED').exists(),
                             'never commit DELIVERED after its HEADER original was replaced')
            self.assertEqual((audit,),allocation.pending_settings_audits(writer))

    def test_delivery_barrier_failure_retains_partial_without_adoption_cleanup_or_resend(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_global_attempt_journal as journal
        import os
        audit=self.settings_audit_oracle()
        for boundary in range(1,7):
            with self.subTest(boundary=boundary),ExitStack() as stack:
                module=load()
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(audit,))
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                delivery=self.root/'project/.tracker/settings-audit-delivery'
                sync=os.fsync; reached=[]
                def failing(fd):
                    if delivery.exists():
                        info=os.fstat(fd)
                        candidates=[delivery.parent,delivery,*delivery.iterdir()]
                        if any((p.stat().st_dev,p.stat().st_ino)==(info.st_dev,info.st_ino) for p in candidates):
                            reached.append(fd)
                            if len(reached)==boundary: raise OSError('owned delivery barrier fault')
                    return sync(fd)
                original={p:p.read_bytes() for p in (self.root/'project/.tracker/settings').rglob('*') if p.is_file()}
                with mock.patch('os.fsync',side_effect=failing),self.assertRaises(allocation.SettingsAuditHold):
                    allocation.record_completed_settings_delivery(writer,owner,bound,unit)
                self.assertEqual(boundary,len(reached)); self.assertTrue(delivery.is_dir())
                if boundary<=4: self.assertFalse((delivery/'DELIVERED').exists())
                retained={p:p.read_bytes() for p in delivery.iterdir()}
                with self.assertRaises(allocation.SettingsAuditHold):
                    allocation.record_completed_settings_delivery(writer,owner,bound,unit)
                self.assertEqual(retained,{p:p.read_bytes() for p in delivery.iterdir()})
                self.assertEqual(original,{p:p.read_bytes() for p in original})
                self.assertEqual((audit,),allocation.pending_settings_audits(writer))
                self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                               journal.inspect_global_unit(owner,bound,unit).outcome))
            if boundary!=6: self.doCleanups(); self.setUp()

    def test_delivery_cold_reader_missing_partial_alias_and_changed_complete_hold(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        import os
        audit=self.settings_audit_oracle()
        faults=('missing-marker','changed-header','same-byte-header','header-alias','partial-namespace','changed-complete')
        for index,fault in enumerate(faults):
            with self.subTest(fault=fault),ExitStack() as stack:
                module=load()
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(audit,))
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                allocation.record_completed_settings_delivery(writer,owner,bound,unit)
                delivery=self.root/'project/.tracker/settings-audit-delivery'
                saved=self.root/'preserved-delivery-original'
                if fault=='missing-marker': (delivery/'DELIVERED').rename(saved)
                elif fault=='changed-header': (delivery/'HEADER').write_bytes(b'{}\n')
                elif fault in ('same-byte-header','header-alias'):
                    image=(delivery/'HEADER').read_bytes(); (delivery/'HEADER').rename(saved)
                    if fault=='same-byte-header': (delivery/'HEADER').write_bytes(image); (delivery/'HEADER').chmod(0o600)
                    else: os.link(saved,delivery/'HEADER')
                elif fault=='partial-namespace': (delivery/'unexpected').write_bytes(b'partial\n')
                else:
                    proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                    (proof/'COMPLETE').write_bytes(b'{}\n')
                original={p:p.read_bytes() for p in (self.root/'project/.tracker/settings').rglob('*') if p.is_file()}
                with self.assertRaises(allocation.SettingsAuditHold):
                    allocation.inspect_completed_settings_delivery(writer,owner,bound,unit)
                with self.assertRaises(allocation.SettingsAuditHold):
                    allocation.pending_settings_audits_after_completed_unit(writer,owner,bound,unit)
                self.assertEqual(original,{p:p.read_bytes() for p in original})
                self.assertEqual((audit,),allocation.pending_settings_audits(writer))
            if index+1<len(faults): self.doCleanups(); self.setUp()

    def test_completed_unit_pending_projection_excludes_only_original_delivered_events_not_later_k(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation, issue_tracker_k_store as settings
        module=load(); audit=self.settings_audit_oracle()
        self.assertTrue(hasattr(allocation,'pending_settings_audits_after_completed_unit'),
            'retained outbox of a verified delivered audit is cleanup-only, never pending resend')
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(audit,))
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            self.assertEqual((),allocation.pending_settings_audits_after_completed_unit(writer,owner,bound,unit))
            settings.apply_local_k_change(self.root/'project/.tracker',token=writer,new_k=4,
                actor='operator:fixture',recorded_at='2026-10-08T10:01:00Z',request_id='change-1',expected_revision=0)
            # Literal independent revision 1; not generated from the pending API.
            payload={'new_k':4,'actor':'operator:fixture','expected_revision':0,'request_id':'change-1'}
            # Existing independent K-chain contract names accepted changes set_k.
            event=canonical({'schema_version':1,'revision':1,'type':'set_k','old_k':3,'new_k':4,
                'actor':'operator:fixture','recorded_at':'2026-10-08T10:01:00Z','request_id':'change-1',
                'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
                'predecessor_sha256':hashlib.sha256((audit['details']+'\n').encode()).hexdigest()})
            expected={'event_id':'settings:1:'+hashlib.sha256(event).hexdigest(),
                'recorded_at_utc':'2026-10-08T10:01:00Z','details':event.decode().rstrip('\n')}
            self.assertEqual((expected,),allocation.pending_settings_audits_after_completed_unit(writer,owner,bound,unit))
            self.assertEqual([audit['event_id']],list(allocation.inspect_completed_settings_delivery(writer,owner,bound,unit).event_ids))
            self.assertEqual(['0.json','1.json'],sorted(p.name for p in (self.root/'project/.tracker/settings/outbox').iterdir()))

    def test_actual_owned_all_business_and_history_continuity_includes_noop_and_preserves_unknown(self):
        from monitor import issue_tracker_history_preread_journal as before
        self.assertTrue(hasattr(before, 'observe_owned_business_continuity'),
                        'fresh ALL business including NOOP and original History must be checked under actual owners')
        from contextlib import ExitStack
        from test_cases.test_req7_history_preread_journal import Req7BusinessPrereadJournalDirectTests
        from monitor.issue_tracker_send_unit import freeze_send_unit
        prototype = Req7BusinessPrereadJournalDirectTests()
        prototype.setUp(); self.addCleanup(prototype.doCleanups)
        before = prototype.module
        from monitor import issue_tracker_global_attempt_journal as journal, issue_tracker_enrollment_journal as enroll
        with ExitStack() as stack:
            _local, _ownership, writer, owner, bound, auth, _config = self.owners(stack,target_id=TARGET)
            original = enroll.prepare_enrollment_journal(owner, bound, prototype.identity)
            nonces = {title: nonce for title, _sid, nonce in original.nonces}
            business = [dict(item) for item in prototype.args['business']]
            business[0]['values'] = {'L': '[MONITOR][down][fabric] old'}
            business[1]['values'] = {'L': '[MONITOR][down][fabric] new'}
            for item in business: item['observed_values'] = {'L': {'stringValue': '[MONITOR][down][fabric] old'}}
            unit = freeze_send_unit(**{**prototype.args, 'business': tuple(business), 'sheet_id': 101, 'history_sheet_id': 105,
                'target_nonce': nonces['ETH&IB Switch'], 'history_nonce': nonces['Update_History'], 'preread_sha256': prototype.digest})
            journal.prepare_global_unit(owner,bound,unit)
            before.prepare_history_preread(owner,bound,unit,prototype.plan,prototype.raw)
            before.prepare_business_preread(owner,bound,prototype.identity,unit,
                manifest=prototype.manifest,business_reads=tuple(prototype.reads))
            journal.record_global_attempt_intent(owner,bound,unit)
            state = self.root/'var/lib/http-ztp-container/issue-tracker'
            retained = {str(path.relative_to(state)):path.read_bytes() for path in state.rglob('*') if path.is_file()}
            identity_read = self.read_owned(stack,writer,owner,bound,auth,'template_identity',identity_response())
            history_read = self.read_owned(stack,writer,owner,bound,auth,'history_tail',json.loads(prototype.raw.data))
            common = {}
            for role,kind in (('discovery','activity'),('occupancy','insertion')):
                common[role+'_response'] = self.read_owned(stack,writer,owner,bound,auth,kind,
                    json.loads(prototype.reads[0][role+'_response'].data),sheet='ETH&IB Switch')
            current = tuple({'operation_id':reading['operation_id'],**common,
                'row_response':self.read_owned(stack,writer,owner,bound,auth,'row',json.loads(reading['row_response'].data),
                    sheet='ETH&IB Switch',row=index+3)} for index,reading in enumerate(prototype.reads))
            options = dict(identity_response=identity_read,history_response=history_read,business_reads=current)
            observed = before.observe_owned_business_continuity(writer,owner,bound,unit,**options)
            self.assertEqual((2,1,prototype.digest),(observed.operations_retained,observed.noop_operations,observed.preread_sha256))
            self.assertFalse(hasattr(observed,'permit')); self.assertFalse(hasattr(observed,'complete'))
            variants = [dict(identity_response=replace(identity_read)),dict(history_response=replace(history_read)),
                        dict(business_reads=current[1:]),dict(business_reads=tuple(reversed(current)))]
            for index in range(2):
                for name in common.keys() | {'row_response'}:
                    changed = [dict(item) for item in current]; changed[index][name] = replace(current[index][name])
                    variants.append(dict(business_reads=tuple(changed)))
            # Operator edit on the NOOP row cannot silently remove its original decision.
            noop = deepcopy(json.loads(prototype.reads[0]['row_response'].data))
            noop['sheets'][0]['data'][0]['rowData'][0]['values'][11]['userEnteredValue'] = {'stringValue':'operator changed NOOP'}
            read = self.read_owned(stack,writer,owner,bound,auth,'row',noop,sheet='ETH&IB Switch',row=3)
            changed = [dict(item) for item in current]; changed[0]['row_response'] = read
            variants.append(dict(business_reads=tuple(changed)))
            history = deepcopy(json.loads(prototype.raw.data))
            history['sheets'][0]['properties']['gridProperties']['rowCount'] += 1
            variants.append(dict(history_response=self.read_owned(stack,writer,owner,bound,auth,'history_tail',history)))
            for changes in variants:
                with self.subTest(changes=tuple(changes)), self.assertRaises(before.HistoryPrereadHold) as caught:
                    before.observe_owned_business_continuity(writer,owner,bound,unit,**{**options,**changes})
                self.assertIsNone(caught.exception.__context__)
            # Same-byte new inode is not the retained original image. Cover
            # replacement just after initial decoding, not only later reads.
            import os
            business_path = state/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.business')/'BUSINESS-RAW'
            preserved = self.root/'preserved-owned-business-original'
            original_raw = business_path.read_bytes(); original_inspect = before._inspect_business
            rebound = [False]
            def replace_after_original_decode(*args,**kwargs):
                result = original_inspect(*args,**kwargs)
                if not rebound[0]:
                    business_path.rename(preserved); business_path.write_bytes(original_raw); business_path.chmod(0o600)
                    rebound[0] = True
                return result
            try:
                with mock.patch.object(before,'_inspect_business',side_effect=replace_after_original_decode):
                    with self.assertRaises(before.HistoryPrereadHold):
                        before.observe_owned_business_continuity(writer,owner,bound,unit,**options)
            finally:
                if rebound[0]: os.replace(preserved,business_path)  # restore only this owned synthetic original
            from monitor import issue_tracker_history_read_launcher as fixed_reads
            with mock.patch.object(fixed_reads,'_monotonic',return_value=__import__('time').monotonic()+31):
                with self.assertRaises(before.HistoryPrereadHold):
                    before.observe_owned_business_continuity(writer,owner,bound,unit,**options)
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                          journal.inspect_global_unit(owner,bound,unit).outcome))
            self.assertEqual(retained,{str(path.relative_to(state)):path.read_bytes() for path in state.rglob('*') if path.is_file()})

    def test_actual_issued_match_rejects_original_count_and_history_namespace_drift(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        module=load()
        for fault in ('count','history-directory'):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                current=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.history')
                preserved=self.root/'preserved-issued-match-history'
                original={p.name:p.read_bytes() for p in current.iterdir()}
                decoding=module.decode.decode_history_tail; changed=[]
                def decode_then_change(plan,raw,**options):
                    result=decoding(plan,raw,**options)
                    if raw is responses['history_response'] and not changed:
                        if fault=='count': journal.record_global_attempt_intent(owner,bound,unit)
                        else:
                            current.rename(preserved); current.mkdir(mode=0o700)
                            for name,image in original.items():
                                path=current/name; path.write_bytes(image); path.chmod(0o600)
                        changed.append(True)
                    return result
                with mock.patch.object(module.decode,'decode_history_tail',side_effect=decode_then_change):
                    with self.assertRaises(module.RemoteHistoryHold):
                        module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)
                self.assertEqual([True],changed)
                seen=journal.inspect_global_unit(owner,bound,unit)
                self.assertEqual((2 if fault=='count' else 1,'UNKNOWN'),(seen.attempt_count,seen.outcome))
                if fault=='history-directory':
                    self.assertEqual(original,{p.name:p.read_bytes() for p in preserved.iterdir()})
                    self.assertEqual(original,{p.name:p.read_bytes() for p in current.iterdir()})
            # Each subcase needs a genuinely new owned state, never an adopted
            # UNKNOWN or a hand-reset original counter.
            if fault=='count': self.doCleanups(); self.setUp()

    def test_actual_owned_complete_proof_is_durable_but_never_applied_or_barrier_release(self):
        module=load()
        self.assertTrue(hasattr(module,'record_owned_completion_evidence'),
                        'fixed issued reads must persist ALL proof rows and original journal identities')
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            state=self.root/'var/lib/http-ztp-container/issue-tracker'
            retained={p:p.read_bytes() for p in state.rglob('*') if p.is_file()}
            seen=module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertEqual(('COMPLETE-PRESENT-NOT-APPLIED',1,2),(seen.state,seen.attempt_count,seen.history_rows_matched))
            self.assertFalse(hasattr(seen,'permit')); self.assertFalse(hasattr(seen,'applied'))
            proof=state/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
            self.assertEqual({'IDENTITY-RAW','HEADERS-RAW','METADATA-RAW','HISTORY-RAW','HEADER','COMPLETE'},
                             {p.name for p in proof.iterdir()})
            for name,file in (('identity_response','IDENTITY-RAW'),('headers_response','HEADERS-RAW'),
                              ('metadata_response','METADATA-RAW'),('history_response','HISTORY-RAW')):
                self.assertEqual(responses[name].data,(proof/file).read_bytes())
            self.assertEqual(retained,{p:p.read_bytes() for p in retained})
            self.assertEqual(seen,module.inspect_completion_evidence(owner,bound,unit))
            with self.assertRaises(module.RemoteHistoryHold):
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                           journal.inspect_global_unit(owner,bound,unit).outcome))
            with self.assertRaises(journal.GlobalAttemptHold): journal.prepare_global_unit(owner,bound,unit)
        # No live read registry, shared Python object, old token or inherited
        # lock FD survives. The child reads the actual retained original store.
        import subprocess
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor import issue_tracker_spreadsheet_owner as owner, issue_tracker_remote_history_match as match
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
path=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((path/'ACTION-PREIMAGE').read_bytes(),(path/'WIRE').read_bytes())
with scoped_fixture(root,owner),owner.spreadsheet_owner(bound) as token:
 seen=match.inspect_completion_evidence(token,bound,unit)
 print(seen.state,seen.attempt_count,seen.history_rows_matched)
'''
        from dataclasses import asdict
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'COMPLETE-PRESENT-NOT-APPLIED 1 2\n',cold.stdout)

    def test_actual_complete_without_original_c6_generation_cannot_advance_applied(self):
        """Real issued reads and full History are necessary, not C6 authority."""
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            observed=module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertEqual(('COMPLETE-PRESENT-NOT-APPLIED',1,2),
                             (observed.state,observed.attempt_count,observed.history_rows_matched))
            roots=(self.root/'project/.tracker',
                   self.root/'var/lib/http-ztp-container/issue-tracker')
            retained={p:(p.stat().st_ino,p.read_bytes())
                      for root in roots for p in root.rglob('*') if p.is_file()}
            self.assertTrue(callable(getattr(module,'record_owned_applied_evidence',None)),
                            'REQ7 original completion has no governed APPLIED handoff')
            # This actual counted unit has only a digest-shaped generation;
            # there is no committed original native C6 generation/receipt.
            with self.assertRaises(module.RemoteHistoryHold):
                module.record_owned_applied_evidence(writer,owner,bound,unit,generation=None)
            self.assertEqual(retained,{p:(p.stat().st_ino,p.read_bytes())
                                      for root in roots for p in root.rglob('*') if p.is_file()})
            historical=self.current_global_state(owner,bound,unit)
            self.assertEqual((1,'UNKNOWN'),(historical.attempt_count,historical.outcome))
            self.assertEqual(observed,module.inspect_completion_evidence(owner,bound,unit))

    def test_native_c6_and_complete_record_applied_only_for_sent_business(self):
        """Full mapping retains NOOP; only genuinely sent operations are APPLIED."""
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,native_generation=True)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            roots=(self.root/'project/.tracker/generations',
                   self.root/'var/lib/http-ztp-container/issue-tracker')
            retained={p:(p.stat().st_ino,p.read_bytes())
                      for root in roots for p in root.rglob('*') if p.is_file()}
            self.assertTrue(callable(getattr(module,'record_owned_applied_evidence',None)),
                            'complete original C6/History proof needs durable APPLIED evidence')
            applied=module.record_owned_applied_evidence(writer,owner,bound,unit,
                                                        generation=self.native_generation)
            self.assertEqual(('APPLIED',1,('switch:0001',)),
                             (applied.state,applied.sequence,applied.applied_operation_ids))
            self.assertEqual(self.native_generation.generation_id,applied.generation_id)
            self.assertEqual(unit.unit_id,applied.unit_id)
            self.assertFalse(hasattr(applied,'permit'))
            self.assertEqual(retained,{p:(p.stat().st_ino,p.read_bytes())
                                      for root in roots for p in root.rglob('*') if p.is_file()})
            self.assertEqual(applied,module.inspect_owned_applied_evidence(writer,owner,bound,unit,
                                                                          generation=self.native_generation))
            historical=self.current_global_state(owner,bound,unit)
            self.assertEqual((1,'UNKNOWN'),(historical.attempt_count,historical.outcome))
            # A duplicate is read-only replay, never a new original marker.
            tracker=self.root/'project/.tracker'
            saved={p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()}
            self.assertEqual(applied,module.record_owned_applied_evidence(writer,owner,bound,unit,
                                                                         generation=self.native_generation))
            self.assertEqual(saved,{p:(p.stat().st_ino,p.read_bytes())
                                   for p in tracker.rglob('*') if p.is_file()})

    def test_actual_completed_to_applied_handoff_uses_one_cold_c6_admission_and_original_replays(self):
        from monitor import issue_tracker_send_unit as composer
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,unit=self.prepare_native_completed(stack,module)
            tracker=self.root/'project/.tracker'
            retained={p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()}
            with mock.patch.object(composer,'_read_original_generation_identity',
                    wraps=composer._read_original_generation_identity) as cold:
                applied=module.record_owned_applied_evidence(writer,owner,bound,unit,
                                                            generation=self.native_generation)
            self.assertEqual(('APPLIED',1,('switch:0001',)),
                             (applied.state,applied.sequence,applied.applied_operation_ids))
            self.assertEqual(1,cold.call_count,'one original C6 admission across actual durable APPLIED handoff')
            self.assertEqual(retained,{p:(p.stat().st_ino,p.read_bytes()) for p in retained})
            self.assertEqual((1,'UNKNOWN'),(self.current_global_state(owner,bound,unit).attempt_count,
                                          self.current_global_state(owner,bound,unit).outcome))

    def test_native_complete_without_applied_pair_cannot_write_key_watermark(self):
        module=load()
        self.assertTrue(callable(getattr(module,'record_owned_applied_key_watermarks',None)),
                        'C6/C19 COMPLETE alone must not advance key high-water')
        with ExitStack() as stack:
            writer,owner,bound,unit=self.prepare_native_completed(stack,module)
            original={p:(p.stat().st_ino,p.read_bytes())
                      for p in self.root.rglob('*') if p.is_file()}
            with self.assertRaises(module.RemoteHistoryHold):
                module.record_owned_applied_key_watermarks(writer,owner,bound,unit,
                                                          generation=self.native_generation)
            self.assertEqual(original,{p:(p.stat().st_ino,p.read_bytes())
                                       for p in self.root.rglob('*') if p.is_file()})
            historical=self.current_global_state(owner,bound,unit)
            self.assertEqual((1,'UNKNOWN'),(historical.attempt_count,historical.outcome))

    def test_native_applied_key_watermark_excludes_noop_and_preserves_original_bundle(self):
        module=load()
        self.assertTrue(callable(getattr(module,'record_owned_applied_key_watermarks',None)),
                        'C6/C19 APPLIED requires durable key high-water before successor admission')
        self.assertTrue(callable(getattr(module,'inspect_owned_applied_key_watermarks',None)),
                        'cold/replayed key high-water needs an original-proof-qualified reader')
        with ExitStack() as stack:
            writer,owner,bound,unit=self.prepare_native_completed(stack,module)
            module.record_owned_applied_evidence(writer,owner,bound,unit,
                                                generation=self.native_generation)
            roots=(self.root/'project/.tracker/generations',
                   self.root/'var/lib/http-ztp-container/issue-tracker')
            original={p:(p.stat().st_ino,p.read_bytes())
                      for root in roots for p in root.rglob('*') if p.is_file()}
            # Literal expected key comes from the independently authored fixture:
            # switch:0000 is NOOP; only switch:0001 genuinely travelled.
            expected=((('switch','node0001','down','fabric'),1),)
            seen=module.record_owned_applied_key_watermarks(writer,owner,bound,unit,
                                                           generation=self.native_generation)
            self.assertEqual(expected,seen)
            self.assertEqual(original,{p:(p.stat().st_ino,p.read_bytes())
                                       for root in roots for p in root.rglob('*') if p.is_file()})
            tracker=self.root/'project/.tracker'
            saved={p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()}
            self.assertEqual(expected,module.inspect_owned_applied_key_watermarks(writer,owner,bound,unit,
                                                                                  generation=self.native_generation))
            self.assertEqual(expected,module.record_owned_applied_key_watermarks(writer,owner,bound,unit,
                                                                                 generation=self.native_generation))
            self.assertEqual(saved,{p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()})
            historical=self.current_global_state(owner,bound,unit)
            self.assertEqual((1,'UNKNOWN'),(historical.attempt_count,historical.outcome))

    def test_key_watermark_same_byte_applied_replacement_never_becomes_new_original(self):
        module=load()
        self.assertTrue(callable(getattr(module,'record_owned_applied_key_watermarks',None)),
                        'C6/C19 key high-water needs actual original APPLIED evidence')
        with ExitStack() as stack:
            writer,owner,bound,unit=self.prepare_native_completed(stack,module)
            module.record_owned_applied_evidence(writer,owner,bound,unit,
                                                generation=self.native_generation)
            marker=self.root/'project/.tracker'/('REMOTE-APPLIED-'+unit.unit_id)
            original=marker.read_bytes(); marker.rename(self.root/'preserved-key-watermark-applied')
            marker.write_bytes(original); marker.chmod(0o600)
            retained={p:(p.stat().st_ino,p.read_bytes())
                      for p in self.root.rglob('*') if p.is_file()}
            with self.assertRaises(module.RemoteHistoryHold):
                module.record_owned_applied_key_watermarks(writer,owner,bound,unit,
                                                          generation=self.native_generation)
            self.assertEqual(retained,{p:(p.stat().st_ino,p.read_bytes())
                                       for p in self.root.rglob('*') if p.is_file()})
            self.assertEqual(original,marker.read_bytes())
            self.assertNotEqual(marker.stat().st_ino,
                                (self.root/'preserved-key-watermark-applied').stat().st_ino)


    def test_key_watermark_interrupted_marker_keeps_partial_evidence_and_blocks_recreation(self):
        from monitor import issue_tracker_local_commit as local
        module=load()
        self.assertTrue(callable(getattr(module,'record_owned_applied_key_watermarks',None)),
                        'partial key high-water must block repair and successor admission')
        with ExitStack() as stack:
            writer,owner,bound,unit=self.prepare_native_completed(stack,module)
            module.record_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
            tracker=self.root/'project/.tracker'
            saved={p:(p.stat().st_ino,p.read_bytes()) for p in self.root.rglob('*') if p.is_file()}
            original=local._rename_new; reached=[]
            marker='REMOTE-KEY-HIGH-WATER-'+unit.unit_id
            def interrupt(parent,source,destination,**options):
                if destination==marker:
                    reached.append(True)
                    raise OSError('owned representative key-watermark marker interruption')
                return original(parent,source,destination,**options)
            with mock.patch.object(local,'_rename_new',side_effect=interrupt):
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_applied_key_watermarks(writer,owner,bound,unit,
                                                              generation=self.native_generation)
            self.assertEqual([True],reached)
            self.assertTrue((tracker/('REMOTE-KEY-HIGH-WATER-STARTED-'+unit.unit_id)).is_file())
            self.assertFalse((tracker/marker).exists())
            self.assertEqual(1,len(list(tracker.glob('.pending-*'))))
            self.assertEqual(saved,{p:(p.stat().st_ino,p.read_bytes()) for p in saved})
            retained={p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()}
            for api in (module.record_owned_applied_key_watermarks,module.inspect_owned_applied_key_watermarks):
                with self.assertRaises(module.RemoteHistoryHold):
                    api(writer,owner,bound,unit,generation=self.native_generation)
            self.assertEqual(retained,{p:(p.stat().st_ino,p.read_bytes())
                                      for p in tracker.rglob('*') if p.is_file()})

    def test_key_watermark_native_cold_process_reopens_all_originals_without_parent_flags(self):
        from dataclasses import asdict
        import subprocess
        module=load()
        self.assertTrue(callable(getattr(module,'record_owned_applied_key_watermarks',None)),
                        'cold high-water must reopen the original durable C6/COMPLETE/APPLIED proof')
        with ExitStack() as stack:
            writer,owner,bound,unit=self.prepare_native_completed(stack,module)
            module.record_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
            self.assertEqual(((('switch','node0001','down','fabric'),1),),
                module.record_owned_applied_key_watermarks(writer,owner,bound,unit,
                                                          generation=self.native_generation))
        saved={p:(p.stat().st_ino,p.read_bytes()) for p in self.root.rglob('*') if p.is_file()}
        program='''import hashlib,importlib.util,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from monitor import issue_tracker_local_commit as local,issue_tracker_spreadsheet_owner as owner
from monitor import issue_tracker_global_attempt_journal as journal
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
spec=importlib.util.spec_from_file_location('monitor.issue_tracker_remote_history_match',sys.argv[3])
match=importlib.util.module_from_spec(spec); sys.modules[spec.name]=match; spec.loader.exec_module(match)
import monitor
monitor.issue_tracker_remote_history_match=match
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
store=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((store/'ACTION-PREIMAGE').read_bytes(),(store/'WIRE').read_bytes())
gid=json.loads(unit.action_preimage)['identity']['generation_id']
state=json.loads((root/'project/.tracker/generations'/gid/'STATE').read_bytes())
with local.writer_owner(root/'project',root/'project/publication') as writer,scoped_fixture(root,owner),owner.spreadsheet_owner(bound) as token:
 generation=local.Generation(gid,state['sequence'],state['manifest_id'],writer)
 expected=((('switch','node0001','down','fabric'),1),)
 assert match.inspect_owned_applied_key_watermarks(writer,token,bound,unit,generation=generation)==expected
 assert match.record_owned_applied_key_watermarks(writer,token,bound,unit,generation=generation)==expected
 historical=journal.inspect_global_unit(token,bound,unit)
 assert (historical.attempt_count,historical.outcome)==(1,'UNKNOWN')
 print('original-key-watermark cold1 UNKNOWN retained')
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root),str(Path(module.__file__))],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'original-key-watermark cold1 UNKNOWN retained\n',cold.stdout)
        self.assertEqual(saved,{p:(p.stat().st_ino,p.read_bytes())
                                for p in self.root.rglob('*') if p.is_file()})

    def prepare_native_completed(self,stack,module):
        writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,native_generation=True)
        responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                   for name,(kind,value) in docs.items()}
        module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
        return writer,owner,bound,unit

    def test_applied_live_start_and_marker_substitution_keep_hold_without_adoption(self):
        """A successful rename is not permission to adopt a replacement inode."""
        from monitor import issue_tracker_local_commit as local
        for phase in ('STARTED','MARKER'):
            with self.subTest(phase=phase),ExitStack() as stack:
                module=load(); writer,owner,bound,unit=self.prepare_native_completed(stack,module)
                tracker=self.root/'project/.tracker'; native=local._rename_new; reached=[]
                target=('REMOTE-APPLIED-STARTED-' if phase=='STARTED' else 'REMOTE-APPLIED-')+unit.unit_id
                def displace_after_rename(parent,source,name,*args):
                    result=native(parent,source,name,*args)
                    if name==target:
                        path=tracker/name; raw=path.read_bytes()
                        path.rename(self.root/'preserved-applied-original')
                        path.write_bytes(raw); path.chmod(0o600); reached.append(True)
                    return result
                with mock.patch.object(local,'_rename_new',side_effect=displace_after_rename):
                    with self.assertRaises(module.RemoteHistoryHold):
                        module.record_owned_applied_evidence(writer,owner,bound,unit,
                                                             generation=self.native_generation)
                self.assertEqual([True],reached)
                self.assertEqual((tracker/target).read_bytes(),(self.root/'preserved-applied-original').read_bytes())
                self.assertNotEqual((tracker/target).stat().st_ino,(self.root/'preserved-applied-original').stat().st_ino)
                if phase=='STARTED': self.assertFalse((tracker/('REMOTE-APPLIED-'+unit.unit_id)).exists())
                state=self.current_global_state(owner,bound,unit)
                self.assertEqual((1,'UNKNOWN'),(state.attempt_count,state.outcome))
            self.doCleanups(); self.setUp()

    def test_applied_cold_same_byte_start_and_marker_are_not_original_pair(self):
        for prefix in ('REMOTE-APPLIED-STARTED-','REMOTE-APPLIED-'):
            with self.subTest(prefix=prefix),ExitStack() as stack:
                module=load(); writer,owner,bound,unit=self.prepare_native_completed(stack,module)
                module.record_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
                tracker=self.root/'project/.tracker'; path=tracker/(prefix+unit.unit_id)
                raw=path.read_bytes(); path.rename(self.root/'preserved-applied-original')
                path.write_bytes(raw); path.chmod(0o600)
                saved={p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()}
                with self.assertRaises(module.RemoteHistoryHold):
                    module.inspect_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
                self.assertEqual(saved,{p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()})
            self.doCleanups(); self.setUp()

    def test_applied_interrupted_pair_is_retained_and_never_recreated(self):
        from monitor import issue_tracker_local_commit as local
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,unit=self.prepare_native_completed(stack,module)
            tracker=self.root/'project/.tracker'; native=local._rename_new; reached=[]
            def interrupt_marker(parent,source,name,*args):
                if name=='REMOTE-APPLIED-'+unit.unit_id:
                    reached.append(True); raise OSError('owned fixture interrupted before marker rename')
                return native(parent,source,name,*args)
            with mock.patch.object(local,'_rename_new',side_effect=interrupt_marker):
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
            self.assertEqual([True],reached)
            self.assertTrue((tracker/('REMOTE-APPLIED-STARTED-'+unit.unit_id)).is_file())
            self.assertFalse((tracker/('REMOTE-APPLIED-'+unit.unit_id)).exists())
            saved={p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()}
            for api in (module.record_owned_applied_evidence,module.inspect_owned_applied_evidence):
                with self.assertRaises(module.RemoteHistoryHold): api(writer,owner,bound,unit,generation=self.native_generation)
            self.assertEqual(saved,{p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()})
            state=self.current_global_state(owner,bound,unit)
            self.assertEqual((1,'UNKNOWN'),(state.attempt_count,state.outcome))

    def test_native_applied_cold_process_needs_original_c6_and_complete_not_parent_objects(self):
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,unit=self.prepare_native_completed(stack,module)
            module.record_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
        import subprocess
        from dataclasses import asdict
        roots=(self.root/'project/.tracker',self.root/'project/publication',
               self.root/'var/lib/http-ztp-container/issue-tracker')
        saved={p:(p.stat().st_ino,p.read_bytes()) for root in roots for p in root.rglob('*') if p.is_file()}
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor import issue_tracker_spreadsheet_owner as owner,issue_tracker_local_commit as local
from monitor import issue_tracker_remote_history_match as match,issue_tracker_global_attempt_journal as journal
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
path=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((path/'ACTION-PREIMAGE').read_bytes(),(path/'WIRE').read_bytes())
action=json.loads(unit.action_preimage); gid=action['identity']['generation_id']
state=json.loads((root/'project/.tracker/generations'/gid/'STATE').read_bytes())
with scoped_fixture(root,owner),local.writer_owner(root/'project',root/'project/publication') as writer,owner.spreadsheet_owner(bound) as token:
 generation=local.Generation(gid,state['sequence'],state['manifest_id'],writer)
 seen=match.inspect_owned_applied_evidence(writer,token,bound,unit,generation=generation)
 assert seen==match.record_owned_applied_evidence(writer,token,bound,unit,generation=generation)
 historical=journal.inspect_global_unit(token,bound,unit)
 print(seen.state,seen.sequence,','.join(seen.applied_operation_ids),historical.attempt_count,historical.outcome)
'''
        child=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,child.returncode,child.stderr)
        self.assertEqual(b'APPLIED 1 switch:0001 1 UNKNOWN\n',child.stdout)
        self.assertEqual(saved,{p:(p.stat().st_ino,p.read_bytes()) for root in roots for p in root.rglob('*') if p.is_file()})

    def test_applied_original_c6_loss_during_marker_commit_never_acknowledges(self):
        from monitor import issue_tracker_local_commit as local
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,unit=self.prepare_native_completed(stack,module)
            generation=self.root/'project/.tracker/generations'/self.native_generation.generation_id
            receipt=generation/'RECEIPT'; original=receipt.read_bytes(); native=local._rename_new; reached=[]
            def displace_receipt_after_marker(parent,source,name,*args):
                result=native(parent,source,name,*args)
                if name=='REMOTE-APPLIED-'+unit.unit_id:
                    receipt.rename(self.root/'preserved-original-c6-receipt')
                    receipt.write_bytes(original); receipt.chmod(0o600); reached.append(True)
                return result
            with mock.patch.object(local,'_rename_new',side_effect=displace_receipt_after_marker):
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
            self.assertEqual([True],reached)
            saved={p:(p.stat().st_ino,p.read_bytes()) for p in (self.root/'project/.tracker').rglob('*') if p.is_file()}
            for api in (module.record_owned_applied_evidence,module.inspect_owned_applied_evidence):
                with self.assertRaises(module.RemoteHistoryHold): api(writer,owner,bound,unit,generation=self.native_generation)
            self.assertEqual(saved,{p:(p.stat().st_ino,p.read_bytes()) for p in (self.root/'project/.tracker').rglob('*') if p.is_file()})

    def test_applied_required_file_and_parent_barriers_fail_without_partial_adoption(self):
        from monitor import issue_tracker_local_commit as local
        for barrier in range(1,5):
            with self.subTest(barrier=barrier),ExitStack() as stack:
                module=load(); writer,owner,bound,unit=self.prepare_native_completed(stack,module)
                tracker=self.root/'project/.tracker'; native=os.fsync; reached=[]
                root_id=(tracker.stat().st_dev,tracker.stat().st_ino)
                def fail_required(fd):
                    info=os.fstat(fd); identity=(info.st_dev,info.st_ino)
                    pending={(p.stat().st_dev,p.stat().st_ino) for p in tracker.iterdir() if p.name.startswith('.pending-')}
                    if identity==root_id or identity in pending:
                        reached.append(identity)
                        if len(reached)==barrier: raise OSError('owned required APPLIED barrier failure')
                    return native(fd)
                with mock.patch.object(os,'fsync',side_effect=fail_required):
                    with self.assertRaises(module.RemoteHistoryHold):
                        module.record_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
                self.assertEqual(barrier,len(reached))
                if barrier<4:
                    saved={p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()}
                    for api in (module.record_owned_applied_evidence,module.inspect_owned_applied_evidence):
                        with self.assertRaises(module.RemoteHistoryHold): api(writer,owner,bound,unit,generation=self.native_generation)
                    self.assertEqual(saved,{p:(p.stat().st_ino,p.read_bytes()) for p in tracker.rglob('*') if p.is_file()})
                else:
                    # Final rename happened. Cold read may re-establish the
                    # exact complete pair's required barriers, not fill a gap.
                    seen=module.inspect_owned_applied_evidence(writer,owner,bound,unit,generation=self.native_generation)
                    self.assertEqual(('APPLIED',('switch:0001',)),(seen.state,seen.applied_operation_ids))
                state=self.current_global_state(owner,bound,unit)
                self.assertEqual((1,'UNKNOWN'),(state.attempt_count,state.outcome))
            self.doCleanups(); self.setUp()

    def test_completion_header_original_identity_and_history_extent_cannot_be_substituted(self):
        module=load()
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local
        for fault in ('same-byte-header','history-extent'):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                path=proof/'HEADER'; original=path.read_bytes()
                if fault=='same-byte-header':
                    path.rename(self.root/'preserved-completion-header'); path.write_bytes(original); path.chmod(0o600)
                else:
                    doc=json.loads(original); doc['matched']['history_last_row_after_read']+=1
                    raw=local._canonical(doc); path.write_bytes(raw)
                    marker=json.loads((proof/'COMPLETE').read_bytes()); marker['header_sha256']=hashlib.sha256(raw).hexdigest()
                    if 'header_identity' in marker:
                        from monitor import issue_tracker_attempt_journal as original_io
                        marker['header_identity']=list(original_io._identity(path.stat()))
                    (proof/'COMPLETE').write_bytes(local._canonical(marker))
                retained={p:p.read_bytes() for p in proof.iterdir()}
                with self.assertRaises(module.RemoteHistoryHold): module.inspect_completion_evidence(owner,bound,unit)
                self.assertEqual(retained,{p:p.read_bytes() for p in proof.iterdir()})
            if fault=='same-byte-header': self.doCleanups(); self.setUp()

    def test_actual_owned_completion_cold_reader_retains_entry_header_and_marker(self):
        from contextlib import ExitStack
        import os
        from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as original_io
        from monitor import issue_tracker_global_attempt_journal as journal
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
            path=proof/'HEADER'; header=path.read_bytes(); marker=json.loads((proof/'COMPLETE').read_bytes())
            reading=original_io._read; changed=[]; original_stat=path.stat()
            retained={p:p.read_bytes() for p in proof.parent.rglob('*') if p.is_file() and proof not in p.parents}
            def read_then_rewrite(folder,name,limit):
                raw=reading(folder,name,limit)
                if name=='HEADER' and os.fstat(folder).st_ino==proof.stat().st_ino and not changed:
                    with path.open('r+b') as held:
                        held.write(header); held.flush(); os.fsync(held.fileno())
                    os.utime(path,ns=(original_stat.st_atime_ns,original_stat.st_mtime_ns+1_000_000))
                    marker['header_identity']=list(original_io._identity(path.stat()))
                    (proof/'COMPLETE').write_bytes(local._canonical(marker)); changed.append(True)
                return raw
            with mock.patch.object(original_io,'_read',side_effect=read_then_rewrite):
                with self.assertRaises(module.RemoteHistoryHold): module.inspect_completion_evidence(owner,bound,unit)
            self.assertEqual([True],changed)
            self.assertEqual(retained,{p:p.read_bytes() for p in retained})
            self.assertEqual((header,original_stat.st_ino),(path.read_bytes(),path.stat().st_ino))
            self.assertNotEqual(original_stat.st_mtime_ns,path.stat().st_mtime_ns)
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                           journal.inspect_global_unit(owner,bound,unit).outcome))

    def test_actual_durable_completion_blocks_new_count_and_original_wire_dispatch(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            seen=module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            state=self.root/'var/lib/http-ztp-container/issue-tracker'
            retained={p:p.read_bytes() for p in state.rglob('*') if p.is_file()}
            with self.assertRaises(journal.GlobalAttemptHold): journal.record_global_attempt_intent(owner,bound,unit)
            issued=[]
            with self.assertRaises(journal.GlobalAttemptHold):
                with journal._hold_counted_original_wire(writer,owner,bound,unit) as image:
                    issued.append(image)
            self.assertEqual([],issued)
            self.assertFalse((state/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.dispatch')).exists())
            self.assertEqual(retained,{p:p.read_bytes() for p in retained})
            self.assertEqual(seen,module.inspect_completion_evidence(owner,bound,unit))
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                           journal.inspect_global_unit(owner,bound,unit).outcome))

    def test_displaced_completion_cannot_reset_count_claim_or_restart_proof_after_cold_acquisition(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            state=self.root/'var/lib/http-ztp-container/issue-tracker'
            key=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            proof=state/(key+'.completion'); saved=self.root/'preserved-completion-proof'
            proof.rename(saved)  # Recoverable owned fault; no deletion.
            retained={p:p.read_bytes() for p in state.rglob('*') if p.is_file()}
            original={p:p.read_bytes() for p in saved.iterdir()}
            with self.assertRaises(journal.GlobalAttemptHold): journal.record_global_attempt_intent(owner,bound,unit)
            issued=[]
            with self.assertRaises(journal.GlobalAttemptHold):
                with journal._hold_counted_original_wire(writer,owner,bound,unit) as image: issued.append(image)
            self.assertEqual([],issued); self.assertFalse((state/(key+'.dispatch')).exists())
            with self.assertRaises(module.RemoteHistoryHold):
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertFalse(proof.exists())
            self.assertEqual(retained,{p:p.read_bytes() for p in retained})
            self.assertEqual(original,{p:p.read_bytes() for p in original})
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                           journal.inspect_global_unit(owner,bound,unit).outcome))
        # A genuinely cold interpreter/acquisition cannot depend on a live
        # read registry or reconstruct a send permission from a missing folder.
        import subprocess
        from dataclasses import asdict
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor import issue_tracker_spreadsheet_owner as owner, issue_tracker_global_attempt_journal as journal
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
path=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((path/'ACTION-PREIMAGE').read_bytes(),(path/'WIRE').read_bytes())
with scoped_fixture(root,owner),owner.spreadsheet_owner(bound) as token:
 try: journal.record_global_attempt_intent(token,bound,unit)
 except journal.GlobalAttemptHold: pass
 else: raise AssertionError('cold count reset')
 seen=journal.inspect_global_unit(token,bound,unit)
 print(seen.attempt_count,seen.outcome)
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr); self.assertEqual(b'1 UNKNOWN\n',cold.stdout)

    def test_cold_completion_replays_raw_semantics_not_a_self_consistent_matched_summary(self):
        """Raw hashes/stat and COMPLETE can agree while the proof rows do not."""
        module=load()
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as original_io
        faults=('fence','nonce','identity','headers','history','request-path')
        for number,fault in enumerate(faults):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                header=json.loads((proof/'HEADER').read_bytes())
                if fault=='request-path':
                    header['responses']['HISTORY-RAW']['request_path_sha256']='0'*64
                else:
                    file={'fence':'METADATA-RAW','nonce':'METADATA-RAW','identity':'IDENTITY-RAW',
                          'headers':'HEADERS-RAW','history':'HISTORY-RAW'}[fault]
                    raw=json.loads((proof/file).read_bytes())
                    if fault in ('fence','nonce'):
                        entries=raw['matchedDeveloperMetadata']
                        chosen=next(entry['developerMetadata'] for entry in entries
                                    if (entry['developerMetadata']['metadataKey']=='z')==(fault=='fence'))
                        chosen['metadataValue']='different-original-value'
                    elif fault=='identity':
                        raw['sheets'][0]['properties']['title']='different-template-title'
                    elif fault=='headers':
                        raw['sheets'][0]['data'][0]['rowData'][0]['values'][0]['userEnteredValue']={'stringValue':'different header'}
                    else:
                        raw['sheets'][0]['data'][0]['rowData'].pop()
                    image=local._canonical(raw); (proof/file).write_bytes(image)
                    header['responses'][file]['sha256']=hashlib.sha256(image).hexdigest()
                    header['responses'][file]['identity']=list(original_io._identity((proof/file).stat()))
                    if file=='METADATA-RAW': header['matched']['metadata_sha256']=hashlib.sha256(image).hexdigest()
                    if file=='HISTORY-RAW': header['matched']['history_sha256']=hashlib.sha256(image).hexdigest()
                image=local._canonical(header); (proof/'HEADER').write_bytes(image)
                marker=json.loads((proof/'COMPLETE').read_bytes())
                marker['header_sha256']=hashlib.sha256(image).hexdigest()
                marker['header_identity']=list(original_io._identity((proof/'HEADER').stat()))
                (proof/'COMPLETE').write_bytes(local._canonical(marker))
                retained={path.name:path.read_bytes() for path in proof.iterdir()}
                with self.assertRaises(module.RemoteHistoryHold):
                    module.inspect_completion_evidence(owner,bound,unit)
                self.assertEqual(retained,{path.name:path.read_bytes() for path in proof.iterdir()})
            if number<len(faults)-1: self.doCleanups(); self.setUp()

    def test_owned_completion_missing_audit_forged_read_and_failed_barrier_never_install_marker(self):
        module=load()
        self.assertTrue(hasattr(module,'record_owned_completion_evidence'),'durable C19 writer missing')
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
            missing=deepcopy(docs['history_response'][1]); missing['sheets'][0]['data'][0]['rowData'].pop()
            changed=self.read_owned(stack,writer,owner,bound,auth,'history_tail',missing)
            for options in ({**responses,'history_response':changed},
                            {**responses,'metadata_response':replace(responses['metadata_response'])}):
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**options)
                self.assertFalse(proof.exists())
            actual=local._write_new
            def failed_header_barrier(folder,name,raw):
                actual(folder,name,raw)
                if name=='HEADER': raise OSError('owned fixture failed HEADER directory barrier')
            with mock.patch.object(local,'_write_new',side_effect=failed_header_barrier):
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertTrue((proof/'HEADER').is_file()); self.assertFalse((proof/'COMPLETE').exists())
            before={p:p.read_bytes() for p in proof.iterdir()}
            with self.assertRaises(module.RemoteHistoryHold): module.inspect_completion_evidence(owner,bound,unit)
            with self.assertRaises(module.RemoteHistoryHold):
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertEqual(before,{p:p.read_bytes() for p in proof.iterdir()})

    def test_completion_marker_never_precedes_any_required_raw_header_or_directory_barrier(self):
        module=load()
        from contextlib import ExitStack
        import os
        # New-folder parent+folder, all four raw file+folder barriers,
        # HEADER file+folder, then explicit folder+parent synchronization.
        for boundary in range(1,15):
            with self.subTest(boundary=boundary),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                actual=os.fsync; calls=[]
                def fail_at(fd):
                    # Matching first synchronizes the pre-existing preread
                    # and nonce stores (nine barriers). A failure there has
                    # created NO partial completion to forbid on the next
                    # read-only retry. Count only this NEW store's barriers,
                    # from its actual mkdir, not global fsync ordinals.
                    if proof.exists():
                        calls.append(fd)
                        if len(calls)==boundary: raise OSError('owned fixture interruption')
                    return actual(fd)
                with mock.patch('os.fsync',side_effect=fail_at),self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual(boundary,len(calls)); self.assertFalse((proof/'COMPLETE').exists())
                original={str(p.relative_to(proof)):p.read_bytes() for p in proof.rglob('*') if p.is_file()}
                with self.assertRaises(module.RemoteHistoryHold): module.inspect_completion_evidence(owner,bound,unit)
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual(original,{str(p.relative_to(proof)):p.read_bytes() for p in proof.rglob('*') if p.is_file()})
            if boundary!=14: self.doCleanups(); self.setUp()

    def test_completion_start_witness_barriers_precede_proof_and_block_cold_recreation(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        import os
        for boundary in (1,2):
            with self.subTest(boundary=boundary),ExitStack() as stack:
                module=load()
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                state=self.root/'var/lib/http-ztp-container/issue-tracker'
                key=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                witness=state/(key+'.completion-started'); proof=state/(key+'.completion')
                actual=os.fsync; calls=[]
                def fail_at(fd):
                    if witness.exists() and not proof.exists():
                        calls.append(fd)
                        if len(calls)==boundary: raise OSError('owned witness barrier fault')
                    return actual(fd)
                with mock.patch('os.fsync',side_effect=fail_at),self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual(boundary,len(calls)); self.assertTrue(witness.is_file()); self.assertFalse(proof.exists())
                retained={p:p.read_bytes() for p in state.rglob('*') if p.is_file()}
                with self.assertRaises(journal.GlobalAttemptHold): journal.record_global_attempt_intent(owner,bound,unit)
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual(retained,{p:p.read_bytes() for p in retained}); self.assertFalse(proof.exists())
                self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                               journal.inspect_global_unit(owner,bound,unit).outcome))
            if boundary==1: self.doCleanups(); self.setUp()

    def test_completion_start_pre_rename_short_write_and_file_barrier_failure_are_retained_stop(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        import os
        for fault in ('short-write','file-fsync'):
            with self.subTest(fault=fault),ExitStack() as stack:
                module=load()
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                state=self.root/'var/lib/http-ztp-container/issue-tracker'
                key=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                witness=state/(key+'.completion-started'); proof=state/(key+'.completion')
                write=os.write; sync=os.fsync; reached=[]
                def is_start_file(fd):
                    info=os.fstat(fd)
                    return any((path.stat().st_dev,path.stat().st_ino)==(info.st_dev,info.st_ino)
                               for path in state.iterdir()
                               if path.name==witness.name or path.name.startswith('.pending-'))
                def writing(fd,raw):
                    if fault=='short-write' and is_start_file(fd): reached.append('short-write'); return 0
                    return write(fd,raw)
                def syncing(fd):
                    if fault=='file-fsync' and is_start_file(fd): reached.append('file-fsync'); raise OSError('owned witness file barrier')
                    return sync(fd)
                with mock.patch('os.write',side_effect=writing),mock.patch('os.fsync',side_effect=syncing),self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual([fault],reached); self.assertFalse(proof.exists())
                retained={p:p.read_bytes() for p in state.rglob('*') if p.is_file()}
                with self.assertRaises(journal.GlobalAttemptHold): journal.record_global_attempt_intent(owner,bound,unit)
                self.assertTrue(witness.is_file(),'even partial witness bytes must retain the fixed STOP name')
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual(retained,{p:p.read_bytes() for p in retained}); self.assertFalse(proof.exists())
                self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                               journal.inspect_global_unit(owner,bound,unit).outcome))
            if fault=='short-write': self.doCleanups(); self.setUp()

    def test_completion_start_witness_original_is_held_through_live_and_cold_returns(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as original_io
        import os
        for phase in ('live','cold'):
            with self.subTest(phase=phase),ExitStack() as stack:
                module=load()
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                state=self.root/'var/lib/http-ztp-container/issue-tracker'
                key=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                witness=state/(key+'.completion-started'); proof=state/(key+'.completion')
                changed=[]
                def rewrite():
                    self.assertTrue(witness.is_file(),'completion must first retain an independent start witness')
                    raw=witness.read_bytes(); saved=witness.stat()
                    with witness.open('r+b') as held:
                        held.write(raw); held.flush(); os.fsync(held.fileno())
                    os.utime(witness,ns=(saved.st_atime_ns,saved.st_mtime_ns+1_000_000))
                    self.assertEqual((raw,saved.st_ino),(witness.read_bytes(),witness.stat().st_ino))
                    changed.append(True)
                if phase=='live':
                    actual=local._write_new
                    def written(folder,name,raw):
                        actual(folder,name,raw)
                        if name=='HEADER' and not changed: rewrite()
                    with mock.patch.object(local,'_write_new',side_effect=written),self.assertRaises(module.RemoteHistoryHold):
                        module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                    self.assertEqual([True],changed); self.assertFalse((proof/'COMPLETE').exists())
                else:
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                    actual=original_io._read
                    def read_then_changed(folder,name,limit):
                        raw=actual(folder,name,limit)
                        if name=='HEADER' and not changed: rewrite()
                        return raw
                    with mock.patch.object(original_io,'_read',side_effect=read_then_changed),self.assertRaises(module.RemoteHistoryHold):
                        module.inspect_completion_evidence(owner,bound,unit)
                    self.assertEqual([True],changed)
            if phase=='live': self.doCleanups(); self.setUp()

    def test_completion_start_write_barrier_and_reader_handoff_cannot_adopt_changed_original(self):
        from contextlib import ExitStack
        import os
        for fault in ('rewrite-at-first-fsync','rebind-before-reader-entry'):
            with self.subTest(fault=fault),ExitStack() as stack:
                module=load()
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                state=self.root/'var/lib/http-ztp-container/issue-tracker'
                key=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                witness=state/(key+'.completion-started'); proof=state/(key+'.completion')
                changed=[]; sync=os.fsync; entering=module._hold_completion_start
                def syncing(fd):
                    if fault=='rewrite-at-first-fsync' and witness.exists() and not proof.exists() and not changed:
                        info=os.fstat(fd); saved=witness.stat()
                        if (info.st_dev,info.st_ino)==(saved.st_dev,saved.st_ino):
                            raw=witness.read_bytes(); changed.append(True)
                            with witness.open('r+b') as original:
                                original.write(raw); original.flush(); sync(original.fileno())
                            os.utime(witness,ns=(saved.st_atime_ns,saved.st_mtime_ns+1_000_000))
                    return sync(fd)
                def entering_after_rebind(*args,**options):
                    if fault=='rebind-before-reader-entry' and not changed:
                        raw=witness.read_bytes(); witness.rename(self.root/'preserved-start-original')
                        witness.write_bytes(raw); witness.chmod(0o600); changed.append(True)
                    return entering(*args,**options)
                with mock.patch('os.fsync',side_effect=syncing), \
                        mock.patch.object(module,'_hold_completion_start',side_effect=entering_after_rebind), \
                        self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual([True],changed); self.assertFalse(proof.exists())
            if fault=='rewrite-at-first-fsync': self.doCleanups(); self.setUp()

    def test_cold_completion_missing_malformed_or_aliased_start_witness_never_adopts_or_resends(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        import os
        faults=('missing','bytes','same-bytes-new-inode','symlink','hardlink','public-mode')
        for number,fault in enumerate(faults):
            with self.subTest(fault=fault),ExitStack() as stack:
                module=load()
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                state=self.root/'var/lib/http-ztp-container/issue-tracker'
                key=hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                witness=state/(key+'.completion-started'); original=witness.read_bytes()
                saved=self.root/'preserved-completion-start-witness'
                if fault=='bytes': witness.write_bytes(b'not matching the original journal\n')
                elif fault=='public-mode': witness.chmod(0o644)
                else:
                    witness.rename(saved)
                    if fault=='same-bytes-new-inode': witness.write_bytes(original); witness.chmod(0o600)
                    elif fault=='symlink': witness.symlink_to(saved)
                    elif fault=='hardlink': os.link(saved,witness)
                before={p:p.read_bytes() for p in (state/(key+'.completion')).iterdir()}
                with self.assertRaises(module.RemoteHistoryHold): module.inspect_completion_evidence(owner,bound,unit)
                with self.assertRaises(journal.GlobalAttemptHold): journal.record_global_attempt_intent(owner,bound,unit)
                issued=[]
                with self.assertRaises(journal.GlobalAttemptHold):
                    with journal._hold_counted_original_wire(writer,owner,bound,unit) as image: issued.append(image)
                self.assertEqual([],issued); self.assertFalse((state/(key+'.dispatch')).exists())
                self.assertEqual(before,{p:p.read_bytes() for p in before})
                self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                               journal.inspect_global_unit(owner,bound,unit).outcome))
            if number<len(faults)-1: self.doCleanups(); self.setUp()

    def test_completion_keeps_original_count_through_header_barrier_and_final_owned_deadline(self):
        module=load()
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local, issue_tracker_global_attempt_journal as journal
        from monitor import issue_tracker_history_read_launcher as reads
        import time
        for fault in ('count-after-header','deadline-after-header'):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                actual=local._write_new; changed=[]
                def after_header(folder,name,raw):
                    actual(folder,name,raw)
                    if name=='HEADER' and not changed:
                        changed.append(True)
                        if fault=='count-after-header': journal.record_global_attempt_intent(owner,bound,unit)
                with mock.patch.object(local,'_write_new',side_effect=after_header), \
                        mock.patch.object(reads,'_monotonic',side_effect=lambda:time.monotonic()+(31 if changed and fault=='deadline-after-header' else 0)):
                    with self.assertRaises(module.RemoteHistoryHold):
                        module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual([True],changed)
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                self.assertFalse((proof/'COMPLETE').exists())
                self.assertEqual((2 if fault=='count-after-header' else 1,'UNKNOWN'),
                    (journal.inspect_global_unit(owner,bound,unit).attempt_count,journal.inspect_global_unit(owner,bound,unit).outcome))
            if fault=='count-after-header': self.doCleanups(); self.setUp()

    def test_completion_writer_cannot_return_after_final_inspection_deadline_or_namespace_drift(self):
        module=load()
        from contextlib import ExitStack
        from monitor import issue_tracker_history_read_launcher as reads
        import time
        for fault in ('deadline','completion-directory'):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                actual=module.inspect_completion_evidence; changed=[]
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                def finish_then_change(*args,**options):
                    seen=actual(*args,**options); changed.append(True)
                    if fault=='completion-directory':
                        originals={p.name:p.read_bytes() for p in proof.iterdir()}
                        proof.rename(self.root/'preserved-completion-original'); proof.mkdir(mode=0o700)
                        for name,raw in originals.items():
                            path=proof/name; path.write_bytes(raw); path.chmod(0o600)
                    return seen
                with mock.patch.object(module,'inspect_completion_evidence',side_effect=finish_then_change), \
                        mock.patch.object(reads,'_monotonic',side_effect=lambda:time.monotonic()+(31 if changed and fault=='deadline' else 0)):
                    with self.assertRaises(module.RemoteHistoryHold):
                        module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual([True],changed)
                self.assertTrue((proof/'COMPLETE').is_file(),'retained historical evidence is never deleted on late failure')
            if fault=='deadline': self.doCleanups(); self.setUp()

    def test_actual_issued_match_cannot_escape_after_matching_original_count_changes(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            matching=module.observe_remote_history_unit; changed=[]
            def matched_then_changed(*args,**options):
                result=matching(*args,**options)
                self.assertEqual('MATCHED_OBSERVATION',result.state)
                journal.record_global_attempt_intent(owner,bound,unit); changed.append(True)
                return result
            with mock.patch.object(module,'observe_remote_history_unit',side_effect=matched_then_changed):
                with self.assertRaises(module.RemoteHistoryHold):
                    module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)
            self.assertEqual([True],changed)
            self.assertEqual((2,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                           journal.inspect_global_unit(owner,bound,unit).outcome))

    def test_actual_fixed_dual_owner_native_reads_feed_original_whole_match_without_settlement(self):
        module = load()
        self.assertTrue(hasattr(module,'observe_owned_remote_history_unit'),'actual issued-read matcher bridge missing')
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        with ExitStack() as stack:
            writer, owner, bound, auth, _config, unit, docs = self.prepare_owned(stack)
            original = {p:p.read_bytes() for p in (self.root/'var/lib/http-ztp-container/issue-tracker').rglob('*') if p.is_file()}
            responses = {name:self.read_owned(stack,writer,owner,bound,auth,kind,value) for name,(kind,value) in docs.items()}
            seen = module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)
            self.assertEqual(('MATCHED_OBSERVATION',2,2,1),(seen.state,seen.history_rows_expected,seen.history_rows_matched,seen.attempt_count))
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,journal.inspect_global_unit(owner,bound,unit).outcome))
            self.assertFalse(hasattr(seen,'permit')); self.assertFalse(hasattr(seen,'applied'))
            self.assertEqual(original,{p:p.read_bytes() for p in (self.root/'var/lib/http-ztp-container/issue-tracker').rglob('*') if p.is_file()})
            for name in responses:
                forged = {**responses,name:replace(responses[name])}
                with self.subTest(copy=name),mock.patch.object(module,'observe_remote_history_unit') as matcher:
                    with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**forged)
                    matcher.assert_not_called()
            from test_cases.test_issue_tracker_online_target import document
            _config.write_text(json.dumps(document(status='disabled')))
            with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)

    def test_actual_issued_bad_header_missing_audit_and_final_policy_revocation_are_not_completion(self):
        module=load()
        self.assertTrue(hasattr(module,'observe_owned_remote_history_unit'),'actual issued-read matcher bridge missing')
        from contextlib import ExitStack
        with ExitStack() as stack:
            writer,owner,bound,auth,config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value) for name,(kind,value) in docs.items()}
            bad_header=deepcopy(docs['headers_response'][1]); bad_header['sheets'][0]['data'][0]['rowData'][0]['values'][0]['userEnteredValue']['stringValue']='foreign header'
            changed=self.read_owned(stack,writer,owner,bound,auth,'template_headers',bad_header)
            with mock.patch.object(module,'observe_remote_history_unit') as matcher:
                with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**{**responses,'headers_response':changed})
                matcher.assert_not_called()
            missing=deepcopy(docs['history_response'][1]); missing['sheets'][0]['data'][0]['rowData'].pop()
            changed=self.read_owned(stack,writer,owner,bound,auth,'history_tail',missing)
            seen=module.observe_owned_remote_history_unit(writer,owner,bound,unit,**{**responses,'history_response':changed})
            self.assertEqual(('CONFLICT',2,1),(seen.state,seen.history_rows_expected,seen.history_rows_matched))
            from monitor import issue_tracker_history_read_launcher as reads
            import time
            actual=module.observe_remote_history_unit; expired=[False]
            def finish_after_deadline(*args,**kwargs):
                seen=actual(*args,**kwargs); expired[0]=True; return seen
            with mock.patch.object(module,'observe_remote_history_unit',side_effect=finish_after_deadline), \
                    mock.patch.object(reads,'_monotonic',side_effect=lambda:time.monotonic()+(31 if expired[0] else 0)):
                with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)
            from test_cases.test_issue_tracker_online_target import document
            actual=module.observe_remote_history_unit
            def revoke(*args,**kwargs):
                seen=actual(*args,**kwargs); config.write_text(json.dumps(document(status='disabled'))); return seen
            with mock.patch.object(module,'observe_remote_history_unit',side_effect=revoke):
                with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)

    def test_owned_whitelist_template_nonce_and_visible_capacity_read_gates_are_not_a_permit(self):
        module=load()
        self.assertTrue(hasattr(module,'observe_owned_unit_read_gates'),'original W1/template/enrollment read gate bridge missing')
        from contextlib import ExitStack
        from monitor.issue_tracker_whitelist import freeze_whitelist_sheet
        from test_cases.test_req7_online_whitelist_read import document as whitelist_document, HEADER
        from monitor import issue_tracker_global_attempt_journal as journal
        snapshot=freeze_whitelist_sheet([HEADER,(None,None,None,None,'leaf-01',None),
                                        (None,None,None,None,'spine-*',None)])
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            meta=deepcopy(docs['metadata_response'][1]); meta['matchedDeveloperMetadata'].pop()
            whitelist_doc=whitelist_document(); whitelist_doc['spreadsheetId']=bound.spreadsheet_id
            whitelist_doc['sheets'][0]['properties']['sheetId']=112
            images={name:self.read_owned(stack,writer,owner,bound,auth,kind,value) for name,(kind,value) in
                    {'identity_response':docs['identity_response'],'headers_response':docs['headers_response'],
                     'metadata_response':('metadata',meta),'whitelist_response':('whitelist',whitelist_doc)}.items()}
            observed=module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**images)
            self.assertEqual(snapshot.sha256,observed.whitelist_sha256)
            self.assertEqual('VISIBLE_ONLY_UNPROVED',observed.capacity_outcome)
            self.assertFalse(hasattr(observed,'permit')); self.assertFalse(hasattr(observed,'applied'))
            self.assertEqual(1,journal.inspect_global_unit(owner,bound,unit).attempt_count)
            wrong_sheet=deepcopy(whitelist_doc); wrong_sheet['sheets'][0]['properties']['sheetId']=113
            read=self.read_owned(stack,writer,owner,bound,auth,'whitelist',wrong_sheet)
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'whitelist_response':read})
            for name in images:
                with self.subTest(copy=name),self.assertRaises(module.RemoteHistoryHold):
                    module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,name:replace(images[name])})
            changed=deepcopy(whitelist_doc); changed['sheets'][0]['data'][0]['rowData'][1]['values'][4]['userEnteredValue']['stringValue']='new-unapproved-device-rule'
            read=self.read_owned(stack,writer,owner,bound,auth,'whitelist',changed)
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'whitelist_response':read})
            read=self.read_owned(stack,writer,owner,bound,auth,'metadata',docs['metadata_response'][1])
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'metadata_response':read})
            bad=deepcopy(meta); bad['matchedDeveloperMetadata'][0]['developerMetadata']['metadataValue']='f'*64
            read=self.read_owned(stack,writer,owner,bound,auth,'metadata',bad)
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'metadata_response':read})
            overflow=deepcopy(meta); overflow['matchedDeveloperMetadata'].append({'developerMetadata': {
                'metadataId':9000,'metadataKey':'x','metadataValue':'a'*30000,'visibility':'DOCUMENT',
                'location':{'locationType':'SHEET','sheetId':101}}})
            read=self.read_owned(stack,writer,owner,bound,auth,'metadata',overflow)
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'metadata_response':read})
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,journal.inspect_global_unit(owner,bound,unit).outcome))


    def assert_native_completed_k_hold(self,bound):
        from dataclasses import asdict
        import subprocess
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); project=root/'project'; bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
folder=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((folder/'ACTION-PREIMAGE').read_bytes(),(folder/'WIRE').read_bytes())
try:
 with scoped_fixture(root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit):
  raise AssertionError('failed write adopted as cold K authority')
except state.TrackerStateHold: print('HOLD')
'''
        result=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(b'HOLD\n',result.stdout)
    def actual_delivered_k_pair(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as scope:
            writer,sheet,bound,unit=self.completed(scope)
            allocation.record_completed_settings_delivery(writer,sheet,bound,unit)
            outbox=self.root/'project/.tracker/settings/outbox'
            (outbox/'0.json').rename(self.root/'preserved-k-change-projection')
        return bound,unit

    def change_after_delivery(self,state,token,**changes):
        args=dict(new_k=6,actor='operator:fixture',recorded_at='2026-10-08T10:01:00Z',
                  request_id='write-after-delivery',expected_revision=0)
        args.update(changes)
        return state.set_k(token,**args)

    def test_native_cold_completed_writer_changes_k_and_replays_without_parent_context(self):
        from dataclasses import asdict
        import subprocess
        bound,unit=self.actual_delivered_k_pair(); tracker=self.root/'project/.tracker'
        old=(tracker/'settings/events/0.json').read_bytes()
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); project=root/'project'; bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
folder=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((folder/'ACTION-PREIMAGE').read_bytes(),(folder/'WIRE').read_bytes())
with scoped_fixture(root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
 for unused in range(2):
  result=state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-08T10:01:00Z',request_id='cold-write-after-delivery',expected_revision=0)
  print(result.revision,result.k,result.replay)
 value=state.current_k(token); print(value.revision,value.k)
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'1 6 False\n1 6 True\n1 6\n',cold.stdout)
        payload={'new_k':6,'actor':'operator:fixture','expected_revision':0,'request_id':'cold-write-after-delivery'}
        expected=canonical({'schema_version':1,'revision':1,'type':'set_k','old_k':3,'new_k':6,
            'actor':'operator:fixture','recorded_at':'2026-10-08T10:01:00Z','request_id':'cold-write-after-delivery',
            'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
            'predecessor_sha256':hashlib.sha256(old).hexdigest()})
        self.assertEqual(expected,(tracker/'settings/events/1.json').read_bytes())
        self.assertEqual(old,(tracker/'settings/events/0.json').read_bytes())
        self.assertFalse((tracker/'settings/outbox/0.json').exists())
        self.assertEqual({'events','outbox','current'},{p.name for p in (tracker/'settings').iterdir()})
        self.assertEqual(unit.wire_bytes,(self.root/'var/lib/http-ztp-container/issue-tracker'/
            (hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')/'WIRE').read_bytes())

    def test_actual_completed_pair_commits_new_event_pointer_outbox_before_ack_and_replays_exactly(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_k_store import KChangeConflict
        bound,unit=self.actual_delivered_k_pair(); project=self.root/'project'; tracker=project/'.tracker'
        old=(tracker/'settings/events/0.json').read_bytes()
        # Literals author the behavioral contract, not the implementation's event.
        payload={'new_k':6,'actor':'operator:fixture','expected_revision':0,'request_id':'write-after-delivery'}
        expected=canonical({'schema_version':1,'revision':1,'type':'set_k','old_k':3,'new_k':6,
            'actor':'operator:fixture','recorded_at':'2026-10-08T10:01:00Z','request_id':'write-after-delivery',
            'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
            'predecessor_sha256':hashlib.sha256(old).hexdigest()})
        digest=hashlib.sha256(expected).hexdigest()
        archives_before={p.name for p in (tracker/'quarantine').iterdir()}
        with scoped_fixture(self.root,sheet),state.tracker_writer(project,project/'publication',
                completed_binding=bound,completed_unit=unit) as token:
            receipt=self.change_after_delivery(state,token)
            self.assertEqual((1,6,digest,False),(receipt.revision,receipt.k,receipt.event_sha256,receipt.replay))
            self.assertEqual(expected,(tracker/'settings/events/1.json').read_bytes())
            self.assertEqual(canonical({'schema_version':1,'revision':1,'event_sha256':digest}),(tracker/'settings/current').read_bytes())
            self.assertEqual(canonical({'schema_version':1,'revision':1,'event_sha256':digest}),(tracker/'settings/outbox/1.json').read_bytes())
            self.assertEqual((1,6),(state.current_k(token).revision,state.current_k(token).k))
            self.assertFalse((tracker/'settings/outbox/0.json').exists())
            archives=[p for p in (tracker/'quarantine').iterdir() if p.name not in archives_before]
            self.assertEqual(2,len(archives),'retain both original pointer and guard recoverably')
            old_pointer=canonical({'schema_version':1,'revision':0,'event_sha256':hashlib.sha256(old).hexdigest()})
            pointer_archives=[p for p in archives if p.read_bytes()==old_pointer]
            self.assertEqual(1,len(pointer_archives),'original current must survive byte-for-byte in quarantine')
            self.assertEqual(0o600,pointer_archives[0].stat().st_mode & 0o777)
            archives=[p for p in archives if p not in pointer_archives]
            self.assertEqual(canonical({'schema_version':1,'request_id':'write-after-delivery',
                'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),'expected_revision':0,
                'event_sha256':digest,'predecessor_sha256':hashlib.sha256(old).hexdigest()}),archives[0].read_bytes())
            self.assertEqual(0o600,archives[0].stat().st_mode & 0o777)
            snapshot={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
            replay=self.change_after_delivery(state,token)
            self.assertEqual((1,6,digest,True),(replay.revision,replay.k,replay.event_sha256,replay.replay))
            for options in ({'new_k':7},{'request_id':'stale-other-request'}):
                with self.subTest(options=options):
                    with self.assertRaises(state.TrackerStateHold) as rejected:
                        self.change_after_delivery(state,token,**options)
                    # The existing relay uses this typed cause to distinguish
                    # a proved pre-mutation conflict from a claimed UNKNOWN.
                    self.assertIsInstance(rejected.exception.__cause__,KChangeConflict)
            self.assertEqual(snapshot,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
            pending=allocation.pending_settings_audits_after_completed_unit(token,
                state._COMPLETED_READ_CONTEXT[token][0],bound,unit)
            self.assertEqual(('settings:1:'+digest,),tuple(audit['event_id'] for audit in pending))
        self.assertEqual(old,(tracker/'settings/events/0.json').read_bytes())
        self.assertEqual(unit.wire_bytes,(self.root/'var/lib/http-ztp-container/issue-tracker'/
            (hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')/'WIRE').read_bytes())

    def test_lost_original_delivery_before_change_never_creates_a_new_event(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        bound,unit=self.actual_delivered_k_pair(); project=self.root/'project'; tracker=project/'.tracker'
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                (tracker/'settings-audit-delivery/DELIVERED').rename(self.root/'preserved-k-change-delivery')
                before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
                with self.assertRaises(state.TrackerStateHold): self.change_after_delivery(state,token)
                self.assertEqual(before,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
                self.assertFalse((tracker/'settings/events/1.json').exists())

    def test_each_required_write_barrier_failure_keeps_cold_k_in_hold_without_repair(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_settings_audit_allocation as candidate
        # Event: temporary-file/installed-parent/held-file; outbox: same three; current:
        # file/old-pointer source/old-pointer archive/new-pointer parent. All
        # original eight remain tested; two new archive barriers extend coverage.
        for boundary in range(1,11):
            with self.subTest(required_barrier=boundary):
                case=type(self)('test_lost_original_delivery_before_change_never_creates_a_new_event'); case.setUp()
                try:
                    bound,unit=case.actual_delivered_k_pair(); project=case.root/'project'
                    tracker=project/'.tracker'; reached=[]; active=[False]; count=[0]
                    native_install=candidate._CompletedSettingsTransition.install; native_fsync=candidate.os.fsync
                    def install(*args,**options):
                        active[0]=True
                        try: return native_install(*args,**options)
                        finally: active[0]=False
                    def fsync(fd):
                        if active[0]:
                            count[0]+=1
                            if count[0]==boundary:
                                reached.append(boundary); raise OSError('owned required K barrier fault')
                        return native_fsync(fd)
                    with scoped_fixture(case.root,sheet),self.assertRaises(state.TrackerStateHold):
                        with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                            with mock.patch.object(candidate._CompletedSettingsTransition,'install',new=install), \
                                    mock.patch.object(candidate.os,'fsync',side_effect=fsync),self.assertRaises(state.TrackerStateHold):
                                case.change_after_delivery(state,token)
                            self.assertEqual([boundary],reached)
                            with self.assertRaises(state.TrackerStateHold): state.current_k(token)
                    # A new native owner cannot adopt a coherent-looking tail,
                    # silently fall back to old K, or restore any projection.
                    before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
                    with scoped_fixture(case.root,sheet),self.assertRaises(state.TrackerStateHold):
                        with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit):
                            self.fail('failed required barrier became cold K authority')
                    case.assert_native_completed_k_hold(bound)
                    self.assertEqual(before,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
                    self.assertFalse((tracker/'settings/outbox/0.json').exists())
                finally: case.doCleanups()

    def test_substituted_pending_name_is_preserved_not_unlinked(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_local_commit as local
        bound,unit=self.actual_delivered_k_pair(); project=self.root/'project'
        events=project/'.tracker/settings/events'; native_link=os.link; native_rename=local._rename_new; replaced=[]
        def replace_pending(parent,temporary,destination):
            info=os.fstat(parent); directory=events.stat()
            if not replaced and (info.st_dev,info.st_ino)==(directory.st_dev,directory.st_ino) and destination=='1.json':
                source=events/temporary
                if source.exists(): source.rename(self.root/'preserved-original-pending')
                source.write_bytes(b'owned foreign replacement evidence\n'); source.chmod(0o600)
                replaced.append(source)
        def link(source,destination,**options):
            result=native_link(source,destination,**options)
            replace_pending(options['src_dir_fd'],source,destination)
            return result
        def rename(parent,source,destination,**options):
            result=native_rename(parent,source,destination,**options)
            replace_pending(parent,source,destination)
            return result
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                with mock.patch('os.link',side_effect=link),mock.patch.object(local,'_rename_new',side_effect=rename),self.assertRaises(state.TrackerStateHold):
                    self.change_after_delivery(state,token)
                self.assertEqual(1,len(replaced),'must actually reach the installed-parent boundary')
                self.assertTrue(replaced[0].exists(),'never unlink substituted pending evidence')
                self.assertEqual(b'owned foreign replacement evidence\n',replaced[0].read_bytes())
                with self.assertRaises(state.TrackerStateHold): state.current_k(token)
        tracker=project/'.tracker'
        before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
        self.assert_native_completed_k_hold(bound)
        self.assertEqual(before,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})


    def test_current_replacement_at_native_install_is_preserved_not_overwritten(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.actual_delivered_k_pair(); project=self.root/'project'; tracker=project/'.tracker'
        raw=b'owned foreign unexplained current pointer; preserve evidence\n'
        current=tracker/'settings/current'; reached=[]; replace=os.replace; rename=allocation.local._rename_new
        def substitute():
            if not reached:
                current.rename(self.root/'preserved-original-current-before-change')
                current.write_bytes(raw); current.chmod(0o600); reached.append(True)
        def replaced(source,destination,**options):
            if destination=='current': substitute()
            return replace(source,destination,**options)
        def moved(parent,source,destination,**options):
            if source=='current': substitute()
            return rename(parent,source,destination,**options)
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                with mock.patch.object(allocation.os,'replace',side_effect=replaced), \
                        mock.patch.object(allocation.local,'_rename_new',side_effect=moved),self.assertRaises(state.TrackerStateHold):
                    self.change_after_delivery(state,token)
                self.assertEqual([True],reached,'owned native boundary must execute')
                self.assertEqual(1,sum(p.read_bytes()==raw for p in tracker.rglob('*') if p.is_file()),
                    'never overwrite an unexplained replacement current object')
                with self.assertRaises(state.TrackerStateHold): state.current_k(token)
        self.assert_native_completed_k_hold(bound)

    def test_current_inserted_after_original_move_is_preserved_without_ack(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.actual_delivered_k_pair(); project=self.root/'project'; tracker=project/'.tracker'
        current=tracker/'settings/current'; old=current.read_bytes()
        foreign=b'owned late current insertion; never replace\n'; reached=[]
        rename=allocation.local._rename_new
        def moved(parent,source,destination,**options):
            result=rename(parent,source,destination,**options)
            if source=='current':
                current.write_bytes(foreign); current.chmod(0o600); reached.append(True)
            return result
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                with mock.patch.object(allocation.local,'_rename_new',side_effect=moved),self.assertRaises(state.TrackerStateHold):
                    self.change_after_delivery(state,token)
                self.assertEqual([True],reached,'must reach recoverable old-pointer move')
                self.assertEqual(foreign,current.read_bytes())
                self.assertEqual(1,sum(p.read_bytes()==old for p in (tracker/'quarantine').iterdir() if p.is_file()))
                with self.assertRaises(state.TrackerStateHold): state.current_k(token)
        self.assert_native_completed_k_hold(bound)

    def test_existing_guard_archive_is_never_overwritten_and_change_is_not_acknowledged(self):
        from types import SimpleNamespace
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.actual_delivered_k_pair(); project=self.root/'project'; tracker=project/'.tracker'
        foreign=tracker/'quarantine'/('completed-K-change-guard-'+'f'*32)
        raw=b'owned pre-existing archive evidence\n'; foreign.write_bytes(raw); foreign.chmod(0o600)
        identity=(foreign.stat().st_dev,foreign.stat().st_ino)
        finish=allocation._CompletedSettingsTransition.finish; reached=[]
        def collision(*args,**options):
            reached.append(True)
            with mock.patch.object(allocation.uuid,'uuid4',return_value=SimpleNamespace(hex='f'*32)):
                return finish(*args,**options)
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                with mock.patch.object(allocation._CompletedSettingsTransition,'finish',new=collision),self.assertRaises(state.TrackerStateHold):
                    self.change_after_delivery(state,token)
                self.assertEqual([True],reached)
                self.assertEqual(raw,foreign.read_bytes())
                self.assertEqual(identity,(foreign.stat().st_dev,foreign.stat().st_ino))
                with self.assertRaises(state.TrackerStateHold): state.current_k(token)
        self.assert_native_completed_k_hold(bound)

    def test_substituted_guard_is_preserved_at_final_cleanup(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.actual_delivered_k_pair(); project=self.root/'project'
        reached=[]; unlink=os.unlink; rename=allocation.local._rename_new
        raw=b'owned foreign unresolved guard; preserve bytes\n'
        def insert(name):
            if str(name).startswith('.pending-K-change-') and not reached:
                guard=project/'.tracker/settings'/name
                guard.rename(self.root/'preserved-original-k-guard')
                guard.write_bytes(raw); guard.chmod(0o600); reached.append(name)
        def substituted_unlink(name,*args,**options):
            insert(name); return unlink(name,*args,**options)
        def substituted_move(parent,name,destination,**options):
            insert(name); return rename(parent,name,destination,**options)
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                with mock.patch.object(allocation.os,'unlink',side_effect=substituted_unlink), \
                        mock.patch.object(allocation.local,'_rename_new',side_effect=substituted_move),self.assertRaises(state.TrackerStateHold):
                    self.change_after_delivery(state,token)
                self.assertEqual(1,len(reached),'owned substitution boundary must execute')
                preserved=[p for p in (project/'.tracker').rglob('*') if p.is_file() and p.read_bytes()==raw]
                self.assertEqual(1,len(preserved),'never delete a substituted unresolved guard, even after recoverable move')
                with self.assertRaises(state.TrackerStateHold): state.current_k(token)
        self.assert_native_completed_k_hold(bound)

    def test_guard_boundaries_and_post_write_authority_loss_retain_cold_hold(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as candidate
        for fault in ('intent-file','intent-parent','intent-cleanup','intent-archive','delivery-loss','pointer-rebind','final-proof-close'):
            with self.subTest(fault=fault):
                case=type(self)('test_lost_original_delivery_before_change_never_creates_a_new_event'); case.setUp()
                try:
                    bound,unit=case.actual_delivered_k_pair(); project=case.root/'project'; tracker=project/'.tracker'
                    native_begin=candidate._CompletedSettingsTransition.begin; native_finish=candidate._CompletedSettingsTransition.finish
                    native_install=candidate._CompletedSettingsTransition.install; native_fsync=candidate.os.fsync
                    native_pair=candidate._hold_completed_k_pair
                    active=[False]; count=[0]; reached=[]
                    def begin(*args,**options):
                        active[0]=fault in ('intent-file','intent-parent')
                        try: return native_begin(*args,**options)
                        finally: active[0]=False
                    def finish(*args,**options):
                        active[0]=fault in ('intent-cleanup','intent-archive')
                        try: return native_finish(*args,**options)
                        finally: active[0]=False
                    def fsync(fd):
                        if active[0]:
                            count[0]+=1
                            limit=2 if fault in ('intent-parent','intent-archive') else 1
                            if count[0]==limit:
                                reached.append(fault); raise OSError('owned unresolved K guard fault')
                        return native_fsync(fd)
                    def install(transition,scope,parent,name,raw,**options):
                        result=native_install(transition,scope,parent,name,raw,**options)
                        if name=='current' and fault in ('delivery-loss','pointer-rebind'):
                            reached.append(fault)
                            if fault=='delivery-loss':
                                (tracker/'settings-audit-delivery/DELIVERED').rename(case.root/'preserved-mid-write-delivery')
                            else:
                                current=tracker/'settings/current'; replacement=case.root/'same-byte-current'
                                replacement.write_bytes(current.read_bytes()); replacement.chmod(0o600)
                                current.rename(case.root/'preserved-mid-write-current'); replacement.rename(current)
                        return result
                    @contextmanager
                    def pair(*args,**options):
                        with native_pair(*args,**options) as result:
                            yield result
                            if fault=='final-proof-close':
                                reached.append(fault)
                                (tracker/'settings-audit-delivery/DELIVERED').rename(case.root/'preserved-final-write-delivery')
                    with scoped_fixture(case.root,sheet),self.assertRaises(state.TrackerStateHold):
                        with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                            with mock.patch.object(candidate._CompletedSettingsTransition,'begin',new=begin), \
                                    mock.patch.object(candidate._CompletedSettingsTransition,'finish',new=finish), \
                                    mock.patch.object(candidate._CompletedSettingsTransition,'install',new=install), \
                                    mock.patch.object(candidate,'_hold_completed_k_pair',new=pair), \
                                    mock.patch.object(candidate.os,'fsync',side_effect=fsync),self.assertRaises(state.TrackerStateHold):
                                case.change_after_delivery(state,token)
                            self.assertEqual([fault],reached)
                            with self.assertRaises(state.TrackerStateHold): state.current_k(token)
                    before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
                    case.assert_native_completed_k_hold(bound)
                    self.assertEqual(before,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
                    self.assertTrue(any(p.name.startswith('.pending-K-change-') for p in (tracker/'settings').iterdir()))
                    self.assertFalse((tracker/'settings/outbox/0.json').exists())
                finally: case.doCleanups()


    def retained_delivery(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with ExitStack() as stack:
            writer,sheet,bound,unit=self.completed(stack)
            allocation.record_completed_settings_delivery(writer,sheet,bound,unit)
        return bound,unit

    def test_cleanup_only_original_delivered_projection_preserves_later_pending_and_replays(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.retained_delivery(); project=self.root/'project'; tracker=project/'.tracker'
        projection=(tracker/'settings/outbox/0.json').read_bytes()
        immutable=(tracker/'settings/events/0.json').read_bytes()
        with scoped_fixture(self.root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
            later=state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-08T10:02:00Z',request_id='cleanup-later-event',expected_revision=0)
            pending=(tracker/'settings/outbox/1.json').read_bytes()
            old_quarantine={p.name for p in (tracker/'quarantine').iterdir()}
            original_sheet=state._COMPLETED_READ_CONTEXT[token][0]
            result=allocation.cleanup_completed_settings_outbox(token,original_sheet,bound,unit)
            self.assertEqual('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',result.state)
            self.assertEqual(unit.unit_id,result.unit_id)
            self.assertEqual(('settings:0:'+hashlib.sha256(immutable).hexdigest(),),result.event_ids)
            self.assertFalse((tracker/'settings/outbox/0.json').exists())
            self.assertEqual(pending,(tracker/'settings/outbox/1.json').read_bytes())
            self.assertEqual(('settings:1:'+later.event_sha256,),tuple(row['event_id'] for row in allocation.pending_settings_audits_after_completed_unit(token,original_sheet,bound,unit)))
            self.assertEqual((1,6),(state.current_k(token).revision,state.current_k(token).k))
            before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
            self.assertEqual(result,allocation.cleanup_completed_settings_outbox(token,original_sheet,bound,unit))
            self.assertEqual(before,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
        archives=[p for p in (tracker/'quarantine').iterdir() if p.name not in old_quarantine]
        self.assertEqual(1,len(archives),'cleanup is recoverable, never deletion of substituted evidence')
        self.assertEqual(projection,archives[0].read_bytes())
        self.assertEqual(0o600,archives[0].stat().st_mode & 0o777)
        self.assertEqual(immutable,(tracker/'settings/events/0.json').read_bytes())
        self.assertEqual(unit.wire_bytes,(self.root/'var/lib/http-ztp-container/issue-tracker'/
            (hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')/'WIRE').read_bytes())

    def test_partial_delivered_pair_cleans_only_remaining_original_projection(self):
        from monitor import issue_tracker_k_store as settings,issue_tracker_state_owner as state
        from monitor import issue_tracker_spreadsheet_owner as sheet,issue_tracker_settings_audit_allocation as allocation
        from test_cases.test_req7_remote_history_match import canonical,load
        event0=self.settings_audit_oracle()
        payload={'new_k':4,'actor':'operator:fixture','expected_revision':0,'request_id':'change-1'}
        image=canonical({'schema_version':1,'revision':1,'type':'set_k','old_k':3,'new_k':4,
            'actor':'operator:fixture','recorded_at':'2026-10-08T10:01:00Z','request_id':'change-1',
            'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
            'predecessor_sha256':hashlib.sha256((event0['details']+'\n').encode()).hexdigest()})
        event1={'event_id':'settings:1:'+hashlib.sha256(image).hexdigest(),
            'recorded_at_utc':'2026-10-08T10:01:00Z','details':image.decode().rstrip('\n')}
        initialize=settings.initialize_local_k_store
        def initialize_and_change(root,**options):
            receipt=initialize(root,**options)
            settings.apply_local_k_change(root,token=options['token'],new_k=4,actor='operator:fixture',
                recorded_at='2026-10-08T10:01:00Z',request_id='change-1',expected_revision=0)
            return receipt
        with ExitStack() as stack:
            with mock.patch.object(settings,'initialize_local_k_store',side_effect=initialize_and_change):
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack,settings_audits=(event0,event1))
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                for name,(kind,value) in docs.items()}
            load().record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            allocation.record_completed_settings_delivery(writer,owner,bound,unit)
            tracker=self.root/'project/.tracker'; missing=tracker/'settings/outbox/0.json'
            missing.rename(self.root/'preserved-partial-cleanup-projection')
        original_projection=(tracker/'settings/outbox/1.json').read_bytes()
        with scoped_fixture(self.root,sheet),state.tracker_writer(self.root/'project',self.root/'project/publication',
                completed_binding=bound,completed_unit=unit) as token:
            owner=state._COMPLETED_READ_CONTEXT[token][0]
            seen=allocation.cleanup_completed_settings_outbox(token,owner,bound,unit)
            self.assertEqual(('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',(event0['event_id'],event1['event_id'])),(seen.state,seen.event_ids))
            self.assertEqual([],[p.name for p in (tracker/'settings/outbox').iterdir()])
            self.assertEqual((1,4),(state.current_k(token).revision,state.current_k(token).k))
            self.assertEqual(1,sum(p.read_bytes()==original_projection for p in (tracker/'quarantine').iterdir()))
            later=state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-08T10:02:00Z',request_id='partial-cleanup-later',expected_revision=1)
            self.assertEqual(('settings:2:'+later.event_sha256,),tuple(row['event_id'] for row in allocation.pending_settings_audits_after_completed_unit(token,owner,bound,unit)))
            self.assertEqual((2,6),(state.current_k(token).revision,state.current_k(token).k))
        self.assertEqual(image,(tracker/'settings/events/1.json').read_bytes())
        self.assertFalse(missing.exists()); self.assertTrue((self.root/'preserved-partial-cleanup-projection').exists())

    def test_native_cold_cleanup_and_replay_read_original_pair_without_parent_context(self):
        from dataclasses import asdict
        import json
        import subprocess
        bound,unit=self.retained_delivery(); tracker=self.root/'project/.tracker'
        event=(tracker/'settings/events/0.json').read_bytes()
        projection=(tracker/'settings/outbox/0.json').read_bytes()
        program='''import sys,json,hashlib,importlib.util
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from monitor import issue_tracker_settings_audit_allocation as allocation
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); project=root/'project'; tracker=project/'.tracker'
bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
folder=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((folder/'ACTION-PREIMAGE').read_bytes(),(folder/'WIRE').read_bytes())
with scoped_fixture(root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
 owner=state._COMPLETED_READ_CONTEXT[token][0]
 result=allocation.cleanup_completed_settings_outbox(token,owner,bound,unit)
 value=state.current_k(token); pending=allocation.pending_settings_audits_after_completed_unit(token,owner,bound,unit)
 print(result.state,value.revision,value.k,len(pending))
 before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
 again=allocation.cleanup_completed_settings_outbox(token,owner,bound,unit)
 print(result==again,before=={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'DELIVERED-PRESENT-OUTBOX-ABSENT-VALID 0 3 0\nTrue True\n',cold.stdout)
        self.assertEqual(event,(tracker/'settings/events/0.json').read_bytes())
        self.assertFalse((tracker/'settings/outbox/0.json').exists())
        self.assertEqual(1,sum(p.read_bytes()==projection for p in (tracker/'quarantine').iterdir()))
        self.assertEqual(unit.wire_bytes,(self.root/'var/lib/http-ztp-container/issue-tracker'/
            (hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')/'WIRE').read_bytes())

    def test_each_cleanup_directory_barrier_fails_without_ack_or_resend(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        for boundary in (1,2):
            with self.subTest(boundary=boundary):
                case=type(self)('test_missing_original_delivery_never_cleans_any_projection'); case.setUp()
                try:
                    bound,unit=case.retained_delivery(); project=case.root/'project'; tracker=project/'.tracker'
                    projection=(tracker/'settings/outbox/0.json').read_bytes()
                    original={str(p.relative_to(tracker)):p.read_bytes() for p in (tracker/'settings/events').iterdir()}
                    native_move=allocation._CompletedOutboxCleanup.move_original; fsync=os.fsync
                    active=[False]; count=[0]; reached=[]
                    def move(*args,**options):
                        active[0]=True
                        try: return native_move(*args,**options)
                        finally: active[0]=False
                    def fail(fd):
                        if active[0]:
                            count[0]+=1
                            if count[0]==boundary:
                                reached.append(boundary); raise OSError('owned cleanup directory barrier fault')
                        return fsync(fd)
                    with scoped_fixture(case.root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                        with mock.patch.object(allocation._CompletedOutboxCleanup,'move_original',new=move), \
                                mock.patch.object(os,'fsync',side_effect=fail),self.assertRaises(allocation.SettingsAuditHold):
                            allocation.cleanup_completed_settings_outbox(token,state._COMPLETED_READ_CONTEXT[token][0],bound,unit)
                        self.assertEqual([boundary],reached)
                        self.assertFalse((tracker/'settings/outbox/0.json').exists())
                        self.assertEqual(1,sum(p.read_bytes()==projection for p in (tracker/'quarantine').iterdir()))
                        self.assertEqual((0,3),(state.current_k(token).revision,state.current_k(token).k))
                        self.assertEqual((),allocation.pending_settings_audits_after_completed_unit(token,state._COMPLETED_READ_CONTEXT[token][0],bound,unit))
                        seen=allocation.cleanup_completed_settings_outbox(token,state._COMPLETED_READ_CONTEXT[token][0],bound,unit)
                        self.assertEqual('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',seen.state)
                        self.assertEqual(original,{str(p.relative_to(tracker)):p.read_bytes() for p in (tracker/'settings/events').iterdir()})
                finally: case.doCleanups()

    def test_delivery_loss_after_move_preserves_archives_and_cold_hold(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.retained_delivery(); project=self.root/'project'; tracker=project/'.tracker'
        raw=(tracker/'settings/outbox/0.json').read_bytes(); rename=allocation.local._rename_new; reached=[]
        def lose(parent,name,destination,**options):
            result=rename(parent,name,destination,**options)
            if name=='0.json':
                (tracker/'settings-audit-delivery/DELIVERED').rename(self.root/'preserved-mid-cleanup-delivery')
                reached.append(name)
            return result
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                with mock.patch.object(allocation.local,'_rename_new',side_effect=lose),self.assertRaises(allocation.SettingsAuditHold):
                    allocation.cleanup_completed_settings_outbox(token,state._COMPLETED_READ_CONTEXT[token][0],bound,unit)
                self.assertEqual(['0.json'],reached)
                self.assertEqual(1,sum(p.read_bytes()==raw for p in (tracker/'quarantine').iterdir()))
                with self.assertRaises(state.TrackerStateHold): state.current_k(token)
        before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
        self.assert_native_completed_k_hold(bound)
        self.assertEqual(before,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})

    def test_substituted_projection_is_preserved_and_never_acknowledged(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.retained_delivery(); project=self.root/'project'; tracker=project/'.tracker'
        projection=tracker/'settings/outbox/0.json'; original=projection.read_bytes()
        foreign=b'owned foreign projection evidence; never erase\n'; rename=allocation.local._rename_new; reached=[]
        def replaced(parent,name,destination,**options):
            if name=='0.json':
                projection.rename(self.root/'preserved-cleanup-original-projection')
                projection.write_bytes(foreign); projection.chmod(0o600); reached.append(name)
            return rename(parent,name,destination,**options)
        with scoped_fixture(self.root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
            with mock.patch.object(allocation.local,'_rename_new',side_effect=replaced),self.assertRaises(allocation.SettingsAuditHold):
                allocation.cleanup_completed_settings_outbox(token,state._COMPLETED_READ_CONTEXT[token][0],bound,unit)
            self.assertEqual(['0.json'],reached)
            self.assertEqual(original,(self.root/'preserved-cleanup-original-projection').read_bytes())
            self.assertEqual(1,sum(p.read_bytes()==foreign for p in (tracker/'quarantine').iterdir()))
            self.assertEqual((0,3),(state.current_k(token).revision,state.current_k(token).k))

    def test_existing_archive_collision_refuses_before_projection_move(self):
        from types import SimpleNamespace
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.retained_delivery(); project=self.root/'project'; tracker=project/'.tracker'
        foreign=tracker/'quarantine'/('completed-settings-'+'f'*32+'-0.json')
        foreign.write_bytes(b'owned pre-existing archive evidence\n'); foreign.chmod(0o600)
        identity=(foreign.stat().st_dev,foreign.stat().st_ino); image=foreign.read_bytes()
        projection=(tracker/'settings/outbox/0.json').read_bytes()
        with scoped_fixture(self.root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
            with mock.patch.object(allocation.uuid,'uuid4',return_value=SimpleNamespace(hex='f'*32)),self.assertRaises(allocation.SettingsAuditHold):
                allocation.cleanup_completed_settings_outbox(token,state._COMPLETED_READ_CONTEXT[token][0],bound,unit)
            self.assertEqual(image,foreign.read_bytes())
            self.assertEqual(identity,(foreign.stat().st_dev,foreign.stat().st_ino))
            self.assertEqual(projection,(tracker/'settings/outbox/0.json').read_bytes())
            self.assertEqual((0,3),(state.current_k(token).revision,state.current_k(token).k))

    def test_cross_device_move_is_rejected_without_copy_delete_or_ack(self):
        import errno
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.retained_delivery(); project=self.root/'project'; tracker=project/'.tracker'
        rename=allocation.local._rename_new; reached=[]
        def exdev(parent,name,destination,**options):
            if name=='0.json':
                reached.append(name); raise OSError(errno.EXDEV,'owned native cross-device rejection')
            return rename(parent,name,destination,**options)
        with scoped_fixture(self.root,sheet),state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
            before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
            with mock.patch.object(allocation.local,'_rename_new',side_effect=exdev),self.assertRaises(allocation.SettingsAuditHold):
                allocation.cleanup_completed_settings_outbox(token,state._COMPLETED_READ_CONTEXT[token][0],bound,unit)
            self.assertEqual(['0.json'],reached)
            self.assertEqual(before,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
            self.assertEqual((0,3),(state.current_k(token).revision,state.current_k(token).k))

    def test_missing_original_delivery_never_cleans_any_projection(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        bound,unit=self.retained_delivery(); project=self.root/'project'; tracker=project/'.tracker'
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_writer(project,project/'publication',completed_binding=bound,completed_unit=unit) as token:
                (tracker/'settings-audit-delivery/DELIVERED').rename(self.root/'preserved-cleanup-delivery')
                before={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
                with self.assertRaises(allocation.SettingsAuditHold):
                    allocation.cleanup_completed_settings_outbox(token,state._COMPLETED_READ_CONTEXT[token][0],bound,unit)
                self.assertEqual(before,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})

    def setup_discovered_settings_cleaned(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        bound,unit=self.retained_delivery()
        project=self.root/'project'; publication=project/'99-output-monitor'
        publication.mkdir(mode=0o700)
        with scoped_fixture(self.root,sheet),state.tracker_writer(project,publication,
                completed_binding=bound,completed_unit=unit) as token:
            allocation.cleanup_completed_settings_outbox(token,state._COMPLETED_READ_CONTEXT[token][0],bound,unit)
        return project,publication,bound,unit

    def test_discovered_actual_pair_reads_and_writes_highest_without_caller_context(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        project,publication,bound,unit=self.setup_discovered_settings_cleaned(); tracker=project/'.tracker'
        original=(tracker/'settings/events/0.json').read_bytes()
        with scoped_fixture(self.root,sheet):
            with state.tracker_settings_writer(project,publication) as token:
                self.assertEqual((0,3),(state.current_k(token).revision,state.current_k(token).k))
                receipt=state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-09T00:00:00Z',
                    request_id='factory-new-k',expected_revision=0)
                self.assertEqual((1,6,False),(receipt.revision,receipt.k,receipt.replay))
            self.assertEqual({},state._COMPLETED_READ_CONTEXT)
            self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
            with state.tracker_settings_writer(project,publication) as token:
                self.assertEqual((1,6),(state.current_k(token).revision,state.current_k(token).k))
        self.assertEqual(original,(tracker/'settings/events/0.json').read_bytes())
        self.assertFalse((tracker/'settings/outbox/0.json').exists())
        self.assertTrue((tracker/'settings/outbox/1.json').is_file())
        self.assertEqual(unit.wire_bytes,(self.root/'var/lib/http-ztp-container/issue-tracker'/
            (hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')/'WIRE').read_bytes())

    def test_discovery_missing_delivery_refuses_before_any_k_change(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        project,publication,bound,unit=self.setup_discovered_settings_cleaned(); tracker=project/'.tracker'
        (tracker/'settings-audit-delivery/DELIVERED').rename(self.root/'preserved-delivery')
        saved={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,publication):
                self.fail('missing actual delivery must not yield a writer')
        self.assertEqual(saved,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_discovered_header_replacement_is_rejected_on_each_read_not_only_scope_exit(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        project,publication,bound,unit=self.setup_discovered_settings_cleaned(); tracker=project/'.tracker'
        header=tracker/'settings-audit-allocation/HEADER'
        with scoped_fixture(self.root,sheet):
            with self.assertRaises(state.TrackerStateHold):
                with state.tracker_settings_writer(project,publication) as token:
                    replacement=self.root/'same-byte-discovery-header'
                    replacement.write_bytes(header.read_bytes()); replacement.chmod(0o600)
                    header.rename(self.root/'preserved-discovery-header'); replacement.rename(header)
                    with self.assertRaises(state.TrackerStateHold): state.current_k(token)
        self.assertFalse((tracker/'settings/events/1.json').exists())
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_discovered_header_replacement_blocks_k_write_before_event_commit(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        project,publication,bound,unit=self.setup_discovered_settings_cleaned(); tracker=project/'.tracker'
        header=tracker/'settings-audit-allocation/HEADER'
        with scoped_fixture(self.root,sheet):
            with self.assertRaises(state.TrackerStateHold):
                with state.tracker_settings_writer(project,publication) as token:
                    replacement=self.root/'same-byte-discovery-header'
                    replacement.write_bytes(header.read_bytes()); replacement.chmod(0o600)
                    header.rename(self.root/'preserved-discovery-header'); replacement.rename(header)
                    with self.assertRaises(state.TrackerStateHold):
                        state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-09T00:00:00Z',
                            request_id='discovery-rebind-must-not-write',expected_revision=0)
        self.assertFalse((tracker/'settings/events/1.json').exists(),'lost held original must stop before commit')
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_mid_write_discovery_original_loss_retains_stop_not_coherent_success(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        project,publication,bound,unit=self.setup_discovered_settings_cleaned(); tracker=project/'.tracker'
        header=tracker/'settings-audit-allocation/HEADER'
        installed=allocation._CompletedSettingsTransition.install; reached=[]
        def changed_after_event(transition,scope,parent,name,raw,**options):
            result=installed(transition,scope,parent,name,raw,**options)
            if parent==transition.events:
                replacement=self.root/'same-byte-mid-write-header'
                replacement.write_bytes(header.read_bytes()); replacement.chmod(0o600)
                header.rename(self.root/'preserved-mid-write-header'); replacement.rename(header)
                reached.append(True)
            return result
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,publication) as token:
                with mock.patch.object(allocation._CompletedSettingsTransition,'install',new=changed_after_event):
                    with self.assertRaises(state.TrackerStateHold):
                        state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-09T00:00:00Z',
                            request_id='discovery-mid-write',expected_revision=0)
                self.assertEqual([True],reached)
                self.assertTrue((tracker/'settings/events/1.json').is_file())
                self.assertTrue(any(p.name.startswith('.pending-K-change-') for p in (tracker/'settings').iterdir()))
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,publication):
                self.fail('retained STOP must reject fresh owner')

    def test_caller_exception_is_preserved_and_context_revoked(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        project,publication,bound,unit=self.setup_discovered_settings_cleaned()
        error=RuntimeError('owned caller exception')
        with scoped_fixture(self.root,sheet),self.assertRaises(RuntimeError) as seen:
            with state.tracker_settings_writer(project,publication):
                raise error
        self.assertIs(error,seen.exception)
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_discovery_cold_reader_needs_only_project_not_parent_binding_or_unit(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        import subprocess
        project,publication,bound,unit=self.setup_discovered_settings_cleaned()
        with scoped_fixture(self.root,sheet),state.tracker_settings_writer(project,publication) as token:
            state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-09T00:00:00Z',
                request_id='cold-discovered-k',expected_revision=0)
        program='''from pathlib import Path
import sys
from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
root=Path(sys.argv[1]); project=root/'project'
assert state._COMPLETED_READ_CONTEXT=={}
assert state._COMPLETED_ORIGINAL_GUARDS=={}
with scoped_fixture(root,sheet),state.tracker_settings_writer(project,project/'99-output-monitor') as token:
 value=state.current_k(token); print(value.revision,value.k)
assert state._COMPLETED_READ_CONTEXT=={}
assert state._COMPLETED_ORIGINAL_GUARDS=={}
print('context-revoked')
'''
        cold=subprocess.run([sys.executable,'-B','-c',program,str(self.root)],cwd=ROOT,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'1 6\ncontext-revoked\n',cold.stdout)
        self.assertFalse((project/'.tracker/settings/outbox/0.json').exists())

    def test_no_delivery_claim_keeps_ordinary_pending_k_update_and_frozen_unknown(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        from contextlib import ExitStack
        with ExitStack() as stack:
            writer,owner,bound,auth,config,unit,docs=self.prepare_owned(stack,settings_audits=(self.settings_audit_oracle(),))
        project=self.root/'project'; publication=project/'99-output-monitor'; publication.mkdir(mode=0o700)
        tracker=project/'.tracker'; assignments=(tracker/'settings-audit-allocation/ASSIGNMENTS').read_bytes()
        with state.tracker_settings_writer(project,publication) as token:
            self.assertNotIn(token,state._COMPLETED_READ_CONTEXT)
            receipt=state.set_k(token,new_k=6,actor='operator:fixture',recorded_at='2026-10-09T00:00:00Z',
                request_id='still-unknown-k',expected_revision=0)
            self.assertEqual((1,6,False),(receipt.revision,receipt.k,receipt.replay))
        self.assertEqual(assignments,(tracker/'settings-audit-allocation/ASSIGNMENTS').read_bytes())
        self.assertTrue((tracker/'settings/outbox/0.json').is_file())
        self.assertTrue((tracker/'settings/outbox/1.json').is_file())
        self.assertFalse((tracker/'settings-audit-delivery').exists())
        self.assertEqual(unit.wire_bytes,(self.root/'var/lib/http-ztp-container/issue-tracker'/
            (hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')/'WIRE').read_bytes())

    def test_discovery_changed_binding_cannot_gain_original_pair_authority(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        import json
        project,publication,bound,unit=self.setup_discovered_settings_cleaned(); tracker=project/'.tracker'
        header=tracker/'settings-audit-allocation/HEADER'; altered=json.loads(header.read_bytes())
        altered['policy_sha256']='f'*64
        header.write_bytes(allocation.local._canonical(altered))
        saved={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,publication):
                self.fail('a plausible binding in local HEADER is only a candidate locator')
        self.assertEqual(saved,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
        self.assertFalse((tracker/'settings/events/1.json').exists())

    def test_discovery_missing_original_wire_cannot_recompile_or_restore(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        project,publication,bound,unit=self.setup_discovered_settings_cleaned(); tracker=project/'.tracker'
        original=(self.root/'var/lib/http-ztp-container/issue-tracker'/
            (hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')/'WIRE')
        original.rename(self.root/'preserved-original-wire')
        saved={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
        with scoped_fixture(self.root,sheet),self.assertRaises(state.TrackerStateHold):
            with state.tracker_settings_writer(project,publication):
                self.fail('missing original wire must not yield a settings writer')
        self.assertEqual(saved,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
        self.assertFalse(original.exists())

    def test_real_manual_factory_reopens_pair_and_preserves_authenticated_replay(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_spreadsheet_owner as sheet
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        project,publication,bound,unit=self.setup_discovered_settings_cleaned(); tracker=project/'.tracker'
        store=SimpleNamespace(scope='prod',project_identity=str(project),root_status_dir=str(self.root/'monitor/status'))
        template=self.root/'monitor/Issue_Tracker_Template_v1.xlsx'
        def broker():
            return make_protected_stage_l_broker(store,http_root=self.root,project=project,publication=publication,
                template_path=template,boot_id='fixture-boot')
        with scoped_fixture(self.root,sheet):
            first=broker()
            self.assertEqual((0,3),(first.settings('nvis','Switch Status')['revision'],first.settings('nvis','Switch Status')['k']))
            changed=first.set_k('nvis','Switch Status',new_k=6,expected_revision=0,request_id='a'*32)
            self.assertEqual(('committed',1,6,False),(changed['settings'],changed['revision'],changed['k'],changed['replay']))
            saved={str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()}
            replay=broker().set_k('nvis','Switch Status',new_k=6,expected_revision=0,request_id='a'*32)
            self.assertEqual({**changed,'replay':True},replay)
            self.assertEqual(saved,{str(p.relative_to(tracker)):p.read_bytes() for p in tracker.rglob('*') if p.is_file()})
        event=__import__('json').loads((tracker/'settings/events/1.json').read_bytes())
        self.assertEqual(('operator:nvis',3,6,'a'*32),(event['actor'],event['old_k'],event['new_k'],event['request_id']))
        self.assertFalse((tracker/'settings/outbox/0.json').exists())
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

class Req7RemoteHistoryManifestTests(unittest.TestCase):
    def test_direct_native_workflow_primary_suite_and_not_run_card_bind_real_dependencies(self):
        registry = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        script = 'monitor/issue_tracker_remote_history_match.py'; test = 'test_cases.test_req7_remote_history_match'
        self.assertEqual(script, registry['scripts'].get(script))
        self.assertTrue(any(script in rule['paths'] and test in rule['tests'] for rule in registry['test_rules']))
        dependencies = {script, 'monitor/issue_tracker_history_preread_journal.py', 'monitor/issue_tracker_global_attempt_journal.py',
            'monitor/issue_tracker_enrollment_journal.py', 'monitor/issue_tracker_spreadsheet_owner.py',
            'monitor/issue_tracker_history_read_launcher.py', 'monitor/issue_tracker_local_commit.py',
            'monitor/issue_tracker_online_target.py', 'monitor/issue_tracker_attempt_supervision.py',
            'monitor/issue_tracker_metadata_capacity.py', 'monitor/issue_tracker_sheets_read_decode.py', 'monitor/issue_tracker_tls_inputs.py'}
        self.assertTrue(any(dependencies <= set(rule['members']) and test in rule['tests'] for rule in registry['workflows']))
        self.assertEqual(['issue-tracker-local'], [suite['id'] for suite in registry['test_suites'] if test in suite['tests']])
        self.assertIn(test, (ROOT / 'test_cases/README.md').read_text())
        cards = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text(); start = cards.index('## TC-REAL-REQ7-REMOTE-HISTORY-MATCH-001')
        end = cards.find('\n## ', start + 1); card = cards[start:] if end == -1 else cards[start:end]
        for term in ('NOT RUN / REAL_ENV REQUIRED', '前置条件', 'Stage O', '证据', 'stat/inode', '清理', '不是 COMPLETE'):
            self.assertIn(term, card)


if __name__ == '__main__': unittest.main()
