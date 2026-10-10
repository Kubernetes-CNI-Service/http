"""Original retained unit -> native C6/APPLIED/key evidence; no NEW authority."""
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import sys
import unittest

from test_cases import test_req7_remote_history_match as remote_tests
from test_cases.test_req7_global_attempt_journal import original_read_files

SOURCE = Path(__file__).resolve().parents[1] / 'monitor/issue_tracker_retained_inventory.py'


def load():
    remote_tests.load_owner(); remote_tests.load_global()
    remote_tests.load_enrollment(); remote_tests.load_before()
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_retained_inventory', SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    monitor.issue_tracker_retained_inventory = module
    return module


class RetainedAppliedInventoryTests(unittest.TestCase):
    def _reserved_settled_successor(self, *, missing_applied=False):
        import time
        from test_cases import test_req7_unit_catalog as catalog_tests
        fixture = catalog_tests.CatalogAppliedNativeWorkflowTests()
        with fixture.completed_and_pending(project_origins=True) as (
                case,catalog,_remote,_inventory,_old,writer,owner,bound,units):
            from monitor import issue_tracker_global_attempt_journal as globals_
            from monitor import issue_tracker_enrollment_journal as enrollment
            from monitor import issue_tracker_history_preread_journal as preread
            # New actual owners require their canonical reservation consumer,
            # not the previous scenario's imported owner/global registries.
            quota = catalog_tests.load_component('issue_tracker_metadata_reservation')
            from monitor.issue_tracker_metadata_capacity import prepare_metadata_capacity_read
            from monitor.issue_tracker_sheets_read_plan import prepare_template_identity_read, prepare_history_tail_read
            from monitor.issue_tracker_sheets_read_decode import decode_template_identity
            from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
            from test_cases.test_req7_sheets_read_decode import identity_response, response
            auth = AuthenticatedToken('synthetic-reserved-successor',time.time()+3600)
            document = identity_response(); document['spreadsheetId'] = bound.spreadsheet_id
            identity = decode_template_identity(prepare_template_identity_read(bound,auth),response(document))
            original = enrollment.inspect_enrollment_journal(owner,bound,identity)
            history = {'spreadsheetId':bound.spreadsheet_id,'sheets':[{'properties':{
                'sheetId':105,'title':'Update_History','sheetType':'GRID',
                'gridProperties':{'rowCount':100,'columnCount':5}},
                'data':[{'startRow':2,'startColumn':0}]}]}
            preread.prepare_history_preread(owner,bound,units[-1],
                prepare_history_tail_read(bound,auth),response(history))
            metadata = {'matchedDeveloperMetadata':[{'developerMetadata':{
                'metadataId':index+1,'metadataKey':'http-ztp-enrollment-v1',
                'metadataValue':nonce,'visibility':'DOCUMENT',
                'location':{'locationType':'SHEET','sheetId':sid}}}
                for index,(_title,sid,nonce) in enumerate(original.nonces)]}
            quota.prepare_metadata_reservation(owner,bound,identity,units[-1],
                prepare_metadata_capacity_read(bound,auth),response(metadata))
            before = original_read_files(case.root)
            if missing_applied:
                marker = case.root/'project/.tracker'/('REMOTE-APPLIED-'+units[0].unit_id)
                marker.rename(case.root/'retained-prior-applied')
                retained = original_read_files(case.root)
                with self.assertRaises(globals_.GlobalAttemptHold):
                    globals_.record_reserved_attempt_intent(owner,bound,identity,units[-1])
                self.assertEqual(retained,original_read_files(case.root))
                self.assertEqual(0,globals_.inspect_global_unit(owner,bound,units[-1]).attempt_count)
            else:
                for count in (1,2):
                    observed = globals_.record_reserved_attempt_intent(owner,bound,identity,units[-1])
                    self.assertEqual((count,'UNKNOWN'),(observed.attempt_count,observed.outcome))
                    self.assertFalse(hasattr(observed,'permit'))
                self.assertTrue(before.items() <= original_read_files(case.root).items())
            self.assertEqual((1,'UNKNOWN'),(globals_.inspect_global_unit(owner,bound,units[0]).attempt_count,
                globals_.inspect_global_unit(owner,bound,units[0]).outcome))

    def test_actual_reserved_successor_joins_settled_catalog_and_retains_every_original(self):
        self._reserved_settled_successor()

    def test_actual_reserved_successor_missing_prior_applied_remains_uncounted_hold(self):
        self._reserved_settled_successor(missing_applied=True)

    def test_fixture_installs_current_inventory_alias_before_original_owner_issuance(self):
        module = load()
        from monitor import issue_tracker_retained_inventory as canonical
        from monitor import issue_tracker_global_attempt_journal as journal
        from monitor import issue_tracker_spreadsheet_owner as owner
        self.assertIs(module, canonical,
            'real counter and workflow oracle must not borrow distinct prior fixture registries')
        self.assertIs(owner,module.ownership); self.assertIs(journal,module.global_journal)

    def test_settled_catalog_key_scope_rejects_unissued_writer_before_shared_reads(self):
        from unittest import mock
        module = remote_tests.load()
        with mock.patch.object(module, '_hold_match_originals') as shared:
            with self.assertRaises(module.RemoteHistoryHold):
                with module._hold_settled_catalog_key_watermarks(object(), object(), object(), object(), object()):
                    self.fail('unissued writer cannot inspect catalog settlement')
            shared.assert_not_called()

    def test_settled_catalog_key_scope_has_no_caller_paths_settlement_or_verifier(self):
        module = remote_tests.load()
        for claims in ({'applied':True}, {'keys':()}, {'path':'foreign'}, {'verify':lambda:None}):
            with self.subTest(claims=tuple(claims)), self.assertRaises(TypeError):
                with module._hold_settled_catalog_key_watermarks(object(), object(), object(), object(), object(), **claims):
                    self.fail('caller label is not original settlement')

    def _catalog_completed_successor(self, *, applied, rebind_after_start=False,
                                     native_nv=False, rebind_after_nv_start=False,
                                     successor_count=False, rebind_after_attempt=False,
                                     lose_applied_before_count=False, another_pending=False,
                                     rebind_attempt_image=False, successor_claim=False,
                                     claim_fault=None):
        """Real C6/catalog/count/COMPLETE originals, not a settlement label."""
        from unittest import mock
        from test_cases.test_req7_unit_catalog import load as load_catalog
        from test_cases.test_req7_send_unit import inputs
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        from test_cases import test_req7_nv_reservation as nv_tests
        module = load()
        case = remote_tests.Req7OwnedHistoryMatchWorkflowTests(); case.setUp()
        try:
            match = remote_tests.load(); catalog = load_catalog(reset_dependencies=False)
            nv = nv_tests.load() if native_nv else None
            from monitor import issue_tracker_global_attempt_journal as globals_
            from monitor import issue_tracker_local_commit as local
            prepare = globals_.prepare_global_unit
            registered = []
            def register_first(owner, bound, unit):
                writers = tuple(local._ACTIVE)
                self.assertEqual(1, len(writers))
                catalog.register_pending_c6_unit(writers[0], owner, bound, unit)
                registered.append(unit.unit_id)
                return prepare(owner, bound, unit)
            with ExitStack() as scope:
                with mock.patch.object(globals_, 'prepare_global_unit', side_effect=register_first):
                    writer, owner, bound, auth, _config, first, docs = case.prepare_owned(scope, native_generation=True)
                self.assertEqual([first.unit_id], registered)
                responses = {name:case.read_owned(scope, writer, owner, bound, auth, kind, value)
                    for name, (kind, value) in docs.items()}
                match.record_owned_completion_evidence(writer, owner, bound, first, **responses)
                if applied:
                    match.record_owned_applied_evidence(writer, owner, bound, first, generation=case.native_generation)
                    match.record_owned_applied_key_watermarks(writer, owner, bound, first, generation=case.native_generation)
                    with module._hold_all_project_fifo_frontier(owner, bound) as (frontier, verify):
                        self.assertEqual((first.unit_id,), frontier.applied)
                        self.assertEqual((), frontier.frontier); self.assertEqual((), frontier.blocked)
                        verify()
                # Independently authored same-key successor. Local sequence 2
                # is real C6, never a caller maximum or APPLIED dataclass.
                if native_nv:
                    from monitor import issue_tracker_history_read_launcher as reads
                    from monitor import issue_tracker_sheets_read_decode as decode
                    from monitor import issue_tracker_enrollment_journal as enrollment
                    import json
                    identity_plan = reads.require_current_owned_read(writer, owner, bound,
                        responses['identity_response'], read_kind='template_identity')
                    identity = decode.decode_template_identity(identity_plan, responses['identity_response'])
                    enrolled = enrollment.inspect_enrollment_journal(owner, bound, identity)
                    arguments = nv_tests.cabling_inputs(enrolled.nonces)
                    sources = []
                    for title, identifiers in (('ETH Cabling', ('NV30016',)), ('IB Cabling', ('NV30101',))):
                        document = json.loads(nv_tests.source(title, identifiers).data)
                        document['spreadsheetId'] = bound.spreadsheet_id
                        response = case.read_owned(scope, writer, owner, bound, auth, 'activity', document, sheet=title)
                        plan = reads.require_current_owned_read(writer, owner, bound, response,
                            read_kind='activity', sheet=title)
                        sources.extend((plan, response))
                else:
                    arguments = inputs()
                    arguments['business'][0]['observed_values'] = {'L': {'stringValue':'down'}}
                arguments['audits'] = ({'event_id':'settings:002', 'recorded_at_utc':'2026-10-08T10:00:00Z', 'details':'K=3'},)
                generation = local.begin_generation(writer, arguments['manifest'])
                local.record_intent(writer, generation, literal_xlsx(), kind='xlsx')
                receipt = local.commit(writer, generation)
                arguments.update(spreadsheet_id=bound.spreadsheet_id, generation_id=generation.generation_id,
                    publish_id=receipt.published_sha256)
                if not native_nv:
                    arguments.update(sheet_id=101, history_sheet_id=105, target_nonce='a'*64, history_nonce='d'*64)
                second = catalog.composer.freeze_send_unit(**arguments)
                if native_nv:
                    from contextlib import contextmanager
                    before = original_read_files(case.root)
                    stem = globals_.ownership._validated_owner(owner, bound).lock_name[:-5]
                    shared = case.root / 'var/lib/http-ztp-container/issue-tracker'
                    reached = []
                    marker = local._owner(writer).project / '.tracker' / ('REMOTE-APPLIED-' + first.unit_id)
                    preserved = case.root / 'preserved-nv-successor-original-applied'
                    original = marker.read_bytes() if applied else None
                    inode = marker.stat().st_ino if applied else None
                    write = nv._write_catalog_image
                    def write_then_rebind(*args, **keywords):
                        result = write(*args, **keywords)
                        if args[1].endswith('.nv-started'):
                            marker.rename(preserved); marker.write_bytes(original); marker.chmod(0o600)
                            reached.append('actual-new-nv-start-then-prior-applied-rebound')
                        return result
                    @contextmanager
                    def preparation():
                        with nv.hold_catalog_nv_preparation(owner, bound, identity, *sources,
                                generation_id=generation.generation_id, publish_id=receipt.published_sha256,
                                sheet='ETH Cabling', requested_keys=nv_tests.KEYS) as prepared:
                            self.assertEqual(tuple(zip(nv_tests.KEYS, ('NV30102','NV30103'))), prepared.observation.reservations)
                            catalog.register_pending_c6_unit(writer, owner, bound, second, _nv_preparation=prepared)
                            yield
                    if rebind_after_nv_start:
                        with mock.patch.object(nv, '_write_catalog_image', side_effect=write_then_rebind):
                            with self.assertRaises(nv.NvReservationHold):
                                with preparation(): self.fail('prior rebound APPLIED cannot authorize successor NV')
                        self.assertEqual(['actual-new-nv-start-then-prior-applied-rebound'], reached)
                        self.assertEqual(inode, preserved.stat().st_ino); self.assertNotEqual(inode, marker.stat().st_ino)
                        self.assertEqual(original, marker.read_bytes()); self.assertEqual(original, preserved.read_bytes())
                        self.assertEqual(1, len(tuple(shared.glob(stem + '.unit-*.nv-started'))))
                        self.assertEqual((), tuple(shared.glob(stem + '.unit-*.nv')),
                            'old original drift must stop before any successor NV directory')
                    elif not applied:
                        with self.assertRaises(nv.NvReservationHold):
                            with preparation(): self.fail('COMPLETE alone is not APPLIED/key settlement')
                        self.assertEqual(before, original_read_files(case.root))
                    else:
                        with preparation(): pass
                        prepare(owner, bound, second)
                        observed = globals_.inspect_catalog_global_units(owner, bound)
                        self.assertEqual((first, second), tuple(unit for unit, _state in observed))
                        self.assertEqual(((1,'UNKNOWN'), (0,'UNATTEMPTED_OBSERVATION')),
                            tuple((state.attempt_count, state.outcome) for _unit, state in observed))
                        with module._hold_all_project_fifo_frontier(owner, bound) as (frontier, verify):
                            self.assertEqual((first.unit_id,), frontier.applied)
                            self.assertEqual((second.unit_id,), frontier.frontier)
                            self.assertEqual((), frontier.blocked); verify()
                    after = original_read_files(case.root)
                    unchanged = {name:image for name,image in before.items()
                        if not rebind_after_nv_start or name != str(marker.relative_to(case.root))}
                    self.assertTrue(unchanged.items() <= after.items())
                    if rebind_after_nv_start:
                        # The genuine unindexed STOP must keep the public
                        # cold catalog reader HOLD. Old count bytes are part
                        # of the unchanged originals assertion above; do not
                        # bypass that reader to pretend this partial tree GO.
                        with self.assertRaises(globals_.GlobalAttemptHold):
                            case.current_global_state(owner, bound, first)
                        attempt = shared / (stem + '.unit-' + first.unit_id + '.journal') / 'ATTEMPT-1'
                        self.assertEqual((1,'UNKNOWN'),
                            (json.loads(attempt.read_bytes())['attempt_count'], json.loads(attempt.read_bytes())['outcome']))
                    else:
                        state = case.current_global_state(owner, bound, first)
                        self.assertEqual((1,'UNKNOWN'), (state.attempt_count, state.outcome))
                    return
                catalog.register_pending_c6_unit(writer, owner, bound, second)
                before = original_read_files(case.root)
                if rebind_after_start:
                    from contextlib import contextmanager
                    started = globals_._write_global_start; reached = []
                    marker = local._owner(writer).project / '.tracker' / ('REMOTE-APPLIED-' + first.unit_id)
                    original = marker.read_bytes(); inode = marker.stat().st_ino
                    preserved = case.root / 'preserved-successor-original-applied'
                    @contextmanager
                    def start_then_rebind(*arguments, **keywords):
                        with started(*arguments, **keywords) as verify:
                            marker.rename(preserved); marker.write_bytes(original); marker.chmod(0o600)
                            reached.append('actual-new-global-start-then-prior-applied-rebound')
                            yield verify
                            verify()
                    with mock.patch.object(globals_, '_write_global_start', side_effect=start_then_rebind):
                        with self.assertRaises(globals_.GlobalAttemptHold): prepare(owner, bound, second)
                    self.assertEqual(['actual-new-global-start-then-prior-applied-rebound'], reached)
                    self.assertEqual(inode, preserved.stat().st_ino); self.assertNotEqual(inode, marker.stat().st_ino)
                    self.assertEqual(original, marker.read_bytes()); self.assertEqual(original, preserved.read_bytes())
                    stem = globals_.ownership._validated_owner(owner, bound).lock_name[:-5]
                    shared = case.root / 'var/lib/http-ztp-container/issue-tracker'
                    self.assertTrue((shared / (stem + '.unit-' + second.unit_id + '.journal-started')).is_file())
                    self.assertFalse((shared / (stem + '.unit-' + second.unit_id + '.journal')).exists(),
                        'prior original drift must stop before creating a new GLOBAL directory')
                elif applied:
                    prepare(owner, bound, second)
                    observed = globals_.inspect_catalog_global_units(owner, bound)
                    self.assertEqual((first, second), tuple(unit for unit, _state in observed))
                    self.assertEqual(((1,'UNKNOWN'), (0,'UNATTEMPTED_OBSERVATION')),
                        tuple((state.attempt_count, state.outcome) for _unit, state in observed))
                    if successor_claim:
                        self._settled_successor_claims(case,globals_,writer,owner,bound,first,second,claim_fault)
                        return
                    if successor_count:
                        from contextlib import contextmanager
                        import json
                        if another_pending:
                            third_arguments = inputs()
                            third_arguments['business'][0]['observed_values'] = {'L': {'stringValue':'down'}}
                            third_arguments['audits'] = ({'event_id':'settings:003',
                                'recorded_at_utc':'2026-10-08T11:00:00Z','details':'K=3'},)
                            third_generation = local.begin_generation(writer,third_arguments['manifest'])
                            local.record_intent(writer,third_generation,literal_xlsx(),kind='xlsx')
                            third_receipt = local.commit(writer,third_generation)
                            third_arguments.update(spreadsheet_id=bound.spreadsheet_id,
                                generation_id=third_generation.generation_id,publish_id=third_receipt.published_sha256,
                                sheet_id=101,history_sheet_id=105,target_nonce='a'*64,history_nonce='d'*64)
                            third = catalog.composer.freeze_send_unit(**third_arguments)
                            catalog.register_pending_c6_unit(writer,owner,bound,third)
                            prepare(owner,bound,third)
                            retained = original_read_files(case.root)
                            for selected in (second,third):
                                with self.assertRaises(globals_.GlobalAttemptHold):
                                    globals_.record_global_attempt_intent(owner,bound,selected)
                            self.assertEqual(retained,original_read_files(case.root),
                                'neither a prior pending nor a nonfinal selected unit may be omitted')
                            observations = globals_.inspect_catalog_global_units(owner,bound)
                            self.assertEqual(((1,'UNKNOWN'),(0,'UNATTEMPTED_OBSERVATION'),(0,'UNATTEMPTED_OBSERVATION')),
                                tuple((state.attempt_count,state.outcome) for _original,state in observations))
                            return
                        marker = local._owner(writer).project / '.tracker' / ('REMOTE-APPLIED-' + first.unit_id)
                        original = marker.read_bytes(); inode = marker.stat().st_ino
                        preserved = case.root / 'preserved-count-successor-original-applied'
                        stem = globals_.ownership._validated_owner(owner, bound).lock_name[:-5]
                        shared = case.root / 'var/lib/http-ztp-container/issue-tracker'
                        attempt = shared / (stem + '.unit-' + second.unit_id + '.journal') / 'ATTEMPT-1'
                        before_count = original_read_files(case.root); reached = []
                        if lose_applied_before_count:
                            marker.rename(preserved)
                            with self.assertRaises(globals_.GlobalAttemptHold):
                                globals_.record_global_attempt_intent(owner, bound, second)
                            self.assertFalse(attempt.exists())
                            self.assertEqual(inode, preserved.stat().st_ino)
                        elif rebind_after_attempt or rebind_attempt_image:
                            started = globals_._write_global_start
                            original_attempt = []; saved_attempt = case.root / 'preserved-count-original-attempt'
                            @contextmanager
                            def attempt_then_rebind(*arguments, **keywords):
                                with started(*arguments, **keywords) as verify:
                                    if arguments[1] == 'ATTEMPT-1':
                                        if rebind_attempt_image:
                                            raw = attempt.read_bytes(); identity = attempt.stat().st_ino
                                            attempt.rename(saved_attempt); attempt.write_bytes(raw); attempt.chmod(0o600)
                                            original_attempt.append((identity,raw))
                                            reached.append('actual-attempt-creator-original-replaced-before-consumer')
                                        else:
                                            marker.rename(preserved); marker.write_bytes(original); marker.chmod(0o600)
                                            reached.append('actual-attempt-original-held-before-old-applied-rebind')
                                    yield verify
                                    verify()
                            with mock.patch.object(globals_, '_write_global_start', side_effect=attempt_then_rebind):
                                with self.assertRaises(globals_.GlobalAttemptHold):
                                    globals_.record_global_attempt_intent(owner, bound, second)
                            self.assertEqual(['actual-attempt-creator-original-replaced-before-consumer'
                                if rebind_attempt_image else 'actual-attempt-original-held-before-old-applied-rebind'], reached)
                            self.assertTrue(attempt.is_file()); self.assertFalse(attempt.with_name('ATTEMPT-2').exists())
                            self.assertEqual((1,'UNKNOWN'),
                                (json.loads(attempt.read_bytes())['attempt_count'],json.loads(attempt.read_bytes())['outcome']))
                            if rebind_attempt_image:
                                self.assertEqual(1,len(original_attempt))
                                self.assertEqual(original_attempt[0][0],saved_attempt.stat().st_ino)
                                self.assertNotEqual(saved_attempt.stat().st_ino,attempt.stat().st_ino)
                                self.assertEqual(original_attempt[0][1],saved_attempt.read_bytes())
                                self.assertEqual(original_attempt[0][1],attempt.read_bytes())
                            else:
                                self.assertEqual(inode, preserved.stat().st_ino)
                                self.assertNotEqual(inode, marker.stat().st_ino)
                                self.assertEqual(original, marker.read_bytes())
                        else:
                            prior_images = before_count
                            for count in range(1,7):
                                state = globals_.record_global_attempt_intent(owner, bound, second)
                                self.assertEqual((count,'UNKNOWN'),(state.attempt_count,state.outcome))
                                self.assertEqual(second.wire_sha256,state.wire_sha256)
                                self.assertEqual(second.action_digest,state.action_digest)
                                current_images = original_read_files(case.root)
                                self.assertTrue(prior_images.items() <= current_images.items())
                                prior_images = current_images
                            retained = original_read_files(case.root)
                            with self.assertRaises(globals_.GlobalAttemptHold):
                                globals_.record_global_attempt_intent(owner, bound, second)
                            self.assertEqual(retained,original_read_files(case.root))
                            self.assertEqual((6,'UNKNOWN'),
                                (globals_.inspect_global_unit(owner,bound,second).attempt_count,
                                 globals_.inspect_global_unit(owner,bound,second).outcome))
                        unchanged = {name:image for name,image in before_count.items()
                            if not (rebind_after_attempt or lose_applied_before_count)
                            or name != str(marker.relative_to(case.root))}
                        self.assertTrue(unchanged.items() <= original_read_files(case.root).items())
                        state = case.current_global_state(owner,bound,first)
                        self.assertEqual((1,'UNKNOWN'),(state.attempt_count,state.outcome))
                        return
                    with module._hold_all_project_fifo_frontier(owner, bound) as (frontier, verify):
                        self.assertEqual((first.unit_id,), frontier.applied)
                        self.assertEqual((second.unit_id,), frontier.frontier)
                        self.assertEqual((), frontier.blocked); verify()
                else:
                    with self.assertRaises(globals_.GlobalAttemptHold): prepare(owner, bound, second)
                    self.assertEqual(before, original_read_files(case.root))
                self.assertEqual((1,'UNKNOWN'), (case.current_global_state(owner,bound,first).attempt_count,
                    case.current_global_state(owner,bound,first).outcome))
                after = original_read_files(case.root)
                unchanged = {name:image for name,image in before.items()
                    if not rebind_after_start or name != str(marker.relative_to(case.root))}
                self.assertTrue(unchanged.items() <= after.items(), 'old originals cannot be rewritten by successor preparation')
        finally:
            case.doCleanups()

    def _settled_successor_claims(self,case,globals_,writer,owner,bound,first,second,fault):
        from contextlib import contextmanager
        from dataclasses import replace
        from unittest import mock
        import json,os
        local = globals_.local
        stem = globals_.ownership._validated_owner(owner,bound).lock_name[:-5]
        shared = case.root / 'var/lib/http-ztp-container/issue-tracker'
        dispatch = shared / (stem + '.unit-' + second.unit_id + '.dispatch')
        marker = local._owner(writer).project / '.tracker' / ('REMOTE-APPLIED-' + first.unit_id)
        receipt = (local._owner(writer).project / '.tracker/generations' /
            local._json(second.action_preimage)['identity']['generation_id'] / 'RECEIPT')
        globals_.record_global_attempt_intent(owner,bound,second)
        before = original_read_files(case.root); reached = []; changed = []
        preserved = case.root / 'preserved-successor-claim-original'
        def denied_without_yield(actual_writer):
            yielded = []
            with self.assertRaises(globals_.GlobalAttemptHold):
                with globals_._hold_counted_original_wire(actual_writer,owner,bound,second):
                    yielded.append(True)
            self.assertEqual([],yielded,'refusal must occur before counted wire handoff')
        def rebound(path):
            raw = path.read_bytes(); inode = path.stat().st_ino
            path.rename(preserved); path.write_bytes(raw); path.chmod(0o600)
            self.assertEqual(inode,preserved.stat().st_ino); self.assertNotEqual(inode,path.stat().st_ino)
            self.assertEqual(raw,path.read_bytes()); self.assertEqual(raw,preserved.read_bytes())
            changed.append(str(path.relative_to(case.root)))
        if fault == 'missing-applied':
            inode = marker.stat().st_ino; marker.rename(preserved)
            denied_without_yield(writer)
            self.assertEqual(inode,preserved.stat().st_ino); changed.append(str(marker.relative_to(case.root)))
            self.assertFalse(dispatch.exists())
        elif fault == 'before-claim-c6':
            rebound(receipt)
            denied_without_yield(writer)
            self.assertFalse(dispatch.exists())
        elif fault == 'foreign-writer':
            project = case.root / 'foreign-claim-project'; publication = project / 'publication'
            project.mkdir(mode=0o700); publication.mkdir(mode=0o700)
            local.create_local_commit_store(project,publication)
            with local.writer_owner(project,publication) as foreign:
                denied_without_yield(foreign)
            self.assertFalse(dispatch.exists())
        elif fault in ('after-claim-applied','claim-image','dispatch-header'):
            creator = globals_._write_global_start
            @contextmanager
            def create_then_rebind(folder,name,raw):
                with creator(folder,name,raw) as verify:
                    if name == ('HEADER' if fault == 'dispatch-header' else 'CLAIM-1'):
                        reached.append('actual-exclusive-' + name)
                        rebound(marker if fault == 'after-claim-applied' else dispatch / name)
                    yield verify
                    verify()
            with mock.patch.object(globals_,'_write_global_start',side_effect=create_then_rebind):
                denied_without_yield(writer)
            self.assertEqual(['actual-exclusive-' + ('HEADER' if fault == 'dispatch-header' else 'CLAIM-1')],reached)
            self.assertEqual(fault != 'dispatch-header',(dispatch / 'CLAIM-1').exists())
            self.assertFalse((dispatch / 'CLAIM-2').exists())
        elif fault in ('consumer-applied','consumer-c6'):
            refused = []; consumed = []
            with self.assertRaises(globals_.GlobalAttemptHold):
                with globals_._hold_counted_original_wire(writer,owner,bound,second) as image:
                    globals_._require_original_wire_launch(writer,owner,bound,second,image,consume=True)
                    reached.append('actual-consumed-claim')
                    rebound(receipt if fault == 'consumer-c6' else marker)
                    try:
                        globals_._require_original_wire_launch(writer,owner,bound,second,image,consume=False)
                    except globals_.GlobalAttemptHold: refused.append(True)
                    else: refused.append(False)
                    consumed.append(globals_._LIVE_WIRE_CLAIMS[image][-1])
            self.assertEqual(['actual-consumed-claim'],reached)
            self.assertEqual([True],refused,'exit rejection cannot replace the actual last consumer rejection')
            self.assertEqual([True],consumed,'failed consumer verification cannot restore once-consumed state')
            self.assertTrue((dispatch / 'CLAIM-1').is_file()); self.assertFalse((dispatch / 'CLAIM-2').exists())
        else:
            prior = before
            for count in range(1,7):
                if count > 1:
                    observed = globals_.record_global_attempt_intent(owner,bound,second)
                    self.assertEqual(count,observed.attempt_count)
                with globals_._hold_counted_original_wire(writer,owner,bound,second) as image:
                    self.assertEqual((count,second.wire_sha256),(image.attempt_count,image.wire_sha256))
                    self.assertEqual(second.wire_bytes,os.pread(image.fd,1024*1024+1,0))
                    self.assertEqual(second.action_preimage,os.pread(image.action_fd,1024*1024+1,0))
                    self.assertFalse(os.get_inheritable(image.fd)); self.assertFalse(hasattr(image,'permit'))
                    with self.assertRaises(globals_.GlobalAttemptHold):
                        globals_._require_original_wire_launch(writer,owner,bound,second,replace(image),consume=True)
                    globals_._require_original_wire_launch(writer,owner,bound,second,image,consume=True)
                    globals_._require_original_wire_launch(writer,owner,bound,second,image,consume=False)
                    with self.assertRaises(globals_.GlobalAttemptHold):
                        globals_._require_original_wire_launch(writer,owner,bound,second,image,consume=True)
                    self.assertEqual({'HEADER','INITIALIZED',*(f'CLAIM-{i}' for i in range(1,count+1))},
                        {path.name for path in dispatch.iterdir()})
                    if count == 1:
                        self._native_successor_claim_child(case,globals_,writer,owner,bound,second,image)
                current = original_read_files(case.root)
                self.assertTrue(prior.items() <= current.items()); prior = current
                denied_without_yield(writer)
            retained = original_read_files(case.root)
            with self.assertRaises(globals_.GlobalAttemptHold): globals_.record_global_attempt_intent(owner,bound,second)
            self.assertEqual(retained,original_read_files(case.root))
        if fault in ('after-claim-applied','claim-image','dispatch-header','consumer-applied','before-claim-c6','consumer-c6'):
            target = (dispatch / ('HEADER' if fault == 'dispatch-header' else 'CLAIM-1')
                if fault in ('claim-image','dispatch-header') else receipt
                if fault in ('before-claim-c6','consumer-c6') else marker)
            self.assertEqual([str(target.relative_to(case.root))],changed,
                'actual same-byte new-inode fault must be witnessed outside production exception normalization')
        unchanged = {name:value for name,value in before.items() if name not in changed}
        self.assertTrue(unchanged.items() <= original_read_files(case.root).items())
        self.assertEqual((1,'UNKNOWN'),(case.current_global_state(owner,bound,first).attempt_count,
            case.current_global_state(owner,bound,first).outcome))
        self.assertEqual((6 if not fault else 1,'UNKNOWN'),
            (case.current_global_state(owner,bound,second).attempt_count,case.current_global_state(owner,bound,second).outcome))

    def _native_successor_claim_child(self,case,globals_,writer,owner,bound,unit,image):
        from test_cases import test_req7_native_supervised_workflow as native_tests
        import hashlib,json,socket,time
        native = native_tests.Req7NativeSupervisedWorkflowTests()
        native.root = case.root / 'owned-successor-mutation-tls'
        native.root.mkdir(mode=0o700)
        native.path = native.root / 'etc/ssl/certs/ca-certificates.crt'
        native.path.parent.mkdir(parents=True); native.path.write_bytes(b'owned fixture pending CA'); native.path.chmod(0o644)
        reply = b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        try:
            with native.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors):
                port = socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                locks = (globals_.local._owner(writer).lock_fd,globals_.ownership.owner_lock_fd(owner,bound))
                raw = json.dumps({'binding':vars(bound),'token':'owned-local-fixture-token',
                    'expires_at':time.time()+3600},sort_keys=True,separators=(',',':')).encode()
                globals_._require_original_wire_launch(writer,owner,bound,unit,image,consume=False)
                child,started = native.launch_original_fixture(port,image,locks)
                result = native_tests.supervision_fixtures.load().supervise_owned_attempt(
                    child,started_monotonic=started,kind='mutation',request_bytes=raw)
                self.assertTrue(result.termination_confirmed); self.assertEqual(0,child.returncode)
                self.assertEqual({'status':401,'wire_sha256':unit.wire_sha256,
                    'response_sha256':hashlib.sha256(b'{}').hexdigest(),'outcome':'UNKNOWN'},json.loads(result.data))
                globals_._require_original_wire_launch(writer,owner,bound,unit,image,consume=False)
            self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(unit.wire_bytes,records[0][2])
        finally:
            native.doCleanups()

    def test_actual_settled_successor_six_counts_claim_once_and_fixed_local_child_keep_unknown(self):
        self._catalog_completed_successor(applied=True,successor_claim=True)

    def test_actual_missing_prior_applied_after_count_refuses_successor_dispatch(self):
        self._catalog_completed_successor(applied=True,successor_claim=True,claim_fault='missing-applied')

    def test_actual_foreign_live_writer_cannot_claim_successor_c6(self):
        self._catalog_completed_successor(applied=True,successor_claim=True,claim_fault='foreign-writer')

    def test_actual_claim_write_prior_applied_rebind_holds_and_retains_claim(self):
        self._catalog_completed_successor(applied=True,successor_claim=True,claim_fault='after-claim-applied')

    def test_actual_claim_creator_original_replacement_is_not_adopted(self):
        self._catalog_completed_successor(applied=True,successor_claim=True,claim_fault='claim-image')

    def test_actual_dispatch_header_creator_original_replacement_stops_before_claim(self):
        self._catalog_completed_successor(applied=True,successor_claim=True,claim_fault='dispatch-header')

    def test_actual_consumed_successor_claim_prior_applied_rebind_cannot_restore_consumption(self):
        self._catalog_completed_successor(applied=True,successor_claim=True,claim_fault='consumer-applied')

    def test_actual_selected_c6_rebind_after_count_refuses_claim_before_dispatch(self):
        self._catalog_completed_successor(applied=True,successor_claim=True,claim_fault='before-claim-c6')

    def test_actual_consumed_successor_claim_selected_c6_rebind_refuses_last_consumer(self):
        self._catalog_completed_successor(applied=True,successor_claim=True,claim_fault='consumer-c6')

    def test_actual_settled_successor_claim_cold_process_cannot_reuse_consumed_count(self):
        from dataclasses import asdict
        import json,subprocess
        from test_cases import test_req7_unit_catalog as catalog_tests
        fixture = catalog_tests.CatalogAppliedNativeWorkflowTests()
        with fixture.completed_and_pending(project_origins=True) as (
                case,catalog,_remote,_inventory,_old_api,writer,owner,bound,units):
            from monitor import issue_tracker_global_attempt_journal as globals_
            globals_.record_global_attempt_intent(owner,bound,units[-1])
            with globals_._hold_counted_original_wire(writer,owner,bound,units[-1]) as image:
                globals_._require_original_wire_launch(writer,owner,bound,units[-1],image,consume=True)
                globals_._require_original_wire_launch(writer,owner,bound,units[-1],image,consume=False)
            before = original_read_files(case.root)
            case.catalog_release_owners()
            program = '''import sys,json
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tools')]
from test_cases import test_req7_unit_catalog as tests
catalog=tests.load()
tests.load_component('issue_tracker_remote_history_match')
from monitor import issue_tracker_global_attempt_journal as journal
from monitor.issue_tracker_online_target import OnlineTargetBinding
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
assert catalog.local._ACTIVE=={}
with catalog.local.writer_owner(root/'project',root/'project/publication') as writer:
 with scoped_fixture(root,catalog.ownership),catalog.ownership.spreadsheet_owner(bound) as owner:
  with catalog.hold_pending_units(owner,bound) as (units,verify):
   assert len(units)==2; selected=units[-1]; verify()
  observed=journal.inspect_catalog_global_units(owner,bound)
  assert tuple((state.attempt_count,state.outcome) for unit,state in observed)==((1,'UNKNOWN'),(1,'UNKNOWN'))
  yielded=[]; refused=False
  try:
   with journal._hold_counted_original_wire(writer,owner,bound,selected):
    yielded.append(True)
  except journal.GlobalAttemptHold: refused=True
  assert refused and not yielded, 'cold consumed count was accepted or yielded'
  assert journal.inspect_global_unit(owner,bound,selected).attempt_count==1
  assert len(journal._LIVE_WIRE_CLAIMS)==0
assert catalog.local._ACTIVE=={}
print('COLD_SETTLED_SUCCESSOR_CONSUMED_COUNT_HOLD_ORIGINAL_UNKNOWN')
'''
            result = subprocess.run([sys.executable,'-B','-c',program,str(SOURCE.parents[1]),str(case.root)],
                input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
            self.assertEqual(0,result.returncode,result.stdout+result.stderr)
            self.assertEqual(b'COLD_SETTLED_SUCCESSOR_CONSUMED_COUNT_HOLD_ORIGINAL_UNKNOWN\n',result.stdout)
            self.assertEqual(before,original_read_files(case.root))

    def test_actual_catalog_complete_applied_keys_allow_same_key_successor_global_preparation(self):
        self._catalog_completed_successor(applied=True)

    def test_settled_original_successor_counts_six_identical_unknowns_without_resetting_prior_count(self):
        self._catalog_completed_successor(applied=True,successor_count=True)

    def test_another_actual_pending_catalog_unit_is_never_omitted_by_successor_count(self):
        self._catalog_completed_successor(applied=True,successor_count=True,another_pending=True)

    def test_missing_actual_prior_applied_after_preparation_denies_successor_first_count(self):
        self._catalog_completed_successor(applied=True,successor_count=True,lose_applied_before_count=True)

    def test_actual_successor_attempt_write_then_prior_applied_rebind_retains_unknown_without_return(self):
        self._catalog_completed_successor(applied=True,successor_count=True,rebind_after_attempt=True)

    def test_actual_successor_attempt_creator_original_replacement_cannot_be_adopted(self):
        self._catalog_completed_successor(applied=True,successor_count=True,rebind_attempt_image=True)

    def test_actual_catalog_complete_without_applied_keys_keeps_successor_unknown_barrier(self):
        self._catalog_completed_successor(applied=False)

    def test_prior_applied_original_rebind_after_new_start_stops_before_successor_global_directory(self):
        self._catalog_completed_successor(applied=True, rebind_after_start=True)

    def test_actual_native_columns_after_complete_applied_keys_allow_successor_nv_without_resetting_count(self):
        self._catalog_completed_successor(applied=True, native_nv=True)

    def test_actual_native_columns_complete_without_applied_keys_refuse_successor_nv(self):
        self._catalog_completed_successor(applied=False, native_nv=True)

    def test_prior_applied_rebind_after_actual_nv_started_stops_before_successor_nv_directory(self):
        self._catalog_completed_successor(applied=True, native_nv=True, rebind_after_nv_start=True)

    def api(self, module):
        api = getattr(module, '_hold_retained_applied_keys', None)
        self.assertTrue(callable(api), 'retained APPLIED keys must derive C6 from held originals, not caller generation/keys')
        return api

    def test_unissued_writer_never_reaches_spreadsheet_inventory(self):
        from unittest import mock
        module = load(); api = self.api(module)
        with mock.patch.object(module, '_hold_retained_inventory') as inventory:
            with self.assertRaises(module.RetainedInventoryHold):
                with api(object(), object(), object()):
                    self.fail('unissued writer yielded original APPLIED keys')
            inventory.assert_not_called()

    def test_no_caller_unit_generation_or_key_list_can_claim_settlement(self):
        module = load(); api = self.api(module)
        for claims in ({'generation': object()}, {'unit': object()}, {'keys': ((('switch', 'foreign'), 999),)}):
            with self.subTest(claims=tuple(claims)), self.assertRaises(TypeError):
                with api(object(), object(), object(), **claims):
                    self.fail('caller settlement claim reached a context')

    def test_actual_native_c6_complete_applied_keys_are_original_readonly_not_new(self):
        module = load(); api = self.api(module)
        case = remote_tests.Req7OwnedHistoryMatchWorkflowTests(); case.setUp()
        try:
            match = remote_tests.load()
            with ExitStack() as scope:
                writer, owner, bound, unit = case.prepare_native_completed(scope, match)
                match.record_owned_applied_evidence(writer, owner, bound, unit, generation=case.native_generation)
                match.record_owned_applied_key_watermarks(writer, owner, bound, unit, generation=case.native_generation)
                before = original_read_files(case.root)
                with api(writer, owner, bound) as (keys, verify):
                    self.assertEqual(((('switch', 'node0001', 'down', 'fabric'), 1),), keys)
                    self.assertIs(type(keys), tuple)
                    self.assertFalse(hasattr(keys, 'permit'))
                    verify()
                self.assertEqual(before, original_read_files(case.root))
                state = case.current_global_state(owner, bound, unit)
                self.assertEqual((1, 'UNKNOWN'), (state.attempt_count, state.outcome))
        finally:
            case.doCleanups()

    def test_held_key_pair_and_c6_replacement_revoke_before_consumer_acceptance(self):
        for target in ('key-marker', 'c6-receipt'):
            with self.subTest(target=target):
                module = load(); api = self.api(module)
                case = remote_tests.Req7OwnedHistoryMatchWorkflowTests(); case.setUp()
                try:
                    match = remote_tests.load()
                    with ExitStack() as scope:
                        writer, owner, bound, unit = case.prepare_native_completed(scope, match)
                        match.record_owned_applied_evidence(writer, owner, bound, unit, generation=case.native_generation)
                        match.record_owned_applied_key_watermarks(writer, owner, bound, unit, generation=case.native_generation)
                        tracker = case.root / 'project/.tracker'
                        path = (tracker / ('REMOTE-KEY-HIGH-WATER-' + unit.unit_id)
                                if target == 'key-marker' else
                                tracker / 'generations' / case.native_generation.generation_id / 'RECEIPT')
                        entered = []
                        with self.assertRaises(module.RetainedInventoryHold):
                            with api(writer, owner, bound) as (keys, verify):
                                entered.append(keys)
                                image = path.read_bytes()
                                path.rename(case.root / 'preserved-settlement-original')
                                path.write_bytes(image); path.chmod(0o600)
                                verify()
                        self.assertEqual([((('switch', 'node0001', 'down', 'fabric'), 1),)], entered)
                        self.assertEqual(image, path.read_bytes())
                        self.assertNotEqual(path.stat().st_ino, (case.root / 'preserved-settlement-original').stat().st_ino)
                        state = case.current_global_state(owner, bound, unit)
                        self.assertEqual((1, 'UNKNOWN'), (state.attempt_count, state.outcome))
                finally:
                    case.doCleanups()

    def test_complete_without_applied_or_key_pair_cannot_be_settled_or_repaired(self):
        module = load(); api = self.api(module)
        case = remote_tests.Req7OwnedHistoryMatchWorkflowTests(); case.setUp()
        try:
            match = remote_tests.load()
            with ExitStack() as scope:
                writer, owner, bound, unit = case.prepare_native_completed(scope, match)
                for applied_present in (False, True):
                    if applied_present:
                        match.record_owned_applied_evidence(writer, owner, bound, unit, generation=case.native_generation)
                    before = original_read_files(case.root)
                    with self.subTest(applied_present=applied_present), self.assertRaises(module.RetainedInventoryHold):
                        with api(writer, owner, bound):
                            self.fail('incomplete settlement yielded keys')
                    self.assertEqual(before, original_read_files(case.root))
        finally:
            case.doCleanups()
