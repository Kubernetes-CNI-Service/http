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
    spec = importlib.util.spec_from_file_location('owned_retained_applied_inventory', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RetainedAppliedInventoryTests(unittest.TestCase):
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
                                     native_nv=False, rebind_after_nv_start=False):
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

    def test_actual_catalog_complete_applied_keys_allow_same_key_successor_global_preparation(self):
        self._catalog_completed_successor(applied=True)

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
