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
