"""Independent immutable pre-send History boundary, never COMPLETE or permission."""
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
    sys.path.insert(0, sys.argv[3]); sys.path.insert(0, str(Path(sys.argv[3]) / 'tools'))
import test_cases
ROOT = Path(test_cases.__file__).resolve().parents[1]
from test_cases.test_req7_spreadsheet_owner import fixture, binding, TARGET, load as load_owner
from test_cases.test_req7_global_attempt_journal import load as load_global, unit
from test_cases.test_req7_history_read import inputs, load as load_read, response, tail_document
SOURCE = ROOT / 'monitor/issue_tracker_history_preread_journal.py'


def load():
    if not SOURCE.is_file(): raise AssertionError('immutable History pre-send journal missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_history_preread_journal', SOURCE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    monitor.issue_tracker_history_preread_journal = module
    return module


class Req7HistoryPrereadJournalDirectTests(unittest.TestCase):
    def setUp(self):
        self.owner = load_owner(); self.global_journal = load_global()
        self.planner = load_read('issue_tracker_sheets_read_plan'); load_read('issue_tracker_sheets_read_decode')
        self.temp = tempfile.TemporaryDirectory(prefix='req7-history-preread-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.locks = self.root / 'var/lib/http-ztp-container/issue-tracker'
        self.locks.mkdir(parents=True, mode=0o700); self.value = unit()
        self.store = self.locks / (hashlib.sha256(TARGET.encode()).hexdigest() + '.history')
        target, token = inputs(); self.plan = self.planner.prepare_history_tail_read(target, token)
        self.raw = response(tail_document())

    def test_original_raw_and_boundary_bind_existing_global_unit_before_any_attempt(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            self.assertFalse(self.store.exists())
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            seen = module.inspect_history_preread(token, binding(), self.value)
            self.assertEqual((3, 7, 99), (seen.history_last_row_before_send, seen.row_count, seen.history_sheet_id))
            self.assertEqual(self.raw.data, (self.store / 'HISTORY-RAW').read_bytes())
            self.assertEqual(hashlib.sha256(self.raw.data).hexdigest(), seen.source_sha256)
            self.assertEqual(self.value.action_digest, seen.action_digest)
            self.assertFalse(hasattr(seen, 'complete')); self.assertFalse(hasattr(seen, 'permit'))
            for count in range(1, 7):
                self.global_journal.record_global_attempt_intent(token, binding(), self.value)
                self.assertEqual(3, module.inspect_history_preread(token, binding(), self.value).history_last_row_before_send)
            with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            self.assertEqual(self.raw.data, (self.store / 'HISTORY-RAW').read_bytes())

    def test_original_capacity_reserves_all_actual_history_rows_and_survives_unknown_without_reallocation(self):
        module = load()
        self.assertTrue(hasattr(module, 'require_history_append_capacity'), 'actual History row reservation missing')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            seen = module.require_history_append_capacity(token, binding(), self.value)
            self.assertEqual((4, 5, 2, 1, 7), (seen.first_row_index, seen.last_row_index, seen.rows_reserved, seen.remaining_rows, seen.row_count))
            self.assertEqual(self.value.action_digest, seen.action_digest)
            for count in range(1, 7):
                self.global_journal.record_global_attempt_intent(token, binding(), self.value)
                self.assertEqual(seen, module.require_history_append_capacity(token, binding(), self.value))
            self.assertFalse(hasattr(seen, 'permit')); self.assertFalse(hasattr(seen, 'complete'))

    def test_history_capacity_full_typed_gap_and_exact_boundary_use_original_not_caller_counter(self):
        module = load()
        self.assertTrue(hasattr(module, 'require_history_append_capacity'), 'actual History row reservation missing')
        for row_count, row_data, expected in ((3, [], None), (4, [], (2, 3, 0)),
                (5, [{'values': [{'userEnteredValue': {'boolValue': False}}]}], (3, 4, 0)),
                (5, [{}, {'values': [{}, {}, {}, {}, {'userEnteredValue': {'stringValue': ''}}]}], None)):
            with self.subTest(row_count=row_count, tail=len(row_data)), tempfile.TemporaryDirectory(prefix='req7-history-capacity-') as directory:
                root = Path(directory).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(parents=True, mode=0o700)
                value = tail_document(row_count); value['sheets'][0]['data'][0]['rowData'] = row_data
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.global_journal.prepare_global_unit(token, binding(), self.value)
                    module.prepare_history_preread(token, binding(), self.value, self.plan, response(value))
                    before = {p.name: p.read_bytes() for p in (locks / self.store.name).iterdir()}
                    if expected is None:
                        with self.assertRaises(module.HistoryPrereadHold): module.require_history_append_capacity(token, binding(), self.value)
                    else:
                        seen = module.require_history_append_capacity(token, binding(), self.value)
                        self.assertEqual(expected, (seen.first_row_index, seen.last_row_index, seen.remaining_rows))
                    self.assertEqual(before, {p.name: p.read_bytes() for p in (locks / self.store.name).iterdir()})
                    with self.assertRaises(TypeError): module.require_history_append_capacity(token, binding(), self.value, rows=1)
    def test_after_first_intent_no_creation_and_revocation_or_changed_binding_no_adoption(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            self.global_journal.record_global_attempt_intent(token, binding(), self.value)
            with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            self.assertFalse(self.store.exists())
        with fixture(self.root), self.assertRaises(module.HistoryPrereadHold): module.inspect_history_preread(token, binding(), self.value)
        for changed in (replace(binding(), policy_sha256='f' * 64), replace(binding(), allowlist_sha256='f' * 64)):
            with fixture(self.root), self.owner.spreadsheet_owner(changed) as fresh:
                with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(fresh, changed, self.value, self.plan, self.raw)
        self.assertFalse(self.store.exists())

    def test_fixed_full_response_retains_all_two_mib_without_manifest_limit_or_truncation(self):
        from types import SimpleNamespace
        module = load(); raw = self.raw.data + b' ' * (2 * 1024 * 1024 - len(self.raw.data))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            with self.assertRaises(module.HistoryPrereadHold):
                module.prepare_history_preread(token, binding(), self.value, self.plan,
                    SimpleNamespace(status=200, complete=True, data=raw + b' '))
            self.assertFalse(self.store.exists())
            module.prepare_history_preread(token, binding(), self.value, self.plan,
                SimpleNamespace(status=200, complete=True, data=raw))
            seen = module.inspect_history_preread(token, binding(), self.value)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), seen.source_sha256)
            self.assertEqual((4, 5), (module.require_history_append_capacity(token, binding(), self.value).first_row_index,
                                     module.require_history_append_capacity(token, binding(), self.value).last_row_index))
        self.assertEqual(raw, (self.store / 'HISTORY-RAW').read_bytes())

    def test_partial_window_wrong_history_identity_and_partial_response_never_create_image(self):
        module = load()
        item = tail_document(); item['sheets'][0]['properties']['sheetId'] = 98
        from types import SimpleNamespace
        cases = ((replace(self.plan, path=self.plan.path.replace('E5002', 'E7')), self.raw),
                 (self.plan, response(item)), (self.plan, SimpleNamespace(status=200, complete=False, data=self.raw.data)))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            for plan, raw in cases:
                with self.assertRaises(module.HistoryPrereadHold) as caught: module.prepare_history_preread(token, binding(), self.value, plan, raw)
                self.assertIsNone(caught.exception.__context__); self.assertFalse(self.store.exists())

    def test_all_six_image_barriers_precede_marker_and_partial_never_backfilled(self):
        module = load(); real_fsync = os.fsync
        for boundary in range(1, 7):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(prefix='req7-before-barrier-') as directory:
                root = Path(directory).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(parents=True, mode=0o700)
                store = locks / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.global_journal.prepare_global_unit(token, binding(), self.value)
                    calls = []
                    def failing(fd):
                        calls.append(fd)
                        if len(calls) == boundary: raise OSError('private synthetic barrier failure')
                        real_fsync(fd)
                    with mock.patch('os.fsync', side_effect=failing), self.assertRaises(module.HistoryPrereadHold):
                        module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
                    self.assertTrue(store.is_dir()); self.assertFalse((store / 'INITIALIZED').exists())
                    with self.assertRaises(module.HistoryPrereadHold): module.inspect_history_preread(token, binding(), self.value)
                    with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
                    self.assertFalse((store / 'INITIALIZED').exists())

    def test_marker_header_raw_alias_extra_namespace_or_global_chain_tamper_hold(self):
        module = load()
        for fault in ('raw', 'header', 'marker', 'mode', 'symlink', 'hardlink', 'extra', 'global'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-before-tamper-') as directory:
                root = Path(directory).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(parents=True, mode=0o700)
                store = locks / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.global_journal.prepare_global_unit(token, binding(), self.value)
                    module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
                    if fault == 'mode': (store / 'HISTORY-RAW').chmod(0o644)
                    elif fault == 'extra': (store / 'foreign').write_bytes(b'foreign')
                    elif fault == 'global': (locks / (hashlib.sha256(TARGET.encode()).hexdigest() + '.journal') / 'WIRE').write_bytes(b'foreign')
                    elif fault in ('symlink', 'hardlink'):
                        (store / 'HISTORY-RAW').rename(root / 'preserved')
                        if fault == 'symlink': (store / 'HISTORY-RAW').symlink_to(root / 'preserved')
                        else: os.link(root / 'preserved', store / 'HISTORY-RAW')
                    else: (store / {'raw': 'HISTORY-RAW', 'header': 'HEADER', 'marker': 'INITIALIZED'}[fault]).write_bytes(b'foreign')
                    before = {p.name: p.read_bytes() for p in store.iterdir()}
                    with self.assertRaises(module.HistoryPrereadHold): module.inspect_history_preread(token, binding(), self.value)
                    self.assertEqual(before, {p.name: p.read_bytes() for p in store.iterdir()})

    def test_coherent_foreign_target_rehash_does_not_retarget_original_global_journal(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            other = 'foreign_spreadsheet_0002'; item = tail_document(); item['spreadsheetId'] = other
            raw = response(item).data; (self.store / 'HISTORY-RAW').write_bytes(raw)
            header = json.loads((self.store / 'HEADER').read_bytes())
            header['read_path'] = header['read_path'].replace(TARGET, other)
            header['source_sha256'] = hashlib.sha256(raw).hexdigest()
            canonical = lambda value: (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
            (self.store / 'HEADER').write_bytes(canonical(header))
            (self.store / 'INITIALIZED').write_bytes(canonical({'schema_version': 1, 'state': 'INITIALIZED',
                'header_sha256': hashlib.sha256(canonical(header)).hexdigest()}))
            with self.assertRaises(module.HistoryPrereadHold): module.inspect_history_preread(token, binding(), self.value)


class Req7HistoryPrereadJournalWorkflowTests(unittest.TestCase):
    setUp = Req7HistoryPrereadJournalDirectTests.setUp

    def test_actual_native_cold_process_redecodes_immutable_before_tail_after_unknown_intent(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            self.global_journal.record_global_attempt_intent(token, binding(), self.value)
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--owned-inspect', str(self.root), str(ROOT)]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr); self.assertEqual(b'3 7\n', result.stdout)
        self.assertEqual(self.raw.data, (self.store / 'HISTORY-RAW').read_bytes())

    def test_manifest_binds_actual_native_and_durable_dependencies_and_not_run_card(self):
        manifest = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        source = 'monitor/issue_tracker_history_preread_journal.py'; test = 'test_cases.test_req7_history_preread_journal'
        self.assertEqual(source, manifest['scripts'].get(source))
        self.assertTrue(any(source in rule['paths'] and test in rule['tests'] for rule in manifest['test_rules']))
        dependencies = {source, 'monitor/issue_tracker_global_attempt_journal.py', 'monitor/issue_tracker_spreadsheet_owner.py',
                        'monitor/issue_tracker_sheets_read_plan.py', 'monitor/issue_tracker_sheets_read_decode.py', 'monitor/issue_tracker_tls_inputs.py'}
        self.assertTrue(any(dependencies <= set(rule['members']) and test in rule['tests'] for rule in manifest['workflows']))
        self.assertEqual(['issue-tracker-local'], [suite['id'] for suite in manifest['test_suites'] if test in suite['tests']])
        self.assertIn(test, (ROOT / 'test_cases/README.md').read_text())
        cards = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text(); start = cards.index('## TC-REAL-REQ7-HISTORY-PREREAD-JOURNAL-001')
        end = cards.find('\n## ', start + 1); card = cards[start:] if end == -1 else cards[start:end]
        for term in ('NOT RUN / REAL_ENV REQUIRED', '前置条件', 'Stage O', '证据', 'stat/inode', '清理', '不是 COMPLETE'):
            self.assertIn(term, card)


class Req7HistoryPrereadNativeWorkflowTests(unittest.TestCase):
    from test_cases.test_req7_history_read import Req7HistoryReadNativeWorkflowTests as _Fixture
    fixture = _Fixture.fixture; certificates = _Fixture.certificates; server = _Fixture.server

    def setUp(self):
        Req7HistoryPrereadJournalDirectTests.setUp(self)
        self.journal_root = self.root
        self._Fixture.setUp(self)
        target, token = inputs(); self.plan = self.planner.prepare_history_tail_read(target, token)

    def test_native_complete_tail_then_actual_owner_durable_image_then_unknown_does_not_replace_before(self):
        module = load(); target, token_value = inputs()
        payload = self.raw.data
        wire = ('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(payload)).encode() + payload
        unit_read = self.tls.NativeHistoryTailReadUnit(target, token_value)
        self.assertEqual(self.root, self.path.parents[3], 'CA fixture must retain its own actual root')
        # Native network fixture and synthetic global-root fixture deliberately
        # do not overlap: TLS/CA file validation retains real UID/path semantics.
        with self.server(wire, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), self.fixture():
            raw = unit_read.send_once()
        self.assertEqual([], errors); self.assertEqual(1, len(records))
        with fixture(self.journal_root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, raw)
            reserved = module.require_history_append_capacity(token, binding(), self.value)
            self.assertEqual((4, 5, 2, 1), (reserved.first_row_index, reserved.last_row_index, reserved.rows_reserved, reserved.remaining_rows))
            self.global_journal.record_global_attempt_intent(token, binding(), self.value)
            seen = module.inspect_history_preread(token, binding(), self.value)
            self.assertEqual((3, 7), (seen.history_last_row_before_send, seen.row_count))
            self.assertEqual(reserved, module.require_history_append_capacity(token, binding(), self.value))
            later = tail_document(); later['sheets'][0]['data'][0]['rowData'].append({'values': [{'userEnteredValue': {'stringValue': 'later'}}]})
            with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, response(later))
            self.assertEqual(payload, (self.store / 'HISTORY-RAW').read_bytes())


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
        owner = load_owner(); module = load()
        with fixture(Path(sys.argv[2])), owner.spreadsheet_owner(binding()) as token:
            seen = module.inspect_history_preread(token, binding(), unit())
            reserved = module.require_history_append_capacity(token, binding(), unit())
            if (reserved.first_row_index, reserved.last_row_index, reserved.rows_reserved, reserved.remaining_rows) != (4, 5, 2, 1):
                raise AssertionError('original cold-process append reservation changed')
            os.write(1, ('%d %d\n' % (seen.history_last_row_before_send, seen.row_count)).encode())
    else: unittest.main()
