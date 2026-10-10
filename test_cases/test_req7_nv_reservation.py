"""Independent C17 durable shared sequence, not an online mutation permit."""
from dataclasses import replace
from contextlib import contextmanager
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
from types import SimpleNamespace

if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
    sys.path.insert(0, sys.argv[3]); sys.path.insert(0, str(Path(sys.argv[3]) / 'tools'))
from test_cases import test_req7_enrollment_journal as enrollment_tests
from test_cases.test_req7_spreadsheet_owner import fixture, binding, TARGET
from test_cases.test_req7_activity_discovery import sheet_document, cabling_row, literal
from test_cases import test_req7_sheets_read_decode as grids

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'monitor/issue_tracker_nv_reservation.py'
KEYS = (('eth_cabling', 'switch-1', 'swp3', 'Link Down'), ('eth_cabling', 'switch-1', 'swp4', 'Mis-wiring'))


def load():
    if not SOURCE.is_file(): raise AssertionError('C17 durable two-Cabling NV reservation missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_nv_reservation', SOURCE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    monitor.issue_tracker_nv_reservation = module
    return module


def source(sheet, identifiers):
    rows = []
    for index, identifier in enumerate(identifiers):
        row = cabling_row(identifier, 'Closed'); row['K'] = literal('unrelated-%d' % index); rows.append(row)
    item = sheet_document(sheet, rows)
    item['spreadsheetId'] = TARGET
    item['sheets'][0]['properties']['sheetId'] = 102 if sheet == 'ETH Cabling' else 103
    return grids.response(item)


def cabling_inputs(nonces, *, identifiers=('NV30102', 'NV30103')):
    from test_cases.test_req7_send_unit import inputs
    args = inputs(); operations = []; business = []
    for index, (key, identifier) in enumerate(zip(KEYS, identifiers)):
        operation_id = 'eth_cabling:%04d' % index
        operations.append({'operation_id': operation_id, 'activity_key': list(key), 'action': 'upsert'})
        values = {letter: '' for letter in ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'K', 'L', 'M', 'N', 'Q', 'R', 'S', 'T', 'U')}
        values.update(A=identifier, E='ETH', F=key[3], G='literal evidence', K=key[1], L=key[2], U='New')
        business.append({'operation_id': operation_id, 'action': 'insert', 'row_index': None, 'values': values,
            'observed_values': None, 'recorded_at_utc': '2026-10-08T10:00:00Z'})
    manifest = (json.dumps({'schema_version': 1, 'operations': operations}, sort_keys=True, separators=(',', ':')) + '\n').encode()
    original = {title: (sid, nonce) for title, sid, nonce in nonces}
    args.update(manifest=manifest, manifest_id=hashlib.sha256(manifest).hexdigest(), generation_id='c' * 64,
        publish_id='d' * 64, sheet='ETH Cabling', sheet_id=102, history_sheet_id=105,
        target_nonce=original['ETH Cabling'][1], history_nonce=original['Update_History'][1], business=tuple(business))
    return args


@contextmanager
def recycled_outer_nv_directory(module, store, foreign):
    """Recycle only this invocation's outer descriptor at its real replay barrier."""
    foreign.write_bytes(b'foreign outer descriptor original')
    foreign_identity = (foreign.stat().st_dev, foreign.stat().st_ino)
    real_inspect = module._inspect; real_sync = os.fsync
    folders = []; recycled = []
    def inspect_original(*args):
        folders.append(args[2])
        return real_inspect(*args)
    def sync_original(fd):
        if folders and not recycled and os.fstat(fd).st_ino == (store / 'INITIALIZED').stat().st_ino:
            original = folders[-1]
            os.close(original)
            opened = os.open(str(foreign), os.O_RDONLY)
            if opened != original:
                os.dup2(opened, original); os.close(opened)
            recycled.append(original)
        return real_sync(fd)
    try:
        with mock.patch.object(module, '_inspect', side_effect=inspect_original), mock.patch('os.fsync', side_effect=sync_original):
            yield recycled, foreign_identity
    finally:
        for fd in recycled:
            try:
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino) == foreign_identity: os.close(fd)
            except OSError: pass


class Req7NvReservationDirectTests(unittest.TestCase):
    def setUp(self):
        enrollment_tests.Req7EnrollmentJournalDirectTests.setUp(self)
        self.enrollment = self.module; self.module = None
        self.store = self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.nv')
        read_binding = replace(self.binding, spreadsheet_id=TARGET)
        self.eth_plan = self.planner.prepare_activity_sheet_read(read_binding, self.token, sheet='ETH Cabling')
        self.ib_plan = self.planner.prepare_activity_sheet_read(read_binding, self.token, sheet='IB Cabling')
        self.eth = source('ETH Cabling', ('NV30016',))
        self.ib = source('IB Cabling', ('NV30101',))
        self.identity = self.decoder.decode_template_identity(
            self.planner.prepare_template_identity_read(read_binding, self.token),
            grids.response({**grids.identity_response(), 'spreadsheetId': TARGET}))
        self.kw = dict(generation_id='c' * 64, publish_id='d' * 64, sheet='ETH Cabling', requested_keys=KEYS)

    def initialize(self, token): return self.enrollment.prepare_enrollment_journal(token, binding(), self.identity)

    def test_original_nv_reservation_binds_an_actual_local_generation_name_without_aliasing(self):
        from monitor.issue_tracker_local_commit import create_local_commit_store, writer_owner, begin_generation
        with tempfile.TemporaryDirectory(prefix='req7-real-local-generation-') as folder:
            project = Path(folder).resolve(); publication = project / 'publication'; publication.mkdir(mode=0o700)
            create_local_commit_store(project, publication)
            with writer_owner(project, publication) as local_token:
                generation = begin_generation(local_token, b'{"schema_version":1}\n')
                name = generation.generation_id
        self.kw['generation_id'] = name
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            self.module = load()
            result = self.reserve(token)
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), result.reservations)
            self.assertEqual(name, json.loads((self.store / 'HEADER').read_bytes())['identity']['generation_id'])
            self.assertEqual(result, self.inspect(token))
            with self.assertRaises(self.module.NvReservationHold):
                self.inspect(token, generation_id=name.replace('00000000000000000001', '00000000000000000002'))

    def reserve(self, token, **changes):
        args = dict(self.kw); args.update(changes)
        return self.module.prepare_nv_reservation(token, binding(), self.identity,
            self.eth_plan, self.eth, self.ib_plan, self.ib, **args)
    def inspect(self, token, **changes):
        args = dict(self.kw); args.update(changes)
        return self.module.inspect_nv_reservation(token, binding(), self.identity, **args)

    def test_two_original_columns_closed_and_unrelated_seed_next_ids_without_rewriting_rows(self):
        self.module = load()
        before = (self.eth.data, self.ib.data)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); seen = self.reserve(token)
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), seen.reservations)
            self.assertEqual(seen, self.inspect(token))
            with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
        self.assertEqual(before, (self.eth.data, self.ib.data))
        self.assertEqual({'ETH-RAW', 'IB-RAW', 'HEADER', 'RESERVATIONS', 'INITIALIZED'}, set(os.listdir(self.store)))
        for private in ('switch-1', 'NV30102'): self.assertNotIn(private, repr(seen))
        for authority in ('permit', 'complete', 'applied', 'send_once'): self.assertFalse(hasattr(seen, authority))

    def test_both_fixed_capacity_responses_retain_full_two_mib_and_reject_overflow_before_store(self):
        self.module = load()
        eth = self.eth.data + b' ' * (2 * 1024 * 1024 - len(self.eth.data))
        ib = self.ib.data + b' ' * (2 * 1024 * 1024 - len(self.ib.data))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            self.eth = SimpleNamespace(status=200, complete=True, data=eth + b' ')
            with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
            self.assertFalse(self.store.exists())
            self.eth = SimpleNamespace(status=200, complete=True, data=eth)
            self.ib = SimpleNamespace(status=200, complete=True, data=ib)
            seen = self.reserve(token); self.assertEqual(seen, self.inspect(token))
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), seen.reservations)
        self.assertEqual(eth, (self.store / 'ETH-RAW').read_bytes()); self.assertEqual(ib, (self.store / 'IB-RAW').read_bytes())

    def test_seed_is_observed_not_hardcoded_and_cross_family_max_never_reused(self):
        self.module = load(); self.eth = source('ETH Cabling', ('NV00008',)); self.ib = source('IB Cabling', ())
        self.kw.update(sheet='IB Cabling', requested_keys=(('ib_cabling', 'switch-2', 'p1', 'Link Down'),))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); seen = self.reserve(token)
            self.assertEqual(((('ib_cabling', 'switch-2', 'p1', 'Link Down'), 'NV00009'),), seen.reservations)

    def test_unknown_global_unit_blocks_new_allocation_but_existing_reservation_survives_unchanged(self):
        self.module = load()
        from test_cases.test_req7_global_attempt_journal import load as global_load, unit
        global_journal = global_load(); value = unit()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); first = self.reserve(token)
            global_journal.prepare_global_unit(token, binding(), value)
            global_journal.record_global_attempt_intent(token, binding(), value)
            self.assertEqual(first, self.inspect(token))
            image = {p.name: p.read_bytes() for p in self.store.iterdir()}
            for changed in ({'publish_id': 'f' * 64}, {'generation_id': 'f' * 64},
                            {'sheet': 'IB Cabling', 'requested_keys': (('ib_cabling', 'other', 'p1', 'Link Down'),)}):
                with self.assertRaises(self.module.NvReservationHold): self.inspect(token, **changed)
            self.assertEqual(image, {p.name: p.read_bytes() for p in self.store.iterdir()})
        with tempfile.TemporaryDirectory(prefix='req7-nv-global-block-') as directory:
            root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'; state.mkdir(parents=True, mode=0o700)
            with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                self.initialize(token); global_journal.prepare_global_unit(token, binding(), value)
                with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
                self.assertFalse((state / self.store.name).exists())

    def test_no_enrollment_partial_reads_cross_duplicate_ids_and_exhaustion_do_not_create_store(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
            self.initialize(token)
            variants = ((source('ETH Cabling', ()), source('IB Cabling', ())),
                        (source('ETH Cabling', ('NV99999',)), self.ib),
                        (source('ETH Cabling', ('NV99998',)), self.ib),
                        (source('ETH Cabling', ('NV30101',)), self.ib),
                        (SimpleNamespace(status=200, complete=False, data=self.eth.data), self.ib))
            for eth, ib in variants:
                self.eth, self.ib = eth, ib
                with self.assertRaises(self.module.NvReservationHold) as caught: self.reserve(token)
                self.assertIsNone(caught.exception.__context__); self.assertFalse(self.store.exists())

    def test_fixed_original_targets_keys_and_unit_encoding_not_caller_sequence_or_identity_alias(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            for options in ({'generation_id': True}, {'publish_id': 'bad'}, {'sheet': 'ETH&IB Switch'},
                            {'requested_keys': ()}, {'requested_keys': (KEYS[0], KEYS[0])},
                            {'requested_keys': (('ib_cabling', 'switch-1', 'p1', 'Link Down'),)}):
                with self.assertRaises(self.module.NvReservationHold): self.reserve(token, **options)
                self.assertFalse(self.store.exists())
            old = self.eth_plan
            for plan in (self.ib_plan, replace(old, path=old.path.replace('5002', '7')),
                         replace(old, path=old.path.replace(TARGET, 'foreign_spreadsheet_0002'))):
                self.eth_plan = plan
                with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
                self.assertFalse(self.store.exists())
            self.eth_plan = old; seen = self.reserve(token)
            canonical_identity = {'schema_version': 1, 'generation_id': 'c' * 64, 'publish_id': 'd' * 64,
                'spreadsheet_id': TARGET, 'sheet': 'ETH Cabling', 'sheet_id': 102}
            raw = (json.dumps(canonical_identity, sort_keys=True, separators=(',', ':')) + '\n').encode()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), seen.unit_id)
            self.assertEqual(seen, self.inspect(token, requested_keys=tuple(reversed(KEYS))))
            self.assertNotIn(b'sentinel.private-token', (self.store / 'HEADER').read_bytes())

    def test_all_ten_image_barriers_precede_marker_partial_store_never_adopted(self):
        self.module = load(); real = os.fsync
        for boundary in range(1, 11):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(prefix='req7-nv-barrier-') as directory:
                root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'; state.mkdir(parents=True, mode=0o700)
                store = state / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.initialize(token); calls = []
                    def failing(fd):
                        if store.exists():
                            calls.append(fd)
                            if len(calls) == boundary: raise OSError('private barrier sentinel')
                        return real(fd)
                    with mock.patch('os.fsync', side_effect=failing), self.assertRaises(self.module.NvReservationHold): self.reserve(token)
                    self.assertTrue(store.is_dir()); self.assertFalse((store / 'INITIALIZED').exists())
                    with self.assertRaises(self.module.NvReservationHold): self.inspect(token)
                    with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
                    self.assertFalse((store / 'INITIALIZED').exists())

    def test_original_binding_identity_raw_and_private_names_must_still_match(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.reserve(token)
            image = {p.name: p.read_bytes() for p in self.store.iterdir()}
            for name in ('ETH-RAW', 'IB-RAW', 'HEADER', 'RESERVATIONS', 'INITIALIZED'):
                (self.store / name).write_bytes(b'private tamper')
                with self.assertRaises(self.module.NvReservationHold): self.inspect(token)
                (self.store / name).write_bytes(image[name])
            changed = replace(self.identity, sheet_ids=tuple((title, 999 if title == 'ETH Cabling' else sid) for title, sid in self.identity.sheet_ids))
            with self.assertRaises(self.module.NvReservationHold):
                self.module.inspect_nv_reservation(token, binding(), changed, **self.kw)
            (self.store / 'RESERVATIONS').chmod(0o644)
            with self.assertRaises(self.module.NvReservationHold): self.inspect(token)
            (self.store / 'RESERVATIONS').chmod(0o600)
        with fixture(self.root), self.assertRaises(self.module.NvReservationHold): self.inspect(token)

    def test_actual_compiled_insert_unit_must_use_every_original_reserved_id_and_nonce(self):
        self.module = load()
        self.assertTrue(hasattr(self.module, 'require_unit_nv_reservation'), 'durable NV-to-actual-batch binding missing')
        from monitor.issue_tracker_send_unit import freeze_send_unit
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); expected = self.reserve(token)
            args = cabling_inputs(original.nonces); unit = freeze_send_unit(**args)
            observed = self.module.require_unit_nv_reservation(token, binding(), self.identity, unit)
            self.assertEqual(expected, observed); self.assertEqual(unit.unit_id, observed.unit_id)
            for identifiers in (('NV30104', 'NV30103'), ('NV30102', 'NV30102'), ('NV30016', 'NV30103')):
                with self.assertRaises(self.module.NvReservationHold):
                    self.module.require_unit_nv_reservation(token, binding(), self.identity,
                        freeze_send_unit(**cabling_inputs(original.nonces, identifiers=identifiers)))
            for changes in ({'publish_id': 'f' * 64}, {'generation_id': 'f' * 64}, {'target_nonce': 'f' * 64},
                            {'history_nonce': 'f' * 64}, {'sheet_id': 103}, {'history_sheet_id': 104}):
                altered = dict(args); altered.update(changes)
                with self.assertRaises(self.module.NvReservationHold):
                    self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**altered))
            before = {path.name: path.read_bytes() for path in self.store.iterdir()}
            altered = dict(args); altered['business'] = args['business'][:1]
            document = json.loads(args['manifest']); document['operations'] = document['operations'][:1]
            altered['manifest'] = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode()
            altered['manifest_id'] = hashlib.sha256(altered['manifest']).hexdigest()
            with self.assertRaises(self.module.NvReservationHold):
                self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**altered))
            self.assertEqual(before, {path.name: path.read_bytes() for path in self.store.iterdir()})

    def test_each_identical_byte_replacement_during_replay_is_not_the_reserved_original(self):
        self.module = load()
        for name in ('ETH-RAW', 'IB-RAW', 'HEADER', 'RESERVATIONS', 'INITIALIZED'):
            with self.subTest(image=name), tempfile.TemporaryDirectory(prefix='req7-nv-original-') as directory:
                root = Path(directory).resolve()
                state = root / 'var/lib/http-ztp-container/issue-tracker'
                state.mkdir(parents=True, mode=0o700)
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.initialize(token); self.reserve(token)
                    store = state / self.store.name
                    path = store / name; saved = state / ('preserved-' + name)
                    raw = path.read_bytes(); inode = path.stat().st_ino
                    marker_inode = (store / 'INITIALIZED').stat().st_ino
                    real_sync = os.fsync; replaced = []
                    def substitute(fd):
                        if not replaced and os.fstat(fd).st_ino == marker_inode:
                            path.rename(saved); path.write_bytes(raw); path.chmod(0o600)
                            replaced.append(path.stat().st_ino)
                        return real_sync(fd)
                    with mock.patch('os.fsync', side_effect=substitute), self.assertRaises(self.module.NvReservationHold):
                        self.inspect(token)
                    self.assertEqual(1, len(replaced)); self.assertNotEqual(inode, replaced[0])
                    self.assertEqual(inode, saved.stat().st_ino)
                    self.assertEqual(raw, saved.read_bytes()); self.assertEqual(raw, path.read_bytes())
                    self.assertEqual(set(('ETH-RAW', 'IB-RAW', 'HEADER', 'RESERVATIONS', 'INITIALIZED')),
                                     {item.name for item in store.iterdir()})

    def test_replay_cleanup_does_not_close_its_marker_fd_recycled_to_foreign_original(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); expected = self.reserve(token)
            self.assertEqual(expected, self.inspect(token))
            marker_inode = (self.store / 'INITIALIZED').stat().st_ino
            foreign = self.state / 'foreign-owned-test-file'; foreign.write_bytes(b'foreign test original')
            foreign_inode = foreign.stat().st_ino
            real_sync = os.fsync; replaced = []
            def substitute(fd):
                if not replaced and os.fstat(fd).st_ino == marker_inode:
                    os.close(fd)
                    opened = os.open(str(foreign), os.O_RDONLY)
                    if opened != fd:
                        os.dup2(opened, fd); os.close(opened)
                    replaced.append(fd)
                return real_sync(fd)
            try:
                with mock.patch('os.fsync', side_effect=substitute), self.assertRaises(self.module.NvReservationHold):
                    self.inspect(token)
                self.assertEqual(1, len(replaced))
                try: seen = os.fstat(replaced[0])
                except OSError: self.fail('NV replay cleanup closed the recycled foreign descriptor')
                self.assertEqual(foreign_inode, seen.st_ino)
                self.assertEqual(b'foreign test original', os.pread(replaced[0], 100, 0))
                self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), expected.reservations)
            finally:
                for fd in replaced:
                    try:
                        if os.fstat(fd).st_ino == foreign_inode: os.close(fd)
                    except OSError: pass

    def test_prepare_outer_directory_recycling_holds_and_preserves_foreign_descriptor(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            with recycled_outer_nv_directory(self.module, self.store, self.state / 'foreign-prepare') as (recycled, foreign_identity):
                held = False
                try: self.reserve(token)
                except self.module.NvReservationHold: held = True
                self.assertEqual(1, len(recycled))
                try: current = os.fstat(recycled[0])
                except OSError: self.fail('prepare cleanup closed another original at its recycled outer fd')
                self.assertEqual(foreign_identity, (current.st_dev, current.st_ino))
                self.assertEqual(b'foreign outer descriptor original', os.pread(recycled[0], 100, 0))
                self.assertTrue(held, 'prepare accepted a rebound outer directory descriptor')
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), self.inspect(token).reservations)

    def test_inspect_outer_directory_recycling_holds_and_preserves_frozen_images(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); expected = self.reserve(token)
            before = {path.name: path.read_bytes() for path in self.store.iterdir()}
            with recycled_outer_nv_directory(self.module, self.store, self.state / 'foreign-inspect') as (recycled, foreign_identity):
                held = False
                try: self.inspect(token)
                except self.module.NvReservationHold: held = True
                self.assertEqual(1, len(recycled))
                try: current = os.fstat(recycled[0])
                except OSError: self.fail('inspect cleanup closed another original at its recycled outer fd')
                self.assertEqual(foreign_identity, (current.st_dev, current.st_ino))
                self.assertEqual(b'foreign outer descriptor original', os.pread(recycled[0], 100, 0))
                self.assertTrue(held, 'inspect accepted a rebound outer directory descriptor')
            self.assertEqual(before, {path.name: path.read_bytes() for path in self.store.iterdir()})
            self.assertEqual(expected, self.inspect(token))

    def test_coherent_compiler_cannot_attach_foreign_activity_key_to_reserved_literal_id(self):
        self.module = load()
        self.assertTrue(hasattr(self.module, 'require_unit_nv_reservation'), 'durable NV-to-actual-batch binding missing')
        from monitor.issue_tracker_send_unit import freeze_send_unit
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); self.reserve(token); args = cabling_inputs(original.nonces)
            args['business'][0]['values']['K'] = 'foreign-node'
            with self.assertRaises(self.module.NvReservationHold):
                self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**args))
        with fixture(self.root), self.assertRaises(self.module.NvReservationHold):
            self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**args))

    def test_mixed_literal_updates_do_not_consume_ids_or_write_existing_a_column(self):
        self.module = load()
        from monitor.issue_tracker_send_unit import freeze_send_unit
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); expected = self.reserve(token); args = cabling_inputs(original.nonces)
            document = json.loads(args['manifest'])
            document['operations'].append({'operation_id': 'eth_cabling:existing',
                'activity_key': ['eth_cabling', 'switch-1', 'swp9', 'Link Down'], 'action': 'upsert'})
            args['manifest'] = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode()
            args['manifest_id'] = hashlib.sha256(args['manifest']).hexdigest()
            update = {'operation_id': 'eth_cabling:existing', 'action': 'update', 'row_index': 3,
                'values': {'G': 'new evidence', 'M': 'a', 'N': 'b', 'S': 'c', 'T': 'd'},
                'observed_values': {column: {} for column in ('G', 'M', 'N', 'S', 'T')},
                'recorded_at_utc': '2026-10-08T10:00:00Z'}
            args['business'] += (update,); unit = freeze_send_unit(**args)
            self.assertEqual(expected, self.module.require_unit_nv_reservation(token, binding(), self.identity, unit))
            image = json.loads(unit.action_preimage)['business'][-1]['requests']
            self.assertEqual([6, 12, 18], [item['updateCells']['start']['columnIndex'] for item in image])
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), expected.reservations)


class Req7NvReservationWorkflowTests(unittest.TestCase):
    setUp = Req7NvReservationDirectTests.setUp
    initialize = Req7NvReservationDirectTests.initialize
    reserve = Req7NvReservationDirectTests.reserve
    inspect = Req7NvReservationDirectTests.inspect

    def test_original_cabling_nv_and_history_quota_chain_dominate_reserved_intent(self):
        from test_cases.test_req7_global_attempt_journal import load as global_load
        from test_cases.test_req7_history_preread_journal import load as history_load
        from test_cases.test_req7_history_read import tail_document, response
        from monitor.issue_tracker_send_unit import freeze_send_unit
        from monitor.issue_tracker_metadata_capacity import prepare_metadata_capacity_read
        global_journal = global_load(); history = history_load(); self.module = load()
        from test_cases.test_req7_metadata_reservation import load as quota_load
        quota = quota_load()  # After this fixture's canonical owner/global reload.
        for prepare_nv in (False, True):
            with self.subTest(original_nv=prepare_nv), tempfile.TemporaryDirectory(prefix='req7-reserved-cabling-') as directory:
                root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'
                state.mkdir(parents=True, mode=0o700)
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    original = self.initialize(token)
                    if prepare_nv: expected = self.reserve(token)
                    value = freeze_send_unit(**cabling_inputs(original.nonces))
                    global_journal.prepare_global_unit(token, binding(), value)
                    raw = tail_document(); raw['sheets'][0]['properties']['sheetId'] = 105
                    history.prepare_history_preread(token, binding(), value,
                        self.planner.prepare_history_tail_read(self.binding, self.token), response(raw))
                    nonces = {title: nonce for title, sid, nonce in original.nonces}
                    metadata = {'matchedDeveloperMetadata': [{'developerMetadata': {
                        'metadataId': index + 1, 'metadataKey': 'http-ztp-enrollment-v1', 'metadataValue': nonces[title],
                        'visibility': 'DOCUMENT', 'location': {'locationType': 'SHEET', 'sheetId': sid}}}
                        for index, (title, sid) in enumerate((('ETH Cabling', 102), ('Update_History', 105)))]}
                    quota.prepare_metadata_reservation(token, binding(), self.identity, value,
                        prepare_metadata_capacity_read(self.binding, self.token), response(metadata))
                    if not prepare_nv:
                        with self.assertRaises(global_journal.GlobalAttemptHold):
                            global_journal.record_reserved_attempt_intent(token, binding(), self.identity, value)
                        self.assertEqual(0, global_journal.inspect_global_unit(token, binding(), value).attempt_count)
                    else:
                        observed = global_journal.record_reserved_attempt_intent(token, binding(), self.identity, value)
                        self.assertEqual((1, 'UNKNOWN'), (observed.attempt_count, observed.outcome))
                        self.assertEqual(expected, self.module.require_unit_nv_reservation(token, binding(), self.identity, value))
                        nv_store = state / self.store.name
                        (nv_store / 'RESERVATIONS').write_bytes(b'damaged original reservation')
                        with self.assertRaises(global_journal.GlobalAttemptHold):
                            global_journal.record_reserved_attempt_intent(token, binding(), self.identity, value)
                        self.assertEqual(1, global_journal.inspect_global_unit(token, binding(), value).attempt_count)

    def test_actual_reserved_unit_global_journal_and_unknown_retry_use_identical_original_ids(self):
        from test_cases.test_req7_global_attempt_journal import load as global_load
        from monitor.issue_tracker_send_unit import freeze_send_unit
        global_journal = global_load()
        self.module = load()
        self.assertTrue(hasattr(self.module, 'require_unit_nv_reservation'), 'durable NV-to-actual-batch binding missing')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); first = self.reserve(token)
            unit = freeze_send_unit(**cabling_inputs(original.nonces))
            self.assertEqual(first, self.module.require_unit_nv_reservation(token, binding(), self.identity, unit))
            global_journal.prepare_global_unit(token, binding(), unit)
            global_journal.record_global_attempt_intent(token, binding(), unit)
            self.assertEqual(first, self.module.require_unit_nv_reservation(token, binding(), self.identity, unit))
            altered = cabling_inputs(original.nonces); altered['business'][0]['values']['G'] = 'changed frozen evidence'
            with self.assertRaises(self.module.NvReservationHold):
                self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**altered))
            self.assertEqual(1, global_journal.inspect_global_unit(token, binding(), unit).attempt_count)
            self.assertEqual(unit.wire_bytes, (self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.journal') / 'WIRE').read_bytes())

    def test_native_cold_process_redecodes_both_original_columns_and_keeps_ids_after_unknown(self):
        self.module = load()
        from test_cases.test_req7_global_attempt_journal import load as global_load, unit
        global_journal = global_load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); seen = self.reserve(token)
            value = unit(); global_journal.prepare_global_unit(token, binding(), value)
            global_journal.record_global_attempt_intent(token, binding(), value)
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--owned-inspect', str(self.root), str(ROOT)]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr); self.assertEqual(b'NV30102 NV30103\n', result.stdout)
        self.assertEqual(self.eth.data, (self.store / 'ETH-RAW').read_bytes())
        self.assertEqual(self.ib.data, (self.store / 'IB-RAW').read_bytes())

    def test_unknown_actual_unit_binding_refuses_rebound_nv_original_without_count_or_payload_change(self):
        from test_cases.test_req7_global_attempt_journal import load as global_load
        from monitor.issue_tracker_send_unit import freeze_send_unit
        global_journal = global_load(); self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); expected = self.reserve(token)
            value = freeze_send_unit(**cabling_inputs(original.nonces))
            global_journal.prepare_global_unit(token, binding(), value)
            global_journal.record_global_attempt_intent(token, binding(), value)
            self.assertEqual(expected, self.module.require_unit_nv_reservation(token, binding(), self.identity, value))
            path = self.store / 'ETH-RAW'; saved = self.state / 'preserved-original-eth'
            raw = path.read_bytes(); inode = path.stat().st_ino
            marker_inode = (self.store / 'INITIALIZED').stat().st_ino
            real_sync = os.fsync; replaced = []
            def substitute(fd):
                if not replaced and os.fstat(fd).st_ino == marker_inode:
                    path.rename(saved); path.write_bytes(raw); path.chmod(0o600)
                    replaced.append(path.stat().st_ino)
                return real_sync(fd)
            with mock.patch('os.fsync', side_effect=substitute), self.assertRaises(self.module.NvReservationHold):
                self.module.require_unit_nv_reservation(token, binding(), self.identity, value)
            self.assertEqual(1, len(replaced)); self.assertNotEqual(inode, replaced[0])
            self.assertEqual(inode, saved.stat().st_ino)
            self.assertEqual(raw, saved.read_bytes()); self.assertEqual(raw, path.read_bytes())
            seen = global_journal.inspect_global_unit(token, binding(), value)
            self.assertEqual((1, 'UNKNOWN'), (seen.attempt_count, seen.outcome))
            wire = self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.journal') / 'WIRE'
            self.assertEqual(value.wire_bytes, wire.read_bytes())
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), expected.reservations)

    def test_unknown_binding_outer_directory_recycling_preserves_foreign_fd_wire_and_count(self):
        from test_cases.test_req7_global_attempt_journal import load as global_load
        from monitor.issue_tracker_send_unit import freeze_send_unit
        global_journal = global_load(); self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); expected = self.reserve(token)
            value = freeze_send_unit(**cabling_inputs(original.nonces))
            global_journal.prepare_global_unit(token, binding(), value)
            global_journal.record_global_attempt_intent(token, binding(), value)
            before = {path.name: path.read_bytes() for path in self.store.iterdir()}
            with recycled_outer_nv_directory(self.module, self.store, self.state / 'foreign-unknown') as (recycled, foreign_identity):
                held = False
                try: self.module.require_unit_nv_reservation(token, binding(), self.identity, value)
                except self.module.NvReservationHold: held = True
                self.assertEqual(1, len(recycled))
                try: current = os.fstat(recycled[0])
                except OSError: self.fail('UNKNOWN binding cleanup closed the recycled foreign descriptor')
                self.assertEqual(foreign_identity, (current.st_dev, current.st_ino))
                self.assertEqual(b'foreign outer descriptor original', os.pread(recycled[0], 100, 0))
                self.assertTrue(held, 'UNKNOWN binding accepted a rebound outer directory descriptor')
            seen = global_journal.inspect_global_unit(token, binding(), value)
            self.assertEqual((1, 'UNKNOWN'), (seen.attempt_count, seen.outcome))
            self.assertEqual(before, {path.name: path.read_bytes() for path in self.store.iterdir()})
            wire = self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.journal') / 'WIRE'
            self.assertEqual(value.wire_bytes, wire.read_bytes())
            self.assertEqual(expected, self.module.require_unit_nv_reservation(token, binding(), self.identity, value))

    def test_manifest_real_multi_script_workflow_primary_suite_and_not_run_card(self):
        manifest = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        script = 'monitor/issue_tracker_nv_reservation.py'; test = 'test_cases.test_req7_nv_reservation'
        self.assertEqual(script, manifest['scripts'].get(script))
        self.assertTrue(any(script in item['paths'] and test in item['tests'] for item in manifest['test_rules']))
        members = {script, 'monitor/issue_tracker_online_nv_ids.py', 'monitor/issue_tracker_enrollment_journal.py',
            'monitor/issue_tracker_global_attempt_journal.py', 'monitor/issue_tracker_spreadsheet_owner.py',
            'monitor/issue_tracker_sheets_read_decode.py', 'monitor/issue_tracker_sheets_read_plan.py', 'monitor/issue_tracker_tls_inputs.py',
            'monitor/issue_tracker_send_unit.py', 'monitor/issue_tracker_send_intent.py', 'monitor/issue_tracker_online_cells.py'}
        self.assertTrue(any(members <= set(item['members']) and test in item['tests'] for item in manifest['workflows']))
        self.assertEqual(['issue-tracker-local'], [item['id'] for item in manifest['test_suites'] if test in item['tests']])
        self.assertIn(test, (ROOT / 'test_cases/README.md').read_text())
        cards = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text(); start = cards.index('## TC-REAL-REQ7-NV-RESERVATION-001')
        end = cards.find('\n## ', start + 1); card = cards[start:] if end == -1 else cards[start:end]
        for term in ('NOT RUN / REAL_ENV REQUIRED', script, '前置条件', 'stat/inode', '证据', '清理', '不是 COMPLETE'):
            self.assertIn(term, card)


class Req7CatalogNvPreparationTests(unittest.TestCase):
    """Native append/replay expectations; no source admission or online permission."""
    setUp = Req7NvReservationDirectTests.setUp
    initialize = Req7NvReservationDirectTests.initialize

    def api(self):
        # The fixture reloads the real owner registry per test. Reload the
        # canonical GLOBAL module BEFORE NV captures its owner dependency;
        # the old module is not allowed to interpret this test's opaque token.
        from test_cases.test_req7_global_attempt_journal import load as global_load
        global_load()
        self.module = load()
        for name in ('hold_catalog_nv_preparation', 'register_catalog_nv_unit', 'inspect_catalog_nv_reservation'):
            self.assertTrue(callable(getattr(self.module, name, None)), 'native multi-unit NV originals need ' + name)
        from test_cases.test_req7_unit_catalog import load as catalog_load
        self.catalog = catalog_load(reset_dependencies=False)
        return self.module

    def preparation(self, token, **changes):
        args = dict(self.kw); args.update(changes)
        return self.module.hold_catalog_nv_preparation(token, binding(), self.identity,
            self.eth_plan, self.eth, self.ib_plan, self.ib, **args)

    def compiled(self, nonces, *, generation='c' * 64, sheet='ETH Cabling', keys=KEYS, identifiers=('NV30102', 'NV30103')):
        from monitor.issue_tracker_send_unit import freeze_send_unit
        args = cabling_inputs(nonces, identifiers=identifiers)
        operations = []; business = []
        for index, (key, identifier) in enumerate(zip(keys, identifiers)):
            operation_id = key[0] + ':%04d' % index
            operations.append({'operation_id': operation_id, 'activity_key': list(key), 'action': 'upsert'})
            row = dict(args['business'][index]); row['values'] = dict(row['values'])
            row.update(operation_id=operation_id)
            row['values'].update(A=identifier, E='ETH' if sheet == 'ETH Cabling' else 'IB', F=key[3], K=key[1], L=key[2])
            business.append(row)
        manifest = (json.dumps({'schema_version': 1, 'operations': operations}, sort_keys=True, separators=(',', ':')) + '\n').encode()
        args.update(manifest=manifest, manifest_id=hashlib.sha256(manifest).hexdigest(), generation_id=generation,
                    sheet=sheet, sheet_id=102 if sheet == 'ETH Cabling' else 103, business=tuple(business),
                    target_nonce=dict((title, nonce) for title, _sid, nonce in nonces)[sheet])
        return freeze_send_unit(**args)

    def files(self):
        return {str(path.relative_to(self.state)): (path.stat().st_ino, path.read_bytes())
                for path in self.state.rglob('*') if path.is_file()}

    @contextmanager
    def native_c6_origin_fixture(self):
        module = self.api()
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        project = self.root / 'native-c6-project'; project.mkdir(mode=0o700)
        publication = project / 'publication'; publication.mkdir(mode=0o700)
        local = self.catalog.local; local.create_local_commit_store(project, publication)
        from test_cases.test_req7_spreadsheet_owner import scoped_fixture
        with local.writer_owner(project, publication) as writer, scoped_fixture(self.root, self.owner), self.owner.spreadsheet_owner(binding()) as token:
            enrolled = self.initialize(token)
            args = cabling_inputs(enrolled.nonces)
            generation = local.begin_generation(writer, args['manifest'])
            local.record_intent(writer, generation, literal_xlsx(), kind='xlsx')
            receipt = local.commit(writer, generation)
            args.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
            unit = self.catalog.composer.freeze_send_unit(**args)
            self.kw.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
            yield module, writer, token, unit

    def test_native_c6_origin_registration_appends_once_and_cold_reads_exact_originals(self):
        import inspect
        self.api()
        self.assertIn('_nv_preparation', inspect.signature(self.catalog.register_pending_c6_unit).parameters,
            'unique real C6 registration must accept the same live preparation, not require a separate append')
        marks = []; failure = None
        try:
            with self.native_c6_origin_fixture() as (module, writer, token, unit):
                actual_append = self.catalog.register_pending_unit
                def append_once(*args, **kwargs):
                    marks.append(('append', args[2].unit_id))
                    return actual_append(*args, **kwargs)
                with self.preparation(token) as prepared, mock.patch.object(self.catalog, 'register_pending_unit', side_effect=append_once):
                    self.catalog.register_pending_c6_unit(writer, token, binding(), unit, _nv_preparation=prepared)
                    marks.append(('registered', unit.unit_id))
                before = self.files()
                with self.catalog.hold_pending_project_c6_units(token, binding()) as (rows, verify):
                    self.assertEqual((unit,), tuple(row.unit for row in rows)); verify()
                self.assertEqual(prepared.observation, module.inspect_catalog_nv_reservation(token, binding(), self.identity, unit))
                self.assertEqual(before, self.files())
                marks.append(('cold', unit.unit_id))
        except Exception as exc: failure = exc
        self.assertIsNone(failure, 'native genuine C6 origin must complete, not merely outer-scope HOLD')
        self.assertEqual(['append', 'registered', 'cold'], [kind for kind, _unit in marks])

    def test_native_c6_origin_lost_all_is_not_a_low_level_catalog_without_origin(self):
        marks = []; failure = None
        try:
            with self.native_c6_origin_fixture() as (module, writer, token, unit):
                with self.preparation(token) as prepared:
                    self.catalog.register_pending_c6_unit(writer, token, binding(), unit, _nv_preparation=prepared)
                origin = self.state / (hashlib.sha256(TARGET.encode()).hexdigest()+'.unit-'+unit.unit_id+'.project-origin')
                origin.rename(self.root / 'preserved-original-native-c6-origin'); marks.append('lost-all')
                before = self.files(); yielded = []
                with self.assertRaises(self.catalog.UnitCatalogHold):
                    with self.catalog.hold_pending_units(token, binding()) as values: yielded.append(values)
                self.assertEqual([], yielded)
                with self.assertRaises(module.NvReservationHold):
                    module.inspect_catalog_nv_reservation(token, binding(), self.identity, unit)
                self.assertEqual(before, self.files()); marks.append('cold-HOLD')
        except Exception as exc: failure = exc
        self.assertIsNone(failure)
        self.assertEqual(['lost-all', 'cold-HOLD'], marks)

    def test_native_c6_origin_complete_before_failed_append_stays_sticky_hold_when_caught(self):
        marks = []; caught = None
        with self.native_c6_origin_fixture() as (_module, writer, token, unit):
            origin = self.state / (hashlib.sha256(TARGET.encode()).hexdigest()+'.unit-'+unit.unit_id+'.project-origin')
            def failed_append(*args, **kwargs):
                self.assertEqual(unit, args[2])
                self.assertEqual({'WITNESS', 'STARTED', 'ORIGIN'}, set(os.listdir(origin)))
                marks.append('original-origin-complete-before-append')
                raise OSError('owned catalog append boundary interruption')
            try:
                with self.preparation(token) as prepared, mock.patch.object(self.catalog, 'register_pending_unit', side_effect=failed_append):
                    with self.assertRaises(self.catalog.UnitCatalogHold):
                        self.catalog.register_pending_c6_unit(writer, token, binding(), unit, _nv_preparation=prepared)
                    marks.append('caller-caught-registration-HOLD')
                    self.assertFalse(any(path.name.endswith('.units') for path in self.state.iterdir()))
            except Exception as exc: caught = exc
            self.assertIs(type(caught), self.module.NvReservationHold)
            self.assertEqual(['original-origin-complete-before-append', 'caller-caught-registration-HOLD'], marks)
            before = self.files()
            with self.assertRaises(self.module.NvReservationHold):
                with self.preparation(token): self.fail('partial/unindexed origin became NEW preparation')
            self.assertEqual(before, self.files())

    def test_native_c6_origin_same_bytes_replacement_after_registration_revokes_scope_and_cold_reader(self):
        marks = []; caught = None
        with self.native_c6_origin_fixture() as (module, writer, token, unit):
            try:
                with self.preparation(token) as prepared:
                    self.catalog.register_pending_c6_unit(writer, token, binding(), unit, _nv_preparation=prepared)
                    origin = self.state / (hashlib.sha256(TARGET.encode()).hexdigest()+'.unit-'+unit.unit_id+'.project-origin')
                    path = origin / 'ORIGIN'; raw = path.read_bytes(); old = path.stat().st_ino
                    preserved = self.root / 'preserved-real-origin-file'; path.rename(preserved)
                    path.write_bytes(raw); path.chmod(0o600)
                    self.assertNotEqual(old, path.stat().st_ino); marks.append('registered-origin-injected')
            except Exception as exc: caught = exc
            self.assertIs(type(caught), module.NvReservationHold)
            self.assertEqual(['registered-origin-injected'], marks)
            self.assertEqual(raw, path.read_bytes()); self.assertEqual(raw, preserved.read_bytes())
            before = self.files(); yielded = []
            with self.assertRaises(self.catalog.UnitCatalogHold):
                with self.catalog.hold_pending_units(token, binding()) as values: yielded.append(values)
            self.assertEqual([], yielded); self.assertEqual(before, self.files())

    def test_two_native_c6_origins_keep_all_old_originals_and_allocate_new_generation_once(self):
        with self.native_c6_origin_fixture() as (module, writer, token, first):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer, token, binding(), first, _nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token, binding(), first)
            old = self.files()
            enrolled = self.enrollment.inspect_enrollment_journal(token, binding(), self.identity)
            args = cabling_inputs(enrolled.nonces, identifiers=('NV30104', 'NV30105'))
            local = self.catalog.local
            from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
            generation = local.begin_generation(writer, args['manifest'])
            local.record_intent(writer, generation, literal_xlsx(), kind='xlsx')
            receipt = local.commit(writer, generation)
            args.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
            second = self.catalog.composer.freeze_send_unit(**args)
            appended = []; actual_append = self.catalog.register_pending_unit
            def append_once(*arguments, **keywords):
                appended.append(arguments[2].unit_id)
                return actual_append(*arguments, **keywords)
            with self.preparation(token, generation_id=generation.generation_id, publish_id=receipt.published_sha256) as prepared, \
                    mock.patch.object(self.catalog, 'register_pending_unit', side_effect=append_once):
                self.assertEqual(((KEYS[0], 'NV30104'), (KEYS[1], 'NV30105')), prepared.observation.reservations)
                self.catalog.register_pending_c6_unit(writer, token, binding(), second, _nv_preparation=prepared)
            self.assertEqual([second.unit_id], appended)
            with self.catalog.hold_pending_project_c6_units(token, binding()) as (rows, verify):
                self.assertEqual((first, second), tuple(row.unit for row in rows)); verify()
            self.assertEqual(old, {name: self.files()[name] for name in old})

    def _exercise_native_c6_origin_first_stat_cleanup(self, recycle):
        marks = []; created = []; foreign_fd = None; error = None
        try:
            with self.native_c6_origin_fixture() as (module, writer, token, unit):
                real_create = module.global_journal._create_folder; real_fstat = os.fstat
                if recycle:
                    foreign = self.root / 'foreign-c6-origin-cleanup'; foreign.write_bytes(b'foreign original must survive')
                    foreign_fd = os.open(str(foreign), os.O_RDONLY)
                def create_origin(*args, **kwargs):
                    result = real_create(*args, **kwargs)
                    if args[1].endswith('.project-origin'):
                        fd = result[0] if isinstance(result, tuple) else result
                        created.append((fd, real_fstat(fd)))
                    return result
                def first_stat(fd):
                    if created and fd == created[0][0] and not marks:
                        if recycle:
                            os.close(fd); os.dup2(foreign_fd, fd)
                        marks.append('first-stat-injected')
                        raise OSError('owned first creator fstat fault')
                    return real_fstat(fd)
                try:
                    with self.preparation(token) as prepared, \
                            mock.patch.object(module.global_journal, '_create_folder', side_effect=create_origin), \
                            mock.patch('os.fstat', side_effect=first_stat):
                        with self.assertRaises(self.catalog.UnitCatalogHold):
                            self.catalog.register_pending_c6_unit(writer, token, binding(), unit, _nv_preparation=prepared)
                        marks.append('registration-HOLD')
                except Exception as exc: error = exc
                self.assertIs(type(error), module.NvReservationHold)
                self.assertEqual(['first-stat-injected', 'registration-HOLD'], marks)
                self.assertEqual(1, len(created))
                fd, original = created[0]
                if recycle:
                    current = real_fstat(fd); external = real_fstat(foreign_fd)
                    self.assertEqual((external.st_dev, external.st_ino), (current.st_dev, current.st_ino))
                    self.assertEqual(b'foreign original must survive', os.pread(fd, 128, 0))
                else:
                    with self.assertRaises(OSError, msg='actual first-stat fault leaked owned original creator FD'):
                        real_fstat(fd)
                self.assertFalse(any(path.name.endswith('.units') for path in self.state.iterdir()))
        finally:
            # Clean only this fixture's exact leaked/recycled objects, even on
            # initial RED. Do not turn cleanup into a production PASS claim.
            for fd, original in created:
                try:
                    current = os.fstat(fd)
                    owned = (original.st_dev, original.st_ino)
                    if foreign_fd is not None:
                        external = os.fstat(foreign_fd); owned = (external.st_dev, external.st_ino)
                    if (current.st_dev, current.st_ino) == owned: os.close(fd)
                except OSError: pass
            if foreign_fd is not None: os.close(foreign_fd)

    def test_native_c6_origin_first_stat_failure_closes_only_owned_creator(self):
        self._exercise_native_c6_origin_first_stat_cleanup(False)

    def test_native_c6_origin_first_stat_failure_preserves_recycled_foreign_creator(self):
        self._exercise_native_c6_origin_first_stat_cleanup(True)

    def test_native_catalog_retained_inventory_reads_all_six_nv_originals_and_witness_without_authority(self):
        from test_cases.test_req7_retained_global_inventory import load as inventory_load
        with self.native_c6_origin_fixture() as (module, writer, token, unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer, token, binding(), unit, _nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token, binding(), unit)
            inventory = inventory_load(reset_support=False); before = self.files()
            with inventory._hold_catalog_retained_inventory(token, binding()) as (rows, verify):
                self.assertEqual((unit,), tuple(row.unit for row in rows))
                self.assertEqual((0,), tuple(row.attempt_count for row in rows))
                self.assertEqual({'enrollment', 'journal', 'journal-started', 'nv', 'nv-started', 'project-origin'},
                    set(rows[0].families))
                prefix = hashlib.sha256(TARGET.encode()).hexdigest() + '.unit-' + unit.unit_id
                original_names = {name for name, _stat, _sha in rows[0].originals}
                self.assertEqual({'ETH-RAW', 'IB-RAW', 'PRIOR', 'HEADER', 'RESERVATIONS', 'INITIALIZED'},
                    {name.split('/')[-1] for name in original_names if name.startswith(prefix + '.nv/')})
                self.assertIn(prefix + '.nv-started', original_names)
                self.assertFalse(any(hasattr(rows[0], name) for name in ('permit', 'applied', 'fresh', 'new')))
                verify()
            self.assertEqual(before, self.files())

    def test_native_catalog_retained_inventory_prior_same_bytes_rebind_revokes_actual_consumer(self):
        from test_cases.test_req7_retained_global_inventory import load as inventory_load
        marks = []; error = None
        with self.native_c6_origin_fixture() as (module, writer, token, unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer, token, binding(), unit, _nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token, binding(), unit)
            inventory = inventory_load(reset_support=False)
            prefix = hashlib.sha256(TARGET.encode()).hexdigest() + '.unit-' + unit.unit_id
            path = self.state / (prefix + '.nv') / 'PRIOR'; saved = self.root / 'retained-prior-original'
            raw = path.read_bytes(); inode = path.stat().st_ino
            try:
                with inventory._hold_catalog_retained_inventory(token, binding()) as (rows, verify):
                    marks.append('actual-inventory-yield')
                    path.rename(saved); path.write_bytes(raw); path.chmod(0o600)
                    marks.append('same-bytes-rebound'); verify(); marks.append('unsafe-verification')
            except Exception as exc: error = exc
            self.assertEqual(['actual-inventory-yield', 'same-bytes-rebound'], marks)
            self.assertIs(type(error), inventory.RetainedInventoryHold)
            self.assertNotEqual(inode, path.stat().st_ino)
            self.assertEqual(inode, saved.stat().st_ino); self.assertEqual(raw, path.read_bytes())
            self.assertEqual((0, 'UNATTEMPTED_OBSERVATION'),
                (lambda row: (row.attempt_count, row.outcome))(
                    module.global_journal.inspect_catalog_global_units(token, binding())[0][1]))

    def test_native_first_append_requires_live_owned_preparation_and_replays_after_scope(self):
        module = self.api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); value = self.compiled(enrollment.nonces)
            with self.preparation(token) as prepared:
                self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), prepared.observation.reservations)
                before = self.files()
                with self.assertRaises(self.catalog.UnitCatalogHold): self.catalog.register_pending_unit(token, binding(), value)
                self.assertEqual(before, self.files())
                module.register_catalog_nv_unit(prepared, value)
            before = self.files()
            seen = module.inspect_catalog_nv_reservation(token, binding(), self.identity, value)
            self.assertEqual(prepared.observation, seen)
            self.assertEqual(seen, module.require_unit_nv_reservation(token, binding(), self.identity, value))
            with self.assertRaises(module.NvReservationHold): module.register_catalog_nv_unit(prepared, value)
            self.assertEqual(before, self.files())
            with self.catalog.hold_pending_units(token, binding()) as (units, verify):
                self.assertEqual((value,), units); verify()

    def test_native_source_observation_and_compiled_handoff_bind_live_owner_and_exact_identity(self):
        module = self.api()
        for name in ('_catalog_nv_source_observation', '_catalog_nv_compiled_observation'):
            self.assertTrue(callable(getattr(module, name, None)), 'actual compiler needs ' + name)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrolled = self.initialize(token); unit = self.compiled(enrolled.nonces)
            with self.preparation(token) as prepared:
                args = dict(self.kw)
                before = self.files()
                self.assertEqual(prepared.observation, module._catalog_nv_source_observation(
                    prepared, token, binding(), self.identity, **args))
                for changes in ({'generation_id': 'e'*64}, {'publish_id': 'e'*64},
                                {'sheet': 'IB Cabling'}, {'requested_keys': KEYS[:1]}):
                    with self.subTest(changes=changes):
                        with self.assertRaises(module.NvReservationHold):
                            module._catalog_nv_source_observation(prepared, token, binding(), self.identity,
                                **{**args, **changes})
                with self.assertRaises(module.NvReservationHold):
                    module._catalog_nv_source_observation(replace(prepared), token, binding(), self.identity, **args)
                self.assertEqual(prepared.observation, module._catalog_nv_compiled_observation(prepared, token, binding(), unit))
                for bad in (self.compiled(enrolled.nonces, generation='e'*64),
                            self.compiled(enrolled.nonces, identifiers=('NV99998', 'NV99999'))):
                    with self.assertRaises(module.NvReservationHold):
                        module._catalog_nv_compiled_observation(prepared, token, binding(), bad)
                self.assertEqual(before, self.files(), 'compiler observation never appends or issues authority')
                module.register_catalog_nv_unit(prepared, unit)
            with self.assertRaises(module.NvReservationHold):
                module._catalog_nv_compiled_observation(prepared, token, binding(), unit)

    def test_native_cross_family_and_same_key_new_generation_allocate_above_all_old_originals(self):
        module = self.api()
        from test_cases.test_req7_global_attempt_journal import load as global_load
        globals_ = global_load()
        ib_keys = (('ib_cabling', 'switch-2', 'p1', 'Link Down'),)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token)
            first = self.compiled(enrollment.nonces)
            with self.preparation(token) as prepared: module.register_catalog_nv_unit(prepared, first)
            globals_.prepare_global_unit(token, binding(), first)
            old = self.files()
            second = self.compiled(enrollment.nonces, generation='e' * 64, sheet='IB Cabling', keys=ib_keys, identifiers=('NV30104',))
            with self.preparation(token, generation_id='e' * 64, sheet='IB Cabling', requested_keys=ib_keys) as prepared:
                self.assertEqual(((ib_keys[0], 'NV30104'),), prepared.observation.reservations)
                module.register_catalog_nv_unit(prepared, second)
            globals_.prepare_global_unit(token, binding(), second)
            third = self.compiled(enrollment.nonces, generation='f' * 64, identifiers=('NV30105', 'NV30106'))
            with self.preparation(token, generation_id='f' * 64) as prepared:
                self.assertEqual(((KEYS[0], 'NV30105'), (KEYS[1], 'NV30106')), prepared.observation.reservations)
                module.register_catalog_nv_unit(prepared, third)
            self.assertTrue(old.items() <= self.files().items(), 'every prior file/inode must survive appends')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            for unit, expected in ((first, ('NV30102', 'NV30103')), (second, ('NV30104',)), (third, ('NV30105', 'NV30106'))):
                self.assertEqual(expected, tuple(identifier for _key, identifier in module.inspect_catalog_nv_reservation(token, binding(), self.identity, unit).reservations))
            prior = self.state / (self.store.name[:-3] + '.unit-' + third.unit_id + '.nv/PRIOR')
            saved = json.loads(prior.read_bytes())
            self.assertEqual([first.unit_id, second.unit_id], [row['unit_id'] for row in saved])
            self.assertEqual(['NV30102', 'NV30103', 'NV30104'], [pair[1] for row in saved for pair in row['reservations']])

    def test_partial_preparation_survives_as_hold_never_catalog_first_use_or_adoption(self):
        module = self.api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); value = self.compiled(enrollment.nonces)
            with self.assertRaises(module.NvReservationHold):
                with self.preparation(token): pass
            before = self.files()
            self.assertTrue(any(path.endswith('.nv-started') for path in before))
            self.assertFalse(any('.units/' in path for path in before))
            reached = []
            with self.assertRaises(module.NvReservationHold):
                with self.preparation(token): reached.append('adopted')
            self.assertEqual([], reached)
            with self.assertRaises(self.catalog.UnitCatalogHold): self.catalog.register_pending_unit(token, binding(), value)
            self.assertEqual(before, self.files())

    def test_every_native_write_boundary_retains_hold_without_resetting_old_namespace(self):
        module = self.api(); real_write = module._write_catalog_image
        for failure in range(1, 8):
            with self.subTest(boundary=failure), tempfile.TemporaryDirectory(prefix='req7-native-nv-interruption-') as directory:
                root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'
                state.mkdir(parents=True, mode=0o700); calls = []; reached = []; injected = []
                def failing(parent, name, raw, *args, **kwargs):
                    calls.append(name)
                    # These seven assertions cover actual committed file
                    # writes, including both RAW writers, not pre-rename IO.
                    result = real_write(parent, name, raw, *args, **kwargs)
                    if len(calls) == failure:
                        injected.append(name); raise OSError('owned NV boundary interruption')
                    return result
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.initialize(token)
                    with mock.patch.object(module, '_write_catalog_image', side_effect=failing), self.assertRaises(module.NvReservationHold):
                        with self.preparation(token): reached.append('yield')
                    self.assertEqual(failure, len(calls)); self.assertEqual([calls[-1]], injected)
                    self.assertEqual([], reached)
                    expected = ['ETH-RAW', 'IB-RAW', 'PRIOR', 'HEADER', 'RESERVATIONS', 'INITIALIZED']
                    self.assertTrue(calls[0].endswith('.nv-started'))
                    self.assertEqual(expected[:failure - 1], calls[1:])
                    before = {str(path.relative_to(state)): path.read_bytes() for path in state.rglob('*') if path.is_file()}
                    self.assertTrue(any(name.endswith('.nv-started') for name in before))
                    with self.assertRaises(module.NvReservationHold):
                        with self.preparation(token): reached.append('repaired')
                    self.assertEqual([], reached)
                    self.assertEqual(before, {str(path.relative_to(state)): path.read_bytes() for path in state.rglob('*') if path.is_file()})

    def test_foreign_same_byte_old_lineage_replacement_before_append_holds_entire_scope(self):
        module = self.api()
        from test_cases.test_req7_global_attempt_journal import load as global_load
        globals_ = global_load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); first = self.compiled(enrollment.nonces)
            with self.preparation(token) as prepared: module.register_catalog_nv_unit(prepared, first)
            globals_.prepare_global_unit(token, binding(), first)
            prior = self.state / (self.store.name[:-3] + '.unit-' + first.unit_id + '.nv/RESERVATIONS')
            second = self.compiled(enrollment.nonces, generation='e' * 64, identifiers=('NV30104', 'NV30105'))
            with self.assertRaises(module.NvReservationHold):
                with self.preparation(token, generation_id='e' * 64) as prepared:
                    original = prior.read_bytes(); prior.rename(self.root / 'held-old-nv-original')
                    prior.write_bytes(original); prior.chmod(0o600)
                    module.register_catalog_nv_unit(prepared, second)
            with self.catalog.hold_pending_units(token, binding()) as (units, verify):
                self.assertEqual((first,), units); verify()

    def test_scope_keeps_its_new_catalog_originals_pinned_after_registration_until_exit(self):
        module = self.api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); value = self.compiled(enrollment.nonces)
            with self.assertRaises(module.NvReservationHold):
                with self.preparation(token) as prepared:
                    module.register_catalog_nv_unit(prepared, value)
                    path = self.state / (self.store.name[:-3] + '.units') / value.unit_id / 'WIRE'
                    original = path.read_bytes(); path.rename(self.root / 'held-owned-catalog-wire')
                    path.write_bytes(original); path.chmod(0o600)
            self.assertEqual(original, path.read_bytes())
            self.assertEqual(original, (self.root / 'held-owned-catalog-wire').read_bytes())

    def test_unissued_copied_preparation_and_wrong_literal_id_cannot_create_catalog(self):
        module = self.api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); value = self.compiled(enrollment.nonces)
            bad = self.compiled(enrollment.nonces, identifiers=('NV30103', 'NV30102'))
            with self.preparation(token) as prepared:
                before = self.files()
                for copy in (object(), replace(prepared)):
                    with self.assertRaises(module.NvReservationHold): module.register_catalog_nv_unit(copy, value)
                with self.assertRaises(module.NvReservationHold): module.register_catalog_nv_unit(prepared, bad)
                self.assertEqual(before, self.files())
                module.register_catalog_nv_unit(prepared, value)

    def test_new_directory_recycled_at_fsync_never_receives_raw_or_owned_cleanup(self):
        module = self.api(); real_sync = os.fsync; changed = []; reached = []
        foreign = self.root / 'foreign-directory'; foreign.mkdir(mode=0o700)
        foreign_identity = (foreign.stat().st_dev, foreign.stat().st_ino)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            def recycle(fd):
                info = os.fstat(fd)
                names = [path for path in self.state.iterdir() if path.name.endswith('.nv')]
                if names and not changed and info.st_ino == names[0].stat().st_ino:
                    os.close(fd); other = os.open(str(foreign), os.O_RDONLY | os.O_DIRECTORY)
                    if other != fd: os.dup2(other, fd); os.close(other)
                    changed.append(fd)
                return real_sync(fd)
            try:
                with mock.patch('os.fsync', side_effect=recycle), self.assertRaises(module.NvReservationHold):
                    with self.preparation(token): reached.append('yield')
                self.assertEqual(1, len(changed)); self.assertEqual([], reached)
                current = os.fstat(changed[0])
                self.assertEqual(foreign_identity, (current.st_dev, current.st_ino))
                self.assertEqual([], list(foreign.iterdir()), 'no actual RAW/header write may target foreign FD')
            finally:
                for fd in changed:
                    try:
                        current = os.fstat(fd)
                        if foreign_identity == (current.st_dev, current.st_ino): os.close(fd)
                    except OSError: pass

    def test_fixed_shared_original_budget_charges_unique_images_before_pread(self):
        self.api(); budget_type = getattr(self.catalog, '_OriginalImageBudget', None)
        self.assertTrue(callable(budget_type), 'one fixed image budget must span old/current/indexed readers')
        budget = budget_type(); readers = []; directory = self.root / 'budget'; directory.mkdir(mode=0o700)
        parent = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY)
        try:
            for index in range(8):
                path = directory / str(index); path.write_bytes(b'x' * (2 * 1024 * 1024)); path.chmod(0o600)
            extra = directory / 'extra'; extra.write_bytes(b'x'); extra.chmod(0o600)
            for iteration in range(3):
                held = self.catalog._Originals(_image_budget=budget); readers.append(held)
                for index in range(8):
                    raw, _identity = held.file(parent, str(index), 2 * 1024 * 1024)
                    self.assertEqual(2 * 1024 * 1024, len(raw))
                held.verify()
            self.assertEqual(16 * 1024 * 1024, budget.bytes)
            real_pread = os.pread; seen = []
            def reading(fd, *args):
                if os.fstat(fd).st_ino == extra.stat().st_ino: seen.append('extra')
                return real_pread(fd, *args)
            with mock.patch('os.pread', side_effect=reading), self.assertRaises(self.catalog.UnitCatalogHold):
                readers[-1].file(parent, 'extra', 1)
            self.assertEqual([], seen, 'aggregate bound must precede reading the extra image')
        finally:
            for held in readers: held.close()
            os.close(parent)

    def test_recycled_directory_after_eth_commit_never_receives_ib_sibling(self):
        module = self.api(); real_raw = module._write_catalog_image; recycled = []; writes = []; reached = []
        foreign = self.root / 'foreign-after-eth'; foreign.mkdir(mode=0o700)
        foreign_identity = (foreign.stat().st_dev, foreign.stat().st_ino)
        def write_then_recycle(parent, name, raw, *args, **kwargs):
            if name in ('ETH-RAW', 'IB-RAW'): writes.append(name)
            result = real_raw(parent, name, raw, *args, **kwargs)
            if name == 'ETH-RAW':
                os.close(parent); other = os.open(str(foreign), os.O_RDONLY | os.O_DIRECTORY)
                if other != parent: os.dup2(other, parent); os.close(other)
                recycled.append(parent)
            return result
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            try:
                with mock.patch.object(module, '_write_catalog_image', side_effect=write_then_recycle), self.assertRaises(module.NvReservationHold):
                    with self.preparation(token): reached.append('yield')
                self.assertEqual(['ETH-RAW'], writes); self.assertEqual([], reached); self.assertEqual(1, len(recycled))
                info = os.fstat(recycled[0]); self.assertEqual(foreign_identity, (info.st_dev, info.st_ino))
                self.assertEqual([], list(foreign.iterdir()))
            finally:
                for fd in recycled:
                    try:
                        info = os.fstat(fd)
                        if foreign_identity == (info.st_dev, info.st_ino): os.close(fd)
                    except OSError: pass

    def test_shared_budget_never_caches_same_inode_drift_or_recovers_after_failure(self):
        self.api(); budget = self.catalog._OriginalImageBudget()
        path = self.root / 'original-budget-image'; path.write_bytes(b'original'); path.chmod(0o600)
        parent = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        old = self.catalog._Originals(_image_budget=budget); current = self.catalog._Originals(_image_budget=budget)
        try:
            raw, identity = old.file(parent, path.name, 8); self.assertEqual(b'original', raw)
            path.write_bytes(b'drifted!')
            self.assertEqual(identity[:2], (path.stat().st_dev, path.stat().st_ino))
            with self.assertRaises(self.catalog.UnitCatalogHold): current.file(parent, path.name, 8)
            self.assertTrue(budget.failed)
            with self.assertRaises(self.catalog.UnitCatalogHold): old.verify()
            self.assertEqual(b'drifted!', path.read_bytes())
        finally:
            current.close(); old.close(); os.close(parent)

    def test_actual_eth_publish_same_byte_replacement_blocks_next_sibling_and_handoff(self):
        module = self.api(); real_sync = os.fsync; injected = []; reached = []; acknowledged = []
        kept = self.root / 'original-eth-written-file'
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); unit = self.compiled(enrollment.nonces)
            def replace_at_directory_barrier(fd):
                result = real_sync(fd)
                paths = list(self.state.glob('*.nv/ETH-RAW'))
                if paths and not injected and os.fstat(fd).st_ino == paths[0].parent.stat().st_ino:
                    path = paths[0]; raw = path.read_bytes(); path.rename(kept)
                    path.write_bytes(raw); path.chmod(0o600); injected.append(path)
                return result
            with mock.patch('os.fsync', side_effect=replace_at_directory_barrier), self.assertRaises(module.NvReservationHold):
                with self.preparation(token) as prepared:
                    reached.append('yield'); module.register_catalog_nv_unit(prepared, unit); acknowledged.append('ack')
            self.assertEqual(1, len(injected)); self.assertEqual([], reached); self.assertEqual([], acknowledged)
            self.assertFalse((injected[0].parent / 'IB-RAW').exists())
            self.assertEqual(kept.read_bytes(), injected[0].read_bytes())
            self.assertNotEqual(kept.stat().st_ino, injected[0].stat().st_ino)

    def test_cold_native_lineage_requires_each_first_written_file_identity(self):
        module = self.api()
        for entry in ('ETH-RAW', 'IB-RAW', 'PRIOR', 'HEADER', 'RESERVATIONS', 'INITIALIZED'):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory(prefix='req7-native-cold-identity-') as directory:
                root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'
                state.mkdir(parents=True, mode=0o700)
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    enrollment = self.initialize(token); unit = self.compiled(enrollment.nonces)
                    with self.preparation(token) as prepared: module.register_catalog_nv_unit(prepared, unit)
                    path = state / (self.store.name[:-3] + '.unit-' + unit.unit_id + '.nv') / entry
                    raw = path.read_bytes(); kept = root / ('first-written-' + entry)
                    path.rename(kept); path.write_bytes(raw); path.chmod(0o600)
                    before = {str(item.relative_to(root)): (item.stat().st_ino, item.read_bytes())
                              for item in root.rglob('*') if item.is_file()}
                    with self.assertRaises(module.NvReservationHold):
                        module.inspect_catalog_nv_reservation(token, binding(), self.identity, unit)
                    self.assertEqual(before, {str(item.relative_to(root)): (item.stat().st_ino, item.read_bytes())
                                             for item in root.rglob('*') if item.is_file()})

    def test_creator_parent_directory_stays_owned_without_fd_number_reuse(self):
        module = self.api(); create = module.global_journal._create_folder; read = module._native_original
        created = []; blockers = []; alive = []; reached = []; acknowledged = []
        blocker = self.root / 'unrelated-owned-fd'; blocker.write_bytes(b'unrelated')
        def creating(parent, name):
            fd = create(parent, name); created.append(fd); return fd
        def inspecting(*args, **kwargs):
            try: alive.append(os.fstat(created[-1]).st_ino == (self.state / args[1]).stat().st_ino)
            except OSError: alive.append(False)
            blockers.append(os.open(str(blocker), os.O_RDONLY))
            return read(*args, **kwargs)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); unit = self.compiled(enrollment.nonces)
            try:
                with mock.patch.object(module.global_journal, '_create_folder', side_effect=creating), mock.patch.object(module, '_native_original', side_effect=inspecting):
                    with self.preparation(token) as prepared:
                        reached.append('yield'); module.register_catalog_nv_unit(prepared, unit); acknowledged.append('ack')
                self.assertEqual([True], alive, 'creator directory must remain open before reader acquisition')
                self.assertEqual(['yield'], reached); self.assertEqual(['ack'], acknowledged)
                self.assertNotEqual(created[0], blockers[0], 'success cannot depend on reusing a closed parent integer')
                self.assertEqual(b'unrelated', os.pread(blockers[0], 9, 0))
            finally:
                for fd in blockers: os.close(fd)

    def test_catalog_reader_rejects_witness_only_native_family_without_marker_anchor(self):
        self.api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); unit = self.compiled(enrollment.nonces)
            self.catalog.register_pending_unit(token, binding(), unit)
            with self.catalog.hold_pending_units(token, binding()) as (units, verify):
                self.assertEqual((unit,), units); verify()
            witness = self.state / (self.store.name[:-3] + '.unit-' + unit.unit_id + '.nv-started')
            witness.write_bytes(b'unanchored native write was started\n'); witness.chmod(0o600)
            before = self.files(); reached = []
            with self.assertRaises(self.catalog.UnitCatalogHold):
                with self.catalog.hold_pending_units(token, binding()) as (units, verify):
                    reached.append(units); verify()
            self.assertEqual([], reached); self.assertEqual(before, self.files())

    def test_cold_marker_same_inode_rewrite_cannot_reanchor_original_images(self):
        module = self.api()
        for replace_raw in (False, True):
            with self.subTest(replace_raw=replace_raw), tempfile.TemporaryDirectory(prefix='req7-native-marker-anchor-') as directory:
                root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'
                state.mkdir(parents=True, mode=0o700)
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    enrollment = self.initialize(token); unit = self.compiled(enrollment.nonces)
                    with self.preparation(token) as prepared: module.register_catalog_nv_unit(prepared, unit)
                    folder = state / (self.store.name[:-3] + '.unit-' + unit.unit_id + '.nv')
                    marker = folder / 'INITIALIZED'; original = marker.stat(); raw = marker.read_bytes()
                    if replace_raw:
                        path = folder / 'ETH-RAW'; payload = path.read_bytes(); path.rename(root / 'first-eth')
                        path.write_bytes(payload); path.chmod(0o600); info = path.stat()
                        changed = json.loads(raw)
                        changed['originals']['ETH-RAW']['identity'] = [info.st_dev, info.st_ino, info.st_mode,
                            info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
                        raw = (json.dumps(changed, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    with marker.open('r+b') as stream:
                        stream.write(raw); stream.truncate()
                    os.utime(marker, ns=(original.st_atime_ns, original.st_mtime_ns + 1000000))
                    self.assertEqual(original.st_ino, marker.stat().st_ino)
                    self.assertNotEqual(original.st_mtime_ns, marker.stat().st_mtime_ns)
                    before = {str(item.relative_to(root)): (item.stat().st_ino, item.read_bytes())
                              for item in root.rglob('*') if item.is_file()}
                    with self.assertRaises(module.NvReservationHold):
                        module.inspect_catalog_nv_reservation(token, binding(), self.identity, unit)
                    self.assertEqual(before, {str(item.relative_to(root)): (item.stat().st_ino, item.read_bytes())
                                             for item in root.rglob('*') if item.is_file()})


class Req7CatalogNvGlobalWorkflowTests(unittest.TestCase):
    setUp = Req7CatalogNvPreparationTests.setUp
    initialize = Req7CatalogNvPreparationTests.initialize
    api = Req7CatalogNvPreparationTests.api
    preparation = Req7CatalogNvPreparationTests.preparation
    compiled = Req7CatalogNvPreparationTests.compiled
    files = Req7CatalogNvPreparationTests.files

    def test_actual_old_new_and_indexed_readers_share_one_fixed_unique_budget(self):
        module = self.api()
        from test_cases.test_req7_global_attempt_journal import load as global_load
        globals_ = global_load(); units = []; reached = []; acknowledgements = []
        # Original full JSON body plus whitespace: real decoder and real raw
        # file writer, not a forged size/stat or caller-adjustable budget.
        for name in ('eth', 'ib'):
            original = getattr(self, name).data
            setattr(self, name, SimpleNamespace(status=200, complete=True,
                data=original + b' ' * (2 * 1024 * 1024 - len(original))))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token)
            for index, generation in enumerate(('c', 'e', 'f')):
                identifiers = ('NV%d' % (30102 + 2 * index), 'NV%d' % (30103 + 2 * index))
                unit = self.compiled(enrollment.nonces, generation=generation * 64, identifiers=identifiers)
                with self.preparation(token, generation_id=generation * 64) as prepared:
                    module.register_catalog_nv_unit(prepared, unit); acknowledgements.append(unit.unit_id)
                    record = module._ACTIVE_CATALOG_PREPARATIONS[prepared]
                    self.assertIs(record['old']._image_budget, record['current']._image_budget)
                    self.assertIs(record['old']._image_budget, record['indexed']._image_budget)
                    with self.catalog.hold_pending_units(token, binding()) as (held, verify):
                        self.assertEqual(tuple(units) + (unit,), held); verify()
                globals_.prepare_global_unit(token, binding(), unit); units.append(unit)
            before = self.files()
            with self.assertRaises(module.NvReservationHold):
                with self.preparation(token, generation_id='a' * 64): reached.append('yield')
            self.assertEqual([], reached); self.assertEqual(3, len(acknowledgements))
            self.assertTrue(before.items() <= self.files().items(), 'all old originals survive budget HOLD')
            with self.catalog.hold_pending_units(token, binding()) as (held, verify):
                self.assertEqual(tuple(units), held); verify()

    def test_real_catalog_global_unknown_blocks_all_new_nv_before_any_witness_write(self):
        module = self.api()
        from test_cases.test_req7_global_attempt_journal import load as global_load
        globals_ = global_load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); first = self.compiled(enrollment.nonces)
            with self.preparation(token) as prepared: module.register_catalog_nv_unit(prepared, first)
            globals_.prepare_global_unit(token, binding(), first)
            globals_.record_global_attempt_intent(token, binding(), first)
            before = self.files()
            for changes in ({'generation_id': 'e' * 64}, {'publish_id': 'f' * 64},
                            {'sheet': 'IB Cabling', 'requested_keys': (('ib_cabling', 'foreign-project', 'p1', 'Link Down'),)}):
                with self.subTest(changes=tuple(changes)), mock.patch.object(module, '_write_catalog_image') as writing:
                    reached = []
                    with self.assertRaises(module.NvReservationHold):
                        with self.preparation(token, **changes): reached.append('yield')
                    self.assertEqual([], reached)
                    writing.assert_not_called()
            self.assertEqual(before, self.files())
            seen = module.require_unit_nv_reservation(token, binding(), self.identity, first)
            self.assertEqual(('NV30102', 'NV30103'), tuple(identifier for _key, identifier in seen.reservations))
            self.assertEqual(1, globals_.inspect_global_unit(token, binding(), first).attempt_count)

    def test_missing_whole_or_partial_old_global_journal_never_grants_new_allocation(self):
        module = self.api()
        from test_cases.test_req7_global_attempt_journal import load as global_load
        globals_ = global_load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); first = self.compiled(enrollment.nonces)
            with self.preparation(token) as prepared: module.register_catalog_nv_unit(prepared, first)
            def deny_without_writes():
                before = self.files()
                reached = []
                with mock.patch.object(module, '_write_catalog_image') as writing, self.assertRaises(module.NvReservationHold):
                    with self.preparation(token, generation_id='e' * 64): reached.append('yield')
                self.assertEqual([], reached)
                writing.assert_not_called(); self.assertEqual(before, self.files())
            deny_without_writes()
            globals_.prepare_global_unit(token, binding(), first)
            prefix = self.store.name[:-3] + '.unit-' + first.unit_id
            (self.state / (prefix + '.journal')).rename(self.root / 'held-original-global-journal')
            deny_without_writes()
            (self.state / (prefix + '.journal-started')).rename(self.root / 'held-original-global-started')
            deny_without_writes()

    def test_legacy_nv_prepare_cannot_bypass_a_native_catalog_unknown_barrier(self):
        module = self.api()
        from test_cases.test_req7_global_attempt_journal import load as global_load
        globals_ = global_load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            enrollment = self.initialize(token); first = self.compiled(enrollment.nonces)
            with self.preparation(token) as prepared: module.register_catalog_nv_unit(prepared, first)
            globals_.prepare_global_unit(token, binding(), first)
            globals_.record_global_attempt_intent(token, binding(), first)
            before = self.files()
            with mock.patch.object(module.local, '_write_new', wraps=module.local._write_new) as writing:
                with self.assertRaises(module.NvReservationHold):
                    module.prepare_nv_reservation(token, binding(), self.identity,
                        self.eth_plan, self.eth, self.ib_plan, self.ib, **self.kw)
                writing.assert_not_called()
            self.assertEqual(before, self.files()); self.assertFalse(self.store.exists())


class Req7NvReservationNativeWorkflowTests(unittest.TestCase):
    from test_cases.test_req7_sheets_read_plan import Req7SheetsNativeReadWorkflowTests as _Fixture
    fixture = _Fixture.fixture; certificates = _Fixture.certificates; server = _Fixture.server
    initialize = Req7NvReservationDirectTests.initialize
    reserve = Req7NvReservationDirectTests.reserve
    inspect = Req7NvReservationDirectTests.inspect

    def setUp(self):
        Req7NvReservationDirectTests.setUp(self); self.journal_root = self.root
        self._Fixture.setUp(self); self.tls = self.module

    def test_two_actual_native_fixed_reads_then_owner_enrollment_and_immutable_reservation(self):
        self.module = load()
        target = replace(self.binding, spreadsheet_id=TARGET)
        originals = (self.eth, self.ib); replies = []
        for sheet, original in zip(('ETH Cabling', 'IB Cabling'), originals):
            unit = self.tls.NativeActivitySheetReadUnit(target, self.token, sheet=sheet)
            payload = original.data
            wire = ('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(payload)).encode() + payload
            with self.server(wire, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), self.fixture():
                replies.append(unit.send_once())
                with self.assertRaises(self.tls.TlsInputHold): unit.send_once()
            self.assertEqual([], errors); self.assertEqual(1, len(records)); self.assertEqual(b'', records[0][2])
            self.assertIn(('GET ' + (self.eth_plan if sheet == 'ETH Cabling' else self.ib_plan).path + ' HTTP/1.1').encode(), records[0][0])
        self.eth, self.ib = replies
        with fixture(self.journal_root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); seen = self.reserve(token)
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), seen.reservations)
            self.assertEqual(seen, self.inspect(token))
            from monitor.issue_tracker_send_unit import freeze_send_unit
            compiled = freeze_send_unit(**cabling_inputs(original.nonces))
            self.assertEqual(seen, self.module.require_unit_nv_reservation(token, binding(), self.identity, compiled))
        self.assertEqual(tuple(raw.data for raw in originals), tuple(raw.data for raw in replies))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
        case = Req7NvReservationDirectTests(); case.setUp(); case.module = load()
        with fixture(Path(sys.argv[2])), case.owner.spreadsheet_owner(binding()) as token:
            seen = case.inspect(token)
        print(' '.join(value for key, value in seen.reservations)); case.doCleanups()
    else: unittest.main()
