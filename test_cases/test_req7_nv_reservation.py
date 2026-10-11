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


@contextmanager
def native_creator_first_stat_fault(module, root, *, recycle=False):
    """Fault only our actual exclusive NV return, retaining exact cleanup IDs."""
    real_create = module.global_journal._create_folder; real_fstat = os.fstat
    created = []; marks = []; foreign_fd = None
    if recycle:
        foreign = root / 'owned-native-creator-foreign'; foreign.write_bytes(b'foreign original must survive')
        foreign_fd = os.open(str(foreign), os.O_RDONLY)
    def creating(*args, **kwargs):
        result = real_create(*args, **kwargs)
        if '.unit-' in args[1] and args[1].endswith('.nv'):
            fd = result[0] if isinstance(result, tuple) else result
            created.append((fd, real_fstat(fd)))
        return result
    def first_stat(fd):
        if created and fd == created[0][0] and not marks:
            if recycle:
                os.close(fd); os.dup2(foreign_fd, fd)
            marks.append('actual-first-stat-fault')
            raise OSError('native receiving stat failed')
        return real_fstat(fd)
    try:
        with mock.patch.object(module.global_journal, '_create_folder', side_effect=creating), \
                mock.patch('os.fstat', side_effect=first_stat):
            yield created, marks, foreign_fd, real_fstat
    finally:
        # Exact fixture-owned cleanup after RED as well as GREEN. Never scan
        # system descriptors or close an unrelated recycled object.
        for fd, original in created:
            try:
                current = real_fstat(fd)
                expected = (original.st_dev, original.st_ino)
                if foreign_fd is not None:
                    external = real_fstat(foreign_fd); expected = (external.st_dev, external.st_ino)
                if (current.st_dev, current.st_ino) == expected: os.close(fd)
            except OSError: pass
        if foreign_fd is not None: os.close(foreign_fd)


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
    def test_native_creator_does_not_accept_caller_settlement_or_verifier_overrides(self):
        module = load()
        for overrides in ({'applied': True}, {'keys': KEYS}, {'verify': lambda: None}, {'_project_proofs': {}}):
            with self.subTest(overrides=tuple(overrides)), self.assertRaises(TypeError):
                with module.hold_catalog_nv_preparation(object(), binding(), self.identity,
                        self.eth_plan, self.eth, self.ib_plan, self.ib, **self.kw, **overrides):
                    self.fail('caller claims cannot release a counted UNKNOWN')

    def test_native_unissued_owner_stops_before_shared_prefix_or_source_decode(self):
        module = load()
        with mock.patch.object(module, '_pin_catalog_prefix') as prefix, \
                mock.patch.object(module, '_read_pair') as decode:
            with self.assertRaises(module.NvReservationHold):
                with module.hold_catalog_nv_preparation(object(), binding(), self.identity,
                        self.eth_plan, self.eth, self.ib_plan, self.ib, **self.kw):
                    self.fail('unissued owner cannot reach native allocation')
            prefix.assert_not_called(); decode.assert_not_called()

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
    def native_c6_origin_fixture(self, *, settings_audit=None):
        module = self.api()
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        project = self.root / 'native-c6-project'; project.mkdir(mode=0o700)
        publication = project / 'publication'; publication.mkdir(mode=0o700)
        local = self.catalog.local; local.create_local_commit_store(project, publication)
        from test_cases.test_req7_spreadsheet_owner import scoped_fixture
        with local.writer_owner(project, publication) as writer, scoped_fixture(self.root, self.owner), self.owner.spreadsheet_owner(binding()) as token:
            enrolled = self.initialize(token)
            args = cabling_inputs(enrolled.nonces)
            if settings_audit is not None:
                from monitor import issue_tracker_k_store as settings
                settings.initialize_local_k_store(project/'.tracker',token=writer,
                    initialized_at='2026-10-08T10:00:00Z',acquisition_id='first-use')
                args['audits']=(settings_audit,)
            generation = local.begin_generation(writer, args['manifest'])
            local.record_intent(writer, generation, literal_xlsx(), kind='xlsx')
            receipt = local.commit(writer, generation)
            args.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
            unit = self.catalog.composer.freeze_send_unit(**args)
            self.kw.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
            yield module, writer, token, unit

    def native_settings_oracle(self):
        canonical=lambda value:(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        payload={'new_k':3,'actor':'system:default','expected_revision':None,'request_id':'first-use'}
        event=canonical({'schema_version':1,'revision':0,'type':'init','old_k':None,
            'new_k':3,'actor':'system:default','recorded_at':'2026-10-08T10:00:00Z',
            'request_id':'first-use','payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
            'predecessor_sha256':None})
        return {'event_id':'settings:0:'+hashlib.sha256(event).hexdigest(),
            'recorded_at_utc':'2026-10-08T10:00:00Z','details':event.decode().rstrip('\n')}

    def native_delivery_leaf_stat_fault(self, name):
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token,binding(),unit)
            from test_cases.test_req7_settings_audit_allocation import load as load_allocation
            allocation=load_allocation()
            directory=allocation.local._directory; stat=os.fstat; owned=[]; failed=[];yielded=[]
            def acquiring(parent,entry,**options):
                result=directory(parent,entry,**options)
                descriptor=result[0] if isinstance(result,tuple) else result
                if entry==name and not owned:owned.append((descriptor,stat(descriptor)))
                return result
            def refuse_after_return(descriptor):
                if owned and descriptor==owned[0][0] and not failed:
                    failed.append(descriptor);raise OSError('owned post-return stat refusal')
                return stat(descriptor)
            try:
                with mock.patch.object(allocation.local,'_directory',side_effect=acquiring), \
                        mock.patch.object(allocation.os,'fstat',side_effect=refuse_after_return):
                    with self.assertRaises(Exception):
                        with allocation._hold_native_catalog_allocation_images(writer,token,binding(),unit):
                            yielded.append(True)
                self.assertEqual([],yielded,'post-return acquisition refusal cannot yield originals')
                self.assertTrue(owned,'actual requested directory must be acquired')
                self.assertEqual([owned[0][0]],failed)
                with self.assertRaises(OSError) as caught:stat(owned[0][0])
                self.assertEqual(9,caught.exception.errno,'post-return stat refusal must not leak the acquired directory')
            finally:
                for descriptor,original in owned:
                    try:current=stat(descriptor)
                    except OSError:continue
                    if (current.st_dev,current.st_ino)==(original.st_dev,original.st_ino):os.close(descriptor)

    def test_native_delivery_settings_directory_after_return_stat_refusal_closes_owned_fd(self):
        self.native_delivery_leaf_stat_fault('settings')

    def test_native_delivery_events_directory_after_return_stat_refusal_closes_owned_fd(self):
        self.native_delivery_leaf_stat_fault('events')

    def test_native_delivery_open_time_ancestor_rebind_closes_acquired_not_previous_inode(self):
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token,binding(),unit)
            from test_cases.test_req7_settings_audit_allocation import load as load_allocation
            allocation=load_allocation();directory=allocation.local._directory;owned=[];reached=[];yielded=[]
            path=self.root/'native-c6-project/.tracker/settings';saved=self.root/'original-settings-directory'
            original=path.stat()
            def rebind_before_open(parent,entry,**options):
                if entry=='settings' and not reached:
                    path.rename(saved);path.mkdir(mode=0o700);reached.append(True)
                result=directory(parent,entry,**options)
                descriptor=result[0] if isinstance(result,tuple) else result
                if entry=='settings' and not owned:owned.append((descriptor,os.fstat(descriptor)))
                return result
            try:
                with mock.patch.object(allocation.local,'_directory',side_effect=rebind_before_open):
                    with self.assertRaises(Exception):
                        with allocation._hold_native_catalog_allocation_images(writer,token,binding(),unit):
                            yielded.append(True)
                self.assertEqual([],yielded,'changed named ancestor cannot yield originals')
                self.assertEqual([True],reached);self.assertTrue(owned)
                self.assertEqual(original.st_ino,saved.stat().st_ino)
                self.assertEqual([],list(path.iterdir()))
                self.assertTrue((saved/'events/0.json').is_file())
                with self.assertRaises(OSError) as caught:os.fstat(owned[0][0])
                self.assertEqual(9,caught.exception.errno)
            finally:
                for descriptor,identity in owned:
                    try:current=os.fstat(descriptor)
                    except OSError:continue
                    if (current.st_dev,current.st_ino)==(identity.st_dev,identity.st_ino):os.close(descriptor)

    def test_native_delivery_consumer_interrupt_survives_graph_cleanup_refusal(self):
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token,binding(),unit)
            from test_cases.test_req7_settings_audit_allocation import load as load_allocation
            allocation=load_allocation()
            close=self.catalog._close_original; primary=KeyboardInterrupt('owned consumer interrupted')
            refused=[]; closed=[]; armed=[]
            def close_then_refuse(descriptor,identity):
                close(descriptor,identity)
                if armed:
                    closed.append(descriptor)
                    if not refused:refused.append(descriptor);raise OSError('owned cleanup refused after original close')
            with mock.patch.object(self.catalog,'_close_original',side_effect=close_then_refuse):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    with allocation._hold_native_catalog_allocation_images(writer,token,binding(),unit):
                        armed.append(True)
                        raise primary
            self.assertIs(primary,caught.exception)
            self.assertIsNotNone(caught.exception.__cause__)
            self.assertGreater(len(closed),1)
            for descriptor in closed:
                with self.assertRaises(OSError):os.fstat(descriptor)

    def test_native_delivery_ancestor_return_foreign_slot_is_not_closed(self):
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token,binding(),unit)
            from test_cases.test_req7_settings_audit_allocation import load as load_allocation
            allocation=load_allocation();directory=allocation.local._directory;reused=[];yielded=[]
            foreign=self.root/'foreign-directory';foreign.mkdir(mode=0o700);identity=foreign.stat()
            def replace_returned_slot(parent,entry,**options):
                result=directory(parent,entry,**options)
                if entry=='settings' and not reused:
                    descriptor=result[0] if isinstance(result,tuple) else result
                    os.close(descriptor);other=os.open(foreign,os.O_RDONLY|os.O_DIRECTORY)
                    if other!=descriptor:os.dup2(other,descriptor);os.close(other)
                    reused.append(descriptor)
                return result
            try:
                with mock.patch.object(allocation.local,'_directory',side_effect=replace_returned_slot):
                    with self.assertRaises(Exception):
                        with allocation._hold_native_catalog_allocation_images(writer,token,binding(),unit):
                            yielded.append(True)
                self.assertEqual([],yielded,'foreign ancestor slot cannot yield originals')
                self.assertEqual(1,len(reused));current=os.fstat(reused[0])
                self.assertEqual((identity.st_dev,identity.st_ino),(current.st_dev,current.st_ino))
            finally:
                for descriptor in reused:
                    try:current=os.fstat(descriptor)
                    except OSError:continue
                    if (current.st_dev,current.st_ino)==(identity.st_dev,identity.st_ino):os.close(descriptor)

    def test_native_settings_scope_refusal_never_bypasses_existing_preparation_cleanup(self):
        failure=None;descriptors=[]
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            try:
                with self.preparation(token) as prepared:
                    self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
                    record=module._ACTIVE_CATALOG_PREPARATIONS[prepared]
                    descriptors=[row[2] for row in record['current'].files]
                    event=module.local._owner(writer).project/'.tracker/settings/events/0.json'
                    raw=event.read_bytes();event.rename(event.parent/'preserved-original-event')
                    event.write_bytes(raw);event.chmod(0o600)
            except Exception as exc:failure=exc
            self.assertNotIn(token,self.catalog._IMAGE_BUDGETS)
            self.assertEqual({},module._ACTIVE_CATALOG_PREPARATIONS)
            self.assertTrue(descriptors)
            for descriptor in descriptors:
                with self.assertRaises(OSError):os.fstat(descriptor)
            self.assertIsInstance(failure,module.NvReservationHold)

    def test_native_creator_graph_interrupt_still_closes_all_owned_images(self):
        primary=KeyboardInterrupt('actual native creator graph interrupted');reached=[];created=[];target=[]
        native_close=None
        def close(descriptor,identity):
            native_close(descriptor,identity)
            if target and descriptor==target[0] and not reached:reached.append(descriptor);raise primary
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            native_close=self.catalog._close_original
            with mock.patch.object(self.catalog,'_close_original',side_effect=close):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    with self.preparation(token) as prepared:
                        self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
                        record=module._ACTIVE_CATALOG_PREPARATIONS[prepared]
                        created=[row[2] for row in record['current'].files]
                        target[:]=[record['current'].files[-1][2]]
            self.assertIs(primary,caught.exception);self.assertEqual(target,reached)
            self.assertNotIn(token,self.catalog._IMAGE_BUDGETS)
            self.assertEqual({},module._ACTIVE_CATALOG_PREPARATIONS)
            self.assertTrue(created)
            for descriptor in created:
                closed=False
                try:os.fstat(descriptor)
                except OSError as exc:closed=exc.errno==9
                self.assertTrue(closed,'native graph interrupt leaked another original creator')
            self.assertFalse(any(path.name.endswith('.journal') for path in self.state.iterdir()))

    def test_native_settings_scope_foreign_fd_refusal_revokes_all_preparation_authority(self):
        native_open=os.open; settings_descriptors=[]; recycled=[]; failure=None; created=[]
        foreign=self.root/'native-settings-foreign';foreign.write_bytes(b'foreign not closed by preparation\n')
        foreign.chmod(0o600)
        def capture(name,*args,**options):
            descriptor=native_open(name,*args,**options)
            if name=='0.json':settings_descriptors.append(descriptor)
            return descriptor
        try:
            with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
                try:
                    with self.preparation(token) as prepared,mock.patch.object(module.os,'open',side_effect=capture):
                        self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
                        record=module._ACTIVE_CATALOG_PREPARATIONS[prepared]
                        created=[row[2] for row in record['current'].files]
                        self.assertGreaterEqual(len(settings_descriptors),2)
                        descriptor=settings_descriptors[0]
                        self.assertEqual((self.native_settings_oracle()['details']+'\n').encode(),os.pread(descriptor,16384,0))
                        os.close(descriptor);other=native_open(foreign,os.O_RDONLY)
                        if other!=descriptor:os.dup2(other,descriptor);os.close(other)
                        recycled.append(descriptor)
                except Exception as exc:failure=exc
                self.assertIsInstance(failure,module.NvReservationHold)
                self.assertNotIn(token,self.catalog._IMAGE_BUDGETS)
                self.assertEqual({},module._ACTIVE_CATALOG_PREPARATIONS)
                self.assertEqual(b'foreign not closed by preparation\n',os.pread(recycled[0],128,0))
                self.assertEqual(foreign.stat().st_ino,os.fstat(recycled[0]).st_ino)
                self.assertTrue(created)
                for descriptor in created:
                    with self.assertRaises(OSError):os.fstat(descriptor)
                self.assertFalse(any(path.name.endswith('.journal') for path in self.state.iterdir()))
        finally:
            for descriptor in recycled:
                try:os.close(descriptor)
                except OSError:pass

    def test_native_allocation_creator_handoff_replacement_refuses_before_catalog_entry(self):
        reached=[];failure=None
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            native=module.local._write_new
            def writing(parent,name,raw,**options):
                result=native(parent,name,raw,**options)
                if name=='ASSIGNMENTS' and not reached:
                    original=os.stat(name,dir_fd=parent,follow_symlinks=False)
                    os.rename(name,'preserved-original-assignment',src_dir_fd=parent,dst_dir_fd=parent)
                    replacement=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=parent)
                    try:os.write(replacement,raw)
                    finally:os.close(replacement)
                    reached.append((original.st_ino,os.stat(name,dir_fd=parent).st_ino))
                return result
            try:
                with self.preparation(token) as prepared,mock.patch.object(module.local,'_write_new',side_effect=writing):
                    self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            except Exception as exc:failure=exc
            self.assertEqual(1,len(reached));self.assertNotEqual(*reached[0])
            self.assertIsInstance(failure,module.NvReservationHold)
            stem=hashlib.sha256(TARGET.encode()).hexdigest()
            self.assertFalse((self.state/(stem+'.units')).exists())
            self.assertFalse(any(path.name.endswith('.journal') for path in self.state.iterdir()))
            self.assertNotIn(token,self.catalog._IMAGE_BUDGETS)

    def test_native_actual_c6_audit_allocation_precedes_unique_catalog_entry_and_cold_reads(self):
        audit=self.native_settings_oracle(); marks=[]
        with self.native_c6_origin_fixture(settings_audit=audit) as (module,writer,token,unit):
            parent=module.ownership._validated_owner(token,binding()).directories[-1][0]
            stem=hashlib.sha256(TARGET.encode()).hexdigest()+'.unit-'+unit.unit_id+'.settings-audit'
            native_append=self.catalog.register_pending_unit
            def append(*args,**kwargs):
                if stem in os.listdir(parent):
                    descriptor=os.open(stem,os.O_RDONLY|os.O_DIRECTORY,dir_fd=parent)
                    try: present=set(os.listdir(descriptor))
                    finally: os.close(descriptor)
                    marks.append(('allocation-before-entry',present))
                else: marks.append(('allocation-missing-before-entry',set()))
                return native_append(*args,**kwargs)
            with self.preparation(token) as prepared,mock.patch.object(self.catalog,'register_pending_unit',side_effect=append):
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            self.assertEqual([('allocation-before-entry',{'HEADER','ASSIGNMENTS','INITIALIZED'})],marks)
            marks[:]=['allocation-before-entry'];marks.append('registered')
            folder=self.state/stem
            assignments=json.loads((folder/'ASSIGNMENTS').read_bytes())
            self.assertEqual([{'revision':0,'event_sha256':audit['event_id'].split(':')[2],'audit':audit}],assignments)
            before=self.files()
            with self.catalog.hold_pending_project_c6_units(token,binding()) as (rows,verify):
                self.assertEqual((unit,),tuple(row.unit for row in rows));verify()
            self.assertEqual(before,self.files());marks.append('cold-originals')
            names=os.listdir(parent)
            self.assertFalse(any(name.endswith('.journal') or name.endswith('.journal-started') for name in names))
        self.assertEqual(['allocation-before-entry','registered','cold-originals'],marks)

    def test_native_catalog_audit_outside_anchor_refuses_lost_all_and_same_byte_replacement(self):
        for fault in ('lost-all','same-byte-assignments'):
            with self.subTest(fault=fault):
                # Each case gets a complete independent real C6/project/owner.
                with tempfile.TemporaryDirectory(prefix='req7-native-audit-anchor-') as directory:
                    old_root=self.root;old_state=self.state
                    self.root=Path(directory).resolve();self.state=self.root/'var/lib/http-ztp-container/issue-tracker'
                    self.state.mkdir(parents=True,mode=0o700)
                    try:
                        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
                            with self.preparation(token) as prepared:
                                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
                            stem=hashlib.sha256(TARGET.encode()).hexdigest()+'.unit-'+unit.unit_id+'.settings-audit'
                            folder=self.state/stem;self.assertTrue(folder.is_dir())
                            if fault=='lost-all':
                                # Only test-owned temp objects; retain moved originals.
                                folder.rename(self.root/'preserved-allocation')
                                (self.state/(stem+'-started')).rename(self.root/'preserved-allocation-started')
                            else:
                                target=folder/'ASSIGNMENTS';raw=target.read_bytes()
                                target.rename(self.root/'preserved-assignment');target.write_bytes(raw);target.chmod(0o600)
                            before=self.files()
                            with self.assertRaises(self.catalog.UnitCatalogHold):
                                with self.catalog.hold_pending_units(token,binding()):pass
                            self.assertEqual(before,self.files())
                    finally:self.root=old_root;self.state=old_state

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

    @contextmanager
    def native_reserved_count_fixture(self):
        from test_cases.test_req7_history_preread_journal import load as history_load
        from test_cases.test_req7_metadata_reservation import load as quota_load
        from test_cases.test_req7_metadata_capacity import entry, reply
        with self.native_c6_origin_fixture() as (module, writer, token, unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer, token, binding(), unit, _nv_preparation=prepared)
            global_journal = module.global_journal
            global_journal.prepare_global_unit(token, binding(), unit)
            read_binding = replace(self.binding, spreadsheet_id=TARGET)
            history_plan = self.planner.prepare_history_tail_read(read_binding, self.token)
            history_raw = grids.response({'spreadsheetId': TARGET, 'sheets': [{'properties': {
                'sheetId': 105, 'title': 'Update_History', 'sheetType': 'GRID',
                'gridProperties': {'rowCount': 100, 'columnCount': 5}},
                'data': [{'startRow': 2, 'startColumn': 0}]}]})
            history_load().prepare_history_preread(token, binding(), unit, history_plan, history_raw)
            nonces = {title: nonce for title, _sid, nonce in
                self.enrollment.inspect_enrollment_journal(token, binding(), self.identity).nonces}
            metadata_plan = self.capacity.prepare_metadata_capacity_read(read_binding, self.token)
            metadata_raw = reply((entry(201, 'http-ztp-enrollment-v1', nonces['ETH Cabling'], sheet=102),
                entry(202, 'http-ztp-enrollment-v1', nonces['Update_History'], sheet=105)))
            quota_load().prepare_metadata_reservation(token, binding(), self.identity, unit, metadata_plan, metadata_raw)
            yield module, token, unit

    def test_actual_native_nv_origin_history_quota_count_keeps_original_ids_and_unknown(self):
        with self.native_reserved_count_fixture() as (module, token, unit):
            before = self.files()
            counted = module.global_journal.record_reserved_attempt_intent(token, binding(), self.identity, unit)
            self.assertEqual((1, 'UNKNOWN'), (counted.attempt_count, counted.outcome))
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')),
                module.require_unit_nv_reservation(token, binding(), self.identity, unit).reservations)
            after = self.files()
            for path, image in before.items():
                if '.journal/' not in path:
                    self.assertEqual(image, after[path], path)
            self.assertFalse(any(hasattr(counted, name) for name in ('permit', 'applied', 'complete', 'send_once')))

    def test_native_nv_original_detach_restore_during_actual_count_retains_unknown_but_refuses_result(self):
        with self.native_reserved_count_fixture() as (module, token, unit):
            raw = self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.unit-' + unit.unit_id + '.nv') / 'ETH-RAW'
            before = self.files(); saved = self.root / 'owned-count-detached-nv-original'
            actual_observe = module.global_journal._observe; marks = []; result = None; failure = None
            def count_while_original_name_is_absent(*args, **kwargs):
                raw.rename(saved); marks.append('original-detached')
                try:
                    counted = actual_observe(*args, **kwargs)
                    self.assertEqual(1, counted.attempt_count)
                    marks.append('actual-count-one')
                    return counted
                finally:
                    saved.rename(raw); marks.append('original-restored')
            with mock.patch.object(module.global_journal, '_observe', side_effect=count_while_original_name_is_absent):
                try:
                    result = module.global_journal.record_reserved_attempt_intent(token, binding(), self.identity, unit)
                except module.global_journal.GlobalAttemptHold as error:
                    failure = error
            self.assertEqual(['original-detached', 'actual-count-one', 'original-restored'], marks)
            self.assertIsNone(result, 'two cold reads must not accept loss of an original during the actual count')
            self.assertIsInstance(failure, module.global_journal.GlobalAttemptHold)
            observed = module.global_journal.inspect_global_unit(token, binding(), unit)
            self.assertEqual((1, 'UNKNOWN'), (observed.attempt_count, observed.outcome))
            after = self.files()
            for path, image in before.items():
                if '.journal/' not in path:
                    self.assertEqual(image, after[path], path)
            self.assertFalse(saved.exists())

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

    def test_two_native_projects_can_allocate_identical_literal_settings_events_independently(self):
        audit=self.native_settings_oracle()
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        from monitor import issue_tracker_k_store as settings
        with self.native_c6_origin_fixture(settings_audit=audit) as (module,writer,token,first):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),first,_nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token,binding(),first);old=self.files()
            local=self.catalog.local
            original_project=local._owner(writer).project_fd
            first_identity=(os.fstat(original_project).st_dev,os.fstat(original_project).st_ino)
            project=self.root/'other-native-audit-project';project.mkdir(mode=0o700)
            publication=project/'publication';publication.mkdir(mode=0o700)
            local.create_local_commit_store(project,publication)
            with local.writer_owner(project,publication) as other:
                settings.initialize_local_k_store(project/'.tracker',token=other,
                    initialized_at='2026-10-08T10:00:00Z',acquisition_id='first-use')
                other_project=local._owner(other).project_fd
                other_identity=(os.fstat(other_project).st_dev,os.fstat(other_project).st_ino)
                self.assertNotEqual(first_identity,other_identity)
                enrolled=self.enrollment.inspect_enrollment_journal(token,binding(),self.identity)
                args=cabling_inputs(enrolled.nonces,identifiers=('NV30104','NV30105'));args['audits']=(audit,)
                generation=local.begin_generation(other,args['manifest'])
                local.record_intent(other,generation,literal_xlsx(),kind='xlsx');receipt=local.commit(other,generation)
                args.update(generation_id=generation.generation_id,publish_id=receipt.published_sha256)
                second=self.catalog.composer.freeze_send_unit(**args)
                with self.preparation(token,generation_id=generation.generation_id,publish_id=receipt.published_sha256) as prepared:
                    self.catalog.register_pending_c6_unit(other,token,binding(),second,_nv_preparation=prepared)
                with self.catalog.hold_pending_project_c6_units(token,binding()) as (rows,verify):
                    self.assertEqual((first,second),tuple(row.unit for row in rows))
                    self.assertEqual((first_identity,other_identity),tuple(row.project_identity for row in rows));verify()
                stem=hashlib.sha256(TARGET.encode()).hexdigest()
                for unit,identity in ((first,first_identity),(second,other_identity)):
                    folder=self.state/(stem+'.unit-'+unit.unit_id+'.settings-audit')
                    self.assertEqual([{'revision':0,'event_sha256':audit['event_id'].split(':')[2],'audit':audit}],
                        json.loads((folder/'ASSIGNMENTS').read_bytes()))
                    self.assertEqual(list(identity),json.loads((folder/'HEADER').read_bytes())['project_identity'])
                self.assertEqual(old,{name:self.files()[name] for name in old})
                self.assertFalse(any(path.name.startswith('ATTEMPT-') for path in self.state.rglob('*')))

    def test_cold_all_catalog_refuses_same_project_event_in_two_actual_native_allocations(self):
        audit=self.native_settings_oracle()
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        from monitor import issue_tracker_settings_audit_allocation as allocation
        with self.native_c6_origin_fixture(settings_audit=audit) as (module,writer,token,first):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),first,_nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token,binding(),first);old=self.files()
            local=self.catalog.local;owner=local._owner(writer)
            project_identity=(os.fstat(owner.project_fd).st_dev,os.fstat(owner.project_fd).st_ino)
            enrolled=self.enrollment.inspect_enrollment_journal(token,binding(),self.identity)
            args=cabling_inputs(enrolled.nonces,identifiers=('NV30104','NV30105'));args['audits']=(audit,)
            generation=local.begin_generation(writer,args['manifest'])
            local.record_intent(writer,generation,literal_xlsx(),kind='xlsx');receipt=local.commit(writer,generation)
            args.update(generation_id=generation.generation_id,publish_id=receipt.published_sha256)
            second=self.catalog.composer.freeze_send_unit(**args);self.assertNotEqual(first.unit_id,second.unit_id)
            actual_assigned=allocation._native_assigned_event_ids;injections=[]
            def omit_only_this_original_event(record,identity):
                # Preserve the genuine original lookup/ALL C6 proof. Only a
                # creator-side classification fault injects the one duplicate;
                # no ENTRY, marker, external anchor or cold reader is forged.
                assigned=actual_assigned(record,identity)
                self.assertEqual(project_identity,identity)
                self.assertEqual({audit['event_id']},assigned)
                reduced=assigned-{audit['event_id']}
                injections.append((identity,frozenset(assigned),frozenset(reduced)))
                return reduced
            creation_error=None
            try:
                with mock.patch.object(allocation,'_native_assigned_event_ids',side_effect=omit_only_this_original_event):
                    with self.preparation(token,generation_id=generation.generation_id,publish_id=receipt.published_sha256) as prepared:
                        self.catalog.register_pending_c6_unit(writer,token,binding(),second,_nv_preparation=prepared)
            except Exception as exc: creation_error=exc
            self.assertEqual([(project_identity,frozenset({audit['event_id']}),frozenset())],injections)
            if creation_error is not None:
                self.assertIn(type(creation_error),(module.NvReservationHold,self.catalog.UnitCatalogHold))
            stem=hashlib.sha256(TARGET.encode()).hexdigest()
            catalog=self.state/(stem+'.units')
            second_entry=json.loads((catalog/('ENTRY-%020d'%2)).read_bytes())
            self.assertEqual(second.unit_id,second_entry['unit_id'])
            for unit in (first,second):
                folder=self.state/(stem+'.unit-'+unit.unit_id+'.settings-audit')
                self.assertEqual({'HEADER','ASSIGNMENTS','INITIALIZED'},set(os.listdir(folder)))
                self.assertEqual([{'revision':0,'event_sha256':audit['event_id'].split(':')[2],'audit':audit}],
                    json.loads((folder/'ASSIGNMENTS').read_bytes()))
                self.assertEqual(list(project_identity),json.loads((folder/'HEADER').read_bytes())['project_identity'])
            self.assertEqual(old,{name:self.files()[name] for name in old})
            before=self.files();yielded=[];collisions=[]
            actual_check=self.catalog._check_native_audit_assignments
            def observe_actual_duplicate_check(seen,unit,origin):
                try: return actual_check(seen,unit,origin)
                except self.catalog.UnitCatalogHold:
                    collisions.append((unit.unit_id,tuple(origin['project_identity']),frozenset(seen)))
                    raise
            with mock.patch.object(self.catalog,'_check_native_audit_assignments',side_effect=observe_actual_duplicate_check):
                with self.assertRaises(self.catalog.UnitCatalogHold):
                    with self.catalog.hold_pending_units(token,binding()) as values: yielded.append(values)
            self.assertEqual([(second.unit_id,project_identity,
                frozenset({(*project_identity,audit['event_id'])}))],collisions)
            self.assertEqual([],yielded);self.assertEqual(before,self.files())
            self.assertFalse(any(path.name.startswith(('ATTEMPT-','CLAIM-')) for path in self.state.rglob('*')))

    def test_native_audit_snapshot_and_actual_count_holder_do_not_require_legacy_shadow(self):
        audit=self.native_settings_oracle()
        from test_cases.test_req7_settings_audit_allocation import load as load_allocation
        with self.native_c6_origin_fixture(settings_audit=audit) as (module,writer,token,unit):
            allocation=load_allocation()
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token,binding(),unit)
            before=self.files();actual=allocation.inspect_settings_audit_allocation(writer,token,binding(),unit)
            self.assertEqual([{'revision':0,'event_sha256':audit['event_id'].split(':')[2],'audit':audit}],json.loads(actual))
            with module.global_journal._hold_receipted_audit_originals(writer,token,binding(),unit) as verify:
                verify();counted=module.global_journal.record_global_attempt_intent(token,binding(),unit);verify()
                self.assertEqual((1,'UNKNOWN'),(counted.attempt_count,counted.outcome))
            after=self.files()
            for name,image in before.items(): self.assertEqual(image,after[name],name)
            project=self.catalog.local._owner(writer).project
            self.assertFalse((project/'.tracker/settings-audit-allocation').exists())
            self.assertFalse((project/'.tracker/SETTINGS-AUDIT-ALLOCATED').exists())

    def _native_audit_last_c6_exit_rebind(self, *, counted):
        from test_cases.test_req7_settings_audit_allocation import load as load_allocation
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            allocation=load_allocation()
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token,binding(),unit)
            stem=hashlib.sha256(TARGET.encode()).hexdigest()
            path=self.state/(stem+'.unit-'+unit.unit_id+'.settings-audit')/'ASSIGNMENTS'
            raw=path.read_bytes();before=self.files();faults=[];armed=[False]
            actual=self.catalog._hold_project_c6_from_origins
            @contextmanager
            def last_exit(*args,**kwargs):
                with actual(*args,**kwargs) as result:yield result
                if armed[0]:
                    old=path.stat().st_ino
                    path.rename(self.root/'preserved-native-audit-original')
                    path.write_bytes(raw);path.chmod(0o600)
                    faults.append((old,path.stat().st_ino,path.read_bytes()))
            with mock.patch.object(self.catalog,'_hold_project_c6_from_origins',last_exit):
                with self.assertRaises(allocation.SettingsAuditHold):
                    with allocation._hold_counted_audit_originals(writer,token,binding(),unit) as verify:
                        verify()
                        if counted:module.global_journal.record_global_attempt_intent(token,binding(),unit)
                        armed[0]=True
            # Outside every sanitizer: prove the actual finalizer fault and
            # original bytes, not an unrelated HOLD or rollback after COUNT.
            self.assertEqual(1,len(faults));self.assertNotEqual(faults[0][0],faults[0][1])
            self.assertEqual(raw,faults[0][2]);self.assertEqual(raw,path.read_bytes())
            # The corrupted immutable graph must also close the public GLOBAL
            # reader. Raw retained intent is failure evidence, not authority.
            with self.assertRaises(module.global_journal.GlobalAttemptHold):
                module.global_journal.inspect_global_unit(token,binding(),unit)
            attempts=list(self.state.rglob('ATTEMPT-*'))
            self.assertEqual(int(counted),len(attempts))
            if counted:
                self.assertEqual('ATTEMPT-1',attempts[0].name)
                self.assertEqual((1,'UNKNOWN'),tuple(json.loads(attempts[0].read_bytes())[key]
                    for key in ('attempt_count','outcome')))
            self.assertFalse(list(self.state.rglob('CLAIM-*')))
            for name,image in before.items():
                if name!=str(path.relative_to(self.state)):self.assertEqual(image,self.files()[name],name)

    def test_native_audit_last_c6_exit_rebind_holds_before_count(self):
        self._native_audit_last_c6_exit_rebind(counted=False)

    def test_native_audit_last_c6_exit_rebind_holds_after_count_without_rollback(self):
        self._native_audit_last_c6_exit_rebind(counted=True)

    @contextmanager
    def _native_successor_with_old_c6(self):
        with self.native_c6_origin_fixture() as (module, writer, token, first):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer, token, binding(), first, _nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token, binding(), first)
            first_action = json.loads(first.action_preimage)
            owner = self.catalog.local._owner(writer)
            receipt = owner.project / '.tracker/generations' / first_action['identity']['generation_id'] / 'RECEIPT'
            enrolled = self.enrollment.inspect_enrollment_journal(token, binding(), self.identity)
            args = cabling_inputs(enrolled.nonces, identifiers=('NV30104', 'NV30105'))
            from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
            generation = self.catalog.local.begin_generation(writer, args['manifest'])
            self.catalog.local.record_intent(writer, generation, literal_xlsx(), kind='xlsx')
            published = self.catalog.local.commit(writer, generation)
            yield module, writer, token, first, receipt, generation, published

    def test_native_successor_refuses_old_real_c6_receipt_rebind_before_any_nv_write(self):
        marks = []; error = None
        with self._native_successor_with_old_c6() as (module, _writer, token, first, receipt, generation, published):
            raw = receipt.read_bytes(); original = receipt.stat().st_ino
            saved = self.root / 'preserved-old-native-receipt'; receipt.rename(saved)
            receipt.write_bytes(raw); receipt.chmod(0o600)
            before = self.files()
            try:
                with self.preparation(token, generation_id=generation.generation_id,
                        publish_id=published.published_sha256):
                    marks.append('unsafe-preparation-yield')
            except Exception as exc: error = exc
            self.assertIs(type(error), module.NvReservationHold)
            self.assertEqual([], marks)
            self.assertEqual(before, self.files(), 'invalid prior real C6 must stop before a new witness or NV directory')
            self.assertEqual(original, saved.stat().st_ino)
            self.assertNotEqual(original, receipt.stat().st_ino)
            self.assertEqual(raw, receipt.read_bytes()); self.assertEqual(raw, saved.read_bytes())
            self.assertEqual((0, 'UNATTEMPTED_OBSERVATION'),
                (lambda state: (state.attempt_count, state.outcome))(
                    module.global_journal.inspect_catalog_global_units(token, binding())[0][1]))

    def test_native_successor_old_c6_rebind_after_actual_witness_stops_before_any_nv_image(self):
        marks = []; writes = []; error = None
        with self._native_successor_with_old_c6() as (module, _writer, token, first, receipt, generation, published):
            raw = receipt.read_bytes(); original = receipt.stat().st_ino
            saved = self.root / 'preserved-inflight-old-native-receipt'
            write_original = module._write_catalog_image
            def write_then_rebind(parent, name, *arguments, **keywords):
                result = write_original(parent, name, *arguments, **keywords)
                writes.append(name)
                if name.endswith('.nv-started'):
                    receipt.rename(saved); receipt.write_bytes(raw); receipt.chmod(0o600)
                    marks.append('actual-witness-then-old-c6-rebound')
                return result
            try:
                with mock.patch.object(module, '_write_catalog_image', side_effect=write_then_rebind):
                    with self.preparation(token, generation_id=generation.generation_id,
                            publish_id=published.published_sha256):
                        marks.append('unsafe-preparation-yield')
            except Exception as exc: error = exc
            self.assertIs(type(error), module.NvReservationHold)
            self.assertEqual(['actual-witness-then-old-c6-rebound'], marks)
            self.assertEqual(1, len(writes)); self.assertTrue(writes[0].endswith('.nv-started'))
            self.assertEqual(original, saved.stat().st_ino); self.assertNotEqual(original, receipt.stat().st_ino)
            self.assertEqual(raw, receipt.read_bytes()); self.assertEqual(raw, saved.read_bytes())
            with self.catalog.hold_pending_units(token, binding()) as (units, verify):
                self.assertEqual((first,), units); verify()
            before = self.files()
            with self.assertRaises(module.NvReservationHold):
                with self.preparation(token, generation_id=generation.generation_id,
                        publish_id=published.published_sha256): self.fail('interrupted NV preparation was adopted')
            self.assertEqual(before, self.files())

    def test_real_two_native_c6_nv_origin_global_all_project_fifo_workflow_keeps_pending_barrier(self):
        from test_cases.test_req7_retained_global_inventory import load as inventory_load
        with self._native_successor_with_old_c6() as (module, writer, token, first, _receipt, generation, published):
            enrolled = self.enrollment.inspect_enrollment_journal(token, binding(), self.identity)
            args = cabling_inputs(enrolled.nonces, identifiers=('NV30104', 'NV30105'))
            args.update(generation_id=generation.generation_id, publish_id=published.published_sha256)
            second = self.catalog.composer.freeze_send_unit(**args)
            with self.preparation(token, generation_id=generation.generation_id,
                    publish_id=published.published_sha256) as prepared:
                self.assertEqual(((KEYS[0], 'NV30104'), (KEYS[1], 'NV30105')), prepared.observation.reservations)
                self.catalog.register_pending_c6_unit(writer, token, binding(), second, _nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token, binding(), second)
            inventory = inventory_load(reset_support=False); before = self.files()
            handles = dict(self.catalog.local._ACTIVE[writer].handles)
            with inventory._hold_all_project_applied_keys(token, binding()) as (rows, verify):
                self.assertEqual((first, second), tuple(row.unit for row in rows))
                self.assertEqual((0, 0), tuple(row.attempt_count for row in rows))
                self.assertEqual(((), ()), tuple(row.key_watermarks for row in rows))
                self.assertEqual(rows[0].project_identity, rows[1].project_identity); verify()
            with inventory._hold_all_project_fifo_frontier(token, binding()) as (frontier, verify):
                self.assertEqual((first.unit_id,), frontier.frontier)
                self.assertEqual(((second.unit_id, (first.unit_id,)),), frontier.blocked)
                self.assertEqual((), frontier.applied); self.assertEqual((), frontier.superseded)
                self.assertFalse(any(hasattr(frontier, name) for name in ('permit', 'fresh', 'new', 'writer_token')))
                verify()
            self.assertEqual(handles, self.catalog.local._ACTIVE[writer].handles)
            self.assertEqual(before, self.files())

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

    def _exercise_native_nv_first_stat_cleanup(self, recycle):
        module = self.api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            with native_creator_first_stat_fault(module, self.root, recycle=recycle) as (created, marks, foreign_fd, real_fstat):
                with self.assertRaises(module.NvReservationHold):
                    with self.preparation(token): self.fail('faulted creator yielded preparation')
                self.assertEqual(['actual-first-stat-fault'], marks)
                self.assertEqual(1, len(created)); fd, original = created[0]
                if recycle:
                    current = real_fstat(fd); external = real_fstat(foreign_fd)
                    self.assertEqual((external.st_dev, external.st_ino), (current.st_dev, current.st_ino))
                    self.assertEqual(b'foreign original must survive', os.pread(fd, 128, 0))
                else:
                    with self.assertRaises(OSError, msg='native first receive leaked exclusive original FD'): real_fstat(fd)
                self.assertEqual(1, len(tuple(self.state.glob('*.nv-started'))))
                folders = tuple(self.state.glob('*.nv')); self.assertEqual(1, len(folders))
                self.assertEqual([], os.listdir(folders[0]))
                self.assertFalse(any(path.name.endswith('.units') or '.journal' in path.name for path in self.state.iterdir()))
                before = self.files()
                with self.assertRaises(module.NvReservationHold):
                    with self.preparation(token): self.fail('interrupted creator was adopted')
                self.assertEqual(before, self.files())

    def test_native_nv_first_stat_failure_closes_only_owned_creator_before_handoff(self):
        self._exercise_native_nv_first_stat_cleanup(False)

    def test_native_nv_first_stat_failure_preserves_foreign_recycled_descriptor(self):
        self._exercise_native_nv_first_stat_cleanup(True)

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

    def test_native_audit_catalog_global_and_retained_inventory_hold_all_originals_without_authority(self):
        from test_cases.test_req7_retained_global_inventory import load as inventory_load
        audit=self.native_settings_oracle()
        with self.native_c6_origin_fixture(settings_audit=audit) as (module,writer,token,unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            original=self.files()
            module.global_journal.prepare_global_unit(token,binding(),unit)
            inventory=inventory_load(reset_support=False);before=self.files()
            with inventory._hold_catalog_retained_inventory(token,binding()) as (rows,verify):
                self.assertEqual((unit,),tuple(row.unit for row in rows))
                self.assertEqual((0,),tuple(row.attempt_count for row in rows))
                self.assertEqual({'enrollment','journal','journal-started','nv','nv-started','project-origin',
                                  'settings-audit','settings-audit-started'},set(rows[0].families))
                prefix=hashlib.sha256(TARGET.encode()).hexdigest()+'.unit-'+unit.unit_id
                names={name for name,_stat,_sha in rows[0].originals}
                self.assertEqual({'HEADER','ASSIGNMENTS','INITIALIZED'},
                    {name.split('/')[-1] for name in names if name.startswith(prefix+'.settings-audit/')})
                self.assertIn(prefix+'.settings-audit-started',names)
                self.assertEqual({'ETH-RAW','IB-RAW','PRIOR','HEADER','RESERVATIONS','INITIALIZED'},
                    {name.split('/')[-1] for name in names if name.startswith(prefix+'.nv/')})
                self.assertFalse(any(hasattr(rows[0],name) for name in ('permit','applied','fresh','new')))
                verify()
            self.assertEqual(before,self.files())
            for name,image in original.items():self.assertEqual(image,self.files()[name],name)
            self.assertEqual((0,'UNATTEMPTED_OBSERVATION'),
                (lambda row:(row.attempt_count,row.outcome))(
                    module.global_journal.inspect_catalog_global_units(token,binding())[0][1]))

    def test_native_retained_assignment_same_bytes_rebind_refuses_after_actual_yield(self):
        from test_cases.test_req7_retained_global_inventory import load as inventory_load
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            module.global_journal.prepare_global_unit(token,binding(),unit)
            inventory=inventory_load(reset_support=False)
            prefix=hashlib.sha256(TARGET.encode()).hexdigest()+'.unit-'+unit.unit_id
            path=self.state/(prefix+'.settings-audit')/'ASSIGNMENTS'
            saved=self.root/'original-retained-native-assignment';raw=path.read_bytes();inode=path.stat().st_ino
            journal_before={name:image for name,image in self.files().items() if name.startswith(prefix+'.journal/')}
            marks=[];failure=None
            try:
                with inventory._hold_catalog_retained_inventory(token,binding()) as (_rows,verify):
                    marks.append('actual-inventory-yield')
                    path.rename(saved);path.write_bytes(raw);path.chmod(0o600)
                    marks.append('same-byte-rebind');verify();marks.append('unsafe-return')
            except Exception as exc:failure=exc
            self.assertEqual(['actual-inventory-yield','same-byte-rebind'],marks)
            self.assertIs(type(failure),inventory.RetainedInventoryHold)
            self.assertNotEqual(inode,path.stat().st_ino);self.assertEqual(inode,saved.stat().st_ino)
            self.assertEqual(raw,path.read_bytes());self.assertEqual(raw,saved.read_bytes())
            self.assertEqual(journal_before,
                {name:image for name,image in self.files().items() if name.startswith(prefix+'.journal/')})
            self.assertFalse(any(name.startswith('ATTEMPT-') for name in os.listdir(self.state/(prefix+'.journal'))))
            with self.assertRaises(module.global_journal.GlobalAttemptHold):
                module.global_journal.inspect_catalog_global_units(token,binding())

    def test_native_audit_unknown_family_suffix_refuses_before_any_retained_consumer(self):
        from test_cases.test_req7_retained_global_inventory import load as inventory_load
        with self.native_c6_origin_fixture(settings_audit=self.native_settings_oracle()) as (module,writer,token,unit):
            with self.preparation(token) as prepared:
                self.catalog.register_pending_c6_unit(writer,token,binding(),unit,_nv_preparation=prepared)
            suffix=hashlib.sha256(TARGET.encode()).hexdigest()+'.unit-'+unit.unit_id+'.settings-audit-foreign'
            (self.state/suffix).mkdir(mode=0o700);before=self.files()
            with self.assertRaises(module.global_journal.GlobalAttemptHold):
                module.global_journal.inspect_catalog_global_units(token,binding())
            inventory=inventory_load(reset_support=False);marks=[]
            with self.assertRaises(inventory.RetainedInventoryHold):
                with inventory._hold_catalog_retained_inventory(token,binding()):marks.append('unsafe-yield')
            self.assertEqual([],marks);self.assertEqual(before,self.files());self.assertTrue((self.state/suffix).is_dir())

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
        def creating(parent, name, **keywords):
            result = create(parent, name, **keywords)
            fd = result[0] if isinstance(result, tuple) else result
            created.append(fd); return result
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
