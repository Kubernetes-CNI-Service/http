"""Independent retained namespace coverage; never a successor/send permit."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.test_req7_spreadsheet_owner import fixture, scoped_fixture, binding, TARGET, load as load_owner
from test_cases.test_req7_global_attempt_journal import load as load_global, unit, original_read_files

SOURCE = Path(__file__).resolve().parents[1] / 'monitor/issue_tracker_retained_inventory.py'
STEM = hashlib.sha256(TARGET.encode()).hexdigest()


def load(*, reset_support=True):
    if not SOURCE.is_file():
        raise AssertionError('retained original namespace inventory is missing')
    if reset_support:
        # Load canonical owner registries BEFORE the new consumer captures
        # their aliases. Reloading them after issuance is not a cold reader.
        load_owner(); load_global()
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_retained_inventory', SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    monitor.issue_tracker_retained_inventory = module
    return module


class RetainedInventoryShapeTests(unittest.TestCase):
    def test_fixture_reload_keeps_normal_import_and_package_alias_on_actual_registry(self):
        import importlib
        import monitor
        name='monitor.issue_tracker_retained_inventory'
        importlib.import_module(name)
        actual=load(reset_support=False)
        self.assertIs(actual,sys.modules[name])
        self.assertIs(actual,importlib.import_module(name))
        self.assertIs(actual,monitor.issue_tracker_retained_inventory,
            'native fixture reload must preserve normal package import identity')

    def test_all_fixed_namespace_families_are_explicit_not_discarded(self):
        module = load()
        suffixes = ('business', 'completion', 'completion-started', 'dispatch', 'enrollment',
                    'history', 'journal', 'journal-started', 'metadata', 'nv')
        names = tuple(STEM + '.' + suffix for suffix in suffixes)
        wanted = tuple((STEM + '.' + suffix, suffix) for suffix in suffixes)
        # Other spreadsheets and this owner's persistent empty lock are not
        # discarded evidence of this spreadsheet; they are distinct owners.
        self.assertEqual(wanted, module._namespace_entries(
            STEM, names + (STEM + '.lock', 'f' * 64 + '.journal')))

    def test_unknown_pending_archive_and_future_unit_names_hold_not_empty(self):
        module = load()
        base = (STEM + '.journal', STEM + '.journal-started')
        for suffix in ('units', 'archive', 'journal.pending', 'journal-old', 'completion.tmp', ''):
            with self.subTest(suffix=suffix), self.assertRaises(module.RetainedInventoryHold):
                module._namespace_entries(STEM, base + (STEM + '.' + suffix,))

    def test_absent_partial_or_ambiguous_namespace_never_first_use_permission(self):
        module = load()
        for names in ((), (STEM + '.lock',), (STEM + '.journal',),
                      (STEM + '.journal-started',), (STEM + '.enrollment',),
                      (STEM + '.journal', STEM + '.journal-started', STEM + '.journal'),
                      (STEM + '.journal', STEM + '.journal-started', None)):
            with self.subTest(names=names), self.assertRaises(module.RetainedInventoryHold):
                module._namespace_entries(STEM, names)

    def test_optional_family_file_shapes_reject_partial_gap_extra_and_missing_marker(self):
        module = load()
        shapes = {
            'enrollment': ('HEADER', 'INITIALIZED', 'NONCES'),
            'history': ('HEADER', 'HISTORY-RAW', 'INITIALIZED'),
            'business': ('BUSINESS-RAW', 'HEADER', 'INITIALIZED', 'MANIFEST'),
            'metadata': ('HEADER', 'INITIALIZED', 'METADATA-RAW', 'RESERVATION'),
            'nv': ('ETH-RAW', 'HEADER', 'IB-RAW', 'INITIALIZED', 'RESERVATIONS'),
            'completion': ('COMPLETE', 'HEADER', 'HEADERS-RAW', 'HISTORY-RAW', 'IDENTITY-RAW', 'METADATA-RAW'),
            'dispatch': ('CLAIM-1', 'CLAIM-2', 'HEADER', 'INITIALIZED'),
            'journal': ('ACTION-PREIMAGE', 'ATTEMPT-1', 'ATTEMPT-2', 'HEADER', 'INITIALIZED', 'WIRE'),
        }
        for family, names in shapes.items():
            with self.subTest(family=family):
                self.assertEqual(tuple(sorted(names)), module._family_entries(family, names))
                for changed in (names[:-1], names + ('foreign',), names + (names[0],)):
                    with self.subTest(changed=changed), self.assertRaises(module.RetainedInventoryHold):
                        module._family_entries(family, changed)
        for family, names in (
                ('dispatch', ('HEADER', 'INITIALIZED', 'CLAIM-2')),
                ('journal', ('ACTION-PREIMAGE', 'HEADER', 'INITIALIZED', 'WIRE', 'ATTEMPT-7'))):
            with self.subTest(family=family), self.assertRaises(module.RetainedInventoryHold):
                module._family_entries(family, names)


@contextmanager
def originals(case, *, count=1, scoped=False):
    owner = sys.modules['monitor.issue_tracker_spreadsheet_owner']
    global_journal = sys.modules['monitor.issue_tracker_global_attempt_journal']
    with tempfile.TemporaryDirectory(prefix='req7-retained-inventory-') as temporary:
        root = Path(temporary).resolve()
        parent = root / 'var/lib/http-ztp-container/issue-tracker'
        parent.mkdir(parents=True, mode=0o700)
        with (scoped_fixture(root, owner) if scoped else fixture(root)), owner.spreadsheet_owner(binding()) as token:
            value = unit()
            global_journal.prepare_global_unit(token, binding(), value)
            for _ in range(count):
                global_journal.record_global_attempt_intent(token, binding(), value)
            yield root, parent, token, value, global_journal


@contextmanager
def business_originals():
    """Actual original enrollment/History/business, no socket or read receipt."""
    from test_cases.test_req7_history_preread_journal import Req7BusinessPrereadJournalDirectTests
    case = Req7BusinessPrereadJournalDirectTests(); case.setUp()
    try:
        with fixture(case.root), case.owner.spreadsheet_owner(binding()) as token:
            case.initialize(token); case.prepare(token)
            case.global_journal.record_global_attempt_intent(token, binding(), case.value)
            yield case.root, case.store.parent, token, case.value
    finally:
        case.doCleanups()


class RetainedInventoryOriginalTests(unittest.TestCase):
    def test_reused_original_descriptor_is_not_closed_as_owned_on_hold(self):
        module = load()
        for kind in ('file', 'directory'):
            with self.subTest(kind=kind), originals(self) as (root, parent, token, _value, _global):
                foreign = root / 'foreign-still-owned-by-consumer'
                foreign.write_bytes(b'foreign-owned-descriptor\n'); foreign.chmod(0o600)
                capture = {}; original_open = os.open
                target = 'WIRE' if kind == 'file' else STEM + '.journal'
                def opening(name, flags, *args, **kwargs):
                    fd = original_open(name, flags, *args, **kwargs)
                    if name == target:
                        capture.setdefault('original', fd)
                    return fd
                foreign_fd = None
                try:
                    with mock.patch.object(module.os, 'open', side_effect=opening):
                        with self.assertRaises(module.RetainedInventoryHold):
                            with module._hold_retained_inventory(token, binding()):
                                os.close(capture['original'])
                                foreign_fd = original_open(str(foreign), os.O_RDONLY | os.O_CLOEXEC)
                    self.assertEqual(capture['original'], foreign_fd)
                    try:
                        actual = os.pread(foreign_fd, 128, 0)
                    except OSError:
                        actual = None
                    self.assertEqual(b'foreign-owned-descriptor\n', actual,
                        'retained inventory must not close a descriptor reused by its consumer')
                finally:
                    if foreign_fd is not None:
                        try:
                            os.close(foreign_fd)
                        except OSError:
                            pass

    def test_inventory_holds_original_global_bytes_without_new_unit_or_write(self):
        module = load()
        with originals(self, count=2) as (root, parent, token, value, _global):
            before = original_read_files(root)
            with module._hold_retained_inventory(token, binding()) as (seen, verify):
                self.assertEqual(value, seen.unit)
                self.assertEqual(2, seen.attempt_count)
                self.assertEqual(('journal', 'journal-started'), seen.families)
                self.assertFalse(hasattr(seen, 'permit'))
                self.assertFalse(hasattr(seen, 'applied'))
                verify()
            self.assertEqual(before, original_read_files(root))

    def test_unknown_namespace_or_displaced_start_is_hold_and_preserves_every_image(self):
        module = load()
        with originals(self) as (root, parent, token, _value, _global):
            extra = parent / (STEM + '.units')
            extra.mkdir(mode=0o700)
            before = original_read_files(root)
            with self.assertRaises(module.RetainedInventoryHold):
                with module._hold_retained_inventory(token, binding()):
                    pass
            self.assertTrue(extra.is_dir())
            self.assertEqual(before, original_read_files(root))
            extra.rename(parent / 'retained-unclaimed-unit-namespace')
            start = parent / (STEM + '.journal-started')
            start.rename(parent / 'retained-displaced-global-start')
            before = original_read_files(root)
            with self.assertRaises(module.RetainedInventoryHold):
                with module._hold_retained_inventory(token, binding()):
                    pass
            self.assertEqual(before, original_read_files(root))

    def test_consumer_same_byte_rebind_and_new_namespace_are_not_adopted(self):
        module = load()
        for change in ('wire-rebind', 'namespace-added'):
            with self.subTest(change=change), originals(self) as (root, parent, token, _value, _global):
                with self.assertRaises(module.RetainedInventoryHold):
                    with module._hold_retained_inventory(token, binding()):
                        if change == 'wire-rebind':
                            wire = parent / (STEM + '.journal') / 'WIRE'
                            saved = wire.read_bytes()
                            wire.rename(wire.with_name('retained-original-wire'))
                            wire.write_bytes(saved); wire.chmod(0o600)
                        else:
                            (parent / (STEM + '.metadata')).mkdir(mode=0o700)
                self.assertTrue((parent / (STEM + '.journal')).is_dir())


class GlobalOriginalOwnedFdTests(unittest.TestCase):
    """Native original-scope cleanup must not close another consumer's FD."""
    def global_module(self):
        load_owner()
        path = SOURCE.with_name('issue_tracker_global_attempt_journal.py')
        spec = importlib.util.spec_from_file_location('monitor.issue_tracker_global_attempt_journal', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        import monitor
        monitor.issue_tracker_global_attempt_journal = module
        return module

    def test_recycled_original_file_and_directory_fds_remain_with_the_new_consumer(self):
        from types import SimpleNamespace
        for target in ('WIRE', STEM + '.journal'):
            with self.subTest(target=target):
                module = self.global_module()
                with originals(self) as (root, parent, token, value, _global):
                    foreign = root / 'independent-consumer-file'
                    foreign.write_bytes(b'independent-consumer-original\n'); foreign.chmod(0o600)
                    before = original_read_files(root)
                    captured = []; original_open = os.open
                    facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
                    def opening(name, flags, *args, **kwargs):
                        fd = original_open(name, flags, *args, **kwargs)
                        if name == target: captured.append(fd)
                        return fd
                    facade.open = opening
                    borrowed = None; entered = False
                    try:
                        # Directory acquisition lives in local._directory;
                        # delegate native FDs while retaining this fixture's
                        # synthetic root metadata (no root access/proof).
                        with mock.patch.object(module, 'os', facade), \
                                mock.patch.object(module.local, 'os', facade), \
                                self.assertRaises(module.GlobalAttemptHold):
                            with module._hold_original_global_unit(token, binding()) as (_unit, _seen, verify):
                                entered = True
                                borrowed = captured[0]
                                os.close(borrowed)
                                allocated = original_open(foreign, os.O_RDONLY | os.O_CLOEXEC)
                                if allocated != borrowed:
                                    os.dup2(allocated, borrowed); os.close(allocated)
                                self.assertEqual((foreign.stat().st_dev, foreign.stat().st_ino),
                                                 (os.fstat(borrowed).st_dev, os.fstat(borrowed).st_ino))
                                verify()
                        self.assertTrue(entered, 'the actual original GLOBAL scope must yield before the fault')
                        try: observed = os.pread(borrowed, 64, 0)
                        except OSError: observed = None
                        self.assertEqual(b'independent-consumer-original\n', observed,
                                         'scope cleanup must not close a recycled foreign object')
                        self.assertEqual(before, original_read_files(root))
                    finally:
                        if borrowed is not None:
                            try: os.close(borrowed)
                            except OSError: pass

    def test_changed_original_bytes_still_close_the_owned_file_after_hold(self):
        from types import SimpleNamespace
        module = self.global_module()
        with originals(self) as (root, parent, token, value, _global):
            captured = []; original_open = os.open
            facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
            def opening(name, flags, *args, **kwargs):
                fd = original_open(name, flags, *args, **kwargs)
                if name == 'WIRE': captured.append(fd)
                return fd
            facade.open = opening
            wire = parent / (STEM + '.journal') / 'WIRE'
            old_inode = wire.stat().st_ino
            entered = False
            with mock.patch.object(module, 'os', facade), self.assertRaises(module.GlobalAttemptHold):
                with module._hold_original_global_unit(token, binding()) as (_unit, _seen, verify):
                    entered = True
                    with wire.open('r+b') as changing:
                        changing.write(b'independently-invalid-wire'); changing.flush(); os.fsync(changing.fileno())
                    verify()
            self.assertTrue(entered, 'the actual original GLOBAL scope must yield before the fault')
            with self.assertRaises(OSError): os.fstat(captured[0])
            self.assertEqual(old_inode, wire.stat().st_ino)


class CompletionStartOwnedFdTests(unittest.TestCase):
    """Actual original reader cleanup; no socket, COMPLETE or new authority."""
    def completion_module(self):
        load_owner(); load_global()
        path = SOURCE.with_name('issue_tracker_remote_history_match.py')
        spec = importlib.util.spec_from_file_location('monitor.issue_tracker_remote_history_match', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        import monitor
        monitor.issue_tracker_remote_history_match = module
        return module

    def test_recycled_completion_start_reader_fd_stays_owned_by_its_new_consumer(self):
        from types import SimpleNamespace
        module = self.completion_module()
        with originals(self, scoped=True) as (root, parent, token, value, _global):
            leaf = STEM + '.completion-started'
            raw = b'independent-retained-completion-start\n'
            _owner, parent_fd, _name, _base = _global._inputs(token, binding(), value)
            identity = module._write_completion_start(parent_fd, leaf, raw)
            foreign = root / 'consumer-original'; foreign.write_bytes(b'consumer-original-bytes\n'); foreign.chmod(0o600)
            before = original_read_files(root)
            capture = []; original_open = os.open
            facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
            def opening(name, flags, *args, **kwargs):
                fd = original_open(name, flags, *args, **kwargs)
                if name == leaf:
                    capture.append(fd)
                return fd
            facade.open = opening
            borrowed = None
            try:
                with mock.patch.object(module, 'os', facade), self.assertRaises(
                        (module.RemoteHistoryHold, module.global_journal.journal.AttemptJournalHold)):
                    with module._hold_completion_start(token, binding(), value,
                                                       expected=raw, expected_identity=identity) as (verify, _identity):
                        self.assertEqual(1, len(capture))
                        borrowed = capture[0]
                        os.close(borrowed)
                        allocated = original_open(foreign, os.O_RDONLY | os.O_CLOEXEC)
                        if allocated != borrowed:
                            os.dup2(allocated, borrowed); os.close(allocated)
                        self.assertEqual((foreign.stat().st_dev, foreign.stat().st_ino),
                                         (os.fstat(borrowed).st_dev, os.fstat(borrowed).st_ino))
                        verify()
                try:
                    observed = os.pread(borrowed, 64, 0)
                except OSError:
                    observed = None
                self.assertEqual(b'consumer-original-bytes\n', observed,
                                 'a recycled descriptor number is not the completion reader\'s owned object')
                self.assertEqual(before, original_read_files(root))
            finally:
                if borrowed is not None:
                    try: os.close(borrowed)
                    except OSError: pass

    def test_changed_original_completion_reader_fd_is_closed_after_hold(self):
        from types import SimpleNamespace
        module = self.completion_module()
        with originals(self, scoped=True) as (root, parent, token, value, _global):
            leaf = STEM + '.completion-started'; raw = b'independent-retained-completion-start\n'
            _owner, parent_fd, _name, _base = _global._inputs(token, binding(), value)
            identity = module._write_completion_start(parent_fd, leaf, raw)
            capture = []; original_open = os.open
            facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
            def opening(name, flags, *args, **kwargs):
                fd = original_open(name, flags, *args, **kwargs)
                if name == leaf: capture.append(fd)
                return fd
            facade.open = opening
            with mock.patch.object(module, 'os', facade), self.assertRaises(
                    (module.RemoteHistoryHold, module.global_journal.journal.AttemptJournalHold)):
                with module._hold_completion_start(token, binding(), value,
                                                   expected=raw, expected_identity=identity) as (verify, _identity):
                    self.assertEqual(1, len(capture))
                    with (parent / leaf).open('r+b') as changing:
                        changing.write(b'changed-original'); changing.flush(); os.fsync(changing.fileno())
                    verify()
            with self.assertRaises(OSError): os.fstat(capture[0])
            self.assertEqual(identity[1], (parent / leaf).stat().st_ino)


class RetainedInventoryWorkflowTests(unittest.TestCase):
    def test_actual_owned_complete_replays_original_proof_without_applied_or_new_authority(self):
        from contextlib import ExitStack
        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests
        from test_cases.test_req7_enrollment_journal import load as load_enrollment
        from test_cases.test_req7_history_preread_journal import load as load_preread
        # Earlier native FD tests deliberately reload the canonical owner and
        # GLOBAL modules. Acquire dependent fixture aliases before issuing any
        # owner token; an old registry cannot validate a newer issued token.
        enrolled = load_enrollment(); preread = load_preread()
        self.assertIs(enrolled.ownership, sys.modules['monitor.issue_tracker_spreadsheet_owner'])
        self.assertIs(preread.ownership, sys.modules['monitor.issue_tracker_spreadsheet_owner'])
        self.assertIs(preread.global_journal, sys.modules['monitor.issue_tracker_global_attempt_journal'])
        case = Req7OwnedHistoryMatchWorkflowTests(); case.setUp()
        try:
            with ExitStack() as scope:
                _writer, token, bound, value = case.completed(scope)
                module = load(reset_support=False)
                before = original_read_files(case.root)
                with module._hold_retained_inventory(token, bound) as (seen, verify):
                    self.assertEqual(value, seen.unit)
                    self.assertEqual(1, seen.attempt_count)
                    self.assertEqual(('completion', 'completion-started', 'enrollment',
                                      'history', 'journal', 'journal-started'), seen.families)
                    self.assertIn(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                                  + '.completion/HISTORY-RAW',
                                  {name for name, _identity, _sha in seen.originals})
                    for authority in ('applied', 'permit', 'admission', 'sent'):
                        self.assertFalse(hasattr(seen, authority))
                    verify()
                self.assertEqual(before, original_read_files(case.root))
                from monitor import issue_tracker_global_attempt_journal as current
                retained = current.inspect_global_unit(token, bound, value)
                self.assertEqual((1, 'UNKNOWN'), (retained.attempt_count, retained.outcome))
        finally:
            case.doCleanups()

    def test_complete_file_shapes_cannot_replace_original_proof_replay(self):
        canonical = lambda value: (json.dumps(value, ensure_ascii=False, sort_keys=True,
                                             separators=(',', ':')) + '\n').encode()
        for change in ('foreign-unit', 'empty-match', 'fake-raw', 'applied-label'):
            with self.subTest(change=change):
                with business_originals() as (root, parent, token, value):
                    module = load(reset_support=False)
                    folder = parent / (STEM + '.completion')
                    folder.mkdir(mode=0o700)
                    header = {'schema_version': 1, 'unit_id': value.unit_id,
                              'matched': {}, 'responses': {}}
                    if change == 'foreign-unit':
                        header['unit_id'] = 'f' * 64
                    raw = canonical(header)
                    (folder / 'HEADER').write_bytes(raw)
                    marker = {'schema_version': 1, 'unit_id': header['unit_id'],
                              'header_sha256': hashlib.sha256(raw).hexdigest(),
                              'state': ('APPLIED' if change == 'applied-label'
                                        else 'COMPLETE-PRESENT-NOT-APPLIED')}
                    (folder / 'COMPLETE').write_bytes(canonical(marker))
                    for name in ('HEADERS-RAW', 'HISTORY-RAW', 'IDENTITY-RAW', 'METADATA-RAW'):
                        (folder / name).write_bytes(b'{"synthetic":"not-original-proof"}\n'
                                                   if change == 'fake-raw' else b'{}\n')
                    (parent / (STEM + '.completion-started')).write_bytes(canonical({
                        'schema_version': 1, 'unit_id': value.unit_id,
                        'state': 'COMPLETION-STARTED-NOT-APPLIED'}))
                    for path in folder.iterdir():
                        path.chmod(0o600)
                    (parent / (STEM + '.completion-started')).chmod(0o600)
                    before = original_read_files(root)
                    with self.assertRaises(module.RetainedInventoryHold):
                        with module._hold_retained_inventory(token, binding()):
                            pass
                    self.assertEqual(before, original_read_files(root),
                                     'unproved completion remains intact, never repaired or APPLIED')

    def test_original_business_images_bind_all_operations_including_noop(self):
        from test_cases.test_req7_history_preread_journal import Req7BusinessPrereadJournalDirectTests
        case = Req7BusinessPrereadJournalDirectTests(); case.setUp()
        module = load(reset_support=False)
        try:
            with fixture(case.root), case.owner.spreadsheet_owner(binding()) as token:
                case.initialize(token); case.prepare(token)
                case.global_journal.record_global_attempt_intent(token, binding(), case.value)
                before = original_read_files(case.root)
                with module._hold_retained_inventory(token, binding()) as (seen, verify):
                    self.assertEqual(case.value, seen.unit)
                    self.assertEqual(1, seen.attempt_count)
                    self.assertEqual(('business', 'enrollment', 'history', 'journal', 'journal-started'), seen.families)
                    self.assertIn(STEM + '.business/MANIFEST',
                                  {name for name, _identity, _sha in seen.originals})
                    self.assertFalse(hasattr(seen, 'admission'))
                    verify()
                self.assertEqual(before, original_read_files(case.root))
        finally:
            case.doCleanups()

    def test_business_coherent_marker_cannot_replace_frozen_preimage_or_noop_coverage(self):
        from test_cases.test_req7_history_preread_journal import Req7BusinessPrereadJournalDirectTests
        canonical = lambda value: (json.dumps(value, ensure_ascii=False, sort_keys=True,
                                             separators=(',', ':')) + '\n').encode()
        for change in ('foreign-unit', 'foreign-manifest', 'raw-digest', 'omitted-noop', 'wrong-envelope-operation'):
            with self.subTest(change=change):
                case = Req7BusinessPrereadJournalDirectTests(); case.setUp()
                module = load(reset_support=False)
                try:
                    with fixture(case.root), case.owner.spreadsheet_owner(binding()) as token:
                        case.initialize(token); case.prepare(token)
                        case.global_journal.record_global_attempt_intent(token, binding(), case.value)
                        header = json.loads((case.store / 'HEADER').read_bytes())
                        if change == 'foreign-unit':
                            header['unit_id'] = 'e' * 64
                        elif change == 'foreign-manifest':
                            (case.store / 'MANIFEST').write_bytes(canonical({'schema_version': 1, 'operations': []}))
                        elif change == 'raw-digest':
                            header['source_sha256'] = 'e' * 64
                        elif change == 'omitted-noop':
                            header['operations_retained'] = 1
                            header['noop_operations'] = 0
                        else:
                            image = json.loads((case.store / 'BUSINESS-RAW').read_bytes())
                            image['operations'][0]['operation_id'] = 'switch:foreign'
                            raw = canonical(image)
                            (case.store / 'BUSINESS-RAW').write_bytes(raw)
                            header['source_sha256'] = hashlib.sha256(raw).hexdigest()
                        raw = canonical(header)
                        (case.store / 'HEADER').write_bytes(raw)
                        (case.store / 'INITIALIZED').write_bytes(canonical({
                            'schema_version': 1, 'state': 'INITIALIZED',
                            'header_sha256': hashlib.sha256(raw).hexdigest()}))
                        before = original_read_files(case.root)
                        with self.assertRaises(module.RetainedInventoryHold):
                            with module._hold_retained_inventory(token, binding()):
                                pass
                        self.assertEqual(before, original_read_files(case.root))
                finally:
                    case.doCleanups()

    def test_original_dispatch_consumption_prefix_is_bound_without_send_authority(self):
        module = load()
        with originals(self, scoped=True) as (root, parent, token, value, global_journal):
            project = root / 'local-project'; project.mkdir(mode=0o700)
            publication = project / 'publication'; publication.mkdir(mode=0o700)
            module.local.create_local_commit_store(project, publication)
            with module.local.writer_owner(project, publication) as writer:
                for count in range(1, 7):
                    if count > 1:
                        global_journal.record_global_attempt_intent(token, binding(), value)
                    with global_journal._hold_counted_original_wire(writer, token, binding(), value):
                        pass
                    before = original_read_files(root)
                    with module._hold_retained_inventory(token, binding()) as (seen, verify):
                        self.assertEqual(count, seen.attempt_count)
                        self.assertEqual(('dispatch', 'journal', 'journal-started'), seen.families)
                        self.assertIn(STEM + '.dispatch/CLAIM-' + str(count),
                                      {name for name, _identity, _sha in seen.originals})
                        self.assertFalse(hasattr(seen, 'permit'))
                        self.assertFalse(hasattr(seen, 'sent'))
                        verify()
                    self.assertEqual(before, original_read_files(root))

    def test_coherent_dispatch_claim_cannot_replace_original_unit_intent_or_fd_identity(self):
        canonical = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        for change in ('foreign-unit', 'foreign-wire-inode', 'foreign-intent', 'false-sent'):
            with self.subTest(change=change):
                module = load()
                with originals(self, scoped=True) as (root, parent, token, value, global_journal):
                    project = root / 'local-project'; project.mkdir(mode=0o700)
                    publication = project / 'publication'; publication.mkdir(mode=0o700)
                    module.local.create_local_commit_store(project, publication)
                    with module.local.writer_owner(project, publication) as writer:
                        with global_journal._hold_counted_original_wire(writer, token, binding(), value):
                            pass
                    folder = parent / (STEM + '.dispatch')
                    header = json.loads((folder / 'HEADER').read_bytes())
                    claim = json.loads((folder / 'CLAIM-1').read_bytes())
                    if change == 'foreign-unit':
                        header['unit_id'] = claim['unit_id'] = 'e' * 64
                    elif change == 'foreign-wire-inode':
                        header['wire_identity'][1] += 1
                    elif change == 'foreign-intent':
                        claim['original_intent_sha256'] = 'e' * 64
                    else:
                        claim['outcome'] = 'SENT'
                    raw = canonical(header)
                    claim['previous_sha256'] = hashlib.sha256(raw).hexdigest()
                    (folder / 'HEADER').write_bytes(raw)
                    (folder / 'INITIALIZED').write_bytes(canonical({
                        'schema_version': 1, 'state': 'INITIALIZED',
                        'header_sha256': hashlib.sha256(raw).hexdigest()}))
                    (folder / 'CLAIM-1').write_bytes(canonical(claim))
                    before = original_read_files(root)
                    with self.assertRaises(module.RetainedInventoryHold):
                        with module._hold_retained_inventory(token, binding()):
                            pass
                    self.assertEqual(before, original_read_files(root))

    def test_coherent_marker_does_not_bind_foreign_history_or_nonce_to_original_unit(self):
        from test_cases.test_req7_remote_history_match import Req7RemoteHistoryMatchDirectTests
        for change in ('foreign-history-unit', 'false-history-capacity', 'foreign-enrollment-nonce'):
            with self.subTest(change=change):
                case = Req7RemoteHistoryMatchDirectTests(); case.setUp()
                module = load(reset_support=False)
                try:
                    with fixture(case.root), case.owner.spreadsheet_owner(binding()) as token:
                        case.prepare(token)
                        folder = case.state / (STEM + ('.enrollment' if change == 'foreign-enrollment-nonce' else '.history'))
                        header = json.loads((folder / 'HEADER').read_bytes())
                        canonical = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
                        if change == 'foreign-enrollment-nonce':
                            rows = json.loads((folder / 'NONCES').read_bytes())
                            rows[0][2] = 'e' * 64
                            nonce_raw = canonical(rows)
                            (folder / 'NONCES').write_bytes(nonce_raw)
                            header['nonces_sha256'] = hashlib.sha256(nonce_raw).hexdigest()
                        elif change == 'foreign-history-unit':
                            header['unit_id'] = 'e' * 64
                        else:
                            header['row_count'] += 1
                        header_raw = canonical(header)
                        (folder / 'HEADER').write_bytes(header_raw)
                        (folder / 'INITIALIZED').write_bytes(canonical({
                            'schema_version': 1, 'state': 'INITIALIZED',
                            'header_sha256': hashlib.sha256(header_raw).hexdigest()}))
                        before = original_read_files(case.root)
                        with self.assertRaises(module.RetainedInventoryHold):
                            with module._hold_retained_inventory(token, binding()):
                                pass
                        self.assertEqual(before, original_read_files(case.root))
                finally:
                    case.doCleanups()

    def test_retained_initialization_and_raw_digest_links_cannot_be_replaced_by_shape(self):
        from test_cases.test_req7_remote_history_match import Req7RemoteHistoryMatchDirectTests
        for change in ('enrollment-nonces', 'history-raw', 'history-header', 'history-marker'):
            with self.subTest(change=change):
                case = Req7RemoteHistoryMatchDirectTests(); case.setUp()
                module = load(reset_support=False)
                try:
                    with fixture(case.root), case.owner.spreadsheet_owner(binding()) as token:
                        case.prepare(token)
                        history = case.state / (STEM + '.history')
                        if change == 'enrollment-nonces':
                            path = case.state / (STEM + '.enrollment') / 'NONCES'
                            rows = json.loads(path.read_bytes()); rows[0][2] = 'e' * 64
                            path.write_bytes((json.dumps(rows, sort_keys=True, separators=(',', ':')) + '\n').encode())
                        elif change == 'history-raw':
                            path = history / 'HISTORY-RAW'
                            raw = json.loads(path.read_bytes()); raw['independent-unbound-image'] = True
                            path.write_bytes((json.dumps(raw, sort_keys=True, separators=(',', ':')) + '\n').encode())
                        elif change == 'history-header':
                            path = history / 'HEADER'
                            header = json.loads(path.read_bytes()); header['source_sha256'] = 'f' * 64
                            path.write_bytes((json.dumps(header, sort_keys=True, separators=(',', ':')) + '\n').encode())
                        else:
                            (history / 'INITIALIZED').write_bytes(b'{}\n')
                        before = original_read_files(case.root)
                        with self.assertRaises(module.RetainedInventoryHold):
                            with module._hold_retained_inventory(token, binding()):
                                pass
                        self.assertEqual(before, original_read_files(case.root))
                finally:
                    case.doCleanups()

    def test_real_enrollment_global_and_history_are_one_held_original_scope(self):
        from test_cases.test_req7_remote_history_match import Req7RemoteHistoryMatchDirectTests
        case = Req7RemoteHistoryMatchDirectTests()
        case.setUp()
        module = load(reset_support=False)
        try:
            with fixture(case.root), case.owner.spreadsheet_owner(binding()) as token:
                case.prepare(token)
                before = original_read_files(case.root)
                with module._hold_retained_inventory(token, binding()) as (seen, verify):
                    self.assertEqual(case.unit, seen.unit)
                    self.assertEqual(1, seen.attempt_count)
                    self.assertEqual(('enrollment', 'history', 'journal', 'journal-started'), seen.families)
                    names = {name for name, _identity, _sha in seen.originals}
                    self.assertIn(STEM + '.enrollment/NONCES', names)
                    self.assertIn(STEM + '.history/HISTORY-RAW', names)
                    self.assertIn(STEM + '.journal/WIRE', names)
                    verify()
                self.assertEqual(before, original_read_files(case.root))
        finally:
            case.doCleanups()

    def test_history_partial_or_same_byte_replacement_never_survives_inventory(self):
        from test_cases.test_req7_remote_history_match import Req7RemoteHistoryMatchDirectTests
        for change in ('partial-history', 'rebind-history'):
            with self.subTest(change=change):
                case = Req7RemoteHistoryMatchDirectTests(); case.setUp()
                module = load(reset_support=False)
                try:
                    with fixture(case.root), case.owner.spreadsheet_owner(binding()) as token:
                        case.prepare(token)
                        history = case.state / (STEM + '.history')
                        if change == 'partial-history':
                            (history / 'INITIALIZED').rename(case.state / 'retained-history-marker')
                            before = original_read_files(case.root)
                            with self.assertRaises(module.RetainedInventoryHold):
                                with module._hold_retained_inventory(token, binding()):
                                    pass
                            self.assertEqual(before, original_read_files(case.root))
                        else:
                            with self.assertRaises(module.RetainedInventoryHold):
                                with module._hold_retained_inventory(token, binding()):
                                    raw = history / 'HISTORY-RAW'; saved = raw.read_bytes()
                                    raw.rename(case.state / 'retained-history-raw')
                                    raw.write_bytes(saved); raw.chmod(0o600)
                finally:
                    case.doCleanups()


if __name__ == '__main__':
    unittest.main(verbosity=2)
