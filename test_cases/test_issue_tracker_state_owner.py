"""REQ7 S0: one local writer authority for settings and generations.

Only private scratch projects are used. These tests do not grant online
eligibility or send to any Issue Tracker service.
"""

import os
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_state_owner import (
    TrackerStateHold, current_k, initialize_tracker_state, set_k, tracker_writer,
)
from monitor.issue_tracker_local_commit import (
    LocalCommitHold, begin_generation, commit, record_intent,
)


T0 = "2026-09-25T00:00:00Z"
T1 = "2026-09-25T00:01:00Z"
MANIFEST = b'{"operations":[],"schema_version":1}\n'
PREPARED = b"scratch-workbook-projection\n"


class TrackerStateOwnerTests(unittest.TestCase):
    def _assert_local_c6_publication_original(self, mutation=None):
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local, issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_unit_catalog as catalog, issue_tracker_attempt_journal as journal
        self.initialize()
        self.assertEqual(0o755,self.publication.stat().st_mode & 0o777)
        with tracker_writer(self.project,self.publication) as token, ExitStack() as scope:
            owner=local._owner(token)
            sources=(owner.project_fd,owner.root_fd,owner.publication_fd,owner.lock_fd)
            identities=tuple(journal._identity(os.fstat(fd)) for fd in sources)
            held=catalog._Originals();raw=allocation._LocalC6Originals(token,scope)
            scope.callback(raw.close)
            raw.retain(held,projects=((self.project,self.publication.name,sources,identities),))
            raw.verify()
            if mutation is not None:
                original=self.publication.stat().st_ino
                if mutation=='replace':
                    self.publication.rename(self.project/'owned-original-publication')
                    self.publication.mkdir(mode=0o755);self.publication.chmod(0o755)
                    self.assertNotEqual(original,self.publication.stat().st_ino)
                elif mutation=='unsafe-mode':
                    self.publication.chmod(0o777)
                else:self.fail('unknown independent publication fault')
                with self.assertRaises((LocalCommitHold,allocation.SettingsAuditHold)):raw.verify()
                with self.assertRaises((LocalCommitHold,allocation.SettingsAuditHold)):scope.close()
            else:
                scope.close()
                self.assertEqual(identities[2][:5],journal._identity(self.publication.stat())[:5])
            self.assertEqual([],raw.slots)

    def test_local_c6_raw_handoff_accepts_original_publication_0755(self):
        self._assert_local_c6_publication_original()

    def test_local_c6_raw_handoff_rejects_replaced_publication_0755(self):
        self._assert_local_c6_publication_original('replace')

    def test_local_c6_raw_handoff_rejects_world_writable_publication(self):
        self._assert_local_c6_publication_original('unsafe-mode')

    def test_local_c6_raw_sheet_tail_retains_lock_after_revoke_and_checks_old_receipt(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local, issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_unit_catalog as catalog, issue_tracker_spreadsheet_owner as ownership
        from test_cases.test_req7_spreadsheet_owner import scoped_fixture, binding
        # Earlier real native fixtures reload canonical owner registries.
        # Refresh references BEFORE issuance; production checks stay strict.
        from test_cases.test_req7_settings_audit_allocation import load as load_allocation
        allocation=load_allocation()
        self.assertIs(allocation.ownership,ownership)
        self.initialize()
        global_root=self.project.parent/'local-sheet-originals'; global_root.mkdir(mode=0o700)
        (global_root/'var/lib/http-ztp-container/issue-tracker').mkdir(parents=True,mode=0o700)
        bound=binding();native_sheet=ownership.spreadsheet_owner
        with tracker_writer(self.project,self.publication) as token,scoped_fixture(global_root,ownership):
            generation=begin_generation(token,MANIFEST);record_intent(token,generation,PREPARED);commit(token,generation)
            receipt=self.project/'.tracker/generations'/generation.generation_id/'RECEIPT'
            old=(receipt.stat().st_ino,receipt.read_bytes());observed=[]
            @contextmanager
            def actual_sheet_last_finalizer():
                with native_sheet(bound) as sheet:
                    yield sheet
                self.assertEqual({},ownership._ACTIVE)
                with self.assertRaises(ownership.SpreadsheetOwnerHold):
                    with native_sheet(bound):self.fail('overlapped original LOCK lost exclusion')
                receipt.rename(self.project.parent/'retained-sheet-tail-receipt')
                receipt.write_bytes(old[1]);receipt.chmod(0o600);observed.append(True)
            with self.assertRaises(allocation.SettingsAuditHold):
                with ExitStack() as scope:
                    raw=allocation._LocalC6Originals(token,scope);scope.callback(raw.close)
                    sheet=scope.enter_context(actual_sheet_last_finalizer())
                    raw.sheet,raw.bound=sheet,bound
                    raw.retain_sheet_originals(ownership._validated_owner(sheet,bound))
                    held=catalog._Originals();parent=held.directory(local._owner(token).root_fd,'generations')
                    folder=held.directory(parent,generation.generation_id);held.file(folder,'RECEIPT',16384)
                    try:raw.retain(held)
                    finally:held.close()
                    raw.verify()
            self.assertEqual([True],observed);self.assertEqual([],raw.slots)
            self.assertEqual(old[1],receipt.read_bytes());self.assertNotEqual(old[0],receipt.stat().st_ino)
            with native_sheet(bound) as new_sheet:ownership._validated_owner(new_sheet,bound)

    def test_local_c6_raw_last_finalizer_rejects_same_bytes_receipt_replacement(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local, issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_unit_catalog as catalog
        self.initialize(); replaced=[]
        with tracker_writer(self.project,self.publication) as token:
            generation=begin_generation(token,MANIFEST);record_intent(token,generation,PREPARED);commit(token,generation)
            receipt=self.project/'.tracker/generations'/generation.generation_id/'RECEIPT'
            original=(receipt.stat().st_ino,receipt.read_bytes())
            def finalizer():
                receipt.rename(self.root/'retained-receipt-original')
                receipt.write_bytes(original[1]);receipt.chmod(0o600);replaced.append(True)
            with self.assertRaises(allocation.SettingsAuditHold):
                with ExitStack() as scope:
                    held=catalog._Originals();parent=held.directory(local._owner(token).root_fd,'generations')
                    folder=held.directory(parent,generation.generation_id);held.file(folder,'RECEIPT',16384)
                    raw=allocation._LocalC6Originals(token,scope);scope.callback(raw.close)
                    try:raw.retain(held)
                    finally:held.close()
                    scope.callback(finalizer)
                    raw.verify()
            self.assertEqual([True],replaced);self.assertEqual(original[1],receipt.read_bytes())
            self.assertNotEqual(original[0],receipt.stat().st_ino)
            self.assertEqual([],raw.slots)

    def test_local_c6_generation_first_recipient_stat_failure_closes_its_original_fd(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local, issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_unit_catalog as catalog
        self.initialize(); opened=[]; native=local._generation_fd; native_stat=os.fstat
        primary=OSError('independent recipient first stat refusal')
        with tracker_writer(self.project,self.publication) as token, ExitStack() as scope:
            held=catalog._Originals(); held.directory(local._owner(token).root_fd,'generations')
            raw=allocation._LocalC6Originals(token,scope); scope.callback(raw.close)
            try:raw.retain(held)
            finally:held.close()
            generation=begin_generation(token,MANIFEST)
            def acquire(*args,**kwargs):
                result=native(*args,**kwargs)
                opened.append(result[0] if isinstance(result,tuple) else result)
                return result
            refused=[]
            def inspecting(fd):
                if opened and fd==opened[-1] and not refused:
                    refused.append(fd); raise primary
                return native_stat(fd)
            try:
                with mock.patch.object(local,'_generation_fd',side_effect=acquire),mock.patch.object(os,'fstat',side_effect=inspecting):
                    with self.assertRaises(OSError) as caught:raw.verify()
                self.assertIs(primary,caught.exception);self.assertEqual(1,len(opened))
                with self.assertRaises(OSError):native_stat(opened[0])
            finally:
                # Reap only a leaked original after assertions, to isolate RED.
                for fd in opened:
                    try:os.close(fd)
                    except OSError:pass

    def test_fixed_local_c6_owner_without_delivery_cannot_excuse_a_missing_projection(self):
        from monitor import issue_tracker_state_owner as state
        self.initialize()
        projection=self.project/'.tracker/settings/outbox/0.json'
        projection.rename(self.root/'owned-undelivered-projection')
        before={str(p):(p.stat().st_ino,p.read_bytes()) for p in self.project.rglob('*') if p.is_file()}
        with self.assertRaises(TrackerStateHold):
            with state.tracker_local_c6_writer(self.project,self.publication):
                self.fail('absent undelivered projection yielded local C6')
        self.assertEqual(before,{str(p):(p.stat().st_ino,p.read_bytes()) for p in self.project.rglob('*') if p.is_file()})
        self.assertEqual({},state._LOCAL_C6_READ_CONTEXT)

    def test_local_c6_read_refuses_an_unissued_context(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        self.initialize()
        with tracker_writer(self.project,self.publication) as token:
            with self.assertRaises(allocation.SettingsAuditHold):
                allocation._read_completed_local_c6_k(token,object())
            self.assertEqual((0,3),(current_k(token).revision,current_k(token).k))

    def test_local_c6_raw_handoff_keeps_old_images_and_accepts_only_real_writer_generation(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_settings_audit_allocation as allocation
        from monitor import issue_tracker_unit_catalog as catalog
        self.initialize()
        with tracker_writer(self.project,self.publication) as token, ExitStack() as scope:
            first=begin_generation(token,MANIFEST)
            record_intent(token,first,PREPARED)
            commit(token,first)
            from monitor.issue_tracker_local_commit import _owner
            held=catalog._Originals()
            generations=held.directory(_owner(token).root_fd,'generations')
            old=held.directory(generations,first.generation_id)
            for name in ('STATE','MANIFEST','INTENT','RECEIPT'):
                held.file(old,name,16384)
            raw=allocation._LocalC6Originals(token,scope);scope.callback(raw.close)
            try:raw.retain(held)
            finally:held.close()
            second=begin_generation(token,MANIFEST)
            record_intent(token,second,PREPARED+b'changed\n')
            commit(token,second)
            raw.verify()
            # An unissued directory is never a writer-produced addition.
            extra=self.project/'.tracker/generations'/('gen-00000000000000000003-'+'a'*32)
            extra.mkdir(mode=0o700)
            with self.assertRaises(allocation.SettingsAuditHold):raw.verify()
            # The stronger last raw check must also refuse the unexplained
            # directory, while still conditionally closing every owned slot.
            with self.assertRaises(allocation.SettingsAuditHold):scope.close()
            self.assertEqual([],raw.slots)

    def test_native_settings_context_unregistered_object_never_grants_missing_projections(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        self.initialize()
        with tracker_writer(self.project,self.publication) as token:
            before={str(path.relative_to(self.project)):path.read_bytes()
                for path in self.project.rglob('*') if path.is_file()}
            with self.assertRaises(allocation.SettingsAuditHold):
                allocation._read_native_completed_k(token,object())
            self.assertEqual(before,{str(path.relative_to(self.project)):path.read_bytes()
                for path in self.project.rglob('*') if path.is_file()})

    def _assert_settings_first_read_failure_revokes(self, primary):
        from monitor import issue_tracker_state_owner as state
        self.initialize(); native=state.current_k; tokens=[]
        before={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        def interrupt_first_read(token, **kwargs):
            self.assertIn(token,state._COMPLETED_ORIGINAL_GUARDS)
            self.assertEqual((0,3),(native(token,**kwargs).revision,native(token,**kwargs).k))
            tokens.append(token)
            raise primary
        try:
            with mock.patch.object(state,'current_k',side_effect=interrupt_first_read):
                with self.assertRaises(type(primary)) as caught:
                    with state.tracker_settings_writer(self.project,self.publication):
                        self.fail('initial read failure yielded a settings writer')
            self.assertIs(primary,caught.exception)
            self.assertEqual(1,len(tokens))
            with self.assertRaises(TrackerStateHold): native(tokens[0])
            self.assertEqual(before,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
            self.assertEqual({},state._COMPLETED_READ_CONTEXT)
            self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        finally:
            # Isolate a failing RED from subsequent cases, after the original
            # contract assertions; this does not perform production cleanup.
            for token in tokens:
                state._COMPLETED_READ_CONTEXT.pop(token,None)
                state._COMPLETED_ORIGINAL_GUARDS.pop(token,None)

    def test_settings_first_read_keyboard_interrupt_revokes_context(self):
        self._assert_settings_first_read_failure_revokes(KeyboardInterrupt('first read interruption'))

    def test_settings_first_read_system_exit_revokes_context(self):
        self._assert_settings_first_read_failure_revokes(SystemExit('first read exit'))

    def test_settings_first_read_runtime_error_revokes_context(self):
        self._assert_settings_first_read_failure_revokes(RuntimeError('first read caller fault'))

    def test_settings_original_finalizer_failure_is_typed_hold_after_revocation(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_settings_audit_allocation as allocation
        self.initialize(); native=allocation._hold_discovered_completed_settings; tokens=[]
        @contextmanager
        def failure_after_real_scope(token):
            with native(token) as original:
                yield original
            raise ValueError('private original finalizer fault')
        with mock.patch.object(allocation,'_hold_discovered_completed_settings',side_effect=failure_after_real_scope):
            with self.assertRaises(TrackerStateHold):
                with state.tracker_settings_writer(self.project,self.publication) as token:
                    tokens.append(token); self.assertEqual(3,state.current_k(token).k)
        self.assertEqual(1,len(tokens))
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        with self.assertRaises(TrackerStateHold): state.current_k(tokens[0])

    def test_settings_caller_exception_survives_original_finalizer_failure(self):
        from monitor import issue_tracker_state_owner as state,issue_tracker_settings_audit_allocation as allocation
        self.initialize(); native=allocation._hold_discovered_completed_settings
        primary=RuntimeError('independent caller interruption')
        @contextmanager
        def failure_after_real_scope(token):
            try:
                with native(token) as original: yield original
            finally:
                raise ValueError('private original finalizer fault')
        with mock.patch.object(allocation,'_hold_discovered_completed_settings',side_effect=failure_after_real_scope):
            with self.assertRaises(RuntimeError) as caught:
                with state.tracker_settings_writer(self.project,self.publication): raise primary
        self.assertIs(primary,caught.exception)
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)

    def test_settings_discovery_never_bootstraps_absent_state(self):
        from monitor import issue_tracker_state_owner as state
        before={str(p.relative_to(self.project)):p.read_bytes() for p in self.project.rglob('*') if p.is_file()}
        with self.assertRaises(TrackerStateHold):
            with state.tracker_settings_writer(self.project,self.publication):
                self.fail('settings discovery must not initialize a missing tracker')
        self.assertFalse(self.root.exists())
        self.assertEqual(before,{str(p.relative_to(self.project)):p.read_bytes() for p in self.project.rglob('*') if p.is_file()})

    def test_settings_discovery_without_delivery_keeps_one_actual_lk_p_and_pending_k(self):
        from monitor import issue_tracker_state_owner as state
        self.initialize()
        with state.tracker_settings_writer(self.project,self.publication) as token:
            self.assertEqual((0,3),(current_k(token).revision,current_k(token).k))
            self.assertNotIn(token,state._COMPLETED_READ_CONTEXT)
            self.assertIn(token,state._COMPLETED_ORIGINAL_GUARDS)
            with self.assertRaises(TrackerStateHold):
                with tracker_writer(self.project,self.publication):
                    self.fail('a second writer acquired the same project')
            changed=set_k(token,new_k=5,actor='operator:fixture',recorded_at=T1,
                          request_id='discovered-ordinary-k',expected_revision=0)
            self.assertEqual((1,5),(changed.revision,changed.k))
            self.assertTrue((self.root/'settings/outbox/0.json').is_file())
            self.assertTrue((self.root/'settings/outbox/1.json').is_file())
        self.assertEqual({},state._COMPLETED_READ_CONTEXT)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        with self.assertRaises(TrackerStateHold): current_k(token)


    def test_completed_writer_rejects_partial_or_forged_context_without_mutation(self):
        self.initialize()
        before={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        for context in ({'completed_binding':object()},
                        {'completed_unit':object()},
                        {'completed_binding':object(),'completed_unit':object()}):
            with self.subTest(context_keys=tuple(context)),self.assertRaises(TrackerStateHold):
                with tracker_writer(self.project,self.publication,**context):
                    self.fail('unproved writer became usable')
        self.assertEqual(before,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        with tracker_writer(self.project,self.publication) as token:
            self.assertEqual((0,3),(current_k(token).revision,current_k(token).k))

    def test_qualified_k_context_cannot_be_partial_or_replace_actual_owners(self):
        self.initialize()
        with tracker_writer(self.project,self.publication) as token:
            before={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
            for context in ({'spreadsheet_token':object()},
                            {'binding':object(),'completed_unit':object()},
                            {'spreadsheet_token':object(),'binding':object(),'completed_unit':object()}):
                with self.subTest(context_keys=tuple(context)),self.assertRaises(TrackerStateHold):
                    current_k(token,**context)
            self.assertEqual((0,3),(current_k(token).revision,current_k(token).k))
            self.assertEqual(before,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tracker-shared-owner-")
        self.addCleanup(self.temp.cleanup)
        base = Path(os.path.realpath(self.temp.name))
        self.project = base / "project"
        self.project.mkdir(mode=0o755)
        self.project.chmod(0o755)
        self.publication = self.project / "99-output-monitor"
        self.publication.mkdir(mode=0o755)
        self.publication.chmod(0o755)
        self.root = self.project / ".tracker"

    def initialize(self):
        return initialize_tracker_state(
            self.project, self.publication, initialized_at=T0,
            acquisition_id="acquisition-0",
        )

    def test_actual_style_paths_share_one_private_root_lock_and_k_zero(self):
        state = self.initialize()
        self.assertEqual((0, 3), (state.revision, state.k))
        self.assertEqual(0, self.root.stat().st_mode & 0o077)
        self.assertEqual(0, (self.root / "LOCK").stat().st_mode & 0o077)
        self.assertEqual({"LOCK", "INITIALIZED", "settings", "generations", "quarantine"},
                         {child.name for child in self.root.iterdir()})
        self.assertEqual(["LOCK"], [child.name for child in self.root.iterdir()
                                    if child.name == "LOCK"])
        with tracker_writer(self.project, self.publication) as token:
            self.assertEqual((0, 3), (current_k(token).revision, current_k(token).k))
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PREPARED)
            receipt = commit(token, generation)
            self.assertEqual(generation.generation_id, receipt.generation_id)
            changed = set_k(token, new_k=5, actor="operator:fixture",
                            recorded_at=T1, request_id="request-1",
                            expected_revision=0)
            self.assertEqual((1, 5), (changed.revision, changed.k))
            self.assertEqual((1, 5), (current_k(token).revision, current_k(token).k))
        with self.assertRaises(TrackerStateHold):
            current_k(token)

    def test_require_current_k_reuses_exact_active_writer_and_rejects_drift(self):
        from monitor.issue_tracker_state_owner import require_current_k

        self.initialize()
        with tracker_writer(self.project, self.publication) as token:
            original = current_k(token)
            require_current_k(token, self.project, self.publication, original)
            with self.assertRaises(TrackerStateHold):
                require_current_k(object(), self.project, self.publication, original)
            with self.assertRaises(TrackerStateHold):
                require_current_k(token, self.project.parent, self.publication, original)
            changed = set_k(token, new_k=5, actor="operator:fixture",
                            recorded_at=T1, request_id="current-k-drift",
                            expected_revision=0)
            self.assertNotEqual(original, changed)
            with self.assertRaises(TrackerStateHold):
                require_current_k(token, self.project, self.publication, original)
            require_current_k(token, self.project, self.publication, current_k(token))

    def test_interrupted_bootstrap_is_not_reinterpreted_as_first_use(self):
        with mock.patch("monitor.issue_tracker_state_owner.initialize_local_k_store",
                        side_effect=OSError("injected crash after root creation")):
            with self.assertRaises(TrackerStateHold):
                self.initialize()
        self.assertTrue(self.root.is_dir())
        self.assertFalse((self.root / "INITIALIZED").exists())
        with self.assertRaises(TrackerStateHold):
            self.initialize()
        with self.assertRaises(TrackerStateHold):
            with tracker_writer(self.project, self.publication):
                self.fail("unfinished tracker state was admitted")
        self.assertFalse((self.root / "settings").exists())

    def test_ancestor_alias_and_rebound_lock_never_authorize_settings_or_commit(self):
        self.initialize()
        alias = self.project.parent / "alias"
        alias.symlink_to(self.project, target_is_directory=True)
        with self.assertRaises(TrackerStateHold):
            with tracker_writer(alias, alias / "99-output-monitor"):
                self.fail("symlink alias acquired state authority")
        with tracker_writer(self.project, self.publication) as token:
            (self.root / "LOCK").unlink()
            (self.root / "LOCK").write_bytes(b"")
            with self.assertRaises(TrackerStateHold):
                current_k(token)
            with self.assertRaises(LocalCommitHold):
                begin_generation(token, MANIFEST)

    def test_rebound_root_or_publication_path_cannot_use_pinned_old_descriptors(self):
        self.initialize()
        with tracker_writer(self.project, self.publication) as token:
            self.root.rename(self.project / ".tracker-detached")
            self.root.mkdir(mode=0o700)
            with self.assertRaises(TrackerStateHold):
                current_k(token)
            with self.assertRaises(LocalCommitHold):
                begin_generation(token, MANIFEST)
        # A second fresh fixture isolates the publication rebind case.
        with tempfile.TemporaryDirectory(prefix="tracker-output-rebind-") as directory:
            project = Path(os.path.realpath(directory)) / "project"
            project.mkdir(mode=0o755)
            project.chmod(0o755)
            publication = project / "99-output-monitor"
            publication.mkdir(mode=0o755)
            publication.chmod(0o755)
            initialize_tracker_state(project, publication, initialized_at=T0,
                                     acquisition_id="acquisition-0")
            with tracker_writer(project, publication) as token:
                publication.rename(project / "output-detached")
                publication.mkdir(mode=0o755)
                publication.chmod(0o755)
                with self.assertRaises(LocalCommitHold):
                    begin_generation(token, MANIFEST)

    def test_caller_body_exception_propagates_without_reclassification(self):
        self.initialize()
        sentinel = ValueError("caller-owned sentinel")
        token = None
        try:
            with tracker_writer(self.project, self.publication) as token:
                raise sentinel
        except ValueError as caught:
            self.assertIs(sentinel, caught)
        else:
            self.fail("caller exception was swallowed")
        with self.assertRaises(TrackerStateHold):
            current_k(token)


if __name__ == "__main__":
    unittest.main()
