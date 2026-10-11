"""C-6 local-only INTENT/RECEIPT, lock-capability and crash contract."""

from dataclasses import replace
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import monitor.issue_tracker_local_commit as local_commit

from monitor.issue_tracker_local_commit import (
    LocalCommitHold, begin_generation, commit, create_local_commit_store,
    inspect_local_generation, quarantine_unresolved, record_intent, writer_owner,
)


MANIFEST = b'{"operations":[],"schema_version":1}\n'
PREPARED = b"local-workbook-fixture\n"


class LocalCommitTests(unittest.TestCase):
    def test_first_name_stat_failure_never_closes_a_foreign_reused_slot(self):
        native_open=os.open; native_stat=os.stat; owned=[]; foreign=[]
        primary=OSError('first pending pathname identity unavailable')
        target=self.project/'independent-foreign'; target.write_bytes(b'foreign remains owned by test\n')
        with writer_owner(self.project,self.publish) as token:
            parent=local_commit._owner(token).root_fd
            def opening(name,*args,**kwargs):
                descriptor=native_open(name,*args,**kwargs)
                if isinstance(name,str) and name.startswith('.pending-'): owned.append(descriptor)
                return descriptor
            def inspecting(name,*args,**kwargs):
                if isinstance(name,str) and name.startswith('.pending-'):
                    os.close(owned[0])
                    descriptor=native_open(target,os.O_RDONLY)
                    if descriptor!=owned[0]:
                        os.dup2(descriptor,owned[0]); os.close(descriptor)
                    foreign.append(owned[0])
                    raise primary
                return native_stat(name,*args,**kwargs)
            try:
                with mock.patch.object(os,'open',side_effect=opening),mock.patch.object(os,'stat',side_effect=inspecting):
                    with self.assertRaises(OSError) as caught:
                        local_commit._write_new(parent,'never-installed',b'new record\n',_return_original=True)
                self.assertIs(primary,caught.exception)
                self.assertEqual(b'foreign remains owned by test\n',os.pread(foreign[0],100,0))
                self.assertEqual(target.stat().st_ino,os.fstat(foreign[0]).st_ino)
                self.assertIsInstance(caught.exception.__cause__,LocalCommitHold)
                self.assertFalse((self.project/'.tracker/never-installed').exists())
            finally:
                for descriptor in foreign:
                    try: os.close(descriptor)
                    except OSError: pass

    def test_first_write_cleanup_refusal_preserves_the_original_interrupt(self):
        native_open=os.open; native_write=os.write; owned=[]; foreign=[]
        primary=KeyboardInterrupt('original first-write interruption')
        target=self.project/'independent-interrupt-foreign'; target.write_bytes(b'foreign interrupt evidence\n')
        with writer_owner(self.project,self.publish) as token:
            parent=local_commit._owner(token).root_fd
            def opening(name,*args,**kwargs):
                descriptor=native_open(name,*args,**kwargs)
                if isinstance(name,str) and name.startswith('.pending-'): owned.append(descriptor)
                return descriptor
            def writing(descriptor,raw):
                if owned and descriptor==owned[0]:
                    os.close(descriptor)
                    replacement=native_open(target,os.O_RDONLY)
                    if replacement!=descriptor:
                        os.dup2(replacement,descriptor); os.close(replacement)
                    foreign.append(descriptor)
                    raise primary
                return native_write(descriptor,raw)
            try:
                with mock.patch.object(os,'open',side_effect=opening),mock.patch.object(os,'write',side_effect=writing):
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        local_commit._write_new(parent,'interrupted-record',b'original intended record\n',_return_original=True)
                self.assertIs(primary,caught.exception)
                self.assertIsInstance(caught.exception.__cause__,LocalCommitHold)
                self.assertEqual(b'foreign interrupt evidence\n',os.pread(foreign[0],100,0))
                self.assertFalse((self.project/'.tracker/interrupted-record').exists())
            finally:
                for descriptor in foreign:
                    try: os.close(descriptor)
                    except OSError: pass

    def test_first_write_can_hand_off_the_actual_original_descriptor_until_reader_closes(self):
        with writer_owner(self.project,self.publish) as token:
            parent=local_commit._owner(token).root_fd
            raw=b'independent first-written immutable image\n'
            descriptor,identity=local_commit._write_new(parent,'owned-first-image',raw,_return_original=True)
            try:
                actual=os.fstat(descriptor); named=os.stat('owned-first-image',dir_fd=parent,follow_symlinks=False)
                self.assertEqual((actual.st_dev,actual.st_ino),(named.st_dev,named.st_ino))
                self.assertEqual((actual.st_dev,actual.st_ino,actual.st_mode,actual.st_uid,actual.st_gid,
                    actual.st_nlink,actual.st_size,actual.st_mtime_ns,actual.st_ctime_ns),identity)
                self.assertEqual(raw,os.pread(descriptor,len(raw)+1,0))
                with self.assertRaises(FileExistsError):
                    local_commit._write_new(parent,'owned-first-image',b'never overwrite',_return_original=True)
                self.assertEqual(raw,os.pread(descriptor,len(raw)+1,0))
                self.assertEqual(raw,(self.project/'.tracker/owned-first-image').read_bytes())
            finally: local_commit._close_written_original(descriptor,identity)
            with self.assertRaises(OSError): os.fstat(descriptor)

    def test_first_write_retained_descriptor_is_closed_when_parent_barrier_refuses(self):
        native_open=os.open; native_fsync=os.fsync; opened=[]
        with writer_owner(self.project,self.publish) as token:
            parent=local_commit._owner(token).root_fd
            def opening(name,*args,**kwargs):
                result=native_open(name,*args,**kwargs)
                if isinstance(name,str) and name.startswith('.pending-'): opened.append(result)
                return result
            def barrier(fd):
                if fd==parent: raise OSError('owned first-written parent barrier failed')
                return native_fsync(fd)
            with mock.patch.object(os,'open',side_effect=opening),mock.patch.object(os,'fsync',side_effect=barrier):
                with self.assertRaises(OSError):
                    local_commit._write_new(parent,'owned-failed-image',b'preserve failed evidence\n',_return_original=True)
            self.assertEqual(1,len(opened))
            with self.assertRaises(OSError): os.fstat(opened[0])
            self.assertEqual(b'preserve failed evidence\n',(self.project/'.tracker/owned-failed-image').read_bytes())

    def original_try_api(self):
        api = getattr(local_commit, '_try_original_writer_owner', None)
        self.assertTrue(callable(api), 'historical acquisition must refuse non-original roots and LOCK before flock')
        return api

    def original_owner_identities(self):
        return tuple((path.stat().st_dev, path.stat().st_ino) for path in
                     (self.project, self.project / '.tracker', self.publish, self.project / '.tracker/LOCK'))

    def test_original_try_writer_guard_preserves_real_owner_hooks_and_rejects_malformed_identity_before_open(self):
        api = self.original_try_api(); identities = self.original_owner_identities()
        with api(self.project, self.publish, identities) as token:
            self.assertEqual({}, local_commit._owner(token).handles)
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PREPARED)
            receipt = commit(token, generation)
            self.assertEqual(hashlib.sha256(PREPARED).hexdigest(), receipt.published_sha256)
        with self.assertRaises(LocalCommitHold):
            local_commit._owner(token)
        with mock.patch.object(local_commit, '_open_absolute_directory',
                               side_effect=LocalCommitHold('malformed identity must not open a project')) as opening:
            for malformed in (None, (), ((True, 1),) + identities[1:], list(identities)):
                with self.subTest(malformed=malformed), self.assertRaises(LocalCommitHold):
                    with api(self.project, self.publish, malformed):
                        self.fail('malformed original identity opened a project')
            opening.assert_not_called()

    def test_original_try_writer_guard_refuses_replaced_lock_before_any_foreign_flock_or_write(self):
        api = self.original_try_api(); identities = self.original_owner_identities()
        lock = self.project / '.tracker/LOCK'; raw = lock.read_bytes()
        lock.rename(self.project / '.tracker/preserved-original-LOCK')
        lock.write_bytes(raw); lock.chmod(0o600)
        before = {str(p.relative_to(self.project)): (p.stat().st_ino, p.read_bytes())
                  for p in self.project.rglob('*') if p.is_file()}
        with mock.patch.object(local_commit.fcntl, 'flock', wraps=local_commit.fcntl.flock) as locking:
            with self.assertRaises(LocalCommitHold):
                with api(self.project, self.publish, identities):
                    self.fail('foreign LOCK acquired original owner')
            locking.assert_not_called()
        self.assertEqual(before, {str(p.relative_to(self.project)): (p.stat().st_ino, p.read_bytes())
                                  for p in self.project.rglob('*') if p.is_file()})
        self.assertEqual({}, local_commit._ACTIVE)

    def try_owner_api(self):
        api = getattr(local_commit, 'try_writer_owner', None)
        self.assertTrue(callable(api), 'historical multi-project ownership must have explicit native nonblocking acquisition')
        return api

    def test_try_writer_owner_uses_real_nonblocking_lock_and_original_hook_and_revocation_contract(self):
        api = self.try_owner_api()
        with mock.patch.object(local_commit.fcntl, 'flock', wraps=local_commit.fcntl.flock) as locking:
            with api(self.project, self.publish) as token:
                owner = local_commit._owner(token)
                self.assertEqual({}, owner.handles)
                self.assertEqual(local_commit.fcntl.LOCK_EX | local_commit.fcntl.LOCK_NB, locking.call_args.args[1])
                with self.assertRaises(LocalCommitHold):
                    with api(self.project, self.publish):
                        self.fail('same process reacquired a live writer')
                generation = begin_generation(token, MANIFEST)
                record_intent(token, generation, PREPARED)
                receipt = commit(token, generation)
                self.assertEqual(hashlib.sha256(PREPARED).hexdigest(), receipt.published_sha256)
                self.assertEqual(PREPARED, (self.publish / (generation.generation_id + '.bin')).read_bytes())
        with self.assertRaises(LocalCommitHold):
            local_commit._owner(token)
        with api(self.project, self.publish) as replacement:
            self.assertIsNot(token, replacement)
            self.assertEqual({}, local_commit._owner(replacement).handles)
            with self.assertRaises(LocalCommitHold):
                commit(replacement, generation)

    def test_try_writer_owner_busy_real_foreign_lock_refuses_without_waiting_writing_or_token(self):
        api = self.try_owner_api()
        import subprocess, sys, time
        before = {str(path.relative_to(self.project)): (path.stat().st_ino, path.read_bytes())
                  for path in self.project.rglob('*') if path.is_file()}
        active = dict(local_commit._ACTIVE)
        from test_cases.test_req7_native_supervised_workflow import owned_ready_lock_holder
        with owned_ready_lock_holder(self.project / '.tracker/LOCK') as child:
            started = time.monotonic()
            with self.assertRaises(LocalCommitHold):
                with api(self.project, self.publish):
                    self.fail('busy foreign lock issued a writer token')
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertEqual(active, local_commit._ACTIVE)
            self.assertEqual(before, {str(path.relative_to(self.project)): (path.stat().st_ino, path.read_bytes())
                                     for path in self.project.rglob('*') if path.is_file()})
        self.assertEqual(0, child.returncode)
        with api(self.project, self.publish) as token:
            self.assertEqual({}, local_commit._owner(token).handles)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tracker-local-commit-")
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name).resolve(strict=True)
        self.publish = self.project / "publication"
        self.publish.mkdir(mode=0o700)
        create_local_commit_store(self.project, self.publish)

    def test_original_owner_directory_scope_opens_each_ancestor_once(self):
        from tools import ufm_collection_pipeline as pipeline
        with writer_owner(self.project, self.publish) as token:
            owner = local_commit._owner(token)
            real_open = os.open
            opened = []
            def opening(*args, **kwargs):
                descriptor = real_open(*args, **kwargs)
                opened.append(descriptor)
                return descriptor
            with mock.patch.object(local_commit.os, 'open', side_effect=opening):
                with pipeline._hold_reusable_directory_reads():
                    for _ in range(32):
                        self.assertIs(owner, local_commit._owner(token))
            self.assertEqual(len(self.project.parts), len(opened),
                'the original ancestor FDs open once, without caching owner checks')

    def test_original_owner_scope_rejects_same_project_under_rebound_parent(self):
        from tools import ufm_collection_pipeline as pipeline
        parent = self.project / 'original-parent'
        parent.mkdir(mode=0o700)
        project = parent / 'project'
        project.mkdir(mode=0o700)
        publication = project / 'publication'
        publication.mkdir(mode=0o700)
        create_local_commit_store(project, publication)
        reached = []
        with writer_owner(project, publication) as token:
            original = project.stat().st_ino
            with self.assertRaises(pipeline.PipelineError):
                with pipeline._hold_reusable_directory_reads():
                    local_commit._owner(token)
                    moved = self.project / 'moved-parent'
                    parent.rename(moved)
                    parent.mkdir(mode=0o700)
                    (moved / 'project').rename(project)
                    self.assertEqual(original, project.stat().st_ino)
                    with self.assertRaises(LocalCommitHold):
                        local_commit._owner(token)
                    reached.append(True)
        self.assertEqual([True], reached)

    def test_original_owner_scope_rechecks_lock_permissions(self):
        from tools import ufm_collection_pipeline as pipeline
        lock = self.project / '.tracker' / 'LOCK'
        with writer_owner(self.project, self.publish) as token:
            with pipeline._hold_reusable_directory_reads():
                local_commit._owner(token)
                lock.chmod(0o666)
                try:
                    with self.assertRaises(LocalCommitHold):
                        local_commit._owner(token)
                finally:
                    lock.chmod(0o600)

    def test_immutable_record_uses_atomic_no_replace_rename_not_hardlink(self):
        with tempfile.TemporaryDirectory(prefix="tracker-rename-record-") as directory:
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(local_commit.os, "link", side_effect=AssertionError(
                        "immutable record must be published by rename")):
                    local_commit._write_new(parent, "RECEIPT", b"old\n")
                    for _ in range(3):
                        with self.assertRaises((LocalCommitHold, FileExistsError)):
                            local_commit._write_new(parent, "RECEIPT", b"replacement\n")
                self.assertEqual(b"old\n", (Path(directory) / "RECEIPT").read_bytes())
                self.assertEqual(1, (Path(directory) / "RECEIPT").stat().st_nlink)
                pending = list(Path(directory).glob(".pending-*"))
                self.assertEqual(3, len(pending))
                self.assertTrue(all(path.read_bytes() == b"replacement\n" for path in pending))
            finally:
                os.close(parent)

    def test_eexist_cleanup_cannot_unlink_foreign_pending_replacement(self):
        with tempfile.TemporaryDirectory(prefix="tracker-eexist-swap-") as directory:
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                local_commit._write_new(parent, "RECEIPT", b"old\n")
                real_stat = os.stat
                swapped = []
                foreign = b"foreign pending evidence\n"

                def swap_after_stat(name, *args, **kwargs):
                    info = real_stat(name, *args, **kwargs)
                    if isinstance(name, str) and name.startswith(".pending-") and not swapped:
                        preserved = ".preserved-" + name
                        os.rename(name, preserved, src_dir_fd=parent, dst_dir_fd=parent)
                        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                     0o600, dir_fd=parent)
                        try:
                            os.write(fd, foreign)
                            os.fsync(fd)
                            swapped.append((name, preserved, os.fstat(fd).st_ino))
                        finally:
                            os.close(fd)
                        os.fsync(parent)
                    return info

                with mock.patch.object(local_commit.os, "stat", side_effect=swap_after_stat), \
                     mock.patch.object(local_commit.os, "unlink", wraps=os.unlink) as unlink:
                    with self.assertRaises((LocalCommitHold, FileExistsError)):
                        local_commit._write_new(parent, "RECEIPT", b"new\n")
                    unlink.assert_not_called()
                # The old stat->unlink path triggers the injected exchange and
                # deletes the foreign pending name. A safe implementation has
                # no cleanup call and leaves its own pending evidence instead.
                if swapped:
                    name, preserved, foreign_ino = swapped[0]
                    self.assertEqual((foreign, foreign_ino),
                                     ((Path(directory) / name).read_bytes(),
                                      (Path(directory) / name).stat().st_ino))
                    self.assertEqual(b"new\n", (Path(directory) / preserved).read_bytes())
                else:
                    pending = list(Path(directory).glob(".pending-*"))
                    self.assertEqual(1, len(pending))
                    self.assertEqual(b"new\n", pending[0].read_bytes())
                self.assertEqual(b"old\n", (Path(directory) / "RECEIPT").read_bytes())
            finally:
                os.close(parent)

    def test_uncertain_record_rename_failure_keeps_pending_evidence(self):
        with tempfile.TemporaryDirectory(prefix="tracker-rename-error-") as directory:
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(local_commit, "_rename_new",
                                       side_effect=OSError(errno.EIO, "injected uncertain rename")):
                    with self.assertRaises(OSError):
                        local_commit._write_new(parent, "INTENT", b"evidence\n")
                self.assertFalse((Path(directory) / "INTENT").exists())
                pending = list(Path(directory).glob(".pending-*"))
                self.assertEqual(1, len(pending))
                self.assertEqual(b"evidence\n", pending[0].read_bytes())
            finally:
                os.close(parent)

    def test_published_destination_appearing_after_listing_is_never_clobbered(self):
        foreign = b"foreign published workbook\n"
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            witness = record_intent(token, generation, PREPARED)
            published = generation.generation_id + ".bin"
            real_listdir = os.listdir
            publication_info = self.publish.stat()
            injected = []

            def inject_after_listing(directory):
                names = real_listdir(directory)
                if (isinstance(directory, int) and not injected
                        and (os.fstat(directory).st_dev, os.fstat(directory).st_ino)
                        == (publication_info.st_dev, publication_info.st_ino)):
                    fd = os.open(published, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                 0o600, dir_fd=directory)
                    try:
                        os.write(fd, foreign)
                        os.fsync(fd)
                        injected.append(os.fstat(fd).st_ino)
                    finally:
                        os.close(fd)
                    os.fsync(directory)
                return names

            with mock.patch("monitor.issue_tracker_local_commit.os.listdir",
                            side_effect=inject_after_listing):
                with self.assertRaises(LocalCommitHold):
                    commit(token, generation)
            self.assertEqual(1, len(injected))
            target = self.publish / published
            self.assertEqual((foreign, injected[0]),
                             (target.read_bytes(), target.stat().st_ino))
            prepared = self.publish / (".prepared-" + generation.generation_id)
            self.assertEqual((PREPARED, witness.ino),
                             (prepared.read_bytes(), prepared.stat().st_ino))
            self.assertFalse((self.project / ".tracker" / "generations" /
                              generation.generation_id / "RECEIPT").exists())

    def test_quarantine_destination_appearing_after_listing_is_never_clobbered(self):
        foreign = b"foreign quarantine evidence\n"
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            witness = record_intent(token, generation, PREPARED)
            quarantine = self.project / ".tracker" / "quarantine"
            quarantine_info = quarantine.stat()
            real_listdir = os.listdir
            injected = []

            def inject_after_listing(directory):
                names = real_listdir(directory)
                if (isinstance(directory, int) and not injected
                        and (os.fstat(directory).st_dev, os.fstat(directory).st_ino)
                        == (quarantine_info.st_dev, quarantine_info.st_ino)):
                    fd = os.open(generation.generation_id + ".bin",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                 0o600, dir_fd=directory)
                    try:
                        os.write(fd, foreign)
                        os.fsync(fd)
                        injected.append(os.fstat(fd).st_ino)
                    finally:
                        os.close(fd)
                    os.fsync(directory)
                return names

            with mock.patch("monitor.issue_tracker_local_commit.os.listdir",
                            side_effect=inject_after_listing):
                with self.assertRaises(LocalCommitHold):
                    quarantine_unresolved(token, generation)
            self.assertEqual(1, len(injected))
            target = quarantine / (generation.generation_id + ".bin")
            self.assertEqual((foreign, injected[0]),
                             (target.read_bytes(), target.stat().st_ino))
            prepared = self.publish / (".prepared-" + generation.generation_id)
            self.assertEqual((PREPARED, witness.ino),
                             (prepared.read_bytes(), prepared.stat().st_ino))
            self.assertFalse((self.project / ".tracker" / "generations" /
                              generation.generation_id / "OBSERVATION").exists())

    def test_prepared_source_swap_after_witness_read_never_issues_receipt(self):
        foreign = b"foreign source replacement\n"
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            witness = record_intent(token, generation, PREPARED)
            source = ".prepared-" + generation.generation_id
            preserved = ".preserved-" + generation.generation_id
            real_listdir = os.listdir
            publication_info = self.publish.stat()
            injected = []

            def inject_after_witness_read(directory):
                names = real_listdir(directory)
                if (isinstance(directory, int) and not injected
                        and (os.fstat(directory).st_dev, os.fstat(directory).st_ino)
                        == (publication_info.st_dev, publication_info.st_ino)):
                    os.rename(source, preserved,
                              src_dir_fd=directory, dst_dir_fd=directory)
                    fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                 0o600, dir_fd=directory)
                    try:
                        os.write(fd, foreign)
                        os.fsync(fd)
                        injected.append(os.fstat(fd).st_ino)
                    finally:
                        os.close(fd)
                    os.fsync(directory)
                return names

            with mock.patch("monitor.issue_tracker_local_commit.os.listdir",
                            side_effect=inject_after_witness_read):
                with self.assertRaises(LocalCommitHold):
                    commit(token, generation)
            self.assertEqual(1, len(injected))
            old_source = self.publish / preserved
            self.assertEqual((PREPARED, witness.ino),
                             (old_source.read_bytes(), old_source.stat().st_ino))
            published = self.publish / (generation.generation_id + ".bin")
            self.assertEqual((foreign, injected[0]),
                             (published.read_bytes(), published.stat().st_ino))
            self.assertFalse((self.project / ".tracker" / "generations" /
                              generation.generation_id / "RECEIPT").exists())

    def test_three_hooks_require_live_owner_and_receipt_follows_intent(self):
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            with self.assertRaises(LocalCommitHold):
                commit(token, generation)
            intent = record_intent(token, generation, PREPARED)
            self.assertEqual(hashlib.sha256(PREPARED).hexdigest(), intent.sha256)
            self.assertGreater(intent.ino, 0)
            self.assertEqual(len(PREPARED), intent.size)
            self.assertEqual("UNRESOLVED", inspect_local_generation(
                self.project, self.publish, generation, token=token).status)
            with self.assertRaises(LocalCommitHold):
                inspect_local_generation(self.project, self.publish, generation)
            receipt = commit(token, generation)
            self.assertEqual(generation.generation_id, receipt.generation_id)
            self.assertEqual(hashlib.sha256(MANIFEST).hexdigest(), receipt.manifest_id)
            self.assertEqual("RECEIPT-PRESENT-NOT-ELIGIBILITY", inspect_local_generation(
                self.project, self.publish, generation, token=token).status)
            self.assertTrue((self.publish / (generation.generation_id + ".bin")).is_file())
        for action in (
            lambda: begin_generation(token, MANIFEST),
            lambda: record_intent(token, generation, PREPARED),
            lambda: commit(token, generation),
        ):
            with self.assertRaises(LocalCommitHold):
                action()

    def test_exception_revokes_old_token_and_new_acquisition_cannot_reuse_it(self):
        old = None
        with self.assertRaisesRegex(RuntimeError, "injected"):
            with writer_owner(self.project, self.publish) as token:
                old = token
                raise RuntimeError("injected")
        with writer_owner(self.project, self.publish) as new:
            with self.assertRaises(LocalCommitHold):
                begin_generation(old, MANIFEST)
            self.assertNotEqual(old, new)
            self.assertEqual(1, begin_generation(new, MANIFEST).sequence)

    def test_intent_without_receipt_never_auto_promotes_after_restart(self):
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            intent = record_intent(token, generation, PREPARED)
        observation = inspect_local_generation(self.project, self.publish, generation)
        self.assertEqual(("UNRESOLVED", "PREPARED-PRESENT"),
                         (observation.status, observation.prepared_observation))
        self.assertFalse((self.project / ".tracker" / "generations" /
                          generation.generation_id / "RECEIPT").exists())
        prepared = self.publish / (".prepared-" + generation.generation_id)
        prepared.write_bytes(PREPARED + b"changed")
        with writer_owner(self.project, self.publish) as token:
            with self.assertRaises(LocalCommitHold):
                commit(token, generation)
        self.assertEqual("UNRESOLVED", inspect_local_generation(
            self.project, self.publish, generation).status)
        self.assertEqual(intent.ino, json.loads((self.project / ".tracker" /
            "generations" / generation.generation_id / "INTENT").read_text())["prepared"]["ino"])

    def test_later_owner_cannot_commit_or_reintent_old_generation_handle(self):
        with writer_owner(self.project, self.publish) as first:
            generation = begin_generation(first, MANIFEST)
            record_intent(first, generation, PREPARED)
        with writer_owner(self.project, self.publish) as second:
            with self.assertRaises(LocalCommitHold):
                commit(second, generation)
            with self.assertRaises(LocalCommitHold):
                record_intent(second, generation, PREPARED)
        self.assertFalse((self.project / ".tracker" / "generations" /
                          generation.generation_id / "RECEIPT").exists())

    def test_reconstructed_generation_handle_in_same_owner_is_not_issued(self):
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            reconstructed = replace(generation)
            with self.assertRaises(LocalCommitHold):
                record_intent(token, reconstructed, PREPARED)
            record_intent(token, generation, PREPARED)

    def test_publication_barrier_failure_leaves_visible_file_but_no_receipt(self):
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PREPARED)
            real = os.fsync
            target = self.publish.stat()
            failed = False

            def inject(descriptor):
                nonlocal failed
                current = os.fstat(descriptor)
                if (not failed and current.st_dev == target.st_dev
                        and current.st_ino == target.st_ino):
                    failed = True
                    raise OSError("publication barrier injected")
                return real(descriptor)

            with mock.patch("monitor.issue_tracker_local_commit.os.fsync", side_effect=inject):
                with self.assertRaises(LocalCommitHold):
                    commit(token, generation)
            self.assertTrue(failed)
            self.assertFalse((self.project / ".tracker" / "generations" /
                              generation.generation_id / "RECEIPT").exists())
        self.assertEqual("UNRESOLVED", inspect_local_generation(
            self.project, self.publish, generation).status)

    def test_visible_receipt_before_parent_barrier_is_not_an_eligibility_grant(self):
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PREPARED)
            generation_dir = (self.project / ".tracker" / "generations" /
                              generation.generation_id).stat()
            real = os.fsync
            failed = False

            def inject(descriptor):
                nonlocal failed
                current = os.fstat(descriptor)
                if (not failed and current.st_dev == generation_dir.st_dev
                        and current.st_ino == generation_dir.st_ino):
                    failed = True
                    raise OSError("receipt parent fsync injection")
                return real(descriptor)

            with mock.patch("monitor.issue_tracker_local_commit.os.fsync", side_effect=inject):
                with self.assertRaises(LocalCommitHold):
                    commit(token, generation)
            self.assertTrue(failed)
        self.assertTrue((self.project / ".tracker" / "generations" /
                         generation.generation_id / "RECEIPT").exists())
        # A later owner must complete the recovery directory barrier, and the
        # resulting observation must still never issue online eligibility.
        real = os.fsync
        def fail_recovery_barrier(descriptor):
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) == (generation_dir.st_dev,
                                                    generation_dir.st_ino):
                raise OSError("recovery receipt barrier injected")
            return real(descriptor)
        with mock.patch("monitor.issue_tracker_local_commit.os.fsync",
                        side_effect=fail_recovery_barrier):
            with self.assertRaises(LocalCommitHold):
                inspect_local_generation(self.project, self.publish, generation)
        self.assertEqual("RECEIPT-PRESENT-NOT-ELIGIBILITY",
                         inspect_local_generation(self.project, self.publish,
                                                  generation).status)

    def test_generation_sequence_is_monotonic_over_abandoned_begin(self):
        with writer_owner(self.project, self.publish) as token:
            first = begin_generation(token, MANIFEST)
        with writer_owner(self.project, self.publish) as token:
            second = begin_generation(token, MANIFEST)
        self.assertEqual((1, 2), (first.sequence, second.sequence))
        self.assertNotEqual(first.generation_id, second.generation_id)

    def test_tampered_manifest_cannot_become_intent_or_receipt(self):
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            manifest = (self.project / ".tracker" / "generations" /
                        generation.generation_id / "MANIFEST")
            manifest.write_bytes(MANIFEST + b" ")
            with self.assertRaises(LocalCommitHold):
                record_intent(token, generation, PREPARED)
            self.assertFalse((manifest.parent / "INTENT").exists())

    def test_ancestor_symlink_alias_is_not_a_second_writer_root(self):
        real = self.project / "real"
        real.mkdir(mode=0o700)
        nested = real / "project"
        nested.mkdir(mode=0o700)
        (nested / "publication").mkdir(mode=0o700)
        alias = self.project / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(LocalCommitHold):
            create_local_commit_store(alias / "project", alias / "project" / "publication")
        self.assertFalse((nested / ".tracker").exists())

    def test_receipt_name_without_bound_published_inode_is_not_even_valid_observation(self):
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PREPARED)
            commit(token, generation)
        published = self.publish / (generation.generation_id + ".bin")
        published.unlink()
        with self.assertRaises(LocalCommitHold):
            inspect_local_generation(self.project, self.publish, generation)
        published.write_bytes(PREPARED)  # Same bytes are not the same inode/lifetime.
        with self.assertRaises(LocalCommitHold):
            inspect_local_generation(self.project, self.publish, generation)

    def test_unresolved_quarantine_preserves_bytes_without_receipt_or_eligibility(self):
        with writer_owner(self.project, self.publish) as token:
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PREPARED)
            observation = quarantine_unresolved(token, generation)
            self.assertEqual("QUARANTINED-OBSERVATION", observation)
            self.assertEqual("UNRESOLVED", inspect_local_generation(
                self.project, self.publish, generation, token=token).status)
        target = self.project / ".tracker" / "quarantine" / (generation.generation_id + ".bin")
        self.assertEqual(PREPARED, target.read_bytes())
        self.assertFalse((self.project / ".tracker" / "generations" /
                          generation.generation_id / "RECEIPT").exists())
        with writer_owner(self.project, self.publish) as token:
            with self.assertRaises(LocalCommitHold):
                commit(token, generation)

    @unittest.skipUnless(hasattr(os, "fork"), "fork not available")
    def test_inherited_token_is_not_active_in_forked_process(self):
        with writer_owner(self.project, self.publish) as token:
            child = os.fork()
            if child == 0:
                try:
                    begin_generation(token, MANIFEST)
                except LocalCommitHold:
                    os._exit(0)
                os._exit(9)
            _, status = os.waitpid(child, 0)
            self.assertEqual(0, os.WEXITSTATUS(status))


if __name__ == "__main__":
    unittest.main()
