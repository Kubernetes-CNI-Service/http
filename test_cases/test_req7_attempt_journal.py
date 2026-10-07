"""Independent immutable attempt-count contract, using owned local state only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_local_commit import create_local_commit_store, writer_owner

BODY=b'{"requests":[{"fixture":"not an online send unit"}]}\n'
UNIT="b"*64


class Req7AttemptJournalDirectTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="req7-attempt-journal-")
        self.addCleanup(self.temp.cleanup)
        self.project=Path(self.temp.name).resolve()
        self.publication=self.project/"publication"; self.publication.mkdir(mode=0o700)
        create_local_commit_store(self.project,self.publication)

    def module(self):
        path=Path(__file__).resolve().parents[1]/"monitor/issue_tracker_attempt_journal.py"
        self.assertTrue(path.is_file(),"immutable attempt journal is missing")
        spec=importlib.util.spec_from_file_location("isolated_req7_attempt_journal",path)
        module=importlib.util.module_from_spec(spec); sys.modules[spec.name]=module; spec.loader.exec_module(module)
        return module

    def test_six_intents_are_immutable_durable_and_never_reset_by_reopening(self):
        module=self.module()
        with writer_owner(self.project,self.publication) as token:
            module.prepare_unit(token,UNIT,BODY)
        for expected in range(1,7):
            with writer_owner(self.project,self.publication) as token:
                record=module.record_attempt_intent(token,UNIT,BODY)
                self.assertEqual(expected,record.attempt_count)
                self.assertEqual(hashlib.sha256(BODY).hexdigest(),record.wire_sha256)
                self.assertEqual("UNKNOWN",record.outcome)
                self.assertFalse(hasattr(record,"permit"))
                raw=(self.project/".tracker/remote-attempts"/UNIT/f"ATTEMPT-{expected}").read_bytes()
                self.assertEqual(expected,json.loads(raw)["attempt_count"])
                self.assertEqual(hashlib.sha256(BODY).hexdigest(),json.loads(raw)["wire_sha256"])
        before={p.name:p.read_bytes() for p in (self.project/".tracker/remote-attempts"/UNIT).iterdir()}
        with writer_owner(self.project,self.publication) as token,self.assertRaises(module.AttemptJournalHold):
            module.record_attempt_intent(token,UNIT,BODY)
        self.assertEqual(before,{p.name:p.read_bytes() for p in (self.project/".tracker/remote-attempts"/UNIT).iterdir()})

    def test_changed_wire_stale_token_and_reinitialization_cannot_allocate_or_overwrite(self):
        module=self.module()
        with writer_owner(self.project,self.publication) as token:
            module.prepare_unit(token,UNIT,BODY)
            with self.assertRaises(module.AttemptJournalHold): module.prepare_unit(token,UNIT,BODY)
            with self.assertRaises(module.AttemptJournalHold): module.record_attempt_intent(token,UNIT,BODY+b" ")
            self.assertEqual(0,module.inspect_unit(token,UNIT,BODY).attempt_count)
        for invalid in (token,object(),None):
            with self.subTest(token=type(invalid).__name__),self.assertRaises(module.AttemptJournalHold):
                module.record_attempt_intent(invalid,UNIT,BODY)

    def test_any_prior_unit_blocks_new_unit_without_remote_complete_authority(self):
        module=self.module()
        with writer_owner(self.project,self.publication) as token:
            module.prepare_unit(token,UNIT,BODY)
            module.record_attempt_intent(token,UNIT,BODY)
            with self.assertRaises(module.AttemptJournalHold): module.prepare_unit(token,"c"*64,BODY)
            self.assertFalse((self.project/".tracker/remote-attempts"/("c"*64)).exists())

    def test_read_image_writer_has_only_fixed_names_and_does_not_expand_wire_or_manifest_limits(self):
        module = self.module()
        fd = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            before = set(os.listdir(fd))
            for name, raw in (('WIRE', b'x'), ('HEADER', b'x'), ('../foreign', b'x'),
                    ('METADATA-RAW', b''), ('METADATA-RAW', bytearray(b'x')),
                    ('METADATA-RAW', b'x' * (2 * 1024 * 1024 + 1))):
                with self.subTest(name=name), self.assertRaises(module.AttemptJournalHold): module._write_read_image(fd, name, raw)
                self.assertEqual(before, set(os.listdir(fd)))
        finally: os.close(fd)
        with writer_owner(self.project, self.publication) as token:
            with self.assertRaises(module.AttemptJournalHold): module.prepare_unit(token, UNIT, b'x' * (1024 * 1024 + 1))
            self.assertFalse((self.project / '.tracker/remote-attempts').exists())

    def test_read_image_short_writes_noreplace_and_failed_progress_keep_original_evidence(self):
        module = self.module(); raw = b'original typed read bytes\n' * 1000
        fd = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            actual = os.write
            with mock.patch('os.write', side_effect=lambda held, view: actual(held, view[:17])):
                module._write_read_image(fd, 'METADATA-RAW', raw)
            self.assertEqual(raw, (self.project / 'METADATA-RAW').read_bytes())
            with self.assertRaises(FileExistsError): module._write_read_image(fd, 'METADATA-RAW', b'replacement')
            self.assertEqual(raw, (self.project / 'METADATA-RAW').read_bytes())
            with mock.patch('os.write', return_value=0), self.assertRaises(module.AttemptJournalHold):
                module._write_read_image(fd, 'HISTORY-RAW', b'incomplete')
            self.assertFalse((self.project / 'HISTORY-RAW').exists())
            self.assertGreaterEqual(sum(name.startswith('.pending-') for name in os.listdir(fd)), 2)
        finally: os.close(fd)

    def test_partial_or_foreign_record_and_gap_fail_closed_without_repair(self):
        module=self.module()
        for name,raw in (("ATTEMPT-2",b"{}"),("ATTEMPT-1",b"partial"),("foreign",b"unknown")):
            with self.subTest(name=name):
                # A separate fresh private project for each independent hostile image.
                with tempfile.TemporaryDirectory(prefix="req7-partial-unit-") as directory:
                    project=Path(directory).resolve(); pub=project/"publication"; pub.mkdir(mode=0o700)
                    create_local_commit_store(project,pub)
                    with writer_owner(project,pub) as token:
                        module.prepare_unit(token,UNIT,BODY)
                        leaf=project/".tracker/remote-attempts"/UNIT/name
                        leaf.write_bytes(raw); leaf.chmod(0o600)
                        with self.assertRaises(module.AttemptJournalHold): module.record_attempt_intent(token,UNIT,BODY)
                        self.assertEqual(raw,leaf.read_bytes())

    def test_failed_directory_barrier_returns_no_observation_and_keeps_evidence(self):
        module=self.module()
        with writer_owner(self.project,self.publication) as token:
            module.prepare_unit(token,UNIT,BODY)
            actual=os.fsync
            def refuse_directory(fd):
                import stat
                if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError("injected directory barrier failure")
                return actual(fd)
            with mock.patch("os.fsync",side_effect=refuse_directory),self.assertRaises(module.AttemptJournalHold):
                module.record_attempt_intent(token,UNIT,BODY)
            folder=self.project/".tracker/remote-attempts"/UNIT
            self.assertTrue(any(p.name.startswith(("ATTEMPT-",".pending-")) for p in folder.iterdir()))

    def test_symlink_hardlink_and_unsafe_wire_remain_untouched(self):
        module=self.module()
        with writer_owner(self.project,self.publication) as token:
            module.prepare_unit(token,UNIT,BODY)
            wire=self.project/".tracker/remote-attempts"/UNIT/"WIRE"
            original=wire.read_bytes(); preserved=wire.with_name("preserved")
            wire.rename(preserved); wire.symlink_to(preserved.name)
            with self.assertRaises(module.AttemptJournalHold): module.record_attempt_intent(token,UNIT,BODY)
            self.assertEqual(original,preserved.read_bytes()); self.assertTrue(wire.is_symlink())

    def test_hardlinked_and_nonprivate_wire_refuse_before_allocating(self):
        module=self.module()
        for fault in ("hardlink","world-readable","group-writable"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix="req7-wire-image-") as directory:
                project=Path(directory).resolve(); pub=project/"publication"; pub.mkdir(mode=0o700)
                create_local_commit_store(project,pub)
                with writer_owner(project,pub) as token:
                    module.prepare_unit(token,UNIT,BODY)
                    folder=project/".tracker/remote-attempts"/UNIT; wire=folder/"WIRE"
                    if fault=="hardlink": os.link(wire,project/"outside-wire-alias")
                    else: wire.chmod(0o644 if fault=="world-readable" else 0o620)
                    before={p.name:p.read_bytes() for p in folder.iterdir()}
                    with self.assertRaises(module.AttemptJournalHold): module.record_attempt_intent(token,UNIT,BODY)
                    self.assertEqual(before,{p.name:p.read_bytes() for p in folder.iterdir()})
                    self.assertFalse((folder/"ATTEMPT-1").exists())

    def test_changed_chain_or_header_refuses_without_repair_or_new_count(self):
        module=self.module()
        for fault in ("header-target","predecessor","counter","outcome"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix="req7-chain-image-") as directory:
                project=Path(directory).resolve(); pub=project/"publication"; pub.mkdir(mode=0o700)
                create_local_commit_store(project,pub)
                with writer_owner(project,pub) as token:
                    module.prepare_unit(token,UNIT,BODY); module.record_attempt_intent(token,UNIT,BODY)
                    folder=project/".tracker/remote-attempts"/UNIT
                    leaf=folder/("HEADER" if fault=="header-target" else "ATTEMPT-1")
                    document=json.loads(leaf.read_bytes())
                    field,value={"header-target":("unit_id","c"*64),"predecessor":("previous_sha256","0"*64),
                                 "counter":("attempt_count",2),"outcome":("outcome","COMPLETE")}[fault]
                    document[field]=value
                    leaf.write_bytes((json.dumps(document,sort_keys=True,separators=(",",":"))+"\n").encode())
                    before={p.name:p.read_bytes() for p in folder.iterdir()}
                    with self.assertRaises(module.AttemptJournalHold): module.record_attempt_intent(token,UNIT,BODY)
                    self.assertEqual(before,{p.name:p.read_bytes() for p in folder.iterdir()})
                    self.assertFalse((folder/"ATTEMPT-2").exists())

    def test_replaced_unit_namespace_returns_hold_and_keeps_original_intent(self):
        module=self.module()
        with writer_owner(self.project,self.publication) as token:
            module.prepare_unit(token,UNIT,BODY)
            folder=self.project/".tracker/remote-attempts"/UNIT
            preserved=folder.with_name("preserved-unit")
            actual=module.local._write_new
            def displace_after_barrier(fd,name,raw):
                actual(fd,name,raw)
                if name=="ATTEMPT-1":
                    folder.rename(preserved); folder.mkdir(mode=0o700)
            with mock.patch.object(module.local,"_write_new",side_effect=displace_after_barrier),self.assertRaises(module.AttemptJournalHold):
                module.record_attempt_intent(token,UNIT,BODY)
            self.assertEqual([],list(folder.iterdir()))
            self.assertEqual(BODY,(preserved/"WIRE").read_bytes())
            self.assertEqual(1,json.loads((preserved/"ATTEMPT-1").read_bytes())["attempt_count"])


class Req7AttemptJournalWorkflowTests(Req7AttemptJournalDirectTests):
    def child(self,attempts,*,crash=False):
        import monitor.issue_tracker_local_commit as local
        main_root=Path(local.__file__).resolve().parents[1]
        source=Path(__file__).resolve().parents[1]/"monitor/issue_tracker_attempt_journal.py"
        code=("import sys,importlib.util,os;from pathlib import Path;sys.path.insert(0,"+repr(str(main_root))+");"
              "from monitor.issue_tracker_local_commit import writer_owner;"
              "s=importlib.util.spec_from_file_location('owned_cold_attempt_journal',"+repr(str(source))+");"
              "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);"
              "project=Path("+repr(str(self.project))+");publication=project/'publication'\n"
              "with writer_owner(project,publication) as token:\n"
              " for _ in range("+repr(attempts)+"):\n"
              "  observed=m.record_attempt_intent(token,"+repr(UNIT)+","+repr(BODY)+")\n"
              +("  os._exit(23)\n" if crash else " print(observed.attempt_count,observed.outcome)\n"))
        return subprocess.run([sys.executable,"-I","-B","-c",code],stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)

    def test_two_native_cold_processes_share_original_six_attempt_limit(self):
        module=self.module()
        with writer_owner(self.project,self.publication) as token: module.prepare_unit(token,UNIT,BODY)
        first=self.child(3); second=self.child(3)
        self.assertEqual((0,b"3 UNKNOWN\n"),(first.returncode,first.stdout),first.stderr)
        self.assertEqual((0,b"6 UNKNOWN\n"),(second.returncode,second.stdout),second.stderr)
        seventh=self.child(1)
        self.assertNotEqual(0,seventh.returncode); self.assertEqual(b"",seventh.stdout)
        with writer_owner(self.project,self.publication) as token:
            self.assertEqual(6,module.inspect_unit(token,UNIT,BODY).attempt_count)

    def test_native_process_death_after_intent_does_not_reset_count_or_unknown(self):
        module=self.module()
        with writer_owner(self.project,self.publication) as token: module.prepare_unit(token,UNIT,BODY)
        crashed=self.child(1,crash=True)
        self.assertEqual((23,b"",b""),(crashed.returncode,crashed.stdout,crashed.stderr))
        with writer_owner(self.project,self.publication) as token:
            before=module.inspect_unit(token,UNIT,BODY)
            self.assertEqual((1,"UNKNOWN"),(before.attempt_count,before.outcome))
        next_process=self.child(1)
        self.assertEqual((0,b"2 UNKNOWN\n"),(next_process.returncode,next_process.stdout),next_process.stderr)

    def test_real_literal_encoder_and_later_rejection_cannot_clear_recorded_unknown(self):
        module=self.module()
        from monitor.issue_tracker_online_cells import encode_tool_cells
        path=Path(__file__).resolve().parents[1]/"monitor/issue_tracker_mutation_rejection.py"
        spec=importlib.util.spec_from_file_location("req7_rejection_journal_workflow",path)
        reject=importlib.util.module_from_spec(spec); sys.modules[spec.name]=reject; spec.loader.exec_module(reject)
        body=encode_tool_cells("ETH&IB Switch",17,"update",{"L":"literal=down"},row_index=31).requests_json
        with mock.patch("socket.socket",side_effect=AssertionError("network forbidden")),writer_owner(self.project,self.publication) as token:
            module.prepare_unit(token,UNIT,body)
            module.record_attempt_intent(token,UNIT,body)
            later=reject.observe_rejection(403,b'{"error":{"code":403,"status":"PERMISSION_DENIED"}}',complete=True)
            self.assertEqual("DEFINITE_REJECTION",later.outcome)
            observed=module.inspect_unit(token,UNIT,body)
            self.assertEqual((1,"UNKNOWN"),(observed.attempt_count,observed.outcome))
            self.assertFalse(hasattr(observed,"permit")); self.assertFalse(hasattr(observed,"receipt"))


if __name__=="__main__": unittest.main()
