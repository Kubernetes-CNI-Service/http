"""Durable original nonces plus actual metadata reads, never online permission."""
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

from test_cases.test_req7_spreadsheet_owner import load as load_owner, fixture, binding, TARGET
from test_cases import test_req7_sheets_read_plan as plans
from test_cases import test_req7_sheets_read_decode as grids
from test_cases import test_req7_metadata_capacity as metadata

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "monitor/issue_tracker_enrollment_journal.py"


def load():
    if not SOURCE.is_file(): raise AssertionError("REQ7 journal-authoritative enrollment nonces missing")
    spec=importlib.util.spec_from_file_location("monitor.issue_tracker_enrollment_journal",SOURCE)
    module=importlib.util.module_from_spec(spec); sys.modules[spec.name]=module
    spec.loader.exec_module(module); return module


class Req7EnrollmentJournalDirectTests(unittest.TestCase):
    def setUp(self):
        plans.Req7SheetsReadPlanDirectTests.setUp(self); self.planner=self.module
        self.capacity=metadata.load(); self.decoder=sys.modules["monitor.issue_tracker_sheets_read_decode"]
        self.identity=self.decoder.decode_template_identity(self.planner.prepare_template_identity_read(self.binding,self.token),
                                                            grids.response(grids.identity_response()))
        self.owner=load_owner(); self.module=load()
        self.temp=tempfile.TemporaryDirectory(prefix="req7-enrollment-"); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve(); self.state=self.root/"var/lib/http-ztp-container/issue-tracker"
        self.state.mkdir(parents=True,mode=0o700)
        self.store=self.state/(hashlib.sha256(TARGET.encode()).hexdigest()+".enrollment")

    def prepare(self,token): return self.module.prepare_enrollment_journal(token,binding(),self.identity)
    def inspect(self,token): return self.module.inspect_enrollment_journal(token,binding(),self.identity)

    def test_four_independent_random_nonces_persist_before_genuine_initialization_and_reopen_without_regeneration(self):
        values=["a"*64,"b"*64,"c"*64,"d"*64]
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            with mock.patch("secrets.token_hex",side_effect=values) as random:
                result=self.prepare(token)
            self.assertEqual([mock.call(32)]*4,random.call_args_list)
            self.assertEqual((("ETH&IB Switch",101,"a"*64),("ETH Cabling",102,"b"*64),
                              ("IB Cabling",103,"c"*64),("Update_History",105,"d"*64)),result.nonces)
            self.assertEqual({"NONCES","HEADER","INITIALIZED"},set(os.listdir(self.store)))
            for private in values: self.assertNotIn(private,repr(result))
            with self.assertRaises(AttributeError): result.nonces=()
        before={p.name:p.read_bytes() for p in self.store.iterdir()}
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as fresh,mock.patch("secrets.token_hex",side_effect=AssertionError("no regeneration")):
            self.assertEqual(result,self.inspect(fresh))
            with self.assertRaises(self.module.EnrollmentHold): self.prepare(fresh)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.store.iterdir()})
        self.assertFalse(hasattr(result,"permit")); self.assertFalse(hasattr(result,"remote_enrolled"))

    def test_every_image_barrier_failure_retains_partial_store_without_marker_or_recovery_adoption(self):
        real=os.fsync
        for boundary in range(1,7):
            with self.subTest(boundary=boundary),tempfile.TemporaryDirectory(prefix="req7-enrollment-fault-") as directory:
                root=Path(directory).resolve(); state=root/"var/lib/http-ztp-container/issue-tracker"; state.mkdir(parents=True,mode=0o700)
                store=state/self.store.name
                with fixture(root),self.owner.spreadsheet_owner(binding()) as token:
                    calls=[]
                    def failing(fd):
                        calls.append(fd)
                        if len(calls)==boundary: raise OSError("private sentinel")
                        return real(fd)
                    with mock.patch("os.fsync",side_effect=failing),self.assertRaises(self.module.EnrollmentHold): self.prepare(token)
                    self.assertTrue(store.exists()); self.assertFalse((store/"INITIALIZED").exists())
                    with self.assertRaises(self.module.EnrollmentHold): self.inspect(token)
                    with self.assertRaises(self.module.EnrollmentHold): self.prepare(token)

    def test_duplicate_malformed_or_failed_randomness_never_creates_a_repairable_nonce_store(self):
        for values in (["a"*64]*4,["a"*64,"b"*64,"c"*64,"bad"],RuntimeError("private randomness")):
            with self.subTest(kind=type(values).__name__),tempfile.TemporaryDirectory(prefix="req7-nonce-input-") as directory:
                root=Path(directory).resolve(); state=root/"var/lib/http-ztp-container/issue-tracker"; state.mkdir(parents=True,mode=0o700)
                with fixture(root),self.owner.spreadsheet_owner(binding()) as token,mock.patch("secrets.token_hex",side_effect=values):
                    with self.assertRaises(self.module.EnrollmentHold) as caught: self.prepare(token)
                    self.assertIsNone(caught.exception.__context__); self.assertNotIn("private",str(caught.exception))
                self.assertFalse((state/self.store.name).exists())

    def test_revoked_owner_changed_target_or_sheet_identity_never_rewrites_original_nonces(self):
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token: self.prepare(token)
        before={p.name:p.read_bytes() for p in self.store.iterdir()}
        with fixture(self.root),self.assertRaises(self.module.EnrollmentHold): self.inspect(token)
        changed=replace(self.identity,sheet_ids=tuple((title,999 if title=="ETH&IB Switch" else sid) for title,sid in self.identity.sheet_ids))
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as fresh:
            with self.assertRaises(self.module.EnrollmentHold): self.module.inspect_enrollment_journal(fresh,binding(),changed)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.store.iterdir()})

    def test_native_cold_process_reopens_same_original_nonce_digest_without_randomness(self):
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            expected=self.prepare(token).journal_sha256
        # Cold storage/OS ownership test, not an isolated SDK/transport proof;
        # retain the configured dependency environment as with global counts.
        code="""import sys,json,pathlib
sys.path.insert(0,sys.argv[2]); sys.path.insert(0,str(pathlib.Path(sys.argv[2])/'tools'))
from test_cases.test_req7_enrollment_journal import load
from test_cases.test_req7_spreadsheet_owner import load as owner_load,fixture,binding
from monitor.issue_tracker_sheets_read_decode import ObservedTemplateIdentity
from unittest import mock
owner=owner_load(); module=load()
identity=ObservedTemplateIdentity(binding().spreadsheet_id,tuple(tuple(x) for x in json.loads(sys.argv[3])),'a'*64)
with fixture(pathlib.Path(sys.argv[1])),owner.spreadsheet_owner(binding()) as token,mock.patch('secrets.token_hex',side_effect=AssertionError('no regeneration')):
    print(module.inspect_enrollment_journal(token,binding(),identity).journal_sha256)
"""
        completed=subprocess.run([sys.executable,"-B","-c",code,str(self.root),str(ROOT),json.dumps(self.identity.sheet_ids)],
                                 stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
        self.assertEqual(0,completed.returncode,completed.stderr); self.assertEqual(expected+"\n",completed.stdout)

    def test_symlink_hardlink_tamper_extra_file_and_mode_are_preserved_hold_not_nonce_repair(self):
        for fault in ("symlink","hardlink","tamper","extra","mode"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix="req7-nonce-tamper-") as directory:
                root=Path(directory).resolve(); state=root/"var/lib/http-ztp-container/issue-tracker"; state.mkdir(parents=True,mode=0o700)
                store=state/self.store.name
                with fixture(root),self.owner.spreadsheet_owner(binding()) as token:
                    self.prepare(token)
                    if fault in ("symlink","hardlink"):
                        (store/"NONCES").rename(root/"preserved")
                        if fault=="symlink": (store/"NONCES").symlink_to(root/"preserved")
                        else: os.link(root/"preserved",store/"NONCES")
                    elif fault=="tamper": (store/"NONCES").write_bytes(b"foreign")
                    elif fault=="extra": (store/"foreign").write_bytes(b"foreign")
                    else: (store/"NONCES").chmod(0o644)
                    with self.assertRaises(self.module.EnrollmentHold): self.inspect(token)
                    self.assertTrue(store.exists())

    def test_compiled_unit_must_match_both_original_journal_nonces_and_actual_sheet_ids(self):
        from test_cases.test_req7_send_unit import inputs
        from monitor.issue_tracker_send_unit import freeze_send_unit
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            observed=self.prepare(token); nonces={name:(sid,nonce) for name,sid,nonce in observed.nonces}
            args=inputs(); args.update(sheet_id=101,history_sheet_id=105,target_nonce=nonces["ETH&IB Switch"][1],history_nonce=nonces["Update_History"][1])
            unit=freeze_send_unit(**args)
            self.module.require_unit_enrollment(token,binding(),self.identity,unit)
            for changes in ({"target_nonce":"e"*64},{"history_nonce":"e"*64},{"sheet_id":18},{"history_sheet_id":99}):
                altered=dict(args); altered.update(changes)
                with self.assertRaises(self.module.EnrollmentHold):
                    self.module.require_unit_enrollment(token,binding(),self.identity,freeze_send_unit(**altered))

    def test_remote_exact_document_sheet_pair_matches_local_original_not_caller_nonce_or_marker_alone(self):
        plan=self.capacity.prepare_metadata_capacity_read(self.binding,self.token)
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            observed=self.prepare(token); local={name:(sid,nonce) for name,sid,nonce in observed.nonces}
            entries=(metadata.entry(201,"http-ztp-enrollment-v1",local["ETH&IB Switch"][1],sheet=101),
                     metadata.entry(202,"http-ztp-enrollment-v1",local["Update_History"][1],sheet=105))
            result=self.module.observe_enrollment_pair(token,binding(),self.identity,plan,metadata.reply(entries),sheet="ETH&IB Switch")
            self.assertIs(True,result.target_nonce_valid); self.assertIs(True,result.history_nonce_valid)
            self.assertFalse(hasattr(result,"complete")); self.assertFalse(hasattr(result,"permit"))
            for value in local.values(): self.assertNotIn(value[1],repr(result))
            bad_cases=(entries[:1],(),(entries[0],entries[0],entries[1]),
                       (metadata.entry(201,"http-ztp-enrollment-v1","e"*64,sheet=101),entries[1]),
                       (metadata.entry(201,"http-ztp-enrollment-v1",entries[0]["metadataValue"],sheet=101,visibility="PROJECT"),entries[1]),
                       (metadata.entry(201,"http-ztp-enrollment-v1",entries[0]["metadataValue"],sheet=None),entries[1]))
            for bad in bad_cases:
                with self.subTest(entries=len(bad)),self.assertRaises(self.module.EnrollmentHold):
                    self.module.observe_enrollment_pair(token,binding(),self.identity,plan,metadata.reply(bad),sheet="ETH&IB Switch")

    def test_incomplete_non200_duplicate_json_or_foreign_metadata_request_never_yields_nonce_valid_flags(self):
        from types import SimpleNamespace
        plan=self.capacity.prepare_metadata_capacity_read(self.binding,self.token)
        raw=(SimpleNamespace(status=200,complete=False,data=b"private sentinel"),
             SimpleNamespace(status=403,complete=True,data=b"private sentinel"),
             SimpleNamespace(status=True,complete=True,data=b"{}"),
             SimpleNamespace(status=200,complete=True,data=b'{"matchedDeveloperMetadata":[],"matchedDeveloperMetadata":[]}'))
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            for response in raw:
                with self.subTest(status=response.status),self.assertRaises(self.module.EnrollmentHold) as caught:
                    self.module.observe_enrollment_pair(token,binding(),self.identity,plan,response,sheet="ETH&IB Switch")
                self.assertIsNone(caught.exception.__context__); self.assertNotIn("private",str(caught.exception))
            with self.assertRaises(self.module.EnrollmentHold):
                self.module.observe_enrollment_pair(token,binding(),self.identity,replace(plan,path=plan.path+"&foreign=1"),metadata.reply(),sheet="ETH&IB Switch")


class Req7EnrollmentJournalWorkflowTests(unittest.TestCase):
    def test_actual_global_owner_nonce_store_composer_and_compiled_action_journal_preserve_same_pair(self):
        from test_cases.test_req7_send_unit import inputs
        from monitor.issue_tracker_send_unit import freeze_send_unit
        from monitor.issue_tracker_send_intent import prepare_send_intent,inspect_send_intent
        from monitor.issue_tracker_local_commit import create_local_commit_store,writer_owner
        setup=Req7EnrollmentJournalDirectTests("test_four_independent_random_nonces_persist_before_genuine_initialization_and_reopen_without_regeneration")
        setup.setUp(); self.addCleanup(setup.doCleanups)
        project=setup.root/"project"; project.mkdir(); publication=project/"publication"; publication.mkdir()
        create_local_commit_store(project,publication)
        with writer_owner(project,publication) as project_token:
            with fixture(setup.root),setup.owner.spreadsheet_owner(binding()) as global_token:
                values={name:(sid,nonce) for name,sid,nonce in setup.prepare(global_token).nonces}
                args=inputs(); args.update(sheet_id=101,history_sheet_id=105,target_nonce=values["ETH&IB Switch"][1],history_nonce=values["Update_History"][1])
                unit=freeze_send_unit(**args); setup.module.require_unit_enrollment(global_token,binding(),setup.identity,unit)
            prepare_send_intent(project_token,unit)
            result=inspect_send_intent(project_token,unit)
            self.assertEqual(unit.action_digest,result.action_digest); self.assertEqual(0,result.attempt_count)
            action=json.loads(unit.action_preimage)
            self.assertEqual(values["ETH&IB Switch"][1],action["target_nonce"])
            self.assertEqual(values["Update_History"][1],action["history_nonce"])

    def test_governed_multi_script_mapping_and_real_environment_card_exist(self):
        manifest=json.loads((ROOT/"test_cases/script_test_manifest.json").read_text())
        script="monitor/issue_tracker_enrollment_journal.py"
        self.assertEqual(script,manifest["scripts"].get(script))
        self.assertTrue(any(script in rule["paths"] and "test_cases.test_req7_enrollment_journal" in rule["tests"] for rule in manifest["test_rules"]))
        self.assertTrue(any({script,"monitor/issue_tracker_spreadsheet_owner.py","monitor/issue_tracker_send_intent.py"}<=set(rule["members"])
                            and "test_cases.test_req7_enrollment_journal" in rule["tests"] for rule in manifest["workflows"]))
        self.assertIn("TC-REAL-REQ7-ENROLLMENT-JOURNAL-001",(ROOT/"test_cases/REAL_ENVIRONMENT.md").read_text())


class Req7EnrollmentJournalNativeReadWorkflowTests(unittest.TestCase):
    setUp=plans.Req7SheetsNativeReadWorkflowTests.setUp
    fixture=plans.Req7SheetsNativeReadWorkflowTests.fixture
    certificates=plans.Req7SheetsNativeReadWorkflowTests.certificates
    server=plans.Req7SheetsNativeReadWorkflowTests.server

    def test_actual_native_metadata_search_matches_both_retained_journal_nonces_not_complete(self):
        setup=Req7EnrollmentJournalDirectTests("test_four_independent_random_nonces_persist_before_genuine_initialization_and_reopen_without_regeneration")
        setup.setUp(); self.addCleanup(setup.doCleanups)
        with fixture(setup.root),setup.owner.spreadsheet_owner(binding()) as token:
            values={name:(sid,nonce) for name,sid,nonce in setup.prepare(token).nonces}
        entries=tuple(metadata.entry(201+i,"http-ztp-enrollment-v1",values[title][1],sheet=values[title][0])
                      for i,title in enumerate(("ETH&IB Switch","Update_History")))
        payload=metadata.reply(entries).data
        wire=("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"%len(payload)).encode()+payload
        unit=setup.capacity.NativeMetadataCapacityReadUnit(setup.binding,setup.token)
        plan=setup.capacity.prepare_metadata_capacity_read(setup.binding,setup.token)
        with self.server(wire,hostname="sheets.googleapis.com",destination="sheets.googleapis.com") as (records,errors):
            with self.fixture(),mock.patch.dict(sys.modules,{"monitor.issue_tracker_tls_inputs":self.module}):
                raw=unit.send_once()
                with self.assertRaises(setup.capacity.MetadataCapacityHold): unit.send_once()
        with fixture(setup.root),setup.owner.spreadsheet_owner(binding()) as token:
            result=setup.module.observe_enrollment_pair(token,binding(),setup.identity,plan,raw,sheet="ETH&IB Switch")
        self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(metadata.BODY,records[0][2])
        self.assertIs(True,result.target_nonce_valid); self.assertIs(True,result.history_nonce_valid)
        self.assertFalse(hasattr(result,"complete")); self.assertFalse(hasattr(result,"permit"))


if __name__=="__main__": unittest.main()
