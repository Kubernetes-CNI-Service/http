"""Independent local generation expectations; no bash/SSH/SDK/children."""
import contextlib
import datetime as dt
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

SUBJECT="tools.ufm_deployment_script_builder"
GLOBAL_BYTES=b"""common:
  switch:
    password: DO_NOT_COPY_INPUT_SECRET_20261013
servers:
- ufm:
    version: 2.5.1-8
    interfaces:
      alias:
        eth0: eno8303
        eth1: eno8403
"""
CSV_BYTES=b"hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\nEXAMPLE-UFM01,ufm,NA,192.0.2.21,24,192.0.2.1,02:00:00:00:00:21\nEXAMPLE-UFM02,ufm,NA,192.0.2.22,24,192.0.2.1,02:00:00:00:00:22\n"

def subject(test):
    spec=importlib.util.find_spec(SUBJECT)
    test.assertIsNotNone(spec,"fixed local stage-script generation entry is absent")
    return importlib.import_module(SUBJECT)

@contextlib.contextmanager
def actual_site():
    with tempfile.TemporaryDirectory() as directory:
        owned=Path(directory).resolve()
        http=owned/"http";project=http/"DAY0-Prepare/project"
        project.mkdir(parents=True);(http/"monitor").mkdir()
        (project/"01-global.yaml").write_bytes(GLOBAL_BYTES)
        (project/"02-devices_config.csv").write_bytes(CSV_BYTES)
        (http/"monitor/02-devices_config.csv").symlink_to("../DAY0-Prepare/project/02-devices_config.csv")
        logs=owned/"private/xdr-initial-setup-logs";logs.mkdir(parents=True);logs.chmod(0o700)
        yield http,project,logs

def expected_script(run_id):
    return ("#!/usr/bin/env bash\nset -euo pipefail\numask 077\n"
        "# F01 phase1_readonly_preflight: GENERATED_NOT_EXECUTED; no deployment completion\n"
        "printf '%s\\n' 'F01_READ_ONLY_PREFLIGHT' 'run-id="+run_id+
        "' 'node=EXAMPLE-UFM01' 'phase=phase1_readonly_preflight'\n"
        "if ! sudo -n -- true; then\n"
        "  printf '%s\\n' 'F01_BLOCKED_SUDO_CHECK' >&2\n"
        "  exit 73\nfi\n"
        "hostname\nip -j link show dev eno8303\nip -j address show dev eno8303\n").encode()

class F01StageScriptBuilderDirectTests(unittest.TestCase):
    def test_fixed_template_contains_only_readonly_probe_and_no_secret_or_vendor_write(self):
        api=subject(self)
        run_id="20261013T000000Z-"+"1"*32
        raw=api._render_stage_probe("EXAMPLE-UFM01","eno8303",run_id)
        self.assertEqual(expected_script(run_id),raw)
        for forbidden in (b"DO_NOT_COPY_INPUT_SECRET",b"passwd",b"reboot",b"docker",b"ufm_ha_cluster",b"authorized_keys"):
            self.assertNotIn(forbidden,raw)
        with self.assertRaises(api.ScriptBuildHold):
            api._render_stage_probe("EXAMPLE-UFM01","eno8303;echo unsafe",run_id)

    def test_public_http_project_or_symlink_log_root_and_unknown_write_stage_refuse_without_artifacts(self):
        api=subject(self)
        with actual_site() as (http,project,logs),mock.patch.object(api,"HTTP_ROOT",http):
            for root in (http/"xdr-initial-setup-logs",project/"xdr-initial-setup-logs"):
                root.mkdir(mode=0o700)
                with self.assertRaises(api.ScriptBuildHold):
                    api.generate_stage_script(address="192.0.2.21",private_logs_root=root)
                self.assertEqual([],list(root.iterdir()))
            alias_parent=logs.parent/"alias";alias_parent.mkdir()
            link=alias_parent/"xdr-initial-setup-logs";link.symlink_to("../xdr-initial-setup-logs")
            with self.assertRaises(api.ScriptBuildHold):
                api.generate_stage_script(address="192.0.2.21",private_logs_root=link)
            with self.assertRaises(api.ScriptBuildHold):
                api.generate_stage_script(address="192.0.2.21",private_logs_root=logs,stage="phase2_upgrade")
            self.assertEqual([],list(logs.iterdir()))

    def test_named_a_opened_b_rejects_admission_but_closes_actual_owned_b_not_foreign_reuse(self):
        api=subject(self)
        for boundary in ("directory-init","directory-child","source"):
            with self.subTest(boundary=boundary),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve();selected=root/"selected";backup=root/"original-a"
                if boundary=="source":selected.write_bytes(b"named A original bytes")
                else:selected.mkdir(mode=0o700)
                original_open=os.open;original_close=os.close;actual=[];closed=[];fault=[]
                def replacement_open(name,*args,**kwargs):
                    named=(Path(name) if os.path.isabs(os.fspath(name)) else root/os.fspath(name))
                    if not fault and named==selected:
                        fault.append(True);selected.rename(backup)
                        if boundary=="source":selected.write_bytes(b"actual B different bytes")
                        else:selected.mkdir(mode=0o700)
                        fd=original_open(name,*args,**kwargs);value=os.fstat(fd)
                        actual.append((fd,(value.st_dev,value.st_ino)))
                        return fd
                    return original_open(name,*args,**kwargs)
                def close_original(fd):
                    value=os.fstat(fd)
                    matched=any(fd==n and (value.st_dev,value.st_ino)==key for n,key in actual)
                    result=original_close(fd)
                    if matched:closed.append(fd)
                    return result
                try:
                    with mock.patch.object(os,"open",side_effect=replacement_open),mock.patch.object(os,"close",side_effect=close_original):
                        with self.assertRaises(api.ScriptBuildHold):
                            if boundary=="source":api._capture_source(selected)
                            elif boundary=="directory-init":api._Directories(selected,private=True)
                            else:
                                owner=api._Directories(root,private=True)
                                try:owner.child("selected")
                                finally:owner.close()
                    self.assertEqual([True],fault);self.assertEqual(1,len(actual))
                    self.assertEqual([actual[0][0]],closed,"actual opened B, not rejected named A, must be conditionally closed")
                finally:
                    for fd,key in actual:
                        try:
                            value=os.fstat(fd)
                            if (value.st_dev,value.st_ino)==key:original_close(fd)
                        except OSError:pass
        # Actual B's first stat is real; a subsequent dup2 foreign slot is
        # neither named-A authority nor actual-B conditional cleanup.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();selected=root/"selected"
            selected.write_bytes(b"named A");foreign=root/"foreign"
            foreign.write_bytes(b"foreign bytes unchanged")
            original_open=os.open;original_close=os.close;original_stat=os.fstat
            foreign_fd=original_open(foreign,os.O_RDWR);os.lseek(foreign_fd,3,os.SEEK_SET)
            fd_holder=[];replaced=[];stat_hit=[];closed_foreign=[]
            def open_b(name,*args,**kwargs):
                if not replaced and Path(name)==selected:
                    replaced.append(True);selected.rename(root/"original-a");selected.write_bytes(b"actual B")
                    fd=original_open(name,*args,**kwargs);fd_holder.append(fd);return fd
                return original_open(name,*args,**kwargs)
            def first_b_then_foreign(fd):
                value=original_stat(fd)
                if fd_holder and fd==fd_holder[0] and not stat_hit:
                    stat_hit.append(True);os.dup2(foreign_fd,fd)
                return value
            def observed_close(fd):
                if fd_holder and fd==fd_holder[0]:closed_foreign.append(fd)
                return original_close(fd)
            try:
                with mock.patch.object(os,"open",side_effect=open_b),mock.patch.object(os,"fstat",side_effect=first_b_then_foreign),mock.patch.object(os,"close",side_effect=observed_close):
                    with self.assertRaises(api.ScriptBuildHold):api._capture_source(selected)
                self.assertEqual([True],stat_hit);self.assertEqual([],closed_foreign)
                self.assertEqual(3,os.lseek(foreign_fd,0,os.SEEK_CUR))
                self.assertEqual(b"foreign bytes unchanged",os.pread(foreign_fd,64,0))
                self.assertEqual((original_stat(foreign_fd).st_dev,original_stat(foreign_fd).st_ino),
                    (original_stat(fd_holder[0]).st_dev,original_stat(fd_holder[0]).st_ino))
            finally:
                if fd_holder:original_close(fd_holder[0])
                original_close(foreign_fd)

class F01StageScriptBuilderInputWorkflowTests(unittest.TestCase):
    def test_actual_selected_global_csv_generate_private_unique_node_stage_and_exact_hashes_without_execution(self):
        api=subject(self)
        with actual_site() as (http,project,logs),mock.patch.object(api,"HTTP_ROOT",http):
            start=dt.datetime.now(dt.timezone.utc)
            first=api.generate_stage_script(address="192.0.2.21",private_logs_root=logs)
            second=api.generate_stage_script(address="192.0.2.21",private_logs_root=logs)
            end=dt.datetime.now(dt.timezone.utc)
            self.assertNotEqual(first.run_id,second.run_id)
            project_key=hashlib.sha256(str(project).encode()).hexdigest()
            for result in (first,second):
                self.assertRegex(result.run_id,r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}$")
                sampled=dt.datetime.strptime(result.run_id[:16],"%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
                self.assertLessEqual(start.replace(microsecond=0),sampled)
                self.assertLessEqual(sampled,end.replace(microsecond=0))
                location=logs/project_key/result.run_id/"EXAMPLE-UFM01"/"phase1_readonly_preflight"
                self.assertEqual(location/"stage.sh",result.script_path)
                self.assertEqual(location/"manifest.json",result.manifest_path)
                self.assertEqual(expected_script(result.run_id),result.script_path.read_bytes())
                metadata=json.loads(result.manifest_path.read_bytes())
                self.assertEqual({"schema_version","state","project_key","project_root","run_id","node","node_ipv4",
                    "management_interface","stage","login_user","interpreter","input_sha256","script_sha256",
                    "script_bytes","syntax_check","sudo_check_scope","execution_permitted","completion"},set(metadata))
                self.assertEqual({"01-global.yaml":hashlib.sha256(GLOBAL_BYTES).hexdigest(),
                    "02-devices_config.csv":hashlib.sha256(CSV_BYTES).hexdigest()},metadata["input_sha256"])
                self.assertEqual(hashlib.sha256(expected_script(result.run_id)).hexdigest(),metadata["script_sha256"])
                self.assertEqual(("GENERATED_NOT_EXECUTED","NOT_RUN",False,False),
                    (metadata["state"],metadata["syntax_check"],metadata["execution_permitted"],metadata["completion"]))
                self.assertEqual(("admin","bash","phase1_readonly_preflight","EXAMPLE-UFM01","eno8303"),
                    (metadata["login_user"],metadata["interpreter"],metadata["stage"],metadata["node"],metadata["management_interface"]))
                self.assertEqual("sudo -n true only; not NOPASSWD or vendor command permission",metadata["sudo_check_scope"])
                self.assertEqual(0o600,result.script_path.stat().st_mode&0o777)
                self.assertEqual(0o600,result.manifest_path.stat().st_mode&0o777)
                for folder in (location,location.parent,location.parent.parent,location.parent.parent.parent):
                    self.assertEqual(0o700,folder.stat().st_mode&0o777)
                self.assertNotIn(b"DO_NOT_COPY_INPUT_SECRET",result.script_path.read_bytes()+result.manifest_path.read_bytes())
            self.assertEqual(GLOBAL_BYTES,(project/"01-global.yaml").read_bytes())
            self.assertEqual(CSV_BYTES,(project/"02-devices_config.csv").read_bytes())

    def test_actual_original_fd_same_length_or_return_time_script_mutation_refuses_and_retains_failure(self):
        api=subject(self)
        for fault in ("same-original-fd","after-manifest"):
            with self.subTest(fault=fault),actual_site() as (http,project,logs),mock.patch.object(api,"HTTP_ROOT",http):
                original_write=os.write;changed=[]
                def actual_corrupt(fd,data):
                    result=original_write(fd,data)
                    if not changed and fault=="same-original-fd" and bytes(data).startswith(b"#!/usr/bin/env bash"):
                        changed.append(True);raw=bytes(data);os.pwrite(fd,b"!"+raw[1:],0)
                    elif not changed and fault=="after-manifest" and b'"script_sha256"' in bytes(data):
                        changed.append(True);stage=next(logs.rglob("stage.sh"));original=stage.read_bytes()
                        with stage.open("r+b") as fixture_owned:fixture_owned.write(b"!"+original[1:])
                    return result
                with mock.patch.object(os,"write",side_effect=actual_corrupt):
                    with self.assertRaises(api.ScriptBuildHold):
                        api.generate_stage_script(address="192.0.2.21",private_logs_root=logs)
                self.assertEqual([True],changed)
                evidence=list(logs.rglob("failure.json"));self.assertEqual(1,len(evidence))
                failure=json.loads(evidence[0].read_bytes())
                self.assertEqual("FAILED_NOT_EXECUTED",failure["state"])
                self.assertFalse(failure["execution_permitted"]);self.assertFalse(failure["completion"])

    def test_actual_input_drift_after_staged_script_preserves_failure_evidence_not_success(self):
        api=subject(self)
        with actual_site() as (http,project,logs),mock.patch.object(api,"HTTP_ROOT",http):
            original_write=os.write;injected=[]
            def actual_write(fd,data):
                value=original_write(fd,data)
                if not injected and bytes(data).startswith(b"#!/usr/bin/env bash"):
                    injected.append(True)
                    (project/"01-global.yaml").write_bytes(GLOBAL_BYTES+b"# changed while generating\n")
                return value
            with mock.patch.object(os,"write",side_effect=actual_write):
                with self.assertRaises(api.ScriptBuildHold):
                    api.generate_stage_script(address="192.0.2.21",private_logs_root=logs)
            self.assertEqual([True],injected)
            self.assertEqual([],list(logs.rglob("manifest.json")))
            evidence=list(logs.rglob("failure.json"))
            self.assertEqual(1,len(evidence))
            failure=json.loads(evidence[0].read_bytes())
            self.assertEqual("FAILED_NOT_EXECUTED",failure["state"])
            self.assertFalse(failure["execution_permitted"]);self.assertFalse(failure["completion"])
            self.assertEqual(0o600,evidence[0].stat().st_mode&0o777)
