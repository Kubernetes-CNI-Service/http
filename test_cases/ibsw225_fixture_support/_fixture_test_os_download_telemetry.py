"""OS download contract: real rendered shell + collector/driver workflow.

All curl/NVOS/SSH IO is synthetic. Numeric expectations are explicit, not
derived from the production parser. No package, service or device is touched.
"""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import ibsw_upgrade_component as component
import ibsw_upgrade_contract as contract
import ibsw_upgrade_driver as driver
import ibsw_upgrade_executor as executor
import ibsw_upgrade_pipeline as pipeline
import test_nvos_observations as tables
import test_three_component_workflow as native

LINE=b'IBSW_DOWNLOAD_RESULT=1|1700000000|1700000599|0|200|2966461709|599.500|4948226.370\n'


class DownloadDirectTests(unittest.TestCase):
    def test_failed_transfers_are_bounded_and_never_start_nv_install(self):
        for code,http,expected_attempts in ((28,'200',4),(22,'404',1)):
            with self.subTest(code=code),tempfile.TemporaryDirectory() as directory:
                root=Path(directory); binaries=root/'bin'; binaries.mkdir()
                curl=binaries/'curl'
                curl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CURL_ARGS"\n'
                    f'printf "{http}|12345|600.000|20.575"\nexit {code}\n')
                curl.chmod(0o700)
                sleeper=binaries/'sleep'; sleeper.write_text('#!/bin/sh\nexit 0\n'); sleeper.chmod(0o700)
                nv=binaries/'nv'; nv.write_text('#!/bin/sh\nprintf "UNEXPECTED" >> "$NV_CALLS"\n'); nv.chmod(0o700)
                policy=contract.normalize_upgrade(contract.load_global_text(tables.COMPLETE_GLOBAL),
                    selected=('os',),method='http')
                node=contract.InventoryDevice('ew-spine01.example','192.0.2.1','02:00:00:00:00:01')
                step=root/'step.sh'
                step.write_text(component.render_declared_step(policy,node,component='os',package_index=1,
                    run_id='timeout-test',method='http',switch_dir=str(root)).script)
                env=dict(os.environ,PATH=str(binaries)+os.pathsep+os.environ['PATH'],
                         CURL_ARGS=str(root/'args'),NV_CALLS=str(root/'nv'))
                result=subprocess.run(['bash',str(step)],env=env,capture_output=True,timeout=8)
                self.assertEqual(result.returncode,code,result.stderr)
                rows=component.parse_download_results(result.stdout)
                self.assertEqual(len(rows),expected_attempts)
                self.assertTrue(all(row['curl_exit']==code for row in rows))
                self.assertTrue(all(row['elapsed_seconds']==600.0 for row in rows))
                self.assertFalse((root/'nv').exists())
                self.assertNotIn(b'IBSW_STAGE=WAIT_DOWNLOAD_RECORD',result.stdout)
                self.assertEqual(len((root/'args').read_text().splitlines()),expected_attempts)

    def test_numeric_report_and_ack_are_strict_and_not_upgrade_success(self):
        rows=component.parse_download_results(LINE)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['attempt'],1)
        self.assertEqual(rows[0]['bytes_downloaded'],2966461709)
        self.assertEqual(rows[0]['elapsed_seconds'],599.5)
        self.assertEqual(rows[0]['average_bytes_per_second'],4948226.37)
        self.assertEqual(rows[0]['curl_exit'],0)
        self.assertNotIn('activation_state',rows[0])
        for invalid in (LINE.replace(b'599.500',b'nan'),LINE+LINE,
                        LINE.replace(b'=1|',b'=5|'),LINE.replace(b'|0|200|',b'|999|200|')):
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):
                component.parse_download_results(invalid)
        # A growing log's incomplete final line is not a complete observation.
        self.assertEqual(component.parse_download_results(LINE[:-1]),[])

    def test_os_jitter_has_eight_device_buckets_and_no_firmware_delay(self):
        self.assertEqual([pipeline.os_jitter_window(n) for n in (1,8,9,16,17,24,25,32)],
                         [60,60,120,120,180,180,240,240])
        with patch.object(pipeline.secrets,'randbelow',return_value=44):
            self.assertEqual(pipeline.os_start_delay(8,canary=False),44)
            self.assertEqual(pipeline.os_start_delay(8,canary=True),0)

    def test_real_os_shell_waits_for_saved_telemetry_before_any_nv_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); bin_dir=root/'bin'; bin_dir.mkdir()
            curl=bin_dir/'curl'
            curl.write_text('#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n'
                'a=sys.argv[1:]; Path(os.environ["CURL_ARGS"]).write_text(json.dumps(a))\n'
                'Path(a[a.index("-o")+1]).write_bytes(b"SYNTHETIC-NOT-FIRMWARE")\n'
                'print("200|2966461709|599.500|4948226.370",end="")\n')
            curl.chmod(0o700)
            nv=bin_dir/'nv'
            nv.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$NV_CALLS"\n')
            nv.chmod(0o700)
            policy=contract.normalize_upgrade(contract.load_global_text(tables.COMPLETE_GLOBAL),
                                              selected=('os',),method='http')
            node=contract.InventoryDevice('ew-spine01.example','192.0.2.1','02:00:00:00:00:01')
            script=component.render_declared_step(policy,node,component='os',package_index=1,
                run_id='telemetry-test',method='http',switch_dir=str(root)).script
            step=root/'step.sh'; step.write_text(script)
            output=root/'execution.stdout'; errors=root/'execution.stderr'
            env=dict(os.environ,PATH=str(bin_dir)+os.pathsep+os.environ['PATH'],
                     CURL_ARGS=str(root/'curl-args.json'),NV_CALLS=str(root/'nv-calls.txt'))
            with output.open('wb') as out,errors.open('wb') as err:
                process=subprocess.Popen(['bash',str(step)],stdout=out,stderr=err,env=env)
                try:
                    until=time.monotonic()+8
                    while b'IBSW_STAGE=WAIT_DOWNLOAD_RECORD\n' not in output.read_bytes():
                        if process.poll() is not None or time.monotonic()>until:
                            self.fail(output.read_text()+errors.read_text())
                        time.sleep(0.02)
                    self.assertFalse((root/'nv-calls.txt').exists(),'install must wait for manager record')
                    args=json.loads((root/'curl-args.json').read_text())
                    self.assertEqual(args[args.index('--max-time')+1],'600')
                    row=component.parse_download_results(output.read_bytes())[0]
                    ack=component.download_ack_bytes('telemetry-test',row['raw_line'].encode())
                    (root/'download-ack').write_bytes(ack)
                    self.assertEqual(process.wait(timeout=8),0,errors.read_text())
                    calls=(root/'nv-calls.txt').read_text().splitlines()
                    self.assertEqual(len(calls),2)
                    self.assertTrue(calls[0].startswith('action fetch system image '))
                    self.assertTrue(calls[1].startswith('action install system image '))
                finally:
                    if process.poll() is None:
                        process.terminate(); process.wait(timeout=5)


class DownloadWorkflowTests(unittest.TestCase):
    def test_original_probe_commits_each_attempt_before_ack_and_keeps_it_after_wipe(self):
        fixture=native.ThreeComponentWorkflowTests()
        with tempfile.TemporaryDirectory() as directory:
            code,report,err,calls,installs=fixture.invoke(Path(directory).resolve(),selection=('--os-only',),
                controlled_grace=True,download_telemetry=True,wipe_remote_on_reboot=True)
            self.assertEqual(code,0,err)
            self.assertEqual(len(installs),1,'telemetry must not cause install redispatch')
            path=Path(report['run_directory'])/native.HOST/'os-0001/download-attempt-01.json'
            record=json.loads(path.read_text())
            self.assertEqual(record['measurement']['bytes_downloaded'],2966461709)
            self.assertEqual(record['measurement']['elapsed_seconds'],599.5)
            self.assertEqual(record['measurement']['average_bytes_per_second'],4948226.37)
            self.assertEqual(record['state'],'DOWNLOAD_MEASUREMENT_DATA_ONLY')
            self.assertEqual(len(report['os_downloads']),1)
            self.assertEqual(report['os_downloads'][0]['measurement']['curl_exit'],0)
            self.assertIn('OS DOWNLOAD',err)
            self.assertTrue(fixture._download_ack_verified)

    def test_failed_local_journal_never_acknowledges_or_resends_install(self):
        original=driver._PreparedRunScope._record_download_attempt
        def refuse(scope,*args,**kwargs):
            raise contract.SharedUpgradeHold('SYNTHETIC disk failure before download acknowledgement')
        fixture=native.ThreeComponentWorkflowTests()
        with tempfile.TemporaryDirectory() as directory,patch.object(
                driver._PreparedRunScope,'_record_download_attempt',refuse):
            code,report,err,calls,installs=fixture.invoke(Path(directory).resolve(),selection=('--os-only',),
                controlled_grace=True,download_telemetry=True)
        self.assertNotEqual(code,0)
        self.assertFalse(fixture._download_ack_verified)

    def test_final_summary_distinguishes_download_and_upgrade_results(self):
        fixture=native.ThreeComponentWorkflowTests()
        with tempfile.TemporaryDirectory() as directory:
            code,report,err,calls,installs=fixture.invoke(Path(directory).resolve(),selection=('--os-only',),
                controlled_grace=True,download_telemetry=True)
        self.assertEqual(code,0,err)
        self.assertIn('OS image download measurements (not installation results)',err)
        self.assertIn('599.500s avg=4.95MB/s',err)
        self.assertEqual(report['os_download_policy']['single_attempt_timeout_seconds'],600)
        self.assertEqual(report['os_download_policy']['max_attempts'],4)


if __name__=='__main__': unittest.main()
