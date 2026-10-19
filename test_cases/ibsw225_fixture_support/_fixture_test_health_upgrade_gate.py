"""Owner contract: failed health blocks before install unless explicit health-only --force."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_three_component_workflow as native
import test_upgrade_cli as fixtures
import test_manual_execution as manual
import ibsw_upgrade_observer as observer
from ibsw_upgrade_contract import record_readonly_query

NA=(b'        operational  applied\n------  -----------  -------\nstatus  N/A\n'
    b'Health Issues\n============\nNo Data\n')
NOT_OK=(b'            operational  applied\n----------  -----------  -------\n'
    b'status      Not OK\nstatus-led  amber\nHealth Issues\n============\n'
    b'Component  Status information\n---------  ------------------\nPSU1       not working\n')


class HealthGateDirectTests(unittest.TestCase):
    def test_not_ok_even_when_existing_is_not_upgrade_eligible(self):
        raw=record_readonly_query(('nv','show','system','health'),NOT_OK,b'',0)
        with self.assertRaises(observer._NativeObservationHold) as caught:
            observer._require_upgrade_health(raw)
        self.assertEqual(caught.exception.reason_code,'HEALTH_PRECHECK_NOT_OK')

    def test_na_query_failure_and_unknown_format_are_not_health_success(self):
        for payload,stderr,status,code in ((NA,b'',0,'HEALTH_STATUS_UNAVAILABLE'),
            (b'',b'PRIVATE_REMOTE_ERROR',1,'HEALTH_QUERY_FAILED'),
            (b'PRIVATE_UNKNOWN_LAYOUT',b'',0,'HEALTH_PARSE_FAILED')):
            with self.subTest(code=code):
                raw=record_readonly_query(('nv','show','system','health'),payload,stderr,status)
                with self.assertRaises(observer._NativeObservationHold) as caught: observer._require_upgrade_health(raw)
                self.assertEqual(caught.exception.reason_code,code)
                self.assertNotIn('PRIVATE',str(caught.exception))

    def test_force_is_explicit_upgrade_only_and_bound_in_original_plan_arguments(self):
        parsed=fixtures.app._parse_cli(['--upgrade','--yes','--force'])
        self.assertIn('--force',parsed.prepare_args)
        prepared=fixtures.driver.parse_prepare_args('/tmp/upgrade.py','/tmp',parsed.prepare_args)
        self.assertTrue(prepared.force_health)
        for args in (['--inspect-only','--force'],['--scripts-only','--force']):
            with self.assertRaises(Exception): fixtures.app._parse_cli(args)


class HealthGateWorkflowTests(unittest.TestCase):
    def invoke(self,**options):
        folder=tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        selection=options.pop('selection',('--os-only',))
        return native.ThreeComponentWorkflowTests().invoke(Path(folder.name).resolve(),selection=selection,**options)

    def test_bad_health_device_is_filtered_before_worker_and_other_device_can_upgrade(self):
        code,report,err,calls,installs=self.invoke(two=True,
            health_payloads={(native.HOST,'startup'):NOT_OK})
        self.assertEqual(code,3,err)
        self.assertEqual([name for name,component,version in installs],['ew-spine02.example'])
        skipped=next(row for row in report['skipped_devices'] if row['hostname']==native.HOST)
        self.assertEqual(skipped['state'],'SKIPPED_HEALTH_CHECK_FAILED')
        self.assertEqual(skipped['reasons'],['HEALTH_PRECHECK_NOT_OK'])
        self.assertEqual(report['health_blocked_ib_count'],1)
        group=next(g for g in report['summary_groups']['device_groups'] if g['category']=='HEALTH_BLOCKED')
        self.assertEqual(group['devices'],[native.HOST])
        self.assertIn('Pre-upgrade health check blocked',err)
        self.assertIn('installer was not dispatched',err)
        self.assertTrue(Path(skipped['log_directory'],'startup-diagnostics.json').is_file())

    def test_health_changed_after_startup_is_checked_again_before_install(self):
        code,report,err,calls,installs=self.invoke(
            health_payloads={(native.HOST,'before_install'):NOT_OK})
        self.assertEqual(code,3,err)
        self.assertEqual(installs,[])
        self.assertIn('HEALTH_PRECHECK_NOT_OK',err)
        self.assertEqual(report['execution_state'],'NOT_EXECUTED')
        group=next(g for g in report['summary_groups']['device_groups'] if g['category']=='HEALTH_BLOCKED')
        self.assertEqual(group['devices'],[native.HOST])
        self.assertTrue(Path(report['run_directory'],native.HOST,'pre-install-diagnostics.json').is_file())

    def test_explicit_force_records_override_and_does_not_mark_health_as_passed(self):
        code,report,err,calls,installs=self.invoke(
            selection=('--os-only','--force'),
            health_payloads={(native.HOST,'startup'):NOT_OK,(native.HOST,'before_install'):NOT_OK,
                             (native.HOST,'after_install'):NA})
        self.assertEqual(code,0,err)
        self.assertEqual(len(installs),1)
        self.assertTrue(report['health_override_used'])
        self.assertEqual(report['health_forced_devices'],[native.HOST])
        self.assertIn('HEALTH OVERRIDE',err)
        self.assertIn('FORCED',err)
        self.assertIn(native.HOST,err)
        self.assertFalse(report.get('health_all_passed',True))
        self.assertNotIn("None identified within this run's selected checks.",err)
        self.assertTrue(any(r['reason_code']=='HEALTH_STATUS_UNAVAILABLE' for r in report['health_overrides']))
        self.assertIn('HEALTH / CHECK_REQUIRED',err)

    def test_force_does_not_release_peers_after_failed_component_canary(self):
        code,report,err,calls,installs=self.invoke(selection=('--os-only','--force'),two=True,wrong_version=True)
        self.assertEqual(code,3,err)
        self.assertEqual([r[0] for r in installs],[native.HOST])
        phase=report['components'][0]
        self.assertEqual(phase['blocked_by_canary'],['ew-spine02.example'])

    def test_force_does_not_ignore_untrusted_ssh_host_key(self):
        code,report,err,calls,installs=self.invoke(selection=('--os-only','--force'),initial_host_key=True)
        self.assertEqual(code,3,err)
        self.assertEqual(installs,[])
        self.assertIn('SSH_HOST_KEY_MISMATCH',err)

    def test_incomplete_health_stream_blocks_by_default_but_force_is_recorded(self):
        for phase in ('startup','before_install','after_install'):
          for force in (False,True):
            with self.subTest(force=force,phase=phase):
                code,report,err,calls,installs=self.invoke(
                    selection=('--os-only','--force') if force else ('--os-only',),
                    health_payloads={(native.HOST,phase):(manual.HEALTH,b'',0,False)})
                self.assertEqual(code,0 if force else 3,err)
                self.assertEqual(len(installs),1 if force or phase=='after_install' else 0)
                if force:
                    self.assertTrue(report['health_override_used'])
                    self.assertTrue(any(r['reason_code']=='HEALTH_QUERY_FAILED' for r in report['health_overrides']))
                    self.assertIn('HEALTH / CHECK_REQUIRED',err)
                else: self.assertIn('HEALTH_QUERY_FAILED',err)

    def test_force_handles_failed_health_query_without_relaxing_other_query_records(self):
        code,report,err,calls,installs=self.invoke(selection=('--os-only','--force'),
            health_payloads={(native.HOST,phase):(b'',b'SYNTHETIC_HEALTH_QUERY_FAILURE',1,True)
                             for phase in ('startup','before_install','after_install')})
        self.assertEqual(code,0,err)
        self.assertEqual(len(installs),1)
        self.assertFalse(report['health_all_passed'])
        self.assertIn('HEALTH_QUERY_FAILED',err)

    def test_force_does_not_bypass_wrong_target_identity(self):
        code,report,err,calls,installs=self.invoke(selection=('--os-only','--force'),initial_identity_mismatch=True)
        self.assertEqual(code,3,err)
        self.assertEqual(installs,[])
        self.assertNotEqual(report['result'],'SUCCESS')

    def test_force_does_not_allow_foreign_pending_or_unverified_configuration(self):
        original=observer._preflight_component_on_session
        def fail(leaf,*args,**kwargs):
            raise observer._NativeObservationHold(reason_code='CONFIG_PENDING_NOT_EMPTY')
        with patch.object(observer,'_preflight_component_on_session',fail):
            code,report,err,calls,installs=self.invoke(selection=('--os-only','--force'))
        self.assertEqual(code,3,err)
        self.assertEqual(installs,[])
        self.assertIn('CONFIG_PENDING_NOT_EMPTY',err)


if __name__=='__main__': unittest.main()
