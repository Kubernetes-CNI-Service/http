"""Independent human-summary contract; device IO is never real."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_upgrade_cli as fixtures
import test_three_component_workflow as native
import ibsw_upgrade_observer as observer
import ibsw_upgrade_schedule as schedule
from ibsw_upgrade_contract import SharedUpgradeHold

app = fixtures.app
NAMES = ('ew-spine001.example', 'ew-spine002.example', 'ew-spine003.example')


def inspection():
    return dict(state='READONLY_INSPECTION_DATA', result='SUCCESS', mode='INSPECT_ONLY',
        execution_state='NOT_EXECUTED', activation_state='UNKNOWN', selected_ib_count=3,
        ready_ib_count=3, skipped_ib_count=0, skipped_devices=[], selected_components=['os','bios','cpld'],
        targets=[dict(hostname=n) for n in NAMES], run_directory='/private/synthetic/run-example',
        version_plan=[dict(hostname=n, component=c, action='AT_TARGET_NO_FLASH', current=v, target=v)
            for n in NAMES for c,v in (('os','25.03.1014'),('bios','0ACQF_06.01.009'),
                ('cpld','CPLD000232_REV0900'))])


class GroupedSummaryTests(unittest.TestCase):
    def view(self, data):
        original=copy.deepcopy(data)
        result=app._summary_groups(data)
        self.assertEqual(data,original, 'presentation must never change original execution facts')
        return result

    def test_inspection_all_at_target_is_three_devices_not_nine_upgrades(self):
        report=inspection()
        view=self.view(report)
        self.assertEqual(view['mode'],'INSPECT_ONLY')
        self.assertEqual([(g['category'],g['count'],g['devices']) for g in view['device_groups']],
            [('AT_TARGET',3,list(NAMES))])
        self.assertEqual(view['upgraded_devices'],0)
        for group in view['component_groups']:
            self.assertEqual(group['groups'][0]['category'],'AT_TARGET')
            self.assertEqual(group['groups'][0]['count'],3)
        text=app._render_summary(report)
        self.assertIn('Mode: INSPECT_ONLY',text)
        self.assertIn('No upgrade was executed',text)
        self.assertNotIn('UPGRADE_PERFORMED',text)
        self.assertEqual(text.count('  - ew-spine001.example'),1,
            'identical component groups should refer to one device list, not repeat FQDNs three times')
        self.assertNotIn('workers',text.lower())

    def test_inspection_required_and_review_groups_are_not_successful_upgrades(self):
        report=inspection()
        report['version_plan'][3].update(action='UPGRADE_REQUIRED',current='25.02.8008')
        report['version_plan'][6].update(action='REVIEW_REQUIRED')
        report['result']='INCOMPLETE'
        view=self.view(report)
        self.assertEqual({g['category']:g['devices'] for g in view['device_groups']},
            {'AT_TARGET':[NAMES[0]],'UPGRADE_REQUIRED':[NAMES[1]],'REVIEW_REQUIRED':[NAMES[2]]})
        self.assertEqual(view['upgraded_devices'],0)
        self.assertTrue(any(NAMES[2] in g['devices'] for g in view['attention']))

    def test_actual_upgrade_groups_are_disjoint_unique_devices_with_component_details(self):
        report=inspection()
        report.update(mode='UPGRADE',state='UPGRADE_INCOMPLETE',result='INCOMPLETE',
                      execution_state='PARTIAL',activation_state='UNKNOWN')
        report['component_results']=[]
        for index,name in enumerate(NAMES):
            for component in ('os','bios','cpld'):
                action='UPGRADE_PERFORMED_AND_VERIFIED' if index==0 and component=='os' else 'ALREADY_AT_TARGET_VERIFIED'
                state='UNKNOWN' if index==2 and component=='os' else 'BLOCKED_PREVIOUS_FAILURE' if index==2 else 'COMPLETE'
                report['component_results'].append(dict(hostname=name,component=component,state=state,
                    action=action if state=='COMPLETE' else 'NOT_VERIFIED',preflight_version='old',
                    target_version='target',reason='Original installer evidence missing' if index==2 else None))
        view=self.view(report)
        self.assertEqual({g['category']:g['devices'] for g in view['device_groups']},
            {'UPGRADED':[NAMES[0]],'AT_TARGET':[NAMES[1]],'UNKNOWN':[NAMES[2]]})
        self.assertEqual(sum(g['count'] for g in view['device_groups']),3)
        self.assertEqual(view['upgraded_devices'],1)
        self.assertEqual(next(p for p in view['component_groups'] if p['component']=='os')['groups'][0]['category'],
                         'UPGRADED')
        text=app._render_summary(report)
        self.assertIn('Upgraded and verified: 1',text)
        self.assertIn('Unverified / failed',text)
        self.assertIn('Original installer evidence missing',text)
        self.assertIn('do not resend',text.lower())

    def test_skipped_devices_group_by_state_and_reason_without_disappearing(self):
        report=inspection()
        report.update(selected_ib_count=5,skipped_ib_count=2,result='INCOMPLETE')
        report['skipped_devices']=[dict(hostname='ib-unreachable',state='SKIPPED_UNREACHABLE',reasons=['SSH_CONNECT_FAILED']),
            dict(hostname='ib-missing-mac',state='SKIPPED_INPUT_INVALID',reasons=['ETH0_MAC_MISSING'])]
        view=self.view(report)
        self.assertEqual(sum(g['count'] for g in view['device_groups']),5)
        self.assertEqual({n for g in view['attention'] for n in g['devices']},
                         {'ib-unreachable','ib-missing-mac'})
        text=app._render_summary(report)
        self.assertIn('SSH_CONNECT_FAILED',text)
        self.assertIn('ETH0_MAC_MISSING',text)
        self.assertIn('routing',text.lower())

    def test_partial_device_success_preserves_actual_component_upgrade_count(self):
        report=inspection()
        report.update(mode='UPGRADE',state='UPGRADE_INCOMPLETE',result='INCOMPLETE',targets=[dict(hostname=NAMES[0])],
                      selected_ib_count=1,ready_ib_count=1)
        report['component_results']=[dict(hostname=NAMES[0],component=c,state=s,action=a,
            preflight_version='old',target_version='target') for c,s,a in (
                ('os','COMPLETE','UPGRADE_PERFORMED_AND_VERIFIED'),
                ('bios','UNKNOWN','NOT_VERIFIED'),('cpld','BLOCKED_PREVIOUS_FAILURE','NOT_VERIFIED'))]
        view=self.view(report)
        self.assertEqual(view['device_groups'][0]['category'],'UNKNOWN')
        self.assertEqual(view['upgraded_devices'],0)
        self.assertEqual(view['upgraded_components'],1)
        self.assertEqual(view['devices_with_component_upgrades'],1)
        self.assertIn('Components upgraded and verified: 1 on 1 device(s)',app._render_summary(report))

    def test_upgrade_output_lists_devices_under_each_component_and_shows_zero_counts(self):
        report=inspection()
        report.update(mode='UPGRADE',state='UPGRADE_VERIFIED',result='SUCCESS')
        report['component_results']=[dict(hostname=n,component=c,state='COMPLETE',
            action='UPGRADE_PERFORMED_AND_VERIFIED' if c=='os' and n==NAMES[0] else 'ALREADY_AT_TARGET_VERIFIED',
            preflight_version='observed',target_version='target') for n in NAMES for c in ('os','bios','cpld')]
        text=app._render_summary(report)
        os_block=text.split('\nOS:',1)[1].split('\nBIOS:',1)[0]
        bios_block=text.split('\nBIOS:',1)[1].split('\nCPLD:',1)[0]
        cpld_block=text.split('\nCPLD:',1)[1].split('+-- 04',1)[0]
        self.assertIn('Upgraded=1  No-change=2  Failed=0  Unknown=0',os_block)
        self.assertIn('Upgraded=0  No-change=3  Failed=0  Unknown=0',bios_block)
        self.assertIn('Blocked=0  Not-executed=0',cpld_block)
        for block in (os_block,bios_block,cpld_block):
            for name in NAMES: self.assertIn(name,block)
            self.assertNotIn('Devices: [D',block,
                'upgrade mode must list actual devices under each component, not only an overall reference')

    def test_no_flash_action_is_separate_from_blocked_final_verification(self):
        report=inspection()
        report.update(mode='UPGRADE',state='UPGRADE_INCOMPLETE',result='INCOMPLETE',
                      selected_components=['bios'])
        report['component_results']=[dict(hostname=name,component='bios',state=state,
            action='ALREADY_AT_TARGET_VERIFIED' if state=='COMPLETE' else 'NOT_VERIFIED',
            reason=reason) for name,state,reason in (
                (NAMES[0],'COMPLETE',None),
                (NAMES[1],'BLOCKED_PREVIOUS_FAILURE','Earlier device failure'),
                (NAMES[2],'NOT_EXECUTED','OS_FINAL_NOT_REACHED'))]
        view=self.view(report)
        phase=view['component_groups'][0]
        self.assertEqual(phase['no_change_counts'],dict(total=3,final_verified=1,preflight_only=2))
        self.assertEqual(next(g['devices'] for g in phase['groups'] if g['category']=='AT_TARGET'),[NAMES[0]])
        # Two different reasons must keep their separate evidence/device lists.
        self.assertEqual(sorted(n for g in phase['groups'] if g['category']=='AT_TARGET_PRECHECK'
                                for n in g['devices']),list(NAMES[1:]))
        self.assertEqual({g['category']:g['devices'] for g in view['device_groups']},
            {'AT_TARGET':[NAMES[0]],'BLOCKED':[NAMES[1]],'NOT_EXECUTED':[NAMES[2]]})
        text=app._render_summary(report)
        self.assertIn('Result: INCOMPLETE',text)
        self.assertIn('Upgraded=0  No-change=3  Failed=0  Unknown=0',text)
        self.assertIn('No-change verification: final-verified=1  preflight-only=2',text)
        self.assertIn('No change / at target in preflight; final verification incomplete',text)
        self.assertIn('OS_FINAL_NOT_REACHED',text)
        self.assertEqual(view['upgraded_components'],0)

    def test_no_flash_precheck_never_hides_live_failures_or_missing_observations(self):
        report=inspection()
        report.update(mode='UPGRADE',state='UPGRADE_INCOMPLETE',result='INCOMPLETE',
                      selected_components=['bios'])
        report['component_results']=[dict(hostname=NAMES[0],component='bios',state='UNKNOWN',
            action='NOT_VERIFIED',reason='Live firmware query failed'),
            dict(hostname=NAMES[1],component='bios',state='FAILED',action='NOT_VERIFIED')]
        phase=self.view(report)['component_groups'][0]
        self.assertEqual(phase['no_change_counts'],dict(total=0,final_verified=0,preflight_only=0))
        self.assertEqual({g['category'] for g in phase['groups']},{'UNKNOWN','FAILED','NOT_EXECUTED'})
        report['component_results'][0]['state']='BLOCKED_PREVIOUS_FAILURE'
        report['version_plan']=[r for r in report['version_plan']
                                if not(r['hostname']==NAMES[0] and r['component']=='bios')]
        self.assertNotIn('AT_TARGET_PRECHECK',repr(self.view(report)['component_groups']))

    def test_preflight_skipped_device_is_not_counted_as_no_change(self):
        report=inspection()
        report.update(mode='UPGRADE',result='INCOMPLETE',selected_components=['bios'],
            selected_ib_count=4,skipped_ib_count=1,
            skipped_devices=[dict(hostname='not-observed',state='SKIPPED_HOST_KEY',reasons=['KNOWN_HOSTS'])])
        report['component_results']=[dict(hostname=n,component='bios',state='BLOCKED_PREVIOUS_FAILURE',
                                          action='NOT_VERIFIED') for n in NAMES]
        view=self.view(report)
        self.assertEqual(view['component_groups'][0]['no_change_counts']['total'],3)
        self.assertTrue(any(g['devices']==['not-observed'] and g['category']=='SKIPPED'
                            for g in view['device_groups']))
        self.assertNotIn('not-observed',repr(view['component_groups']))

    def test_component_device_lists_mark_only_their_own_canary(self):
        report=inspection()
        report.update(mode='UPGRADE',state='UPGRADE_VERIFIED',result='SUCCESS')
        report['component_results']=[dict(hostname=n,component=c,state='COMPLETE',
            action='UPGRADE_PERFORMED_AND_VERIFIED' if (i,j) in ((0,0),(1,1),(2,2)) else 'ALREADY_AT_TARGET_VERIFIED',
            preflight_version='observed',target_version='target')
            for i,n in enumerate(NAMES) for j,c in enumerate(('os','bios','cpld'))]
        report['components']=[dict(component=c,canary=NAMES[i],canary_requirement='REQUIRED',
            targets=[r for r in report['component_results'] if r['component']==c])
            for i,c in enumerate(('os','bios','cpld'))]
        text=app._render_summary(report)
        blocks=(text.split('\nOS:',1)[1].split('\nBIOS:',1)[0],
                text.split('\nBIOS:',1)[1].split('\nCPLD:',1)[0],
                text.split('\nCPLD:',1)[1].split('+-- 04',1)[0])
        for index,block in enumerate(blocks):
            self.assertIn('Canary: '+NAMES[index]+' | COMPLETE',block)
            self.assertIn('- '+NAMES[index]+' [CANARY]',block)
            for peer in NAMES:
                if peer!=NAMES[index]: self.assertNotIn(peer+' [CANARY]',block)

    def test_missing_component_observation_is_review_not_at_target(self):
        report=inspection()
        report['version_plan']=[r for r in report['version_plan'] if not(r['hostname']==NAMES[0] and r['component']=='bios')]
        report['component_precheck_issues']=[dict(hostname=NAMES[0],component='bios',reason_code='FIRMWARE_VERSION_PARSE_FAILED')]
        view=self.view(report)
        self.assertIn(NAMES[0],next(g for g in view['device_groups'] if g['category']=='REVIEW_REQUIRED')['devices'])

    def test_selected_component_scope_does_not_invent_other_component_results(self):
        report=inspection()
        report['selected_components']=['os']
        report['version_plan']=[r for r in report['version_plan'] if r['component']=='os']
        view=self.view(report)
        self.assertEqual([g['component'] for g in view['component_groups']],['os'])
        text=app._render_summary(report)
        self.assertNotIn('\nBIOS',text)
        self.assertNotIn('\nCPLD',text)

    def test_scripts_only_is_declared_not_observed_or_upgraded(self):
        report=inspection()
        report.update(state='DECLARED_CANDIDATES_NOT_EXECUTED',mode='SCRIPTS_ONLY',version_plan=[])
        view=self.view(report)
        self.assertEqual(view['device_groups'][0]['category'],'DECLARED_ONLY')
        self.assertEqual(view['upgraded_devices'],0)
        self.assertIn('not executed or verified',app._render_summary(report))

    def test_summary_is_deterministic_and_never_renders_terminal_control_codes(self):
        report=inspection()
        report['targets'].reverse()
        report['version_plan'].reverse()
        self.assertEqual(self.view(report),self.view(inspection()))
        report['skipped_devices']=[dict(hostname='bad\x1b[2Jhost',state='SKIPPED_INPUT_INVALID',reasons=['bad\nline'])]
        text=app._render_summary(report)
        self.assertNotIn('\x1b',text)
        self.assertNotIn('bad\nline',text)

    def test_terminal_defaults_to_human_summary_json_requires_explicit_flag(self):
        output=io.StringIO()
        output.isatty=lambda: True
        with contextlib.redirect_stdout(output):
            self.assertFalse(app._emit_report_json(inspection(),force=False))
        self.assertEqual(output.getvalue(),'')
        with contextlib.redirect_stdout(output):
            self.assertTrue(app._emit_report_json(inspection(),force=True))
        self.assertEqual(json.loads(output.getvalue())['execution_state'],'NOT_EXECUTED')
        args=app._parse_cli(['--json'])
        self.assertTrue(args.output_json)
        self.assertNotIn('--json',args.prepare_args)

    def test_redirected_stdout_keeps_machine_readable_json(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(app._emit_report_json(inspection(),force=False))
        self.assertEqual(json.loads(output.getvalue())['mode'],'INSPECT_ONLY')


class NativeSummaryWorkflowTests(unittest.TestCase):
    invoke=native.ThreeComponentWorkflowTests.invoke

    def test_os_failure_keeps_firmware_no_flash_actions_but_not_final_success(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),two=True,
                firmware_at_target=True,fail=(native.HOST,'os'))
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual([(n,c) for n,c,v in installs],[(native.HOST,'os')])
            self.assertEqual(report['result'],'INCOMPLETE')
            self.assertEqual(report['summary_groups']['upgraded_components'],0)
            for component in ('bios','cpld'):
                phase=next(p for p in report['summary_groups']['component_groups'] if p['component']==component)
                self.assertEqual(phase['no_change_counts'],dict(total=2,final_verified=0,preflight_only=2))
                self.assertEqual({g['category'] for g in phase['groups']},{'AT_TARGET_OBSERVED'})
                raw=[r for r in report['component_results'] if r['component']==component]
                self.assertTrue(all(r['state']=='PREFLIGHT_NO_CHANGE' for r in raw))
                self.assertTrue(all(r['action']=='AT_TARGET_PREFLIGHT' for r in raw))
                self.assertFalse(any(g['component']==component for g in report['summary_groups']['attention']))
            self.assertIn('No-change verification: final-verified=0  preflight-only=2',err)
            self.assertEqual(json.loads((Path(report['run_directory'])/'run-report.json').read_text()),report)

    def test_real_inspection_reports_grouped_observations_without_claiming_upgrade(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),inspect=True,old_os=False,
                                                    selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(report['summary_groups']['device_groups'][0]['category'],'AT_TARGET')
            self.assertEqual(report['summary_groups']['upgraded_devices'],0)
            self.assertIn('Mode: INSPECT_ONLY',err)
            self.assertIn('No upgrade was executed',err)
            self.assertEqual(json.loads((Path(report['run_directory'])/'run-report.json').read_text()),report)

    def test_real_upgrade_report_has_grouped_component_actions_saved_before_print(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(len(installs),1)
            self.assertEqual(report['summary_groups']['upgraded_devices'],1)
            self.assertIn('UPGRADED',repr(report['summary_groups']))
            self.assertIn('01 OVERVIEW',err)
            self.assertIn('02 DEVICE GROUPS',err)
            self.assertIn('03 COMPONENT RESULTS',err)
            self.assertIn('05 ATTENTION & NEXT ACTIONS',err)
            self.assertIn('06 EVIDENCE',err)
            self.assertEqual(json.loads((Path(report['run_directory'])/'run-report.json').read_text()),report)

    def test_all_at_target_has_no_upgrade_canary_and_no_device_is_flashed(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),two=True,old_os=False,
                                                    selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(installs,[])
            self.assertIsNone(report['components'][0]['canary'])
            status=json.loads((Path(report['run_directory'])/'os-status.json').read_text())
            self.assertIsNone(status['canary'],'no-flash component status must not retain a placeholder canary')
            self.assertNotIn('[CANARY OS]',err)
            self.assertIn('excluded from upgrade queue',err)
            self.assertEqual(report['summary_groups']['device_groups'][0]['count'],2)

    def test_all_at_target_never_enters_the_postcheck_callback_or_fails_from_it(self):
        original=observer._observe_component_completion_once
        invoked=[]
        def observe(leaf,dispatch,**kwargs):
            invoked.append(leaf.node.hostname)
            if leaf.node.hostname==native.HOST:
                raise observer._NativeObservationHold(reason_code='READONLY_QUERY_FAILED')
            return original(leaf,dispatch,**kwargs)
        with tempfile.TemporaryDirectory() as folder,patch.object(observer,'_observe_component_completion_once',observe):
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),two=True,old_os=False,
                                                    selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(installs,[])
            self.assertIsNone(report['components'][0]['canary'])
            self.assertEqual(report['components'][0]['targets'],[])
            self.assertEqual(len(report['components'][0]['no_change']),2)
            self.assertEqual(invoked,[])

    def test_each_component_selects_its_own_actual_upgrade_canary(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),different_canaries=True)
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual([(p['component'],p['canary']) for p in report['components']],
                [('os','ew-spine01.example'),('bios','ew-spine02.example'),('cpld','ew-spine03.example')])
            self.assertEqual([(n,c) for n,c,v in installs],
                [('ew-spine01.example','os'),('ew-spine02.example','bios'),('ew-spine03.example','cpld')])
            self.assertEqual([p['canary_state'] for p in report['summary_groups']['component_groups']],['COMPLETE']*3)
            component_text=err.split('03 COMPONENT RESULTS',1)[1].split('05 ATTENTION',1)[0]
            self.assertEqual(component_text.count('[CANARY]'),3)

    def test_no_flash_preflight_never_authorizes_a_later_write_or_claims_final_state(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),old_os=False,
                unplanned_downgrade=True,selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(report['component_results'][0]['state'],'PREFLIGHT_NO_CHANGE')
            self.assertEqual(report['component_results'][0]['verification_basis'],'PREFLIGHT_OBSERVATION_ONLY')
            self.assertEqual(report['activation_state'],'NOT_REQUIRED')

    def test_no_flash_health_is_checked_once_but_not_reported_as_post_upgrade_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),old_os=False,two=True,
                no_write_health_fail=True,selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(report['components'][0]['targets'],[])
            self.assertTrue(all(r['state']=='PREFLIGHT_NO_CHANGE' for r in report['component_results']))
            self.assertEqual(sum(c=='nv show system health' for n,c in calls),2)
            self.assertEqual(report['health_summary']['counts']['PASS'],2)
            status=json.loads((Path(report['run_directory'])/'os-status.json').read_text())
            self.assertIsNone(status['canary'])


class NoFlashStatusTests(unittest.TestCase):
    def test_native_status_accepts_explicit_absence_but_not_unknown_canary_or_skip_override(self):
        node=dict(hostname='ib-one',address='192.0.2.1',mac='02:00:00:00:00:01')
        initial=schedule.native_component_status_document('os','run-'+'a'*32,'b'*64,['c'*64,'d'*64],[node],'ib-one')
        absent=copy.deepcopy(initial)
        absent.update(canary=None,revision=1)
        self.assertEqual(schedule.validate_native_component_status_document(absent,initial)['canary'],None)
        self.assertEqual(absent['execution_state'],'OBSERVATION_FACTS_ONLY')
        unknown=copy.deepcopy(absent)
        unknown['canary']='not-selected'
        with self.assertRaises(ValueError): schedule.validate_native_component_status_document(unknown,initial)
        skipped=copy.deepcopy(initial)
        skipped['canary']=None
        with self.assertRaises(ValueError): schedule.validate_native_component_status_document(initial,skipped)

    def test_no_canary_attribution_is_single_use_and_cannot_clear_terminal_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            project,home,known=fixtures.WorkflowTests().fixture(Path(folder).resolve())
            args=('--project',str(project),'--os-only','--method','http','--standalone-inputs')
            prepared=fixtures.driver.prepare_manual_run(app.__file__,str(project),args)
            with fixtures.driver.open_manual_run(app.__file__,str(project),args,prepared['run_directory']) as scope:
                scope.enable_cooperative_status_snapshots()
                scope.initialize_native_component_status_data()
                scope._native_schedule_started=True
                scope._record_native_component_no_canary('os')
                self.assertIsNone(scope.read_component_status_data('os')['canary'])
                scope._record_native_component_failure('os','ew-spine01.example','UNKNOWN','SYNTHETIC')
                with self.assertRaises(SharedUpgradeHold): scope._record_native_component_no_canary('os')
                with self.assertRaises(SharedUpgradeHold): scope._record_native_component_canary('os','ew-spine02.example')
                self.assertEqual(scope.read_component_status_data('os')['targets'][0]['state'],'UNKNOWN')


if __name__=='__main__':
    unittest.main()
