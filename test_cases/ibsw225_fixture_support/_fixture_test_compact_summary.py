"""Owner's compact terminal contract; full JSON evidence remains unchanged."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import test_grouped_summary as groups
import test_three_component_workflow as native

app=groups.app
NAMES=groups.NAMES
REASON=('COMPONENT_FILE_CHANGED at ibsw_upgrade_executor.py:1267 '
        '(_read_stable_component_file_bounded) | phase=WAIT_DOWNLOAD_RECORD | installer may have started;')


def report(names=NAMES):
    data=groups.inspection()
    data.update(mode='UPGRADE',state='UPGRADE_INCOMPLETE',result='INCOMPLETE',selected_components=['os'],
        selected_ib_count=len(names),ready_ib_count=len(names),targets=[dict(hostname=n) for n in names],
        version_plan=[dict(hostname=n,component='os',action='UPGRADE_REQUIRED',
            current='25.02.7002',target='25.03.1014') for n in names])
    data['component_results']=[dict(hostname=n,component='os',state='UNKNOWN',action='NOT_VERIFIED',
        preflight_version='25.02.7002',target_version='25.03.1014',reason=REASON,
        log_directory='/private/synthetic/run-example/'+n+'/os-0003') for n in names]
    return data


MANY_NAMES=tuple(f'ew-spine{number:03d}.aus04.gs1.nsw.sharonai.au' for number in range(1,10))
FOUR_PER_LINE=(
    'ew-spine001.aus04.gs1.nsw.sharonai.au, ew-spine002.aus04.gs1.nsw.sharonai.au, ew-spine003.aus04.gs1.nsw.sharonai.au, ew-spine004.aus04.gs1.nsw.sharonai.au',
    'ew-spine005.aus04.gs1.nsw.sharonai.au, ew-spine006.aus04.gs1.nsw.sharonai.au, ew-spine007.aus04.gs1.nsw.sharonai.au, ew-spine008.aus04.gs1.nsw.sharonai.au',
    'ew-spine009.aus04.gs1.nsw.sharonai.au',
)


class CompactSummaryDirectTests(unittest.TestCase):
    def test_device_lists_wrap_at_four_names_not_at_terminal_width(self):
        expected={0:[],1:[MANY_NAMES[0]],4:[FOUR_PER_LINE[0]],
            5:[FOUR_PER_LINE[0],MANY_NAMES[4]],8:list(FOUR_PER_LINE[:2]),9:list(FOUR_PER_LINE)}
        for count,rows in expected.items():
            with self.subTest(count=count):
                data=report(MANY_NAMES[:count]); original=copy.deepcopy(data)
                text=app._render_summary(data)
                block=text.split('+-- 03 COMPONENT RESULTS',1)[1].split('+-- 04',1)[0]
                actual=[line for line in block.splitlines() if line.startswith('    - ')]
                self.assertEqual(actual,['    - '+row for row in rows])
                self.assertEqual(data,original,'formatting cannot change facts or counts')

    def test_ssd_and_attention_lists_use_the_same_four_name_boundary(self):
        data=report(MANY_NAMES)
        data['ssd_checks']=[dict(hostname=name,state='PASS',status='MATCH',expected_version='CE00A474',
            observed_version='CE00A474',reason_code=None) for name in MANY_NAMES]
        text=app._render_summary(data)
        ssd=text.split('SSD firmware (informational only):',1)[1].split('+-- 04',1)[0]
        self.assertEqual([line for line in ssd.splitlines() if line.startswith('      - ')],
            ['      - '+row for row in FOUR_PER_LINE])
        attention=text.split('+-- 05 ATTENTION',1)[1].split('+-- 06',1)[0]
        self.assertEqual([line for line in attention.splitlines() if line.startswith('  - ')],
            ['  - '+row for row in FOUR_PER_LINE])
        self.assertEqual(attention.count('  Reason: '+REASON+'\n'),1)

    def test_health_and_inspection_groups_keep_four_names_per_line(self):
        data=report(MANY_NAMES)
        for row in data['component_results']:
            row.update(state='NOT_EXECUTED',reason='HEALTH_PRECHECK_NOT_OK private detail')
        text=app._render_summary(data)
        attention=text.split('+-- 05 ATTENTION',1)[1].split('+-- 06',1)[0]
        self.assertEqual([line for line in attention.splitlines() if line.startswith('  - ')],
            ['  - '+row for row in FOUR_PER_LINE])
        self.assertNotIn('private detail',text)
        data.update(mode='INSPECT_ONLY',component_results=[])
        text=app._render_summary(data)
        block=text.split('+-- 02 DEVICE GROUPS',1)[1].split('+-- 03',1)[0]
        self.assertEqual([line for line in block.splitlines() if line.startswith('  - ')],
            ['  - '+row for row in FOUR_PER_LINE])

    def test_canary_labels_and_route_coverage_obey_four_device_limit(self):
        data=report(MANY_NAMES)
        data['components']=[dict(component='os',canary=MANY_NAMES[0],canaries=list(MANY_NAMES),
            canary_requirement='REQUIRED',canary_routes=[dict(hostname=name,
                path=['25.02.7002','25.03.1014'],files=['nvos-amd64-25.03.1014.bin'],
                covers=list(MANY_NAMES)) for name in MANY_NAMES],targets=data['component_results'])]
        text=app._render_summary(data)
        block=text.split('\nOS:',1)[1].split('+-- 04',1)[0]
        self.assertIn('  Canaries (9):\n',block)
        start=block.split('  Canaries (9):\n',1)[1].split('    Path (',1)[0]
        self.assertEqual([len(line.split(', ')) for line in start.splitlines() if line.startswith('    - ')],
            [4,4,1])
        self.assertIn('    - '+MANY_NAMES[0]+' [UNKNOWN], '+MANY_NAMES[1]+' [UNKNOWN]',start)
        self.assertEqual([line for line in block.splitlines() if line.startswith('      - ')],
            ['      - '+row for row in FOUR_PER_LINE]*9)
        actual=[line for line in block.splitlines() if line.startswith('    - ') and '[CANARY]' in line]
        self.assertEqual([len(line.split(', ')) for line in actual],[4,4,1])
        self.assertTrue(all('[CANARY]' in name for line in actual for name in line[6:].split(', ')))

    def test_versions_names_and_reasons_remain_on_single_logical_lines(self):
        data=report(); original=copy.deepcopy(data)
        text=app._render_summary(data)
        self.assertIn('    Observed before: 25.02.7002    Target: 25.03.1014\n',text)
        self.assertIn('    - '+', '.join(NAMES)+'\n',text)
        self.assertIn('    Reason: '+REASON+'\n',text)
        self.assertNotIn('\n    (_read_stable_component_file_bounded)',text)
        self.assertEqual(data,original)

    def test_paths_are_only_in_final_evidence_section(self):
        text=app._render_summary(report())
        before,evidence=text.split('+-- 06 EVIDENCE',1)
        self.assertNotIn('Logs:',before)
        self.assertNotIn('Logs (',text)
        self.assertNotIn('/private/synthetic/',before)
        self.assertIn('Logs: /private/synthetic/run-example\n',evidence)
        self.assertIn('Report: /private/synthetic/run-example/run-report.json\n',evidence)

    def test_ssd_groups_pass_warning_and_not_checked_without_one_row_per_host(self):
        data=report()
        data['ssd_checks']=[dict(hostname=name,state=state,status=status,expected_version='CE00A474',
            observed_version=observed,reason_code=reason) for name,state,status,observed,reason in (
                (NAMES[0],'PASS','MATCH','CE00A474',None),
                (NAMES[1],'PASS','MATCH','CE00A474',None),
                (NAMES[2],'WARNING','MISMATCH','CE00A400','SSD_VERSION_MISMATCH'),
                ('ib-not-reached','NOT_CHECKED','NOT_REACHED',None,'OS_POSTCHECK_NOT_REACHED'))]
        original=copy.deepcopy(data)
        block=app._render_summary(data).split('SSD firmware (informational only):',1)[1].split('+-- 04',1)[0]
        self.assertEqual(block.count('PASS / MATCH'),1)
        self.assertIn('PASS / MATCH: 2 device(s)',block)
        self.assertIn('      - '+', '.join(NAMES[:2])+'\n',block)
        self.assertIn('WARNING / MISMATCH: 1 device(s)',block)
        self.assertIn('NOT_CHECKED / NOT_REACHED: 1 device(s)',block)
        self.assertEqual(data,original)

    def test_download_measurement_is_one_line_with_http_and_curl_status(self):
        data=report()
        name='ew-leaf001.aus04.gs1.nsw.sharonai.au'
        data['os_downloads']=[dict(hostname=name,stage='os-0003',measurement=dict(attempt=1,
            bytes_downloaded=2966461709,elapsed_seconds=270.936,average_bytes_per_second=10950000,
            http_status=200,curl_exit=0))]
        line='    '+name+' os-0003: attempt=1 2966.5MB 270.936s avg=10.95MB/s HTTP=200 curl-exit=0\n'
        self.assertIn(line,app._render_summary(data))

    def test_same_category_has_one_header_even_when_versions_or_causes_differ(self):
        data=report()
        data['component_results'][1]['preflight_version']='25.02.8008'
        data['component_results'][2]['reason']='NVOS_CLI_NOT_READY_AFTER_5_CHECKS'
        text=app._render_summary(data)
        phase=text.split('\nOS:',1)[1].split('+-- 04',1)[0]
        self.assertEqual(phase.count('Unknown / manual verification required:'),1)
        self.assertIn('Unknown / manual verification required: 3 device(s)',phase)
        attention=text.split('+-- 05 ATTENTION',1)[1].split('+-- 06',1)[0]
        self.assertEqual(attention.count('OS / UNKNOWN:'),1)
        self.assertEqual(attention.count('  Next:'),2,
            'each different cause keeps the guidance next to its own device group')
        self.assertIn('NVOS_CLI_NOT_READY_AFTER_5_CHECKS',attention)
        self.assertIn(REASON,attention)

    def test_health_details_coalesce_without_erasing_native_json_reasons(self):
        data=report()
        for row,code in zip(data['component_results'],('HEALTH_PRECHECK_NOT_OK','HEALTH_STATUS_UNAVAILABLE','HEALTH_QUERY_FAILED')):
            row.update(state='NOT_EXECUTED',reason=code+' PRIVATE_HEALTH_DETAILS')
        data.update(health_override_used=True,health_forced_devices=[NAMES[2]],
                    health_overrides=[dict(hostname=NAMES[2],phase='after_install',
                        reason_code='HEALTH_STATUS_UNAVAILABLE',status='N/A',issue_count=None)])
        original=copy.deepcopy(data)
        text=app._render_summary(data)
        self.assertNotIn('PRIVATE_HEALTH_DETAILS',text)
        self.assertNotIn('HEALTH_STATUS_UNAVAILABLE',text)
        attention=text.split('+-- 05 ATTENTION',1)[1].split('+-- 06',1)[0]
        self.assertEqual(attention.count('HEALTH / CHECK_REQUIRED:'),1)
        self.assertIn('HEALTH / CHECK_REQUIRED: 3 device(s)',attention)
        self.assertIn('  - '+', '.join(NAMES)+'\n',attention)
        self.assertIn('nv show system health',attention)
        self.assertIn('HEALTH OVERRIDE USED',text)
        self.assertEqual(data,original)


class CompactSummaryWorkflowTests(unittest.TestCase):
    def test_real_nine_device_workflow_formats_four_per_line_without_changing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            code,data,err,calls,installs=native.ThreeComponentWorkflowTests().invoke(
                Path(directory).resolve(),selection=('--os-only',),ssd_version='CE00A474',
                os_branch_case=dict(currents=['25.02.8008']*9,available=['25.03.1014']))
            self.assertEqual(code,0,err)
            self.assertEqual(len(installs),9)
            self.assertEqual(data['selected_ib_count'],9)
            self.assertEqual(len(data['ssd_checks']),9)
            summary=err.split('========== IB Upgrade Summary ==========',1)[1]
            expected=[
                '    - ew-spine01.example [CANARY], ew-spine02.example, ew-spine03.example, ew-spine04.example',
                '    - ew-spine05.example, ew-spine06.example, ew-spine07.example, ew-spine08.example',
                '    - ew-spine09.example',
            ]
            component=summary.split('\nOS:',1)[1].split('  SSD firmware',1)[0]
            self.assertEqual([line for line in component.splitlines() if line.startswith('    - ')],expected)
            ssd=summary.split('SSD firmware (informational only):',1)[1].split('+-- 04',1)[0]
            self.assertEqual([line for line in ssd.splitlines() if line.startswith('      - ')],
                ['  '+line for line in expected])
            self.assertEqual(json.loads((Path(data['run_directory'])/'run-report.json').read_text()),data)

    def test_real_two_device_ssd_summary_groups_but_report_keeps_per_device_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            code,data,err,calls,installs=native.ThreeComponentWorkflowTests().invoke(
                Path(directory).resolve(),selection=('--os-only',),two=True,ssd_version='CE00A474')
            self.assertEqual(code,0,err)
            self.assertEqual(len(installs),2)
            summary=err.split('========== IB Upgrade Summary ==========',1)[1]
            self.assertIn('PASS / MATCH: 2 device(s)',summary)
            self.assertIn('ew-spine01.example [CANARY], ew-spine02.example',summary)
            self.assertEqual(len(data['ssd_checks']),2)
            self.assertEqual(json.loads((Path(data['run_directory'])/'run-report.json').read_text()),data)

    def test_real_failure_keeps_cause_and_device_paths_in_json_not_repeated_terminal_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            code,data,err,calls,installs=native.ThreeComponentWorkflowTests().invoke(
                Path(directory).resolve(),selection=('--os-only',),prewrite_query_timeout='nv config show -o commands')
            self.assertEqual(code,3,err)
            self.assertEqual(installs,[])
            self.assertEqual(err.count('Logs:'),1)
            self.assertIn('query=nv config show -o commands',err)
            self.assertTrue(data['component_results'][0]['log_directory'])
            self.assertEqual(json.loads((Path(data['run_directory'])/'run-report.json').read_text()),data)


if __name__=='__main__': unittest.main()
