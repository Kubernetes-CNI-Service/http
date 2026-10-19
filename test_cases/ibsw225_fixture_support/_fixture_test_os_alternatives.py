"""Owner-approved alternative stages; fixed expectations, no real device IO."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml
import ibsw_upgrade_contract as contract
import ibsw_upgrade_driver as driver
import ibsw_upgrade_executor as executor
import test_upgrade_cli as fixtures
import test_three_component_workflow as native


def document():
    doc=yaml.safe_load(fixtures.GLOBAL)
    ib=doc['switches'][0]['ib']
    ib['version']='25.03.1014'
    ib['upgrade']['packages']['os']['files']=[
        {'file':'nvosv25-02-7002amd64.bin'},
        {'alternatives':[{'file':'nvos-amd64-25.02.8008.bin'},
                         {'file':'nvos-amd64-25.02.8010.bin'}]},
        {'file':'nvos-amd64-25.03.1014.bin'}]
    return doc


def policy(doc=None):
    return contract.normalize_upgrade(doc or document(),selected=('os',),method='http')


class AlternativeStageDirectTests(unittest.TestCase):
    def path(self, current, available=None, doc=None):
        selected=policy(doc)
        paths=None if available is None else frozenset('/var/www/html/'+name for name in available)
        return [p.version for p in contract.select_os_path(selected,current,available=paths)]

    def test_older_source_uses_one_candidate_then_final_not_both(self):
        self.assertEqual(self.path('25.02.7002'),['25.02.8008','25.03.1014'])

    def test_both_group_members_skip_siblings_and_reach_final(self):
        for current in ('25.02.8008','25.02.8010'):
            self.assertEqual(self.path(current),['25.03.1014'])

    def test_only_second_candidate_available_is_a_valid_path(self):
        self.assertEqual(self.path('25.02.7002',('nvos-amd64-25.02.8010.bin',
            'nvos-amd64-25.03.1014.bin')),['25.02.8010','25.03.1014'])

    def test_priority_is_declaration_order_not_highest_or_lowest_version(self):
        doc=document()
        doc['switches'][0]['ib']['upgrade']['packages']['os']['files'][1]['alternatives'].reverse()
        self.assertEqual(self.path('25.02.7002',doc=doc),['25.02.8010','25.03.1014'])

    def test_current_and_sibling_packages_need_not_exist(self):
        for current in ('25.02.8008','25.02.8010'):
            self.assertEqual(self.path(current,('nvos-amd64-25.03.1014.bin',)),['25.03.1014'])
        self.assertEqual(self.path('25.03.1014',()),[])

    def test_missing_entire_stage_or_final_never_skips_that_stage(self):
        for available in ((),('nvos-amd64-25.03.1014.bin',),('nvos-amd64-25.02.8008.bin',)):
            with self.subTest(available=available),self.assertRaises(ValueError):
                self.path('25.02.7002',available)

    def test_unknown_current_version_is_not_guessed_or_downgraded(self):
        for version in ('25.02.8009','25.03.2000'):
            with self.assertRaises(ValueError): self.path(version)

    def test_flat_linear_contract_and_serialized_policy_are_unchanged(self):
        legacy=contract.normalize_upgrade(yaml.safe_load(fixtures.GLOBAL),selected=('os',),method='http')
        self.assertEqual([p.version for p in contract.select_os_path(legacy,'25.02.8008')],['25.03.1010'])
        self.assertNotIn('os_stages',driver._policy_document(legacy))
        self.assertEqual(driver._policy_document(policy())['os_stages'],((0,),(1,2),(3,)))

    def test_two_alternative_stages_choose_one_per_stage(self):
        doc=document()
        doc['switches'][0]['ib']['upgrade']['packages']['os']['files'].insert(2,
            {'alternatives':[{'file':'nvos-amd64-25.02.9000.bin'},
                             {'file':'nvos-amd64-25.02.9001.bin'}]})
        self.assertEqual(self.path('25.02.7002',doc=doc),['25.02.8008','25.02.9000','25.03.1014'])

    def test_bad_group_shapes_are_rejected_by_shared_global_validator(self):
        bad=[{'alternatives':[]},{'alternatives':[{'file':'nvos-amd64-25.02.8008.bin'}]},
             {'alternatives':'25.02.8008'},
             {'file':'nvos-amd64-25.02.8008.bin','alternatives':[]},
             {'alternatives':[{'alternatives':[]},{'file':'nvos-amd64-25.02.8010.bin'}]}]
        for entry in bad:
            doc=document(); doc['switches'][0]['ib']['upgrade']['packages']['os']['files'][1]=entry
            with self.subTest(entry=entry),self.assertRaises(ValueError):
                contract.load_global_text(yaml.safe_dump(doc))

    def test_duplicates_crossing_stages_final_group_and_version_conflicts_are_rejected(self):
        variations=[]
        doc=document(); doc['switches'][0]['ib']['upgrade']['packages']['os']['files'][1]['alternatives'][1]=copy.deepcopy(
            doc['switches'][0]['ib']['upgrade']['packages']['os']['files'][1]['alternatives'][0]); variations.append(doc)
        doc=document(); doc['switches'][0]['ib']['upgrade']['packages']['os']['files'].insert(2,
            {'file':'nvos-amd64-25.02.8010.bin'}); variations.append(doc)
        doc=document(); doc['switches'][0]['ib']['upgrade']['packages']['os']['files'][-1]=(
            {'alternatives':[{'file':'nvos-amd64-25.03.1013.bin'},{'file':'nvos-amd64-25.03.1014.bin'}]}); variations.append(doc)
        doc=document(); doc['switches'][0]['ib']['upgrade']['packages']['os']['files'][1]['alternatives'][0]['version']='25.02.8011'; variations.append(doc)
        doc=document(); doc['switches'][0]['ib']['upgrade']['packages']['os']['files'][1]['alternatives'][0]['file']='nvos-amd64-25.03.2000.bin'; variations.append(doc)
        for doc in variations:
            with self.subTest(doc=doc),self.assertRaises(ValueError): contract.load_global_text(yaml.safe_dump(doc))


class PackageSourceDirectTests(unittest.TestCase):
    def source(self,root):
        return contract.Package('test.bin','25.02.8008',str(root/'test.bin'))

    def test_missing_file_has_safe_specific_reason_and_exact_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); package=self.source(root)
            with self.assertRaises(executor._PackageSourceHold) as caught:
                executor._package_source_snapshot(str(root),package)
            self.assertEqual(caught.exception.reason_code,'PACKAGE_SOURCE_MISSING')
            self.assertEqual(caught.exception.package_path,str(root/'test.bin'))
            code,message=fixtures.app._failure_detail(caught.exception,'UPGRADE')
            self.assertEqual(code,'PACKAGE_SOURCE_MISSING')
            self.assertIn(str(root/'test.bin'),message)

    def test_empty_nonregular_and_unreadable_files_cannot_be_selected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); path=root/'test.bin'; package=self.source(root)
            path.touch()
            with self.assertRaises(executor._PackageSourceHold) as caught: executor._package_source_snapshot(str(root),package)
            self.assertEqual(caught.exception.reason_code,'PACKAGE_SOURCE_EMPTY')
            path.unlink(); path.mkdir()
            with self.assertRaises(executor._PackageSourceHold) as caught: executor._package_source_snapshot(str(root),package)
            self.assertEqual(caught.exception.reason_code,'PACKAGE_SOURCE_NOT_REGULAR')
            path.rmdir(); path.write_bytes(b'SYNTHETIC')
            with patch.object(executor.os,'access',return_value=False):
                with self.assertRaises(executor._PackageSourceHold) as caught: executor._package_source_snapshot(str(root),package)
            self.assertEqual(caught.exception.reason_code,'PACKAGE_SOURCE_ACCESS_DENIED')

    def test_leaf_and_parent_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); target=root/'real.bin'; target.write_bytes(b'SYNTHETIC')
            (root/'test.bin').symlink_to(target)
            with self.assertRaises(executor._PackageSourceHold): executor._package_source_snapshot(str(root),self.source(root))
            (root/'link').symlink_to(root,target_is_directory=True)
            package=contract.Package('real.bin','25.02.8008',str(root/'link/real.bin'))
            with self.assertRaises(executor._PackageSourceHold) as caught: executor._package_source_snapshot(str(root),package)
            self.assertEqual(caught.exception.reason_code,'PACKAGE_SOURCE_UNAPPROVED_LINK')


class AlternativeStageWorkflowTests(unittest.TestCase):
    invoke=native.ThreeComponentWorkflowTests.invoke

    def run_case(self,case,selection=('--os-only',),**kwargs):
        folder=tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root=Path(folder.name).resolve()
        return root,self.invoke(root,os_branch_case=case,selection=selection,**kwargs)

    def test_reverse_priority_is_used_by_native_dispatch_not_just_the_display(self):
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002',),
            priority=('25.02.8010','25.02.8008'),available=('25.02.8008','25.02.8010','25.03.1014')))
        self.assertEqual(code,0,err+repr(report))
        self.assertEqual([v for n,c,v in installs],['25.02.8010','25.03.1014'])

    def test_all_components_keep_final_os_gate_and_only_final_hop_collects_ssd(self):
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002','25.02.8010'),
            available=('25.02.8008','25.03.1014')),selection=(),ssd_version='CE00A474')
        self.assertEqual(code,0,err+repr(report))
        self.assertEqual([c for n,c,v in installs],['os','os','os','bios','bios','cpld','cpld'])
        self.assertEqual([r['status'] for r in report['ssd_checks']],['MATCH','MATCH'])
        self.assertTrue(all(row['os']=='25.03.1014' for row in self._ssd_query_context if row['postcheck']))

    def test_final_target_no_change_needs_no_package_and_no_canary(self):
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.03.1014',),available=()))
        self.assertEqual(code,0,err+repr(report))
        self.assertEqual(installs,[])
        self.assertIsNone(report['components'][0]['canary'])
        self.assertEqual(report['component_results'][0]['action'],'AT_TARGET_PREFLIGHT')
        self.assertEqual(report['components'][0]['targets'],[])

    def test_failed_first_hop_stops_own_next_hop_and_component_peers(self):
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002','25.02.8010'),
            available=('25.02.8008','25.03.1014')),fail=(native.HOST,'os'))
        self.assertEqual(code,3,err+repr(report))
        self.assertEqual(installs,[(native.HOST,'os','25.02.8008')])
        self.assertEqual([r['state'] for r in report['targets']],['UNKNOWN','BLOCKED_CANARY'])

    def test_unselected_candidate_change_is_not_a_change_to_the_frozen_route(self):
        changed=[]
        def hook(root,name,command,installs):
            if changed or not list(root.rglob('os-route-plan.json')): return
            (root/'packages/image/nvos-amd64-25.02.8010.bin').write_bytes(b'UNSELECTED SYNTHETIC SOURCE')
            changed.append(True)
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002',),
            available=('25.02.8008','25.02.8010','25.03.1014')),os_branch_hook=hook)
        self.assertEqual(code,0,err+repr(report))
        self.assertEqual([v for n,c,v in installs],['25.02.8008','25.03.1014'])

    def test_tampered_route_evidence_stops_before_any_installer(self):
        changed=[]
        def hook(root,name,command,installs):
            files=list(root.rglob('os-route-plan.json'))
            if changed or not files: return
            files[0].write_text('{}\n'); changed.append(True)
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002',),
            available=('25.02.8008','25.03.1014')),os_branch_hook=hook)
        self.assertEqual(code,2,err+repr(report))
        self.assertEqual(installs,[])

    def test_mixed_7002_8008_8010_and_target_upgrade_in_one_run(self):
        root,(code,report,err,calls,installs)=self.run_case(dict(
            currents=('25.02.7002','25.02.8008','25.02.8010','25.03.1014'),
            available=('25.02.8008','25.02.8010','25.03.1014')))
        self.assertEqual(code,0,err+repr(report))
        paths={name:[v for n,c,v in installs if n==name] for name in ('ew-spine01.example','ew-spine02.example','ew-spine03.example','ew-spine04.example')}
        self.assertEqual(paths,{'ew-spine01.example':['25.02.8008','25.03.1014'],
            'ew-spine02.example':['25.03.1014'],'ew-spine03.example':['25.03.1014'],'ew-spine04.example':[]})
        self.assertEqual(report['components'][0]['canary'],'ew-spine01.example')
        self.assertEqual(installs[:2],[(native.HOST,'os','25.02.8008'),(native.HOST,'os','25.03.1014')])
        self.assertEqual([r['state'] for r in report['targets']],
                         ['COMPLETE','COMPLETE','COMPLETE','NO_CHANGE'])
        for row in report['version_plan']:
            stored=json.loads((Path(report['run_directory'])/row['hostname']/'os-route-plan.json').read_text())
            self.assertEqual(stored['versions'],row['path'])

    def test_only_8010_available_and_absent_current_package_are_supported(self):
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002',),
            available=('25.02.8010','25.03.1014')))
        self.assertEqual(code,0,err+repr(report))
        self.assertEqual([v for n,c,v in installs],['25.02.8010','25.03.1014'])
        self.assertIn('25.02.7002 -> 25.02.8010 -> 25.03.1014',err)

    def test_no_intermediate_files_needed_for_both_current_group_members(self):
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.8008','25.02.8010'),
            available=('25.03.1014',)))
        self.assertEqual(code,0,err+repr(report))
        self.assertEqual(sorted(installs),[('ew-spine01.example','os','25.03.1014'),('ew-spine02.example','os','25.03.1014')])

    def test_missing_complete_route_is_skipped_before_key_preparation_but_ready_peer_runs(self):
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002','25.02.8010'),
            available=('25.03.1014',)))
        self.assertEqual(code,3,err+repr(report))
        self.assertEqual(installs,[('ew-spine02.example','os','25.03.1014')])
        self.assertEqual(report['ready_ib_count'],1)
        self.assertEqual(report['skipped_devices'][0]['reasons'],['OS_PACKAGE_ROUTE_UNAVAILABLE'])
        self.assertIn('nvos-amd64-25.02.8008.bin',err)
        self.assertIn('nvos-amd64-25.02.8010.bin',err)
        self.assertFalse(any(e['hostname']==native.HOST for e in report.get('progress_events',[])))

    def test_inspection_can_select_second_candidate_but_never_writes_device(self):
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002',),
            available=('25.02.8010','25.03.1014')),inspect=True)
        self.assertEqual(code,0,err+repr(report))
        self.assertEqual(installs,[])
        self.assertEqual(report['version_plan'][0]['path'],['25.02.7002','25.02.8010','25.03.1014'])
        self.assertFalse(any(c.startswith(('nv set','nv config apply','nv config patch')) for n,c in calls))

    def test_chosen_source_removed_after_plan_does_not_fall_back_or_launch(self):
        changed=[]
        def hook(root,name,command,installs):
            if changed or not list(root.rglob('os-route-plan.json')): return
            (root/'packages/image/nvos-amd64-25.02.8008.bin').unlink(); changed.append(True)
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002',),
            available=('25.02.8008','25.02.8010','25.03.1014')),os_branch_hook=hook)
        self.assertEqual(code,2,err+repr(report))
        self.assertEqual(installs,[])
        self.assertIn('PACKAGE_SOURCE_CHANGED',err)

    def test_chosen_source_replaced_after_first_hop_does_not_launch_next_hop(self):
        changed=[]
        def hook(root,name,command,installs):
            if changed or not installs: return
            path=root/'packages/image/nvos-amd64-25.03.1014.bin'
            path.unlink(); path.write_bytes(b'REPLACED SYNTHETIC SOURCE'); changed.append(True)
        root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002',),
            available=('25.02.8008','25.03.1014')),os_branch_hook=hook)
        self.assertEqual(code,2,err+repr(report))
        self.assertEqual(installs,[(native.HOST,'os','25.02.8008')])
        self.assertIn('PACKAGE_SOURCE_CHANGED',err)

    def test_route_record_failure_stops_before_auth_preparation_or_install(self):
        with patch.object(driver._PreparedRunScope,'_record_os_route_plan',side_effect=OSError('PRIVATE_FAILURE')):
            root,(code,report,err,calls,installs)=self.run_case(dict(currents=('25.02.7002',),
                available=('25.02.8008','25.03.1014')))
        self.assertEqual(code,2,err+repr(report))
        self.assertEqual(installs,[])
        self.assertNotIn('PRIVATE_FAILURE',err)


if __name__=='__main__': unittest.main()
