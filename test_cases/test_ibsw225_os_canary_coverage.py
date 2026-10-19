"""Fixed owner-approved path-cover canaries; external device IO is simulated."""

# NEW canonical test-header binding; original named bodies below are unchanged.
import unittest as _ibsw225_unittest
from test_cases.ibsw225_fixture_support.runtime_source_support import support as _ibsw225_support
_ibsw225_runtime = _ibsw225_support(_ibsw225_unittest.TestCase())
from test_cases.ibsw225_fixture_support.fixed_fixture_registry import install_fixed_fixtures as _ibsw225_install_fixed_fixtures
_ibsw225_fixed_fixture_modules = _ibsw225_install_fixed_fixtures()

import copy
import contextlib
import json
from pathlib import Path
import tempfile
import unittest
import yaml

import ibsw_upgrade_schedule as schedule
import ibsw_upgrade_contract as contract
import ibsw_upgrade_driver as driver
import test_os_alternatives as alternatives
import test_three_component_workflow as native
import test_upgrade_cli as fixtures


NAMES = tuple('ew-spine%02d.example' % n for n in range(1, 6))
PATHS = {
    '25.02.7002': ['25.02.7002', '25.02.8008', '25.03.1014'],
    '25.02.8008': ['25.02.8008', '25.03.1014'],
    '25.02.8010': ['25.02.8010', '25.03.1014'],
    '25.03.1014': ['25.03.1014'],
}


def rows(*currents):
    return [dict(hostname=NAMES[i], component='os', current=v, target='25.03.1014',
                 action='AT_TARGET_NO_FLASH' if v == '25.03.1014' else 'UPGRADE_REQUIRED',
                 path=list(PATHS[v])) for i, v in enumerate(currents)]


class CanaryCoverageDirectTests(unittest.TestCase):
    def select(self, *currents, policy=None, records=None):
        records = rows(*currents) if records is None else records
        return schedule.select_os_canaries(policy or alternatives.policy(), records,
                                           [r['hostname'] for r in records])

    def test_later_longer_route_covers_earlier_short_route(self):
        plan = self.select('25.02.8008', '25.02.7002', '25.03.1014')
        self.assertEqual(plan['canaries'], [NAMES[1]])
        self.assertEqual(plan['routes'][0]['path'], PATHS['25.02.7002'])
        self.assertEqual(plan['routes'][0]['covers'], list(NAMES[:2]))
        self.assertEqual(plan['routes'][0]['files'],
                         ['nvos-amd64-25.02.8008.bin', 'nvos-amd64-25.03.1014.bin'])

    def test_alternative_branch_needs_an_additional_canary(self):
        plan = self.select('25.02.8008', '25.02.7002', '25.02.8010', '25.02.8008')
        self.assertEqual(plan['canaries'], [NAMES[1], NAMES[2]])
        self.assertEqual([r['covers'] for r in plan['routes']],
                         [[NAMES[0], NAMES[1], NAMES[3]], [NAMES[2]]])

    def test_same_path_ties_use_original_order_and_never_duplicate_canaries(self):
        records = rows('25.02.8008', '25.02.8008', '25.02.8010', '25.02.8010')
        before = copy.deepcopy(records)
        plan = self.select(records=records)
        self.assertEqual(plan['canaries'], [NAMES[0], NAMES[2]])
        self.assertEqual(records, before)

    def test_all_at_target_needs_no_canary(self):
        self.assertEqual(self.select('25.03.1014', '25.03.1014'),
                         dict(canaries=[], routes=[]))

    def test_flat_chain_also_prefers_the_longest_actual_path(self):
        policy = contract.normalize_upgrade(yaml.safe_load(fixtures.GLOBAL),
                                            selected=('os',), method='http')
        records = [dict(hostname=NAMES[0], component='os', current='25.03.1010',
                        target='25.03.1010', action='AT_TARGET_NO_FLASH', path=['25.03.1010']),
                   dict(hostname=NAMES[1], component='os', current='25.02.8008',
                        target='25.03.1010', action='UPGRADE_REQUIRED',
                        path=['25.02.8008', '25.03.1010'])]
        self.assertEqual(self.select(policy=policy, records=records)['canaries'], [NAMES[1]])

    def test_route_gap_unlisted_version_false_nochange_and_unknown_target_are_refused(self):
        for change in (dict(path=['25.02.7002', '25.03.1014']),
                       dict(current='25.02.8009'), dict(action='AT_TARGET_NO_FLASH'),
                       dict(target='25.03.2000'), dict(files=['wrong.bin'])):
            records = rows('25.02.7002'); records[0].update(change)
            with self.subTest(change=change), self.assertRaises(contract.SharedUpgradeHold):
                self.select(records=records)

    def test_duplicate_missing_and_foreign_rows_fail_closed(self):
        records = rows('25.02.7002')
        for bad, names in ((records * 2, [NAMES[0]]), ([], [NAMES[0]]),
                           (records, [NAMES[1]]), (records, [NAMES[0], NAMES[0]])):
            with self.subTest(bad=bad, names=names), self.assertRaises(contract.SharedUpgradeHold):
                schedule.select_os_canaries(alternatives.policy(), bad, names)

    def test_three_independent_branches_are_not_silently_capped_at_two(self):
        doc = alternatives.document()
        group = doc['switches'][0]['ib']['upgrade']['packages']['os']['files'][1]['alternatives']
        group.insert(1, {'file': 'nvos-amd64-25.02.8009.bin'})
        policy = contract.normalize_upgrade(doc, selected=('os',), method='http')
        records = rows('25.02.8008', '25.02.8010')
        records.append(dict(hostname=NAMES[2], component='os', current='25.02.8009',
                            target='25.03.1014', action='UPGRADE_REQUIRED',
                            path=['25.02.8009', '25.03.1014']))
        self.assertEqual(self.select(policy=policy, records=records)['canaries'], list(NAMES[:3]))


class CanaryCoverageWorkflowTests(unittest.TestCase):
    invoke = native.ThreeComponentWorkflowTests.invoke

    def run_case(self, currents, **kwargs):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        root = Path(folder.name).resolve()
        options = dict(currents=currents, available=('25.02.8008', '25.02.8010', '25.03.1014'))
        options.update(kwargs.pop('branch', {}))
        result = self.invoke(root, os_branch_case=options, controlled_grace=True,
                             selection=kwargs.pop('selection', ('--os-only',)), **kwargs)
        return root, result

    def test_longer_later_device_finishes_both_hops_before_shorter_first_device(self):
        root, (code, report, err, calls, installs) = self.run_case(('25.02.8008', '25.02.7002'))
        self.assertEqual(code, 0, err + repr(report))
        self.assertEqual(installs, [(NAMES[1], 'os', '25.02.8008'),
                                   (NAMES[1], 'os', '25.03.1014'),
                                   (NAMES[0], 'os', '25.03.1014')])
        phase = report['components'][0]
        self.assertEqual(phase['canaries'], [NAMES[1]])
        status = json.loads((Path(report['run_directory'])/'os-status.json').read_text())
        self.assertEqual(status['canaries'], [NAMES[1]])
        self.assertEqual(status['canary_routes'][0]['covers'], list(NAMES[:2]))
        self.assertIn(NAMES[1] + ' [CANARY]', err)

    def test_two_full_path_canaries_must_finish_before_any_ordinary_device(self):
        checks = []
        def hook(root, name, command, installs):
            if name in (NAMES[0], NAMES[3]) and command.startswith('/usr/bin/nohup '):
                status = json.loads(next(root.rglob('os-status.json')).read_text())
                checks.append({r['node']['hostname']: r['state'] for r in status['targets']})
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.7002', '25.02.8010', '25.02.8008'), os_branch_hook=hook)
        self.assertEqual(code, 0, err + repr(report))
        self.assertEqual(installs[:3], [(NAMES[1], 'os', '25.02.8008'),
                                      (NAMES[1], 'os', '25.03.1014'),
                                      (NAMES[2], 'os', '25.03.1014')])
        self.assertEqual(report['components'][0]['canaries'], [NAMES[1], NAMES[2]])
        self.assertEqual(len(checks), 2)
        self.assertTrue(all(r[NAMES[1]] == r[NAMES[2]] == 'VERIFIED' for r in checks))
        view = report['summary_groups']['component_groups'][0]
        self.assertEqual([r['hostname'] for r in view['canaries']], [NAMES[1], NAMES[2]])
        self.assertEqual([r['state'] for r in view['canaries']], ['COMPLETE', 'COMPLETE'])
        self.assertIn('Canaries (2)', err)
        for name in (NAMES[1], NAMES[2]): self.assertIn(name + ' [CANARY]', err)
        self.assertEqual(json.loads((Path(report['run_directory'])/'run-report.json').read_text()), report)

    def test_second_canary_failure_keeps_first_success_but_blocks_all_ordinary_devices(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.7002', '25.02.8010', '25.02.8008'), fail=(NAMES[2], 'os'))
        self.assertEqual(code, 3, err + repr(report))
        self.assertEqual([n for n, c, v in installs], [NAMES[1], NAMES[1], NAMES[2]])
        states = {r['hostname']: r['state'] for r in report['targets']}
        self.assertEqual(states, {NAMES[0]: 'BLOCKED_CANARY', NAMES[1]: 'COMPLETE',
                                  NAMES[2]: 'UNKNOWN', NAMES[3]: 'BLOCKED_CANARY'})
        self.assertEqual(report['result'], 'INCOMPLETE')

    def test_first_canary_failure_does_not_rotate_to_second_or_retry_first(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.7002', '25.02.8010'), fail=(NAMES[1], 'os'))
        self.assertEqual(code, 3, err + repr(report))
        self.assertEqual(installs, [(NAMES[1], 'os', '25.02.8008')])
        self.assertEqual(report['components'][0]['canaries'], [NAMES[1], NAMES[2]])

    def test_more_than_two_canaries_are_run_and_recorded(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.8009', '25.02.8010', '25.02.7002'),
            branch=dict(priority=('25.02.8008', '25.02.8009', '25.02.8010'),
                        available=('25.02.8008', '25.02.8009', '25.02.8010', '25.03.1014')))
        self.assertEqual(code, 0, err + repr(report))
        self.assertEqual(report['components'][0]['canaries'], [NAMES[3], NAMES[1], NAMES[2]])
        self.assertEqual([n for n, c, v in installs[:4]], [NAMES[3], NAMES[3], NAMES[1], NAMES[2]])

    def test_explicit_skip_remains_explicit_and_nochange_never_exercises_a_canary(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.7002', '25.02.8010'), skip_canary=True)
        self.assertEqual(code, 0, err + repr(report))
        self.assertEqual(report['components'][0]['canaries'], [])
        self.assertEqual(report['components'][0]['canary_requirement'], 'EXPLICITLY_SKIPPED')
        root, (code, report, err, calls, installs) = self.run_case(('25.03.1014', '25.03.1014'))
        self.assertEqual(code, 0, err + repr(report))
        self.assertEqual(installs, [])
        self.assertEqual(report['components'][0]['canaries'], [])

    def test_bios_and_cpld_remain_independent_single_component_canaries(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.7002', '25.02.8010'), selection=())
        self.assertEqual(code, 0, err + repr(report))
        self.assertEqual([p['canaries'] for p in report['components']],
                         [[NAMES[1], NAMES[2]], [NAMES[0]], [NAMES[0]]])
        self.assertTrue(all(c == 'os' for n, c, v in installs[:4]))

    def test_canary_source_drift_cannot_silently_skip_the_unverified_first_hop(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.7002'), os_branch_drift={NAMES[1]: '25.02.8008'})
        self.assertEqual(code, 3, err + repr(report))
        self.assertEqual(installs, [])
        self.assertIn('OS_CANARY_ROUTE_CHANGED', err)
        self.assertEqual({r['hostname']: r['state'] for r in report['targets']},
                         {NAMES[0]: 'BLOCKED_CANARY', NAMES[1]: 'NOT_EXECUTED'})

    def test_first_hop_success_does_not_release_peers_if_second_hop_fails(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.7002', '25.02.8010'),
            os_branch_fail_target=(NAMES[1], '25.03.1014'))
        self.assertEqual(code, 3, err + repr(report))
        self.assertEqual(installs, [(NAMES[1], 'os', '25.02.8008'), (NAMES[1], 'os', '25.03.1014')])
        self.assertEqual({r['hostname']: r['state'] for r in report['targets']},
            {NAMES[0]: 'BLOCKED_CANARY', NAMES[1]: 'UNKNOWN', NAMES[2]: 'BLOCKED_CANARY'})

    def test_ordinary_failure_does_not_block_other_ordinary_devices_after_coverage(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.8008', '25.02.7002', '25.02.8010'), fail=(NAMES[0], 'os'))
        self.assertEqual(code, 3, err + repr(report))
        self.assertEqual(report['components'][0]['canaries'], [NAMES[2], NAMES[3]])
        self.assertEqual({r['hostname']: r['state'] for r in report['targets']},
            {NAMES[0]: 'UNKNOWN', NAMES[1]: 'COMPLETE', NAMES[2]: 'COMPLETE', NAMES[3]: 'COMPLETE'})

    def test_ordinary_source_regression_cannot_add_an_uncovered_hop_in_a_flat_chain(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.8008'),
            branch=dict(flat=True, priority=('25.02.8008',)),
            os_branch_drift={NAMES[1]: '25.02.7002'})
        self.assertEqual(code, 3, err + repr(report))
        self.assertEqual(installs, [(NAMES[0], 'os', '25.03.1014')])
        self.assertIn('OS_COVERAGE_ROUTE_CHANGED', err)

    def test_ordinary_already_advanced_on_its_covered_route_is_not_reflashed(self):
        root, (code, report, err, calls, installs) = self.run_case(
            ('25.02.8008', '25.02.8008'), branch=dict(flat=True, priority=('25.02.8008',)),
            os_branch_drift={NAMES[1]: '25.03.1014'})
        self.assertEqual(code, 0, err + repr(report))
        self.assertEqual(installs, [(NAMES[0], 'os', '25.03.1014')])
        ordinary = next(r for r in report['component_results'] if r['hostname']==NAMES[1])
        self.assertEqual(ordinary['action'], 'ALREADY_AT_TARGET_VERIFIED')


class CanaryStatusDirectTests(unittest.TestCase):
    def initial(self):
        nodes = [dict(hostname=n, address='192.0.2.%d' % (i+1), mac='02:00:00:00:00:%02x' % i)
                 for i, n in enumerate(NAMES[:3])]
        return schedule.native_component_status_document('os', 'run-'+'a'*32, 'b'*64,
            ['c'*64, 'd'*64], nodes, NAMES[0], canaries=[NAMES[0]], canary_routes=[])

    def test_new_native_status_records_complete_canary_set_and_routes(self):
        initial = self.initial(); actual = copy.deepcopy(initial)
        actual.update(canary=NAMES[1], canaries=[NAMES[1], NAMES[2]],
            canary_routes=[dict(hostname=NAMES[1], path=PATHS['25.02.7002'],
                files=['nvos-amd64-25.02.8008.bin','nvos-amd64-25.03.1014.bin'], covers=list(NAMES[:2])),
                dict(hostname=NAMES[2], path=PATHS['25.02.8010'],
                files=['nvos-amd64-25.03.1014.bin'], covers=[NAMES[2]])])
        self.assertEqual(actual['schema_version'], 3)
        self.assertEqual(schedule.validate_native_component_status_document(actual, initial), actual)

    def test_duplicate_foreign_inconsistent_or_malformed_canaries_are_refused(self):
        initial = self.initial()
        for change in (dict(canaries=[NAMES[0], NAMES[0]]), dict(canaries=['foreign']),
                       dict(canaries=[]), dict(canary_routes=[{}])):
            actual = copy.deepcopy(initial); actual.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                schedule.validate_native_component_status_document(actual, initial)

    def test_legacy_schema_two_observations_remain_readable_but_never_become_authority(self):
        old = schedule.native_component_status_document('os', 'run-'+'a'*32, 'b'*64,
            ['c'*64,'d'*64], [dict(hostname=NAMES[0])], NAMES[0])
        self.assertEqual(old['schema_version'], 2)
        self.assertEqual(schedule.validate_native_component_status_document(old, old), old)
        changed = copy.deepcopy(old); changed['targets'][0]['state'] = 'VERIFIED'
        with self.assertRaises(ValueError): schedule.validate_native_component_status_document(changed, old)


class CanaryStatusDriverWorkflowTests(unittest.TestCase):
    @contextlib.contextmanager
    def scope(self):
        with tempfile.TemporaryDirectory() as folder:
            project, home, known = fixtures.WorkflowTests().fixture(Path(folder).resolve())
            args = ('--project', str(project), '--os-only', '--method', 'http', '--standalone-inputs')
            prepared = driver.prepare_manual_run(fixtures.app.__file__, str(project), args)
            with driver.open_manual_run(fixtures.app.__file__, str(project), args, prepared['run_directory']) as scope:
                scope.enable_cooperative_status_snapshots()
                scope.initialize_native_component_status_data()
                scope._native_schedule_started = True
                yield scope

    def test_second_canary_negative_fact_blocks_native_preflight_not_just_the_first(self):
        with self.scope() as scope:
            scope._record_native_component_canaries('os', NAMES[:2])
            scope._record_native_component_failure('os', NAMES[1], 'UNKNOWN', 'SYNTHETIC_SECOND_CANARY')
            self.assertEqual(scope.read_component_status_data('os')['canaries'], list(NAMES[:2]))
            with scope._request_namespace_lease(), self.assertRaises(driver.PreparationHold):
                scope._component_negative_preflight_locked(NAMES[0], 'os')

    def test_recorded_multi_canary_set_is_single_use_and_cannot_be_replaced(self):
        with self.scope() as scope:
            scope._record_native_component_canaries('os', NAMES[:2])
            with self.assertRaises(contract.SharedUpgradeHold):
                scope._record_native_component_canaries('os', (NAMES[1],))
            self.assertEqual(scope.read_component_status_data('os')['canaries'], list(NAMES[:2]))

    def test_foreign_canary_is_rejected_before_changing_the_original_list(self):
        with self.scope() as scope:
            before = scope.read_component_status_data('os')
            with self.assertRaises(contract.SharedUpgradeHold):
                scope._record_native_component_canaries('os', ('foreign.example',))
            self.assertEqual(scope.read_component_status_data('os'), before)


if __name__ == '__main__':
    unittest.main()
