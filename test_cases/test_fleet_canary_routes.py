"""I-017/R-007 literal route, gate and append expectations, independent of selection implementation."""
import hashlib
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'test_cases'))
import fleet_engine as engine
import ibsw_v2_device as ib
import test_fleet_engine as fixture
from ibsw_upgrade_contract import load_global_text, normalize_upgrade
from test_ibsw_v2_device import policy_for


def segment(component, start, target, files, digests):
    return (component, start, target, tuple(files), tuple(digests))


def record(item, **changes):
    value = dict(component=item[0], from_version=item[1], to_version=item[2],
                 image_files=list(item[3]), sha256=list(item[4]), run_id='prior',
                 hostname='previous-csv-host', utc='2026-11-01T00:00:00Z', canary=True)
    value.update(changes)
    return value


class RouteFamily(fixture.FakeFamily):
    """Independent literal adapter: whole-route baseline selector deliberately ignores health."""
    def __init__(self, packages, routes, scope='route'):
        super().__init__(packages)
        self.routes, self.scope, self.calls = routes, scope, 0

    def segments(self, plan, component, infos):
        return self.routes[id(plan)]

    def canaries(self, component, members):
        self.calls += 1
        if self.scope == 'component':
            return [members[0][0]]
        return None  # New route-policy interface; real IB workflow is the independent legacy business RED.


class CanaryRouteTests(unittest.TestCase):
    def make_world(self, needs=None, *, forced=(), selected='os', scope='route', upgrade=True, skip=False,
                   speed=1000):
        needs = needs or {'sw01': [['os-2.bin']], 'sw02': [['os-2.bin']]}
        world = fixture.World(self, list(needs), selected=(selected,), upgrade=upgrade, speed=speed,
                              needs={host: {selected: path} for host, path in needs.items()},
                              install=0.001, down=0.002, nvue=0.001)
        packages = world.family.by_name
        routes = {}
        for host, plan in world.ops.plans.items():
            start = '1.0' if len(needs[host]) > 1 else ('2.0' if needs[host] and needs[host][0] == ['os-3.bin'] else '1.0')
            route = []
            for files in needs[host]:
                target = packages[files[0]].version
                route.append(segment(selected, start, target, files,
                                     [hashlib.sha256(Path(packages[name].path).read_bytes()).hexdigest() for name in files]))
                start = target
            routes[id(plan)] = route
        family = RouteFamily(packages, routes, scope)
        family.components = (selected,)
        world.family = world.engine.family = family
        original = world.ops.precheck
        def precheck(device, **kwargs):
            result = original(device, **kwargs)
            if device.hostname in forced:
                result['health'] = dict(observed='FAIL', reason='SYNTHETIC_HEALTH', admitted=True)
            return result
        world.ops.precheck = precheck
        world.engine.options = engine.Options(**dict(world.options.__dict__, skip_canary=skip))
        world.record_path = world.engine.evidence.root.parent / 'canary-routes.jsonl'
        world.routes = {host: routes[id(plan)] for host, plan in world.ops.plans.items()}
        return world

    def five(self):
        return self.make_world({'sw01': [['os-2.bin'], ['os-3.bin']],
                                **{f'sw0{i}': [['os-3.bin']] for i in range(2, 6)}}, forced=('sw01',))

    def test_forced_device_only_covers_its_own_segments(self):
        world = self.five()
        result = world.run()
        self.assertEqual(set(result.values()), {('UPGRADED', None)})
        dispatches = world.events('dispatch')
        self.assertEqual(dispatches[0][1], 'sw02', 'healthy suffix must be proved before forced first hop')
        text = world.out.getvalue()
        self.assertIn('[OS CANARY PLAN]', text)
        self.assertIn('forced-only', text)
        self.assertEqual({v['hostname'] for v in map(json.loads, world.record_path.read_text().splitlines())},
                         {'sw01', 'sw02'})

    def test_forced_canary_failure_does_not_block_healthy_devices(self):
        world = self.five()
        world.ops.verify_behaviour['sw01'] = 'unknown'
        result = world.run()
        self.assertEqual([result[f'sw0{i}'] for i in range(2, 6)], [('UPGRADED', None)] * 4)
        self.assertEqual(result['sw01'], ('UNKNOWN', 'COMPONENT_VERSION_NOT_VERIFIED'))
        self.assertEqual(len([v for v in world.events('dispatch') if v[1] == 'sw01']), 1)

    def test_forced_failure_does_not_cancel_waiting_healthy_followers(self):
        world = self.make_world({'sw01': [['os-2.bin'], ['os-3.bin']],
                                 **{f'sw0{i}': [['os-3.bin']] for i in range(2, 6)}},
                                forced=('sw01',), speed=10000)
        failed = threading.Event()
        original_fetch, original_verify = world.ops.fetch, world.ops.verify
        def fetch(device, *args, **kwargs):
            if device.hostname in ('sw03', 'sw04', 'sw05'):
                if not failed.wait(5):
                    raise AssertionError('forced failure must precede these healthy fetch completions')
            return original_fetch(device, *args, **kwargs)
        def verify(device, *args, **kwargs):
            if device.hostname == 'sw01':
                failed.set()
                return dict(state='UNKNOWN', reason='COMPONENT_VERSION_NOT_VERIFIED')
            return original_verify(device, *args, **kwargs)
        world.ops.fetch, world.ops.verify = fetch, verify
        result = world.run()
        self.assertTrue(failed.is_set())
        self.assertEqual([result[f'sw0{i}'] for i in range(2, 6)], [('UPGRADED', None)] * 4)

    def test_forced_only_failure_blocks_only_dependent_devices(self):
        world = self.make_world({'sw01': [['os-2.bin'], ['os-3.bin']], 'sw02': [['os-2.bin'], ['os-3.bin']],
                                 'sw03': [['os-3.bin']]}, forced=('sw01', 'sw02'))
        world.ops.verify_behaviour['sw01'] = 'unknown'
        result = world.run()
        self.assertEqual(result['sw03'], ('UPGRADED', None))
        self.assertEqual(result['sw02'], ('BLOCKED', 'CANARY_FAILED'))
        self.assertFalse(any(v[1] == 'sw02' for v in world.events('dispatch')))

    def test_no_forced_no_record_longest_then_csv_matches_suffix_cover(self):
        world = self.make_world({'sw01': [['os-3.bin']], 'sw02': [['os-2.bin'], ['os-3.bin']],
                                 'sw03': [['os-2.bin'], ['os-3.bin']]})
        world.run()
        self.assertIn('canaries: sw02', world.out.getvalue())
        self.assertEqual(world.events('dispatch')[0][1], 'sw02')
        self.assertIn('[CANARY OS] all canaries passed', world.out.getvalue())

    def test_healthy_canary_failure_keeps_whole_component_gate(self):
        world = self.make_world({'sw01': [['os-2.bin']], 'sw02': [['os-3.bin']],
                                 'sw03': [['os-2.bin']], 'sw04': [['os-3.bin']]})
        world.ops.verify_behaviour['sw02'] = 'unknown'
        result = world.run()
        self.assertEqual(result['sw01'], ('UPGRADED', None))
        self.assertEqual(result['sw03'], ('BLOCKED', 'CANARY_FAILED'))
        self.assertEqual(result['sw04'], ('BLOCKED', 'CANARY_FAILED'))
        self.assertFalse(any(v[1] in ('sw03', 'sw04') for v in world.events('dispatch')))

    def test_recorded_route_is_released_when_unrelated_canary_fails(self):
        world = self.make_world({'sw01': [['os-2.bin']], 'sw02': [['os-3.bin']], 'sw03': [['os-3.bin']]})
        world.record_path.write_text(json.dumps(record(world.routes['sw01'][0])) + '\n')
        world.ops.verify_behaviour['sw02'] = 'unknown'
        result = world.run()
        self.assertEqual(result['sw01'], ('UPGRADED', None))
        self.assertEqual(result['sw03'], ('BLOCKED', 'CANARY_FAILED'))
        self.assertIn('prior', world.out.getvalue())

    def test_exception_route_waits_for_all_segments_before_first_hop(self):
        # Remaining lengths tie after the prefix record; CSV puts the suffix canary first.
        world = self.make_world({'sw02': [['os-3.bin']], 'sw01': [['os-2.bin'], ['os-3.bin']]})
        world.record_path.write_text(json.dumps(record(world.routes['sw01'][0])) + '\n')
        world.ops.verify_behaviour['sw02'] = 'unknown'
        result = world.run()
        self.assertEqual(result['sw01'], ('BLOCKED', 'CANARY_FAILED'))
        self.assertFalse(any(v[1] == 'sw01' for v in world.events('dispatch')),
                         'do not stop a record-assisted follower at an intermediate version')

    def test_component_firmware_uses_only_first_healthy_canary(self):
        for component in ('bios', 'cpld'):
            with self.subTest(component=component):
                world = self.make_world({'sw01': [['fw.bin']], 'sw02': [['fw.bin']], 'sw03': [['fw.bin']]},
                                        forced=('sw01',), selected=component, scope='component')
                world.run()
                self.assertIn(f'[PHASE {component.upper()}] 3 switch(es); canaries: sw02', world.out.getvalue())
                self.assertEqual(world.events('dispatch')[0][1], 'sw02')

    def test_records_plan_coverage_without_choosing(self):
        world = self.make_world(upgrade=False)
        item = record(world.routes['sw01'][0])
        world.record_path.write_text(json.dumps(item) + '\n')
        world.run(plan_only=True)
        self.assertEqual(world.family.calls, 0)
        self.assertFalse(world.events('dispatch'))
        self.assertIn('[OS CANARY PLAN]', world.out.getvalue())
        self.assertIn('prior', world.out.getvalue())
        self.assertIn('previous-csv-host', world.out.getvalue())

    def test_skip_route_output_explicitly_names_the_actual_choice(self):
        world = self.make_world({'sw01': [['os-2.bin']]}, skip=True)
        world.run()
        self.assertIn('  1.0 -> 2.0 os-2.bin: explicit skip-canary', world.out.getvalue().splitlines())
        self.assertNotIn('component canary / skipped', world.out.getvalue())

    def test_component_other_start_output_names_the_actual_representative(self):
        world = self.make_world({'sw01': [['fw.bin']], 'sw02': [['fw.bin']], 'sw03': [['fw.bin']]},
                                forced=('sw01',), selected='bios', scope='component')
        old = world.routes['sw03'][0]
        world.routes['sw03'][0] = segment(old[0], 'different-start', old[2], old[3], old[4])
        world.run()
        self.assertIn('  different-start -> fw2 fw.bin: component canary sw02', world.out.getvalue().splitlines())
        self.assertIn('  1.0 -> fw2 fw.bin: current canary sw02', world.out.getvalue().splitlines())

    def test_plan_uncovered_route_keeps_no_record_without_selecting(self):
        world = self.make_world({'sw01': [['os-2.bin']]}, upgrade=False)
        world.run(plan_only=True)
        self.assertIn('  1.0 -> 2.0 os-2.bin: no record', world.out.getvalue().splitlines())
        self.assertEqual(world.family.calls, 0)

    def test_component_version_image_or_hash_change_requires_canary(self):
        for field, value in [('component', 'bios'), ('from_version', 'other'), ('to_version', 'other'),
                             ('image_files', ['different.bin']), ('sha256', ['0' * 64])]:
            with self.subTest(field=field):
                world = self.make_world()
                world.record_path.write_text(json.dumps(record(world.routes['sw01'][0], **{field: value})) + '\n')
                world.run()
                self.assertIn('canaries: sw01', world.out.getvalue())
                self.assertIn('[OS CANARY PLAN]', world.out.getvalue())

    def test_bad_missing_and_unreadable_records_have_no_coverage(self):
        for bad in ('missing', 'bad-lines', 'unreadable'):
            with self.subTest(case=bad):
                world = self.make_world()
                if bad == 'bad-lines':
                    world.record_path.write_text('not-json\n{}\n' + json.dumps({'component': 'os'}) + '\n')
                elif bad == 'unreadable':
                    world.record_path.mkdir()
                # Plan is sufficient to independently observe record reading, with no append involved.
                world.run(plan_only=True)
                self.assertIn('[OS CANARY PLAN]', world.out.getvalue())
                self.assertNotIn('previous-csv-host', world.out.getvalue())
                self.assertEqual(world.out.getvalue().count('[CANARY ROUTES]'), int(bad == 'unreadable'))

    def test_verified_skip_writes_nine_fields_and_repairs_only_tail_separator(self):
        world = self.make_world({'sw01': [['os-2.bin']]}, skip=True)
        world.record_path.write_text('{partial')
        result = world.run()
        self.assertEqual(set(result.values()), {('UPGRADED', None)})
        lines = world.record_path.read_text().splitlines()
        self.assertEqual(lines[0], '{partial')
        self.assertEqual(len(lines), 2, 'same segment is appended once even with skip canary')
        item = json.loads(lines[1])
        self.assertEqual(set(item), {'component', 'from_version', 'to_version', 'image_files', 'sha256',
                                     'run_id', 'hostname', 'utc', 'canary'})
        self.assertEqual((item['run_id'], item['hostname'], item['canary']), ('r1', 'sw01', False))
        self.assertEqual(item['sha256'], list(world.routes['sw01'][0][4]))
        self.assertTrue(item['utc'].endswith('Z'))

    def test_skip_two_csv_devices_deduplicate_the_same_verified_segment(self):
        world = self.make_world({'Csv-SW01.Example': [['os-2.bin']],
                                 'Csv-SW02.Example': [['os-2.bin']]}, skip=True)
        result = world.run()
        self.assertEqual(result, {'Csv-SW01.Example': ('UPGRADED', None),
                                  'Csv-SW02.Example': ('UPGRADED', None)})
        rows = list(map(json.loads, world.record_path.read_text().splitlines()))
        self.assertEqual(len(rows), 1, 'same actual VERIFIED segment is appended only once')
        self.assertIn(rows[0]['hostname'], ('Csv-SW01.Example', 'Csv-SW02.Example'))
        self.assertEqual((rows[0]['component'], rows[0]['from_version'], rows[0]['to_version'], rows[0]['canary']),
                         ('os', '1.0', '2.0', False))
        self.assertEqual(rows[0]['image_files'], ['os-2.bin'])
        self.assertEqual(rows[0]['sha256'], list(world.routes['Csv-SW01.Example'][0][4]))

    def test_at_target_and_failed_verification_never_create_records(self):
        world = self.make_world({'sw01': [], 'sw02': [['os-2.bin']]})
        world.ops.verify_behaviour['sw02'] = 'unknown'
        world.run()
        self.assertFalse(world.record_path.exists(), 'AT_TARGET and non-VERIFIED cannot certify routes')

    def test_route_canary_at_target_does_not_release_or_record(self):
        world = self.make_world()
        world.ops.dispatch = lambda *args, **kwargs: {'state': 'AT_TARGET'}
        result = world.run()
        self.assertEqual(result['sw02'], ('BLOCKED', 'CANARY_FAILED'))
        self.assertFalse(world.record_path.exists())
        self.assertIn('CANARY_NOT_PERFORMED_AND_VERIFIED', world.out.getvalue())

    def test_remaining_route_length_is_measured_after_record_coverage(self):
        world = self.make_world({'sw01': [['os-2.bin'], ['os-3.bin']],
                                 'sw02': [['fw.bin'], ['cfg.txt']]})
        world.record_path.write_text(json.dumps(record(world.routes['sw01'][0])) + '\n')
        world.run()
        self.assertEqual(world.events('dispatch')[0][1], 'sw02', 'two uncovered hops precede one uncovered hop')

    def test_all_forced_firmware_keeps_one_component_canary_and_two_image_record(self):
        world = self.make_world({'sw01': [['fw.bin', 'cfg.txt']], 'sw02': [['fw.bin', 'cfg.txt']]},
                                forced=('sw01', 'sw02'), selected='cpld', scope='component')
        # Distinct starting firmware versions do not multiply component canaries.
        old = world.routes['sw02'][0]
        changed = segment(old[0], 'different-slot-revision', old[2], old[3], old[4])
        world.routes['sw02'][0] = changed
        world.run()
        self.assertIn('[PHASE CPLD] 2 switch(es); canaries: sw01', world.out.getvalue())
        rows = list(map(json.loads, world.record_path.read_text().splitlines()))
        self.assertEqual(len(rows), 2, 'only actually verified distinct starts get separate records')
        self.assertEqual([row['canary'] for row in rows], [True, False])
        self.assertTrue(all(len(row['image_files']) == len(row['sha256']) == 2 for row in rows))

    def test_record_append_failure_uses_existing_evidence_error_and_stops(self):
        import os
        world = self.make_world()
        real_open = os.open
        def open_file(path, flags, *args, **kwargs):
            if Path(path) == world.record_path:
                raise OSError(28, 'synthetic evidence full')
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(engine.os, 'open', side_effect=open_file):
            with self.assertRaisesRegex(engine.EvidenceError, 'canary route evidence'):
                world.run()
        self.assertEqual([host for _, host, _ in world.events('dispatch')], ['sw01'])
        self.assertNotIn('all canaries passed', world.out.getvalue())


class IbFamilySegmentsTests(unittest.TestCase):
    def test_os_hops_bios_and_one_cpld_segment_bind_both_images(self):
        temporary = __import__('tempfile').TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        policy = policy_for(base / 'http')
        # Independent real normalized firmware policy uses two distinct package bytes and digests.
        firmware = base / 'http/firmware'
        firmware.mkdir()
        for name in ('FUI1_BURN_CPLD000123_REV0400.vme', 'FUI1_REFRESH_CPLD000123_REV0400.vme', '0ACQF.cab'):
            (firmware / name).write_bytes(name.encode())
        policy = normalize_upgrade(load_global_text(f'''schema_version: 2
common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.10
      port: 8088
      http_root: {base / 'http'}
switches:
- ib:
    version: '25.02.8008'
    upgrade:
      package_dir: {base / 'http'}
      packages:
        os:
          sub_dir: image
          files:
          - file: nvos-amd64-25.02.6077.bin
          - file: nvos-amd64-25.02.7002.bin
          - file: nvos-amd64-25.02.8008.bin
        bios:
          sub_dir: firmware
          file: 0ACQF.cab
          version: '0ACQF_06.01.008'
        cpld:
          sub_dir: firmware
          burn:
            file: FUI1_BURN_CPLD000123_REV0400.vme
          refresh:
            file: FUI1_REFRESH_CPLD000123_REV0400.vme
'''), selected=('os', 'bios', 'cpld'), method='http')
        family = ib.IbFamily(policy)
        method = getattr(family, 'segments', None)
        self.assertTrue(callable(method), 'approved family segment provider is required')
        infos = {p.path: engine.PackageInfo.read(p) for p in family.packages(('os', 'bios', 'cpld'))}
        plan = __import__('types').SimpleNamespace(os_path=policy.os[1:], bios=True, cpld=True,
            rows=({'component': 'os', 'current': '25.02.6077'}, {'component': 'bios', 'current': '2'},
                  {'component': 'cpld', 'current': 'CPLD000123_REV0300'}))
        self.assertEqual([(s[0], s[1], s[2], s[3]) for s in method(plan, 'os', infos)],
                         [('os', '25.02.6077', '25.02.7002', ('nvos-amd64-25.02.7002.bin',)),
                          ('os', '25.02.7002', '25.02.8008', ('nvos-amd64-25.02.8008.bin',))])
        self.assertEqual(method(plan, 'bios', infos)[0][:4], ('bios', '2', '0ACQF_06.01.008', ('0ACQF.cab',)))
        cpld = method(plan, 'cpld', infos)
        self.assertEqual(len(cpld), 1)
        self.assertEqual(cpld[0][1:4], ('CPLD000123_REV0300', 'CPLD000123_REV0400',
                         ('FUI1_BURN_CPLD000123_REV0400.vme', 'FUI1_REFRESH_CPLD000123_REV0400.vme')))
        self.assertEqual(cpld[0][4], tuple(hashlib.sha256((firmware / n).read_bytes()).hexdigest() for n in cpld[0][3]))
        self.assertNotEqual(cpld[0][4][0], cpld[0][4][1])
