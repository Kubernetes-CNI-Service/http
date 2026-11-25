"""I-017 real five-device Engine/LiveOps/component/owned-runner routes, then record reuse."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'test_cases'))
import fleet_engine as engine
import fleet_link
import fleet_probe
import fleet_ssh as ssh
import ibsw_v2_device as ib
from ibsw_upgrade_contract import InventoryDevice, load_global_text, normalize_upgrade
from ibsw_v2_switch_sim import LocalSwitch, SimFleet, HEALTH_OK
from test_ibsw_v2_device import policy_for, SENTINEL

FAST = fleet_probe.Timings(upgrading_ping=.03, reboot_wait=.05, ladder_ping=.03, ladder_retry=.03,
                           ssh_check=.3, dwell=3, ladder_budget=2, deadline=8, post_ready_settle=.03)


class UpgradeCanaryRoutesWorkflowTests(unittest.TestCase):
    def test_forced_first_failure_four_healthy_complete_then_recorded_second_run(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        policy_for(base / 'http')
        firmware = base / 'http/firmware'
        firmware.mkdir()
        files = ('FUI1_BURN_CPLD000123_REV0400.vme', 'FUI1_REFRESH_CPLD000123_REV0400.vme')
        for name in files:
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
        cpld:
          sub_dir: firmware
          burn:
            file: {files[0]}
          refresh:
            file: {files[1]}
'''), selected=('os', 'cpld'), method='http')
        key = ssh._sdk().ECDSAKey.generate()
        switches, devices, pin_lines = [], [], []
        for i in range(1, 6):
            host, address, mac = f'sw0{i}', f'192.0.2.{20+i}', f'02:00:00:00:00:{20+i:02x}'
            switch = LocalSwitch(base / 'switches', host, address, mac,
                                 '25.02.6077' if i == 1 else '25.02.7002', password=SENTINEL,
                                 nvue=1000 if i == 1 else .03, down=.03)
            (switch.state / 'cpld').write_text('CPLD000123_REV0300')
            if i == 1:
                (switch.state / 'health').write_text(HEALTH_OK.replace('status      OK', 'status      FAIL'))
            switches.append(switch)
            devices.append(InventoryDevice(host, address, mac))
            pin_lines.append(f'{address} {key.get_name()} {key.get_base64()}\n')
        fleet = SimFleet(switches, base / 'http', key.get_base64())
        def run(run_id, current, *, plan=False):
            creds = ssh.Credentials('admin', key, ssh.fingerprint(key.asbytes()), SENTINEL)
            ops = ib.LiveOps(pins=ssh.HostPins(''.join(pin_lines).encode()), credentials=creds, policy=policy,
                             selected=('os', 'cpld'), run_id=run_id, force_health=True,
                             management_line=f'{key.get_name()} {key.get_base64()} mgmt\n'.encode(),
                             connector=fleet.connector, ping_run=fleet.ping_run, tcp_probe=fleet.tcp,
                             dir_for=fleet.dir_for)
            options = engine.Options(run_id=run_id, selected=('os', 'cpld'), upgrade=not plan,
                                     link=fleet_link.decide(1000, source='override'), groups={}, timings=FAST,
                                     progress_seconds=.5, later_hop_batch_seconds=.03)
            out = io.StringIO()
            app = engine.Engine(current, ib.IbFamily(policy), ops, options,
                                engine.Evidence(base / run_id), out=out)
            result = app.run(plan_only=plan)
            return result, out.getvalue()
        first, output = run('first', devices)
        results = {r['hostname']: r for r in first['devices']}
        self.assertEqual([results[d.hostname]['category'] for d in devices[1:]], ['UPGRADED'] * 4, output)
        self.assertEqual(results['sw01']['category'], 'UNKNOWN', output)
        self.assertIn('[PHASE OS] 5 switch(es); canaries: sw[01-02]', output)
        self.assertIn('[PHASE CPLD] 4 switch(es); canaries: sw02', output)
        self.assertIn('forced-only', output)
        records = list(map(json.loads, (base / 'canary-routes.jsonl').read_text().splitlines()))
        self.assertEqual({r['component'] for r in records}, {'os', 'cpld'})
        for switch in switches[1:]:
            self.assertEqual((switch.state / 'version').read_text(), '25.02.8008')
            self.assertEqual((switch.state / 'cpld').read_text(), 'CPLD000123_REV0400')
            self.assertEqual((switch.state / 'cpld-installs').read_text().splitlines(), list(files))
            # The same project upgrades another fresh occurrence of the identical route.
            (switch.state / 'version').write_text('25.02.7002')
            (switch.state / 'cpld').write_text('CPLD000123_REV0300')
        planned, plan_output = run('plan', devices[1:], plan=True)
        self.assertNotIn('[PHASE ', plan_output)
        self.assertIn('[OS CANARY PLAN]', plan_output)
        self.assertIn('first', plan_output)
        self.assertIn('sw02', plan_output)
        second, second_output = run('second', devices[1:])
        self.assertEqual([r['category'] for r in second['devices']], ['UPGRADED'] * 4, second_output)
        self.assertIn('[PHASE OS] 4 switch(es); canaries: none', second_output)
        self.assertIn('[PHASE CPLD] 4 switch(es); canaries: none', second_output)
        self.assertIn('record', second_output)
        for root in ('first', 'plan', 'second'):
            for path in (base / root).rglob('*'):
                if path.is_file():
                    self.assertNotIn(SENTINEL.encode(), path.read_bytes(), str(path))
