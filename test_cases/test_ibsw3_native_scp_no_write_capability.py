"""UNRUN natural SCP all-at-target capability; not SCP transfer permission."""
import importlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

from test_cases import scp_native_cli_fixture_v2 as SCP


class NativeScpNoWriteCapabilityTests(unittest.TestCase):
    def test_natural_scp_os_at_target_needs_no_source_owner_or_package_stream(self):
        # Syntax-only front gate. The workflow below uses the fixture's real
        # private project argv, not this placeholder or the returned Namespace.
        try:
            parsed = SCP.app._parse_cli((
                '--project', '/SYNTHETIC-CLI-ONLY/project', '--os-only',
                '--method', 'scp', '--known-hosts', '/SYNTHETIC-CLI-ONLY/known_hosts',
                '--upgrade', '--yes'))
        except SCP.app._InspectionHold:
            self.fail('MISSING_NATIVE_SCP_CLI_CAPABILITY; '
                      'no-write/factory/borrow/final-OS=NOT_REACHED')
        self.assertEqual('scp', parsed.method)
        self.assertIsNone(sys.getprofile())
        self.assertIsNone(threading.getprofile())
        provider = importlib.import_module('ibsw_upgrade_scp')
        freeze = SCP.driver._PreparedRunScope.freeze_scp_package_sources
        factory = provider.package_content_owner
        constructor = provider._PackageContentOwner.__init__
        begin = SCP.pipeline.NativeAdapter.begin
        prepare = SCP.driver.prepare_manual_run
        counts = dict(prepare=0, freeze=0, factory=0, begin=0, original_package_os_read=0)

        def observe(frame, event, argument):
            # Passive original-code/globals observations; no method, factory,
            # verifier, OS function or IO callback is substituted here.
            if event == 'call':
                for name, function in (('prepare', prepare), ('freeze', freeze),
                                       ('factory', factory), ('begin', begin)):
                    if frame.f_code is function.__code__ and frame.f_globals is function.__globals__:
                        counts[name] += 1
            elif (event == 'c_call' and argument is provider.os.read
                  and frame.f_code is constructor.__code__
                  and frame.f_globals is constructor.__globals__):
                # The original holder's only os.read is its actual package
                # digest stream. Do not inspect, close or adopt numeric FDs.
                counts['original_package_os_read'] += 1

        try:
            sys.setprofile(observe)
            threading.setprofile(observe)
            with tempfile.TemporaryDirectory() as raw:
                code, report, err, calls, installs = SCP.ThreeComponentWorkflowTests().invoke(
                    Path(raw).resolve(), old_os=False, selection=('--os-only',))
        finally:
            threading.setprofile(None)
            sys.setprofile(None)

        self.assertEqual(0, code, 'natural SCP no-write capability: '+err)
        self.assertEqual([], installs)
        self.assertGreater(counts['prepare'], 0, 'real main must reach its original factory graph')
        self.assertEqual(0, counts['freeze'])
        self.assertEqual(0, counts['factory'])
        self.assertEqual(0, counts['original_package_os_read'])
        self.assertIn((SCP.HOST, 'nv show system version'), calls)
        rows = [row for row in report['version_plan'] if row['component'] == 'os']
        self.assertEqual(1, len(rows))
        self.assertEqual(dict(hostname='ew-spine01.example', component='os',
                              current='25.03.1010', target='25.03.1010',
                              action='AT_TARGET_NO_FLASH', path=['25.03.1010']),
                         {name: rows[0][name] for name in (
                             'hostname','component','current','target','action','path')})
        # Begin is a witness, not a mandated phase: the original scheduler may
        # remove an at-target node before execution. Never invent an owner to
        # make this counter nonzero.
        print('SCP_NO_WRITE_PASSIVE_COUNTS='+json.dumps(counts, sort_keys=True))
