"""Passive fixture-reachability witness; no real device or exit-success claim.

Only the existing remote_hook is used. The original delayed lstat closure runs
once per call with unchanged results/exceptions; queries, boot, clocks and live
verification remain unchanged. The initial uncorrected fixture failed
missing==2; this regression requires that diagnostic branch to execute.
"""
import inspect
from pathlib import Path
import tempfile
import unittest

from test_cases import test_ibsw225_three_component_workflow as workflow


class DelayedOwnedExitWitnessTests(unittest.TestCase):
    def test_two_missing_diagnostics_release_lease_then_live_verification(self):
        fixture = workflow.ThreeComponentWorkflowTests(
            'test_delayed_owned_exit_waits_without_relaunch_or_global_transaction')
        missing = []
        bindings = []

        def hook(remote):
            delegate = remote.lstat
            delayed = inspect.getclosurevars(delegate).nonlocals['delayed']
            bindings.append((delegate.__globals__ is workflow.__dict__,
                             delegate.__qualname__))

            def observe_lstat(path):
                if not path.endswith('/owned-exit.record'):
                    return delegate(path)
                entry = delayed.get(path)
                scope = entry[1] if entry is not None else None
                before = scope is not None and scope._active_request_lease is None
                try:
                    result = delegate(path)
                except FileNotFoundError:
                    missing.append(dict(remaining=entry[0] if entry else None,
                        before=before,
                        after=scope is not None and scope._active_request_lease is None))
                    raise
                else:
                    return result

            remote.lstat = observe_lstat

        with tempfile.TemporaryDirectory() as folder:
            code, report, err, calls, installs = fixture.invoke(
                Path(folder).resolve(), selection=('--os-only',), delayed_exit=2,
                remote_hook=hook)
            # Original success/install assertions remain; these are simulated IO
            # inputs processed by the real original pipeline/live verifier.
            self.assertEqual(code, 0, err + repr(report))
            self.assertEqual(len(installs), 1)
            self.assertEqual(installs, [('ew-spine01.example', 'os', '25.03.1010')])
            self.assertEqual(report['targets'][0]['state'], 'COMPLETE')
            component = report['component_results'][0]
            self.assertEqual(component['verification_basis'], 'LIVE_POST_REBOOT')
            self.assertIsNone(component['installer_exit_code'])
            self.assertIs(report['components'][0]['targets'][0]['health_verified'], True)
            self.assertEqual(bindings,
                [(True, 'ThreeComponentWorkflowTests.invoke.<locals>.lstat')])
            self.assertEqual(len(missing), 2, 'DELAYED_OWNED_EXIT_MISSING_NOT_EXERCISED')
            self.assertEqual([row['remaining'] for row in missing], [2, 1])
            for row in missing:
                with self.subTest(remaining=row['remaining']):
                    self.assertIs(row['before'], True)
                    self.assertIs(row['after'], True)
            # No successful owned-exit probe required. Exact boot-before/after
            # payloads are not dynamically observed by this lstat-only witness.
            # Production source restricts this optional probe to the old boot;
            # final LIVE_POST_REBOOT completion uses its unchanged live checks.


if __name__ == '__main__':
    unittest.main()
