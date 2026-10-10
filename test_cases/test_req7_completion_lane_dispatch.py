"""Durable collection cannot be relabelled by independent tracker lanes."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases import test_collection_cycle_persistence as persistence
from test_cases import test_collection_cycle_handoff_workflow as native


class CompletionLaneDispatchDirectTests(unittest.TestCase):
    def test_manifest_registers_dispatch_direct_and_real_collector_workflow(self):
        registry = json.loads((Path(__file__).resolve().parent/'script_test_manifest.json').read_text())
        test = 'test_cases.test_req7_completion_lane_dispatch'
        self.assertEqual(['issue-tracker-local'],
            [suite['id'] for suite in registry['test_suites'] if test in suite['tests']])
        self.assertTrue(any('monitor/switch-collection-worker.py' in rule['paths']
            and test in rule['tests'] for rule in registry['test_rules']))
        required = {'monitor/switch-collection-worker.py', 'monitor/collection_v2_emitter.py',
            'monitor/switch_collection_gate.py', 'ethernet/monitor/cron.sh',
            'infiniband/monitor/cron.sh', 'nvlink/monitor/cron.sh'}
        self.assertTrue(any(required <= set(item['members']) and test in item['tests']
            for item in registry['workflows']))

    def api(self):
        api = getattr(persistence.WORKER, '_publish_issue_tracker_lanes_after_completion', None)
        self.assertTrue(callable(api), 'durable completion needs independent tracker lane boundaries')
        return api

    def test_ordinary_status_failure_does_not_skip_local_lane(self):
        api = self.api(); store = object(); calls = []
        def status(actual):
            calls.append(('status', actual)); raise ValueError('owned synthetic failure')
        def local(actual): calls.append(('local', actual))
        with mock.patch.object(persistence.WORKER, '_publish_stage_l_status_after_completion', side_effect=status), \
                mock.patch.object(persistence.WORKER, '_publish_stage_l_local_after_completion', side_effect=local), \
                mock.patch.object(persistence.WORKER.sys, 'stderr', io.StringIO()):
            self.assertIsNone(api(store))
        self.assertEqual([('status', store), ('local', store)], calls)

    def test_local_ordinary_failure_does_not_escape_or_echo_exception(self):
        api = self.api(); stream = io.StringIO()
        with mock.patch.object(persistence.WORKER, '_publish_stage_l_status_after_completion') as status, \
                mock.patch.object(persistence.WORKER, '_publish_stage_l_local_after_completion',
                    side_effect=ValueError('synthetic-private-detail')) as local, \
                mock.patch.object(persistence.WORKER.sys, 'stderr', stream):
            self.assertIsNone(api(object()))
        status.assert_called_once(); local.assert_called_once()
        self.assertNotIn('synthetic-private-detail', stream.getvalue())

    def test_operator_interrupt_is_not_an_ordinary_lane_failure(self):
        api = self.api()
        for failure in (KeyboardInterrupt, SystemExit):
            with self.subTest(failure=failure.__name__), \
                    mock.patch.object(persistence.WORKER, '_publish_stage_l_status_after_completion', side_effect=failure), \
                    mock.patch.object(persistence.WORKER, '_publish_stage_l_local_after_completion') as local:
                with self.assertRaises(failure): api(object())
                local.assert_not_called()


class CompletionLaneDispatchWorkflowTests(unittest.TestCase):
    make_layout = native.CollectionCycleHandoffWorkflowTests.make_layout
    run_workflow = native.CollectionCycleHandoffWorkflowTests.run_workflow

    def exercise(self, fault=None):
        marker = 'original_interruptible = worker["run_interruptible"]'
        self.assertEqual(1, native.BOOTSTRAP.count(marker))
        observe = '''tracker_facts = []
tracker_fault = FAULT_LITERAL
def observe_tracker_lane(phase):
    def observe(store):
        paths = sorted(Path(store.records_dir).glob("*.json"))
        raw = {path.name: path.read_bytes() for path in paths}
        completed = [json.loads(data) for name,data in raw.items() if name.endswith(".completion.json")]
        tracker_facts.append({"phase": phase, "names": list(raw),
            "sha256": {name: hashlib.sha256(data).hexdigest() for name,data in raw.items()},
            "cycle_ids": [value["identity"]["cycle_id"] for value in completed],
            "outcomes": [value["outcome"] for value in completed]})
        if phase == "status" and tracker_fault == "status-oserror": raise OSError("owned status fault")
        if phase == "status" and tracker_fault == "status-valueerror": raise ValueError("owned status fault")
        if phase == "local" and tracker_fault == "local-valueerror": raise ValueError("owned local fault")
        return None
    return observe
worker["run_collection_cycle_coordinator"].__globals__["_publish_stage_l_status_after_completion"] = observe_tracker_lane("status")
worker["run_collection_cycle_coordinator"].__globals__["_publish_stage_l_local_after_completion"] = observe_tracker_lane("local")
'''.replace('FAULT_LITERAL', repr(fault))
        result_field = '"persisted": persisted if action in ("persisted", "sigkill") else None,'
        self.assertEqual(1, native.BOOTSTRAP.count(result_field))
        bootstrap = native.BOOTSTRAP.replace(marker, observe + marker).replace(result_field,
            result_field + '\n        "tracker_facts": tracker_facts,')
        with tempfile.TemporaryDirectory(prefix='req7-completion-lanes-') as directory, \
                mock.patch.object(native, 'BOOTSTRAP', bootstrap):
            root = self.make_layout(directory)
            completed, payload, traces = self.run_workflow(root, 'prod', action='persisted')
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIsNotNone(payload, completed.stdout)
            self.assertTrue(payload['returned'], payload)
            records = payload['persisted']['records']
            completion = records['00000000000000000001.completion.json']
            self.assertEqual(payload['result'], completion['run_result'])
            self.assertEqual('cycle_completed', completion['outcome'])
            expected_names = ['00000000000000000001.completion.json',
                '00000000000000000001.launch.json', '00000000000000000001.start.json']
            self.assertEqual(['status', 'local'], [fact['phase'] for fact in payload['tracker_facts']])
            for fact in payload['tracker_facts']:
                self.assertEqual(expected_names, fact['names'])
                self.assertEqual([completion['identity']['cycle_id']], fact['cycle_ids'])
                self.assertEqual(['cycle_completed'], fact['outcomes'])
                actual = root/'monitor/status/collection-cycles'/completion['identity']['project_key']/'prod/switch_collection/records'
                self.assertEqual({name: hashlib.sha256((actual/name).read_bytes()).hexdigest()
                    for name in expected_names}, fact['sha256'])
            self.assertEqual(3, len(traces))
            self.assertEqual(['accepted']*3, [item['outcome'] for item in payload['result']['outcomes']])

    def test_real_coordinator_status_oserror_cannot_skip_local_after_durable_completion(self):
        self.exercise('status-oserror')

    def test_real_coordinator_status_valueerror_cannot_relabel_completion(self):
        self.exercise('status-valueerror')

    def test_real_coordinator_local_valueerror_cannot_relabel_completion(self):
        self.exercise('local-valueerror')

    def test_real_coordinator_local_not_due_none_keeps_completion_and_lane_order(self):
        self.exercise()
