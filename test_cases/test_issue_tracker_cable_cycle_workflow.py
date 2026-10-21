"""Actual shared model/XLSX/merge/cycle; only the external IO is a private stub."""
import importlib
import json
from pathlib import Path
import tempfile
import unittest

from test_cases import test_issue_tracker_cable_merge as cases


class CableCycleWorkflowTests(unittest.TestCase):
    def module(self):
        cases.load(self)
        path=Path(__file__).resolve().parents[1]/'monitor/issue_tracker_cable_cycle.py'
        self.assertTrue(path.is_file(),'fresh-read cycle module required')
        return importlib.import_module('monitor.issue_tracker_cable_cycle')

    def test_write_effect_then_error_next_cycle_reads_actual_changed_online_and_preserves_local(self):
        cycle=self.module();merge=cases.load(self)
        from monitor.issue_tracker_collected_source import collected_changes
        from test_cases.test_issue_tracker_source_adapter import candidates
        from monitor.issue_tracker_local_workbook import project_cabling_workbook_image
        from test_cases.test_issue_tracker_local_workbook import fake_workbook
        from monitor.issue_tracker_online_cells import source_tool_values
        changes=collected_changes((candidates()[0],))
        current=cases.book(merge)
        values=source_tool_values(changes.cabling[0],'insert',reserved_id='NV30001')
        after=cases.book(merge,eth=((2,cases.columns(29,values)),))
        events=[]
        class Wire:
            state=current
            def read_current(self):events.append('READ');return self.state
            def write_business(self,body):
                events.append(('WRITE',json.loads(body)))
                self.state=after
                raise OSError('SECRET must not be echoed')
            def append_history(self,rows):events.append('HISTORY')
        wire=Wire()
        with tempfile.TemporaryDirectory() as directory:
            from monitor import issue_tracker_local_commit as durable
            project=Path(directory).resolve(strict=True)
            publication=project/'publication'
            publication.mkdir(mode=0o700)
            durable.create_local_commit_store(project,publication)
            image=project_cabling_workbook_image(fake_workbook(),changes.cabling)
            with durable.writer_owner(project,publication) as token:
                generation=durable.begin_generation(token,b'{"operations":[],"schema_version":1}\n')
                durable.record_intent(token,generation,image,kind='xlsx')
                receipt=durable.commit(token,generation)
            local=publication/(generation.generation_id+'.xlsx')
            self.assertEqual(local.read_bytes(),image)
            import hashlib
            self.assertEqual(receipt.published_sha256,hashlib.sha256(image).hexdigest())
            result=cycle.sync_current_once(changes,wire)
            self.assertEqual((result.state,result.phase),('FAILED','business'))
            self.assertEqual(result.business_effect,'UNKNOWN')
            self.assertNotIn('SECRET',repr(result))
            self.assertEqual(local.read_bytes(),image)
            again=cycle.sync_current_once(changes,wire)
            self.assertEqual((again.state,again.phase),('NO_CHANGE','complete'))
            self.assertEqual([event for event in events if event=='READ'],['READ','READ'])
            self.assertEqual(len([event for event in events if type(event) is tuple]),1)
            self.assertNotIn('HISTORY',events)
            self.assertEqual(local.read_bytes(),image)

    def test_read_and_history_failure_are_distinguished_no_same_cycle_retry_or_latch(self):
        cycle=self.module();merge=cases.load(self)
        from monitor.issue_tracker_source_model import TrackerChanges
        changes=TrackerChanges((cases.cabling(),),())
        class Wire:
            failure='read'
            calls=[]
            def read_current(self):
                self.calls.append('read')
                if self.failure=='read':raise RuntimeError('token')
                return cases.book(merge)
            def write_business(self,body):self.calls.append('write')
            def append_history(self,rows):
                self.calls.append('history')
                if self.failure=='history':raise OSError('token')
        wire=Wire()
        first=cycle.sync_current_once(changes,wire)
        self.assertEqual((first.state,first.phase),('FAILED','read'))
        self.assertEqual(wire.calls,['read'])
        wire.failure='history'
        second=cycle.sync_current_once(changes,wire)
        self.assertEqual((second.state,second.phase),('FAILED','history'))
        self.assertEqual(second.business_effect,'API_RETURNED')
        self.assertEqual(wire.calls,['read','read','write','history'])
        wire.failure=None
        third=cycle.sync_current_once(changes,wire)
        self.assertEqual((third.state,third.phase),('API_RETURNED','complete'))
        self.assertEqual(wire.calls,['read','read','write','history','read','write','history'])

    def test_operator_interrupt_propagates_without_retry(self):
        cycle=self.module()
        from monitor.issue_tracker_source_model import TrackerChanges
        class Wire:
            def read_current(self):raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):cycle.sync_current_once(TrackerChanges((),()),Wire())


if __name__=='__main__':unittest.main()
