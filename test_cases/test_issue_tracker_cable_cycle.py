"""Cycle ordering and sanitized failures; backend calls are observations only."""
import importlib
from pathlib import Path
import unittest

from monitor.issue_tracker_source_model import TrackerChanges
from test_cases import test_issue_tracker_cable_merge as cases


class CableCycleTests(unittest.TestCase):
    def module(self):
        cases.load(self)
        self.assertTrue((Path(__file__).resolve().parents[1]/'monitor/issue_tracker_cable_cycle.py').is_file())
        return importlib.import_module('monitor.issue_tracker_cable_cycle')

    def test_unusable_current_snapshot_stops_before_writes_without_exception_text(self):
        cycle=self.module()
        events=[]
        class Wire:
            def read_current(self):events.append('read');return ()
            def write_business(self,body):events.append('write')
            def append_history(self,rows):events.append('history')
        result=cycle.sync_current_once(TrackerChanges((cases.cabling(),),()),Wire())
        self.assertEqual((result.state,result.phase,result.business_effect),
                         ('FAILED','merge','NOT_ATTEMPTED'))
        self.assertEqual(events,['read'])
        self.assertFalse(hasattr(result,'permit'))

    def test_each_call_has_exactly_one_current_read_then_business_then_history(self):
        cycle=self.module();merge=cases.load(self)
        events=[]
        class Wire:
            def read_current(self):events.append('read');return cases.book(merge)
            def write_business(self,body):events.append('write')
            def append_history(self,rows):events.append('history')
        result=cycle.sync_current_once(TrackerChanges((cases.cabling(),),()),Wire())
        self.assertEqual((result.state,result.phase,result.business_effect),
                         ('API_RETURNED','complete','API_RETURNED'))
        self.assertEqual(events,['read','write','history'])


if __name__=='__main__':unittest.main()
