"""Literal current N=1 policy original-content workflow, tests-first."""
import json
import unittest
from test_cases import n_policy_original_window_fixture as f


class NPolicyOriginalWindowTests(unittest.TestCase):
    def test_actual_cold_n_policy_semantics_keep_the_previously_held_global(self):
        facts=f.run_workflow(self)
        print('N_POLICY_ORIGINAL_WINDOW='+json.dumps(facts,sort_keys=True),flush=True)
        self.assertNotIn('carrier_error_type',facts)
        self.assertEqual([],facts['observer_errors'])
        self.assertTrue(facts['parent_closed'])
        self.assertEqual(['mark_success_return','exit_call','exit_return'],facts['parent_events'])
        self.assertTrue(facts['healthy_complete'])
        self.assertEqual('NO_SEND',facts['healthy_outcome'])
        self.assertEqual('synthetic_spreadsheet_id_0001',facts['healthy_target'])
        self.assertEqual(sorted([
            ['eth_cabling','leaf-a','swp1','Mis-wiring'],
            ['ib_cabling','leaf01','sw1p1','Mis-wiring'],
            ['switch','leaf-a','fan','PSU1/FAN1'],
            ['switch','nvsw01','asic_temp','ASIC1']]),facts['healthy_keys'])
        self.assertTrue(facts['healthy_graph_unchanged'])
        self.assertGreater(len(facts['healthy_semantics']),0)
        for value in facts['healthy_semantics']:
            self.assertEqual(1,value['publish_every_cycles'])
            self.assertTrue(value['raw_matches_actual_pin'])
        self.assertTrue(facts['healthy_slots_closed'])
        self.assertTrue(facts['healthy_local_revoked'])
        self.assertTrue(facts['audit_armed'])
        self.assertEqual(1,facts['arm_count'])
        self.assertTrue(facts['actual_a_frame'])
        self.assertTrue(facts['actual_pin_live'])
        self.assertTrue(facts['same_bytes_new_inode'])
        self.assertTrue(facts['same_mode'])
        self.assertTrue(facts['restored_original'])
        self.assertEqual('CableSourceHold',facts['window_error_type'])
        self.assertTrue(facts['fault_originals_closed'])
        self.assertTrue(facts['fault_slots_closed'])
        self.assertGreater(facts['fault_slot_count'],0)
        self.assertTrue(facts['fault_local_revoked'])
        self.assertTrue(facts['lease_closed'])
        self.assertTrue(facts['local_unchanged'])
        self.assertEqual(0,facts['foreign_open_count'],'N_POLICY_CONTENT_REOPENED_AFTER_ACTUAL_PIN')
        self.assertEqual(0,facts['foreign_read_count'])
        self.assertTrue(facts['healthy_same_fd_semantics'],'HEALTHY_N_POLICY_MUST_PARSE_ACTUAL_HELD_FD')
        self.assertTrue(facts['profile_restored'])
        self.assertEqual((0,0),(facts['network'],facts['nested_children']))
