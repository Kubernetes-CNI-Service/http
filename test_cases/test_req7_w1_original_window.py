"""Independent local W1 original-content workflow, tests-first SOURCE NOT RUN."""
import hashlib
import json
import unittest
from test_cases import w1_original_window_fixture as f


class W1OriginalWindowTests(unittest.TestCase):
    def test_actual_cold_w1_semantics_keep_the_previously_held_template(self):
        facts=f.run_workflow(self)
        print('W1_ORIGINAL_WINDOW='+json.dumps(facts,sort_keys=True),flush=True)
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
            self.assertEqual([],value['rules'])
            self.assertEqual('5b5d0a',value['canonical_hex'])
            self.assertEqual(hashlib.sha256(b'[]\n').hexdigest(),value['whitelist_sha256'])
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
        self.assertEqual(0,facts['foreign_open_count'],'W1_CONTENT_REOPENED_AFTER_ACTUAL_PIN')
        self.assertEqual(0,facts['foreign_read_count'])
        self.assertTrue(facts['healthy_same_fd_semantics'],'HEALTHY_W1_MUST_PARSE_ACTUAL_HELD_FD')
        self.assertTrue(facts['profile_restored'])
        self.assertEqual((0,0),(facts['network'],facts['nested_children']))
