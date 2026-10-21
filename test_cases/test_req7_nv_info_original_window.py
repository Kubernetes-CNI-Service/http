"""Independent NV original archive window: SOURCE ONLY / NOT RUN."""
import json
import unittest
from test_cases import nv_info_original_window_fixture as f


class NvInfoOriginalWindowTests(unittest.TestCase):
    def test_actual_cold_nv_semantics_never_read_replacement_after_original_pin(self):
        facts = f.run_workflow(self)
        print('NV_INFO_ORIGINAL_WINDOW=' + json.dumps(facts, sort_keys=True), flush=True)
        self.assertNotIn('carrier_error_type', facts)
        self.assertEqual([], facts['observer_errors'])
        self.assertTrue(facts['parent_closed'])
        self.assertEqual(['mark_success_return', 'exit_call', 'exit_return'],
                         facts['parent_events'])
        self.assertTrue(facts['healthy_complete'])
        self.assertEqual('NO_SEND', facts['healthy_outcome'])
        self.assertEqual('synthetic_spreadsheet_id_0001', facts['healthy_target'])
        self.assertEqual(sorted([
            ['eth_cabling', 'leaf-a', 'swp1', 'Mis-wiring'],
            ['ib_cabling', 'leaf01', 'sw1p1', 'Mis-wiring'],
            ['switch', 'leaf-a', 'fan', 'PSU1/FAN1'],
            ['switch', 'nvsw01', 'asic_temp', 'ASIC1'],
        ]), facts['healthy_keys'])
        self.assertTrue(facts['healthy_graph_unchanged'])
        self.assertGreater(len(facts['healthy_nv_semantics']), 0)
        for value in facts['healthy_nv_semantics']:
            self.assertEqual('nvlink/prod', value['source_slot'])
            self.assertEqual(['nvsw01'], value['selected_hosts'])
            self.assertEqual([['nvsw01', 'asic_temp', 'ASIC1']], value['abnormal_keys'])
            self.assertEqual([['nvsw01', ['fan', 'psu']]], value['not_applicable'])
            self.assertTrue(value['raw_matches_actual_pin'])
        self.assertTrue(facts['healthy_slots_closed'])
        self.assertTrue(facts['healthy_local_revoked'])
        self.assertTrue(facts['audit_armed'])
        self.assertEqual(1, facts['arm_count'])
        self.assertIn(facts['arm_route'], ('actual_nv_guard_return', 'actual_original_raw_call'))
        self.assertTrue(facts['actual_pin_live'])
        self.assertTrue(facts['same_bytes_new_inode'])
        self.assertTrue(facts['same_mode'])
        self.assertTrue(facts['restored_original'])
        self.assertEqual('CableSourceHold', facts['window_error_type'])
        self.assertEqual(0, facts['foreign_open_count'],
                         'NV_CONTENT_REOPENED_AFTER_ACTUAL_GUARD_AND_PIN')
        self.assertEqual(0, facts['foreign_read_count'])
        self.assertTrue(facts['fault_originals_closed'])
        self.assertTrue(facts['fault_slots_closed'])
        self.assertGreater(facts['fault_slot_count'], 0)
        self.assertTrue(facts['fault_local_token_revoked'])
        self.assertTrue(facts['healthy_pin_consumption_witness'],
                        'HEALTHY_NV_SEMANTIC_READ_MUST_USE_ACTUAL_HELD_FD')
        self.assertTrue(facts['lease_closed'])
        self.assertTrue(facts['profile_restored'])
        self.assertEqual((0, 0), (facts['network'], facts['nested_children']))
        self.assertTrue(facts['local_unchanged'])
