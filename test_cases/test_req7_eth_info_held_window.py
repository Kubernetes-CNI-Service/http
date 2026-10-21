"""One independent ETH info held-original window workflow SOURCE; NOT RUN."""
import json
import unittest
from test_cases import eth_info_held_window_fixture as f


class EthInfoHeldWindowTests(unittest.TestCase):
    def test_actual_cold_eth_consumer_never_reads_replacement_after_original_pin(self):
        facts = f.run_workflow(self)
        print('ETH_INFO_HELD_WINDOW=' + json.dumps(facts, sort_keys=True), flush=True)
        self.assertNotIn('carrier_error_type', facts)
        self.assertEqual([], facts['observer_errors'])
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
        self.assertTrue(facts['audit_armed'])
        self.assertEqual(1, facts['arm_count'])
        self.assertTrue(facts['actual_pin_live'])
        self.assertTrue(facts['same_bytes_new_inode'])
        self.assertTrue(facts['restored_original'])
        self.assertEqual('CableSourceHold', facts['window_error_type'])
        self.assertEqual(0, facts['foreign_open_count'],
                         'ETH_INFO_CONSUMER_REOPENS_AFTER_ACTUAL_ORIGINAL_PIN')
        self.assertEqual(0, facts['foreign_read_count'])
        self.assertTrue(facts['fault_originals_closed'])
        self.assertTrue(facts['fault_slots_closed'])
        self.assertGreater(facts['fault_slot_count'], 0)
        self.assertTrue(facts['fault_local_token_revoked'])
        self.assertTrue(facts['healthy_pin_consumption_witness'],
                        'HEALTHY_ETH_SEMANTIC_READ_MUST_USE_ACTUAL_HELD_FD')
        self.assertTrue(facts['profile_restored'])
        self.assertEqual((0, 0), (facts['network'], facts['nested_children']))
        self.assertTrue(facts['local_unchanged'])
