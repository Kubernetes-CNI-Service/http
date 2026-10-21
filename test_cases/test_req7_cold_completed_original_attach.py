"""One whole test-side cold attach qualification SOURCE, NOT RUN."""
import json
import unittest
from test_cases import cold_completed_original_attach_fixture as f


class ColdCompletedOriginalAttachTests(unittest.TestCase):
    def test_actual_parent_c6_cold_no_send_then_same_byte_and_missing_graph_refuse_before_borrow(self):
        for fault in ('same-byte-inode', 'missing-role'):
            with self.subTest(fault=fault):
                facts = f.run_case(self, fault)
                healthy_status, healthy, healthy_raw = facts['healthy']
                negative_status, negative, negative_raw = facts['negative']
                # Outside ALL original owners/facades/finalizers. Preserve raw
                # sanitized child facts before any final assertion can fail.
                print(healthy_raw.decode('ascii'), end='', flush=True)
                print(negative_raw.decode('ascii'), end='', flush=True)
                print('COLD_ATTACH_PARENT_FACTS=' + json.dumps({key: value for key, value in facts.items()
                    if key not in ('healthy', 'negative')}, sort_keys=True), flush=True)
                self.assertTrue(facts['parent_closed'])
                self.assertEqual(('mark_success_return', 'exit_call', 'exit_return'), facts['parent_events'])
                self.assertEqual(0, healthy_status, 'COLD_SOURCE_CARRIER_HEALTH_NOT_REACHED')
                self.assertEqual('NO_SEND_ATTACHED', healthy['state'])
                self.assertTrue(healthy['profile_armed'])
                self.assertTrue(healthy['profile_restored'])
                self.assertEqual(1, healthy['a_calls'])
                self.assertGreater(healthy['borrow_calls'], 0)
                self.assertTrue(healthy['c5_returns'])
                self.assertTrue(all(healthy['c5_returns']))
                self.assertTrue(healthy['reader_current_child'])
                self.assertTrue(healthy['native_current_child'])
                self.assertEqual('NO_SEND', healthy['outcome'])
                self.assertEqual('synthetic_spreadsheet_id_0001', healthy['target'])
                self.assertEqual(sorted([
                    ['eth_cabling', 'leaf-a', 'swp1', 'Mis-wiring'],
                    ['ib_cabling', 'leaf01', 'sw1p1', 'Mis-wiring'],
                    ['switch', 'leaf-a', 'fan', 'PSU1/FAN1'],
                    ['switch', 'nvsw01', 'asic_temp', 'ASIC1'],
                ]), healthy['keys'])
                for field in ('source_live', 'all_pins_live', 'all_pins_closed',
                              'source_revoked', 'lease_closed', 'graph_unchanged'):
                    self.assertTrue(healthy[field], field)
                self.assertEqual((0, 0), (healthy['network'], healthy['children']))
                self.assertTrue(facts['after_health'])
                self.assertTrue(facts['same_bytes_new_inode'] if fault == 'same-byte-inode'
                                else facts['really_missing'])
                self.assertEqual(3, negative_status)
                self.assertEqual('GRAPH_REFUSED_BEFORE_BORROW', negative['state'])
                self.assertTrue(negative['profile_armed'])
                self.assertTrue(negative['profile_restored'])
                self.assertEqual((0, 0, []), (negative['a_calls'], negative['borrow_calls'], negative['c5_returns']))
                self.assertEqual((0, 0), (negative['network'], negative['children']))
                self.assertTrue(facts['after_negative'])
                self.assertTrue(facts['original_preserved'])
                self.assertTrue(facts['local_unchanged'])
                self.assertEqual((0, 0), facts['old_parent_network_children'])
                self.assertEqual(2, facts['actual_cold_child_count'])
