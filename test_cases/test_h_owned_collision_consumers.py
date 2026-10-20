"""Original sink identity survives discovery into ordering consumers."""
import ast
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT

SOURCE = '''
import os
def stop_native_ztp_monitors(root):
    pass
class Writer:
    def commit(self):
        os.unlink('01-global.yaml')
class Display:
    def commit(self):
        pass
def main():
    writer = Writer()
    writer.commit()
    stop_native_ztp_monitors('.')
'''

class OwnedCollisionConsumerTests(unittest.TestCase):
    def test_correct_writer_collision_preserves_qualified_original_sink(self):
        tree = ast.parse(SOURCE)
        # Existing owner-label grammar includes the enclosing module scope.
        self.assertEqual({'<module>.Writer.commit@6', 'main'},
                         SUBJECT.literal_governed_mutation_sinks(tree))

    def test_discovered_collision_sink_before_stop_is_rejected(self):
        tree = ast.parse(SOURCE)
        sinks = SUBJECT.literal_governed_mutation_sinks(tree)
        with self.assertRaises(AssertionError):
            SUBJECT.assert_quiesce_structurally_precedes_reachable_sink(
                self, tree, 'main', sinks)

    def test_discovered_collision_sink_after_stop_remains_supported(self):
        tree = ast.parse(SOURCE.replace("    writer.commit()\n    stop_native_ztp_monitors('.')",
                                        "    stop_native_ztp_monitors('.')\n    writer.commit()"))
        SUBJECT.assert_quiesce_structurally_precedes_reachable_sink(
            self, tree, 'main', SUBJECT.literal_governed_mutation_sinks(tree))
