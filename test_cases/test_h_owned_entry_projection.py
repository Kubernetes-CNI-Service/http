"""A supported module entry must bind actual owned mutations by identity."""
import ast
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT

class OwnedEntryProjectionTests(unittest.TestCase):
    def test_original_bound_writer_adds_its_actual_module_entry(self):
        tree=ast.parse('''
import os
class Writer:
    def commit(self):
        os.unlink('01-global.yaml')
def main():
    tx=Writer()
    tx.commit()
''')
        self.assertEqual({'commit','main'},SUBJECT.literal_governed_mutation_sinks(tree))

    def test_unrelated_same_named_method_cannot_supply_entry_coverage(self):
        tree=ast.parse('''
import os
class Writer:
    def commit(self):
        os.unlink('01-global.yaml')
class Display:
    def commit(self):
        return None
def main():
    display=Display()
    display.commit()
''')
        self.assertEqual({'<module>.Writer.commit@4'},SUBJECT.literal_governed_mutation_sinks(tree))
