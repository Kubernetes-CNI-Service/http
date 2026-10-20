"""Original-node index is independent of module-only name projection."""
import ast
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT

class OwnedGraphDefinitionIndexTests(unittest.TestCase):
    def test_invoked_nested_definition_is_original_not_module_function(self):
        tree=ast.parse('''
def main():
    def extract():
        return None
    extract()
''')
        nested=tree.body[0].body[0]
        graph=SUBJECT.local_call_graph(tree)
        self.assertNotIn('extract',SUBJECT.production_functions(tree))
        self.assertIn('extract',graph['main'])
        self.assertIs(nested,graph.definitions['extract'])
