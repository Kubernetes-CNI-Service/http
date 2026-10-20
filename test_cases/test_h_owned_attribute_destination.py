"""Literal expectations: class fields must retain their original lexical owner.

Only AST analysis: none of these writer bodies are executed.
"""
import ast
from pathlib import Path
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


class OwnedAttributeDestinationTests(unittest.TestCase):
    def scan(self, source):
        return SUBJECT.literal_governed_mutation_sinks(ast.parse(source))

    def test_same_owner_attribute_reaches_real_replace(self):
        self.assertEqual({'commit'}, self.scan('''
import os
class Transaction:
    def bind(self):
        target = '01-global.yaml'
        self.target = target
    def commit(self):
        os.replace('candidate', self.target)
'''))

    def test_same_basename_other_owner_and_other_field_do_not_inherit(self):
        self.assertEqual(set(), self.scan('''
import os
class Transaction:
    def bind(self):
        self.target = '01-global.yaml'
    def commit(self):
        self.output = 'scratch.txt'
        os.replace('candidate', self.output)
class Display:
    def commit(self):
        self.target = 'scratch.txt'
        os.replace('candidate', self.target)
'''))

    def test_transitive_same_owner_fields_are_order_independent(self):
        self.assertEqual({'commit'}, self.scan('''
import os
class Transaction:
    def commit(self):
        target = self.final.name
        os.replace('candidate', target)
    def derive(self):
        self.final = self.original
    def bind(self):
        self.original = '01-global.yaml'
'''))

    def test_actual_feedback_commit_destination_not_only_old_open_summary(self):
        source = (Path(SUBJECT.ROOT)/'ztp/optimize/feedback.py').read_text()
        self.assertIn('commit', self.scan(source))
        spelling = 'temporary_name, self.target_path.name,'
        self.assertEqual(1, source.count(spelling))
        changed = source.replace(spelling, "temporary_name, 'scratch.txt',")
        self.assertNotIn('commit', self.scan(changed))


if __name__ == '__main__':
    unittest.main()
