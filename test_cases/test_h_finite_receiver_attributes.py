"""Finite literal DATA fields are not method namespace writes, AST-only."""
import ast
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT

class FiniteReceiverAttributeTests(unittest.TestCase):
    def source(self, fields):
        return '''
class Transaction:
    def commit(self):
        return None
    def close(self):
        for attribute in FIELDS:
            value = getattr(self, attribute)
            if value is not None:
                setattr(self, attribute, None)
def main():
    tx = Transaction()
    tx.close()
    tx.commit()
'''.replace('FIELDS', fields)

    def test_literal_data_only_fields_preserve_original_method(self):
        tree=ast.parse(self.source("('_parent_fd', '_target_fd')"))
        graph=SUBJECT.local_call_graph(tree)
        original=tree.body[0].body[0]
        labels=[key for key,node in graph.definitions.items() if node is original]
        self.assertEqual(1,len(labels))
        self.assertIn(labels[0],graph['main'])

    def test_finite_method_or_special_namespace_member_still_refuses(self):
        for fields in ("('_parent_fd', 'commit')", "('_target_fd', '__dict__')"):
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(AssertionError,'^WDISC_UNRESOLVED'):
                    SUBJECT.local_call_graph(ast.parse(self.source(fields)))
