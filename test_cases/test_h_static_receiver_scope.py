"""A static helper's first parameter is not a bound instance, AST-only."""
import ast
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT

class StaticReceiverScopeTests(unittest.TestCase):
    def test_static_fd_parameter_cannot_be_misclassified_as_instance(self):
        tree=ast.parse('''
import os
class Transaction:
    @staticmethod
    def write_fd(descriptor, data):
        os.write(descriptor, data)
    def commit(self):
        self.write_fd(17, b'data')
def main():
    tx=Transaction()
    tx.commit()
''')
        graph=SUBJECT.local_call_graph(tree)
        self.assertIn('commit',graph['main'])
        self.assertIs(tree.body[1].body[1],graph.definitions['commit'])

    def test_plain_method_receiver_still_refuses_unknown_escape(self):
        tree=ast.parse('''
class Transaction:
    def unsafe(self):
        unknown(self)
    def commit(self):
        return None
def main():
    tx=Transaction()
    tx.unsafe()
    tx.commit()
''')
        with self.assertRaisesRegex(AssertionError,'^WDISC_UNRESOLVED'):
            SUBJECT.local_call_graph(tree)
