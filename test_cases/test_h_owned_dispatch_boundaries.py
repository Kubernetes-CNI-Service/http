"""Dispatch mutations must not borrow original definitions, AST-only."""
import ast
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


TRANSACTION = '''
class Transaction:
    def __enter__(self):
        return self
    def __exit__(self, kind, error, traceback):
        self.commit()
    def commit(self):
        return None
'''


class OwnedDispatchBoundaryTests(unittest.TestCase):
    def assert_no_borrow(self, source, label):
        try:
            graph = SUBJECT.local_call_graph(ast.parse(source))
        except AssertionError as error:
            self.assertTrue(str(error).startswith('WDISC_UNRESOLVED'), str(error))
            return
        reached = {'main'}
        pending = ['main']
        while pending:
            for target in graph.get(pending.pop(), ()):
                if target not in reached:
                    reached.add(target)
                    pending.append(target)
        self.assertNotIn(label, reached)

    def test_rebound_callback_formal_does_not_invoke_original_argument(self):
        self.assert_no_borrow('''
def writer():
    return None
def benign():
    return None
def helper(operation):
    operation = benign
    operation()
def main():
    helper(writer)
''', 'writer')

    def test_class_method_rebinding_does_not_invoke_original_method(self):
        self.assert_no_borrow(TRANSACTION + '''
def innocent(self):
    return None
Transaction.commit = innocent
def main():
    with Transaction():
        pass
''', 'commit')

    def test_metaclass_dispatch_is_not_plain_constructor_evidence(self):
        source = TRANSACTION.replace('class Transaction:', 'class Transaction(metaclass=unknown_factory):')
        self.assert_no_borrow(source + '''
def main():
    with Transaction():
        pass
''', 'commit')

    def test_foreign_enter_result_is_not_the_manager_receiver(self):
        source = TRANSACTION.replace('        return self', '        return None').replace('        self.commit()', '        pass')
        self.assert_no_borrow(source + '''
def main():
    with Transaction() as other:
        other.commit()
''', 'commit')
