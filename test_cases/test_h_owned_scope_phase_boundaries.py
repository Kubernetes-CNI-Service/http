"""Unused scope and exception-exit facts; no production execution."""
import ast
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT

PRELUDE = '''
def stop_native_ztp_monitors(root):
    return None
class Transaction:
    def __enter__(self):
        return self
    def __exit__(self, kind, error, traceback):
        self.commit()
    def commit(self):
        return None
'''

class OwnedScopePhaseBoundaryTests(unittest.TestCase):
    def check(self, main):
        SUBJECT.assert_quiesce_structurally_precedes_reachable_sink(
            self, ast.parse(PRELUDE+main), 'main', {'commit'},
        )

    def test_unused_lambda_stop_does_not_authorize_context_exit_write(self):
        with self.assertRaises(AssertionError):
            self.check('''
def main():
    unused = lambda: stop_native_ztp_monitors('.')
    with Transaction():
        pass
''')

    def test_exception_exit_cannot_borrow_unreachable_later_stop(self):
        with self.assertRaises(AssertionError):
            self.check('''
def main():
    with Transaction():
        raise RuntimeError('injected')
        stop_native_ztp_monitors('.')
''')
