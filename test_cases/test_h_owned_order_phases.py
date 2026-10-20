"""Independent phase/callsite checks; AST only, never execute writer bodies."""
import ast
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


PRELUDE = '''
import os
def stop_native_ztp_monitors(root):
    return None
class Transaction:
    def __enter__(self):
        return self
    def __exit__(self, kind, error, traceback):
        self.commit()
    def commit(self):
        os.unlink('01-global.yaml')
'''


class OwnedOrderPhaseTests(unittest.TestCase):
    def check(self, source):
        SUBJECT.assert_quiesce_structurally_precedes_reachable_sink(
            self, ast.parse(source), 'main', {'commit'},
        )

    def test_exit_write_before_later_stop_is_rejected(self):
        with self.assertRaises(AssertionError):
            self.check(PRELUDE + '''
def main():
    with Transaction() as transaction:
        pass
    stop_native_ztp_monitors('.')
''')

    def test_exit_write_after_stop_in_body_is_allowed(self):
        self.check(PRELUDE + '''
def main():
    with Transaction() as transaction:
        stop_native_ztp_monitors('.')
''')

    def test_unused_nested_stop_cannot_authorize_later_write(self):
        with self.assertRaises(AssertionError):
            self.check(PRELUDE + '''
def main():
    def never_called():
        stop_native_ztp_monitors('.')
    with Transaction() as transaction:
        pass
''')

    def test_foreign_stop_cannot_borrow_module_stop_identity(self):
        with self.assertRaises(AssertionError):
            self.check(PRELUDE + '''
class Display:
    def stop_native_ztp_monitors(self, root):
        return None
def main():
    display = Display()
    display.stop_native_ztp_monitors('.')
    with Transaction() as transaction:
        pass
''')

    def test_return_exit_cannot_borrow_unreachable_later_stop(self):
        with self.assertRaises(AssertionError):
            self.check(PRELUDE + '''
def main():
    with Transaction() as transaction:
        return
        stop_native_ztp_monitors('.')
''')

    def test_enter_write_cannot_borrow_stop_in_body(self):
        entering = PRELUDE.replace('        return self', '        self.commit()\n        return self')
        with self.assertRaises(AssertionError):
            self.check(entering + '''
def main():
    with Transaction() as transaction:
        stop_native_ztp_monitors('.')
''')
