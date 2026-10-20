"""Independent owner-preserving call-graph expectations, AST only."""
import ast
from pathlib import Path
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


def forward(graph, root):
    reached = {root}
    pending = [root]
    while pending:
        for target in graph.get(pending.pop(), set()):
            if target not in reached:
                reached.add(target)
                pending.append(target)
    return reached


class OwnedCallGraphTests(unittest.TestCase):
    def test_context_manager_entry_and_exit_reach_original_methods(self):
        tree = ast.parse('''
class Transaction:
    def __enter__(self):
        self.snapshot()
        return self
    def snapshot(self):
        return None
    def __exit__(self, kind, error, traceback):
        self.commit()
    def commit(self):
        return None
def main():
    with Transaction() as transaction:
        pass
''')
        reached = forward(SUBJECT.local_call_graph(tree), 'main')
        self.assertIn('snapshot', reached)
        self.assertIn('commit', reached)

    def test_unrelated_bound_method_cannot_borrow_module_function(self):
        tree = ast.parse('''
def commit():
    return None
class Display:
    def commit(self):
        return None
def main():
    display = Display()
    display.commit()
''')
        try:
            graph = SUBJECT.local_call_graph(tree)
        except AssertionError as error:
            # The existing bare-name API may refuse an unrepresentable owner;
            # no generic exception or empty graph substitutes for this hold.
            self.assertTrue(str(error).startswith('WDISC_UNRESOLVED'), str(error))
        else:
            self.assertNotIn('commit', graph['main'])

    def test_actual_feedback_entry_reaches_real_snapshot_and_commit(self):
        tree = ast.parse((Path(SUBJECT.ROOT)/'ztp/optimize/feedback.py').read_text())
        reached = forward(SUBJECT.local_call_graph(tree), 'main')
        self.assertIn('_snapshot_authority', reached)
        self.assertIn('commit', reached)
