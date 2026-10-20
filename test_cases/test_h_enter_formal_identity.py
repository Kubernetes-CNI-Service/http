"""Original __enter__ parameter identity, AST DATA only; SOURCE NOT RUN."""
import ast
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


class EnterFormalIdentityTests(unittest.TestCase):
    def test_rebinding_enter_formal_cannot_borrow_the_original_manager_receiver(self):
        for label, replacement in (('none-result', 'None'), ('other-owner-result', 'Other()')):
            source = '''
class Other:
    def commit(self):
        return None
class Transaction:
    def __enter__(self):
        self = REPLACEMENT
        return self
    def __exit__(self, kind, error, traceback):
        pass
    def commit(self):
        return None
def main():
    with Transaction() as result:
        result.commit()
'''.replace('REPLACEMENT', replacement)
            with self.subTest(case=label):
                tree = ast.parse(source)
                transaction = next(node for node in tree.body
                    if isinstance(node, ast.ClassDef) and node.name == 'Transaction')
                other = next(node for node in tree.body
                    if isinstance(node, ast.ClassDef) and node.name == 'Other')
                original_commit = next(node for node in transaction.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'commit')
                other_commit = next(node for node in other.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'commit')
                original_enter = next(node for node in transaction.body
                    if isinstance(node, ast.FunctionDef) and node.name == '__enter__')
                original_exit = next(node for node in transaction.body
                    if isinstance(node, ast.FunctionDef) and node.name == '__exit__')
                try:
                    graph = SUBJECT.local_call_graph(tree)
                except AssertionError as error:
                    self.assertTrue(str(error).startswith('WDISC_UNRESOLVED'),
                        'generic assertion cannot qualify as source-identity refusal: ' + str(error))
                    continue
                self.assertIn('main', graph)
                labels = {}
                for role, definition in (('original', original_commit), ('other', other_commit),
                                         ('enter', original_enter), ('exit', original_exit)):
                    matches = [name for name, node in graph.definitions.items() if node is definition]
                    self.assertEqual(1, len(matches), 'preserve the exact owned definition, not a basename')
                    labels[role] = matches[0]
                reached = {'main'}
                pending = ['main']
                while pending:
                    for target in graph.get(pending.pop(), ()):
                        if target not in reached:
                            reached.add(target)
                            pending.append(target)
                # __exit__ stays on the manager, NOT on the with-as result.
                self.assertIn(labels['enter'], reached)
                self.assertIn(labels['exit'], reached)
                self.assertNotIn(labels['original'], reached,
                    'REBOUND_ENTER_FORMAL_BORROWED_ORIGINAL_MANAGER_METHOD')
                if label == 'other-owner-result':
                    # A resolver that elects not to HOLD must prove the actual
                    # returned owner's target, not silently drop this edge.
                    self.assertIn(labels['other'], reached,
                        'exactly resolve the Other method or explicitly refuse')
