"""Special receiver namespaces: independent literal AST DATA, SOURCE NOT RUN."""
import ast
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


class SpecialReceiverNamespaceTests(unittest.TestCase):
    def test_normal_instance_data_field_preserves_original_method(self):
        tree = ast.parse('''
class Transaction:
    def commit(self):
        return None
def main():
    tx = Transaction()
    tx.ready = True
    tx.commit()
''')
        original = tree.body[0].body[0]
        graph = SUBJECT.local_call_graph(tree)
        self.assertIn('main', graph)
        labels = [label for label, node in graph.definitions.items() if node is original]
        self.assertEqual(1, len(labels))
        self.assertIn(labels[0], self._reachable(graph))

    def test_special_namespace_replacement_cannot_borrow_original_method(self):
        for label, replacement, actual_role in (
            ('instance-class', 'tx.__class__ = Other', 'other'),
            ('instance-dictionary', "tx.__dict__ = {'commit': innocent}", 'innocent'),
        ):
            source = '''
class Other:
    def commit(self):
        return None
class Transaction:
    def commit(self):
        return None
def innocent():
    return None
def main():
    tx = Transaction()
    REPLACEMENT
    tx.commit()
'''.replace('REPLACEMENT', replacement)
            with self.subTest(case=label):
                tree = ast.parse(source)
                definitions = {
                    'other': tree.body[0].body[0],
                    'original': tree.body[1].body[0],
                    'innocent': tree.body[2],
                }
                try:
                    graph = SUBJECT.local_call_graph(tree)
                except AssertionError as error:
                    self.assertTrue(str(error).startswith('WDISC_UNRESOLVED'),
                        'generic failure is not a dispatch-identity refusal: ' + str(error))
                    continue
                self.assertIn('main', graph)
                labels = {}
                for role, definition in definitions.items():
                    matches = [name for name, node in graph.definitions.items()
                               if node is definition]
                    self.assertEqual(1, len(matches),
                        'keep exact original source definitions, not matching basenames')
                    labels[role] = matches[0]
                reached = self._reachable(graph)
                self.assertNotIn(labels['original'], reached,
                    'SPECIAL_NAMESPACE_BORROWED_ORIGINAL_DISPATCH')
                # Resolving the replacement is optional; silently dropping its
                # actual edge instead of explicitly refusing is not acceptable.
                self.assertIn(labels[actual_role], reached,
                    'prove the actual replacement target or refuse as WDISC_UNRESOLVED')

    @staticmethod
    def _reachable(graph):
        reached = {'main'}
        pending = ['main']
        while pending:
            for target in graph.get(pending.pop(), ()):
                if target not in reached:
                    reached.add(target)
                    pending.append(target)
        return reached
