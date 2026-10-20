"""Aliased builtin receives a whole receiver: literal AST DATA, SOURCE NOT RUN."""
import ast
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


class AliasedReceiverEscapeTests(unittest.TestCase):
    def test_known_local_helper_data_write_preserves_original_dispatch(self):
        tree = ast.parse('''
class Transaction:
    def commit(self):
        return None
def set_ready(instance):
    instance.ready = True
def main():
    tx = Transaction()
    set_ready(tx)
    tx.commit()
''')
        graph = SUBJECT.local_call_graph(tree)
        self.assertIn('main', graph)
        reached = self._reachable(graph)
        for definition in (tree.body[0].body[0], tree.body[1]):
            labels = [name for name, node in graph.definitions.items() if node is definition]
            self.assertEqual(1, len(labels), 'preserve the exact original definition')
            self.assertIn(labels[0], reached)

    def test_setattr_name_alias_cannot_borrow_original_instance_method(self):
        tree = ast.parse('''
class Transaction:
    def commit(self):
        return None
def innocent():
    return None
def main():
    write = setattr
    tx = Transaction()
    write(tx, 'commit', innocent)
    tx.commit()
''')
        original = tree.body[0].body[0]
        actual = tree.body[1]
        try:
            graph = SUBJECT.local_call_graph(tree)
        except AssertionError as error:
            self.assertTrue(str(error).startswith('WDISC_UNRESOLVED'),
                'generic failure cannot stand in for a source-identity refusal: ' + str(error))
            return
        self.assertIn('main', graph)
        labels = {}
        for role, definition in (('original', original), ('actual', actual)):
            matches = [name for name, node in graph.definitions.items() if node is definition]
            self.assertEqual(1, len(matches), 'no empty graph or basename substitution')
            labels[role] = matches[0]
        reached = self._reachable(graph)
        self.assertNotIn(labels['original'], reached,
            'ALIASED_SETATTR_BORROWED_ORIGINAL_INSTANCE_METHOD')
        self.assertIn(labels['actual'], reached,
            'resolve the literal replacement callable or explicitly refuse')

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
