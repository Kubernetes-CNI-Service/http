"""Two-hop lexical receiver handoff contract; literal AST DATA, SOURCE NOT RUN."""
import ast
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


class TwoHopReceiverHandoffTests(unittest.TestCase):
    def test_known_two_hop_data_only_helpers_preserve_all_original_edges(self):
        tree = ast.parse('''
class Transaction:
    def commit(self):
        return None
def set_ready(instance):
    instance.ready = True
def handoff(instance):
    set_ready(instance)
def main():
    tx = Transaction()
    handoff(tx)
    tx.commit()
''')
        graph = SUBJECT.local_call_graph(tree)
        self.assertIn('main', graph)
        labels = self._labels(graph, {
            'commit': tree.body[0].body[0],
            'set_ready': tree.body[1],
            'handoff': tree.body[2],
        })
        reached = self._reachable(graph)
        for label in labels.values():
            self.assertIn(label, reached, 'all source-bound two-hop targets must remain reachable')
        self.assertIn(labels['handoff'], graph['main'])
        self.assertIn(labels['set_ready'], graph[labels['handoff']])
        self.assertIn(labels['commit'], graph['main'])

    def test_known_helper_forwarding_receiver_to_unknown_alias_cannot_preserve_dispatch(self):
        tree = ast.parse('''
class Transaction:
    def commit(self):
        return None
def innocent():
    return None
def handoff(instance):
    route = setattr
    route(instance, 'commit', innocent)
def main():
    tx = Transaction()
    handoff(tx)
    tx.commit()
''')
        try:
            graph = SUBJECT.local_call_graph(tree)
        except AssertionError as error:
            self.assertTrue(str(error).startswith('WDISC_UNRESOLVED'),
                'generic failure is not a receiver-flow refusal: ' + str(error))
            return
        self.assertIn('main', graph)
        labels = self._labels(graph, {
            'commit': tree.body[0].body[0],
            'innocent': tree.body[1],
            'handoff': tree.body[2],
        })
        reached = self._reachable(graph)
        self.assertIn(labels['handoff'], graph['main'])
        self.assertIn(labels['handoff'], reached)
        self.assertNotIn(labels['commit'], reached,
            'TWO_HOP_UNKNOWN_RECEIVER_ESCAPE_BORROWED_ORIGINAL_METHOD')
        self.assertIn(labels['innocent'], reached,
            'prove the literal replacement target or explicitly refuse the unknown escape')

    def _labels(self, graph, definitions):
        result = {}
        for role, original in definitions.items():
            matches = [name for name, node in graph.definitions.items() if node is original]
            self.assertEqual(1, len(matches), 'preserve original AST identity, not only a basename')
            result[role] = matches[0]
        return result

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
