"""One comprehension iter-dependency boundary; AST DATA, SOURCE NOT RUN."""
import ast
from pathlib import Path
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


PRELUDE = '''
class Transaction:
    ready = True
    def commit(self):
        return None
def handoff(payload):
    return None
'''
WHOLE = '''def main():
    tx = Transaction()
    handoff([item for item in [tx]])
    tx.commit()
'''
DATA = '''def main():
    tx = Transaction()
    handoff([item for item in [tx.ready]])
    tx.commit()
'''


class ComprehensionReceiverDependencyTests(unittest.TestCase):
    def test_literal_comprehension_iter_whole_receiver_must_refuse(self):
        tree = ast.parse(PRELUDE + WHOLE)
        with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
            SUBJECT.local_call_graph(tree)

    def test_literal_comprehension_data_field_does_not_become_whole_receiver(self):
        tree = ast.parse(PRELUDE + DATA)
        graph = SUBJECT.local_call_graph(tree)
        self.assertEqual({'commit': set(), 'handoff': set(),
                          'main': {'commit', 'handoff'}}, dict(graph))
        self.assertIs(tree.body[0].body[1], graph.definitions['commit'])
        self.assertIs(tree.body[1], graph.definitions['handoff'])
        self.assertIs(tree.body[2], graph.definitions['main'])
        original_call = tree.body[2].body[1].value
        self.assertEqual({'handoff'}, graph.call_targets[original_call])

    def test_actual_feedback_comprehension_iter_refuses_with_runtime_original_present(self):
        root = Path(SUBJECT.ROOT)
        runtime = ast.parse((root / 'tools/ztp_service_runtime.py').read_text(encoding='utf-8'))
        self.assertIn('stop_native_ztp_monitors', SUBJECT.production_functions(runtime))
        feedback = ast.parse((root / 'ztp/optimize/feedback.py').read_text(encoding='utf-8'))
        main = SUBJECT.production_functions(feedback)['main']
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == '_h_comp_item'
            for node in ast.walk(main)), 'the independent literal must not capture existing locals')
        sites = []
        for node in ast.walk(main):
            if not isinstance(node, ast.With):
                continue
            for item in node.items:
                expression = item.context_expr
                if (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name)
                        and expression.func.id == 'GlobalWritebackTransaction'
                        and isinstance(item.optional_vars, ast.Name)):
                    sites.append((node, item.optional_vars.id))
        self.assertEqual(1, len(sites), 'use the actual original transaction with-as site')
        block, receiver_name = sites[0]
        additions = ast.parse('unproved_receiver_handoff('
            '[_h_comp_item for _h_comp_item in [SOURCE_RECEIVER]])\n')

        class BindOriginalReceiver(ast.NodeTransformer):
            def visit_Name(self, node):
                if node.id == 'SOURCE_RECEIVER':
                    return ast.copy_location(ast.Name(id=receiver_name, ctx=node.ctx), node)
                return node

        additions = BindOriginalReceiver().visit(additions)
        block.body[0:0] = additions.body
        with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
            SUBJECT.local_call_graph(feedback)
