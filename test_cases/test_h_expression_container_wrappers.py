"""Explicit expression-wrapped receiver containers: AST DATA, SOURCE NOT RUN."""
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
FORMS = (
    ('direct-concatenation', 'handoff([SOURCE_RECEIVER] + [])\n'),
    ('direct-conditional', 'handoff([SOURCE_RECEIVER] if _h_expr_ready else [])\n'),
    ('stored-concatenation', '_h_expr_container = ([SOURCE_RECEIVER] + [])\n'
        'handoff(_h_expr_container)\n'),
)


class ExpressionContainerWrappersTests(unittest.TestCase):
    def test_whole_receiver_explicit_wrappers_refuse_unknown_handoff(self):
        for label, statements in FORMS:
            with self.subTest(form=label):
                body = ''.join('    ' + line + '\n'
                    for line in statements.replace('SOURCE_RECEIVER', 'tx').splitlines())
                tree = ast.parse(PRELUDE + 'def main():\n    tx = Transaction()\n'
                    '    _h_expr_ready = True\n' + body + '    tx.commit()\n')
                with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
                    SUBJECT.local_call_graph(tree)

    def test_corresponding_data_wrappers_keep_original_definition_and_edges(self):
        for label, statements in FORMS:
            with self.subTest(form=label):
                body = ''.join('    ' + line + '\n'
                    for line in statements.replace('SOURCE_RECEIVER', 'tx.ready').splitlines())
                tree = ast.parse(PRELUDE + 'def main():\n    tx = Transaction()\n'
                    '    _h_expr_ready = True\n' + body + '    tx.commit()\n')
                graph = SUBJECT.local_call_graph(tree)
                self.assertEqual({'commit': set(), 'handoff': set(),
                    'main': {'handoff', 'commit'}}, dict(graph))
                self.assertIs(tree.body[0].body[1], graph.definitions['commit'])
                self.assertIs(tree.body[1], graph.definitions['handoff'])
                self.assertIs(tree.body[2], graph.definitions['main'])

    def test_original_call_proven_data_results_and_wrappers_keep_original_edges(self):
        for label, statements in (
            ('id-result', 'handoff(id(tx))\n'),
            ('getattr-result', "handoff(getattr(tx, 'ready'))\n"),
            ('id-concatenation', 'handoff([id(tx)] + [])\n'),
            ('getattr-concatenation', "handoff([getattr(tx, 'ready')] + [])\n"),
            ('id-conditional', 'handoff([id(tx)] if _h_expr_ready else [])\n'),
            ('getattr-conditional', "handoff([getattr(tx, 'ready')] if _h_expr_ready else [])\n"),
            ('id-stored', '_h_expr_container = [id(tx)] + []\nhandoff(_h_expr_container)\n'),
            ('getattr-stored', "_h_expr_container = [getattr(tx, 'ready')] + []\n"
                'handoff(_h_expr_container)\n'),
        ):
            with self.subTest(form=label):
                body = ''.join('    ' + line + '\n' for line in statements.splitlines())
                tree = ast.parse(PRELUDE + 'def main():\n    tx = Transaction()\n'
                    '    _h_expr_ready = True\n' + body + '    tx.commit()\n')
                graph = SUBJECT.local_call_graph(tree)
                self.assertEqual({'commit': set(), 'handoff': set(),
                    'main': {'handoff', 'commit'}}, dict(graph))
                self.assertIs(tree.body[0].body[1], graph.definitions['commit'])
                self.assertIs(tree.body[1], graph.definitions['handoff'])
                self.assertIs(tree.body[2], graph.definitions['main'])

    def test_actual_feedback_same_wrappers_refuse_with_original_runtime_present(self):
        root = Path(SUBJECT.ROOT)
        runtime = ast.parse((root / 'tools/ztp_service_runtime.py').read_text(encoding='utf-8'))
        self.assertIn('stop_native_ztp_monitors', SUBJECT.production_functions(runtime))
        for label, statements in FORMS:
            with self.subTest(form=label):
                feedback = ast.parse((root / 'ztp/optimize/feedback.py').read_text(encoding='utf-8'))
                main = SUBJECT.production_functions(feedback)['main']
                self.assertFalse(any(isinstance(node, ast.Name)
                    and node.id in {'_h_expr_ready', '_h_expr_container'} for node in ast.walk(main)),
                    'independent literal mutation locals must not capture existing bindings')
                sites = []
                for node in ast.walk(main):
                    if not isinstance(node, ast.With):
                        continue
                    for item in node.items:
                        call = item.context_expr
                        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                                and call.func.id == 'GlobalWritebackTransaction'
                                and isinstance(item.optional_vars, ast.Name)):
                            sites.append((node, item.optional_vars.id))
                self.assertEqual(1, len(sites), 'use the real original transaction with-as site')
                block, original_receiver_name = sites[0]
                additions = ast.parse('_h_expr_ready = True\n' + statements)

                class BindOriginalReceiver(ast.NodeTransformer):
                    def visit_Name(self, node):
                        if node.id == 'SOURCE_RECEIVER':
                            return ast.copy_location(ast.Name(id=original_receiver_name, ctx=node.ctx), node)
                        if node.id == 'handoff':
                            return ast.copy_location(ast.Name(id='unproved_receiver_handoff', ctx=node.ctx), node)
                        return node

                additions = BindOriginalReceiver().visit(additions)
                block.body[0:0] = additions.body
                with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
                    SUBJECT.local_call_graph(feedback)
