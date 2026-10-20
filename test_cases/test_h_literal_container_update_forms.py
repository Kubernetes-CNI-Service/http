"""Two bounded explicit container forms; AST DATA only, SOURCE NOT RUN."""
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
WHOLE_FORMS = (
    ('augassign', '    payload = []\n    payload += [tx]\n    handoff(payload)\n'),
    ('namedexpr', '    handoff(payload := [tx])\n'),
)
DATA_FORMS = (
    ('augassign', '    payload = []\n    payload += [tx.ready]\n    handoff(payload)\n'),
    ('namedexpr', '    handoff(payload := [tx.ready])\n'),
)


class LiteralContainerUpdateFormsTests(unittest.TestCase):
    def test_whole_receiver_literal_augassign_and_namedexpr_are_refused(self):
        for label, statement in WHOLE_FORMS:
            with self.subTest(form=label):
                tree = ast.parse(PRELUDE + 'def main():\n    tx = Transaction()\n'
                                 + statement + '    tx.commit()\n')
                with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
                    SUBJECT.local_call_graph(tree)

    def test_same_forms_with_only_data_field_preserve_original_edges(self):
        for label, statement in DATA_FORMS:
            with self.subTest(form=label):
                tree = ast.parse(PRELUDE + 'def main():\n    tx = Transaction()\n'
                                 + statement + '    tx.commit()\n')
                graph = SUBJECT.local_call_graph(tree)
                self.assertEqual({'commit': set(), 'handoff': set(),
                                  'main': {'handoff', 'commit'}}, dict(graph))
                self.assertIs(tree.body[0].body[1], graph.definitions['commit'])
                self.assertIs(tree.body[1], graph.definitions['handoff'])
                self.assertIs(tree.body[2], graph.definitions['main'])

    def test_actual_feedback_receiver_same_forms_refuse_with_runtime_original_present(self):
        root = Path(SUBJECT.ROOT)
        runtime = ast.parse((root / 'tools/ztp_service_runtime.py').read_text(encoding='utf-8'))
        self.assertIn('stop_native_ztp_monitors', SUBJECT.production_functions(runtime))
        for label, literal in (
            ('augassign', '_h_literal_container_probe = []\n'
                '_h_literal_container_probe += [SOURCE_RECEIVER]\n'
                'unproved_receiver_handoff(_h_literal_container_probe)\n'),
            ('namedexpr', 'unproved_receiver_handoff('
                '_h_literal_container_probe := [SOURCE_RECEIVER])\n'),
        ):
            with self.subTest(form=label):
                feedback = ast.parse((root / 'ztp/optimize/feedback.py').read_text(encoding='utf-8'))
                main = SUBJECT.production_functions(feedback)['main']
                self.assertFalse(any(isinstance(node, ast.Name)
                    and node.id == '_h_literal_container_probe' for node in ast.walk(main)),
                    'literal mutator needs its own unused local name')
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
                self.assertEqual(1, len(sites), 'mutate the real original transaction site')
                block, receiver_name = sites[0]
                additions = ast.parse(literal)

                class OriginalReceiverName(ast.NodeTransformer):
                    def visit_Name(self, node):
                        if node.id == 'SOURCE_RECEIVER':
                            return ast.copy_location(ast.Name(id=receiver_name, ctx=node.ctx), node)
                        return node

                additions = OriginalReceiverName().visit(additions)
                block.body[0:0] = additions.body
                with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
                    SUBJECT.local_call_graph(feedback)
