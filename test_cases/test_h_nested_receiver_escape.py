"""Finite whole-receiver containment checks; never execute hostile AST bodies."""
import ast
from pathlib import Path
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT

PRELUDE = '''
import os
class Transaction:
    def commit(self):
        os.unlink('01-global.yaml')
def handoff(payload):
    return None
'''


class NestedReceiverEscapeTests(unittest.TestCase):
    def test_direct_container_and_expansion_cannot_preserve_receiver_certificate(self):
        for spelling in ('[tx]', '(tx,)', "{'receiver': tx}", '*[tx]', "**{'payload': tx}"):
            with self.subTest(spelling=spelling):
                tree = ast.parse(PRELUDE + '''
def main():
    tx = Transaction()
    handoff(''' + spelling + ''')
    tx.commit()
''')
                with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
                    SUBJECT.local_call_graph(tree)

    def test_stored_container_and_helper_containment_remain_fail_closed(self):
        cases = (
            '''
def main():
    tx = Transaction()
    payload = [tx]
    forwarded = payload
    handoff(forwarded)
    tx.commit()
''',
            '''
def forward(instance):
    payload = (instance,)
    handoff(payload)
def main():
    tx = Transaction()
    forward(tx)
    tx.commit()
''',
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
                    SUBJECT.local_call_graph(ast.parse(PRELUDE + source))

    def test_data_field_container_does_not_escape_the_whole_receiver(self):
        tree = ast.parse(PRELUDE + '''
def main():
    tx = Transaction()
    handoff([tx.ready])
    tx.commit()
''')
        graph = SUBJECT.local_call_graph(tree)
        self.assertEqual({'handoff', 'commit'}, graph['main'])
        self.assertIs(tree.body[1].body[0], graph.definitions['commit'])

    def test_actual_feedback_receiver_containment_is_rejected_with_runtime_source_present(self):
        root = Path(SUBJECT.ROOT)
        feedback = ast.parse((root / 'ztp/optimize/feedback.py').read_text())
        runtime = ast.parse((root / 'tools/ztp_service_runtime.py').read_text())
        self.assertIn('stop_native_ztp_monitors', SUBJECT.production_functions(runtime))
        main = SUBJECT.production_functions(feedback)['main']
        injected = 0
        for node in ast.walk(main):
            if not isinstance(node, ast.With):
                continue
            for item in node.items:
                call = item.context_expr
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id == 'GlobalWritebackTransaction'
                        and isinstance(item.optional_vars, ast.Name)):
                    node.body.insert(0, ast.Expr(value=ast.Call(
                        func=ast.Name(id='unproved_receiver_handoff', ctx=ast.Load()),
                        args=[ast.List(elts=[ast.Name(id=item.optional_vars.id, ctx=ast.Load())],
                                       ctx=ast.Load())], keywords=[])))
                    injected += 1
        self.assertEqual(1, injected, 'mutate the actual supported transaction site')
        with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
            SUBJECT.local_call_graph(feedback)
