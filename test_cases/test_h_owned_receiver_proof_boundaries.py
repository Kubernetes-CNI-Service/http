"""Independent receiver identity controls, AST only, SOURCE NOT RUN.

These trees are data, never exec/eval/imported as business code. A specific
WDISC_UNRESOLVED refusal is acceptable; generic exceptions/empty graphs are not.
"""
import ast
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


TRANSACTION = '''
class Transaction:
    def __init__(self):
        self.ready = False
    def __enter__(self):
        return self
    def __exit__(self, kind, error, traceback):
        pass
    def commit(self):
        return None
def innocent():
    return None
'''


def forward(graph):
    reached = {'main'}
    pending = ['main']
    while pending:
        for target in graph.get(pending.pop(), ()):
            if target not in reached:
                reached.add(target)
                pending.append(target)
    return reached


class OwnedReceiverProofBoundaryTests(unittest.TestCase):
    def original_commit(self, tree):
        owner = next(node for node in tree.body
                     if isinstance(node, ast.ClassDef) and node.name == 'Transaction')
        return next(node for node in owner.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'commit')

    def assert_no_original_commit_borrow(self, source):
        tree = ast.parse(source)
        try:
            graph = SUBJECT.local_call_graph(tree)
        except AssertionError as error:
            self.assertTrue(str(error).startswith('WDISC_UNRESOLVED'),
                'only explicit source-identity refusal qualifies, not generic failure: ' + str(error))
            return
        # Refusing by erasing the graph is not an original-owner proof.
        self.assertIn('main', graph)
        self.assertIn('commit', graph)
        self.assertIs(graph.definitions['commit'], self.original_commit(tree))
        self.assertNotIn('commit', forward(graph),
            'FOREIGN_OR_UNPROVED_RECEIVER_BORROWED_ORIGINAL_COMMIT')

    def test_complete_self_return_and_nonmethod_data_field_keep_original_receiver(self):
        tree = ast.parse(TRANSACTION + '''
def main():
    with Transaction() as transaction:
        transaction.ready = True
        transaction.commit()
''')
        graph = SUBJECT.local_call_graph(tree)
        self.assertIs(graph.definitions['commit'], self.original_commit(tree))
        self.assertIn('commit', forward(graph),
            'ordinary instance DATA is not an assignment to the dispatch slot')

    def test_instance_dispatch_replacement_does_not_borrow_the_original_method(self):
        for label, declaration, body in (
                ('direct-slot', TRANSACTION, '''
        transaction.commit = innocent
        transaction.commit()
'''),
                ('alias-slot', TRANSACTION, '''
        alias = transaction
        alias.commit = innocent
        transaction.commit()
'''),
                ('constructor-slot', TRANSACTION.replace(
                    '        self.ready = False',
                    '        self.ready = False\n        self.commit = innocent'), '''
        transaction.commit()
''')):
            with self.subTest(case=label):
                self.assert_no_original_commit_borrow(declaration +
                    '\ndef main():\n    with Transaction() as transaction:\n' + body)

    def test_partial_self_returns_do_not_prove_all_normal_enter_results(self):
        for label, enter in (
                ('conditional-fallthrough', '''
        if self.ready:
            return self
'''),
                ('empty-loop-fallthrough', '''
        for unused in ():
            return self
''')):
            source = TRANSACTION.replace('        return self', enter.rstrip()) + '''
def main():
    with Transaction() as transaction:
        transaction.commit()
'''
            # On these literal source paths __enter__ returns implicit None;
            # manager.__exit__ still belongs to Transaction, but the with-as
            # target cannot call that class's original commit method.
            with self.subTest(case=label):
                self.assert_no_original_commit_borrow(source)

    def test_namespace_escape_cannot_preserve_a_method_dispatch_certificate(self):
        for label, extra, body in (
                ('setattr', '', '''
        setattr(transaction, 'commit', innocent)
        transaction.commit()
'''),
                ('vars-subscript', '', '''
        namespace = vars(transaction)
        namespace['commit'] = innocent
        transaction.commit()
'''),
                ('known-helper-escape', '''
def replace_dispatch(receiver):
    receiver.commit = innocent
''', '''
        replace_dispatch(transaction)
        transaction.commit()
''')):
            with self.subTest(case=label):
                self.assert_no_original_commit_borrow(TRANSACTION + extra +
                    '\ndef main():\n    with Transaction() as transaction:\n' + body)
