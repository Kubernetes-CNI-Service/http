"""Graph-lifetime original-scope derivation counts; AST DATA, SOURCE NOT RUN."""
import ast
import unittest
from unittest import mock

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


LITERAL = '''
class Transaction:
    def commit(self):
        return None
    def prepare(self):
        return None
    def close(self):
        return None
def foreign():
    return None
def main():
    tx = Transaction()
    tx.commit()
'''


class GraphLocalScopeMemoTests(unittest.TestCase):
    def test_each_original_scope_is_derived_once_per_graph_and_again_next_graph(self):
        tree = ast.parse(LITERAL)
        transaction, foreign, main = tree.body
        expected_scopes = {tree, transaction, foreign, main, *transaction.body}
        real_bindings = SUBJECT._source_scope_bindings
        snapshots = []
        for invocation in (1, 2):
            with self.subTest(invocation=invocation):
                counts = {}

                def counted(scope):
                    counts[scope] = counts.get(scope, 0) + 1
                    # Delegate the complete actual derivation; no fake table,
                    # intercepted return, or mocked graph is supplied.
                    return real_bindings(scope)

                with mock.patch.object(SUBJECT, '_source_scope_bindings', new=counted):
                    graph = SUBJECT.local_call_graph(tree)
                snapshots.append(counts)
                self.assertEqual({
                    'commit': set(), 'prepare': set(), 'close': set(),
                    'foreign': set(), 'main': {'commit'},
                }, dict(graph))
                self.assertIs(transaction.body[0], graph.definitions['commit'])
                self.assertIs(transaction.body[1], graph.definitions['prepare'])
                self.assertIs(transaction.body[2], graph.definitions['close'])
                self.assertIs(foreign, graph.definitions['foreign'])
                self.assertIs(main, graph.definitions['main'])
                self.assertEqual(expected_scopes, set(counts),
                    'each invocation must derive its own original scope tables')
                self.assertEqual(1, counts[tree], 'MODULE_SCOPE_BINDINGS_REBUILT_WITHIN_GRAPH')
                self.assertEqual({scope: 1 for scope in expected_scopes}, counts,
                    'ORIGINAL_SCOPE_BINDINGS_MUST_BE_ONCE_PER_GRAPH_NOT_GLOBAL')
        self.assertIsNot(snapshots[0], snapshots[1])
        self.assertEqual(snapshots[0], snapshots[1],
            'a new graph must rebuild all original scope tables, not borrow the previous cache')

    def test_same_ast_new_graph_rejects_a_new_literal_receiver_mutation(self):
        tree = ast.parse(LITERAL)
        first = SUBJECT.local_call_graph(tree)
        self.assertEqual({'commit'}, first['main'])
        self.assertIs(tree.body[0].body[0], first.definitions['commit'])
        # New source statement comes from an independent fixed literal, not
        # from candidate output. Reuse the exact Module and function objects.
        mutation = ast.parse("setattr(tx, 'commit', foreign)").body[0]
        main = tree.body[2]
        main.body.insert(1, mutation)
        with self.assertRaisesRegex(AssertionError, '^WDISC_UNRESOLVED:'):
            SUBJECT.local_call_graph(tree)

    def test_colliding_owner_labels_and_actual_callsite_edges_remain_original(self):
        tree = ast.parse('''
class Transaction:
    def commit(self):
        return None
class Display:
    def commit(self):
        return None
def main():
    tx = Transaction()
    tx.commit()
''')
        graph = SUBJECT.local_call_graph(tree)
        self.assertEqual({
            '<module>.Transaction.commit@3': set(),
            '<module>.Display.commit@6': set(),
            'main': {'<module>.Transaction.commit@3'},
        }, dict(graph))
        self.assertIs(tree.body[0].body[0],
            graph.definitions['<module>.Transaction.commit@3'])
        self.assertIs(tree.body[1].body[0],
            graph.definitions['<module>.Display.commit@6'])
        original_call = tree.body[2].body[1].value
        self.assertEqual({'<module>.Transaction.commit@3'}, graph.call_targets[original_call])


# Independent immutable literals. Only AST nodes are edited; neither source body
# is compiled or executed as a writer. The real scanner/ordering functions run.
_SUMMARY_PASS = """import os
def publish(destination):
    pass
def main():
    publish('01-global.yaml')
"""
_SUMMARY_WRITE = """import os
def publish(destination):
    os.replace('temporary', destination)
def main():
    publish('01-global.yaml')
"""


class MutableGenericSummaryEpochTests(unittest.TestCase):
    def _change_original_publish_body(self, tree, replacement_source):
        original_module = tree
        original_function = tree.body[1]
        replacement = ast.parse(replacement_source)
        original_function.body[:] = replacement.body[1].body
        self.assertIs(tree, original_module)
        self.assertIs(tree.body[1], original_function)
        return original_function

    def _consume_actual_scanner_and_ordering(self, tree):
        # This is the real W1-style nonempty admission, not a classifier forced
        # to reject an empty discovery set. No source_path means the original
        # helper's AST-keyed cache is exercised, not its uncached path branch.
        discovered = SUBJECT.literal_governed_mutation_sinks(tree)
        self.assertIs(type(discovered), set)
        if not discovered:
            return discovered, 'EMPTY'
        # Both the actual callee and its governed callsite must be retained.
        self.assertEqual(discovered, {'publish', 'main'})
        ordering = SUBJECT.assert_quiesce_structurally_precedes_reachable_sink
        self.assertIs(ordering.__globals__, SUBJECT.__dict__)
        error = None
        try:
            ordering(self, tree, 'main', discovered)
        except AssertionError as caught:
            error = caught
        self.assertIsNotNone(error, 'ACTUAL_NO_STOP_WRITER_MUST_BE_REFUSED')
        self.assertEqual(error.args, ('[] is not true : main has no direct quiesce',))
        trace = error.__traceback__
        original_ordering_frame = False
        while trace is not None:
            original_ordering_frame |= (
                trace.tb_frame.f_code is ordering.__code__
                and trace.tb_frame.f_globals is SUBJECT.__dict__)
            trace = trace.tb_next
        self.assertTrue(original_ordering_frame)
        return discovered, 'HOLD'

    def test_same_module_and_function_pass_to_write_recomputes_parameter_summary(self):
        tree = ast.parse(_SUMMARY_PASS)
        function = tree.body[1]
        self.assertEqual(
            SUBJECT.generic_mutation_parameter_summaries(tree)['publish'], set())
        # Fresh equivalent source is an independent positive control, not a
        # value copied from the stale cached AST or candidate implementation.
        self.assertEqual(
            SUBJECT.generic_mutation_parameter_summaries(
                ast.parse(_SUMMARY_WRITE))['publish'], {0})
        self.assertIs(self._change_original_publish_body(tree, _SUMMARY_WRITE), function)
        self.assertEqual(
            SUBJECT.generic_mutation_parameter_summaries(tree)['publish'], {0},
            'SAME_AST_NEW_WRITE_MUST_NOT_REUSE_EMPTY_SUMMARY')

    def test_same_module_and_function_write_to_pass_drops_parameter_taint(self):
        tree = ast.parse(_SUMMARY_WRITE)
        function = tree.body[1]
        self.assertEqual(
            SUBJECT.generic_mutation_parameter_summaries(tree)['publish'], {0})
        self.assertEqual(
            SUBJECT.generic_mutation_parameter_summaries(
                ast.parse(_SUMMARY_PASS))['publish'], set())
        self.assertIs(self._change_original_publish_body(tree, _SUMMARY_PASS), function)
        self.assertEqual(
            SUBJECT.generic_mutation_parameter_summaries(tree)['publish'], set(),
            'SAME_AST_REMOVED_WRITE_MUST_NOT_REUSE_OLD_TAINT')

    def test_scanner_then_original_ordering_sees_new_write_in_same_ast(self):
        tree = ast.parse(_SUMMARY_PASS)
        self.assertEqual(self._consume_actual_scanner_and_ordering(tree),
                         (set(), 'EMPTY'))
        self.assertEqual(self._consume_actual_scanner_and_ordering(
            ast.parse(_SUMMARY_WRITE)), ({'publish', 'main'}, 'HOLD'))
        self._change_original_publish_body(tree, _SUMMARY_WRITE)
        self.assertEqual(self._consume_actual_scanner_and_ordering(tree),
                         ({'publish', 'main'}, 'HOLD'),
                         'SAME_AST_NEW_WRITER_MUST_REACH_ORIGINAL_ORDERING')

    def test_scanner_then_original_ordering_drops_removed_write_in_same_ast(self):
        tree = ast.parse(_SUMMARY_WRITE)
        self.assertEqual(self._consume_actual_scanner_and_ordering(tree),
                         ({'publish', 'main'}, 'HOLD'))
        self.assertEqual(self._consume_actual_scanner_and_ordering(
            ast.parse(_SUMMARY_PASS)), (set(), 'EMPTY'))
        self._change_original_publish_body(tree, _SUMMARY_PASS)
        self.assertEqual(self._consume_actual_scanner_and_ordering(tree),
                         (set(), 'EMPTY'),
                         'SAME_AST_REMOVED_WRITER_MUST_NOT_RETAIN_OLD_HOLD')


class ReturnedGenericSummaryIsolationTests(unittest.TestCase):
    def test_editing_first_returned_set_cannot_change_later_summary(self):
        tree = ast.parse(_SUMMARY_WRITE)
        returned = SUBJECT.generic_mutation_parameter_summaries(tree)
        self.assertEqual(returned['publish'], {0})
        self.assertEqual(SUBJECT.generic_mutation_parameter_summaries(
            ast.parse(_SUMMARY_WRITE))['publish'], {0})
        # Only the public returned DATA is edited. The AST and cache object,
        # entries, slot and contents are never directly touched by this test.
        returned['publish'].clear()
        self.assertEqual(returned['publish'], set())
        after = SUBJECT.generic_mutation_parameter_summaries(tree)
        self.assertIn('publish', after)
        self.assertEqual(after['publish'], {0},
                         'EDITED_FIRST_RETURN_MUST_NOT_POISON_ORIGINAL_SUMMARY')

    def test_deleting_key_from_cache_hit_return_cannot_change_later_summary(self):
        tree = ast.parse(_SUMMARY_WRITE)
        first = SUBJECT.generic_mutation_parameter_summaries(tree)
        self.assertEqual(first['publish'], {0})
        cache_hit_return = SUBJECT.generic_mutation_parameter_summaries(tree)
        self.assertEqual(cache_hit_return['publish'], {0})
        self.assertEqual(SUBJECT.generic_mutation_parameter_summaries(
            ast.parse(_SUMMARY_WRITE))['publish'], {0})
        del cache_hit_return['publish']
        self.assertNotIn('publish', cache_hit_return)
        after = SUBJECT.generic_mutation_parameter_summaries(tree)
        self.assertIn('publish', after,
                      'EDITED_CACHE_HIT_RETURN_MUST_NOT_DELETE_ORIGINAL_SUMMARY')
        self.assertEqual(after['publish'], {0})

    def test_edited_returned_data_cannot_hide_writer_from_original_ordering(self):
        consume = MutableGenericSummaryEpochTests._consume_actual_scanner_and_ordering
        self.assertEqual(consume(self, ast.parse(_SUMMARY_WRITE)),
                         ({'publish', 'main'}, 'HOLD'))
        tree = ast.parse(_SUMMARY_WRITE)
        returned = SUBJECT.generic_mutation_parameter_summaries(tree)
        self.assertEqual(returned['publish'], {0})
        returned['publish'].clear()
        self.assertEqual(returned['publish'], set())
        # Actual scanner plus the unchanged original ordering helper must see
        # the source-owned writer, not the caller-edited summary DATA. This is
        # AST/protocol only: no writer body, service or device action executes.
        self.assertEqual(consume(self, tree), ({'publish', 'main'}, 'HOLD'),
                         'EDITED_RETURN_MUST_NOT_HIDE_REAL_SCANNER_WRITER')


# Independently fixed supported ABI literal. It is never executed or imported
# as a native bridge; the complete original helper inspects only its AST.
_SUPPORTED_FFI_LITERAL = (
    "import ctypes\nimport os\nimport sys\nfrom pathlib import Path\n"
    "def _rename_noreplace(source, destination):\n"
    "    destination = Path('/srv/http/01-global.yaml')\n"
    "    if sys.platform.startswith('linux'):\n"
    "        libc = ctypes.CDLL(None, use_errno=True)\n"
    "        renameat2 = getattr(libc, 'renameat2', None)\n"
    "        if renameat2 is not None:\n"
    "            renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)\n"
    "            renameat2.restype = ctypes.c_int\n"
    "            renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1)\n"
)


class EmptyFfiSchemaMetadataTests(unittest.TestCase):
    def _with_private_type_params(self, tree, values):
        # Model the schema on private nodes only, including under Python3.9.
        # Instance _fields assignments never modify ast.FunctionDef._fields.
        function = tree.body[4]
        if 'type_params' not in function._fields:
            function._fields = (*function._fields, 'type_params')
        function.type_params = values
        return tree

    def _inspect_original_without_mutating_tree(self, tree, relative):
        before_dump = ast.dump(tree, include_attributes=True)
        before_nodes = tuple(ast.walk(tree))
        before_fields = tuple(node._fields for node in before_nodes)
        before_global_fields = ast.FunctionDef._fields
        helper = SUBJECT._source_bound_native_rename_calls
        self.assertIs(helper.__globals__, SUBJECT.__dict__)
        actual = helper(tree, relative)
        self.assertEqual(ast.dump(tree, include_attributes=True), before_dump)
        after_nodes = tuple(ast.walk(tree))
        self.assertEqual(len(after_nodes), len(before_nodes))
        self.assertTrue(all(after is before
                            for after, before in zip(after_nodes, before_nodes)))
        self.assertEqual(tuple(node._fields for node in after_nodes), before_fields)
        self.assertIs(ast.FunctionDef._fields, before_global_fields)
        return actual

    def test_supported_ffi_retains_original_call_across_empty_schema_metadata(self):
        cases = (
            ('ordinary-parsed', ast.parse(_SUPPORTED_FFI_LITERAL)),
            ('modeled-empty-type-params', self._with_private_type_params(
                ast.parse(_SUPPORTED_FFI_LITERAL), [])),
        )
        for label, tree in cases:
            with self.subTest(schema=label):
                # Fixed literal structural position, not a candidate-discovered
                # call selected by its returned proof or hashed output.
                original_call = tree.body[4].body[1].body[2].body[2].value
                self.assertIs(type(original_call), ast.Call)
                actual = self._inspect_original_without_mutating_tree(
                    tree, 'tools/deploy-shared-artifacts.py')
                self.assertEqual(len(actual), 1, 'EMPTY_SCHEMA_MUST_NOT_WITHDRAW_ORIGINAL_FFI')
                self.assertIs(next(iter(actual)), original_call)
                self.assertEqual(actual[original_call], 'libc.renameat2')

    def test_nonempty_schema_or_source_or_path_drift_still_withdraws_ffi(self):
        changed_flag = _SUPPORTED_FFI_LITERAL.replace(
            'os.fsencode(destination), 1)', 'os.fsencode(destination), 2)')
        self.assertNotEqual(changed_flag, _SUPPORTED_FFI_LITERAL)
        cases = (
            ('nonempty-type-params', self._with_private_type_params(
                ast.parse(_SUPPORTED_FFI_LITERAL), [ast.Name(id='T', ctx=ast.Load())]),
             'tools/deploy-shared-artifacts.py'),
            ('unknown-empty-tuple', self._with_private_type_params(
                ast.parse(_SUPPORTED_FFI_LITERAL), ()), 'tools/deploy-shared-artifacts.py'),
            ('unknown-empty-string', self._with_private_type_params(
                ast.parse(_SUPPORTED_FFI_LITERAL), ''), 'tools/deploy-shared-artifacts.py'),
            ('unknown-none', self._with_private_type_params(
                ast.parse(_SUPPORTED_FFI_LITERAL), None), 'tools/deploy-shared-artifacts.py'),
            ('changed-no-replace-flag', self._with_private_type_params(
                ast.parse(changed_flag), []), 'tools/deploy-shared-artifacts.py'),
            ('foreign-source-path', self._with_private_type_params(
                ast.parse(_SUPPORTED_FFI_LITERAL), []), 'tools/not-the-reviewed-ffi.py'),
        )
        for label, tree, relative in cases:
            with self.subTest(refusal=label):
                self.assertEqual(self._inspect_original_without_mutating_tree(
                    tree, relative), {})


_PAIR_SOURCE_CASES = (
    (
        'load-report',
        ('DAY0-Prepare/11-load.py', 'tools/generation_report.py'),
        '_source_bound_load_report_path',
        {
            'native_guard': "local_services_supported and runtime_backend_instance.name == 'systemd' and (not args.dry_run)",
            'quiesce': 'stop_native_ztp_monitors(HTTP_ROOT)',
            'handoff': 'generation_report.commit_prepared_generation_report(report_candidate)',
            'mutation': 'os.replace(candidate.temporary.name, REPORT_NAME, src_dir_fd=descriptor, dst_dir_fd=descriptor)',
        },
        {'native_guard': 0, 'quiesce': 0, 'handoff': 0, 'mutation': 1},
        (
            ('import generation_report\n', 'import unrelated_report as generation_report\n'),
            ('REPORT_NAME = "generation-report.json"', 'REPORT_NAME = "unexpected-report.json"'),
        ),
    ),
    (
        'feedback-runtime',
        ('ztp/optimize/feedback.py', 'tools/ztp_service_runtime.py'),
        '_source_bound_feedback_recovery_path',
        {
            'lock': 'deployment_lock(plan.http_base)',
            'stop': 'stop_native_ztp_monitors(plan.http_base)',
            'recover': 'recover_global_writeback_state(authority, workspace_root=plan.http_base, held_lock_fd=held_lock_fd)',
            'pid_files': '_native_monitor_pid_files(root)',
        },
        {'lock': 0, 'stop': 0, 'recover': 0, 'pid_files': 1},
        (
            ('stop_native_ztp_monitors(plan.http_base)', 'unrelated_stop(plan.http_base)'),
            ('pid_files = _native_monitor_pid_files(root)', 'pid_files = ()'),
        ),
    ),
)


class PairSourceSchemaTests(unittest.TestCase):
    def _private_empty_schema(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if 'type_params' not in node._fields:
                    node._fields = (*node._fields, 'type_params')
                node.type_params = []
        return tree

    def _inspect_pair_without_original_changes(self, name, trees):
        helper = getattr(SUBJECT, name)
        self.assertIs(helper.__globals__, SUBJECT.__dict__)
        before_dumps = tuple(ast.dump(tree, include_attributes=True) for tree in trees)
        before_nodes = tuple(tuple(ast.walk(tree)) for tree in trees)
        before_fields = tuple(tuple(node._fields for node in nodes)
                              for nodes in before_nodes)
        classes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        before_global_fields = tuple(cls._fields for cls in classes)
        proof = helper(*trees)
        self.assertEqual(tuple(ast.dump(tree, include_attributes=True)
                               for tree in trees), before_dumps)
        after_nodes = tuple(tuple(ast.walk(tree)) for tree in trees)
        self.assertEqual(tuple(map(len, after_nodes)), tuple(map(len, before_nodes)))
        for original, after in zip(before_nodes, after_nodes):
            self.assertTrue(all(a is b for a, b in zip(original, after)))
        self.assertEqual(tuple(tuple(node._fields for node in nodes)
                               for nodes in after_nodes), before_fields)
        self.assertTrue(all(cls._fields is previous
                            for cls, previous in zip(classes, before_global_fields)))
        return proof, before_nodes

    def test_original_source_pair_roles_survive_only_empty_schema_metadata(self):
        for label, paths, name, expected, role_owners, _mutants in _PAIR_SOURCE_CASES:
            sources = tuple((SUBJECT.ROOT / path).read_text(encoding='utf-8')
                            for path in paths)
            for modeled in (False, True):
                with self.subTest(pair=label, modeled_empty=modeled):
                    trees = tuple(ast.parse(source) for source in sources)
                    if modeled:
                        for tree in trees:
                            self._private_empty_schema(tree)
                    proof, original_nodes = self._inspect_pair_without_original_changes(
                        name, trees)
                    self.assertEqual(set(proof), set(expected),
                                     'EMPTY_SCHEMA_MUST_RETAIN_BOTH_ORIGINAL_SOURCE_ROLES')
                    self.assertEqual({role: ast.unparse(node)
                                      for role, node in proof.items()}, expected)
                    for role, node in proof.items():
                        self.assertTrue(any(node is original
                                            for original in original_nodes[role_owners[role]]),
                                        'PROOF_MUST_REFERENCE_ORIGINAL_SOURCE_NOT_A_COPY')

    def test_each_source_endpoint_nonempty_unknown_or_content_drift_is_refused(self):
        for label, paths, name, _expected, _role_owners, mutants in _PAIR_SOURCE_CASES:
            sources = tuple((SUBJECT.ROOT / path).read_text(encoding='utf-8')
                            for path in paths)
            for endpoint in (0, 1):
                for mutation in ('nonempty', 'unknown-empty-tuple', 'content'):
                    with self.subTest(pair=label, endpoint=endpoint, mutation=mutation):
                        current_sources = list(sources)
                        if mutation == 'content':
                            needle, replacement = mutants[endpoint]
                            self.assertEqual(current_sources[endpoint].count(needle), 1)
                            current_sources[endpoint] = current_sources[endpoint].replace(
                                needle, replacement, 1)
                            self.assertNotEqual(current_sources[endpoint], sources[endpoint])
                        trees = tuple(self._private_empty_schema(ast.parse(source))
                                      for source in current_sources)
                        if mutation != 'content':
                            definition = next(node for node in ast.walk(trees[endpoint])
                                              if isinstance(node, (ast.FunctionDef,
                                                  ast.AsyncFunctionDef, ast.ClassDef)))
                            self.assertIn('type_params', definition._fields)
                            definition.type_params = (
                                [ast.Name(id='T', ctx=ast.Load())]
                                if mutation == 'nonempty' else ())
                        proof, _original_nodes = self._inspect_pair_without_original_changes(
                            name, trees)
                        self.assertEqual(proof, {},
                                         'SCHEMA_OR_SOURCE_DRIFT_MUST_WITHDRAW_PAIR_CERTIFICATE')
