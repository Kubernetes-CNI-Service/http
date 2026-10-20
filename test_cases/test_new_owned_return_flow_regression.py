"""NEW governed resolver return regression through the original scanner.

Only literal AST syntax is analyzed; no Path construction or write executes.
A potential publish must reach the original failclosed classifier, or the
original scanner must explicitly refuse. Neither outcome grants a writer.
"""
import ast
import types
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


FACTS = []
MODULE_RETURN_WRITER = (
    "from pathlib import Path\n"
    "def resolve_target():\n"
    "    return Path('01-global.yaml')\n"
    "def publish():\n"
    "    target = resolve_target()\n"
    "    target.write_text('updated')\n"
)
NESTED_RETURN_WRITER = (
    "from pathlib import Path\n"
    "def publish():\n"
    "    def resolve_target():\n"
    "        return Path('01-global.yaml')\n"
    "    target = resolve_target()\n"
    "    target.write_text('updated')\n"
)
RELATIVE = "tools/new_owned_return_writer_literal.py"

class SourceAdmissionHold(RuntimeError):
    pass


def _from_original(error, function):
    tb = error.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code is function.__code__ and tb.tb_frame.f_globals is function.__globals__:
            return True
        tb = tb.tb_next
    return False


def _consume(source, label):
    if type(SUBJECT) is not types.ModuleType:
        raise SourceAdmissionHold("complete canonical analyzer missing")
    for name in ("literal_governed_mutation_sinks", "generic_mutation_parameter_summaries",
                 "_assert_governed_writer_is_classified"):
        fn = SUBJECT.__dict__.get(name)
        if type(fn) is not types.FunctionType or fn.__globals__ is not SUBJECT.__dict__:
            raise SourceAdmissionHold("original existing API/globals missing")
    tree = ast.parse(source, filename="<new-owned-return-" + label + ">")
    if any(isinstance(node, ast.Constant) and type(node.value) is str
           and node.value.endswith(".py") for node in ast.walk(tree)):
        raise SourceAdmissionHold("independent no-script-literal cache premise absent")
    publish = tree.body[-1]
    if not isinstance(publish, ast.FunctionDef) or publish.name != "publish":
        raise SourceAdmissionHold("original literal publish node missing")
    resolver = publish.body[0] if label == "nested-return" else tree.body[1]
    if not (isinstance(resolver, ast.FunctionDef) and resolver.name == "resolve_target"
            and len(resolver.body) == 1 and isinstance(resolver.body[0], ast.Return)):
        raise SourceAdmissionHold("original sole resolver definition/return missing")
    returned = resolver.body[0].value
    if not (isinstance(returned, ast.Call) and isinstance(returned.func, ast.Name)
            and returned.func.id == "Path" and len(returned.args) == 1
            and not returned.keywords and isinstance(returned.args[0], ast.Constant)
            and returned.args[0].value == "01-global.yaml"):
        raise SourceAdmissionHold("independent governed return literal missing")
    assignment, statement = publish.body[-2:]
    if not (isinstance(assignment, ast.Assign) and len(assignment.targets) == 1
            and isinstance(assignment.targets[0], ast.Name) and assignment.targets[0].id == "target"
            and isinstance(assignment.value, ast.Call) and isinstance(assignment.value.func, ast.Name)
            and assignment.value.func.id == "resolve_target"
            and not assignment.value.args and not assignment.value.keywords):
        raise SourceAdmissionHold("original return-to-target assignment missing")
    call = statement.value if isinstance(statement, ast.Expr) else None
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name) and call.func.value.id == "target"
            and call.func.attr == "write_text" and len(call.args) == 1
            and isinstance(call.args[0], ast.Constant) and call.args[0].value == "updated"
            and not call.keywords):
        raise SourceAdmissionHold("original target writer missing")
    original_cache = SUBJECT._GOVERNED_SCRIPT_BASENAMES
    if original_cache is not None and type(original_cache) is not set:
        raise SourceAdmissionHold("unknown original delegated cache")
    original_members = frozenset(original_cache) if original_cache is not None else None
    weak = SUBJECT._GENERIC_MUTATION_SUMMARY_CACHE
    weak_items = tuple(weak.items())
    literal_cache = set()
    result = None
    outcome = "POTENTIAL_WRITER_LOST"
    classifier_called = False
    classifier_error = False
    unresolved = False
    try:
        SUBJECT._GOVERNED_SCRIPT_BASENAMES = literal_cache
        try:
            result = SUBJECT.literal_governed_mutation_sinks(tree, RELATIVE)
        except AssertionError as error:
            if not (
                error.args and type(error.args[0]) is str
                and error.args[0].startswith("WDISC_UNRESOLVED:")
                and _from_original(error, SUBJECT.literal_governed_mutation_sinks)
            ):
                raise
            unresolved = True
            outcome = "HOLD"
        else:
            if type(result) is not set:
                raise SourceAdmissionHold("unknown original scanner result shape")
            # Require this independently specified governed caller, not a
            # harmless same-name definition or classifier(empty) rejection.
            if "publish" in result:
                classifier_called = True
                try:
                    SUBJECT._assert_governed_writer_is_classified(
                        RELATIVE, result, set(), {},
                    )
                except AssertionError as error:
                    if not _from_original(error, SUBJECT._assert_governed_writer_is_classified):
                        raise SourceAdmissionHold("foreign classifier rejection") from error
                    classifier_error = True
                    outcome = "HOLD"
                else:
                    outcome = "UNLISTED_WRITER_WAS_CLASSIFIED"
    finally:
        current = SUBJECT._GOVERNED_SCRIPT_BASENAMES
        if current is literal_cache:
            SUBJECT._GOVERNED_SCRIPT_BASENAMES = original_cache
        elif current is not original_cache:
            raise SourceAdmissionHold("foreign cache slot; do not overwrite")
        if SUBJECT._GOVERNED_SCRIPT_BASENAMES is not original_cache:
            raise SourceAdmissionHold("original cache restoration unknown")
        if original_cache is not None and frozenset(original_cache) != original_members:
            raise SourceAdmissionHold("original cache members changed")
        if SUBJECT._GENERIC_MUTATION_SUMMARY_CACHE is not weak or tuple(weak.items()) != weak_items:
            raise SourceAdmissionHold("nonNone source weak cache changed")
    fact = dict(label=label, outcome=outcome, discovered=sorted(result) if type(result) is set else None,
                classifier_called=classifier_called, original_classifier_error=classifier_error,
                original_scanner_unresolved=unresolved, cache_restored=True)
    FACTS.append(fact)
    return fact


class OwnedReturnFlowRegressionTests(unittest.TestCase):
    def test_01_module_resolver_preserves_governed_writer_control(self):
        fact = _consume(MODULE_RETURN_WRITER, "module-return")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(
            fact["outcome"], "HOLD",
            "NEW_MODULE_GOVERNED_RETURN_CONTROL_MUST_REACH_CONSUMER",
        )

    def test_02_nested_resolver_cannot_hide_governed_writer(self):
        fact = _consume(NESTED_RETURN_WRITER, "nested-return")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(
            fact["outcome"], "HOLD",
            "NEW_NESTED_GOVERNED_RETURN_MUST_NOT_BECOME_EMPTY_SAFE",
        )
