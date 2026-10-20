"""NEW lexical-owner refusal-boundary contracts through the existing scanner.

The AST literals are never executed. A source summary or membership is not a
class/receiver/FD grant. The real classifier must still reject these unlisted
writer paths; a scanner's original WDISC rejection is also failclosed.
"""
import ast
import types
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


FACTS = []
UNRELATED_OWNER = (
    "import os\n"
    "def unrelated():\n"
    "    def remove(destination):\n"
    "        os.unlink(destination)\n"
    "    return None\n"
    "def publish():\n"
    "    def remove(destination):\n"
    "        return None\n"
    "    remove('01-global.yaml')\n"
)
REPEATED_LOCAL_DEFINITION = (
    "import os\n"
    "def publish():\n"
    "    def remove(destination):\n"
    "        os.unlink(destination)\n"
    "    def remove(destination):\n"
    "        return None\n"
    "    remove('01-global.yaml')\n"
)
RELATIVE = "tools/new_owned_scope_boundary_literal.py"


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
    tree = ast.parse(source, filename="<new-owned-scope-" + label + ">")
    if any(isinstance(node, ast.Constant) and type(node.value) is str
           and node.value.endswith(".py") for node in ast.walk(tree)):
        raise SourceAdmissionHold("independent no-script-literal cache premise absent")
    publish = tree.body[-1]
    if not isinstance(publish, ast.FunctionDef) or publish.name != "publish":
        raise SourceAdmissionHold("original literal publish node missing")
    call = publish.body[-1].value
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id == "remove" and len(call.args) == 1
            and isinstance(call.args[0], ast.Constant) and call.args[0].value == "01-global.yaml"):
        raise SourceAdmissionHold("original governed argument/call missing")
    original_cache = SUBJECT._GOVERNED_SCRIPT_BASENAMES
    if original_cache is not None and type(original_cache) is not set:
        raise SourceAdmissionHold("unknown original delegated cache")
    original_members = frozenset(original_cache) if original_cache is not None else None
    weak = SUBJECT._GENERIC_MUTATION_SUMMARY_CACHE
    weak_items = tuple(weak.items())
    literal_cache = set()
    result = None
    outcome = "EMPTY"
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
            # These are the two independent potential roles in the repeated
            # local literal. Never manufacture HOLD by classifying empty.
            if result & {"publish", "remove"}:
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


class OwnedSourceScopeBoundaryTests(unittest.TestCase):
    def test_01_unrelated_owner_mutator_cannot_taint_unique_local_benign_helper(self):
        fact = _consume(UNRELATED_OWNER, "unrelated-owner")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(fact["discovered"], [])
        self.assertEqual(fact["outcome"], "EMPTY")
        self.assertFalse(fact["original_scanner_unresolved"])
        self.assertFalse(fact["classifier_called"])
        self.assertFalse(fact["original_classifier_error"])

    def test_02_actual_scope_repeated_mutating_definition_cannot_be_empty_safe(self):
        fact = _consume(REPEATED_LOCAL_DEFINITION, "repeated-local")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(
            fact["outcome"], "HOLD",
            "NEW_ACTUAL_SCOPE_REPEATED_MUTATOR_MUST_NOT_BECOME_EMPTY_SAFE",
        )
