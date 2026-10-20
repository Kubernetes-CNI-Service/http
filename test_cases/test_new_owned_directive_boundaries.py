"""Independent source-scope directive refusal boundaries.

Nonlocal lookup stops at the nearest enclosing function binding. Global lookup
uses the module binding rather than an intervening nested mutator. These two
fixed AST literals must be empty; no body/runtime/callee authority is executed.
"""
import ast
import types
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


FACTS = []
NONLOCAL_NEAREST_BENIGN = (
    "import os\n"
    "def outer():\n"
    "    def remove(destination):\n"
    "        os.unlink(destination)\n"
    "    def middle():\n"
    "        def remove(destination):\n"
    "            return None\n"
    "        def publish():\n"
    "            nonlocal remove\n"
    "            remove('01-global.yaml')\n"
    "        return publish\n"
    "    return middle\n"
)
GLOBAL_MODULE_BENIGN = (
    "import os\n"
    "def remove(destination):\n"
    "    return None\n"
    "def outer():\n"
    "    def remove(destination):\n"
    "        os.unlink(destination)\n"
    "    def publish():\n"
    "        global remove\n"
    "        remove('01-global.yaml')\n"
    "    return publish\n"
)
RELATIVE = "tools/new_owned_directive_boundary_literal.py"

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
    tree = ast.parse(source, filename="<new-directive-boundary-" + label + ">")
    if any(isinstance(node, ast.Constant) and type(node.value) is str
           and node.value.endswith(".py") for node in ast.walk(tree)):
        raise SourceAdmissionHold("independent no-script-literal cache premise absent")
    if label == "nonlocal-nearest":
        outer = tree.body[1]
        if not (isinstance(outer, ast.FunctionDef) and outer.name == "outer" and len(outer.body) == 3):
            raise SourceAdmissionHold("original outer source missing")
        mutator, middle = outer.body[:2]
        if not (isinstance(middle, ast.FunctionDef) and middle.name == "middle" and len(middle.body) == 3):
            raise SourceAdmissionHold("original nearest enclosing function missing")
        callee, publish = middle.body[:2]
        if not (isinstance(outer.body[2], ast.Return) and isinstance(outer.body[2].value, ast.Name)
                and outer.body[2].value.id == "middle" and isinstance(middle.body[2], ast.Return)
                and isinstance(middle.body[2].value, ast.Name) and middle.body[2].value.id == "publish"):
            raise SourceAdmissionHold("original nested owner membership missing")
        directive_type = ast.Nonlocal
    else:
        callee, outer = tree.body[1:3]
        if not (isinstance(outer, ast.FunctionDef) and outer.name == "outer" and len(outer.body) == 3):
            raise SourceAdmissionHold("original intervening owner missing")
        mutator, publish = outer.body[:2]
        if not (isinstance(outer.body[2], ast.Return) and isinstance(outer.body[2].value, ast.Name)
                and outer.body[2].value.id == "publish"):
            raise SourceAdmissionHold("original publish owner membership missing")
        directive_type = ast.Global
    if not (isinstance(callee, ast.FunctionDef) and callee.name == "remove"
            and len(callee.args.args) == 1 and callee.args.args[0].arg == "destination"
            and len(callee.body) == 1 and isinstance(callee.body[0], ast.Return)
            and isinstance(callee.body[0].value, ast.Constant) and callee.body[0].value.value is None
            and isinstance(mutator, ast.FunctionDef) and mutator.name == "remove"
            and mutator is not callee and len(mutator.args.args) == 1
            and mutator.args.args[0].arg == "destination" and len(mutator.body) == 1
            and isinstance(mutator.body[0], ast.Expr)):
        raise SourceAdmissionHold("independent benign-versus-mutating definitions missing")
    mutation = mutator.body[0].value
    if not (isinstance(mutation, ast.Call) and isinstance(mutation.func, ast.Attribute)
            and isinstance(mutation.func.value, ast.Name) and mutation.func.value.id == "os"
            and mutation.func.attr == "unlink" and len(mutation.args) == 1
            and isinstance(mutation.args[0], ast.Name) and mutation.args[0].id == "destination"
            and not mutation.keywords):
        raise SourceAdmissionHold("original other-scope mutator missing")
    if not (isinstance(publish, ast.FunctionDef) and publish.name == "publish"
            and len(publish.body) == 2 and type(publish.body[0]) is directive_type
            and publish.body[0].names == ["remove"] and isinstance(publish.body[1], ast.Expr)):
        raise SourceAdmissionHold("original exact directive/caller missing")
    call = publish.body[1].value
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id == "remove" and len(call.args) == 1
            and isinstance(call.args[0], ast.Constant) and call.args[0].value == "01-global.yaml"
            and not call.keywords):
        raise SourceAdmissionHold("original governed argument Call missing")
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
            if result:
                outcome = "OTHER_POTENTIAL"
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


class OwnedDirectiveBoundaryTests(unittest.TestCase):
    def test_01_nonlocal_nearest_benign_binding_blocks_farther_mutator(self):
        fact = _consume(NONLOCAL_NEAREST_BENIGN, "nonlocal-nearest")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(fact["discovered"], [])
        self.assertEqual(
            fact["outcome"], "EMPTY",
            "NEW_NONLOCAL_MUST_STOP_AT_NEAREST_ENCLOSING_BINDING",
        )

    def test_02_global_benign_module_binding_blocks_enclosing_mutator(self):
        fact = _consume(GLOBAL_MODULE_BENIGN, "global-module")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(fact["discovered"], [])
        self.assertEqual(
            fact["outcome"], "EMPTY",
            "NEW_GLOBAL_MUST_NOT_BORROW_ENCLOSING_MUTATOR",
        )
