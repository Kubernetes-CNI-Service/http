"""Independent boundaries for raising source-scope routing.

Unused declared returns do not reach the actual staging mutation destination.
A parsed nonlocal-through-global chain is unsupported AST (CP312 rejects its
compilation), not a valid runtime callee or permission to select module benign.
"""
import ast
import types
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


FACTS = []
UNUSED_DECLARED_RETURN = (
    "from pathlib import Path\n"
    "def publish():\n"
    "    global missing\n"
    "    governed_unused = Path('01-global.yaml')\n"
    "    value = missing()\n"
    "    target = Path('staging.txt')\n"
    "    target.write_text('updated')\n"
)
UNSUPPORTED_NONLOCAL_GLOBAL_CHAIN = (
    "import os\n"
    "def remove(destination):\n"
    "    return None\n"
    "def outer():\n"
    "    def remove(destination):\n"
    "        os.unlink(destination)\n"
    "    def middle():\n"
    "        global remove\n"
    "        def publish():\n"
    "            nonlocal remove\n"
    "            remove('01-global.yaml')\n"
    "        return publish\n"
    "    return middle\n"
)
RELATIVE = "tools/new_scope_routing_boundaries_literal.py"

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
    tree = ast.parse(source, filename="<new-route-boundary-" + label + ">")
    if any(isinstance(node, ast.Constant) and type(node.value) is str
           and node.value.endswith(".py") for node in ast.walk(tree)):
        raise SourceAdmissionHold("independent no-script-literal cache premise absent")
    if not any(isinstance(node, ast.Constant) and node.value == "01-global.yaml"
               for node in ast.walk(tree)):
        raise SourceAdmissionHold("independent authority literal premise missing")
    if label == "unused-missing":
        publish = tree.body[1]
        if not (isinstance(publish, ast.FunctionDef) and publish.name == "publish"
                and len(publish.body) == 5 and type(publish.body[0]) is ast.Global
                and publish.body[0].names == ["missing"]):
            raise SourceAdmissionHold("original missing declared source node absent")
        governed, unused, staging = publish.body[1:4]
        if not (isinstance(governed, ast.Assign) and len(governed.targets) == 1
                and isinstance(governed.targets[0], ast.Name) and governed.targets[0].id == "governed_unused"
                and isinstance(governed.value, ast.Call) and isinstance(governed.value.func, ast.Name)
                and governed.value.func.id == "Path" and len(governed.value.args) == 1
                and isinstance(governed.value.args[0], ast.Constant)
                and governed.value.args[0].value == "01-global.yaml"):
            raise SourceAdmissionHold("independent non-earlyreturn authority premise absent")
        if not (isinstance(unused, ast.Assign) and len(unused.targets) == 1
                and isinstance(unused.targets[0], ast.Name) and unused.targets[0].id == "value"
                and isinstance(unused.value, ast.Call) and isinstance(unused.value.func, ast.Name)
                and unused.value.func.id == "missing" and not unused.value.args and not unused.value.keywords
                and isinstance(staging, ast.Assign) and len(staging.targets) == 1
                and isinstance(staging.targets[0], ast.Name) and staging.targets[0].id == "target"
                and isinstance(staging.value, ast.Call) and isinstance(staging.value.func, ast.Name)
                and staging.value.func.id == "Path" and len(staging.value.args) == 1
                and isinstance(staging.value.args[0], ast.Constant) and staging.value.args[0].value == "staging.txt"):
            raise SourceAdmissionHold("original unused-versus-destination source distinction absent")
        call = publish.body[4].value
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name) and call.func.value.id == "target"
                and call.func.attr == "write_text" and len(call.args) == 1
                and isinstance(call.args[0], ast.Constant) and call.args[0].value == "updated"
                and not call.keywords):
            raise SourceAdmissionHold("original staging writer absent")
    else:
        benign, outer = tree.body[1:3]
        if not (isinstance(benign, ast.FunctionDef) and benign.name == "remove"
                and len(benign.body) == 1 and isinstance(benign.body[0], ast.Return)
                and isinstance(benign.body[0].value, ast.Constant) and benign.body[0].value.value is None
                and isinstance(outer, ast.FunctionDef) and outer.name == "outer" and len(outer.body) == 3):
            raise SourceAdmissionHold("original benign module and outer scope absent")
        mutator, middle = outer.body[:2]
        if not (isinstance(mutator, ast.FunctionDef) and mutator.name == "remove"
                and len(mutator.body) == 1 and isinstance(mutator.body[0], ast.Expr)
                and isinstance(middle, ast.FunctionDef) and middle.name == "middle"
                and len(middle.body) == 3 and type(middle.body[0]) is ast.Global
                and middle.body[0].names == ["remove"]):
            raise SourceAdmissionHold("original unsupported enclosing Global source absent")
        mutation = mutator.body[0].value
        publish = middle.body[1]
        if not (isinstance(mutation, ast.Call) and isinstance(mutation.func, ast.Attribute)
                and isinstance(mutation.func.value, ast.Name) and mutation.func.value.id == "os"
                and mutation.func.attr == "unlink" and len(mutation.args) == 1
                and isinstance(mutation.args[0], ast.Name) and mutation.args[0].id == "destination"
                and isinstance(publish, ast.FunctionDef) and publish.name == "publish"
                and len(publish.body) == 2 and type(publish.body[0]) is ast.Nonlocal
                and publish.body[0].names == ["remove"]):
            raise SourceAdmissionHold("original mutator/nonlocal source chain absent")
        call = publish.body[1].value
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id == "remove" and len(call.args) == 1
                and isinstance(call.args[0], ast.Constant) and call.args[0].value == "01-global.yaml"):
            raise SourceAdmissionHold("original governed call in unsupported AST absent")
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


class OwnedRoutingBoundaryTests(unittest.TestCase):
    def test_01_unused_declared_return_cannot_route_before_destination_use(self):
        fact = _consume(UNUSED_DECLARED_RETURN, "unused-missing")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(
            fact["outcome"], "EMPTY",
            "NEW_UNUSED_DECLARED_RETURN_MUST_NOT_ROUTE_WITHOUT_DESTINATION_USE",
        )

    def test_02_nonlocal_through_global_must_be_unsupported_ast_hold(self):
        fact = _consume(UNSUPPORTED_NONLOCAL_GLOBAL_CHAIN, "unsupported-chain")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(
            fact["outcome"], "HOLD",
            "NEW_UNSUPPORTED_NONLOCAL_CHAIN_MUST_NOT_SELECT_MODULE_BENIGN",
        )
