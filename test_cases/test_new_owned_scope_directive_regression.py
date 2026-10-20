"""NEW scope-directive regression through the complete existing scanner.

These source literals are AST-only. Python's global/nonlocal declarations are
explicit independent scope facts; potential mutation cannot become empty-safe.
No directive, Name, classifier rejection or integer is runtime authority.
"""
import ast
import types
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


FACTS = []
GLOBAL_PARAMETER_WRITER = (
    "import os\n"
    "def remove(destination):\n"
    "    os.unlink(destination)\n"
    "def publish():\n"
    "    global remove\n"
    "    remove('01-global.yaml')\n"
)
NONLOCAL_PARAMETER_WRITER = (
    "import os\n"
    "def build():\n"
    "    def remove(destination):\n"
    "        os.unlink(destination)\n"
    "    def publish():\n"
    "        nonlocal remove\n"
    "        remove('01-global.yaml')\n"
    "    return publish\n"
)
RELATIVE = "tools/new_owned_scope_directive_literal.py"

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
    tree = ast.parse(source, filename="<new-owned-directive-" + label + ">")
    if any(isinstance(node, ast.Constant) and type(node.value) is str
           and node.value.endswith(".py") for node in ast.walk(tree)):
        raise SourceAdmissionHold("independent no-script-literal cache premise absent")
    definitions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    publishes = [node for node in definitions if node.name == "publish"]
    mutators = [node for node in definitions if node.name == "remove"]
    if len(publishes) != 1 or len(mutators) != 1:
        raise SourceAdmissionHold("unique original publish/mutator missing")
    publish, mutator = publishes[0], mutators[0]
    if not (len(mutator.args.args) == 1 and mutator.args.args[0].arg == "destination"
            and len(mutator.body) == 1 and isinstance(mutator.body[0], ast.Expr)):
        raise SourceAdmissionHold("original sole mutation parameter missing")
    mutation = mutator.body[0].value
    if not (isinstance(mutation, ast.Call) and isinstance(mutation.func, ast.Attribute)
            and isinstance(mutation.func.value, ast.Name) and mutation.func.value.id == "os"
            and mutation.func.attr == "unlink" and len(mutation.args) == 1
            and isinstance(mutation.args[0], ast.Name) and mutation.args[0].id == "destination"
            and not mutation.keywords):
        raise SourceAdmissionHold("original parameter-to-unlink Call missing")
    directive_type = ast.Global if label == "global-control" else ast.Nonlocal
    if not (len(publish.body) == 2 and type(publish.body[0]) is directive_type
            and publish.body[0].names == ["remove"]):
        raise SourceAdmissionHold("independent scope-directive node missing")
    if label == "global-control":
        if not (mutator is tree.body[1] and publish is tree.body[2]):
            raise SourceAdmissionHold("original module scope relation missing")
    else:
        build = tree.body[1]
        if not (isinstance(build, ast.FunctionDef) and build.name == "build"
                and len(build.body) == 3 and build.body[0] is mutator
                and build.body[1] is publish and isinstance(build.body[2], ast.Return)
                and isinstance(build.body[2].value, ast.Name) and build.body[2].value.id == "publish"):
            raise SourceAdmissionHold("original enclosing nonlocal definition relation missing")
    call = publish.body[-1].value
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id == "remove" and len(call.args) == 1
            and isinstance(call.args[0], ast.Constant) and call.args[0].value == "01-global.yaml"
            and not call.keywords):
        raise SourceAdmissionHold("original governed argument/call missing")
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


class OwnedScopeDirectiveRegressionTests(unittest.TestCase):
    def test_01_global_module_mutator_keeps_governed_caller_control(self):
        fact = _consume(GLOBAL_PARAMETER_WRITER, "global-control")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(
            fact["outcome"], "HOLD",
            "NEW_GLOBAL_MODULE_MUTATOR_CONTROL_MUST_REACH_CONSUMER",
        )

    def test_02_nonlocal_owned_mutator_cannot_become_empty_safe(self):
        fact = _consume(NONLOCAL_PARAMETER_WRITER, "nonlocal-owned")
        self.assertTrue(fact["cache_restored"])
        self.assertEqual(
            fact["outcome"], "HOLD",
            "NEW_NONLOCAL_OWNED_MUTATOR_MUST_NOT_BECOME_EMPTY_SAFE",
        )
