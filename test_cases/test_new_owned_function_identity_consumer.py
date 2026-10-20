"""NEW lexical-owner source contract through existing original APIs only.

Literal bodies are parsed, never executed. No new index API, Frame, FD,
provider grant or class permission is manufactured. The consumer scenario
must not treat an empty discovery result as safe/classified.
"""
import ast
import types
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT


FACTS = []
GLOBAL_CONTROL = (
    "def emit():\n"
    "    return None\n"
    "class Display:\n"
    "    def show(self):\n"
    "        return None\n"
)
GLOBAL_COLLISION = (
    "def emit():\n"
    "    return None\n"
    "class Display:\n"
    "    def emit(self):\n"
    "        return None\n"
)
CLASS_CONTROL = (
    "import os\n"
    "class Writer:\n"
    "    def emit(self):\n"
    "        destination = '01-global.yaml'\n"
    "        os.unlink(destination)\n"
    "def entry():\n"
    "    owner = Writer()\n"
    "    owner.emit()\n"
)
CLASS_COLLISION = (
    "import os\n"
    "class Writer:\n"
    "    def emit(self):\n"
    "        destination = '01-global.yaml'\n"
    "        os.unlink(destination)\n"
    "class Display:\n"
    "    def emit(self):\n"
    "        return None\n"
    "def entry():\n"
    "    owner = Writer()\n"
    "    owner.emit()\n"
)
RELATIVE = "tools/new_owned_function_literal.py"


class SourceAdmissionHold(RuntimeError):
    pass


def _received():
    if type(SUBJECT) is not types.ModuleType:
        raise SourceAdmissionHold("complete canonical analyzer missing")
    for name in (
        "production_functions", "literal_governed_mutation_sinks",
        "generic_mutation_parameter_summaries",
        "_assert_governed_writer_is_classified",
    ):
        fn = SUBJECT.__dict__.get(name)
        if type(fn) is not types.FunctionType or fn.__globals__ is not SUBJECT.__dict__:
            raise SourceAdmissionHold("existing full-module API/global premise missing")
    return SUBJECT


def _original_error(error, fn):
    tb = error.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code is fn.__code__ and tb.tb_frame.f_globals is fn.__globals__:
            return True
        tb = tb.tb_next
    return False


def _scan_consume(source, label):
    subject = _received()
    tree = ast.parse(source, filename="<new-owned-consumer-" + label + ">")
    if any(
        isinstance(node, ast.Constant) and type(node.value) is str
        and node.value.endswith(".py") for node in ast.walk(tree)
    ):
        raise SourceAdmissionHold("independent no-script-literal cache premise absent")
    owner = tree.body[1]
    method = owner.body[0]
    mutation = method.body[1].value
    if not (
        isinstance(owner, ast.ClassDef) and owner.name == "Writer"
        and isinstance(method, ast.FunctionDef) and method.name == "emit"
        and isinstance(mutation, ast.Call)
        and isinstance(mutation.func, ast.Attribute) and mutation.func.attr == "unlink"
        and isinstance(mutation.func.value, ast.Name) and mutation.func.value.id == "os"
    ):
        raise SourceAdmissionHold("literal original owner/mutation node premise absent")
    original_cache = subject._GOVERNED_SCRIPT_BASENAMES
    if original_cache is not None and (
        type(original_cache) is not set
        or not all(type(name) is str for name in original_cache)
    ):
        raise SourceAdmissionHold("foreign delegated-cache state")
    original_members = frozenset(original_cache) if original_cache is not None else None
    weak = subject._GENERIC_MUTATION_SUMMARY_CACHE
    weak_items = tuple(weak.items())
    literal_cache = set()
    outcome = "POTENTIAL_WRITER_LOST"
    discovered = None
    classifier_called = False
    classifier_error = False
    scanner_unresolved = False
    try:
        subject._GOVERNED_SCRIPT_BASENAMES = literal_cache
        try:
            discovered = subject.literal_governed_mutation_sinks(tree, RELATIVE)
        except AssertionError as error:
            if (
                type(error.args[0] if error.args else None) is str
                and error.args[0].startswith("WDISC_UNRESOLVED:")
                and _original_error(error, subject.literal_governed_mutation_sinks)
            ):
                scanner_unresolved = True
                outcome = "HOLD"
            else:
                raise
        else:
            # This is the real W1 empty-result behavior, not a call to a
            # classifier that would reject even an artificially empty set.
            if type(discovered) is not set:
                raise SourceAdmissionHold("foreign existing scanner result shape")
            # W1 dispatches every nonempty discovered set, including original
            # owner-qualified labels; an empty result must still be lost.
            if discovered:
                classifier_called = True
                try:
                    subject._assert_governed_writer_is_classified(
                        RELATIVE, discovered, set(), {},
                    )
                except AssertionError as error:
                    if not _original_error(error, subject._assert_governed_writer_is_classified):
                        raise SourceAdmissionHold("foreign classifier rejection") from error
                    classifier_error = True
                    outcome = "HOLD"
                else:
                    outcome = "UNPROVED_CLASS_WAS_CLASSIFIED"
    finally:
        current = subject._GOVERNED_SCRIPT_BASENAMES
        if current is literal_cache:
            subject._GOVERNED_SCRIPT_BASENAMES = original_cache
        elif current is not original_cache:
            raise SourceAdmissionHold("foreign cache slot; do not overwrite")
        if subject._GOVERNED_SCRIPT_BASENAMES is not original_cache:
            raise SourceAdmissionHold("cache restoration unknown")
        if original_cache is not None and frozenset(original_cache) != original_members:
            raise SourceAdmissionHold("original cache contents changed")
        if subject._GENERIC_MUTATION_SUMMARY_CACHE is not weak or tuple(weak.items()) != weak_items:
            raise SourceAdmissionHold("nonNone-source-path weak-cache premise changed")
    fact = {
        "label": label, "outcome": outcome,
        "discovered": sorted(discovered) if type(discovered) is set else None,
        "classifier_called": classifier_called,
        "original_classifier_error": classifier_error,
        "original_scanner_unresolved": scanner_unresolved,
        "cache_restored": True,
    }
    FACTS.append(fact)
    return fact


class OwnedFunctionIdentityTests(unittest.TestCase):
    def test_01_class_method_does_not_overwrite_original_module_function(self):
        subject = _received()
        control = ast.parse(GLOBAL_CONTROL, filename="<new-global-owner-control>")
        original = control.body[0]
        self.assertIs(subject.production_functions(control)["emit"], original)
        collision = ast.parse(GLOBAL_COLLISION, filename="<new-global-owner-collision>")
        module_function = collision.body[0]
        class_method = collision.body[1].body[0]
        self.assertIsNot(module_function, class_method)
        self.assertIsInstance(module_function, ast.FunctionDef)
        self.assertIsInstance(class_method, ast.FunctionDef)
        selected = subject.production_functions(collision)["emit"]
        FACTS.append({"label": "module-lookup", "original_module_selected": selected is module_function})
        self.assertTrue(
            selected is module_function,
            "NEW_MODULE_LOOKUP_MUST_NOT_SELECT_SAME_NAMED_CLASS_METHOD",
        )

    def test_02_colliding_class_writer_still_reaches_real_failclosed_consumer(self):
        control = _scan_consume(CLASS_CONTROL, "unique-class")
        self.assertEqual(control["outcome"], "HOLD", "NEW_UNIQUE_CLASS_CONTROL_MUST_RETAIN_POTENTIAL")
        self.assertTrue(control["cache_restored"])
        collision = _scan_consume(CLASS_COLLISION, "colliding-class")
        self.assertTrue(collision["cache_restored"])
        self.assertEqual(
            collision["outcome"], "HOLD",
            "NEW_OWNED_WRITER_MUST_NOT_DISAPPEAR_BEFORE_REAL_CLASSIFIER",
        )
