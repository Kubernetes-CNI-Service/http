"""NEW test-side scanner/consumer scenario, not a native workflow proof.

The exact existing overall scanner and classifier functions really execute.
Neither literal body executes. No Frame/FD ticket, writer permission, class
report API, historical H55 body or repository-inventory proof is created.
"""
import ast
import types
import unittest

from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT
OBSERVATIONS = []
_MISSING = object()
_REAL_DICT = dict
RELATIVE = "tools/new_alias_consumer_literal.py"
SINGLE = (
    "import os\n"
    "def mutate():\n"
    "    destination = '01-global.yaml'\n"
    "    alias = os.unlink\n"
    "    alias(destination)\n"
)
CONFLICT = (
    "import os\n"
    "def mutate():\n"
    "    destination = '01-global.yaml'\n"
    "    alias = os.unlink\n"
    "    alias = os.remove\n"
    "    alias(destination)\n"
)
CLASSIFIER_MESSAGE = (
    "unclassified governed mutation sink in tools/new_alias_consumer_literal.py: "
    "local={'mutate'}, imported=set()"
)


class SourceAdmissionHold(RuntimeError):
    pass


class _BudgetStop(BaseException):
    pass


def _workflow(source, label):
    subject = SUBJECT
    if type(subject) is not types.ModuleType:
        raise SourceAdmissionHold("complete current analyzer module missing")
    for name in (
        "literal_governed_mutation_sinks", "generic_mutation_parameter_summaries",
        "_assert_governed_writer_is_classified", "_mutation_aliases",
        "_extend_mutation_aliases", "_delegated_governed_script_constants",
    ):
        fn = subject.__dict__.get(name)
        if type(fn) is not types.FunctionType or fn.__globals__ is not subject.__dict__:
            raise SourceAdmissionHold("actual original scanner/consumer premise missing")
    tree = ast.parse(source, filename="<new-scanner-consumer-" + label + ">")
    if any(
        type(node.value) is str and node.value.endswith(".py")
        for node in ast.walk(tree) if isinstance(node, ast.Constant)
    ):
        raise SourceAdmissionHold("literal may depend on delegated script discovery")
    old_cache = subject._GOVERNED_SCRIPT_BASENAMES
    if old_cache is not None and type(old_cache) is not set:
        raise SourceAdmissionHold("unknown original delegated cache")
    old_members = frozenset(old_cache) if old_cache is not None else None
    literal_empty_cache = set()
    old_dict = subject.__dict__.get("dict", _MISSING)
    weakcache = subject._GENERIC_MUTATION_SUMMARY_CACHE
    old_items = list(weakcache.items())
    sentinel = _BudgetStop("single held iteration bound")
    counter = {"attempts": 0}

    class BoundedAliases(_REAL_DICT):
        def __setitem__(self, key, value):
            counter["attempts"] += 1
            if counter["attempts"] > 32:
                raise sentinel
            return _REAL_DICT.__setitem__(self, key, value)

    fact = {
        "label": label, "outcome": "NOT_COMPLETED", "scanner_completed": False,
        "discovered": None, "classifier_called": False,
        "original_classifier_error": False, "scanner_unresolved": False,
        "sentinel_seen": False, "write_attempts": 0, "restored": False,
    }
    try:
        subject.__dict__["dict"] = BoundedAliases
        subject._GOVERNED_SCRIPT_BASENAMES = literal_empty_cache
        try:
            discovered = subject.literal_governed_mutation_sinks(tree, RELATIVE)
        except _BudgetStop as error:
            if error is not sentinel:
                raise SourceAdmissionHold("foreign sentinel") from error
            fact["sentinel_seen"] = True
            fact["outcome"] = "ITERATION_NOT_FINISHED"
        except AssertionError as error:
            # A future scanner may explicitly reject unresolved mutation.
            # It must be the real scanner's own error path, not the budget.
            tb = error.__traceback__
            own_frame = False
            while tb is not None:
                own_frame |= (
                    tb.tb_frame.f_code is subject.literal_governed_mutation_sinks.__code__
                    and tb.tb_frame.f_globals is subject.__dict__
                )
                tb = tb.tb_next
            if not (
                own_frame and error.args and type(error.args[0]) is str
                and error.args[0].startswith("WDISC_UNRESOLVED:")
            ):
                raise
            fact["scanner_unresolved"] = True
            fact["outcome"] = "HOLD"
        else:
            if type(discovered) is not set:
                raise SourceAdmissionHold("existing scanner set API missing")
            fact["scanner_completed"] = True
            fact["discovered"] = sorted(discovered)
            if discovered != {"mutate"}:
                # Never manufacture HOLD by calling the classifier with an
                # empty set which real W1 would skip before consumption.
                fact["outcome"] = "POTENTIAL_WRITER_NOT_RETAINED"
            else:
                fact["classifier_called"] = True
                try:
                    subject._assert_governed_writer_is_classified(
                        RELATIVE, discovered, set(), {},
                    )
                except AssertionError as error:
                    if error.args != (CLASSIFIER_MESSAGE,):
                        raise
                    tb = error.__traceback__
                    own_frame = False
                    while tb is not None:
                        own_frame |= (
                            tb.tb_frame.f_code is subject._assert_governed_writer_is_classified.__code__
                            and tb.tb_frame.f_globals is subject.__dict__
                        )
                        tb = tb.tb_next
                    if not own_frame:
                        raise SourceAdmissionHold("classifier error not from original function")
                    fact["original_classifier_error"] = True
                    fact["outcome"] = "HOLD"
                else:
                    fact["outcome"] = "UNCLASSIFIED_WRITER_WAS_ACCEPTED"
    finally:
        known = True
        if subject.__dict__.get("dict", _MISSING) is BoundedAliases:
            if old_dict is _MISSING:
                del subject.__dict__["dict"]
            else:
                subject.__dict__["dict"] = old_dict
        else:
            known = False
        if subject._GOVERNED_SCRIPT_BASENAMES is literal_empty_cache and not literal_empty_cache:
            subject._GOVERNED_SCRIPT_BASENAMES = old_cache
        else:
            known = False
        known &= subject.__dict__.get("dict", _MISSING) is old_dict
        known &= subject._GOVERNED_SCRIPT_BASENAMES is old_cache
        known &= old_cache is None or frozenset(old_cache) == old_members
        known &= subject._GENERIC_MUTATION_SUMMARY_CACHE is weakcache
        known &= list(weakcache.items()) == old_items
        if not known:
            raise SourceAdmissionHold("literal fixture slot/cache restoration UNKNOWN")
        fact["restored"] = True
        fact["write_attempts"] = counter["attempts"]
        OBSERVATIONS.append(fact)
    return fact


class AliasScannerClassifierWorkflowTests(unittest.TestCase):
    def test_governed_conflicting_alias_cannot_disappear_before_real_classifier(self):
        control = _workflow(SINGLE, "single")
        self.assertTrue(control["restored"])
        self.assertTrue(control["scanner_completed"])
        self.assertEqual(control["discovered"], ["mutate"])
        self.assertTrue(control["classifier_called"])
        self.assertTrue(control["original_classifier_error"])
        self.assertFalse(control["sentinel_seen"])
        self.assertEqual(control["outcome"], "HOLD")
        conflict = _workflow(CONFLICT, "conflicting")
        self.assertTrue(conflict["restored"])
        self.assertLessEqual(conflict["write_attempts"], 33)
        self.assertEqual(
            conflict["outcome"], "HOLD",
            "NEW_GOVERNED_CONFLICT_MUST_RETAIN_WRITER_OR_FAIL_CLOSED",
        )
