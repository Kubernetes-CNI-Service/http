"""NEW current-source regression; not restoration of H28 or missing H55.

Only literal ASTs and the received analyzer's original alias API are used.
The bounded dict double diagnoses state iteration, not native execution or
termination of an uninstrumented infinite loop. No class/writer authority is
granted by the exact-alias projection tested here.
"""
import ast
import types
import unittest


from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT
OBSERVATIONS = []
_MISSING = object()
_REAL_DICT = dict

SAME_CANONICAL = "import os\nalias = os.unlink\nalias = os.unlink\n"
CONFLICTING_CANONICALS = "import os\nalias = os.unlink\nalias = os.remove\n"


class SourceAdmissionHold(RuntimeError):
    """A missing source/API premise is not the alias assertion RED."""


class _WriteBudgetStop(BaseException):
    pass


def _received():
    if type(SUBJECT) is not types.ModuleType:
        raise SourceAdmissionHold("received complete analyzer module absent")
    for name in (
        "_mutation_aliases", "_extend_mutation_aliases",
        "_literal_reflected_mutation", "_walk_local_scope", "_assigned_names",
    ):
        fn = SUBJECT.__dict__.get(name)
        if type(fn) is not types.FunctionType or fn.__globals__ is not SUBJECT.__dict__:
            raise SourceAdmissionHold("original alias helper/global premise absent")
    return SUBJECT


def _probe(source, label):
    subject = _received()
    tree = ast.parse(source, filename="<new-current679d-alias-" + label + ">")
    sentinel = _WriteBudgetStop("one held bounded-iteration sentinel")
    counter = {"writes": 0}

    class BoundedAliases(_REAL_DICT):
        def __setitem__(self, key, value):
            counter["writes"] += 1
            if counter["writes"] > 32:
                raise sentinel
            return _REAL_DICT.__setitem__(self, key, value)

    original = subject.__dict__.get("dict", _MISSING)
    result = None
    completed = False
    sentinel_seen = False
    try:
        subject.__dict__["dict"] = BoundedAliases
        try:
            result = subject._mutation_aliases(tree)
            completed = True
        except _WriteBudgetStop as error:
            if error is not sentinel:
                raise SourceAdmissionHold("foreign iteration sentinel") from error
            sentinel_seen = True
    finally:
        if subject.__dict__.get("dict", _MISSING) is not BoundedAliases:
            raise SourceAdmissionHold("received dict slot changed unexpectedly")
        if original is _MISSING:
            del subject.__dict__["dict"]
        else:
            subject.__dict__["dict"] = original
        if subject.__dict__.get("dict", _MISSING) is not original:
            raise SourceAdmissionHold("received dict slot restoration uncertain")
    if completed and not isinstance(result, _REAL_DICT):
        raise SourceAdmissionHold("alias projection is not the existing dict API")
    fact = {
        "label": label,
        "completed": completed,
        "sentinel_seen": sentinel_seen,
        "writes": counter["writes"],
        "dict_binding_restored": True,
    }
    OBSERVATIONS.append(fact)
    return result, fact


class CurrentSourceAliasFixedPointTests(unittest.TestCase):
    def test_02_conflicting_canonicals_finish_without_unique_exact_alias(self):
        result, fact = _probe(CONFLICTING_CANONICALS, "conflicting")
        self.assertTrue(fact["dict_binding_restored"])
        self.assertLessEqual(fact["writes"], 33)
        exact_alias = result.get("alias") if fact["completed"] else None
        # No assertion requires an ambiguous call to disappear from discovery.
        # A later consumer contract must retain potential mutation or HOLD.
        self.assertEqual(
            (fact["completed"], exact_alias),
            (True, None),
            "NEW_ALIAS_CONFLICT_MUST_FINISH_WITHOUT_UNIQUE_EXACT_PROOF",
        )

    def test_01_identical_canonical_assignments_reach_literal_fixed_point(self):
        result, fact = _probe(SAME_CANONICAL, "identical")
        self.assertTrue(fact["dict_binding_restored"])
        self.assertFalse(fact["sentinel_seen"])
        self.assertTrue(fact["completed"])
        self.assertLessEqual(fact["writes"], 32)
        self.assertEqual(
            result,
            {"os": "os", "alias": "os.unlink"},
            "NEW_IDENTICAL_CANONICAL_MUST_REACH_LITERAL_FIXED_POINT",
        )
