"""NEW finite regression SOURCE, not historical H28/H55 restoration.

Run only the received monotone candidate after source admission. In particular,
do not run these conflicting literals against the known-unbounded baseline.
No dict double, sentinel, implementation iteration limit, or product body exec
is used. Completing these finite cases is not a proof for every Python program.
"""
import ast
import types
import unittest


from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT
OBSERVATIONS = []

REPEATED = "import os\nalias = os.unlink\nalias = os.unlink\n"
FORWARD = (
    "import os\na = b\nb = c\nc = d\nd = e\ne = f\nf = g\ng = h\n"
    "h = os.unlink\n"
)
REVERSE = (
    "import os\nh = os.unlink\ng = h\nf = g\ne = f\nd = e\nc = d\nb = c\n"
    "a = b\n"
)
UNUSED_CONFLICT = "import os\nalias = os.unlink\nalias = os.remove\n"
INHERITED_CONFLICT = (
    "import os\nalias = os.unlink\nalias = os.remove\n"
    "def mutate(destination):\n"
    "    relay = alias\n"
    "    relay(destination)\n"
)


class SourceAdmissionHold(RuntimeError):
    pass


def _received():
    if type(SUBJECT) is not types.ModuleType:
        raise SourceAdmissionHold("complete received analyzer absent")
    if "dict" in SUBJECT.__dict__:
        raise SourceAdmissionHold("no-instrumentation dict-binding premise absent")
    for name in (
        "_mutation_aliases", "_extend_mutation_aliases",
        "generic_mutation_parameter_summaries",
    ):
        fn = SUBJECT.__dict__.get(name)
        if type(fn) is not types.FunctionType or fn.__globals__ is not SUBJECT.__dict__:
            raise SourceAdmissionHold("whole-source function/global premise absent")
    return SUBJECT


class UninstrumentedFiniteAliasClosureTests(unittest.TestCase):
    def test_finite_alias_closure_and_inherited_conflict_without_dict_double(self):
        subject = _received()
        cache = subject._GENERIC_MUTATION_SUMMARY_CACHE
        before_cache = tuple(cache.items())
        before_delegated = subject._GOVERNED_SCRIPT_BASENAMES
        before_root = subject.ROOT
        cases = (
            ("repeat", REPEATED, {"os": "os", "alias": "os.unlink"}),
            ("forward", FORWARD, {
                "os": "os", "a": "os.unlink", "b": "os.unlink",
                "c": "os.unlink", "d": "os.unlink", "e": "os.unlink",
                "f": "os.unlink", "g": "os.unlink", "h": "os.unlink",
            }),
            ("reverse", REVERSE, {
                "os": "os", "a": "os.unlink", "b": "os.unlink",
                "c": "os.unlink", "d": "os.unlink", "e": "os.unlink",
                "f": "os.unlink", "g": "os.unlink", "h": "os.unlink",
            }),
            ("unused-conflict", UNUSED_CONFLICT, {"os": "os"}),
        )
        for label, source, expected in cases:
            tree = ast.parse(source, filename="<new-uninstrumented-" + label + ">")
            actual = subject._mutation_aliases(tree)
            self.assertEqual(actual, expected, "NEW_FINITE_ALIAS_PROJECTION_" + label)
            self.assertNotIn("dict", subject.__dict__)
            OBSERVATIONS.append({"label": label, "returned": True})

        tree = ast.parse(INHERITED_CONFLICT, filename="<new-inherited-conflict>")
        error = None
        try:
            subject.generic_mutation_parameter_summaries(
                tree, "tools/new_uninstrumented_alias_literal.py",
            )
        except AssertionError as caught:
            error = caught
        self.assertIsNotNone(error, "NEW_INHERITED_AMBIGUITY_MUST_NOT_DISAPPEAR")
        self.assertEqual(
            error.args, ("WDISC_UNRESOLVED: ambiguous mutation alias", "relay"),
            "NEW_INHERITED_AMBIGUITY_MUST_REMAIN_EXPLICIT_HOLD",
        )
        frame = error.__traceback__
        actual_generic = False
        while frame is not None:
            if (
                frame.tb_frame.f_code
                is subject.generic_mutation_parameter_summaries.__code__
                and frame.tb_frame.f_globals is subject.__dict__
            ):
                actual_generic = True
            frame = frame.tb_next
        self.assertTrue(actual_generic, "NEW_HOLD_MUST_COME_FROM_ACTUAL_GENERIC")
        self.assertIs(subject._GENERIC_MUTATION_SUMMARY_CACHE, cache)
        self.assertEqual(tuple(cache.items()), before_cache)
        self.assertIs(subject._GOVERNED_SCRIPT_BASENAMES, before_delegated)
        self.assertIs(subject.ROOT, before_root)
        self.assertNotIn("dict", subject.__dict__)
        OBSERVATIONS.append({
            "label": "inherited-conflict", "actual_generic_hold": True,
            "cache_unchanged": True, "dict_double": False,
        })
