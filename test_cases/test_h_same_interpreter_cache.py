"""Independent test-side cache restoration and ordinary composition contracts.

No synthetic source body executes; no native process or writer is authorized.
The original scanner and complete original consumer methods actually execute.
"""
import io
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as scanner
from test_cases import test_new_scanner_classifier_conflict_writer as consumer


class SameInterpreterCacheTests(unittest.TestCase):
    def test_unknown_cache_shape_still_refuses_and_preserves_original_slot(self):
        previous = scanner._GOVERNED_SCRIPT_BASENAMES
        unknown = ['not-the-supported-cache-type']
        scanner._GOVERNED_SCRIPT_BASENAMES = unknown
        try:
            with self.assertRaisesRegex(consumer.SourceAdmissionHold, 'unknown original delegated cache'):
                consumer._workflow(consumer.SINGLE, 'unknown-cache')
            self.assertIs(unknown, scanner._GOVERNED_SCRIPT_BASENAMES)
            self.assertEqual(['not-the-supported-cache-type'], unknown)
        finally:
            scanner._GOVERNED_SCRIPT_BASENAMES = previous

    def test_existing_set_identity_and_members_survive_original_consumer(self):
        previous = scanner._GOVERNED_SCRIPT_BASENAMES
        original = {'literal-existing-writer.py', 'literal-other-writer.py'}
        scanner._GOVERNED_SCRIPT_BASENAMES = original
        before = frozenset(original)
        facts = []
        rejected = []
        try:
            for source, label in ((consumer.SINGLE, 'single'), (consumer.CONFLICT, 'conflict')):
                try:
                    facts.append(consumer._workflow(source, label))
                except consumer.SourceAdmissionHold as error:
                    rejected.append(str(error))
            self.assertIs(original, scanner._GOVERNED_SCRIPT_BASENAMES)
            self.assertEqual(before, frozenset(original))
            self.assertEqual([], rejected, 'KNOWN_SET_CACHE_MUST_NOT_REJECT_NORMAL_CONSUMER')
            self.assertEqual(2, len(facts))
            self.assertEqual(['HOLD', 'HOLD'], [fact['outcome'] for fact in facts])
            self.assertTrue(all(fact['restored'] for fact in facts))
        finally:
            scanner._GOVERNED_SCRIPT_BASENAMES = previous

    def test_real_predecessor_then_original_complete_consumer_in_one_interpreter(self):
        previous = scanner._GOVERNED_SCRIPT_BASENAMES
        try:
            # Either untouched state or a real earlier test's supported cache
            # is allowed. Do not reset it to arrange the predecessor/successor.
            self.assertTrue(previous is None or type(previous) is set)
            previous_members = frozenset(previous) if previous is not None else None
            predecessor = scanner.MonitorWriterQuiesceWorkflowTests(
                'test_literal_reflected_os_replace_is_not_an_undiscovered_writer')
            output = io.StringIO()
            first = unittest.TextTestRunner(stream=output, verbosity=2).run(unittest.TestSuite([predecessor]))
            self.assertTrue(first.wasSuccessful(), output.getvalue())
            original = scanner._GOVERNED_SCRIPT_BASENAMES
            self.assertIs(type(original), set, 'actual predecessor must populate delegated cache')
            if previous is not None:
                self.assertIs(previous, original)
                self.assertEqual(previous_members, frozenset(previous))
            before = frozenset(original)
            successor = consumer.AliasScannerClassifierWorkflowTests(
                'test_governed_conflicting_alias_cannot_disappear_before_real_classifier')
            second = unittest.TextTestRunner(stream=output, verbosity=2).run(unittest.TestSuite([successor]))
            self.assertIs(original, scanner._GOVERNED_SCRIPT_BASENAMES)
            self.assertEqual(before, frozenset(original))
            self.assertTrue(second.wasSuccessful(), 'ORIGINAL_TESTS_MUST_COMPOSE_WITHOUT_CACHE_RESET\n' + output.getvalue())
        finally:
            scanner._GOVERNED_SCRIPT_BASENAMES = previous
