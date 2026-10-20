"""Stop provenance cannot destroy the independently supported terminal guard."""
import ast
import unittest
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT

BODY='''
def write_authority():
    pass
def main(parser):
    try:
        stop_native_ztp_monitors('.')
    except Exception:
        parser.error('fatal')
    write_authority()
'''

class OwnedStopProvenanceTests(unittest.TestCase):
    def test_bound_stop_keeps_original_argparse_terminal_guard(self):
        source='from tools.ztp_service_runtime import stop_native_ztp_monitors\n'+BODY
        SUBJECT.assert_quiesce_structurally_precedes_reachable_sink(
            self,ast.parse(source),'main',{'write_authority'},
        )

    def test_unbound_stop_name_is_not_a_trusted_quiesce(self):
        with self.assertRaises(AssertionError):
            SUBJECT.assert_quiesce_structurally_precedes_reachable_sink(
                self,ast.parse(BODY),'main',{'write_authority'},
            )
