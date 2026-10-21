"""NOTRUN: direct public stdout selection only, not a manager/ACK authority proof."""
import unittest

from test_cases.ibsw225_fixture_support.runtime_source_support import support


# All protocol expectations below are fixed literal DATA, not formatter/parser output.
HEADER = (b'["run-1","ew-spine01.example","192.0.2.1","02:00:00:00:00:01",'
          b'"os","25.03.1010"]\n')
PROGRESS = b'IBSW_STAGE=PACKAGE_DOWNLOAD\nIBSW_STAGE=WAIT_DOWNLOAD_RECORD\n'
CONTENT = (b'IBSW_SCP_CONTENT_VERIFIED=1|'
           b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|'
           b'L2ltYWdlLmJpbg|22|'
           b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')
NUMERIC = b'IBSW_SCP_DOWNLOAD_RESULT=1|100|102|0|0|22|2.0|11.0'
PACKET = CONTENT + b'\n' + NUMERIC + b'\n'


class ScpStdoutPacketDirectTests(unittest.TestCase):
    def subject(self):
        # Complete normal canonical runtime bootstrap; no registry replacement,
        # single-module loader, test class import, network or project fixture.
        runtime = support(self)
        self.assertTrue(callable(getattr(runtime.executor, '_scp_download_packet', None)),
                        'MISSING_SCP_STDOUT_PACKET_SELECTOR capability; parser body NOT_REACHED')
        return runtime.executor._scp_download_packet

    def test_literal_pair_both_orders_and_incomplete_facts(self):
        select = self.subject()
        for body in (CONTENT + b'\n' + NUMERIC + b'\n',
                     NUMERIC + b'\n' + CONTENT + b'\n'):
            with self.subTest(order=body.startswith(CONTENT)):
                self.assertEqual(PACKET, select(HEADER + PROGRESS + body + b'ordinary progress\n'))
        for body in (
                b'ordinary progress\n', CONTENT + b'\n', NUMERIC + b'\n',
                CONTENT, NUMERIC,
                CONTENT + b'\n' + NUMERIC,
                NUMERIC + b'\n' + CONTENT,
                PACKET + b'IBSW_SCP_CONTENT_VERIFIED=1|still-growing'):
            with self.subTest(incomplete=body):
                self.assertIsNone(select(HEADER + PROGRESS + body))

    def test_every_complete_reserved_candidate_refuses_before_or_after_healthy_pair(self):
        select = self.subject()
        bad_complete = (
            b'IBSW_SCP_UNKNOWN=1\n',
            b'IBSW_SCP_ERROR=TRANSFER_FAILED\n',
            b'IBSW_SCP_CONTENT_VERIFIED=\n',
            b'IBSW_SCP_DOWNLOAD_RESULT=\n',
            CONTENT.replace(b'=1|', b'=2|', 1) + b'\n',
            CONTENT + b'|extra\n',
            NUMERIC.replace(b'|0|0|22|', b'|1|0|22|', 1) + b'\n',
            NUMERIC + b'|extra\n',
            CONTENT + b'\n',
            NUMERIC + b'\n',
        )
        for bad in bad_complete:
            for payload in (HEADER + bad + PACKET, HEADER + PACKET + bad):
                with self.subTest(candidate=bad, before=payload.startswith(HEADER + bad)):
                    with self.assertRaises(ValueError):
                        select(payload)
        for payload in (
                HEADER + CONTENT + b'\r\n' + NUMERIC + b'\n',
                HEADER + CONTENT + b'\n' + NUMERIC + b'\r\n',
                b'x' * (512 * 1024 + 1),
                None, '', bytearray(PACKET), memoryview(PACKET), 1):
            with self.subTest(invalid_type_or_bound=type(payload).__name__):
                with self.assertRaises(ValueError):
                    select(payload)
