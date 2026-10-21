"""Independent UNIT/PROTOCOL literals; NOT RUN, no manager or execution permit.

Load the complete canonical component through the existing source loader. A
private coherent runner may replace SUBJECT with its complete component module;
it must not change these expectations or substitute individual functions.
No Bash/SDK/network/package/project/ACK-file write occurs in this module.
"""
from pathlib import Path
import unittest

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
SUBJECT = load_script('ibsw_upgrade_component', ROOT / 'tools' / 'ibsw_upgrade_component.py')

RUN = 'literal-scp-data'
PATH = '/srv/image.bin'
ABC_SHA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
BINDING = '1' * 64
MARKER = (b'IBSW_SCP_CONTENT_VERIFIED=1|' + BINDING.encode('ascii')
          + b'|L3Nydi9pbWFnZS5iaW4|3|' + ABC_SHA.encode('ascii'))
LINE = b'IBSW_SCP_DOWNLOAD_RESULT=1|1700000000|1700000001|0|0|3|1.000000|3.000000'
HTTP = b'IBSW_DOWNLOAD_RESULT=1|1700000000|1700000001|0|200|3|1.000000|3.000000'
PAYLOAD = MARKER + b'\n' + LINE + b'\n'


def expected_content():
    # Independent UNIT inputs, not trusted parent/request-companion evidence.
    return dict(binding_sha256=BINDING, path=PATH, size=3, sha256=ABC_SHA)


class ScpComponentDataProtocolTests(unittest.TestCase):
    def _api(self, name):
        result = getattr(SUBJECT, name, None)
        self.assertTrue(callable(result), 'SCP_DATA_PROTOCOL_CAPABILITY_MISSING:' + name)
        return result

    def test_exact_success_pair_preserves_scp_numbers_and_original_lines(self):
        parse = self._api('parse_scp_download_results')
        expected = dict(attempt=1, started_epoch=1700000000, finished_epoch=1700000001,
                        scp_exit=0, reserved_status=0, bytes_downloaded=3,
                        elapsed_seconds=1.0, average_bytes_per_second=3.0,
                        content_marker=MARKER, raw_line=LINE)
        for payload in (PAYLOAD, LINE + b'\n' + MARKER + b'\n'):
            with self.subTest(order=payload.startswith(MARKER)):
                inputs = expected_content()
                self.assertEqual(expected, parse(payload, inputs))
                self.assertEqual(expected_content(), inputs)
        self.assertNotIn('http_status', expected)
        self.assertNotIn('activation_state', expected)
        # The helper encodes UTF-8 paths, not ASCII-only source paths.
        import base64
        unicode_path = '/srv/镜像.bin'
        reference = base64.urlsafe_b64encode(unicode_path.encode('utf-8')).rstrip(b'=')
        marker = MARKER.replace(b'L3Nydi9pbWFnZS5iaW4', reference)
        inputs = expected_content(); inputs['path'] = unicode_path
        unicode_expected = dict(expected, content_marker=marker)
        self.assertEqual(unicode_expected, parse(marker + b'\n' + LINE + b'\n', inputs))
        # 1025 UTF-8 bytes is producer-supported and fits the whole packet.
        long_path = '/' + 'a' * 1024
        reference = base64.urlsafe_b64encode(long_path.encode('utf-8')).rstrip(b'=')
        marker = MARKER.replace(b'L3Nydi9pbWFnZS5iaW4', reference)
        inputs = expected_content(); inputs['path'] = long_path
        packet = marker + b'\n' + LINE + b'\n'
        self.assertEqual(1025, len(long_path.encode('utf-8')))
        self.assertLessEqual(len(packet), 4096)
        self.assertEqual(dict(expected, content_marker=marker), parse(packet, inputs))
        largest = 2**63 - 1
        marker = MARKER.replace(b'|3|', b'|' + str(largest).encode('ascii') + b'|')
        line = LINE.replace(b'|0|0|3|', b'|0|0|' + str(largest).encode('ascii') + b'|')
        inputs = expected_content(); inputs['size'] = largest
        self.assertEqual(dict(expected, bytes_downloaded=largest, content_marker=marker, raw_line=line),
                         parse(marker + b'\n' + line + b'\n', inputs))

    def test_incomplete_duplicate_foreign_and_malformed_pairs_are_refused(self):
        parse = self._api('parse_scp_download_results')
        bad = (
            b'', LINE + b'\n', MARKER + b'\n', PAYLOAD[:-1],
            PAYLOAD + b'\n', PAYLOAD + b'unrecognized-line\n',
            PAYLOAD + MARKER + b'\n', PAYLOAD + LINE + b'\n',
            MARKER + b'\n' + HTTP + b'\n',
            PAYLOAD.replace(b'CONTENT_VERIFIED=1|', b'CONTENT_VERIFIED=2|'),
            PAYLOAD.replace(b'DOWNLOAD_RESULT=1|', b'DOWNLOAD_RESULT=2|'),
            PAYLOAD.replace(b'|0|0|3|', b'|0|200|3|'),
            PAYLOAD.replace(b'|0|0|3|', b'|1|0|3|'),
            PAYLOAD.replace(b'1700000001', b'1699999999'),
            PAYLOAD.replace(b'1.000000', b'nan'),
            PAYLOAD.replace(b'3.000000', b'-3.0'),
            PAYLOAD.replace(b'3.000000', b'1e309'),
            PAYLOAD.replace(b'|0|0|3|', b'|0|0|4|'),
            PAYLOAD.replace(b'L3Nydi9pbWFnZS5iaW4', b'L3Nydi9vdGhlci5iaW4'),
            PAYLOAD.replace(b'L3Nydi9pbWFnZS5iaW4', b'L3Nydi9pbWFnZS5iaW4='),
            PAYLOAD.replace(b'|' + BINDING.encode('ascii') + b'|', b'|' + b'2' * 64 + b'|'),
            PAYLOAD.replace(ABC_SHA.encode('ascii'), b'0' * 64),
            PAYLOAD.replace(ABC_SHA.encode('ascii'), ABC_SHA.upper().encode('ascii')),
            PAYLOAD.replace(b'\n', b'\r\n'),
            b'x' * 4097, bytearray(PAYLOAD), PAYLOAD.decode('ascii'), None,
        )
        for index, value in enumerate(bad):
            with self.subTest(index=index), self.assertRaises(ValueError):
                parse(value, expected_content())
        for key, value in (('binding_sha256', '2' * 64), ('path', '/srv/other.bin'),
                           ('size', 4), ('sha256', '0' * 64), ('size', True),
                           ('size', '3'), ('size', 0), ('path', b'/srv/image.bin')):
            changed = expected_content(); changed[key] = value
            with self.subTest(expected_key=key, value=value), self.assertRaises(ValueError):
                parse(PAYLOAD, changed)
        # Matching marker/result/expected values still cannot exceed signed-63-bit size.
        for size in (0, 2**63, 10**20):
            encoded = str(size).encode('ascii')
            marker = MARKER.replace(b'|3|', b'|' + encoded + b'|')
            line = LINE.replace(b'|0|0|3|', b'|0|0|' + encoded + b'|')
            inputs = expected_content(); inputs['size'] = size
            with self.subTest(out_of_range_size=size), self.assertRaises(ValueError):
                parse(marker + b'\n' + line + b'\n', inputs)
        for value in (None, (), {}, dict(expected_content(), permission=True)):
            with self.subTest(expected_type=type(value).__name__), self.assertRaises(ValueError):
                parse(PAYLOAD, value)

    def test_v2_ack_binds_exact_marker_and_scp_numeric_line_only(self):
        ack = self._api('scp_download_ack_bytes')
        # Standard SHA-256 over this independent exact public marker, not an
        # expected value copied from the component formatter or its parser.
        import hashlib
        digest = hashlib.sha256(MARKER).hexdigest().encode('ascii')
        self.assertEqual(b'IBSW_SCP_DOWNLOAD_ACK_V2|literal-scp-data|' + digest + b'|' + LINE + b'\n',
                         ack(RUN, MARKER, LINE))
        for marker, line in ((b'', LINE), (MARKER, HTTP),
                             (MARKER + b'\n', LINE), (MARKER, LINE + b'\n'),
                             (MARKER + b'|extra', LINE),
                             (MARKER.replace(b'|3|', b'|4|'), LINE),
                             (MARKER, LINE.replace(b'|0|0|3|', b'|0|200|3|')),
                             (MARKER, LINE.replace(b'|0|0|3|', b'|9|0|3|')),
                             (MARKER, b'IBSW_DOWNLOAD_ACK_V1|literal-scp-data|' + LINE),
                             (bytearray(MARKER), LINE), (MARKER, LINE.decode('ascii'))):
            with self.subTest(marker_type=type(marker).__name__, line=line), self.assertRaises(ValueError):
                ack(RUN, marker, line)
        for size in (0, 2**63, 10**20):
            encoded = str(size).encode('ascii')
            marker = MARKER.replace(b'|3|', b'|' + encoded + b'|')
            line = LINE.replace(b'|0|0|3|', b'|0|0|' + encoded + b'|')
            with self.subTest(out_of_range_size=size), self.assertRaises(ValueError):
                ack(RUN, marker, line)
        for run_id in ('', '-bad', 'line\nbreak', 'x' * 97, 1, None):
            with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                ack(run_id, MARKER, LINE)

    def test_original_http_v1_contract_is_byte_exact_and_not_relabelled(self):
        rows = SUBJECT.parse_download_results(HTTP + b'\n')
        self.assertEqual([dict(attempt=1, started_epoch=1700000000, finished_epoch=1700000001,
                               curl_exit=0, http_status=200, bytes_downloaded=3,
                               elapsed_seconds=1.0, average_bytes_per_second=3.0,
                               raw_line=HTTP.decode('ascii'))], rows)
        self.assertEqual(b'IBSW_DOWNLOAD_ACK_V1|literal-scp-data|' + HTTP + b'\n',
                         SUBJECT.download_ack_bytes(RUN, HTTP))
        self.assertEqual([], SUBJECT.parse_download_results(PAYLOAD))
        # The old generic V1 formatter is intentionally unchanged. It does not
        # confer SCP authority; only future caller selection may use new V2.
        self.assertEqual(b'IBSW_DOWNLOAD_ACK_V1|literal-scp-data|' + LINE + b'\n',
                         SUBJECT.download_ack_bytes(RUN, LINE))


if __name__ == '__main__':
    unittest.main()
