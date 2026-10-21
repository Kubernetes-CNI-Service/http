"""NOTRUN: transport-aware display DATA direct tests, not download/ACK permission."""
import contextlib
import copy
import io
import unittest

from test_cases.ibsw225_fixture_support.runtime_source_support import support


HOST = 'ew-spine01.example'


def measurement(transport):
    row = dict(attempt=1, bytes_downloaded=3000000, elapsed_seconds=2.0,
               average_bytes_per_second=1500000)
    if transport == 'scp':
        row.update(scp_exit=0, reserved_status=0)
    else:
        row.update(http_status=200, curl_exit=0)
    return dict(hostname=HOST, stage='os-0002', measurement=row)


def summary(record):
    # Literal display input only; no summary_groups or implementation-produced
    # expectation, no completed upgrade/device observation/owner/permit.
    return dict(mode='UPGRADE', state='UPGRADE_INCOMPLETE', result='INCOMPLETE',
        execution_state='PARTIAL', activation_state='UNKNOWN',
        selected_components=['os'], selected_ib_count=1, ready_ib_count=1,
        skipped_ib_count=0, skipped_devices=[], targets=[dict(hostname=HOST)],
        version_plan=[dict(hostname=HOST, component='os', action='UPGRADE_REQUIRED',
                           current='25.02.7002', target='25.03.1014')],
        component_results=[dict(hostname=HOST, component='os', state='UNKNOWN',
            action='NOT_VERIFIED', preflight_version='25.02.7002',
            target_version='25.03.1014', reason='INSTALLER_EXIT_NONZERO_BEFORE_REBOOT')],
        os_downloads=[record])


class DownloadTransportDisplayDirectTests(unittest.TestCase):
    def capture_bus(self, record):
        app = support(self).app
        original = copy.deepcopy(record)
        bus = app._ProgressBus()
        output, failure = io.StringIO(), None
        with contextlib.redirect_stderr(output):
            bus.emit_download(record)
            self.assertEqual('', output.getvalue(), 'emit only enqueues, never reports permission')
            try:
                bus.drain(set())
                bus.drain(set())
            except Exception as error:
                failure = error
        self.assertEqual(original, record, 'display cannot rewrite measurement facts')
        self.assertIsNone(failure, 'real drain must accept original transport fields')
        return output.getvalue()

    def render_summary(self, record):
        app = support(self).app
        report = summary(record)
        original = copy.deepcopy(report)
        text, failure = None, None
        try:
            text = app._render_summary(report)
        except Exception as error:
            failure = error
        self.assertEqual(original, report, 'summary cannot rewrite execution or transport facts')
        self.assertIsNone(failure, 'real final summary must accept original transport fields')
        return text

    def test_scp_emit_and_real_drain_report_scp_without_http_fields(self):
        record = measurement('scp')
        self.assertNotIn('http_status', record['measurement'])
        self.assertNotIn('curl_exit', record['measurement'])
        self.assertEqual(
            '[OS DOWNLOAD] ew-spine01.example os-0002 attempt=1 bytes=3000000 '
            'elapsed=2.000s avg=1.50MB/s scp-exit=0 reserved-status=0\n',
            self.capture_bus(record))

    def test_http_emit_and_real_drain_keep_original_exact_text(self):
        self.assertEqual(
            '[OS DOWNLOAD] ew-spine01.example os-0002 attempt=1 bytes=3000000 '
            'elapsed=2.000s avg=1.50MB/s http=200 curl-exit=0\n',
            self.capture_bus(measurement('http')))

    def test_scp_actual_final_summary_counts_transfer_without_http_facts(self):
        record = measurement('scp')
        self.assertNotIn('http_status', record['measurement'])
        self.assertNotIn('curl_exit', record['measurement'])
        text = self.render_summary(record)
        self.assertIn('  OS image download measurements (not installation results):\n'
                      '    Attempts=1 successful-transfers=1\n', text)
        self.assertIn(
            '    ew-spine01.example os-0002: attempt=1 3.0MB 2.000s '
            'avg=1.50MB/s SCP-exit=0 reserved-status=0\n', text)
        self.assertNotIn('HTTP=', text)
        self.assertNotIn('curl-exit=', text)
        self.assertIn('Result: INCOMPLETE\n', text)
        self.assertIn('Upgraded and verified: 0 device(s)', text)

    def test_http_actual_final_summary_keeps_original_download_text(self):
        text = self.render_summary(measurement('http'))
        self.assertIn('  OS image download measurements (not installation results):\n'
                      '    Attempts=1 successful-transfers=1\n', text)
        self.assertIn(
            '    ew-spine01.example os-0002: attempt=1 3.0MB 2.000s '
            'avg=1.50MB/s HTTP=200 curl-exit=0\n', text)
        self.assertNotIn('SCP-exit=', text)
        self.assertNotIn('reserved-status=', text)
        self.assertIn('Result: INCOMPLETE\n', text)
        self.assertIn('Upgraded and verified: 0 device(s)', text)
