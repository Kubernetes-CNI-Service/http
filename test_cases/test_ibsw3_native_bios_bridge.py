"""SOURCE ONLY BIOS direct + real native workflow; no test has been run."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from test_cases import native_bios_safe_image as GATE
from test_cases import native_bios_flow as FLOW
from test_cases import native_bios_isolation as ISOLATION

PACKAGE = '0ACQF.cab'
PACKAGE_BYTES = b'SYNTHETIC-NOT-FIRMWARE'
PACKAGE_SHA = 'd6dae7bf679709c175a9debecedc655878142fefc0a916149592a6f56d6996af'


class NativeBiosBridgeTests(unittest.TestCase):
    def test_bios_two_site_image_inverse_and_step_guard_are_finite(self):
        self.assertEqual(56, len(GATE.COPY_FILES))
        self.assertEqual(56, len(set(GATE.COPY_FILES)))
        self.assertEqual(('test_cases.test_ibsw3_native_bios_bridge.NativeBiosBridgeTests.test_native_bios_real_dispatch_exit93_and_companion_drift_before_send',), ISOLATION.ROSTER)
        source = Path(GATE.__file__).resolve().parents[1]
        provider = GATE._read(source / GATE.PROVIDER)
        template = GATE._read(source / GATE.TEMPLATE)
        own = Path(tempfile.mkdtemp(prefix='bios-gate-direct-', dir='/private/tmp')).resolve()
        own.chmod(0o700)
        print('IBSW_BIOS_DIRECT_OWNED_ROOT=' + str(own), flush=True)
        private = own / 'tools/native-bios-io'
        lowered_p, lowered_t, facts = GATE.lower_fixed_io_images(provider, template,
            private / 'private-ssh', private / 'private-scp', private / 'private-nv')
        self.assertEqual((1, 1, 2), facts['replacement_counts'])
        self.assertIs(facts['inverse_full_bytes_equal'], True)
        self.assertEqual((provider, template), GATE._restore(lowered_p, lowered_t, own))
        common, os_body, bios_body, cpld_body = GATE._sections(template)
        low_common, low_os, low_bios, low_cpld = GATE._sections(lowered_t)
        self.assertEqual((common, os_body, cpld_body), (low_common, low_os, low_cpld))
        token = ('\n' + str(private / 'private-nv') + ' ').encode()
        self.assertEqual(2, bios_body.count(b'\nnv '))
        self.assertEqual(bios_body.replace(b'\nnv ', token), low_bios)
        self.assertEqual(0, low_bios.count(b'\nnv '))
        self.assertEqual(22, len(PACKAGE_BYTES))
        self.assertEqual(PACKAGE_SHA, hashlib.sha256(PACKAGE_BYTES).hexdigest())
        self.assertEqual(19, len(GATE.PRODUCTION_PINS), 'old U19 pins must not be replaced')
        self.assertEqual((4, 2), tuple(len(rows) for rows in GATE._BIOS_REGIONS.values()))
        vector = {p: GATE._read(source / p) for p in GATE.PRODUCTION_PINS}
        original = GATE._verified_source_vector(vector)
        self.assertEqual('887a3faf2808cfd2107849825cea2a14fe041f9468987249c5bba07c39030f01',
            hashlib.sha256(original['tools/ibsw_upgrade_driver.py']).hexdigest())
        self.assertEqual('1736c076376873e2de2a2ce14639cde357bf15f058f0e486fcbf176b5ef02f51',
            hashlib.sha256(original['tools/ibsw_upgrade_executor.py']).hexdigest())
        for label, raw in (('prefix', b'# FOREIGN\n' + vector['tools/ibsw_upgrade_driver.py']),
                           ('suffix', vector['tools/ibsw_upgrade_driver.py'] + b'# FOREIGN\n')):
            with self.subTest(bios_source=label), self.assertRaises(AssertionError):
                GATE._verified_source_vector(dict(vector, **{'tools/ibsw_upgrade_driver.py': raw}))
        for label, payload in (
                ('missing', lowered_t.replace(token, b'\nnv ', 1)),
                ('duplicate', lowered_t + token),
                ('outside-prefix', b'# FOREIGN\n' + lowered_t),
                ('outside-suffix', lowered_t + b'# FOREIGN\n')):
            with self.subTest(kind=label), self.assertRaises(AssertionError):
                GATE._restore(lowered_p, payload, own)
        # No metadata/source/stub witness means refuse before any Popen.
        with self.assertRaises((AssertionError, FileNotFoundError)):
            GATE.require_safe_command(own, ['/usr/bin/python3', '-c', 'pass', 'probe'], own)

    @ISOLATION.isolated_whole
    def test_native_bios_real_dispatch_exit93_and_companion_drift_before_send(self):
        fixture = FLOW.BiosExercise()
        with self.subTest(flow='healthy'):
            r = fixture.exercise()
            fixture.healthy(r)
            self.assertEqual([22], r.selected_package_reads)
            self.assertEqual([], r.unselected_package_reads)
            self.assertEqual([], r.after_freeze_package_reads)
            self.assertEqual([], r.result[4])
            self.assertEqual('UNKNOWN', r.result[1]['targets'][0]['state'])
            self.assertTrue(any(x.get('child_exit_code') == 93 for x in r.manager))
            self.assertEqual(['source_test@198.51.100.44:' +
                              str(r.root / 'packages/firmware' / PACKAGE)], r.scp_records)
            self.assertEqual([['action', 'fetch', 'platform', 'firmware', 'BIOS',
                              'file://' + str(r.switch / PACKAGE)]], r.nv_records)
            self.assertFalse(list(r.switch.rglob('download-ack')), 'BIOS must not fabricate OS ACK')
        with self.subTest(flow='companion-drift'):
            r = fixture.exercise('companion_same_inode_rewrite_after_context')
            self.assertIsNone(r.fault_error)
            self.assertTrue(r.fault_fired and r.same_inode)
            self.assertTrue(r.contexts, 'actual original context required, not caller DATA')
            self.assertEqual([], r.dispatches)
            self.assertEqual([], r.scp_records)
            self.assertEqual([], r.nv_records)
            self.assertEqual([22], r.selected_package_reads)
            self.assertEqual([], r.unselected_package_reads)
            self.assertEqual([], r.after_freeze_package_reads)
            launch = [c for c in r.channels if len(__import__('shlex').split(c.command or '')) == 6]
            self.assertTrue(all(c.send_calls == 0 for c in launch))
            self.assertEqual([], [code for record in r.public_records for code in record['codes']])
            child, leaf, parent, stage, held, raw = r.contexts[0]
            self.assertIsInstance(parent._package_source_lifecycle_failure, FLOW.FIXTURE.driver.SharedUpgradeHold)
            for owner in (parent, child):
                rows = [row for row in r.live_close_verifications if row[0] is owner]
                self.assertEqual(1, len(rows))
                original, error, marker, before, after, tail_marker = rows[0]
                self.assertIs(original, owner)
                self.assertIs(before, False); self.assertIs(after, False)
                self.assertIs(error, parent._package_source_lifecycle_failure)
                self.assertIs(marker, error); self.assertIs(tail_marker, error)
                self.assertTrue(owner.closed)
            self.assertTrue((stage / 'request.json').is_file())
            self.assertFalse((stage / 'component-dispatch.json').exists())
            self.assertFalse(list(r.switch.rglob('download-ack')))
            self.assertEqual(1, len(r.freezes))
            self.assertEqual(2, len(r.factories))
            if r.invoke_error is None:
                self.assertNotEqual(0, r.result[0]); self.assertEqual([], r.result[4])
            else:
                self.assertIsInstance(r.invoke_error, FLOW.FIXTURE.driver.SharedUpgradeHold)
            fixture.secrecy(r)
