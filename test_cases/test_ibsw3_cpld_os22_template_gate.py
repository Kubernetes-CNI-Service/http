"""NOTRUN CPLD test-image compatibility only; no production/child execution."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from test_cases import native_cpld_safe_image as SUBJECT
from test_cases.native_cpld_physical_io import lower_fixed_io_images


PROVIDER = 'tools/ibsw_upgrade_scp.py'
TEMPLATE = 'infiniband/bringup/xdr-upgrade/upgrade-component.sh'
DATA = Path(__file__).resolve().parent / 'fixtures'
OLD_SHA = 'a2bde38c42ff14cc73ed5c5cbd3859701e93a8193eb78ae67f2bd5575393b502'
NEW_SHA = '53de009cb6031d2892b631475797c64238bff0599d8c062214b33107ee3cbc5f'
PROVIDER_SHA = '685cae25a02fae9cb447528c7a5e57abd3dc459f3247f9b5c5015662af7536d1'
# Reviewed complete old/new regions, not values obtained from SUBJECT.
REGIONS = ((4813, 314, 4813, 262), (6537, 221, 6485, 1239),
           (6948, 299, 7914, 260))
_EXPECTED_COPY_FILES = (
    'tools/_package_common.py', 'tools/project_contract.py',
    'tools/ssh_key_preparation.py', 'tools/ib_bringup_runtime_guard.py',
    'tools/ibsw_upgrade_contract.py', 'tools/ibsw_upgrade_inputs.py',
    'tools/ibsw_upgrade_driver.py', 'tools/ibsw_upgrade_schedule.py',
    'tools/ibsw_upgrade_component.py', 'tools/ibsw_upgrade_observer.py',
    'tools/ibsw_upgrade_executor.py', 'tools/ibsw_upgrade_access.py',
    'tools/ibsw_upgrade_pipeline.py', PROVIDER,
    'infiniband/bringup/xdr-upgrade/upgrade.py',
    'infiniband/bringup/xdr-upgrade/upgrade.sh', TEMPLATE,
    'infiniband/bringup/xdr-upgrade/upgrade-owned-runner.sh',
    'infiniband/bringup/xdr-upgrade/requirements.txt',
    'test_cases/__init__.py', 'test_cases/module_loader.py',
    'test_cases/ibsw225_fixture_support/runtime_source_support.py',
    'test_cases/ibsw225_fixture_support/fixed_fixture_registry.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_upgrade_cli.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_known_hosts.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_manual_execution.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_nvos_observations.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_three_component_workflow.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_access_recovery.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_grouped_summary.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_runtime_budgets.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_os_alternatives.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_input_isolation.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_health_upgrade_gate.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_compact_summary.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_os_download_telemetry.py',
    'test_cases/ibsw225_fixture_support/_fixture_test_standalone_links.py',
    'test_cases/fixtures/nvos-25.02.8008-system-version.txt',
    'test_cases/fixtures/nvos-system-health.txt',
    'test_cases/fixtures/nvos-six-cpld-firmware.txt',
    'test_cases/scp_source_cli_fixture.py',
    'test_cases/test_ibsw3_scp_source_cli_prompt_binding.py',
    'test_cases/scp_native_cpld_bridge_fixture.py',
    'test_cases/scp_native_cpld_bridge_isolation.py',
    'test_cases/native_cpld_physical_io.py',
    'test_cases/native_cpld_stub_sources.py',
    'test_cases/native_cpld_safe_image.py',
    'test_cases/test_ibsw3_native_cpld_bridge.py',
)


class CpldOs22TemplateGateDirectTests(unittest.TestCase):
    def inputs(self):
        root = Path(SUBJECT.__file__).resolve().parents[1]
        provider = (root / PROVIDER).read_bytes()
        old = (DATA / 'native-cpld-template-pre-os22.sh.txt').read_bytes()
        new = (DATA / 'native-cpld-template-with-os22.sh.txt').read_bytes()
        self.assertEqual(PROVIDER_SHA, hashlib.sha256(provider).hexdigest())
        self.assertEqual(OLD_SHA, hashlib.sha256(old).hexdigest())
        self.assertEqual(NEW_SHA, hashlib.sha256(new).hexdigest())
        self.assertEqual(PROVIDER_SHA, SUBJECT.PROVIDER_PREIMAGE)
        self.assertEqual(OLD_SHA, SUBJECT.TEMPLATE_PREIMAGE, 'do not replace original whole-template pin')
        self.assertEqual(48, len(_EXPECTED_COPY_FILES))
        self.assertEqual(_EXPECTED_COPY_FILES, SUBJECT.COPY_FILES)
        return root, provider, old, new

    def restore(self, provider, template, root):
        result, failure = None, None
        try:
            result = SUBJECT._restore(provider, template, root)
        except Exception as error:
            failure = error
        self.assertIsNone(failure, 'reviewed complete OS3 template must admit without executing old bytes')
        return result

    def test_old_and_exact_os3_template_preserve_actual_bytes_through_prepare_and_io_inverse(self):
        root, provider, old, new = self.inputs()
        own = Path(tempfile.mkdtemp(prefix='cpld-os3-direct-', dir='/private/tmp')).resolve()
        print('CPLD_OS3_DIRECT_OWNED_ROOT=' + str(own), flush=True)
        self.assertEqual((provider, old), self.restore(provider, old, own))
        self.assertEqual((provider, new), self.restore(provider, new, own))
        # Old fixed IO transformer supplies INPUTS only. Expected inverse is
        # the independent original full new fixture, not SUBJECT output.
        private = own / 'tools/native-cpld-io'
        p, t, facts = lower_fixed_io_images(provider, new, private/'private-ssh',
                                           private/'private-scp', private/'private-nv')
        self.assertEqual((1, 1, 4), facts['replacement_counts'])
        self.assertEqual((provider, new), self.restore(p, t, own))
        self.assertEqual(new, (root / TEMPLATE).read_bytes())
        image = SUBJECT.prepare_image(root)
        print('CPLD_OS3_PREPARED_IMAGE=' + str(image), flush=True)
        lowered = (image / TEMPLATE).read_bytes()
        marker = b'# IBSW_BODY_CPLD\n'
        prefix, body = new.split(marker, 1)
        self.assertEqual(4, body.count(b'\nnv '))
        token = ('\n' + str(image / 'tools/native-cpld-io/private-nv') + ' ').encode()
        self.assertEqual(prefix + marker + body.replace(b'\nnv ', token), lowered)
        self.assertEqual((provider, new),
            self.restore((image / PROVIDER).read_bytes(), lowered, image))
        metadata = json.loads((image / SUBJECT.METADATA).read_bytes())
        self.assertEqual(set(_EXPECTED_COPY_FILES), set(metadata['hashes']))
        self.assertEqual(NEW_SHA, metadata['io_lowering']['template_before'])
        self.assertEqual([1, 1, 4], metadata['io_lowering']['replacement_counts'])
        self.assertEqual((image / PROVIDER).read_bytes(), SUBJECT.validate_image(image))

    def test_partial_missing_truncated_duplicate_reordered_or_external_template_changes_refuse(self):
        root, provider, old, new = self.inputs()
        own = Path(tempfile.mkdtemp(prefix='cpld-os3-negative-', dir='/private/tmp')).resolve()
        print('CPLD_OS3_DIRECT_OWNED_ROOT=' + str(own), flush=True)
        bad = {'prefix': b'# UNREVIEWED\n' + new, 'suffix': new + b'# UNREVIEWED\n',
               'middle': new[:100] + bytes([new[100] ^ 1]) + new[101:],
               'old_external': old + b'# UNREVIEWED\n'}
        for ordinal, (a, alen, b, blen) in enumerate(REGIONS, 1):
            original, reviewed = old[a:a+alen], new[b:b+blen]
            bad['missing-' + str(ordinal)] = new[:b] + new[b+blen:]
            bad['truncated-' + str(ordinal)] = new[:b+blen-1] + new[b+blen:]
            bad['duplicate-' + str(ordinal)] = new + reviewed
            bad['extra-old-' + str(ordinal)] = new + original
            bad['partial-' + str(ordinal)] = new[:b] + original + new[b+blen:]
        first, second = REGIONS[:2]
        a, alen, b, blen = first[2], first[3], second[2], second[3]
        bad['reordered'] = new[:a] + new[b:b+blen] + new[a+alen:b] + new[a:a+alen] + new[b+blen:]
        for label, payload in bad.items():
            with self.subTest(kind=label):
                with self.assertRaises(AssertionError):
                    SUBJECT._restore(provider, payload, own)
        private = own / 'tools/native-cpld-io'
        p, t, facts = lower_fixed_io_images(provider, new, private/'private-ssh',
                                           private/'private-scp', private/'private-nv')
        with self.assertRaises(AssertionError):
            SUBJECT._restore(p, t + b'# UNREVIEWED\n', own)
