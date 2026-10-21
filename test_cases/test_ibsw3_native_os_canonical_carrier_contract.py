"""SOURCE ONLY independent fixed OS3 carrier/identity UNIT; not native workflow.

No production imports or subprocess calls are made by this direct module.
Its cold-image preparation copies only fixed original sources and private
executables; a deliberate source edit is detected without executing that image.
"""
import ast
import hashlib
import importlib
from pathlib import Path
import unittest

PROVIDER = 'tools/ibsw_upgrade_scp.py'
TEMPLATE = 'infiniband/bringup/xdr-upgrade/upgrade-component.sh'

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

EXPECTED_COPY55 = _EXPECTED_COPY_FILES + (
    'test_cases/native_os_stub_sources.py',
    'test_cases/native_os_safe_image.py',
    'test_cases/native_os_dual_channel.py',
    'test_cases/native_os_physical_bridge.py',
    'test_cases/native_os_test_isolation.py',
    'test_cases/scp_native_os_manager_fixture.py',
    'test_cases/test_ibsw3_native_os_manager_workflow.py',
)
MODULE = 'test_cases.test_ibsw3_native_os_manager_workflow'
CLASS = 'NativeOsManagerWorkflowTests'
EXPECTED_ROSTER = (
    'test_cases.test_ibsw3_native_os_manager_workflow.NativeOsManagerWorkflowTests.test_single_target_v2_ack_record_precedes_private_fetch_without_releasing_unknown_slot',
    'test_cases.test_ibsw3_native_os_manager_workflow.NativeOsManagerWorkflowTests.test_native_scp_os_missing_or_wrong_content_keeps_manager_ack_absent',
    'test_cases.test_ibsw3_native_os_manager_workflow.NativeOsManagerWorkflowTests.test_native_scp_os_critical_measurement_commit_failure_withholds_ack',
)
EXPECTED_BODY_SHA256 = {
    'require_dispatch': '226a18682bf2dd473c673cd3194ae3eadf9091783998bf6fa96cdf1a2b6772d1',
    'test_native_scp_os_missing_or_wrong_content_keeps_manager_ack_absent': '315028adbdbe364f8168b52493a1924eec64115fda973fd4d63bba227dcb5ca6',
    'test_native_scp_os_critical_measurement_commit_failure_withholds_ack': 'd41134f20c2a18d4a7cb00c12c08ddb131daf76a7b2ef18f88294eecf9f723dd',
    'test_single_target_v2_ack_record_precedes_private_fetch_without_releasing_unknown_slot': '73d58a09e067d9c6660ce19b005005a6b9404a4a306c7201789c30d726fd2410',
}


class NativeOsCanonicalCarrierContractTests(unittest.TestCase):
    def test_literal_55_mapping_three_selectors_and_original_method_bodies(self):
        safe = importlib.import_module('test_cases.native_os_safe_image')
        isolation = importlib.import_module('test_cases.native_os_test_isolation')
        self.assertEqual(55, len(EXPECTED_COPY55))
        self.assertEqual(55, len(set(EXPECTED_COPY55)))
        self.assertEqual(EXPECTED_COPY55, safe.COPY_FILES,
                         'new canonical OS3 replaces only the private old test path')
        self.assertEqual(EXPECTED_ROSTER, isolation.ROSTER,
                         'only the independent single positive plus original negative2')
        root = Path(safe.__file__).resolve().parents[1]
        path = root / 'test_cases/test_ibsw3_native_os_manager_workflow.py'
        self.assertTrue(path.is_file() and not path.is_symlink())
        tree = ast.parse(path.read_bytes())
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == CLASS]
        self.assertEqual(1, len(classes))
        methods = {n.name: n for n in classes[0].body if isinstance(n, ast.FunctionDef)}
        self.assertEqual(set(EXPECTED_BODY_SHA256), set(methods))
        for name, expected in EXPECTED_BODY_SHA256.items():
            with self.subTest(method=name):
                node = methods[name]
                exact = '\n'.join(ast.dump(x, include_attributes=False) for x in node.body)
                self.assertEqual(expected, hashlib.sha256(exact.encode()).hexdigest(),
                                 'same independent original body and all assertions')
                decorators = [ast.dump(x, include_attributes=False) for x in node.decorator_list]
                self.assertEqual([] if name == 'require_dispatch' else
                    ["Name(id='isolated_whole', ctx=Load())"], decorators)

    def test_foreign_selector_and_cold_image_source_tamper_refuse(self):
        safe = importlib.import_module('test_cases.native_os_safe_image')
        isolation = importlib.import_module('test_cases.native_os_test_isolation')
        self.assertEqual(EXPECTED_ROSTER, isolation.ROSTER,
                         'capability guard precedes any cold-image preparation')
        self.assertIsNone(isolation._ACTIVE_CHILD_SELECTOR)
        old = ('test_cases.test_ibsw3_native_os_manager_ack.'
               'NativeOsManagerAckWorkflowTests.'
               'test_native_scp_os_manager_commits_v2_ack_before_private_first_fetch')
        for selector in (old, 'test_cases.foreign.Case.test_run',
                         EXPECTED_ROSTER[0] + '.foreign'):
            with self.subTest(selector=selector):
                with self.assertRaises(RuntimeError):
                    isolation._child_main(selector, '0' * 32)
                self.assertIsNone(isolation._ACTIVE_CHILD_SELECTOR)
        with self.assertRaises(RuntimeError):
            isolation._child_main(EXPECTED_ROSTER[0], 'not-a-valid-owned-nonce')
        self.assertIsNone(isolation._ACTIVE_CHILD_SELECTOR)
        root = Path(safe.__file__).resolve().parents[1]
        image = safe.prepare_image(root)
        print('CANONICAL_OS3_DIRECT_RETAINED_IMAGE=' + str(image), flush=True)
        safe.validate_image(image)
        target = image / 'test_cases/test_ibsw3_native_os_manager_workflow.py'
        raw = target.read_bytes()
        target.write_bytes(raw + b'# INDEPENDENT COLD SOURCE MUTATION\n')
        with self.assertRaises(AssertionError):
            safe.validate_image(image)
        self.assertIsNone(isolation._ACTIVE_CHILD_SELECTOR)
