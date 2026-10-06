"""F02 real manual writer -> local generation journal, with isolated device I/O.

These tests never connect to a device. Only the remote boundary and release
preflight are fixtures; trigger_one, receipt publication and generation/veto
transitions execute their production implementations.
"""

from contextlib import ExitStack
from datetime import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class ConfigSyncAuthorityWorkflowTests(unittest.TestCase):
    def test_initial_method_reader_latches_own_era_and_withdraws_drift_without_nine_stage_laundering(self):
        from test_cases.module_loader import load_script
        from test_cases.test_config_sync_authority import ConfigSyncAuthorityTests
        monitor = load_script("f02_initial_current_method_reader", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        html = load_script("f02_initial_current_method_html", ROOT / "monitor/generate-monitor-html.py")
        authority = monitor.config_sync_authority
        reconcile = getattr(monitor, "apply_current_initial_method_authority", None)
        self.assertTrue(callable(reconcile), "initial-setup authority needs a current reader, not a bootstrap receipt")
        for case in ("positive", "drift", "late-new-writer", "late-read-error"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve() / "configuration-methods"
                ticket = authority.begin_method(root, "IB01", "initial-own", "initial-own-IB01", "initial_setup_managed")
                receipt = ConfigSyncAuthorityTests.method_receipt_v2(ticket, hostname="IB01", type="ib", config_method="initial-setup",
                    trigger_source="initial_setup_managed", transport_ip="192.0.2.10", mac_plain="020000000001",
                    live_state_sha256="a" * 64, input_sha256="b" * 64, source_receipt_sha256="c" * 64)
                authority.finish_method(root, ticket, receipt)
                captured = authority.read_method_current(root, "IB01")
                proof = {"schema_version": 1, "hostname": "IB01", "batch_identity_verified": True, "config_verified": case != "drift",
                         "interface": "eth0", "transport_ip": "192.0.2.10", "mac_plain": "020000000001",
                         "live_state_sha256": "a" * 64, "input_sha256": "b" * 64, "observation_sha256": "c" * 64,
                         "reason": "" if case != "drift" else "independent missing installed key"}
                device = {"hostname": "IB01", "type": "ib", "config_method": "initial-setup", "ip": "192.0.2.10",
                          "mac_plain": "020000000001", "ztp_round": 1, "observed_at": "2026-10-07T07:00:00+08:00",
                          "configuration_source_observation": {"reason": "old unrelated bootstrap"},
                          "issues": [], "events": [], "stages": {name: monitor.stage("pending") for name in monitor.STAGE_NAMES}}
                with ExitStack() as stack:
                    if case == "late-read-error":
                        real_read = authority.read_method_receipt
                        stack.enter_context(mock.patch.object(authority, "read_method_receipt", side_effect=(receipt, authority.AuthorityError("late read fault"))))
                    elif case == "late-new-writer":
                        real_read = authority.read_method_receipt
                        inserted = False
                        def concurrent_writer(*args):
                            nonlocal inserted
                            value = real_read(*args)
                            if not inserted:
                                inserted = True
                                authority.begin_method(root, "IB01", "newer", "newer-IB01", "initial_setup_managed")
                            return value
                        stack.enter_context(mock.patch.object(authority, "read_method_receipt", side_effect=concurrent_writer))
                    reconcile(device, root, captured, proof, "b" * 64)
                self.assertEqual("success" if case == "positive" else "warning", device["stages"]["config_apply"]["status"])
                current = authority.read_method_current(root, "IB01")
                self.assertEqual("success" if case == "positive" else "pending" if case == "late-new-writer" else "failed", current["state"])
                self.assertEqual(2 if case == "late-new-writer" else 1, current["generation"])
                monitor.finalize_device(device)
                self.assertNotEqual("success", device["overall"])
                self.assertFalse(monitor.completion_handoff_device_complete(device))
                self.assertFalse(html.ztp_completed(device))
                self.assertEqual("pending" if case == "positive" else "warning", device["stages"]["complete"]["status"])

    def test_monitor_once_mints_method_boundary_before_session_and_rechecks_current_release_input(self):
        from test_cases.module_loader import load_script
        from test_cases import test_load_release_transaction as fixture_module
        from test_cases.test_manual_applied_config import MonitorMethodConfigurationTests, protocol
        monitor = load_script("f02_method_release_current_cycle", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        fixture = fixture_module.ReleaseTransactionTests("test_writes_parent_release_after_all_components_match")
        fixture.setUp()
        try:
            project = fixture.project.resolve()
            expected = MonitorMethodConfigurationTests.EXPECTED.replace("leaf1", "leaf01")
            config = project / "99-output-eth/20260830_120000_combine/leaf01.yaml"
            config.write_text(expected)
            manifest_path = config.parent / "release-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["devices"][0]["config_sha256"] = hashlib.sha256(expected.encode()).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            fixture_module.LOAD.validate_and_publish_release(project, fixture.inputs, publish=True)
            apache, dhcp, air = project / "apache.log", project / "dhcp.log", project / "air.json"
            apache.write_text("")
            dhcp.write_text("")
            air.write_text('{"nodes": {}}')
            args = monitor.parser().parse_args([str(project), "--output-dir", str(project / "reports"),
                                               "--apache-log", str(apache), "--dhcp-log", str(dhcp)])
            root = project / "99-output-ztp/configuration-methods"
            previous = []
            for cycle in (1, 2, 3):
                live = expected if cycle != 2 else expected.replace("192.0.2.53", "192.0.2.54")
                raw = ("__HOSTNAME_BEGIN__\nleaf01\n__HOSTNAME_END__\n"
                       "__ETH0_MAC_BEGIN__\n02:00:00:00:00:01\n__ETH0_MAC_END__\n"
                       "__ETH1_MAC_BEGIN__\n\n__ETH1_MAC_END__\n"
                       "__HTTP_MONITOR_LIVE_V1_BEGIN__\n" + live + "\n__HTTP_MONITOR_LIVE_V1_END__=0\n"
                       "__HTTP_MONITOR_APPLIED_V1_BEGIN__\n" + protocol(expected) + "\n__HTTP_MONITOR_APPLIED_V1_END__=0\n")
                def transport(command, **kwargs):
                    self.assertIn("BatchMode=yes", command)
                    boundary = monitor.config_sync_authority.read_method_current(root, "leaf01")
                    self.assertIsNotNone(boundary, "local pending boundary MUST precede actual SSH")
                    self.assertEqual((cycle, "pending", True), tuple(boundary[k] for k in ("generation", "state", "veto")))
                    if cycle == 3:
                        config.write_text(expected.replace("Asia/Shanghai", "UTC"))
                    return {"returncode": 0, "stdout": raw, "stderr": ""}
                with mock.patch.object(monitor, "service_runtime_backend", return_value=SimpleNamespace(name="systemd")), \
                        mock.patch.object(monitor, "service_state", return_value={"active": "fixture", "enabled": "fixture", "error": ""}), \
                        mock.patch.object(monitor, "ACTIVE_AIR_JSON", air), \
                        mock.patch.object(monitor, "run_command", side_effect=transport):
                    output = monitor.monitor_once(args, project)
                device = json.loads((output / "report.json").read_text())["devices"][0]
                current = monitor.config_sync_authority.read_method_current(root, "leaf01")
                self.assertEqual((cycle, "success" if cycle == 1 else "failed", cycle != 1),
                                 tuple(current[k] for k in ("generation", "state", "veto")))
                self.assertEqual("success" if cycle == 1 else "failed", device["configuration_method_authority"]["state"])
                self.assertEqual("success" if cycle == 1 else "warning", device["stages"]["config_apply"]["status"])
                self.assertNotEqual("success", device["overall"], "configuration never fabricates missing bootstrap stages")
                if cycle == 1:
                    previous = monitor.snapshot_device_state({"devices": [device]})
                    changed = json.loads(json.dumps(device))
                    changed["configuration_method_authority"]["generation"] += 1
                    self.assertNotEqual(previous, monitor.snapshot_device_state({"devices": [changed]}),
                                        "method generations must be audit-visible even when stages do not change")
        finally:
            fixture.tearDown()

    def test_current_method_comparison_publishes_own_era_then_drift_withdraws_it(self):
        from test_cases.module_loader import load_script
        from test_cases.test_manual_applied_config import MonitorMethodConfigurationTests, protocol
        monitor = load_script("f02_method_semantic_writer_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        html = load_script("f02_method_semantic_writer_html", ROOT / "monitor/generate-monitor-html.py")
        authority = monitor.config_sync_authority
        finish = getattr(monitor, "finish_monitor_method_cycle", None)
        self.assertTrue(callable(finish), "the current comparison must finish its own pending local era")
        expected = MonitorMethodConfigurationTests.EXPECTED
        device = {"hostname": "leaf1", "type": "eth", "config_method": "ztp", "ip": "192.0.2.10",
                  "ssh_user": "cumulus", "ssh_ips": ["192.0.2.10"],
                  "mac": "02:00:00:00:00:01", "mac_plain": "020000000001", "ztp_round": 1,
                  "issues": [], "events": [], "stages": {name: monitor.stage("success", "old log",
                    "2026-09-01T12:00:00+08:00", 1) for name in monitor.STAGE_NAMES}}
        raw = ("__HOSTNAME_BEGIN__\nleaf1\n__HOSTNAME_END__\n"
               "__ETH0_MAC_BEGIN__\n02:00:00:00:00:01\n__ETH0_MAC_END__\n"
               "__ETH1_MAC_BEGIN__\n\n__ETH1_MAC_END__\n"
               "__HTTP_MONITOR_LIVE_V1_BEGIN__\n" + expected + "\n__HTTP_MONITOR_LIVE_V1_END__=0\n"
               "__HTTP_MONITOR_APPLIED_V1_BEGIN__\n" + protocol(expected) + "\n__HTTP_MONITOR_APPLIED_V1_END__=0\n")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "configuration-methods"
            ticket = authority.begin_method(root, "leaf1", "cycle-1", "leaf1-cycle-1", "ztp_monitor_cycle")
            with mock.patch.object(monitor, "run_command", return_value={"returncode": 0, "stdout": raw, "stderr": ""}) as transport:
                result = monitor.collect_switch(device, 5, None, root.parent / "known-hosts")
            self.assertEqual(1, transport.call_count)
            self.assertIn("BatchMode=yes", transport.call_args.args[0])
            finish(device, result, root, ticket, expected)
            receipt = authority.read_method_receipt(root, "leaf1")
            self.assertEqual("success", receipt["state"])
            self.assertEqual(ticket["generation"], receipt["generation"])
            self.assertEqual(hashlib.sha256(expected.encode()).hexdigest(), receipt["input_sha256"])
            self.assertEqual(receipt, device["configuration_method_authority"])
            old_image = (root / ".authority/leaf1.method.json").read_bytes()
            second = authority.begin_method(root, "leaf1", "cycle-2", "leaf1-cycle-2", "ztp_monitor_cycle")
            live = expected.replace("Asia/Shanghai", "UTC")
            drift = {**result, "live_config_observation": {"kind": "ok", "text": live,
                     "sha256": hashlib.sha256(live.encode()).hexdigest()}}
            finish(device, drift, root, second, expected)
            self.assertEqual((2, "failed", True), tuple(authority.read_method_current(root, "leaf1")[k]
                              for k in ("generation", "state", "veto")))
            self.assertIsNone(authority.read_method_receipt(root, "leaf1"))
            self.assertFalse(authority.monitor_method_observation_allows_completion(device))
            monitor.finalize_device(device)
            self.assertNotEqual("success", device["stages"]["config_apply"]["status"])
            self.assertFalse(monitor.completion_handoff_device_complete(device))
            self.assertFalse(html.ztp_completed(device))
            self.assertNotEqual(old_image, (root / ".authority/leaf1.method.json").read_bytes())

    def test_method_v2_backend_does_not_launder_nine_stage_or_manual_application_authority(self):
        from test_cases.module_loader import load_script
        from test_cases.test_config_sync_authority import ConfigSyncAuthorityTests
        authority = load_script("f02_method_v2_writer_reader", ROOT / "ztp/config_sync_authority.py")
        monitor = load_script("f02_method_v2_report_consumer", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        html = load_script("f02_method_v2_html_consumer", ROOT / "monitor/generate-monitor-html.py")
        text = "- set:\n    system:\n      hostname: leaf1\n"
        digest = hashlib.sha256(text.encode()).hexdigest()
        # The receipt's positive schema is not evidence for old nine stages.
        # Do not obtain an expected success by calling any analyzer under test.
        device = {"hostname": "leaf1", "type": "eth", "config_method": "ztp", "ip": "192.0.2.10",
                  "mac": "02:00:00:00:00:01", "mac_plain": "020000000001", "ztp_round": 1, "issues": [], "events": [],
                  "stages": {name: {"status": "success", "timestamp": "2026-09-01T12:00:00+08:00",
                                    "success_index": 1, "detail": "independent old success"}
                             for name in ("dhcp", "bootstrap", "config_http", "ssh", "network", "version",
                                          "config_apply", "ssh_keys", "complete")}}
        result = {"kind": "ok", "returncode": 0, "batch_mode_verified": True, "identity_frame_valid": True,
                  "connected_ip": "192.0.2.10", "remote_hostname": "leaf1", "remote_eth0_mac": "02:00:00:00:00:01",
                  "live_config_observation": {"kind": "ok", "text": text, "sha256": digest}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "configuration-methods"
            first = authority.begin_method(root, "leaf1", "cycle-1", "leaf1-cycle-1", "ztp_monitor_cycle")
            authority.finish_method(root, first, ConfigSyncAuthorityTests.method_receipt_v2(first, live_state_sha256=digest))
            observed = authority.read_method_receipt(root, "leaf1")
            self.assertEqual((2, 1, "success"), tuple(observed[k] for k in ("schema_version", "generation", "state")))
            device["configuration_observation"] = monitor.bind_monitor_live_observation(device, result)
            self.assertIs(True, device["configuration_observation"]["batch_identity_verified"])
            self.assertEqual(digest, device["configuration_observation"]["live_state_sha256"])
            device["configuration_source_observation"] = None
            device["configuration_authority"] = observed
            self.assertFalse(authority.monitor_current_config_sync_allows_application(device))
            monitor.finalize_device(device)
            self.assertNotEqual("success", device["stages"]["config_apply"]["status"])
            self.assertNotEqual("success", device["overall"])
            self.assertFalse(monitor.completion_handoff_device_complete(device))
            self.assertFalse(html.ztp_completed(device))
            report = {"generated_at": "2026-09-01T12:00:00+08:00", "project": "demo", "scope": "prod",
                      "devices": [device], "services": {}, "collection_errors": [], "since_minutes": 10}
            output = monitor.write_report(report, root.parent / "reports", {})
            stored = json.loads((output / "report.json").read_text())["devices"][0]
            self.assertEqual(observed, stored["configuration_authority"])
            self.assertFalse(html.ztp_completed(stored))
            second = authority.begin_method(root, "leaf1", "cycle-2", "leaf1-cycle-2", "ztp_monitor_cycle")
            self.assertIsNone(authority.read_method_receipt(root, "leaf1"))
            self.assertIsNone(authority.revoke_method(root, "leaf1", expected=first))
            self.assertEqual(second, authority.read_method_current(root, "leaf1"))

    def test_no_ssh_current_cycle_cannot_borrow_persisted_nine_stage_completion(self):
        from test_cases.module_loader import load_script
        from test_cases import test_load_release_transaction as release_fixture
        monitor = load_script("f02_uncollected_current_observation", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        html = load_script("f02_uncollected_completion_html", ROOT / "monitor/generate-monitor-html.py")
        expected_stages = ("dhcp", "bootstrap", "config_http", "ssh", "network",
                           "version", "config_apply", "ssh_keys", "complete")
        for history in (False, True):
            with self.subTest(history=history):
                fixture = release_fixture.ReleaseTransactionTests("test_writes_parent_release_after_all_components_match")
                fixture.setUp()
                try:
                    project = fixture.project.resolve()
                    fixture.global_file.write_text(fixture.global_file.read_text().replace("status: enabled", "status: disabled"))
                    inputs = release_fixture.LOAD.replace(fixture.inputs, settings=release_fixture.LOAD.replace(fixture.inputs.settings, dhcp_enabled=False))
                    release_fixture.LOAD.validate_and_publish_release(project, inputs, publish=True)
                    apache, air, reports = project / "apache.log", project / "air.json", project / "reports"
                    apache.write_text("")
                    air.write_text('{"nodes": {}}')
                    old_path, old_bytes = None, None
                    if history:
                        prior = {"hostname": "leaf01", "type": "eth", "ip": "192.0.2.10",
                                 "mac": "02:00:00:00:00:01", "mac_plain": "020000000001", "ztp_round": 1, "overall": "success",
                                 "issues": [], "events": [], "progress": {"done": 9, "total": 9, "percent": 100},
                                 "stages": {name: {"status": "success", "detail": "independent old success",
                                                     "timestamp": "2026-09-01T12:00:00+08:00", "success_index": 1}
                                            for name in expected_stages}}
                        self.assertTrue(monitor.completion_handoff_device_complete(prior))
                        self.assertTrue(html.ztp_completed(prior))
                        report = {"project": "demo", "scope": "prod", "devices": [prior], "services": {},
                                  "collection_errors": [], "generated_at": "2026-09-01T12:00:00+08:00", "since_minutes": 10}
                        old_path = monitor.write_report(report, reports, {}) / "report.json"
                        old_bytes = old_path.read_bytes()
                    args = monitor.parser().parse_args([str(project), "--offline", "--no-ssh", "--apache-log", str(apache),
                                                       "--air-json", str(air), "--output-dir", str(reports)])
                    monitor.validate_monitor_mode(args, project)
                    with mock.patch.object(monitor, "collect_switch", side_effect=AssertionError("no SSH admitted")), \
                            mock.patch.object(monitor, "collect_dhcp", side_effect=AssertionError("disabled cannot read DHCP")), \
                            mock.patch.object(monitor, "service_state", side_effect=AssertionError("offline cannot query services")):
                        current = monitor.monitor_once(args, project)
                    device = json.loads((current / "report.json").read_text())["devices"][0]
                    with self.subTest(history=history, check="current-observation"):
                        observation = device.get("configuration_observation", {})
                        self.assertIs(False, observation.get("batch_identity_verified"))
                        self.assertEqual("", observation.get("live_state_sha256"))
                        self.assertEqual("transport-not-verified", observation.get("reason"))
                    with self.subTest(history=history, check="overall"):
                        self.assertNotEqual("success", device["overall"])
                    with self.subTest(history=history, check="machine"):
                        self.assertFalse(monitor.completion_handoff_device_complete(device))
                    with self.subTest(history=history, check="html"):
                        self.assertFalse(html.ztp_completed(device))
                    if old_path is not None:
                        self.assertEqual(old_bytes, old_path.read_bytes(), "retain prior snapshot as history, never rewrite it as current proof")
                    self.assertFalse((project / "99-output-ztp/manual-config-sync").exists(), "absent collection cannot mint an era or receipt")
                finally:
                    fixture.tearDown()

    def test_disabled_offline_admission_cannot_be_reused_after_real_release_mode_changes(self):
        from test_cases.module_loader import load_script
        from test_cases import test_load_release_transaction as release_fixture
        monitor = load_script("f02_offline_admission_release_race", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        fixture = release_fixture.ReleaseTransactionTests("test_writes_parent_release_after_all_components_match")
        fixture.setUp()
        try:
            project = fixture.project
            fixture.global_file.write_text(fixture.global_file.read_text().replace("status: enabled", "status: disabled"))
            disabled = release_fixture.LOAD.replace(fixture.inputs, settings=release_fixture.LOAD.replace(fixture.inputs.settings, dhcp_enabled=False))
            release_fixture.LOAD.validate_and_publish_release(project, disabled, publish=True)
            apache, air = project / "apache.log", project / "air.json"
            apache.write_text("")
            air.write_text('{"nodes": {}}')
            args = monitor.parser().parse_args([str(project), "--offline", "--no-ssh", "--apache-log", str(apache),
                                               "--air-json", str(air), "--output-dir", str(project / "reports")])
            monitor.validate_monitor_mode(args, project)
            fixture.global_file.write_text(fixture.global_file.read_text().replace("status: disabled", "status: enabled"))
            release_fixture.LOAD.validate_and_publish_release(project, fixture.inputs, publish=True)
            with mock.patch.object(monitor, "read_devices", side_effect=AssertionError("changed admission must fail before inventory")), \
                    mock.patch.object(monitor, "collect_dhcp", side_effect=AssertionError("changed admission cannot fall back to local DHCP")):
                with self.assertRaisesRegex(ValueError, "offline.*release.*变化"):
                    monitor.monitor_once(args, project)
            self.assertFalse((project / "reports").exists())
        finally:
            fixture.tearDown()

    def test_real_release_disabled_offline_admission_needs_no_dhcp_files(self):
        from test_cases.module_loader import load_script
        from test_cases import test_load_release_transaction as release_fixture
        monitor = load_script("f02_disabled_offline_admission", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        for enabled, supplied in ((False, False), (False, True), (True, False), (True, True)):
            with self.subTest(enabled=enabled, supplied=supplied):
                fixture = release_fixture.ReleaseTransactionTests("test_writes_parent_release_after_all_components_match")
                fixture.setUp()
                try:
                    project = fixture.project
                    if not enabled:
                        fixture.global_file.write_text(fixture.global_file.read_text().replace("status: enabled", "status: disabled"))
                    inputs = release_fixture.LOAD.replace(fixture.inputs, settings=release_fixture.LOAD.replace(fixture.inputs.settings, dhcp_enabled=enabled))
                    parent = release_fixture.LOAD.validate_and_publish_release(project, inputs, publish=True)
                    self.assertEqual("enabled" if enabled else "disabled", parent["dhcp_status"])
                    apache, air = project / "apache.log", project / "air.json"
                    apache.write_text("")
                    air.write_text('{"nodes": {}}')
                    dhcp, leases = project / "unused-dhcp", project / "unused-leases"
                    arguments = [str(project), "--offline", "--no-ssh", "--apache-log", str(apache),
                                 "--air-json", str(air), "--output-dir", str(project / "offline-reports")]
                    if supplied:
                        # Disabled must not even stat provided stale DHCP paths.
                        if enabled:
                            dhcp.write_text("")
                            leases.write_text("")
                        arguments += ["--dhcp-log", str(dhcp), "--dhcp-leases", str(leases)]
                    args = monitor.parser().parse_args(arguments)
                    real_lstat = Path.lstat
                    def lstat(path, *positional, **keyword):
                        if not enabled:
                            self.assertNotIn(path, (dhcp, leases), "disabled admission cannot inspect DHCP sources")
                        return real_lstat(path, *positional, **keyword)
                    with mock.patch.object(Path, "lstat", lstat):
                        if enabled and not supplied:
                            with self.assertRaisesRegex(ValueError, "--dhcp-log.*--dhcp-leases"):
                                monitor.validate_monitor_mode(args, project)
                            self.assertFalse((project / "offline-reports").exists())
                            continue
                        monitor.validate_monitor_mode(args, project)
                        with mock.patch.object(monitor, "collect_dhcp", wraps=monitor.collect_dhcp) as collector, \
                                mock.patch.object(monitor, "service_state", side_effect=AssertionError("offline cannot query services")), \
                                mock.patch.object(monitor, "collect_switch", side_effect=AssertionError("offline cannot connect devices")):
                            run = monitor.monitor_once(args, project)
                    self.assertEqual(int(enabled), collector.call_count)
                    report = json.loads((run / "report.json").read_text())
                    self.assertEqual("enabled" if enabled else "disabled", report["dhcp_status"])
                    self.assertNotEqual("success", report["devices"][0]["overall"])
                    self.assertFalse(monitor.completion_handoff_device_complete(report["devices"][0]))
                    if not enabled:
                        self.assertFalse(dhcp.exists())
                        self.assertFalse(leases.exists())
                finally:
                    fixture.tearDown()

    def test_monitor_rejects_missing_or_untyped_release_mode_before_inventory_or_report_io(self):
        from test_cases.module_loader import load_script
        monitor = load_script("f02_unbound_release_mode_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        for mode in (None, True, 0, "", "DISABLED", [], {}):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                project = Path(directory)
                args = monitor.parser().parse_args([str(project), "--offline", "--no-ssh", "--output-dir", str(project / "reports")])
                release = {"release_id": "a" * 20, "generated_at": "2026-10-07T01:00:00+08:00", "dhcp_status": mode}
                with mock.patch.object(monitor, "load_release_identity", return_value=release), \
                        mock.patch.object(monitor, "read_devices", side_effect=AssertionError("must not read inventory under an unbound mode")) as inventory:
                    with self.assertRaisesRegex(ValueError, "可信 DHCP 模式"):
                        monitor.monitor_once(args, project)
                inventory.assert_not_called()
                self.assertFalse((project / "reports").exists())

    def test_current_disabled_release_does_not_read_dhcp_sources_and_static_collection_continues(self):
        from test_cases.module_loader import load_script
        from test_cases import test_load_release_transaction as release_fixture
        from ztp import dynamic_air_inventory
        monitor = load_script("f02_disabled_monitor_workflow", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        for enabled, absent in ((False, False), (False, True), (True, False)):
            with self.subTest(enabled=enabled, absent=absent):
                fixture = release_fixture.ReleaseTransactionTests("test_writes_parent_release_after_all_components_match")
                fixture.setUp()
                try:
                    project = fixture.project
                    if not enabled:
                        fixture.global_file.write_text(fixture.global_file.read_text().replace("status: enabled", "status: disabled"))
                    inputs = release_fixture.LOAD.replace(fixture.inputs, settings=release_fixture.LOAD.replace(fixture.inputs.settings, dhcp_enabled=enabled))
                    parent = release_fixture.LOAD.validate_and_publish_release(project, inputs, publish=True)
                    self.assertEqual("enabled" if enabled else "disabled", parent["dhcp_status"])
                    apache, dhcp, leases, air = [project / name for name in ("apache.log", "dhcp.log", "leases", "air.json")]
                    apache.write_text("")
                    dhcp.write_text("2026-10-07T01:00:00+08:00 host dhcpd: DHCPACK on 192.0.2.10 to 02:00:00:00:00:01 (leaf01) via eth0\n")
                    leases.write_text("lease 192.0.2.99 { binding state active; hardware ethernet 02:00:00:00:00:01; ends never; }\n")
                    air.write_text('{"nodes": {}}')
                    args = monitor.parser().parse_args([str(project), "--output-dir", str(project / "reports"), "--apache-log", str(apache), "--dhcp-log", str(dhcp), "--dhcp-leases", str(leases)])
                    original = {path: (path.read_bytes(), path.stat().st_ino) for path in (dhcp, leases)}
                    if absent:
                        for path in original:
                            path.rename(path.with_name(path.name + ".retained"))
                    real_leases = dynamic_air_inventory.active_leases
                    real_read = monitor._read_bounded_regular_text
                    def lease_read(path, **kwargs):
                        if not enabled:
                            self.assertIsNone(path, "disabled cannot use a local lease file for addresses")
                        return real_leases(path, **kwargs)
                    def bounded_read(path, **kwargs):
                        if not enabled:
                            self.assertNotIn(path, (dhcp, leases), "disabled must not hash/read local DHCP evidence either")
                        return real_read(path, **kwargs)
                    text = "- set: {}\n"
                    observed = {"kind": "ok", "returncode": 0, "batch_mode_verified": True, "identity_frame_valid": True,
                                "connected_ip": "192.0.2.10", "remote_hostname": "leaf01", "remote_eth0_mac": "02:00:00:00:00:01", "remote_eth1_mac": "",
                                "observed_at": "2026-10-07T01:00:05+08:00", "ztp_log": "", "ifreload_log": "", "failed_yaml": "", "stderr": "", "attempts": [], "host_key_commands": [],
                                "live_config_observation": {"kind": "ok", "text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}}
                    with mock.patch.object(monitor, "ACTIVE_AIR_JSON", air), \
                            mock.patch.object(monitor, "service_runtime_backend", return_value=SimpleNamespace(name="systemd")), \
                            mock.patch.object(monitor, "service_state", return_value={"active": "fixture", "enabled": "fixture", "error": ""}) as services, \
                            mock.patch.object(monitor, "collect_switch", return_value=observed) as collect, \
                            mock.patch.object(monitor, "collect_dhcp", wraps=monitor.collect_dhcp) as local_dhcp, \
                            mock.patch.object(monitor, "_read_bounded_regular_text", side_effect=bounded_read), \
                            mock.patch.object(dynamic_air_inventory, "active_leases", side_effect=lease_read):
                        run = monitor.monitor_once(args, project)
                    report = json.loads((run / "report.json").read_text())
                    self.assertEqual(1, collect.call_count, "DHCP disabled must preserve independent static SSH collection")
                    self.assertEqual("192.0.2.10", collect.call_args.args[0]["ip"])
                    self.assertEqual(int(enabled), local_dhcp.call_count)
                    self.assertEqual(["apache2", "isc-dhcp-server"] if enabled else ["apache2"], [call.args[0] for call in services.call_args_list])
                    self.assertEqual("enabled" if enabled else "disabled", report.get("dhcp_status"))
                    self.assertEqual("success" if enabled else "pending", report["devices"][0]["stages"]["dhcp"]["status"])
                    self.assertNotEqual("success", report["devices"][0]["overall"])
                    sidecar = json.loads((project / "reports" / monitor.COLLECTION_ATTRIBUTION_STATE_NAME).read_text())
                    self.assertEqual(enabled, "dhcp_leases" in sidecar["input_digests"])
                    for path, before in original.items():
                        retained = path.with_name(path.name + ".retained") if absent else path
                        self.assertEqual(before, (retained.read_bytes(), retained.stat().st_ino))
                finally:
                    fixture.tearDown()

    def monitor_cycle_fixture(self, project, *, live_text=None):
        from test_cases.module_loader import load_script
        monitor = load_script("f02_current_generation_monitor_workflow", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        receipt, produced = self.published_receipt(project)
        device = {"hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10",
                  "mac_plain": "020000000001", "ztp_round": 1,
                  "stages": {name: monitor.stage("success", "old log", "2026-10-07T01:00:00+08:00", 1) for name in monitor.STAGE_NAMES},
                  "issues": [], "events": []}
        text = "- set:\n    system:\n      hostname: EXAMPLE-Leaf01\n" if live_text is None else live_text
        result = {"kind": "ok", "returncode": 0, "batch_mode_verified": True,
                  "identity_frame_valid": True, "connected_ip": "192.0.2.10",
                  "remote_hostname": "EXAMPLE-Leaf01", "remote_eth0_mac": "02:00:00:00:00:01",
                  "observed_at": "2026-10-07T01:00:05+08:00",
                  "live_config_observation": {"kind": "ok", "text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}}
        return monitor, receipt, produced, device, result

    def current_monitor_gate(self, monitor):
        gate = getattr(monitor, "apply_current_config_sync_authority", None)
        self.assertTrue(callable(gate), "monitor must bind fresh observations to the captured local generation, not old logs")
        return gate

    def test_monitor_live_drift_revokes_current_writer_success_and_old_log_cannot_override_it(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor, receipt, _produced, device, result = self.monitor_cycle_fixture(Path(directory).resolve(), live_text="- set: {}\n")
            root = receipt.parents[2]
            authority = self.manual.config_sync_authority
            expected = authority.read_current(root, "EXAMPLE-Leaf01")
            old = receipt.read_bytes()
            self.current_monitor_gate(monitor)(device, result, root, expected)
            self.assertEqual("warning", device["stages"]["config_apply"]["status"])
            self.assertEqual("warning", device["stages"]["complete"]["status"])
            self.assertEqual((1, "failed", True), tuple(authority.read_current(root, "EXAMPLE-Leaf01")[key] for key in ("generation", "state", "veto")))
            self.assertEqual(old, receipt.read_bytes())
            monitor.finalize_device(device)
            self.assertNotEqual("success", device["overall"])
            self.assertFalse(monitor.completion_handoff_device_complete(device))

    def test_monitor_matches_current_receipt_but_cannot_borrow_old_nine_stage_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor, receipt, produced, device, result = self.monitor_cycle_fixture(Path(directory).resolve())
            root = receipt.parents[2]
            expected = self.manual.config_sync_authority.read_current(root, "EXAMPLE-Leaf01")
            self.current_monitor_gate(monitor)(device, result, root, expected)
            self.assertEqual("success", device["stages"]["config_apply"]["status"])
            current = device.get("configuration_authority", {})
            self.assertEqual((1, expected["source_identity"], "success", False),
                             tuple(current.get(key) for key in ("generation", "source_identity", "state", "veto")))
            self.assertEqual(produced["live_state_sha256"], current.get("live_state_sha256"))
            self.assertEqual("monitor_batchmode", current.get("observation_source"))
            monitor.finalize_device(device)
            self.assertNotEqual("success", device["overall"])
            self.assertFalse(monitor.completion_handoff_device_complete(device))

    def test_actual_missing_bootstrap_source_does_not_veto_verified_current_manual_sync(self):
        from test_cases.module_loader import load_script
        html = load_script("f02_manual_source_independence_html", ROOT / "monitor/generate-monitor-html.py")
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            monitor, receipt, _produced, _device, result = self.monitor_cycle_fixture(project)
            authority = self.manual.config_sync_authority
            root = receipt.parents[2]
            original, current = receipt.read_bytes(), authority.read_current(root, "EXAMPLE-Leaf01")
            (project / "02-devices_config.csv").write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip,config_method\n"
                "EXAMPLE-Leaf01,eth,oob,192.0.2.10,24,192.0.2.1,02:00:00:00:00:01,,,,,,ztp\n", encoding="utf-8")
            apache, dhcp, air = project / "apache.log", project / "dhcp.log", project / "air.json"
            apache.write_text("")
            dhcp.write_text("")
            air.write_text('{"nodes": {}}')
            args = monitor.parser().parse_args([str(project), "--output-dir", str(project / "reports"),
                                               "--apache-log", str(apache), "--dhcp-log", str(dhcp)])
            # Actual collector/decoder, not a synthetic positive trusted flag.
            # No bootstrap source frame exists, while this SSH session supplies
            # its own identity and the live bytes of the real manual receipt.
            raw = ("__HOSTNAME_BEGIN__\nEXAMPLE-Leaf01\n__HOSTNAME_END__\n"
                   "__ETH0_MAC_BEGIN__\n02:00:00:00:00:01\n__ETH0_MAC_END__\n"
                   "__ETH1_MAC_BEGIN__\n\n__ETH1_MAC_END__\n"
                   "__HTTP_MONITOR_LIVE_V1_BEGIN__\n" + result["live_config_observation"]["text"]
                   + "\n__HTTP_MONITOR_LIVE_V1_END__=0\n")
            with mock.patch.object(monitor, "load_release_identity", return_value={"release_id": "fixture", "generated_at": "2026-10-07T01:00:00+08:00", "dhcp_status": "enabled"}), \
                    mock.patch.object(monitor, "service_runtime_backend", return_value=SimpleNamespace(name="systemd")), \
                    mock.patch.object(monitor, "service_state", return_value={"active": "fixture", "enabled": "fixture", "error": ""}), \
                    mock.patch.object(monitor, "ACTIVE_AIR_JSON", air), \
                    mock.patch.object(monitor, "run_command", return_value={"returncode": 0, "stdout": raw, "stderr": ""}) as ssh:
                run = monitor.monitor_once(args, project)
            self.assertEqual(1, ssh.call_count)
            self.assertIn("BatchMode=yes", ssh.call_args.args[0])
            device = json.loads((run / "report.json").read_text())["devices"][0]
            self.assertIs(False, device["configuration_source_observation"]["source_receipt_verified"])
            self.assertEqual("success", device["configuration_authority"]["state"])
            self.assertEqual("success", device["stages"]["config_apply"]["status"],
                             "independent current manual receipt does not require bootstrap provenance")
            self.assertNotEqual("success", device["stages"]["complete"]["status"])
            self.assertFalse(monitor.completion_handoff_device_complete(device))
            self.assertFalse(html.ztp_completed(device))
            self.assertEqual(current, authority.read_current(root, "EXAMPLE-Leaf01"))
            self.assertEqual(original, receipt.read_bytes())

    def test_new_generation_started_during_collection_cannot_be_revoked_by_an_old_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor, receipt, _produced, device, result = self.monitor_cycle_fixture(Path(directory).resolve())
            root = receipt.parents[2]
            authority = self.manual.config_sync_authority
            expected = authority.read_current(root, "EXAMPLE-Leaf01")
            new = authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli")
            self.current_monitor_gate(monitor)(device, result, root, expected)
            self.assertEqual(new, authority.read_current(root, "EXAMPLE-Leaf01"))
            self.assertNotEqual("success", device["stages"]["config_apply"]["status"])
            self.assertNotEqual("success", device["stages"]["complete"]["status"])

    def test_disabled_collection_is_unknown_and_cannot_mutate_the_writer_history(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor, receipt, _produced, device, _result = self.monitor_cycle_fixture(Path(directory).resolve())
            root = receipt.parents[2]
            authority = self.manual.config_sync_authority
            expected = authority.read_current(root, "EXAMPLE-Leaf01")
            for kind in ("not-collected", "ssh_disabled"):
                with self.subTest(kind=kind):
                    self.current_monitor_gate(monitor)(device, {"kind": kind}, root, expected)
                    self.assertEqual(expected, authority.read_current(root, "EXAMPLE-Leaf01"))
                    self.assertNotEqual("success", device["stages"]["config_apply"]["status"])

    def test_negative_current_generation_gate_preserves_explicit_stage_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor, receipt, _produced, device, result = self.monitor_cycle_fixture(Path(directory).resolve(), live_text="- set: {}\n")
            root = receipt.parents[2]
            expected = self.manual.config_sync_authority.read_current(root, "EXAMPLE-Leaf01")
            device["stages"]["config_apply"] = monitor.stage("failed", "actual apply failed", result["observed_at"])
            device["stages"]["complete"] = monitor.stage("failed", "actual completion failed", result["observed_at"])
            self.current_monitor_gate(monitor)(device, result, root, expected)
            self.assertEqual("failed", device["stages"]["config_apply"]["status"])
            self.assertEqual("failed", device["stages"]["complete"]["status"])

    def test_monitor_cannot_turn_an_inflight_pending_writer_into_a_failed_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor, receipt, _produced, device, result = self.monitor_cycle_fixture(Path(directory).resolve())
            root = receipt.parents[2]
            authority = self.manual.config_sync_authority
            pending = authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli")
            self.current_monitor_gate(monitor)(device, result, root, pending)
            self.assertEqual(pending, authority.read_current(root, "EXAMPLE-Leaf01"))
            self.assertNotEqual("success", device["stages"]["config_apply"]["status"])

    def test_monitor_rejects_boolean_and_float_generation_without_mutating_current_history(self):
        for generation in (True, 1.0):
            with self.subTest(generation=generation), tempfile.TemporaryDirectory() as directory:
                monitor, receipt, _produced, device, result = self.monitor_cycle_fixture(Path(directory).resolve())
                root = receipt.parents[2]
                authority = self.manual.config_sync_authority
                current = authority.read_current(root, "EXAMPLE-Leaf01")
                forged = {**current, "generation": generation}
                self.current_monitor_gate(monitor)(device, result, root, forged)
                self.assertEqual(current, authority.read_current(root, "EXAMPLE-Leaf01"))
                self.assertIs(True, device["configuration_authority"]["veto"])
                self.assertNotEqual("success", device["stages"]["config_apply"]["status"])

    def test_monitor_rechecks_generation_after_secure_receipt_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor, receipt, _produced, device, result = self.monitor_cycle_fixture(Path(directory).resolve())
            root = receipt.parents[2]
            authority = self.manual.config_sync_authority
            expected = authority.read_current(root, "EXAMPLE-Leaf01")
            real_read = authority.read_current_receipt
            new = []
            def read_then_change(*args, **kwargs):
                answer = real_read(*args, **kwargs)
                new.append(authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli"))
                return answer
            with mock.patch.object(monitor.config_sync_authority, "read_current_receipt", side_effect=read_then_change):
                self.current_monitor_gate(monitor)(device, result, root, expected)
            self.assertEqual(new[0], authority.read_current(root, "EXAMPLE-Leaf01"))
            self.assertIs(True, device["configuration_authority"]["veto"])
            self.assertNotEqual("success", device["stages"]["config_apply"]["status"])

    def test_monitor_compare_and_revoke_preserves_new_writer_started_at_revoke_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor, receipt, _produced, device, result = self.monitor_cycle_fixture(Path(directory).resolve(), live_text="- set: {}\n")
            root = receipt.parents[2]
            authority = self.manual.config_sync_authority
            expected = authority.read_current(root, "EXAMPLE-Leaf01")
            real_revoke = authority.revoke
            new = []
            def begin_then_revoke(*args, **kwargs):
                self.assertEqual(expected, kwargs["expected"], "the exact captured era must be passed into lock-held CAS")
                new.append(authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli"))
                return real_revoke(*args, **kwargs)
            with mock.patch.object(monitor.config_sync_authority, "revoke", side_effect=begin_then_revoke):
                self.current_monitor_gate(monitor)(device, result, root, expected)
            self.assertEqual(new[0], authority.read_current(root, "EXAMPLE-Leaf01"))
            self.assertIs(True, device["configuration_authority"]["veto"])

    def test_monitor_missing_unsafe_or_ambiguous_current_receipt_cannot_borrow_old_log_success(self):
        for damage in ("missing", "unsafe-mode", "ambiguous"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as directory:
                monitor, receipt, _produced, device, result = self.monitor_cycle_fixture(Path(directory).resolve())
                root = receipt.parents[2]
                authority = self.manual.config_sync_authority
                expected = authority.read_current(root, "EXAMPLE-Leaf01")
                original = receipt.read_bytes()
                if damage == "missing":
                    receipt.rename(receipt.with_name("retained-result.json"))
                elif damage == "unsafe-mode":
                    receipt.chmod(0o644)
                else:
                    duplicate = root / "second/EXAMPLE-Leaf01/result.json"
                    duplicate.parent.mkdir(parents=True, mode=0o700)
                    duplicate.write_bytes(original)
                    duplicate.chmod(0o600)
                self.current_monitor_gate(monitor)(device, result, root, expected)
                self.assertIs(True, device["configuration_authority"]["veto"])
                self.assertNotEqual("success", device["stages"]["config_apply"]["status"])
                self.assertEqual("failed", authority.read_current(root, "EXAMPLE-Leaf01")["state"])
                retained = receipt.with_name("retained-result.json") if damage == "missing" else receipt
                self.assertEqual(original, retained.read_bytes())

    def test_actual_monitor_once_captures_generation_before_collect_and_publishes_current_veto(self):
        for drift, newer_during_collect in ((False, False), (True, False), (False, True)):
            with self.subTest(drift=drift, newer=newer_during_collect), tempfile.TemporaryDirectory() as directory:
                project = Path(directory).resolve()
                monitor, receipt, _produced, _device, result = self.monitor_cycle_fixture(project)
                authority = self.manual.config_sync_authority
                root = receipt.parents[2]
                original = receipt.read_bytes()
                (project / "02-devices_config.csv").write_text(
                    "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip,config_method\n"
                    "EXAMPLE-Leaf01,eth,oob,192.0.2.10,24,192.0.2.1,02:00:00:00:00:01,,,,,,ztp\n", encoding="utf-8")
                apache, dhcp = project / "apache.log", project / "dhcp.log"
                apache.write_text("")
                dhcp.write_text("")
                air = project / "air.json"
                air.write_text('{"nodes": {}}', encoding="utf-8")
                args = monitor.parser().parse_args([
                    str(project), "--output-dir", str(project / "monitor-reports"),
                    "--apache-log", str(apache), "--dhcp-log", str(dhcp),
                ])
                captured = []
                def collect(*_args, **_kwargs):
                    captured.append(authority.read_current(root, "EXAMPLE-Leaf01"))
                    if newer_during_collect:
                        authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli")
                    live = "- set: {}\n" if drift else result["live_config_observation"]["text"]
                    return {**result, "ztp_log": "", "ifreload_log": "", "failed_yaml": "", "stderr": "",
                            "attempts": [], "remote_eth1_mac": "", "host_key_commands": [],
                            "applied_config_observation": {"trusted": False, "fingerprint": "", "reason": "missing", "receipt": {}, "raw_yaml": ""},
                            "live_config_observation": {"kind": "ok", "text": live, "sha256": hashlib.sha256(live.encode()).hexdigest()}}
                with mock.patch.object(monitor, "load_release_identity", return_value={"release_id": "isolated-fixture", "generated_at": "2026-10-07T01:00:00+08:00", "dhcp_status": "enabled"}), \
                        mock.patch.object(monitor, "service_runtime_backend", return_value=SimpleNamespace(name="systemd")), \
                        mock.patch.object(monitor, "service_state", return_value={"active": "fixture", "enabled": "fixture", "error": ""}), \
                        mock.patch.object(monitor, "ACTIVE_AIR_JSON", air), \
                        mock.patch.object(monitor, "collect_switch", side_effect=collect):
                    run = monitor.monitor_once(args, project)
                report = json.loads((run / "report.json").read_text())
                self.assertEqual(1, len(captured), "one actual monitor collection, not a synthetic post-finalize call")
                device = report["devices"][0]
                record = device["configuration_authority"]
                self.assertEqual(2 if newer_during_collect else 1, record["generation"])
                self.assertIs(drift or newer_during_collect, record["veto"])
                self.assertEqual("warning" if drift or newer_during_collect else "success", device["stages"]["config_apply"]["status"])
                self.assertNotEqual("success", device["overall"])
                self.assertFalse(monitor.completion_handoff_device_complete(device))
                current = authority.read_current(root, "EXAMPLE-Leaf01")
                self.assertEqual("pending" if newer_during_collect else "failed" if drift else "success", current["state"])
                self.assertEqual(original, receipt.read_bytes())

    def test_real_writer_receipt_is_readable_only_in_its_current_local_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, produced = self.published_receipt(Path(directory).resolve())
            authority = self.manual.config_sync_authority
            root = receipt.parents[2]
            original, inode = receipt.read_bytes(), receipt.stat().st_ino
            self.assertEqual(produced, authority.read_current_receipt(root, "EXAMPLE-Leaf01", receipt))
            newer = authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli")
            self.assertEqual(2, newer["generation"])
            self.assertIsNone(authority.read_current_receipt(root, "EXAMPLE-Leaf01", receipt))
            self.assertEqual((original, inode), (receipt.read_bytes(), receipt.stat().st_ino))

    def test_real_writer_and_monitor_observe_own_identity_and_same_live_digest_without_inheriting_receipt(self):
        from test_cases.module_loader import load_script
        monitor = load_script("f02_writer_monitor_bound_live_workflow", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, text = self.fixture(project)
            root = project / "99-output-ztp/manual-config-sync"
            authority = self.manual.config_sync_authority
            ticket = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            written = self.run_writer(project, client, prepared, run="first", ticket=ticket)
            raw = (
                "__HOSTNAME_BEGIN__\nEXAMPLE-Leaf01\n__HOSTNAME_END__\n"
                "__ETH0_MAC_BEGIN__\n02:00:00:00:00:01\n__ETH0_MAC_END__\n"
                "__ETH1_MAC_BEGIN__\n\n__ETH1_MAC_END__\n"
                "__HTTP_MONITOR_LIVE_V1_BEGIN__\n" + text + "\n__HTTP_MONITOR_LIVE_V1_END__=0\n"
            )
            device = {"hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10",
                      "mac_plain": "020000000001", "ssh_user": "cumulus", "ssh_ips": ["192.0.2.10"]}
            with mock.patch.object(monitor, "run_command", return_value={"returncode": 0, "stdout": raw, "stderr": ""}) as run:
                observed = monitor.collect_switch(device, 5, None, project / "known-hosts")
            self.assertEqual(1, run.call_count)
            self.assertIn("BatchMode=yes", run.call_args.args[0])
            proof = monitor.bind_monitor_live_observation(device, observed)
            expected = hashlib.sha256(text.encode()).hexdigest()
            self.assertIs(True, proof["batch_identity_verified"])
            self.assertEqual(expected, proof["live_state_sha256"])
            self.assertEqual(expected, written["live_state_sha256"])
            self.assertNotIn("generation", proof, "observer must not invent a generation from an old writer receipt")
            missing = {**observed, "live_config_observation": {"kind": "missing", "text": "", "sha256": ""}}
            self.assertIs(False, monitor.bind_monitor_live_observation(device, missing)["batch_identity_verified"])
            self.assertEqual("success", authority.read_current(root, "EXAMPLE-Leaf01")["state"])

    def test_same_connection_identity_mismatch_withdraws_previous_success(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, text = self.fixture(project)
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            first = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            previous = self.run_writer(project, client, prepared, run="first", ticket=first)
            self.assertEqual("success", authority.read_current(root, "EXAMPLE-Leaf01")["state"])
            second = authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli")
            client.run.side_effect = [
                SimpleNamespace(returncode=0, stdout=text, stderr=""),
                SimpleNamespace(returncode=0, stdout="saved\n", stderr=""),
                SimpleNamespace(returncode=0, stdout="HTTP_CONFIG_SYNC_LIVE_V1\nEXAMPLE-Leaf01\n02:00:00:00:00:02\n" + text, stderr=""),
            ]
            rejected = self.run_writer(project, client, prepared, run="second", ticket=second)
            self.assertEqual("failed", rejected["state"])
            self.assertNotIn("live_state_sha256", rejected)
            self.assertEqual(previous, json.loads((root / "first/EXAMPLE-Leaf01/result.json").read_text()))
            current = authority.read_current(root, "EXAMPLE-Leaf01")
            self.assertEqual((2, "failed", True), (current["generation"], current["state"], current["veto"]))

    def test_separate_identity_check_cannot_authorize_an_unbound_live_state_read(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, text = self.fixture(project)
            # The older two-SSH implementation accepts plain matching YAML
            # even though that later connection supplied no hostname or MAC.
            client.run.side_effect = [
                SimpleNamespace(returncode=0, stdout=text, stderr=""),
                SimpleNamespace(returncode=0, stdout="saved\n", stderr=""),
                SimpleNamespace(returncode=0, stdout=text, stderr=""),
            ]
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            ticket = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            result = self.run_writer(project, client, prepared, run="unbound", ticket=ticket)
            self.assertEqual("failed", result["state"])
            self.assertNotIn("live_state_sha256", result)
            current = authority.read_current(root, "EXAMPLE-Leaf01")
            self.assertEqual((1, "failed", True), (current["generation"], current["state"], current["veto"]))

    def test_real_writer_cannot_launder_an_unsafe_previous_receipt_into_success(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            root = project / "99-output-ztp/manual-config-sync"
            ticket = self.manual.config_sync_authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            receipt = root / "first/EXAMPLE-Leaf01/result.json"
            receipt.parent.mkdir(parents=True)
            original = b'{"state":"failed","reason":"unsafe-existing-evidence"}\n'
            receipt.write_bytes(original)
            receipt.chmod(0o666)
            before = receipt.stat()
            with self.assertRaises((OSError, ValueError)):
                self.run_writer(project, client, prepared, run="first", ticket=ticket)
            self.assertEqual(original, receipt.read_bytes())
            self.assertEqual(before.st_ino, receipt.stat().st_ino)
            self.assertEqual(0o666, stat.S_IMODE(receipt.stat().st_mode))
            self.assertEqual(ticket, self.manual.config_sync_authority.read_current(root, "EXAMPLE-Leaf01"))
            self.assertFalse(list(receipt.parent.glob(".result.json.*")))

    def test_real_writer_stage_rebind_cannot_mint_current_success(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            root = project / "99-output-ztp/manual-config-sync"
            ticket = self.manual.config_sync_authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            foreign = project / "foreign.json"
            image = b'{"state":"triggered","reason":"foreign"}\n'
            foreign.write_bytes(image)
            real_sync = os.fsync
            changed = []
            def replace_result_stage(descriptor):
                real_sync(descriptor)
                if changed or not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    return
                stages = list(root.glob("first/EXAMPLE-Leaf01/.result.json.*"))
                if not stages:
                    return
                self.assertEqual(1, len(stages))
                stage = stages[0]
                self.assertEqual(os.fstat(descriptor).st_ino, stage.stat().st_ino)
                stage.unlink()
                stage.symlink_to(foreign)
                changed.append(stage)
            with mock.patch.object(self.manual.os, "fsync", side_effect=replace_result_stage):
                with self.assertRaises(OSError):
                    self.run_writer(project, client, prepared, run="first", ticket=ticket)
            self.assertEqual(1, len(changed))
            self.assertTrue(changed[0].is_symlink())
            self.assertEqual(image, foreign.read_bytes())
            self.assertEqual(ticket, self.manual.config_sync_authority.read_current(root, "EXAMPLE-Leaf01"))

    def test_worker_receipt_wire_budget_rejects_and_retains_padding_without_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, _summary = self.worker_bundle(project)
            original = receipt.read_bytes()
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                self.assertEqual(produced, self.accept_own_writer())
                # JSON whitespace does not alter its journal digest, so only
                # the raw-file versioned bound can reject this input.
                oversized = b" " * 16384 + original
                receipt.write_bytes(oversized)
                self.assertEqual({}, self.accept_own_writer())
                self.assertEqual(oversized, receipt.read_bytes())
                receipt.write_bytes(original)
                self.assertEqual(produced, self.accept_own_writer())

    def test_real_writer_emits_closed_versioned_receipt_for_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, _summary = self.worker_bundle(project)
            fields = {
                "schema_version", "hostname", "type", "state", "transport_ip",
                "interface", "action", "started_at", "command_started_at", "operation",
                "effective_operation", "requested_operation", "operation_id", "trigger_source",
                "trigger_id", "command_ztp_log_sha256", "command_ztp_complete",
                "batch_identity_verified", "batch_identity_verified_at", "live_state_sha256",
                "finished_at", "generation", "source_identity",
            }
            self.assertEqual(fields, set(produced))
            self.assertEqual(1, produced["schema_version"])
            self.assertEqual(produced, self.manual.config_sync_authority.decode_receipt(
                self.manual.config_sync_authority.wire(produced),
            ))
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                self.assertEqual(produced, self.accept_own_writer())
            self.assertEqual(produced, json.loads(receipt.read_text()))

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "f02_authority_manual_writer", ROOT / "ztp/manual-ztp.py",
        )
        cls.manual = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.manual)
        worker_spec = importlib.util.spec_from_file_location(
            "f02_authority_worker_reader", ROOT / "monitor/manual-ztp-worker.py",
        )
        cls.worker = importlib.util.module_from_spec(worker_spec)
        worker_spec.loader.exec_module(cls.worker)

    def fixture(self, project):
        release = project / "release"
        release.mkdir(exist_ok=True)
        marker = release / ".published-complete"
        marker.write_text("ok\n", encoding="utf-8")
        expected = release / "EXAMPLE-Leaf01.yaml"
        text = "- set:\n    system:\n      hostname: EXAMPLE-Leaf01\n"
        expected.write_text(text, encoding="utf-8")
        prepared = {
            "published_marker": str(marker), "expected_yaml": str(expected),
            "published_release_dir": str(release.resolve()),
            "expected_yaml_sha256": self.manual.normalized_nvue_config(text, label="fixture")[2],
            "current_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "applied_fingerprint": "a" * 64, "published_mac_links": [],
        }
        client = mock.Mock()
        client.args.command_timeout = 20
        client.args.ssh_password = False
        client.run.side_effect = [
            SimpleNamespace(returncode=0, stdout=text, stderr=""),
            SimpleNamespace(returncode=0, stdout="saved\n", stderr=""),
            SimpleNamespace(returncode=0, stdout="HTTP_CONFIG_SYNC_LIVE_V1\nEXAMPLE-Leaf01\n02:00:00:00:00:01\n" + text, stderr=""),
        ]
        return client, prepared, text

    def run_writer(self, project, client, prepared, *, run, ticket):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                self.manual, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ))
            stack.enter_context(mock.patch.object(self.manual, "verify_prepared_release_binding"))
            stack.enter_context(mock.patch.object(
                self.manual, "collect_applied_config", return_value={"fingerprint": "a" * 64},
            ))
            stack.enter_context(mock.patch.object(
                self.manual, "evaluate_replace_config_guard", return_value={"allowed": True},
            ))
            return self.manual.trigger_one(
                client, {"hostname": "EXAMPLE-Leaf01", "type": "eth", "mac_plain": "020000000001"}, "",
                project / "99-output-ztp/manual-config-sync" / run,
                trigger_source="manual_config_sync_cli", trigger_id=ticket["trigger_id"],
                operation="replace-config", operation_id=ticket["operation_id"],
                prepared=prepared, requested_operation="replace-config", authority_ticket=ticket,
            )

    def test_real_writer_receipt_binds_own_current_generation_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, text = self.fixture(project)
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            ticket = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            self.assertEqual((1, "pending", True), (ticket["generation"], ticket["state"], ticket["veto"]))
            result = self.run_writer(project, client, prepared, run="first", ticket=ticket)
            self.assertEqual("triggered", result["state"])
            self.assertIs(result["batch_identity_verified"], True)
            self.assertEqual(hashlib.sha256(text.encode("utf-8")).hexdigest(), result["live_state_sha256"])
            self.assertEqual((1, ticket["source_identity"]), (result["generation"], result["source_identity"]))
            receipt = root / "first/EXAMPLE-Leaf01/result.json"
            self.assertEqual(result, json.loads(receipt.read_text(encoding="utf-8")))
            current = authority.read_current(root, "EXAMPLE-Leaf01")
            # Independently serialize the writer's own receipt; do not ask
            # the production digest helper to generate the expected hash.
            expected_wire = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            self.assertEqual(hashlib.sha256(expected_wire).hexdigest(), current["receipt_sha256"])
            self.assertEqual((1, "success", False), (current["generation"], current["state"], current["veto"]))
            self.assertEqual(3, client.run.call_count)

    def test_failed_next_writer_withdraws_old_success_and_old_finish_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            first = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            previous = self.run_writer(project, client, prepared, run="first", ticket=first)
            self.assertEqual("success", authority.read_current(root, "EXAMPLE-Leaf01")["state"])
            second = authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli")
            self.assertEqual((2, "pending", True), (second["generation"], second["state"], second["veto"]))
            client.run.side_effect = self.manual.ManualZtpError("fixture transport failed")
            failed = self.run_writer(project, client, prepared, run="second", ticket=second)
            self.assertEqual("failed", failed["state"])
            current = authority.read_current(root, "EXAMPLE-Leaf01")
            self.assertEqual((2, "failed", True), (current["generation"], current["state"], current["veto"]))
            with self.assertRaises(authority.AuthorityError):
                authority.finish(root, first, previous)
            self.assertEqual(current, authority.read_current(root, "EXAMPLE-Leaf01"))

    def test_real_writer_identity_proof_must_be_inside_its_finished_session(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, produced = self.published_receipt(Path(directory).resolve())
            before = receipt.read_bytes()
            self.assertTrue(self.worker.config_sync_promotion_ready(produced))
            independent = {
                **produced, "command_started_at": "2026-10-03T10:00:00+08:00",
                "batch_identity_verified_at": "2026-10-03T10:00:01+08:00",
                "finished_at": "2026-10-03T10:00:02+08:00",
            }
            for updates in (
                {"finished_at": ""}, {"finished_at": None},
                {"finished_at": "2026-10-03T10:00:02"},
                {"finished_at": "2026-10-03T09:59:59+08:00"},
                {"batch_identity_verified_at": "2026-10-03T10:00:03+08:00"},
            ):
                with self.subTest(updates=updates):
                    self.assertFalse(self.worker.config_sync_promotion_ready({
                        **independent, **updates,
                    }))
            self.assertEqual(before, receipt.read_bytes())
            project = Path(directory).resolve()
            devices = project / "02-devices_config.csv"
            devices.write_text("hostname,type\nEXAMPLE-Leaf01,eth\n", encoding="utf-8")
            self.manual.atomic_json(receipt.parent.parent / "summary.json", {
                "state": "triggered", "operation": "replace-config",
                "effective_operation": "replace-config", "operation_id": "op-1",
                "trigger_source": "manual_config_sync_cli", "generation": 1,
                "targets": [{"hostname": "EXAMPLE-Leaf01", "trigger_id": "trigger-1",
                             "effective_operation": "replace-config", "generation": 1}],
                "results": [produced],
            })
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                imported = self.worker.latest_cli_operations()["example-leaf01"]
            self.assertEqual(produced["finished_at"], imported["finished_at"])
            self.assertTrue(self.worker.config_sync_promotion_ready(imported))

    def test_interactive_writer_cannot_publish_successful_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            client.args.ssh_password = True
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            ticket = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            result = self.run_writer(project, client, prepared, run="interactive", ticket=ticket)
            self.assertEqual("failed", result["state"])
            self.assertNotIn("live_state_sha256", result)
            current = authority.read_current(root, "EXAMPLE-Leaf01")
            self.assertEqual((1, "failed", True), (current["generation"], current["state"], current["veto"]))

    def test_writer_late_authority_rebinding_cannot_return_a_promotable_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            ticket = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            private = root / ".authority"
            marker = private / "example-leaf01.pending"
            witness = private / "example-leaf01.witness.json"
            foreign = project / "foreign.json"
            foreign.write_bytes(b"foreign-writer-witness\n")
            foreign.chmod(0o600)
            changed = False
            real_fsync = os.fsync

            def rebind_after_guard_unlink(descriptor):
                nonlocal changed
                real_fsync(descriptor)
                value = os.fstat(descriptor)
                if (stat.S_ISDIR(value.st_mode) and value.st_ino == private.stat().st_ino
                        and not marker.exists() and not changed):
                    changed = True
                    witness.unlink()
                    witness.symlink_to(foreign)

            with mock.patch.object(authority.os, "fsync", side_effect=rebind_after_guard_unlink):
                with self.assertRaises(authority.AuthorityError):
                    self.run_writer(project, client, prepared, run="late-rebind", ticket=ticket)
            self.assertTrue(changed)
            self.assertEqual(b"foreign-writer-witness\n", foreign.read_bytes())
            self.assertTrue(witness.is_symlink())
            self.assertTrue(marker.exists())
            with self.assertRaises(authority.AuthorityError):
                authority.read_current(root, "EXAMPLE-Leaf01")

    def test_real_main_preview_does_not_advance_and_failed_preflight_revokes_previous_era(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            device = {"hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10", "mac_plain": "021122334455"}
            root = project / "99-output-ztp/manual-config-sync"
            authority = self.manual.config_sync_authority
            first = authority.begin(root, device["hostname"], "op-1", "trigger-1", "manual_config_sync_cli")
            previous = self.run_writer(project, client, prepared, run="first", ticket=first)
            current = authority.read_current(root, device["hostname"])
            self.assertEqual("success", current["state"])
            with ExitStack() as stack:
                for name, value in (
                    ("resolve_project", project), ("read_devices", [device]),
                    ("acquire_deployment_lock", None), ("release_deployment_lock", None),
                    ("apply_sudo_policy", None), ("dedicated_yaml_ready", (True, "")),
                    ("SshClient", client), ("display_preflight_diff", None),
                ):
                    stack.enter_context(mock.patch.object(self.manual, name, return_value=value))
                stack.enter_context(mock.patch("sys.stdout", new=io.StringIO()))
                stack.enter_context(mock.patch("sys.stderr", new=io.StringIO()))
                args = [device["hostname"], "--project", "prod", "--replace-config", "--non-interactive", "--yes"]
                with mock.patch.object(self.manual, "preflight_one", return_value=dict(prepared)):
                    self.assertEqual(0, self.manual.main(args + ["--preflight-only", "--operation-id", "preview", "--trigger-id", "preview-trigger"]))
                self.assertEqual(current, authority.read_current(root, device["hostname"]), "read-only preview cannot revoke or mint an era")

                def failed_preflight(*_args, **_kwargs):
                    pending = authority.read_current(root, device["hostname"])
                    self.assertEqual((2, "pending", True), (pending["generation"], pending["state"], pending["veto"]))
                    raise self.manual.ManualZtpError("fixture preflight failed before device writes")

                with mock.patch.object(self.manual, "preflight_one", side_effect=failed_preflight):
                    self.assertEqual(2, self.manual.main(args + ["--operation-id", "op-2", "--trigger-id", "trigger-2"]))
            pending = authority.read_current(root, device["hostname"])
            self.assertEqual((2, "pending", True), (pending["generation"], pending["state"], pending["veto"]))
            with self.assertRaises(authority.AuthorityError):
                authority.finish(root, first, previous)
            summaries = [json.loads(path.read_text(encoding="utf-8")) for path in root.glob("*/summary.json")]
            self.assertEqual({"preview_ready", "failed"}, {item["state"] for item in summaries})
            failed = next(item for item in summaries if item["state"] == "failed")
            self.assertEqual((2, 2), (failed["generation"], failed["targets"][0]["generation"]))
            self.assertEqual([], failed["results"])

    def published_receipt(self, project):
        client, prepared, _text = self.fixture(project)
        root = project / "99-output-ztp/manual-config-sync"
        ticket = self.manual.config_sync_authority.begin(
            root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli",
        )
        produced = self.run_writer(project, client, prepared, run="first", ticket=ticket)
        return root / "first/EXAMPLE-Leaf01/result.json", produced

    def worker_bundle(self, project):
        receipt, produced = self.published_receipt(project)
        devices = project / "02-devices_config.csv"
        devices.write_text("hostname,type\nEXAMPLE-Leaf01,eth\n", encoding="utf-8")
        summary = {
            "state": "triggered", "operation": "replace-config",
            "effective_operation": "replace-config", "operation_id": "op-1",
            "trigger_source": "manual_config_sync_cli", "generation": 1,
            "targets": [{"hostname": "EXAMPLE-Leaf01", "trigger_id": "trigger-1",
                         "effective_operation": "replace-config", "generation": 1}],
            "results": [produced],
        }
        self.manual.atomic_json(receipt.parent.parent / "summary.json", summary)
        return devices, receipt, produced, summary

    def accept_own_writer(self):
        return self.worker.accepted_result(
            "trigger-1", hostname="EXAMPLE-Leaf01", operation_id="op-1",
            operation="replace-config", trigger_source="manual_config_sync_cli",
        )

    def test_worker_cannot_reuse_success_after_local_revocation_or_new_pending_era(self):
        for transition in ("revoke", "next-era", "missing-authority"):
            with self.subTest(transition=transition), tempfile.TemporaryDirectory() as directory:
                project = Path(directory).resolve()
                devices, receipt, produced, _summary = self.worker_bundle(project)
                root = receipt.parents[2]
                before = receipt.read_bytes()
                authority = self.manual.config_sync_authority
                with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                    self.assertEqual(produced, self.accept_own_writer())
                    if transition == "revoke":
                        authority.revoke(root, "EXAMPLE-Leaf01")
                    elif transition == "next-era":
                        pending = authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli")
                        self.assertEqual((2, "pending", True), (pending["generation"], pending["state"], pending["veto"]))
                    else:
                        (root / ".authority").rename(root / "isolated-old-authority")
                    self.assertEqual({}, self.accept_own_writer())
                self.assertEqual(before, receipt.read_bytes())
                if transition == "missing-authority":
                    self.assertFalse((root / ".authority").exists(), "reader cannot mint replacement history")

    def test_worker_checks_own_generation_namespace_digest_and_summary_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, summary = self.worker_bundle(project)
            summary_path = receipt.parent.parent / "summary.json"
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                self.assertEqual(produced, self.accept_own_writer())
                for field, value in (("generation", None), ("generation", True),
                                     ("generation", 1.0), ("generation", 2),
                                     ("source_identity", "0:0"),
                                     ("live_state_sha256", "b" * 64)):
                    with self.subTest(receipt_field=field, value=value):
                        mutant = {**produced, field: value}
                        self.manual.atomic_json(receipt, mutant)
                        self.manual.atomic_json(summary_path, {**summary, "results": [mutant]})
                        before = receipt.read_bytes()
                        self.assertEqual({}, self.accept_own_writer())
                        self.assertEqual(before, receipt.read_bytes())
                self.manual.atomic_json(receipt, produced)
                for value in (None, True, 1.0, 2):
                    with self.subTest(summary_generation=value):
                        self.manual.atomic_json(summary_path, {**summary, "generation": value})
                        self.assertEqual({}, self.accept_own_writer())
                    with self.subTest(target_generation=value):
                        self.manual.atomic_json(summary_path, {**summary, "targets": [
                            {**summary["targets"][0], "generation": value},
                        ]})
                        self.assertEqual({}, self.accept_own_writer())
                self.manual.atomic_json(summary_path, summary)
                self.assertEqual(produced, self.accept_own_writer())

    def test_worker_rechecks_local_era_after_receipt_and_summary_read(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, _summary = self.worker_bundle(project)
            original_read = self.worker._read_new_config_sync_receipt
            changed = False
            def next_era_after_summary(path, **kwargs):
                nonlocal changed
                value = original_read(path, **kwargs)
                if path.name == "summary.json" and not changed:
                    changed = True
                    self.manual.config_sync_authority.begin(
                        receipt.parents[2], "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
                    )
                return value
            with mock.patch.object(self.worker, "DEVICES_CSV", devices), \
                    mock.patch.object(self.worker, "_read_new_config_sync_receipt", side_effect=next_era_after_summary):
                self.assertEqual({}, self.accept_own_writer())
            self.assertTrue(changed)
            self.assertEqual(produced, json.loads(receipt.read_text()))

    def test_cli_import_uses_local_generation_not_reporter_wall_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, previous, summary = self.worker_bundle(project)
            root = receipt.parents[2]
            # Old reporter wall time is deliberately much newer than the next
            # causal era. Only the local single writer chooses the generation.
            self.manual.atomic_json(receipt.parent.parent / "summary.json", {
                **summary, "requested_at": "9999-01-01T00:00:00Z",
                "generated_at": "9999-01-01T00:00:00Z",
            })
            client, prepared, _text = self.fixture(project)
            ticket = self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            self.assertEqual(2, ticket["generation"])
            with mock.patch.object(self.manual, "datetime") as clock:
                clock.now.return_value = datetime.fromisoformat("2020-01-01T00:00:00+00:00")
                current = self.run_writer(project, client, prepared, run="second", ticket=ticket)
            self.manual.atomic_json(root / "second/summary.json", {
                **summary, "generation": 2, "operation_id": "op-2",
                "requested_at": "2020-01-01T00:00:00Z", "generated_at": "2020-01-01T00:00:00Z",
                "targets": [{**summary["targets"][0], "generation": 2, "trigger_id": "trigger-2"}],
                "results": [current],
            })
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                imported = self.worker.latest_cli_operations()["example-leaf01"]
                self.assertEqual(("op-2", "trigger-2", 2, current["source_identity"]), (
                    imported["operation_id"], imported["trigger_id"], imported.get("generation"),
                    imported.get("source_identity"),
                ))
                self.assertTrue(self.worker.config_sync_promotion_ready(imported))
                self.manual.config_sync_authority.revoke(root, "EXAMPLE-Leaf01")
                revoked = self.worker.latest_cli_operations().get("example-leaf01", {})
                self.assertFalse(self.worker.config_sync_promotion_ready(revoked))
            self.assertEqual(previous, json.loads(receipt.read_text()))

    def test_cli_import_cannot_launder_missing_tampered_or_ambiguous_receipt(self):
        for defect in ("missing", "digest", "duplicate-summary", "unsafe-summary", "missing-authority"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                project = Path(directory).resolve()
                devices, receipt, produced, summary = self.worker_bundle(project)
                root = receipt.parents[2]
                before = receipt.read_bytes()
                with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                    self.assertTrue(self.worker.config_sync_promotion_ready(
                        self.worker.latest_cli_operations()["example-leaf01"],
                    ))
                    if defect == "missing":
                        receipt.rename(receipt.with_name("retained-receipt.json"))
                    elif defect == "digest":
                        mutant = {**produced, "live_state_sha256": "b" * 64}
                        self.manual.atomic_json(receipt, mutant)
                        self.manual.atomic_json(receipt.parent.parent / "summary.json", {**summary, "results": [mutant]})
                    elif defect == "duplicate-summary":
                        self.manual.atomic_json(root / "duplicate/summary.json", summary)
                    elif defect == "unsafe-summary":
                        (receipt.parent.parent / "summary.json").chmod(0o666)
                    else:
                        (root / ".authority").rename(root / "retained-authority")
                    value = self.worker.latest_cli_operations().get("example-leaf01", {})
                    self.assertFalse(self.worker.config_sync_promotion_ready(value))
                if defect == "missing":
                    self.assertEqual(before, receipt.with_name("retained-receipt.json").read_bytes())
                elif defect != "digest":
                    self.assertEqual(before, receipt.read_bytes())

    def test_cli_import_selects_current_pending_era_without_reusing_success(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, summary = self.worker_bundle(project)
            root = receipt.parents[2]
            self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            self.manual.atomic_json(root / "pending/summary.json", {
                **summary, "generation": 2, "operation_id": "op-2", "state": "preflight",
                "requested_at": "2020-01-01T00:00:00Z", "generated_at": "2020-01-01T00:00:00Z",
                "targets": [{**summary["targets"][0], "generation": 2, "trigger_id": "trigger-2"}],
                "results": [],
            })
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                value = self.worker.latest_cli_operations()["example-leaf01"]
            self.assertEqual(("op-2", "trigger-2", 2, "running"), (
                value["operation_id"], value["trigger_id"], value.get("generation"), value["state"],
            ))
            self.assertFalse(self.worker.config_sync_promotion_ready(value))

    def test_promotion_requires_a_strict_bounded_generation_and_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, produced = self.published_receipt(Path(directory).resolve())
            self.assertTrue(self.worker.config_sync_promotion_ready(produced))
            for field, value in (("generation", None), ("generation", True),
                                 ("generation", 1.0), ("generation", 0),
                                 ("generation", -1), ("generation", 2 ** 63),
                                 ("source_identity", None), ("source_identity", ""),
                                 ("source_identity", "-1:2"), ("source_identity", "1:2:3"),
                                 ("source_identity", f"{2 ** 64}:2")):
                with self.subTest(field=field, value=value):
                    self.assertFalse(self.worker.config_sync_promotion_ready({**produced, field: value}))
            self.assertEqual(produced, json.loads(receipt.read_text()))

    def test_cli_import_rechecks_local_era_after_last_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, _summary = self.worker_bundle(project)
            original = self.worker.accepted_result
            def advance_after_acceptance(*args, **kwargs):
                value = original(*args, **kwargs)
                self.assertTrue(value)
                self.manual.config_sync_authority.begin(
                    receipt.parents[2], "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
                )
                return value
            with mock.patch.object(self.worker, "DEVICES_CSV", devices), \
                    mock.patch.object(self.worker, "accepted_result", side_effect=advance_after_acceptance):
                self.assertEqual({}, self.worker.latest_cli_operations())

    def test_cli_pending_import_does_not_cross_into_legacy_ztp_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, summary = self.worker_bundle(project)
            root = receipt.parents[2]
            self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            pending = {
                **summary, "generation": 2, "operation_id": "op-2", "state": "preflight",
                "targets": [{**summary["targets"][0], "generation": 2, "trigger_id": "trigger-2"}],
                "results": [],
            }
            path = root / "pending/summary.json"
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                for defect in ("operation", "effective_operation", "target-effective"):
                    with self.subTest(defect=defect):
                        mutant = {**pending, defect: "ztp"} if defect != "target-effective" else {
                            **pending, "targets": [{**pending["targets"][0], "effective_operation": "ztp"}],
                        }
                        self.manual.atomic_json(path, mutant)
                        self.assertEqual({}, self.worker.latest_cli_operations())

    def run_worker_once(self, project, devices):
        """Execute the real poll/status path, entirely inside our private fixture."""
        status_dir = project / "worker-status"
        status_dir.mkdir(exist_ok=True)
        queue = status_dir / "request.json"
        if not queue.exists():
            queue.write_text("{}\n", encoding="utf-8")
        with ExitStack() as stack:
            for name, path in (
                ("DEVICES_CSV", devices), ("STATUS_DIR", status_dir),
                ("STATUS_FILE", status_dir / "status.json"),
                ("REQUEST_FILE", queue), ("PID_FILE", status_dir / "own.pid"),
                ("ZTP_STATUS_DIR", project / "isolated-ztp-status"),
            ):
                stack.enter_context(mock.patch.object(self.worker, name, path))
            stack.enter_context(mock.patch("sys.argv", ["fixture-worker", "--scope", "prod"]))
            stack.enter_context(mock.patch.object(self.worker.time, "sleep", side_effect=KeyboardInterrupt))
            self.assertEqual(130, self.worker.main())
        return json.loads((status_dir / "status.json").read_text())["devices"]

    def test_real_worker_persists_own_proof_and_receipt_loss_withdrawal_is_sticky(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, _summary = self.worker_bundle(project)
            states = self.run_worker_once(project, devices)
            current = states["EXAMPLE-Leaf01"]
            self.assertEqual("config_sync_success", current["state"])
            for field in ("generation", "source_identity", "command_started_at", "finished_at",
                          "batch_identity_verified", "batch_identity_verified_at", "live_state_sha256",
                          "transport_ip", "interface"):
                with self.subTest(proof_field=field):
                    self.assertEqual(produced[field], current.get(field))
            original = receipt.read_bytes()
            retained = receipt.with_name("retained-result.json")
            receipt.rename(retained)
            revoked = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
            self.assertEqual("failed", revoked["state"])
            self.assertIs(revoked.get("authority_revoked"), True)
            retained.rename(receipt)
            restored = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
            self.assertEqual("failed", restored["state"], "restoring the same old receipt cannot undo withdrawal")
            self.assertIs(restored.get("authority_revoked"), True)
            self.assertEqual(original, receipt.read_bytes())

    def test_real_worker_adopts_new_causal_generation_despite_old_status_future_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, summary = self.worker_bundle(project)
            status_dir = project / "worker-status"
            status_dir.mkdir()
            self.manual.atomic_json(status_dir / "status.json", {
                "scope": "prod", "devices": {"EXAMPLE-Leaf01": {
                    **produced, "state": "config_sync_success",
                    "started_at": "9999-01-01T00:00:00Z",
                }},
            })
            root = receipt.parents[2]
            client, prepared, _text = self.fixture(project)
            ticket = self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            self.assertEqual(2, ticket["generation"])
            with mock.patch.object(self.manual, "datetime") as clock:
                clock.now.return_value = datetime.fromisoformat("2020-01-01T00:00:00+00:00")
                new = self.run_writer(project, client, prepared, run="next", ticket=ticket)
            self.manual.atomic_json(root / "next/summary.json", {
                **summary, "generation": 2, "operation_id": "op-2",
                "targets": [{**summary["targets"][0], "generation": 2, "trigger_id": "trigger-2"}],
                "results": [new],
            })
            current = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
            self.assertEqual(("config_sync_success", "op-2", 2), (
                current["state"], current["operation_id"], current.get("generation"),
            ))
            self.assertIs(current["batch_identity_verified"], True)
            self.assertEqual(new["live_state_sha256"], current["live_state_sha256"])
            # Reusing labels is not authority: a truly newer local integer
            # era may supersede the old veto, but generation 2 cannot do so.
            client, prepared, _text = self.fixture(project)
            ticket = self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            self.assertEqual(3, ticket["generation"])
            third = self.run_writer(project, client, prepared, run="third", ticket=ticket)
            self.manual.atomic_json(root / "third/summary.json", {
                **summary, "generation": 3, "operation_id": "op-2",
                "targets": [{**summary["targets"][0], "generation": 3, "trigger_id": "trigger-2"}],
                "results": [third],
            })
            current = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
            self.assertEqual(("config_sync_success", "op-2", 3), (
                current["state"], current["operation_id"], current["generation"],
            ))
            self.assertEqual(third["finished_at"], current["finished_at"])

    def test_real_worker_rejects_corrupt_saved_proof_without_repromoting_same_era(self):
        for field, invalid in (("batch_identity_verified", 1), ("generation", True),
                               ("source_identity", "0:0"), ("authority_revoked", 0),
                               ("live_state_sha256", "b" * 64)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                project = Path(directory).resolve()
                devices, _receipt, _produced, _summary = self.worker_bundle(project)
                self.run_worker_once(project, devices)
                path = project / "worker-status/status.json"
                previous = json.loads(path.read_text())
                previous["devices"]["EXAMPLE-Leaf01"][field] = invalid
                self.manual.atomic_json(path, previous)
                value = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
                self.assertEqual("failed", value["state"])
                self.assertIs(value.get("authority_revoked"), True)

    def test_receipt_loss_revokes_journal_even_if_old_worker_status_is_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, _summary = self.worker_bundle(project)
            self.run_worker_once(project, devices)
            status_path = project / "worker-status/status.json"
            previous = status_path.read_bytes()
            retained = receipt.with_name("retained-result.json")
            receipt.rename(retained)
            self.assertEqual("failed", self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]["state"])
            current = self.manual.config_sync_authority.read_current(receipt.parents[2], "EXAMPLE-Leaf01")
            self.assertEqual((1, "failed", True), tuple(current[field] for field in ("generation", "state", "veto")))
            retained.rename(receipt)
            status_path.write_bytes(previous)
            self.assertEqual("failed", self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]["state"])

    def test_receipt_loss_observer_cannot_revoke_a_concurrently_started_new_era(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, _summary = self.worker_bundle(project)
            self.run_worker_once(project, devices)
            receipt.rename(receipt.with_name("retained-result.json"))
            authority = self.manual.config_sync_authority
            original = authority.revoke
            advanced = False
            def begin_before_revocation(root, hostname, **kwargs):
                nonlocal advanced
                self.assertEqual(1, kwargs["expected"]["generation"])
                advanced = True
                authority.begin(root, hostname, "op-2", "trigger-2", "manual_config_sync_cli")
                return original(root, hostname, **kwargs)
            with mock.patch.object(authority, "revoke", side_effect=begin_before_revocation):
                self.assertEqual("failed", self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]["state"])
            self.assertTrue(advanced, "observer must attempt a guarded local revocation")
            current = authority.read_current(receipt.parents[2], "EXAMPLE-Leaf01")
            self.assertEqual((2, "pending", True, "op-2"), tuple(
                current[field] for field in ("generation", "state", "veto", "operation_id")
            ))

    def test_real_worker_cannot_leave_success_after_state_directory_sync_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, _summary = self.worker_bundle(project)
            status_dir = project / "worker-status"
            status_dir.mkdir()
            status_path = status_dir / "status.json"
            real_sync = os.fsync
            injected = False
            def fail_success_directory_sync(descriptor):
                nonlocal injected
                held = os.fstat(descriptor)
                if (stat.S_ISDIR(held.st_mode) and held.st_ino == status_dir.stat().st_ino
                        and status_path.exists() and not injected):
                    value = json.loads(status_path.read_text())
                    if value.get("devices", {}).get("EXAMPLE-Leaf01", {}).get("state") == "config_sync_success":
                        injected = True
                        raise OSError("injected worker success directory durability failure")
                real_sync(descriptor)
            with mock.patch.object(self.worker.os, "fsync", side_effect=fail_success_directory_sync):
                with self.assertRaisesRegex(OSError, "success directory durability failure"):
                    self.run_worker_once(project, devices)
            self.assertTrue(injected)
            saved = json.loads(status_path.read_text())
            self.assertNotEqual("config_sync_success", saved["devices"].get("EXAMPLE-Leaf01", {}).get("state"))
            self.assertEqual(produced, json.loads(receipt.read_text()))
            self.assertFalse(list(status_dir.glob(".status.json.*")))

    def test_real_worker_rejects_writer_receipt_with_unsafe_mode_or_foreign_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, produced = self.published_receipt(Path(directory).resolve())
            self.assertEqual(produced, self.worker._read_new_config_sync_receipt(receipt))
            receipt.chmod(0o666)
            with self.subTest(metadata="unsafe-mode"):
                self.assertEqual({}, self.worker._read_new_config_sync_receipt(receipt))
            receipt.chmod(0o600)
            real_fstat = os.fstat

            def foreign_owner(descriptor):
                observed = real_fstat(descriptor)
                fields = {name: getattr(observed, name) for name in (
                    "st_dev", "st_ino", "st_size", "st_nlink", "st_mode", "st_uid", "st_gid",
                    "st_mtime_ns", "st_ctime_ns",
                )}
                fields["st_uid"] = os.geteuid() + 1
                return SimpleNamespace(**fields)

            with mock.patch.object(self.worker.os, "fstat", side_effect=foreign_owner):
                with self.subTest(metadata="foreign-owner"):
                    self.assertEqual({}, self.worker._read_new_config_sync_receipt(receipt))
            self.assertEqual(produced, self.worker._read_new_config_sync_receipt(receipt))

    def test_real_worker_rejects_duplicate_members_in_writer_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, produced = self.published_receipt(Path(directory).resolve())
            raw = receipt.read_bytes()
            duplicate = raw.rstrip()[:-1] + b',"hostname":"EXAMPLE-Leaf01"}\n'
            receipt.write_bytes(duplicate)
            self.assertEqual({}, self.worker._read_new_config_sync_receipt(receipt))
            self.assertEqual(duplicate, receipt.read_bytes(), "reject-and-retain malformed evidence")
            self.assertEqual("EXAMPLE-Leaf01", produced["hostname"])

    def test_real_worker_rechecks_visible_writer_receipt_after_held_read(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, _produced = self.published_receipt(Path(directory).resolve())
            foreign = receipt.parent / "foreign.json"
            foreign.write_bytes(b'{"foreign":true}\n')
            foreign.chmod(0o600)
            real_read = os.read
            changed = False

            def rebind_visible_path(descriptor, count):
                nonlocal changed
                raw = real_read(descriptor, count)
                if raw and not changed:
                    changed = True
                    receipt.unlink()
                    receipt.symlink_to(foreign)
                return raw

            with mock.patch.object(self.worker.os, "read", side_effect=rebind_visible_path):
                self.assertEqual({}, self.worker._read_new_config_sync_receipt(receipt))
            self.assertTrue(changed)
            self.assertTrue(receipt.is_symlink())
            self.assertEqual(b'{"foreign":true}\n', foreign.read_bytes())

    def test_worker_validates_entire_summary_before_accepting_own_writer_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            receipt, produced = self.published_receipt(project)
            devices = project / "02-devices_config.csv"
            devices.write_text("hostname,type\nEXAMPLE-Leaf01,eth\n", encoding="utf-8")
            target = {"hostname": "EXAMPLE-Leaf01", "trigger_id": "trigger-1", "effective_operation": "replace-config", "generation": 1}
            summary = {
                "state": "triggered", "operation": "replace-config", "effective_operation": "replace-config",
                "operation_id": "op-1", "trigger_source": "manual_config_sync_cli", "generation": 1,
                "targets": [target], "results": [produced],
            }
            summary_path = receipt.parent.parent / "summary.json"

            def accept():
                return self.worker.accepted_result(
                    "trigger-1", hostname="EXAMPLE-Leaf01", operation_id="op-1",
                    operation="replace-config", trigger_source="manual_config_sync_cli",
                )

            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                self.manual.atomic_json(summary_path, summary)
                self.assertEqual(produced, accept())
                other_target = {"hostname": "OTHER-Leaf02", "trigger_id": "other-trigger", "effective_operation": "replace-config", "generation": 1}
                other_result = {"hostname": "OTHER-Leaf02", "trigger_id": "other-trigger", "state": "triggered"}
                mutations = (
                    {"targets": [target, other_target, {**other_target, "hostname": "other-leaf02"}], "results": [produced, other_result]},
                    {"targets": [target, other_target], "results": [produced, other_result, {**other_result, "hostname": "other-leaf02"}]},
                    {"results": [produced, other_result]},
                    {"targets": [target, other_target]},
                    {"targets": [target, "malformed-host-member"]},
                    {"results": [produced, {"trigger_id": "no-hostname"}]},
                )
                for mutation in mutations:
                    with self.subTest(mutation=mutation):
                        self.manual.atomic_json(summary_path, {**summary, **mutation})
                        before = summary_path.read_bytes()
                        self.assertEqual({}, accept())
                        self.assertEqual(before, summary_path.read_bytes(), "whole-summary reject-and-retain")
                self.manual.atomic_json(summary_path, summary)
                self.assertEqual(produced, accept())


if __name__ == "__main__":
    unittest.main()
