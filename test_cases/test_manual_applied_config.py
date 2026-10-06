"""Runtime NVUE normalization and manual ZTP preview/confirm comparisons."""

import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import subprocess
from unittest import mock
import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "manual_applied_config_under_test", ROOT / "ztp/manual-ztp.py",
)
MANUAL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MANUAL)

FEEDBACK_SPEC = importlib.util.spec_from_file_location(
    "manual_feedback_mac_contract_under_test", ROOT / "ztp/optimize/feedback.py",
)
FEEDBACK = importlib.util.module_from_spec(FEEDBACK_SPEC)
assert FEEDBACK_SPEC.loader is not None
FEEDBACK_SPEC.loader.exec_module(FEEDBACK)

MONITOR_SPEC = importlib.util.spec_from_file_location(
    "manual_result_monitor_under_test", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
)
MONITOR = importlib.util.module_from_spec(MONITOR_SPEC)
assert MONITOR_SPEC.loader is not None
sys.modules[MONITOR_SPEC.name] = MONITOR
try:
    MONITOR_SPEC.loader.exec_module(MONITOR)
finally:
    sys.modules.pop(MONITOR_SPEC.name, None)


MAC = "02:00:00:00:00:01"
DEVICE = {
    "hostname": "leaf01", "type": "eth", "ip": "192.0.2.10",
    "mac_plain": "020000000001", "identity_macs": {"eth0": "020000000001"},
}


def analyze_bootstrap_log_fixture(monitor, log, device_type="eth"):
    """Independent identity/clock fixture; expected stage values stay in tests."""
    device = {
        **DEVICE, "type": device_type, "ssh_ips": ["192.0.2.10"],
        "ssh_interfaces": {"192.0.2.10": "eth0"},
        "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
        "issues": [], "events": [],
    }
    monitor.analyze_switch(device, {
        "kind": "ok", "observed_at": "2026-10-06T12:00:00+00:00",
        "connected_ip": "192.0.2.10", "attempts": [],
        "remote_hostname": "leaf01", "remote_eth0_mac": MAC,
        "remote_eth1_mac": "", "remote_interface_macs": {"eth0": MAC},
        "local_started_epoch": "1000", "local_finished_epoch": "1000",
        "remote_time_start": "1000", "remote_time_end": "1000",
        "boot_id": "fixture-boot", "boot_time": "1",
        "ztp_log": log, "ifreload_log": "", "failed_yaml": "",
        "stderr": "", "host_key_refreshed": False,
    })
    return device


class BootstrapPublicationDurabilityWorkflowTests(unittest.TestCase):
    def test_real_failed_receipt_publication_does_not_promote_monitor_stages(self):
        from test_cases.test_ztp_applied_receipt import MAIN_MARKER, TEMPLATE, run_cumulus_mode_bootstrap
        for product, device_type in (("SN5600", "eth"), ("Q3400", "ib"), ("N5200", "nvl")):
            with self.subTest(product=product), tempfile.TemporaryDirectory() as directory:
                source = TEMPLATE.replace(
                    MAIN_MARKER,
                    'stage_applied_source_bound() { return 86; }\n' + MAIN_MARKER,
                    1,
                )
                result, events, _ = run_cumulus_mode_bootstrap(
                    Path(directory), mode_behavior="replace", product=product,
                    prior_applied=b"- set:\n    system:\n      hostname: leaf01\n",
                    template_source=source,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(any(event.startswith("nv:") for event in events))
                self.assertIn("Could not stage applied-config YAML", result.stdout)
                device = analyze_bootstrap_log_fixture(MONITOR, result.stdout, device_type)
                self.assertEqual("warning", device["stages"]["config_apply"]["status"])
                self.assertEqual("warning", device["stages"]["complete"]["status"])
                self.assertIn("APPLIED_CONFIG_PUBLICATION_HOLD", [issue["code"] for issue in device["issues"]])

    def test_real_upgrade_revokes_old_helper_trust_and_preserves_foreign_hold(self):
        from test_cases.test_ztp_applied_receipt import (
            AppliedConfigHelperTests, MAIN_MARKER, TEMPLATE, run_cumulus_mode_bootstrap,
        )
        for product in ("SN5600", "VX-test"):
            for foreign_hold in (False, True):
                with self.subTest(product=product, foreign_hold=foreign_hold), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = TEMPLATE
                    if foreign_hold:
                        source = source.replace(
                            MAIN_MARKER,
                            'printf "foreign HOLD\\n" > "${APPLIED_STATE_DIR}/.receipt-publication.pending"\n'
                            'chmod 0600 "${APPLIED_STATE_DIR}/.receipt-publication.pending"\n' + MAIN_MARKER,
                            1,
                        )
                    result, events, _ = run_cumulus_mode_bootstrap(
                        root, mode_behavior="replace", product=product,
                        prior_applied=b"- set:\n    system:\n      hostname: leaf01\n",
                        upgrade_enabled=True, template_source=source,
                    )
                    if foreign_hold:
                        self.assertNotEqual(0, result.returncode)
                        self.assertFalse(any(event.startswith(("onie-install:", "reboot:", "nv:")) for event in events))
                        self.assertEqual(b"foreign HOLD\n", (root / "state/.receipt-publication.pending").read_bytes())
                    else:
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual(2, events.count("guard:present"))
                        self.assertNotIn("guard:absent", events)
                    helper = AppliedConfigHelperTests().write_helper(root)

                    class LocalEvidenceClient:
                        args = SimpleNamespace(command_timeout=10)

                        def run(self, device, host, command, **kwargs):
                            return subprocess.run(["sh", str(helper)], capture_output=True, text=True, check=False)

                    evidence = MANUAL.collect_applied_config(LocalEvidenceClient(), DEVICE, "192.0.2.10")
                    self.assertIs(False, evidence["trusted"], "upgrade must not borrow a prior configuration success")
                    self.assertEqual({}, evidence["receipt"])

    def test_real_device_branches_refuse_nv_mutation_when_prior_hold_is_unknown(self):
        from test_cases.test_ztp_applied_receipt import MAIN_MARKER, TEMPLATE, run_cumulus_mode_bootstrap
        for product in ("SN5600", "Q3400", "N5200"):
            with self.subTest(product=product), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = TEMPLATE.replace(
                    MAIN_MARKER,
                    'printf "foreign HOLD\\n" > "${APPLIED_STATE_DIR}/.receipt-publication.pending"\n'
                    'chmod 0600 "${APPLIED_STATE_DIR}/.receipt-publication.pending"\n' + MAIN_MARKER,
                    1,
                )
                result, events, _receipt = run_cumulus_mode_bootstrap(
                    root, mode_behavior="replace", product=product,
                    prior_applied=b"- set:\n    system:\n      hostname: leaf01\n",
                    template_source=source,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertFalse(any(line.startswith("nv:") for line in events), "unknown prior HOLD must stop before any device mutation")
                self.assertEqual(b"foreign HOLD\n", (root / "state/.receipt-publication.pending").read_bytes())

    def test_real_cumulus_and_nvos_attempt_revoke_prior_success_before_nv_mutation(self):
        from test_cases.test_ztp_applied_receipt import (
            AppliedConfigHelperTests, MAIN_MARKER, TEMPLATE, run_cumulus_mode_bootstrap,
        )
        for product in ("SN5600", "Q3400", "N5200"):
            with self.subTest(product=product), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                raw = b"- set:\n    system:\n      hostname: leaf01\n"
                # Fault the actual early persistence boundary, after a new NV
                # operation. The historical success has identical YAML bytes.
                source = TEMPLATE.replace(
                    MAIN_MARKER,
                    'stage_applied_source_bound() { return 86; }\n' + MAIN_MARKER,
                    1,
                )
                result, events, receipt = run_cumulus_mode_bootstrap(
                    root, mode_behavior="replace", product=product,
                    prior_applied=raw, template_source=source,
                )
                self.assertEqual(0, result.returncode, result.stderr + result.stdout)
                mutations = [line for line in events if line.startswith("nv:")]
                self.assertTrue(mutations, "must exercise the actual device config branch")
                self.assertNotIn("guard:absent", events, "old success must be revoked before the first NV call")
                self.assertEqual(len(mutations), events.count("guard:present"))
                self.assertIn("Could not stage applied-config YAML", result.stdout)
                self.assertEqual("2026-08-31T12:34:56+00:00", receipt["applied_at"])
                self.assertIn(
                    "ssh-ed25519 AAAATEST ztp-test",
                    (root / "home/cumulus/.ssh/authorized_keys").read_text(),
                    "all device families must use the hermetic home directory",
                )
                helper = AppliedConfigHelperTests().write_helper(root)

                class LocalEvidenceClient:
                    args = SimpleNamespace(command_timeout=10)

                    def run(self, device, host, command, **kwargs):
                        return subprocess.run(["sh", str(helper)], capture_output=True, text=True, check=False)

                evidence = MANUAL.collect_applied_config(LocalEvidenceClient(), DEVICE, "192.0.2.10")
                self.assertIs(False, evidence["trusted"], "historical matching bytes cannot mask a later failed attempt")
                self.assertEqual({}, evidence["receipt"])
                self.assertTrue((root / "state/.receipt-publication.pending").exists())

    def test_real_bootstrap_late_directory_failure_cannot_be_trusted_by_manual_reader(self):
        from test_cases.test_ztp_applied_receipt import (
            AppliedConfigHelperTests, library_harness, run_bash,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = b"- set:\n    system:\n      hostname: leaf01\n"
            helper_tests = AppliedConfigHelperTests()
            receipt, _applied = helper_tests.prepare_state(root, raw)
            original = receipt.read_bytes()
            source = root / "same-config.yaml"
            source.write_bytes(raw)
            harness = library_harness(root, '''
                real_sync=$(declare -f fsync_applied_state)
                eval "${real_sync/fsync_applied_state/fsync_applied_state_real}"
                sync_calls=0
                fsync_applied_state() {
                    sync_calls=$((sync_calls + 1))
                    if (( sync_calls == 3 )); then
                        log "TEST_FAULT: final receipt directory fsync"
                        return 86
                    fi
                    fsync_applied_state_real "$@"
                }
                persist_applied_receipt "$1" success dedicated replace 020000000001.yaml 02:00:00:00:00:01
            ''')
            written = run_bash(harness, source)
            self.assertEqual(0, written.returncode, "receipt diagnostics remain nonfatal to bootstrap")
            self.assertIn("TEST_FAULT", (root / "test.log").read_text())
            self.assertNotEqual(original, receipt.read_bytes(), "fault must occur after actual receipt rename")
            helper = helper_tests.write_helper(root)
            observed = []

            class LocalEvidenceClient:
                args = SimpleNamespace(command_timeout=10)

                def run(self, device, host, command, **kwargs):
                    observed.append(command)
                    self_result = subprocess.run(["sh", str(helper)], capture_output=True, text=True, check=False)
                    return self_result

            evidence = MANUAL.collect_applied_config(LocalEvidenceClient(), DEVICE, "192.0.2.10")
            self.assertEqual([MANUAL.APPLIED_CONFIG_HELPER], observed)
            self.assertIs(False, evidence["trusted"], "real writer/helper/manual boundary must refuse uncertain success")
            self.assertEqual({}, evidence["receipt"])
            self.assertTrue((root / "state/.receipt-publication.pending").exists())


def completed(stdout="", returncode=0, stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def protocol(
    raw_yaml, *, source_kind="dedicated", apply_mode="replace",
    mac=MAC, raw_sha256=None, failed_raw_sha256="",
):
    digest = raw_sha256 or hashlib.sha256(raw_yaml.encode("utf-8")).hexdigest()
    lines = [
        MANUAL.APPLIED_CONFIG_MAGIC,
        "schema=1",
        "status=success",
        f"source_kind={source_kind}",
        f"apply_mode={apply_mode}",
        f"raw_sha256={digest}",
        "source_name=020000000001.yaml",
        f"eth0_mac={mac}",
        "applied_at=2026-08-31T12:34:56+00:00",
    ]
    if failed_raw_sha256:
        lines.append(f"failed_raw_sha256={failed_raw_sha256}")
    return "\n".join(lines) + "\n---\n" + raw_yaml


def dhcp_mode_release_fixture(http_root: Path, mode: str, *, legacy: bool = False):
    """Build one independent, real parent/child/DHCP publication fixture."""
    project = http_root / "DAY0-Prepare/site-a"
    project.mkdir(parents=True)
    global_data = yaml.safe_load(
        (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(encoding="utf-8")
    )
    global_data["common"]["mgmt"]["dhcp-server"]["status"] = mode
    (project / "01-global.yaml").write_text(
        yaml.safe_dump(global_data, sort_keys=True), encoding="utf-8",
    )
    (project / "02-devices_config.csv").write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
    (project / "02-dhcp-subnet_config.csv").write_text("subnet\n192.0.2.0/24\n", encoding="utf-8")
    source = project / "fixture-p2p.xlsx"
    source.write_bytes(b"independent-p2p-workbook-fixture\n")
    (project / "p2p.xlsx").symlink_to(source.name)
    input_paths = {
        "global": project / "01-global.yaml",
        "devices": project / "02-devices_config.csv",
        "subnet": project / "02-dhcp-subnet_config.csv",
        "p2p": project / "p2p.xlsx",
    }
    inputs = {name: hashlib.sha256(path.read_bytes()).hexdigest()
              for name, path in input_paths.items()}

    release_dir = project / "99-output-eth/release-a"
    release_dir.mkdir(parents=True)
    config = release_dir / "leaf01.yaml"
    config.write_text("hostname: leaf01\n", encoding="utf-8")
    child = release_dir / "release-manifest.json"
    child.write_text(json.dumps({
        "release_id": "child-a",
        "devices": [{
            "hostname": "leaf01", "config": config.name,
            "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        }],
    }) + "\n", encoding="utf-8")
    marker = release_dir / ".published-complete"
    marker.write_text("complete\n", encoding="utf-8")
    (release_dir.parent / "latest").symlink_to(release_dir.name)
    public_latest = http_root / "ztp/config/cumulus/latest_yaml"
    public_latest.parent.mkdir(parents=True)
    public_latest.symlink_to(release_dir)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    components = {"cumulus": {
        "release_id": "child-a", "release_dir": "99-output-eth/release-a",
        "manifest_sha256": digest(child),
        "published_marker_sha256": digest(marker),
    }}

    dhcp_dir = http_root / "ztp/config/isc-dhcp-server"
    dhcp_dir.mkdir(parents=True)
    outputs = {}
    for name in ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"):
        path = dhcp_dir / name
        path.write_text(f"stale-or-current-{name}\n", encoding="utf-8")
        outputs[name] = {"sha256": digest(path)}
    dhcp_manifest = project / "99-output-dhcp/dhcp-release-manifest.json"
    dhcp_manifest.parent.mkdir(parents=True)
    dhcp_manifest.write_text(json.dumps({
        "release_id": "dhcp-a", "outputs": outputs,
    }) + "\n", encoding="utf-8")
    public_dhcp = dhcp_dir / "dhcp-release-manifest.json"
    public_dhcp.symlink_to(os.path.relpath(dhcp_manifest, dhcp_dir))
    if mode == "enabled":
        components["dhcp"] = {
            "release_id": "dhcp-a", "manifest_sha256": digest(dhcp_manifest),
        }
    basis = {
        "project": "site-a", "deployment_scope": "air", "switch_scope": "eth",
        "inputs": inputs,
        "input_sources": {"p2p": {"path": source.name, "sha256": digest(source)}},
        "components": components,
        "inventory": [{
            "hostname": "leaf01", "type": "eth",
            "eth0_mac": DEVICE["mac_plain"], "eth1_mac": None,
            "identity_state": "identified", "identity_source": "devices_config",
        }],
    }
    if not legacy:
        basis["dhcp_status"] = mode
    release_id = hashlib.sha256(json.dumps(
        basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()[:20]
    parent = {
        "schema_version": 1 if legacy else 2,
        "validation": "passed", "release_id": release_id, **basis,
    }
    parent_path = project / "99-output-ztp/current-release.json"
    parent_path.parent.mkdir(parents=True)
    parent_path.write_text(json.dumps(parent, sort_keys=True) + "\n", encoding="utf-8")
    return project, parent_path, parent, public_dhcp, dhcp_dir


def load_activation_consumer():
    """Load the actual container reader for the cross-script release witness."""
    spec = importlib.util.spec_from_file_location(
        "manual_dhcp_mode_activation_under_test", ROOT / "infra/docker/activate.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


class ParentReleaseInputContractTests(unittest.TestCase):
    def test_optional_air_policy_is_hash_bound_and_backward_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            inputs = {
                "global": project / "01-global.yaml",
                "devices": project / "02-devices_config.csv",
                "subnet": project / "02-dhcp-subnet_config.csv",
                "p2p": project / "p2p.xlsx",
            }
            for name, path in inputs.items():
                path.write_text(f"{name}\n", encoding="utf-8")
            expected = {
                name: MANUAL.sha256_path(path) for name, path in inputs.items()
            }

            # Old/current projects without a policy keep the original contract.
            MANUAL.validate_parent_release_input_hashes(project, expected)

            policy = project / "03-air-topology-policy.json"
            policy.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "AIR.*已变化"):
                MANUAL.validate_parent_release_input_hashes(project, expected)

            expected["air_topology_policy"] = MANUAL.sha256_path(policy)
            MANUAL.validate_parent_release_input_hashes(project, expected)
            policy.write_text('{"changed": true}\n', encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "AIR.*已变化"):
                MANUAL.validate_parent_release_input_hashes(project, expected)
            policy.unlink()
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "AIR.*无法读取"):
                MANUAL.validate_parent_release_input_hashes(project, expected)


class DhcpModeManualActivationWorkflowTests(unittest.TestCase):
    """One real parent is read by both manual preflight and container activation."""

    def test_legacy_v1_enabled_fixture_is_valid_before_mode_extension(self):
        activate = load_activation_consumer()
        with tempfile.TemporaryDirectory() as directory:
            http_root = Path(directory) / "html"
            project, parent_path, _parent, public_dhcp, _dhcp_dir = (
                dhcp_mode_release_fixture(http_root, "enabled", legacy=True)
            )
            settings = activate.Settings(
                project_name="site-a", scope="air", switch_scope="eth",
                http_root=http_root,
            )
            with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST", public_dhcp):
                binding = MANUAL.validate_parent_release_binding(project, DEVICE)
                self.assertEqual("dhcp-a", binding["dhcp_release_id"])
            identity = activate.validate_parent_release(settings, parent_path)
            self.assertIn("dhcp", identity["parent_components"])

    def test_disabled_v2_ignores_stale_dhcp_artifacts_and_rejects_injected_binding(self):
        activate = load_activation_consumer()
        with tempfile.TemporaryDirectory() as directory:
            http_root = Path(directory) / "html"
            project, parent_path, _parent, public_dhcp, dhcp_dir = (
                dhcp_mode_release_fixture(http_root, "disabled")
            )
            # These are intentionally present but stale: absence of a current
            # DHCP component, not artifact deletion, is the published mode.
            (dhcp_dir / "dhcpd.conf").write_text("stale-after-parent\n", encoding="utf-8")
            public_dhcp.unlink()
            public_dhcp.write_text("not-a-current-manifest\n", encoding="utf-8")
            settings = activate.Settings(
                project_name="site-a", scope="air", switch_scope="eth",
                http_root=http_root,
            )
            with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST", public_dhcp):
                binding = MANUAL.validate_parent_release_binding(project, DEVICE)
                self.assertEqual("disabled", binding["dhcp_status"])
                self.assertFalse(any(
                    key.startswith("dhcp_") and key != "dhcp_status"
                    for key in binding
                ))
                MANUAL.verify_prepared_release_binding(binding)
                injected = dict(binding, dhcp_manifest_path=str(public_dhcp),
                                dhcp_manifest_sha256="0" * 64)
                with self.assertRaises(MANUAL.ManualZtpError):
                    MANUAL.verify_prepared_release_binding(injected)
            identity = activate.validate_parent_release(settings, parent_path)
            self.assertNotIn("dhcp", identity["parent_components"])

    def test_enabled_v2_and_legacy_v1_require_current_dhcp_outputs(self):
        activate = load_activation_consumer()
        for legacy in (False, True):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory() as directory:
                http_root = Path(directory) / "html"
                project, parent_path, _parent, public_dhcp, dhcp_dir = (
                    dhcp_mode_release_fixture(http_root, "enabled", legacy=legacy)
                )
                settings = activate.Settings(
                    project_name="site-a", scope="air", switch_scope="eth",
                    http_root=http_root,
                )
                with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST", public_dhcp):
                    binding = MANUAL.validate_parent_release_binding(project, DEVICE)
                    self.assertEqual("enabled", binding["dhcp_status"])
                    self.assertEqual("dhcp-a", binding["dhcp_release_id"])
                    MANUAL.verify_prepared_release_binding(binding)
                identity = activate.validate_parent_release(settings, parent_path)
                self.assertIn("dhcp", identity["parent_components"])
                (dhcp_dir / "dhcpd.conf").write_text("drift-after-parent\n", encoding="utf-8")
                with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST", public_dhcp):
                    with self.assertRaises(MANUAL.ManualZtpError):
                        MANUAL.validate_parent_release_binding(project, DEVICE)
                with self.assertRaises(activate.ActivationError):
                    activate.validate_parent_release(settings, parent_path)

    def test_parent_mode_and_release_id_are_not_inferred_from_missing_artifacts(self):
        activate = load_activation_consumer()
        cases = (
            ("disabled", True, None),  # v1 cannot express disabled.
            ("enabled", False, None),  # relabel without rebuilding release_id.
            ("disabled", False, "enabled"),  # current mode disagrees with parent.
        )
        for mode, legacy, status_override in cases:
            with self.subTest(mode=mode, legacy=legacy, override=status_override), \
                    tempfile.TemporaryDirectory() as directory:
                http_root = Path(directory) / "html"
                project, parent_path, parent, public_dhcp, _dhcp_dir = (
                    dhcp_mode_release_fixture(http_root, mode, legacy=legacy)
                )
                if mode == "enabled" and not legacy:
                    parent["dhcp_status"] = "disabled"
                    parent_path.write_text(json.dumps(parent) + "\n", encoding="utf-8")
                if status_override is not None:
                    global_path = project / "01-global.yaml"
                    data = yaml.safe_load(global_path.read_text(encoding="utf-8"))
                    data["common"]["mgmt"]["dhcp-server"]["status"] = status_override
                    global_path.write_text(yaml.safe_dump(data), encoding="utf-8")
                    parent["inputs"]["global"] = hashlib.sha256(
                        global_path.read_bytes()
                    ).hexdigest()
                    basis_keys = (
                        "project", "deployment_scope", "switch_scope", "inputs",
                        "input_sources", "dhcp_status", "components", "inventory",
                    )
                    parent["release_id"] = hashlib.sha256(json.dumps(
                        {key: parent[key] for key in basis_keys if key in parent},
                        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                    ).encode("utf-8")).hexdigest()[:20]
                    parent_path.write_text(json.dumps(parent) + "\n", encoding="utf-8")
                settings = activate.Settings(
                    project_name="site-a", scope="air", switch_scope="eth",
                    http_root=http_root,
                )
                with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST", public_dhcp):
                    with self.assertRaises(MANUAL.ManualZtpError):
                        MANUAL.validate_parent_release_binding(project, DEVICE)
                with self.assertRaises(activate.ActivationError):
                    activate.validate_parent_release(settings, parent_path)


class RuntimeMacYamlWorkflowTests(unittest.TestCase):
    def test_manual_and_feedback_agree_on_quoted_and_unquoted_digit_mac(self):
        mac = ":".join(("46", "38", "39", "01", "01", "01"))

        def payload(rendered_mac):
            return (
                "- set:\n"
                "    system:\n"
                "      global:\n"
                f"        anycast-mac: {rendered_mac}\n"
                "    vrf:\n"
                "      default:\n"
                "        router:\n"
                "          bgp:\n"
                "            autonomous-system: 65001\n"
                "    metadata:\n"
                "      elapsed: 12:34:56\n"
            )

        unquoted = payload(mac)
        quoted = payload(f"'{mac}'")
        manual_unquoted = MANUAL.normalized_nvue_config(
            unquoted, label="runtime",
        )
        manual_quoted = MANUAL.normalized_nvue_config(
            quoted, label="latest",
        )
        self.assertEqual(manual_quoted, manual_unquoted)

        encoded = FEEDBACK.encode_source_yaml(
            unquoted.encode("utf-8"), "leaf01",
        )
        feedback = FEEDBACK._decode_source_config(encoded)
        self.assertEqual(manual_unquoted[0], feedback)
        self.assertEqual(
            mac, feedback["system"]["global"]["anycast-mac"],
        )
        self.assertIsInstance(
            feedback["system"]["global"]["anycast-mac"], str,
        )
        self.assertEqual(
            65001,
            feedback["vrf"]["default"]["router"]["bgp"][
                "autonomous-system"
            ],
        )
        self.assertEqual(45296, feedback["metadata"]["elapsed"])

class AppliedHelperProtocolTests(unittest.TestCase):
    def client(self, result):
        client = mock.Mock()
        client.args.command_timeout = 20
        client.run.return_value = result
        return client

    def test_valid_protocol_checks_fixed_helper_mac_and_raw_sha(self):
        raw = "- set:\n    system:\n      hostname: leaf01\n"
        client = self.client(completed(protocol(raw)))
        parsed = MANUAL.collect_applied_config(client, DEVICE, "192.0.2.10")
        self.assertTrue(parsed["trusted"])
        self.assertEqual(raw, parsed["raw_yaml"])
        self.assertEqual("dedicated", parsed["receipt"]["source_kind"])
        self.assertRegex(parsed["fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            MANUAL.APPLIED_CONFIG_HELPER,
            client.run.call_args.args[2],
        )

    def test_applied_receipt_schema_rejects_unknown_remote_field(self):
        raw = "- set:\n    system:\n      hostname: leaf01\n"
        forged = protocol(raw).replace(
            "applied_at=2026-08-31T12:34:56+00:00\n",
            "applied_at=2026-08-31T12:34:56+00:00\nforeign_authority=success\n",
            1,
        )
        parsed = MANUAL.collect_applied_config(
            self.client(completed(forged)), DEVICE, "192.0.2.10",
        )
        self.assertFalse(parsed["trusted"])
        self.assertIn("receipt", parsed["reason"])

    def test_applied_receipt_rejects_inconsistent_optional_and_mode_fields(self):
        raw = "- set:\n    system:\n      hostname: leaf01\n"
        base = protocol(raw)
        cases = {
            "failed hash on dedicated": base.replace(
                "applied_at=2026-08-31T12:34:56+00:00\n",
                "applied_at=2026-08-31T12:34:56+00:00\n"
                + "failed_raw_sha256=" + "a" * 64 + "\n",
            ),
            "default replace": protocol(raw, source_kind="default", apply_mode="replace"),
            "fallback without failed hash": protocol(
                raw, source_kind="fallback_default", apply_mode="patch",
            ),
            "foreign failed mode source": protocol(
                raw, source_kind="fallback_default", apply_mode="patch",
                failed_raw_sha256="a" * 64,
            ).replace(
                "failed_raw_sha256=" + "a" * 64 + "\n",
                "failed_raw_sha256=" + "a" * 64 + "\n"
                "failed_source_name=020000000002.mode\n",
            ),
        }
        for label, forged in cases.items():
            with self.subTest(label=label):
                parsed = MANUAL.collect_applied_config(
                    self.client(completed(forged)), DEVICE, "192.0.2.10",
                )
                self.assertFalse(parsed["trusted"], label)

    def test_corrupt_missing_oversize_or_wrong_identity_is_untrusted(self):
        raw = "- set:\n    system:\n      hostname: leaf01\n"
        cases = {
            "missing helper": completed("", returncode=1, stderr="not found"),
            "wrong magic": completed(protocol(raw).replace(
                MANUAL.APPLIED_CONFIG_MAGIC, "WRONG", 1,
            )),
            "wrong hash": completed(protocol(raw, raw_sha256="0" * 64)),
            "wrong mac": completed(protocol(raw, mac="02:00:00:00:00:02")),
        }
        for label, result in cases.items():
            with self.subTest(label=label):
                parsed = MANUAL.collect_applied_config(
                    self.client(result), DEVICE, "192.0.2.10",
                )
                self.assertFalse(parsed["trusted"])
                self.assertTrue(parsed["reason"])
        with mock.patch.object(MANUAL, "MAX_APPLIED_CONFIG_BYTES", 32):
            parsed = MANUAL.collect_applied_config(
                self.client(completed(protocol(raw))), DEVICE, "192.0.2.10",
            )
        self.assertFalse(parsed["trusted"])
        self.assertIn("安全上限", parsed["reason"])


class PreflightAppliedComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.release = self.root / "release"
        self.release.mkdir()
        self.marker = self.release / ".published-complete"
        self.marker.write_text("complete\n", encoding="utf-8")
        self.expected = self.release / "leaf01.yaml"
        self.expected_text = (
            "- set:\n"
            "    interface:\n"
            "      swp1:\n"
            "        type: swp\n"
            "      swp2:\n"
            "        type: swp\n"
            "    system:\n"
            "      hostname: leaf01\n"
        )
        self.expected.write_text(self.expected_text, encoding="utf-8")
        self.evidence = self.root / "evidence"

    def tearDown(self):
        self.temporary.cleanup()

    def run_preflight(self, helper_result, current_text=None):
        current_text = current_text or self.expected_text
        client = mock.Mock()
        client.args.command_timeout = 20
        client.run.side_effect = [completed(current_text), helper_result]
        binding = {
            "binding_sha256": "b" * 64,
            "child_config_sha256": hashlib.sha256(
                self.expected_text.encode("utf-8")
            ).hexdigest(),
        }
        with mock.patch.object(
            MANUAL, "validate_parent_release_binding", return_value=binding,
        ), mock.patch.object(
            MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
        ), mock.patch.object(
            MANUAL, "published_yaml_paths",
            return_value=(self.marker, self.expected, self.release / "mac.yaml"),
        ), mock.patch.object(
            MANUAL, "published_mac_paths", return_value=[],
        ):
            evidence = MANUAL.preflight_one(
                client, self.root, DEVICE, self.evidence,
            )
        return evidence, client

    def test_current_runtime_is_primary_comparison_and_evidence_is_private(self):
        evidence, _client = self.run_preflight(
            completed(protocol(self.expected_text)),
        )
        self.assertEqual("nv_config_show_runtime", evidence["comparison_source"])
        self.assertIsNone(evidence["payload_matches_latest"])
        self.assertIs(evidence["runtime_matches_latest"], True)
        self.assertTrue(evidence["configuration_matches"])
        self.assertIsNone(evidence["fallback_semantic_matches"])
        self.assertIn("当前 nv config show", evidence["comparison_reason"])
        self.assertEqual(0o700, os.stat(self.evidence).st_mode & 0o777)
        for name in (
            "before.yaml", "expected.yaml", "applied.yaml", "config.diff",
            "preflight.json",
        ):
            self.assertEqual(
                0o600, os.stat(self.evidence / name).st_mode & 0o777, name,
            )

    def test_trusted_receipt_does_not_hide_live_runtime_drift(self):
        drifted = self.expected_text.replace(
            "    system:\n",
            "      vlan999:\n"
            "        ip:\n"
            "          address:\n"
            "            1.2.3.4/24: {}\n"
            "        type: svi\n"
            "    system:\n",
        )
        evidence, _client = self.run_preflight(
            completed(protocol(self.expected_text)), drifted,
        )
        self.assertIsNone(evidence["payload_matches_latest"])
        self.assertIs(evidence["runtime_matches_latest"], False)
        self.assertFalse(evidence["configuration_matches"])
        self.assertIn(
            "interface.vlan999", evidence["diff_summary"]["changed_paths"],
        )
        self.assertIn("vlan999", (self.evidence / "config.diff").read_text())

    def test_hashed_password_is_unobservable_only_in_runtime_comparison(self):
        expected = (
            "- set:\n"
            "    system:\n"
            "      aaa:\n"
            "        user:\n"
            "          cumulus:\n"
            "            hashed-password: $6$published-secret-hash\n"
            "      hostname: leaf01\n"
        )
        masked_show = (
            "- header:\n"
            "    model: vx\n"
            "- set:\n"
            "    system:\n"
            "      aaa:\n"
            "        user:\n"
            "          cumulus:\n"
            "            hashed-password: '*'\n"
            "      hostname: leaf01\n"
        )
        missing_show = "- set:\n    system:\n      hostname: leaf01\n"

        full_expected = MANUAL.normalized_nvue_config(expected, label="expected")
        changed_hash = MANUAL.normalized_nvue_config(
            expected.replace("published-secret-hash", "new-secret-hash"),
            label="changed expected",
        )
        self.assertNotEqual(full_expected[2], changed_hash[2])

        comparable_expected = MANUAL.runtime_comparable_nvue_config(
            expected, label="expected",
        )
        for label, current in (("masked", masked_show), ("missing", missing_show)):
            with self.subTest(label=label):
                comparable_current = MANUAL.runtime_comparable_nvue_config(
                    current, label=label,
                )
                self.assertEqual(comparable_expected, comparable_current)
                self.assertNotIn("hashed-password", comparable_current[1])

    def test_hashed_password_does_not_hide_other_runtime_drift(self):
        expected = (
            "- set:\n"
            "    system:\n"
            "      aaa:\n"
            "        user:\n"
            "          cumulus:\n"
            "            hashed-password: $6$published-secret-hash\n"
            "            role: system-admin\n"
            "      hostname: leaf01\n"
        )
        current = expected.replace(
            "hashed-password: $6$published-secret-hash",
            "hashed-password: '*'",
        ).replace("role: system-admin", "role: nvue-monitor")
        expected_value = MANUAL.runtime_comparable_nvue_config(
            expected, label="expected",
        )[0]
        current_value = MANUAL.runtime_comparable_nvue_config(
            current, label="current",
        )[0]
        self.assertEqual(
            ["system.aaa.user.cumulus.role"],
            MANUAL._changed_config_paths(current_value, expected_value),
        )

        unrelated_expected = (
            "- set:\n"
            "    system:\n"
            "      config:\n"
            "        hashed-password: must-remain-observable\n"
        )
        unrelated_current = unrelated_expected.replace(
            "must-remain-observable", "changed",
        )
        unrelated_expected_value = MANUAL.runtime_comparable_nvue_config(
            unrelated_expected, label="unrelated expected",
        )[0]
        unrelated_current_value = MANUAL.runtime_comparable_nvue_config(
            unrelated_current, label="unrelated current",
        )[0]
        self.assertEqual(
            ["system.config.hashed-password"],
            MANUAL._changed_config_paths(
                unrelated_current_value, unrelated_expected_value,
            ),
        )

    def test_preflight_ignores_hashed_password_in_diff_and_summary(self):
        current = self.expected_text
        self.expected_text = self.expected_text.replace(
            "    system:\n",
            "    system:\n"
            "      aaa:\n"
            "        user:\n"
            "          cumulus:\n"
            "            hashed-password: $6$published-secret-hash\n",
        )
        self.expected.write_text(self.expected_text, encoding="utf-8")
        evidence, _client = self.run_preflight(
            completed(protocol(self.expected_text)), current,
        )
        self.assertTrue(evidence["runtime_matches_latest"])
        self.assertEqual([], evidence["diff_summary"]["changed_paths"])
        self.assertNotIn(
            "hashed-password",
            (self.evidence / "config.diff").read_text(encoding="utf-8"),
        )
        self.assertIn("忽略 hashed-password", evidence["comparison_reason"])
        self.assertEqual(
            MANUAL.normalized_nvue_config(
                self.expected_text, label="full latest",
            )[2],
            evidence["expected_yaml_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(self.expected_text.encode("utf-8")).hexdigest(),
            evidence["expected_yaml_raw_sha256"],
        )

    def test_compact_vlan_selector_is_expanded_before_runtime_comparison(self):
        current = (
            "- header:\n"
            "    model: vx\n"
            "- set:\n"
            "    interface:\n"
            "      vlan106,999:\n"
            "        type: svi\n"
            "      vlan999:\n"
            "        ipv4:\n"
            "          address:\n"
            "            1.2.3.4/24: {}\n"
            "        vlan: 999\n"
        )
        expected = (
            "- set:\n"
            "    interface:\n"
            "      vlan106:\n"
            "        type: svi\n"
        )
        current_value, _current_json, _current_hash = MANUAL.normalized_nvue_config(
            current, label="current",
        )
        expected_value, _expected_json, _expected_hash = MANUAL.normalized_nvue_config(
            expected, label="expected",
        )
        self.assertEqual(
            ["interface.vlan999"],
            MANUAL._changed_config_paths(current_value, expected_value),
        )

    def test_breakout_lane_ranges_are_expanded_on_the_minor_axis(self):
        self.assertEqual(
            ["swp1s0", "swp1s1", "swp1s2", "swp1s3"],
            MANUAL._expand_nvue_selector("swp1s0-3"),
        )
        self.assertEqual(
            [f"swp15s{lane}" for lane in range(8)],
            MANUAL._expand_nvue_selector("swp15s0-7"),
        )

    def test_combined_breakout_selectors_expand_both_axes_and_shorthand(self):
        self.assertEqual(
            [
                "swp1s0", "swp1s1", "swp2s0", "swp2s1",
                "swp15s0", "swp15s1", "swp15s2",
                "swp20s3", "swp20s5", "swp20s6",
            ],
            MANUAL._expand_nvue_selector(
                "swp1-2s0-1,15s0-2,swp20s3,s5-6"
            ),
        )

    def test_breakout_show_and_explicit_latest_are_semantically_equal(self):
        compact_show = (
            "- header:\n"
            "    model: vx\n"
            "- set:\n"
            "    interface:\n"
            "      swp1s0-3:\n"
            "        link:\n"
            "          mtu: 9216\n"
        )
        explicit_latest = (
            "- set:\n"
            "    interface:\n"
            "      swp1s0:\n"
            "        link:\n"
            "          mtu: 9216\n"
            "      swp1s1:\n"
            "        link:\n"
            "          mtu: 9216\n"
            "      swp1s2:\n"
            "        link:\n"
            "          mtu: 9216\n"
            "      swp1s3:\n"
            "        link:\n"
            "          mtu: 9216\n"
        )
        current_value, _current_json, current_hash = MANUAL.normalized_nvue_config(
            compact_show, label="current",
        )
        expected_value, _expected_json, expected_hash = MANUAL.normalized_nvue_config(
            explicit_latest, label="expected",
        )
        self.assertEqual(expected_value, current_value)
        self.assertEqual(expected_hash, current_hash)

    def test_ordinary_port_vlan_and_mixed_selectors_do_not_regress(self):
        self.assertEqual(
            [*(f"swp{number}" for number in range(1, 50)), "swp51"],
            MANUAL._expand_nvue_selector("swp1-49,51"),
        )
        self.assertEqual(
            ["vlan106", "vlan999"],
            MANUAL._expand_nvue_selector("vlan106,999"),
        )
        self.assertEqual(
            [
                "bond49bond51",
                *(f"swp{number}" for number in range(1, 50)),
                "swp51",
            ],
            MANUAL._expand_nvue_selector("bond49bond51,swp1-49,51"),
        )

    def test_invalid_breakout_selector_is_preserved_fail_closed(self):
        malformed = "swp1s0-3,swp2s3-0"
        self.assertEqual(
            [malformed],
            MANUAL._expand_nvue_selector(malformed),
        )
        normalized = MANUAL._normalize_nvue_selectors({malformed: {"type": "swp"}})
        self.assertEqual({malformed: {"type": "swp"}}, normalized)
        oversized = "swp1-200s0-100"
        self.assertEqual(
            [oversized],
            MANUAL._expand_nvue_selector(oversized),
        )

    def test_default_fallback_and_same_failed_payload_have_explicit_diagnosis(self):
        expected_sha = hashlib.sha256(
            self.expected_text.encode("utf-8")
        ).hexdigest()
        default_yaml = "- set:\n    system:\n      timezone: Etc/UTC\n"
        evidence, _client = self.run_preflight(completed(protocol(
            default_yaml, source_kind="fallback_default", apply_mode="patch",
            failed_raw_sha256=expected_sha,
        )))
        self.assertIsNone(evidence["payload_matches_latest"])
        self.assertTrue(evidence["runtime_matches_latest"])
        self.assertIn("当前 nv config show", evidence["comparison_reason"])
        self.assertFalse(evidence["failed_payload_matches_latest"])

    def test_old_device_fallback_strips_header_and_expands_show_selectors(self):
        compact_show = (
            "- header:\n"
            "    model: test\n"
            "- set:\n"
            "    interface:\n"
            "      swp1-2:\n"
            "        type: swp\n"
            "    system:\n"
            "      hostname: leaf01\n"
        )
        evidence, _client = self.run_preflight(
            completed("", returncode=1, stderr="helper missing"), compact_show,
        )
        self.assertEqual("nv_config_show_runtime", evidence["comparison_source"])
        self.assertIsNone(evidence["payload_matches_latest"])
        self.assertIsNone(evidence["fallback_semantic_matches"])
        self.assertTrue(evidence["configuration_matches"])
        self.assertTrue(evidence["comparison_warnings"])
        self.assertNotIn("applied.yaml", {item.name for item in self.evidence.iterdir()})

    def test_applied_receipt_state_is_bound_into_confirmed_expected_fingerprint(self):
        first, _client = self.run_preflight(completed(protocol(self.expected_text)))
        changed = self.expected_text.replace("hostname: leaf01", "hostname: old-leaf")
        second, _client = self.run_preflight(completed(protocol(changed)))
        self.assertNotEqual(first["applied_fingerprint"], second["applied_fingerprint"])
        self.assertNotEqual(first["expected_sha256"], second["expected_sha256"])


class ReplaceConfigGuardTests(unittest.TestCase):
    @staticmethod
    def config(*, eth0="192.0.2.10/24", ssh_port=22,
               users=None, acl_rule="accept", hostname="leaf01"):
        users = users or {
            "cumulus": {"hashed-password": "$6$stable", "role": "system-admin"},
        }
        user_lines = []
        for name, values in users.items():
            user_lines.extend((
                f"          {name}:\n",
                f"            hashed-password: {values['hashed-password']}\n",
                f"            role: {values['role']}\n",
            ))
        return "".join((
            "- set:\n",
            "    interface:\n",
            "      eth0:\n",
            "        ip:\n",
            "          address:\n",
            f"            {eth0}: {{}}\n",
            "    system:\n",
            "      aaa:\n",
            "        user:\n",
            *user_lines,
            "      ssh-server:\n",
            f"        port: {ssh_port}\n",
            f"      hostname: {hostname}\n",
            "    acl:\n",
            "      ipv4:\n",
            "        web-generated:\n",
            f"          rule: {acl_rule}\n",
        ))

    @classmethod
    def applied(cls, raw_yaml=None, *, trusted=True, mode="replace"):
        raw_yaml = cls.config() if raw_yaml is None else raw_yaml
        return {
            "trusted": trusted,
            "reason": "fixture-untrusted" if not trusted else "",
            "raw_yaml": raw_yaml,
            "receipt": {"apply_mode": mode},
            "fingerprint": "a" * 64,
        }

    def guard(self, current=None, applied=None, expected=None):
        return MANUAL.evaluate_replace_config_guard(
            current or self.config(),
            applied or self.applied(),
            expected or self.config(hostname="leaf01-new"),
        )

    def assert_refused(self, code, **kwargs):
        result = self.guard(**kwargs)
        self.assertFalse(result["allowed"], result)
        self.assertEqual(code, result["reason_code"], result)
        return result

    def test_replace_allows_only_unprotected_changes_and_acl_is_not_protected(self):
        expected = self.config(hostname="leaf01-new", acl_rule="drop")
        result = self.guard(expected=expected)
        self.assertTrue(result["allowed"], result)
        self.assertEqual("ready", result["reason_code"])
        self.assertEqual([], result["protected_changed_paths"])
        self.assertTrue(result["runtime_matches_prior"])

    def test_replace_rejects_each_observable_protected_prefix(self):
        cases = {
            "interface.eth0": self.config(eth0="198.51.100.10/24"),
            "system.ssh-server": self.config(ssh_port=2222),
            "system.aaa.user": self.config(users={
                "cumulus": {
                    "hashed-password": "$6$stable", "role": "nvue-monitor",
                },
            }),
        }
        for prefix, expected in cases.items():
            with self.subTest(prefix=prefix):
                result = self.assert_refused(
                    "protected-prefix-changed", expected=expected,
                )
                self.assertTrue(any(
                    path == prefix or path.startswith(prefix + ".")
                    for path in result["protected_changed_paths"]
                ), result)

    def test_hashes_use_prior_full_config_and_cover_multiple_users(self):
        prior_users = {
            "cumulus": {"hashed-password": "$6$cumulus", "role": "system-admin"},
            "operator": {"hashed-password": "$6$operator", "role": "nvue-monitor"},
        }
        prior = self.config(users=prior_users)
        current = prior.replace("$6$cumulus", "'*'").replace("$6$operator", "'*'")
        for label, users in (
            ("changed", {**prior_users, "operator": {
                "hashed-password": "$6$changed", "role": "nvue-monitor",
            }}),
            ("removed", {"cumulus": prior_users["cumulus"]}),
            ("added", {**prior_users, "newuser": {
                "hashed-password": "$6$new", "role": "nvue-monitor",
            }}),
        ):
            with self.subTest(label=label):
                result = self.assert_refused(
                    "protected-prefix-changed",
                    current=current,
                    applied=self.applied(prior),
                    expected=self.config(users=users),
                )
                self.assertTrue(any(
                    path.startswith("system.aaa.user.")
                    for path in result["protected_changed_paths"]
                ), result)

    def test_masked_runtime_hashes_do_not_block_unchanged_prior_hashes(self):
        prior = self.config()
        current = prior.replace("$6$stable", "'*'")
        result = self.guard(
            current=current,
            applied=self.applied(prior),
            expected=self.config(hostname="leaf01-new"),
        )
        self.assertTrue(result["allowed"], result)

    def test_prior_receipt_and_full_payload_fail_closed_with_distinct_codes(self):
        self.assert_refused("untrusted-prior", applied=self.applied(trusted=False))
        self.assert_refused("patch-mode-prior", applied=self.applied(mode="patch"))
        self.assert_refused(
            "prior-full-parse-failed", applied=self.applied("not: [valid"),
        )
        missing_aaa = "- set:\n    system:\n      hostname: leaf01\n"
        self.assert_refused(
            "aaa-subtree-absent", applied=self.applied(missing_aaa),
        )

    def test_runtime_drift_from_prior_is_rejected_before_replace(self):
        drifted = self.config().replace("hostname: leaf01", "hostname: drifted")
        result = self.assert_refused("runtime-drift", current=drifted)
        self.assertFalse(result["runtime_matches_prior"])

    def test_replace_flag_is_mutually_exclusive_with_original_operations(self):
        parser = MANUAL.parser()
        args = parser.parse_args(["leaf01", "--replace-config"])
        self.assertTrue(args.replace_config)
        with self.assertRaises(SystemExit):
            parser.parse_args([
                "leaf01", "--replace-config", "--operation", "renew",
            ])


class ManualCommandHelpTests(unittest.TestCase):
    def test_public_flags_explain_environment_and_timeout_units(self):
        public_help = " ".join(MANUAL.parser().format_help().split())
        expected = {
            "--air": "只选 AIR 环境设备",
            "--prod": "只选 Production 环境设备",
            "--connect-timeout": "SSH 建连超时（秒，默认 10）",
            "--command-timeout": "设备命令超时（秒，默认 900）",
            "--http-timeout": "HTTP 请求超时（秒，默认 10）",
        }
        for flag, explanation in expected.items():
            with self.subTest(flag=flag):
                self.assertIn(flag, public_help)
                self.assertIn(explanation, public_help)

    def test_reset_help_has_only_supported_public_timeout_flags(self):
        reset_help = " ".join(MANUAL.parser("reset").format_help().split())
        self.assertIn("SSH 建连超时（秒，默认 10）", reset_help)
        self.assertIn("设备命令超时（秒，默认 900）", reset_help)
        self.assertNotIn("--http-timeout", reset_help)


class MonitorConfigMethodInventoryTests(unittest.TestCase):
    HEADER = "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip"

    def inventory(self, root, entries, *, explicit=True):
        lines = [self.HEADER + (",config_method" if explicit else "")]
        for index, (name, kind, method) in enumerate(entries, 10):
            row = [name, kind, "oob" if kind == "eth" else "NA", f"192.0.2.{index}", "24", "192.0.2.1", f"02:00:00:00:00:{index:02x}", "", "", "", "", ""]
            if explicit:
                row.append(method)
            lines.append(",".join(row))
        path = root / "02-devices_config.csv"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_monitor_materializes_legacy_defaults_without_a_configuration_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.inventory(Path(directory), [("leaf01", "eth", ""), ("ib01", "ib", ""), ("nvl01", "nvl", ""), ("server01", "server", "")], explicit=False)
            devices = MONITOR.read_devices(path, dhcp_leases=None)
            self.assertEqual({"leaf01": "ztp", "ib01": "ztp", "nvl01": "ztp"}, {item["hostname"]: item.get("config_method") for item in devices})
            self.assertTrue(all(item["stages"]["config_apply"]["status"] != "success" for item in devices))
            self.assertNotIn("server01", {item["hostname"] for item in devices})

    def test_load_and_monitor_keep_each_declared_method_bound_to_the_same_device(self):
        from test_cases.module_loader import load_script
        load = load_script("f02_monitor_method_load_workflow", ROOT / "DAY0-Prepare/11-load.py")
        with tempfile.TemporaryDirectory() as directory:
            path = self.inventory(Path(directory), [("Leaf01", "eth", " ZTP "), ("IB01", "ib", "initial-setup"), ("server01", "server", "deploy_infra")])
            declared = {}
            self.assertEqual(frozenset({"eth", "ib", "server"}), load.load_device_types(path, schema_version=1, methods_out=declared))
            devices = MONITOR.read_devices(path, dhcp_leases=None)
            self.assertEqual({"leaf01": "ztp", "ib01": "initial-setup", "server01": "deploy_infra"}, declared)
            self.assertEqual({"leaf01": "ztp", "ib01": "initial-setup"}, {item["hostname"].casefold(): item.get("config_method") for item in devices})

    def test_incompatible_unknown_or_empty_method_fails_before_monitoring(self):
        for kind, method in (("eth", "initial-setup"), ("nvl", "initial-setup"), ("ib", "unknown-executor"), ("ib", ""), ("server", "ztp")):
            with self.subTest(kind=kind, method=method), tempfile.TemporaryDirectory() as directory:
                path = self.inventory(Path(directory), [("bad01", kind, method)])
                with self.assertRaisesRegex(ValueError, r"(?:第 )?2 行.*bad01.*config_method"):
                    MONITOR.read_devices(path, dhcp_leases=None)

    def test_duplicate_method_header_cannot_hide_an_invalid_declaration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            path.write_text(self.HEADER + ",config_method,config_method\nleaf01,eth,NA,192.0.2.10,24,192.0.2.1,02:00:00:00:00:01,,,,,,initial-setup,ztp\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "config_method.*重复"):
                MONITOR.read_devices(path, dhcp_leases=None)

    def test_snapshot_state_distinguishes_method_changes_without_promoting_completion(self):
        base = {"hostname": "ib01", "type": "ib", "config_method": "ztp", "stages": {}, "issues": [], "progress": {}}
        first = MONITOR.snapshot_device_state({"devices": [base]})
        second = MONITOR.snapshot_device_state({"devices": [{**base, "config_method": "initial-setup"}]})
        self.assertNotEqual(first, second)

    def test_dynamic_air_identity_gets_a_method_not_a_configuration_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.inventory(Path(directory), [("server01", "server", "deploy_infra")])
            runtime = {"hostname": "AIR-dynamic01", "ip": "192.0.2.77", "mac": MAC, "mac_plain": "020000000001"}
            with mock.patch.object(MONITOR, "dynamic_air_devices", return_value=[runtime]):
                devices = MONITOR.read_devices(path, scope="air", dhcp_leases=None)
            self.assertEqual(1, len(devices))
            self.assertEqual("ztp", devices[0].get("config_method"))
            self.assertNotEqual("success", devices[0]["stages"]["config_apply"]["status"])

    def test_scope_filter_and_header_spelling_cannot_erase_method_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.inventory(Path(directory), [("bad01", "eth", "initial-setup")])
            path.write_text(path.read_text().replace(",config_method\n", ", CONFIG_METHOD \n"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "config_method"):
                MONITOR.read_devices(path, scope="air", dhcp_leases=None)


class MonitorBoundLiveObservationTests(unittest.TestCase):
    LIVE = "- set:\n    system:\n      hostname: leaf01\n"

    def result(self):
        return {
            "kind": "ok", "returncode": 0, "batch_mode_verified": True,
            "identity_frame_valid": True, "connected_ip": "192.0.2.10",
            "remote_hostname": "leaf01", "remote_eth0_mac": MAC,
            "remote_eth1_mac": "", "remote_interface_macs": {"eth0": MAC},
            "live_config_observation": {"kind": "ok", "text": self.LIVE,
                "sha256": hashlib.sha256(self.LIVE.encode()).hexdigest()},
            "ztp_log": "", "ifreload_log": "", "failed_yaml": "",
            "stderr": "", "attempts": [], "host_key_commands": [],
        }

    def observer(self):
        observer = getattr(MONITOR, "bind_monitor_live_observation", None)
        self.assertTrue(callable(observer), "monitor must bind its own live digest to the same BatchMode identity")
        return observer

    def test_positive_observation_is_closed_and_carries_only_own_digest_and_identity(self):
        proof = self.observer()(DEVICE, self.result())
        self.assertEqual({
            "schema_version": 1, "source": "monitor_batchmode",
            "batch_identity_verified": True, "hostname": "leaf01",
            "interface": "eth0", "transport_ip": "192.0.2.10",
            "mac_plain": "020000000001", "reason": "",
            "live_state_sha256": hashlib.sha256(self.LIVE.encode()).hexdigest(),
        }, proof)

    def test_missing_ambiguous_nonboolean_transport_and_foreign_identity_have_no_proof(self):
        for mutation in (
            {"batch_mode_verified": 1}, {"batch_mode_verified": False},
            {"identity_frame_valid": 1}, {"identity_frame_valid": False},
            {"returncode": True}, {"returncode": 255}, {"kind": "ssh_failed"},
            {"remote_hostname": "leaf01.foreign.example"},
            {"remote_eth0_mac": "02:00:00:00:00:02"},
            {"remote_eth0_mac": ""}, {"connected_ip": "192.0.2.99"},
        ):
            with self.subTest(mutation=mutation):
                proof = self.observer()(DEVICE, {**self.result(), **mutation})
                self.assertIs(False, proof["batch_identity_verified"])
                self.assertEqual("", proof["live_state_sha256"])
        for mutation in ({"kind": "missing"}, {"sha256": "a" * 64}, {"text": ""}, {"foreign": True}):
            with self.subTest(live=mutation):
                result = self.result()
                result["live_config_observation"] = {**result["live_config_observation"], **mutation}
                proof = self.observer()(DEVICE, result)
                self.assertIs(False, proof["batch_identity_verified"])
                self.assertEqual("", proof["live_state_sha256"])

    def test_selected_secondary_interface_cannot_borrow_primary_mac(self):
        device = {**DEVICE, "candidate_identity": {"192.0.2.11": ("eth1", "020000000002")}}
        result = {**self.result(), "connected_ip": "192.0.2.11", "remote_eth1_mac": "02:00:00:00:00:02"}
        proof = self.observer()(device, result)
        self.assertIs(True, proof["batch_identity_verified"])
        self.assertEqual(("eth1", "192.0.2.11", "020000000002"), (proof["interface"], proof["transport_ip"], proof["mac_plain"]))
        result["remote_eth1_mac"] = MAC
        self.assertIs(False, self.observer()(device, result)["batch_identity_verified"])

    def test_transition_hostname_can_be_collected_but_cannot_prove_configuration(self):
        device = {**DEVICE, "dynamic_dhcp": True, "ssh_ips": [DEVICE["ip"]],
            "stages": {name: MONITOR.stage() for name in MONITOR.STAGE_NAMES}, "issues": [], "events": []}
        MONITOR.analyze_switch(device, {**self.result(), "remote_hostname": "cumulus"})
        self.assertEqual("success", device["stages"]["ssh"]["status"])
        proof = device.get("configuration_observation", {})
        self.assertIs(False, proof.get("batch_identity_verified"))
        self.assertEqual("", proof.get("live_state_sha256"))

    def test_next_failed_observation_withdraws_previous_in_memory_proof_before_early_return(self):
        device = {**DEVICE, "ssh_ips": [DEVICE["ip"]],
            "stages": {name: MONITOR.stage() for name in MONITOR.STAGE_NAMES}, "issues": [], "events": []}
        MONITOR.analyze_switch(device, self.result())
        self.assertIs(True, device.get("configuration_observation", {}).get("batch_identity_verified"))
        MONITOR.analyze_switch(device, {**self.result(), "kind": "unreachable", "returncode": 255})
        proof = device["configuration_observation"]
        self.assertIs(False, proof["batch_identity_verified"])
        self.assertEqual("", proof["live_state_sha256"])

    def test_collector_duplicate_identity_frames_never_bind_first_match_to_live_state(self):
        output = (
            "__HOSTNAME_BEGIN__\nleaf01\n__HOSTNAME_END__\n"
            "__ETH0_MAC_BEGIN__\n02:00:00:00:00:01\n__ETH0_MAC_END__\n"
            "__ETH1_MAC_BEGIN__\n\n__ETH1_MAC_END__\n"
            + MonitorLiveConfigTransportTests.frame(self.LIVE)
        )
        device = {**DEVICE, "ssh_user": "cumulus", "ssh_ips": [DEVICE["ip"]]}
        for extra in ("", "__HOSTNAME_BEGIN__\nforeign\n__HOSTNAME_END__\n",
                      "__ETH0_MAC_BEGIN__\n02:00:00:00:00:02\n__ETH0_MAC_END__\n"):
            with self.subTest(extra=extra), mock.patch.object(MONITOR, "run_command", return_value={"returncode": 0, "stdout": output + extra, "stderr": ""}) as run:
                result = MONITOR.collect_switch(device, 5, None, Path("/private/fixture-known-hosts"))
                self.assertEqual(1, run.call_count)
                proof = self.observer()(device, result)
                self.assertIs(not bool(extra), proof["batch_identity_verified"])
                if extra:
                    self.assertEqual("", proof["live_state_sha256"])

    def test_optional_missing_interface_uses_real_zero_line_framing_not_a_synthetic_blank_line(self):
        raw = (
            "__HOSTNAME_BEGIN__\nleaf01\n__HOSTNAME_END__\n"
            "__ETH0_MAC_BEGIN__\n02:00:00:00:00:01\n__ETH0_MAC_END__\n"
            "__ETH1_MAC_BEGIN__\n__ETH1_MAC_END__\n"
        )
        self.assertIs(True, MONITOR.monitor_identity_frame_valid(raw))
        self.assertIs(False, MONITOR.monitor_identity_frame_valid(raw.replace("leaf01\n", "leaf01\nforeign\n")))

    def test_malformed_candidate_interface_is_a_negative_observation_not_a_monitor_crash(self):
        for selected in (([], "020000000001"), (None, "020000000001"), ("eth0", "unsafe-020000000001")):
            with self.subTest(selected=selected):
                device = {**DEVICE, "candidate_identity": {"192.0.2.10": selected}}
                proof = self.observer()(device, self.result())
                self.assertIs(False, proof["batch_identity_verified"])
                self.assertEqual("", proof["live_state_sha256"])

    def test_server_unknown_and_unbound_identity_cannot_acquire_switch_configuration_proof(self):
        for mutation in ({"type": "server"}, {"type": "ufm"}, {"type": "unknown"},
                         {"unbound_identity": True}, {"unbound_identity": 0}):
            with self.subTest(mutation=mutation):
                proof = self.observer()({**DEVICE, **mutation}, self.result())
                self.assertIs(False, proof["batch_identity_verified"])
                self.assertEqual("", proof["live_state_sha256"])


class MonitorAppliedConfigObservationTests(unittest.TestCase):
    RAW = "- set:\n    system:\n      hostname: leaf01\n\n"

    @staticmethod
    def wire(raw):
        # Fixed V1 contract, not a protocol generated by the implementation.
        return ("ZTP_APPLIED_CONFIG_V1\nschema=1\nstatus=success\n"
                "source_kind=dedicated\napply_mode=replace\nraw_sha256="
                + hashlib.sha256(raw.encode()).hexdigest()
                + "\nsource_name=020000000001.yaml\neth0_mac=02:00:00:00:00:01\n"
                  "applied_at=2026-08-31T12:34:56+00:00\n---\n" + raw)

    @staticmethod
    def frame(payload, code=0):
        return ("__HTTP_MONITOR_APPLIED_V1_BEGIN__\n" + payload
                + "\n__HTTP_MONITOR_APPLIED_V1_END__=" + str(code) + "\n")

    def parse(self, text):
        parser = getattr(MONITOR, "parse_applied_config_observation", None)
        self.assertTrue(callable(parser), "bootstrap provenance needs its own bounded frame in the same SSH observation")
        return parser(text, DEVICE)

    def test_exact_source_receipt_is_a_read_only_observation_not_a_generation(self):
        payload = self.wire(self.RAW)
        observed = self.parse(self.frame(payload))
        self.assertIs(True, observed["trusted"])
        self.assertEqual(self.RAW, observed["raw_yaml"])
        self.assertEqual(hashlib.sha256(self.RAW.encode()).hexdigest(), observed["receipt"]["raw_sha256"])
        self.assertEqual({"trusted", "fingerprint", "reason", "receipt", "raw_yaml"}, set(observed))
        self.assertNotIn("generation", observed)
        client = mock.Mock(args=SimpleNamespace(command_timeout=5))
        client.run.return_value = completed(payload)
        self.assertEqual(MANUAL.collect_applied_config(client, DEVICE, DEVICE["ip"]), observed)

    def test_ambiguous_failed_corrupt_foreign_or_missing_source_never_supplies_yaml(self):
        payload = self.wire(self.RAW)
        valid = self.frame(payload)
        for label, text in (
            ("missing", "old bootstrap complete\n"), ("duplicate", valid + valid),
            ("truncated", valid[:-5]), ("failed-helper", self.frame(payload, 23)),
            ("bad-status", self.frame(payload, "0junk")),
            ("wrong-hash", self.frame(payload.replace(hashlib.sha256(self.RAW.encode()).hexdigest(), "a" * 64))),
            ("foreign-mac", self.frame(payload.replace(MAC, "02:00:00:00:00:02"))),
            ("unknown-member", self.frame(payload.replace("schema=1\n", "schema=1\ngeneration=999\n"))),
            ("misaligned-begin", "junk" + valid),
        ):
            with self.subTest(case=label):
                observed = self.parse(text)
                self.assertIs(False, observed["trusted"])
                self.assertEqual({}, observed["receipt"])
                self.assertEqual("", observed["raw_yaml"])
                self.assertTrue(observed["reason"])

    def test_independent_v1_maximum_positive_and_degenerate_budget(self):
        # The entire V1 helper response (header included) accepts 8 MiB.
        prefix = "- set: {}\n#"
        raw = prefix + "x" * (8388608 - len(self.wire(prefix + "\n").encode())) + "\n"
        payload = self.wire(raw)
        self.assertEqual(8388608, len(payload.encode()))
        self.assertIs(True, self.parse(self.frame(payload))["trusted"])
        with mock.patch.object(MONITOR, "MAX_APPLIED_CONFIG_BYTES", 8388607):
            observed = self.parse(self.frame(payload))
            self.assertIs(False, observed["trusted"])
            self.assertEqual("", observed["raw_yaml"])
        self.assertIs(False, self.parse(self.frame(self.wire(raw + "x")))["trusted"])

    def test_actual_fixed_helper_is_read_in_one_private_collector_connection_and_hold_is_retained(self):
        from test_cases.test_ztp_applied_receipt import AppliedConfigHelperTests
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = AppliedConfigHelperTests()
            receipt, applied = fixture.prepare_state(root, self.RAW.encode())
            helper = fixture.write_helper(root)
            live, trace = root / "live", root / "trace"
            live.write_text(self.RAW)
            bodies = {
                "ssh": 'printf "SSH\\n" >> "$TRACE"\nfor argument do remote=$argument; done\nexec /bin/sh -c "$remote"\n',
                "hostname": 'printf "leaf01\\n"\n',
                "cat": 'case "$1" in /sys/class/net/eth0/address) printf "02:00:00:00:00:01\\n";; /proc/sys/kernel/random/boot_id) printf "private-boot\\n";; "$STATE/"*|/dev/fd/*) exec /bin/cat "$@";; *) exit 1;; esac\n',
                "nv": 'test "$*" = "config show" || exit 92\n/bin/cat "$LIVE"\n',
                "date": 'printf "1000\\n"\n', "awk": 'exit 0\n', "ls": 'exit 0\n', "journalctl": 'exit 0\n',
                "sudo": 'if [ "$*" = "-n -- /usr/local/sbin/http-manual-ztp-applied-config" ]; then\nprintf "helper\\n" >> "$TRACE"\nexec /bin/sh "$HELPER"\nfi\nexit 0\n',
            }
            for name, body in bodies.items():
                executable = root / name
                executable.write_text("#!/bin/sh\n" + body)
                executable.chmod(0o700)
            device = {**DEVICE, "ssh_user": "cumulus", "ssh_ips": [DEVICE["ip"]]}
            prior = (receipt.read_bytes(), applied.read_bytes())
            with mock.patch.dict(os.environ, {"PATH": str(root) + ":/usr/bin:/bin", "TRACE": str(trace), "LIVE": str(live), "HELPER": str(helper), "STATE": str(root / "state")}):
                for hold in (False, True):
                    with self.subTest(hold=hold):
                        if hold:
                            (root / "state/.receipt-publication.pending").write_text("independent pending writer\n")
                            (root / "state/.receipt-publication.pending").chmod(0o600)
                        result = MONITOR.collect_switch(device, 5, None, root / "known-hosts")
                        observed = result.get("applied_config_observation", {})
                        self.assertIs(not hold, observed.get("trusted"), "only the actual fixed helper may attest its own source bytes")
                        self.assertEqual("" if hold else self.RAW, observed["raw_yaml"])
                        self.assertEqual(self.RAW, result["live_config_observation"]["text"], "receipt failure must not suppress independent live collection")
                        self.assertEqual(prior, (receipt.read_bytes(), applied.read_bytes()))
            self.assertEqual(["SSH", "helper", "SSH", "helper"], trace.read_text().splitlines())
            self.assertEqual("independent pending writer\n", (root / "state/.receipt-publication.pending").read_text())

    def test_failed_attempt_receipt_cannot_be_borrowed_by_a_later_connection(self):
        device = {**DEVICE, "ssh_user": "cumulus", "ssh_ips": [DEVICE["ip"], "192.0.2.11"]}
        with mock.patch.object(MONITOR, "run_command", side_effect=[
            {"returncode": 255, "stdout": self.frame(self.wire(self.RAW)), "stderr": "closed"},
            {"returncode": 0, "stdout": "__HOSTNAME_BEGIN__\nleaf01\n__HOSTNAME_END__\n", "stderr": ""},
        ]):
            result = MONITOR.collect_switch(device, 5, None, Path("/private/fixture-known-hosts"))
        self.assertEqual("192.0.2.11", result["connected_ip"])
        observed = result.get("applied_config_observation", {})
        self.assertIs(False, observed.get("trusted"))
        self.assertEqual({}, observed["receipt"])
        self.assertEqual("", observed["raw_yaml"])


class MonitorLiveConfigTransportTests(unittest.TestCase):
    LIVE = "- set:\n    system:\n      hostname: leaf01\n\n"

    @staticmethod
    def frame(text, code=0):
        return "__HTTP_MONITOR_LIVE_V1_BEGIN__\n" + text + "\n__HTTP_MONITOR_LIVE_V1_END__=" + str(code) + "\n"

    def parser(self):
        parser = getattr(MONITOR, "parse_live_config_observation", None)
        self.assertTrue(callable(parser), "monitor must collect its own same-connection live state")
        return parser

    def test_collector_retains_exact_live_bytes_from_its_one_batch_connection(self):
        output = "__HOSTNAME_BEGIN__\nleaf01\n__HOSTNAME_END__\n" + self.frame(self.LIVE)
        device = {**DEVICE, "ssh_user": "cumulus", "ssh_ips": [DEVICE["ip"]]}
        with mock.patch.object(MONITOR, "run_command", return_value={"returncode": 0, "stdout": output, "stderr": ""}) as run:
            result = MONITOR.collect_switch(device, 5, None, Path("/private/fixture-known-hosts"))
        self.assertEqual({"kind": "ok", "text": self.LIVE, "sha256": hashlib.sha256(self.LIVE.encode()).hexdigest()}, result.get("live_config_observation"))
        self.assertEqual(1, run.call_count)
        self.assertIn("BatchMode=yes", run.call_args.args[0])
        self.assertIn("nv config show", run.call_args.args[0][-1])

    def test_missing_failed_ambiguous_or_truncated_frame_has_no_positive_digest(self):
        valid = self.frame(self.LIVE)
        for label, text in (
            ("missing", "old apply and save complete"),
            ("duplicate", valid + valid),
            ("truncated", valid[:-5]),
            ("nonzero", self.frame(self.LIVE, 23)),
            ("empty", self.frame("")),
            ("bad-status", self.frame(self.LIVE, "0junk")),
            ("foreign-version", valid.replace("_V1_", "_V2_")),
        ):
            with self.subTest(case=label):
                observation = self.parser()(text)
                self.assertNotEqual("ok", observation["kind"])
                self.assertEqual("", observation["sha256"])
                self.assertEqual("", observation["text"])

    def test_live_frame_independent_maximum_and_degenerate_budget(self):
        # Version 1 accepts an independently fixed 8 MiB live payload; this
        # fixture length does not come from a production constant.
        text = "- set: {}\n#" + "x" * (8 * 1024 * 1024 - 12) + "\n"
        self.assertEqual(8388608, len(text.encode()))
        parsed = self.parser()(self.frame(text))
        self.assertEqual("ok", parsed["kind"])
        self.assertEqual(text, parsed["text"])
        with mock.patch.object(MONITOR, "MAX_LIVE_CONFIG_BYTES", 8388607):
            rejected = self.parser()(self.frame(text))
            self.assertNotEqual("ok", rejected["kind"])
            self.assertEqual("", rejected["sha256"])
        self.assertNotEqual("ok", self.parser()(self.frame(text + "x"))["kind"])

    def test_failed_attempt_cannot_supply_live_digest_to_another_connection(self):
        device = {**DEVICE, "ssh_user": "cumulus", "ssh_ips": [DEVICE["ip"], "192.0.2.11"]}
        with mock.patch.object(MONITOR, "run_command", side_effect=[
            {"returncode": 255, "stdout": self.frame(self.LIVE), "stderr": "connection closed"},
            {"returncode": 0, "stdout": "__HOSTNAME_BEGIN__\nleaf01\n__HOSTNAME_END__\n", "stderr": ""},
        ]):
            result = MONITOR.collect_switch(device, 5, None, Path("/private/fixture-known-hosts"))
        self.assertEqual("192.0.2.11", result["connected_ip"])
        self.assertEqual({"kind": "missing", "text": "", "sha256": ""}, result.get("live_config_observation"))

    def test_actual_private_shell_monitor_and_manual_observe_same_raw_live_bytes(self):
        script = getattr(MONITOR, "REMOTE_LIVE_CONFIG_SCRIPT", None)
        self.assertIsInstance(script, str)
        self.assertIn(script, MONITOR.REMOTE_SCRIPT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = root / "live.yaml"
            live.write_text(self.LIVE, encoding="utf-8")
            for name, body in {
                "hostname": 'printf "leaf01\\n"\n',
                "cat": 'printf "02:00:00:00:00:01\\n"\n',
                "nv": 'test "$*" = "config show" || exit 92\n/bin/cat "$LIVE"\nexit "$NV_EXIT"\n',
            }.items():
                executable = root / name
                executable.write_text("#!/bin/sh\n" + body, encoding="utf-8")
                executable.chmod(0o700)
            for code in (0, 23):
                with self.subTest(nv_exit=code):
                    def execute(command):
                        return subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True, check=False,
                                              timeout=5, env={"PATH": str(root) + ":/usr/bin:/bin", "LIVE": str(live), "NV_EXIT": str(code)})
                    observed = self.parser()(execute(script).stdout)
                    client = mock.Mock(args=SimpleNamespace(command_timeout=5, ssh_password=False))
                    client.run.side_effect = lambda _device, _host, command, **_kwargs: execute(command)
                    if code:
                        self.assertEqual("failed", observed["kind"])
                        with self.assertRaises(MANUAL.ManualZtpError):
                            MANUAL.collect_config_sync_live_state(client, DEVICE, DEVICE["ip"], "eth0")
                    else:
                        manual = MANUAL.collect_config_sync_live_state(client, DEVICE, DEVICE["ip"], "eth0")
                        self.assertEqual(self.LIVE, observed["text"])
                        self.assertEqual(manual, observed["text"])
                        self.assertEqual(hashlib.sha256(self.LIVE.encode()).hexdigest(), observed["sha256"])

    def test_real_collector_command_runs_full_remote_script_without_network_or_prior_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = root / "live.yaml"
            live.write_text(self.LIVE, encoding="utf-8")
            trace = root / "trace"
            bodies = {
                "ssh": 'printf "SSH\\n" >> "$TRACE"\nfor argument do remote=$argument; done\nexec /bin/sh -c "$remote"\n',
                "hostname": 'printf "hostname\\n" >> "$TRACE"\nprintf "leaf01\\n"\n',
                "cat": 'case "$1" in /sys/class/net/eth0/address) printf "mac\\n" >> "$TRACE"; printf "02:00:00:00:00:01\\n";; /proc/sys/kernel/random/boot_id) printf "private-boot\\n";; *) exit 1;; esac\n',
                "nv": 'test "$*" = "config show" || exit 92\nprintf "live\\n" >> "$TRACE"\n/bin/cat "$LIVE"\n',
                "date": 'printf "1000\\n"\n',
                "awk": 'exit 0\n',
                "ls": 'exit 0\n',
                "sudo": 'exit 0\n',
                "journalctl": 'exit 0\n',
            }
            for name, body in bodies.items():
                executable = root / name
                executable.write_text("#!/bin/sh\n" + body, encoding="utf-8")
                executable.chmod(0o700)
            device = {**DEVICE, "ssh_user": "cumulus", "ssh_ips": [DEVICE["ip"]]}
            with mock.patch.dict(os.environ, {"PATH": str(root) + ":/usr/bin:/bin", "TRACE": str(trace), "LIVE": str(live)}):
                result = MONITOR.collect_switch(device, 5, None, root / "known-hosts")
            self.assertEqual("ok", result["kind"], result["stderr"])
            self.assertEqual("leaf01", result["remote_hostname"])
            self.assertEqual(MAC, result["remote_eth0_mac"])
            self.assertEqual(self.LIVE, result["live_config_observation"]["text"])
            self.assertEqual(hashlib.sha256(self.LIVE.encode()).hexdigest(), result["live_config_observation"]["sha256"])
            self.assertEqual(["SSH", "hostname", "mac", "live"], trace.read_text().splitlines())
            proof = MONITOR.bind_monitor_live_observation(device, result)
            self.assertIs(True, proof["batch_identity_verified"])
            self.assertEqual(("leaf01", "eth0", "192.0.2.10", "020000000001"),
                             (proof["hostname"], proof["interface"], proof["transport_ip"], proof["mac_plain"]))
            self.assertEqual(hashlib.sha256(self.LIVE.encode()).hexdigest(), proof["live_state_sha256"])


class ConfigSyncSingleConnectionProofTests(unittest.TestCase):
    LIVE = "- set:\n    system:\n      hostname: leaf01\n"

    def observer(self):
        observer = getattr(MANUAL, "collect_config_sync_live_state", None)
        self.assertTrue(callable(observer), "identity and live state need one authenticated observation")
        return observer

    def test_identity_and_live_state_use_one_batch_connection_and_exact_raw_digest_input(self):
        client = mock.Mock(args=SimpleNamespace(command_timeout=20, ssh_password=False))
        client.run.return_value = completed("HTTP_CONFIG_SYNC_LIVE_V1\nleaf01\n" + MAC + "\n" + self.LIVE)
        self.assertEqual(self.LIVE, self.observer()(client, DEVICE, "192.0.2.10", "eth0"))
        self.assertEqual(1, client.run.call_count)
        remote = client.run.call_args.args[2]
        self.assertIn("hostname", remote)
        self.assertIn("/sys/class/net/eth0/address", remote)
        self.assertIn("nv config show", remote)
        self.assertEqual(20, client.run.call_args.kwargs["timeout"])

    def test_unbound_or_incomplete_same_connection_evidence_cannot_promote(self):
        valid = "HTTP_CONFIG_SYNC_LIVE_V1\nleaf01\n" + MAC + "\n" + self.LIVE
        for label, output, code, password, interface in (
            ("old-separate-read", self.LIVE, 0, False, "eth0"),
            ("foreign-host", valid.replace("\nleaf01\n", "\nforeign\n", 1), 0, False, "eth0"),
            ("foreign-mac", valid.replace(MAC, "02:00:00:00:00:02"), 0, False, "eth0"),
            ("malformed-mac", valid.replace(MAC, "junk" + MAC), 0, False, "eth0"),
            ("empty-live-state", "HTTP_CONFIG_SYNC_LIVE_V1\nleaf01\n" + MAC + "\n", 0, False, "eth0"),
            ("remote-failed", valid, 23, False, "eth0"),
            ("interactive", valid, 0, True, "eth0"),
            ("unsafe-interface", valid, 0, False, "eth0; touch forbidden"),
        ):
            with self.subTest(case=label):
                client = mock.Mock(args=SimpleNamespace(command_timeout=20, ssh_password=password))
                client.run.return_value = completed(output, returncode=code)
                with self.assertRaises(MANUAL.ManualZtpError):
                    self.observer()(client, DEVICE, "192.0.2.10", interface)
                if password or ";" in interface:
                    client.run.assert_not_called()

    def test_selected_endpoint_identity_interface_is_not_assumed_to_be_eth0(self):
        device = {**DEVICE, "candidate_identity": {"192.0.2.11|eth1": ("eth1", "020000000002")}}
        client = mock.Mock(args=SimpleNamespace(command_timeout=20, ssh_password=False))
        client.run.return_value = completed("HTTP_CONFIG_SYNC_LIVE_V1\nleaf01\n02:00:00:00:00:02\n" + self.LIVE)
        self.assertEqual(self.LIVE, self.observer()(client, device, "192.0.2.11", "eth1"))
        self.assertIn("/sys/class/net/eth1/address", client.run.call_args.args[2])
        client.run.return_value = completed("HTTP_CONFIG_SYNC_LIVE_V1\nleaf01\n" + MAC + "\n" + self.LIVE)
        with self.assertRaises(MANUAL.ManualZtpError):
            self.observer()(client, device, "192.0.2.11", "eth1")

    def test_remote_observation_executes_identity_then_live_state_in_one_private_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / "trace"
            live = root / "live.yaml"
            live.write_text(self.LIVE, encoding="utf-8")
            bodies = {
                "hostname": 'printf "hostname\\n" >> "$TRACE"\nprintf "leaf01\\n"\n',
                "cat": 'test "$1" = /sys/class/net/eth0/address || exit 91\nprintf "mac\\n" >> "$TRACE"\nprintf "02:00:00:00:00:01\\n"\n',
                "nv": 'test "$*" = "config show" || exit 92\nprintf "nv\\n" >> "$TRACE"\n/bin/cat "$LIVE"\nexit "$NV_EXIT"\n',
            }
            for name, body in bodies.items():
                path = root / name
                path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
                path.chmod(0o700)
            for code in (0, 23):
                with self.subTest(remote_exit=code):
                    trace.unlink(missing_ok=True)
                    def execute(_device, _host, command, *, timeout):
                        return subprocess.run(
                            ["/bin/sh", "-c", command], timeout=timeout,
                            text=True, capture_output=True, check=False,
                            env={"PATH": str(root) + ":/usr/bin:/bin", "TRACE": str(trace),
                                 "LIVE": str(live), "NV_EXIT": str(code)},
                        )
                    client = mock.Mock(args=SimpleNamespace(command_timeout=20, ssh_password=False))
                    client.run.side_effect = execute
                    if code:
                        with self.assertRaises(MANUAL.ManualZtpError):
                            self.observer()(client, DEVICE, "192.0.2.10", "eth0")
                    else:
                        self.assertEqual(self.LIVE, self.observer()(client, DEVICE, "192.0.2.10", "eth0"))
                    self.assertEqual(["hostname", "mac", "nv"], trace.read_text().splitlines())
                    self.assertEqual(1, client.run.call_count)


class ConfirmAppliedFingerprintTests(unittest.TestCase):
    def test_replace_config_rechecks_guard_and_uses_full_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            marker = release / ".published-complete"
            marker.write_text("ok\n", encoding="utf-8")
            expected = release / "leaf01.yaml"
            prior = ReplaceConfigGuardTests.config()
            expected_text = ReplaceConfigGuardTests.config(
                hostname="leaf01-new", acl_rule="drop",
            )
            expected.write_text(expected_text, encoding="utf-8")
            applied_output = protocol(prior)
            applied_reader = mock.Mock(
                args=SimpleNamespace(command_timeout=20),
                run=mock.Mock(return_value=completed(applied_output)),
            )
            applied_fingerprint = MANUAL.collect_applied_config(
                applied_reader, DEVICE, "192.0.2.10",
            )["fingerprint"]
            client = mock.Mock()
            client.args = SimpleNamespace(command_timeout=20, ssh_password=False)
            client.run.side_effect = [
                completed(prior), completed(applied_output), completed("saved\n"),
                completed("HTTP_CONFIG_SYNC_LIVE_V1\nleaf01\n" + MAC + "\n" + expected_text),
            ]
            prepared = {
                "published_marker": str(marker),
                "expected_yaml": str(expected),
                "published_release_dir": str(release.resolve()),
                "expected_yaml_sha256": MANUAL.normalized_nvue_config(
                    expected_text, label="expected",
                )[2],
                "current_sha256": hashlib.sha256(
                    prior.encode("utf-8")
                ).hexdigest(),
                "applied_fingerprint": applied_fingerprint,
                "published_mac_links": [],
            }
            with mock.patch.object(
                MANUAL, "connect_and_verify",
                return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(
                MANUAL, "verify_prepared_release_binding",
            ):
                result = MANUAL.trigger_one(
                    client, DEVICE, "", root / "manual-config-sync/run1",
                    operation="replace-config", prepared=prepared,
                )
            self.assertEqual("triggered", result["state"], result)
            self.assertIs(result.get("batch_identity_verified"), True)
            self.assertEqual(
                hashlib.sha256(expected_text.encode("utf-8")).hexdigest(),
                result.get("live_state_sha256"),
            )
            self.assertEqual(4, client.run.call_count)
            remote_call = client.run.call_args_list[-2]
            remote = remote_call.args[2]
            self.assertIn("nv config replace", remote)
            self.assertIn("nv config apply -y", remote)
            self.assertIn("nv config save", remote)
            self.assertNotIn("nv config patch", remote)
            self.assertEqual(expected_text, remote_call.kwargs["stdin"])

            for label, password_auth, post_state in (
                ("interactive", True, expected_text),
                ("live-drift", False, prior),
            ):
                with self.subTest(case=label):
                    unsafe = mock.Mock()
                    unsafe.args = SimpleNamespace(
                        command_timeout=20, ssh_password=password_auth,
                    )
                    unsafe.run.side_effect = [
                        completed(prior), completed(applied_output),
                        completed("saved\n"),
                        completed("HTTP_CONFIG_SYNC_LIVE_V1\nleaf01\n" + MAC + "\n" + post_state),
                    ]
                    with mock.patch.object(
                        MANUAL, "connect_and_verify",
                        return_value=("192.0.2.10", "eth0"),
                    ), mock.patch.object(
                        MANUAL, "verify_prepared_release_binding",
                    ):
                        rejected = MANUAL.trigger_one(
                            unsafe, DEVICE, "",
                            root / f"manual-config-sync/{label}",
                            operation="replace-config", prepared=prepared,
                        )
                    self.assertEqual("failed", rejected["state"], rejected)
                    self.assertNotIn("live_state_sha256", rejected)

    def test_trigger_rechecks_applied_fingerprint_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            marker = release / ".published-complete"
            marker.write_text("ok\n", encoding="utf-8")
            expected = release / "leaf01.yaml"
            expected_text = "- set:\n    system:\n      hostname: leaf01\n"
            expected.write_text(expected_text, encoding="utf-8")
            before = protocol(expected_text)
            after = protocol(expected_text.replace("leaf01", "changed"))
            client = mock.Mock()
            client.args.command_timeout = 20
            client.run.side_effect = [completed(expected_text), completed(after)]
            prepared = {
                "published_marker": str(marker),
                "expected_yaml": str(expected),
                "published_release_dir": str(release.resolve()),
                "expected_yaml_sha256": MANUAL.normalized_nvue_config(
                    expected_text, label="expected",
                )[2],
                "current_sha256": hashlib.sha256(
                    expected_text.encode("utf-8")
                ).hexdigest(),
                "applied_fingerprint": MANUAL.collect_applied_config(
                    mock.Mock(
                        args=SimpleNamespace(command_timeout=20),
                        run=mock.Mock(return_value=completed(before)),
                    ),
                    DEVICE, "192.0.2.10",
                )["fingerprint"],
                "published_mac_links": [],
            }
            with mock.patch.object(
                MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(
                MANUAL, "verify_prepared_release_binding",
            ):
                result = MANUAL.trigger_one(
                    client, DEVICE, "", root / "manual-reset/run1",
                    operation="reset", prepared=prepared,
                )
            self.assertEqual("failed", result["state"])
            self.assertIn("ZTP 输入凭据发生变化", result["reason"])
            self.assertEqual(2, client.run.call_count)


class ManualReceiptPublicationBoundaryTests(unittest.TestCase):
    def test_manual_publication_rechecks_parent_permissions_after_stage_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "result.json"
            original = b'{"state":"failed"}\n'
            target.write_bytes(original)
            target.chmod(0o600)
            real_sync = os.fsync
            changed = []
            def change_permissions(descriptor):
                real_sync(descriptor)
                if not changed and stat.S_ISREG(os.fstat(descriptor).st_mode):
                    root.chmod(0o777)
                    changed.append(True)
            with mock.patch.object(MANUAL.os, "fsync", side_effect=change_permissions):
                with self.assertRaises((OSError, ValueError)):
                    MANUAL.atomic_json(target, {"state": "triggered"})
            self.assertEqual([True], changed)
            self.assertEqual(original, target.read_bytes())
            self.assertEqual(0o777, stat.S_IMODE(root.stat().st_mode))
            self.assertFalse(list(root.glob(".result.json.*")))

    def test_manual_publication_requires_current_principal_without_chown_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "result.json"
            original = b'{"state":"failed"}\n'
            target.write_bytes(original)
            target.chmod(0o600)
            principal = os.geteuid()
            with mock.patch.object(MANUAL.os, "geteuid", return_value=principal + 1), \
                    mock.patch.object(MANUAL.os, "fchown") as chown:
                with self.assertRaises((OSError, ValueError)):
                    MANUAL.atomic_json(target, {"state": "triggered"})
            chown.assert_not_called()
            self.assertEqual(original, target.read_bytes())
            self.assertEqual(principal, target.stat().st_uid)
            self.assertFalse(list(root.glob(".result.json.*")))

    def test_manual_publication_rejects_unsafe_prior_image_and_parent_without_repair(self):
        for location in ("target", "parent"):
            for unsafe_mode in (0o022, 0o002):
                with self.subTest(location=location, mode=unsafe_mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    target = root / "result.json"
                    original = b'{"state":"failed","reason":"retained"}\n'
                    target.write_bytes(original)
                    target.chmod(0o600)
                    subject = target if location == "target" else root
                    mode = (0o600 if location == "target" else 0o700) | unsafe_mode
                    subject.chmod(mode)
                    before = subject.stat()
                    with self.assertRaises((OSError, ValueError)):
                        MANUAL.atomic_json(target, {"state": "triggered"})
                    self.assertEqual(original, target.read_bytes())
                    self.assertEqual(before.st_ino, subject.stat().st_ino)
                    self.assertEqual(mode, stat.S_IMODE(subject.stat().st_mode))
                    self.assertFalse(list(root.glob(".result.json.*")))

    def test_new_receipt_parent_entries_are_synced_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "new-run" / "leaf1" / "result.json"
            observed = []
            real_sync = os.fsync
            def observe(descriptor):
                held = os.fstat(descriptor)
                if stat.S_ISDIR(held.st_mode):
                    observed.append((held.st_dev, held.st_ino))
                real_sync(descriptor)
            with mock.patch.object(MANUAL.os, "fsync", side_effect=observe):
                MANUAL.atomic_json(target, {"state": "failed"})
            expected = [(p.stat().st_dev, p.stat().st_ino)
                        for p in (root, root / "new-run", target.parent)]
            self.assertEqual(expected, observed)
            self.assertEqual({"state": "failed"}, json.loads(target.read_text()))

    def test_manual_receipt_rollback_preserves_old_image_and_foreign_stage(self):
        for mutation in ("directory-failure", "symlink", "hardlink", "regular", "mode", "late-image"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                target = root / "result.json"
                old = b'{"state":"failed","reason":"prior-veto"}\n'
                target.write_bytes(old)
                target.chmod(0o640)
                foreign = root / "foreign.json"
                image = b'{"state":"failed","reason":"foreign-writer"}\n'
                foreign.write_bytes(image)
                foreign.chmod(0o600)
                real_sync = os.fsync
                changed = []
                def inject(descriptor):
                    held = os.fstat(descriptor)
                    if mutation == "directory-failure" and stat.S_ISDIR(held.st_mode) and not changed:
                        changed.append(target)
                        raise OSError("injected manual receipt directory sync failure")
                    real_sync(descriptor)
                    if changed:
                        return
                    if mutation == "late-image":
                        if stat.S_ISDIR(held.st_mode):
                            changed.append(target)
                            foreign.replace(target)
                        return
                    if mutation == "directory-failure" or not stat.S_ISREG(held.st_mode):
                        return
                    stages = list(root.glob(".result.json.*"))
                    self.assertEqual(1, len(stages))
                    stage = stages[0]
                    self.assertEqual(held.st_ino, stage.stat().st_ino)
                    changed.append(stage)
                    if mutation == "mode":
                        stage.chmod(0o666)
                    else:
                        stage.unlink()
                        if mutation == "symlink":
                            stage.symlink_to(foreign)
                        elif mutation == "hardlink":
                            os.link(foreign, stage)
                        else:
                            stage.write_bytes(image)
                            stage.chmod(0o600)
                with mock.patch.object(MANUAL.os, "fsync", side_effect=inject):
                    with self.assertRaises(OSError):
                        MANUAL.atomic_json(target, {"state": "triggered"})
                self.assertEqual(1, len(changed))
                if mutation == "late-image":
                    self.assertEqual(image, target.read_bytes())
                else:
                    self.assertEqual(old, target.read_bytes())
                    self.assertEqual(0o640, stat.S_IMODE(target.stat().st_mode))
                    self.assertEqual(image, foreign.read_bytes())
                    self.assertEqual(0o600, stat.S_IMODE(foreign.stat().st_mode))
                    if mutation == "directory-failure":
                        self.assertFalse(list(root.glob(".result.json.*")))
                    else:
                        self.assertTrue(changed[0].exists(), "retain a foreign stage")

    def test_rebind_after_visible_check_cannot_redirect_fd_relative_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            visible = root / "run"
            detached = root / "detached"
            attacker = root / "attacker"
            visible.mkdir()
            attacker.mkdir()
            target = visible / "result.json"
            original_check = MANUAL._assert_receipt_parent_bound
            checked = False

            def rebind_after_first_check(path, parent_fd):
                nonlocal checked
                original_check(path, parent_fd)
                if checked:
                    return
                checked = True
                visible.rename(detached)
                visible.symlink_to(attacker, target_is_directory=True)
                staged = next(detached.glob(".result.json.*"))
                (attacker / staged.name).write_bytes(staged.read_bytes())

            with mock.patch.object(
                MANUAL, "_assert_receipt_parent_bound",
                side_effect=rebind_after_first_check,
            ):
                with self.assertRaisesRegex(ValueError, "publication parent changed"):
                    MANUAL.atomic_json(target, {"state": "triggered"})

            self.assertTrue(checked)
            self.assertFalse((attacker / "result.json").exists())
            self.assertFalse((detached / "result.json").exists())

    def test_rebound_result_parent_cannot_publish_to_attacker_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            visible = root / "manual-trigger" / "rebound" / DEVICE["hostname"]
            detached = root / "detached"
            attacker = root / "attacker"
            visible.mkdir(parents=True)
            attacker.mkdir()
            target = visible / "result.json"
            good = root / "manual-trigger" / "good" / DEVICE["hostname"] / "result.json"
            MANUAL.atomic_json(good, {
                "hostname": DEVICE["hostname"], "state": "triggered",
                "trigger_id": "good", "trigger_source": "manual_cli",
                "finished_at": "2026-09-26T01:00:00+08:00",
            })
            original_fsync = os.fsync
            moved = False

            def rebind_after_receipt_flush(descriptor):
                nonlocal moved
                original_fsync(descriptor)
                if moved:
                    return
                moved = True
                visible.rename(detached)
                visible.symlink_to(attacker, target_is_directory=True)
                staged = next(detached.glob(".result.json.*"))
                (attacker / staged.name).write_bytes(staged.read_bytes())

            with mock.patch.object(
                MANUAL.os, "fsync", side_effect=rebind_after_receipt_flush,
            ):
                with self.assertRaisesRegex(ValueError, "publication parent changed"):
                    MANUAL.atomic_json(target, {
                        "hostname": DEVICE["hostname"], "state": "triggered",
                        "trigger_id": "rebound", "trigger_source": "manual_cli",
                        "finished_at": "2026-09-26T01:01:00+08:00",
                    })

            self.assertTrue(moved)
            self.assertFalse((attacker / "result.json").exists())
            self.assertFalse((detached / "result.json").exists())
            markers = MONITOR.latest_manual_trigger_markers(root)
            self.assertEqual("good", markers[DEVICE["hostname"]]["trigger_id"])


class ManualMarkerMonitorWorkflowTests(unittest.TestCase):
    def test_issue0014_invalid_only_result_is_rejected_with_visible_diagnostic(self):
        for label, value in (("junk", "zzz"), ("blank", "   "), ("missing", None)):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bad_path = (
                    root / "manual-trigger" / "bad" / DEVICE["hostname"] / "result.json"
                )
                bad_path.parent.mkdir(parents=True)
                result = {
                    "hostname": DEVICE["hostname"], "state": "triggered",
                    "trigger_id": "bad",
                }
                if value is not None:
                    result["finished_at"] = value
                bad_path.write_text(json.dumps(result), encoding="utf-8")

                warnings = io.StringIO()
                with redirect_stderr(warnings):
                    markers = MONITOR.latest_manual_trigger_markers(root)

                self.assertEqual({}, markers)
                self.assertIn("[WARN]", warnings.getvalue())
                self.assertIn(DEVICE["hostname"], warnings.getvalue())
                self.assertIn("result.json", warnings.getvalue())
                self.assertRegex(warnings.getvalue(), r"(?i)(timestamp|时间戳)")
                if value:
                    self.assertIn(value.strip(), warnings.getvalue())

    def test_same_id_real_manual_result_repairs_persisted_junk_without_new_round(self):
        """A real manual result repairs stored junk without replaying its round."""
        valid_marker = "2026-09-24T08:45:00+08:00"
        previous_report = {
            "generated_at": "2026-09-24T08:00:00+08:00",
            "devices": [{
                "hostname": DEVICE["hostname"], "ztp_round": 2,
                "manual_cycle_marker": "zzz", "trigger_id": "same",
                "trigger_source": "manual_cli", "manual_operation": "ztp",
                "cycle_started_at": "zzz",
                "manual_command_finished_at": "zzz", "stages": {},
            }],
        }
        client = mock.Mock()
        client.args.command_timeout = 10
        client.args.non_interactive = True
        client.sudo_command.return_value = ("sudo -n helper", "")
        client.run.side_effect = [
            completed("config\n"),
            completed("[2026-09-24T00:45:00Z] [ZTP] Cumulus provision complete\n"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(
                MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(MANUAL, "datetime") as clock:
                clock.now.return_value = datetime.fromisoformat(valid_marker)
                result = MANUAL.trigger_one(
                    client, DEVICE, "http://192.0.2.2/ztp/ztp-bootstrap_oob.sh",
                    root / "manual-trigger" / "same", "manual_cli", "same",
                )
            self.assertEqual("triggered", result["state"], result)
            manual_markers = MONITOR.latest_manual_trigger_markers(root)

        self.assertEqual({DEVICE["hostname"]}, set(manual_markers))
        devices = [{"hostname": DEVICE["hostname"], "events": [], "stages": {}}]
        MONITOR.assign_ztp_rounds(devices, previous_report, manual_markers)
        self.assertEqual(2, devices[0]["ztp_round"])
        self.assertEqual("same", devices[0]["trigger_id"])
        self.assertEqual(valid_marker, devices[0]["manual_cycle_marker"])
        self.assertEqual(valid_marker, devices[0]["cycle_started_at"])
        self.assertEqual(valid_marker, devices[0]["manual_command_finished_at"])

        repeated = [{"hostname": DEVICE["hostname"], "events": [], "stages": {}}]
        MONITOR.assign_ztp_rounds(
            repeated,
            {"generated_at": valid_marker, "devices": devices},
            manual_markers,
        )
        self.assertEqual(2, repeated[0]["ztp_round"])
        self.assertEqual(valid_marker, repeated[0]["manual_cycle_marker"])

    def test_issue0014_real_manual_result_beats_invalid_result_in_both_scan_orders(self):
        fixed_time = datetime(2026, 9, 24, 8, 45, tzinfo=timezone(timedelta(hours=8)))
        client = mock.Mock()
        client.args.command_timeout = 10
        client.args.non_interactive = True
        client.sudo_command.return_value = ("sudo -n helper", "")
        client.run.side_effect = [
            completed("config\n"),
            completed("[2026-09-24T00:45:00Z] [ZTP] Cumulus provision complete\n"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good_path = root / "manual-trigger" / "good" / DEVICE["hostname"] / "result.json"
            with mock.patch.object(
                MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(MANUAL, "datetime") as clock:
                clock.now.return_value = fixed_time
                result = MANUAL.trigger_one(
                    client, DEVICE, "http://192.0.2.2/ztp/ztp-bootstrap_oob.sh",
                    root / "manual-trigger" / "good", "manual_cli", "good",
                )
            self.assertEqual("triggered", result["state"], result)
            self.assertTrue(good_path.is_file())
            self.assertEqual(fixed_time, datetime.fromisoformat(result["finished_at"]))

            bad_path = root / "manual-trigger" / "bad" / DEVICE["hostname"] / "result.json"
            bad_path.parent.mkdir(parents=True)
            bad_path.write_text(json.dumps({
                "hostname": DEVICE["hostname"], "state": "triggered",
                "finished_at": "zzz", "trigger_id": "bad",
                "command_ztp_log_sha256": "", "command_ztp_complete": False,
            }), encoding="utf-8")
            original_glob = Path.glob
            for order in ((bad_path, good_path), (good_path, bad_path)):
                def ordered_glob(path, pattern):
                    if path == root / "manual-trigger" and pattern == "*/*/result.json":
                        return iter(order)
                    return original_glob(path, pattern)

                with self.subTest(first=order[0].parent.parent.name), mock.patch.object(
                    Path, "glob", new=ordered_glob,
                ):
                    markers = MONITOR.latest_manual_trigger_markers(root)
                    self.assertEqual({DEVICE["hostname"]}, set(markers))
                    self.assertEqual("good", markers[DEVICE["hostname"]]["trigger_id"])
                    self.assertEqual("manual_cli", markers[DEVICE["hostname"]]["trigger_source"])
                    self.assertEqual(
                        fixed_time,
                        datetime.fromisoformat(markers[DEVICE["hostname"]]["timestamp"]),
                    )


if __name__ == "__main__":
    unittest.main()
