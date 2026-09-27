"""Runtime NVUE normalization and manual ZTP preview/confirm comparisons."""

import hashlib
import importlib.util
import io
import json
import os
import sys
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
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
            client.args = SimpleNamespace(command_timeout=20)
            client.run.side_effect = [
                completed(prior), completed(applied_output), completed("saved\n"),
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
            remote_call = client.run.call_args_list[-1]
            remote = remote_call.args[2]
            self.assertIn("nv config replace", remote)
            self.assertIn("nv config apply -y", remote)
            self.assertIn("nv config save", remote)
            self.assertNotIn("nv config patch", remote)
            self.assertEqual(expected_text, remote_call.kwargs["stdin"])

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
