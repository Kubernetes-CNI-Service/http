"""Runtime NVUE normalization and manual ZTP preview/confirm comparisons."""

import ast
import hashlib
import importlib.util
import io
import json
import os
import sys
from contextlib import contextmanager, redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
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

WORKER_SPEC = importlib.util.spec_from_file_location(
    "manual_config_sync_worker_under_test", ROOT / "monitor/manual-ztp-worker.py",
)
WORKER = importlib.util.module_from_spec(WORKER_SPEC)
assert WORKER_SPEC.loader is not None
WORKER_SPEC.loader.exec_module(WORKER)


MAC = "02:00:00:00:00:01"
DEVICE = {
    "hostname": "leaf01", "type": "eth", "ip": "192.0.2.10",
    "mac_plain": "020000000001", "identity_macs": {"eth0": "020000000001"},
}


def completed(stdout="", returncode=0, stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


@contextmanager
def host_timezone_utc():
    """Exercise timestamp contracts independently of the runner host zone."""
    previous = os.environ.get("TZ")
    try:
        os.environ["TZ"] = "UTC"
        time.tzset()
        yield
    finally:
        if previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous
        time.tzset()


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
    (project / "02-dhcp-subnet_config.csv").write_text(
        "shared_network,subnet,netmask,range_start,range_end,routers,"
        "ztp_service_ip,cumulus_profile,nvos_ztp\n"
        "fabric,192.0.2.0,255.255.255.0,192.0.2.10,192.0.2.20,"
        "192.0.2.1,,none,no\n",
        encoding="utf-8",
    )
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

    def test_runtime_drift_reports_only_fixed_categories_and_bounded_counts(self):
        secret_key = "tenant-super-secret-unique-key"
        drifted = self.config().replace(
            "      eth0:\n",
            f"      {secret_key}:\n        type: swp\n      eth0:\n",
        ).replace("hostname: leaf01", "hostname: hidden-new-name").replace(
            "rule: accept", "rule: drop",
        ).replace(
            "    acl:\n", "    private-root-key:\n      private-leaf: 1\n    acl:\n",
        )
        result = self.assert_refused("runtime-drift", current=drifted)
        self.assertEqual({
            "difference_count": 4,
            "capped": False,
            "categories": {"acl": 1, "interface": 1, "system": 1, "other": 1},
        }, result["runtime_drift_summary"])
        self.assertNotIn(secret_key, json.dumps(result, ensure_ascii=False))
        self.assertNotIn("hidden-new-name", json.dumps(result, ensure_ascii=False))
        self.assertNotIn("drop", json.dumps(result, ensure_ascii=False))
        self.assertNotIn("private-root-key", json.dumps(result, ensure_ascii=False))

    def test_runtime_drift_summary_caps_unbounded_dynamic_map_keys(self):
        added = "".join(
            f"      tenant-private-{index}:\n        type: swp\n"
            for index in range(130)
        )
        drifted = self.config().replace("      eth0:\n", added + "      eth0:\n")
        result = self.assert_refused("runtime-drift", current=drifted)
        self.assertEqual(100, result["runtime_drift_summary"]["difference_count"])
        self.assertTrue(result["runtime_drift_summary"]["capped"])
        self.assertEqual(
            {"interface": 100}, result["runtime_drift_summary"]["categories"],
        )
        self.assertNotIn("tenant-private-", json.dumps(result, ensure_ascii=False))

    def test_capped_summary_omits_unobserved_categories_instead_of_zero(self):
        added = "".join(
            f"      tenant-private-{index}:\n        type: swp\n"
            for index in range(100)
        )
        drifted = self.config().replace(
            "      eth0:\n", added + "      eth0:\n",
        ).replace("hostname: leaf01", "hostname: changed")
        result = self.assert_refused("runtime-drift", current=drifted)
        self.assertEqual({
            "difference_count": 100,
            "capped": True,
            "categories": {"interface": 100},
        }, result["runtime_drift_summary"])

    def test_replace_flag_is_mutually_exclusive_with_original_operations(self):
        parser = MANUAL.parser()
        args = parser.parse_args(["leaf01", "--replace-config"])
        self.assertTrue(args.replace_config)
        with self.assertRaises(SystemExit):
            parser.parse_args([
                "leaf01", "--replace-config", "--operation", "renew",
            ])


class RuntimeDriftPreviewWorkflowTests(unittest.TestCase):
    def test_worker_preview_refuses_drift_without_confirm_or_replace(self):
        prior = ReplaceConfigGuardTests.config()
        current = prior.replace("hostname: leaf01", "hostname: sensitive-live-value")
        expected_text = ReplaceConfigGuardTests.config(hostname="leaf01-new")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            marker = release / ".published-complete"
            marker.write_text("complete\n", encoding="utf-8")
            expected = release / "leaf01.yaml"
            expected.write_text(expected_text, encoding="utf-8")
            evidence = root / "preview-evidence"
            client = mock.Mock()
            client.args.command_timeout = 20
            client.run.side_effect = [
                completed(current), completed(protocol(prior)),
            ]
            commands = []

            def local_preflight(command, **_kwargs):
                commands.append(command)
                self.assertEqual(str(ROOT / "ztp/manual-ztp.py"), command[1])
                self.assertIn("--replace-config", command)
                self.assertIn("--preflight-only", command)
                try:
                    MANUAL.preflight_one(
                        client, root, DEVICE, evidence, replace_config=True,
                    )
                except MANUAL.ManualZtpError as exc:
                    return completed("", 1, str(exc))
                return completed("unexpected preview success")

            with mock.patch.object(
                MANUAL, "validate_parent_release_binding",
                return_value={"binding_sha256": "b" * 64},
            ), mock.patch.object(
                MANUAL, "connect_and_verify",
                return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(
                MANUAL, "published_yaml_paths",
                return_value=(marker, expected, release / "mac.yaml"),
            ), mock.patch.object(
                WORKER.subprocess, "run", side_effect=local_preflight,
            ), mock.patch.object(
                WORKER, "write_device_status",
            ) as write_status, mock.patch.object(
                WORKER, "preview_result", side_effect=AssertionError("preview ready"),
            ) as preview_result, mock.patch.object(
                MANUAL, "trigger_one", side_effect=AssertionError("replace"),
            ) as trigger_one, redirect_stderr(io.StringIO()):
                WORKER.execute_preview(
                    "leaf01", "eth", 20, "replace-config", "operation-1", "trigger-1",
                )

            self.assertEqual(1, len(commands))
            self.assertEqual(2, client.run.call_count)
            self.assertEqual("nv config show", client.run.call_args_list[0].args[2])
            self.assertEqual(
                MANUAL.APPLIED_CONFIG_HELPER,
                client.run.call_args_list[1].args[2],
            )
            self.assertFalse(evidence.exists())
            preview_result.assert_not_called()
            trigger_one.assert_not_called()
            self.assertEqual(["previewing", "failed"], [
                call.args[1] for call in write_status.call_args_list
            ])
            failure = write_status.call_args_list[-1].kwargs
            self.assertEqual("preview", failure["phase"])
            self.assertEqual("replace-config", failure["requested_operation"])
            self.assertIn("runtime-drift", failure["reason"])
            self.assertIn("差异节点=1; 类别=system:1", failure["reason"])
            self.assertNotIn("sensitive-live-value", failure["reason"])


class ConsecutiveConfigSyncBaselineTests(unittest.TestCase):
    """A verified manual replace can become the next guarded prior input."""

    @staticmethod
    def previous_sync(
        project, prior_text, receipt_fingerprint, *, state="triggered",
        stamp="20261001_100000_000001",
    ):
        root = project / "99-output-ztp/manual-config-sync" / stamp
        evidence = root / DEVICE["hostname"]
        evidence.mkdir(parents=True)
        root.chmod(0o700)
        evidence.chmod(0o700)
        raw_digest = hashlib.sha256(prior_text.encode("utf-8")).hexdigest()
        runtime_digest = MANUAL.runtime_comparable_nvue_config(
            prior_text, label="prior manual sync",
        )[2]
        expected = evidence / "expected.yaml"
        expected.write_text(prior_text, encoding="utf-8")
        expected.chmod(0o600)
        preflight = {
            "hostname": DEVICE["hostname"], "operation_id": "old-operation",
            "trigger_id": "old-trigger", "applied_fingerprint": receipt_fingerprint,
            "expected_yaml_raw_sha256": raw_digest,
            "replace_guard_baseline_source": "device-ztp-receipt",
            "replace_guard": {"allowed": True, "reason_code": "ready"},
        }
        result = {
            "hostname": DEVICE["hostname"], "type": "eth",
            "state": state, "operation": "replace-config",
            "effective_operation": "replace-config",
            "operation_id": "old-operation", "trigger_id": "old-trigger",
            "trigger_source": "manual_config_sync_web",
            "config_sync_outcome": "runtime-verified" if state == "triggered" else "outcome-unknown",
            "config_sync_verification": {
                "schema": 1, "hostname": DEVICE["hostname"],
                "eth0_mac": DEVICE["mac_plain"],
                "operation_id": "old-operation", "trigger_id": "old-trigger",
                "expected_raw_sha256": raw_digest,
                "expected_runtime_sha256": runtime_digest,
                "actual_runtime_sha256": runtime_digest,
                "receipt_refreshed": False,
            },
        }
        summary = {
            "state": state, "operation": "replace-config",
            "effective_operation": "replace-config",
            "operation_id": "old-operation", "trigger_source": "manual_config_sync_web",
            "confirmed_at": "2026-10-01T10:00:00+08:00",
            "targets": [{"hostname": DEVICE["hostname"], "type": "eth",
                         "trigger_id": "old-trigger", "effective_operation": "replace-config"}],
            "preflight": [preflight],
            "results": [result],
        }
        for name, value, directory in (
            ("preflight.json", preflight, evidence),
            ("result.json", result, evidence),
            ("summary.json", summary, root),
        ):
            path = directory / name
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)
        return evidence

    def test_verified_previous_sync_is_next_guard_baseline_but_not_device_receipt(self):
        old_ztp = ReplaceConfigGuardTests.config()
        prior_sync = old_ztp.replace(
            "    acl:\n", "    vrf:\n      customer:\n        table: 1001\n    acl:\n",
        )
        desired = prior_sync.replace("rule: accept", "rule: drop")
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.previous_sync(project, prior_sync, applied["fingerprint"])
            selected = MANUAL.select_replace_guard_baseline(project, DEVICE, applied)
            self.assertEqual("manual-sync-readback", selected["source"])
            self.assertNotEqual(applied["raw_yaml"], selected["applied"]["raw_yaml"])
            self.assertEqual(old_ztp, applied["raw_yaml"])
            guard = MANUAL.evaluate_replace_config_guard(
                prior_sync, selected["applied"], desired,
            )
            self.assertTrue(guard["allowed"], guard)
            self.assertEqual("ready", guard["reason_code"])
            drifted = old_ztp.replace("rule: accept", "rule: quarantine")
            drift_guard = MANUAL.evaluate_replace_config_guard(
                drifted, selected["applied"], desired,
            )
            self.assertFalse(drift_guard["allowed"])
            self.assertEqual("runtime-drift", drift_guard["reason_code"])

    def test_failed_or_tampered_later_sync_never_becomes_baseline(self):
        old_ztp = ReplaceConfigGuardTests.config()
        prior_sync = old_ztp.replace("rule: accept", "rule: drop")
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            evidence = self.previous_sync(project, prior_sync, applied["fingerprint"])
            result_path = evidence / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["config_sync_verification"]["actual_runtime_sha256"] = "f" * 64
            result_path.write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.select_replace_guard_baseline(project, DEVICE, applied)

    def test_later_submitted_failure_blocks_reusing_older_success(self):
        old_ztp = ReplaceConfigGuardTests.config()
        prior_sync = old_ztp.replace("rule: accept", "rule: drop")
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.previous_sync(project, prior_sync, applied["fingerprint"])
            self.previous_sync(
                project, prior_sync, applied["fingerprint"], state="failed",
                stamp="20261001_110000_000001",
            )
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "最近配置同步结果"):
                MANUAL.select_replace_guard_baseline(project, DEVICE, applied)

    def test_clock_rollback_cannot_reuse_success_before_later_failed_submit(self):
        old_ztp = ReplaceConfigGuardTests.config()
        prior_sync = old_ztp.replace("rule: accept", "rule: drop")
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.previous_sync(
                project, prior_sync, applied["fingerprint"],
                stamp="20261001_120000_000001",
            )
            # The next confirmed attempt starts after the wall clock moves back.
            self.previous_sync(
                project, prior_sync, applied["fingerprint"], state="failed",
                stamp="20261001_090000_000001",
            )
            with self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.select_replace_guard_baseline(project, DEVICE, applied)

    def test_two_legacy_confirmed_successes_without_order_anchor_fail_closed(self):
        old_ztp = ReplaceConfigGuardTests.config()
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            for stamp in ("20261001_100000_000001", "20261001_110000_000001"):
                self.previous_sync(
                    project, old_ztp, applied["fingerprint"], stamp=stamp,
                )
            with self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.select_replace_guard_baseline(project, DEVICE, applied)

    def test_order_anchor_selects_later_failed_submit_after_clock_rollback(self):
        old_ztp = ReplaceConfigGuardTests.config()
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            success = self.previous_sync(
                project, old_ztp, applied["fingerprint"],
                stamp="20261001_120000_000001",
            )
            failed = self.previous_sync(
                project, old_ztp, applied["fingerprint"], state="failed",
                stamp="20261001_090000_000001",
            )
            first = MANUAL.publish_confirmed_sync_anchor(
                project, DEVICE, success.parent, "old-operation", "old-trigger",
                applied["fingerprint"],
            )
            second = MANUAL.publish_confirmed_sync_anchor(
                project, DEVICE, failed.parent, "old-operation", "old-trigger",
                applied["fingerprint"],
            )
            self.assertEqual((1, 2), (first, second))
            with self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.select_replace_guard_baseline(project, DEVICE, applied)

    def test_order_anchor_rollback_is_detected_against_run_markers(self):
        old_ztp = ReplaceConfigGuardTests.config()
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            first = self.previous_sync(
                project, old_ztp, applied["fingerprint"],
                stamp="20261001_100000_000001",
            )
            second = self.previous_sync(
                project, old_ztp, applied["fingerprint"],
                stamp="20261001_110000_000001",
            )
            MANUAL.publish_confirmed_sync_anchor(
                project, DEVICE, first.parent, "old-operation", "old-trigger",
                applied["fingerprint"],
            )
            anchor = MANUAL.confirmed_sync_anchor_path(project, DEVICE)
            older_anchor = anchor.read_bytes()
            MANUAL.publish_confirmed_sync_anchor(
                project, DEVICE, second.parent, "old-operation", "old-trigger",
                applied["fingerprint"],
            )
            anchor.write_bytes(older_anchor)
            evidence_paths = (
                anchor,
                first.parent / DEVICE["hostname"] / "confirmed-order.json",
                second.parent / DEVICE["hostname"] / "confirmed-order.json",
            )
            before = {path: (path.stat().st_ino, path.read_bytes())
                      for path in evidence_paths}
            with self.assertRaises(MANUAL.ManualZtpError) as caught:
                MANUAL.select_replace_guard_baseline(project, DEVICE, applied)
            message = str(caught.exception)
            for required in ("结果未知", "保留", "只读核查", "不要盲目重试"):
                self.assertIn(required, message)
            self.assertEqual(before, {
                path: (path.stat().st_ino, path.read_bytes())
                for path in evidence_paths
            })

    def test_crash_between_run_marker_and_order_anchor_fails_closed(self):
        old_ztp = ReplaceConfigGuardTests.config()
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            evidence = self.previous_sync(project, old_ztp, applied["fingerprint"])
            anchor_path = MANUAL.confirmed_sync_anchor_path(project, DEVICE)
            publish = MANUAL.atomic_json

            def crash_before_anchor(path, value):
                if path == anchor_path:
                    raise OSError("simulated interruption before anchor publish")
                return publish(path, value)

            with mock.patch.object(MANUAL, "atomic_json", side_effect=crash_before_anchor):
                with self.assertRaisesRegex(OSError, "simulated interruption"):
                    MANUAL.publish_confirmed_sync_anchor(
                        project, DEVICE, evidence.parent, "old-operation",
                        "old-trigger", applied["fingerprint"],
                    )
            self.assertTrue((evidence / "confirmed-order.json").is_file())
            self.assertFalse(anchor_path.exists())
            marker_path = evidence / "confirmed-order.json"
            marker_before = (marker_path.stat().st_ino, marker_path.read_bytes())
            with self.assertRaises(MANUAL.ManualZtpError) as caught:
                MANUAL.select_replace_guard_baseline(project, DEVICE, applied)
            message = str(caught.exception)
            for required in ("结果未知", "保留", "只读核查", "不要盲目重试"):
                self.assertIn(required, message)
            self.assertEqual(marker_before,
                             (marker_path.stat().st_ino, marker_path.read_bytes()))
            self.assertFalse(anchor_path.exists())

    def test_orphan_order_guidance_reaches_web_worker_as_failure(self):
        old_ztp = ReplaceConfigGuardTests.config()
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            evidence = self.previous_sync(project, old_ztp, applied["fingerprint"])
            marker_path = evidence / "confirmed-order.json"
            MANUAL.atomic_json(marker_path, {
                "schema": 1, "hostname": DEVICE["hostname"],
                "stamp": evidence.parent.name, "sequence": 1,
                "operation_id": "old-operation", "trigger_id": "old-trigger",
                "receipt_fingerprint": applied["fingerprint"],
            })
            marker_before = (marker_path.stat().st_ino, marker_path.read_bytes())
            with self.assertRaises(MANUAL.ManualZtpError) as caught:
                MANUAL.select_replace_guard_baseline(project, DEVICE, applied)
            self.assertIn("结果未知", str(caught.exception))

            devices_csv = project / "02-devices_config.csv"
            devices_csv.write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            writes = []
            with mock.patch.object(WORKER, "DEVICES_CSV", devices_csv), \
                 mock.patch.object(WORKER, "latest_device_state", return_value={}), \
                 mock.patch.object(WORKER, "command_for", return_value=["fixed-helper"]), \
                 mock.patch.object(
                     WORKER, "write_device_status",
                     side_effect=lambda _host, state, **kw: writes.append((state, kw)),
                 ), mock.patch.object(
                     WORKER.subprocess, "run",
                     return_value=completed(
                         returncode=1, stderr=f"[ERROR] {caught.exception}\n",
                     ),
                 ) as local_command:
                WORKER.execute(
                    "leaf01", "prod", 30, 60, 1,
                    operation="replace-config", operation_id="new-operation",
                    trigger_id="new-trigger", requested_operation="replace-config",
                    preview_fingerprint={"current_sha256": "a" * 64},
                )
            local_command.assert_called_once()
            self.assertEqual("failed", writes[-1][0])
            self.assertNotIn("config_sync_success", [state for state, _ in writes])
            self.assertEqual("config_sync", writes[-1][1]["phase"])
            for required in ("结果未知", "保留", "只读核查", "不要盲目重试"):
                self.assertIn(required, writes[-1][1]["reason"])
            self.assertEqual(marker_before,
                             (marker_path.stat().st_ino, marker_path.read_bytes()))
            self.assertFalse(MANUAL.confirmed_sync_anchor_path(project, DEVICE).exists())

    def test_main_reserves_single_manual_run_before_first_summary_write(self):
        tree = ast.parse((ROOT / "ztp/manual-ztp.py").read_text(encoding="utf-8"))
        main = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        bindings = [node for node in ast.walk(main)
                    if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "run_dir"
                            for target in node.targets)]
        reservations = [node for node in ast.walk(main)
                        if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "reserve_manual_run_dir"]
        summary_writes = [node for node in ast.walk(main)
                          if isinstance(node, ast.Call)
                          and isinstance(node.func, ast.Name)
                          and node.func.id == "atomic_json"
                          and node.args and any(
                              isinstance(child, ast.Name) and child.id == "run_dir"
                              for child in ast.walk(node.args[0]))]
        self.assertEqual(1, len(bindings))
        self.assertEqual(1, len(reservations))
        self.assertTrue(summary_writes)
        self.assertEqual(bindings[0].end_lineno + 1, reservations[0].lineno)
        self.assertLess(reservations[0].lineno,
                        min(write.lineno for write in summary_writes))

    def test_repeated_wall_clock_stamp_cannot_overwrite_old_run_evidence(self):
        old_ztp = ReplaceConfigGuardTests.config()
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            evidence = self.previous_sync(
                project, old_ztp, applied["fingerprint"],
                stamp="20261001_120000_000001",
            )
            summary = evidence.parent / "summary.json"
            old_bytes = summary.read_bytes()
            with self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.reserve_manual_run_dir(evidence.parent)
            self.assertEqual(old_bytes, summary.read_bytes())

    def test_symlinked_private_evidence_does_not_become_baseline(self):
        old_ztp = ReplaceConfigGuardTests.config()
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            evidence = self.previous_sync(project, old_ztp, applied["fingerprint"])
            expected = evidence / "expected.yaml"
            outside = project / "outside.yaml"
            outside.write_bytes(expected.read_bytes())
            expected.unlink()
            expected.symlink_to(outside)
            with self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.select_replace_guard_baseline(project, DEVICE, applied)

    def test_new_device_ztp_receipt_invalidates_old_manual_baseline(self):
        old_ztp = ReplaceConfigGuardTests.config()
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            evidence = self.previous_sync(project, old_ztp, applied["fingerprint"])
            MANUAL.publish_confirmed_sync_anchor(
                project, DEVICE, evidence.parent, "old-operation", "old-trigger",
                applied["fingerprint"],
            )
            newer = dict(applied, fingerprint="c" * 64)
            selected = MANUAL.select_replace_guard_baseline(project, DEVICE, newer)
            self.assertEqual("device-ztp-receipt", selected["source"])
            self.assertIs(newer, selected["applied"])

    def test_worker_preview_accepts_only_matching_verified_manual_prior(self):
        old_ztp = ReplaceConfigGuardTests.config()
        prior_sync = old_ztp.replace("rule: accept", "rule: drop")
        desired = prior_sync.replace("      hostname: leaf01\n", "      hostname: leaf01-new\n")
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            release = project / "release"
            release.mkdir()
            marker = release / ".published-complete"
            marker.write_text("ok\n", encoding="utf-8")
            expected = release / "leaf01.yaml"
            expected.write_text(desired, encoding="utf-8")
            applied_output = protocol(old_ztp)
            applied_reader = mock.Mock(
                args=SimpleNamespace(command_timeout=20),
                run=mock.Mock(return_value=completed(applied_output)),
            )
            applied = MANUAL.collect_applied_config(
                applied_reader, DEVICE, "192.0.2.10",
            )
            self.previous_sync(project, prior_sync, applied["fingerprint"])
            client = mock.Mock(args=SimpleNamespace(command_timeout=20))
            client.run.side_effect = [completed(prior_sync), completed(applied_output)]
            new_run = project / "99-output-ztp/manual-config-sync/20261001_120000_000001"
            devices_csv = project / "02-devices_config.csv"
            devices_csv.write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            previews = []

            def local_preflight(command, **_kwargs):
                self.assertEqual(str(ROOT / "ztp/manual-ztp.py"), command[1])
                self.assertIn("--preflight-only", command)
                evidence = MANUAL.preflight_one(
                    client, project, DEVICE, new_run / DEVICE["hostname"],
                    replace_config=True,
                )
                previews.append(evidence)
                new_run.chmod(0o700)
                evidence.update(operation_id="new-operation", trigger_id="new-trigger")
                MANUAL.atomic_json(new_run / DEVICE["hostname"] / "preflight.json", evidence)
                MANUAL.atomic_json(new_run / "summary.json", {
                    "state": "preview_ready", "operation": "replace-config",
                    "effective_operation": "replace-config",
                    "operation_id": "new-operation", "trigger_source": "manual_config_sync_web",
                    "generated_at": "2026-10-01T12:00:00+08:00",
                    "targets": [{"hostname": DEVICE["hostname"],
                                 "trigger_id": "new-trigger",
                                 "effective_operation": "replace-config"}],
                    "preflight": [evidence], "results": [],
                })
                return completed("preview prepared\n")

            with mock.patch.object(
                MANUAL, "validate_parent_release_binding",
                return_value={"binding_sha256": "b" * 64},
            ), mock.patch.object(
                MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(
                MANUAL, "published_yaml_paths",
                return_value=(marker, expected, release / "mac.yaml"),
            ), mock.patch.object(
                WORKER, "DEVICES_CSV", devices_csv,
            ), mock.patch.object(
                WORKER.subprocess, "run", side_effect=local_preflight,
            ), mock.patch.object(
                WORKER, "write_device_status",
            ) as write_status, mock.patch.object(
                MANUAL, "trigger_one", side_effect=AssertionError("replace"),
            ) as trigger_one:
                WORKER.execute_preview(
                    DEVICE["hostname"], "eth", 20, "replace-config",
                    "new-operation", "new-trigger",
                )
            self.assertEqual(1, len(previews))
            preview = previews[0]
            self.assertTrue(preview["replace_guard"]["allowed"], preview)
            self.assertEqual("manual-sync-readback", preview["replace_guard_baseline_source"])
            self.assertEqual("preview_ready", write_status.call_args_list[-1].args[1])
            self.assertTrue(write_status.call_args_list[-1].kwargs["replace_guard"]["allowed"])
            trigger_one.assert_not_called()
            self.assertEqual(2, client.run.call_count)

    def test_confirm_rejects_changed_manual_evidence_before_remote_replace(self):
        old_ztp = ReplaceConfigGuardTests.config()
        prior_sync = old_ztp.replace("rule: accept", "rule: drop")
        desired = prior_sync.replace("hostname: leaf01", "hostname: leaf01-new")
        applied_output = protocol(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            release = project / "release"
            release.mkdir()
            marker = release / ".published-complete"
            marker.write_text("ok\n", encoding="utf-8")
            expected = release / "leaf01.yaml"
            expected.write_text(desired, encoding="utf-8")
            applied_reader = mock.Mock(
                args=SimpleNamespace(command_timeout=20),
                run=mock.Mock(return_value=completed(applied_output)),
            )
            applied = MANUAL.collect_applied_config(
                applied_reader, DEVICE, "192.0.2.10",
            )
            old_evidence = self.previous_sync(
                project, prior_sync, applied["fingerprint"],
            )
            run_dir = project / "99-output-ztp/manual-config-sync/20261001_120000_000001"
            preview_client = mock.Mock(args=SimpleNamespace(command_timeout=20))
            preview_client.run.side_effect = [completed(prior_sync), completed(applied_output)]
            with mock.patch.object(
                MANUAL, "validate_parent_release_binding",
                return_value={"binding_sha256": "b" * 64},
            ), mock.patch.object(
                MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(
                MANUAL, "published_yaml_paths",
                return_value=(marker, expected, release / "mac.yaml"),
            ), mock.patch.object(
                MANUAL, "published_mac_paths", return_value=[],
            ):
                prepared = MANUAL.preflight_one(
                    preview_client, project, DEVICE, run_dir / DEVICE["hostname"],
                    replace_config=True,
                )
            self.assertTrue(prepared["replace_guard"]["allowed"])
            result_path = old_evidence / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["config_sync_verification"]["actual_runtime_sha256"] = "f" * 64
            result_path.write_text(json.dumps(result), encoding="utf-8")
            trigger_client = mock.Mock(args=SimpleNamespace(command_timeout=20))
            trigger_client.run.side_effect = [completed(prior_sync), completed(applied_output)]
            with mock.patch.object(
                MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(
                MANUAL, "verify_prepared_release_binding",
            ):
                outcome = MANUAL.trigger_one(
                    trigger_client, DEVICE, "", run_dir,
                    operation="replace-config", prepared=prepared,
                    operation_id="new-operation", trigger_id="new-trigger",
                )
            self.assertEqual("failed", outcome["state"], outcome)
            self.assertEqual("not-submitted", outcome["config_sync_outcome"])
            self.assertEqual(2, trigger_client.run.call_count)
            self.assertFalse(any(
                "nv config replace" in call.args[2]
                for call in trigger_client.run.call_args_list
            ))

    def test_second_verified_sync_can_confirm_and_submit_once(self):
        old_ztp = ReplaceConfigGuardTests.config()
        prior_sync = old_ztp.replace("rule: accept", "rule: drop")
        desired = prior_sync.replace("hostname: leaf01", "hostname: leaf01-new")
        applied = ReplaceConfigGuardTests.applied(old_ztp)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            release = project / "release"
            release.mkdir()
            marker = release / ".published-complete"
            marker.write_text("ok\n", encoding="utf-8")
            expected = release / "leaf01.yaml"
            expected.write_text(desired, encoding="utf-8")
            self.previous_sync(project, prior_sync, applied["fingerprint"])
            run_dir = project / "99-output-ztp/manual-config-sync/20261001_120000_000001"
            preview_client = mock.Mock(args=SimpleNamespace(command_timeout=20))
            preview_client.run.return_value = completed(prior_sync)
            with mock.patch.object(
                MANUAL, "validate_parent_release_binding",
                return_value={"binding_sha256": "b" * 64},
            ), mock.patch.object(
                MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(
                MANUAL, "published_yaml_paths",
                return_value=(marker, expected, release / "mac.yaml"),
            ), mock.patch.object(
                MANUAL, "published_mac_paths", return_value=[],
            ), mock.patch.object(
                MANUAL, "collect_applied_config", return_value=applied,
            ):
                prepared = MANUAL.preflight_one(
                    preview_client, project, DEVICE, run_dir / DEVICE["hostname"],
                    replace_config=True,
                )
            self.assertTrue(prepared["replace_guard"]["allowed"])
            trigger_client = mock.Mock(args=SimpleNamespace(command_timeout=20))
            anchor_path = MANUAL.confirmed_sync_anchor_path(project, DEVICE)

            def run_with_anchor_before_replace(*_args, **_kwargs):
                if trigger_client.run.call_count == 1:
                    return completed(prior_sync)
                self.assertTrue(anchor_path.is_file(), "order anchor must precede remote replace")
                published = json.loads(anchor_path.read_text(encoding="utf-8"))
                self.assertEqual(run_dir.name, published["stamp"])
                return completed("applied\n")

            trigger_client.run.side_effect = run_with_anchor_before_replace
            devices_csv = project / "02-devices_config.csv"
            devices_csv.write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            with mock.patch.object(WORKER, "DEVICES_CSV", devices_csv):
                prior_results = WORKER._result_snapshot("replace-config")
            self.assertEqual(1, len(prior_results))
            raw_sha = hashlib.sha256(desired.encode("utf-8")).hexdigest()
            runtime_sha = MANUAL.runtime_comparable_nvue_config(
                desired, label="second expected sync",
            )[2]
            verified = {
                "schema": 1, "hostname": DEVICE["hostname"],
                "eth0_mac": DEVICE["mac_plain"],
                "expected_raw_sha256": raw_sha,
                "expected_runtime_sha256": runtime_sha,
                "actual_runtime_sha256": runtime_sha,
                "receipt_refreshed": False,
            }
            with mock.patch.object(
                MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(
                MANUAL, "verify_prepared_release_binding",
            ), mock.patch.object(
                MANUAL, "collect_applied_config", return_value=applied,
            ), mock.patch.object(
                MANUAL, "verify_config_sync_readback", return_value=verified,
            ) as readback:
                outcome = MANUAL.trigger_one(
                    trigger_client, DEVICE, "", run_dir,
                    trigger_source="manual_config_sync_web", trigger_id="new-trigger",
                    operation="replace-config", operation_id="new-operation",
                    prepared=prepared,
                )
            self.assertEqual("triggered", outcome["state"], outcome)
            self.assertEqual("runtime-verified", outcome["config_sync_outcome"])
            with mock.patch.object(WORKER, "DEVICES_CSV", devices_csv):
                accepted = WORKER.accepted_result(
                    DEVICE["hostname"], "new-operation", "new-trigger",
                    "replace-config", "manual_config_sync_web", prior_results,
                )
            self.assertEqual(outcome, accepted)
            self.assertTrue(WORKER.config_sync_verified(
                accepted, DEVICE["hostname"], "new-operation", "new-trigger",
            ))
            submit = [call for call in trigger_client.run.call_args_list
                      if "nv config replace" in call.args[2]]
            self.assertEqual(1, len(submit))
            self.assertEqual(desired, submit[0].kwargs["stdin"])
            readback.assert_called_once_with(trigger_client, DEVICE, "192.0.2.10", desired)


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
                hostname="leaf01", acl_rule="drop",
            )
            expected.write_text(expected_text, encoding="utf-8")
            applied_output = protocol(prior)
            applied_reader = mock.Mock(
                args=SimpleNamespace(command_timeout=20),
                run=mock.Mock(return_value=completed(applied_output)),
            )
            applied_record = MANUAL.collect_applied_config(
                applied_reader, DEVICE, "192.0.2.10",
            )
            applied_fingerprint = applied_record["fingerprint"]
            client = mock.Mock()
            client.args = SimpleNamespace(command_timeout=20)
            client.run.side_effect = [
                completed(prior), completed(applied_output), completed("saved\n"),
                completed("leaf01\n02:00:00:00:00:01\n"), completed(expected_text),
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
                "replace_guard_baseline_source": "device-ztp-receipt",
                "replace_guard_baseline_fingerprint": applied_fingerprint,
                "published_mac_links": [],
            }
            sync_run = root / "99-output-ztp/manual-config-sync/20261001_120000_000001"
            with mock.patch.object(
                MANUAL, "connect_and_verify",
                return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(
                MANUAL, "verify_prepared_release_binding",
            ):
                result = MANUAL.trigger_one(
                    client, DEVICE, "", sync_run,
                    trigger_source="manual_config_sync_web",
                    operation="replace-config", prepared=prepared, operation_id="op", trigger_id="tr",
                )
            self.assertEqual("triggered", result["state"], result)
            self.assertEqual("runtime-verified", result["config_sync_outcome"])
            self.assertFalse(result["config_sync_verification"]["receipt_refreshed"])
            for field, value in (
                ("schema", True), ("hostname", "other"), ("eth0_mac", "invalid"),
                ("trigger_id", "old"), ("operation_id", "old"),
                ("actual_runtime_sha256", "f" * 64), ("expected_raw_sha256", "invalid"),
                ("receipt_refreshed", True),
            ):
                with self.subTest(evidence_field=field):
                    changed = dict(result, config_sync_verification=dict(result["config_sync_verification"]))
                    changed["config_sync_verification"][field] = value
                    self.assertFalse(WORKER.config_sync_verified(changed, "leaf01", "op", "tr"))
            remote_call = client.run.call_args_list[2]
            remote = remote_call.args[2]
            self.assertIn("nv config replace", remote)
            self.assertIn("nv config apply -y", remote)
            self.assertIn("nv config save", remote)
            self.assertNotIn("nv config patch", remote)
            self.assertEqual(expected_text, remote_call.kwargs["stdin"])
            failures = (
                ("identity", [completed("saved"), completed("wrong\n02:00:00:00:00:01\n")], "applied-but-unverified"),
                ("mismatch", [completed("saved"), completed("leaf01\n02:00:00:00:00:01\n"), completed(prior)], "applied-but-unverified"),
                ("parse", [completed("saved"), completed("leaf01\n02:00:00:00:00:01\n"), completed("[invalid")], "applied-but-unverified"),
                ("read-timeout", [completed("saved"), completed("leaf01\n02:00:00:00:00:01\n"), MANUAL.subprocess.TimeoutExpired("show", 1)], "applied-but-unverified"),
                ("command-timeout", [MANUAL.subprocess.TimeoutExpired("replace", 1)], "outcome-unknown"),
                ("command-error", [completed("", returncode=1)], "outcome-unknown"),
            )
            for index, (name, replies, outcome) in enumerate(failures, start=2):
                failure_run = (root / "failures" / name
                               / "99-output-ztp/manual-config-sync"
                               / f"20261001_120000_{index:06d}")
                with self.subTest(name=name), mock.patch.object(
                    MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
                ), mock.patch.object(MANUAL, "verify_prepared_release_binding"):
                    failed_client = mock.Mock(args=SimpleNamespace(command_timeout=1))
                    failed_client.run.side_effect = [completed(prior), completed(applied_output), *replies]
                    failed = MANUAL.trigger_one(
                        failed_client, DEVICE, "", failure_run,
                        operation="replace-config", prepared=prepared, operation_id="op", trigger_id=name,
                    )
                    self.assertEqual("failed", failed["state"])
                    self.assertEqual(outcome, failed["config_sync_outcome"])
                    self.assertNotIn("config_sync_verification", failed)
                    self.assertIn("不要自动重试", failed["reason"])
                    self.assertEqual(1, sum("nv config replace" in c.args[2]
                                            for c in failed_client.run.call_args_list))
                    self.assertEqual(failed, json.loads((failure_run / "leaf01/result.json").read_text()))
                    self.assertTrue(MANUAL.confirmed_sync_anchor_path(
                        root / "failures" / name, DEVICE,
                    ).is_file())
                    with self.assertRaises(MANUAL.ManualZtpError):
                        MANUAL.select_replace_guard_baseline(
                            root / "failures" / name, DEVICE, applied_record,
                        )
            # Real producer result -> worker's durable Web reader and CLI reader.
            inventory = root / "02-devices_config.csv"
            inventory.write_text("hostname\nleaf01\n", encoding="utf-8")
            # The helper must publish this result during the worker's command,
            # never leave a matching result on disk before the command starts.
            produced_result = sync_run / "leaf01/result.json"
            produced_result.unlink()

            def publish_current_result(*_args, **_kwargs):
                MANUAL.atomic_json(produced_result, result)
                return completed()

            writes = []
            with mock.patch.object(WORKER, "DEVICES_CSV", inventory), \
                 mock.patch.object(WORKER, "write_device_status", side_effect=lambda host, state, **kw: writes.append(state)), \
                 mock.patch.object(WORKER, "latest_device_state", return_value={}), \
                 mock.patch.object(WORKER, "command_for", return_value=["local-test"]), \
                 mock.patch.object(WORKER.subprocess, "run", side_effect=publish_current_result):
                WORKER.execute("leaf01", "prod", 1, 1, 1, operation="replace-config",
                               operation_id="op", trigger_id="tr", requested_operation="replace-config",
                               preview_fingerprint={"current_sha256": "a" * 64})
                self.assertEqual(["config_sync_running", "config_sync_success"], writes)
                summary = sync_run / "summary.json"
                summary.write_text(json.dumps({
                    "trigger_source": "manual_config_sync_cli", "operation": "replace-config",
                    "targets": [DEVICE], "results": [result],
                }), encoding="utf-8")
                projected = WORKER.latest_cli_operations()["leaf01"]
                self.assertTrue(WORKER.config_sync_verified(projected, "leaf01", "op", "tr"))
                result.pop("config_sync_verification")
                summary.write_text(json.dumps({
                    "trigger_source": "manual_config_sync_cli", "operation": "replace-config",
                    "targets": [DEVICE], "results": [result],
                }), encoding="utf-8")
                self.assertFalse(WORKER.config_sync_verified(WORKER.latest_cli_operations()["leaf01"], "leaf01", "op", "tr"))

    def test_post_save_readback_rejects_mismatch_identity_and_timeout_without_retry(self):
        expected = ReplaceConfigGuardTests.config()
        cases = (
            ([completed("other\n02:00:00:00:00:01\n")], 1),
            ([completed("leaf01\n02:00:00:00:00:02\n")], 1),
            ([completed("leaf01\n02:00:00:00:00:01\n"), completed(expected.replace("leaf01", "drifted"))], 2),
            ([completed("leaf01\n02:00:00:00:00:01\n"), completed("", returncode=1)], 2),
            ([MANUAL.subprocess.TimeoutExpired("identity", 1)], 1),
            ([completed("leaf01\n02:00:00:00:00:01\n"), MANUAL.subprocess.TimeoutExpired("show", 1)], 2),
        )
        for replies, calls in cases:
            with self.subTest(calls=calls, replies=str(replies)):
                client = mock.Mock(args=SimpleNamespace(command_timeout=1))
                client.run.side_effect = replies
                with self.assertRaises((MANUAL.ManualZtpError, MANUAL.subprocess.TimeoutExpired)):
                    MANUAL.verify_config_sync_readback(client, DEVICE, "192.0.2.10", expected)
                self.assertEqual(calls, client.run.call_count)
                self.assertFalse(any("config replace" in c.args[2] for c in client.run.call_args_list))

    def test_post_save_readback_accepts_confirmed_hostname_change_with_same_mac(self):
        expected = ReplaceConfigGuardTests.config(hostname="leaf01-renamed")
        client = mock.Mock(args=SimpleNamespace(command_timeout=1))
        client.run.side_effect = [completed("leaf01-renamed\n02:00:00:00:00:01\n"), completed(expected)]
        evidence = MANUAL.verify_config_sync_readback(client, DEVICE, "192.0.2.10", expected)
        self.assertEqual("leaf01", evidence["hostname"])
        self.assertEqual("020000000001", evidence["eth0_mac"])
        self.assertEqual(2, client.run.call_count)
        self.assertEqual(["192.0.2.10", "192.0.2.10"], [c.args[1] for c in client.run.call_args_list])
        self.assertIn("/sys/class/net/eth0/address", client.run.call_args_list[0].args[2])
        self.assertEqual("nv config show", client.run.call_args_list[1].args[2])

    def test_unverified_cli_two_polls_are_idempotent_but_new_trigger_is_not_hidden(self):
        for triggers, expected_writes in ((["tr", "tr"], 1), (["tr", "new"], 2)):
            with self.subTest(triggers=triggers), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                status = {"devices": {}}
                writes = []
                def write(host, state, **values):
                    writes.append((host, state, values))
                    status["devices"][host] = dict(values, state=state)
                operation = {
                    "hostname": "leaf01", "type": "eth", "state": "triggered",
                    "operation": "replace-config", "operation_id": "op",
                    "trigger_source": "manual_config_sync_cli",
                    "started_at": "2026-10-01T00:00:00+00:00", "updated_at": "2026-10-01T00:00:01+00:00",
                }
                with mock.patch.object(WORKER, "STATUS_DIR", root), \
                     mock.patch.object(WORKER, "PID_FILE", root / "absent.pid"), \
                     mock.patch.object(sys, "argv", ["worker", "--scope", "prod"]), \
                     mock.patch.object(WORKER, "initialize_status", return_value={"devices": {}}), \
                     mock.patch.object(WORKER, "read_status", return_value=status), \
                     mock.patch.object(WORKER, "write_device_status", side_effect=write), \
                     mock.patch.object(WORKER, "reconcile_failed_operations"), \
                     mock.patch.object(WORKER, "latest_cli_operations", side_effect=[{"leaf01": dict(operation, trigger_id=t)} for t in triggers]), \
                     mock.patch.object(WORKER, "pop_requests", return_value=[]), \
                     mock.patch.object(WORKER.time, "sleep", side_effect=[None, KeyboardInterrupt]):
                    self.assertEqual(130, WORKER.main())
                self.assertEqual(expected_writes, len(writes))
                self.assertTrue(all(state == "failed" for _, state, _ in writes))

    def test_config_sync_outer_timeout_warns_unknown_and_does_not_retry(self):
        writes = []
        with tempfile.TemporaryDirectory() as directory:
            devices_csv = Path(directory) / "02-devices_config.csv"
            devices_csv.write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            with mock.patch.object(WORKER, "DEVICES_CSV", devices_csv), \
                 mock.patch.object(WORKER, "write_device_status", side_effect=lambda host, state, **kw: writes.append((state, kw))), \
                 mock.patch.object(WORKER, "latest_device_state", return_value={}), \
                 mock.patch.object(WORKER, "command_for", return_value=["local-test"]), \
                 mock.patch.object(WORKER.subprocess, "run", side_effect=MANUAL.subprocess.TimeoutExpired("sync", 1)) as run, \
                 mock.patch.object(WORKER, "accepted_result") as accepted:
                WORKER.execute("leaf01", "prod", 1, 1, 1, operation="replace-config",
                               operation_id="op", trigger_id="tr", requested_operation="replace-config",
                               preview_fingerprint={"current_sha256": "a" * 64})
        self.assertEqual(["config_sync_running", "failed"], [state for state, _ in writes])
        self.assertIn("结果未知", writes[-1][1]["reason"])
        self.assertIn("不要自动重试", writes[-1][1]["reason"])
        self.assertEqual(1, run.call_count)
        run.assert_called_once()
        accepted.assert_not_called()

    def test_worker_rejects_unverified_triggered_for_web_and_cli_projection(self):
        result = {"hostname": "leaf01", "state": "triggered", "operation": "replace-config",
                  "operation_id": "op", "trigger_id": "tr"}
        self.assertFalse(WORKER.config_sync_verified(result, "leaf01", "op", "tr"))
        writes = []
        with tempfile.TemporaryDirectory() as directory:
            devices_csv = Path(directory) / "02-devices_config.csv"
            devices_csv.write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            with mock.patch.object(WORKER, "DEVICES_CSV", devices_csv), \
                 mock.patch.object(WORKER, "write_device_status", side_effect=lambda host, state, **kw: writes.append(state)), \
                 mock.patch.object(WORKER, "latest_device_state", return_value={}), \
                 mock.patch.object(WORKER, "command_for", return_value=["local-test"]), \
                 mock.patch.object(WORKER.subprocess, "run", return_value=completed()) as run, \
                 mock.patch.object(WORKER, "accepted_result", return_value=result) as accepted:
                WORKER.execute("leaf01", "prod", 1, 1, 1, operation="replace-config",
                               operation_id="op", trigger_id="tr", requested_operation="replace-config",
                               preview_fingerprint={"current_sha256": "a" * 64})
        self.assertEqual(["config_sync_running", "failed"], writes)
        run.assert_called_once()
        accepted.assert_called_once_with(
            "leaf01", "op", "tr", "replace-config", "manual_config_sync_web", set(),
        )

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
    def test_trigger_one_preserves_aware_clock_offset_under_utc_host(self):
        """One script must not rewrite an aware command timestamp to host UTC."""
        marker = "2026-09-24T08:45:00+08:00"
        client = mock.Mock()
        client.args.command_timeout = 10
        client.args.non_interactive = True
        client.sudo_command.return_value = ("sudo -n helper", "")
        client.run.side_effect = [completed("config\n"), completed("done\n")]
        with tempfile.TemporaryDirectory() as directory, host_timezone_utc():
            with mock.patch.object(
                MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ), mock.patch.object(MANUAL, "datetime") as clock:
                clock.now.return_value = datetime.fromisoformat(marker)
                result = MANUAL.trigger_one(
                    client, DEVICE, "http://192.0.2.2/ztp/ztp-bootstrap_oob.sh",
                    Path(directory) / "manual-trigger" / "same", "manual_cli", "same",
                )
        self.assertEqual("triggered", result["state"], result)
        self.assertEqual(marker, result["started_at"])
        self.assertEqual(marker, result["command_started_at"])
        self.assertEqual(marker, result["finished_at"])

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
            with host_timezone_utc(), mock.patch.object(
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
