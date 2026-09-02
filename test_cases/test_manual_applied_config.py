"""Runtime NVUE normalization and manual ZTP preview/confirm comparisons."""

import hashlib
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "manual_applied_config_under_test", ROOT / "ztp/manual-ztp.py",
)
MANUAL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MANUAL)


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


class ConfirmAppliedFingerprintTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
