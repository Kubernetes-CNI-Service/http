"""Independent hostname-glob expectations; real CLI/input/observer boundaries.

Only synthetic temporary inputs and SSH observations are used. The expected
device lists below are fixed independently of fnmatch and the selector.
"""

# NEW canonical test-header binding; original named bodies below are unchanged.
import unittest as _ibsw225_unittest
from test_cases.ibsw225_fixture_support.runtime_source_support import support as _ibsw225_support
_ibsw225_runtime = _ibsw225_support(_ibsw225_unittest.TestCase())
from test_cases.ibsw225_fixture_support.fixed_fixture_registry import install_fixed_fixtures as _ibsw225_install_fixed_fixtures
_ibsw225_fixed_fixture_modules = _ibsw225_install_fixed_fixtures()

import contextlib
import csv
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import test_upgrade_cli as fixtures
import test_standalone_links as linked_fixtures
import ibsw_upgrade_contract as contract

app, driver, observer = fixtures.app, fixtures.driver, fixtures.observer
NAMES = (
    "ew-spine000.example", "ew-spine001.example", "ew-spine009.example",
    "ew-spine010.example", "ew-spine019.example", "ew-spine099.example",
    "ew-spine100.example", "EW-SPINE002.EXAMPLE",
    "ib-poda-leaf01.example", "ib-podb-leaf01.example",
    "ib-podc-leaf01.example", "ib-podd-leaf01.example", "ib-pode-leaf01.example",
)


def inventory_text():
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(fixtures.HEADER)
    for number, name in enumerate(NAMES, 1):
        writer.writerow([name, "ib", "NA", f"192.0.2.{number}", "24", "192.0.2.254",
                         f"02:00:00:00:00:{number:02x}"] + [""] * 12)
    # A matching invalid IB must retain its local skip, not disappear.
    writer.writerow(["ew-spine004.example", "ib", "NA", "192.0.2.40", "24", "192.0.2.254", ""] + [""] * 12)
    # These match some patterns but must never become IB candidates.
    for number, kind in ((3, "eth"), (7, "eth_jump")):
        writer.writerow([f"ew-spine00{number}.example", kind, "NA", f"192.0.2.{100+number}",
                         "24", "192.0.2.254", f"02:00:00:00:00:{100+number:02x}"] + [""] * 12)
    return output.getvalue()


class DeviceGlobDirectTests(unittest.TestCase):
    def selected(self, pattern):
        snapshot = contract.snapshot_inventory(inventory_text(), fixtures.GLOBAL)
        return contract.select_inventory_devices(snapshot, pattern)

    def test_decimal_range_matches_one_position(self):
        selected = self.selected("ew-spine00[0-9].example")
        self.assertEqual([node.hostname for node in selected.devices], [
            "ew-spine000.example", "ew-spine001.example", "ew-spine009.example", "EW-SPINE002.EXAMPLE"])
        self.assertEqual([node.hostname for node in selected.blocked_devices], ["ew-spine004.example"])

    def test_adjacent_character_ranges_select_a_fixed_width_number(self):
        selected = self.selected("ew-spine0[0-1][0-9].example")
        self.assertEqual([node.hostname for node in selected.devices], [
            "ew-spine000.example", "ew-spine001.example", "ew-spine009.example",
            "ew-spine010.example", "ew-spine019.example", "EW-SPINE002.EXAMPLE"])

    def test_alphabetic_range_includes_both_ends(self):
        selected = self.selected("ib-pod[a-d]-leaf01.example")
        self.assertEqual([node.hostname for node in selected.devices], [
            "ib-poda-leaf01.example", "ib-podb-leaf01.example",
            "ib-podc-leaf01.example", "ib-podd-leaf01.example"])

    def test_explicit_character_set_is_not_a_substring_or_regex(self):
        selected = self.selected("ib-pod[ace]-leaf01.example")
        self.assertEqual([node.hostname for node in selected.devices], [
            "ib-poda-leaf01.example", "ib-podc-leaf01.example", "ib-pode-leaf01.example"])

    def test_exclamation_negates_one_character(self):
        selected = self.selected("ib-pod[!a-d]-leaf01.example")
        self.assertEqual([node.hostname for node in selected.devices], ["ib-pode-leaf01.example"])

    def test_uppercase_range_and_hostname_remain_case_insensitive(self):
        selected = self.selected("IB-POD[A-D]-LEAF01.EXAMPLE")
        self.assertEqual([node.hostname for node in selected.devices], [
            "ib-poda-leaf01.example", "ib-podb-leaf01.example",
            "ib-podc-leaf01.example", "ib-podd-leaf01.example"])

    def test_ranges_compose_with_question_mark_and_asterisk(self):
        selected = self.selected("IB-POD?-LEAF[0-9][0-9].*")
        self.assertEqual([node.hostname for node in selected.devices], [
            "ib-poda-leaf01.example", "ib-podb-leaf01.example", "ib-podc-leaf01.example",
            "ib-podd-leaf01.example", "ib-pode-leaf01.example"])

    def test_brackets_do_not_match_multiple_characters(self):
        with self.assertRaisesRegex(ValueError, "matched no IB"):
            self.selected("ew-spine[0-9].example")

    def test_non_ib_only_or_empty_range_selection_refuses_instead_of_selecting_all(self):
        for pattern in ("ew-spine00[7-8].example", "ib-pod[f-z]-leaf01.example"):
            with self.subTest(pattern=pattern), self.assertRaisesRegex(ValueError, "matched no IB"):
                self.selected(pattern)

    def test_invalid_fields_of_selected_ib_are_still_reported_locally(self):
        selected = self.selected("EW-SPINE00[1-4].EXAMPLE")
        self.assertEqual([node.hostname for node in selected.devices], ["ew-spine001.example", "EW-SPINE002.EXAMPLE"])
        self.assertEqual([(node.hostname, node.reasons) for node in selected.blocked_devices], [
            ("ew-spine004.example", ("ETH0_MAC_MISSING",))])

    def test_shell_regex_and_brace_expressions_are_not_new_execution_syntax(self):
        for pattern in ("$(hostname)", "ew-spine{001,002}*", "ew-(spine|leaf)*", "ew-spine*;id"):
            with self.subTest(pattern=pattern), self.assertRaisesRegex(ValueError, "bounded hostname glob"):
                self.selected(pattern)

    def test_cli_preserves_range_expression_for_both_option_forms(self):
        for arguments in (("--devices", "IB-POD[A-D]-LEAF[0-9][0-9].*"),
                          ("--devices=IB-POD[A-D]-LEAF[0-9][0-9].*",)):
            with self.subTest(arguments=arguments):
                parsed = app._parse_cli(arguments)
                self.assertTrue(parsed.inspect_only)
                self.assertEqual(parsed.prepare_args, ("--devices", "IB-POD[A-D]-LEAF[0-9][0-9].*"))

    def test_help_explains_ranges_sets_and_required_shell_quoting(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
            app._parse_cli(("--help",))
        self.assertEqual(result.exception.code, 0)
        help_text = " ".join(output.getvalue().split())
        for fragment in ("[0-9]", "[a-d]", "[abc]", "[!0-9]", "one character", "Quote"):
            self.assertIn(fragment, help_text)


class DeviceGlobWorkflowTests(unittest.TestCase):
    def test_real_cli_diagnostics_with_linked_inputs_retains_selected_skips_without_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = linked_fixtures.StandaloneLinkTests().fixture(Path(directory).resolve())
            (project / "02-devices_config.csv").write_text(inventory_text())
            out, err = io.StringIO(), io.StringIO()
            with patch.object(app, "__file__", str(entry / "upgrade.py")), \
                 patch.object(app, "_fixed_driver", return_value=driver), \
                 patch.object(app.os, "getcwd", return_value=str(entry)), \
                 patch.object(app, "_read_password", side_effect=AssertionError("No prompt in diagnostics")), \
                 patch.object(app, "_check_runtime", side_effect=AssertionError("No auth runtime in diagnostics")), \
                 patch.object(socket, "socket", side_effect=AssertionError("No real network")), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = app.main(["--devices", "EW-SPINE00[1-4].EXAMPLE", "--os-only", "--diagnose-inputs"])
            self.assertEqual(code, 3, err.getvalue())
            report = json.loads(out.getvalue())
            self.assertEqual(report["state"], "INPUT_PREFLIGHT_INCOMPLETE")
            self.assertEqual((report["selected_ib_count"], report["eligible_ib_count"], report["skipped_ib_count"]), (3, 2, 1))
            self.assertEqual(report["skipped_devices"][0]["hostname"], "ew-spine004.example")
            self.assertEqual(report["skipped_devices"][0]["reasons"], ["ETH0_MAC_MISSING"])
            self.assertFalse(report["ssh_attempted"])
            self.assertFalse(report["local_artifacts_created"])
            self.assertFalse((workspace / "ztp/.setup_manifest").exists())
            self.assertEqual(list((entry / "xdr-upgrade-logs").iterdir()), [])

    def test_real_cli_inspection_queries_only_range_selected_devices_and_preserves_selector(self):
        attempted = []
        @contextlib.contextmanager
        def session(leaf, **kwargs):
            attempted.append(leaf.node.hostname)
            identity = (leaf.node.hostname + "\n" + leaf.node.mac + "\n").encode()
            yield object(), 99999999999, (identity, b"", 0), "password", "synthetic-pin"
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = fixtures.WorkflowTests().fixture(Path(directory).resolve())
            (project / "02-devices_config.csv").write_text(inventory_text())
            trust = known.read_text()
            known.write_text(trust.replace("192.0.2.1 ", "192.0.2.2 ") + trust.replace("192.0.2.1 ", "192.0.2.8 "))
            pattern = "EW-SPINE00[1-2].EXAMPLE"
            with patch.object(observer, "_signed_session", session), \
                 patch.object(observer, "_read_channel", return_value=(fixtures.OS_TABLE, b"", 0, True)):
                code, out, err, prompts = fixtures.WorkflowTests().invoke(project, home, "--devices", pattern, "--inspect-only")
            self.assertEqual(code, 0, err)
            self.assertEqual(attempted, ["ew-spine001.example", "EW-SPINE002.EXAMPLE"])
            report = json.loads(out)
            self.assertEqual((report["selected_ib_count"], report["ready_ib_count"], report["skipped_ib_count"]), (2, 2, 0))
            self.assertEqual(report["execution_state"], "NOT_EXECUTED")
            plan_paths = list(project.glob("99-output-ib_nvl/bringup/xdr-upgrade-logs/*/plan.json"))
            self.assertEqual(len(plan_paths), 1)
            plan = json.loads(plan_paths[0].read_text())
            self.assertEqual([node["hostname"] for node in plan["devices"]], ["ew-spine001.example", "EW-SPINE002.EXAMPLE"])
            self.assertIn(pattern, plan_paths[0].read_text())
            self.assertEqual((plan_paths[0].parent / "input-inventory.csv").read_bytes(), inventory_text().encode())
            self.assertFalse(list(plan_paths[0].parent.glob("*/os-*/request.json")))


if __name__ == "__main__":
    unittest.main()
