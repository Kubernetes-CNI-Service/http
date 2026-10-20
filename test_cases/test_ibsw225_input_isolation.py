"""Per-device input isolation: fixed expectations, temporary data, no device IO."""

# Canonical test-header binding; original behavior assertions are retained.
# Readonly IO fixture keeps provider and consumer test doubles identity-coherent.
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
import ibsw_upgrade_contract as contract
from ibsw_upgrade_schedule import ScheduleResult

app, driver, observer = fixtures.app, fixtures.driver, fixtures.observer
HEADER, GLOBAL, OS_TABLE = fixtures.HEADER, fixtures.GLOBAL, fixtures.OS_TABLE


def ib_row(name, ip, mac):
    return [name, "ib", "NA", ip, "24", "192.0.2.254", mac] + [""] * 12


def csv_text(rows):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(HEADER)
    writer.writerows(rows)
    return buffer.getvalue()


GOOD1 = ib_row("ew-spine01.example", "192.0.2.1", "02:00:00:00:00:01")
GOOD2 = ib_row("ew-spine02.example", "192.0.2.2", "02:00:00:00:00:02")
BAD = ib_row("ew-spine061.example", "192.0.2.61", "")
EXPECTED_SKIP = {"hostname": "ew-spine061.example", "csv_row": 2,
                 "state": "SKIPPED_INPUT_INVALID", "reasons": ["ETH0_MAC_MISSING"]}


class InventoryIsolationTests(unittest.TestCase):
    def test_missing_mac_does_not_discard_the_later_healthy_devices(self):
        snapshot = contract.snapshot_inventory(csv_text([BAD, GOOD1, GOOD2]), GLOBAL)
        self.assertEqual([node.hostname for node in snapshot.devices], ["ew-spine01.example", "ew-spine02.example"])
        self.assertEqual(len(snapshot.blocked_devices), 1)
        issue = snapshot.blocked_devices[0]
        self.assertEqual((issue.hostname, issue.csv_row, issue.reasons),
                         ("ew-spine061.example", 2, ("ETH0_MAC_MISSING",)))

    def test_missing_and_invalid_mac_are_local_including_zero_and_multicast(self):
        for value, reason in (("", "ETH0_MAC_MISSING"), ("NA", "ETH0_MAC_MISSING"),
                              ("None", "ETH0_MAC_MISSING"), ("null", "ETH0_MAC_MISSING"),
                              ("021122334455", "ETH0_MAC_INVALID"), ("xx:11:22:33:44:55", "ETH0_MAC_INVALID"),
                              ("00:00:00:00:00:00", "ETH0_MAC_INVALID"), ("01:11:22:33:44:55", "ETH0_MAC_INVALID")):
            with self.subTest(value=value):
                snapshot = contract.snapshot_inventory(csv_text([
                    ib_row("bad", "192.0.2.61", value), GOOD1]), GLOBAL)
                self.assertEqual([node.hostname for node in snapshot.devices], ["ew-spine01.example"])
                self.assertEqual(snapshot.blocked_devices[0].reasons, (reason,))

    def test_missing_and_invalid_ip_are_local_and_do_not_accept_hostnames(self):
        for value, reason in (("", "ETH0_IP_MISSING"), ("N/A", "ETH0_IP_MISSING"),
                              ("NA", "ETH0_IP_MISSING"), ("999.0.0.1", "ETH0_IP_INVALID"),
                              ("switch.example", "ETH0_IP_INVALID"), ("127.0.0.1", "ETH0_IP_INVALID"),
                              ("0.0.0.0", "ETH0_IP_INVALID"), ("224.0.0.1", "ETH0_IP_INVALID"),
                              ("fe80::1", "ETH0_IP_INVALID")):
            with self.subTest(value=value):
                snapshot = contract.snapshot_inventory(csv_text([
                    ib_row("bad", value, "02:00:00:00:00:61"), GOOD1]), GLOBAL)
                self.assertEqual([node.hostname for node in snapshot.devices], ["ew-spine01.example"])
                self.assertEqual(snapshot.blocked_devices[0].reasons, (reason,))

    def test_both_invalid_fields_are_reported_without_raw_values(self):
        snapshot = contract.snapshot_inventory(csv_text([
            ib_row("bad", "PRIVATE_IP_VALUE", "PRIVATE_MAC_VALUE"), GOOD1]), GLOBAL)
        self.assertEqual(snapshot.blocked_devices[0].reasons, ("ETH0_IP_INVALID", "ETH0_MAC_INVALID"))
        self.assertNotIn("PRIVATE", repr(snapshot.blocked_devices))

    def test_selector_filters_valid_and_blocked_devices_case_insensitively(self):
        snapshot = contract.snapshot_inventory(csv_text([BAD, GOOD1, GOOD2]), GLOBAL)
        healthy = contract.select_inventory_devices(snapshot, "EW-SPINE01*")
        self.assertEqual(len(healthy.devices), 1)
        self.assertEqual(healthy.blocked_devices, ())
        blocked = contract.select_inventory_devices(snapshot, "EW-SPINE061*")
        self.assertEqual(blocked.devices, ())
        self.assertEqual(len(blocked.blocked_devices), 1)
        with self.assertRaisesRegex(ValueError, "matched no IB"):
            contract.select_inventory_devices(snapshot, "missing*")

    def test_all_invalid_is_an_explicit_empty_eligible_selection_not_a_missing_inventory(self):
        snapshot = contract.snapshot_inventory(csv_text([BAD]), GLOBAL)
        self.assertEqual(snapshot.devices, ())
        self.assertEqual(len(snapshot.blocked_devices), 1)
        with self.assertRaisesRegex(ValueError, "no IB targets"):
            contract.snapshot_inventory(csv_text([]), GLOBAL)

    def test_duplicate_names_ips_and_macs_still_fail_closed(self):
        for row in (ib_row(GOOD1[0], "192.0.2.2", GOOD2[6]),
                    ib_row(GOOD2[0], "192.0.2.1", GOOD2[6]),
                    ib_row(GOOD2[0], "192.0.2.2", GOOD1[6])):
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "duplicate IB"):
                contract.snapshot_inventory(csv_text([GOOD1, row]), GLOBAL)

    def test_fake_but_well_formed_mac_is_not_treated_as_authenticated_identity(self):
        snapshot = contract.snapshot_inventory(csv_text([GOOD1]), GLOBAL)
        from types import SimpleNamespace
        leaf = SimpleNamespace(node=snapshot.devices[0])
        actual = (GOOD1[0] + "\n02:00:00:00:99:99\n").encode()
        with self.assertRaises(observer._NativeObservationHold) as raised:
            observer._validate_identity(leaf, (actual, b"", 0, True))
        self.assertEqual(raised.exception.reason_code, "DEVICE_IDENTITY_MISMATCH")


class DeviceIsolationWorkflowTests(unittest.TestCase):
    def fixture(self, root, rows=None):
        project, home, known = fixtures.WorkflowTests().fixture(root)
        (project / "02-devices_config.csv").write_text(csv_text(rows if rows is not None else [BAD, GOOD1, GOOD2]))
        known.write_text(known.read_text() + known.read_text().replace("192.0.2.1 ", "192.0.2.2 "))
        return project, home, known

    def test_diagnostic_reports_partial_inventory_without_prompts_network_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            code, out, err = fixtures.InputDiagnosticsTests().invoke(project)
            report = json.loads(out)
            self.assertEqual(code, 3)
            self.assertEqual(report["state"], "INPUT_PREFLIGHT_INCOMPLETE")
            self.assertEqual(report["result"], "INCOMPLETE")
            self.assertEqual((report["selected_ib_count"], report["eligible_ib_count"], report["skipped_ib_count"]), (3, 2, 1))
            self.assertEqual(report["skipped_devices"], [EXPECTED_SKIP])
            self.assertFalse(report["ssh_attempted"])
            self.assertFalse((project / "99-output-ib_nvl").exists())

    def test_real_scripts_only_flow_prepares_healthy_nodes_and_retains_skip_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            code, out, err, prompts = fixtures.WorkflowTests().invoke(project, home, "--scripts-only", "--method", "http")
            self.assertEqual(code, 3, err)
            report = json.loads(out)
            self.assertEqual(report["result"], "INCOMPLETE")
            self.assertEqual(report["skipped_devices"], [EXPECTED_SKIP])
            self.assertEqual([node["hostname"] for node in report["targets"]], [GOOD1[0], GOOD2[0]])
            self.assertEqual(prompts, 0)
            self.assertIn("SKIPPED_INPUT_INVALID", err)
            run = next(project.glob("99-output-ib_nvl/bringup/xdr-upgrade-logs/*/plan.json")).parent
            plan = json.loads((run / "plan.json").read_text())
            self.assertEqual([node["hostname"] for node in plan["devices"]], [GOOD1[0], GOOD2[0]])
            self.assertEqual(plan["skipped_devices"], [{k: v for k, v in EXPECTED_SKIP.items() if k != "state"}])
            self.assertEqual((run / "input-inventory.csv").read_bytes(), (project / "02-devices_config.csv").read_bytes())
            self.assertFalse((run / BAD[0]).exists())
            self.assertEqual(len(list(run.glob("ew-spine*/os-*/step.sh"))), 4)

    def test_real_readonly_observation_never_authenticates_the_blocked_device(self):
        import ibsw_upgrade_executor as executor
        attempted = []
        @contextlib.contextmanager
        def session(leaf, **kwargs):
            attempted.append(leaf.node.hostname)
            identity = (leaf.node.hostname + "\n" + leaf.node.mac + "\n").encode()
            yield object(), 99999999999, (identity, b"", 0), "password", "synthetic-pin"
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            # The provider and explicit IO consumer share the same test double;
            # do not leave executor holding an original provider function while
            # replacing only observer before real entry identity admission.
            with patch.object(observer, "_signed_session", side_effect=session) as session_io, \
                 patch.object(executor, "_signed_session", session_io), \
                 patch.object(observer, "_read_channel", return_value=(OS_TABLE, b"", 0, True)) as read_io, \
                 patch.object(executor, "_read_channel", read_io):
                self.assertIs(observer._signed_session, executor._signed_session)
                self.assertIs(observer._read_channel, executor._read_channel)
                code, out, err, prompts = fixtures.WorkflowTests().invoke(project, home)
            self.assertEqual(code, 3, err)
            self.assertEqual(attempted, [GOOD1[0], GOOD2[0]])
            self.assertEqual(json.loads(out)["skipped_devices"], [EXPECTED_SKIP])
            self.assertEqual(prompts, 1)

    def test_upgrade_handoff_cannot_admit_blocked_node_or_claim_whole_batch_verified(self):
        handed_off = []
        def upgrade(scope, ready, parsed, password, loaded_driver, entry, cwd, run_directory):
            handed_off.extend(scope.devices)
            self.assertEqual(list(scope.devices), [GOOD1[0], GOOD2[0]])
            with self.assertRaisesRegex(ValueError, "node absent from original live CSV"):
                with scope.open_readonly_query_inputs(BAD[0], known_hosts_path=parsed.known_hosts,
                        identity_path=None, management_public_path=None, user="admin"):
                    self.fail("Blocked target cannot acquire a device input leaf")
            return {"state": "COMPLETE", "targets": [{"hostname": GOOD1[0], "state": "COMPLETE"},
                                                        {"hostname": GOOD2[0], "state": "COMPLETE"}], "components": []}
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            from test_access_recovery import install_pair
            install_pair(home)
            with patch.object(app, "_parallel_component_upgrade", side_effect=upgrade), \
                 patch.object(app, "_collect_readiness", side_effect=lambda scope, nodes, parsed, password: (nodes, [])):
                code, out, err, prompts = fixtures.WorkflowTests().invoke(project, home, "--upgrade", "--yes", "--exclusive-config-window")
            self.assertEqual(code, 3, err)
            report = json.loads(out)
            self.assertEqual(report["state"], "UPGRADE_INCOMPLETE")
            self.assertEqual(report["result"], "INCOMPLETE")
            self.assertNotEqual(report["execution_state"], "COMPLETE")
            self.assertEqual(report["skipped_devices"], [EXPECTED_SKIP])
            self.assertEqual(handed_off, [GOOD1[0], GOOD2[0]])

    def test_only_invalid_selected_target_stops_before_auth_runtime_or_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            out, err = io.StringIO(), io.StringIO()
            with patch.object(app, "_resolve_auth", side_effect=AssertionError("No auth for zero eligible devices")), \
                 patch.object(app, "_check_runtime", side_effect=AssertionError("No runtime for zero eligible devices")), \
                 patch.object(driver, "prepare_not_executed_run", side_effect=AssertionError("No empty artifacts")), \
                 patch.object(socket, "socket", side_effect=AssertionError("No network")), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = app.main(["--project", str(project), "--os-only", "--devices", BAD[0]])
            self.assertEqual(code, 3, err.getvalue())
            report = json.loads(out.getvalue())
            self.assertEqual(report["state"], "NO_ELIGIBLE_IB_DEVICES")
            self.assertEqual(report["skipped_devices"], [EXPECTED_SKIP])
            self.assertEqual(report["targets"], [])
            self.assertFalse((project / "99-output-ib_nvl").exists())

    def test_unselected_invalid_device_does_not_make_a_healthy_selection_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            code, out, err, prompts = fixtures.WorkflowTests().invoke(project, home, "--scripts-only", "--method", "http", "--devices", GOOD1[0])
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["targets"], [{"hostname": GOOD1[0]}])
            self.assertNotIn("SKIPPED_INPUT_INVALID", err)

    def test_changed_rejected_row_still_invalidates_the_original_bound_source(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            entry, cwd = app.__file__, str(project)
            args = ("--project", str(project), "--os-only")
            plan = driver.parse_prepare_args(entry, cwd, args)
            with driver.open_regular_inputs(plan.paths) as scope:
                self.assertEqual(len(scope.inventory().blocked_devices), 1)
                (project / "02-devices_config.csv").write_text(csv_text([GOOD1, GOOD2]))
                with self.assertRaises(ValueError):
                    scope.verify()

    def test_user_scenario_192_ib_rows_one_missing_mac_yields_191_eligible(self):
        rows = [ib_row(f"ew-spine{n:03d}.example", f"192.0.2.{n}",
                       "" if n == 61 else f"02:00:00:00:00:{n:02x}") for n in range(1, 193)]
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve(), rows)
            code, out, err = fixtures.InputDiagnosticsTests().invoke(project)
            self.assertEqual(code, 3, err)
            report = json.loads(out)
            self.assertEqual((report["selected_ib_count"], report["eligible_ib_count"], report["skipped_ib_count"]), (192, 191, 1))
            self.assertEqual(report["skipped_devices"], [{"hostname": "ew-spine061.example", "csv_row": 62,
                             "state": "SKIPPED_INPUT_INVALID", "reasons": ["ETH0_MAC_MISSING"]}])

    def test_empty_eligible_set_cannot_prepare_a_native_upgrade_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve(), [BAD])
            with self.assertRaisesRegex(ValueError, "no eligible IB targets"):
                driver.prepare_not_executed_run(app.__file__, str(project), ("--project", str(project), "--os-only"))
            self.assertFalse((project / "99-output-ib_nvl").exists())

    def test_prior_clean_and_partial_plans_are_verified_against_their_own_raw_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve(), [GOOD1, GOOD2])
            args = ("--project", str(project), "--os-only")
            entry, cwd = app.__file__, str(project)
            first = driver.prepare_not_executed_run(entry, cwd, args)
            self.assertNotIn("skipped_devices", json.loads((Path(first["run_directory"]) / "plan.json").read_text()))
            (project / "02-devices_config.csv").write_text(csv_text([BAD, GOOD1, GOOD2]))
            second = driver.prepare_not_executed_run(entry, cwd, args)
            with driver.open_prepared_run(entry, cwd, args, second["run_directory"]) as scope:
                with scope._request_namespace_lease():
                    scope._inventory_requests_locked(GOOD1[0])
            # Reverting to a clean selected inventory still verifies the older
            # partial plan and its original immutable skipped-row evidence.
            (project / "02-devices_config.csv").write_text(csv_text([GOOD1, GOOD2]))
            third = driver.prepare_not_executed_run(entry, cwd, args)
            with driver.open_prepared_run(entry, cwd, args, third["run_directory"]) as scope:
                with scope._request_namespace_lease():
                    scope._inventory_requests_locked(GOOD1[0])

    def test_invalid_first_device_is_absent_from_native_component_canary_status(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            args = ("--project", str(project), "--os-only", "--yes", "--exclusive-config-window")
            entry, cwd = app.__file__, str(project)
            prepared = driver.prepare_not_executed_run(entry, cwd, args)
            with driver.open_prepared_run(entry, cwd, args, prepared["run_directory"]) as scope:
                scope.initialize_native_component_status_data()
                status = json.loads((Path(prepared["run_directory"]) / "os-status.json").read_text())
                self.assertEqual([row["node"]["hostname"] for row in status["targets"]], [GOOD1[0], GOOD2[0]])
                self.assertEqual(status["canary"], GOOD1[0])


if __name__ == "__main__":
    unittest.main()
