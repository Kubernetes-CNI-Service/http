"""R-016/R-007: real entry, project pointer, inventory comparator and fleet engine.

All device I/O and credentials are synthetic; the engine and IB data planning are real.
"""
from __future__ import annotations

import json
import csv
import unittest
import zipfile
from types import SimpleNamespace
from unittest import mock
from test_cases.ibsw_upgrade_runtime_fixture import OwnedWorkflow


class UpgradeProjectInventoryWorkflowTests(unittest.TestCase):
    def test_real_pointer_failure_stops_before_ops_or_evidence(self):
        fixture = OwnedWorkflow(self)
        pointer = fixture.project.parent / 'activate-project'
        pointer.unlink()
        pointer.write_text('not a symlink\n')
        self.assertEqual(fixture.run(['--plan']), 2)
        self.assertIn('ERROR: DAY0-Prepare/activate-project is not a link:', fixture.out.getvalue())
        self.assertNotIn('Traceback', fixture.out.getvalue())
        self.assertIsNone(fixture.ops)
        self.assertEqual(fixture.reports(), [])
        self.assertFalse((fixture.project / '99-output-ib_nvl').exists())

    def test_active_project_subset_and_early_evidence_are_real(self):
        fixture = OwnedWorkflow(self)
        (fixture.project / "ib.csv").write_text("\n".join([
            (fixture.project / "02-devices_config.csv").read_text().splitlines()[0], fixture.rows[1]]) + "\n")
        self.assertEqual(fixture.run(["--plan"]), 3)
        [report] = fixture.reports()
        self.assertEqual([row["hostname"] for row in report["devices"]], ["example-ib02"])
        self.assertEqual([(row["category"], row["reason"]) for row in report["devices"]],
                         [("NOT_EXECUTED", "PLAN_ONLY")])
        self.assertEqual([item[2] for item in fixture.ops.log if item[1] == "precheck"], ["example-ib02"])
        output = fixture.out.getvalue()
        early = next(line for line in output.splitlines() if line.startswith("[RUN] evidence: "))
        final = next(line for line in output.splitlines() if line.startswith("evidence: "))
        self.assertEqual(early.removeprefix("[RUN] "), final)
        self.assertLess(output.index(early), output.index("[PREFLIGHT PROGRESS]"))
        self.assertIn(str(fixture.project / "p2p.xlsx"), output)
        self.assertFalse((fixture.repository / "infiniband/bringup/xdr-upgrade/xdr-upgrade-v2-logs").exists())
        [plan] = list((fixture.project / "99-output-ib_nvl/bringup/xdr-upgrade-v2-logs").glob("*/plan.json"))
        self.assertEqual(json.loads(plan.read_text())["inputs"]["csv"], str(fixture.project / "ib.csv"))
        self.assertIs(type(fixture.captured.get("available")), frozenset)
        self.assertIn(str(fixture.http / "image/nvos-amd64-25.02.8008.bin"), fixture.captured["available"])
        self.assertEqual({item.path for item in fixture.captured["locked_inputs"]},
                         {str(fixture.private), str(fixture.public)})
        self.assertEqual([item.path for item in fixture.captured["watched_inputs"]], [str(fixture.hosts)])
        self.assertEqual(fixture.captured["packages_ready"].__self__, fixture.ops)

    def test_inventory_mismatch_stops_before_ops_and_skip_is_narrow(self):
        fixture = OwnedWorkflow(self)
        text = (fixture.project / "02-devices_config.csv").read_text()
        (fixture.project / "ib.csv").write_text(text.replace("192.0.2.41", "192.0.2.51"))
        self.assertEqual(fixture.run(["--plan"]), 2)
        self.assertIsNone(fixture.ops)
        self.assertEqual(fixture.reports(), [])
        self.assertIn("INVENTORY MISMATCH: example-ib01; eth0_ip; ib.csv=192.0.2.51; 02=192.0.2.41; value",
                      fixture.out.getvalue())
        self.assertEqual(fixture.run(["--plan", "--inventory-checked"]), 3)
        self.assertIsNotNone(fixture.ops)

    def test_unsplit_project_uses_master_without_compare(self):
        fixture = OwnedWorkflow(self)
        self.assertEqual(fixture.run(["--plan"]), 3)
        [report] = fixture.reports()
        self.assertEqual([row["hostname"] for row in report["devices"]], ["example-ib01", "example-ib02"])
        self.assertNotIn("INVENTORY MISMATCH", fixture.out.getvalue())

    def test_scp_watches_both_snapshots_and_does_not_lock_shared_files(self):
        import fleet_ssh
        fixture = OwnedWorkflow(self)
        server_hosts = fixture.root / "server_known_hosts"
        server_hosts.write_bytes(b"# synthetic scp snapshot\n")
        with mock.patch.object(fleet_ssh.HostPins, "known_hosts_text", return_value=b"synthetic-public-host-key\n"):
            self.assertEqual(fixture.run(["--plan", "--method", "scp", "--mgmt-server", "192.0.2.10",
                                          "--mgmt-user", "example-operator", "--scp-known-hosts", str(server_hosts)]), 3)
        self.assertEqual({item.path for item in fixture.captured["watched_inputs"]},
                         {str(fixture.hosts), str(server_hosts)})
        self.assertEqual({item.path for item in fixture.captured["locked_inputs"]},
                         {str(fixture.private), str(fixture.public)})

    def test_all_input_failures_stop_before_contact_or_evidence(self):
        for kind in ("csv", "global", "devices", "private", "known-hosts", "p2p"):
            with self.subTest(kind=kind):
                fixture = OwnedWorkflow(self)
                extra = ["--plan"]
                if kind == "csv":
                    (fixture.project / "02-devices_config.csv").write_text("bad,columns\n")
                elif kind == "global":
                    fixture.global_path.write_text("schema_version: 2\n")
                elif kind == "devices":
                    extra += ["--devices", "absent-ib*"]
                elif kind == "private":
                    fixture.private.unlink()
                elif kind == "known-hosts":
                    fixture.hosts.unlink()
                else:
                    (fixture.project / "p2p.xlsx").write_bytes(b"not an OOXML workbook")
                self.assertEqual(fixture.run(extra), 2)
                self.assertIn("ERROR:", fixture.out.getvalue())
                expected_path = {"csv": fixture.project / "02-devices_config.csv", "global": fixture.global_path,
                                 "devices": fixture.project / "02-devices_config.csv", "private": fixture.private,
                                 "known-hosts": fixture.hosts, "p2p": fixture.project / "p2p.xlsx"}[kind]
                self.assertIn(str(expected_path), fixture.out.getvalue())
                self.assertNotIn("Traceback", fixture.out.getvalue())
                self.assertIsNone(fixture.ops)
                self.assertEqual(fixture.reports(), [])

    def test_malformed_yaml_and_xlsx_are_friendly_with_the_exact_path(self):
        for kind in ("yaml", "xlsx"):
            with self.subTest(kind=kind):
                fixture = OwnedWorkflow(self)
                if kind == "yaml":
                    path = fixture.global_path
                    path.write_text("common: [unterminated\n")
                else:
                    path = fixture.project / "p2p.xlsx"
                    with zipfile.ZipFile(path, "w") as archive:
                        archive.writestr("xl/sharedStrings.xml", "<malformed")
                try:
                    code = fixture.run(["--plan"])
                except Exception as error:
                    self.fail("ordinary " + kind + " parse failure must return 2, not " + type(error).__name__)
                self.assertEqual(code, 2)
                self.assertIn("ERROR:", fixture.out.getvalue())
                self.assertIn(str(path), fixture.out.getvalue())
                self.assertNotIn("Traceback", fixture.out.getvalue())
                self.assertIsNone(fixture.ops)
                self.assertEqual(fixture.reports(), [])

    def test_sdk_and_key_errors_name_only_the_key_paths(self):
        import fleet_ssh
        for code in ("SDK_UNAVAILABLE", "KEY_INVALID"):
            with self.subTest(code=code):
                fixture = OwnedWorkflow(self)
                fixture.key_error = fleet_ssh.SshError(code)
                self.assertEqual(fixture.run(["--plan"]), 2)
                text = fixture.out.getvalue()
                self.assertIn("ERROR: " + code, text)
                self.assertIn(str(fixture.private), text)
                self.assertIn(str(fixture.public), text)
                self.assertNotIn("synthetic-private-never-parsed", text)
                self.assertIsNone(fixture.ops)
                self.assertEqual(fixture.reports(), [])

    def test_real_p2p_csv_and_late_ooxml_crc_errors_are_friendly(self):
        # RV89: keep the actual distribution -> initial P2P parser boundary.
        # Both inputs are owned malformed data; neither bypasses the real reader.
        for kind in ("csv-reader", "xlsx-late-crc"):
            with self.subTest(kind=kind):
                fixture = OwnedWorkflow(self)
                limit = csv.field_size_limit()
                try:
                    if kind == "csv-reader":
                        path = fixture.project / "p2p.csv"
                        path.write_text("a-node,a-port,z-node,z-port\n" + "x" * 129 + ",eth0,leaf,swp1\n")
                        csv.field_size_limit(128)
                    else:
                        path = fixture.project / "p2p.xlsx"
                        payload = b'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>'
                        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                            archive.writestr("xl/sharedStrings.xml", payload)
                        raw = path.read_bytes()
                        self.assertEqual(raw.count(payload), 1)
                        path.write_bytes(raw.replace(payload, payload[:-2] + b"X>", 1))
                    try:
                        code = fixture.run(["--plan", "--p2p", str(path)])
                    except Exception as error:
                        self.fail("ordinary P2P parse failure must return 2, not " + type(error).__name__)
                finally:
                    csv.field_size_limit(limit)
                self.assertEqual(code, 2)
                self.assertIn("ERROR: invalid P2P input: " + str(path), fixture.out.getvalue())
                self.assertNotIn("Traceback", fixture.out.getvalue())
                self.assertIsNone(fixture.ops)
                self.assertEqual(fixture.reports(), [])

    def test_missing_os_stage_only_blocks_devices_that_need_it(self):
        fixture = OwnedWorkflow(self)
        (fixture.http / "image/nvos-amd64-25.02.8008.bin").unlink()
        factory = fixture.factory
        def mixed(**kwargs):
            ops = factory(**kwargs)
            ops.sims["example-ib02"].version = "25.02.8008"
            return ops
        fixture.factory = mixed
        self.assertEqual(fixture.run(["--plan"]), 3)
        [report] = fixture.reports()
        self.assertIsNone(report["hold"])
        self.assertEqual({row["hostname"]: (row["category"], row["reason"]) for row in report["devices"]},
                         {"example-ib01": ("REVIEW_REQUIRED", "OS_PACKAGE_ROUTE_UNAVAILABLE"),
                          "example-ib02": ("AT_TARGET", None)})

    def test_inventory_comparison_read_and_parse_failures_name_both_paths(self):
        # RV89 / approved b+g: failures from the real M4 reader are caller-owned
        # input rejections, not a new M4 behavior or a generic Exception fallback.
        for kind in ("subset-utf8", "master-utf8", "csv-parser", "short-row", "missing"):
            with self.subTest(kind=kind):
                fixture = OwnedWorkflow(self)
                master, subset = fixture.project / "02-devices_config.csv", fixture.project / "ib.csv"
                subset.write_bytes(master.read_bytes())
                extra = ["--plan"]
                limit = csv.field_size_limit()
                try:
                    if kind == "subset-utf8":
                        subset.write_bytes(b"\xff\n")
                    elif kind == "master-utf8":
                        master.write_bytes(b"\xff\n")
                    elif kind == "csv-parser":
                        csv.field_size_limit(128)
                        subset.write_text("hostname,type\n" + "x" * 129 + ",ib\n")
                    elif kind == "short-row":
                        master.write_text("type,hostname\nib,example-ib01\n")
                        subset.write_text("type,hostname\nib\n")
                    else:
                        subset.unlink()
                        extra += ["--ib-csv", str(subset)]
                    try:
                        code = fixture.run(extra)
                    except Exception as error:
                        self.fail("comparison input must return 2, not " + type(error).__name__)
                finally:
                    csv.field_size_limit(limit)
                self.assertEqual(code, 2)
                self.assertIn("ERROR:", fixture.out.getvalue())
                self.assertIn(str(subset), fixture.out.getvalue())
                self.assertIn(str(master), fixture.out.getvalue())
                self.assertNotIn("Traceback", fixture.out.getvalue())
                self.assertIsNone(fixture.ops)
                self.assertEqual(fixture.reports(), [])

    def test_real_key_reader_rejects_non_ascii_private_and_invalid_public(self):
        import fleet_ssh
        for kind in ("private-ascii", "public-grammar"):
            with self.subTest(kind=kind):
                fixture = OwnedWorkflow(self)
                fixture.use_real_key_reader = True
                fixture.private.chmod(0o600)
                if kind == "private-ascii":
                    fixture.private.write_bytes(b"\xff\n")
                else:
                    fixture.private.write_text("synthetic-owned-not-a-parsed-key\n")
                    fixture.public.write_text("not-an-openssh-public-key\n")
                # The original reader performs lstat/ascii/public grammar. These
                # ordinary failures occur before any SDK key parse; no real key.
                with mock.patch.object(fleet_ssh, "_sdk", return_value=SimpleNamespace()):
                    try:
                        code = fixture.run(["--plan"])
                    except Exception as error:
                        self.fail("real key input must return 2, not " + type(error).__name__)
                text = fixture.out.getvalue()
                self.assertEqual(code, 2)
                self.assertIn("ERROR: KEY_INVALID", text)
                self.assertIn(str(fixture.private), text)
                self.assertIn(str(fixture.public), text)
                self.assertNotIn("synthetic-owned-not-a-parsed-key", text)
                self.assertNotIn("not-an-openssh-public-key", text)
                self.assertIsNone(fixture.ops)
                self.assertEqual(fixture.reports(), [])
