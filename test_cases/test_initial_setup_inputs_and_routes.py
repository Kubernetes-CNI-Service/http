"""v315 r617 WP1 input/routing contracts; owned PUBLIC files, no transport.

Real initial reader/main/cache and real M4 comparison/selection are used. Only
local interface observation, service/key input boundary and device transport are
replaced. Library main avoids the production instance/identity/venv entry.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, redirect_stdout, redirect_stderr
import csv
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
HEADER = ("hostname", "type", "eth0_ip", "netmask", "eth0_gw", "eth0_mac",
          "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "vlan_id", "svi_ip",
          "netmask", "bgp_asn", "bond_mac")


class InputsAndRoutesTests(unittest.TestCase):
    def setUp(self):
        own = Path(os.environ["HTTP_TEST_OWNED_ROOT"])
        info = own.lstat()
        self.assertEqual(own, Path(os.environ["TMPDIR"]))
        self.assertEqual(own, own.resolve())
        self.assertFalse(stat.S_ISLNK(info.st_mode))
        self.assertEqual(os.geteuid(), info.st_uid)
        self.assertEqual(0o700, stat.S_IMODE(info.st_mode))
        self.tmp = tempfile.TemporaryDirectory(prefix="v315-inputs-", dir=own)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.project = self.root / "example-project"
        self.project.mkdir()
        self.csv = self.project / "ib.csv"
        self.master = self.project / "02-devices_config.csv"
        self.p2p = self.project / "p2p.csv"
        self.p2p.write_text("a-node,a-port,z-node,z-port\nexample-ib01,eth0,example-jump01,swp7\n")
        self.app = load_script("v315_wp1_inputs_" + self.root.name.replace("-", "_"), INITIAL)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(self.home)}))
        for owner, name in ((subprocess, "Popen"), (os, "system"), (os, "execve")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError(
                "WP1 owned input tests must not launch any child")))
        self.stack.enter_context(mock.patch("socket.socket", side_effect=AssertionError("no network")))
        self.stack.enter_context(mock.patch.object(self.app, "interactive_run", side_effect=AssertionError("no SSH")))
        self.stack.enter_context(mock.patch.object(self.app, "_service_profile", return_value=None))
        self.stack.enter_context(mock.patch.object(self.app, "_public_key_profile", return_value=[]))
        self.stack.enter_context(mock.patch.object(self.app, "_read_local_interfaces", return_value=(), create=True))
        self.stack.enter_context(mock.patch.object(self.app, "local_ethernet_keys", return_value=set()))
        self.sessions = self.stack.enter_context(mock.patch.object(
            self.app, "_new_jump_sessions", side_effect=self.app.SetupError(
                "PUBLIC WP1 reached device boundary; no session or temporary socket directory created")))
        self.addCleanup(self.close_report)
        self.write_inventory([self.ib(), self.jump()])

    def close_report(self):
        if self.app.REPORT_HANDLE is not None:
            self.app.REPORT_HANDLE.close()
            self.app.REPORT_HANDLE = None

    @staticmethod
    def ib(host="example-ib01", address="192.0.2.10", mac="02:00:00:00:00:10", **changes):
        row = dict(hostname=host, type="ib", eth0_ip=address, netmask="24",
                   eth0_gw="192.0.2.1", eth0_mac=mac)
        row.update(changes)
        return row

    @staticmethod
    def jump(host="example-jump01", **changes):
        row = dict(hostname=host, type="eth_jump", eth0_ip="198.51.100.1",
                   eth0_mac="02:00:00:00:01:01")
        row.update(changes)
        return row

    def write_inventory(self, rows, *, master=None):
        def write(path, values):
            with path.open("w", newline="") as out:
                writer = csv.writer(out)
                writer.writerow(HEADER)
                for row in values:
                    writer.writerow([row.get(name, "") for name in HEADER])
        write(self.csv, rows)
        write(self.master, rows if master is None else master)

    def read(self):
        try:
            return self.app.load_devices(self.csv)
        except self.app.SetupError as error:
            self.fail("r617 WP1 per-device input must not abort inventory: " + str(error))

    def issue_fields(self, device, attr="input_issues"):
        self.assertTrue(hasattr(device, attr), "WP1 reader must retain " + attr)
        return {item.field for item in getattr(device, attr)}

    def invoke(self, *options, project=True):
        self.close_report()
        argv = [str(self.app.__file__), *(["--project-dir", str(self.project)] if project else []),
                "--p2p", str(self.p2p),
                "--report", str(self.root / "report.log"),
                "--target-cache", str(self.root / "targets.json"),
                "--snapshot-dir", str(self.root / "snapshots"), *options]
        output = io.StringIO()
        with mock.patch.object(sys, "argv", argv), redirect_stdout(output), redirect_stderr(output):
            try:
                code = self.app.main()
            except self.app.SetupError as error:
                print("ERROR: " + str(error))
                code = 2
            except SystemExit as error:
                code = error.code
        self.close_report()
        return code, output.getvalue()

    def output_state(self):
        """All outputs, including temporary/checksum/evidence files, not only report."""
        rows = []
        for path in sorted(self.root.rglob("*")):
            if path == self.project or self.project in path.parents or path == self.home or self.home in path.parents:
                continue
            rows.append((str(path.relative_to(self.root)), "dir" if path.is_dir() else "file",
                         None if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()))
        return tuple(rows)

    @contextmanager
    def copied_app(self, layout, *, missing=None, real_location=False):
        """Actual same-byte source in one owned layout; no cold child/canonical borrow."""
        tree = self.root / (layout + ("-" + missing if missing else ""))
        script = (tree / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
                  if layout in {"repository", "management_leaf_tools"} else tree / "initial-setup.py")
        script.parent.mkdir(parents=True)
        tools = (script.parent if layout == "management_leaf_tools" else tree) / "tools"
        tools.mkdir()
        original = INITIAL.read_bytes()
        script.write_bytes(original)
        self.assertEqual(original, script.read_bytes())
        for name in ("login_path", "device_identity", "hostname_ranges", "inventory_subset"):
            if name != missing:
                raw = (ROOT / "tools" / (name + ".py")).read_bytes()
                (tools / (name + ".py")).write_bytes(raw)
                self.assertEqual(raw, (tools / (name + ".py")).read_bytes())
        with ExitStack() as stack:
            paths = [entry for entry in sys.path
                     if Path(entry or os.curdir).resolve() not in {ROOT, ROOT / "tools"}]
            stack.enter_context(mock.patch.object(sys, "path", [str(tools.parent), *paths]))
            stack.enter_context(mock.patch.dict(sys.modules))
            for name in ("tools", "tools.login_path", "tools.device_identity",
                         "tools.hostname_ranges", "tools.inventory_subset"):
                sys.modules.pop(name, None)
            package = importlib.import_module("tools")
            self.assertIn(str(tools), list(package.__path__))
            # Keep the real Python namespace loader, but give this owned-copy
            # fixture one source tree; missing dependencies cannot fall back to
            # another namespace portion from a preceding test or user site.
            stack.enter_context(mock.patch.object(package, "__path__", [str(tools)]))
            previous, previous_sessions = self.app, self.sessions
            self.app = load_script("v315_wp1_copy_" + tree.name.replace("-", "_"), script)
            stack.enter_context(mock.patch.object(self.app, "_service_profile", return_value=None))
            stack.enter_context(mock.patch.object(self.app, "_public_key_profile", return_value=[]))
            if not real_location:
                stack.enter_context(mock.patch.object(self.app, "local_ethernet_keys", return_value=set()))
            stack.enter_context(mock.patch.object(self.app, "_read_local_interfaces", return_value=(), create=True))
            stack.enter_context(mock.patch.object(self.app, "interactive_run", side_effect=AssertionError("no SSH")))
            self.sessions = stack.enter_context(mock.patch.object(self.app, "_new_jump_sessions",
                side_effect=self.app.SetupError("PUBLIC owned copy reached device boundary")))
            try:
                yield tree
            finally:
                self.close_report()
                self.app, self.sessions = previous, previous_sessions

    def test_one_bad_eth0_only_skips_that_device(self):
        self.write_inventory([self.ib(), self.ib("example-ib02", "", "02:00:00:00:00:12"),
            self.ib("example-ib03", "192.0.2.13", "02:00:00:00:00:13", eth0_gw="198.51.100.1"),
            self.ib("example-ib04", "192.0.2.14", ""), self.jump()])
        devices, _ = self.read()
        self.assertEqual(4, len(devices))
        self.assertEqual(set(), self.issue_fields(devices["example-ib01"]))
        for host, field in (("example-ib02", "eth0_ip"), ("example-ib03", "eth0_gw"),
                            ("example-ib04", "eth0_mac")):
            self.assertIn(field, self.issue_fields(devices[host]))

    def test_cross_device_eth0_conflicts_follow_o9_even_without_macs(self):
        self.write_inventory([self.ib("example-ib01", mac=""),
                              self.ib("example-ib02", mac=""),
                              self.ib("example-ib03", "203.0.113.10", "02:00:00:00:00:13", eth0_gw="203.0.113.1"), self.jump()])
        devices, _ = self.read()
        for host, other in (("example-ib01", "example-ib02"), ("example-ib02", "example-ib01")):
            self.assertTrue(hasattr(devices[host], "input_issues"))
            self.assertTrue(any(other in i.problem and i.blocking for i in devices[host].input_issues))
        self.assertEqual(set(), self.issue_fields(devices["example-ib03"]))

    def test_conflicting_eth0_gateway_blocks_only_involved_subnet(self):
        self.write_inventory([self.ib(), self.ib("example-ib02", "192.0.2.12", "02:00:00:00:00:12", eth0_gw="192.0.2.2"),
            self.ib("example-ib03", "203.0.113.10", "02:00:00:00:00:13", eth0_gw="203.0.113.1"), self.jump()])
        devices, _ = self.read()
        for host in ("example-ib01", "example-ib02"):
            self.assertIn("eth0_gw", self.issue_fields(devices[host]))
        self.assertEqual(set(), self.issue_fields(devices["example-ib03"]))

    def test_eth0_gateway_owned_by_another_ib_blocks_the_two_involved(self):
        # Different declared subnet widths isolate address ownership from the
        # separate same-planning-subnet gateway-consistency rule.
        self.write_inventory([self.ib(eth0_gw="192.0.2.12"),
            self.ib("example-ib02", "192.0.2.12", "02:00:00:00:00:12", netmask="25"),
            self.ib("example-ib03", "203.0.113.10", "02:00:00:00:00:13", eth0_gw="203.0.113.1"), self.jump()])
        devices, _ = self.read()
        for name in ("example-ib01", "example-ib02"):
            self.assertTrue(self.issue_fields(devices[name]))
        self.assertEqual(set(), self.issue_fields(devices["example-ib03"]))

    def test_cross_device_eth1_conflicts_only_hint(self):
        self.write_inventory([self.ib(eth1_ip="203.0.113.10", eth1_gw="203.0.113.1"),
            self.ib("example-ib02", "192.0.2.12", "02:00:00:00:00:12", eth1_ip="203.0.113.10", eth1_gw="203.0.113.1"), self.jump()])
        devices, _ = self.read()
        for device in devices.values():
            self.assertEqual(set(), self.issue_fields(device))
            self.assertIn("eth1_ip", self.issue_fields(device, "eth1_hints"))
            self.assertEqual("", device.eth1_prefix)
            self.assertTrue(device.eth0_prefix)

    def test_eth1_address_without_gateway_survives_and_only_hints(self):
        self.write_inventory([self.ib(eth1_ip="203.0.113.10", eth1_gw="", eth1_mac="02:00:00:00:00:19"), self.jump()])
        devices, _ = self.read()
        device = devices["example-ib01"]
        self.assertEqual("203.0.113.10/24", device.eth1_prefix)
        self.assertEqual("", device.eth1_gateway)
        self.assertTrue(self.issue_fields(device, "eth1_hints"))
        self.assertEqual(set(), self.issue_fields(device))

    def test_eth1_address_overlaps_other_eth0_only_suppresses_eth1(self):
        self.write_inventory([self.ib(eth1_ip="192.0.2.12", eth1_gw="192.0.2.1"),
            self.ib("example-ib02", "192.0.2.12", "02:00:00:00:00:12"), self.jump()])
        devices, _ = self.read()
        self.assertEqual("", devices["example-ib01"].eth1_prefix)
        self.assertIn("eth1_ip", self.issue_fields(devices["example-ib01"], "eth1_hints"))
        self.assertEqual(set(), self.issue_fields(devices["example-ib01"]))
        self.assertEqual(set(), self.issue_fields(devices["example-ib02"]))

    def test_eth1_gateway_conflicts_suppress_only_that_item(self):
        self.write_inventory([self.ib(eth1_ip="203.0.113.10", eth1_gw="203.0.113.1"),
            self.ib("example-ib02", "192.0.2.12", "02:00:00:00:00:12",
                    eth1_ip="203.0.113.12", eth1_gw="203.0.113.2"), self.jump()])
        devices, _ = self.read()
        for host, address in (("example-ib01", "203.0.113.10/24"),
                              ("example-ib02", "203.0.113.12/24")):
            self.assertEqual(set(), self.issue_fields(devices[host]))
            self.assertEqual(address, devices[host].eth1_prefix)
            self.assertEqual("", devices[host].eth1_gateway)
            self.assertIn("eth1_gw", self.issue_fields(devices[host], "eth1_hints"))
        self.write_inventory([self.ib(eth1_ip="203.0.113.10", eth1_gw="203.0.113.12"),
            self.ib("example-ib02", "203.0.113.12", "02:00:00:00:00:12",
                    eth0_gw="203.0.113.1"), self.jump()])
        devices, _ = self.read()
        self.assertEqual("203.0.113.10/24", devices["example-ib01"].eth1_prefix)
        self.assertEqual("", devices["example-ib01"].eth1_gateway)
        self.assertEqual(set(), self.issue_fields(devices["example-ib02"]))
        self.assertIn("eth1_gw", self.issue_fields(devices["example-ib01"], "eth1_hints"))

    def test_hostname_invalid_or_duplicate_still_aborts(self):
        for rows in ([self.ib("bad name"), self.jump()], [self.ib(), self.ib(), self.jump()], [self.jump()]):
            with self.subTest(rows=rows):
                self.write_inventory(rows)
                with self.assertRaises(self.app.SetupError):
                    self.app.load_devices(self.csv)

    def test_jump_row_lexical_errors_follow_o22(self):
        self.write_inventory([self.ib(), self.jump(eth0_ip="bad", eth0_mac="wrong",
            vlan_id="20", svi_ip="198.51.100.20", bgp_asn="not-asn", bond_mac="not-mac")])
        _, jumps = self.read()
        jump = jumps["example-jump01"]
        self.assertEqual("198.51.100.20", jump.login_ip)
        self.assertEqual("", jump.eth0_mac)
        self.assertTrue(hasattr(jump, "jump_candidates"))
        self.assertEqual((("198.51.100.20", "JUMP_VLAN20"),),
                         tuple((v.address, v.entry) for v in jump.jump_candidates))

    def test_two_jump_rows_same_login_do_not_abort(self):
        self.write_inventory([self.ib(), self.jump(), self.jump("example-jump02")])
        _, jumps = self.read()
        self.assertEqual(2, len(jumps))

    def test_jump_without_any_candidate_is_retained_with_issue(self):
        self.write_inventory([self.ib(), self.jump(eth0_ip="bad")])
        _, jumps = self.read()
        jump = jumps["example-jump01"]
        self.assertEqual("", jump.login_ip)
        self.assertTrue(hasattr(jump, "jump_candidates"))
        self.assertEqual((), jump.jump_candidates)
        self.assertTrue(self.issue_fields(jump))

    def test_non_jump_ethernet_rows_need_no_login_address(self):
        for kind in ("eth", "eth_spx", "spx", "ethernet"):
            with self.subTest(kind=kind):
                self.write_inventory([self.ib(), self.jump(type=kind, eth0_ip="")])
                devices, peers = self.read()
                target = self.app.build_targets(self.app.parse_p2p(self.p2p), devices, peers)[0]
                self.assertEqual("example-ib01", target.ib.hostname)
                self.assertTrue(hasattr(target, "route"))
                self.assertEqual(("direct", "PEER_NOT_JUMP"), (target.route.path, target.route.reason))

    def test_no_links_no_longer_aborts(self):
        self.write_inventory([self.ib()])
        devices, peers = self.read()
        self.assertEqual({}, peers)
        targets = self.app.build_targets([], devices, peers)
        self.assertEqual(1, len(targets))
        self.assertIsNone(targets[0].ethernet)
        self.assertTrue(hasattr(targets[0], "route"))
        self.assertEqual("NO_MGMT_LINK", targets[0].route.reason)

    def test_inventory_compare_runs_first_and_exits_2(self):
        master = [self.ib(address="192.0.2.99"), self.jump()]
        self.write_inventory([self.ib(), self.jump()], master=master)
        before = self.output_state()
        code, out = self.invoke("--plan")
        self.assertEqual(2, code)
        self.assertIn("INVENTORY MISMATCH: example-ib01; eth0_ip; ib.csv=192.0.2.10; 02=192.0.2.99; value", out)
        self.assertFalse((self.root / "report.log").exists())
        self.assertFalse((self.root / "targets.json").exists())
        self.assertEqual(before, self.output_state())
        self.sessions.assert_not_called()

    def test_inventory_compare_in_every_mode_and_skip_flag(self):
        self.write_inventory([self.ib(), self.jump()], master=[self.ib(address="192.0.2.99"), self.jump()])
        for options in ((), ("--plan",), ("--generate-json",)):
            with self.subTest(options=options):
                before = self.output_state()
                code, out = self.invoke(*options)
                self.assertEqual(2, code)
                self.assertIn("INVENTORY MISMATCH", out)
                self.assertFalse((self.root / "report.log").exists())
                self.assertEqual(before, self.output_state())
                self.sessions.assert_not_called()
        code, out = self.invoke("--plan", "--inventory-checked")
        self.assertEqual(0, code)
        self.assertNotIn("INVENTORY MISMATCH", out)
        with mock.patch.object(sys, "argv", [str(INITIAL), "--help"]), redirect_stdout(io.StringIO()) as help_text:
            with self.assertRaises(SystemExit) as caught:
                self.app.parse_args()
        self.assertEqual(0, caught.exception.code)
        self.assertNotIn("--inventory-checked", help_text.getvalue())

    def test_inventory_missing_master_is_friendly_without_output(self):
        self.master.unlink()
        for options in ((), ("--plan",), ("--generate-json",)):
            with self.subTest(options=options):
                before = self.output_state()
                code, out = self.invoke(*options)
                self.assertEqual(2, code)
                self.assertIn(str(self.master), out)
                self.assertNotIn("Traceback", out)
                self.assertFalse((self.root / "targets.json").exists())
                self.assertEqual(before, self.output_state())
                self.sessions.assert_not_called()

    def test_repository_master_path_and_same_canonical_shortcut(self):
        with self.copied_app("repository") as tree:
            master = tree / "infiniband/02-devices_config.csv"
            master.write_bytes(self.master.read_bytes().replace(b"192.0.2.10", b"192.0.2.99"))
            before = self.output_state()
            code, out = self.invoke("--plan", "--ib-csv", str(self.csv), project=False)
            self.assertEqual(2, code)
            self.assertIn("02=192.0.2.99", out)
            self.assertEqual(before, self.output_state())
            self.sessions.assert_not_called()
            master.unlink()
            master.symlink_to(self.csv)
            library = importlib.import_module("tools.inventory_subset")
            self.assertEqual(tree / "tools/inventory_subset.py", Path(library.__file__).resolve())
            with mock.patch.object(library, "compare", wraps=library.compare) as compare:
                code, out = self.invoke("--plan", "--ib-csv", str(self.csv), project=False)
            self.assertEqual(0, code)
            self.assertIn("JUMP_LINK", out)
            compare.assert_not_called()

    def test_consistent_subset_and_an_extra_subset_row_have_independent_results(self):
        self.write_inventory([self.ib(), self.jump()], master=[self.ib(), self.jump(),
            self.ib("example-ib02", "192.0.2.12", "02:00:00:00:00:12")])
        code, out = self.invoke("--generate-json")
        self.assertEqual(0, code)
        payload = json.loads((self.root / "targets.json").read_text())
        self.assertIn("inventory_check", payload)
        self.assertEqual("compared", payload["inventory_check"]["status"])
        # The same owned output set must survive a subsequent rejected input.
        self.write_inventory([self.ib(), self.jump(), self.ib("example-ib03", "192.0.2.13", "02:00:00:00:00:13")],
                             master=[self.ib(), self.jump()])
        before = self.output_state()
        code, out = self.invoke("--generate-json")
        self.assertEqual(2, code)
        self.assertIn("INVENTORY MISMATCH: example-ib03; hostname;", out)
        self.assertIn("not-in-master", out)
        self.assertEqual(before, self.output_state())
        self.sessions.assert_not_called()

    def test_management_role_with_adjacent_tools_uses_fixed_repository_master(self):
        with self.copied_app("management_leaf_tools") as tree:
            master = tree / "infiniband/02-devices_config.csv"
            master.write_bytes(self.master.read_bytes())
            self.assertFalse((tree / "tools").exists(), "preserve the one real Leaf module layout")
            code, out = self.invoke("--generate-json", "--execution-mode", "management",
                                    "--ib-csv", str(self.csv), project=False)
            self.assertEqual(0, code)
            self.assertIn("JUMP_LINK", out)
            payload = json.loads((self.root / "targets.json").read_text())
            self.assertEqual({"status": "compared", "subset_sha256": hashlib.sha256(self.csv.read_bytes()).hexdigest(),
                "master_sha256": hashlib.sha256(master.read_bytes()).hexdigest()}, payload["inventory_check"])
            master.write_bytes(self.master.read_bytes().replace(b"192.0.2.10", b"192.0.2.99"))
            before = self.output_state()
            for mode in ((), ("--plan",), ("--generate-json",)):
                with self.subTest(mode=mode):
                    code, out = self.invoke(*mode, "--execution-mode", "management",
                                            "--ib-csv", str(self.csv), project=False)
                    self.assertEqual(2, code)
                    self.assertIn("INVENTORY MISMATCH: example-ib01; eth0_ip;", out)
                    self.assertEqual(before, self.output_state())
                    self.sessions.assert_not_called()

    def test_auto_management_cache_hit_compares_master_before_any_output(self):
        with self.copied_app("management_leaf_tools", real_location=True) as tree:
            master = tree / "infiniband/02-devices_config.csv"
            master.write_bytes(self.master.read_bytes())
            code, out = self.invoke("--generate-json", "--execution-mode", "management",
                                    "--ib-csv", str(self.csv), project=False)
            self.assertEqual(0, code)
            self.assertIsNotNone(self.app.load_target_cache(
                self.root / "targets.json", self.csv, self.p2p))
            master.write_bytes(self.master.read_bytes().replace(b"192.0.2.10", b"192.0.2.99"))
            before = self.output_state()
            with mock.patch.object(self.app.socket, "gethostname", return_value="example-management01"), \
                 mock.patch.object(self.app.socket, "getfqdn", return_value="example-management01.example.test"):
                code, out = self.invoke("--plan", "--execution-mode", "auto",
                                        "--ib-csv", str(self.csv), project=False)
            self.assertEqual(2, code)
            self.assertIn("INVENTORY MISMATCH: example-ib01; eth0_ip;", out)
            self.assertEqual(before, self.output_state())
            self.sessions.assert_not_called()

    def test_auto_management_adjacent_tools_cold_cache_uses_real_comparison(self):
        with self.copied_app("management_leaf_tools", real_location=True) as tree:
            master = tree / "infiniband/02-devices_config.csv"
            master.write_bytes(self.master.read_bytes())
            self.assertFalse((tree / "tools").exists())
            self.assertFalse((self.root / "targets.json").exists())
            with mock.patch.object(self.app.socket, "gethostname", return_value="example-management01"), \
                 mock.patch.object(self.app.socket, "getfqdn", return_value="example-management01.example.test"):
                code, out = self.invoke("--plan", "--execution-mode", "auto",
                                        "--ib-csv", str(self.csv), project=False)
            self.assertEqual(0, code)
            self.assertIn("JUMP_LINK", out)
            payload = json.loads((self.root / "targets.json").read_text())
            self.assertEqual({"status": "compared",
                "subset_sha256": hashlib.sha256(self.csv.read_bytes()).hexdigest(),
                "master_sha256": hashlib.sha256(master.read_bytes()).hexdigest()}, payload["inventory_check"])
            self.sessions.assert_not_called()

    def test_auto_local_leaf_repository_tools_accepts_only_qualified_cache(self):
        with self.copied_app("repository", real_location=True) as tree:
            code, out = self.invoke("--generate-json", "--execution-mode", "management")
            self.assertEqual(0, code)
            cache = self.root / "targets.json"
            self.assertIsNotNone(self.app.load_target_cache(cache, self.csv, self.p2p))
            self.master.unlink()
            (tree / "tools/inventory_subset.py").unlink()
            with mock.patch.object(self.app.socket, "gethostname", return_value="example-jump01"), \
                 mock.patch.object(self.app.socket, "getfqdn", return_value="example-jump01.example.test"), \
                 mock.patch.object(self.app, "load_devices", wraps=self.app.load_devices) as parse:
                code, out = self.invoke("--plan", "--execution-mode", "auto")
                self.assertEqual(0, code)
                self.assertIn("JUMP_LINK", out)
                parse.assert_not_called()
                payload = json.loads(cache.read_text())
                payload.pop("inventory_check")
                raw = json.dumps(payload).encode()
                cache.write_bytes(raw)
                cache.with_name(cache.name + ".sha256").write_text(
                    hashlib.sha256(raw).hexdigest() + "  " + cache.name + "\n")
                before = self.output_state()
                code, out = self.invoke("--plan", "--execution-mode", "auto")
            self.assertEqual(2, code)
            self.assertIn("regenerate version 6 on the management server", out)
            self.assertEqual(before, self.output_state())
            self.sessions.assert_not_called()

    def test_local_leaf_with_only_input_blocked_targets_still_reports_each_device(self):
        self.write_inventory([self.ib(mac=""), self.jump()])
        with self.copied_app("leaf", real_location=True) as tree:
            code, out = self.invoke("--generate-json", "--execution-mode", "management")
            self.assertEqual(0, code)
            cache = self.root / "targets.json"
            raw = cache.read_bytes()
            checksum_path = cache.with_name(cache.name + ".sha256")
            checksum = checksum_path.read_bytes()
            self.master.unlink()
            (tree / "tools/inventory_subset.py").unlink()
            self.assertFalse(self.master.exists(), "Leaf must not need the absent master")
            self.assertFalse((tree / "tools/inventory_subset.py").exists())
            sessions = mock.Mock()
            sessions.records = {}
            with mock.patch.object(self.app.socket, "gethostname", return_value="example-jump01"), \
                 mock.patch.object(self.app.socket, "getfqdn", return_value="example-jump01.example.test"), \
                 mock.patch.object(self.app, "_new_jump_sessions", return_value=sessions), \
                 mock.patch.object(self.app, "collect_ethernet_interfaces", side_effect=AssertionError(
                     "input-blocked Leaf target must not take a device snapshot")) as snapshot, \
                 mock.patch.object(self.app, "execute_ib_task", side_effect=AssertionError(
                     "input-blocked Leaf target must never dispatch")) as execute, \
                 mock.patch.object(self.app.multiprocessing, "get_context", side_effect=AssertionError(
                     "zero eligible targets must not start a worker")), \
                 mock.patch.object(self.app.getpass, "getpass", side_effect=AssertionError("no password prompt")), \
                 mock.patch("builtins.input", side_effect=AssertionError("no consent/password input")):
                code, out = self.invoke("--execution-mode", "ethernet")
            self.assertEqual(2, code)
            self.assertEqual(raw, cache.read_bytes())
            self.assertEqual(checksum, checksum_path.read_bytes())
            paths = list(self.root.glob("devices-*/summary.json"))
            self.assertEqual(1, len(paths), "a matched local Leaf must reach the structured per-device result")
            payload = json.loads(paths[0].read_text())
            self.assertEqual("INCOMPLETE", payload["result"])
            self.assertEqual({"example-ib01"}, set(payload["records"]))
            record = payload["records"]["example-ib01"]
            self.assertEqual("SKIPPED_INPUT_INCOMPLETE", record["category"])
            self.assertIs(False, record["writes_attempted"])
            self.assertIn("eth0_mac", record["reason"])
            self.assertFalse(record.get("script_error", False))
            snapshot.assert_not_called()
            execute.assert_not_called()
            sessions.probe_jump_key.assert_not_called()
            sessions.close_jump_masters.assert_called_once_with()

    def test_leaf_missing_each_mandatory_tool_fails_before_output_or_session(self):
        for missing in ("login_path", "hostname_ranges", "device_identity"):
            with self.subTest(missing=missing), self.copied_app("leaf", missing=missing):
                before = self.output_state()
                observed, code, out = None, None, ""
                try:
                    code, out = self.invoke("--plan")
                except Exception as error:
                    observed = error
                self.assertIsNone(observed, "a missing declared module must be friendly, not "
                                  + (type(observed).__name__ if observed is not None else ""))
                self.assertEqual(2, code)
                self.assertIn(missing, out)
                self.assertEqual(before, self.output_state())
                self.sessions.assert_not_called()

    def test_missing_local_ip_command_reports_non_same_subnet(self):
        self.write_inventory([self.ib()])
        self.p2p.write_text("a-node,a-port,z-node,z-port\nother-a,swp1,other-b,swp2\n")
        with mock.patch.object(self.app, "_read_local_interfaces", side_effect=FileNotFoundError("PUBLIC ip absent"), create=True) as read:
            code, out = self.invoke("--plan")
        self.assertEqual(0, code)
        self.assertIn("NO_MGMT_LINK", out)
        self.assertIn("ip", out)
        self.assertIn("unavailable", out)
        read.assert_called_once_with()

    def test_direct_access_cli_and_ethernet_restriction(self):
        code, out = self.invoke("--plan", "--direct-access", "example-ib01")
        self.assertEqual(0, code)
        self.assertIn("DIRECT_ACCESS", out)
        code, out = self.invoke("--plan", "--direct-access", "missing")
        self.assertEqual(2, code)
        self.assertIn("missing", out)
        code, out = self.invoke("--plan", "--execution-mode", "ethernet", "--direct-access", "all")
        self.assertEqual(2, code)
        self.assertIn("--direct-access", out)

    def test_classification_table_plan_and_generate_json(self):
        for options in (("--plan",), ("--generate-json",)):
            with self.subTest(options=options):
                code, out = self.invoke(*options)
                self.assertEqual(0, code)
                self.assertIn("JUMP_LINK", out)
                self.assertIn("example-ib01", out)
        payload = json.loads((self.root / "targets.json").read_text())
        self.assertIn("routes", payload, "WP1 cache must retain its classified routes")
        self.assertEqual("jump", payload["routes"]["example-ib01"]["path"])

    def test_jump_input_hints_are_reported_without_blocking_the_valid_vlan(self):
        self.write_inventory([self.ib(),
            self.ib("example-ib02", "192.0.2.12", "02:00:00:00:00:12"),
            self.jump(eth0_ip="not-an-address", vlan_id="20", svi_ip="198.51.100.20",
                      bgp_asn="not-an-asn"),
            self.jump("example-jump02", eth0_ip="also-not-an-address")])
        self.p2p.write_text("a-node,a-port,z-node,z-port\n"
            "example-ib01,eth0,example-jump01,swp7\n"
            "example-ib02,eth0,example-jump02,swp8\n")

        code, generated = self.invoke("--generate-json")
        self.assertEqual(0, code)
        payload = json.loads((self.root / "targets.json").read_text())
        self.assertEqual("198.51.100.20", payload["targets"][0]["ethernet"]["login_ip"])
        self.assertEqual("", payload["targets"][1]["ethernet"]["login_ip"])
        code, plan = self.invoke("--plan")
        self.assertEqual(0, code)
        for output in (generated, plan):
            with self.subTest(output="plan" if output is plan else "generate"):
                for hostname, field in (("example-jump01", "bgp_asn"),
                                        ("example-jump02", "eth0_ip")):
                    self.assertTrue(any(hostname in line and field in line
                                        for line in output.splitlines()), output)
        self.assertIn("[example-ib01] Initial configuration commands:", plan)
        self.assertTrue(any("example-ib02" in line and "SKIPPED_JUMP_ADDRESS_INVALID" in line
                            for line in plan.splitlines()), plan)
        self.assertNotIn("[example-ib02] Initial configuration commands:", plan)
        self.sessions.assert_not_called()

    def test_leaf_role_skips_direct_targets_before_endpoint_or_credentials(self):
        """D1b-O15: a qualified Leaf with no explicit direct flag never runs direct targets."""
        self.write_inventory([
            self.ib(),
            self.ib("example-ib02", "192.0.2.12", "02:00:00:00:00:12"),
            dict(hostname="example-leaf01", type="eth", eth0_ip="not-a-login"),
        ])
        self.p2p.write_text("a-node,a-port,z-node,z-port\nexample-ib01,eth0,example-leaf01,7\n")
        with self.copied_app("leaf", real_location=True) as tree:
            code, out = self.invoke("--generate-json", "--execution-mode", "management")
            self.assertEqual(0, code, out)
            cache = self.root / "targets.json"
            checksum = cache.with_name(cache.name + ".sha256")
            before = cache.read_bytes(), checksum.read_bytes()
            self.master.unlink()
            (tree / "tools/inventory_subset.py").unlink()
            for mode, flags in (("ethernet", ()), ("auto", ("--apply", "--yes"))):
                with self.subTest(mode=mode, flags=flags):
                    known = set(self.root.glob("devices-*/summary.json"))
                    sessions = mock.Mock()
                    sessions.records = {}
                    with mock.patch.object(self.app.socket, "gethostname", return_value="example-leaf01"), \
                         mock.patch.object(self.app.socket, "getfqdn", return_value="example-leaf01.example.test"), \
                         mock.patch.object(self.app, "_new_jump_sessions", return_value=sessions), \
                         mock.patch.object(self.app, "_direct_endpoint_for", side_effect=AssertionError(
                             "D1b-O15: a Leaf must skip direct targets before constructing any direct endpoint")) as endpoint, \
                         mock.patch.object(self.app, "resolve_initial_ib_password", side_effect=AssertionError(
                             "D1b-O15: no credentials needed when all selected targets are skipped")) as credentials, \
                         mock.patch.object(self.app, "collect_ethernet_interfaces", side_effect=AssertionError(
                             "D1b-O15: a direct-only selection has no Jump snapshot")) as snapshot, \
                         mock.patch.object(self.app, "execute_ib_task", side_effect=AssertionError(
                             "D1b-O15: no device work must be dispatched for a direct target on a Leaf")) as execute, \
                         mock.patch.object(self.app, "verify_management_direct_ssh", side_effect=AssertionError(
                             "D1b-O15: a NOT_TESTED row must not probe a device")) as probe, \
                         mock.patch.object(self.app.multiprocessing, "get_context", side_effect=AssertionError(
                             "D1b-O15: no worker must be launched for this selection")) as worker:
                        code, out = self.invoke("--execution-mode", mode, *flags)
                    self.assertEqual(2, code, out)
                    self.assertEqual(before, (cache.read_bytes(), checksum.read_bytes()))
                    summary_file, = set(self.root.glob("devices-*/summary.json")) - known
                    payload = json.loads(summary_file.read_text(encoding="utf-8"))
                    self.assertEqual("INCOMPLETE", payload["result"])
                    self.assertEqual(["example-ib01", "example-ib02"], payload["selection"]["selected"])
                    self.assertEqual([], payload["selection"]["unmapped"])
                    self.assertEqual(
                        [("example-ib01", "eth0", "NOT_TESTED"), ("example-ib02", "eth0", "NOT_TESTED")],
                        [(row["hostname"], row["interface"], row["status"]) for row in payload["direct_rows"]],
                    )
                    self.assertEqual({"example-ib01", "example-ib02"}, set(payload["records"]))
                    for host, reason in (("example-ib01", "PEER_NOT_JUMP"), ("example-ib02", "NO_MGMT_LINK")):
                        record = payload["records"][host]
                        self.assertEqual(("direct", reason), (record["route"]["path"], record["route"]["reason"]))
                        self.assertEqual(("SKIPPED", "SKIPPED"), (record["outcome"], record["category"]))
                        self.assertIs(False, record["writes_attempted"])
                        self.assertIs(False, record["verified_complete"])
                        self.assertIn("直接登录只在管理服务器上执行", record["reason"])
                    for unused in (endpoint, credentials, snapshot, execute, probe, worker, sessions.probe_jump_key):
                        unused.assert_not_called()

    def test_leaf_cached_selection_preserves_csv_order_and_original_names(self):
        self.write_inventory([
            self.ib("example-IB02", "192.0.2.12", "02:00:00:00:00:12", eth0_mac=""),
            self.jump(),
            self.ib("example-IB01", eth0_mac=""),
        ])
        self.p2p.write_text("a-node,a-port,z-node,z-port\nexample-IB01,eth0,example-jump01,swp7\n")
        with self.copied_app("leaf", real_location=True) as tree:
            code, out = self.invoke("--generate-json", "--execution-mode", "management")
            self.assertEqual(0, code, out)
            self.master.unlink()
            (tree / "tools/inventory_subset.py").unlink()
            for mode in ("ethernet", "auto"):
                with self.subTest(mode=mode):
                    known = set(self.root.glob("devices-*/summary.json"))
                    sessions = mock.Mock(records={})
                    with mock.patch.object(self.app.socket, "gethostname", return_value="example-jump01"), \
                         mock.patch.object(self.app.socket, "getfqdn", return_value="example-jump01.example.test"), \
                         mock.patch.object(self.app, "_new_jump_sessions", return_value=sessions), \
                         mock.patch.object(self.app, "load_devices", wraps=self.app.load_devices) as parse, \
                         mock.patch.object(self.app, "execute_ib_task", side_effect=AssertionError(
                             "inputs without an eth0 MAC must not reach a device")) as execute:
                        code, out = self.invoke("--execution-mode", mode,
                                                "--devices", "example-ib01,example-ib02")
                    self.assertEqual(2, code, out)
                    summary, = set(self.root.glob("devices-*/summary.json")) - known
                    selection = json.loads(summary.read_text(encoding="utf-8"))["selection"]
                    self.assertEqual(["example-IB02", "example-IB01"], selection["selected"])
                    self.assertEqual([], selection["unmapped"])
                    # Live Spine routing still reads the pinned topology later;
                    # it must be the only full inventory parse on this route.
                    parse.assert_called_once_with(self.csv)
                    execute.assert_not_called()
                    sessions.probe_jump_key.assert_not_called()

    def test_p2p_link_count_excludes_unlinked_targets_not_direct_routes(self):
        self.write_inventory([self.ib(),
            self.ib("example-ib02", "192.0.2.12", "02:00:00:00:00:12"),
            self.ib("example-ib03", "192.0.2.13", "02:00:00:00:00:13"),
            self.jump(), self.jump("example-leaf01", type="eth", eth0_ip="")])
        self.p2p.write_text("a-node,a-port,z-node,z-port\n"
            "example-ib01,eth0,example-jump01,swp7\n"
            "example-ib02,eth0,example-leaf01,swp8\n")

        for mode in ("--generate-json", "--plan"):
            with self.subTest(mode=mode):
                code, output = self.invoke(mode, "--direct-access", "example-ib01")
                self.assertEqual(0, code, output)
                self.assertIn("Route example-ib01: direct DIRECT_ACCESS", output)
                self.assertIn("Route example-ib02: direct PEER_NOT_JUMP", output)
                self.assertIn("Route example-ib03: direct NO_MGMT_LINK", output)
                self.assertIn("IB targets with P2P management links: 2; Classified IB targets: 3", output)
        self.sessions.assert_not_called()

    def test_cache_six_records_inventory_and_direct_targets(self):
        self.p2p.write_text("a-node,a-port,z-node,z-port\nother-a,swp1,other-b,swp2\n")
        code, out = self.invoke("--generate-json")
        self.assertEqual(0, code)
        payload = json.loads((self.root / "targets.json").read_text())
        self.assertEqual(6, payload["version"])
        self.assertEqual({"status": "compared", "subset_sha256": hashlib.sha256(self.csv.read_bytes()).hexdigest(),
                          "master_sha256": hashlib.sha256(self.master.read_bytes()).hexdigest()}, payload["inventory_check"])
        self.assertEqual("direct", payload["routes"]["example-ib01"]["path"])
        self.assertIsNone(payload["targets"][0]["ethernet"])

    def test_direct_access_is_per_invocation_not_sticky_in_base_cache(self):
        # r617 static target cache + argv contract, clarified by Root before
        # implementation: the override must not destroy the P2P jump source.
        code, out = self.invoke("--generate-json", "--direct-access", "all")
        self.assertEqual(0, code)
        self.assertIn("DIRECT_ACCESS", out)
        path = self.root / "targets.json"
        payload = json.loads(path.read_text())
        self.assertEqual("jump", payload["routes"]["example-ib01"]["path"])
        self.assertEqual("JUMP_LINK", payload["routes"]["example-ib01"]["reason"])
        self.assertEqual("example-jump01", payload["targets"][0]["ethernet"]["hostname"])
        base_bytes = path.read_bytes()
        code, out = self.invoke("--plan")
        self.assertEqual(0, code)
        self.assertIn("JUMP_LINK", out)
        self.assertNotIn("DIRECT_ACCESS", out)
        self.assertEqual(base_bytes, path.read_bytes())

    def test_save_requires_explicit_valid_inventory_record_before_any_artifact(self):
        ib, ethernet = self.read()
        targets = self.app.build_targets(self.app.parse_p2p(self.p2p), ib, ethernet)
        actual = {"status": "compared",
            "subset_sha256": hashlib.sha256(self.csv.read_bytes()).hexdigest(),
            "master_sha256": hashlib.sha256(self.master.read_bytes()).hexdigest()}
        bad = (None, {}, {"status": "checked_by_caller", "extra": "not approved"},
               {**actual, "subset_sha256": "0" * 64},
               {**actual, "master_sha256": "not-a-sha256"})
        for number, record in enumerate(bad):
            with self.subTest(record=record):
                before = self.output_state()
                cache = self.root / ("invalid-" + str(number) + ".json")
                with self.assertRaises((self.app.SetupError, ValueError)):
                    self.app.save_target_cache(cache, self.csv, self.p2p, 1, targets,
                        services=None, public_keys=[], inventory_check=record)
                self.assertFalse(cache.exists())
                self.assertFalse(cache.with_name(cache.name + ".tmp").exists())
                self.assertFalse(cache.with_name(cache.name + ".sha256").exists())
                self.assertFalse(cache.with_name(cache.name + ".sha256.tmp").exists())
                self.assertEqual(before, self.output_state())
        cache = self.root / "qualified-save.json"
        self.app.save_target_cache(cache, self.csv, self.p2p, 1, targets,
            services=None, public_keys=[], inventory_check=actual)
        self.assertIsNotNone(self.app.load_target_cache(cache, self.csv, self.p2p))
        self.sessions.assert_not_called()

    def test_cache_without_inventory_record_is_not_admitted(self):
        code, out = self.invoke("--generate-json")
        self.assertEqual(0, code)
        path = self.root / "targets.json"
        accepted = self.app.load_target_cache(path, self.csv, self.p2p)
        self.assertIsNotNone(accepted, "the same canonical cache must first be admitted")
        self.assertEqual(1, accepted[0])
        self.assertEqual(["example-ib01"], [t.ib.hostname for t in accepted[1]])
        payload = json.loads(path.read_text())
        payload.pop("inventory_check", None)
        raw = json.dumps(payload).encode()
        path.write_bytes(raw)
        path.with_name(path.name + ".sha256").write_text(hashlib.sha256(raw).hexdigest() + "  " + path.name + "\n")
        self.assertIsNone(self.app.load_target_cache(path, self.csv, self.p2p))
        checksum = path.with_name(path.name + ".sha256").read_bytes()
        with mock.patch.object(self.app, "load_devices", wraps=self.app.load_devices) as parse:
            code, out = self.invoke("--execution-mode", "ethernet")
        self.assertEqual(2, code)
        parse.assert_not_called()
        self.assertIn("regenerate version 6 on the management server", out)
        self.sessions.assert_not_called()
        self.assertEqual(raw, path.read_bytes(), "Leaf must not rebuild the unadmitted cache")
        self.assertEqual(checksum, path.with_name(path.name + ".sha256").read_bytes())
        self.assertFalse((self.root / "snapshots").exists())

    @staticmethod
    def source_tuple(target):
        source = getattr(target, "source_attachment", None)
        return None if source is None else (source.peer, source.peer_type, source.port)

    def ordinary_leaf_inventory(self, *, mac="02:00:00:00:00:10"):
        self.write_inventory([self.ib(mac=mac),
                              dict(hostname="example-leaf01", type="eth", eth0_ip="not-a-login")])
        self.p2p.write_text("a-node,a-port,z-node,z-port\nexample-ib01,eth0,example-leaf01,7\n")

    def resign_owned_cache(self, payload):
        cache = self.root / "targets.json"
        raw = json.dumps(payload).encode()
        cache.write_bytes(raw)
        cache.with_name(cache.name + ".sha256").write_text(
            hashlib.sha256(raw).hexdigest() + "  " + cache.name + "\n")

    def test_source_attachment_literals_keep_four_ordinary_peers_without_fake_jump(self):
        for kind in ("eth", "eth_spx", "spx", "ethernet", "eth_jump"):
            with self.subTest(kind=kind):
                peer = dict(hostname="example-leaf01", type=kind, eth0_ip="")
                self.write_inventory([self.ib(), peer])
                self.p2p.write_text("a-node,a-port,z-node,z-port\nexample-ib01,eth0,EXAMPLE-LEAF01,7\n")
                ib, eth = self.read()
                target, = self.app.build_targets(self.app.parse_p2p(self.p2p), ib, eth)
                self.assertEqual(("example-leaf01", kind, "swp7"), self.source_tuple(target))
                self.assertIsNone(target.attachment, "old spine execution attachment is not topology metadata")
                self.assertEqual("JUMP_LINK" if kind == "eth_jump" else "PEER_NOT_JUMP", target.route.reason)
                if kind != "eth_jump":
                    self.assertIsNone(target.ethernet)
                    self.assertIsNone(target.route.jump)
                    self.assertIsNone(target.route.port)
        target, = self.app.build_targets([], ib, eth)
        self.assertIsNone(getattr(target, "source_attachment", None))
        self.assertEqual("NO_MGMT_LINK", target.route.reason)

    def test_source_attachment_real_cache_roundtrip_preserves_old_four_and_nine(self):
        self.ordinary_leaf_inventory()
        code, _ = self.invoke("--generate-json", "--execution-mode", "management")
        self.assertEqual(0, code)
        payload = json.loads((self.root / "targets.json").read_text())
        self.assertEqual({"example-ib01": {"peer": "example-leaf01", "peer_type": "eth", "port": "swp7"}},
                         payload.get("source_attachments"))
        item, = payload["targets"]
        self.assertEqual({"ib", "ethernet", "ethernet_port", "ib_port_alias"}, set(item))
        self.assertEqual({"hostname", "dev_type", "login_ip", "eth0_prefix", "eth0_gateway", "eth0_mac",
                          "eth1_prefix", "eth1_gateway", "login_interface"}, set(item["ib"]))
        self.assertIsNone(item["ethernet"])
        cached = self.app.load_target_cache(self.root / "targets.json", self.csv, self.p2p)
        self.assertIsNotNone(cached)
        self.assertEqual(("example-leaf01", "eth", "swp7"), self.source_tuple(cached[1][0]))
        self.assertEqual({"status": "compared", "subset_sha256": hashlib.sha256(self.csv.read_bytes()).hexdigest(),
                          "master_sha256": hashlib.sha256(self.master.read_bytes()).hexdigest()}, payload["inventory_check"])

    def test_source_attachment_cache_rejects_missing_and_structurally_wrong_maps(self):
        self.ordinary_leaf_inventory()
        code, _ = self.invoke("--generate-json")
        self.assertEqual(0, code)
        cache = self.root / "targets.json"
        self.assertIsNotNone(self.app.load_target_cache(cache, self.csv, self.p2p))
        original = json.loads(cache.read_text())
        for source in ("missing", None, [], {}, {"other-ib": None},
                       {"example-ib01": None}, {"example-ib01": []},
                       {"example-ib01": {"peer": "example-leaf01", "peer_type": "eth"}},
                       {"example-ib01": {"peer": "example-leaf01", "peer_type": 1, "port": "swp7"}},
                       {"example-ib01": {"peer": "example-leaf01", "peer_type": "eth_jump", "port": "swp7"}},
                       {"example-ib01": {"peer": "example-leaf01", "peer_type": "eth", "port": "swp7", "extra": "x"}}):
            with self.subTest(source=source):
                payload = json.loads(json.dumps(original))
                if source == "missing":
                    payload.pop("source_attachments", None)
                else:
                    payload["source_attachments"] = source
                self.resign_owned_cache(payload)
                self.assertIsNone(self.app.load_target_cache(cache, self.csv, self.p2p))
        self.resign_owned_cache(original)
        old_csv, old_p2p = self.csv.read_bytes(), self.p2p.read_bytes()
        for path in (self.csv, self.p2p):
            with self.subTest(input=path.name):
                self.resign_owned_cache(original)
                self.assertIsNotNone(self.app.load_target_cache(cache, self.csv, self.p2p))
                path.write_bytes(path.read_bytes() + b"\n")
                self.assertIsNone(self.app.load_target_cache(cache, self.csv, self.p2p))
                path.write_bytes(old_csv if path == self.csv else old_p2p)

    def test_ordinary_leaf_qualified_cache_uses_real_source_role_not_management_key(self):
        self.ordinary_leaf_inventory()
        with self.copied_app("leaf", real_location=True) as tree:
            code, _ = self.invoke("--generate-json", "--execution-mode", "management")
            self.assertEqual(0, code)
            cache = self.root / "targets.json"
            raw, checksum = cache.read_bytes(), cache.with_name(cache.name + ".sha256").read_bytes()
            self.master.unlink()
            (tree / "tools/inventory_subset.py").unlink()
            queried_keys = []
            original_is_file = Path.is_file

            def observe_file(path):
                if Path(path) == self.home / ".ssh/id_ed25519":
                    queried_keys.append(str(path))
                return original_is_file(path)

            with mock.patch.object(self.app.socket, "gethostname", return_value="example-leaf01"), \
                 mock.patch.object(self.app.socket, "getfqdn", return_value="example-leaf01.example.test"), \
                 mock.patch.object(self.app, "_compare_inventory", wraps=self.app._compare_inventory) as compare, \
                 mock.patch.object(Path, "is_file", observe_file), \
                 mock.patch.object(self.app, "_new_jump_sessions", side_effect=self.app.SetupError(
                     "PUBLIC source role reached session factory; no session created")) as boundary:
                code, out = self.invoke("--execution-mode", "auto")
                self.assertEqual(2, code)
                self.assertIn("PUBLIC source role reached session factory; no session created", out)
                compare.assert_not_called()
                self.assertEqual([], queried_keys)
                boundary.assert_called_once()
                self.assertEqual(set(), boundary.call_args.kwargs["local_keys"], "ordinary peer is not a transport Jump")
                code, out = self.invoke("--plan", "--execution-mode", "ethernet")
                self.assertEqual(0, code, out)
            self.assertEqual(raw, cache.read_bytes())
            self.assertEqual(checksum, cache.with_name(cache.name + ".sha256").read_bytes())

    def test_source_attachment_cache_rejects_jump_and_no_link_relation_corruption(self):
        for linked in (True, False):
            with self.subTest(linked=linked):
                self.write_inventory([self.ib(), self.jump()])
                self.p2p.write_text("a-node,a-port,z-node,z-port\n" + (
                    "example-ib01,eth0,example-jump01,7\n" if linked else "unrelated-a,1,unrelated-b,2\n"))
                code, _ = self.invoke("--generate-json")
                self.assertEqual(0, code)
                cache = self.root / "targets.json"
                self.assertIsNotNone(self.app.load_target_cache(cache, self.csv, self.p2p))
                original = json.loads(cache.read_text())
                expected = {"peer": "example-jump01", "peer_type": "eth_jump", "port": "swp7"} if linked else None
                self.assertEqual({"example-ib01": expected}, original.get("source_attachments"))
                wrong = (None, {"peer": "other-jump", "peer_type": "eth_jump", "port": "swp7"},
                         {"peer": "example-jump01", "peer_type": "eth_jump", "port": "swp8"},
                         {"peer": "example-jump01", "peer_type": "eth", "port": "swp7"}) if linked else (
                         {"peer": "example-leaf01", "peer_type": "eth", "port": "swp7"},)
                for source in wrong:
                    with self.subTest(source=source):
                        payload = json.loads(json.dumps(original))
                        payload["source_attachments"] = {"example-ib01": source}
                        self.resign_owned_cache(payload)
                        self.assertIsNone(self.app.load_target_cache(cache, self.csv, self.p2p))

    def test_ordinary_leaf_bad_cache_stays_cache_only_without_master_or_outputs(self):
        self.ordinary_leaf_inventory()
        with self.copied_app("leaf", real_location=True) as tree:
            code, _ = self.invoke("--generate-json")
            self.assertEqual(0, code)
            cache = self.root / "targets.json"
            original = json.loads(cache.read_text())
            self.master.unlink()
            (tree / "tools/inventory_subset.py").unlink()
            for fault in ("source_attachments", "inventory_check", "checksum", "missing"):
                for mode in ("auto", "ethernet"):
                    with self.subTest(fault=fault, mode=mode):
                        payload = json.loads(json.dumps(original))
                        if fault in {"source_attachments", "inventory_check"}:
                            payload.pop(fault, None)
                        self.resign_owned_cache(payload)
                        if fault == "checksum":
                            cache.with_name(cache.name + ".sha256").write_text("0" * 64 + "  targets.json\n")
                        elif fault == "missing":
                            cache.unlink()
                        before = self.output_state()
                        with mock.patch.object(self.app.socket, "gethostname", return_value="example-leaf01"), \
                             mock.patch.object(self.app.socket, "getfqdn", return_value="example-leaf01.example.test"), \
                             mock.patch.object(self.app, "_compare_inventory", wraps=self.app._compare_inventory) as compare, \
                             mock.patch.object(self.app, "load_devices", wraps=self.app.load_devices) as parse:
                            code, out = self.invoke("--plan", "--execution-mode", mode)
                        self.assertEqual(2, code)
                        self.assertIn("version 6 on the management server", out)
                        compare.assert_not_called()
                        if mode == "ethernet":
                            parse.assert_not_called()
                        self.assertEqual(before, self.output_state())
                        self.sessions.assert_not_called()

    def test_ordinary_peer_cache_does_not_exempt_actual_manager_from_m4(self):
        self.ordinary_leaf_inventory()
        with self.copied_app("leaf", real_location=True):
            code, _ = self.invoke("--generate-json")
            self.assertEqual(0, code)
            self.master.write_text(self.master.read_text().replace("192.0.2.10", "192.0.2.99"))
            for cached in (True, False):
                with self.subTest(cached=cached):
                    if not cached:
                        (self.root / "targets.json").unlink()
                    before = self.output_state()
                    with mock.patch.object(self.app.socket, "gethostname", return_value="example-manager01"), \
                         mock.patch.object(self.app.socket, "getfqdn", return_value="example-manager01.example.test"):
                        code, out = self.invoke("--plan", "--execution-mode", "auto")
                    self.assertEqual(2, code)
                    self.assertIn("INVENTORY MISMATCH: example-ib01; eth0_ip;", out)
                    self.assertEqual(before, self.output_state())
                    self.sessions.assert_not_called()

    def test_source_role_survives_bad_inputs_and_runtime_direct_overlay(self):
        self.ordinary_leaf_inventory(mac="")
        with self.copied_app("leaf", real_location=True):
            ib, eth = self.read()
            targets = self.app.build_targets(self.app.parse_p2p(self.p2p), ib, eth)
            with mock.patch.object(self.app.socket, "gethostname", return_value="example-leaf01"), \
                 mock.patch.object(self.app.socket, "getfqdn", return_value="example-leaf01.example.test"):
                self.assertEqual({"example-leaf01"}, self.app.local_ethernet_keys(targets, "auto", ""))
                overlaid = self.app._runtime_routes(targets, frozenset({"example-ib01"}), emit=lambda _line: None)
                self.assertEqual({"example-leaf01"}, self.app.local_ethernet_keys(overlaid, "auto", ""))
            self.assertEqual(("example-leaf01", "eth", "swp7"), self.source_tuple(overlaid[0]))
            self.assertEqual("DIRECT_ACCESS", overlaid[0].route.reason)
            code, _ = self.invoke("--generate-json", "--direct-access", "all")
            self.assertEqual(0, code)
            payload = json.loads((self.root / "targets.json").read_text())
            self.assertEqual("PEER_NOT_JUMP", payload["routes"]["example-ib01"]["reason"])
            self.assertEqual({"example-ib01": {"peer": "example-leaf01", "peer_type": "eth", "port": "swp7"}},
                             payload.get("source_attachments"))

    def test_unknown_peer_source_is_retained_but_does_not_grant_leaf_identity(self):
        self.p2p.write_text("a-node,a-port,z-node,z-port\nexample-ib01,eth0,unknown-leaf,7\n")
        with self.copied_app("leaf", real_location=True):
            ib, eth = self.read()
            targets = self.app.build_targets(self.app.parse_p2p(self.p2p), ib, eth)
            self.assertEqual(("unknown-leaf", "", "swp7"), self.source_tuple(targets[0]))
            with mock.patch.object(self.app.socket, "gethostname", return_value="unknown-leaf"), \
                 mock.patch.object(self.app.socket, "getfqdn", return_value="unknown-leaf.example.test"):
                self.assertEqual(set(), self.app.local_ethernet_keys(targets, "auto", ""))

    def managed_inventory_observation(self, *, different_decoy=False):
        """Real bound project/M4, stopped immediately after inventory admission."""
        authority = load_script("wp1_managed_inventory_" + self.root.name.replace("-", "_"),
                                ROOT / "ztp/config_sync_authority.py")
        cycle = authority.ManagedInitialMethodCycle(self.project, self.app)
        decoy = self.root / "forwarded-project"
        decoy.mkdir()
        decoy_csv = self.csv.read_text()
        if different_decoy:
            decoy_csv = decoy_csv.replace("192.0.2.10", "192.0.2.99")
        (decoy / "02-devices_config.csv").write_text(decoy_csv)
        records, opened = [], []
        compare, original_open = self.app._compare_inventory, Path.open

        def observe_compare(*args, **kwargs):
            record = compare(*args, **kwargs)
            records.append(record)
            return record

        def observe_open(path, *args, **kwargs):
            opened.append(Path(path).resolve())
            return original_open(path, *args, **kwargs)

        argv = [str(INITIAL), "--ib-csv", str(self.csv), "--p2p", str(self.p2p),
                "--project-dir", str(decoy), "--execution-mode", "management", "--apply", "--yes",
                "--target-cache", str(self.root / "targets.json"),
                "--report", str(self.root / "report.log"),
                "--snapshot-dir", str(self.root / "snapshots")]
        before, output = self.output_state(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), redirect_stdout(output), redirect_stderr(output), \
             mock.patch.object(Path, "open", observe_open), \
             mock.patch.object(self.app, "_compare_inventory", side_effect=observe_compare), \
             mock.patch.object(self.app, "resolve_host_key_refresh_selector", side_effect=self.app.SetupError(
                 "PUBLIC managed inventory admitted; stop before outputs")) as next_stage, \
             mock.patch.object(cycle, "admit_paths", wraps=cycle.admit_paths) as admit:
            with self.assertRaises(self.app.SetupError) as stopped:
                self.app.main(method_cycle=cycle)
        self.close_report()
        self.assertEqual(before, self.output_state())
        self.sessions.assert_not_called()
        admit.assert_not_called()
        self.assertEqual([], [path for path in opened if path.is_relative_to(decoy)])
        return records, next_stage, str(stopped.exception), output.getvalue()

    def test_managed_inventory_rejects_own_mismatch_despite_valid_forwarded_master(self):
        self.master.write_text(self.master.read_text().replace("192.0.2.10", "192.0.2.11"))
        records, next_stage, error, output = self.managed_inventory_observation()
        self.assertEqual([], records)
        next_stage.assert_not_called()
        self.assertIn("inventory", error.lower())
        self.assertIn("192.0.2.10", output)

    def test_managed_inventory_rejects_missing_own_master_despite_valid_forwarded_master(self):
        self.master.unlink()
        records, next_stage, error, _ = self.managed_inventory_observation()
        self.assertEqual([], records)
        next_stage.assert_not_called()
        self.assertIn(str(self.master), error)

    def test_managed_inventory_compares_bound_project_not_forwarded_project(self):
        records, next_stage, error, _ = self.managed_inventory_observation(different_decoy=True)
        self.assertEqual([{"status": "compared",
                           "subset_sha256": hashlib.sha256(self.csv.read_bytes()).hexdigest(),
                           "master_sha256": hashlib.sha256(self.master.read_bytes()).hexdigest()}], records)
        next_stage.assert_called_once()
        self.assertEqual("PUBLIC managed inventory admitted; stop before outputs", error)

    def test_bad_input_and_unusable_jump_do_not_prevent_healthy_peer_dispatch(self):
        # WP1/WP5 boundary: real MAIN -> snapshot qualification -> real queue
        # -> report/summary. Only transport observations and the final per-device
        # executor are replaced; this does not claim SSH/identity verification.
        self.write_inventory([self.ib(), self.ib("example-ib02", "192.0.2.12", ""),
            self.ib("example-ib03", "192.0.2.13", "02:00:00:00:00:13"),
            self.jump(), self.jump("example-jump02", eth0_ip="bad")])
        self.p2p.write_text("a-node,a-port,z-node,z-port\n"
            "example-ib01,eth0,example-jump01,swp7\n"
            "example-ib02,eth0,example-jump01,swp8\n"
            "example-ib03,eth0,example-jump02,swp9\n")
        sessions = mock.Mock()
        sessions.records = {}
        sessions.probe_jump_key.return_value = "key"
        dispatched = []

        def execute(task, *_args):
            dispatched.append((task.target.ib.hostname, task.target.ethernet.hostname,
                               task.neighbor.ipv6, task.neighbor.mac,
                               task.neighbor.interface, task.neighbor.address_source))
            return {"outcome": "CHECK_ONLY", "reason": "PUBLIC WP1 dispatch observation",
                    "direct_rows": [], "stage_status": {}}

        links = "7: swp7: <UP> mtu 1500 state UP\n    link/ether 02:00:00:00:01:07\n"
        fdb = "02:00:00:00:00:10 dev swp7 dynamic\n"
        # r757 WP2: swp7 is a routed port; the third snapshot is the VLAN table, not NDP.
        vlans = "port              vlan-id\n"
        with mock.patch.object(self.app, "_new_jump_sessions", return_value=sessions), \
             mock.patch.object(self.app, "collect_ethernet_interfaces", return_value=(
                 "example-jump01", "Interface Admin Oper\nswp7 up up\n")) as interfaces, \
             mock.patch.object(self.app, "collect_ethernet_network_tables", return_value=(
                 links, fdb, vlans)) as network, \
             mock.patch.object(self.app, "interface_vrf", return_value="default"), \
             mock.patch.object(self.app, "resolve_initial_ib_password", return_value="PUBLIC-fixture-only"), \
             mock.patch.object(self.app.multiprocessing, "get_context", side_effect=AssertionError(
                 "this three-IB WP1 observer must stay in the real single inline slot")), \
             mock.patch.object(self.app, "execute_ib_task", side_effect=execute):
            code, out = self.invoke()
        self.assertEqual(2, code, "one healthy check-only task does not make three devices configured")
        # Independent EUI-64 for PUBLIC 02:00:00:00:00:10; flip U/L and insert ff:fe.
        self.assertEqual([("example-ib01", "example-jump01", "fe80::ff:fe00:10",
                           "02:00:00:00:00:10", "swp7", "CSV_EUI64")], dispatched)
        self.assertEqual(1, interfaces.call_count)
        self.assertEqual("example-jump01", interfaces.call_args.args[0].hostname)
        self.assertEqual(1, network.call_count)
        self.assertEqual("example-jump01", network.call_args.args[0].hostname)
        self.assertIn("SKIPPED_INPUT_INCOMPLETE", out)
        self.assertIn("SKIPPED_JUMP_ADDRESS_INVALID", out)
        sessions.close_jump_masters.assert_called_once_with()
        summaries = list(self.root.glob("devices-*/summary.json"))
        self.assertEqual(1, len(summaries))
        payload = json.loads(summaries[0].read_text())
        self.assertEqual("INCOMPLETE", payload["result"])
        self.assertEqual({"example-ib01", "example-ib02", "example-ib03"}, set(payload["records"]))
        self.assertEqual("CHECK_ONLY", payload["records"]["example-ib01"]["outcome"])
        self.assertEqual("SKIPPED_INPUT_INCOMPLETE", payload["records"]["example-ib02"]["category"])
        self.assertEqual("SKIPPED_JUMP_ADDRESS_INVALID", payload["records"]["example-ib03"]["category"])
        for host in ("example-ib01", "example-ib02", "example-ib03"):
            self.assertIs(False, payload["records"][host]["writes_attempted"])
            self.assertEqual("JUMP_LINK", payload["records"][host]["route"]["reason"])
            self.assertFalse(payload["records"][host].get("script_error", False))
        self.assertEqual("eth0_mac", payload["input_issues"]["example-ib02"][0]["field"])
