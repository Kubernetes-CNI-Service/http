"""ufm-setup-upgrade under I-037 (v3.1.6 B0, WP-3 to WP-5): the inventory check against 02, inputs judged per
UFM, the route of every UFM decided before any login, the jump path and the direct path.

Expected values come from 需求文档 R-016 (:970-977), 问题文档 I-037 (:1544-1656) and I-054 (:1867-1874), the I-037
design rules 1-8 and the v3.1.6 guide (B0-O1..O13); each assertion names its source.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_cases.test_ufm_setup_upgrade as tufm

ufm = tufm.ufm
U1, U2 = "ufm01.site01.example.test", "ufm02.site01.example.test"
UFM01_NO_GW = tufm.UFM01.replace("198.51.101.254", "")


class Terminal:
    @staticmethod
    def isatty():
        return True


def write_inventory(directory, rows, master_rows=None):
    """ib.csv and the master 02 beside it (B0-O6 (b): an explicit --input-dir holds its own 02)."""
    directory = Path(directory)
    (directory / "ib.csv").write_text(tufm.HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    (directory / "02-devices_config.csv").write_text(
        tufm.HEADER + "\n" + "\n".join(rows if master_rows is None else master_rows) + "\n", encoding="utf-8")


class UfmCliCase(tufm.FakeSshCase):
    """main() end to end against the fake ssh, switch and UFM tools of test_ufm_setup_upgrade."""

    def write_rows(self, rows, master_rows=None):
        write_inventory(self.inputs, rows, master_rows)

    def run_cli(self, argv):
        if not self.state_path.exists():
            self.state.setdefault("image_url", tufm.IMAGE_URL)
            self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        calls_path = Path(str(self.state_path) + ".calls")
        if calls_path.exists():
            calls_path.write_text("")
        logs = self.inputs / ufm.LOGS_NAME
        before = set(logs.glob("*")) if logs.exists() else set()
        prompts, out = [], io.StringIO()
        with mock.patch.object(ufm, "read_secret", side_effect=lambda text: prompts.append(text) or self.NEW), \
                mock.patch.object(sys, "stdin", Terminal()), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(out):
            code = ufm.main(["--input-dir", str(self.inputs)] + argv)
        runs = sorted(path for path in (set(logs.glob("*")) if logs.exists() else set()) - before)
        calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
        return code, out.getvalue(), prompts, runs, calls

    def login_with(self, **kwargs):
        """run_login on the state as this test has set it now (a fresh calls log each time)."""
        self.state.setdefault("image_url", tufm.IMAGE_URL)
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        calls_path = Path(str(self.state_path) + ".calls")
        if calls_path.exists():
            calls_path.write_text("")
        return self.run_login(**kwargs)

    @staticmethod
    def leaf_calls(calls, address="203.0.112.119"):
        return [call["remote"] for call in calls if call["target"] == f"cumulus@{address}"]

    @staticmethod
    def logins(calls, link_local):
        return [call for call in calls if "ssh -6" in call["remote"] and f"root@{link_local}" in call["remote"]]

    @staticmethod
    def nodes_of(run):
        return {item["hostname"]: item for item in json.loads((run / "result.json").read_text())["nodes"]}

    @staticmethod
    def touched(calls, *needles):
        return [call for call in calls if any(needle in call["target"] or needle in call["remote"]
                                              for needle in needles)]


class UfmLoginRouteTests(UfmCliCase):
    # ---------------------------------------------------------------- WP-3: inventory check against 02

    def test_inventory_mismatch_exits_2_before_any_prompt(self):
        # 需求文档 :974-976 (R-016): every script with changes compares ib.csv with 02 when run by hand, the
        # read-only mode too; a difference prints where and exits 2 (B0-O12); v3.1.4 指导 :1065 (A2 format).
        master = [row.replace("198.51.101.254,02:00:00:00:02:01", "198.51.101.253,02:00:00:00:02:01")
                  for row in tufm.OTHER_ROWS + [tufm.UFM01, tufm.UFM02]]
        self.write_rows(tufm.OTHER_ROWS + [tufm.UFM01, tufm.UFM02], master)
        # bounded upgrade waits: a run that passed the check by mistake must not sleep for minutes
        for argv in (["check"], ["check", "--inputs-only"],
                     ["config-upgrade", "--apply", "--yes", "--wait-initial", "0", "--wait-max", "60"],
                     ["ha-setup", "--apply", "--yes"], ["ha-post-config", "--apply", "--yes"]):
            with self.subTest(argv=argv):
                code, out, prompts, runs, calls = self.run_cli(argv)
                self.assertEqual(code, 2, out)
                self.assertIn(f"INVENTORY MISMATCH: {U2}; eth0_gw; ib.csv=198.51.101.254; 02=198.51.101.253; value",
                              out)
                self.assertEqual((prompts, runs, calls), ([], [], []), "nothing asked, no run directory, no session")
        code, out, _prompts, _runs, _calls = self.run_cli(["check", "--inputs-only", "--inventory-checked"])
        self.assertEqual(code, 0, out)   # 需求文档 :976: bringup has already compared (--inventory-checked)
        self.assertNotIn("INVENTORY MISMATCH", out)
        # 需求文档 :974: ib.csv that is the same file as 02 passes; P3b point 10: eth in 02 -> eth_jump allowed
        self.write_rows(tufm.OTHER_ROWS + [tufm.UFM01, tufm.UFM02],
                        [row.replace("oob-leaf117,eth_jump,", "oob-leaf117,eth,") for row in
                         tufm.OTHER_ROWS + [tufm.UFM01, tufm.UFM02]])
        code, out, _prompts, _runs, _calls = self.run_cli(["check", "--inputs-only"])
        self.assertEqual(code, 0, out)
        (self.inputs / "ib.csv").unlink()
        (self.inputs / "ib.csv").symlink_to("02-devices_config.csv")
        code, out, _prompts, _runs, _calls = self.run_cli(["check", "--inputs-only"])
        self.assertEqual(code, 0, out)

    def test_master_inventory_location(self):
        # B0-O6 (b); 需求文档 :976; v3.1.4 指导 :1065: an explicit --input-dir uses its own 02, never the
        # repository's; without one, 02 must be readable or the run exits 2 naming the path.
        master = self.inputs / "02-devices_config.csv"
        master.unlink()
        code, out, prompts, runs, calls = self.run_cli(["check"])
        self.assertEqual(code, 2, out)
        self.assertIn(str(master), out)
        self.assertEqual((prompts, runs, calls), ([], [], []))
        master.mkdir()
        code, out, prompts, runs, _calls = self.run_cli(["check", "--inputs-only"])
        self.assertEqual(code, 2, out)
        self.assertIn(str(master), out)
        self.assertEqual((prompts, runs), ([], []))
        with tempfile.TemporaryDirectory() as tmp:
            tool = tufm.standalone_tool(tmp)
            tufm.make_inputs(tool)
            repository_master = Path(tmp) / "infiniband/02-devices_config.csv"
            (tool / "02-devices_config.csv").write_text("hostname,type\nother,eth\n", encoding="utf-8")
            env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
            run = lambda *extra: subprocess.run(   # noqa: E731
                [sys.executable, "-B", str(tool / tufm.SCRIPT.name), *extra, "check", "--inputs-only"],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=60)
            default = run()
            self.assertEqual(default.returncode, 0, default.stdout + default.stderr)   # <repo>/infiniband/02
            repository_master.write_text(repository_master.read_text().replace("02:00:00:00:02:01", "02:00:00:00:02:09"))
            default = run()
            self.assertEqual(default.returncode, 2, default.stdout + default.stderr)
            self.assertIn("INVENTORY MISMATCH", default.stdout + default.stderr)
            (tool / "02-devices_config.csv").unlink()
            repository_master.write_text((tool / "ib.csv").read_text())
            explicit = run("--input-dir", str(tool))
            self.assertEqual(explicit.returncode, 2, explicit.stdout + explicit.stderr)
            self.assertIn(str(tool / "02-devices_config.csv"), explicit.stdout + explicit.stderr)

    # ---------------------------------------------------------------- WP-3: --direct-access

    def test_direct_access_selector(self):
        # I-037 设计 :54; 问题文档 :1562; D1b-O17 (a): matched against every server_ufm, --node or not;
        # an item that matches nothing exits 2 before any device is touched.
        for value, direct in (("ufm*", {U1, U2}), ("ufm0[1-2]", {U1, U2}), ("all", {U1, U2}), ("ufm01", {U1})):
            with self.subTest(value=value):
                code, out, _prompts, _runs, _calls = self.run_cli(["check", "--inputs-only", "--direct-access", value])
                self.assertEqual(code, 0, out)
                for host in (U1, U2):
                    reason = "DIRECT_ACCESS" if host in direct else "JUMP_LINK"
                    self.assertRegex(out, rf"(?m)^.*{host}.*\b{reason}\b", host)
        code, out, _prompts, _runs, _calls = self.run_cli(
            ["check", "--inputs-only", "--node", "ufm01", "--direct-access", "ufm02"])
        self.assertEqual(code, 0, out)
        self.assertRegex(out, rf"(?m)^.*{U2}.*\bDIRECT_ACCESS\b")
        for value in ("ufm09", "oob-leaf117"):
            with self.subTest(value=value):
                code, out, prompts, runs, calls = self.run_cli(["check", "--direct-access", value])
                self.assertEqual(code, 2, out)
                self.assertIn("--direct-access", out)
                self.assertIn(value, out)
                self.assertEqual((prompts, runs, calls), ([], [], []))

    # ---------------------------------------------------------------- WP-3: inputs per UFM

    def test_one_node_input_issue_skips_only_that_node(self):
        # I-037 设计 :11, :62; 问题文档 :1619「我们不能因为一台设备的信息问题影响其他设备的操作。」, :1621, :1643
        cases = {"eth0_gw": UFM01_NO_GW,
                 "eth0_gw outside": tufm.UFM01.replace("198.51.101.254", "198.51.102.1"),
                 "eth0_mac": tufm.UFM01.replace("02:00:00:00:01:01", ""),
                 "eth0_mac bad": tufm.UFM01.replace("02:00:00:00:01:01", "02:00:00:00:01")}
        for case, row in cases.items():
            with self.subTest(case=case):
                self.write_rows(tufm.OTHER_ROWS + [row, tufm.UFM02])
                code, out, _prompts, _runs, _calls = self.run_cli(["check", "--inputs-only"])
                self.assertEqual(code, 1, out)   # B0-O7 (a): per-node issues leave nothing to do -> unfinished
                self.assertRegex(out, rf"(?m)^.*{U1}.*INPUT_INCOMPLETE.*{case.split()[0]}")
                code, out, _prompts, runs, calls = self.run_cli(["check"])
                self.assertEqual(code, 1, out)
                self.assertTrue(runs, "the run goes on for the other UFM: " + out)
                nodes = self.nodes_of(runs[-1])
                self.assertEqual(nodes[U1]["status"], "INPUT_INCOMPLETE")
                self.assertIn(case.split()[0], nodes[U1]["detail"])
                self.assertEqual(self.touched(calls, "198.51.101.130", tufm.UFM01_LL), [], "no session for ufm01")
                self.assertTrue(self.touched(calls, "198.51.101.132", tufm.UFM02_LL), "ufm02 is checked as usual")

    def test_ufm_side_eth0_rules_survive_the_shared_check(self):
        # WP-3 item 4 point 2 (v3.1.6 指导 :1194): /23 and 23 stay equivalent; a gateway equal to eth0_ip and an
        # address prefix that differs from the netmask column stay this UFM's blocking problems.
        with tempfile.TemporaryDirectory() as tmp:
            plan = ufm.build_plan(tufm.make_inputs(tmp, csv_rows=tufm.OTHER_ROWS + [
                tufm.UFM01.replace(",23,", ",/23,"), tufm.UFM02]))
        self.assertEqual(plan.errors, [])
        self.assertEqual([node.hostname for node in plan.nodes], [U1, U2])
        for case, row in (("eth0_gw", tufm.UFM01.replace(",198.51.101.254,", ",198.51.101.130,")),
                          ("netmask", tufm.UFM01.replace("198.51.101.130,23", "198.51.101.130/24,23"))):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                plan = ufm.build_plan(tufm.make_inputs(tmp, csv_rows=tufm.OTHER_ROWS + [row, tufm.UFM02]))
                self.assertEqual(plan.errors, [])
                self.assertEqual([node.hostname for node in plan.nodes], [U2])
                self.assertIn(case, "; ".join(plan.incomplete[U1]))

    def test_cross_node_conflicts_skip_involved_nodes(self):
        # 问题文档 :1619; D1b-O9 (b); B0-O7 (a): only the UFMs involved are skipped, a VIP clash stays whole-run.
        def plan_of(rows=None, p2p_rows=tufm.P2P_ROWS):
            with tempfile.TemporaryDirectory() as tmp:
                return ufm.build_plan(tufm.make_inputs(tmp, csv_rows=rows, p2p_rows=p2p_rows))
        twin = plan_of(tufm.OTHER_ROWS + [tufm.UFM01, tufm.UFM02.replace("02:00:00:00:02:01", "02:00:00:00:01:01")])
        self.assertEqual(twin.errors, [])
        self.assertEqual(twin.nodes, [])
        self.assertIn(U2, "; ".join(twin.incomplete[U1]))
        self.assertIn(U1, "; ".join(twin.incomplete[U2]))
        clash = "oob-leaf119,eth_jump,NA,198.51.101.130,23,203.0.113.254,02:00:00:00:a1:19,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
        taken = plan_of(tufm.OTHER_ROWS + [clash, tufm.UFM01, tufm.UFM02])
        self.assertEqual(taken.errors, [])
        self.assertEqual([node.hostname for node in taken.nodes], [U2])
        self.assertIn("oob-leaf119 eth0_ip", "; ".join(taken.incomplete[U1]))
        vip_on_switch = "oob-leaf119,eth_jump,NA,198.51.101.133,23,203.0.113.254,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
        vip = plan_of(tufm.OTHER_ROWS + [vip_on_switch, tufm.UFM01, tufm.UFM02])
        self.assertTrue([error for error in vip.errors if "198.51.101.133（vip）" in error], vip.errors)
        doubled = plan_of(p2p_rows=tufm.P2P_ROWS + [["ufm-01", "eno8303", "oob-leaf115", "40"]])
        self.assertEqual(doubled.errors, [])
        self.assertEqual([node.hostname for node in doubled.nodes], [U2])
        self.assertIn("管理口", "; ".join(doubled.incomplete[U1]))
        apart = plan_of(tufm.OTHER_ROWS + [tufm.UFM01, tufm.UFM02.replace("198.51.101.132,23,198.51.101.254",
                                                                          "198.51.105.132,23,198.51.105.254")])
        self.assertEqual(apart.errors, [])
        self.assertEqual(apart.nodes, [])
        self.assertEqual(set(apart.incomplete), {U1, U2})

    def test_ha_setup_with_one_incomplete_node_touches_neither(self):
        # I-037 设计 :187「HA 步骤仍要两台都就绪」; B0-O7 (a); 核对 A, A-M4
        self.write_rows(tufm.OTHER_ROWS + [UFM01_NO_GW, tufm.UFM02])
        code, out, _prompts, runs, calls = self.run_cli(["ha-setup", "--apply", "--yes"])
        self.assertEqual(code, 1, out)
        self.assertTrue(runs, out)
        nodes = self.nodes_of(runs[-1])
        self.assertEqual(nodes[U1]["status"], "INPUT_INCOMPLETE")
        self.assertEqual((nodes[U2]["status"], nodes[U2]["detail"]), ("INPUT_ERROR", "HA 需要两台 UFM"))
        self.assertEqual(calls, [], "no session, no address probe of the VIP")

    def test_an_incomplete_peer_keeps_the_pair_netplan_shape(self):
        # v3.1.6 指导 8.6 (RV31-42), B6-O1: the pair facts come from the server_ufm rows before any filter.
        with tempfile.TemporaryDirectory() as tmp:
            plan = ufm.build_plan(tufm.make_inputs(tmp, csv_rows=tufm.OTHER_ROWS + [UFM01_NO_GW, tufm.UFM02]))
            self.assertEqual(plan.errors, [])
            self.assertEqual([node.hostname for node in plan.nodes], [U2])
            self.assertIn(U1, plan.incomplete)
            self.assertEqual(plan.source_ufm_count, 2)
            ha_link = ufm.node_netplan(plan, plan.nodes[0])["network"]["ethernets"]["eno8403"]
            self.assertIs(ha_link.get("ignore-carrier"), True)
            self.assertEqual(ha_link["addresses"], ["192.0.2.2/30"], "the secondary role block of global")
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            session = ufm.Session(plan, ufm.Credentials("root", self.NEW, "", "cumulus"), 5, run_dir,
                                  lambda _text: None, lambda: "", apply=True)
            results = session.ha_setup(plan.nodes)
        self.assertEqual([(item.hostname, item.status, item.detail) for item in results],
                         [(U2, "INPUT_ERROR", "HA 需要两台 UFM")])

    def test_a_mac_owned_by_another_row_is_found_in_any_spelling(self):
        # P3b :163 (B0 reads other rows' MACs through tools/device_identity); B0-O7 (a); 核对 A, A-L11
        for spelling in ("02-00-00-00-02-01", "0200.0000.0201", "020000000201"):
            row = f"oob-leaf119,eth_jump,NA,203.0.112.121,23,203.0.113.254,{spelling},,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
            with self.subTest(spelling=spelling), tempfile.TemporaryDirectory() as tmp:
                plan = ufm.build_plan(tufm.make_inputs(tmp, csv_rows=tufm.OTHER_ROWS + [row, tufm.UFM01, tufm.UFM02]))
                self.assertEqual(plan.errors, [])
                self.assertEqual([node.hostname for node in plan.nodes], [U1])
                self.assertIn("oob-leaf119 eth0_mac", "; ".join(plan.incomplete[U2]))

    # ---------------------------------------------------------------- WP-3: route classes

    def test_only_jump_types_are_jumps(self):
        # 问题文档 :1563, :1579, owner :1656 (only a type ending in jump is a jump); D1b-O21 (a); B0-O11 (a)
        eth_leaf = "oob-leaf117,eth,NA,,,,02:00:00:00:A1:17,,,,02:00:00:00:A1:18,,,,,,,,,,,,,,,,,,,,,,,,,"
        rows = [row for row in tufm.OTHER_ROWS if not row.startswith("oob-leaf117,")] + [eth_leaf]
        self.write_rows(rows + [tufm.UFM01, tufm.UFM02])
        code, out, _prompts, _runs, _calls = self.run_cli(["check", "--inputs-only"])
        self.assertEqual(code, 0, out)   # the eth row has no login address and that is no error
        for host in (U1, U2):
            self.assertRegex(out, rf"(?m)^.*{host}.*\bPEER_NOT_JUMP\b")
        # B0-O11 (a): management port and BMC on eth Leafs: both read-only switch checks are UNCHECKED and
        # neither Leaf is logged into (UFM README :186-187: what cannot be read is UNCHECKED)
        bmc_leaf = "oob-leaf115,eth,NA,,,,02:00:00:00:A1:15,,,,02:00:00:00:A1:16,,,,,,,,,,,,,,,,,,,,,,,,,"
        rows = [row for row in rows if not row.startswith("oob-leaf115,")] + [bmc_leaf]
        self.write_rows(rows + [tufm.UFM01, tufm.UFM02])
        code, out, _prompts, runs, calls = self.run_cli(["check"])
        self.assertTrue(runs, out)
        self.assertEqual([call for call in calls if call["target"].startswith("cumulus@")], [])
        for host, item in self.nodes_of(runs[-1]).items():
            self.assertEqual({check["outcome"] for check in item["facts"]["address_check"]}, {"UNCHECKED"}, host)
        self.write_rows(tufm.OTHER_ROWS + [tufm.UFM01, tufm.UFM02])
        code, out, _prompts, _runs, _calls = self.run_cli(["check", "--inputs-only"])
        self.assertEqual(code, 0, out)
        for host in (U1, U2):
            self.assertRegex(out, rf"(?m)^.*{host}.*\bJUMP_LINK\b.*oob-leaf117")

    def test_routes_classified_and_printed_before_login(self):
        # I-037 设计 :67-73; 问题文档 :1561: the table (device, path, jump and port, reason, same subnet, skip
        # reason) comes before any session and is kept in report.log and result.json.
        rows = [row for row in tufm.P2P_ROWS if row[:2] != ["ufm-02", "8303"]]
        tufm.write_xlsx(self.inputs / "p2p.xlsx", rows)
        code, out, _prompts, _runs, _calls = self.run_cli(["check", "--inputs-only"])
        self.assertEqual(code, 0, out)
        self.assertRegex(out, rf"(?m)^.*{U1}.*\bJUMP_LINK\b.*oob-leaf117.*swp17")
        self.assertRegex(out, rf"(?m)^.*{U2}.*\bNO_MGMT_LINK\b")
        code, out, _prompts, runs, _calls = self.run_cli(["check", "--direct-access", "ufm01"])
        self.assertTrue(runs, out)
        report = (runs[-1] / "report.log").read_text(encoding="utf-8")
        table = report.find("DIRECT_ACCESS")
        self.assertGreater(table, -1, report)
        self.assertLess(table, report.find("地址占用检查"), "the route table comes before any switch or UFM session")
        nodes = self.nodes_of(runs[-1])
        self.assertEqual({host: (nodes[host]["login_route"]["path"], nodes[host]["login_route"]["reason"])
                          for host in (U1, U2)},
                         {U1: ("direct", "DIRECT_ACCESS"), U2: ("direct", "NO_MGMT_LINK")})
        self.assertEqual(set(nodes[U1]["login_route"]), {"path", "reason", "jump", "port", "same_subnet", "skip"})


FDB_UFM01 = "02:00:00:00:01:01 dev swp17 vlan 1000 master br_default\n"
LEAF119 = tufm.csv_row("oob-leaf119", "eth_jump", eth0_ip="203.0.112.121", netmask="23")
LOCAL_SAME = {'addresses': [{'ifname': 'eno1', 'addr_info': [{'family': 'inet', 'local': '198.51.101.10', 'prefixlen': 23}, {'family': 'inet6', 'local': 'fe80::10', 'prefixlen': 64}]}], 'neigh': {}}
NEIGH_UFM01 = "198.51.101.130 dev eno1 lladdr 02:00:00:00:01:01 REACHABLE"


def leaf119(fdb):
    return tufm.switch_state("oob-leaf119", tufm.LEAF_INTERFACES, tufm.LEAF_LINKS, fdb, "",
                             tufm.address_rows(("eth0", "203.0.112.121/23", None, "UP")), reach=[])


class UfmJumpRouteTests(UfmCliCase):
    """WP-4: a UFM cabled to a *jump (I-037 rules 4-7; B0-O1, O3, O5, O9, O10)."""

    def leaf(self):
        return self.state["switches"]["203.0.112.119"]

    def test_jump_route_uses_csv_link_local_and_expected_port_vlan(self):
        # I-037 rules 4, 5 (设计 :14-15, :80-87): the CSV MAC's EUI-64, the SVI of the expected port's VLAN
        # (from `bridge vlan show`), never a neighbour-table address; the snapshot has no `ip neighbor`
        leaf = self.leaf()
        leaf["neigh"] = "fe80::1:2:3:4 dev vlan1000 lladdr 02:00:00:00:01:01 REACHABLE\n" + leaf["neigh"]
        leaf["links"] += ("42: vlan2000@br_default: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master oob state UP\n"
                          "    vlan protocol 802.1Q id 2000 <REORDER_HDR>\n")
        leaf["fdb"] = leaf["fdb"].replace("02:00:00:00:01:01 dev swp17 vlan 1000", "02:00:00:00:01:01 dev swp17 vlan 2000")
        results, _state, calls, _logs = self.login_with()
        one = results["ufm01"]
        self.assertEqual((one.status, one.path), ("VERIFIED", "OOB-IPv6"), one.detail)
        self.assertEqual(one.neighbor, {"ipv6": tufm.UFM01_LL, "interface": "vlan1000", "vrf": "oob",
                                        "source": "CSV_EUI64"})
        self.assertTrue(self.logins(calls, tufm.UFM01_LL))
        self.assertTrue(all("-B vlan1000" in call["remote"] for call in self.logins(calls, tufm.UFM01_LL)))
        self.assertFalse([call for call in calls if "fe80::1:2:3:4" in call["remote"]])
        remotes = self.leaf_calls(calls)
        self.assertTrue([remote for remote in remotes if "bridge vlan show" in remote])
        self.assertFalse([remote for remote in remotes if "ip neighbor" in remote])

    def test_cable_check_reports_expected_and_actual(self):
        # I-037 设计 :88-95; 问题文档 :1628-1631; B0-O10 (a): another port of the same jump, another jump; a
        # cascade port between two *jump rows is never the actual place
        self.leaf()["fdb"] = tufm.LEAF_FDB.replace("01:01 dev swp17", "01:01 dev swp20")
        results, _state, calls, logs = self.login_with()
        one = results["ufm01"]
        self.assertEqual(one.status, "CABLE_CHECK_FAILED", one.detail)
        self.assertEqual((one.facts["cabling"]["expected_port"], one.facts["cabling"]["actual_ports"]),
                         ("oob-leaf117 swp17", ["oob-leaf117 swp20"]))
        self.assertIn("预期 oob-leaf117 swp17", one.detail)
        self.assertEqual(self.logins(calls, tufm.UFM01_LL), [])
        self.assertNotIn("[y/N]", logs)
        self.assertEqual(results["ufm02"].status, "VERIFIED")

        self.write_rows(tufm.OTHER_ROWS + [LEAF119, tufm.UFM01, tufm.UFM02])
        self.leaf()["fdb"] = tufm.LEAF_FDB.replace(FDB_UFM01, "")
        self.state["switches"]["203.0.112.121"] = leaf119("02:00:00:00:01:01 dev swp5 vlan 1000 master br_default\n")
        results, _state, calls, _logs = self.login_with()
        one = results["ufm01"]
        self.assertEqual(one.status, "CABLE_CHECK_FAILED", one.detail)
        self.assertEqual(one.facts["cabling"]["actual_ports"], ["oob-leaf119 swp5"])
        self.assertEqual(self.logins(calls, tufm.UFM01_LL), [])

        tufm.write_xlsx(self.inputs / "p2p.xlsx", tufm.P2P_ROWS + [["oob-leaf117", "49", "oob-leaf119", "1"]])
        self.state["switches"]["203.0.112.121"] = leaf119("02:00:00:00:01:01 dev swp1 vlan 1000 master br_default\n")
        results, _state, _calls, _logs = self.login_with()
        one = results["ufm01"]
        self.assertEqual(one.status, "CABLE_CHECK_FAILED", one.detail)
        self.assertEqual(one.facts["cabling"]["actual_ports"], [], "the cascade port swp1 is not where the UFM is")
        self.assertIn("ping 后仍没学到", one.detail)

    def test_not_learned_pings_once_then_rereads(self):
        # I-037 设计 :99-106; 问题文档 :1633-1640; D1b-O4 (a): one ping from the expected jump, one more FDB read
        self.leaf()["fdb"] = tufm.LEAF_FDB.replace(FDB_UFM01, "")
        self.state["ping_learns"] = {tufm.UFM01_LL: ["203.0.112.119", FDB_UFM01]}
        results, _state, calls, _logs = self.login_with()
        one = results["ufm01"]
        self.assertEqual(one.status, "VERIFIED", one.detail)
        pings = [remote for remote in self.leaf_calls(calls) if " ping " in remote]
        self.assertEqual(len(pings), 1, pings)
        self.assertIn(f"ip vrf exec oob ping -6 -c 2 -W 1 {tufm.UFM01_LL}%vlan1000", pings[0])
        self.assertEqual(len([remote for remote in self.leaf_calls(calls) if "bridge fdb show" in remote]), 2)
        self.assertEqual((one.facts["cabling"]["outcome"], one.facts["cabling"]["after_ping"],
                          one.facts["cabling"]["ping_ok"]), ("MATCH", True, True))
        self.state.pop("ping_learns")
        results, _state, calls, _logs = self.login_with()
        one = results["ufm01"]
        self.assertEqual(one.status, "CABLE_CHECK_FAILED")
        self.assertIn("ping 后仍没学到", one.detail)
        self.assertIn("ping 通", one.detail)
        self.assertEqual(self.logins(calls, tufm.UFM01_LL), [])
        self.leaf()["interfaces"] = tufm.nv_interface_table([("swp17", "down", "", ""), ("swp18", "up", "", "")])
        results, _state, _calls, _logs = self.login_with()
        self.assertEqual(results["ufm01"].status, "CABLE_CHECK_FAILED")
        self.assertIn("oob-leaf117 swp17 Oper Status=down", results["ufm01"].detail)

    def test_ignore_cable_check_logs_in_via_expected_vlan(self):
        # I-037 设计 :16, :96; 问题文档 :1587 第 4 条; B0-O3 (a)
        self.leaf()["fdb"] = tufm.LEAF_FDB.replace("01:01 dev swp17", "01:01 dev swp20")
        results, _state, calls, logs = self.login_with()
        self.assertEqual(results["ufm01"].status, "CABLE_CHECK_FAILED")
        self.assertNotIn("[y/N]", logs)
        results, _state, calls, _logs = self.login_with(ignore_cable_check=True)
        one = results["ufm01"]
        self.assertEqual((one.status, one.path), ("VERIFIED", "OOB-IPv6"), one.detail)
        self.assertEqual((one.neighbor["ipv6"], one.neighbor["interface"]), (tufm.UFM01_LL, "vlan1000"))
        self.assertEqual((one.facts["cabling"]["outcome"], one.facts["cabling"]["ignored"]), ("ELSEWHERE", True))
        printed = []
        with tempfile.TemporaryDirectory() as tmp:
            ufm.summarize(ufm.parse_args(["check"]), list(results.values()), Path(tmp), printed.append)
        text = "\n".join(printed)
        self.assertIn("按 --ignore-cable-check 继续", text)
        self.assertIn("oob-leaf117 swp20", text)

    def test_jump_candidates_switch_only_on_network_failure(self):
        # D1b-O2 (v3.1.5 指导 :345); B0-O1 (a): only a network failure moves to the next candidate
        row = tufm.csv_row("oob-leaf117", "eth_jump", eth0_ip="203.0.112.119", netmask="23", vlan_id="1000",
                           svi_ip="198.19.0.117", svi_mask="24")
        self.write_rows([r for r in tufm.OTHER_ROWS if not r.startswith("oob-leaf117,")] + [row, tufm.UFM01, tufm.UFM02])
        self.state["switches"] = {"198.19.0.117": self.leaf()}
        results, _state, calls, _logs = self.login_with()
        one = results["ufm01"]
        self.assertEqual(one.status, "VERIFIED", one.detail)
        self.assertEqual((one.route["jump_address"], one.route["jump_entry"]), ("198.19.0.117", "JUMP_VLAN1000"))
        self.assertEqual(len(self.leaf_calls(calls)), 1, "eth0 was tried once, then the VLAN address stuck")
        self.state["switches"] = {"203.0.112.119": self.state["switches"]["198.19.0.117"],
                                  "198.19.0.117": self.state["switches"]["198.19.0.117"]}
        self.state["leaf_keys"] = False
        results, _state, calls, _logs = self.login_with(eth_password="", ask_eth=lambda: "")
        self.assertNotEqual(results["ufm01"].status, "VERIFIED")
        self.assertEqual(self.leaf_calls(calls, "198.19.0.117"), [], "a refusal on eth0 never tries the VLAN address")

    def test_jump_identity_by_address_and_filled_eth0_mac(self):
        # D1b-O2, O2a (a); owner 10-19 identity by address (UFM::owns_address)
        row = tufm.csv_row("oob-leaf117", "eth_jump", eth0_ip="203.0.112.119", netmask="23", vlan_id="1000",
                           svi_ip="198.19.0.117", svi_mask="24")
        others = [r for r in tufm.OTHER_ROWS if not r.startswith("oob-leaf117,")]
        self.write_rows(others + [row, tufm.UFM01, tufm.UFM02])
        leaf = self.leaf()
        leaf["addresses"] = tufm.address_rows(("eth0", "203.0.112.99/23", None, "UP"),
                                              ("vlan1000", "198.19.0.117/24", tufm.LEAF_LL, "UP"))
        self.state["switches"]["198.19.0.117"] = leaf
        results, _state, calls, _logs = self.login_with()
        self.assertEqual(results["ufm01"].status, "OOB_DISCOVERY_FAILED")
        self.assertIn("交换机身份不符", results["ufm01"].detail)
        self.assertEqual(self.leaf_calls(calls, "198.19.0.117"), [], "an identity mismatch is not a network failure")

        self.write_rows(tufm.OTHER_ROWS + [tufm.UFM01, tufm.UFM02])   # eth0_mac 02:00:00:00:A1:17 filled
        leaf["addresses"] = tufm.address_rows(("eth0", "203.0.112.119/23", None, "UP"),
                                              ("vlan1000", "198.19.0.117/24", tufm.LEAF_LL, "UP"))
        leaf["addresses"][0]["address"] = "02:00:00:00:a1:99"
        results, _state, _calls, _logs = self.login_with()
        self.assertEqual(results["ufm01"].status, "OOB_DISCOVERY_FAILED")
        self.assertIn("eth0_mac", results["ufm01"].detail)

        unfilled = "oob-leaf117,eth_jump,NA,203.0.112.119,23,203.0.113.254,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
        self.write_rows(others + [unfilled, tufm.UFM01, tufm.UFM02])
        results, _state, _calls, logs = self.login_with()
        self.assertEqual(results["ufm01"].status, "VERIFIED", results["ufm01"].detail)
        self.assertIn("跳板 eth0_mac 未填，eth0 入口只核了地址", logs)

    def test_jump_failure_never_falls_back_to_ipv4(self):
        # I-037 设计 :17, :117-118, :180; 问题文档 :1557, :1656: the key over IPv4 first, then only the jump
        self.state["switches"] = {}
        results, _state, calls, _logs = self.login_with(action="open_node")
        one = results["ufm01"]
        self.assertEqual(one.status, "JUMP_UNREACHABLE", one.detail)
        self.assertIn("oob-leaf117", one.detail)
        self.assertIn("--direct-access ufm01", one.detail)
        self.assertEqual([a for a in one.attempts if a["path"] == "IPv4"], [])
        self.assertEqual(len([call for call in calls if call["target"] == "root@198.51.101.130"]), 1,
                         "only the deployment-key attempt")
        self.state["switches"] = self.switches()
        self.state["ufms"]["ufm01"]["password"] = self.OTHER
        results, _state, calls, _logs = self.login_with(action="open_node")
        one = results["ufm01"]
        self.assertEqual(one.status, "AUTH_REJECTED", one.detail)
        self.assertIn("--direct-access ufm01", one.detail)
        self.assertEqual({a["path"] for a in one.attempts}, {"OOB-IPv6"})
        self.assertEqual(len([call for call in calls if call["target"] == "root@198.51.101.130"]), 1)


class UfmSpineRouteTests(UfmCliCase):
    """WP-4 item 6 (D1b-O1, B0-O4 (a)): the Spine variant of the jump path."""
    CSV_ROWS = tufm.OTHER_ROWS + tufm.SPINE_ROWS + [tufm.UFM01, tufm.UFM02]

    def switches(self):
        return tufm.SpineJumpLoginTest.switches(self)

    def test_spine_route_uses_csv_link_local_and_leaf_port_vlan(self):
        # D1b-O1 ①-④; v3.1.5 指导 :344: Spine choice unchanged, link-local from the CSV MAC, VLAN from the Leaf port
        spine2 = self.state["switches"]["203.0.113.202"]
        spine2["neigh"] = "fe80::2:2:2:2 dev vlan1000 lladdr 02:00:00:00:02:01 REACHABLE\n"
        results, _state, calls, _logs = self.login_with()
        for short, link_local in (("ufm01", tufm.UFM01_LL), ("ufm02", tufm.UFM02_LL)):
            item = results[short]
            self.assertEqual(item.status, "VERIFIED", item.detail)
            self.assertEqual((item.route["jump"], item.route["vlan"]), ("oob-spine02.site01.example.test", "1000"))
            self.assertEqual(item.neighbor, {"ipv6": link_local, "interface": "vlan1000", "vrf": "oob",
                                             "source": "CSV_EUI64"})
        self.assertFalse([call for call in calls if "ip neighbor" in call["remote"]])
        self.assertFalse([call for call in calls if "fe80::2:2:2:2" in call["remote"]])
        leaf = self.state["switches"]["203.0.112.119"]
        leaf["links"] = "\n".join(tufm.LEAF_LINKS.splitlines()[:9]) + "\n"   # no SVI of VLAN 1000 on the Leaf
        leaf["addresses"] = tufm.address_rows(("eth0", "203.0.112.119/23", None, "UP"))
        leaf["fdb"] = tufm.LEAF_FDB.replace(FDB_UFM01, "")
        self.state["ping_learns"] = {tufm.UFM01_LL: ["203.0.112.119", FDB_UFM01]}
        results, _state, calls, _logs = self.login_with()
        self.assertEqual(results["ufm01"].status, "VERIFIED", results["ufm01"].detail)
        self.assertEqual(results["ufm01"].route["reason"], "LEAF_SVI_MISSING")
        pings = [call for call in calls if " ping -6 " in call["remote"]]
        self.assertEqual([call["target"] for call in pings], ["cumulus@203.0.113.202"])
        self.assertIn(f"{tufm.UFM01_LL}%vlan1000", pings[0]["remote"])


class UfmDirectRouteTests(UfmCliCase):
    """WP-5: the direct path (I-037 设计 :111-114; 问题文档 :1575, :1577)."""
    U1 = U1

    def direct(self, **changes):
        self.state["ufms"]["ufm01"].update(changes)
        return self.login_with(direct_access=frozenset({U1}))

    def test_same_subnet_link_local_then_ipv4_only_when_unreachable(self):
        self.state["local"] = json.loads(json.dumps(LOCAL_SAME))
        self.state["local"]["neigh"]["198.51.101.130"] = NEIGH_UFM01
        results, _state, calls, _logs = self.direct(answers_on="198.51.101.130", ipv4="198.51.101.130/23",
                                                    expired=False, password=self.NEW)
        one = results["ufm01"]
        self.assertEqual((one.status, one.path), ("VERIFIED", "IPv4"), one.detail)
        self.assertEqual([(a["path"], a["outcome"]) for a in one.attempts], [("LINK-LOCAL", "UNREACHABLE"), ("IPv4", "OK")])
        self.assertTrue([call for call in calls if call["target"] == f"root@{tufm.UFM01_LL}%eno1"])
        for change, status in (({"local_link": True, "password": self.OTHER}, "AUTH_REJECTED"),
                               ({"local_link": True, "reported_mac": "02:00:00:00:01:02"}, "IDENTITY_MISMATCH")):
            with self.subTest(status=status):
                results, _state, _calls, _logs = self.direct(**change)
                self.assertEqual(results["ufm01"].status, status)
                self.assertEqual({a["path"] for a in results["ufm01"].attempts}, {"LINK-LOCAL"})
                self.state["ufms"]["ufm01"].update(password=self.NEW, reported_mac="02:00:00:00:01:01")

    def test_ipv4_after_link_local_needs_matching_arp(self):
        # I-037 设计 :113; v3.1.5 WP-3 item 1: the server's neighbour entry must carry the CSV MAC
        self.state["local"] = json.loads(json.dumps(LOCAL_SAME))
        self.state["local"]["neigh"]["198.51.101.130"] = NEIGH_UFM01.replace("02:00:00:00:01:01", "02:aa:bb:cc:dd:ee")
        results, _state, calls, _logs = self.direct(answers_on="198.51.101.130", ipv4="198.51.101.130/23",
                                                    expired=False, password=self.NEW)
        self.assertEqual(results["ufm01"].status, "IDENTITY_MISMATCH")
        self.assertEqual([call for call in calls if call["target"] == "root@198.51.101.130"], [])
        self.state["local"]["neigh"] = {}
        self.state["local"]["ping_learns"] = {"198.51.101.130": NEIGH_UFM01}
        results, state, _calls, _logs = self.direct()
        self.assertEqual((results["ufm01"].status, results["ufm01"].path), ("VERIFIED", "IPv4"))
        self.assertEqual(state["local"]["pings"], ["198.51.101.130"], "one ping, then the entry is read again")
        self.state["local"] = json.loads(json.dumps(LOCAL_SAME))
        results, state, calls, _logs = self.direct()
        self.assertEqual(results["ufm01"].status, "UNREACHABLE")
        self.assertEqual(state["local"]["pings"], ["198.51.101.130"])
        self.assertEqual([call for call in calls if call["target"] == "root@198.51.101.130"], [])

    def test_other_subnet_or_no_ip_command_goes_to_ipv4(self):
        # I-037 设计 :111, :114: another subnet, or no `ip` on this server, is IPv4 first
        for local in (None, {"addresses": [{"ifname": "eno1", "addr_info": [
                {"family": "inet", "local": "192.0.2.10", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::10", "prefixlen": 64}]}], "neigh": {}}):
            with self.subTest(local=local):
                self.state.pop("local", None)
                if local is not None:
                    self.state["local"] = local
                results, _state, calls, _logs = self.direct(answers_on="198.51.101.130", ipv4="198.51.101.130/23",
                                                            expired=False, password=self.NEW)
                self.assertEqual(results["ufm01"].attempts[0]["path"], "IPv4")
                self.assertFalse([call for call in calls if "%" in call["target"]])


class UfmKeyLoginRouteTests(tufm.ConfiguredPairCase):
    """WP-4 item 5 and WP-5 on two configured UFMs that take the deployment key."""

    def fresh(self, **kwargs):
        self.state_path.write_text(json.dumps(dict(self.state, image_url=tufm.IMAGE_URL)), encoding="utf-8")
        calls_path = Path(str(self.state_path) + ".calls")
        if calls_path.exists():
            calls_path.write_text("")
        return self.run_login(**kwargs)

    def test_cable_check_runs_before_login_in_check(self):
        # B0-O9 (a) (00 原则 :30, no check is dropped): check and config-upgrade check the cabling of a jump-routed
        # UFM before logging in, even when the key works; a --direct-access UFM is not checked
        results, _state, calls, _logs = self.fresh(action="check", apply=False)
        self.assertEqual({item.facts["cabling"]["outcome"] for item in results.values()}, {"MATCH"})
        targets = [call["target"] for call in calls]
        first_fdb = next(i for i, call in enumerate(calls) if "bridge fdb show" in call["remote"])
        self.assertLess(first_fdb, targets.index("root@198.51.101.130"))
        results, _state, _calls, _logs = self.fresh(action="check", apply=False, direct_access=frozenset({U1}))
        self.assertEqual(results["ufm01"].facts["cabling"]["outcome"], "UNCHECKED")
        self.assertIn("--direct-access", results["ufm01"].facts["cabling"]["detail"])
        self.assertEqual(results["ufm02"].facts["cabling"]["outcome"], "MATCH")

    def test_identity_checks_address_mask_gateway_on_both_ipv4_paths(self):
        # 问题文档 :1565, :1568-1569; I-037 设计 :124-126: both IPv4 paths check address, netmask and gateway
        one = self.state["ufms"]["ufm01"]
        for change in ({"ipv4": "198.51.101.130/24"},
                       {"default": "default via 198.51.101.1 dev eno8303 proto static"}):
            with self.subTest(change=change):
                saved = dict(one)
                one.update(change)
                results, state, _calls, _logs = self.fresh(action="config_upgrade_all")
                self.assertEqual(results["ufm01"].status, "IDENTITY_MISMATCH", results["ufm01"].detail)
                self.assertEqual(results["ufm01"].path, "IPv4-KEY")
                self.assertNotIn("applied", state["ufms"]["ufm01"], "nothing written")
                one.clear()
                one.update(saved)
        one["default"] = ""
        results, _state, _calls, _logs = self.fresh(action="open_node")
        self.assertEqual(results["ufm01"].status, "VERIFIED", "no default route passes")
        one["default"] = self.state["ufms"]["ufm02"]["default"]
        one["files"].pop("root/.ssh/authorized_keys")
        (self.sandbox / "ufm01/root/.ssh/authorized_keys").unlink()   # the deployment key is gone from ufm01
        one["ipv4"] = "198.51.101.130/24"
        results, _state, _calls, _logs = self.fresh(action="open_node", direct_access=frozenset({U1}))
        self.assertEqual((results["ufm01"].status, results["ufm01"].path), ("IDENTITY_MISMATCH", "IPv4"))
        results, _state, _calls, _logs = self.fresh(action="open_node")
        self.assertEqual((results["ufm01"].status, results["ufm01"].path), ("VERIFIED", "OOB-IPv6"),
                         "the link-local path checks the MAC only")

    def test_key_login_identity_mismatch_stops_without_a_password(self):
        # 问题文档 :1587 第 5 条; I-037 设计 :18; B0-O13 (a) (I-054)
        self.state["ufms"]["ufm01"]["reported_mac"] = "02:00:00:00:01:02"
        results, _state, calls, _logs = self.fresh(action="open_node")
        one = results["ufm01"]
        self.assertEqual(one.status, "IDENTITY_MISMATCH", one.detail)
        self.assertIn(["mac", "02:00:00:00:01:01", "02:00:00:00:01:02"], [list(item) for item in one.identity["mismatches"]])
        self.assertEqual(one.attempts, [], "no password login")
        self.assertEqual(len([call for call in calls if call["target"] == "root@198.51.101.130"]), 1)
        self.assertEqual([call for call in calls if "ssh -6" in call["remote"]], [])
        results, _state, calls, _logs = self.fresh(action="trust")
        self.assertIn("IDENTITY_MISMATCH", results["ufm01"].detail)
        self.assertEqual(len([call for call in calls if call["target"] == "root@198.51.101.130"]), 1)
        self.state["ufms"]["ufm01"]["reported_mac"] = "02:00:00:00:01:01"
        self.state["no_direct"] = ["198.51.101.130"]
        results, _state, _calls, _logs = self.fresh(action="open_node")
        self.assertEqual((results["ufm01"].status, results["ufm01"].path), ("VERIFIED", "OOB-IPv6"))


class UfmRouteSummaryTests(unittest.TestCase):
    def test_summary_names_unreachable_jumps_and_the_route_of_each_ufm(self):
        # I-037 设计 :155-160 (v3.1.6 指导 WP-7 item 1): an unreachable jump is its own line naming the jump;
        # each UFM's line carries its route reason
        route = {"path": "jump", "reason": "JUMP_LINK", "jump": "oob-leaf117", "port": "swp17", "same_subnet": None,
                 "skip": ""}
        results = [ufm.NodeResult(U1, "primary", status="JUMP_UNREACHABLE", detail="跳板 oob-leaf117 连不上",
                                  login_route=route),
                   ufm.NodeResult(U2, "secondary", status="COMPLIANT",
                                  login_route=dict(route, path="direct", reason="DIRECT_ACCESS", jump=None, port=None))]
        printed = []
        with tempfile.TemporaryDirectory() as tmp:
            code = ufm.summarize(ufm.parse_args(["check"]), results, Path(tmp), printed.append)
        text = "\n".join(printed)
        self.assertEqual(code, 1)
        self.assertIn("跳板不可达: oob-leaf117（ufm01）", text)
        self.assertRegex(text, rf"(?m)^  {U2}\s+COMPLIANT\s+直接登录 DIRECT_ACCESS$")


if __name__ == "__main__":
    unittest.main()
