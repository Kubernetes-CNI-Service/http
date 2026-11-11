"""v15 OOB Spine routing and the real main() over it, kept on the merged initial-setup.

What: (1) the parent-side router `prepare_routed_ib_tasks` -- real Leaf/Spine selection over fake
snapshots, then the real nested SSH argv of each routed task; (2) the real main() -- CSV, P2P,
target cache, OOB snapshots, Spine routing, the task queue (inline slot or 2 real fork workers),
the per-device stages, the summary and summary.json.  Only the OOB command runner
(run_on_ethernet), the IB/PTY transport (interactive_run), the OOB key probe, the human inputs, the
Spine random choice and the clock are replaced; nothing reaches a device.

Expectation sources (not derived from the implementation):
- v15 design `参考/initial-setup-v15/V15-OOB-SPINE.md`: :6-8 and :54-58 (Leaf with SVI+IPv4 keeps the
  Leaf path, otherwise the LLDP Spine branch), :60-62 (Spine branch needs the CSV eth0 MAC; a
  missing MAC blocks only that IB), :64-67 (LLDP only; CSV-only Spines are never logged in to),
  :69-76 (candidate gates, one random choice per Leaf, an unreachable candidate is dropped), :83-85
  (attachment metadata, physical Leaf/port kept, the unchanged nested SSH is reused), :95-97
  (worker formula, final direct SSH not replaced by a Spine login), :112-117 (per-device oob/port vs
  jump, spine_jump_routes, Leaf and Spine snapshot failures counted separately, shared evidence write
  errors are not a device result); `参考/initial-setup-v15/CURRENT-CONTRACT.md` :20-21, :26-40, :52,
  :59-60, :64-67.
- The v15 delivered test `initial-setup-v15-test-cases/test_v15_oob_spine.py` classes
  SpineRoutingWorkflowTests (:191-324) and MainWorkerWorkflowTests (:327-482), bytes bound by
  `HANDOFF-SHA256SUMS:62`.  EntryGuardCrossScriptWorkflowTests (:485-503) is not moved: after the
  merge there is one entry (guide :831).

Fixture rewrites (guide :835 and :765 class 4; no assertion was relaxed):
- main() is called in-process (never _guarded_main or a `__main__` subprocess), HOME points into the
  temporary project, time.sleep is patched (verify_ipv4_login waits 10 s, guide :173).
- No empty `<project>/publickey/` (guide :835: v3.1.1 layout; 0 keys either way).
- `infra-neutral.conf` sits where --project-dir reads it, `<project>/infiniband/bringup/xdr-initial-setup/`,
  not `infra/` (O6, guide :259: DEV local read; WP-8 table 8-1, :923).
- v15 imported `test_desktop_initial_setup` for its global and password; local equivalents here:
  the global carries a synthetic hash and the IB target is assembled at run time (public audit), and
  ProjectPasswordPolicy.password/matches are patched as v15 did.
- With a project global on a management run the merged main() takes the strict DEV path
  (args._strict_cache): the IB authentication read is a DEV phase session and the IPv4 readiness
  probe is unframed (table 6-1 row 9, guide :752).  The fake transport therefore answers the phase
  markers through the real _IBPhase observer (adapted from
  test_initial_setup_credentials_fd_workflow.py `_PhaseSession`/`_World`) and the strict probe;
  everything else is v15's fake unchanged.  Pending diffs stay empty, as v15's fake already
  answered (T15, guide :2301).
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import re
import shlex
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_setup_v15_oob_spine_main", INITIAL)

MAC1 = "02:00:00:00:00:10"
MAC2 = "02:00:00:00:00:12"


def secret(label):
    # Assembled at run time so no credential literal appears in the source (public audit).
    return "-".join(("PUBLIC", "wp7", label, "Zq7"))


def global_text():
    # v15 test_desktop_initial_setup.global_text(), with a synthetic hash (public audit).
    global_hash = "$" + "6$PUBLICsalt$" + "A" * 86
    return ("schema_version: 2\ncommon:\n  switch:\n    system:\n      config:\n"
            "        auto-save:\n          state: enabled\n"
            "switches:\n- ib:\n    system:\n      aaa:\n        user:\n          admin:\n"
            "            password: {}\n").format(json.dumps(global_hash))


def device(host, ip="198.51.100.10", kind="eth_jump"):
    return app.Device(host, kind, ip, "", "", "", "", "")


def target(number=1, leaf=None):
    mac = MAC1 if number == 1 else MAC2
    ib = app.Device("ib%02d.example.test" % number, "ib", "192.0.2.%d" % (number + 10),
                    "192.0.2.%d/24" % (number + 10), "192.0.2.1", mac, "", "")
    return app.Target(ib, leaf or device("oob-leaf01"), "swp%d" % number, "eth0")


def interface_table(peers=(), ports=(1, 2)):
    header = ["Interface", "Admin Status", "Oper Status", "Speed", "MTU", "Type",
              "Remote Host", "Remote Port", "Summary"]
    widths = [16, 15, 15, 8, 8, 12, 38, 18, 12]

    def row(values):
        return "".join(str(value).ljust(width) for value, width in zip(values, widths)).rstrip()
    rows = [row(header), row(["-" * (n - 2) for n in widths])]
    rows += [row(["swp%d" % p, "up", "up", "1G", "9216", "swp", "nvos", "eth0", ""]) for p in ports]
    for p, peer, oper in peers:
        rows.append(row([p, "up", oper, "100G", "9216", "swp", peer, "swp1", ""]))
    return "\n".join(rows) + "\n"


def links(with_svi=True, vlan=1000, bridge="br_default"):
    value = ("1: br_default: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 state UP\n"
             "    bridge forward_delay 1500\n"
             "2: swp1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master br_default state UP\n"
             "3: swp2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master br_default state UP\n")
    if with_svi:
        value += ("4: vlan%d@%s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master oob state UP\n"
                  "    vlan protocol 802.1Q id %d <REORDER_HDR>\n") % (vlan, bridge, vlan)
    return value


def addresses(ipv4=True, ipv6=True, interface="vlan1000", state="UP"):
    items = []
    if ipv4:
        items.append({"family": "inet", "local": "192.0.2.1", "prefixlen": 24, "scope": "global"})
    if ipv6:
        items.append({"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"})
    return [{"ifname": interface, "flags": ["BROADCAST", "MULTICAST", "UP"],
             "operstate": state, "addr_info": items}]


def fdb(mac=MAC1, port="swp1", vlan=1000):
    return "%s dev %s vlan %s master br_default\n" % (mac, port, vlan)


class _PhaseSession:
    """Feed device output to the real responder as interactive_run does (DEV phase sessions).

    Adapted from test_initial_setup_credentials_fd_workflow.py; an OOB public-key login has no
    outer password prompt, so only the IB prompt is fed.
    """

    def __init__(self, responder) -> None:
        self.responder, self.phase = responder, responder._phase
        self.output = ""
        self.reader, self.writer = os.pipe()

    def feed(self, text: str):
        self.output += text
        self.phase.observe(self.output)
        reply = self.responder(app.strip_ansi(self.output))
        if reply is not None:
            self.phase.write_reply(self.writer, reply, self.responder, time.monotonic() + 60)
            os.read(self.reader, 65536)
        return reply

    def result(self, code: int):
        os.close(self.reader)
        os.close(self.writer)
        return app.SessionResult(app.strip_ansi(self.output), code)


class OobSpineMainTests(unittest.TestCase):
    # ---- v15 SpineRoutingWorkflowTests (test_v15_oob_spine.py:191-324) -------------------------
    # "Real selector -> legacy readiness -> real nested SSH argv; IO is fake."
    def run_route(self, *, leaf_svi=False, leaf_ipv4=False, peers=None, spine_specs=None,
                  targets=None, bad_mac=False, address_failure=False, second_vlan=1000,
                  spine_links=None):
        targets = targets or [target(1), target(2)]
        leaf = targets[0].ethernet
        a, b = device("oob-spine01", "198.51.100.21"), device("oob-spine02", "198.51.100.22")
        spines = [a, b]
        interfaces = {leaf.hostname: interface_table(peers if peers is not None else [
            ("swp49", a.hostname, "up"), ("swp50", b.hostname, "up")])}
        leaf_fdb = fdb("02:00:00:00:ff:ff" if bad_mac else MAC1) + fdb(MAC2, "swp2", second_vlan)
        tables = {leaf.hostname: (links(leaf_svi), leaf_fdb,
                                  "fe80::10 dev vlan1000 lladdr %s REACHABLE\n" % MAC1 +
                                  "fe80::12 dev vlan1000 lladdr %s REACHABLE\n" % MAC2)}
        failures, outcomes, records, fetched = {}, {}, {}, []
        passwords = {leaf.hostname: secret("leaf")}
        specs = spine_specs or {a.hostname: addresses(), b.hostname: addresses()}

        def fetch(dev):
            if dev.hostname == leaf.hostname:
                if address_failure:
                    raise app.SetupError("address snapshot query failed")
                return addresses(leaf_ipv4) if leaf_svi else []
            if isinstance(specs.get(dev.hostname), Exception):
                raise specs[dev.hostname]
            return specs.get(dev.hostname, [])

        def collect(devices):
            fetched.extend(d.hostname for d in devices)
            for dev in devices:
                passwords[dev.hostname] = dev.hostname + "-password"
                interfaces[dev.hostname] = interface_table()
                tables[dev.hostname] = ((spine_links or {}).get(dev.hostname, links()), "", "")
        args = SimpleNamespace(eth_user="cumulus", ib_user="admin", connect_timeout=5)
        chooser = patch.object(app, "choose_oob_spine", side_effect=lambda rows: rows[-1])
        with chooser as choose, patch.object(app, "interface_vrf", return_value="oob"), \
                contextlib.redirect_stdout(io.StringIO()):
            tasks = app.prepare_routed_ib_tasks(targets, args, passwords, set(), interfaces,
                                                tables, failures, outcomes, records, spines=spines,
                                                fetch_addresses=fetch, collect_spines=collect)
        return tasks, records, fetched, choose.call_count

    # v15 SpineRoutingWorkflowTests.test_l3_leaf_uses_unchanged_legacy_path_and_no_spine_io
    # (test_v15_oob_spine.py:229).  V15-OOB-SPINE.md:6-7, :54; CURRENT-CONTRACT.md:26-27.
    def test_l3_leaf_uses_unchanged_legacy_path_and_no_spine_io(self):
        tasks, records, fetched, choices = self.run_route(leaf_svi=True, leaf_ipv4=True)
        self.assertEqual(len(tasks), 2)
        self.assertTrue(all(t.target.ethernet.hostname == "oob-leaf01" for t in tasks))
        self.assertEqual(fetched, [])
        self.assertEqual(choices, 0)

    # v15 SpineRoutingWorkflowTests.test_l2_leaf_one_random_choice_shared_by_all_ib_tasks
    # (test_v15_oob_spine.py:236).  V15-OOB-SPINE.md:7-8, :74-75, :83-85; CURRENT-CONTRACT.md:39.
    def test_l2_leaf_one_random_choice_shared_by_all_ib_tasks(self):
        tasks, records, fetched, choices = self.run_route()
        self.assertEqual(len(tasks), 2)
        self.assertEqual(choices, 1)
        self.assertEqual(set(fetched), {"oob-spine01", "oob-spine02"})
        self.assertEqual({t.target.ethernet.hostname for t in tasks}, {"oob-spine02"})
        self.assertEqual({t.ethernet_password for t in tasks}, {"oob-spine02-password"})
        for task in tasks:
            self.assertEqual(task.target.attachment.ethernet.hostname, "oob-leaf01")
            self.assertEqual(task.neighbor.interface, "vlan1000")
            self.assertEqual(task.neighbor.vrf, "oob")
            argv = app.nested_ssh_command(task.target, task.neighbor, "cumulus", "admin", 5,
                                          ["nv", "config", "show", "-o", "commands"])
            self.assertIn("cumulus@198.51.100.22", argv)
            self.assertNotIn("cumulus@198.51.100.10", argv)
            self.assertIn("vlan1000", argv[-1])

    # v15 SpineRoutingWorkflowTests.test_leaf_ipv6_only_svi_selects_spine
    # (test_v15_oob_spine.py:253).  V15-OOB-SPINE.md:56.
    def test_leaf_ipv6_only_svi_selects_spine(self):
        tasks, _, _, choices = self.run_route(leaf_svi=True, leaf_ipv4=False)
        self.assertEqual(choices, 1)
        self.assertTrue(all(t.target.attachment is not None for t in tasks))

    # v15 SpineRoutingWorkflowTests.test_spine_in_csv_but_absent_from_lldp_is_never_queried
    # (test_v15_oob_spine.py:258).  V15-OOB-SPINE.md:67; CURRENT-CONTRACT.md:32.
    def test_spine_in_csv_but_absent_from_lldp_is_never_queried(self):
        tasks, _, fetched, _ = self.run_route(peers=[("swp49", "oob-spine01", "up")])
        self.assertEqual(fetched, ["oob-spine01"])
        self.assertEqual({t.target.ethernet.hostname for t in tasks}, {"oob-spine01"})

    # v15 SpineRoutingWorkflowTests.test_no_lldp_candidate_skips_without_ib_login
    # (test_v15_oob_spine.py:263).  V15-OOB-SPINE.md:58.
    def test_no_lldp_candidate_skips_without_ib_login(self):
        tasks, rows, fetched, _ = self.run_route(peers=[])
        self.assertEqual(tasks, [])
        self.assertEqual(fetched, [])
        self.assertEqual({r["category"] for r in rows.values()}, {"SKIPPED_NO_LLDP_SPINE"})

    # v15 SpineRoutingWorkflowTests.test_bad_access_mac_never_bypassed_by_spine
    # (test_v15_oob_spine.py:269).  V15-OOB-SPINE.md:57, :60; CURRENT-CONTRACT.md:26, :36.
    def test_bad_access_mac_never_bypassed_by_spine(self):
        tasks, rows, _, _ = self.run_route(targets=[target(1)], bad_mac=True)
        self.assertEqual(tasks, [])
        self.assertEqual(rows["ib01.example.test"]["category"], "SKIPPED_MAC_MISMATCH")

    # v15 SpineRoutingWorkflowTests.test_one_missing_inventory_mac_does_not_block_other_ib_on_same_leaf
    # (test_v15_oob_spine.py:274).  V15-OOB-SPINE.md:61; CURRENT-CONTRACT.md:36.
    def test_one_missing_inventory_mac_does_not_block_other_ib_on_same_leaf(self):
        missing = replace(target(1), ib=replace(target(1).ib, eth0_mac=""))
        tasks, rows, _, _ = self.run_route(targets=[missing, target(2)])
        self.assertEqual([t.target.ib.hostname for t in tasks], ["ib02.example.test"])
        self.assertEqual(rows["ib01.example.test"]["category"], "SKIPPED_INVENTORY_MAC_UNAVAILABLE")

    # v15 SpineRoutingWorkflowTests.test_address_collection_error_does_not_trigger_fallback
    # (test_v15_oob_spine.py:280).  V15-OOB-SPINE.md:57; CURRENT-CONTRACT.md:28.
    def test_address_collection_error_does_not_trigger_fallback(self):
        tasks, rows, fetched, _ = self.run_route(address_failure=True)
        self.assertEqual(tasks, [])
        self.assertEqual(fetched, [])
        self.assertEqual({r["category"] for r in rows.values()}, {"SKIPPED_OOB_ADDRESS_UNVERIFIED"})

    # v15 SpineRoutingWorkflowTests.test_only_one_spine_has_addresses_choose_only_that_one
    # (test_v15_oob_spine.py:286).  V15-OOB-SPINE.md:69-70, :76.
    def test_only_one_spine_has_addresses_choose_only_that_one(self):
        tasks, _, _, _ = self.run_route(spine_specs={"oob-spine01": addresses(),
                                                     "oob-spine02": addresses(False)})
        self.assertEqual({t.target.ethernet.hostname for t in tasks}, {"oob-spine01"})

    # v15 SpineRoutingWorkflowTests.test_no_qualified_spine_preserves_reasons_per_candidate
    # (test_v15_oob_spine.py:291).  V15-OOB-SPINE.md:58, :117.
    def test_no_qualified_spine_preserves_reasons_per_candidate(self):
        tasks, rows, _, _ = self.run_route(spine_specs={"oob-spine01": addresses(False),
                                                        "oob-spine02": addresses(ipv6=False)})
        self.assertEqual(tasks, [])
        for row in rows.values():
            self.assertEqual(row["category"], "SKIPPED_NO_QUALIFIED_SPINE")
            self.assertIn("oob-spine01", row["reason"])
            self.assertIn("oob-spine02", row["reason"])

    # v15 SpineRoutingWorkflowTests.test_spine_query_failure_does_not_block_another_qualified_candidate
    # (test_v15_oob_spine.py:300).  V15-OOB-SPINE.md:76.
    def test_spine_query_failure_does_not_block_another_qualified_candidate(self):
        tasks, _, _, _ = self.run_route(spine_specs={"oob-spine01": app.SetupError("connection timed out"),
                                                     "oob-spine02": addresses()})
        self.assertEqual(len(tasks), 2)
        self.assertEqual({t.target.ethernet.hostname for t in tasks}, {"oob-spine02"})

    # v15 SpineRoutingWorkflowTests.test_one_spine_must_cover_all_fallback_vlans_for_leaf
    # (test_v15_oob_spine.py:306).  V15-OOB-SPINE.md:69-70; CURRENT-CONTRACT.md:34, :40.
    def test_one_spine_must_cover_all_fallback_vlans_for_leaf(self):
        extra_link = "5: vlan2000@br_default: <BROADCAST,UP> state UP\n    vlan protocol 802.1Q id 2000\n"
        tasks, _, _, choices = self.run_route(
            second_vlan=2000,
            spine_specs={"oob-spine01": addresses(),
                         "oob-spine02": addresses() + addresses(interface="vlan2000")},
            spine_links={"oob-spine02": links() + extra_link})
        self.assertEqual(choices, 1)
        self.assertEqual({t.target.ethernet.hostname for t in tasks}, {"oob-spine02"})
        self.assertEqual({t.neighbor.interface for t in tasks}, {"vlan1000", "vlan2000"})

    # v15 SpineRoutingWorkflowTests.test_no_common_spine_does_not_split_same_leaf_group
    # (test_v15_oob_spine.py:315).  CURRENT-CONTRACT.md:39-40.
    def test_no_common_spine_does_not_split_same_leaf_group(self):
        tasks, rows, _, choices = self.run_route(second_vlan=2000)
        self.assertEqual(tasks, [])
        self.assertEqual(choices, 0)
        self.assertEqual({r["category"] for r in rows.values()}, {"SKIPPED_NO_QUALIFIED_SPINE"})

    # v15 SpineRoutingWorkflowTests.test_shared_evidence_failure_is_not_a_device_skip
    # (test_v15_oob_spine.py:321).  V15-OOB-SPINE.md:117; CURRENT-CONTRACT.md:60.
    def test_shared_evidence_failure_is_not_a_device_skip(self):
        with self.assertRaises(app.OobRoutingEvidenceError):
            self.run_route(spine_specs={"oob-spine01": app.OobRoutingEvidenceError("disk full"),
                                        "oob-spine02": addresses()})

    # ---- v15 MainWorkerWorkflowTests (test_v15_oob_spine.py:327-482) ---------------------------
    # "Real CSV/P2P/cache -> parent routing -> workers -> nested command/readback -> summary.
    #  Only transport and human input are replaced. Worker processes, command framing, config
    #  comparison, report creation and the summary are real."

    # v15 MainWorkerWorkflowTests.test_full_readonly_spine_workflow_and_cache_rerun_recollect_snapshots
    # (test_v15_oob_spine.py:333).  CURRENT-CONTRACT.md:20 (cache never replaces this run's
    # Leaf/Spine checks), :59; V15-OOB-SPINE.md:47.
    def test_full_readonly_spine_workflow_and_cache_rerun_recollect_snapshots(self):
        self.run_main(count=2, leaf_svi=False, repeat=True)

    # v15 MainWorkerWorkflowTests.test_real_parallel_workers_keep_access_leaf_and_selected_jump_distinct
    # (test_v15_oob_spine.py:336).  V15-OOB-SPINE.md:95, :112-113; CURRENT-CONTRACT.md:21, :64-65.
    # Two real fork workers (17 ready tasks); timed separately for the wq decision (guide :857).
    def test_real_parallel_workers_keep_access_leaf_and_selected_jump_distinct(self):
        self.run_main(count=17, leaf_svi=False)

    # v15 MainWorkerWorkflowTests.test_normal_leaf_main_uses_no_spine_and_same_ib_pipeline
    # (test_v15_oob_spine.py:339).  V15-OOB-SPINE.md:6-7, :54, :83.
    def test_normal_leaf_main_uses_no_spine_and_same_ib_pipeline(self):
        self.run_main(count=2, leaf_svi=True)

    # v15 MainWorkerWorkflowTests.test_spine_apply_reuses_real_initial_network_and_verification_commands
    # (test_v15_oob_spine.py:342).  V15-OOB-SPINE.md:83-85, :96; CURRENT-CONTRACT.md:52.
    def test_spine_apply_reuses_real_initial_network_and_verification_commands(self):
        self.run_main(count=2, leaf_svi=False, apply=True)

    # v15 MainWorkerWorkflowTests.test_failed_unused_spine_does_not_inflate_leaf_failure_count
    # (test_v15_oob_spine.py:345).  V15-OOB-SPINE.md:76, :114.
    def test_failed_unused_spine_does_not_inflate_leaf_failure_count(self):
        self.run_main(count=2, leaf_svi=False, unreachable_spine=True)

    # v15 MainWorkerWorkflowTests.test_all_leaf_snapshots_failed_still_produces_incomplete_summary_without_dispatch
    # (test_v15_oob_spine.py:348).  CURRENT-CONTRACT.md:64 (zero ready starts no worker), :67.
    def test_all_leaf_snapshots_failed_still_produces_incomplete_summary_without_dispatch(self):
        self.run_main(count=2, leaf_svi=False, unreachable_leaf=True)

    def run_main(self, count, leaf_svi, repeat=False, apply=False,
                 unreachable_spine=False, unreachable_leaf=False):
        target_password = secret("ib-target")
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            root = Path(directory)
            # O6 (guide :259): one local neutral file (DEV local read), under --project-dir the
            # project's infiniband/bringup/xdr-initial-setup/ one (WP-8 table 8-1, :923).
            neutral = root / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
            neutral.parent.mkdir(parents=True, exist_ok=True)
            neutral.write_text("DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=Etc/UTC\n")
            (root / "01-global.yaml").write_text(global_text())
            devices = []
            with (root / "ib.csv").open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["hostname", "type", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"])
                for n in range(1, count + 1):
                    mac = "02:00:00:00:00:%02x" % (16 + 2 * (n - 1))
                    writer.writerow(["ib%02d.example.test" % n, "ib", "192.0.2.%d" % (n + 10), "24",
                                     "192.0.2.1", mac])
                    devices.append(app.Device("ib%02d.example.test" % n, "ib", "192.0.2.%d" % (n + 10),
                                              "192.0.2.%d/24" % (n + 10), "192.0.2.1", mac, "", ""))
                for hostname, address in (("oob-leaf01", "198.51.100.10"),
                                          ("oob-spine01", "198.51.100.21"),
                                          ("oob-spine02", "198.51.100.22")):
                    writer.writerow([hostname, "eth_jump", address, "", "", ""])
            (root / "p2p.dot").write_text("\n".join('"%s":"eth0" -- "oob-leaf01":"swp%d"' %
                                                    (d.hostname, n) for n, d in enumerate(devices, 1)) + "\n")
            by_ll = {app.mac_to_link_local(d.eth0_mac): d for d in devices}
            by_ip = {d.login_ip: d for d in devices}
            configured = {d.hostname: not apply for d in devices}
            hits, writes = [], []
            argv = [str(INITIAL), "--project-dir", str(root), "--ib-csv", str(root / "ib.csv"),
                    "--p2p", str(root / "p2p.dot"), "--target-cache", str(root / "targets.json"),
                    "--report", str(root / "report.log"), "--snapshot-dir", str(root / "snapshots"),
                    "--execution-mode", "management"]
            if apply:
                argv += ["--apply", "--yes"]

            def ethernet(dev, user, password, command, timeout, **kwargs):
                app.ethernet_command_argv(command)
                hits.append((dev.hostname, tuple(command)))
                if ((unreachable_leaf and dev.hostname == "oob-leaf01")
                        or (unreachable_spine and dev.hostname == "oob-spine01")):
                    raise app.SetupError("SSH connection timed out: " + dev.hostname)
                if command == ["hostname"]:
                    return dev.hostname + "\n"
                if command == ["nv", "show", "interface"]:
                    return interface_table([("swp49", "oob-spine01", "up"), ("swp50", "oob-spine02", "up")],
                                           tuple(range(1, count + 1)))
                if command == ["ip", "-d", "link", "show"]:
                    base = links(leaf_svi if dev.hostname == "oob-leaf01" else True)
                    return base + "".join("%d: swp%d: <UP> mtu 9216 master br_default state UP\n" %
                                          (n + 10, n) for n in range(3, count + 1))
                if command == ["bridge", "fdb", "show"]:
                    return "".join(fdb(d.eth0_mac, "swp%d" % n) for n, d in enumerate(devices, 1))
                if command == ["ip", "neighbor"]:
                    return "".join("%s dev vlan1000 lladdr %s REACHABLE\n" %
                                   (app.mac_to_link_local(d.eth0_mac), d.eth0_mac) for d in devices)
                if command == ["ip", "-j", "address", "show"]:
                    return json.dumps(addresses() if leaf_svi or dev.hostname != "oob-leaf01" else [])
                if command == ["ifquery", "vlan1000"]:
                    return "iface vlan1000\n    vrf oob\n"
                raise AssertionError(command)

            def payload(dev, text):
                if re.search(r"\bnv (?:set|unset)\b|\bnv config (?:apply|save)\b", text):
                    if not apply:
                        raise AssertionError("Unexpected device write in CHECK_ONLY")
                    writes.append(text)
                    self.assertIn("cumulus@198.51.100.21", text)
                    if "nv config save" in text:
                        configured[dev.hostname] = True
                    return ""
                if "true" in text and "nv " not in text:
                    return ""
                if "nv show system ztp" in text:
                    return "service disabled\n"
                if "nv config diff" in text:
                    return ""
                if "nv config show" in text:
                    body = ("\n".join(shlex.join(c) for c in app.desired_commands(dev)
                                      if c[:2] == ["nv", "set"]) + "\n") if configured[dev.hostname] \
                        else "nv set system hostname nvos\n"
                    body += "\n".join(shlex.join(c) for c in app.initial_configuration_commands()
                                      if c[:2] == ["nv", "set"]) + "\n"
                    body += ("nv set system dns server 192.0.2.53\n"
                             "nv set system ntp server 192.0.2.123 state enabled\n"
                             "nv set system date-time timezone Etc/UTC\n")
                    return body
                raise AssertionError(text)

            def phase_session(command, responder, text, nonce, operation):
                # Strict IB authentication read (DEV phase session, guide table 6-1 row 9 :752):
                # the IB prompt goes through the real _IBPhase observer, then v15's readback.
                peer = re.search(r"admin@([a-f0-9:]+)", text).group(1)
                dev = by_ll.get(peer)
                if not dev:
                    raise AssertionError(peer)
                session = _PhaseSession(responder)
                end = f"__HTTP_IB_AUTH_{nonce}_{operation}__=EXIT:"
                session.feed(f"\n__HTTP_IB_AUTH_{nonce}_{operation}__=BEGIN\n")
                if session.feed(f"admin@{peer}'s password: ") is None:
                    raise AssertionError("no IB credential answered in the phase session")
                body = payload(dev, "nv config show")
                session.feed(f"\n__HTTP_IB_BEGIN_{nonce}__\n{body}__HTTP_IB_END_{nonce}__=0\n{end}0\n")
                return session.result(0)

            def transport(command, responder, timeout, **kwargs):
                text = " ".join(command)
                auth = re.search(r"__HTTP_IB_AUTH_([0-9a-f]{32})_"
                                 r"(auth-probe-readonly|password-change|post-change-read)__=BEGIN", text)
                if auth is not None:
                    return phase_session(command, responder, text, *auth.groups())
                begin = re.search(r"__HTTP_IB_BEGIN_([a-f0-9]+)__", text)
                if begin is None:
                    # Strict IPv4 readiness probe (DEV, unframed: guide table 6-1 row 9 :752).
                    if not apply or not re.search(r"ip vrf exec \S+ ssh .*admin@192\.0\.2\.\d+ true", text):
                        raise AssertionError(text)
                    self.assertIn("cumulus@198.51.100.21", text)
                    return app.SessionResult("", 0)
                nonce = begin.group(1)
                peer = re.search(r"admin@([a-f0-9:.]+)", text).group(1)
                dev = by_ll.get(peer) or by_ip.get(peer)
                if not dev:
                    raise AssertionError(peer)
                return app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + payload(dev, text) +
                                         "__HTTP_IB_END_" + nonce + "__=0\n", 0)
            home = root / "home"
            home.mkdir()
            stack.enter_context(patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(patch.object(Path, "home", return_value=home))
            stack.enter_context(patch.object(app, "run_on_ethernet", ethernet))
            stack.enter_context(patch.object(app, "interactive_run", transport))
            stack.enter_context(patch.object(app.subprocess, "run",
                                             side_effect=AssertionError("External commands forbidden")))
            stack.enter_context(patch.object(app, "probe_ethernet_key", return_value="key"))
            stack.enter_context(patch.object(app, "resolve_initial_ib_password",
                                             return_value=target_password if apply else "admin"))
            stack.enter_context(patch.object(app.ProjectPasswordPolicy, "password", return_value=target_password))
            stack.enter_context(patch.object(app.ProjectPasswordPolicy, "matches",
                                             side_effect=lambda value: value == target_password))
            stack.enter_context(patch.object(app, "choose_oob_spine", side_effect=lambda values: values[0]))
            stack.enter_context(patch.object(app.time, "sleep", return_value=None))
            stack.enter_context(patch.object(app, "REPORT_HANDLE", None))
            stack.enter_context(patch.object(sys, "argv", argv))
            for iteration in range(2 if repeat else 1):
                with contextlib.redirect_stdout(io.StringIO()) as console:
                    try:
                        result = app.main()
                    finally:
                        if app.REPORT_HANDLE:
                            app.REPORT_HANDLE.close()
                output = console.getvalue()
                self.assertEqual(result, 2 if unreachable_leaf else 0, output)
                if apply:
                    self.assertTrue(writes)
                    self.assertTrue(any("nv config apply -y" in text for text in writes))
                    self.assertTrue(all(configured.values()))
                else:
                    self.assertEqual(writes, [])
                if iteration:
                    self.assertIn("Target cache: reused", output)
                report = max(root.rglob("summary.json"), key=lambda p: p.stat().st_mtime)
                facts = json.loads(report.read_text())
                self.assertEqual(len(facts["records"]), count)
                self.assertEqual(facts["workers"], 0 if unreachable_leaf else 2 if count == 17 else 1)
                if unreachable_leaf:
                    self.assertEqual({r["outcome"] for r in facts["records"].values()}, {"SKIPPED"})
                    self.assertEqual(facts["spine_jump_routes"], [])
                    self.assertNotIn("oob-spine01", facts["oob_snapshot_failures"])
                    continue
                selected_jump = "oob-leaf01" if leaf_svi else "oob-spine02" if unreachable_spine else "oob-spine01"
                for row in facts["records"].values():
                    self.assertEqual(row["oob"], "oob-leaf01")
                    self.assertEqual(row["jump"]["hostname"], selected_jump)
                    self.assertEqual(row["stage_status"]["day0"], "VERIFIED" if apply else "ALREADY_PRESENT")
                    self.assertEqual(row["stage_status"]["direct_ssh"], "VERIFIED")
                if not leaf_svi:
                    self.assertEqual(len(facts["spine_jump_routes"]), 1)
                    self.assertEqual(facts["spine_jump_routes"][0]["spine"], selected_jump)
                    if unreachable_spine:
                        self.assertEqual(facts["oob_snapshot_failures"], {})
                        self.assertIn("oob-spine01", facts["spine_snapshot_failures"])
                else:
                    self.assertEqual(facts["spine_jump_routes"], [])
            collected = sum(host == "oob-leaf01" and cmd == ("bridge", "fdb", "show") for host, cmd in hits)
            self.assertEqual(collected, 0 if unreachable_leaf else 2 if repeat else 1)
            if leaf_svi:
                self.assertFalse(any(host.startswith("oob-spine") for host, _ in hits))


if __name__ == "__main__":
    unittest.main()
