"""r629 WP2 subset of the five-real-script login-path workflow; NOT RUN.

Real main, CSV/P2P, inventory comparison and M4 modules, login_path and D4
JumpSessions remain in the chain. Only external commands/human observations are
modelled. The read-only profile boundary stops before worker execution, so these
tests do not claim WP3 direct transport, WP4 identity/backup or WP5 final summary.
Sources: guide 642--650, WP2 table 666--668, WP5 842--854 and I20/O2/O2a.
"""
from __future__ import annotations

import json
import unittest

from test_cases.test_initial_setup_cable_check import (
    _World, IB1, IB2, IB3, JA, JB, SP, JMAC, MAC1, MAC2, MAC3,
    LL1, LL2, LL3, LINKS, VLANS, _fdb,
)


class LoginPathWorkflowTests(unittest.TestCase):
    def first_command(self, world, host, command):
        event = ("command", host, tuple(command))
        self.assertIn(event, world.events, "real external boundary must observe " + repr(event))
        return world.events.index(event)

    def assert_first_eth0_identity(self, world):
        """An observed real MAC read must precede the first interface snapshot."""
        hostname = self.first_command(world, JA, ["hostname"])
        identity = self.first_command(world, JA, ["ip", "-j", "address", "show"])
        snapshot = self.first_command(world, JA, ["nv", "show", "interface"])
        self.assertLess(hostname, identity, "K9 hostname before K2 MAC callback")
        self.assertLess(identity, snapshot, "callback must run on FIRST acquire, not on later reuse")
        self.assertTrue(world.sessions.records[JA]["verify_identity"] is not None)

    def test_real_main_cable_ping_and_ignore_preserve_same_facts(self):
        """Guide 642/643 and WP5 cable subset: real five-script chain, not fake ready rows."""
        for ignored in (False, True):
            with self.subTest(ignored=ignored), _World(self) as world:
                world.write_inventory(two_jumps=True, three=True)
                world.tables[JA] = (LINKS, [_fdb(MAC1) + _fdb(MAC2)], VLANS)
                world.tables[JB] = (LINKS, ["", _fdb(MAC3)], VLANS)
                world.invoke("--refresh-host-key", IB1, *(["--ignore-cable-check"] if ignored else []))
                self.assertEqual((IB1, IB2, IB3) if ignored else (IB1, IB3),
                                 tuple(t.target.ib.hostname for t in world.prepared))
                self.assertEqual({JA: 1, JB: 2}, world.fdb_reads)
                self.assertEqual([("ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "1",
                                   LL3 + "%ib-mgmt")], [cmd for cmd in world.commands(JB) if "ping" in cmd])
                self.assertTrue({"load_devices", "parse_p2p", "_compare_inventory",
                                 "prepare_ready_ib_tasks", "prepare_routed_ib_tasks"} <= world.entered)
                self.assertTrue({"inventory_subset.py", "hostname_ranges.py", "device_identity.py",
                                 "login_path.py"} <= world.entered_files)
                self.assertNotIn(("ip", "neighbor"), world.commands())
                if ignored:
                    cable = world.record_fact(IB2, "cable_check")
                    self.assertIn("ignored", cable)
                    self.assertIs(True, cable["ignored"])
                    self.assertEqual((JA, "swp8", LL2, "ib-mgmt"),
                        (world.prepared[1].target.ethernet.hostname, world.prepared[1].target.ethernet_port,
                         world.prepared[1].neighbor.ipv6, world.prepared[1].neighbor.interface))
                else:
                    self.assertEqual("SKIPPED_CABLE_CHECK_FAILED", world.records[IB2]["category"])
                    self.assertIn("swp7", json.dumps(world.record_fact(IB2, "cable_check")))

    def test_first_key_master_has_hostname_mac_before_snapshot(self):
        """Guide 647/K9: a key hit cannot create ready before attaching its callback."""
        with _World(self) as world:
            world.invoke()
            self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual([("master", "198.51.100.10", "key")],
                             [e for e in world.events if e[0] == "master"])
            self.assert_first_eth0_identity(world)

    def test_real_p2p_cascade_is_not_reported_as_actual_device_port(self):
        """I-037 rule 4: source P2P, not a fake CableCheck, identifies a cascade."""
        with _World(self) as world:
            world.write_inventory(two_jumps=True, three=True)
            with world.p2p.open("a") as handle:
                handle.write(JA + ",swp49," + JB + ",swp49\n")
            world.tables[JA] = (LINKS, [_fdb(MAC1, "swp49") + _fdb(MAC2, "swp8")], VLANS)
            world.tables[JB] = (LINKS, [_fdb(MAC1, "swp8") + _fdb(MAC3)], VLANS)
            world.invoke()
            self.assertEqual((IB2, IB3), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual("SKIPPED_CABLE_CHECK_FAILED", world.records[IB1]["category"])
            cable = json.dumps(world.record_fact(IB1, "cable_check"))
            self.assertIn(JB, cable)
            self.assertIn("swp8", cable)
            self.assertNotIn("swp49", cable)
            self.assertFalse(any("ping" in cmd for cmd in world.commands()))

    def test_real_bond_mapping_keeps_physical_expected_port_and_csv_address(self):
        """4.1/WP2: real pipeline maps FDB bond name without rewriting source facts."""
        with _World(self) as world:
            bonded = LINKS.replace("swp7: <UP> mtu 1500 master br_default", "swp7: <UP> mtu 1500 master bond1")
            bonded += "6: bond1: <UP> mtu 1500 master br_default state UP\n"
            world.tables[JA] = (bonded, [_fdb(MAC1, "bond1") + _fdb(MAC2, "swp8")], VLANS)
            world.invoke()
            self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
            first = world.prepared[0]
            self.assertEqual((JA, "swp7", "swp7", LL1, "ib-mgmt"),
                             (first.target.ethernet.hostname, first.target.ethernet_port,
                              first.target.source_attachment.port, first.neighbor.ipv6, first.neighbor.interface))

    def test_first_password_master_has_same_identity_boundary(self):
        """Guide 647: failed key then original hidden-password path is not a MAC bypass."""
        with _World(self) as world:
            world.key_denied.add("198.51.100.10")
            world.invoke()
            self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual([("master", "198.51.100.10", "key"),
                              ("master", "198.51.100.10", "password")],
                             [e for e in world.events if e[0] == "master"])
            self.assert_first_eth0_identity(world)

    def test_i20_candidates_switch_only_on_network_failure_and_record_vlan(self):
        """Guide 646--650: exact CSV order and real selected entry, not compatibility login_ip."""
        with _World(self) as world:
            world.network.update(("198.51.100.10", "198.51.100.11"))
            world.invoke()
            self.assertEqual([("master", "198.51.100.10", "key"),
                              ("master", "198.51.100.11", "key"),
                              ("master", "198.51.100.12", "key")],
                             [e for e in world.events if e[0] == "master"])
            self.assertEqual("198.51.100.12", world.sessions.records[JA]["address"])
            first_snapshot = self.first_command(world, JA, ["nv", "show", "interface"])
            self.assertFalse(any(e == ("command", JA, ("ip", "-j", "address", "show"))
                                 for e in world.events[:first_snapshot]), "VLAN entry only checks hostname")
            self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertIn(IB1, world.records, "selected entry must survive real preparation")
            jump = world.record_fact(IB1, "jump")
            self.assertIn("entry", jump)
            self.assertIn("login_ip", jump)
            self.assertEqual(("JUMP_VLAN2000", "198.51.100.12"),
                             (jump["entry"], jump["login_ip"]))
            self.assertEqual("ib-mgmt", world.prepared[0].neighbor.interface,
                             "CSV entry VLAN is not the IB access VLAN interface")

    def test_i20_final_auth_does_not_try_later_candidate_or_stop_other_jump(self):
        """O2: auth after eth0 network failure stops only this jump, never falls through."""
        with _World(self) as world:
            world.write_inventory(two_jumps=True, three=True)
            world.network.add("198.51.100.10")
            world.authentication.add("198.51.100.11")
            world.invoke()
            self.assertEqual((IB3,), tuple(t.target.ib.hostname for t in world.prepared))
            tried = [e[1] for e in world.events if e[0] == "master"]
            self.assertIn("198.51.100.11", tried)
            self.assertNotIn("198.51.100.12", tried)
            self.assertIn("203.0.113.10", tried)
            self.assertEqual("OOB_JUMP_AUTHENTICATION", world.records[IB1]["failure_kind"])
            self.assertFalse(any(cmd[:2] == ("nv", "set") for cmd in world.commands()))
            self.assertEqual([("master", "198.51.100.10", "key"),
                              ("master", "198.51.100.11", "key"),
                              ("master", "198.51.100.11", "password")],
                [event for event in world.events if event[0] == "master"
                 and event[1] in {"198.51.100.10", "198.51.100.11", "198.51.100.12"}],
                "password retry stays on the candidate requesting it; no exhausted eth0 replay")

    def test_i20_mac_mismatch_refuses_before_snapshot_and_keeps_other_jump(self):
        """Guide 648: actual callback read, no later VLAN candidate or dependent IB task."""
        with _World(self) as world:
            world.write_inventory(two_jumps=True, three=True)
            observed = "02:00:00:00:01:99"
            world.mac[JA] = observed
            output = world.invoke()
            self.assertEqual((IB3,), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual("SKIPPED_OOB_IDENTITY_CONFLICT", world.records[IB1]["category"])
            self.assertIn(("ip", "-j", "address", "show"), world.commands(JA))
            self.assertNotIn(("nv", "show", "interface"), world.commands(JA))
            self.assertNotIn("198.51.100.11", [e[1] for e in world.events if e[0] == "master"])
            self.assertNotIn("198.51.100.12", [e[1] for e in world.events if e[0] == "master"])
            self.assertIn(JMAC, output)
            self.assertIn(observed, output)

    def test_i20_hostkey_and_hostname_never_try_another_candidate(self):
        """Guide 647: these two identity failures are not network fallback evidence."""
        for problem in ("hostkey", "hostname"):
            with self.subTest(problem=problem), _World(self) as world:
                if problem == "hostkey":
                    world.hostkey.add("198.51.100.10")
                else:
                    world.hostname[JA] = "example-wrong-jump"
                world.invoke()
                self.assertEqual((), world.prepared)
                world.initial_password.assert_not_called()
                self.assertEqual([("master", "198.51.100.10", "key")],
                                 [e for e in world.events if e[0] == "master"])
                self.assertNotIn(("nv", "show", "interface"), world.commands(JA))

    def test_real_rebuild_repeats_same_entry_identity_before_next_command(self):
        """Guide 649: master loss after first snapshot reuses address and actual callback."""
        with _World(self) as world:
            world.drop_after_snapshot = True
            world.invoke()
            self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual([("master", "198.51.100.10", "key"),
                              ("master", "198.51.100.10", "key")],
                             [e for e in world.events if e[0] == "master"])
            snapshot = self.first_command(world, JA, ["nv", "show", "interface"])
            links = self.first_command(world, JA, ["ip", "-d", "link", "show"])
            identity = ("command", JA, ("ip", "-j", "address", "show"))
            between = world.events[snapshot + 1:links]
            self.assertIn(("command", JA, ("hostname",)), between)
            self.assertIn(identity, between, "rebuild must execute, not merely retain, the callback")
            self.assertLess(between.index(("command", JA, ("hostname",))), between.index(identity))

    def test_i20_missing_or_invalid_jump_mac_is_explicitly_hostname_only(self):
        """O2a: no invented MAC verification, but this usable jump is not refused."""
        for supplied in ("", "invalid"):
            with self.subTest(mac_shape=supplied), _World(self) as world:
                world.write_inventory(jump_mac=supplied)
                output = world.invoke()
                self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
                first_snapshot = self.first_command(world, JA, ["nv", "show", "interface"])
                self.assertFalse(any(e == ("command", JA, ("ip", "-j", "address", "show"))
                                     for e in world.events[:first_snapshot]))
                self.assertIn("eth0_mac", output)
                self.assertRegex(output,
                    r"(?im)^(?=[^\n]*eth0_mac)(?=[^\n]*(?:host.?name[^\n]*only|only[^\n]*host.?name|只[^\n]*主机名))[^\n]*$",
                    "one explicit eth0_mac + hostname-only notice, not a required language")

    def test_inventory_mismatch_refuses_before_master_and_partial_outputs(self):
        """WP5 workflow inventory subset: true M4 mismatch, not a mocked success flag."""
        with _World(self) as world:
            world.master.write_text(world.master.read_text().replace("192.0.2.10", "192.0.2.18", 1))
            output = world.invoke(expect_dispatch=False)
            self.assertEqual(2, world.exit_code)
            self.assertIn("INVENTORY MISMATCH:", output)
            self.assertIn(IB1, output)
            self.assertIn("eth0_ip", output)
            self.assertEqual([], world.events)
            self.assertIsNone(world.sessions)
            self.assertFalse((world.root / "report.log").exists())
            self.assertFalse((world.root / "targets.json").exists())
            self.assertFalse((world.root / "snapshots").exists())


class LoginPathCompletedReadonlyWorkflowTests(unittest.TestCase):
    """WP5 no-global slice: real MAIN/worker/finish/summary, never a checkpoint.

    Only fixed PUBLIC external command replies are modelled. Future identity,
    backup/deferred APPLY and real phase/native/PTY behavior are not claimed.
    """

    def _complete_direct_main(self, *, two_devices=False):
        import csv
        import hashlib
        import io
        import os
        from pathlib import Path
        import re
        import shlex
        import sys
        from contextlib import redirect_stderr, redirect_stdout
        from unittest import mock
        from test_cases.test_initial_setup_direct_transport import DirectWorld, HEADER, INITIAL, ROOT, PUBLIC_REPLY

        # Independent CSV/remote device facts. The second device deliberately
        # has another subnet, gateway, MAC and an explicit direct selector.
        first_reason = "NO_MGMT_LINK" if two_devices else "DIRECT_ACCESS"
        devices = [(IB1, "192.0.2.10", "192.0.2.1", MAC1, first_reason, "en-public7")]
        if two_devices:
            devices.append((IB2, "198.51.100.20", "198.51.100.1", MAC2, "DIRECT_ACCESS", None))
        expected_routes = {name: {"hostname": name, "path": "direct", "reason": reason,
            "jump": None, "port": None, "same_subnet": interface}
            for name, ip, gateway, mac, reason, interface in devices}
        before_home, before_cwd, previous_profile = os.environ.get("HOME"), Path.cwd(), sys.getprofile()
        with DirectWorld(self) as world:
            app = world.app
            self.assertFalse((world.project / "01-global.yaml").exists(), "this slice must really have no global")
            for path in (world.csv, world.master):
                with path.open("w", newline="") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(HEADER)
                    for name, ip, gateway, mac, reason, interface in devices:
                        row = [name, "ib", ip, "24", gateway, mac]
                        writer.writerow(row + [""] * (len(HEADER) - len(row)))
            # A real nonempty PUBLIC P2P input, not a parser bypass or fake LP.
            world.p2p.write_text("a-node,a-port,z-node,z-port\n"
                "example-unselected-ib99,eth0,example-unselected-leaf99,swp7\n", encoding="utf-8")
            endpoints = {}
            for device in devices:
                name, ip, gateway, mac, reason, interface = device
                endpoints["admin@" + ip] = device
                if interface is not None:
                    # MAC1's independently fixed PUBLIC link-local address.
                    self.assertEqual(MAC1, mac)
                    endpoints["admin@fe80::ff:fe00:10%en-public7"] = device
            external_calls, external_errors = [], []
            required = {"tools.device_identity": "main", "tools.hostname_ranges": "main",
                        "tools.login_path": "main", "tools.inventory_subset": "_compare_inventory"}
            observed = {"files": set(), "modules": {}, "tasks": (), "execute": [],
                        "finished": [], "batch": None, "stamp": None, "order": []}

            def external(argv, responder, timeout, **options):
                self.assertTrue(type(argv) is list and len(argv) >= 3 and argv[0] == "ssh",
                                "only a direct PUBLIC SSH vector is modelled")
                self.assertTrue(argv[-2] in endpoints, "direct destination must bind one independent CSV device")
                self.assertTrue(getattr(responder, "_phase", None) is None,
                                "no-global readonly must not borrow a fabricated private phase")
                self.assertTrue(type(responder) is (app.NestedResponder if "ConnectionAttempts=1" in argv
                                                    else app._DirectResponder), "exact actual direct responder")
                self.assertTrue(responder.ib_default_password == PUBLIC_REPLY,
                                "the existing initial/current PUBLIC credential is retained")
                name, ip, gateway, mac, reason, interface = endpoints[argv[-2]]
                remote = shlex.split(argv[-1])
                self.assertTrue(len(remote) == 3 and remote[:2] == ["sh", "-c"], "closed ordinary remote carrier")
                markers = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertEqual(1, len(markers))
                marker = markers[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix) and remote[2].endswith(suffix),
                                "one exact actual frame owns command and status")
                text = remote[2][len(prefix):-len(suffix)]
                command = shlex.split(text)
                self.assertEqual(shlex.join(command), text, "the model admits no extra shell statement")
                if command == ["nv", "config", "show", "-o", "commands"]:
                    body = ("nv set system hostname " + name + "\n"
                        "nv set interface eth0 ipv4 address " + ip + "/24\n"
                        "nv set interface eth0 ipv4 gateway " + gateway + "\n"
                        "nv set interface eth0-1 link state up\n"
                        "nv set interface eth0-1 type eth\n"
                        "nv set system config auto-save state enabled\n"
                        "nv set system ztp config-save enabled\n")
                elif command == ["nv", "show", "system", "ztp"]:
                    body = "service disabled\nstate disabled\n"
                elif command == ["ip", "addr", "show", "eth0"]:
                    body = ("2: eth0: <UP> mtu 1500 state UP\n    link/ether " + mac
                            + " brd ff:ff:ff:ff:ff:ff\n    inet " + ip + "/24 scope global eth0\n")
                elif command == ["ip", "route"]:
                    body = "default via " + gateway + " dev eth0\n"
                elif command == ["hostname"]:
                    # U4 (v3.1.6 D1d, guide 8.11): the closed Linux hostname read after the NVUE
                    # hostname is verified; this healthy device's Linux name is its NVUE hostname.
                    body = name + "\n"
                else:
                    raise RuntimeError("FIXTURE HOLD: command outside the closed WP5 readonly model")
                external_calls.append((name, argv[-2], tuple(command)))
                return app.SessionResult("__HTTP_IB_BEGIN_" + marker + "__\n" + body
                                         + "__HTTP_IB_END_" + marker + "__=0\n", 0)

            def observed_external(*args, **kwargs):
                try:
                    return external(*args, **kwargs)
                except BaseException as error:
                    external_errors.append(error)
                    raise

            def profile(frame, event, value):
                filename = Path(frame.f_code.co_filename)
                if event == "call" and filename in {INITIAL, *(ROOT / "tools" / (name + ".py")
                    for name in ("device_identity", "hostname_ranges", "inventory_subset", "login_path"))}:
                    observed["files"].add(filename)
                if frame.f_globals is not app.__dict__:
                    return
                name = frame.f_code.co_name
                if event == "return" and name == "_new_jump_sessions" and value is not None:
                    world.sessions = value
                elif event == "return" and name == "_import_tools":
                    requested, caller = frame.f_locals.get("name"), frame.f_back
                    if (requested in required and caller is not None and caller.f_globals is app.__dict__
                            and caller.f_code.co_name == required[requested]):
                        observed["modules"].setdefault(requested, []).append(value)
                elif event == "call" and name == "run_prepared_tasks":
                    observed["tasks"] = tuple(frame.f_locals["tasks"])
                    args = frame.f_locals["args"]
                    observed["stamp"] = args.run_stamp
                    world.expected_device_prefix = "devices-" + args.run_stamp + "-"
                    self.assertIsNone(frame.f_locals["policy"], "this is a genuine no-global workflow")
                    observed["order"].append("dispatch")
                elif event == "call" and name == "execute_ib_task":
                    observed["execute"].append(frame.f_locals["task"])
                    observed["order"].append("execute")
                elif name == "finish" and "task" in frame.f_locals and "record" in frame.f_locals:
                    if event == "call":
                        observed["order"].append("finish-enter")
                    elif event == "return" and frame.f_locals["task"].target.ib.hostname in expected_routes:
                        # The closure's ordinary None return does not imply success;
                        # final batch and actual per-device JSON are checked below.
                        observed["finished"].append(frame.f_locals["task"].target.ib.hostname)
                elif event == "return" and name == "run_prepared_tasks":
                    observed["batch"] = value
                    observed["order"].append("batch-return")

            output = io.StringIO()
            argv = [str(INITIAL), "--project-dir", str(world.project), "--ib-csv", str(world.csv),
                "--p2p", str(world.p2p), "--report", str(world.root / "report.log"),
                "--target-cache", str(world.root / "targets.json"), "--snapshot-dir", str(world.root / "snapshots"),
                "--execution-mode", "management", "--max-workers", "1", "--connect-timeout", "2"]
            argv.extend(["--direct-access", IB2 if two_devices else IB1])
            try:
                with mock.patch.object(sys, "argv", argv), \
                     mock.patch.object(app, "interactive_run", new=observed_external), \
                     redirect_stdout(output), redirect_stderr(output):
                    sys.setprofile(profile)
                    code = app._standalone_main_with_report_cleanup()
            finally:
                sys.setprofile(previous_profile)
            if external_errors:
                raise external_errors[0]  # no adapter error swallowed as a worker/business FAIL
            if type(observed["batch"]) is not dict:
                raise RuntimeError("PREREQUISITE HOLD: real WP5 MAIN did not return a complete batch")
            if any(record.get("script_error") for record in observed["batch"]["records"].values()):
                raise RuntimeError("SOURCE ERROR: real WP5 worker program error is not behavior RED")
            self.assertEqual(0, code, "real no-global readonly MAIN must finish successfully")
            self.assertEqual([row[0] for row in devices], observed["finished"])
            self.assertEqual(len(devices), len(observed["execute"]))
            self.assertEqual(tuple(observed["tasks"]), tuple(observed["execute"]))
            self.assertTrue(all(type(task.neighbor) is app.DirectEndpoint and task.local is False
                                and task.target.ethernet is None for task in observed["tasks"]))
            self.assertEqual({INITIAL, *(ROOT / "tools" / (name + ".py") for name in
                ("device_identity", "hostname_ranges", "inventory_subset", "login_path"))}, observed["files"])
            self.assertEqual(set(required), set(observed["modules"]))
            for name, modules in observed["modules"].items():
                self.assertTrue(bool(modules))
                for module in modules:
                    self.assertIs(module, sys.modules[name])
                    self.assertEqual((ROOT / "tools" / (name.split(".")[1] + ".py")).resolve(),
                                     Path(module.__file__).resolve())
            folder = Path(observed["batch"]["log_dir"])
            self.assertEqual(world.root, folder.parent)
            self.assertTrue(folder.name.startswith("devices-" + observed["stamp"] + "-"), "one real run stamp")
            summary = json.loads((folder / "summary.json").read_text())
            self.assertEqual("SUCCESS", summary["result"])
            self.assertEqual("CHECK_ONLY", summary["mode"])
            self.assertEqual(expected_routes, summary["routes"])
            self.assertEqual(set(expected_routes), set(summary["records"]))
            self.assertEqual(hashlib.sha256(INITIAL.read_bytes()).hexdigest(), summary["source_sha256"])
            for name, expected in expected_routes.items():
                record = summary["records"][name]
                self.assertTrue({"hostname", "route", "jump", "neighbor", "cable_check", "oob", "outcome",
                    "writes_attempted", "input_issues", "eth1_hints"} <= set(record),
                    "actual summary record must contain the frozen WP5 first-slice fields")
                self.assertEqual(name, record["hostname"])
                self.assertEqual(expected, record["route"])
                self.assertIsNone(record["jump"], "direct records cannot invent a Jump")
                self.assertIsNone(record["neighbor"], "direct endpoints cannot invent Neighbor fields")
                self.assertIsNone(record["cable_check"], "unmeasured direct cable facts are not a passed check")
                self.assertIsNone(record["oob"])
                self.assertEqual("ALREADY_CONFIGURED", record["outcome"])
                self.assertIs(False, record["writes_attempted"])
                self.assertEqual([], record["input_issues"])
                self.assertEqual(1, len(record["eth1_hints"]), "one filled MAC retains the I041 nonblocking hint")
                hint = record["eth1_hints"][0]
                self.assertEqual({"hostname", "field", "value", "problem", "blocking"}, set(hint))
                self.assertEqual({"hostname": name, "field": "eth1_mac", "value": "", "blocking": False},
                                 {key: hint[key] for key in ("hostname", "field", "value", "blocking")})
                self.assertTrue(type(hint["problem"]) is str and bool(hint["problem"].strip()),
                                "the independent hint must retain meaningful nonempty diagnostic text")
                self.assertNotIn("csv_fdb_mac_check", record, "WP5 replaces the Jump/FDB-only legacy field")
                saved = json.loads((folder / (name + ".json")).read_text())
                self.assertTrue({"route", "jump", "neighbor", "cable_check", "input_issues", "eth1_hints"} <= set(saved),
                                "actual per-device JSON must contain the same frozen first-slice fields")
                for field in ("route", "jump", "neighbor", "cable_check", "input_issues", "eth1_hints"):
                    self.assertEqual(record[field], saved[field], "durable and summary fields must agree: " + field)
            self.assertFalse(any(call[2][:2] in (("nv", "set"), ("sh", "-c")) for call in external_calls))
            self.assertFalse(world.masters, "real final jump-session cleanup must leave no owned master")
            self.assertTrue(app.REPORT_HANDLE is not None and app.REPORT_HANDLE.closed is True,
                            "the original finally closes the actual report; it need not clear its reference")
            self.assertEqual((world.root / "report.log").resolve(), Path(app.REPORT_HANDLE.name).resolve())
            self.assertIsNone(app._ACTIVE_COORDINATOR)
            self.assertIsNone(app._TASK_DEADLINE)
            self.assertIsNone(app._TASK_LOG_BUFFER)
            self.assertIs(previous_profile, sys.getprofile())
            # WP5 final-only consumer: independent PUBLIC device inputs above
            # are the oracle, not serialization of the formatter's own output.
            expected_body = []
            for name, ip, gateway, mac, reason, interface in devices:
                record = summary["records"][name]
                saved = json.loads((folder / (name + ".json")).read_text())
                for field in ("route", "cable_check", "identity", "input_issues",
                              "eth1_hints", "backup", "outcome", "category",
                              "writes_attempted", "metrics"):
                    self.assertIn(field, saved)
                    self.assertIn(field, record)
                    self.assertEqual(record[field], saved[field],
                                     "actual per-device and summary fields differ: " + field)
                via_ipv4 = interface is None
                self.assertEqual({
                    "ok": True, "via_ipv4": via_ipv4,
                    "expected": {"mac": mac, "ipv4": ip + "/24" if via_ipv4 else None,
                                 "gateway": gateway if via_ipv4 else None},
                    "observed": {"mac": mac, "ipv4": [ip + "/24"],
                                 "gateways": [gateway] if via_ipv4 else []},
                    "mismatches": [],
                }, record["identity"])
                self.assertIsNone(record["backup"], "readonly cannot invent a backup receipt")
                route_subnet = 'null' if interface is None else '"' + interface + '"'
                identity_line = (f'    Identity: ok=yes via_ipv4={"yes" if via_ipv4 else "no"}'
                                 f' mac_expected="{mac}" mac_observed="{mac}"')
                if via_ipv4:
                    identity_line += (f' ipv4_expected="{ip}/24" ipv4_observed=["{ip}/24"]'
                                      f' gateway_expected="{gateway}" gateways_observed=["{gateway}"]')
                expected_body.extend([
                    "  Device facts: " + name,
                    f'    Route: path="direct" reason="{reason}" same_subnet=' + route_subnet,
                    identity_line,
                    ("hint-transport", name),
                ])
            final_report = (world.root / "report.log").read_text(encoding="utf-8")
            for channel, text in (("console", output.getvalue()), ("report", final_report)):
                with self.subTest(final_channel=channel):
                    anchor = "  TOTAL: " + str(len(devices)) + "\n"
                    self.assertEqual(1, text.count(anchor))
                    after = text.split(anchor, 1)[1]
                    self.assertIn("\n+-- 04 CONFIGURATION STAGES", after)
                    body = after.split("\n+-- 04 CONFIGURATION STAGES", 1)[0].strip("\n").splitlines()
                    self.assertEqual(len(expected_body), len(body), "no hidden, missing or extra final fact lines")
                    for expected, line in zip(expected_body, body):
                        if type(expected) is str:
                            self.assertEqual(expected, line)
                        else:
                            # No exact English wording requirement is invented:
                            # only the existing meaningful diagnostic's transport.
                            hint = summary["records"][expected[1]]["eth1_hints"][0]
                            self.assertEqual({"hostname": expected[1], "field": "eth1_mac",
                                              "value": "", "blocking": False},
                                {key: hint[key] for key in ("hostname", "field", "value", "blocking")})
                            self.assertTrue(type(hint["problem"]) is str and bool(hint["problem"].strip()))
                            match = re.fullmatch(r'    eth1 hint: field="eth1_mac" value="" problem=("(?:[^"\\]|\\.)*")', line)
                            self.assertIsNotNone(match)
                            self.assertEqual(hint["problem"], json.loads(match.group(1)))
                    self.assertEqual(7, len(re.findall(r"(?m)^\+-- \d\d ", text)))
        self.assertTrue(before_home == os.environ.get("HOME"), "original HOME restored without exposing its value")
        self.assertTrue(before_cwd == Path.cwd(), "original cwd restored")
        self.assertIs(previous_profile, sys.getprofile())
        return summary

    def test_no_global_readonly_direct_main_finishes_null_jump_and_real_summary(self):
        self._complete_direct_main()

    def test_two_direct_routes_keep_device_facts_separate_through_finish_and_summary(self):
        summary = self._complete_direct_main(two_devices=True)
        self.assertEqual("NO_MGMT_LINK", summary["records"][IB1]["route"]["reason"])
        self.assertEqual("en-public7", summary["records"][IB1]["route"]["same_subnet"])
        self.assertEqual("DIRECT_ACCESS", summary["records"][IB2]["route"]["reason"])
        self.assertIsNone(summary["records"][IB2]["route"]["same_subnet"])

    def test_facts_excludes_null_direct_neighbor_without_changing_legacy_nd_or_fdb_counts(self):
        from unittest import mock
        from test_cases.test_initial_setup_direct_transport import DirectWorld
        direct = {"hostname": IB1, "outcome": "ALREADY_CONFIGURED", "writes_attempted": False,
            "metrics": {"ib_ssh_attempts": 1}, "stage_status": {"authentication": "VERIFIED"},
            "jump": None, "neighbor": None, "cable_check": None,
            "route": {"hostname": IB1, "path": "direct", "reason": "DIRECT_ACCESS",
                      "jump": None, "port": None, "same_subnet": "en-public7"}}
        nd = {"hostname": IB2, "outcome": "ALREADY_CONFIGURED", "writes_attempted": False,
            "metrics": {"ib_ssh_attempts": 2}, "stage_status": {"authentication": "VERIFIED"},
            "neighbor": {"ipv6": LL2, "interface": "ib-mgmt", "vrf": "oob",
                         "mac": MAC2, "address_source": "ND"}}
        fdb = {"hostname": IB3, "outcome": "ALREADY_CONFIGURED", "writes_attempted": False,
            "metrics": {"ib_ssh_attempts": 3}, "stage_status": {"authentication": "VERIFIED"},
            "neighbor": {"ipv6": LL3, "interface": "ib-mgmt", "vrf": "oob",
                         "mac": MAC3, "address_source": "FDB_EUI64_CANDIDATE"}}
        legacy = {IB2: nd, IB3: fdb}
        records = {IB1: direct, **legacy}
        before = json.loads(json.dumps(records))
        with DirectWorld(self) as world, \
             mock.patch.object(world.app, "interactive_run", side_effect=world.deny), \
             mock.patch.object(world.app.subprocess, "run", side_effect=world.deny):
            old_facts = world.app.initial_setup_facts(legacy, [])
            facts = world.app.initial_setup_facts(records, [])
        expected_sources = {"ND": 1, "FDB_EUI64_CANDIDATE": 1}
        expected_fallback = {"candidates": 1, "authenticated": 1, "not_verified": 0}
        self.assertEqual(expected_sources, old_facts["ipv6_address_sources"])
        self.assertEqual(expected_sources, facts["ipv6_address_sources"])
        self.assertEqual(expected_fallback, old_facts["ipv6_fallback"])
        self.assertEqual(expected_fallback, facts["ipv6_fallback"])
        self.assertEqual({"ib_ssh_attempts": 5}, old_facts["metrics"])
        self.assertEqual({"ib_ssh_attempts": 6}, facts["metrics"])
        self.assertEqual({"CHECKED_EXISTING_CONFIGURATION": 3}, facts["categories"])
        self.assertEqual({"VERIFIED": 3}, facts["stages"]["authentication"])
        self.assertEqual(before, records, "facts must not invent or mutate per-device evidence")


class LoginPathCompletedJumpWorkflowTests(unittest.TestCase):
    """S2 actual parent preparation -> worker -> finish -> durable evidence."""

    def _complete_mixed_main(self, *, vlan_entry):
        from contextlib import redirect_stderr, redirect_stdout
        import io
        from pathlib import Path
        import re
        import shlex
        import sys
        from unittest import mock
        from test_cases.test_initial_setup_direct_transport import DirectWorld, INITIAL, ROOT
        from test_cases.test_initial_setup_cable_check import PUBLIC_REPLY

        address = "198.51.100.12" if vlan_entry else "198.51.100.10"
        entry = "JUMP_VLAN2000" if vlan_entry else "JUMP_ETH0"
        expected_jump = {"hostname": JA, "login_ip": address, "entry": entry, "type": "eth_jump",
            "interface": "ib-mgmt", "vrf": "oob", "access_vlan": None, "selection_reason": "LEAF_LOCAL_PATH"}
        expected_cable = {"hostname": IB2, "mac": MAC2, "link_local": LL2, "expected": [JA, "swp8"],
            "verdict": "MATCH", "actual": [[JA, "swp8"]], "extra_macs": [], "login_interface": "ib-mgmt",
            "after_ping": False, "ping_ok": None, "ignored": False}
        expected_routes = {
            IB1: {"hostname": IB1, "path": "direct", "reason": "DIRECT_ACCESS", "jump": None,
                  "port": None, "same_subnet": "en-public7"},
            IB2: {"hostname": IB2, "path": "jump", "reason": "JUMP_LINK", "jump": JA,
                  "port": "swp8", "same_subnet": None},
        }
        previous = sys.getprofile()
        with DirectWorld(self) as world:
            app = world.app
            # Keep actual P2P/CSV/Leaf tables; only IB01 gets the real selector.
            world.write_inventory()
            if vlan_entry:
                world.network.update(("198.51.100.10", "198.51.100.11"))
            self.assertFalse((world.project / "01-global.yaml").exists())
            observed = {"prepared": None, "selected": None, "tasks": (), "workers": {},
                        "finished": [], "batch": None, "stamp": None, "metrics": {}, "modules": {}, "files": set()}
            required = {"tools.device_identity": "main", "tools.hostname_ranges": "main",
                        "tools.login_path": "main", "tools.inventory_subset": "_compare_inventory"}
            required_files = {INITIAL, *(ROOT / "tools" / (name + ".py") for name in
                ("device_identity", "hostname_ranges", "inventory_subset", "login_path"))}
            ib_calls, external_errors = [], []
            safe_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
            original_run = app.subprocess.run

            def control_bridge(argv, **kwargs):
                if (type(argv) is list and len(argv) == 6 and all(type(word) is str for word in argv)
                        and argv[:2] == ["ssh", "-o"] and argv[2].startswith("ControlPath=")
                        and argv[3] == "-O" and argv[4] in ("check", "exit")):
                    return _World.control(world, argv, **kwargs)
                return original_run(argv, **kwargs)

            world.stack.enter_context(mock.patch.object(app.subprocess, "run", new=control_bridge))

            def device_reply(remote, name, ip, mac):
                words = shlex.split(remote)
                self.assertTrue(len(words) == 3 and words[:2] == ["sh", "-c"], "closed nested remote carrier")
                markers = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", words[2])
                self.assertEqual(1, len(markers))
                marker = markers[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(words[2].startswith(prefix) and words[2].endswith(suffix), "exact actual frame")
                text = words[2][len(prefix):-len(suffix)]
                command = shlex.split(text)
                self.assertEqual(shlex.join(command), text, "no extra shell statement is modelled")
                if command == ["nv", "config", "show", "-o", "commands"]:
                    body = ("nv set system hostname " + name + "\n"
                        "nv set interface eth0 ipv4 address " + ip + "/24\n"
                        "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
                        "nv set interface eth0-1 link state up\nnv set interface eth0-1 type eth\n"
                        "nv set system config auto-save state enabled\nnv set system ztp config-save enabled\n")
                elif command == ["nv", "show", "system", "ztp"]:
                    body = "service disabled\nstate disabled\n"
                elif command == ["ip", "addr", "show", "eth0"]:
                    body = ("2: eth0: <UP> mtu 1500 state UP\n    link/ether " + mac
                            + " brd ff:ff:ff:ff:ff:ff\n    inet " + ip + "/24 scope global eth0\n")
                elif command == ["ip", "route"]:
                    body = "default via 192.0.2.1 dev eth0\n"
                elif command == ["hostname"]:
                    # U4 (v3.1.6 D1d, guide 8.11): the closed Linux hostname read after the NVUE
                    # hostname is verified; this healthy device's Linux name is its NVUE hostname.
                    body = name + "\n"
                else:
                    raise RuntimeError("FIXTURE HOLD: outside the closed S2 readonly IB command model")
                ib_calls.append((name, tuple(command)))
                return app.SessionResult("__HTTP_IB_BEGIN_" + marker + "__\n" + body
                                         + "__HTTP_IB_END_" + marker + "__=0\n", 0)

            def external(argv, responder, timeout, **kwargs):
                self.assertTrue(type(argv) is list and bool(argv) and argv[0] == "ssh", "only PUBLIC SSH boundary")
                if "-M" in argv:
                    return _World.interactive(world, argv, responder, timeout, **kwargs)
                destination = argv[-2]
                if destination.startswith("cumulus@"):
                    carrier = shlex.split(argv[-1])
                    self.assertTrue(len(carrier) == 3 and carrier[:2] == ["sh", "-c"]
                                    and carrier[2].startswith(safe_path), "exact outer PATH carrier")
                    inner = shlex.split(carrier[2][len(safe_path):])
                    if inner[:5] != ["ip", "vrf", "exec", "oob", "ssh"]:
                        # Actual original master/snapshot/identity/bridge/ping model.
                        return _World.interactive(world, argv, responder, timeout, **kwargs)
                    path = world._scoped_path(argv)
                    self.assertIn(path, world.masters, "nested IB must use an actual owned acquired master")
                    self.assertEqual(address, world.masters[path], "actual selected entry, not compatibility login_ip")
                    self.assertTrue(destination in {"cumulus@198.51.100.10", "cumulus@198.51.100.11",
                                                     "cumulus@198.51.100.12"}, "same PUBLIC Jump only")
                    header = ["ip", "vrf", "exec", "oob", "ssh", "-6", "-tt", "-o", "ConnectTimeout=2",
                        "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", "-o", "ControlMaster=no",
                        "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1"]
                    password_only = ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"]
                    tail = ["-B", "ib-mgmt", "admin@" + LL2]
                    self.assertTrue(inner[:-1] in (header + tail, header + password_only + tail),
                                    "closed original nested options, endpoint and separately bound interface")
                    self.assertTrue(type(responder) is app.NestedResponder and responder._phase is None,
                                    "ordinary real nested responder, no fake private phase")
                    self.assertTrue(responder.ib_default_password == PUBLIC_REPLY, "actual selected PUBLIC IB current")
                    return device_reply(inner[-1], IB2, "192.0.2.12", MAC2)
                self.assertTrue(destination in {"admin@" + LL1 + "%en-public7", "admin@192.0.2.10",
                                                "admin@192.0.2.12"}, "closed direct/final IPv4 destinations")
                self.assertTrue(getattr(responder, "_phase", None) is None, "no-global has no fabricated private phase")
                expected_type = app.NestedResponder if "ConnectionAttempts=1" in argv else app._DirectResponder
                self.assertIs(type(responder), expected_type)
                self.assertTrue(responder.ib_default_password == PUBLIC_REPLY, "same PUBLIC selected credential")
                if destination == "admin@192.0.2.12":
                    return device_reply(argv[-1], IB2, "192.0.2.12", MAC2)
                return device_reply(argv[-1], IB1, "192.0.2.10", MAC1)

            def external_observer(*args, **kwargs):
                try:
                    return external(*args, **kwargs)
                except BaseException as error:
                    external_errors.append(error)
                    raise

            def profile(frame, event, value):
                if event == "call" and Path(frame.f_code.co_filename) in required_files:
                    observed["files"].add(Path(frame.f_code.co_filename))
                if frame.f_globals is not app.__dict__:
                    return
                name = frame.f_code.co_name
                if event == "return" and name == "_new_jump_sessions" and value is not None:
                    world.sessions = value
                elif event == "return" and name == "_import_tools":
                    requested, caller = frame.f_locals.get("name"), frame.f_back
                    if (requested in required and caller is not None and caller.f_globals is app.__dict__
                            and caller.f_code.co_name == required[requested]):
                        observed["modules"].setdefault(requested, []).append(value)
                elif event == "return" and name == "prepare_routed_ib_tasks":
                    # A passive reach witness, never the source of expected data.
                    record = frame.f_locals["records"].get(IB2)
                    observed["prepared"] = json.loads(json.dumps(record)) if record is not None else None
                elif event == "call" and name == "run_prepared_tasks":
                    observed["tasks"] = tuple(frame.f_locals["tasks"])
                    observed["selected"] = world.sessions.records[JA]["address"]
                    args = frame.f_locals["args"]
                    observed["stamp"] = args.run_stamp
                    world.expected_device_prefix = "devices-" + args.run_stamp + "-"
                    self.assertIsNone(frame.f_locals["policy"])
                elif event == "return" and name == "execute_ib_task" and type(value) is dict:
                    hostname = frame.f_locals["task"].target.ib.hostname
                    observed["workers"][hostname] = {key: json.loads(json.dumps(value[key]))
                        for key in ("outcome", "stage_status", "writes_attempted") if key in value}
                elif name == "finish" and "task" in frame.f_locals and "record" in frame.f_locals:
                    hostname = frame.f_locals["task"].target.ib.hostname
                    if event == "call":
                        observed["metrics"][hostname] = dict(frame.f_locals["metrics"] or {})
                    elif event == "return":
                        observed["finished"].append(hostname)
                elif event == "return" and name == "run_prepared_tasks":
                    observed["batch"] = value

            output = io.StringIO()
            argv = [str(INITIAL), "--project-dir", str(world.project), "--ib-csv", str(world.csv),
                "--p2p", str(world.p2p), "--direct-access", IB1, "--report", str(world.root / "report.log"),
                "--target-cache", str(world.root / "targets.json"), "--snapshot-dir", str(world.root / "snapshots"),
                "--execution-mode", "management", "--max-workers", "1", "--connect-timeout", "2"]
            try:
                with mock.patch.object(sys, "argv", argv), mock.patch.object(app, "interactive_run", new=external_observer), \
                     redirect_stdout(output), redirect_stderr(output):
                    sys.setprofile(profile)
                    code = app._standalone_main_with_report_cleanup()
            finally:
                sys.setprofile(previous)
            if external_errors:
                raise external_errors[0]
            if type(observed["batch"]) is not dict:
                raise RuntimeError("PREREQUISITE HOLD: real mixed MAIN did not complete its actual batch")
            if any(record.get("script_error") for record in observed["batch"]["records"].values()):
                raise RuntimeError("SOURCE ERROR: real mixed worker program error is not behavior RED")
            self.assertEqual(0, code, "two independently fully configured readonly devices must use the original success formula")
            self.assertEqual(address, observed["selected"])
            self.assertIs(type(observed["prepared"]), dict)
            self.assertEqual(expected_jump, observed["prepared"]["jump"])
            self.assertEqual(expected_cable, observed["prepared"]["cable_check"])
            self.assertEqual({IB1, IB2}, set(observed["workers"]))
            self.assertEqual({IB1, IB2}, set(observed["finished"]))
            self.assertEqual(2, len(observed["finished"]))
            self.assertEqual(required_files, observed["files"])
            self.assertEqual(set(required), set(observed["modules"]))
            for module_name, modules in observed["modules"].items():
                for module in modules:
                    self.assertIs(module, sys.modules[module_name])
                    self.assertEqual((ROOT / "tools" / (module_name.split(".")[1] + ".py")).resolve(),
                                     Path(module.__file__).resolve())
            folder = Path(observed["batch"]["log_dir"])
            self.assertEqual(world.root, folder.parent)
            self.assertTrue(folder.name.startswith("devices-" + observed["stamp"] + "-"))
            summary = json.loads((folder / "summary.json").read_text())
            self.assertEqual("SUCCESS", summary["result"])
            self.assertEqual(expected_routes, summary["routes"])
            for hostname in (IB1, IB2):
                record = summary["records"][hostname]
                self.assertTrue({"route", "jump", "neighbor", "cable_check", "input_issues", "eth1_hints"} <= set(record))
                self.assertEqual(expected_routes[hostname], record["route"])
                self.assertEqual([], record["input_issues"])
                self.assertEqual(1, len(record["eth1_hints"]))
                hint = record["eth1_hints"][0]
                self.assertEqual({"hostname", "field", "value", "problem", "blocking"}, set(hint))
                self.assertEqual({"hostname": hostname, "field": "eth1_mac", "value": "", "blocking": False},
                    {key: hint[key] for key in ("hostname", "field", "value", "blocking")})
                self.assertTrue(type(hint["problem"]) is str and bool(hint["problem"].strip()))
                self.assertNotIn("csv_fdb_mac_check", record)
                self.assertEqual("ALREADY_CONFIGURED", observed["workers"][hostname]["outcome"])
                self.assertEqual("VERIFIED", observed["workers"][hostname]["stage_status"]["authentication"])
                self.assertEqual("VERIFIED", observed["workers"][hostname]["stage_status"]["direct_ssh"])
                saved = json.loads((folder / (hostname + ".json")).read_text())
                for key in ("outcome", "stage_status", "writes_attempted"):
                    self.assertEqual(observed["workers"][hostname][key], record[key], "parent metadata must not overwrite worker " + key)
                    self.assertEqual(record[key], saved[key])
                self.assertTrue(observed["metrics"][hostname].get("ib_ssh_attempts", 0) > 0)
                self.assertEqual(observed["metrics"][hostname], record["metrics"], "metadata cannot overwrite real session metrics")
                self.assertEqual(record["metrics"], saved["metrics"])
                for key in ("route", "jump", "neighbor", "cable_check", "input_issues", "eth1_hints"):
                    self.assertIn(key, saved)
                    self.assertEqual(record[key], saved[key], "durable and summary evidence must agree: " + key)
            jump_record, direct_record = summary["records"][IB2], summary["records"][IB1]
            self.assertEqual(expected_jump, jump_record["jump"])
            self.assertEqual(expected_cable, jump_record["cable_check"])
            self.assertEqual({"ipv6": LL2, "interface": "ib-mgmt", "vrf": "oob", "mac": MAC2,
                              "address_source": "CSV_EUI64"}, jump_record["neighbor"])
            self.assertIsNone(direct_record["jump"])
            self.assertIsNone(direct_record["neighbor"])
            self.assertIsNone(direct_record["cable_check"], "direct cannot inherit the other device's measured cable fact")
            self.assertEqual({IB1, IB2}, {name for name, command in ib_calls})
            expected_masters = [("master", item, "key") for item in
                (("198.51.100.10", "198.51.100.11", "198.51.100.12") if vlan_entry else ("198.51.100.10",))]
            self.assertEqual(expected_masters, [event for event in world.events if event[0] == "master"])
            self.assertFalse(world.masters, "original Jump lifetime must close the actual acquired master")
            self.assertTrue(app.REPORT_HANDLE is not None and app.REPORT_HANDLE.closed is True,
                            "the original finally closes the actual report; it need not clear its reference")
            self.assertEqual((world.root / "report.log").resolve(), Path(app.REPORT_HANDLE.name).resolve())
            self.assertIsNone(app._ACTIVE_COORDINATOR)
            self.assertIsNone(app._TASK_DEADLINE)
            self.assertIsNone(app._TASK_LOG_BUFFER)
            self.assertIs(previous, sys.getprofile())
            # Same true MAIN/finish path; independently specified physical
            # cable/route/identity facts must survive into the final panel.
            expected_body = []
            for hostname, ip, mac in ((IB1, "192.0.2.10", MAC1), (IB2, "192.0.2.12", MAC2)):
                record = summary["records"][hostname]
                saved = json.loads((folder / (hostname + ".json")).read_text())
                for field in ("route", "cable_check", "identity", "input_issues",
                              "eth1_hints", "backup", "outcome", "category",
                              "writes_attempted", "metrics"):
                    self.assertIn(field, saved)
                    self.assertIn(field, record)
                    self.assertEqual(record[field], saved[field],
                                     "actual per-device and summary fields differ: " + field)
                self.assertEqual({
                    "ok": True, "via_ipv4": False,
                    "expected": {"mac": mac, "ipv4": None, "gateway": None},
                    "observed": {"mac": mac, "ipv4": [ip + "/24"], "gateways": []},
                    "mismatches": [],
                }, record["identity"])
                self.assertIsNone(record["backup"])
                expected_body.append("  Device facts: " + hostname)
                if hostname == IB1:
                    expected_body.append('    Route: path="direct" reason="DIRECT_ACCESS" same_subnet="en-public7"')
                else:
                    expected_body.extend([
                        '    Route: path="jump" reason="JUMP_LINK" same_subnet=null',
                        '    Cable: expected="example-jump-a:swp8" actual=["example-jump-a:swp8"] verdict=MATCH after_ping=no ping_ok=unknown ignored=no',
                    ])
                expected_body.extend([
                    f'    Identity: ok=yes via_ipv4=no mac_expected="{mac}" mac_observed="{mac}"',
                    ("hint-transport", hostname),
                ])
            self.assertEqual({"candidates": 1, "authenticated": 1, "not_verified": 0},
                             summary["summary"].get("ipv6_csv_eui64"))
            final_report = (world.root / "report.log").read_text(encoding="utf-8")
            for channel, text in (("console", output.getvalue()), ("report", final_report)):
                with self.subTest(final_channel=channel):
                    self.assertEqual(1, text.count("  TOTAL: 2\n"))
                    after = text.split("  TOTAL: 2\n", 1)[1]
                    self.assertIn("\n+-- 04 CONFIGURATION STAGES", after)
                    body = after.split("\n+-- 04 CONFIGURATION STAGES", 1)[0].strip("\n").splitlines()
                    self.assertEqual(len(expected_body), len(body), "complete final fact body must be retained")
                    for expected, line in zip(expected_body, body):
                        if type(expected) is str:
                            self.assertEqual(expected, line)
                        else:
                            hint = summary["records"][expected[1]]["eth1_hints"][0]
                            self.assertTrue(type(hint["problem"]) is str and bool(hint["problem"].strip()))
                            match = re.fullmatch(r'    eth1 hint: field="eth1_mac" value="" problem=("(?:[^"\\]|\\.)*")', line)
                            self.assertIsNotNone(match)
                            self.assertEqual(hint["problem"], json.loads(match.group(1)))
                    self.assertIn("CSV-derived IPv6 candidates: 1; authenticated=1; not-verified=0", text)
                    self.assertEqual(7, len(re.findall(r"(?m)^\+-- \d\d ", text)))

    def test_mixed_jump_eth0_preflight_cable_survives_real_finish_and_summary(self):
        self._complete_mixed_main(vlan_entry=False)

    def test_mixed_jump_selected_vlan_entry_survives_real_finish_and_summary(self):
        self._complete_mixed_main(vlan_entry=True)


class LoginPathCableAndReadonlyIdentityFinalWorkflowTests(unittest.TestCase):
    """r660 WP5 remaining readonly final consumers, not the WP2 checkpoint.

    Five PUBLIC cases are frozen in wp5-cable-final-design-20261118.txt
    (913918d8baa8291cc309656807ce74ee9fdcd430c7ae553429faab4525bd4363).
    The two older completed helpers above retain their success-only contracts.
    """

    def _complete_case(self, case_name):
        from contextlib import redirect_stderr, redirect_stdout
        import hashlib
        import io
        import os
        from pathlib import Path
        import re
        import shlex
        import sys
        from unittest import mock
        from test_cases.test_initial_setup_cable_check import _Facade, PUBLIC_REPLY
        from test_cases.test_initial_setup_direct_transport import DirectWorld, INITIAL, ROOT

        # Independent input/model literals, never obtained from a CableCheck,
        # worker record or formatter. Only these five cases are admitted.
        cases = {
            "elsewhere": ("ELSEWHERE", False, None, False),
            "ping-ok": ("NOT_LEARNED", True, True, False),
            "ping-fail": ("NOT_LEARNED", True, False, False),
            "ignored": ("ELSEWHERE", False, None, True),
            "identity": ("MATCH", False, None, False),
        }
        if case_name not in cases:
            raise RuntimeError("FIXTURE HOLD: unknown finite WP5 case")
        verdict, after_ping, ping_ok, ignored = cases[case_name]
        preflight_skip = case_name in ("elsewhere", "ping-ok", "ping-fail")
        mismatch = case_name == "identity"
        expected_code, expected_result = ((0, "SUCCESS") if ignored else (2, "INCOMPLETE"))
        expected_workers = {IB1} if preflight_skip else {IB1, IB2}
        expected_routes = {
            IB1: {"hostname": IB1, "path": "direct", "reason": "DIRECT_ACCESS", "jump": None,
                  "port": None, "same_subnet": "en-public7"},
            IB2: {"hostname": IB2, "path": "jump", "reason": "JUMP_LINK", "jump": JA,
                  "port": "swp8", "same_subnet": None},
        }
        expected_cable = {
            "hostname": IB2, "mac": "02:00:00:00:00:12", "link_local": "fe80::ff:fe00:12",
            "expected": ["example-jump-a", "swp8"], "verdict": verdict,
            "actual": ([] if after_ping else [["example-jump-a", "swp8" if mismatch else "swp7"]]),
            "extra_macs": [], "login_interface": "ib-mgmt", "after_ping": after_ping,
            "ping_ok": ping_ok, "ignored": ignored,
        }
        expected_jump = {"hostname": JA, "login_ip": "198.51.100.10", "entry": "JUMP_ETH0",
            "type": "eth_jump", "interface": "ib-mgmt", "vrf": "oob", "access_vlan": None,
            "selection_reason": "LEAF_LOCAL_PATH"}
        expected_neighbor = {"ipv6": "fe80::ff:fe00:12", "interface": "ib-mgmt", "vrf": "oob",
                             "mac": "02:00:00:00:00:12", "address_source": "CSV_EUI64"}
        expected_identities = {
            IB1: {"ok": True, "via_ipv4": False,
                "expected": {"mac": "02:00:00:00:00:10", "ipv4": None, "gateway": None},
                "observed": {"mac": "02:00:00:00:00:10", "ipv4": ["192.0.2.10/24"], "gateways": []},
                "mismatches": []},
            IB2: {"ok": not mismatch, "via_ipv4": False,
                "expected": {"mac": "02:00:00:00:00:12", "ipv4": None, "gateway": None},
                "observed": {"mac": "02:00:00:00:00:99" if mismatch else "02:00:00:00:00:12",
                             "ipv4": ["192.0.2.12/24"], "gateways": []},
                "mismatches": ([{"field": "mac", "expected": "02:00:00:00:00:12",
                                 "observed": "02:00:00:00:00:99"}] if mismatch else [])},
        }
        cable_lines = {
            "elsewhere": '    Cable: expected="example-jump-a:swp8" actual=["example-jump-a:swp7"] verdict=ELSEWHERE after_ping=no ping_ok=unknown ignored=no',
            "ping-ok": '    Cable: expected="example-jump-a:swp8" actual=[] verdict=NOT_LEARNED unlearned=yes after_ping=yes ping_ok=yes ignored=no',
            "ping-fail": '    Cable: expected="example-jump-a:swp8" actual=[] verdict=NOT_LEARNED unlearned=yes after_ping=yes ping_ok=no ignored=no',
            "ignored": '    Cable: expected="example-jump-a:swp8" actual=["example-jump-a:swp7"] verdict=ELSEWHERE after_ping=no ping_ok=unknown ignored=yes',
            "identity": '    Cable: expected="example-jump-a:swp8" actual=["example-jump-a:swp8"] verdict=MATCH after_ping=no ping_ok=unknown ignored=no',
        }
        expected_body = [
            "  Device facts: example-ib01",
            '    Route: path="direct" reason="DIRECT_ACCESS" same_subnet="en-public7"',
            '    Identity: ok=yes via_ipv4=no mac_expected="02:00:00:00:00:10" mac_observed="02:00:00:00:00:10"',
            ("hint-transport", IB1),
            "  Device facts: example-ib02",
            '    Route: path="jump" reason="JUMP_LINK" same_subnet=null',
            cable_lines[case_name],
        ]
        if not preflight_skip:
            expected_body.append(
                '    Identity: ok=no via_ipv4=no mac_expected="02:00:00:00:00:12" mac_observed="02:00:00:00:00:99"'
                if mismatch else
                '    Identity: ok=yes via_ipv4=no mac_expected="02:00:00:00:00:12" mac_observed="02:00:00:00:00:12"')
        expected_body.append(("hint-transport", IB2))
        previous_profile, before_home, before_cwd = sys.getprofile(), os.environ.get("HOME"), Path.cwd()
        module_names = ("tools", "tools.device_identity", "tools.hostname_ranges",
                        "tools.inventory_subset", "tools.login_path")
        absent = object()
        before_modules = {name: sys.modules.get(name, absent) for name in module_names}
        with DirectWorld(self) as world:
            app = world.app
            self.assertFalse((world.project / "01-global.yaml").exists(), "genuine no-global readonly")
            world.write_inventory()
            # Keep MAC10 in each FDB, including both reads of NOT_LEARNED.
            if after_ping:
                world.tables[JA] = (LINKS, [_fdb(MAC1), _fdb(MAC1)], VLANS)
                if ping_ok is False:
                    world.ping_fail.add("fe80::ff:fe00:12%ib-mgmt")
            elif not mismatch:
                world.tables[JA] = (LINKS, [_fdb(MAC1) + _fdb(MAC2, "swp7")], VLANS)
            required = {"tools.device_identity": "main", "tools.hostname_ranges": "main",
                        "tools.login_path": "main", "tools.inventory_subset": "_compare_inventory"}
            required_files = {INITIAL, *(ROOT / "tools" / (name + ".py") for name in
                ("device_identity", "hostname_ranges", "inventory_subset", "login_path"))}
            observed = {"files": set(), "modules": {}, "entered": set(), "prepared": None,
                        "tasks": (), "execute": [], "workers": {}, "finished": [], "metrics": {},
                        "batch": None, "stamp": None, "summary_returned": False}
            ib_calls, external_errors = [], []
            safe_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
            # Closed PUBLIC ordinary options copied from the already existing
            # carrier grammar, not obtained by calling a product argv builder.
            ssh_options = ["-o", "ConnectTimeout=2", "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR"]
            password_only_options = ["-o", "PubkeyAuthentication=no",
                                     "-o", "PreferredAuthentications=password,keyboard-interactive"]

            def reject(*args, **kwargs):
                error = RuntimeError("FIXTURE HOLD: outside finite WP5 external boundary")
                external_errors.append(error)
                raise error

            def control_bridge(argv, **kwargs):
                if (type(argv) is list and len(argv) == 6 and all(type(word) is str for word in argv)
                        and argv[:2] == ["ssh", "-o"] and argv[2].startswith("ControlPath=")
                        and argv[3] == "-O" and argv[4] in ("check", "exit")
                        and argv[5] == "198.51.100.10"):
                    try:
                        return _World.control(world, argv, **kwargs)
                    except BaseException as error:
                        external_errors.append(error)
                        raise
                return reject()

            # These are deliberate external-IO substitutions, NOT profile
            # observations. DirectWorld has already really loaded this package;
            # MAIN still performs its original mandatory _import_tools checks.
            # Only module references change: shared subprocess.run/time do not.
            # In particular, never delegate to DirectWorld.control's native arm.
            app.subprocess = _Facade(app.subprocess, run=control_bridge, Popen=reject)
            world.paths.subprocess = _Facade(world.paths.subprocess, run=reject, Popen=reject)

            def device_reply(remote, hostname):
                words = shlex.split(remote)
                self.assertTrue(len(words) == 3 and words[:2] == ["sh", "-c"], "ordinary closed remote carrier")
                markers = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", words[2])
                self.assertEqual(1, len(markers))
                marker = markers[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(words[2].startswith(prefix) and words[2].endswith(suffix), "one actual frame")
                text = words[2][len(prefix):-len(suffix)]
                command = shlex.split(text)
                self.assertEqual(shlex.join(command), text, "no additional shell statement")
                self.assertIn(hostname, (IB1, IB2))
                ip = "192.0.2.10" if hostname == IB1 else "192.0.2.12"
                mac = "02:00:00:00:00:10" if hostname == IB1 else "02:00:00:00:00:12"
                if command == ["nv", "config", "show", "-o", "commands"]:
                    body = ("nv set system hostname " + hostname + "\n"
                        "nv set interface eth0 ipv4 address " + ip + "/24\n"
                        "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
                        "nv set interface eth0-1 link state up\nnv set interface eth0-1 type eth\n"
                        "nv set system config auto-save state enabled\nnv set system ztp config-save enabled\n")
                elif command == ["nv", "show", "system", "ztp"]:
                    body = "service disabled\nstate disabled\n"
                elif command == ["ip", "addr", "show", "eth0"]:
                    # The sole O5 failure input is an actual external addr
                    # reply, never a category/worker-result injection.
                    if mismatch and hostname == IB2:
                        mac = "02:00:00:00:00:99"
                    body = ("2: eth0: <UP> mtu 1500 state UP\n    link/ether " + mac
                            + " brd ff:ff:ff:ff:ff:ff\n    inet " + ip + "/24 scope global eth0\n")
                elif command == ["ip", "route"]:
                    body = "default via 192.0.2.1 dev eth0\n"
                elif command == ["hostname"]:
                    # U4 (v3.1.6 D1d, guide 8.11): the closed Linux hostname read after the NVUE
                    # hostname is verified; this healthy device's Linux name is its NVUE hostname.
                    body = hostname + "\n"
                else:
                    return reject()
                ib_calls.append((hostname, tuple(command)))
                return app.SessionResult("__HTTP_IB_BEGIN_" + marker + "__\n" + body
                                         + "__HTTP_IB_END_" + marker + "__=0\n", 0)

            def external(argv, responder, timeout, **kwargs):
                self.assertTrue(type(argv) is list and len(argv) >= 3 and all(type(word) is str for word in argv))
                self.assertEqual("ssh", argv[0], "no real executable or alternate boundary")
                if "-M" in argv:
                    path = world._scoped_path(argv)
                    self.assertEqual(["ssh", "-M", "-N", *ssh_options, "-o", "ControlPath=" + path,
                        "-o", "ControlPersist=600", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
                        "cumulus@198.51.100.10"], argv)
                    return _World.interactive(world, argv, responder, timeout, **kwargs)
                destination = argv[-2]
                if destination == "cumulus@198.51.100.10":
                    carrier = shlex.split(argv[-1])
                    self.assertTrue(len(carrier) == 3 and carrier[:2] == ["sh", "-c"]
                                    and carrier[2].startswith(safe_path), "exact outer PATH carrier")
                    inner = shlex.split(carrier[2][len(safe_path):])
                    path = world._scoped_path(argv)
                    nested = inner[:5] == ["ip", "vrf", "exec", "oob", "ssh"]
                    self.assertEqual(["ssh", *(["-tt"] if nested else []), *ssh_options,
                        "-o", "ControlMaster=no", "-o", "ControlPath=" + path, destination], argv[:-1])
                    if not nested:
                        # Original PUBLIC snapshot/identity/FDB/typed-ping
                        # model; no shell or SSH client is executed.
                        if tuple(inner) not in {
                            ("hostname",), ("nv", "show", "interface"),
                            ("ip", "-j", "address", "show"), ("ip", "-d", "link", "show"),
                            ("bridge", "vlan", "show"), ("bridge", "fdb", "show"),
                            ("ifquery", "ib-mgmt"),
                            ("ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "1",
                             "fe80::ff:fe00:12%ib-mgmt"),
                        }:
                            return reject()
                        return _World.interactive(world, argv, responder, timeout, **kwargs)
                    self.assertIn(path, world.masters)
                    self.assertEqual("198.51.100.10", world.masters[path])
                    header = ["ip", "vrf", "exec", "oob", "ssh", "-6", "-tt", "-o", "ConnectTimeout=2",
                        "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", "-o", "ControlMaster=no",
                        "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1"]
                    password_only = ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"]
                    tail = ["-B", "ib-mgmt", "admin@fe80::ff:fe00:12"]
                    self.assertTrue(inner[:-1] in (header + tail, header + password_only + tail),
                                    "exact original nested IPv6 carrier")
                    self.assertIs(type(responder), app.NestedResponder)
                    self.assertIsNone(responder._phase)
                    self.assertEqual(PUBLIC_REPLY, responder.ib_default_password)
                    return device_reply(inner[-1], IB2)
                self.assertIn(destination, ("admin@fe80::ff:fe00:10%en-public7",
                                           "admin@192.0.2.10", "admin@192.0.2.12"))
                self.assertIsNone(getattr(responder, "_phase", None))
                expected_type = app.NestedResponder if "ConnectionAttempts=1" in argv else app._DirectResponder
                self.assertIs(type(responder), expected_type)
                self.assertEqual(PUBLIC_REPLY, responder.ib_default_password)
                direct_header = ["ssh", "-6" if destination == "admin@fe80::ff:fe00:10%en-public7" else "-4",
                                 "-tt", *ssh_options]
                if "ConnectionAttempts=1" in argv:
                    direct_header += ["-o", "ConnectionAttempts=1"]
                direct_header += ["-o", "ProxyCommand=none", "-o", "ProxyJump=none",
                    "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1"]
                admitted = [direct_header + password_only_options + [destination]]
                if "ConnectionAttempts=1" not in argv:
                    admitted.append(direct_header + [destination])
                self.assertIn(argv[:-1], admitted, "only the exact ordinary direct/final-read carrier")
                return device_reply(argv[-1], IB2 if destination == "admin@192.0.2.12" else IB1)

            def external_observer(*args, **kwargs):
                try:
                    return external(*args, **kwargs)
                except BaseException as error:
                    external_errors.append(error)
                    raise

            def profile(frame, event, value):
                filename = Path(frame.f_code.co_filename)
                if event == "call" and filename in required_files:
                    observed["files"].add(filename)
                if frame.f_globals is not app.__dict__:
                    return
                name = frame.f_code.co_name
                if event == "call":
                    observed["entered"].add(name)
                if event == "return" and name == "_new_jump_sessions" and value is not None:
                    world.sessions = value
                elif event == "return" and name == "_import_tools":
                    requested, caller = frame.f_locals.get("name"), frame.f_back
                    if (requested in required and caller is not None and caller.f_globals is app.__dict__
                            and caller.f_code.co_name == required[requested]):
                        observed["modules"].setdefault(requested, []).append(value)
                elif event == "return" and name == "prepare_routed_ib_tasks":
                    observed["prepared"] = json.loads(json.dumps(frame.f_locals["records"].get(IB2)))
                elif event == "call" and name == "run_prepared_tasks":
                    observed["tasks"] = tuple(frame.f_locals["tasks"])
                    observed["stamp"] = frame.f_locals["args"].run_stamp
                    world.expected_device_prefix = "devices-" + observed["stamp"] + "-"
                    self.assertIsNone(frame.f_locals["policy"])
                elif name == "execute_ib_task":
                    hostname = frame.f_locals["task"].target.ib.hostname
                    if event == "call":
                        observed["execute"].append(hostname)
                    elif event == "return" and type(value) is dict:
                        observed["workers"][hostname] = {key: json.loads(json.dumps(value[key]))
                            for key in ("outcome", "stage_status", "writes_attempted") if key in value}
                elif name == "finish" and "task" in frame.f_locals and "record" in frame.f_locals:
                    hostname = frame.f_locals["task"].target.ib.hostname
                    if event == "call":
                        observed["metrics"][hostname] = dict(frame.f_locals["metrics"] or {})
                    elif event == "return":
                        observed["finished"].append(hostname)
                elif event == "return" and name == "run_prepared_tasks":
                    observed["batch"] = value
                elif event == "return" and name == "print_initial_setup_summary":
                    observed["summary_returned"] = True

            output = io.StringIO()
            argv = [str(INITIAL), "--project-dir", str(world.project), "--ib-csv", str(world.csv),
                "--p2p", str(world.p2p), "--direct-access", IB1, "--report", str(world.root / "report.log"),
                "--target-cache", str(world.root / "targets.json"), "--snapshot-dir", str(world.root / "snapshots"),
                "--execution-mode", "management", "--max-workers", "1", "--connect-timeout", "2"]
            if ignored:
                argv.append("--ignore-cable-check")
            try:
                with mock.patch.object(sys, "argv", argv), mock.patch.object(app, "interactive_run", new=external_observer), \
                     redirect_stdout(output), redirect_stderr(output):
                    sys.setprofile(profile)
                    code = app._standalone_main_with_report_cleanup()
            finally:
                sys.setprofile(previous_profile)
            if external_errors:
                raise external_errors[0]
            if type(observed["batch"]) is not dict or not observed["summary_returned"]:
                raise RuntimeError("PREREQUISITE HOLD: real WP5 MAIN/final summary did not complete")
            if any(record.get("script_error") for record in observed["batch"]["records"].values()):
                raise RuntimeError("SOURCE ERROR: a worker program error is not business RED")
            self.assertEqual(expected_code, code)
            self.assertEqual(required_files, observed["files"])
            self.assertTrue({"main", "prepare_routed_ib_tasks", "prepare_ready_ib_tasks", "execute_ib_task",
                             "run_prepared_tasks", "print_initial_setup_summary"} <= observed["entered"])
            self.assertEqual(set(required), set(observed["modules"]))
            for module_name, modules in observed["modules"].items():
                self.assertTrue(bool(modules))
                for module in modules:
                    self.assertIs(module, sys.modules[module_name])
                    self.assertEqual((ROOT / "tools" / (module_name.split(".")[1] + ".py")).resolve(),
                                     Path(module.__file__).resolve())
            self.assertEqual(expected_workers, {task.target.ib.hostname for task in observed["tasks"]})
            self.assertEqual(expected_workers, set(observed["execute"]))
            self.assertEqual(len(expected_workers), len(observed["execute"]))
            self.assertEqual(expected_workers, set(observed["workers"]))
            self.assertEqual(expected_workers, set(observed["finished"]))
            self.assertEqual(len(expected_workers), len(observed["finished"]))
            self.assertEqual(expected_cable, observed["prepared"]["cable_check"])
            self.assertEqual({JA: 2 if after_ping else 1}, world.fdb_reads)
            expected_pings = [("ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "1",
                               "fe80::ff:fe00:12%ib-mgmt")] if after_ping else []
            self.assertEqual(expected_pings, [command for command in world.commands(JA) if "ping" in command])
            self.assertEqual([("master", "198.51.100.10", "key")],
                             [event for event in world.events if event[0] == "master"])
            self.assertNotIn(("ip", "neighbor"), world.commands())
            folder = Path(observed["batch"]["log_dir"])
            self.assertEqual(world.root, folder.parent)
            self.assertTrue(folder.name.startswith("devices-" + observed["stamp"] + "-"))
            summary_path = folder / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(0o600, summary_path.stat().st_mode & 0o777)
            self.assertEqual(expected_result, summary["result"])
            self.assertEqual("CHECK_ONLY", summary["mode"])
            self.assertEqual(hashlib.sha256(INITIAL.read_bytes()).hexdigest(), summary["source_sha256"])
            self.assertEqual(expected_routes, summary["routes"])
            self.assertEqual({IB1, IB2}, set(summary["records"]))
            for hostname in (IB1, IB2):
                record = summary["records"][hostname]
                self.assertEqual(hostname, record["hostname"])
                self.assertEqual(expected_routes[hostname], record["route"])
                self.assertIs(False, record["writes_attempted"])
                self.assertEqual([], record["input_issues"])
                self.assertEqual(1, len(record["eth1_hints"]))
                hint = record["eth1_hints"][0]
                self.assertEqual({"hostname", "field", "value", "problem", "blocking"}, set(hint))
                self.assertEqual({"hostname": hostname, "field": "eth1_mac", "value": "", "blocking": False},
                    {key: hint[key] for key in ("hostname", "field", "value", "blocking")})
                self.assertTrue(type(hint["problem"]) is str and bool(hint["problem"].strip()))
                self.assertNotIn("csv_fdb_mac_check", record)
                if hostname == IB2 and preflight_skip:
                    self.assertEqual("SKIPPED", record["outcome"])
                    self.assertEqual("SKIPPED_CABLE_CHECK_FAILED", record["category"])
                    self.assertFalse((folder / (hostname + ".json")).exists(), "no finish means no fabricated device JSON")
                    # No demand for unmeasured identity/backup keys or files.
                    continue
                expected_outcome = "FAILED" if hostname == IB2 and mismatch else "ALREADY_CONFIGURED"
                expected_category = ("FAILED_IDENTITY_MISMATCH" if hostname == IB2 and mismatch
                                     else "CHECKED_EXISTING_CONFIGURATION")
                self.assertEqual(expected_outcome, record["outcome"])
                self.assertEqual(expected_category, record["category"])
                self.assertEqual(expected_identities[hostname], record["identity"])
                self.assertIsNone(record["backup"], "readonly has no backup receipt")
                expected_authentication = "FAILED" if hostname == IB2 and mismatch else "VERIFIED"
                self.assertEqual(expected_authentication, observed["workers"][hostname]["stage_status"]["authentication"])
                if hostname == IB2 and mismatch:
                    self.assertEqual("authentication", record["failed_stage"])
                if not (hostname == IB2 and mismatch):
                    self.assertEqual("VERIFIED", observed["workers"][hostname]["stage_status"]["direct_ssh"])
                saved = json.loads((folder / (hostname + ".json")).read_text(encoding="utf-8"))
                for key in ("outcome", "stage_status", "writes_attempted"):
                    self.assertEqual(observed["workers"][hostname][key], record[key], "parent cannot replace worker " + key)
                for key in ("route", "cable_check", "identity", "input_issues", "eth1_hints", "backup",
                            "jump", "neighbor", "outcome", "category", "writes_attempted", "metrics", "stage_status"):
                    self.assertIn(key, saved)
                    self.assertEqual(record[key], saved[key], "durable/summary mismatch: " + key)
                self.assertTrue(observed["metrics"][hostname].get("ib_ssh_attempts", 0) > 0)
                self.assertEqual(observed["metrics"][hostname], record["metrics"])
            direct_record, jump_record = summary["records"][IB1], summary["records"][IB2]
            self.assertIsNone(direct_record["jump"])
            self.assertIsNone(direct_record["neighbor"])
            self.assertIsNone(direct_record["cable_check"])
            self.assertEqual(expected_cable, jump_record["cable_check"])
            if not preflight_skip:
                self.assertEqual(expected_jump, jump_record["jump"])
                self.assertEqual(expected_neighbor, jump_record["neighbor"])
            self.assertEqual(expected_workers, {hostname for hostname, command in ib_calls})
            if mismatch:
                self.assertEqual([("nv", "config", "show", "-o", "commands"), ("ip", "addr", "show", "eth0")],
                                 [command for hostname, command in ib_calls if hostname == IB2],
                                 "real O5 failure stops only IB2 before ZTP/readiness and any write")
            self.assertFalse(any(command[:2] == ("nv", "set") or command[:2] == ("sh", "-c")
                                 for hostname, command in ib_calls))
            # Check production finally *before* the world's safety cleanup.
            self.assertFalse(world.masters)
            self.assertTrue(app.REPORT_HANDLE is not None and app.REPORT_HANDLE.closed is True)
            self.assertEqual((world.root / "report.log").resolve(), Path(app.REPORT_HANDLE.name).resolve())
            self.assertIsNone(app._ACTIVE_COORDINATOR)
            self.assertIsNone(app._TASK_DEADLINE)
            self.assertIsNone(app._TASK_LOG_BUFFER)
            self.assertIs(previous_profile, sys.getprofile())
            report = (world.root / "report.log").read_text(encoding="utf-8")
            for channel, text in (("console", output.getvalue()), ("report", report)):
                with self.subTest(final_channel=channel):
                    panels = list(re.finditer(r"(?m)^\+-- (\d\d) ", text))
                    self.assertEqual(["01", "02", "03", "04", "05", "06", "07"],
                                     [panel.group(1) for panel in panels])
                    panel03 = text[panels[2].start():panels[3].start()]
                    self.assertEqual(1, panel03.count("  TOTAL: 2\n"))
                    body = panel03.split("  TOTAL: 2\n", 1)[1].strip("\n").splitlines()
                    self.assertEqual(len(expected_body), len(body), "whole final facts block, not a startup/log match")
                    for expected, line in zip(expected_body, body):
                        if type(expected) is str:
                            self.assertEqual(expected, line)
                        else:
                            match = re.fullmatch(r'    eth1 hint: field="eth1_mac" value="" problem=("(?:[^"\\]|\\.)*")', line)
                            self.assertIsNotNone(match)
                            # Business fields/nonempty problem were independently
                            # checked above. This comparison checks transport only.
                            self.assertEqual(summary["records"][expected[1]]["eth1_hints"][0]["problem"],
                                             json.loads(match.group(1)))
            expected_csv_counts = {
                "elsewhere": {"candidates": 0, "authenticated": 0, "not_verified": 0},
                "ping-ok": {"candidates": 0, "authenticated": 0, "not_verified": 0},
                "ping-fail": {"candidates": 0, "authenticated": 0, "not_verified": 0},
                "ignored": {"candidates": 1, "authenticated": 1, "not_verified": 0},
                "identity": {"candidates": 1, "authenticated": 0, "not_verified": 1},
            }[case_name]
            # CSV-only provenance must not accidentally revive legacy ND/FDB
            # counters. This runs after the full final-panel assertions.
            self.assertEqual(expected_csv_counts, summary["summary"].get("ipv6_csv_eui64"))
            self.assertEqual({"candidates": 0, "authenticated": 0, "not_verified": 0},
                             summary["summary"]["ipv6_fallback"])
            self.assertEqual(0, summary["summary"]["ipv6_address_sources"].get("ND", 0))
            self.assertEqual(0, summary["summary"]["ipv6_address_sources"].get("FDB_EUI64_CANDIDATE", 0))
        self.assertTrue(before_home == os.environ.get("HOME"), "original HOME restored without disclosure")
        self.assertEqual(before_cwd, Path.cwd())
        self.assertIs(previous_profile, sys.getprofile())
        for module_name, module in before_modules.items():
            self.assertIs(module, sys.modules.get(module_name, absent), "original module binding restored")

    def test_elsewhere_cable_skip_survives_real_main_final_panel(self):
        self._complete_case("elsewhere")

    def test_not_learned_ping_ok_survives_real_main_final_panel(self):
        self._complete_case("ping-ok")

    def test_not_learned_ping_fail_survives_real_main_final_panel(self):
        self._complete_case("ping-fail")

    def test_ignored_elsewhere_keeps_original_facts_after_real_finish(self):
        self._complete_case("ignored")

    def test_readonly_identity_mismatch_isolated_and_summarised(self):
        self._complete_case("identity")


class LoginPathPlanCheckClassificationWorkflowTests(unittest.TestCase):
    def test_plan_classification_matches_summary_routes(self):
        """Four valid PUBLIC inputs, two real MAINs, no new PLAN artifact."""
        from contextlib import redirect_stderr, redirect_stdout
        import hashlib
        import io
        import os
        from pathlib import Path
        import re
        import shlex
        import sys
        from unittest import mock
        from test_cases.test_initial_setup_cable_check import _Facade, PUBLIC_REPLY
        from test_cases.test_initial_setup_direct_transport import DirectWorld, INITIAL, ROOT

        # Frozen before implementation: 45b498 design section 2/3. The master
        # is independently written, not generated by editing the subset.
        subset = (
            "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
            "example-ib01,ib,192.0.2.10,24,192.0.2.1,02:00:00:00:00:10,,,\n"
            "example-ib02,ib,192.0.2.12,24,192.0.2.1,02:00:00:00:00:12,,,\n"
            "example-ib03,ib,192.0.2.14,24,192.0.2.1,02:00:00:00:00:14,,,\n"
            "example-ib04,ib,192.0.2.16,24,192.0.2.1,02:00:00:00:00:16,,,\n"
            "example-jump-a,eth_jump,198.51.100.10,,,02:00:00:00:01:10,,,\n"
            "example-access01,eth,,,,,,,\n")
        master = (
            "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
            "example-ib01,ib,192.0.2.10,24,192.0.2.1,02:00:00:00:00:10,,,\n"
            "example-ib02,ib,192.0.2.12,24,192.0.2.1,02:00:00:00:00:12,,,\n"
            "example-ib03,ib,192.0.2.14,24,192.0.2.1,02:00:00:00:00:14,,,\n"
            "example-ib04,ib,192.0.2.16,24,192.0.2.1,02:00:00:00:00:16,,,\n"
            "example-jump-a,eth,198.51.100.10,,,02:00:00:00:01:10,,,\n"
            "example-access01,eth,,,,,,,\n")
        p2p = ("a-node,a-port,z-node,z-port\n"
            "example-ib01,eth0,example-jump-a,swp7\n"
            "example-ib02,eth0,example-access01,swp2\n"
            "example-ib04,eth0,example-jump-a,swp8\n")
        expected_lines = [
            "Route example-ib01: jump JUMP_LINK; jump=example-jump-a port=swp7 same_subnet=no",
            "Route example-ib02: direct PEER_NOT_JUMP; jump=- port=- same_subnet=en-public7",
            "Route example-ib03: direct NO_MGMT_LINK; jump=- port=- same_subnet=en-public7",
            "Route example-ib04: direct DIRECT_ACCESS; jump=- port=- same_subnet=en-public7",
        ]
        expected_routes = {
            "example-ib01": {"hostname": "example-ib01", "path": "jump", "reason": "JUMP_LINK",
                "jump": "example-jump-a", "port": "swp7", "same_subnet": None},
            "example-ib02": {"hostname": "example-ib02", "path": "direct", "reason": "PEER_NOT_JUMP",
                "jump": None, "port": None, "same_subnet": "en-public7"},
            "example-ib03": {"hostname": "example-ib03", "path": "direct", "reason": "NO_MGMT_LINK",
                "jump": None, "port": None, "same_subnet": "en-public7"},
            "example-ib04": {"hostname": "example-ib04", "path": "direct", "reason": "DIRECT_ACCESS",
                "jump": None, "port": None, "same_subnet": "en-public7"},
        }
        # Independent external device facts, not copied from targets/records.
        devices = {
            "example-ib01": ("192.0.2.10", "02:00:00:00:00:10"),
            "example-ib02": ("192.0.2.12", "02:00:00:00:00:12"),
            "example-ib03": ("192.0.2.14", "02:00:00:00:00:14"),
            "example-ib04": ("192.0.2.16", "02:00:00:00:00:16"),
        }
        direct_ll = {
            "admin@fe80::ff:fe00:12%en-public7": "example-ib02",
            "admin@fe80::ff:fe00:14%en-public7": "example-ib03",
            "admin@fe80::ff:fe00:16%en-public7": "example-ib04",
        }
        final_ipv4 = {
            "admin@192.0.2.10": "example-ib01", "admin@192.0.2.12": "example-ib02",
            "admin@192.0.2.14": "example-ib03", "admin@192.0.2.16": "example-ib04",
        }
        previous_profile, before_home, before_cwd = sys.getprofile(), os.environ.get("HOME"), Path.cwd()
        names = ("tools", "tools.device_identity", "tools.hostname_ranges", "tools.inventory_subset", "tools.login_path")
        absent = object()
        before_modules = {name: sys.modules.get(name, absent) for name in names}
        with DirectWorld(self) as world:
            app = world.app
            self.assertFalse((world.project / "01-global.yaml").exists())
            world.csv.write_text(subset, encoding="utf-8")
            world.master.write_text(master, encoding="utf-8")
            world.p2p.write_text(p2p, encoding="utf-8")
            originals = {path: path.read_bytes() for path in (world.csv, world.master, world.p2p)}
            world.by_address = {"198.51.100.10": "example-jump-a"}
            world.tables[JA] = (LINKS, ["02:00:00:00:00:10 dev swp7 vlan 1000 master br_default\n"], VLANS)
            self.assertEqual('[{"ifname": "en-public7", "addr_info": [{"family": "inet", "local": "192.0.2.1", "prefixlen": 24}, '
                '{"family": "inet6", "local": "fe80::1", "prefixlen": 64}]}]', world.local_json)
            required = {"tools.device_identity": "main", "tools.hostname_ranges": "main",
                "tools.login_path": "main", "tools.inventory_subset": "_compare_inventory"}
            required_files = {INITIAL, *(ROOT / "tools" / (name + ".py") for name in
                ("device_identity", "hostname_ranges", "inventory_subset", "login_path"))}
            external_errors, ib_calls = [], []
            ssh_options = ["-o", "ConnectTimeout=2", "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR"]
            password_options = ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"]
            safe_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "

            def reject(*args, **kwargs):
                error = RuntimeError("FIXTURE HOLD: outside finite PLAN/CHECK PUBLIC IO")
                external_errors.append(error)
                raise error

            def control_bridge(argv, **kwargs):
                try:
                    self.assertIs(type(argv), list)
                    self.assertEqual(6, len(argv))
                    self.assertTrue(all(type(word) is str for word in argv))
                    path = world._scoped_path(argv)
                    self.assertEqual("0", Path(path).name)
                    self.assertRegex(Path(path).parent.name, r"^isj-[A-Za-z0-9_-]+$")
                    self.assertEqual(world.sessions.records[JA]["path"], path)
                    self.assertIn(argv, (["ssh", "-o", "ControlPath=" + path, "-O", "check", "198.51.100.10"],
                                         ["ssh", "-o", "ControlPath=" + path, "-O", "exit", "198.51.100.10"]))
                    self.assertEqual({"text": True, "capture_output": True, "timeout": 2, "check": False}, kwargs)
                    return _World.control(world, argv, **kwargs)
                except BaseException as error:
                    external_errors.append(error)
                    raise

            # Explicit local external facades, not profile mutation or shared
            # stdlib.run/time patches. Never call DirectWorld.control's native arm.
            app.subprocess = _Facade(app.subprocess, run=control_bridge, Popen=reject)
            world.paths.subprocess = _Facade(world.paths.subprocess, run=reject, Popen=reject)

            def device_reply(remote, hostname, *, final=False):
                words = shlex.split(remote)
                self.assertEqual(3, len(words))
                self.assertEqual(["sh", "-c"], words[:2])
                self.assertEqual(shlex.join(words), remote)
                markers = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", words[2])
                self.assertEqual(1, len(markers))
                marker = markers[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(words[2].startswith(prefix) and words[2].endswith(suffix))
                text = words[2][len(prefix):-len(suffix)]
                command = shlex.split(text)
                self.assertEqual(shlex.join(command), text)
                self.assertIn(hostname, devices)
                ip, mac = devices[hostname]
                if command == ["nv", "config", "show", "-o", "commands"]:
                    body = ("nv set system hostname " + hostname + "\n"
                        "nv set interface eth0 ipv4 address " + ip + "/24\n"
                        "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
                        "nv set interface eth0-1 link state up\nnv set interface eth0-1 type eth\n"
                        "nv set system config auto-save state enabled\nnv set system ztp config-save enabled\n")
                elif not final and command == ["nv", "show", "system", "ztp"]:
                    body = "service disabled\nstate disabled\n"
                elif not final and command == ["ip", "addr", "show", "eth0"]:
                    body = ("2: eth0: <UP> mtu 1500 state UP\n    link/ether " + mac
                        + " brd ff:ff:ff:ff:ff:ff\n    inet " + ip + "/24 scope global eth0\n")
                elif not final and command == ["ip", "route"]:
                    body = "default via 192.0.2.1 dev eth0\n"
                elif not final and command == ["hostname"]:
                    # U4 (v3.1.6 D1d, guide 8.11): the closed Linux hostname read after the NVUE
                    # hostname is verified; this healthy device's Linux name is its NVUE hostname.
                    body = hostname + "\n"
                else:
                    return reject()
                ib_calls.append((hostname, "ipv4" if final else "ll", tuple(command)))
                return app.SessionResult("__HTTP_IB_BEGIN_" + marker + "__\n" + body
                    + "__HTTP_IB_END_" + marker + "__=0\n", 0)

            def ordinary_responder(responder, destination, cls):
                self.assertIs(type(responder), cls)
                self.assertIsNone(responder._phase)
                self.assertEqual(destination, responder.ib_destination)
                self.assertEqual(PUBLIC_REPLY, responder.ib_default_password)
                self.assertIs(False, responder.allow_password_change)
                self.assertIsNone(responder.ib_new_password)

            def external(argv, responder, timeout, **kwargs):
                self.assertIs(type(argv), list)
                self.assertTrue(all(type(word) is str for word in argv))
                self.assertEqual({}, kwargs)
                self.assertGreaterEqual(len(argv), 3)
                if "-M" in argv:
                    path = world._scoped_path(argv)
                    self.assertEqual("0", Path(path).name)
                    self.assertEqual(world.sessions.records[JA]["path"], path)
                    self.assertEqual(["ssh", "-M", "-N", *ssh_options, "-o", "ControlPath=" + path,
                        "-o", "ControlPersist=600", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
                        "cumulus@198.51.100.10"], argv)
                    self.assertEqual(15, timeout)
                    self.assertIsNone(responder("PUBLIC no credential prompt"))
                    return _World.interactive(world, argv, responder, timeout, **kwargs)
                destination = argv[-2]
                if destination == "cumulus@198.51.100.10":
                    carrier = shlex.split(argv[-1])
                    self.assertEqual(3, len(carrier))
                    self.assertEqual(["sh", "-c"], carrier[:2])
                    self.assertEqual(shlex.join(carrier), argv[-1])
                    self.assertTrue(carrier[2].startswith(safe_path))
                    inner_text = carrier[2][len(safe_path):]
                    inner = shlex.split(inner_text)
                    self.assertEqual(shlex.join(inner), inner_text)
                    path = world._scoped_path(argv)
                    self.assertIn(path, world.masters)
                    self.assertEqual("198.51.100.10", world.masters[path])
                    nested = inner[:5] == ["ip", "vrf", "exec", "oob", "ssh"]
                    self.assertEqual(["ssh", *(["-tt"] if nested else []), *ssh_options,
                        "-o", "ControlMaster=no", "-o", "ControlPath=" + path, destination], argv[:-1])
                    if not nested:
                        self.assertEqual(2, timeout)
                        self.assertIn(tuple(inner), {("hostname",), ("nv", "show", "interface"),
                            ("ip", "-j", "address", "show"), ("ip", "-d", "link", "show"),
                            ("bridge", "vlan", "show"), ("bridge", "fdb", "show"), ("ifquery", "ib-mgmt")})
                        self.assertIsNone(responder("PUBLIC no credential prompt"))
                        return _World.interactive(world, argv, responder, timeout, **kwargs)
                    self.assertEqual(60, timeout)
                    header = ["ip", "vrf", "exec", "oob", "ssh", "-6", "-tt", "-o", "ConnectTimeout=2",
                        "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", "-o", "ControlMaster=no",
                        "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1"]
                    tail = ["-B", "ib-mgmt", "admin@fe80::ff:fe00:10"]
                    self.assertIn(inner[:-1], (header + tail, header + password_options + tail))
                    ordinary_responder(responder, "admin@fe80::ff:fe00:10", app.NestedResponder)
                    self.assertEqual("", responder.ethernet_password)
                    self.assertIsNone(responder("cumulus@198.51.100.10's password: "))
                    self.assertEqual(PUBLIC_REPLY, responder("admin@fe80::ff:fe00:10's password: "))
                    return device_reply(inner[-1], "example-ib01")
                if destination in direct_ll:
                    self.assertEqual(60, timeout)
                    header = ["ssh", "-6", "-tt", *ssh_options, "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
                        "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1"]
                    self.assertIn(argv[:-1], (header + [destination], header + password_options + [destination]))
                    ordinary_responder(responder, destination, app._DirectResponder)
                    self.assertEqual("", responder.ethernet_password)
                    return device_reply(argv[-1], direct_ll[destination])
                self.assertIn(destination, final_ipv4)
                self.assertEqual(15, timeout)
                self.assertEqual(["ssh", "-4", "-tt", *ssh_options, "-o", "ConnectionAttempts=1",
                    "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no",
                    "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1", *password_options, destination], argv[:-1])
                ordinary_responder(responder, destination, app.NestedResponder)
                self.assertEqual("", responder.ethernet_password)
                return device_reply(argv[-1], final_ipv4[destination], final=True)

            def external_observer(*args, **kwargs):
                try:
                    return external(*args, **kwargs)
                except BaseException as error:
                    external_errors.append(error)
                    raise

            runs = []
            for planning, report_name in ((True, "plan-report.log"), (False, "check-report.log")):
                observed = {"files": set(), "modules": {}, "calls": [], "tasks": (), "execute": [],
                    "finished": [], "workers": {}, "batch": None, "summary": False}

                def profile(frame, event, value):
                    filename = Path(frame.f_code.co_filename)
                    if event == "call" and filename in required_files:
                        observed["files"].add(filename)
                    if frame.f_globals is not app.__dict__:
                        return
                    name = frame.f_code.co_name
                    if event == "call":
                        observed["calls"].append(name)
                    if event == "return" and name == "_import_tools":
                        requested, caller = frame.f_locals.get("name"), frame.f_back
                        if (requested in required and caller is not None and caller.f_globals is app.__dict__
                                and caller.f_code.co_name == required[requested]):
                            observed["modules"].setdefault(requested, []).append(value)
                    elif event == "return" and name == "_new_jump_sessions" and value is not None:
                        world.sessions = value  # external carrier observation, no production metadata
                    elif event == "call" and name == "run_prepared_tasks":
                        observed["tasks"] = tuple(frame.f_locals["tasks"])
                        world.expected_device_prefix = "devices-" + frame.f_locals["args"].run_stamp + "-"
                        self.assertIsNone(frame.f_locals["policy"])
                    elif name == "execute_ib_task":
                        hostname = frame.f_locals["task"].target.ib.hostname
                        if event == "call":
                            observed["execute"].append(hostname)
                        elif event == "return" and type(value) is dict:
                            observed["workers"][hostname] = json.loads(json.dumps(value))
                    elif name == "finish" and "task" in frame.f_locals and event == "return":
                        observed["finished"].append(frame.f_locals["task"].target.ib.hostname)
                    elif event == "return" and name == "run_prepared_tasks":
                        observed["batch"] = value
                    elif event == "return" and name == "print_initial_setup_summary":
                        observed["summary"] = True

                report_path = world.root / report_name
                argv = [str(INITIAL), "--project-dir", str(world.project), "--ib-csv", str(world.csv),
                    "--p2p", str(world.p2p), "--direct-access", "example-ib04", "--report", str(report_path),
                    "--target-cache", str(world.root / "targets.json"), "--snapshot-dir", str(world.root / "snapshots"),
                    "--execution-mode", "management", "--max-workers", "1", "--connect-timeout", "2"]
                if planning:
                    argv.append("--plan")
                output = io.StringIO()
                try:
                    with mock.patch.object(sys, "argv", argv), mock.patch.object(app, "interactive_run", new=external_observer), \
                         redirect_stdout(output), redirect_stderr(output):
                        sys.setprofile(profile)
                        code = app._standalone_main_with_report_cleanup()
                finally:
                    sys.setprofile(previous_profile)
                if external_errors:
                    raise external_errors[0]
                if not planning:
                    if type(observed["batch"]) is not dict or not observed["summary"]:
                        raise RuntimeError("PREREQUISITE HOLD: real CHECK MAIN/final summary did not complete")
                    if any(record.get("script_error") for record in observed["batch"]["records"].values()):
                        raise RuntimeError("SOURCE ERROR: worker program error is not business RED")
                self.assertEqual(0, code)
                self.assertEqual(1, observed["calls"].count("main"))
                self.assertEqual(required_files, observed["files"])
                self.assertEqual(set(required), set(observed["modules"]))
                for module_name, modules in observed["modules"].items():
                    for module in modules:
                        self.assertIs(module, sys.modules[module_name])
                        self.assertEqual((ROOT / "tools" / (module_name.split(".")[1] + ".py")).resolve(),
                            Path(module.__file__).resolve())
                for path, original in originals.items():
                    self.assertEqual(original, path.read_bytes())
                # Production finally, before the world's emergency cleanup.
                self.assertFalse(world.masters)
                self.assertIsNone(app._JUMP_SESSIONS)
                self.assertIsNone(app._ACTIVE_COORDINATOR)
                self.assertIsNone(app._TASK_DEADLINE)
                self.assertIsNone(app._TASK_LOG_BUFFER)
                self.assertTrue(app.REPORT_HANDLE is not None and app.REPORT_HANDLE.closed is True)
                self.assertEqual(report_path.resolve(), Path(app.REPORT_HANDLE.name).resolve())
                self.assertIs(previous_profile, sys.getprofile())
                report = report_path.read_text(encoding="utf-8")
                route_lines = re.findall(r"(?m)^Route .*$", output.getvalue())
                self.assertEqual(expected_lines, route_lines)
                self.assertEqual(expected_lines, re.findall(r"(?m)^Route .*$", report))
                runs.append((observed, route_lines))
                if planning:
                    self.assertTrue({"main", "build_targets", "_compare_inventory", "_runtime_routes"}
                        <= set(observed["calls"]))
                    for name in ("_new_jump_sessions", "prepare_ready_ib_tasks", "prepare_routed_ib_tasks",
                                 "run_prepared_tasks", "execute_ib_task", "finish", "print_initial_setup_summary"):
                        self.assertNotIn(name, observed["calls"])
                    self.assertEqual([], world.events)
                    self.assertEqual([], ib_calls)
                    self.assertIsNone(world.sessions)
                    self.assertIsNone(observed["batch"])
                    self.assertEqual([], list(world.root.glob("devices-*")))
                    base_cache = json.loads((world.root / "targets.json").read_text(encoding="utf-8"))
                    self.assertEqual({"hostname": "example-ib04", "path": "jump", "reason": "JUMP_LINK",
                        "jump": "example-jump-a", "port": "swp8", "same_subnet": None}, base_cache["routes"]["example-ib04"])
                    continue
                self.assertTrue({"main", "prepare_ready_ib_tasks", "prepare_routed_ib_tasks", "run_prepared_tasks",
                    "execute_ib_task", "finish", "print_initial_setup_summary"} <= set(observed["calls"]))
                self.assertEqual(1, observed["calls"].count("prepare_routed_ib_tasks"))
                self.assertEqual(1, observed["calls"].count("prepare_ready_ib_tasks"))
                self.assertEqual(1, observed["calls"].count("run_prepared_tasks"))
                self.assertEqual(set(devices), {task.target.ib.hostname for task in observed["tasks"]})
                self.assertEqual(4, len(observed["tasks"]))
                self.assertEqual(set(devices), set(observed["execute"]))
                self.assertEqual(4, len(observed["execute"]))
                self.assertEqual(set(devices), set(observed["finished"]))
                self.assertEqual(4, len(observed["finished"]))
                self.assertEqual(set(devices), set(observed["workers"]))
                self.assertTrue(observed["summary"])
                self.assertIs(type(observed["batch"]), dict)
                self.assertEqual(1, observed["batch"]["workers"])
                folder = Path(observed["batch"]["log_dir"])
                self.assertEqual(world.root, folder.parent)
                summary_path = folder / "summary.json"
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                self.assertEqual(0o600, summary_path.stat().st_mode & 0o777)
                self.assertEqual("SUCCESS", summary["result"])
                self.assertEqual("CHECK_ONLY", summary["mode"])
                self.assertEqual(hashlib.sha256(INITIAL.read_bytes()).hexdigest(), summary["source_sha256"])
                self.assertEqual(expected_routes, summary["routes"])
                self.assertEqual(set(devices), set(summary["records"]))
                self.assertEqual(set(devices), {path.stem for path in folder.glob("*.json")} - {"summary"})
                for hostname in devices:
                    record = summary["records"][hostname]
                    worker = observed["workers"][hostname]
                    if record.get("script_error"):
                        raise RuntimeError("SOURCE ERROR: worker program error is not business RED")
                    self.assertEqual(expected_routes[hostname], record["route"])
                    self.assertEqual([], record["input_issues"])
                    self.assertEqual("ALREADY_CONFIGURED", record["outcome"])
                    self.assertEqual("CHECKED_EXISTING_CONFIGURATION", record["category"])
                    self.assertIs(False, record["writes_attempted"])
                    self.assertIsNone(record["backup"])
                    self.assertEqual("VERIFIED", record["stage_status"]["authentication"])
                    self.assertEqual("VERIFIED", record["stage_status"]["direct_ssh"])
                    self.assertIs(True, record["identity"]["ok"])
                    self.assertEqual(devices[hostname][1], record["identity"]["expected"]["mac"])
                    self.assertEqual(devices[hostname][1], record["identity"]["observed"]["mac"])
                    self.assertNotIn("csv_fdb_mac_check", record)
                    if hostname == "example-ib01":
                        self.assertEqual("MATCH", record["cable_check"]["verdict"])
                        self.assertEqual("CSV_EUI64", record["neighbor"]["address_source"])
                    else:
                        for key in ("jump", "neighbor", "cable_check"):
                            self.assertIsNone(record[key])
                    saved_path = folder / (hostname + ".json")
                    saved = json.loads(saved_path.read_text(encoding="utf-8"))
                    self.assertEqual(expected_routes[hostname], saved["route"])
                    for key in ("outcome", "stage_status", "writes_attempted"):
                        self.assertEqual(worker[key], record[key])
                    for key in ("route", "identity", "cable_check", "backup", "jump", "neighbor", "input_issues",
                                "eth1_hints", "outcome", "category", "writes_attempted", "stage_status", "metrics"):
                        self.assertEqual(record[key], saved[key])
                    for metric in ("nvue_write_commands", "config_backup_attempts", "public_key_install_attempts"):
                        self.assertEqual(0, record["metrics"].get(metric, 0))
                self.assertEqual({JA: 1}, world.fdb_reads)
                self.assertEqual([("master", "198.51.100.10", "key")],
                    [event for event in world.events if event[0] == "master"])
                self.assertFalse(any("ping" in command or command == ("ip", "neighbor") for command in world.commands()))
                self.assertEqual(set(devices), {hostname for hostname, transport, command in ib_calls if transport == "ll"})
                self.assertEqual(set(devices), {hostname for hostname, transport, command in ib_calls if transport == "ipv4"})
                self.assertEqual(4, len([1 for hostname, transport, command in ib_calls if transport == "ipv4"]))
                # Both independent oracles passed above. Only now compare the
                # two actual representations as transport, not expected data.
                projected = []
                for line in runs[0][1]:
                    match = re.fullmatch(r"Route (\S+): (\S+) (\S+); jump=(\S+) port=(\S+) same_subnet=(\S+)", line)
                    self.assertIsNotNone(match)
                    row = list(match.groups())
                    row[3:] = [None if word in ("-", "no") else word for word in row[3:]]
                    projected.append(tuple(row))
                self.assertEqual(projected, [tuple(summary["routes"][name][key] for key in
                    ("hostname", "path", "reason", "jump", "port", "same_subnet")) for name in sorted(summary["routes"])])
        self.assertTrue(before_home == os.environ.get("HOME"), "original HOME restored without disclosure")
        self.assertEqual(before_cwd, Path.cwd())
        self.assertIs(previous_profile, sys.getprofile())
        for module_name, module in before_modules.items():
            self.assertIs(module, sys.modules.get(module_name, absent), "original module binding restored")


if __name__ == "__main__":
    unittest.main()
