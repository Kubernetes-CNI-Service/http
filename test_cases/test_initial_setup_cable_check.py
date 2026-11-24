"""r629 WP2 independent direct contracts; static tests-first draft, not run.

Oracle sources: guide 624--697, 4.0 K2/K8/K9, I-037 rules 4--6,
D1b-O1/O2/O2a/O3/O4/O11. Values below are PUBLIC hand-written vectors.
The shared world also supports the WP2 subset in login_path_workflow. It uses
real main/readers/M4/login_path/JumpSessions, but models only the external SSH
boundary in process. It never executes an SSH client or an IB worker.
"""
from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import csv
import importlib
import io
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.native_cpld_physical_io import owned_test_root


ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
IB1, IB2, IB3 = "example-ib01", "example-ib02", "example-ib03"
JA, JB, SP = "example-jump-a", "example-jump-b", "oob-spine01"
MAC1, MAC2, MAC3 = "02:00:00:00:00:10", "02:00:00:00:00:12", "02:00:00:00:00:14"
LL1, LL2, LL3 = "fe80::ff:fe00:10", "fe80::ff:fe00:12", "fe80::ff:fe00:14"
JMAC = "02:00:00:00:01:10"
PUBLIC_REPLY = "-".join(("PUBLIC", "wp2", "response", "Zq7"))
HEADER = ("hostname", "type", "eth0_ip", "netmask", "eth0_gw", "eth0_mac",
          "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac", "vlan_ports",
          "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac", "vlan_ports")
VLANS = "port              vlan-id\nswp7              1000 PVID Egress Untagged\nswp8              1000 PVID Egress Untagged\n"
LINKS = ("1: br_default: <UP> mtu 1500 state UP\n"
         "2: swp7: <UP> mtu 1500 master br_default state UP\n"
         "3: swp8: <UP> mtu 1500 master br_default state UP\n"
         "4: ib-mgmt@br_default: <UP> mtu 1500 master oob state UP\n"
         "    vlan protocol 802.1Q id 1000 <REORDER_HDR>\n")
LEAF_NO_SVI = LINKS.split("4: ib-mgmt@")[0]


def _fdb(mac, port="swp7"):
    return mac + " dev " + port + " vlan 1000 master br_default\n"


def _interfaces(ports=("swp7", "swp8"), *, down=(), spine=None):
    # Column widths are fixture literals; real LLDP parsing must use Remote Host.
    widths = (16, 15, 15, 10, 8, 10, 28, 16, 16)
    def row(values):
        return "".join(str(v).ljust(w) for v, w in zip(values, widths)).rstrip()
    lines = [row(("Interface", "Admin Status", "Oper Status", "Speed", "MTU", "Type",
                  "Remote Host", "Remote Port", "Summary"))]
    for port in ports:
        lines.append(row((port, "up", "down" if port in down else "up", "1G", "1500", "swp",
                          "nvos", "eth0", "")))
    if spine is not None:
        lines.append(row(("swp49", "up", "up", "100G", "1500", "swp", spine, "swp1", "")))
    return "\n".join(lines) + "\n"


def _addresses(*, with_svi=True, mac=JMAC):
    rows = [{"ifname": "eth0", "address": mac, "flags": ["UP"], "operstate": "UP",
             "addr_info": [{"family": "inet", "local": "198.51.100.10", "prefixlen": 24}]}]
    if with_svi:
        rows.append({"ifname": "ib-mgmt", "flags": ["UP"], "operstate": "UP", "addr_info": [
            {"family": "inet", "local": "192.0.2.1", "prefixlen": 24},
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64}]})
    return json.dumps(rows)


class _DispatchReached(Exception):
    """Read-only profile hook stopped before the real task runner's first line."""


class _Facade:
    """Replace an app reference, never shared stdlib attributes."""
    def __init__(self, original, **changes):
        self._original, self._changes = original, changes

    def __getattr__(self, name):
        return self._changes[name] if name in self._changes else getattr(self._original, name)


class _World:
    """Owned PUBLIC IO model. No production function or return value is faked.

    Only external command/human/local-interface observations are substituted.
    sys.setprofile records real preparation returns without changing them and
    raises at run_prepared_tasks entry; no worker outcome/summary is fabricated.
    All per-device summary assertions beyond this boundary belong to WP5.
    """
    def __init__(self, case):
        self.case = case
        self.stack = ExitStack()
        self.events, self.prepared, self.records, self.entered = [], (), {}, set()
        self.entered_files = set()
        self.masters, self.fdb_reads, self.sessions = {}, {}, None
        self.tables = {
            JA: (LINKS, [_fdb(MAC1) + _fdb(MAC2, "swp8")], VLANS),
            JB: (LINKS, [_fdb(MAC3)], VLANS),
            SP: (LINKS, [""], VLANS),
        }
        self.oper, self.mac, self.hostname = {}, {}, {}
        self.network, self.key_denied, self.authentication, self.hostkey = set(), set(), set(), set()
        self.ping_fail = set()
        self.spine_leaf = False
        self.drop_after_snapshot, self.dropped = False, False

    def deny(self, *args, **kwargs):
        raise AssertionError("WP2 unexpected external effect")

    def __enter__(self):
        try:
            own = owned_test_root()
            self.case.assertEqual(own, Path(os.environ["TMPDIR"]))
            self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="wp2-", dir=own))
            self.root = Path(self.temp)
            self.case.assertEqual(0o700, stat.S_IMODE(self.root.lstat().st_mode))
            self.home = self.root / "home"
            self.home.mkdir(mode=0o700)
            self.project = self.root / "project"
            self.project.mkdir(mode=0o700)
            self.csv, self.master = self.project / "ib.csv", self.project / "02-devices_config.csv"
            self.p2p = self.project / "p2p.csv"
            original_cwd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
            def restore_cwd():
                try:
                    os.fchdir(original_cwd)
                finally:
                    os.close(original_cwd)
            self.stack.callback(restore_cwd)
            os.chdir(own)
            self.stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(self.home)}))
            self.stack.enter_context(mock.patch.object(sys, "path", [str(ROOT), *sys.path]))
            self.stack.enter_context(mock.patch.dict(sys.modules))
            for name in ("tools", "tools.login_path", "tools.device_identity", "tools.hostname_ranges",
                         "tools.inventory_subset"):
                sys.modules.pop(name, None)
            self.stack.enter_context(mock.patch.object(subprocess, "Popen", side_effect=self.deny))
            self.stack.enter_context(mock.patch.object(socket, "socket", side_effect=self.deny))
            self.stack.enter_context(mock.patch.object(os, "system", side_effect=self.deny))
            self.stack.enter_context(mock.patch.object(os, "execve", side_effect=self.deny))
            for name in ("execv", "execvp", "execvpe", "execl", "execlp", "execlpe",
                         "posix_spawn", "posix_spawnp", "fork"):
                if hasattr(os, name):
                    self.stack.enter_context(mock.patch.object(os, name, side_effect=self.deny))
            self.app = load_script("v315_wp2_" + self.root.name.replace("-", "_"), INITIAL)
            package = importlib.import_module("tools")
            self.stack.enter_context(mock.patch.object(package, "__path__", [str(ROOT / "tools")]))
            self.paths = self.app._import_tools("tools.login_path")
            real_mkdtemp = tempfile.mkdtemp
            def own_master_directory(*args, **kwargs):
                self.case.assertEqual((), args)
                self.case.assertEqual("isj-", kwargs.get("prefix"))
                # The production dir argument is only an observed boundary
                # input. It does not grant test write authority or define WP2.
                path = Path(real_mkdtemp(prefix="isj-", dir=own))
                self.case.assertEqual(own, path.parent)
                self.case.assertEqual(path, path.resolve())
                info = path.lstat()
                self.case.assertEqual(os.geteuid(), info.st_uid)
                self.case.assertEqual(0o700, stat.S_IMODE(info.st_mode))
                self.stack.callback(lambda: path.rmdir() if path.exists() else None)
                relative = str(path.relative_to(own))
                self.case.assertLessEqual(len(os.fsencode(relative)) + 17, 104)
                return relative  # short SSH path, cwd is the owned root
            self.app.tempfile = _Facade(tempfile, mkdtemp=own_master_directory)
            self.app.subprocess = _Facade(subprocess, run=self.control, Popen=self.deny)
            self.app.socket = _Facade(socket, gethostname=lambda: "example-management",
                                      getfqdn=lambda: "example-management.example.test", socket=self.deny)
            self.app.time = _Facade(time, sleep=lambda delay: self.events.append(("sleep", delay)))
            self.stack.enter_context(mock.patch.object(self.app, "interactive_run", side_effect=self.interactive))
            self.stack.enter_context(mock.patch.object(self.app, "_read_local_interfaces", return_value=()))
            self.initial_password = self.stack.enter_context(mock.patch.object(
                self.app, "resolve_initial_ib_password", return_value=PUBLIC_REPLY))
            self.stack.enter_context(mock.patch.object(self.app.sys.stdin, "isatty", return_value=True))
            self.stack.enter_context(mock.patch("builtins.input", return_value="yes"))
            self.stack.enter_context(mock.patch.object(self.app.getpass, "getpass", return_value=PUBLIC_REPLY))
            self.write_inventory()
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *error):
        try:
            if getattr(self, "app", None) is not None and self.app.REPORT_HANDLE is not None:
                self.app.REPORT_HANDLE.close()
                self.app.REPORT_HANDLE = None
            if self.sessions is not None and self.sessions.directory is not None:
                self.sessions.close_jump_masters()
        finally:
            self.stack.close()
        return False

    def write_inventory(self, *, two_jumps=False, three=False, leaf_kind="eth_jump", jump_mac=JMAC):
        rows = [[IB1, "ib", "192.0.2.10", "24", "192.0.2.1", MAC1],
                [IB2, "ib", "192.0.2.12", "24", "192.0.2.1", MAC2],
                [JA, leaf_kind, "198.51.100.10", "", "", jump_mac,
                 "1000", "198.51.100.11", "24", "", "", "",
                 "2000", "198.51.100.12", "24"]]
        links = [(IB1, "eth0", JA, "swp7"), (IB2, "eth0", JA, "swp8")]
        if two_jumps:
            rows.append([JB, "eth_jump", "203.0.113.10", "", "", ""])
        if three:
            rows.append([IB3, "ib", "192.0.2.14", "24", "192.0.2.1", MAC3])
            links.append((IB3, "eth0", JB, "swp7"))
        if self.spine_leaf:
            rows.append([SP, "eth_jump", "198.51.100.21", "", "", ""])
            links.append((JA, "swp49", SP, "swp1"))
        for file in (self.csv, self.master):
            with file.open("w", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(HEADER)
                writer.writerows([row + [""] * (len(HEADER) - len(row)) for row in rows])
        with self.p2p.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(("a-node", "a-port", "z-node", "z-port"))
            writer.writerows(links)
        self.by_address = {"198.51.100.10": JA, "198.51.100.11": JA,
                           "198.51.100.12": JA, "203.0.113.10": JB, "198.51.100.21": SP}

    def _scoped_path(self, argv):
        values = [x.split("=", 1)[1] for x in argv if x.startswith("ControlPath=")]
        self.case.assertEqual(1, len(values), "one actual multiplex path")
        path = Path(values[0])
        self.case.assertNotEqual("none", str(path), "real D4 master required")
        self.case.assertEqual(owned_test_root(), path.resolve().parent.parent)
        return str(path)

    def control(self, argv, **kwargs):
        self.case.assertIs(type(argv), list)
        self.case.assertEqual(("ssh", "-o", "-O"), (argv[0], argv[1], argv[3]))
        self.case.assertEqual(6, len(argv))
        self.case.assertIn(argv[4], ("check", "exit"))
        path = self._scoped_path(argv)
        self.case.assertIn(argv[5], self.by_address)
        code = 0 if path in self.masters else 255
        self.events.append(("control", argv[4], argv[5]))
        if argv[4] == "exit":
            self.masters.pop(path, None)
        return subprocess.CompletedProcess(argv, code, "", "")

    def interactive(self, argv, responder, timeout, **kwargs):
        self.case.assertIs(type(argv), list)
        self.case.assertEqual("ssh", argv[0], "no absolute or non-SSH executable")
        path = self._scoped_path(argv)
        if "-M" in argv:
            self.case.assertIn("-N", argv)
            endpoint = argv[-1]
            self.case.assertTrue(endpoint.startswith("cumulus@"))
            address = endpoint.split("@", 1)[1]
            self.case.assertIn(address, self.by_address)
            key = "BatchMode=yes" in argv
            self.events.append(("master", address, "key" if key else "password"))
            if address in self.network:
                return self.app.SessionResult("ssh: connect to host " + address + " port 22: Connection timed out\n", 255)
            if address in self.hostkey:
                return self.app.SessionResult("REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed.\n", 255)
            if key and (address in self.key_denied or address in self.authentication):
                return self.app.SessionResult("Permission denied (publickey).\n", 255)
            if not key:
                self.case.assertEqual(PUBLIC_REPLY, responder(endpoint + "'s password: "))
                if address in self.authentication:
                    return self.app.SessionResult("Permission denied (password).\n", 255)
            self.masters[path] = address
            return self.app.SessionResult("", 0)
        self.case.assertIn(path, self.masters)
        address = self.masters[path]
        # ControlPath is authoritative for the selected master. The original
        # Device's compatibility login_ip can still appear in the outer argv.
        self.case.assertTrue(argv[-2].startswith("cumulus@"))
        self.case.assertIn(argv[-2].split("@", 1)[1], self.by_address)
        self.case.assertEqual(self.by_address[address], self.by_address[argv[-2].split("@", 1)[1]])
        outer = shlex.split(argv[-1])
        self.case.assertEqual(["sh", "-c"], outer[:2])
        self.case.assertEqual(3, len(outer))
        prefix, separator, command = outer[2].partition("; exec ")
        self.case.assertTrue(prefix.startswith("export PATH="))
        self.case.assertEqual("; exec ", separator)
        remote = shlex.split(command)
        host = self.by_address[address]
        self.events.append(("command", host, tuple(remote)))
        if remote == ["hostname"]:
            output = self.hostname.get(host, host) + "\n"
        elif remote == ["nv", "show", "interface"]:
            output = _interfaces(down=self.oper.get(host, ()), spine=SP if self.spine_leaf and host == JA else None)
            if host == JA and self.drop_after_snapshot and not self.dropped:
                self.masters.pop(path)
                self.dropped = True
        elif remote == ["ip", "-d", "link", "show"]:
            output = self.tables[host][0]
        elif remote == ["bridge", "vlan", "show"]:
            output = self.tables[host][2]
        elif remote == ["bridge", "fdb", "show"]:
            index = self.fdb_reads.get(host, 0)
            self.fdb_reads[host] = index + 1
            options = self.tables[host][1]
            output = options[min(index, len(options) - 1)]
        elif remote == ["ip", "neighbor"]:
            # Deliberately wrong legacy address; new code must never ask for it.
            output = "fe80::1234 dev ib-mgmt lladdr " + MAC1 + " REACHABLE\n"
        elif remote == ["ip", "-j", "address", "show"]:
            output = _addresses(with_svi=not (self.spine_leaf and host == JA), mac=self.mac.get(host, JMAC))
        elif remote == ["ifquery", "ib-mgmt"]:
            output = "iface ib-mgmt\n    vrf oob\n"
        elif remote[:10] == ["ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "1"]:
            self.case.assertEqual(11, len(remote))
            self.case.assertIn(remote[10], (LL1 + "%ib-mgmt", LL2 + "%ib-mgmt", LL3 + "%ib-mgmt"))
            if remote[10] in self.ping_fail:
                return self.app.SessionResult("", 1)
            output = ""
        else:
            raise AssertionError("unmodelled PUBLIC jump command: " + repr(remote))
        return self.app.SessionResult(output, 0)

    def profile(self, frame, event, value):
        name = frame.f_code.co_name
        if event == "call" and frame.f_code.co_filename.startswith(str(ROOT / "tools") + os.sep):
            self.entered_files.add(Path(frame.f_code.co_filename).name)
        if frame.f_globals is self.app.__dict__:
            if event == "call":
                self.entered.add(name)
                if name == "choose_oob_spine":
                    self.events.append(("spine-choice",))
                if name == "run_prepared_tasks":
                    self.prepared = tuple(frame.f_locals["tasks"])
                    self.events.append(("dispatch", tuple(t.target.ib.hostname for t in self.prepared)))
                    raise _DispatchReached()
            elif event == "return":
                if name == "_new_jump_sessions" and value is not None:
                    self.sessions = value
                if name in {"prepare_ready_ib_tasks", "prepare_routed_ib_tasks"}:
                    self.records.update(frame.f_locals.get("records", {}))

    def invoke(self, *options, expect_dispatch=True):
        argv = [str(INITIAL), "--project-dir", str(self.project), "--p2p", str(self.p2p),
                "--report", str(self.root / "report.log"), "--target-cache", str(self.root / "targets.json"),
                "--snapshot-dir", str(self.root / "snapshots"), "--execution-mode", "management", *options]
        output = io.StringIO()
        previous = sys.getprofile()
        reached, code = False, None
        with mock.patch.object(sys, "argv", argv), redirect_stdout(output), redirect_stderr(output):
            try:
                sys.setprofile(self.profile)
                code = self.app.main()
            except _DispatchReached:
                reached = True
            except self.app.SetupError as error:
                # Expose the exact refusal to the test; never treat code 2 as success.
                print("SETUP_REFUSAL:", str(error))
                code = 2
            finally:
                sys.setprofile(previous)
                if self.app.REPORT_HANDLE is not None:
                    self.app.REPORT_HANDLE.close()
                    self.app.REPORT_HANDLE = None
        self.exit_code, self.dispatched = code, reached
        if expect_dispatch:
            self.case.assertTrue(reached, "real pipeline must reach owned pre-dispatch boundary: " + output.getvalue())
            self.case.assertIsNone(code)
        else:
            self.case.assertFalse(reached, "entry refusal must precede task dispatch")
        return output.getvalue()

    def commands(self, host=None):
        return [e[2] for e in self.events if e[0] == "command" and (host is None or e[1] == host)]

    def record_fact(self, host, field):
        self.case.assertIn(host, self.records, "real preparation must retain this device's facts")
        self.case.assertIn(field, self.records[host], "WP2 must retain the " + field + " fact")
        fact = self.records[host][field]
        self.case.assertIs(type(fact), dict)
        return fact


class CableCheckTests(unittest.TestCase):
    def test_jump_readonly_table_accepts_vlan_and_fixed_ping(self):
        """Guide 658: exact new vectors; K8 old vectors/rejections remain."""
        with _World(self) as world:
            app = world.app
            positive = [["hostname"], ["nv", "show", "interface"], ["nv", "config", "show"],
                        ["ip", "-d", "link", "show"], ["bridge", "fdb", "show"], ["ip", "neighbor"],
                        ["ip", "-j", "address", "show"], ["ifquery", "ib-mgmt"], ["bridge", "vlan", "show"],
                        ["ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "1", LL1 + "%ib-mgmt"]]
            for vector in positive:
                with self.subTest(vector=vector):
                    supplied = list(vector)
                    try:
                        actual = app.ethernet_command_argv(supplied)
                    except app.SetupError as error:
                        self.fail("approved read-only vector was refused: " + str(error))
                    self.assertEqual(vector, actual)
                    self.assertEqual(vector, supplied)
            negative = [["bridge", "vlan", "show", "extra"],
                        ["ip", "ping", "-6", "-c", "2", "-W", "1", LL1 + "%ib-mgmt"],
                        ["ip", "vrf", "exec", "oob", "ping", "-6", "-c", "3", "-W", "1", LL1 + "%ib-mgmt"],
                        ["ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "2", LL1 + "%ib-mgmt"],
                        ["ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "1", "2001:db8::10%ib-mgmt"],
                        ["ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "1", LL1 + "%ib-mgmt;id"],
                        ["ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "1", LL1 + "%ib-mgmt", "extra"],
                        ["nv", "config", "apply", "-y"], ["nv", "config", "save"],
                        ["nv", "set", "system", "hostname", "example"], ["sh", "-c", "true"], ["scp", "PUBLIC"]]
            for vector in negative:
                with self.subTest(vector=vector), self.assertRaises(app.SetupError):
                    app.ethernet_command_argv(vector)
            self.assertEqual([], world.events)

    def test_snapshot_reads_vlans_not_neighbors(self):
        """Guide 637/659: actual collector and file publication use VLAN third slot."""
        with _World(self) as world:
            app = world.app
            _, jumps = app.load_devices(world.csv)
            jump = jumps[JA]
            # Real D4 acquire, real outer command builder; only IO response is synthetic.
            sessions = app.JumpSessions(timeout=5)
            world.sessions = sessions
            with mock.patch.object(app, "_JUMP_SESSIONS", sessions):
                sessions.open_jump_master(jump, "cumulus", None)
                network = app.collect_ethernet_network_tables(jump, "cumulus", "", 5)
                self.assertEqual((LINKS.rstrip(), (_fdb(MAC1) + _fdb(MAC2, "swp8")).rstrip(), VLANS.rstrip()), network)
                path = app.save_ethernet_snapshot(world.root / "snapshots", jump, JA, "SSH", "PUBLIC interfaces", *network)
            self.assertEqual([("hostname",), ("ip", "-d", "link", "show"),
                              ("bridge", "fdb", "show"), ("bridge", "vlan", "show")], world.commands(JA))
            content = path.read_text()
            self.assertIn("===== bridge vlan show =====\n" + VLANS, content)
            self.assertNotIn("===== ip neighbor =====", content)

    def test_cable_check_outcomes_in_pipeline(self):
        """Guide 660, O3: other dynamic MAC hints do not block a real match."""
        with _World(self) as world:
            world.tables[JA] = (LINKS, [_fdb(MAC1) + _fdb(MAC2, "swp8") + _fdb("02:00:00:00:00:19")], VLANS)
            world.invoke()
            self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual((LL1, "ib-mgmt", MAC1, "oob", "CSV_EUI64"),
                             tuple(getattr(world.prepared[0].neighbor, key) for key in
                                   ("ipv6", "interface", "mac", "vrf", "address_source")))
            self.assertNotIn(("ip", "neighbor"), world.commands())

    def test_cable_check_cross_jump_cascade_and_bond_literals(self):
        """4.1: all actual tables, cascade exclusion and physical bond member."""
        with _World(self) as world:
            api = world.paths
            tables = [api.JumpTables(JA, LINKS, _fdb(MAC1, "swp8"), VLANS),
                      api.JumpTables(JB, LINKS, _fdb(MAC1), VLANS)]
            fact = api.check_cable(IB1, MAC1, (JA, "swp7"), tables,
                                   cascade_ports=frozenset({(JA, "swp8")}))
            self.assertEqual(("ELSEWHERE", ((JB, "swp7"),), LL1), (fact.verdict, fact.actual, fact.link_local))
            bonded = LINKS.replace("swp7: <UP> mtu 1500 master br_default", "swp7: <UP> mtu 1500 master bond1")
            bonded += "6: bond1: <UP> mtu 1500 master br_default state UP\n"
            fact = api.check_cable(IB1, MAC1, (JA, "swp7"),
                [api.JumpTables(JA, bonded, _fdb(MAC1, "bond1"), VLANS)], cascade_ports=frozenset())
            self.assertEqual(("MATCH", ((JA, "bond1"),), "ib-mgmt"),
                             (fact.verdict, fact.actual, fact.login_interface))
            self.assertEqual([], world.events)

    def test_bonded_cascade_port_is_not_an_actual_device_location(self):
        """Guide485: physical cascade exclusion follows explicit member->bond facts."""
        with _World(self) as world:
            api = world.paths
            links = (LINKS + "6: swp49: <UP> mtu 1500 master bond49 state UP\n"
                     "7: bond49: <UP> mtu 1500 master br_default state UP\n")
            fact = api.check_cable(IB1, MAC1, (JA, "swp7"),
                [api.JumpTables(JA, links, _fdb(MAC1, "bond49"), VLANS)],
                cascade_ports=frozenset({(JA, "swp49")}))
            self.assertEqual(((JA, "swp7"), "NOT_LEARNED", (), LL1),
                             (fact.expected, fact.verdict, fact.actual, fact.link_local))
            self.assertEqual([], world.events)

    def test_real_bonded_cascade_learning_pings_then_rereads_leaf(self):
        """Guide485/642: P2P physical cascade is not ELSEWHERE or a spine fallback."""
        with _World(self) as world:
            # Only use the writer's transit peer/P2P fixture.  The live Leaf
            # still has its own working SVI in LINKS and ip-j observations.
            world.spine_leaf = True
            world.write_inventory()
            world.spine_leaf = False
            links = (LINKS + "6: swp49: <UP> mtu 1500 master bond49 state UP\n"
                     "7: bond49: <UP> mtu 1500 master br_default state UP\n")
            sibling = _fdb(MAC2, "swp8")
            world.tables[JA] = (links, [_fdb(MAC1, "bond49") + sibling,
                                       _fdb(MAC1, "swp7") + sibling], VLANS)
            world.invoke()
            ping = ("command", JA, ("ip", "vrf", "exec", "oob", "ping", "-6", "-c", "2", "-W", "1",
                                     "fe80::ff:fe00:10%ib-mgmt"))
            self.assertEqual([ping], [event for event in world.events
                                      if event[0] == "command" and "ping" in event[2]])
            fdb_positions = [index for index, event in enumerate(world.events)
                             if event == ("command", JA, ("bridge", "fdb", "show"))]
            self.assertEqual(2, len(fdb_positions))
            self.assertLess(fdb_positions[0], world.events.index(ping))
            self.assertLess(world.events.index(ping), fdb_positions[1])
            self.assertEqual((IB1, IB2), tuple(task.target.ib.hostname for task in world.prepared))
            self.assertEqual((JA, JA), tuple(task.target.ethernet.hostname for task in world.prepared))
            self.assertNotIn(("spine-choice",), world.events)
            cable = world.record_fact(IB1, "cable_check")
            self.assertEqual(("MATCH", ((JA, "swp7"),), True, True),
                             (cable["verdict"], cable["actual"], cable["after_ping"], cable["ping_ok"]))

    def test_ping_once_per_jump_then_one_fdb_reread(self):
        """Guide 642/661: three probes, two second reads, FDB (not echo) authoritative."""
        with _World(self) as world:
            world.write_inventory(two_jumps=True, three=True)
            world.tables[JA] = (LINKS, ["", _fdb(MAC1)], VLANS)
            world.tables[JB] = (LINKS, ["", _fdb(MAC3)], VLANS)
            world.ping_fail.add(LL1 + "%ib-mgmt")
            world.invoke()
            self.assertEqual((IB1, IB3), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual({JA: 2, JB: 2}, world.fdb_reads)
            pings = [e for e in world.events if e[0] == "command" and "ping" in e[2]]
            self.assertCountEqual([(JA, LL1 + "%ib-mgmt"), (JA, LL2 + "%ib-mgmt"), (JB, LL3 + "%ib-mgmt")],
                                  [(e[1], e[2][-1]) for e in pings])
            first_pass = set()
            second_reads, ping_positions = [], []
            for index, event in enumerate(world.events):
                if event in pings:
                    ping_positions.append(index)
                if event[0] == "command" and event[2] == ("bridge", "fdb", "show"):
                    if event[1] in first_pass:
                        second_reads.append(index)
                    first_pass.add(event[1])
            self.assertLess(max(ping_positions), min(second_reads))
            row = world.records[IB2]
            self.assertEqual("SKIPPED_CABLE_CHECK_FAILED", row["category"])
            cable = world.record_fact(IB2, "cable_check")
            self.assertIn("after_ping", cable)
            self.assertIn("ping_ok", cable)
            self.assertIs(True, cable["after_ping"])
            self.assertIs(True, cable["ping_ok"])
            self.assertIn("ping", row["reason"].casefold())

    def test_link_down_still_pings(self):
        """O4: a known down port is not an early skip before the FDB recheck."""
        with _World(self) as world:
            world.oper[JA] = ("swp7",)
            world.tables[JA] = (LINKS, [_fdb(MAC2, "swp8"), _fdb(MAC1) + _fdb(MAC2, "swp8")], VLANS)
            world.invoke()
            self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual(1, sum(cmd[-1:] == (LL1 + "%ib-mgmt",) for cmd in world.commands(JA)))

    def test_unknown_port_still_refuses_without_ping(self):
        """O11: an absent port remains a dependency error, distinct from Oper down."""
        with _World(self) as world:
            world.tables[JA] = (LINKS, [_fdb(MAC1) + _fdb(MAC2, "swp8")], VLANS)
            real = world.interactive
            def missing(argv, responder, timeout, **kwargs):
                result = real(argv, responder, timeout, **kwargs)
                if world.events and world.events[-1] == ("command", JA, ("nv", "show", "interface")):
                    return world.app.SessionResult(_interfaces(ports=("swp8",)), 0)
                return result
            with mock.patch.object(world.app, "interactive_run", side_effect=missing):
                world.invoke()
            self.assertEqual((IB2,), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual("SKIPPED_PORT_STATE_UNKNOWN", world.records[IB1]["category"])
            self.assertFalse(any("ping" in cmd for cmd in world.commands(JA)))

    def test_unknown_unlearned_port_refuses_before_any_ping(self):
        """O11/guide355,642: unknown port has no cable eligibility, unlike DOWN."""
        with _World(self) as world:
            # The physical link/VLAN facts remain complete, but the current
            # interface observation has no swp7 and no FDB has MAC1.  A good
            # sibling must still be prepared; missing learning cannot promote
            # the unknown physical port into the centralized ping plan.
            world.tables[JA] = (LINKS, [_fdb(MAC2, "swp8")], VLANS)
            real = world.interactive
            def missing(argv, responder, timeout, **kwargs):
                result = real(argv, responder, timeout, **kwargs)
                if world.events and world.events[-1] == ("command", JA, ("nv", "show", "interface")):
                    return world.app.SessionResult(_interfaces(ports=("swp8",)), 0)
                return result
            with mock.patch.object(world.app, "interactive_run", side_effect=missing):
                world.invoke()
            self.assertEqual((IB2,), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual("SKIPPED_PORT_STATE_UNKNOWN", world.records[IB1]["category"])
            self.assertFalse(any("ping" in cmd for cmd in world.commands()),
                             "an unknown physical port must be refused before centralized ping")

    def test_ignore_cable_check_logs_in_via_expected_vlan(self):
        """Guide 643/662: ignore retains expected endpoint, CSV address and actual evidence."""
        with _World(self) as world:
            world.tables[JA] = (LINKS, [_fdb(MAC1, "swp8") + _fdb(MAC2, "swp8")], VLANS)
            world.invoke("--ignore-cable-check")
            self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
            first = world.prepared[0]
            self.assertEqual((IB1, JA, "swp7", LL1, "ib-mgmt", "CSV_EUI64"),
                (first.target.ib.hostname, first.target.ethernet.hostname, first.target.ethernet_port,
                 first.neighbor.ipv6, first.neighbor.interface, first.neighbor.address_source))
            cable = world.record_fact(IB1, "cable_check")
            self.assertIn("ignored", cable)
            self.assertIs(True, cable["ignored"])
            self.assertIn("swp8", json.dumps(cable))

    def test_link_local_always_from_csv_mac(self):
        """Guide 663: deliberately inconsistent old ND must never be queried."""
        with _World(self) as world:
            world.invoke()
            self.assertEqual((LL1, LL2), tuple(t.neighbor.ipv6 for t in world.prepared))
            self.assertNotIn(("ip", "neighbor"), world.commands())
            self.assertTrue(all(t.neighbor.address_source == "CSV_EUI64" for t in world.prepared))

    def test_leaf_without_svi_keeps_physical_cable_fact(self):
        """Guide 642: optional transport interface must not erase physical verdict."""
        with _World(self) as world:
            api = world.paths
            try:
                fact = api.check_cable(IB1, MAC1, (JA, "swp7"),
                    [api.JumpTables(JA, LEAF_NO_SVI, _fdb(MAC1), VLANS)], cascade_ports=frozenset())
            except ValueError as error:
                self.fail("unique Leaf VLAN without local SVI still has a cable fact: " + str(error))
            self.assertEqual(((JA, "swp7"), "MATCH", ((JA, "swp7"),), LL1, None),
                             (fact.expected, fact.verdict, fact.actual, fact.link_local, fact.login_interface))
            with self.assertRaises(ValueError):
                api.login_interface(LEAF_NO_SVI, VLANS, "swp7")
            for links, vlans in ((LINKS, VLANS + "swp7              2000\n"),
                                  (LINKS + "9: extra@br_default: <UP>\n    vlan id 1000\n", VLANS)):
                with self.subTest(links=links, vlans=vlans):
                    with self.assertRaises(ValueError):
                        api.login_interface(links, vlans, "swp7")
                    with self.assertRaises(ValueError):
                        api.check_cable(IB1, MAC1, (JA, "swp7"),
                            [api.JumpTables(JA, links, _fdb(MAC1), vlans)], cascade_ports=frozenset())

    def test_all_cable_failures_never_request_ib_credentials(self):
        """Rule 4/P11: blocked-before-login tasks cannot cause an IB credential prompt."""
        with _World(self) as world:
            world.tables[JA] = (LINKS, [_fdb(MAC1, "swp8") + _fdb(MAC2)], VLANS)
            world.invoke()
            self.assertEqual((), world.prepared)
            world.initial_password.assert_not_called()
            self.assertEqual({IB1, IB2}, set(world.records))
            self.assertEqual({"SKIPPED_CABLE_CHECK_FAILED"}, {row["category"] for row in world.records.values()})

    def test_spine_uses_csv_link_local_and_port_vlan(self):
        """Guide 642/644/664: selected spine pings; physical Leaf is reread."""
        with _World(self) as world:
            world.spine_leaf = True
            world.write_inventory()
            world.tables[JA] = (LEAF_NO_SVI, ["", _fdb(MAC1) + _fdb(MAC2, "swp8")], VLANS)
            world.invoke()
            self.assertEqual((IB1, IB2), tuple(t.target.ib.hostname for t in world.prepared))
            self.assertEqual((SP, SP), tuple(t.target.ethernet.hostname for t in world.prepared))
            self.assertEqual((LL1, LL2), tuple(t.neighbor.ipv6 for t in world.prepared))
            self.assertTrue(all(t.target.source_attachment.peer == JA for t in world.prepared))
            self.assertTrue(all(t.target.attachment.ethernet.hostname == JA for t in world.prepared))
            self.assertEqual(1, world.events.count(("spine-choice",)))
            self.assertEqual(2, world.fdb_reads[JA])
            self.assertEqual([(SP, LL1 + "%ib-mgmt"), (SP, LL2 + "%ib-mgmt")],
                [(e[1], e[2][-1]) for e in world.events if e[0] == "command" and "ping" in e[2]])

    def test_spine_needs_jump_typed_leaf(self):
        """Guide 665/O21: physical ordinary Leaf is not a login endpoint."""
        with _World(self) as world:
            world.write_inventory(leaf_kind="eth")
            devices, ethernet = world.app.load_devices(world.csv)
            links = world.app.parse_p2p(world.p2p)
            targets = world.app.build_targets(links, devices, ethernet)
            self.assertEqual(("direct", "direct"), tuple(t.route.path for t in targets))
            self.assertEqual(("PEER_NOT_JUMP", "PEER_NOT_JUMP"), tuple(t.route.reason for t in targets))
            self.assertTrue(all(t.ethernet is None for t in targets))
            self.assertTrue(all(t.source_attachment.peer == JA for t in targets))
            self.assertEqual([], world.events)


if __name__ == "__main__":
    unittest.main()
