"""WP-3 real authority loader -> initial readiness -> unique HostKeyChange parser.

Only synthetic SSH output and a fake clock replace external transport. This is
not the future editor/refresh workflow, native PTY, managed MAIN or field proof.
"""
from contextlib import ExitStack
from pathlib import Path
from dataclasses import asdict, replace
import csv
import io
import json
import os
import re
import shlex
import subprocess
import tempfile
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from test_cases.module_loader import load_script
from test_cases import test_login_path as hostkeys
from test_cases import test_initial_setup_ipv4_readiness as readiness
from test_cases.initial_setup_jump_fixture import legacy_jump_sessions_factory

ROOT = Path(__file__).resolve().parents[1]


class HostKeyReadinessWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        authority = load_script("wp3_real_authority", ROOT / "ztp/config_sync_authority.py")
        cls.app = authority.load_initial_method_executor()

    def verify(self, output, *, strict=False, local=False):
        app = self.app
        with tempfile.TemporaryDirectory(prefix="wp3-hostkey-") as directory, ExitStack() as stack:
            stack.enter_context(mock.patch.object(app, "verify_password_hash", return_value=True))
            kwargs = {"local": local, "ib_password": readiness.credential("current")}
            if strict:
                kwargs = {"_ib_current_password": readiness.credential("current"),
                          "_password_policy": readiness.strict_policy(app, directory)}
            waits = stack.enter_context(mock.patch.object(app.time, "sleep"))
            run = stack.enter_context(mock.patch.object(app, "interactive_run",
                                      return_value=app.SessionResult(output, 255)))
            with self.assertRaises(app.SetupError) as caught:
                app.verify_ipv4_login(readiness.target(app), "oob", "cumulus",
                                      readiness.credential("outer"), "admin", 2, **kwargs)
            run.assert_called_once()
            self.assertEqual([mock.call(15)], waits.call_args_list)
            return caught.exception

    def test_inner_host_key_fatal_carries_real_change_before_safe_choke(self):
        api = hostkeys.parser_module(self)
        error = self.verify(hostkeys.warning(), strict=True)
        self.assertEqual(("management IB operation failed; device state is UNKNOWN",), error.args)
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        change = getattr(error, "host_key_change", None)
        self.assertIs(type(change), api.HostKeyChange, "real parser fact must survive strict fixed-literal choke")
        self.assertEqual(("192.0.2.10", "jump", "EXAMPLE-JUMP01", (7, 9)),
                         (change.address, change.location, change.jump, change.lines))
        self.assertEqual("TARGET_HOST_KEY_CHANGED", error.failure_kind)
        self.assertNotIn("WARNING:", repr(vars(error)))
        self.assertNotIn("@@@@", repr(vars(error)))

    def test_outer_host_key_fact_belongs_to_local_operator(self):
        api = hostkeys.parser_module(self)
        error = self.verify(hostkeys.warning("198.51.100.10", path="/home/operator/.ssh/known_hosts"))
        change = getattr(error, "host_key_change", None)
        self.assertIs(type(change), api.HostKeyChange)
        self.assertEqual(("198.51.100.10", "local", None),
                         (change.address, change.location, change.jump))
        self.assertEqual("outer", error.hop)

    def test_local_leaf_inner_fact_is_local_not_jump(self):
        api = hostkeys.parser_module(self)
        error = self.verify(hostkeys.warning(), local=True)
        change = getattr(error, "host_key_change", None)
        self.assertIs(type(change), api.HostKeyChange)
        self.assertEqual(("192.0.2.10", "local", None),
                         (change.address, change.location, change.jump))

    def test_incomplete_warning_stops_without_fabricating_change(self):
        hostkeys.parser_module(self)
        error = self.verify(hostkeys.warning().replace(hostkeys.FINGERPRINT, "missing"), strict=True)
        self.assertEqual(("management IB operation failed; device state is UNKNOWN",), error.args)
        self.assertIsNone(getattr(error, "host_key_change", None))
        self.assertEqual("TARGET_HOST_KEY_CHANGED", error.failure_kind)


class LocalManagementHostKeyWorkflowTests(unittest.TestCase):
    """Real initial caller -> real parser/editor/refresh; only SSH is synthetic."""
    @classmethod
    def setUpClass(cls):
        hostkeys.LocalHostKeyRefreshTests.setUpClass.__func__(cls)
        cls.app = readiness.load_app("wp4_local_management")

    @classmethod
    def tearDownClass(cls):
        cls.keys_root.cleanup()

    def setUp(self):
        hostkeys.LocalHostKeyRefreshTests.setUp(self)

    def warning(self, *, address="192.0.2.10", path=None):
        return hostkeys.warning(address, path=str(path or self.path), fingerprint=self.keys["new"][1]).replace(
            ":7\r\n", ":2\r\n").replace(":9\r\n", ":3\r\n")

    def options(self, *, apply=True, reader=True):
        return dict(apply=apply, read_device_fingerprint=(lambda _: self.keys["new"][1]) if reader else None,
                    host_key_records=self.records)

    def password_transport(self, argv, *_args, **_kwargs):
        self.calls.append(argv)
        if len(self.calls) == 1:
            return self.app.SessionResult(self.warning(), 255)
        self.assertNotIn("192.0.2.10", self.path.read_text(), "retry occurs only after removal")
        with self.path.open("a") as output:
            output.write("192.0.2.10 " + self.keys["new"][0] + "\n")
        marker = re.search(r"__HTTP_IB_BEGIN_([a-f0-9]{32})__", " ".join(argv)).group(1)
        return self.app.SessionResult("__HTTP_IB_BEGIN_" + marker + "__\n"
                    "nv set system hostname EXAMPLE-IB01\n"
                    "nv set interface eth0 ipv4 address 192.0.2.10/24\n"
                    "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n"
                    "__HTTP_IB_END_" + marker + "__=0\n", 0)

    def test_management_side_record_is_refreshed(self):
        # r508 :736 / D34-O4: actual synthetic file and real two-module transaction.
        self.calls, self.records = [], []
        app = self.app
        with mock.patch.object(Path, "home", return_value=self.home), \
                mock.patch.object(app, "interactive_run", side_effect=self.password_transport), \
                mock.patch.object(app.time, "sleep", side_effect=AssertionError("hostkey retry must not network-wait")):
            rows = app.run_management_direct_checks([readiness.target(app)], {"example-ib01": readiness.credential("current")},
                    "admin", 2, on_management_server=True, **self.options())
        self.assertEqual(["PASS"], [row["status"] for row in rows])
        self.assertEqual(2, len(self.calls))
        self.assertEqual(1, len(self.records))
        self.assertIs(type(self.records[0]), self.api.HostKeyRefreshRecord)
        self.assertEqual(("192.0.2.10", (2, 3), "verified", "refreshed"),
                         (self.records[0].address, self.records[0].lines, self.records[0].verification, self.records[0].result))
        self.assertTrue(self.path.read_text().startswith(self.before.splitlines(True)[0]))
        self.assertNotIn("@@@@", repr(rows) + repr(self.records))

    def test_readonly_or_missing_reader_does_not_delete(self):
        self.records = []
        for options in (self.options(apply=False), self.options(reader=False)):
            self.records.clear()
            with self.subTest(options=options), mock.patch.object(Path, "home", return_value=self.home), \
                    mock.patch.object(self.app, "interactive_run", return_value=self.app.SessionResult(self.warning(), 255)) as run:
                rows = self.app.run_management_direct_checks([readiness.target(self.app)],
                    {"example-ib01": readiness.credential("current")}, "admin", 2,
                    on_management_server=True, **options)
                self.assertEqual(["FAIL"], [row["status"] for row in rows])
                run.assert_called_once()
                self.assertEqual(self.before, self.path.read_text())
                # r508 WP5 item7: failed connectivity remains FAIL, while a
                # matching readonly fact is pending, not refreshed or removed.
                if not options["apply"]:
                    self.assertEqual(1, len(self.records))
                    self.assertEqual("refresh-pending", self.records[0].result)
                    self.assertIsNone(self.records[0].removal)
                    self.assertEqual("HOST_KEY_REFRESH_PENDING", rows[0]["failure_kind"])
                else:
                    self.assertEqual([], self.records)
                self.assertNotIn("@@@@", repr(rows))

    def test_public_key_verification_refreshes_with_original_key_precheck(self):
        self.records, calls = [], []
        app = self.app
        private = Path(self.keys_root.name) / "old"
        real_run = subprocess.run
        def run(argv, **kwargs):
            if argv[0] == "ssh-keygen":
                return real_run(argv, **kwargs)  # all paths are synthetic fixture keys/files.
            self.assertEqual("ssh", argv[0])
            calls.append(argv)
            if len(calls) == 1:
                return subprocess.CompletedProcess(argv, 255, "", self.warning())
            with self.path.open("a") as output:
                output.write("192.0.2.10 " + self.keys["new"][0] + "\n")
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.object(Path, "home", return_value=self.home), mock.patch.object(app.subprocess, "run", side_effect=run):
            app.verify_management_key_possession(readiness.target(app), "admin", {"fingerprint": self.keys["old"][1]},
                                                 private, 2, **self.options())
        self.assertEqual(2, len(calls))
        self.assertEqual(1, len(self.records))
        self.assertEqual("refreshed", self.records[0].result)

    def test_foreign_path_or_address_cannot_refresh_this_target(self):
        self.records = []
        for warning in (self.warning(address="192.0.2.99"), self.warning(path=self.home / "elsewhere")):
            with self.subTest(warning=warning[:7]), mock.patch.object(Path, "home", return_value=self.home), \
                    mock.patch.object(self.app, "interactive_run", return_value=self.app.SessionResult(warning, 255)) as run:
                rows = self.app.run_management_direct_checks([readiness.target(self.app)],
                        {"example-ib01": readiness.credential("current")}, "admin", 2,
                        on_management_server=True, **self.options())
                self.assertEqual(["FAIL"], [row["status"] for row in rows])
                self.assertEqual(self.before, self.path.read_text())
                self.assertEqual([], self.records)
                run.assert_called_once()

    def test_key_stage_forwards_local_refresh_context_without_reinstalling(self):
        app = self.app
        target = readiness.target(app)
        reader, records = mock.Mock(), []
        entry = {"name": "mgmt-server.pub", "fingerprint": self.keys["old"][1]}
        with mock.patch.object(app, "key_install_command", return_value=["PUBLIC-install"]), \
                mock.patch.object(app, "run_on_ib", return_value=app.SessionResult("IBSW_PUBLIC_KEYS_UNCHANGED\n", 0)) as install, \
                mock.patch.object(app, "verify_management_key_possession") as verify:
            app.run_key_stage(target, app.Neighbor("fe80::10", "vlan1000", target.ib.eth0_mac),
                "cumulus", readiness.credential("outer"), "admin", 2, [entry], local=False,
                apply=True, authorized=True, management_private_key=Path(self.keys_root.name) / "old",
                ib_password=readiness.credential("current"), read_device_fingerprint=reader,
                host_key_records=records)
        install.assert_called_once()
        self.assertIs(True, verify.call_args.kwargs["apply"])
        self.assertIs(reader, verify.call_args.kwargs["read_device_fingerprint"])
        self.assertIs(records, verify.call_args.kwargs["host_key_records"])

    def test_local_leaf_actual_non_cumulus_account_can_refresh_own_file(self):
        # WP5 item3: actual passwd user == eth-user; remote cumulus rule is not local rule.
        app = self.app
        task = app.PreparedIBTask(readiness.target(app), app.Neighbor("fe80::10", "vlan1000", "02:00:00:00:00:10"), "", True)
        change = self.api.parse_host_key_change(self.warning(), location="local")
        parent = app.RuntimeCoordinator(SimpleNamespace(apply=True, yes=True, eth_user="operator", connect_timeout=2),
            None, readiness.credential("initial"), [task], SimpleNamespace(assert_unchanged=lambda: None))
        parent.current_target = task.target
        with mock.patch.object(Path, "home", return_value=self.home), \
                mock.patch.object(app.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="operator")), \
                mock.patch.object(app, "_ACTIVE_COORDINATOR", parent), \
                mock.patch.object(app, "interactive_run", side_effect=AssertionError("Leaf edit must stay local")):
            records = []
            try:
                result = app.refresh_ib_host_key(change, task, eth_user="operator", timeout=2, apply=True,
                    read_device_fingerprint=lambda _: self.keys["new"][1],
                    retry=lambda: hostkeys.LocalHostKeyRefreshTests.accept_new(self),
                    operator_forced=False, host_key_records=records)
            except app.SetupError:
                self.fail("same-user non-cumulus Leaf must refresh its own synthetic known_hosts")
        self.assertEqual("refreshed", result.result)
        self.assertEqual(1, len(records))
        self.assertEqual(self.before, self.path.with_name("known_hosts.old").read_text())

    def test_unparseable_banner_is_reported_without_raw_warning(self):
        self.records = []
        output = "@@@@ PUBLIC warning\n" + self.warning().replace(self.keys["new"][1], "missing")
        with mock.patch.object(Path, "home", return_value=self.home), \
                mock.patch.object(self.app, "interactive_run", return_value=self.app.SessionResult(output, 255)) as run:
            rows = self.app.run_management_direct_checks([readiness.target(self.app)],
                    {"example-ib01": readiness.credential("current")}, "admin", 2,
                    on_management_server=True, **self.options())
        self.assertEqual(["FAIL"], [row["status"] for row in rows])
        self.assertNotIn("@@@@", repr(rows))
        self.assertIn("unparseable", rows[0]["detail"])
        self.assertEqual(self.before, self.path.read_text())
        run.assert_called_once()

    def test_password_framed_warning_missing_facts_is_fixed_refusal(self):
        # r508 :718/:780, RV76: OpenSSH warning phrase may be framed or indented.
        self.records = []
        raw = self.warning().replace(self.keys["new"][1], "missing").replace(
            "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @")
        raw = "@@@@ PUBLIC frame @@@@\r\n  " + raw
        with mock.patch.object(Path, "home", return_value=self.home), \
                mock.patch.object(self.app, "interactive_run", return_value=self.app.SessionResult(raw, 255)) as run:
            rows = self.app.run_management_direct_checks([readiness.target(self.app)],
                {"example-ib01": readiness.credential("current")}, "admin", 2,
                on_management_server=True, **self.options())
        self.assertEqual(["FAIL"], [row["status"] for row in rows])
        self.assertIn("unparseable", rows[0]["detail"])
        self.assertNotIn("@@@@", repr(rows))
        self.assertNotIn("REMOTE HOST", repr(rows))
        self.assertEqual(self.before, self.path.read_text())
        self.assertEqual([], self.records)
        run.assert_called_once()

    def test_publickey_framed_warning_missing_facts_is_fixed_refusal(self):
        self.records, calls = [], []
        raw = self.warning().replace(self.keys["new"][1], "missing").replace(
            "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @")
        raw = "@@@@ PUBLIC frame @@@@\r\n  " + raw
        real_run = subprocess.run
        def run(argv, **kwargs):
            if argv[0] == "ssh-keygen":
                return real_run(argv, **kwargs)
            self.assertEqual("ssh", argv[0])
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 255, "", raw)
        with mock.patch.object(Path, "home", return_value=self.home), \
                mock.patch.object(self.app.subprocess, "run", side_effect=run):
            with self.assertRaises(self.app.SetupError) as caught:
                self.app.verify_management_key_possession(readiness.target(self.app), "admin",
                    {"fingerprint": self.keys["old"][1]}, Path(self.keys_root.name) / "old", 2, **self.options())
        self.assertIn("unparseable", str(caught.exception))
        self.assertNotIn("@@@@", str(caught.exception))
        self.assertNotIn("REMOTE HOST", str(caught.exception))
        self.assertEqual(self.before, self.path.read_text())
        self.assertEqual([], self.records)
        self.assertEqual(1, len(calls))


class HostKeyRefreshWorkflowTests(unittest.TestCase):
    """r508 WP5 actual main/selector/queue/report and four actual product modules.

    Real local synthetic keygen/files; only device transport, native hash and
    interactive input boundaries are replaced. No native/KAT or real SSH.
    """
    # Independent EUI-64 vector for the PUBLIC CSV MAC 02:00:00:00:00:10.
    LINK_LOCAL = "fe80::ff:fe00:10"
    SCOPED_LINK_LOCAL = "fe80::ff:fe00:10%vlan1000"
    GLOBAL_HASH = "$" + "6$PUBLICsalt$" + "A" * 86

    @classmethod
    def setUpClass(cls):
        hostkeys.LocalHostKeyRefreshTests.setUpClass.__func__(cls)
        cls.app = readiness.load_app("wp5_real_main")

    @classmethod
    def tearDownClass(cls):
        cls.keys_root.cleanup()

    def project(self, root):
        neutral = root / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
        neutral.parent.mkdir(parents=True)
        neutral.write_text("DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=Etc/UTC\n")
        (root / "01-global.yaml").write_text("schema_version: 2\nswitches:\n- ib:\n    system:\n"
            "      aaa:\n        user:\n          admin:\n            pass" + "word: " + self.GLOBAL_HASH + "\n")
        with (root / "ib.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["hostname", "type", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"])
            writer.writerow(["example-ib01", "ib", "192.0.2.10", "24", "192.0.2.1", "02:00:00:00:00:10"])
            writer.writerow(["EXAMPLE-JUMP01", "eth_jump", "198.51.100.10", "", "", ""])
        (root / "02-devices_config.csv").write_bytes((root / "ib.csv").read_bytes())
        (root / "p2p.dot").write_text('"example-ib01":"eth0" -- "EXAMPLE-JUMP01":"swp1"\n')
        return [str(self.app.__file__), "--project-dir", str(root), "--p2p", str(root / "p2p.dot"),
                "--target-cache", str(root / "tasks.json"), "--report", str(root / "report.log"),
                "--snapshot-dir", str(root / "snapshots"), "--execution-mode", "management"]

    def run_main(self, *, project_password=True, forced=False, readonly=False, local_conflict=False,
                 linklocal_conflict=False, ipv4_unready=False, unverifiable=False, confirm=None):
        app = self.app
        with tempfile.TemporaryDirectory(prefix="wp5-real-main-") as directory, ExitStack() as stack:
            root = Path(directory).resolve()
            home = root / "home"
            (home / ".ssh").mkdir(parents=True)
            jump_path = root / "jump-known_hosts"
            before = ("192.0.2.11 " + self.keys["old"][0] + "\n"
                      "192.0.2.10 " + self.keys["old"][0] + "\n"
                      "192.0.2.10 " + self.keys["rsa"][0] + "\n"
                      "192.0.2.12 " + self.keys["old"][0] + "\n")
            jump_path.write_text(before)
            if linklocal_conflict:
                jump_path.write_text(before.replace("192.0.2.10", self.SCOPED_LINK_LOCAL))
            local_path = home / ".ssh/known_hosts"
            local_path.write_text(before if local_conflict else "")
            argv = self.project(root) + ([] if readonly else ["--apply", *(["--yes"] if confirm is None else [])])
            if forced:
                argv += ["--refresh-host-key", "example-ib01"]
            # Frozen PUBLIC device states; the only transition follows the
            # complete authorized PAM exchange, never a rejected login.
            device_state = ("target", False) if project_password else ("factory", True)
            auth_roles, reads, removals, ipv4 = [], [], [], []
            phase_events, phase_nonces = [], set()
            actual_run = subprocess.run

            def keygen_lookup(address):
                p = actual_run(["ssh-keygen", "-l", "-F", address, "-f", str(jump_path)],
                               capture_output=True, text=True, timeout=10)
                self.assertIn(p.returncode, (0, 1))
                return p.stdout

            def ethernet(device, user, password, command, timeout, **kwargs):
                key = tuple(command)
                values = {
                    ("hostname",): "EXAMPLE-JUMP01\n",
                    ("nv", "show", "interface"): "swp1 up up\n",
                    ("ip", "-d", "link", "show"): "1: swp1: <UP> mtu 1500 master br_default\n40: br_default: <UP> mtu 1500\n    bridge vlan_filtering 1\n41: vlan1000@br_default: <UP> mtu 1500 master oob\n    vlan protocol 802.1Q id 1000 <REORDER_HDR>\n",
                    ("bridge", "fdb", "show"): "02:00:00:00:00:10 dev swp1 vlan 1000 master br_default\n",
                    ("bridge", "vlan", "show"): "port vlan-id\nswp1 1000 PVID Egress Untagged\n",
                    ("ip", "neighbor"): self.LINK_LOCAL + " dev vlan1000 lladdr 02:00:00:00:00:10 REACHABLE\n",
                    ("ip", "-j", "address", "show"): json.dumps([{"ifname": "vlan1000", "flags": ["UP"], "operstate": "UP", "addr_info": [{"family": "inet", "local": "192.0.2.1", "prefixlen": 24}, {"family": "inet6", "local": "fe80::1", "prefixlen": 64}]}]),
                    ("ifquery", "vlan1000"): "iface vlan1000\n    vrf oob\n",
                }
                if key[:3] == ("ssh-keygen", "-l", "-F"):
                    app.ethernet_command_argv(command)  # actual table, independent literal checks elsewhere.
                    return keygen_lookup(key[3])
                self.assertIn(key, values, "unexpected OOB command")
                return values[key]

            body = ("nv set system hostname example-ib01\nnv set interface eth0 ipv4 address 192.0.2.10/24\n"
                    "nv set interface eth0-1 ipv4 gateway 192.0.2.1\nnv set interface eth0-1 link state up\n"
                    "nv set interface eth0-1 type eth\nnv set system config auto-save state enabled\n"
                    "nv set system ztp config-save enabled\nnv set system dns server 192.0.2.53\n"
                    "nv set system ntp server 192.0.2.123 state enabled\nnv set system date-time timezone Etc/UTC\n")

            def warning(path, address="192.0.2.10"):
                return hostkeys.warning(address, path=str(path), fingerprint=self.keys["new"][1]).replace(
                    ":7\r\n", ":2\r\n").replace(":9\r\n", ":3\r\n")

            def has_old_key(path, address):
                old = {address + " " + self.keys[key][0] for key in ("old", "rsa")}
                return any(line in old for line in path.read_text().splitlines())

            def remember_new_key(path, address):
                line = address + " " + self.keys["new"][0]
                if line not in path.read_text().splitlines():
                    with path.open("a") as handle:
                        handle.write(line + "\n")

            def identity_reply(command, marker):
                """Only the two complete framed PUBLIC identity reads qualify."""
                frame_argv = shlex.split(command[-1])
                self.assertEqual(["sh", "-c"], frame_argv[:2])
                self.assertEqual(3, len(frame_argv))
                outer_prefix = ("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec ")
                if frame_argv[2].startswith(outer_prefix):
                    nested_argv = shlex.split(frame_argv[2][len(outer_prefix):])
                    self.assertEqual(["ip", "vrf", "exec"], nested_argv[:3])
                    self.assertEqual("ssh", nested_argv[4])
                    frame_argv = shlex.split(nested_argv[-1])
                    self.assertEqual(["sh", "-c"], frame_argv[:2])
                    self.assertEqual(3, len(frame_argv))
                reads = {
                    ("ip", "addr", "show", "eth0"): (
                        "2: eth0: <UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:10 brd ff:ff:ff:ff:ff:ff\n"
                        "    inet 192.0.2.10/24 scope global eth0\n"),
                    ("ip", "route"): "default via 192.0.2.1 dev eth0\n",
                }
                for read, payload in reads.items():
                    expected = ('printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
                                + shlex.join(read)
                                + '; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                                + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                    if frame_argv[2] == expected:
                        return payload
                return None

            def transport(command, responder, timeout, **kwargs):
                nonlocal device_state
                text = " ".join(command)
                if "ssh-keygen -f" in text:
                    self.assertIn(hostkeys.KNOWN_HOSTS, text)
                    address = self.SCOPED_LINK_LOCAL if self.SCOPED_LINK_LOCAL in text else "192.0.2.10"
                    p = actual_run(["ssh-keygen", "-f", str(jump_path), "-R", address],
                                   capture_output=True, text=True, timeout=10)
                    removals.append("jump")
                    return app.SessionResult((p.stdout + p.stderr).replace(str(jump_path), hostkeys.KNOWN_HOSTS), p.returncode)
                frame = re.search(r"__HTTP_IB_BEGIN_([a-f0-9]{32})__", text)
                auth = re.search(r"__HTTP_IB_AUTH_([a-f0-9]{32})_(auth-probe-readonly|password-change|post-change-read)__=BEGIN", text)
                nested = ("admin@" + self.LINK_LOCAL) in text
                if auth:
                    if linklocal_conflict and has_old_key(jump_path, self.SCOPED_LINK_LOCAL):
                        return app.SessionResult(warning(hostkeys.KNOWN_HOSTS, self.SCOPED_LINK_LOCAL), 255)
                    nonce, operation = auth.groups()
                    self.assertIn(operation, ("auth-probe-readonly", "password-change", "post-change-read"))
                    phase, output = responder._phase, ""
                    self.assertIs(type(phase), app._IBPhase)
                    self.assertEqual((nonce, operation, "admin@" + self.LINK_LOCAL,
                                      "cumulus@198.51.100.10"),
                                     (phase.nonce, phase.operation, phase.endpoint, phase.outer_endpoint))
                    self.assertNotIn(nonce, phase_nonces, "every phase must be a fresh session")
                    phase_nonces.add(nonce)
                    reader, writer = os.pipe()
                    try:
                        def feed(value):
                            nonlocal output
                            output += value
                            phase.observe(output)
                            reply = responder(output)
                            if responder.password_change_blocked:
                                # Same external cancellation observation as
                                # strict_stage_skeleton._Session/interactive_run.
                                # There is no PTY child or credential write here.
                                self.assertEqual("auth-probe-readonly", operation)
                                self.assertFalse(responder.allow_password_change)
                                self.assertEqual("\x03", reply)
                                phase.cancel_requested = True
                                return reply
                            if reply is not None:
                                phase.write_reply(writer, reply, responder, time.monotonic() + 60)
                                written = os.read(reader, 65536)
                                self.assertTrue(written == reply.encode("utf-8") + b"\n",
                                                "PUBLIC phase reply must complete its actual pipe write")
                            return reply
                        feed(f"\n__HTTP_IB_AUTH_{nonce}_{operation}__=BEGIN\n")
                        answer = feed("admin@" + self.LINK_LOCAL + "'s password: ")
                        qualified = {readiness.credential("target"): "target",
                                     readiness.credential("factory"): "factory"}
                        self.assertTrue(answer in qualified, "unexpected synthetic credential role")
                        auth_roles.append(qualified[answer])
                        accepted_role, expired = device_state
                        if answer != readiness.credential(accepted_role):
                            self.assertEqual("auth-probe-readonly", operation,
                                             "PAM/fresh read must not retry a rejected credential")
                            phase_events.append((operation, qualified[answer], "rejected"))
                            feed(f"\nadmin@{self.LINK_LOCAL}: Permission denied (password).\n__HTTP_IB_AUTH_{nonce}_{operation}__=EXIT:255\n")
                            return app.SessionResult(output, 255)
                        if operation == "password-change":
                            self.assertEqual(("factory", True), device_state)
                            self.assertTrue(responder.allow_password_change)
                            self.assertIsNotNone(app._ACTIVE_COORDINATOR)
                            self.assertTrue(app._ACTIVE_COORDINATOR.authorized)
                            self.assertEqual(1, app._ACTIVE_COORDINATOR.metrics.get("password_change_sessions", 0))
                            old = feed("\nYour password has expired.\n(current) UNIX password: ")
                            new = feed("\nNew password: ")
                            again = feed("\nRetype new password: ")
                            self.assertTrue(old == readiness.credential("factory")
                                            and new == readiness.credential("target")
                                            and again == readiness.credential("target"),
                                            "PAM must consume only the fixed current/project PUBLIC roles")
                            feed(f"\npasswd: password updated successfully\n__HTTP_IB_AUTH_{nonce}_{operation}__=EXIT:0\n")
                            self.assertTrue(phase.pam_current_done and phase.new_done and phase.confirm_done)
                            self.assertTrue(phase.updated)
                            device_state = ("target", False)
                            phase_events.append((operation, "factory", "changed"))
                            return app.SessionResult(output, 0,
                                password_change_attempted=responder.password_change_attempted)
                        self.assertFalse(responder.allow_password_change)
                        if expired:
                            self.assertEqual("auth-probe-readonly", operation)
                            self.assertEqual("\x03", feed(
                                "\nYour password has expired.\n(current) UNIX password: "))
                            self.assertFalse(phase.new_done or phase.confirm_done)
                            phase_events.append((operation, "factory", "expired-cancelled"))
                            return app.SessionResult(output, 255,
                                password_change_required=responder.password_change_blocked)
                        if operation == "post-change-read":
                            self.assertEqual(("target", False), device_state)
                            self.assertEqual("changed", phase_events[-1][2])
                        if linklocal_conflict:
                            remember_new_key(jump_path, self.SCOPED_LINK_LOCAL)
                        feed(f"\n__HTTP_IB_BEGIN_{nonce}__\n{body}__HTTP_IB_END_{nonce}__=0\n__HTTP_IB_AUTH_{nonce}_{operation}__=EXIT:0\n")
                        phase_events.append((operation, accepted_role, "readback"))
                        return app.SessionResult(output, 0)
                    finally:
                        os.close(reader)
                        os.close(writer)
                self.assertIsNotNone(frame, "normal IB read commands retain the actual frame")
                marker = frame.group(1)
                identity = identity_reply(command, marker)
                # O5/D4 require a fresh framed MAC/IPv4/gateway readback,
                # not the former empty success from a bare true command.
                if not nested and "198.51.100.10" in text:
                    self.assertIsNotNone(identity, "IPv4 readiness accepts only its two fixed identity reads")
                    ipv4.append("route" if identity.startswith("default via ") else "address")
                    if ipv4_unready:
                        return app.SessionResult("ssh: connect to host 192.0.2.10 port 22: Connection refused", 255)
                    if has_old_key(jump_path, "192.0.2.10"):
                        return app.SessionResult(warning(hostkeys.KNOWN_HOSTS), 255)
                    remember_new_key(jump_path, "192.0.2.10")
                    return app.SessionResult(f"__HTTP_IB_BEGIN_{marker}__\n{identity}__HTTP_IB_END_{marker}__=0\n", 0)
                if nested and "cat /etc/ssh/ssh_host_ed25519_key.pub" in text:
                    self.assertEqual(readiness.credential(device_state[0]),
                                     responder("admin@" + self.LINK_LOCAL + "'s password: "))
                    reads.append("ED25519")
                    payload = self.keys["old" if unverifiable else "new"][0] + "\n"
                elif not nested and local_conflict and has_old_key(local_path, "192.0.2.10"):
                    return app.SessionResult(warning(local_path), 255)
                else:
                    if not nested and local_conflict:
                        remember_new_key(local_path, "192.0.2.10")
                    # U4 (v3.1.6 D1d, guide 8.11): the closed Linux hostname read after the NVUE
                    # hostname is verified; this healthy device's Linux name is its NVUE hostname.
                    linux = re.findall(r"(?m)^nv set system hostname (\S+)$", body)
                    payload = (linux[-1] + "\n" if identity is None and "; hostname; task_rc=" in text else
                        identity if identity is not None else
                        "service disabled\nstatus aborted\nconfig-save enabled enabled\n" if "nv show system ztp" in text else body)
                return app.SessionResult(f"__HTTP_IB_BEGIN_{marker}__\n{payload}__HTTP_IB_END_{marker}__=0\n", 0)

            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home), "TMPDIR": str(root)}))
            stack.enter_context(mock.patch.object(Path, "home", return_value=home))
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
            stack.enter_context(mock.patch.object(app, "_new_jump_sessions", legacy_jump_sessions_factory(app)))
            stack.enter_context(mock.patch.object(app, "probe_ethernet_key", return_value="key"))
            stack.enter_context(mock.patch.object(app, "run_on_ethernet", side_effect=ethernet))
            stack.enter_context(mock.patch.object(app, "interactive_run", side_effect=transport))
            stack.enter_context(mock.patch.object(
                app, "verify_password_hash",
                side_effect=lambda supplied, stored: (
                    supplied == readiness.credential("target") and stored == self.GLOBAL_HASH),
            ))
            stack.enter_context(mock.patch.object(app, "resolve_initial_ib_password", return_value=readiness.credential("factory")))
            stack.enter_context(mock.patch.object(app.getpass, "getpass", return_value=readiness.credential("target")))
            consent = stack.enter_context(mock.patch("builtins.input", return_value="y" if confirm else "n"))
            stack.enter_context(mock.patch.object(app.time, "sleep", return_value=None))
            out = stack.enter_context(__import__("contextlib").redirect_stdout(io.StringIO()))
            try:
                code = app.main()
            finally:
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
                    app.REPORT_HANDLE = None
            summaries = list(root.glob("devices-*/summary.json"))
            self.assertEqual(1, len(summaries))
            evidence = json.loads(summaries[0].read_text())
            self.confirmation_calls = consent.call_count
            self.phase_events = phase_events
            self.phase_session_count = len(phase_nonces)
            return code, evidence, out.getvalue(), auth_roles, reads, removals, ipv4

    def test_reset_device_reruns_to_success_in_both_password_states(self):
        # Factory expiry must use the real three-phase protocol and permit;
        # an already-project-ready device must never rotate its password.
        for project_password in (False, True):
            with self.subTest(project_password=project_password):
                code, evidence, output, auth, reads, removals, ipv4 = self.run_main(project_password=project_password)
                self.assertEqual(0, code, output)
                record = evidence["records"]["example-ib01"]
                self.assertNotEqual("FAILED_OOB_IPV4_READINESS", record["category"])
                # I-039: the project credential gets the first chance.
                self.assertEqual(["target"] if project_password else
                                 ["target", "factory", "factory", "target"], auth)
                expected_phases = ([("auth-probe-readonly", "target", "readback")]
                    if project_password else [
                        ("auth-probe-readonly", "target", "rejected"),
                        ("auth-probe-readonly", "factory", "expired-cancelled"),
                        ("password-change", "factory", "changed"),
                        ("post-change-read", "target", "readback"),
                    ])
                self.assertEqual(expected_phases, self.phase_events)
                self.assertEqual(len(expected_phases), self.phase_session_count)
                self.assertTrue(record["writes_attempted"], "the real host-key removal is a device write")
                self.assertEqual(1, record["metrics"].get("host_key_remove_attempts", 0))
                for metric in ("nvue_write_commands", "public_key_install_attempts", "config_backup_attempts"):
                    self.assertEqual(0, record["metrics"].get(metric, 0),
                                     "already-configured device must not perform " + metric)
                self.assertEqual(0 if project_password else 1,
                                 record["metrics"].get("password_change_sessions", 0))
                self.assertEqual(["ED25519"], reads)
                self.assertEqual(["jump"], removals)
                self.assertEqual(["address", "address", "route"], ipv4,
                                 "failed address, then one complete IPv4 retry")
                self.assertEqual(["jump"], [row["location"] for row in record["host_key"]])
                self.assertEqual("verified", record["host_key"][0]["verification"])
                self.assertNotIn("@@@@", json.dumps(evidence) + output)

    def test_forced_selector_drives_actual_main_without_fingerprint_read(self):
        code, evidence, output, auth, reads, removals, ipv4 = self.run_main(forced=True)
        self.assertEqual(0, code, output)
        self.assertEqual([], reads)
        self.assertEqual(["jump"], removals)
        self.assertEqual("operator-forced-unverified", evidence["records"]["example-ib01"]["host_key"][0]["verification"])

    def test_one_device_can_record_jump_and_management_refresh(self):
        code, evidence, output, auth, reads, removals, ipv4 = self.run_main(local_conflict=True)
        self.assertEqual(0, code, output)
        rows = evidence["records"]["example-ib01"]["host_key"]
        self.assertEqual(["jump", "local"], [row["location"] for row in rows])
        self.assertEqual(["ED25519", "ED25519"], reads)
        self.assertNotIn("@@@@", json.dumps(evidence))

    def test_linklocal_auth_conflict_requires_operator_list_and_one_caller_retry(self):
        # r508 WP5 item5: no unauthenticated key read / no extra phase login.
        code, evidence, output, auth, reads, removals, ipv4 = self.run_main(linklocal_conflict=True)
        record = evidence["records"]["example-ib01"]
        self.assertNotEqual(0, code)
        self.assertEqual("FAILED_TARGET_HOST_KEY_CHANGED", record["category"])
        self.assertEqual([], auth)
        self.assertEqual([], reads)
        self.assertEqual([], removals)
        code, evidence, output, auth, reads, removals, ipv4 = self.run_main(linklocal_conflict=True, forced=True)
        self.assertEqual(0, code, output)
        self.assertEqual(["target"], auth)
        self.assertEqual([], reads)
        self.assertEqual(["jump"], removals)
        self.assertEqual(self.SCOPED_LINK_LOCAL, evidence["records"]["example-ib01"]["host_key"][0]["address"])

    def test_readonly_actual_main_records_pending_without_deletion(self):
        code, evidence, output, auth, reads, removals, ipv4 = self.run_main(readonly=True, local_conflict=True)
        self.assertEqual(2, code, output)
        record = evidence["records"]["example-ib01"]
        self.assertEqual("CHECKED_HOST_KEY_REFRESH_PENDING", record["category"])
        self.assertFalse(record["writes_attempted"])
        self.assertEqual([], removals)
        self.assertEqual("refresh-pending", record["host_key"][0]["result"])
        self.assertIsNone(record["host_key"][0]["removal"])

    def test_real_ipv4_exhaustion_is_not_overwritten_by_final_hostkey_refusal(self):
        code, evidence, output, auth, reads, removals, ipv4 = self.run_main(
            ipv4_unready=True, local_conflict=True, unverifiable=True)
        record = evidence["records"]["example-ib01"]
        self.assertEqual(9, len(ipv4))
        self.assertEqual("FAILED_OOB_IPV4_READINESS", record["category"])
        self.assertEqual("ipv4_readiness", record["failed_stage"])
        self.assertEqual("TARGET_HOST_KEY_CHANGED", record["direct_rows"][0]["failure_kind"])
        self.assertEqual([], removals)

    def test_real_ipv4_failure_keeps_priority_over_verified_pending_and_no_later_write(self):
        code, evidence, output, auth, reads, removals, ipv4 = self.run_main(ipv4_unready=True, local_conflict=True)
        record = evidence["records"]["example-ib01"]
        self.assertEqual("FAILED_OOB_IPV4_READINESS", record["category"])
        self.assertEqual("ipv4_readiness", record["failed_stage"])
        self.assertEqual("HOST_KEY_REFRESH_PENDING", record["direct_rows"][0]["failure_kind"])
        self.assertEqual("refresh-pending", record["host_key"][0]["result"])
        self.assertIsNone(record["host_key"][0]["removal"])
        self.assertFalse(record["writes_attempted"])
        self.assertEqual([], removals)

    def test_forced_initial_auth_conflict_still_needs_original_first_consent(self):
        code, evidence, output, auth, reads, removals, ipv4 = self.run_main(
            linklocal_conflict=True, forced=True, confirm=False)
        self.assertEqual(1, code, output)
        self.assertEqual(1, self.confirmation_calls)
        self.assertEqual([], auth)
        self.assertEqual([], removals)
        self.assertFalse(evidence["records"]["example-ib01"]["writes_attempted"])


class InlineTypedHostKeyWorkflowTests(unittest.TestCase):
    """Real initial -> original login_path refresh -> real inline parent/closed remove.

    The only transport is an explicit fixed-output model. No real keygen, SSH,
    files, credentials, process, clock sleep or native backend is used by these cases.
    """
    def run_refresh(self, *, fail, next_lookup):
        app = readiness.load_app("r551_inline_refresh_" + next_lookup + str(fail))
        api = app._import_tools("tools.login_path")
        target = readiness.target(app)
        task = app.PreparedIBTask(target, app.Neighbor("fe80::10", "vlan1000", target.ib.eth0_mac),
                                  readiness.credential("outer"), False)
        change = api.parse_host_key_change(hostkeys.warning(), location="jump", jump="EXAMPLE-JUMP01")
        old = ("# Host 192.0.2.10 found: line 7\n256 ED25519 SHA256:" + "B" * 43 + "\n"
               "# Host 192.0.2.10 found: line 9\n2048 RSA SHA256:" + "B" * 43 + "\n")
        new = "# Host 192.0.2.10 found: line 11\n256 ED25519 " + hostkeys.FINGERPRINT + "\n"
        args = SimpleNamespace(apply=True, yes=True, eth_user="cumulus", connect_timeout=2)
        parent = app.RuntimeCoordinator(args, None, readiness.credential("initial"), [task],
                                         SimpleNamespace(assert_unchanged=lambda: None))
        parent.current_target = target
        events, records, retry_calls, lookups = [], [], [], []

        def reader(key_type):
            self.assertEqual("ED25519", key_type)
            events.append("verify")
            return hostkeys.FINGERPRINT

        def lookup(device, user, password, command, timeout, **kwargs):
            self.assertEqual(["ssh-keygen", "-l", "-F", "192.0.2.10", "-f", hostkeys.KNOWN_HOSTS], command)
            self.assertEqual((target.ethernet, "cumulus", readiness.credential("outer"), 2),
                             (device, user, password, timeout))
            lookups.append(command)
            events.append("lookup")
            if len(lookups) <= 2:
                return old  # library's read, then parent's independent fresh read.
            if fail:
                return "" if next_lookup == "empty" else old
            return "" if len(lookups) == 3 else new

        def transport(command, responder, timeout):
            self.assertEqual("ssh", command[0])
            self.assertIn("ssh-keygen", command[-1])
            self.assertIn("-R", command[-1])
            self.assertIn("192.0.2.10", command[-1])
            events.append("remove")
            if fail:
                return app.SessionResult("ssh: connect to host 198.51.100.10 port 22: Connection timed out", 255)
            return app.SessionResult("Original contents retained as " + hostkeys.KNOWN_HOSTS + ".old\n", 0)

        def retry():
            events.append("retry")
            retry_calls.append(1)

        caught = record = None
        with mock.patch.object(app, "_WORKER_CONNECTION", None), \
                mock.patch.object(app, "_ACTIVE_COORDINATOR", parent), \
                mock.patch.object(app, "_JUMP_SESSIONS", None), \
                mock.patch.object(app, "run_on_ethernet", side_effect=lookup), \
                mock.patch.object(app, "interactive_run", side_effect=transport), \
                mock.patch.object(app.subprocess, "run", side_effect=AssertionError("unexpected real child")):
            try:
                record = app.refresh_ib_host_key(change, task, eth_user="cumulus", timeout=2, apply=True,
                    read_device_fingerprint=reader, retry=retry, operator_forced=False, host_key_records=records)
            except app.SshFailure as error:
                caught = error
            except AttributeError as error:
                # Capture this one known old dict-as-receipt outcome, never an unknown fixture ERROR.
                if str(error) != "'dict' object has no attribute 'lines'":
                    raise
                caught = error
        return app, caught, record, records, events, retry_calls, parent

    def test_inline_refresh_typed_delete_failure_stops_before_followup_lookup_or_retry(self):
        for state in ("empty", "remaining"):
            with self.subTest(next_lookup=state):
                app, error, record, records, events, retries, parent = self.run_refresh(fail=True, next_lookup=state)
                self.assertEqual(["verify", "lookup", "lookup", "remove"], events,
                                 "typed removal failure must stop before any post-remove lookup or retry")
                self.assertIsInstance(error, app.SshFailure)
                self.assertEqual(("OOB_JUMP_UNREACHABLE", "outer", "198.51.100.10", "EXAMPLE-JUMP01"),
                                 (error.failure_kind, error.hop, error.address, error.jump))
                self.assertIsNone(record)
                self.assertEqual([], records)
                self.assertEqual([], retries)
                self.assertTrue(parent.writes_attempted)
                self.assertEqual({"host_key_remove_attempts": 1}, parent.metrics)

    def test_inline_refresh_success_keeps_receipt_and_single_retry(self):
        app, error, record, records, events, retries, parent = self.run_refresh(fail=False, next_lookup="empty")
        self.assertIsNone(error)
        self.assertEqual(["verify", "lookup", "lookup", "remove", "lookup", "retry", "lookup"], events)
        self.assertEqual([1], retries)
        self.assertEqual([record], records)
        self.assertEqual(("refreshed", "verified", "192.0.2.10", (7, 9)),
                         (record.result, record.verification, record.address, record.lines))
        self.assertEqual((True, None, None, None, None),
                         (record.removal.old_file, record.removal.inode_before, record.removal.inode_after,
                          record.removal.mode_before, record.removal.mode_after))
        self.assertEqual({"host_key_remove_attempts": 1}, parent.metrics)
        self.assertNotIn("WARNING:", repr(record))
        self.assertNotIn("@@@@", repr(record))


class JumpCoordinatorWorkflowTests(unittest.TestCase):
    """Actual fork/IPC + original parent scheduler and closed writer; fake SSH only."""
    @classmethod
    def setUpClass(cls):
        hostkeys.LocalHostKeyRefreshTests.setUpClass.__func__(cls)
        cls.app = readiness.load_app("wp5_real_coordinator")

    @classmethod
    def tearDownClass(cls):
        cls.keys_root.cleanup()

    def run_queue(self, *, multi, fresh):
        app = self.app
        with tempfile.TemporaryDirectory(prefix="wp5-parent-") as directory, ExitStack() as stack:
            root = Path(directory).resolve()
            home = root / "home"
            home.mkdir()
            path = root / "known_hosts"
            before = ("192.0.2.99 " + self.keys["old"][0] + "\n"
                      "192.0.2.10 " + self.keys["old"][0] + "\n"
                      "192.0.2.20 " + self.keys["old"][0] + "\n"
                      "192.0.2.10 " + self.keys["rsa"][0] + "\n"
                      "192.0.2.20 " + self.keys["rsa"][0] + "\n")
            path.write_text(before)
            first = readiness.target(app)
            tasks = [app.PreparedIBTask(replace(first, ib=replace(first.ib,
                hostname="EXAMPLE-IB" + str(i + 1), login_ip="192.0.2." + str(10 + i * 10))),
                app.Neighbor("fe80::10", "vlan1000", first.ib.eth0_mac), readiness.credential("outer"), False)
                for i in range(17 if multi else 2)]
            args = SimpleNamespace(apply=True, yes=True, eth_user="cumulus", ib_user="admin", connect_timeout=2,
                                   max_workers=2, task_timeout=30, report=root / "report.log", verbose=False)
            completed = app.multiprocessing.get_context("fork").Event()
            simultaneous = app.multiprocessing.get_context("fork").Barrier(2) if multi and not fresh else None
            actual_run, seen = subprocess.run, []
            def lookup(device, user, password, command, timeout, **kwargs):
                self.assertEqual(["ssh-keygen", "-l", "-F"], command[:3])
                p = actual_run(["ssh-keygen", "-l", "-F", command[3], "-f", str(path)],
                               capture_output=True, text=True, timeout=10)
                self.assertIn(p.returncode, (0, 1))
                return p.stdout
            def outer(device, user, command, timeout, **kwargs):
                self.assertEqual(["ssh-keygen", "-f", hostkeys.KNOWN_HOSTS, "-R"], command[:4])
                return ["PUBLIC-closed", command[4]]
            def transport(command, responder, timeout, **kwargs):
                self.assertEqual("PUBLIC-closed", command[0])
                seen.append((command[1], path.read_text()))  # parent-only actual writer observations.
                p = actual_run(["ssh-keygen", "-f", str(path), "-R", command[1]],
                               capture_output=True, text=True, timeout=10)
                return app.SessionResult((p.stdout + p.stderr).replace(str(path), hostkeys.KNOWN_HOSTS), p.returncode)
            def execute(task, *_args, **_kwargs):
                if task.target.ib.hostname not in {"EXAMPLE-IB1", "EXAMPLE-IB2"}:
                    return {"outcome": "ALREADY_CONFIGURED", "direct_rows": [], "reason": "", "stage_status": {}}
                address = task.target.ib.login_ip
                lines = (2, 4) if address == "192.0.2.10" else (3, 5)
                if fresh and address == "192.0.2.20":
                    if not completed.wait(10):
                        raise AssertionError("owned first worker did not finish")
                    rows = app._import_tools("tools.login_path").parse_known_host_fingerprints(
                        lookup(task.target.ethernet, "cumulus", "", ["ssh-keygen", "-l", "-F", address], 2))
                    lines = tuple(row[0] for row in rows)  # fresh warning fact, not a product expectation.
                api = hostkeys.parser_module(self)
                change = api.HostKeyChange(address, "ED25519", self.keys["new"][1], hostkeys.KNOWN_HOSTS,
                                           lines, "jump", task.target.ethernet.hostname)
                editor = app.JumpKnownHostsEditor(task, change, eth_user="cumulus", timeout=2)
                if simultaneous is not None:
                    simultaneous.wait(10)  # both warning facts exist before either request.
                try:
                    receipt = editor.remove(address)
                    result = {"outcome": "ALREADY_CONFIGURED", "receipt": asdict(receipt), "reason": ""}
                except app.SetupError as error:
                    result = {"outcome": "FAILED", "reason": str(error)}
                if address == "192.0.2.10":
                    completed.set()
                result.update(direct_rows=[], stage_status={})
                return result
            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home), "TMPDIR": str(root)}))
            stack.enter_context(mock.patch.object(app, "_JUMP_SESSIONS", None))
            stack.enter_context(mock.patch.object(app, "execute_ib_task", side_effect=execute))
            stack.enter_context(mock.patch.object(app, "run_on_ethernet", side_effect=lookup))
            stack.enter_context(mock.patch.object(app, "outer_ssh_command", side_effect=outer))
            stack.enter_context(mock.patch.object(app, "interactive_run", side_effect=transport))
            stack.enter_context(mock.patch.object(app.time, "sleep", return_value=None))
            stack.enter_context(__import__("contextlib").redirect_stdout(io.StringIO()))
            result = app.run_prepared_tasks(tasks, args, None, readiness.credential("factory"), None, [], None)
            return result, seen, path.read_text(), before

    def test_multiworker_deletions_are_parent_serial_and_fresh_lookup_sees_first(self):
        result, writes, content, before = self.run_queue(multi=True, fresh=True)
        self.assertEqual(2, result["workers"])
        self.assertEqual(["192.0.2.10", "192.0.2.20"], [row[0] for row in writes])
        self.assertNotIn("192.0.2.10", writes[1][1])
        self.assertEqual(before.splitlines(True)[0], content)
        self.assertTrue(result["records"]["example-ib1"]["writes_attempted"])
        self.assertTrue(result["records"]["example-ib2"]["writes_attempted"])

    def test_inline_uses_same_parent_gate_and_fresh_view(self):
        result, writes, content, before = self.run_queue(multi=False, fresh=True)
        self.assertEqual(1, result["workers"])
        self.assertEqual(2, len(writes))
        self.assertNotIn("192.0.2.10", writes[1][1])
        self.assertEqual(before.splitlines(True)[0], content)

    def test_simultaneous_old_warning_lines_are_not_silently_adopted(self):
        result, writes, content, before = self.run_queue(multi=True, fresh=False)
        self.assertEqual(1, len(writes), "the stale second warning must not remove another shifted row")
        rows = [result["records"]["example-ib1"], result["records"]["example-ib2"]]
        self.assertEqual(1, sum(row["outcome"] == "FAILED" for row in rows))
        self.assertEqual(1, sum(bool(row["writes_attempted"]) for row in rows))
        self.assertNotIn("@@@@", repr(rows))


if __name__ == "__main__":
    unittest.main()
