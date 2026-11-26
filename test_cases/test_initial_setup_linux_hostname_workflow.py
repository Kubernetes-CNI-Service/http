"""U4 / R-026 (v3.1.6 D1d): one controlled `sudo -n hostnamectl hostname` for a default Linux name.

Expectations come only from the owner's 2026-11-15 ruling on issue section 12 ("初始配置完后再做
sudo hostnamectl hostname一次没有关系，admin用户默认可以sudo") and from the v3.1.6 guide 8.11
(tag guide-v3.1.6-approved-r839, :2161-2181), never from the implementation:

- the Linux name is read once with the closed read vector ("hostname",) after the NVUE hostname is
  verified, at the same place for patch (after IPv4 readiness and the Network SKIP line, before
  Infra Services) and replace (after the readiness that follows the replace, before REPLACED);
- equal to the CSV full name: zero sudo; a default name (DEFAULT_HOSTNAMES: "nvos" or a successful
  empty read): one fixed `sudo -n hostnamectl hostname <CSV full name>` under the original consent,
  backup, write permit, input/cancel/deadline checks, then a real read back; any other name is
  refused and reported with no sudo; a multi-line or failed read is never guessed;
- the setter is a closed NVUE-class write (backup, permit, nvue_write_commands), bound to this
  target's CSV full name at the call and again in the strict helper admission;
- sudo failure, a wrong or failed read back stop the device before Infra Services with the reason
  "Linux 主机名未生效，hostnamectl 补设失败";
- `sudo: unable to resolve host` is a known warning in the record and report, not a failure;
- check-only reads once and reports NEEDS_SET in planned_changes with needs_change true;
- the record carries linux_hostname {"observed", "action", "warning"} (guide 8.11 step 5).

The workflow class drives the real initial-setup MAIN (five PUBLIC devices of the D6 results
workflow), then the real upgrade identity check (tools/ibsw_upgrade_observer.py through the real
upgrade entry infiniband/bringup/xdr-upgrade/upgrade.py).  Only the remote devices, the consent
terminal and the upgrade's SSH replies are PUBLIC models; no real sudo, SSH or device is used.
"""
from __future__ import annotations

from contextlib import ExitStack
import importlib
import inspect
from pathlib import Path
import re
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("d1d_linux_hostname_source", INITIAL)

NAME = "ew-leaf001.example"
CURRENT = "PUBLIC-Current-D1d-74!"
PROFILE = {"dns": ["203.0.113.53"], "ntp": ["ntp.example.test"], "timezone": "Etc/UTC"}
INITIAL_ROWS = ["nv set system config auto-save state enabled", "nv set system ztp config-save enabled"]
NETWORK_ROWS = ["nv set interface eth0 ipv4 address 192.0.2.10/24",
                "nv set interface eth0 ipv4 gateway 192.0.2.1",
                "nv set interface eth0-1 link state up",
                "nv set interface eth0-1 type eth",
                "nv set system hostname " + NAME]
SERVICE_ROWS = ["nv set system dns server 203.0.113.53",
                "nv set system ntp server ntp.example.test",
                "nv set system date-time timezone Etc/UTC"]
READ = ("hostname",)
SUDO = ("sudo", "-n", "hostnamectl", "hostname", NAME)
DIFF = ("nv", "config", "diff", "-o", "commands")
STAMP = "20261126-090000"
# Guide 8.11 (:2176, :2178, :2177) and issue 12.4 item 5, verbatim.
REFUSED_TEXT = "Linux 主机名与 ib.csv 不同且不是默认名，不自动修改"
FAILED_TEXT = "Linux 主机名未生效，hostnamectl 补设失败"
CONSENT_TEXT = "补设 Linux 主机名"
CHECK_TEXT = "Linux 主机名未生效，--apply 时会补设"
RESOLVE_WARNING = "sudo: unable to resolve host"
FRAME = re.compile(
    r'^printf "\\n__HTTP_IB_BEGIN_([0-9a-f]{32})__\\n"; (.*); '
    r'task_rc=\$\?; printf "\\n__HTTP_IB_END_([0-9a-f]{32})__=%s\\n" '
    r'"\$task_rc"; exit "\$task_rc"$', re.S)
SAFE = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "


def device():
    return app.Device(NAME, "ib", "192.0.2.10", "192.0.2.10/24", "192.0.2.1", "02:00:00:00:00:10", "", "")


class _HostDevice:
    """A PUBLIC NVOS model: applied NVUE rows, the Linux hostname and the fixed replies only."""

    def __init__(self, test, applied, linux, *, follows=False, faults=()):
        self.test = test
        self.applied = list(applied)
        self.linux = linux
        self.follows = follows  # A healthy device: an applied NVUE hostname reaches Linux.
        self.faults = set(faults)
        self.pending = []
        self.events = []
        self.reads = 0
        self.on_first_read = None

    def frame(self, argv):
        # Decode the shell quoting as data and never execute it; one complete frame only.
        found = []

        def visit(text, depth):
            if depth > 6:
                return
            match = FRAME.fullmatch(text)
            if match:
                self.test.assertEqual(match[1], match[3])
                found.append((match[1], tuple(shlex.split(match[2]))))
                return
            if text.startswith(SAFE):
                text = text[len(SAFE):]
            try:
                words = shlex.split(text)
            except ValueError:
                return
            for word in words:
                if word != text and "__HTTP_IB_BEGIN_" in word:
                    visit(word, depth + 1)
        for value in argv:
            visit(value, 0)
        self.test.assertEqual(1, len(found), "one complete PUBLIC command frame is required")
        return found[0]

    def reply(self, command):
        from test_cases.test_initial_setup_identity_and_backup import EXPECTED_BACKUP_SCRIPT
        self.events.append(command)
        if command == ("nv", "config", "show", "-o", "commands"):
            return "".join(row + "\n" for row in self.applied), 0
        if command == ("ip", "addr", "show", "eth0"):
            return ("2: eth0: <UP> mtu 1500 state UP\n"
                    "    link/ether 02:00:00:00:00:10 brd ff:ff:ff:ff:ff:ff\n"
                    "    inet 192.0.2.10/24 scope global eth0\n"), 0
        if command == ("ip", "route"):
            return "default via 192.0.2.1 dev eth0\n", 0
        if command == ("nv", "show", "system", "ztp"):
            return "service disabled\nstate disabled\n", 0
        if command == DIFF:
            return "", 0
        if command == READ:
            self.reads += 1
            if self.reads == 1 and self.on_first_read is not None:
                self.on_first_read()
            if self.reads == 1 and "read-multiline" in self.faults:
                return "nvos\nnvos-second-line\n", 0
            if self.reads == 1 and "read-fails" in self.faults:
                return "hostname: PUBLIC read failure\n", 1
            if self.reads > 1 and "readback-fails" in self.faults:
                return "hostname: PUBLIC read failure\n", 1
            return self.linux + "\n", 0
        if command[:4] == SUDO[:4]:
            if "sudo-nonzero" in self.faults:
                return "sudo: a password is required\n", 1
            if "sudo-no-effect" not in self.faults:
                self.linux = command[4]
            if "resolve-warning" in self.faults:
                return f"sudo: unable to resolve host {command[4]}: Temporary failure in name resolution\n", 0
            return "", 0
        if (len(command) == 5 and command[:2] == ("sh", "-c") and command[2] == EXPECTED_BACKUP_SCRIPT
                and command[3] == "--"):
            if "backup-failed" in self.faults:
                return "IB configuration backup failed\n", 1
            return f"path=/home/PUBLIC/current_{command[4]}.yaml\nbytes=137\n", 0
        if len(command) == 5 and command[:2] == ("sh", "-c") and command[3:] == ("--", STAMP):
            # The direct IPv4 Network write's deferred apply/save launcher (D4).
            self.events.append(("deferred-apply",))
            self.commit()
            return "", 0
        if command[:2] == ("nv", "set"):
            self.pending.append(command)
            return "", 0
        if command == ("nv", "config", "apply", "-y"):
            self.commit()
            return "", 0
        if command == ("nv", "config", "save"):
            return "", 0
        raise AssertionError("PUBLIC U4 model refused an unlisted command: " + repr(command))

    def commit(self):
        for row in self.pending:
            line = shlex.join(row)
            if row[:5] not in (("nv", "set", "system", "dns", "server"), ("nv", "set", "system", "ntp", "server")):
                self.applied = [old for old in self.applied if tuple(shlex.split(old))[:-1] != row[:-1]]
            if line not in self.applied:
                self.applied.append(line)
            if row[:4] == ("nv", "set", "system", "hostname") and self.follows:
                self.linux = row[4]
        self.pending.clear()

    def transport(self, argv, _responder, _timeout):
        marker, command = self.frame(argv)
        body, status = self.reply(command)
        return app.SessionResult(
            f"__HTTP_IB_BEGIN_{marker}__\n{body}__HTTP_IB_END_{marker}__={status}\n", status)


def scene(name):
    """Applied NVUE rows: everything present, or Network (with the NVUE name) and Services missing."""
    if name == "present":
        return INITIAL_ROWS + NETWORK_ROWS + SERVICE_ROWS
    return ["nv set system hostname nvos", *INITIAL_ROWS]


class LinuxHostnameDirectTests(unittest.TestCase):
    """U4 (R-026) direct matrix through the real execute_ib_task stage skeleton."""

    def flow(self, model, *, route="jump", apply=True, yes=True, consent=True, authority_file=None,
             refuse_permit=False):
        logged, asked = [], []
        with ExitStack() as context:
            context.enter_context(mock.patch.dict(sys.modules))
            for name in list(sys.modules):
                if name == "tools" or name.startswith("tools."):
                    del sys.modules[name]
            context.enter_context(mock.patch.object(sys, "path", [str(ROOT), *sys.path]))
            context.enter_context(mock.patch.object(app, "_TOOLS_ROOT", None))
            ib = device()
            if route == "jump":
                t = app.Target(ib, app.Device("oob-leaf001", "eth_jump", "198.51.100.10", "", "", "", "", ""),
                               "swp1", "eth0")
                point = app.Neighbor("fe80::10", "vlan1000", ib.eth0_mac, "oob")
                outer = "PUBLIC-Outer-Only"
            else:
                path = app._import_tools("tools.login_path").Route(ib.hostname, "direct", "PUBLIC", None, None, None)
                t = app.Target(ib, None, "", "eth0", route=path)
                point = app.DirectEndpoint("192.0.2.10")
                outer = ""
            task = app.PreparedIBTask(t, point, outer, False)
            args = SimpleNamespace(eth_user="cumulus", ib_user="admin", connect_timeout=5,
                                   apply=apply, yes=yes, force=False, run_stamp=STAMP,
                                   execution_mode="ethernet" if route == "jump" else "management",
                                   _on_management_server=route != "jump")
            authority = app.RuntimeInputAuthority([] if authority_file is None else [authority_file])
            coordinator = app.RuntimeCoordinator(args, None, "PUBLIC-Factory-U4", [task], authority)
            coordinator.current_target = t
            real_permit = app.obtain_write_permit

            def permit(category="nvue"):
                model.events.append(("permit", category))
                if refuse_permit and category == "nvue":
                    raise app.SetupError("PUBLIC write permit refused")
                return real_permit(category)

            def ask(_target, reason, **_options):
                asked.append(reason)
                model.events.append(("consent", consent))
                return consent

            def inspected(device_target, endpoint, *_args, **options):
                self.assertIs(t, device_target)
                self.assertIs(point, endpoint)
                result = app.SessionResult("".join(row + "\n" for row in model.applied), 0)
                if route != "jump":
                    result._direct_endpoint = point
                return result, CURRENT, options["authorized"]

            def ready(*_args, **_options):
                model.events.append(("readiness",))
                return "".join(row + "\n" for row in model.applied)

            def direct_ready(_target, _user, _credential, _timeout, **options):
                model.events.append(("readiness",))
                options["details"].update(identity={"ok": True, "via_ipv4": True}, endpoint=point)
                return "".join(row + "\n" for row in model.applied)

            def keys(*_args, **options):
                model.events.append(("keys",))
                return options["authorized"]

            for name, value in (("_TASK_IB_CONFIG", None), ("_ACTIVE_COORDINATOR", coordinator),
                                ("_WORKER_CONNECTION", None), ("_WORKER_STOP", None),
                                ("_TASK_DEADLINE", None), ("_TASK_LOG_BUFFER", None),
                                ("_JUMP_SESSIONS", None)):
                context.enter_context(mock.patch.object(app, name, value))
            context.enter_context(mock.patch.object(app, "interactive_run", side_effect=model.transport))
            context.enter_context(mock.patch.object(app, "obtain_write_permit", side_effect=permit))
            context.enter_context(mock.patch.object(app, "_ask_first_device_change", side_effect=ask))
            context.enter_context(mock.patch.object(app, "inspect_ib_device", side_effect=inspected))
            context.enter_context(mock.patch.object(app, "verify_ipv4_login", side_effect=ready))
            context.enter_context(mock.patch.object(app, "_wait_direct_ipv4_readback", side_effect=direct_ready))
            context.enter_context(mock.patch.object(app, "run_key_stage", side_effect=keys))
            context.enter_context(mock.patch.object(app, "run_management_direct_checks", return_value=[]))
            context.enter_context(mock.patch.object(app, "refresh_ib_host_key",
                side_effect=AssertionError("PUBLIC U4 model has no host-key change")))
            context.enter_context(mock.patch.object(app, "log", side_effect=lambda text="", *_a, **_k:
                                                    logged.append(str(text))))
            result = app.execute_ib_task(task, args, None, "PUBLIC-Factory-U4", PROFILE, [], None)
        return result, coordinator, "\n".join(logged), asked

    @staticmethod
    def nvue_events(model):
        return [event for event in model.events if event == ("deferred-apply",) or event[:4] == SUDO[:4]
                or event[:2] == ("nv", "set") or event[:3] in (("nv", "config", "apply"), ("nv", "config", "save"))]

    @staticmethod
    def service_writes(model):
        return [event for event in model.events if event[:2] == ("nv", "set")
                and event[:4] in (("nv", "set", "system", "dns"), ("nv", "set", "system", "ntp"),
                                  ("nv", "set", "system", "date-time"))]

    def test_argv_admits_only_the_fixed_read_and_sudo_shapes_and_classifies_the_write(self):
        # Step 2: a read-only ("hostname",); step 3: a fixed sudo shape that is an NVUE-class write.
        def admitted(argv):
            try:
                return app.ib_command_argv(argv) == argv
            except app.SetupError:
                return False
        self.assertTrue(admitted(["hostname"]), "the closed read vector is admitted")
        self.assertIsNone(app._ib_write_category(["hostname"]))
        self.assertTrue(admitted(list(SUDO)), "the fixed setter shape is admitted")
        self.assertEqual("nvue", app._ib_write_category(list(SUDO)))
        for label, argv in (
                ("missing-n", ["sudo", "hostnamectl", "hostname", NAME]),
                ("extra-argument", [*SUDO, "--static"]),
                ("other-verb", ["sudo", "-n", "hostnamectl", "set-hostname", NAME]),
                ("other-user", ["sudo", "-n", "-u", "root", "hostnamectl", "hostname", NAME]),
                ("invalid-name", ["sudo", "-n", "hostnamectl", "hostname", "bad_name;reboot"]),
                ("empty-name", ["sudo", "-n", "hostnamectl", "hostname", ""]),
                ("hostname-with-argument", ["hostname", NAME]),
                ("shell", ["sh", "-c", "sudo -n hostnamectl hostname " + NAME])):
            with self.subTest(case=label), self.assertRaises(app.SetupError):
                app.ib_command_argv(argv)

    def test_strict_helper_admission_binds_the_setter_to_this_target_full_name(self):
        # Step 3: the strict helper's single-task admission binds the name once more.
        class Guard:
            @staticmethod
            def assert_unchanged():
                return None

        for direct in (False, True):
            ib = device()
            if direct:
                with ExitStack() as context:
                    context.enter_context(mock.patch.dict(sys.modules))
                    for name in list(sys.modules):
                        if name == "tools" or name.startswith("tools."):
                            del sys.modules[name]
                    context.enter_context(mock.patch.object(sys, "path", [str(ROOT), *sys.path]))
                    context.enter_context(mock.patch.object(app, "_TOOLS_ROOT", None))
                    path = app._import_tools("tools.login_path").Route(NAME, "direct", "PUBLIC", None, None, None)
                t = app.Target(ib, None, "", "eth0", route=path)
                point, outer_user, outer = app.DirectEndpoint("192.0.2.10"), "", ""
            else:
                t = app.Target(ib, app.Device("oob-leaf001", "eth_jump", "198.51.100.10", "", "", "", "", ""),
                               "swp1", "eth0")
                point, outer_user, outer = app.Neighbor("fe80::10", "vlan1000", ib.eth0_mac, "oob"), "cumulus", "OOB"
            for name, admitted in ((NAME, True), ("ew-leaf002.example", False), ("ew-leaf001", False),
                                   ("EW-LEAF001.EXAMPLE", False)):
                sent = []

                def run(*arguments, **_options):
                    sent.append(tuple(arguments[7]))
                    return app.SessionResult("", 0)
                with self.subTest(direct=direct, name=name), \
                        mock.patch.object(app, "run_on_ib", side_effect=run), \
                        mock.patch.object(app, "_ib_project_value", return_value=None), \
                        mock.patch.object(app, "_validate_direct_endpoint", return_value=None):
                    error = None
                    try:
                        app._run_authorized_ib_command_core(
                            t, point, outer_user, outer, "admin", CURRENT, 5,
                            ["sudo", "-n", "hostnamectl", "hostname", name], direct=direct, _password_policy=Guard())
                    except app.SetupError as exc:
                        error = exc
                    if admitted:
                        self.assertIsNone(error, error)
                        self.assertEqual([("sudo", "-n", "hostnamectl", "hostname", NAME)], sent)
                    else:
                        self.assertIsInstance(error, app.SetupError)
                        self.assertEqual([], sent, "another name never reaches the transport")

    def test_default_linux_name_is_set_once_after_consent_backup_and_permit_then_read_back(self):
        for route in ("jump", "direct"):
            for where in ("present", "network"):
                for observed in ("nvos", "NVOS", ""):
                    model = _HostDevice(self, scene(where), observed)
                    with self.subTest(route=route, scene=where, observed=observed):
                        result, coordinator, logged, _ = self.flow(model, route=route)
                        self.assertNotIn("failed_stage", result, result.get("reason"))
                        events = model.events
                        reads = [index for index, event in enumerate(events) if event == READ]
                        self.assertEqual(2, len(reads), events)
                        self.assertEqual(1, sum(event[:4] == SUDO[:4] for event in events))
                        sudo = events.index(SUDO)  # the exact CSV full name, `-n`, no extra argument
                        from test_cases.test_initial_setup_identity_and_backup import EXPECTED_BACKUP_SCRIPT
                        backup = next(index for index, event in enumerate(events)
                                      if event[:3] == ("sh", "-c", EXPECTED_BACKUP_SCRIPT))
                        # read -> write backup -> real NVUE permit -> sudo -> read back (steps 2-3).
                        self.assertTrue(reads[0] < sudo < reads[1], events)
                        self.assertLess(backup, sudo)
                        self.assertEqual(("permit", "nvue"), events[sudo - 1])
                        self.assertEqual(reads[1], sudo + 1, "the read back follows the sudo directly")
                        # Placement (step 1): after IPv4 readiness and every Network write, before Services.
                        readiness = max(index for index, event in enumerate(events) if event == ("readiness",))
                        self.assertLess(readiness, reads[0])
                        network = [index for index, event in enumerate(events) if event == ("deferred-apply",)
                                   or event[:2] == ("nv", "set") and event[:4] in (
                                       ("nv", "set", "interface", "eth0"), ("nv", "set", "system", "hostname"))]
                        if where == "network":
                            self.assertTrue(network and max(network) < reads[0], events)
                            if route == "direct":
                                self.assertIn(("deferred-apply",), events)
                            services = [events.index(row) for row in self.service_writes(model)]
                            self.assertTrue(services and reads[1] < min(services), events)
                        self.assertLess(reads[1], events.index(("keys",)))
                        self.assertNotIn(("nv", "show", "system", "health"), events)
                        self.assertEqual(NAME, model.linux)
                        # Step 4/5: the sudo is a real NVUE write attempt on the original counter.
                        self.assertEqual(len(self.nvue_events(model)),
                                         coordinator.metrics.get("nvue_write_commands"))
                        self.assertTrue(coordinator.writes_attempted)
                        self.assertEqual({"observed": observed, "action": "SET", "warning": None},
                                         result.get("linux_hostname"))
                        self.assertEqual("CHECKED_AND_CONFIGURED", app.record_category(
                            {**result, "metrics": dict(coordinator.metrics),
                             "writes_attempted": coordinator.writes_attempted}))

    def test_matching_linux_name_issues_no_sudo_or_write(self):
        for route in ("jump", "direct"):
            for observed in (NAME, NAME.upper(), NAME + "."):
                model = _HostDevice(self, scene("present"), observed)
                with self.subTest(route=route, observed=observed):
                    result, coordinator, _, asked = self.flow(model, route=route, yes=False)
                    self.assertNotIn("failed_stage", result, result.get("reason"))
                    self.assertEqual(1, model.events.count(READ))
                    self.assertFalse(any(event[:1] == ("sudo",) or event[:2] == ("sh", "-c")
                                         or event[0] == "permit" for event in model.events), model.events)
                    self.assertEqual([], asked)
                    self.assertFalse(coordinator.writes_attempted)
                    self.assertEqual({"observed": observed, "action": "NONE", "warning": None},
                                     result.get("linux_hostname"))

    def test_non_default_different_name_is_refused_and_reported_without_sudo(self):
        for route in ("jump", "direct"):
            for apply in (True, False):
                model = _HostDevice(self, scene("present"), "ew-other001.example")
                with self.subTest(route=route, apply=apply):
                    result, coordinator, logged, _ = self.flow(model, route=route, apply=apply)
                    self.assertNotIn("failed_stage", result, result.get("reason"))
                    self.assertEqual(1, model.events.count(READ))
                    self.assertFalse(any(event[:1] == ("sudo",) for event in model.events), model.events)
                    self.assertEqual({"observed": "ew-other001.example", "action": "REFUSED",
                                      "warning": REFUSED_TEXT}, result.get("linux_hostname"))
                    self.assertIn(REFUSED_TEXT, logged)
                    self.assertEqual("ew-other001.example", model.linux)
                    self.assertFalse(coordinator.writes_attempted)

    def test_unreadable_or_multiline_name_fails_without_guessing_or_writing(self):
        for route in ("jump", "direct"):
            for fault in ("read-multiline", "read-fails"):
                model = _HostDevice(self, scene("present"), "nvos", faults=(fault,))
                with self.subTest(route=route, fault=fault):
                    result, coordinator, _, _ = self.flow(model, route=route)
                    self.assertEqual("FAILED", result["outcome"])
                    self.assertEqual("day0", result.get("failed_stage"), result.get("reason"))
                    self.assertEqual(1, model.events.count(READ))
                    self.assertFalse(any(event[:1] == ("sudo",) or event[:2] == ("sh", "-c")
                                         for event in model.events), model.events)
                    self.assertEqual("NOT_REACHED", result["stage_status"]["services"])
                    self.assertNotIn(("keys",), model.events)
                    self.assertFalse(coordinator.writes_attempted)

    def test_sudo_failure_or_bad_read_back_stops_the_device_before_services(self):
        for route in ("jump", "direct"):
            for fault in ("sudo-nonzero", "sudo-no-effect", "readback-fails"):
                model = _HostDevice(self, scene("network"), "nvos", faults=(fault,))
                with self.subTest(route=route, fault=fault):
                    result, coordinator, _, _ = self.flow(model, route=route)
                    self.assertEqual("FAILED", result["outcome"])
                    self.assertEqual("day0", result.get("failed_stage"), result.get("reason"))
                    self.assertTrue(result["reason"].startswith(FAILED_TEXT), result["reason"])
                    self.assertEqual(1, model.events.count(SUDO), "at most one sudo, never replayed")
                    self.assertEqual(2 if fault != "sudo-nonzero" else 1, model.events.count(READ))
                    self.assertEqual([], self.service_writes(model))
                    self.assertNotIn(DIFF, model.events[model.events.index(SUDO):])
                    self.assertNotIn(("keys",), model.events)
                    self.assertEqual("NOT_REACHED", result["stage_status"]["services"])
                    # The attempted sudo is counted like every other NVUE write (step 4).
                    self.assertEqual(len(self.nvue_events(model)), coordinator.metrics.get("nvue_write_commands"))
                    self.assertTrue(result.get("linux_hostname") is not None
                                    and result["linux_hostname"]["action"] != "SET")

    def test_unresolved_host_warning_is_reported_not_failed(self):
        for route in ("jump", "direct"):
            model = _HostDevice(self, scene("present"), "nvos", faults=("resolve-warning",))
            with self.subTest(route=route):
                result, _, logged, _ = self.flow(model, route=route)
                self.assertNotIn("failed_stage", result, result.get("reason"))
                record = result.get("linux_hostname")
                self.assertIsNotNone(record, "the Linux hostname step is recorded")
                self.assertEqual(("nvos", "SET"), (record["observed"], record["action"]))
                self.assertIn(RESOLVE_WARNING, record["warning"])
                self.assertIn(RESOLVE_WARNING, logged)
                self.assertEqual(NAME, model.linux)

    def test_consent_authority_cancel_deadline_backup_and_permit_gate_the_sudo(self):
        import tempfile as _tempfile
        for route in ("jump", "direct"):
            for consent in (True, False):
                model = _HostDevice(self, scene("present"), "nvos")
                with self.subTest(route=route, consent=consent):
                    result, coordinator, _, asked = self.flow(model, route=route, yes=False, consent=consent)
                    self.assertEqual([CONSENT_TEXT], asked)
                    answered = model.events.index(("consent", consent))
                    self.assertLess(model.events.index(READ), answered)
                    self.assertFalse(any(event[:1] == ("sudo",) or event[:2] == ("sh", "-c")
                                         for event in model.events[:answered]))
                    if consent:
                        self.assertLess(answered, model.events.index(SUDO))
                        self.assertNotIn("failed_stage", result, result.get("reason"))
                    else:
                        self.assertNotIn(SUDO, model.events)
                        self.assertEqual("nvos", model.linux)
                        self.assertFalse(coordinator.writes_attempted)
            for fault in ("batch-stopped", "input-changed", "deadline", "permit-refused", "backup-failed"):
                model = _HostDevice(self, scene("present"), "nvos",
                                    faults=("backup-failed",) if fault == "backup-failed" else ())
                with self.subTest(route=route, fault=fault), _tempfile.TemporaryDirectory() as folder:
                    pinned = Path(folder) / "01-global.yaml"
                    pinned.write_text("PUBLIC U4 pinned input\n", encoding="ascii")

                    def disturb():
                        if fault == "batch-stopped":
                            app._ACTIVE_COORDINATOR.stopped = True
                            app._ACTIVE_COORDINATOR.fatal = "PUBLIC operator stop"
                        elif fault == "input-changed":
                            pinned.write_text("PUBLIC U4 changed input\n", encoding="ascii")
                        elif fault == "deadline":
                            app._TASK_DEADLINE = -1.0
                    model.on_first_read = disturb
                    result, coordinator, _, _ = self.flow(model, route=route, authority_file=pinned,
                                                          refuse_permit=fault == "permit-refused")
                    self.assertEqual("day0", result.get("failed_stage"), result.get("reason"))
                    self.assertNotIn(SUDO, model.events)
                    self.assertEqual("nvos", model.linux)
                    self.assertEqual(0, coordinator.metrics.get("nvue_write_commands", 0))
                    self.assertNotIn(("keys",), model.events)
                    if fault == "backup-failed":
                        self.assertEqual("FAILED_CONFIG_BACKUP", result.get("category"))
                    if fault in ("batch-stopped", "input-changed", "deadline"):
                        self.assertFalse(any(event[:2] == ("sh", "-c") for event in model.events))

    def test_check_only_reads_once_and_reports_needs_set_without_sudo(self):
        for route in ("jump", "direct"):
            model = _HostDevice(self, scene("present"), "nvos")
            with self.subTest(route=route, case="default-name"):
                result, coordinator, logged, _ = self.flow(model, route=route, apply=False)
                self.assertEqual(1, model.events.count(READ))
                self.assertNotIn(SUDO, model.events)
                self.assertFalse(any(event[0] == "permit" for event in model.events))
                self.assertEqual({"observed": "nvos", "action": "NEEDS_SET", "warning": None},
                                 result.get("linux_hostname"))
                self.assertIn({"item": "linux hostname", "value": NAME}, result["planned_changes"])
                self.assertIs(True, result["needs_change"])
                self.assertEqual("CHECK_ONLY", result["outcome"])
                self.assertIn(CHECK_TEXT, logged)
                self.assertFalse(coordinator.writes_attempted)
            # The NVUE hostname is still the default: Network would set it; no Linux read yet.
            model = _HostDevice(self, scene("network"), "nvos")
            with self.subTest(route=route, case="nvue-not-configured"):
                result, _, _, _ = self.flow(model, route=route, apply=False)
                self.assertNotIn(READ, model.events)
                self.assertIsNone(result.get("linux_hostname"))
                self.assertFalse(any(entry["item"] == "linux hostname" for entry in result["planned_changes"]))

    def test_nvue_hostname_conflict_never_reads_or_sets_the_linux_name(self):
        rows = [row if not row.startswith("nv set system hostname ") else "nv set system hostname ew-other001"
                for row in scene("present")]
        for route in ("jump", "direct"):
            for apply in (True, False):
                model = _HostDevice(self, rows, "nvos")
                with self.subTest(route=route, apply=apply):
                    result, _, _, _ = self.flow(model, route=route, apply=apply)
                    self.assertEqual("BLOCKED_NETWORK_CONFLICT", result.get("category"))
                    self.assertNotIn(READ, model.events)
                    self.assertNotIn(SUDO, model.events)
                    self.assertIsNone(result.get("linux_hostname"))

    def test_sudo_and_reads_follow_the_stage_route_on_all_four_ib_paths(self):
        # Step 4: ordinary and strict/helper, jump and direct route the sudo like any stage write.
        self.assertIn("_settle_linux_hostname", dir(app))
        parameters = inspect.signature(app._settle_linux_hostname).parameters
        for name in ("local", "strict", "policy", "apply", "authorized", "nvue_verified", "record"):
            self.assertIs(inspect.Parameter.KEYWORD_ONLY, parameters[name].kind, name)
        for strict in (False, True):
            for direct in (False, True):
                ib = device()
                if direct:
                    t, point = app.Target(ib, None, "", "eth0"), app.DirectEndpoint("192.0.2.10")
                else:
                    t = app.Target(ib, app.Device("oob-leaf001", "eth_jump", "198.51.100.10", "", "", "", "", ""),
                                   "swp1", "eth0")
                    point = app.Neighbor("fe80::10", "vlan1000", ib.eth0_mac, "oob")
                timeline = []
                state = {"linux": "nvos"}

                def reply(label, command):
                    command = tuple(command)
                    timeline.append((label, command))
                    if command == SUDO:
                        state["linux"] = NAME
                    result = app.SessionResult(state["linux"] + "\n" if command == READ else "", 0)
                    result._direct_endpoint = point
                    return result

                class Guard:
                    @staticmethod
                    def assert_unchanged():
                        timeline.append(("guard", ()))

                record = {"linux_hostname": None, "planned_changes": []}
                with self.subTest(strict=strict, direct=direct), \
                        mock.patch.object(app, "run_on_ib", side_effect=lambda *a, **_k: reply("run_on_ib", a[7])), \
                        mock.patch.object(app, "_run_authorized_ib_command",
                                          side_effect=lambda *a, **_k: reply("jump-helper", a[7])), \
                        mock.patch.object(app, "_run_authorized_ib_direct_command",
                                          side_effect=lambda *a, **_k: reply("direct-helper", a[7])), \
                        mock.patch.object(app, "log"):
                    authorized = app._settle_linux_hostname(
                        t, point, "" if direct else "cumulus", "" if direct else "OOB", "admin", CURRENT, 5,
                        local=False, strict=strict, policy=Guard() if strict else None, apply=True,
                        authorized=True, nvue_verified=True, record=record)
                    self.assertIs(True, authorized)
                    route = ("direct-helper" if direct else "jump-helper") if strict else "run_on_ib"
                    self.assertEqual([(route, READ), (route, SUDO), (route, READ)],
                                     [item for item in timeline if item[0] != "guard"])
                    self.assertEqual("SET", record["linux_hostname"]["action"])


class _LinuxNameDevices:
    """Factory for the D6 five-device world with a Linux hostname per device (built lazily)."""

    @staticmethod
    def build(results_workflow):
        names = results_workflow.NAMES

        class Devices(results_workflow._FiveDevices):
            def __init__(self, test, app_module, kat):
                super().__init__(test, app_module, kat)
                # EXAMPLE-IB001 (factory, jump): a healthy device; the NVUE hostname reaches Linux.
                # EXAMPLE-IB002 (complete, jump): the field case, NVUE right and Linux still "nvos".
                # EXAMPLE-IB004 (jump): Linux carries some other non-default name.
                # EXAMPLE-IB005 (complete, direct): a successful empty Linux name.
                self.linux = {names[0]: "nvos", names[1]: "nvos", names[2]: "nvos",
                              names[3]: "EXAMPLE-OTHER", names[4]: ""}

            def _reply(self, name, command):
                if command == READ:
                    self.events.append((name, command))
                    return self.linux[name] + "\n", 0
                if command[:4] == SUDO[:4]:
                    self.events.append((name, command))
                    self.test.assertEqual(("sudo", "-n", "hostnamectl", "hostname", name), command)
                    self.linux[name] = command[4]
                    return "", 0
                if command == ("nv", "config", "apply", "-y") and name == names[0]:
                    named = [setter for setter in self.pending[name] if setter[:4] == ("nv", "set", "system", "hostname")]
                    answer = super()._reply(name, command)
                    if named:
                        self.linux[name] = named[-1][4]
                    return answer
                return super()._reply(name, command)
        return Devices


class LinuxHostnameToUpgradeWorkflowTests(unittest.TestCase):
    """Real initial-setup MAIN -> permits/helper -> real read back and D6 summary -> real upgrade identity."""

    @classmethod
    def setUpClass(cls):
        cls.app = load_script("d1d_linux_hostname_workflow_source", INITIAL)

    def run_initial(self, *, apply):
        from test_cases import test_initial_setup_bringup_results_workflow as results_workflow
        devices = _LinuxNameDevices.build(results_workflow)
        with mock.patch.object(results_workflow, "_FiveDevices", devices):
            code, evidence, console, report, world, per_device = (
                results_workflow.BringupResultsWorkflowTests.run_five(self, apply=apply))
        self.assertIs(type(world), devices)
        return evidence, report, world, per_device, results_workflow.NAMES

    def upgrade_identity(self, name, linux, mac):
        """The original upgrade read-only identity rule on the real inventory snapshot and observer."""
        from test_cases import test_ibsw225_three_component_workflow as upgrade_workflow
        contract = importlib.import_module("ibsw_upgrade_contract")
        fixtures = upgrade_workflow.fixtures
        rows = [",".join(fixtures.HEADER),
                ",".join([name, "ib", "NA", "203.0.113.12", "24", "203.0.113.1", "02:00:00:00:00:12"] + [""] * 12)]
        snapshot = contract.snapshot_inventory("\n".join(rows) + "\n", fixtures.GLOBAL)
        leaf = SimpleNamespace(node=snapshot.devices[0])
        try:
            upgrade_workflow.observer._validate_identity(leaf, ((linux + "\n" + mac + "\n").encode(), b"", 0, True))
        except upgrade_workflow.observer._NativeObservationHold as hold:
            return hold.reason_code
        return "OK"

    def upgrade_entry(self, linux_ok):
        """The real upgrade entry's read-only inspection with this device's identity answer."""
        from test_cases import test_ibsw225_three_component_workflow as upgrade_workflow
        with tempfile.TemporaryDirectory() as folder:
            fixture = upgrade_workflow.ThreeComponentWorkflowTests("test_inspection_is_strictly_read_only_for_all_components")
            code, report, err, calls, installs = fixture.invoke(
                Path(folder).resolve(), inspect=True, initial_identity_mismatch=not linux_ok)
        identity = upgrade_workflow.observer._IDENTITY_COMMAND
        self.assertIn(identity, [command for _, command in calls])
        self.assertEqual([], installs)
        return code, report, err

    def test_apply_sets_the_default_linux_name_and_the_upgrade_identity_check_passes(self):
        evidence, report, world, per_device, names = self.run_initial(apply=True)
        records = evidence["records"]
        expected = {names[0]: {"observed": names[0], "action": "NONE", "warning": None},
                    names[1]: {"observed": "nvos", "action": "SET", "warning": None},
                    names[3]: {"observed": "EXAMPLE-OTHER", "action": "REFUSED", "warning": REFUSED_TEXT},
                    names[4]: {"observed": "", "action": "SET", "warning": None}}
        for name, linux_record in expected.items():
            with self.subTest(device=name):
                record = records[name.casefold()]
                self.assertNotIn("failed_stage", record, record.get("reason"))
                self.assertEqual(linux_record, record.get("linux_hostname"))
                self.assertEqual(record, next(item for item in per_device if item["hostname"] == name))
                events = [command for peer, command in world.events if peer == name]
                sudo = [command for command in events if command[:1] == ("sudo",)]
                self.assertEqual([("sudo", "-n", "hostnamectl", "hostname", name)] if linux_record["action"] == "SET"
                                 else [], sudo)
        self.assertIsNone(records[names[2].casefold()].get("linux_hostname"))
        for name in (names[1], names[4]):
            record = records[name.casefold()]
            events = [command for peer, command in world.events if peer == name]
            self.assertIn(("sudo", "-n", "hostnamectl", "hostname", name), events)
            sudo = events.index(("sudo", "-n", "hostnamectl", "hostname", name))
            from test_cases.test_initial_setup_identity_and_backup import EXPECTED_BACKUP_SCRIPT
            backup = next(index for index, command in enumerate(events)
                          if command[:3] == ("sh", "-c", EXPECTED_BACKUP_SCRIPT))
            self.assertLess(backup, sudo)
            self.assertEqual(READ, events[sudo + 1])
            self.assertEqual(1, record["metrics"]["nvue_write_commands"])
            self.assertEqual("CHECKED_AND_CONFIGURED", record["category"])
            self.assertIsNotNone(record["backup"])
            self.assertEqual(name, world.linux[name])
            self.assertIn(name, report)
        self.assertIn(REFUSED_TEXT, report)
        # The original upgrade identity rule now admits the corrected device and still refuses the others.
        self.assertEqual("OK", self.upgrade_identity(names[1], world.linux[names[1]], "02:00:00:00:00:12"))
        self.assertEqual("DEVICE_IDENTITY_MISMATCH",
                         self.upgrade_identity(names[1], world.linux[names[3]], "02:00:00:00:00:12"))
        self.assertEqual("DEVICE_IDENTITY_MISMATCH",
                         self.upgrade_identity(names[1], world.linux[names[1]], "02:00:00:00:00:99"))
        code, report_json, err = self.upgrade_entry(app_normal(world.linux[names[1]]) == app_normal(names[1]))
        self.assertEqual(0, code, err)
        self.assertEqual("NOT_EXECUTED", report_json["execution_state"])

    def test_check_only_reports_needs_set_and_the_upgrade_identity_check_still_refuses(self):
        evidence, report, world, per_device, names = self.run_initial(apply=False)
        records = evidence["records"]
        for name, observed in ((names[1], "nvos"), (names[4], "")):
            with self.subTest(device=name):
                record = records[name.casefold()]
                self.assertEqual({"observed": observed, "action": "NEEDS_SET", "warning": None},
                                 record.get("linux_hostname"))
                self.assertIn({"item": "linux hostname", "value": name}, record["planned_changes"])
                self.assertIs(True, record["needs_change"])
                self.assertEqual("CHECKED_NEEDS_CONFIGURATION", record["category"])
        self.assertIsNone(records[names[0].casefold()].get("linux_hostname"))
        self.assertFalse(any(command[:1] == ("sudo",) for _, command in world.events))
        self.assertEqual([], world.permits)
        self.assertIn(CHECK_TEXT, report)
        self.assertEqual("nvos", world.linux[names[1]])
        self.assertEqual("DEVICE_IDENTITY_MISMATCH",
                         self.upgrade_identity(names[1], world.linux[names[1]], "02:00:00:00:00:12"))
        code, report_json, err = self.upgrade_entry(app_normal(world.linux[names[1]]) == app_normal(names[1]))
        self.assertEqual(3, code, err)
        self.assertEqual(["DEVICE_IDENTITY_MISMATCH"], report_json["skipped_devices"][0]["reasons"])


def app_normal(value):
    return app.normalize_name(value)


if __name__ == "__main__":
    unittest.main()
