"""Workflow: initial-setup --credentials-fd reads passwords through tools/credentials_fd.py.

Expectations come from the R-012 design §8.3 (:340-348) and §19 (:619), the v3.1.3 guide WP-5 and
O10, and v15's summary contract (INCOMPLETE = 2), not from the implementation.

Real CSV/P2P/target cache, real main(), real OOB snapshot collection and routing, real per-device
stages, real report and summary.json; only the SSH/PTY transport (initial-setup's interactive_run),
the OOB public-key probe and the clock are replaced.  The fake transport answers a password prompt
only with the expected credential and records every argv and the process environment it sees.
Credentials travel on an inherited pipe; every value is assembled at run time.  Without a project
global the management run takes the v15 per-device path (guide table 6-1 row 10, P1); with one, the
strict path, whose DEV phase sessions the fake device answers through the real _IBPhase observer.
"""

from __future__ import annotations

import builtins
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import csv
import getpass
import io
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
JUMPS = (("EXAMPLE-JUMP01", "198.51.100.10"), ("EXAMPLE-JUMP02", "198.51.100.11"))
IBS = (("example-ib01.example.test", "192.0.2.11", "02:00:00:00:00:10", "EXAMPLE-JUMP01"),
       ("example-ib02.example.test", "192.0.2.12", "02:00:00:00:00:12", "EXAMPLE-JUMP02"))
SERVICE_LINES = ("nv set system dns server 192.0.2.53\nnv set system ntp server 192.0.2.123\n"
                 "nv set system date-time timezone Etc/UTC\n")


def secret(label: str) -> str:
    return "-".join(("PUBLIC", "fd", label, str(os.getpid()), "Zq7"))


def project_global() -> str:
    # Assembled so no credential literal appears in the source (public audit).
    global_hash = "$" + "6$PUBLICsalt$" + "A" * 86
    return ("schema_version: 2\ncommon:\n  switch:\n    system:\n      hostname: PUBLIC-COMMON\n"
            "switches:\n- ib:\n    system:\n      aaa:\n        user:\n          admin:\n"
            "            password: {}\n").format(json.dumps(global_hash))


class _PhaseSession:
    """Feed device output to the real responder as interactive_run does (DEV phase sessions)."""

    def __init__(self, app, responder) -> None:
        self.app, self.responder, self.phase = app, responder, responder._phase
        self.output = ""
        self.reader, self.writer = os.pipe()

    def feed(self, text: str):
        self.output += text
        self.phase.observe(self.output)
        reply = self.responder(self.app.strip_ansi(self.output))
        if reply is not None:
            self.phase.write_reply(self.writer, reply, self.responder, time.monotonic() + 60)
            os.read(self.reader, 65536)
        return reply

    def result(self, code: int):
        os.close(self.reader)
        os.close(self.writer)
        return self.app.SessionResult(self.app.strip_ansi(self.output), code)


class _World:
    """One project directory and the fake device side for one run."""

    def __init__(self, test: unittest.TestCase, app, root: Path, *, jump_passwords: dict,
                 ib_password: str, configured: bool, global_text: str = "",
                 ib_passwords=None) -> None:
        self.test, self.app, self.root = test, app, root
        self.jump_passwords = dict(jump_passwords)
        self.ib_password = ib_password
        self.ib_passwords = dict(ib_passwords or {})
        self.configured = {host: configured for host, *_ in IBS}
        self.argvs: list[list[str]] = []
        self.environments: list[dict] = []
        self.writes: list[str] = []
        self.rejected: list[str] = []
        with (root / "ib.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["hostname", "type", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"])
            for host, address, mac, _jump in IBS:
                writer.writerow([host, "ib", address, "24", "192.0.2.1", mac])
            for host, address in JUMPS:
                writer.writerow([host, "eth_jump", address, "", "", ""])
        (root / "p2p.dot").write_text("".join(
            f'"{host}":"eth0" -- "{jump}":"swp1"\n' for host, _a, _m, jump in IBS), encoding="utf-8")
        (root / "infra-neutral.conf").write_text(
            "DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=Etc/UTC\n", encoding="utf-8")
        if global_text:
            (root / "01-global.yaml").write_text(global_text, encoding="utf-8")
        self.devices = {host: app.Device(host, "ib", address, address + "/24", "192.0.2.1", mac, "", "")
                        for host, address, mac, _jump in IBS}
        self.jump_of = {host: jump for host, _a, _m, jump in IBS}
        self.by_link_local = {app.mac_to_link_local(device.eth0_mac): device
                              for device in self.devices.values()}
        self.by_ip = {device.login_ip: device for device in self.devices.values()}

    def argv(self, *extra: str) -> list[str]:
        root = self.root
        return [str(INITIAL), "--project-dir", str(root), "--ib-csv", str(root / "ib.csv"),
                "--p2p", str(root / "p2p.dot"), "--target-cache", str(root / "targets.json"),
                "--report", str(root / "report.log"), "--snapshot-dir", str(root / "snapshots"),
                "--execution-mode", "management", *extra]

    # -- Ethernet side -------------------------------------------------------------------------
    def ethernet_output(self, jump: str, command: list[str]) -> str:
        ib = next(self.devices[host] for host, owner in self.jump_of.items() if owner == jump)
        if command == ["hostname"]:
            return jump + "\n"
        if command == ["nv", "show", "interface"]:
            header = ["Interface", "Admin Status", "Oper Status", "Speed", "MTU", "Type",
                      "Remote Host", "Remote Port", "Summary"]
            widths = [16, 15, 15, 8, 8, 12, 38, 18, 12]

            def row(values):
                return "".join(str(v).ljust(w) for v, w in zip(values, widths)).rstrip()
            return "\n".join([row(header), row(["-" * (w - 2) for w in widths]),
                              row(["swp1", "up", "up", "1G", "9216", "swp", "nvos", "eth0", ""])]) + "\n"
        if command == ["ip", "-d", "link", "show"]:
            return ("1: br_default: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 state UP\n"
                    "    bridge forward_delay 1500\n"
                    "2: swp1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master br_default state UP\n"
                    "4: vlan1000@br_default: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master oob state UP\n"
                    "    vlan protocol 802.1Q id 1000 <REORDER_HDR>\n")
        if command == ["bridge", "fdb", "show"]:
            return f"{ib.eth0_mac} dev swp1 vlan 1000 master br_default\n"
        if command == ["ip", "neighbor"]:
            return f"{self.app.mac_to_link_local(ib.eth0_mac)} dev vlan1000 lladdr {ib.eth0_mac} REACHABLE\n"
        if command == ["ip", "-j", "address", "show"]:
            return json.dumps([{"ifname": "vlan1000", "flags": ["BROADCAST", "MULTICAST", "UP"],
                                "operstate": "UP", "addr_info": [
                                    {"family": "inet", "local": "192.0.2.1", "prefixlen": 24, "scope": "global"},
                                    {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]}])
        if command == ["ifquery", "vlan1000"]:
            return "iface vlan1000\n    vrf oob\n"
        raise AssertionError(f"unexpected Ethernet command {command}")

    # -- IB side ---------------------------------------------------------------------------------
    def ib_payload(self, device, text: str) -> str:
        app = self.app
        if re.search(r"\bnv (?:set|unset)\b|\bnv config (?:apply|save)\b", text):
            self.writes.append(text)
            if "nv config save" in text:
                self.configured[device.hostname] = True
            return ""
        if "nv show system ztp" in text:
            return "service disabled\n"
        if "nv config diff" in text:
            return ""
        if "nv config show" in text:
            payload = ("\n".join(shlex.join(c) for c in app.desired_commands(device) if c[:2] == ["nv", "set"]) + "\n"
                       + SERVICE_LINES if self.configured[device.hostname] else "nv set system hostname nvos\n")
            payload += "\n".join(shlex.join(c) for c in app.initial_configuration_commands()
                                 if c[:2] == ["nv", "set"]) + "\n"
            return payload
        if "true" in text and "nv " not in text:
            return ""
        raise AssertionError(f"unexpected IB command {text}")

    def transport(self, command, responder, timeout, **_kwargs):
        app = self.app
        self.argvs.append(list(command))
        self.environments.append(dict(os.environ))
        text = " ".join(command)
        begin = re.search(r"__HTTP_IB_BEGIN_([a-f0-9]+)__", text)
        auth = re.search(r"__HTTP_IB_AUTH_([0-9a-f]{32})_(auth-probe-readonly|password-change|post-change-read)__=BEGIN",
                         text)
        if auth is not None:
            return self.phase_session(command, responder, text, *auth.groups())
        if begin is None and "ip vrf exec" in text:
            return self.strict_ipv4_probe(responder, text)
        if begin is None:
            # Outer SSH to one Ethernet jump: ssh ... cumulus@<ip> "sh -c '<script>'"
            address = re.search(r"@([0-9.]+)$", command[-2]).group(1)
            jump = next(host for host, ip in JUMPS if ip == address)
            answer = responder(f"cumulus@{address}'s password: ")
            if answer != self.jump_passwords.get(jump):
                self.rejected.append(jump)
                return app.SessionResult("Permission denied, please try again.\n", 255)
            script = shlex.split(command[-1])[2]
            remote = shlex.split(script.split("; exec ", 1)[1])
            return app.SessionResult(self.ethernet_output(jump, remote), 0)
        nonce = begin.group(1)
        prompt = ""
        outer = re.search(r"cumulus@([0-9.]+)", text)
        if outer is not None:
            jump = next(host for host, ip in JUMPS if ip == outer.group(1))
            prompt = f"cumulus@{outer.group(1)}'s password: "
            if responder(prompt) != self.jump_passwords.get(jump):
                self.rejected.append(jump)
                return app.SessionResult(prompt + "\nPermission denied, please try again.\n", 255)
        peer = re.search(r"admin@\[?([a-f0-9:.]+)", text).group(1)
        device = self.by_link_local.get(peer) or self.by_ip.get(peer)
        if device is None:
            raise AssertionError(f"unknown IB peer {peer}")
        prompt += f"\nadmin@{peer}'s password: "
        if responder(prompt) != self.ib_passwords.get(device.hostname, self.ib_password):
            self.rejected.append(device.hostname)
            return app.SessionResult(prompt + f"\nadmin@{peer}: Permission denied (password).\n", 255,
                                     ib_authentication_rejected=True)
        payload = self.ib_payload(device, text)
        return app.SessionResult(f"__HTTP_IB_BEGIN_{nonce}__\n{payload}__HTTP_IB_END_{nonce}__=0\n", 0)

    def phase_session(self, command, responder, text, nonce, operation):
        """A strict read: the DEV phase markers around the framed nv config show."""
        app = self.app
        session = _PhaseSession(app, responder)
        outer = re.search(r"cumulus@([0-9.]+)", text)
        jump = next(host for host, ip in JUMPS if ip == outer.group(1))
        if session.feed(f"cumulus@{outer.group(1)}'s password: ") != self.jump_passwords.get(jump):
            self.rejected.append(jump)
            session.feed("\nPermission denied, please try again.\n")
            return session.result(255)
        peer = re.search(r"admin@\[?([a-f0-9:.]+)", text).group(1)
        device = self.by_link_local[peer]
        end = f"__HTTP_IB_AUTH_{nonce}_{operation}__=EXIT:"
        session.feed(f"\n__HTTP_IB_AUTH_{nonce}_{operation}__=BEGIN\n")
        if session.feed(f"admin@{peer}'s password: ") != self.ib_passwords.get(device.hostname, self.ib_password):
            self.rejected.append(device.hostname)
            session.feed(f"\nadmin@{peer}: Permission denied (password).\n{end}255\n")
            return session.result(255)
        payload = self.ib_payload(device, "nv config show")
        session.feed(f"\n__HTTP_IB_BEGIN_{nonce}__\n{payload}__HTTP_IB_END_{nonce}__=0\n{end}0\n")
        return session.result(0)

    def strict_ipv4_probe(self, responder, text):
        """The strict IPv4 readiness probe (no command frame): answer both prompts, exit 0."""
        app = self.app
        outer = re.search(r"cumulus@([0-9.]+)", text)
        jump = next(host for host, ip in JUMPS if ip == outer.group(1))
        prompt = f"cumulus@{outer.group(1)}'s password: "
        if responder(prompt) != self.jump_passwords.get(jump):
            self.rejected.append(jump)
            return app.SessionResult(prompt + "\nPermission denied, please try again.\n", 255)
        peer = re.search(r"admin@([0-9.]+)", text).group(1)
        device = self.by_ip[peer]
        prompt += f"\nadmin@{peer}'s password: "
        if responder(prompt) != self.ib_passwords.get(device.hostname, self.ib_password):
            self.rejected.append(device.hostname)
            return app.SessionResult(prompt + f"\nadmin@{peer}: Permission denied (password).\n", 255,
                                     ib_authentication_rejected=True)
        return app.SessionResult(prompt + "\n", 0)

    def outputs(self) -> str:
        texts = [path.read_text(encoding="utf-8", errors="replace")
                 for path in self.root.rglob("*") if path.is_file() and path.suffix in (".log", ".json")]
        return "\n".join(texts)

    def summary(self) -> dict:
        found = sorted(self.root.rglob("summary.json"))
        self.test.assertEqual(1, len(found), "one structured summary per run")
        return json.loads(found[0].read_text(encoding="utf-8"))


class InitialSetupCredentialsFdWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = load_script("credentials_fd_workflow_initial", INITIAL)

    def world(self, root: Path, **kwargs) -> _World:
        return _World(self, self.app, root, **kwargs)

    def run_main(self, world: _World, argv: list[str], payload=None, *, environment=None,
                 forbid_prompts=True):
        """Run the real entry (SetupError -> 2) with the fake transport; returns (code, stderr)."""
        app = self.app
        fds = []
        if payload is not None:
            reader, writer = os.pipe()
            os.write(writer, json.dumps(payload).encode("utf-8"))
            os.close(writer)
            fds.append(reader)
            argv = argv + ["--credentials-fd", str(reader)]
        prompts = mock.Mock(side_effect=AssertionError("fd mode must not prompt"))
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.dict(os.environ, environment or {}, clear=False))
            stack.enter_context(mock.patch.object(app, "interactive_run", world.transport))
            stack.enter_context(mock.patch.object(app, "probe_ethernet_key", return_value="password"))
            stack.enter_context(mock.patch.object(app.subprocess, "run",
                                                  side_effect=AssertionError("external commands forbidden")))
            stack.enter_context(mock.patch.object(app.time, "sleep", return_value=None))
            stack.enter_context(mock.patch.object(Path, "home", return_value=world.root / "home"))
            stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
            if forbid_prompts:
                stack.enter_context(mock.patch.object(getpass, "getpass", prompts))
                stack.enter_context(mock.patch.object(builtins, "input", prompts))
                stack.enter_context(mock.patch.object(app, "_hidden_password_timeout", prompts))
            err = stack.enter_context(redirect_stderr(io.StringIO()))
            stack.enter_context(redirect_stdout(io.StringIO()))
            try:
                code = app._standalone_main_with_report_cleanup()
            except SystemExit as exc:
                code = exc.code
            finally:
                for fd in fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
        if forbid_prompts:
            self.assertEqual(0, prompts.call_count, "fd mode must not prompt")
        return code, err.getvalue()

    def credentials(self, *, jump=None, initial=None, target=None, missing=()):
        payload = {}
        if jump is not None:
            payload["jump_passwords"] = jump
        if initial is not None:
            payload["nvos_initial_password"] = initial
        if target is not None:
            payload["ib_target_password"] = target
        for key in missing:
            payload.pop(key, None)
        return payload

    def test_fd_mode_never_prompts(self) -> None:
        # R-012 design :345: in fd mode the script asks nothing.  A read-only check and an
        # --apply --yes run both finish with getpass, input and the 5-second prompt refused.
        jumps = {host: secret("jump-" + host[-2:]) for host, _ in JUMPS}
        initial, target = secret("initial"), secret("target")
        with tempfile.TemporaryDirectory(prefix="fd-check-") as folder:
            world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=True)
            code, err = self.run_main(world, world.argv(), self.credentials(jump=jumps, initial=initial))
            self.assertEqual(0, code, err)
            self.assertEqual([], world.rejected)
            self.assertEqual([], world.writes)
        with tempfile.TemporaryDirectory(prefix="fd-apply-") as folder:
            world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=False)
            code, err = self.run_main(world, world.argv("--apply", "--yes"),
                                      self.credentials(jump=jumps, initial=initial, target=target))
            self.assertEqual(0, code, err)
            self.assertEqual([], world.rejected)
            self.assertTrue(any("nv config apply -y" in text for text in world.writes))
            self.assertTrue(all(world.configured.values()))
        # With a project global the IB target comes from the fd, verified against the global
        # (guide WP-5: ProjectPasswordPolicy(target_password=..., interactive=False)).
        global_hash = "$" + "6$PUBLICsalt$" + "A" * 86
        global_text = ("schema_version: 2\ncommon:\n  switch:\n    system:\n      hostname: PUBLIC-COMMON\n"
                       "switches:\n- ib:\n    system:\n      aaa:\n        user:\n          admin:\n"
                       "            password: {}\n").format(json.dumps(global_hash))
        constructed = []
        real_init = self.app.ProjectPasswordPolicy.__init__

        def recording_init(policy, *args, **kwargs):
            constructed.append(dict(kwargs))
            return real_init(policy, *args, **kwargs)

        with tempfile.TemporaryDirectory(prefix="fd-global-") as folder, ExitStack() as stack:
            world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=True,
                               global_text=global_text)
            stack.enter_context(mock.patch.object(self.app.ProjectPasswordPolicy, "__init__", recording_init))
            stack.enter_context(mock.patch.object(self.app.ProjectPasswordPolicy, "matches",
                                                  side_effect=lambda value: value == target))
            code, err = self.run_main(world, world.argv(),
                                      self.credentials(jump=jumps, initial=initial, target=target))
            # Both devices already hold every CSV, service and Initial value and the read-only run
            # has no blocker: SUCCESS, exit 0 (v15 CURRENT-CONTRACT.md:67, main :5875; O10 only
            # makes a rejected device INCOMPLETE, and none is rejected here).
            self.assertEqual(0, code, err)
            self.assertTrue(constructed, "the run must build the project policy from the fd target")
            for kwargs in constructed:
                self.assertEqual(target, kwargs.get("target_password"))
                self.assertIs(False, kwargs.get("interactive"))

    def test_no_secret_in_argv_env_report_or_summary(self) -> None:
        # R-012 design :346 and :619: passwords never appear in argv, the environment, the report,
        # summary.json or the device logs.
        jumps = {host: secret("jump-" + host[-2:]) for host, _ in JUMPS}
        initial, target = secret("initial"), secret("target")
        values = (*jumps.values(), initial, target)
        with tempfile.TemporaryDirectory(prefix="fd-secret-") as folder:
            world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=False)
            code, err = self.run_main(world, world.argv("--apply", "--yes"),
                                      self.credentials(jump=jumps, initial=initial, target=target))
            self.assertEqual(0, code, err)
            self.assertTrue(world.argvs, "the transport must have been used")
            written = world.outputs()
            self.assertIn("summary.json", " ".join(str(p) for p in world.root.rglob("summary.json")))
            for value in values:
                for argv in world.argvs:
                    self.assertNotIn(value, " ".join(argv))
                for environment in world.environments:
                    self.assertNotIn(value, " ".join(f"{k}={v}" for k, v in environment.items()))
                self.assertNotIn(value, written)
                self.assertNotIn(value, err)

    def test_fd_mode_ignores_password_environment(self) -> None:
        # R-012 design :346 ("不经 argv、环境变量或文件"): a wrong initial password in the
        # environment is not used; the fd value is.
        jumps = {host: secret("jump-" + host[-2:]) for host, _ in JUMPS}
        initial = secret("initial")
        wrong = secret("environment")
        environment = {"NVOS_INITIAL_PASSWORD": wrong, "NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD": wrong}
        with tempfile.TemporaryDirectory(prefix="fd-environment-") as folder:
            world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=True)
            code, err = self.run_main(world, world.argv(), self.credentials(jump=jumps, initial=initial),
                                      environment=environment)
            self.assertEqual(0, code, err)
            self.assertEqual([], world.rejected, "the IB session must use the fd initial password")

    def test_missing_target_key_exits_2_before_any_device_contact(self) -> None:
        # R-012 design :344: a missing required key exits 2 at the entry.  With --apply and IB
        # targets in the CSV the target password is required; a read-only check does not need it.
        jumps = {host: secret("jump-" + host[-2:]) for host, _ in JUMPS}
        initial = secret("initial")
        with tempfile.TemporaryDirectory(prefix="fd-missing-") as folder:
            world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=True)
            # 06 WP6-10: run_main patches probe_ethernet_key again, so that guard never fires; as in
            # the two fd entry tests below (guide :649), the OOB key probe is guarded at its only
            # caller, prompt_ethernet_passwords.
            probe_gate = mock.Mock(side_effect=AssertionError("no OOB key probe before the entry check"))
            with mock.patch.object(self.app, "probe_ethernet_key",
                                   side_effect=AssertionError("no device contact before the entry check")), \
                    mock.patch.object(self.app, "prompt_ethernet_passwords", probe_gate):
                code, err = self.run_main(world, world.argv("--apply", "--yes"),
                                          self.credentials(jump=jumps, initial=initial))
            self.assertEqual(0, probe_gate.call_count, "the missing-key refusal precedes the OOB key probe")
            self.assertEqual(2, code)
            self.assertIn("ib_target_password", err)
            self.assertEqual([], world.argvs, "no SSH before the entry refusal")
        with tempfile.TemporaryDirectory(prefix="fd-missing-check-") as folder:
            world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=True)
            code, err = self.run_main(world, world.argv(), self.credentials(jump=jumps, initial=initial))
            self.assertEqual(0, code, err)
            self.assertTrue(world.argvs, "the read-only check runs normally")

    def test_rejected_jump_password_fails_only_its_devices(self) -> None:
        # R-012 design :345 (fd mode never asks again; rejection exits 2); O10: the rejected jump's
        # devices fail, the other jump's devices proceed; v15 print_initial_setup_summary and
        # main: a failed device makes the run INCOMPLETE, exit 2.
        jumps = {host: secret("jump-" + host[-2:]) for host, _ in JUMPS}
        initial = secret("initial")
        wrong = dict(jumps)
        wrong["EXAMPLE-JUMP01"] = secret("wrong")
        # Added after the first RED (mutation W6, see the D1b report): a jump that is absent from
        # the fd table fails its devices like a rejected one, again without a prompt (R-012 design
        # :345).  D1a2 correction (D1b-14 subcase): it is never logged in to, so it receives no
        # password answer at all (R-012 design §7.3 :302, §8.3 :345; guide :648; O10).
        absent = {host: value for host, value in jumps.items() if host != "EXAMPLE-JUMP01"}
        for label, supplied in (("rejected", wrong), ("absent", absent)):
            with self.subTest(jump01=label), tempfile.TemporaryDirectory(prefix="fd-rejected-") as folder:
                world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=True)
                code, err = self.run_main(world, world.argv(), self.credentials(jump=supplied, initial=initial))
                self.assertEqual(2, code, err)
                if label == "rejected":
                    self.assertIn("EXAMPLE-JUMP01", world.rejected)
                else:
                    self.assertFalse([argv for argv in world.argvs if "cumulus@198.51.100.10" in " ".join(argv)],
                                     "an fd table without this jump means no login and no password answer")
                    self.assertNotIn("EXAMPLE-JUMP01", world.rejected)
                self.assertNotIn("EXAMPLE-JUMP02", world.rejected)
                records = world.summary()["records"]
                outcome = {name.casefold(): record.get("outcome") for name, record in records.items()}
                self.assertNotIn(outcome.get("example-ib01.example.test"), ("ALREADY_CONFIGURED", "CONFIGURED"))
                self.assertIn(outcome.get("example-ib02.example.test"), ("ALREADY_CONFIGURED", "CONFIGURED"))
                self.assertEqual("INCOMPLETE", world.summary()["result"])

    def test_ethernet_password_argv_is_refused_before_any_device_contact(self) -> None:
        # R-012 design :346 (no password in argv); v15 main :5375-5376 kept (table 6-1 row 4).
        value = secret("argv")
        with tempfile.TemporaryDirectory(prefix="fd-argv-") as folder:
            world = self.world(Path(folder), jump_passwords={}, ib_password=secret("initial"), configured=True)
            # 06 WP6-10: run_main patches probe_ethernet_key again, so that guard never fires; the
            # OOB key probe is guarded at its only caller, prompt_ethernet_passwords (guide :649).
            probe_gate = mock.Mock(side_effect=AssertionError("no OOB key probe before the entry check"))
            with mock.patch.object(self.app, "probe_ethernet_key",
                                   side_effect=AssertionError("no device contact before the argv refusal")), \
                    mock.patch.object(self.app, "prompt_ethernet_passwords", probe_gate):
                code, err = self.run_main(world, world.argv("--ethernet-password", value))
            self.assertEqual(0, probe_gate.call_count, "the argv refusal precedes the OOB key probe")
            self.assertEqual(2, code)
            self.assertIn("Do not put passwords in argv", err)
            self.assertNotIn(value, err)
            self.assertNotIn(value, world.outputs())
            self.assertEqual([], world.argvs)

    def test_fd_apply_without_yes_exits_2_before_any_device_contact(self) -> None:
        # R-012 design §8.3 :345 ("fd 模式下不再提问"); guide :648 (fd mode calls no getpass, input
        # or _hidden_password_timeout) and :649 (what the entry can decide exits 2).  The first-change
        # confirmation is an input() question, so fd mode with --apply needs --yes.
        jumps = {host: secret("jump-" + host[-2:]) for host, _ in JUMPS}
        initial, target = secret("initial"), secret("target")
        with tempfile.TemporaryDirectory(prefix="fd-no-yes-") as folder:
            world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=False)
            # Guide :649 (the entry decides before any device contact): run_main itself replaces
            # probe_ethernet_key, so the OOB key probe is guarded at its only caller.
            probe_gate = mock.Mock(side_effect=AssertionError("no OOB key probe before the entry check"))
            with mock.patch.object(self.app, "prompt_ethernet_passwords", probe_gate):
                code, err = self.run_main(world, world.argv("--apply"),
                                          self.credentials(jump=jumps, initial=initial, target=target))
            self.assertEqual(0, probe_gate.call_count, "the --yes refusal precedes the OOB key probe")
            self.assertEqual(2, code, err)
            self.assertIn("--yes", err)
            self.assertEqual([], world.argvs, "no SSH before the entry refusal")
            self.assertEqual([], world.writes)

    def test_fd_malformed_target_password_exits_2_before_any_device_contact(self) -> None:
        # R-012 design §8.3 :344 ("缺少必需的键就在入口以 2 退出（严出）"); guide :570 (the password
        # shape is expressed again by the fd tests) and :649.  Checked at the entry, with or without
        # a project global, before any device contact including the OOB key probe.
        jumps = {host: secret("jump-" + host[-2:]) for host, _ in JUMPS}
        initial = secret("initial")
        cases = (("short", "-".join(("Zq", "7")), ""), ("control", secret("ctl") + "\x01", ""),
                 ("short-with-global", "-".join(("Zq", "7")), project_global()))
        for label, value, global_text in cases:
            with self.subTest(shape=label), tempfile.TemporaryDirectory(prefix="fd-shape-") as folder:
                world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=True,
                                   global_text=global_text)
                # run_main itself replaces probe_ethernet_key: guard the probe at its only caller.
                probe_gate = mock.Mock(side_effect=AssertionError("no OOB key probe before the entry check"))
                with mock.patch.object(self.app, "prompt_ethernet_passwords", probe_gate):
                    code, err = self.run_main(world, world.argv("--apply", "--yes"),
                                              self.credentials(jump=jumps, initial=initial, target=value))
                self.assertEqual(0, probe_gate.call_count, "the shape refusal precedes the OOB key probe")
                self.assertEqual(2, code, err)
                self.assertIn("IB target password", err)
                self.assertNotIn(value, err)
                self.assertEqual([], world.argvs, "no SSH before the entry refusal")

    def test_fd_rejected_initial_and_target_fail_only_that_device_without_a_prompt(self) -> None:
        # R-012 design §8.3 :345 ("fd 模式下不再提问：被拒就以 2 退出"); guide :648 and section 10 T18
        # (r224 :2304 "fd 模式下不能问，按 O10 这台失败"); O10: the rejected device fails, the other
        # proceeds, the run is INCOMPLETE (exit 2).  With a project global the management run takes
        # the strict path, so this exercises the one credential implementation (D1a2 item 2).
        jumps = {host: secret("jump-" + host[-2:]) for host, _ in JUMPS}
        initial, target, actual = secret("initial"), secret("target"), secret("actual")
        passwords = {"example-ib01.example.test": actual, "example-ib02.example.test": target}
        with tempfile.TemporaryDirectory(prefix="fd-t18-") as folder, ExitStack() as stack:
            world = self.world(Path(folder), jump_passwords=jumps, ib_password=initial, configured=True,
                               global_text=project_global(), ib_passwords=passwords)
            stack.enter_context(mock.patch.object(self.app.ProjectPasswordPolicy, "matches",
                                                  side_effect=lambda value: value == target))
            code, err = self.run_main(world, world.argv("--apply", "--yes"),
                                      self.credentials(jump=jumps, initial=initial, target=target))
            self.assertEqual(2, code, err)
            self.assertEqual(2, world.rejected.count("example-ib01.example.test"),
                             "the initial and the project target were each tried once")
            records = world.summary()["records"]
            outcome = {name.casefold(): record.get("outcome") for name, record in records.items()}
            self.assertEqual("FAILED", outcome.get("example-ib01.example.test"))
            self.assertIn(outcome.get("example-ib02.example.test"), ("ALREADY_CONFIGURED", "CONFIGURED"))
            self.assertEqual("INCOMPLETE", world.summary()["result"])
            self.assertNotIn(actual, world.outputs())

    def test_leaf_directory_without_the_fd_module_exits_2_naming_the_file(self) -> None:
        # Guide :664 (O5: a tools problem in _import_tools ends as SetupError, exit 2, not a traceback).
        with tempfile.TemporaryDirectory(prefix="fd-leaf-") as folder, ExitStack() as stack:
            leaf = Path(folder).resolve()
            script = leaf / "initial-setup.py"
            script.write_bytes(INITIAL.read_bytes())
            (leaf / "tools").mkdir()
            app = load_script("credentials_fd_leaf_layout_" + str(os.getpid()), script)
            reader, writer = os.pipe()
            os.write(writer, b"{}")
            os.close(writer)
            stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
            stack.enter_context(mock.patch.object(sys, "argv", [str(script), "--credentials-fd", str(reader)]))
            stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
            err = stack.enter_context(redirect_stderr(io.StringIO()))
            stack.enter_context(redirect_stdout(io.StringIO()))
            try:
                code = app._standalone_main_with_report_cleanup()
            except ModuleNotFoundError as exc:
                code = type(exc).__name__
            finally:
                try:
                    os.close(reader)
                except OSError:
                    pass
            self.assertEqual(2, code)
            self.assertIn(str(leaf / "tools" / "credentials_fd.py"), err.getvalue())


if __name__ == "__main__":
    unittest.main()
