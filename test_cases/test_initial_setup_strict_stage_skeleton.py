"""Direct: the strict branch (management-server task with the project global) runs the v15 stages.

The owner chose (a) for 04 Q-035 (2026-11-10 17:47:44, "Q-035:a"): the strict branch takes v15's
stage skeleton and judgments; only each IB read and write goes through the DEV phase session or
the authorized helper (P3c map D32d :284; map 4.5 P1 :356).  Every expectation below names that
decision, the map line, or a sentence of the v15 design documents
(参考/initial-setup-v15/CURRENT-CONTRACT.md); a "v15 :N" mention only locates the code.

Real CSV/P2P/global/target cache, real main(), real snapshots and routing, real per-device stages,
real DEV phase protocol objects and authorized helper, real report and summary.json.  Only the
SSH/PTY transport (initial-setup's interactive_run), the OOB public-key probe, the password hash
backend and the clock are replaced.  The fake device answers through the real responders: a phase
session feeds its output to the real _IBPhase observer and lets the real responder write its reply
into a pipe, as interactive_run does.  Every password is assembled at run time.
"""

from __future__ import annotations

import ast
import base64
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
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
AUTH_RE = re.compile(r"__HTTP_IB_AUTH_([0-9a-f]{32})_(auth-probe-readonly|password-change|post-change-read)__=BEGIN")
FRAME_RE = re.compile(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__")
EXPIRY = "\nYou are required to change your password immediately (administrator enforced)\n"
SERVICES = ("nv set system dns server 192.0.2.53", "nv set system ntp server 192.0.2.123",
            "nv set system date-time timezone Etc/UTC")
INITIAL_SET = ("nv set system config auto-save state enabled", "nv set system ztp config-save enabled")
INITIAL_ALL = (*INITIAL_SET, "nv config apply -y", "nv config save")
WRITE_PREFIXES = ("nv set ", "nv unset ", "nv config apply", "nv config save")


def secret(label: str) -> str:
    return "-".join(("PUBLIC", "strict", label, str(os.getpid()), "Zq7"))


def host(index: int) -> str:
    return f"example-ib{index:02d}.example.test"


def network_lines(index: int, *, ports: bool = True, hostname: str = "") -> list:
    lines = [f"nv set interface eth0 ipv4 address 192.0.2.{11 + index}/24",
             "nv set interface eth0-1 ipv4 gateway 192.0.2.1"]
    if ports:
        lines += ["nv set interface eth0-1 link state up", "nv set interface eth0-1 type eth"]
    return lines + [f"nv set system hostname {hostname or host(index)}"]


def complete_lines(index: int) -> list:
    return [*network_lines(index), *SERVICES, *INITIAL_SET]


def unconfigured_lines() -> list:
    return ["nv set system hostname nvos", *INITIAL_SET]


def public_key_line(seed: int, comment: str) -> str:
    """A deterministic, well-formed OpenSSH ed25519 public line (no private key exists)."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " " + comment + "\n"


class _Device:
    """One fake NVOS switch: applied commands, ZTP state, password and expiry."""

    def __init__(self, index: int, *, password: str, lines, ztp: str = "disabled", expired=False,
                 ztp_sticky=False, post_change_lines=None, ipv4_codes=(), drop_services=False,
                 after_initial_lines=None) -> None:
        self.index = index
        self.hostname = host(index)
        self.address = f"192.0.2.{11 + index}"
        self.mac = "02:00:00:00:01:%02x" % (16 + index)
        self.jump, self.jump_ip = f"EXAMPLE-JUMP{index:02d}", f"198.51.100.{10 + index}"
        self.password, self.expired, self.ztp, self.ztp_sticky = password, expired, ztp, ztp_sticky
        self.lines = list(lines)
        self.post_change_lines = post_change_lines
        self.ipv4_codes = list(ipv4_codes)
        self.drop_services = drop_services
        self.after_initial_lines = after_initial_lines
        self.on_pending = None  # optional hook run when the pending diff is read

    def readback(self) -> str:
        return "".join(line + "\n" for line in self.lines)

    def ztp_text(self) -> str:
        return {"disabled": "service disabled\n", "enabled": "service enabled\n", "unknown": ""}[self.ztp]

    def apply_set(self, command: str) -> None:
        if self.drop_services and command.startswith(("nv set system dns", "nv set system ntp",
                                                      "nv set system date-time")):
            return
        tokens = command.split()
        single = (tokens[2:4] in (["system", "hostname"], ["system", "config"], ["system", "ztp"],
                                  ["system", "date-time"])
                  or (tokens[2] == "interface" and tokens[4:6] in (["ipv4", "gateway"], ["link", "state"])
                      or tokens[2] == "interface" and tokens[4:5] == ["type"]))
        if single:
            self.lines = [line for line in self.lines if line.split()[:-1] != tokens[:-1]]
        if command not in self.lines:
            self.lines.append(command)

    def save(self) -> None:
        if "nv set system ztp config-save enabled" in self.lines and not self.ztp_sticky:
            self.ztp = "disabled"
        if self.after_initial_lines is not None:
            self.lines, self.after_initial_lines = list(self.after_initial_lines), None


class _Session:
    """Feed device output to the real responder exactly as interactive_run does."""

    def __init__(self, app, responder) -> None:
        self.app, self.responder = app, responder
        self.phase = getattr(responder, "_phase", None)
        self.output = ""
        self.reader, self.writer = os.pipe()

    def feed(self, text: str):
        self.output += text
        if self.phase is not None:
            self.phase.observe(self.output)
        reply = self.responder(self.app.strip_ansi(self.output))
        if getattr(self.responder, "password_change_blocked", False):
            if self.phase is not None:
                self.phase.cancel_requested = True
            return "\x03"
        if reply is not None and self.phase is not None:
            self.phase.write_reply(self.writer, reply, self.responder, time.monotonic() + 60)
            os.read(self.reader, 65536)
        return reply

    def result(self, code: int):
        app = self.app
        os.close(self.reader)
        os.close(self.writer)
        clean = app.strip_ansi(self.output)
        attempted = bool(getattr(self.responder, "password_change_attempted", False))
        endpoint = getattr(self.responder, "ib_destination", None)
        rejected = bool(endpoint and not app._NETWORK_FAILURE.search(clean) and re.search(
            re.escape(endpoint) + r":[^\n]*Permission denied", clean, re.I))
        return app.SessionResult(clean, code, attempted and bool(app._PASSWORD_UPDATED.search(clean)),
                                 bool(getattr(self.responder, "password_change_blocked", False)),
                                 attempted, rejected)


class _World:
    """One project directory, its strict inputs and the fake device side for one run."""

    def __init__(self, test, app, root: Path, devices, *, jump_passwords=None, global_file=True) -> None:
        self.test, self.app, self.root = test, app, root
        self.devices = {device.hostname: device for device in devices}
        self.jump_passwords = ({device.jump: secret("jump-%02d" % device.index) for device in devices}
                               if jump_passwords is None else jump_passwords)
        self.calls_path = root / "calls.tsv"
        self.calls_path.write_text("", encoding="utf-8")
        with (root / "ib.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["hostname", "type", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"])
            for device in devices:
                writer.writerow([device.hostname, "ib", device.address, "24", "192.0.2.1", device.mac])
            for device in devices:
                writer.writerow([device.jump, "eth_jump", device.jump_ip, "", "", ""])
        (root / "p2p.dot").write_text("".join(
            f'"{device.hostname}":"eth0" -- "{device.jump}":"swp1"\n' for device in devices), encoding="utf-8")
        (root / "infra-neutral.conf").write_text(
            "DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=Etc/UTC\n", encoding="utf-8")
        if global_file:
            # Assembled so no credential literal appears in the source (public audit).
            global_hash = "$" + "6$PUBLICsalt$" + "A" * 86
            (root / "01-global.yaml").write_text((
                "schema_version: 2\ncommon:\n  switch:\n    system:\n      hostname: PUBLIC-COMMON\n"
                "switches:\n- ib:\n    system:\n      aaa:\n        user:\n          admin:\n"
                "            password: {}\n").format(json.dumps(global_hash)), encoding="utf-8")
        self.by_peer = {}
        for device in devices:
            self.by_peer[app.mac_to_link_local(device.mac)] = device
            self.by_peer[device.address] = device
        self.by_jump_ip = {device.jump_ip: device for device in devices}

    def argv(self, *extra: str) -> list:
        root = self.root
        return [str(INITIAL), "--project-dir", str(root), "--ib-csv", str(root / "ib.csv"),
                "--p2p", str(root / "p2p.dot"), "--target-cache", str(root / "targets.json"),
                "--report", str(root / "report.log"), "--snapshot-dir", str(root / "snapshots"),
                "--execution-mode", "management", *extra]

    def note(self, device, kind: str, detail: str) -> None:
        # Appended per call so forked workers record too.
        with self.calls_path.open("a", encoding="utf-8") as stream:
            stream.write(f"{device.hostname}\t{kind}\t{detail}\n")

    def calls(self, hostname=None) -> list:
        rows = [tuple(line.split("\t", 2)) for line in
                self.calls_path.read_text(encoding="utf-8").splitlines() if line]
        return [(kind, detail) for name, kind, detail in rows if hostname is None or name == hostname]

    def writes(self, hostname) -> list:
        return [detail for kind, detail in self.calls(hostname)
                if kind == "run" and detail.startswith(WRITE_PREFIXES)]

    # -- Ethernet side -------------------------------------------------------------------------
    def ethernet_output(self, device, command) -> str:
        if command == ["hostname"]:
            return device.jump + "\n"
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
            return f"{device.mac} dev swp1 vlan 1000 master br_default\n"
        if command == ["ip", "neighbor"]:
            return f"{self.app.mac_to_link_local(device.mac)} dev vlan1000 lladdr {device.mac} REACHABLE\n"
        if command == ["ip", "-j", "address", "show"]:
            return json.dumps([{"ifname": "vlan1000", "flags": ["BROADCAST", "MULTICAST", "UP"],
                                "operstate": "UP", "addr_info": [
                                    {"family": "inet", "local": "192.0.2.1", "prefixlen": 24, "scope": "global"},
                                    {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]}])
        if command == ["ifquery", "vlan1000"]:
            return "iface vlan1000\n    vrf oob\n"
        raise AssertionError(f"unexpected Ethernet command {command}")

    # -- transport -------------------------------------------------------------------------------
    def transport(self, command, responder, timeout, **_kwargs):
        app = self.app
        app.check_task_cancelled()  # the real interactive_run starts with this check
        text = " ".join(command)
        auth, frame = AUTH_RE.search(text), FRAME_RE.search(text)
        outer = re.search(r"cumulus@([0-9.]+)", text)
        if outer is not None and auth is None and frame is None and "ip vrf exec" not in text:
            device = self.by_jump_ip[outer.group(1)]
            expected = self.jump_passwords.get(device.jump, "")
            if expected and responder(f"cumulus@{outer.group(1)}'s password: ") != expected:
                return app.SessionResult("Permission denied, please try again.\n", 255)
            script = shlex.split(command[-1])[2]
            remote = shlex.split(script.split("; exec ", 1)[1])
            return app.SessionResult(self.ethernet_output(device, remote), 0)
        session = _Session(app, responder)
        if outer is not None:
            jump_device = self.by_jump_ip[outer.group(1)]
            expected = self.jump_passwords.get(jump_device.jump, "")
            if expected and session.feed(f"cumulus@{outer.group(1)}'s password: ") != expected:
                session.feed("\nPermission denied, please try again.\n")
                return session.result(255)
        peer = re.search(r"admin@\[?([0-9a-f:.]+)", text).group(1)
        device = self.by_peer[peer]
        if auth is not None:
            return self.phase_session(session, device, peer, *auth.groups())
        session_kind = "direct" if command[0] == "ssh" and "-4" in command else "run"
        if frame is None:  # the strict IPv4 readiness probe (DEV argv, no command frame)
            reply = session.feed(f"\nadmin@{peer}'s password: ")
            self.note(device, "ipv4", "strict")
            if reply != device.password:
                session.feed(f"\nadmin@{peer}: Permission denied (password).\n")
                return session.result(255)
            code = device.ipv4_codes.pop(0) if device.ipv4_codes else 0
            if code:
                session.feed("\nPUBLIC interface not ready yet\n")
            return session.result(code)
        marker = frame.group(1)
        inner = re.search(r"__HTTP_IB_BEGIN_" + marker + r'__\\n"; (.*?); task_rc=', text)
        reply = session.feed(f"\nadmin@{peer}'s password: ")
        if reply != device.password:
            self.note(device, session_kind + "-rejected", "")
            session.feed(f"\nadmin@{peer}: Permission denied (password).\n")
            return session.result(255)
        if "IBSW_PUBLIC_KEYS" in text:
            self.note(device, "run", "public-key install")
            payload = "IBSW_PUBLIC_KEYS_UPDATED\n"
        else:
            inner_command = inner.group(1)
            if inner_command == "true":
                self.note(device, "ipv4", "v15")
                code = device.ipv4_codes.pop(0) if device.ipv4_codes else 0
                if code:
                    session.feed("\nPUBLIC interface not ready yet\n")
                    return session.result(code)
                payload = ""
            else:
                self.note(device, session_kind, inner_command)
                if inner_command == "nv show system ztp":
                    payload = device.ztp_text()
                elif inner_command == "nv config diff -o commands":
                    if device.on_pending is not None:
                        device.on_pending()
                    payload = ""
                elif inner_command == "nv config show -o commands":
                    payload = device.readback()
                elif inner_command.startswith("nv set "):
                    device.apply_set(inner_command)
                    payload = ""
                elif inner_command == "nv config apply -y":
                    payload = ""
                elif inner_command == "nv config save":
                    device.save()
                    payload = ""
                else:
                    raise AssertionError(f"unexpected IB command {inner_command}")
        session.feed(f"\n__HTTP_IB_BEGIN_{marker}__\n{payload}__HTTP_IB_END_{marker}__=0\n")
        return session.result(0)

    def phase_session(self, session, device, peer, nonce, operation):
        end = f"__HTTP_IB_AUTH_{nonce}_{operation}__=EXIT:"
        session.feed(f"\n__HTTP_IB_AUTH_{nonce}_{operation}__=BEGIN\n")
        reply = session.feed(f"admin@{peer}'s password: ")
        if reply != device.password:
            self.note(device, "phase:" + operation, "rejected")
            session.feed(f"\nadmin@{peer}: Permission denied (password).\n{end}255\n")
            return session.result(255)
        self.note(device, "phase:" + operation, "accepted")
        if operation == "password-change":
            session.feed(EXPIRY)
            current = session.feed("(current) UNIX password: ")
            new = session.feed("\nNew password: ")
            again = session.feed("\nRetype new password: ")
            if current != device.password or not new or new != again:
                raise AssertionError("unexpected PAM answers")
            device.password, device.expired = new, False
            if device.post_change_lines is not None:
                device.lines = list(device.post_change_lines)
            session.feed(f"\npasswd: password updated successfully\n{end}0\n")
            return session.result(0)
        if device.expired:
            session.feed(EXPIRY)
            session.feed("(current) UNIX password: ")
            return session.result(255)
        session.feed(f"\n__HTTP_IB_BEGIN_{nonce}__\n{device.readback()}__HTTP_IB_END_{nonce}__=0\n{end}0\n")
        return session.result(0)

    def summary(self) -> dict:
        found = sorted(self.root.rglob("summary.json"))
        self.test.assertEqual(1, len(found), "one structured summary per run")
        return json.loads(found[0].read_text(encoding="utf-8"))

    def record(self, index: int) -> dict:
        return self.summary()["records"][host(index).casefold()]

    def report(self) -> str:
        return (self.root / "report.log").read_text(encoding="utf-8", errors="replace")


class InitialSetupStrictStageSkeletonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = load_script("strict_stage_skeleton_initial", INITIAL)

    def world(self, root: Path, devices, **kwargs) -> _World:
        return _World(self, self.app, root, devices, **kwargs)

    def run_main(self, world, argv, payload=None, *, target=None, extra=()):
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
            stack.enter_context(mock.patch.object(app, "interactive_run", world.transport))
            stack.enter_context(mock.patch.object(app, "probe_ethernet_key", return_value="password"))
            stack.enter_context(mock.patch.object(app.subprocess, "run",
                                                  side_effect=AssertionError("external commands forbidden")))
            stack.enter_context(mock.patch.object(Path, "home", return_value=world.root / "home"))
            stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
            # Only the native hash backend is replaced: the project target is the fd value.
            stack.enter_context(mock.patch.object(app.ProjectPasswordPolicy, "matches",
                                                  side_effect=lambda value: value == target))
            for item in extra:
                stack.enter_context(item)
            if not any(getattr(item, "attribute", None) == "sleep" for item in extra):
                stack.enter_context(mock.patch.object(app.time, "sleep", return_value=None))
            if payload is not None:
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
        self.assertEqual(0, prompts.call_count, "fd mode must not prompt")
        return code, err.getvalue()

    def credentials(self, world, *, initial, target=None) -> dict:
        payload = {"jump_passwords": dict(world.jump_passwords), "nvos_initial_password": initial}
        if target is not None:
            payload["ib_target_password"] = target
        return payload

    def apply(self, folder, devices, *, initial, target, extra=(), args=("--apply", "--yes"), **kwargs):
        world = self.world(Path(folder), devices, **kwargs)
        code, err = self.run_main(world, world.argv(*args), self.credentials(world, initial=initial, target=target),
                                  target=target, extra=extra)
        return world, code, err

    def assertBefore(self, calls, first, second, message):
        self.assertIn(first, calls, message)
        self.assertIn(second, calls, message)
        self.assertLess(calls.index(first), calls.index(second), message)

    # -- b-2 ---------------------------------------------------------------------------------------
    def test_strict_initial_reads_ztp_before_and_after_initial_writes(self) -> None:
        # Owner Q-035 (a) item 1 (04 Q-035: "读 `nv show system ztp`，ZTP 没关就拒"); P3c map T17 :344
        # ("每台都走 run_initial_stage；`nv show system ztp` 的输出读不出状态就拒"): the strict Initial
        # stage reads the operational ZTP state first and verifies it disabled after save (locates
        # v15 :2792-2794, :2828-2830).  The v15 CURRENT-CONTRACT.md and RUNBOOK.md have no ZTP
        # sentence (grep, measured), so the map row is the design source.
        target = secret("target")
        with self.subTest(case="enabled-then-disabled"), \
                tempfile.TemporaryDirectory(prefix="strict-ztp-") as folder:
            devices = [_Device(1, password=target, lines=complete_lines(1), ztp="enabled"),
                       _Device(2, password=target, lines=complete_lines(2))]
            world, code, err = self.apply(folder, devices, initial=target, target=target)
            calls = world.calls(host(1))
            self.assertIn(("run", "nv show system ztp"), calls, "ZTP state is read before Initial")
            first_ztp = calls.index(("run", "nv show system ztp"))
            initial_writes = [index for index, call in enumerate(calls)
                              if call[0] == "run" and call[1] in INITIAL_ALL]
            self.assertTrue(initial_writes and first_ztp < initial_writes[0],
                            "the ZTP read precedes every Initial write")
            # v15 initial_configuration_commands: all four commands, in order.
            self.assertEqual(list(INITIAL_ALL), [calls[index][1] for index in initial_writes[:4]])
            later = [index for index, call in enumerate(calls)
                     if call == ("run", "nv show system ztp") and index > initial_writes[3]]
            self.assertTrue(later, "ZTP is verified disabled again after the Initial save")
            self.assertIn("Initial setup SUCCESS: saved configuration and disabled ZTP verified.", world.report())
            self.assertEqual("VERIFIED", world.record(1)["stage_status"]["initial"])
            # Owner 04 Q-037 (b) and the Q-038 list :85 ("--apply" keeps the v15 rule): with --apply
            # a device that needed only Initial is ALREADY_CONFIGURED, needs_configuration false.
            self.assertEqual("ALREADY_CONFIGURED", world.record(1)["outcome"])
            self.assertIs(False, world.record(1)["needs_configuration"])
            self.assertEqual(0, code, err)
        with self.subTest(case="unknown"), tempfile.TemporaryDirectory(prefix="strict-ztp-unknown-") as folder:
            devices = [_Device(1, password=target, lines=complete_lines(1), ztp="unknown"),
                       _Device(2, password=target, lines=complete_lines(2))]
            world, code, err = self.apply(folder, devices, initial=target, target=target)
            self.assertIn(("run", "nv show system ztp"), world.calls(host(1)))
            self.assertEqual([], world.writes(host(1)), "an unreadable ZTP state blocks every write")
            self.assertEqual("FAILED", world.record(1)["outcome"])
            self.assertIn(world.record(2)["outcome"], ("CONFIGURED", "ALREADY_CONFIGURED"))
            self.assertEqual(2, code, err)

    # -- b-3 ---------------------------------------------------------------------------------------
    def test_strict_partial_or_conflicting_network_is_refused_before_any_write(self) -> None:
        # Owner Q-035 (a); CURRENT-CONTRACT.md:54-55 ("真冲突或不明 pending 不盲目覆盖"; "--force 只补缺失
        # Network 字段，不绕过身份、密码、冲突或 pending"): partial or CSV-conflicting Network fields stop
        # this device before any write (locates v15 base_stage_needed :2706-2711).
        target = secret("target")
        cases = (("conflict", [*network_lines(1, hostname="example-other.example.test"), *SERVICES, *INITIAL_SET]),
                 ("partial", ["nv set system hostname " + host(1), *INITIAL_SET]))
        for label, lines in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="strict-partial-") as folder:
                devices = [_Device(1, password=target, lines=lines),
                           _Device(2, password=target, lines=complete_lines(2))]
                world, code, err = self.apply(folder, devices, initial=target, target=target)
                record = world.record(1)
                self.assertIn("Network fields are partial or conflict with CSV", record.get("reason", ""))
                self.assertEqual([], world.writes(host(1)), "no Initial, Network, Services or key write")
                self.assertEqual("FAILED", record["outcome"])
                self.assertIn(world.record(2)["outcome"], ("CONFIGURED", "ALREADY_CONFIGURED"))
                self.assertEqual(2, code, err)

    def test_strict_complete_addresses_with_unready_ports_fill_only_the_port_setters(self) -> None:
        # Owner Q-035 (a); CURRENT-CONTRACT.md:53 ("保留原条件决定哪些阶段需要写入"): addresses that match
        # the CSV but reserved ports that are not link-up/eth still need Network (locates v15
        # _management_ports_ready :2690-2698); the write set stays the missing setters (guide T16).
        target = secret("target")
        with tempfile.TemporaryDirectory(prefix="strict-ports-") as folder:
            lines = [*network_lines(1, ports=False), *SERVICES, *INITIAL_SET]
            devices = [_Device(1, password=target, lines=lines)]
            world, code, err = self.apply(folder, devices, initial=target, target=target)
            self.assertEqual(["nv set interface eth0-1 link state up", "nv set interface eth0-1 type eth",
                              "nv config apply -y", "nv config save"], world.writes(host(1)))
            self.assertEqual("VERIFIED", world.record(1)["stage_status"]["day0"])
            self.assertEqual("CONFIGURED", world.record(1)["outcome"])
            self.assertEqual(0, code, err)

    # -- b-4 ---------------------------------------------------------------------------------------
    def test_strict_ipv4_readiness_follows_network_on_every_apply(self) -> None:
        # Owner Q-035 (a); map D32d :284 ("IPv4 失败只停这一台（表 6-1 第 1 行）"); CURRENT-CONTRACT.md:60
        # ("单设备失败隔离"): every --apply verifies IPv4 readiness right after Network, before Infra
        # Services, even when Network wrote nothing (locates v15 :4232-4240).
        target = secret("target")
        with self.subTest(case="every-apply"), tempfile.TemporaryDirectory(prefix="strict-ipv4-") as folder:
            devices = [_Device(1, password=target, lines=complete_lines(1)),
                       _Device(2, password=target, lines=unconfigured_lines())]
            world, code, err = self.apply(folder, devices, initial=target, target=target)
            self.assertIn(("ipv4", "strict"), world.calls(host(1)), "configured device still verifies IPv4")
            self.assertEqual("VERIFIED", world.record(1)["stage_status"]["ipv4_readiness"])
            self.assertEqual("VERIFIED", world.record(1)["stage_status"]["initial"])
            calls = world.calls(host(2))
            # Initial is already present on this device, so its first save closes Network.
            network_save = calls.index(("run", "nv config save"))
            ipv4 = calls.index(("ipv4", "strict"))
            services = calls.index(("run", SERVICES[0]))
            self.assertTrue(network_save < ipv4 < services, "IPv4 follows Network and precedes Services")
            self.assertNotIn("SUCCESS: configuration verified; IPv4 SSH", world.report())
            self.assertEqual(0, code, err)
        with self.subTest(case="failure-stops-only-this-device"), \
                tempfile.TemporaryDirectory(prefix="strict-ipv4-fail-") as folder:
            devices = [_Device(1, password=target, lines=unconfigured_lines(), ipv4_codes=(255, 255, 255)),
                       _Device(2, password=target, lines=unconfigured_lines())]
            world, code, err = self.apply(folder, devices, initial=target, target=target)
            record = world.record(1)
            self.assertEqual("FAILED", record["outcome"])
            self.assertEqual("ipv4_readiness", record.get("failed_stage"))
            self.assertFalse([write for write in world.writes(host(1)) if "system dns" in write],
                             "a failed IPv4 check stops this device before Services")
            self.assertEqual("CONFIGURED", world.record(2)["outcome"], "the other device continues")
            self.assertEqual(2, code, err)

    # -- b-5 ---------------------------------------------------------------------------------------
    def test_strict_apply_requires_current_password_equal_to_project_target(self) -> None:
        # Map 4.5 P1 :356 ("有 global 的严格分支 policy 必非空，照 v15 inspect_ib_device :552，--apply
        # 时当前口令须等于项目目标"); owner Q-035 (a).
        target, initial = secret("target"), secret("initial")
        with tempfile.TemporaryDirectory(prefix="strict-drift-") as folder:
            devices = [_Device(1, password=initial, lines=unconfigured_lines()),
                       _Device(2, password=target, lines=unconfigured_lines())]
            world, code, err = self.apply(folder, devices, initial=initial, target=target)
            record = world.record(1)
            self.assertIn("current IB password does not match project global", record.get("reason", ""))
            self.assertEqual([], world.writes(host(1)), "the drifted device gets no write")
            self.assertEqual("CONFIGURED", world.record(2)["outcome"])
            self.assertEqual(2, code, err)

    # -- b-16 --------------------------------------------------------------------------------------
    def test_initial_readback_recomputes_the_later_stage_state(self) -> None:
        # P3c map D32d :284 ("合并：v15 的阶段骨架和失败隔离") and map 2.3 run_initial_stage :118 ("v15 留
        # Stage 1 骨架"; 06 D1a-L); CURRENT-CONTRACT.md:53 ("保留原条件决定哪些阶段需要写入"): after
        # Initial the Network decision uses the Initial readback, not the earlier read (locates v15
        # :4199-4204).  The no-global subcase is the same single stage implementation (P1).
        target = secret("target")
        for label, global_file in (("strict", True), ("no-global", False)):
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="strict-readback-") as folder:
                before = ["nv set system hostname nvos", "nv set system ztp config-save enabled"]
                after = complete_lines(1)
                devices = [_Device(1, password=target, lines=before, after_initial_lines=after)]
                world, code, err = self.apply(folder, devices, initial=target, target=target,
                                              global_file=global_file)
                self.assertEqual([], [write for write in world.writes(host(1))
                                      if write.startswith("nv set interface") or "system hostname" in write],
                                 "the post-Initial readback already holds the Network values")
                self.assertEqual("ALREADY_PRESENT", world.record(1)["stage_status"]["day0"])
                self.assertEqual(0, code, err)

    # -- b-6 / P5 ----------------------------------------------------------------------------------
    def test_strict_password_reads_and_change_follow_the_one_v15_sequence(self) -> None:
        # Map 2.3 _authenticate_ib_read :129 (P5: "只留一个落点，指一套实现"; "v15 留口令来源顺序（初始→
        # 项目目标→问当前口令，I14、WP-5）、改密流程和 IBPasswordChangeUncertain"), map D32d :284 ("认证、
        # 改密到项目目标" taken into the v15 skeleton) and CURRENT-CONTRACT.md:50 ("兼容已强制改密，改密写
        # 后用新连接验证").
        target, initial = secret("target"), secret("initial")
        with self.subTest(case="forced-change"), tempfile.TemporaryDirectory(prefix="strict-change-") as folder:
            devices = [_Device(1, password=initial, expired=True, lines=unconfigured_lines())]
            world, code, err = self.apply(folder, devices, initial=initial, target=target)
            phases = [kind for kind, _detail in world.calls(host(1)) if kind.startswith("phase:")]
            self.assertEqual(["phase:auth-probe-readonly", "phase:password-change", "phase:post-change-read"],
                             phases)
            self.assertIn("IB new-password authentication and NVUE readback verified.", world.report())
            self.assertEqual("CONFIGURED", world.record(1)["outcome"])
            self.assertEqual(0, code, err)
        with self.subTest(case="unverifiable-readback-after-change"), \
                tempfile.TemporaryDirectory(prefix="strict-change-unknown-") as folder:
            devices = [_Device(1, password=initial, expired=True, lines=unconfigured_lines(),
                               post_change_lines=["# PUBLIC readback without NVUE setters"]),
                       _Device(2, password=target, lines=complete_lines(2))]
            world, code, err = self.apply(folder, devices, initial=initial, target=target)
            record = world.record(1)
            self.assertIn("IB password-write outcome is UNKNOWN", record.get("reason", ""),
                          "the fresh readback after the change must parse as NVUE configuration")
            self.assertEqual([], world.writes(host(1)))
            self.assertEqual(2, code, err)
        with self.subTest(case="initial-rejected-target-fallback"), \
                tempfile.TemporaryDirectory(prefix="strict-fallback-") as folder:
            devices = [_Device(1, password=target, lines=complete_lines(1))]
            world, code, err = self.apply(folder, devices, initial=initial, target=target)
            self.assertIn("Initial IB credential rejected; trying the project IB password (no rotation).",
                          world.report())
            self.assertEqual(0, code, err)
        # One implementation: the third credential source (T18) is asked from one place only.
        # Its own subTest, so it is reported even when a run above fails.
        with self.subTest(case="t18-one-call-site"):
            tree = ast.parse(INITIAL.read_text(encoding="utf-8"))
            askers = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                      and isinstance(node.func, ast.Name) and node.func.id == "request_current_ib_password"]
            self.assertEqual(1, len(askers), "the current-password fallback has one call site")

    # -- a-10 --------------------------------------------------------------------------------------
    def test_ipv4_readiness_has_one_wait_and_retry_loop(self) -> None:
        # Guide 2.3 :204 ("verify_ipv4_login 的「3 次、每次先等 10 秒」，不另加第二套"); P3c map 2.3
        # verify_ipv4_login :126; owner Q-035 (a).
        with self.subTest(case="one-loop-in-source"):
            tree = ast.parse(INITIAL.read_text(encoding="utf-8"))
            function = next(node for node in tree.body
                            if isinstance(node, ast.FunctionDef) and node.name == "verify_ipv4_login")
            sleeps = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                      and isinstance(node.func, ast.Attribute) and node.func.attr == "sleep"]
            loops = [node for node in ast.walk(function) if isinstance(node, ast.For)
                     and isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name)
                     and node.iter.func.id == "range"]
            self.assertEqual(1, len(sleeps), "one wait before each attempt")
            self.assertEqual(1, len(loops), "one bounded attempt loop")
        target = secret("target")
        waits = []
        with self.subTest(case="three-attempts-strict"), \
                tempfile.TemporaryDirectory(prefix="strict-ipv4-retry-") as folder:
            devices = [_Device(1, password=target, lines=unconfigured_lines(), ipv4_codes=(255, 255, 0))]
            world, code, err = self.apply(folder, devices, initial=target, target=target,
                                          extra=(mock.patch.object(self.app.time, "sleep", side_effect=waits.append),))
            self.assertEqual(3, world.calls(host(1)).count(("ipv4", "strict")))
            self.assertEqual([10, 10, 10], [value for value in waits if value == 10])
            self.assertEqual(0, code, err)

    # -- check-only --------------------------------------------------------------------------------
    def test_strict_check_only_reports_v15_stage_results_without_a_pending_read(self) -> None:
        # P3c map D32d :284 ("合并：v15 的阶段骨架和失败隔离"; the DEV strict branch's check-only
        # pending report is not part of that skeleton); CURRENT-CONTRACT.md:59 ("check-only 不写设备
        # 配置，仍只读 SSH 并生成本地报告"): the read-only strict run plans Network like v15 and stops the
        # device there (locates v15 :4208-4216); it does not add the DEV pending-diff report.
        target = secret("target")
        with tempfile.TemporaryDirectory(prefix="strict-check-") as folder:
            devices = [_Device(1, password=target, lines=unconfigured_lines()),
                       _Device(2, password=target, lines=complete_lines(2))]
            world = self.world(Path(folder), devices)
            code, err = self.run_main(world, world.argv(), self.credentials(world, initial=target), target=target)
            self.assertFalse([call for call in world.calls() if call == ("run", "nv config diff -o commands")],
                             "check-only reads no pending diff")
            record = world.record(1)
            self.assertEqual("CHECK_ONLY", record["outcome"])
            self.assertEqual("NEEDS_CONFIGURATION", record["stage_status"]["day0"])
            self.assertEqual("NOT_REACHED", record["stage_status"]["services"])
            self.assertIn("WOULD APPLY: nv set interface eth0 ipv4 address 192.0.2.12/24", world.report())
            self.assertEqual("ALREADY_CONFIGURED", world.record(2)["outcome"])
            self.assertEqual("CHECKED", world.record(2)["stage_status"]["initial"])
            self.assertEqual([], world.writes(host(1)) + world.writes(host(2)))
            self.assertEqual(2, code, err)

    def test_check_only_with_only_initial_missing_needs_configuration(self) -> None:
        # Owner 04 Q-037 (b) (deadline 2026-11-10 23:10:38 passed without an answer, default taken,
        # R-260): a read-only check whose Initial stage cannot be skipped (the two settings are not
        # both enabled, or ZTP is not disabled: the same condition under which run_initial_stage
        # would write Initial) needs configuration: CHECK_ONLY, needs_configuration true, and the
        # run maps to INCOMPLETE / exit 2 (table 6-1 row 11, guide :754).  DEV
        # initial-setup.py:6226-6229@4bbdcce2fdb5a315946824f4332293e621e3412a only locates the DEV
        # rule (Initial missing counted as a change).
        app = self.app
        target = secret("target")
        only_auto_save_missing = [*network_lines(1), *SERVICES, "nv set system ztp config-save enabled"]

        def leaf_transport(world):
            def transport(command, responder, timeout, **kwargs):
                text = " ".join(command)
                if list(command[:2]) == ["sh", "-c"] and "admin@" not in text:
                    # The Leaf runs its own Ethernet reads locally (the fixed-PATH wrapper, T14).
                    app.check_task_cancelled()
                    remote = shlex.split(command[2].split("; exec ", 1)[1])
                    device = next(iter(world.devices.values()))
                    return app.SessionResult(world.ethernet_output(device, remote), 0)
                return world.transport(command, responder, timeout, **kwargs)
            return transport

        cases = (("strict-one-setting-missing", only_auto_save_missing, "disabled"),
                 ("strict-ztp-not-disabled", complete_lines(1), "enabled"))
        for label, lines, ztp in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="check-initial-") as folder:
                world = self.world(Path(folder), [_Device(1, password=target, lines=lines, ztp=ztp)])
                code, err = self.run_main(world, world.argv(), self.credentials(world, initial=target),
                                          target=target)
                record = world.record(1)
                self.assertEqual("CHECK_ONLY", record["outcome"])
                self.assertIs(True, record["needs_configuration"])
                self.assertEqual("INCOMPLETE", world.summary()["result"])
                self.assertEqual(2, code, err)
                self.assertEqual([], world.writes(host(1)), "a read-only check writes nothing")
        with self.subTest(case="leaf-local-no-global"), \
                tempfile.TemporaryDirectory(prefix="check-initial-leaf-") as folder:
            world = self.world(Path(folder), [_Device(1, password=target, lines=only_auto_save_missing)],
                               global_file=False)
            # P1 on the management server first: the Leaf only consumes the version 5 cache.
            code, err = self.run_main(world, world.argv("--generate-json"), None, target=target)
            self.assertEqual(0, code, err)
            for stale in world.root.rglob("summary.json"):
                stale.rename(stale.with_name("p1-summary.json.done"))
            # The override names the Leaf; never resolve the real host name (socket.getfqdn()
            # makes macOS libc keep an mDNSResponder socket open for the rest of the process).
            code, err = self.run_main(
                world, world.argv("--execution-mode", "ethernet", "--local-ethernet-hostname", "EXAMPLE-JUMP01"),
                self.credentials(world, initial=target), target=target,
                extra=(mock.patch.object(app, "interactive_run", leaf_transport(world)),
                       mock.patch.object(app.socket, "gethostname", return_value="EXAMPLE-JUMP01"),
                       mock.patch.object(app.socket, "getfqdn", return_value="EXAMPLE-JUMP01")))
            self.assertIn("Local Ethernet execution", world.report(), "the run is the Leaf-local path")
            record = world.record(1)
            self.assertEqual("CHECK_ONLY", record["outcome"])
            self.assertIs(True, record["needs_configuration"])
            self.assertEqual("INCOMPLETE", world.summary()["result"])
            self.assertEqual(2, code, err)
            self.assertEqual([], world.writes(host(1)), "a read-only check writes nothing")

    # -- first change confirmation -----------------------------------------------------------------
    def test_strict_first_change_confirmation_names_the_first_v15_write_stage(self) -> None:
        # P3c map 4.1 difficulty 4 :313 ("两种改动授权"; 取法 v15 RuntimeCoordinator.authorize, "DEV 的
        # apply_authorized 只剩协调者 authorized 的初值") and map D32d :284: the coordinator asks once, at the first write, for that stage's own action (locates v15
        # run_initial_stage :2808-2811 and, for a forced change, inspect_ib_device :521-527: the
        # verified target first, then the question).
        app = self.app
        target, initial = secret("target"), secret("initial")
        cases = (
            ("initial", _Device(1, password=target, lines=["nv set system hostname nvos",
                                                           "nv set system ztp config-save enabled"]),
             target, "Required action: enable auto-save and ZTP config-save"),
            ("password-change", _Device(1, password=initial, expired=True, lines=unconfigured_lines()),
             initial, "Required action: change the expired IB password to the verified project IB password"),
        )
        for label, device, first_password, expected in cases:
            events = []

            def hidden(prompt=""):
                events.append(("getpass", prompt))
                return target

            def answer(prompt=""):
                events.append(("input", prompt))
                return "y"

            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="strict-confirm-") as folder:
                world = self.world(Path(folder), [device], jump_passwords={})
                terminal = mock.Mock()
                terminal.isatty.return_value = True
                extra = (mock.patch.object(app, "probe_ethernet_key", return_value="key"),
                         mock.patch.object(getpass, "getpass", side_effect=hidden),
                         mock.patch.object(builtins, "input", side_effect=answer),
                         mock.patch.object(sys, "stdin", terminal),
                         mock.patch.dict(os.environ, {"NVOS_INITIAL_PASSWORD": first_password}))
                code, err = self.run_main(world, world.argv("--apply"), None, target=target, extra=extra)
                report = world.report()
                self.assertIn(expected, report)
                self.assertNotIn("apply eligible Initial, Network, Services and public-key changes", report)
                self.assertNotIn("change the initial NVOS password to the independently verified", report)
                kinds = [kind for kind, _prompt in events]
                self.assertIn("input", kinds)
                self.assertIn("getpass", kinds)
                self.assertLess(kinds.index("getpass"), kinds.index("input"),
                                "the verified target is read before the operator is asked")
                self.assertEqual(0, code, err)

    # -- Services wrapper --------------------------------------------------------------------------
    def test_strict_service_verification_failure_is_reported_as_partial_writes(self) -> None:
        # Owner Q-035 (a); CURRENT-CONTRACT.md:60 ("单设备失败隔离，已完成阶段事实保留") and P3c map 2.3
        # run_service_stage :121 ("v15 的 IBConfigurationStageUncertain 包装保留").
        target = secret("target")
        with tempfile.TemporaryDirectory(prefix="strict-services-") as folder:
            devices = [_Device(1, password=target, lines=[*network_lines(1), *INITIAL_SET], drop_services=True),
                       _Device(2, password=target, lines=complete_lines(2))]
            world, code, err = self.apply(folder, devices, initial=target, target=target)
            record = world.record(1)
            self.assertEqual("services", record.get("failed_stage"))
            self.assertIn("services were not fully verified; writes may be partial", record.get("reason", ""))
            self.assertIn(world.record(2)["outcome"], ("CONFIGURED", "ALREADY_CONFIGURED"))
            self.assertEqual(2, code, err)

    # -- stop and input change ---------------------------------------------------------------------
    def test_strict_batch_stop_during_ipv4_readiness_stops_the_batch(self) -> None:
        # CURRENT-CONTRACT.md:60 ("共享输入/证据落盘错误仍应停止公共流程") and map D32d :284 (v15 的失败
        # 隔离): a coordinator stop inside a strict stage is a batch stop, not a device failure
        # (locates v15 execute_ib_task :4273-4279).
        app = self.app
        target = secret("target")

        def stop(seconds):
            coordinator = app._ACTIVE_COORDINATOR
            if seconds == 10 and coordinator is not None and not coordinator.stopped:
                coordinator.stopped, coordinator.fatal = True, "PUBLIC operator stop"

        with self.subTest(case="stop-during-ipv4"), tempfile.TemporaryDirectory(prefix="strict-stop-") as folder:
            devices = [_Device(1, password=target, lines=unconfigured_lines()),
                       _Device(2, password=target, lines=unconfigured_lines())]
            world, code, err = self.apply(folder, devices, initial=target, target=target,
                                          extra=(mock.patch.object(app.time, "sleep", side_effect=stop),))
            record = world.record(1)
            self.assertEqual("UNVERIFIED", record["stage_status"]["ipv4_readiness"])
            self.assertIn("PUBLIC operator stop", record.get("batch_error", ""))
            later = world.summary()["records"].get(host(2).casefold(), {})
            self.assertNotIn(later.get("outcome"), ("CONFIGURED", "ALREADY_CONFIGURED"))
            self.assertEqual("FAILED", world.summary()["result"])
            self.assertEqual(1, code, err)
        with self.subTest(case="input-change-before-initial-writes"), \
                tempfile.TemporaryDirectory(prefix="strict-input-") as folder:
            # The project global changes while the pending diff is read just before the Initial
            # writes: the next per-command check stops the batch (locates v15 run_initial_stage :2816).
            first = _Device(1, password=target, lines=["nv set system hostname nvos",
                                                       "nv set system ztp config-save enabled"])
            devices = [first, _Device(2, password=target, lines=unconfigured_lines())]
            global_path = Path(folder) / "01-global.yaml"

            def change_global():
                if first.on_pending is not None:
                    first.on_pending = None
                    global_path.write_text(global_path.read_text(encoding="utf-8") + "# PUBLIC changed\n",
                                           encoding="utf-8")

            first.on_pending = change_global
            world, code, err = self.apply(folder, devices, initial=target, target=target)
            record = world.record(1)
            self.assertEqual("UNVERIFIED", record["stage_status"]["initial"])
            self.assertIn("project global changed", record.get("batch_error", ""))
            self.assertEqual([], world.writes(host(1)), "no Initial write after the input changed")
            self.assertEqual("FAILED", world.summary()["result"])
            self.assertEqual(1, code, err)

    # -- D32d: the authorized helper (WP-6 supplement 3-1, 06 D1a2-da1) -----------------------------
    def test_strict_stage_reads_and_writes_go_through_the_authorized_helper(self) -> None:
        # P3c map D32d :284 ("管理服务器任务的每次读写走 DEV 的阶段隔离和授权执行；写前 pending 按 T15")
        # and map section 9 item 1 :478 ("严格授权执行只用于管理服务器上的任务"); 06 D1a2-01 (a read-only
        # check reads ZTP before Initial without the helper).  The fake transport serves a helper
        # command and a plain run_on_ib command alike, so the real helper is wrapped and the
        # commands it carried are compared with what the device served.
        app = self.app
        target = secret("target")
        pending = "nv config diff -o commands"
        lines = ["nv set system hostname nvos", "nv set system ztp config-save enabled"]

        def carried(helper) -> list:
            commands = []
            for call in helper.call_args_list:
                command = call.args[7] if len(call.args) > 7 else call.kwargs["ib_command"]
                text = shlex.join(command)
                commands.append("public-key install" if "IBSW_PUBLIC_KEYS" in text else text)
            return commands

        def keygen(argv, *args, **kwargs):
            # Only the project-key check ssh-keygen -l reaches here; its answer names the line's
            # own fingerprint (fixture), anything else stays forbidden.
            if Path(str(argv[0])).name == "ssh-keygen" and list(argv[1:]) == ["-l", "-E", "sha256", "-f",
                                                                             "/dev/stdin"]:
                line = kwargs["input"].strip()
                return subprocess.CompletedProcess(
                    argv, 0, f"256 {app._public_key_fingerprint(line)} PUBLIC (ED25519)\n", "")
            raise AssertionError("external commands forbidden")

        real_which = shutil.which

        def which(name, *args, **kwargs):
            return "/usr/bin/ssh-keygen" if name == "ssh-keygen" else real_which(name, *args, **kwargs)

        with self.subTest(case="strict-apply"), tempfile.TemporaryDirectory(prefix="strict-helper-") as folder:
            world = self.world(Path(folder), [_Device(1, password=target, lines=lines)])
            (world.root / "publickey").mkdir()
            (world.root / "publickey" / "laptop.pub").write_text(public_key_line(7, "PUBLIC-laptop"),
                                                                 encoding="ascii")
            helper = mock.Mock(wraps=app._run_authorized_ib_command)
            code, err = self.run_main(
                world, world.argv("--apply", "--yes"), self.credentials(world, initial=target, target=target),
                target=target, extra=(mock.patch.object(app, "_run_authorized_ib_command", helper),
                                      mock.patch.object(app.subprocess, "run", side_effect=keygen),
                                      mock.patch.object(app.shutil, "which", side_effect=which)))
            self.assertEqual(0, code, err)
            served = [detail for kind, detail in world.calls(host(1)) if kind == "run"]
            commands = carried(helper)
            for stage, command in (("Initial", "nv show system ztp"), ("Initial", INITIAL_SET[0]),
                                   ("Network", "nv set interface eth0 ipv4 address 192.0.2.12/24"),
                                   ("Services", SERVICES[0]), ("Keys", "public-key install"),
                                   ("readback", "nv config show -o commands")):
                self.assertIn(command, commands, f"{stage} command went through the authorized helper")
            # T15: the pre-write pending reads are plain reads, never through the helper.
            self.assertIn(pending, served, "T15 reads the pending diff before the writes")
            self.assertNotIn(pending, commands, "the T15 pending read does not use the helper")
            # Every other stage read and write the device served came through the helper, in order.
            self.assertEqual([detail for detail in served if detail != pending], commands)
        with self.subTest(case="check-only"), tempfile.TemporaryDirectory(prefix="strict-helper-check-") as folder:
            world = self.world(Path(folder), [_Device(1, password=target, lines=lines)])
            helper = mock.Mock(wraps=app._run_authorized_ib_command)
            code, err = self.run_main(world, world.argv(), self.credentials(world, initial=target), target=target,
                                      extra=(mock.patch.object(app, "_run_authorized_ib_command", helper),))
            # 06 WP6-a8 (WP-6 review A wa-9): a check-only run that finds configuration to do is
            # INCOMPLETE, exit 2 (table 6-1 row 11, guide :754).
            self.assertEqual(2, code, err)
            self.assertIn(("run", "nv show system ztp"), world.calls(host(1)), "check-only reads ZTP first")
            self.assertNotIn("nv show system ztp", carried(helper),
                             "the check-only ZTP read before Initial does not use the helper (06 D1a2-01)")
        with self.subTest(case="no-global"), tempfile.TemporaryDirectory(prefix="strict-helper-none-") as folder:
            world = self.world(Path(folder), [_Device(1, password=target, lines=lines)], global_file=False)
            helper = mock.Mock(wraps=app._run_authorized_ib_command)
            code, err = self.run_main(world, world.argv("--apply", "--yes"),
                                      self.credentials(world, initial=target, target=target), target=target,
                                      extra=(mock.patch.object(app, "_run_authorized_ib_command", helper),))
            # 06 WP6-a8 (WP-6 review A wa-9): without the project global --apply still runs (table
            # 6-1 row 10, guide :753) and a fully verified run is SUCCESS, exit 0 (row 11, :754).
            self.assertEqual(0, code, err)
            self.assertTrue(world.writes(host(1)), "the no-global run still writes its stages")
            self.assertEqual(0, helper.call_count, "a run without the project global never uses the helper")

    # -- b-7 (owner Q-036, 05 P-014) ---------------------------------------------------------------
    def test_strict_run_with_two_real_workers_uses_the_pinned_policy_copy(self) -> None:
        # Guide :440 ("非受管运行仍按 automatic_worker_count 和 --max-workers") and 05 P-014 (owner
        # Q-036: the type gate admits exactly one more class, WorkerPasswordPolicy).  17 ready devices
        # give ceil(17/16) = 2 slots; --max-workers 2 keeps both, so tasks run in forked workers.
        app = self.app
        target = secret("target")
        with tempfile.TemporaryDirectory(prefix="strict-workers-") as folder:
            devices = [_Device(index, password=target, lines=unconfigured_lines()) for index in range(1, 18)]
            world, code, err = self.apply(folder, devices, initial=target, target=target,
                                          args=("--apply", "--yes", "--max-workers", "2"))
            with self.subTest(case="two-real-workers"):
                summary = world.summary()
                self.assertEqual(2, summary["workers"])
                self.assertEqual({"CONFIGURED"}, {record["outcome"] for record in summary["records"].values()})
                phased = {name for name, kind, _detail in (line.split("\t", 2) for line in
                          world.calls_path.read_text(encoding="utf-8").splitlines())
                          if kind == "phase:auth-probe-readonly"}
                self.assertEqual({device.hostname for device in devices}, phased,
                                 "every worker task authenticated through the DEV phase session")
                self.assertEqual(0, code, err)
            # The gate admits the pinned worker copy and no other subclass.
            with self.subTest(case="type-gate"):
                global_path = world.root / "01-global.yaml"
                policy = app.ProjectPasswordPolicy(global_path, "admin", target_password=target,
                                                   interactive=False)
                app._ib_project_value(app.WorkerPasswordPolicy.pinned_copy(policy), user="admin")

                class OtherPolicy(app.ProjectPasswordPolicy):
                    pass

                other = object.__new__(OtherPolicy)
                other.__dict__.update(policy.__dict__)
                with self.assertRaises(app.SetupError):
                    app._ib_project_value(other, user="admin")

    # -- FX3: every IB authentication session is one counted IB SSH attempt -------------------------
    def fx3_observe(self, outcomes, entry, *, target):
        """Call entry(policy) with record_metric observed (not replaced); return (events, result).

        Each IB session answers the next outcome ("accept", "reject" or "transport"): the DEV phase
        session is _execute_ib_phase, a plain session is interactive_run (run_on_ib stays real).
        The project authority and the policy return `target`; log is silenced.  A SetupError the
        entry raises is returned as its result.
        """
        app = self.app
        events, script = [], list(outcomes)
        real_record = app.record_metric

        def record(name):
            events.append(("metric", name))
            return real_record(name)

        def answer(text=None):
            outcome = script.pop(0)
            if text is None:
                if outcome == "accept":
                    return app.SessionResult("nv set system hostname nvos\n", 0)
                if outcome == "reject":
                    raise app.IBAuthenticationError("PUBLIC synthetic rejection")
                raise app.SetupError("PUBLIC synthetic phase transport failure")
            if outcome == "accept":
                nonce = FRAME_RE.search(text).group(1)
                return app.SessionResult(f"__HTTP_IB_BEGIN_{nonce}__\nnv set system hostname nvos\n"
                                         f"__HTTP_IB_END_{nonce}__=0\n", 0)
            if outcome == "reject":
                return app.SessionResult("", 255, ib_authentication_rejected=True)
            return app.SessionResult("ssh: connect to host fe80::12 port 22: Network is unreachable\n", 255)

        def phase(*_args, **kwargs):
            events.append(("phase", kwargs.get("_phase_operation")))
            return answer()

        def transport(command, _responder, _timeout, **_kwargs):
            events.append(("run", "ib"))
            return answer(" ".join(command))

        policy = mock.Mock(spec=["password"])
        policy.password.return_value = target
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app, "record_metric", side_effect=record))
            stack.enter_context(mock.patch.object(app, "_execute_ib_phase", side_effect=phase))
            stack.enter_context(mock.patch.object(app, "interactive_run", side_effect=transport))
            stack.enter_context(mock.patch.object(app, "_ib_project_value", return_value=target))
            stack.enter_context(mock.patch.object(app, "log"))
            try:
                return events, entry(policy)
            except app.SetupError as error:
                return events, error

    def fx3_endpoints(self) -> tuple:
        app = self.app
        ib = app.Device(host(1), "ib", "192.0.2.12", "192.0.2.12/24", "192.0.2.1", "02:00:00:00:00:12", "", "")
        jump = app.Device("example-oob-leaf01.example.test", "eth_jump", "198.51.100.10", "", "", "", "", "")
        return (app.Target(ib, jump, "swp1", "eth0"), app.Neighbor("fe80::12", "ib-mgmt1000", "02:00:00:00:00:12"),
                "cumulus", secret("oob"), "admin")

    def test_strict_authentication_read_counts_each_ib_session_before_it_starts(self) -> None:
        # FX3 (v3.1.3 integration fix; WP-7 review B "FX3 修法" item 1).  Expectation sources, not the
        # implementation: v15 counts each IB SSH session once, before it starts and whatever its
        # result (参考/initial-setup-v15/initial-setup-20261019-v15_oob-spine.py:2494-2495:
        # record_metric("ib_ssh_attempts"), then interactive_run); each credential the IB
        # authentication readback tries is one such session (v15 :494-496 the initial password,
        # :505-507 the project target); P3c map :120 (run_on_ib keeps v15's record_metric) and :219
        # (record_metric: take v15's counting), guide :419 (the run_on_ib merge keeps v15's counter),
        # all at tag guide-v3.1.3-approved-r302.  The strict read is a DEV phase session (map :129),
        # so its own branch counts it.  Only the phase session, the project authority and log are
        # replaced.
        app = self.app
        initial, target = secret("initial"), secret("target")
        metric, phase = ("metric", "ib_ssh_attempts"), ("phase", "auth-probe-readonly")
        exhausted, transport = app._IB_CREDENTIALS_EXHAUSTED, "PUBLIC synthetic phase transport failure"
        names = set()
        for case, outcomes, password, expected, ending in (
                ("accepted", ["accept"], initial, [metric, phase], initial),
                ("rejected-then-target-accepted", ["reject", "accept"], initial, [metric, phase] * 2, target),
                ("initial-equals-target-rejected", ["reject"], target, [metric, phase], exhausted),
                ("transport-failure", ["transport"], initial, [metric, phase], transport)):
            with self.subTest(case=case):
                events, result = self.fx3_observe(
                    outcomes, lambda policy: app._authenticate_ib_read(
                        *self.fx3_endpoints(), password, 5, local=False, _password_policy=policy,
                        strict=True), target=target)
                names.update(name for kind, name in events if kind == "metric")
                self.assertEqual(expected, events)
                self.assertEqual(ending, result.current_password if isinstance(result, app._IBLogin)
                                 else str(result))
        with self.subTest(case="counter-name"):
            self.assertEqual({"ib_ssh_attempts"}, names)

    def test_fx3_controls_count_each_run_on_ib_session_once(self) -> None:
        # FX3 control group (WP-7 review B C1, C2): green before and after FX3.  Same sources as the
        # test above (v15 :2494-2495: one count per IB SSH session, before it starts).
        # C1: the non-strict authentication read is one v15 password-only run_on_ib session per
        #     credential (v15 :494-496, :505-507); run_on_ib stays real, interactive_run answers.
        # C2: the strict T18 read, the password change and the fresh read after it are run_on_ib
        #     phase sessions (v15 :515-517, :530-533, :538-540; map :120), each counted once.
        app = self.app
        initial, target = secret("initial"), secret("target")
        metric, run = ("metric", "ib_ssh_attempts"), ("run", "ib")
        for case, outcomes, expected in (
                ("C1-accepted", ["accept"], [metric, run]),
                ("C1-rejected-then-target-accepted", ["reject", "accept"], [metric, run] * 2),
                ("C1-both-rejected", ["reject", "reject"], [metric, run] * 2),
                ("C1-transport-failure", ["transport"], [metric, run])):
            with self.subTest(case=case):
                events, _result = self.fx3_observe(
                    outcomes, lambda policy: app._authenticate_ib_read(
                        *self.fx3_endpoints(), initial, 5, local=False, _password_policy=policy,
                        strict=False), target=target)
                self.assertEqual(expected, events)
        for operation, allow in (("auth-probe-readonly", False), ("password-change", True),
                                 ("post-change-read", False)):
            with self.subTest(case="C2-" + operation):
                events, _result = self.fx3_observe(
                    ["accept"], lambda policy: app.run_on_ib(
                        *self.fx3_endpoints(), initial, 5, ["nv", "config", "show", "-o", "commands"],
                        local=False, allow_password_change=allow, ib_new_password=target if allow else None,
                        _phase_operation=operation, _password_policy=policy), target=target)
                self.assertEqual([metric, ("phase", operation)], events)


if __name__ == "__main__":
    unittest.main()
