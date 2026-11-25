"""D6: five PUBLIC devices through real MAIN, device stages and saved results.

Expected facts come from approved r757 D67-O1/O2/O3/O8/O9 and the frozen
results schema, not source-produced results.  The transport model never
executes SSH or any remote shell. Native password qualification (original
fixed reader/8s worker) and public-key validation (original 10s validator)
are real. Its private KAT remains RAM/own0600 inputs, never diagnostics.
The author has NOT RUN this file; Root owns precise runtime admission.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hmac
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.initial_setup_jump_fixture import legacy_jump_sessions_factory
from test_cases.test_initial_setup_identity_and_backup import EXPECTED_BACKUP_SCRIPT
from test_cases.test_initial_setup_bringup_results import (
    EXPECTED_INSTALL_KEY_SCRIPT, EXPECTED_READONLY_KEY_SCRIPT)
from test_cases.test_req10b_services_keys_workflow import (
    credentials_fd, public_key, strict_fd_payload, strict_global_text, strict_kat)


INITIAL = (Path(__file__).resolve().parents[1]
           / "infiniband/bringup/xdr-initial-setup/initial-setup.py")
NAMES = ["EXAMPLE-IB001", "EXAMPLE-IB002", "EXAMPLE-IB003", "EXAMPLE-IB004", "EXAMPLE-IB005"]
JUMP = "EXAMPLE-JUMP01"
CSV_HEADER = "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
CSV_ROWS = (
    "EXAMPLE-IB001,ib,203.0.113.11,24,203.0.113.1,02:00:00:00:00:11,,,\n"
    "EXAMPLE-IB002,ib,203.0.113.12,24,203.0.113.1,02:00:00:00:00:12,,,\n"
    "EXAMPLE-IB003,ib,203.0.113.13,24,203.0.113.1,02:00:00:00:00:13,,,\n"
    "EXAMPLE-IB004,ib,203.0.113.14,24,203.0.113.1,02:00:00:00:00:14,,,\n"
    "EXAMPLE-IB005,ib,203.0.113.15,24,203.0.113.1,02:00:00:00:00:15,,,\n"
    "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n")
# Independent master literal, never a copy of a generated subset/result.
MASTER_ROWS = (
    "EXAMPLE-IB001,ib,203.0.113.11,24,203.0.113.1,02:00:00:00:00:11,,,\n"
    "EXAMPLE-IB002,ib,203.0.113.12,24,203.0.113.1,02:00:00:00:00:12,,,\n"
    "EXAMPLE-IB003,ib,203.0.113.13,24,203.0.113.1,02:00:00:00:00:13,,,\n"
    "EXAMPLE-IB004,ib,203.0.113.14,24,203.0.113.1,02:00:00:00:00:14,,,\n"
    "EXAMPLE-IB005,ib,203.0.113.15,24,203.0.113.1,02:00:00:00:00:15,,,\n"
    "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n")
P2P = ('"EXAMPLE-IB001":"eth0" -- "EXAMPLE-JUMP01":"swp1";\n'
       '"EXAMPLE-IB002":"eth0" -- "EXAMPLE-JUMP01":"swp2";\n'
       '"EXAMPLE-IB003":"eth0" -- "EXAMPLE-JUMP01":"swp3";\n'
       '"EXAMPLE-IB004":"eth0" -- "EXAMPLE-JUMP01":"swp4";\n')
HELD = ["nv set system config auto-save state enabled",
        "nv set system ztp config-save enabled",
        "nv set interface eth0-1 link state up", "nv set interface eth0-1 type eth"]
SERVICE_ROWS = ["nv set system dns server 203.0.113.53",
                "nv set system ntp server ntp.ubuntu.com state enabled",
                "nv set system ntp server time.ib.example.test state enabled"]
EXTRA_ROWS = ["nv set system dns server 198.51.100.53",
              "nv set system ntp server time.extra.example.test state enabled"]
FRAME = re.compile(
    r'^printf "\\n__HTTP_IB_BEGIN_([0-9a-f]{32})__\\n"; (.*); '
    r'task_rc=\$\?; printf "\\n__HTTP_IB_END_([0-9a-f]{32})__=%s\\n" '
    r'"\$task_rc"; exit "\$task_rc"$', re.S)
SAFE_PREFIX = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "


class _FiveDevices:
    """Only physical OOB/IB replies; no fake producer, stage or result record."""
    def __init__(self, test, app, kat):
        self.test, self.app, self.kat = test, app, kat
        self.events, self.permits, self.delays, self.readiness = [], [], [], []
        self.pending = {name: [] for name in NAMES}
        self.keys_present = {name: name != NAMES[0] for name in NAMES}
        self.rows = {}
        for index, name in enumerate(NAMES, 11):
            address = "198.51.100.13/24" if name == NAMES[2] else f"203.0.113.{index}/24"
            self.rows[name] = (["nv set system hostname nvos"] if name == NAMES[0] else [
                *HELD, f"nv set system hostname {name}",
                "nv set interface eth0 ipv4 address " + address,
                "nv set interface eth0 ipv4 gateway 203.0.113.1", *SERVICE_ROWS,
                "nv set system date-time timezone " + ("Etc/UTC" if name == NAMES[3] else "Asia/Taipei")])
        self.rows[NAMES[1]].extend(EXTRA_ROWS)
        self.endpoints = {f"fe80::ff:fe00:{index:x}": name for index, name in enumerate(NAMES[:4], 17)}
        self.endpoints.update({f"203.0.113.{index}": name for index, name in enumerate(NAMES, 11)})
        required = public_key(17, "PUBLIC-results-required").strip()
        # This exact PUBLIC line is input and transport expectation, not SUT output.
        self.public_line = required
        self.key_payload = base64.b64encode((required + "\n").encode("ascii")).decode("ascii")

    def configuration(self, name):
        return "\n".join(self.rows[name]) + "\n"

    def public_failure_note(self, evidence):
        """Bounded context only; redact before truncation and ASCII serialization."""
        try:
            variants = set()
            for name in ("PASSWORD", "YESCRYPT"):
                value = self.kat[name]
                if type(value) is not str or not value:
                    return "PUBLIC diagnostic unavailable"
                variants.update((value, repr(value), repr(value)[1:-1]))
                for ascii_only in (False, True):
                    encoded = json.dumps(value, ensure_ascii=ascii_only)
                    variants.update((encoded, encoded[1:-1]))
            variants = sorted(variants, key=len, reverse=True)

            def public_text(value):
                if type(value) is not str:
                    return ""
                for private in variants:
                    value = value.replace(private, "<redacted>")
                if any(private in value for private in variants):
                    return "PUBLIC diagnostic unavailable"
                return value[:240]

            allowed = {"AssertionError", "AttributeError", "TypeError", "ValueError",
                       "KeyError", "IndexError", "NameError", "RuntimeError", "OSError"}
            rows = []
            for name in NAMES:
                record = evidence.get("records", {}).get(name.casefold(), {})
                reason = public_text(record.get("reason"))
                kind = reason.split(":", 1)[0]
                rows.append({"hostname": name, "category": public_text(record.get("category")),
                    "failed_stage": public_text(record.get("failed_stage")),
                    "script_error": record.get("script_error") is True,
                    "batch_error_present": bool(record.get("batch_error")),
                    "exception_type": kind if record.get("script_error") is True and kind in allowed else None,
                    "reason": reason})
            note = json.dumps({"fatal_present": bool(evidence.get("batch_stop_reason")),
                               "devices": rows}, ensure_ascii=True, separators=(",", ":"))
            if any(private in note for private in variants):
                return "PUBLIC diagnostic unavailable"
            return "PUBLIC failure context: " + note
        except Exception:
            return "PUBLIC diagnostic unavailable"

    def ethernet(self, device, user, password, command, timeout, **options):
        self.test.assertEqual((JUMP, "cumulus", ""), (device.hostname, user, password))
        command = tuple(command)
        if command == ("hostname",):
            return JUMP + "\n"
        if command == ("nv", "show", "interface"):
            return "swp1 up up\nswp2 up up\nswp3 up up\nswp4 up up\n"
        if command == ("ip", "-d", "link", "show"):
            return ("1: swp1: <UP> mtu 1500 master br_default\n"
                    "2: swp2: <UP> mtu 1500 master br_default\n"
                    "3: swp3: <UP> mtu 1500 master br_default\n"
                    "4: swp4: <UP> mtu 1500 master br_default\n"
                    "40: br_default: <UP> mtu 1500\n    bridge forward_delay 1500 vlan_filtering 1\n"
                    "41: ib-mgmt1000@br_default: <UP> mtu 1500 master oob\n"
                    "    vlan protocol 802.1Q id 1000 <REORDER_HDR>\n")
        if command == ("bridge", "fdb", "show"):
            return ("02:00:00:00:00:11 dev swp1 vlan 1000 master br_default\n"
                    "02:00:00:00:00:12 dev swp2 vlan 1000 master br_default\n"
                    "02:00:00:00:00:13 dev swp3 vlan 1000 master br_default\n"
                    "02:00:00:00:00:14 dev swp4 vlan 1000 master br_default\n")
        if command == ("bridge", "vlan", "show"):
            return ("port vlan-id\nswp1 1000 PVID Egress Untagged\nswp2 1000 PVID Egress Untagged\n"
                    "swp3 1000 PVID Egress Untagged\nswp4 1000 PVID Egress Untagged\n")
        if command == ("ip", "neighbor"):
            return ""  # CSV MAC/EUI64, not ND or HTML, owns each IB endpoint.
        if command == ("ip", "-j", "address", "show"):
            return '[{"ifname":"ib-mgmt1000","flags":["UP"],"operstate":"UP","addr_info":[{"family":"inet","local":"203.0.113.1","prefixlen":24,"scope":"global"},{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}]'
        if command == ("ifquery", "ib-mgmt1000"):
            return "iface ib-mgmt1000\n    vrf oob\n"
        raise AssertionError("five-device model refused an unknown OOB command")

    def _frame(self, argv):
        # Decode shell quoting as DATA, never execute it. The only accepted leaf
        # is a complete original nonce frame; unknown/duplicate frames fail.
        candidates = []
        def visit(text, depth):
            if depth > 9:
                return
            match = FRAME.fullmatch(text)
            if match:
                self.test.assertEqual(match[1], match[3])
                candidates.append((match[1], tuple(shlex.split(match[2]))))
                return
            if text.startswith(SAFE_PREFIX):
                text = text[len(SAFE_PREFIX):]
            try:
                words = shlex.split(text)
            except ValueError:
                return
            for word in words:
                if word != text and ("__HTTP_IB_BEGIN_" in word or "export PATH=" in word):
                    visit(word, depth + 1)
        for value in argv:
            visit(value, 0)
        self.test.assertEqual(1, len(candidates), "one complete command frame is required")
        return candidates[0]

    def _reply(self, name, command):
        self.events.append((name, command))
        if command == ("nv", "config", "show", "-o", "commands"):
            return self.configuration(name), 0
        if command == ("ip", "addr", "show", "eth0"):
            index = NAMES.index(name) + 11
            # O5 matches MAC even on the independently conflicting NVUE device;
            # conflict handling, not a fabricated login mismatch, owns that case.
            return (f"2: eth0: <UP> mtu 1500\n    link/ether 02:00:00:00:00:{index+6:02x}\n"
                    f"    inet 203.0.113.{index}/24 scope global eth0\n"), 0
        if command == ("ip", "route"):
            return "default via 203.0.113.1 dev eth0\n", 0
        if command == ("nv", "show", "system", "ztp"):
            return ("service disabled\nstatus " + ("success" if name == NAMES[3] else "aborted")
                    + "\nconfig-save enabled enabled\n"), 0
        if command == ("nv", "config", "diff", "-o", "commands"):
            self.test.assertEqual([], self.pending[name])
            return "", 0
        if command == ("true",):
            return "", 0
        if len(command) == 5 and command[:2] == ("sh", "-c") and command[3] == "--":
            if command[2] == EXPECTED_BACKUP_SCRIPT:
                self.test.assertRegex(command[4], r"^[0-9]{8}-[0-9]{6}$")
                return f"path=/home/admin/current_{command[4]}.yaml\nbytes=137\n", 0
            self.test.assertEqual(self.key_payload, command[4], "only the independent PUBLIC key payload is allowed")
            if command[2] == EXPECTED_READONLY_KEY_SCRIPT:
                return "", 0 if self.keys_present[name] else 34
            if command[2] == EXPECTED_INSTALL_KEY_SCRIPT:
                changed = not self.keys_present[name]
                self.keys_present[name] = True
                return "IBSW_PUBLIC_KEYS_" + ("UPDATED" if changed else "UNCHANGED") + "\n", 0
            raise AssertionError("five-device model refused an unknown closed shell")
        setters = {
            ("nv", "set", "system", "config", "auto-save", "state", "enabled"),
            ("nv", "set", "system", "ztp", "config-save", "enabled"),
            ("nv", "set", "interface", "eth0-1", "link", "state", "up"),
            ("nv", "set", "interface", "eth0-1", "type", "eth"),
            ("nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.11/24"),
            ("nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"),
            ("nv", "set", "system", "hostname", "EXAMPLE-IB001"),
            ("nv", "set", "system", "dns", "server", "203.0.113.53"),
            ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
            ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
            ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"),
        }
        if command in setters:
            self.test.assertIn(name, (NAMES[0], NAMES[3]), "only the independently incomplete devices may write")
            self.pending[name].append(command)
            return "", 0
        if command == ("nv", "config", "apply", "-y"):
            for setter in self.pending[name]:
                row = shlex.join(setter)
                if setter[:5] == ("nv", "set", "system", "date-time", "timezone"):
                    self.rows[name] = [old for old in self.rows[name]
                                       if not old.startswith("nv set system date-time timezone ")]
                if setter[:4] == ("nv", "set", "system", "hostname"):
                    self.rows[name] = [old for old in self.rows[name]
                                       if not old.startswith("nv set system hostname ")]
                if setter[:5] == ("nv", "set", "system", "ntp", "server"):
                    row += " state enabled"
                if row not in self.rows[name]:
                    self.rows[name].append(row)
            self.pending[name].clear()
            return "", 0
        if command == ("nv", "config", "save"):
            return "", 0
        raise AssertionError("five-device model refused an unknown IB command")

    def _carrier(self, argv, responder, timeout):
        if argv[:2] == ["sh", "-c"]:
            phase = getattr(responder, "_phase", None)
            self.test.assertIs(type(phase), self.app._IBPhase)
            self.test.assertEqual(("auth-probe-readonly", "", "admin@203.0.113.15"),
                                 (phase.operation, phase.outer_endpoint, phase.endpoint))
            self.test.assertEqual(phase.endpoint, responder.ib_destination)
            self.test.assertRegex(phase.nonce, r"^[0-9a-f]{32}$")
            self.test.assertEqual(60, timeout)
            nonce = phase.nonce
            # Independent protocol literals, never a SUT argv/script builder.
            read = (r'printf "\n__HTTP_IB_BEGIN_' + nonce + r'__\n"; nv config show -o commands; '
                    r'task_rc=$?; printf "\n__HTTP_IB_END_' + nonce
                    + r'__=%s\n" "$task_rc"; exit "$task_rc"')
            expected_inner = ["ssh", "-4", "-tt", "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
                "-o", "ControlMaster=no", "-o", "ControlPath=none",
                "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                "admin@203.0.113.15", shlex.join(["sh", "-c", read])]
            begin = r'printf "\n__HTTP_IB_AUTH_' + nonce + r'_auth-probe-readonly__=BEGIN\n"; '
            end = (r'; inner_rc=$?; printf "\n__HTTP_IB_AUTH_' + nonce
                   + r'_auth-probe-readonly__=EXIT:%s\n" "$inner_rc"; exit "$inner_rc"')
            self.test.assertEqual(["sh", "-c", begin + shlex.join(expected_inner) + end], argv)
            # Parse the admitted ACTUAL carrier as data; never run the wrapper.
            return shlex.split(argv[2][len(begin):-len(end)])
        self.test.assertEqual("ssh", argv[0])
        phase = getattr(responder, "_phase", None)
        if phase is not None or any("__HTTP_IB_AUTH_" in word for word in argv):
            self.test.assertIs(type(phase), self.app._IBPhase)
            self.test.assertEqual("auth-probe-readonly", phase.operation)
            self.test.assertEqual("cumulus@192.0.2.10", phase.outer_endpoint)
            self.test.assertEqual(phase.endpoint, responder.ib_destination)
            self.test.assertIn(phase.endpoint, ("admin@fe80::ff:fe00:11", "admin@fe80::ff:fe00:12",
                                                 "admin@fe80::ff:fe00:13", "admin@fe80::ff:fe00:14"))
            self.test.assertIsNotNone(re.fullmatch(r"[0-9a-f]{32}", phase.nonce))
            self.test.assertEqual(60, timeout)
            nonce = phase.nonce
            read = (r'printf "\n__HTTP_IB_BEGIN_' + nonce + r'__\n"; nv config show -o commands; '
                    r'task_rc=$?; printf "\n__HTTP_IB_END_' + nonce
                    + r'__=%s\n" "$task_rc"; exit "$task_rc"')
            expected_nested = ["ip", "vrf", "exec", "oob", "ssh", "-6", "-tt",
                "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "LogLevel=ERROR", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                "-B", "ib-mgmt1000", phase.endpoint, shlex.join(["sh", "-c", read])]
            begin = r'printf "\n__HTTP_IB_AUTH_' + nonce + r'_auth-probe-readonly__=BEGIN\n"; '
            end = (r'; inner_rc=$?; printf "\n__HTTP_IB_AUTH_' + nonce
                   + r'_auth-probe-readonly__=EXIT:%s\n" "$inner_rc"; exit "$inner_rc"')
            expected_program = begin + shlex.join(expected_nested) + end
            expected = ["ssh", "-tt", "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                "-o", "ControlMaster=no", "-o", "ControlPath=none", "cumulus@192.0.2.10",
                shlex.join(["sh", "-c", SAFE_PREFIX + shlex.join(["sh", "-c", expected_program])])]
            self.test.assertEqual(expected, argv)
            # Only after COMPLETE qualification, remove exact AUTH boundaries
            # before tokenizing the actual inner data (never strip semicolons).
            outer = shlex.split(argv[-1])
            auth = shlex.split(outer[2][len(SAFE_PREFIX):])
            nested = shlex.split(auth[2][len(begin):-len(end)])
            self.test.assertEqual(expected_nested, nested)
            return [*argv[:-1], *nested]
        return argv

    def transport(self, argv, responder, timeout, **options):
        carrier = self._carrier(argv, responder, timeout)
        destination = responder.ib_destination
        self.test.assertTrue(type(destination) is str and destination.startswith("admin@"))
        peer = destination[len("admin@"):]
        self.test.assertIn(peer, self.endpoints)
        name = self.endpoints[peer]
        is_jump = "cumulus@192.0.2.10" in carrier
        if peer.startswith("fe80:"):
            self.test.assertTrue(is_jump)
        else:
            self.test.assertTrue(is_jump or "admin@" + peer in carrier)
        marker, command = self._frame(carrier)
        phase = getattr(responder, "_phase", None)
        session = ""
        reader = writer = None
        try:
            if phase is not None:
                self.test.assertEqual("auth-probe-readonly", phase.operation)
                self.test.assertEqual(marker, phase.nonce)
                self.test.assertEqual(destination, phase.endpoint)
                session = f"\n__HTTP_IB_AUTH_{marker}_auth-probe-readonly__=BEGIN\n"
                phase.observe(session)
            session += destination + "'s password: "
            if phase is not None:
                phase.observe(session)
            reply = responder(session)
            self.test.assertTrue(type(reply) is str and hmac.compare_digest(reply, self.kat["PASSWORD"]),
                                 "the authenticated IB phase must use the original selected credential")
            if phase is not None:
                reader, writer = os.pipe()
                phase.write_reply(writer, reply, responder, time.monotonic() + 60)
                os.read(reader, 8192)
            body, status = self._reply(name, command)
            session += f"\n__HTTP_IB_BEGIN_{marker}__\n{body}__HTTP_IB_END_{marker}__={status}\n"
            if phase is not None:
                session += f"__HTTP_IB_AUTH_{marker}_auth-probe-readonly__=EXIT:{status}\n"
                phase.observe(session)
            return self.app.SessionResult(session, status)
        finally:
            for descriptor in (reader, writer):
                if descriptor is not None:
                    os.close(descriptor)


class BringupResultsWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_script("wp6_five_results_workflow_source", INITIAL)

    def run_five(self, *, apply):
        app = self.app
        kat = strict_kat(app)  # Original reader/native qualification, never a stub.
        world = _FiveDevices(self, app, kat)
        with tempfile.TemporaryDirectory(prefix="wp6-five-results-") as directory, ExitStack() as stack:
            root = Path(directory)
            home = root / "home"
            home.mkdir(mode=0o700)
            (root / "ib.csv").write_text(CSV_HEADER + CSV_ROWS, encoding="ascii")
            (root / "02-devices_config.csv").write_text(CSV_HEADER + MASTER_ROWS, encoding="ascii")
            (root / "p2p.dot").write_text(P2P, encoding="ascii")
            global_path = root / "01-global.yaml"
            global_path.write_text(strict_global_text(kat), encoding="utf-8")
            global_path.chmod(0o600)
            (root / "required.pub").write_text(world.public_line + "\n", encoding="ascii")
            neutral = root / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
            neutral.parent.mkdir(parents=True)
            neutral.write_text("DNS=192.0.2.53\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n", encoding="ascii")
            report = root / "out" / "report.log"
            argv = [str(INITIAL), "--project-dir", str(root), "--ib-csv", str(root / "ib.csv"),
                    "--p2p", str(root / "p2p.dot"), "--target-cache", str(root / "targets.json"),
                    "--report", str(report), "--snapshot-dir", str(root / "snapshots"),
                    "--execution-mode", "management", "--devices", "EXAMPLE-IB00[1-5]"]
            if apply:
                argv += ["--apply", "--yes"]
            fd_options = stack.enter_context(credentials_fd(strict_fd_payload(kat)))
            argv += fd_options
            original_run = app.subprocess.run
            def admitted_local(argv, **options):
                vector = tuple(argv)
                native = (sys.executable, "-I", "-S", "-B", str(INITIAL.resolve()), "--_verify-password")
                # Exact original public validator has six words, not a shell.
                validator = len(vector) == 6 and vector[1:] == ("-l", "-E", "sha256", "-f", "/dev/stdin")
                if vector == native:
                    self.assertEqual(8, options.get("timeout"))
                    self.assertNotIn("HOME", options.get("env", {}))
                elif validator:
                    self.assertEqual("ssh-keygen", Path(vector[0]).name)
                    self.assertEqual(10, options.get("timeout"))
                    self.assertEqual(world.public_line + "\n", options.get("input"))
                else:
                    raise AssertionError("five-device workflow refused an unadmitted local child")
                return original_run(list(vector), **options)
            def deny(*unused, **ignored):
                raise AssertionError("five-device workflow refused an unmodeled external effect")
            real_permit = app.obtain_write_permit
            def permit(category):
                world.permits.append(category)
                return real_permit(category)
            real_readiness = app.verify_ipv4_login
            real_direct_readiness = app._wait_direct_ipv4_readback
            def readiness(target, *arguments, **options):
                world.readiness.append((target.ib.hostname, options["readiness_policy"].first_delay))
                return real_readiness(target, *arguments, **options)
            def direct_readiness(target, *arguments, **options):
                world.readiness.append((target.ib.hostname, options["readiness_policy"].first_delay))
                return real_direct_readiness(target, *arguments, **options)
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
            stack.enter_context(mock.patch.object(Path, "home", return_value=home))
            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(mock.patch.object(app, "_new_jump_sessions", legacy_jump_sessions_factory(app)))
            stack.enter_context(mock.patch.object(app, "probe_ethernet_key", return_value="key"))
            stack.enter_context(mock.patch.object(app, "run_on_ethernet", side_effect=world.ethernet))
            stack.enter_context(mock.patch.object(app, "interactive_run", side_effect=world.transport))
            stack.enter_context(mock.patch.object(app, "_read_local_interfaces", return_value=()))
            stack.enter_context(mock.patch.object(app, "obtain_write_permit", side_effect=permit))
            stack.enter_context(mock.patch.object(app, "verify_ipv4_login", side_effect=readiness))
            stack.enter_context(mock.patch.object(app, "_wait_direct_ipv4_readback", side_effect=direct_readiness))
            stack.enter_context(mock.patch.object(app, "time", SimpleNamespace(
                monotonic=time.monotonic, time=time.time, strftime=time.strftime,
                sleep=lambda seconds: world.delays.append(seconds))))
            stack.enter_context(mock.patch.object(app, "subprocess", SimpleNamespace(
                run=admitted_local, Popen=deny, TimeoutExpired=subprocess.TimeoutExpired,
                SubprocessError=subprocess.SubprocessError, PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL)))
            console, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(console), redirect_stderr(errors):
                code = app._standalone_main_with_report_cleanup()
            summaries = list(report.parent.rglob("summary.json"))
            self.assertEqual(1, len(summaries), "exactly one own-run summary must be saved")
            evidence = json.loads(summaries[0].read_text(encoding="utf-8"))
            self.assertTrue(app.REPORT_HANDLE is not None and app.REPORT_HANDLE.closed is True)
            self.assertEqual(report.resolve(), Path(app.REPORT_HANDLE.name).resolve())
            report_text = report.read_text(encoding="utf-8")
            for value in (kat["PASSWORD"], kat["YESCRYPT"]):
                self.assertFalse(value in console.getvalue() or value in errors.getvalue() or value in report_text,
                                 "private qualification data must not enter diagnostics")
            per_device = [json.loads(path.read_text(encoding="utf-8")) for path in summaries[0].parent.glob("*.json")
                          if path.name != "summary.json"]
            return code, evidence, console.getvalue(), report_text, world, per_device

    def check_common(self, code, evidence, console, report, world, per_device, *, apply):
        self.assertEqual(2, code, world.public_failure_note(evidence))
        self.assertEqual("INCOMPLETE", evidence["result"])
        self.assertEqual(1, evidence["schema_version"])
        # A.11: the actual check/apply summary reports this frozen release identity.
        self.assertEqual("http-v3.1.5", evidence["revision"])
        self.assertEqual("patch", evidence["config_mode"])
        self.assertEqual({"selector": "EXAMPLE-IB00[1-5]", "selected": NAMES, "unmapped": []}, evidence["selection"])
        self.assertEqual(5, evidence["csv_ib_candidates"])
        self.assertEqual(5, evidence["p2p_management_targets"])
        self.assertEqual(1, evidence["workers"])
        records = evidence["records"]
        self.assertEqual(NAMES, sorted(item["hostname"] for item in records.values()))
        self.assertEqual({name.lower(): "patch" for name in NAMES},
                         {name: row["config_mode"] for name, row in records.items()})
        self.assertEqual(NAMES, sorted(item["hostname"] for item in per_device))
        self.assertEqual("direct", evidence["routes"][NAMES[4]]["path"])
        self.assertIsNone(evidence["routes"][NAMES[4]]["jump"])
        self.assertIn((NAMES[4], ("ip", "route")), world.events)
        self.assertIn("TOTAL: 5", console)
        self.assertIn("TOTAL: 5", report)
        expected_need = [True, False, True, True, False]
        expected_verified = [apply, True, False, apply, True]
        expected_categories = ["CHECKED_AND_CONFIGURED" if apply else "CHECKED_NEEDS_CONFIGURATION",
                               "CHECKED_EXISTING_KEYS_VERIFIED" if apply else "CHECKED_EXISTING_CONFIGURATION",
                               "BLOCKED_NETWORK_CONFLICT",
                               "CHECKED_AND_CONFIGURED" if apply else "CHECKED_NEEDS_CONFIGURATION",
                               "CHECKED_EXISTING_KEYS_VERIFIED" if apply else "CHECKED_EXISTING_CONFIGURATION"]
        expected_attention = [None if apply else "CHECKED_NEEDS_CONFIGURATION", None,
                              "BLOCKED_NETWORK_CONFLICT", None if apply else "CHECKED_NEEDS_CONFIGURATION", None]
        for name, needed, verified, category, attention in zip(
                NAMES, expected_need, expected_verified, expected_categories, expected_attention):
            record = records[name.casefold()]
            self.assertEqual("factory" if name == NAMES[0] else "existing", record["device_state"])
            self.assertEqual("patch", record["config_mode"])
            self.assertIs(record["needs_change"], needed)
            self.assertIs(record["verified_complete"], verified)
            self.assertEqual(category, record["category"])
            self.assertEqual(attention, record["attention_category"])
            self.assertIs(record["identity"]["ok"], True)
            self.assertEqual({"read": True, "service": "disabled",
                              "status": "success" if name == NAMES[3] else "aborted",
                              "provisioned": name == NAMES[3] if name != NAMES[0] else None}, record["ztp"])
            for entry in record["existing_configuration"]:
                self.assertEqual({"item", "relation", "value"}, set(entry))
                self.assertIn(entry["relation"], ("same", "extra", "overwritten"))
                self.assertIs(type(entry["value"]), str)
            for entry in record["planned_changes"]:
                self.assertEqual({"item", "value"}, set(entry))
                self.assertIs(type(entry["value"]), str)
            observed = [command for peer, command in world.events if peer == name]
            self.assertEqual(2 if apply and name == NAMES[0] else 1,
                             observed.count(("nv", "show", "system", "ztp")),
                             "reuse the first read; preserve the second read after Initial writes")
            self.assertLess(observed.index(("ip", "addr", "show", "eth0")),
                            observed.index(("nv", "show", "system", "ztp")))
            self.assertEqual(record, next(item for item in per_device if item["hostname"] == name))
        attention_by_device = {device["hostname"]: group["category"]
                               for group in evidence["summary"]["attention"] for device in group["devices"]}
        self.assertEqual({name: category for name, category in zip(NAMES, expected_attention) if category is not None},
                         attention_by_device)
        conflict = records[NAMES[2].casefold()]
        self.assertEqual("FAILED", conflict["outcome"])
        self.assertEqual("BLOCKED_NETWORK_CONFLICT", conflict["category"])
        self.assertIs(conflict["writes_attempted"], False)
        self.assertIsNone(conflict["backup"])
        self.assertEqual([{"field": "eth0 address", "expected": "203.0.113.13/24",
                           "actual": ["198.51.100.13/24"]}], conflict["conflicts"])
        conflict_events = [command for peer, command in world.events if peer == NAMES[2]]
        self.assertFalse(any(command[:2] == ("nv", "set") or command[:2] == ("sh", "-c")
                             for command in conflict_events))
        self.assertNotIn("management network", conflict["reason"].casefold())
        self.assertNotIn("203.0.113.13/24", conflict["reason"])
        self.assertNotIn("198.51.100.13/24", conflict["reason"])
        conflict_lines = [line for line in report.splitlines() if "CONFLICT" in line and "198.51.100.13/24" in line]
        self.assertTrue(conflict_lines)
        self.assertTrue(any("203.0.113.13/24" in line for line in conflict_lines))
        self.assertFalse(any("management network" in line.casefold() for line in conflict_lines))
        existing = records[NAMES[1].casefold()]["existing_configuration"]
        self.assertIn(("dns", "198.51.100.53", "extra"),
                      [(entry["item"], entry["value"], entry["relation"]) for entry in existing])
        self.assertIn(("dns", "203.0.113.53", "same"),
                      [(entry["item"], entry["value"], entry["relation"]) for entry in existing])
        self.assertIn(("ntp", "time.extra.example.test", "extra"),
                      [(entry["item"], entry["value"], entry["relation"]) for entry in existing])
        tz = records[NAMES[3].casefold()]
        self.assertIn(("timezone", "Etc/UTC", "overwritten"),
                      [(entry["item"], entry["value"], entry["relation"]) for entry in tz["existing_configuration"]])
        self.assertIn(("timezone", "Asia/Taipei"), [(entry["item"], entry["value"]) for entry in tz["planned_changes"]])
        factory_plan = records[NAMES[0].casefold()]["planned_changes"]
        for expected in (("hostname", "EXAMPLE-IB001"), ("eth0 address", "203.0.113.11/24"),
                         ("eth0 gateway", "203.0.113.1"), ("dns", "203.0.113.53"),
                         ("ntp", "ntp.ubuntu.com"), ("ntp", "time.ib.example.test"),
                         ("timezone", "Asia/Taipei")):
            self.assertIn(expected, [(entry["item"], entry["value"]) for entry in factory_plan])
        self.assertIn(("public_keys", "append missing required public keys"),
                      [(entry["item"], entry["value"]) for entry in factory_plan])
        self.assertFalse(any(entry["item"] == "public_keys" for entry in records[NAMES[1].casefold()]["planned_changes"]))
        for name in (NAMES[1], NAMES[4]):
            self.assertEqual([], records[name.casefold()]["planned_changes"])
            commands = [command for peer, command in world.events if peer == name]
            readonly = ("sh", "-c", EXPECTED_READONLY_KEY_SCRIPT, "--", world.key_payload)
            installer = ("sh", "-c", EXPECTED_INSTALL_KEY_SCRIPT, "--", world.key_payload)
            if not apply:
                self.assertIn(readonly, commands)
                self.assertEqual(1, commands.count(readonly))
                self.assertFalse(any(command[:3] == ("sh", "-c", EXPECTED_INSTALL_KEY_SCRIPT) for command in commands))
            else:
                self.assertNotIn(readonly, commands)
                self.assertEqual(1, commands.count(installer))
                record = records[name.casefold()]
                self.assertEqual("UNCHANGED", record["public_key_update"]["content_action"])
                self.assertIs(record["writes_attempted"], True)
                for metric in ("public_key_install_attempts", "public_key_install_completed",
                               "public_key_content_unchanged"):
                    self.assertEqual(1, record["metrics"].get(metric, 0))
                for metric in ("nvue_write_commands", "password_change_sessions", "config_backup_attempts"):
                    self.assertEqual(0, record["metrics"].get(metric, 0))
                self.assertFalse(any(command[:2] == ("nv", "set")
                                     or command[:3] in (("nv", "config", "apply"), ("nv", "config", "save"))
                                     or command[:3] == ("sh", "-c", EXPECTED_BACKUP_SCRIPT)
                                     for command in commands))
            self.assertIsNone(records[name.casefold()]["backup"])
        writes = [(peer, command) for peer, command in world.events
                  if command[:2] == ("nv", "set") or command[:2] == ("sh", "-c")
                  and command[2] != EXPECTED_READONLY_KEY_SCRIPT]
        if not apply:
            self.assertEqual([], writes)
            self.assertEqual([], world.permits)
            self.assertEqual([], world.delays)
            self.assertEqual([], world.readiness)
            self.assertTrue(all(record["backup"] is None for record in records.values()))
        else:
            for name in (NAMES[0], NAMES[3]):
                receipt = records[name.casefold()]["backup"]
                self.assertEqual(137, receipt["bytes"])
                self.assertRegex(receipt["path"], r"^/home/admin/current_[0-9]{8}-[0-9]{6}\.yaml$")
                commands = [command for peer, command in world.events if peer == name]
                backup_index = next(index for index, command in enumerate(commands)
                                    if command[:3] == ("sh", "-c", EXPECTED_BACKUP_SCRIPT))
                setter_index = next(index for index, command in enumerate(commands) if command[:2] == ("nv", "set"))
                self.assertLess(backup_index, setter_index)
                self.assertEqual(1, sum(command[:3] == ("sh", "-c", EXPECTED_BACKUP_SCRIPT) for command in commands))
            self.assertGreater(len(world.permits), 0)
            self.assertEqual([(NAMES[0], 15), (NAMES[1], 0), (NAMES[3], 0), (NAMES[4], 0)],
                             sorted(world.readiness))
            self.assertIn("EXAMPLE-IB002", report)
            self.assertIn("no initial wait", report)
        return records

    def test_check_five_devices_preserves_initial_facts_and_real_direct_target(self):
        result = self.run_five(apply=False)
        self.check_common(*result, apply=False)

    def test_apply_five_devices_preserves_plan_and_verifies_only_completed_devices(self):
        result = self.run_five(apply=True)
        self.check_common(*result, apply=True)

    def test_direct_phase_carrier_admission_rejects_near_misses_without_io(self):
        # Pure model control: no KAT/native/credential input, phase execution or
        # pipe is used. The real phase object only supplies its inert metadata.
        nonce = "0123456789abcdef0123456789abcdef"
        phase = self.app._IBPhase(nonce, "auth-probe-readonly", "admin@203.0.113.15", "", None)
        responder = SimpleNamespace(_phase=phase, ib_destination="admin@203.0.113.15")
        world = _FiveDevices(self, self.app, {})
        read = (r'printf "\n__HTTP_IB_BEGIN_0123456789abcdef0123456789abcdef__\n"; '
                r'nv config show -o commands; task_rc=$?; '
                r'printf "\n__HTTP_IB_END_0123456789abcdef0123456789abcdef__=%s\n" '
                r'"$task_rc"; exit "$task_rc"')
        inner = ["ssh", "-4", "-tt", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "admin@203.0.113.15", shlex.join(["sh", "-c", read])]
        wrapper = (r'printf "\n__HTTP_IB_AUTH_0123456789abcdef0123456789abcdef_auth-probe-readonly__=BEGIN\n"; '
                   + shlex.join(inner)
                   + r'; inner_rc=$?; printf "\n__HTTP_IB_AUTH_0123456789abcdef0123456789abcdef_auth-probe-readonly__=EXIT:%s\n" "$inner_rc"; exit "$inner_rc"')
        admitted = ["sh", "-c", wrapper]
        self.assertEqual(inner, world._carrier(admitted, responder, 60))
        bad = (["sh", "-c", "true"], ["sh", "-c", wrapper + "; true"],
               ["sh", "-c", wrapper, "extra"], ["bash", "-c", wrapper],
               ["sh", "-c", wrapper.replace("203.0.113.15", "203.0.113.14")],
               ["sh", "-c", wrapper.replace("ProxyJump=none", "ProxyJump=foreign")],
               ["sh", "-c", wrapper.replace("nv config show -o commands", "nv config save")],
               ["sh", "-c", wrapper.replace(nonce, "f" * 32, 1)])
        for number, vector in enumerate(bad):
            with self.subTest(near_miss=number), self.assertRaises(AssertionError):
                world._carrier(vector, responder, 60)
        for invalid in (SimpleNamespace(ib_destination=phase.endpoint),
                        SimpleNamespace(_phase=SimpleNamespace(), ib_destination=phase.endpoint)):
            with self.subTest(metadata="invalid"), self.assertRaises(AssertionError):
                world._carrier(admitted, invalid, 60)
        with self.assertRaises(AssertionError):
            world._carrier(admitted, responder, 59)
        self.assertEqual([], world.events)
        self.assertEqual([], world.permits)
        self.assertEqual(0, phase.current_done)

    def test_jump_phase_carrier_admission_rejects_near_misses_without_io(self):
        nonce = "0123456789abcdef0123456789abcdef"
        world = _FiveDevices(self, self.app, {})
        # Four fixed PUBLIC peers; the independent vector is not a SUT builder.
        for peer in ("admin@fe80::ff:fe00:11", "admin@fe80::ff:fe00:12",
                     "admin@fe80::ff:fe00:13", "admin@fe80::ff:fe00:14"):
            with self.subTest(peer=peer):
                phase = self.app._IBPhase(nonce, "auth-probe-readonly", peer, "cumulus@192.0.2.10", None)
                responder = SimpleNamespace(_phase=phase, ib_destination=peer)
                read = (r'printf "\n__HTTP_IB_BEGIN_0123456789abcdef0123456789abcdef__\n"; '
                        r'nv config show -o commands; task_rc=$?; '
                        r'printf "\n__HTTP_IB_END_0123456789abcdef0123456789abcdef__=%s\n" '
                        r'"$task_rc"; exit "$task_rc"')
                nested = ["ip", "vrf", "exec", "oob", "ssh", "-6", "-tt",
                    "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "LogLevel=ERROR", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                    "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
                    "-o", "PreferredAuthentications=password,keyboard-interactive",
                    "-B", "ib-mgmt1000", peer, shlex.join(["sh", "-c", read])]
                program = (r'printf "\n__HTTP_IB_AUTH_0123456789abcdef0123456789abcdef_auth-probe-readonly__=BEGIN\n"; '
                           + shlex.join(nested)
                           + r'; inner_rc=$?; printf "\n__HTTP_IB_AUTH_0123456789abcdef0123456789abcdef_auth-probe-readonly__=EXIT:%s\n" "$inner_rc"; exit "$inner_rc"')
                outer = ["ssh", "-tt", "-o", "ConnectTimeout=10",
                    "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
                    "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                    "-o", "ControlMaster=no", "-o", "ControlPath=none", "cumulus@192.0.2.10",
                    shlex.join(["sh", "-c", SAFE_PREFIX + shlex.join(["sh", "-c", program])])]
                carrier = world._carrier(outer, responder, 60)
                self.assertEqual([*outer[:-1], *nested], carrier)
                self.assertEqual((nonce, ("nv", "config", "show", "-o", "commands")), world._frame(carrier))
                bad = ([*outer[:-1], outer[-1] + "; true"],
                       [*outer[:-1], outer[-1].replace("ib-mgmt1000", "foreign-svi")],
                       [*outer[:-1], outer[-1].replace("exec oob", "exec default")],
                       [*outer[:-1], outer[-1].replace(peer, "admin@fe80::ff:fe00:99")],
                       [*outer[:-1], outer[-1].replace("nv config show -o commands", "nv config save")],
                       [*outer[:-1], outer[-1].replace(nonce, "f" * 32, 1)],
                       ["ServerAliveCountMax=3" if item == "ServerAliveCountMax=2" else item for item in outer],
                       ["cumulus@192.0.2.11" if item == "cumulus@192.0.2.10" else item for item in outer])
                for number, vector in enumerate(bad):
                    with self.subTest(near_miss=number), self.assertRaises(AssertionError):
                        world._carrier(vector, responder, 60)
                invalid = [SimpleNamespace(ib_destination=peer),
                           SimpleNamespace(_phase=SimpleNamespace(), ib_destination=peer)]
                for operation, endpoint, jump in (("password-change", peer, "cumulus@192.0.2.10"),
                         ("auth-probe-readonly", "admin@fe80::ff:fe00:99", "cumulus@192.0.2.10"),
                         ("auth-probe-readonly", peer, "cumulus@192.0.2.11")):
                    wrong = self.app._IBPhase(nonce, operation, endpoint, jump, None)
                    invalid.append(SimpleNamespace(_phase=wrong, ib_destination=endpoint))
                malformed = self.app._IBPhase(nonce, "auth-probe-readonly", peer, "cumulus@192.0.2.10", None)
                malformed.nonce += "\n"
                invalid.append(SimpleNamespace(_phase=malformed, ib_destination=peer))
                for number, metadata in enumerate(invalid):
                    with self.subTest(metadata=number), self.assertRaises(AssertionError):
                        world._carrier(outer, metadata, 60)
                with self.assertRaises(AssertionError):
                    world._carrier(outer, responder, 59)
                self.assertEqual(0, phase.current_done)
        self.assertEqual([], world.events)
        self.assertEqual([], world.permits)


"""r757 managed two-select-one workflow; independent PUBLIC oracle; NOT RUN.

Real MAIN, hostname_ranges, device_identity, authority, complete cache/profile,
strict policy/native/helper and own-session observer remain in the chain.
Existing strict_management_boundary models only its documented private phase
and ordinary device transport; this is NOT another PTY/frame-authentication
proof. The observer's lowest external transport returns a fixed PUBLIC wire,
after exact BatchMode vector/held-FD admission. No SSH/key-install shell runs.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import unittest
from unittest import mock

from test_cases import test_initial_setup_bringup_results as direct
from test_cases import test_req10b_services_keys_workflow as original
from test_cases.initial_setup_jump_fixture import legacy_jump_sessions_factory
from test_cases.module_loader import load_script


INITIAL = direct.INITIAL
AUTHORITY = INITIAL.parents[3] / "ztp/config_sync_authority.py"
HOST = "EXAMPLE-IB01"
STATE = (
    "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
    "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
    "nv set interface eth0-1 link state up\n"
    "nv set interface eth0-1 type eth\n"
    "nv set system hostname EXAMPLE-IB01\n"
    "nv set system config auto-save state enabled\n"
    "nv set system ztp config-save enabled\n"
    "nv set system dns server 203.0.113.53\n"
    "nv set system ntp server ntp.ubuntu.com\n"
    "nv set system ntp server time.ib.example.test\n"
    "nv set system date-time timezone Asia/Taipei\n"
)
# Independent original immutable observer command; never fetched from a SUT constant.
OBSERVATION_SCRIPT = (
    "set -eu; printf '__HTTP_INITIAL_METHOD_V1_IDENTITY_BEGIN__\\n'; "
    "hostname; cat /sys/class/net/eth0/address; "
    "printf '__HTTP_INITIAL_METHOD_V1_IDENTITY_END__\\n'; "
    "printf '__HTTP_INITIAL_METHOD_V1_CONFIG_BEGIN__\\n'; "
    "set +e; nv config show -o commands; rc=$?; set -e; "
    "printf '__HTTP_INITIAL_METHOD_V1_CONFIG_END__=%s\\n' \"$rc\"; "
    "printf '__HTTP_INITIAL_METHOD_V1_KEYS_BEGIN__\\n'; "
    "test -n \"${HOME:-}\" && test ! -L \"$HOME/.ssh\" && "
    "test ! -L \"$HOME/.ssh/authorized_keys\" && test -f \"$HOME/.ssh/authorized_keys\"; "
    "set +e; cat \"$HOME/.ssh/authorized_keys\"; rc=$?; set -e; "
    "printf '__HTTP_INITIAL_METHOD_V1_KEYS_END__=%s\\n' \"$rc\""
)


class ManagedSelectionWorkflowTests(unittest.TestCase):
    def setup_helper(self):
        helper = direct.ManagedSelectionTests()
        helper.app = load_script("wp6_managed_selection_main", INITIAL)
        helper.authority = load_script("wp6_managed_selection_main_authority", AUTHORITY)
        return helper

    def run_managed(self, helper, f, label, *, drift=False):
        app, authority = helper.app, helper.authority
        cycle = authority.ManagedInitialMethodCycle(f["root"], app)
        output, errors, calls, entered = io.StringIO(), [], [], set()
        private = f["root"] / ".ssh/id_ed25519"
        private.parent.mkdir(mode=0o700, exist_ok=True)
        if not private.exists():
            private.write_text("PUBLIC owned non-key transport sentinel\n", encoding="ascii")
            private.chmod(0o600)
        key_lines = (f["laptop"].strip(), f["management"].strip())
        payload = base64.b64encode(("\n".join(key_lines) + "\n").encode("ascii")).decode("ascii")
        wire = ("__HTTP_INITIAL_METHOD_V1_IDENTITY_BEGIN__\nEXAMPLE-IB01\n02:00:00:00:00:01\n"
                "__HTTP_INITIAL_METHOD_V1_IDENTITY_END__\n__HTTP_INITIAL_METHOD_V1_CONFIG_BEGIN__\n"
                + STATE + "__HTTP_INITIAL_METHOD_V1_CONFIG_END__=0\n"
                "__HTTP_INITIAL_METHOD_V1_KEYS_BEGIN__\n" + "\n".join(key_lines) + "\n"
                "__HTTP_INITIAL_METHOD_V1_KEYS_END__=0\n")
        report = f["root"] / "out" / label / "report.log"
        report.parent.mkdir()
        kat = original.strict_kat(app)  # ORIGINAL qualified reader/8-second worker, future only.
        real_run = subprocess.run

        def guarded(callback):
            def run(*args, **kwargs):
                try:
                    return callback(*args, **kwargs)
                except BaseException as error:
                    errors.append(error)
                    raise
            return run

        def ib_transport(*args, **kwargs):
            self.assertEqual(HOST, args[0].ib.hostname)
            command = list(args[7])
            pending = authority.read_method_current(cycle.root, HOST)
            self.assertEqual(("pending", True), (pending["state"], pending["veto"]))
            if command == ["nv", "config", "show", "-o", "commands"]:
                body = STATE
            elif command == ["nv", "config", "diff", "-o", "commands"]:
                body = ""
            elif command == ["nv", "show", "system", "ztp"]:
                body = "service disabled\nstate disabled\nstatus aborted\n"
            elif command == ["ip", "addr", "show", "eth0"]:
                body = ("2: eth0: <UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n")
            elif command == ["sh", "-c", direct.EXPECTED_INSTALL_KEY_SCRIPT, "--", payload]:
                body = "IBSW_PUBLIC_KEYS_UNCHANGED\n"
            else:
                raise AssertionError("PUBLIC managed model: unknown ordinary command")
            calls.append(("ib", HOST, tuple(command[:2])))
            return app.SessionResult(body, 0)

        def observer_transport(command, timeout, *, pass_fds=()):
            self.assertEqual(1, len(pass_fds))
            fd = pass_fds[0]
            held, named = os.fstat(fd), private.stat()
            self.assertEqual((named.st_dev, named.st_ino, os.geteuid(), 0o600, 1),
                             (held.st_dev, held.st_ino, held.st_uid, stat.S_IMODE(held.st_mode), held.st_nlink))
            self.assertEqual(["ssh", "-i", "/dev/fd/" + str(fd), "-o", "BatchMode=yes",
                "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "IdentitiesOnly=yes",
                "-o", "ConnectTimeout=2", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "LogLevel=ERROR", "admin@203.0.113.2", shlex.join(["sh", "-c", OBSERVATION_SCRIPT])], command)
            self.assertEqual(30, timeout)
            calls.append(("observer", HOST))
            if drift:
                old = "EXAMPLE-IB02,ib,203.0.113.3,24"
                text = f["csv"].read_text(encoding="ascii")
                self.assertEqual(1, text.count(old))
                f["csv"].write_text(text.replace(old, "EXAMPLE-IB02,ib,203.0.113.99,24"), encoding="ascii")
            return subprocess.CompletedProcess(command, 0, wire, "")

        def local_transport(argv, **kwargs):
            native = [sys.executable, "-I", "-S", "-B", str(INITIAL.resolve()), "--_verify-password"]
            if argv == native:
                self.assertEqual({"input", "text", "capture_output", "timeout", "check", "env"}, set(kwargs))
                self.assertEqual(8, kwargs["timeout"])
                self.assertIs(True, kwargs["text"])
                self.assertIs(True, kwargs["capture_output"])
                self.assertIs(False, kwargs["check"])
                self.assertEqual({"PATH": os.defpath, "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"}, kwargs["env"])
                data = json.loads(kwargs["input"])
                self.assertTrue(set(data) == {"password", "hash"}
                                and data["password"] == kat["PASSWORD"] and data["hash"] == kat["YESCRYPT"],
                                "native worker must retain original qualified inputs; values withheld")
                calls.append(("native",))
                return real_run(argv, **kwargs)
            if argv == ["/usr/bin/ssh-keygen", "-l", "-E", "sha256", "-f", "/dev/stdin"]:
                self.assertEqual({"input", "capture_output", "text", "timeout", "check"}, set(kwargs))
                self.assertTrue(kwargs["input"] in tuple(line + "\n" for line in key_lines))
                self.assertEqual(10, kwargs["timeout"])
                self.assertIs(True, kwargs["capture_output"])
                self.assertIs(True, kwargs["text"])
                self.assertIs(False, kwargs["check"])
                calls.append(("public-fingerprint",))
                return real_run(argv, **kwargs)
            if argv == ["ssh-keygen", "-y", "-f", str(private)]:
                self.assertEqual(dict(stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                      timeout=10, check=False), kwargs)
                calls.append(("modeled-public-derivation", HOST))
                return subprocess.CompletedProcess(argv, 0, key_lines[1] + "\n", "")
            possession = ["ssh", "-4", "-i", str(private), "-o", "BatchMode=yes",
                "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=2",
                "-o", "ConnectionAttempts=1", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
                "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "LogLevel=ERROR", "admin@203.0.113.2", "true"]
            if argv == possession:
                self.assertEqual(dict(stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                      timeout=15, check=False), kwargs)
                calls.append(("modeled-key-possession", HOST))
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError("PUBLIC managed model: unknown local subprocess vector")

        def deny(*args, **kwargs):
            raise AssertionError("PUBLIC managed model: unexpected PTY/process/socket")

        def ipv4(target, *args, **kwargs):
            self.assertEqual(HOST, target.ib.hostname)
            calls.append(("modeled-ipv4-readiness", HOST))

        def direct_ssh(device, interface, user, password, timeout, **kwargs):
            self.assertEqual((HOST, "eth0", "admin", 2), (device.hostname, interface, user, timeout))
            self.assertTrue(password == kat["PASSWORD"], "direct credential remains qualified; value withheld")
            app.verify_state(device, app.parse_nvue_state(STATE))
            calls.append(("modeled-final-direct", HOST))

        required_files = {str(INITIAL.resolve()), str(AUTHORITY.resolve()),
                          str(INITIAL.parents[3] / "tools/hostname_ranges.py"),
                          str(INITIAL.parents[3] / "tools/device_identity.py")}
        def profile(frame, event, value):
            if event == "call" and frame.f_code.co_filename in required_files:
                entered.add(Path(frame.f_code.co_filename))

        argv = [str(INITIAL), "--ib-csv", str(f["csv"]), "--p2p", str(f["p2p"]),
                "--target-cache", str(f["cache"]), "--report", str(report),
                "--snapshot-dir", str(report.parent / "snapshots"), "--apply", "--yes",
                "--execution-mode", "management", "--max-workers", "1", "--connect-timeout", "2",
                "--devices", HOST]
        before_profile = sys.getprofile()
        try:
            with ExitStack() as stack, helper.authority_events() as events:
                stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(f["root"]), "NVOS_INITIAL_PASSWORD": kat["PASSWORD"]}))
                stack.enter_context(mock.patch.object(sys, "argv", argv))
                stack.enter_context(mock.patch.object(app, "_new_jump_sessions", legacy_jump_sessions_factory(app)))
                for name, value in (("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "PUBLIC-jump-model"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "PUBLIC table")),
                    ("collect_ethernet_network_tables", (
                        "7: swp7: <UP> mtu 1500 state UP\n8: swp8: <UP> mtu 1500 state UP\n",
                        "02:00:00:00:00:01 dev swp7 master bridge dynamic\n02:00:00:00:00:02 dev swp8 master bridge dynamic\n",
                        "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n")),
                    ("save_ethernet_snapshot", report.parent / "snapshot"),
                    ("interface_status_line", "swp7 up"), ("interface_oper_status", "up"), ("interface_vrf", "default")):
                    stack.enter_context(mock.patch.object(app, name, return_value=value))
                stack.enter_context(mock.patch.object(app, "subprocess", new=direct.SimpleNamespace(
                    run=guarded(local_transport), Popen=guarded(deny), DEVNULL=subprocess.DEVNULL,
                    PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired, SubprocessError=subprocess.SubprocessError)))
                stack.enter_context(mock.patch.object(app, "run_on_ib", new=guarded(ib_transport)))
                stack.enter_context(mock.patch.object(app, "_run_initial_observation", new=guarded(observer_transport)))
                stack.enter_context(mock.patch.object(app, "verify_ipv4_login", new=guarded(ipv4)))
                stack.enter_context(mock.patch.object(app, "verify_management_direct_ssh", new=guarded(direct_ssh)))
                witness = stack.enter_context(original.strict_management_boundary(self, app, kat=kat, held_rows=()))
                stack.enter_context(redirect_stdout(output))
                stack.enter_context(redirect_stderr(output))
                sys.setprofile(profile)
                result = app.main(method_cycle=cycle)
                cycle.close()
            if errors:
                raise errors[0]  # never let a model error become a device-business FAIL
            original.assert_strict_management_path(self, witness, global_path=f["global_file"], devices=(HOST,))
        finally:
            sys.setprofile(before_profile)
            cycle.close()
            if app.REPORT_HANDLE is not None:
                app.REPORT_HANDLE.close()
        if errors:
            raise errors[0]
        self.assertEqual({INITIAL.resolve(), AUTHORITY.resolve(), INITIAL.parents[3] / "tools/hostname_ranges.py",
                          INITIAL.parents[3] / "tools/device_identity.py"}, entered)
        self.assertFalse(any(name.casefold() == "example-ib02" for kind, name in events))
        self.assertEqual(1, sum(call[:1] == ("observer",) for call in calls))
        return result, cycle, calls, wire, report

    def test_real_managed_one_of_two_cold_and_warm_keep_full_cache_and_old_ledger(self):
        helper = self.setup_helper()
        with helper.fixture(strict=True) as f:
            storage = f["cycle"].root
            old = helper.authority.begin_method(storage, "EXAMPLE-IB02", "prior-public-writer",
                                                "prior-public-writer:EXAMPLE-IB02", "initial_setup_managed")
            helper.authority.revoke_method(storage, "EXAMPLE-IB02", expected=old)
            before = helper.ledger_images(storage, "EXAMPLE-IB02")
            # Only own fixture cache pair; MAIN must regenerate the full two-target cache.
            f["cache"].unlink()
            f["cache"].with_name(f["cache"].name + ".sha256").unlink()
            for generation, label in ((1, "cold"), (2, "warm")):
                with self.subTest(cache=label):
                    warm_image = None
                    if label == "warm":
                        info = f["cache"].stat()
                        warm_image = (info.st_dev, info.st_ino, hashlib.sha256(f["cache"].read_bytes()).hexdigest())
                    result, cycle, calls, wire, report = self.run_managed(helper, f, label)
                    self.assertEqual(0, result)
                    if warm_image is not None:
                        info = f["cache"].stat()
                        self.assertEqual(warm_image, (info.st_dev, info.st_ino, hashlib.sha256(f["cache"].read_bytes()).hexdigest()))
                        self.assertTrue("Target cache: reused " in report.read_text(), "warm MAIN did not report real full-cache reuse")
                    self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], [target.ib.hostname for target in cycle.targets])
                    self.assertEqual(["example-ib01"], list(cycle.tickets))
                    self.assertEqual(["example-ib01"], list(cycle.expected))
                    current = helper.authority.read_method_current(storage, HOST)
                    self.assertEqual((generation, "success", False),
                                     (current["generation"], current["state"], current["veto"]))
                    receipt = helper.authority.read_method_receipt(storage, HOST)
                    self.assertEqual((HOST, "ib", "initial-setup", "initial_setup_managed", "success", True, True),
                                     tuple(receipt[key] for key in ("hostname", "type", "config_method", "trigger_source",
                                                                   "state", "batch_identity_verified", "config_verified")))
                    self.assertEqual(hashlib.sha256(STATE.encode()).hexdigest(), receipt["live_state_sha256"])
                    self.assertEqual(hashlib.sha256(wire.encode()).hexdigest(), receipt["source_receipt_sha256"])
                    fingerprints = ["SHA256:" + base64.b64encode(hashlib.sha256(
                        base64.b64decode(line.split()[1])).digest()).decode("ascii").rstrip("=")
                        for line in (f["laptop"], f["management"])]
                    basis = {"schema_version": 1, "type": "ib", "config_method": "initial-setup", "hostname": HOST,
                             "eth0": "203.0.113.2/24", "eth0_gateway": "203.0.113.1", "eth1": "", "eth1_gateway": "",
                             "eth0_mac": "02:00:00:00:00:01", "dns": ["203.0.113.53"],
                             "ntp": ["ntp.ubuntu.com", "time.ib.example.test"], "timezone": "Asia/Taipei",
                             "key_fingerprints": sorted(fingerprints)}
                    expected_input = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(",", ":"),
                                                               ensure_ascii=False).encode()).hexdigest()
                    self.assertEqual(expected_input, receipt["input_sha256"])
                    self.assertEqual(("eth0", "203.0.113.2", "020000000001"),
                                     (receipt["interface"], receipt["transport_ip"], receipt["mac_plain"]))
                    cache = json.loads(f["cache"].read_text())
                    self.assertEqual(2, cache["ib_candidate_count"])
                    self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], [row["ib"]["hostname"] for row in cache["targets"]])
                    self.assertEqual(before, helper.ledger_images(storage, "EXAMPLE-IB02"))
                    summaries = list(report.parent.rglob("summary.json"))
                    self.assertEqual(1, len(summaries))
                    summary = json.loads(summaries[0].read_text())
                    self.assertEqual({"example-ib01"}, set(summary["records"]))

    def test_real_managed_unselected_drift_invalidates_full_current_input_proof(self):
        helper = self.setup_helper()
        with helper.fixture(strict=True) as f:
            result, cycle, calls, wire, report = self.run_managed(helper, f, "drift", drift=True)
            self.assertEqual(1, result, "changed shared input remains a common-flow failure")
            self.assertIsNone(helper.authority.read_method_receipt(cycle.root, HOST))
            self.assertEqual("failed", helper.authority.read_method_current(cycle.root, HOST)["state"])
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], [target.ib.hostname for target in cycle.targets])


# U3 / R-025 (v3.1.6 D1c).  Expectations: owner 2026-11-14 「T15按你说的改，记录成U3放3.1.6」 on the
# issue file's 11.4/11.5 and v3.1.6 guide 8.10 steps 1-6 (:2133-2140).  The 11.5 field scenario:
# an earlier run wrote one DNS row in Infra Services and was interrupted before apply; the rerun
# with --apply detaches it, writes DNS/NTP/timezone, applies and verifies the readback, while a
# device with unrelated pending in the same run is refused with zero detach and zero writes.
_U3_DIFF = ("nv", "config", "diff", "-o", "commands")
_U3_DETACH = ("nv", "config", "detach")
_U3_SERVICES = (("nv", "set", "system", "dns", "server", "203.0.113.53"),
                ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
                ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
                ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"))
_U3_HINT = "用 `nv config diff -o commands` 核对，确认后在设备上手工 detach 或 apply，再重跑"


class _PendingFiveDevices(_FiveDevices):
    """The same five PUBLIC devices with independently stated pending diffs (U3)."""

    def __init__(self, test, app, kat):
        super().__init__(test, app, kat)
        # EXAMPLE-IB004 (jump): the 11.5 field case, no services applied, one DNS row pending.
        self.rows[NAMES[3]] = [row for row in self.rows[NAMES[3]] if not row.startswith(
            ("nv set system dns ", "nv set system ntp ", "nv set system date-time "))]
        self.pending[NAMES[3]] = [_U3_SERVICES[0]]
        # EXAMPLE-IB005 (direct): only the timezone is missing and that row is pending.
        self.rows[NAMES[4]] = [row for row in self.rows[NAMES[4]]
                               if not row.startswith("nv set system date-time ")]
        self.pending[NAMES[4]] = [_U3_SERVICES[3]]
        # EXAMPLE-IB001 (factory): one row that no profile or CSV value owns.
        self.pending[NAMES[0]] = [("nv", "set", "system", "dns", "server", "198.51.100.99")]

    def _reply(self, name, command):
        if command == _U3_DIFF:
            self.events.append((name, command))
            body = "".join(shlex.join(row) + "\n" for row in self.pending[name])
            return body, 1 if self.pending[name] else 0
        if command == _U3_DETACH:
            self.events.append((name, command))
            self.pending[name] = []
            return "", 0
        if command in _U3_SERVICES and name in (NAMES[3], NAMES[4]):
            self.events.append((name, command))
            self.pending[name].append(command)
            return "", 0
        return super()._reply(name, command)


class OwnedPendingWorkflowTests(unittest.TestCase):
    """Real MAIN -> stages -> closed commands -> write permits -> summary.json, U3 pending."""

    @classmethod
    def setUpClass(cls):
        cls.app = load_script("d1c_u3_pending_workflow_source", INITIAL)

    def run_pending(self, *, apply):
        with mock.patch(__name__ + "._FiveDevices", _PendingFiveDevices):
            return BringupResultsWorkflowTests.run_five(self, apply=apply)

    def test_apply_detaches_owned_pending_and_refuses_unrelated_pending(self):
        code, evidence, console, report, world, per_device = self.run_pending(apply=True)
        self.assertIs(type(world), _PendingFiveDevices)
        records = evidence["records"]
        foreign = records[NAMES[0].casefold()]
        self.assertEqual("FAILED", foreign["outcome"], world.public_failure_note(evidence))
        self.assertIn("有 1 行不认识的待提交", foreign["reason"])
        self.assertIn(_U3_HINT, foreign["reason"])
        self.assertIs(False, foreign["writes_attempted"])
        self.assertIsNone(foreign["backup"])
        self.assertEqual([], foreign.get("pending_detached"))
        events = [command for peer, command in world.events if peer == NAMES[0]]
        self.assertEqual(1, events.count(_U3_DIFF))
        self.assertFalse(any(command == _U3_DETACH or command[:2] in (("nv", "set"), ("sh", "-c"))
                             or command[:3] in (("nv", "config", "apply"), ("nv", "config", "save"))
                             for command in events), events)
        self.assertEqual([("nv", "set", "system", "dns", "server", "198.51.100.99")], world.pending[NAMES[0]])
        for name, line in ((NAMES[3], "nv set system dns server 203.0.113.53"),
                           (NAMES[4], "nv set system date-time timezone Asia/Taipei")):
            with self.subTest(device=name):
                record = records[name.casefold()]
                self.assertNotIn("failed_stage", record, world.public_failure_note(evidence))
                self.assertEqual([{"stage": "services", "lines": [line], "detached": True}],
                                 record.get("pending_detached"))
                events = [command for peer, command in world.events if peer == name]
                diffs = [index for index, command in enumerate(events) if command == _U3_DIFF]
                backup = next(index for index, command in enumerate(events)
                              if command[:3] == ("sh", "-c", EXPECTED_BACKUP_SCRIPT))
                detach = events.index(_U3_DETACH)
                setters = [index for index, command in enumerate(events) if command[:2] == ("nv", "set")]
                self.assertEqual(1, events.count(_U3_DETACH))
                self.assertTrue(len(diffs) == 2 and diffs[0] < backup < detach < diffs[1] < setters[0], events)
                self.assertLess(detach, events.index(("nv", "config", "apply", "-y")))
                self.assertEqual([], world.pending[name])
                rows = world.rows[name]
                for row in ("nv set system dns server 203.0.113.53",
                            "nv set system ntp server ntp.ubuntu.com state enabled",
                            "nv set system ntp server time.ib.example.test state enabled",
                            "nv set system date-time timezone Asia/Taipei"):
                    self.assertIn(row, rows)
                nvue = [command for command in events if command == _U3_DETACH or command[:2] == ("nv", "set")
                        or command[:3] in (("nv", "config", "apply"), ("nv", "config", "save"))]
                self.assertEqual(len(nvue), record["metrics"]["nvue_write_commands"])
                self.assertIs(True, record["writes_attempted"])
                self.assertEqual("CHECKED_AND_CONFIGURED", record["category"])
                self.assertIs(True, record["verified_complete"])
                self.assertIn(line, report)
                self.assertEqual(record, next(item for item in per_device if item["hostname"] == name))

    def test_check_only_reports_owned_and_unrelated_pending_without_detach(self):
        code, evidence, console, report, world, per_device = self.run_pending(apply=False)
        records = evidence["records"]
        self.assertNotIn(_U3_DETACH, [command for _, command in world.events])
        self.assertEqual([], world.permits)
        foreign = records[NAMES[0].casefold()]
        self.assertIn("有 1 行不认识的待提交，--apply 会拒绝", foreign["reason"], world.public_failure_note(evidence))
        owned = records[NAMES[3].casefold()]
        self.assertIn({"item": "pending", "value": "1 owned lines"}, owned["planned_changes"])
        self.assertIs(True, owned["needs_change"])
        self.assertEqual([], owned.get("pending_detached"))
        self.assertEqual(1, [command for peer, command in world.events if peer == NAMES[3]].count(_U3_DIFF))
        self.assertIn("有 1 行自有待提交，--apply 时会 detach 后重做", report)
        self.assertEqual([_U3_SERVICES[0]], world.pending[NAMES[3]])
