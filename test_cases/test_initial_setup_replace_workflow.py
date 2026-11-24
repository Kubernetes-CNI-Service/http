"""r757 D7 real generator/publisher -> MAIN/stages -> persisted result.

Author NOT RUN. Only the SSH/public device boundary is modeled. Original
KAT reader/8-second verifier and public fingerprint validator require Root's
separate runtime ticket. No captured shell or device command is executed.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import hashlib
import hmac
import io
import json
import multiprocessing
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

# Keep PyYAML's Python/C class family inside every sys.modules snapshot.
# Reloading only its Python modules between cases can split C-loader identity.
import yaml

from test_cases.module_loader import load_script
from test_cases.native_cpld_physical_io import owned_test_root
from test_cases.initial_setup_jump_fixture import legacy_jump_sessions_factory
from test_cases.test_req10b_services_keys_workflow import (
    credentials_fd, public_key, strict_fd_payload, strict_kat)
from test_cases.test_initial_setup_identity_and_backup import (
    EXPECTED_BACKUP_SCRIPT, EXPECTED_LAUNCH_SCRIPT, EXPECTED_READ_RC_SCRIPT)
from test_cases.test_initial_setup_bringup_results import (
    EXPECTED_INSTALL_KEY_SCRIPT, EXPECTED_READONLY_KEY_SCRIPT)
from test_cases.test_initial_setup_config_mode import (
    ROOT, INITIAL, NAMES, MACS, Facade, EXPECTED_REPLACE_SCRIPT, WARNING,
    EXPECTED_D7_LAUNCH_SCRIPT, EXPECTED_D7_READ_RC_SCRIPT)


JUMP = "EXAMPLE-JUMP01"
HEADER = "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac\n"
CSV = (HEADER +
       "EXAMPLE-IB001,ib,leaf,203.0.113.11,24,203.0.113.1,02:00:00:00:00:11,NA,NA,NA,NA\n"
       "EXAMPLE-IB002,ib,leaf,203.0.113.12,24,203.0.113.1,02:00:00:00:00:12,NA,NA,NA,NA\n"
       "EXAMPLE-JUMP01,eth_jump,leaf,192.0.2.10,NA,NA,NA,NA,NA,NA,NA\n")
READ = ("nv", "config", "show", "-o", "commands")
APPLY = ("nv", "config", "apply", "-y")
SAVE = ("nv", "config", "save")
DETACH = ("nv", "config", "detach")
ZTP = ("nv", "show", "system", "ztp")
AUTOSAVE = ("nv", "set", "system", "config", "auto-save", "state", "enabled")
CONFIGSAVE = ("nv", "set", "system", "ztp", "config-save", "enabled")
NTP = ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com")
SSH_OPTIONS = ["-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
               "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR"]
PASSWORD_ONLY = ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"]
CONTROL = ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
SAFE_PREFIX = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
FRAME = re.compile(r'^printf "\\n__HTTP_IB_BEGIN_([0-9a-f]{32})__\\n"; (.*); '
                   r'task_rc=\$\?; printf "\\n__HTTP_IB_END_([0-9a-f]{32})__=%s\\n" '
                   r'"\$task_rc"; exit "\$task_rc"$', re.S)


def frame(command, nonce):
    return ('printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; ' + shlex.join(command)
            + '; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
            + '__=%s\\n" "$task_rc"; exit "$task_rc"')


def public_workbook(path):
    """Minimal independently written OOXML name/port groups, no SDK/child."""
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rows = [("name", "port", "name", "port"),
            (NAMES[0], "eth0", JUMP, "swp1"), (NAMES[1], "eth0", JUMP, "swp2")]
    sheet = '<worksheet xmlns="' + ns + '"><sheetData>'
    for number, row in enumerate(rows, 1):
        sheet += '<row r="' + str(number) + '">'
        for column, value in zip("ABCD", row):
            sheet += '<c r="' + column + str(number) + '" t="inlineStr"><is><t>' + value + '</t></is></c>'
        sheet += '</row>'
    sheet += '</sheetData></worksheet>'
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/workbook.xml", '<workbook xmlns="' + ns
            + '" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
              '<sheets><sheet name="PUBLIC" sheetId="1" r:id="rId1"/></sheets></workbook>')
        archive.writestr("xl/_rels/workbook.xml.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>')
        archive.writestr("xl/worksheets/sheet1.xml", sheet)


class _ReplaceWorld:
    """Two independently declared PUBLIC switches, full-vector SSH replies only."""
    def __init__(self, test, app, kat, *, failure=None, direct=False):
        self.test, self.app, self.kat, self.failure, self.direct = test, app, kat, failure, direct
        self.events, self.permits, self.effects, self.delays, self.readiness, self.local_children = ([] for _ in range(6))
        self.sleep_witnesses = []
        self.prompts, self.device_files, self.payloads = [], {}, {}
        self.authorizations = []
        self.confirmation_texts = []
        self.elapsed = 0.0
        self.clock_base = time.monotonic()
        self.rc_reads = {name: 0 for name in NAMES}
        self.replaced, self.pending = set(), {name: [] for name in NAMES}
        self.replace_pending = set()
        self.keys_present = {name: True for name in NAMES}
        self.ztp = {NAMES[0]: False, NAMES[1]: True}
        self.rows = {NAMES[0]: ["nv set system hostname nvos"], NAMES[1]: self.complete(NAMES[1])}
        self.required_line = public_key(17, "PUBLIC-D7-required").strip()
        self.key_payload = base64.b64encode((self.required_line + "\n").encode()).decode("ascii")

    def monotonic(self):
        return self.clock_base + self.elapsed

    def sleep(self, seconds):
        self.delays.append(seconds)
        if self.events:
            name, phase = self.events[-1]
            if name in NAMES and phase in ("RC_PENDING", "DIRECT_READY", "D4"):
                self.sleep_witnesses.append((name, phase, seconds))
        self.elapsed += seconds

    def deny(self, *_args, **_kwargs):
        self.effects.append("unknown-effect")
        raise RuntimeError("FIXTURE HOLD: D7 refused an unknown external effect")

    def complete(self, name, *, after_replace=False):
        index = NAMES.index(name) + 11
        rows = ["nv set interface eth0-1 link state up", "nv set interface eth0-1 type eth",
                "nv set system hostname " + name,
                f"nv set interface eth0 ipv4 address 203.0.113.{index}/24",
                "nv set interface eth0 ipv4 gateway 203.0.113.1",
                "nv set system ztp config-save enabled",
                "nv set system dns server 203.0.113.53", "nv set system date-time timezone Asia/Taipei"]
        if not after_replace:
            rows += [shlex.join(AUTOSAVE), shlex.join(NTP) + " state enabled"]
        return rows

    def ethernet(self, device, user, password, command, timeout, **options):
        if (device.hostname, user, password, timeout) != (JUMP, "cumulus", "", 10):
            return self.deny()
        self.events.append((JUMP, tuple(command)))
        answers = {
            ("hostname",): JUMP + "\n",
            ("nv", "show", "interface"): "swp1 up up\nswp2 up up\n",
            ("ip", "-d", "link", "show"):
                "1: swp1: <UP> mtu 1500 master br_default\n2: swp2: <UP> mtu 1500 master br_default\n"
                "40: br_default: <UP> mtu 1500\n    bridge forward_delay 1500 vlan_filtering 1\n"
                "41: ib-mgmt1000@br_default: <UP> mtu 1500 master oob\n    vlan protocol 802.1Q id 1000 <REORDER_HDR>\n",
            ("bridge", "fdb", "show"):
                "02:00:00:00:00:11 dev swp1 vlan 1000 master br_default\n"
                "02:00:00:00:00:12 dev swp2 vlan 1000 master br_default\n",
            ("bridge", "vlan", "show"): "port vlan-id\nswp1 1000 PVID Egress Untagged\nswp2 1000 PVID Egress Untagged\n",
            ("ip", "neighbor"): "",
            ("ip", "-j", "address", "show"):
                '[{"ifname":"ib-mgmt1000","flags":["UP"],"operstate":"UP","addr_info":'
                '[{"family":"inet","local":"203.0.113.1","prefixlen":24,"scope":"global"},'
                '{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}]',
            ("ifquery", "ib-mgmt1000"): "iface ib-mgmt1000\n    vrf oob\n"}
        if tuple(command) not in answers:
            return self.deny()
        return answers[tuple(command)]

    def _carrier_data(self, argv, responder, timeout):
        """Qualify the COMPLETE private carrier before projecting its DATA.

        AUTH's terminating semicolon is shell syntax, not part of the quoted
        READ frame. Never tokenize that program before exact qualification.
        """
        if type(argv) is not list or any(type(word) is not str for word in argv):
            return self.deny()
        phase = getattr(responder, "_phase", None)
        if phase is None:
            if any("__HTTP_IB_AUTH_" in word for word in argv):
                return self.deny()
            return argv
        if (type(phase) is not self.app._IBPhase or phase.operation != "auth-probe-readonly"
                or type(phase.nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", phase.nonce) is None
                or timeout != 60 or phase.endpoint != getattr(responder, "ib_destination", None)):
            return self.deny()
        direct = self.direct and phase.endpoint == "admin@203.0.113.11"
        if direct and (len(argv) != 3 or argv[:2] != ["sh", "-c"]):
            return self.deny()  # An ordinary fresh-direct vector cannot impersonate AUTH.
        # This compares the entire original outer/inner SSH/program/frame with
        # independent literals, including endpoint/outer_endpoint and timeout.
        self.validate_carrier(argv, responder, timeout, phase.nonce, READ)
        begin = 'printf "\\n__HTTP_IB_AUTH_' + phase.nonce + '_auth-probe-readonly__=BEGIN\\n"; '
        end = ('; inner_rc=$?; printf "\\n__HTTP_IB_AUTH_' + phase.nonce
               + '_auth-probe-readonly__=EXIT:%s\\n" "$inner_rc"; exit "$inner_rc"')
        if direct:
            program = argv[2]
        else:
            outer = shlex.split(argv[-1])
            auth = shlex.split(outer[2][len(SAFE_PREFIX):])
            program = auth[2]
        # Only exact, already-qualified boundaries are sliced. No strip(';'),
        # punctuation recovery, arbitrary-shell interpretation or SUT renderer.
        if not (program.startswith(begin) and program.endswith(end)):
            return self.deny()
        data = program[len(begin):-len(end)]
        inner = shlex.split(data)
        if shlex.join(inner) != data:
            return self.deny()
        return inner

    def decode_frame(self, argv):
        found = []
        def visit(text, depth):
            if depth > 9:
                return self.deny()
            match = FRAME.fullmatch(text)
            if match:
                if match[1] != match[3]:
                    return self.deny()
                command = shlex.split(match[2])
                if frame(command, match[1]) != text:
                    return self.deny()
                found.append((match[1], tuple(command)))
                return
            if text.startswith(SAFE_PREFIX):
                text = text[len(SAFE_PREFIX):]
            try:
                words = shlex.split(text)
            except ValueError:
                return
            for word in words:
                if word != text and "__HTTP_IB_BEGIN_" in word:
                    visit(word, depth + 1)
        for text in argv:
            visit(text, 0)
        if len(found) != 1:
            return self.deny()
        return found[0]

    def validate_carrier(self, argv, responder, timeout, nonce, command):
        peer = getattr(responder, "ib_destination", None)
        peers = {"admin@fe80::ff:fe00:11": NAMES[0], "admin@fe80::ff:fe00:12": NAMES[1],
                 "admin@203.0.113.11": NAMES[0], "admin@203.0.113.12": NAMES[1]}
        if peer not in peers:
            return self.deny()
        remote = shlex.join(["sh", "-c", frame(command, nonce)])
        phase = getattr(responder, "_phase", None)
        inner = []
        if peer.startswith("admin@fe80:"):
            inner = ["ip", "vrf", "exec", "oob", "ssh", "-6", "-tt", "-o", "ConnectTimeout=10",
                     "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", *CONTROL,
                     "-o", "NumberOfPasswordPrompts=1"]
            if phase is not None or command[:3] == ("sh", "-c", EXPECTED_BACKUP_SCRIPT):
                inner += PASSWORD_ONLY
            inner += ["-B", "ib-mgmt1000", peer, remote]
        elif argv[:1] == ["ssh"] and argv[-2] == peer and "ConnectionAttempts=1" in argv:
            # The established final read-only probe has its own shorter bounds.
            expected = ["ssh", "-4", "-tt", "-o", "ConnectTimeout=3", *SSH_OPTIONS[2:],
                        "-o", "ConnectionAttempts=1",
                        "-o", "ProxyCommand=none", "-o", "ProxyJump=none", *CONTROL,
                        "-o", "NumberOfPasswordPrompts=1", *PASSWORD_ONLY, peer, remote]
            if argv != expected or timeout != 15:
                return self.deny()
            return peers[peer]
        elif self.direct and peers[peer] == NAMES[0]:
            inner = ["ssh", "-4", "-tt", *SSH_OPTIONS, "-o", "ProxyCommand=none",
                     "-o", "ProxyJump=none", *CONTROL, "-o", "NumberOfPasswordPrompts=1"]
            if phase is not None or command[:3] == ("sh", "-c", EXPECTED_BACKUP_SCRIPT):
                inner += PASSWORD_ONLY
            inner += [peer, remote]
        else:
            # Original strict Jump -> fresh IPv4 identity read, not a new write carrier.
            inner = ["ip", "vrf", "exec", "oob", "ssh", "-o", "ConnectTimeout=10",
                     "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", *CONTROL, peer, remote]
        if phase is not None:
            if (type(phase) is not self.app._IBPhase or phase.operation != "auth-probe-readonly"
                    or phase.nonce != nonce or phase.endpoint != peer or command != READ):
                return self.deny()
            begin = 'printf "\\n__HTTP_IB_AUTH_' + nonce + '_auth-probe-readonly__=BEGIN\\n"; '
            end = ('; inner_rc=$?; printf "\\n__HTTP_IB_AUTH_' + nonce
                   + '_auth-probe-readonly__=EXIT:%s\\n" "$inner_rc"; exit "$inner_rc"')
            if self.direct and peers[peer] == NAMES[0]:
                expected = ["sh", "-c", begin + shlex.join(inner) + end]
                if phase.outer_endpoint != "":
                    return self.deny()
            else:
                if phase.outer_endpoint != "cumulus@192.0.2.10":
                    return self.deny()
                inner = ["sh", "-c", begin + shlex.join(inner) + end]
                expected = ["ssh", "-tt", *SSH_OPTIONS, *CONTROL, "cumulus@192.0.2.10",
                            shlex.join(["sh", "-c", SAFE_PREFIX + shlex.join(inner)])]
        elif self.direct and peers[peer] == NAMES[0]:
            expected = inner
        else:
            expected = ["ssh", "-tt", *SSH_OPTIONS, *CONTROL, "cumulus@192.0.2.10",
                        shlex.join(["sh", "-c", SAFE_PREFIX + shlex.join(inner)])]
        direct_task = self.direct and peers[peer] == NAMES[0]
        expected_timeout = 45 if peer.startswith("admin@203.") and not direct_task else 60
        if argv != expected or timeout != (60 if phase is not None else expected_timeout):
            return self.deny()
        return peers[peer]

    def reply(self, name, command):
        # Append only PUBLIC labels; a KAT-bearing YAML/base64 never enters events.
        if command == READ:
            self.events.append((name, "READ"))
            if self.failure == "restore-readback" and name == NAMES[0] and name in self.replaced:
                observed = [event for owner, event in self.events if owner == name]
                post = observed[observed.index("REPLACE") + 1:]
                if NTP in post and post.count("SAVE") >= 2:
                    missing_line = "nv set system ntp server ntp.ubuntu.com state enabled"
                    if self.rows[name].count(missing_line) != 1:
                        return self.deny()
                    self.events.append((name, "RESTORE_READBACK_MISSING"))
                    return "\n".join(row for row in self.rows[name] if row != missing_line) + "\n", 0
            return "\n".join(self.rows[name]) + "\n", 0
        if command == ("ip", "addr", "show", "eth0"):
            self.events.append((name, "O5"))
            index = NAMES.index(name)
            mac = MACS[1] if self.failure == "identity" and name == NAMES[0] else MACS[index]
            return (f"2: eth0: <UP> mtu 1500\n    link/ether {mac}\n"
                    f"    inet 203.0.113.{index+11}/24 scope global eth0\n"), 0
        if command == ("ip", "route"):
            self.events.append((name, "ROUTE"))
            return "default via 203.0.113.1 dev eth0\n", 0
        if command == ZTP:
            self.events.append((name, "ZTP"))
            if self.failure == "post-ztp" and name == NAMES[0] and name in self.replaced:
                return "service enabled\nstatus in-progress\n", 0
            return "service " + ("disabled" if self.ztp[name] else "enabled") + "\nstatus aborted\n", 0
        if command == ("nv", "config", "diff", "-o", "commands"):
            self.events.append((name, "PENDING"))
            body = "".join(shlex.join(item) + "\n" for item in self.pending[name])
            if name in self.replace_pending:
                body += "nv set system hostname " + name + "\n"
            return body, 0
        if len(command) == 6 and command[:4] == ("sh", "-c", EXPECTED_REPLACE_SCRIPT, "--"):
            wanted = self.payloads[name]
            if (not hmac.compare_digest(command[4], base64.b64encode(wanted).decode("ascii"))
                    or not hmac.compare_digest(command[5], hashlib.sha256(wanted).hexdigest())):
                return self.deny()
            if self.failure == "replace-preparation" and name == NAMES[0]:
                self.events.append((name, "REPLACE_PREPARATION_FAILED"))
                return "IB configuration replace failed\n", 1
            self.events.append((name, "REPLACE"))
            self.device_files[name] = wanted  # PUBLIC device model; never a host shell write.
            self.replaced.add(name)
            if self.failure == "replace" and name == NAMES[0]:
                return "rc=7\nfailed_operation=replace\n", 1
            self.replace_pending.add(name)
            path = "/home/admin/initial-setup-replace.yaml"
            digest = hashlib.sha256(wanted).hexdigest()
            if name == NAMES[0] and self.failure == "receipt-path":
                path = "/home/admin/PUBLIC-other.yaml"
            if name == NAMES[0] and self.failure == "receipt-hash":
                digest = "0" * 64
            receipt = "path=" + path + "\nsha256=" + digest + "\n"
            if name == NAMES[0] and self.failure == "receipt-extra":
                receipt += "PUBLIC unexpected output\n"
            return receipt, 0
        if len(command) == 5 and command[:2] == ("sh", "-c") and command[3] == "--":
            script, payload = command[2], command[4]
            if script in (EXPECTED_D7_LAUNCH_SCRIPT, EXPECTED_D7_READ_RC_SCRIPT):
                if (not self.direct or name != NAMES[0] or name not in self.replaced
                        or not re.fullmatch(r"[0-9]{8}-[0-9]{6}", payload)):
                    return self.deny()
                if script == EXPECTED_D7_LAUNCH_SCRIPT:
                    self.events.append((name, "DEFER"))
                    if self.failure not in {"rc", "typed-apply7", "typed-contradiction"}:
                        self.apply_pending(name)
                    return "", 0
                self.rc_reads[name] += 1
                if self.rc_reads[name] == 1 or self.failure == "rc-pending":
                    self.events.append((name, "RC_PENDING"))
                    return "rc=\nfailed_operation=pending\n", 0
                failed = {
                    "rc": ("RC_FAILED", "rc=7\nfailed_operation=apply\n"),
                    "typed-apply7": ("RC_APPLY_FAILED", "rc=7\nfailed_operation=apply\n"),
                    "typed-save7": ("RC_SAVE_FAILED", "rc=7\nfailed_operation=save\n"),
                    "typed-contradiction": ("RC_UNQUALIFIED", "rc=7\nfailed_operation=none\n"),
                }
                label, receipt = failed.get(self.failure, ("RC_READY", "rc=0\nfailed_operation=none\n"))
                self.events.append((name, label))
                return receipt, 0
            if script in (EXPECTED_BACKUP_SCRIPT, EXPECTED_LAUNCH_SCRIPT, EXPECTED_READ_RC_SCRIPT):
                if not re.fullmatch(r"[0-9]{8}-[0-9]{6}", payload):
                    return self.deny()
                if script == EXPECTED_BACKUP_SCRIPT:
                    self.events.append((name, "BACKUP"))
                    if self.failure == "backup" and name == NAMES[0]:
                        return "", 1
                    return "path=/home/admin/current_" + payload + ".yaml\nbytes=137\n", 0
                if script == EXPECTED_LAUNCH_SCRIPT:
                    self.events.append((name, "DEFER"))
                    self.apply_pending(name)
                    return "", 0
                self.rc_reads[name] += 1
                if self.rc_reads[name] == 1 or self.failure == "rc-pending" and name == NAMES[0]:
                    self.events.append((name, "RC_PENDING"))
                    return "rc=\n", 0
                if self.failure == "rc" and name == NAMES[0]:
                    self.events.append((name, "RC_FAILED"))
                    return "rc=7\n", 0
                self.events.append((name, "RC_READY"))
                return "rc=0\n", 0
            if not hmac.compare_digest(payload, self.key_payload):
                return self.deny()
            if script == EXPECTED_READONLY_KEY_SCRIPT:
                self.events.append((name, "KEY_READ"))
                return "", 0
            if script == EXPECTED_INSTALL_KEY_SCRIPT:
                self.events.append((name, "KEY"))
                return "IBSW_PUBLIC_KEYS_UNCHANGED\n", 0
            return self.deny()
        if command in (AUTOSAVE, CONFIGSAVE, NTP):
            self.events.append((name, command))
            self.pending[name].append(command)
            return "", 0
        if command == APPLY:
            self.events.append((name, "APPLY"))
            if self.failure in {"apply", "apply-detach"} and name == NAMES[0] and name in self.replaced:
                return "", 7
            self.apply_pending(name)
            return "", 0
        if command == SAVE:
            self.events.append((name, "SAVE"))
            if self.failure == "save" and name == NAMES[0] and name in self.replaced:
                return "", 7
            return "", 0
        if command == DETACH:
            self.events.append((name, "DETACH"))
            if not (self.failure == "apply-detach" and name == NAMES[0]):
                self.replace_pending.discard(name)
                self.pending[name].clear()
            return "", 7 if self.failure == "apply-detach" and name == NAMES[0] else 0
        return self.deny()

    def apply_pending(self, name):
        if name in self.replace_pending:
            self.rows[name] = self.complete(name, after_replace=True)
            self.replace_pending.remove(name)
        for command in self.pending[name]:
            row = shlex.join(command) + (" state enabled" if command == NTP else "")
            if row not in self.rows[name]:
                self.rows[name].append(row)
        self.pending[name].clear()
        self.ztp[name] = True

    def transport(self, argv, responder, timeout, **options):
        if options or type(argv) is not list:
            return self.deny()
        carrier = self._carrier_data(argv, responder, timeout)
        nonce, command = self.decode_frame(carrier)
        name = self.validate_carrier(argv, responder, timeout, nonce, command)
        phase = getattr(responder, "_phase", None)
        peer = responder.ib_destination
        session = ""
        descriptors = []
        try:
            if phase is not None:
                session = "\n__HTTP_IB_AUTH_" + nonce + "_auth-probe-readonly__=BEGIN\n"
                phase.observe(session)
            session += peer + "'s password: "
            if phase is not None:
                phase.observe(session)
            answer = responder(session)
            if type(answer) is not str or not hmac.compare_digest(answer, self.kat["PASSWORD"]):
                return self.deny()
            if phase is not None:
                reader, writer = os.pipe()
                descriptors += [reader, writer]
                phase.write_reply(writer, answer, responder, self.monotonic() + 60)
                os.read(reader, 8192)
            body, code = self.reply(name, command)
            session += "\n__HTTP_IB_BEGIN_" + nonce + "__\n" + body + "__HTTP_IB_END_" + nonce + "__=" + str(code) + "\n"
            if phase is not None:
                session += "__HTTP_IB_AUTH_" + nonce + "_auth-probe-readonly__=EXIT:" + str(code) + "\n"
                phase.observe(session)
            result = self.app.SessionResult(session, code)
            if (name == NAMES[0] and len(command) == 6 and command[2] == EXPECTED_REPLACE_SCRIPT
                    and self.failure == "receipt-auth"):
                result.password_change_attempted = True
            return result
        finally:
            for descriptor in descriptors:
                os.close(descriptor)


def _global(kat):
    # Independent input, not a rendering of the initial-setup parser/profile.
    return ("schema_version: 1\ncommon:\n  mgmt:\n    dhcp-server:\n      status: disabled\n"
            "    ztp:\n      status: disabled\n    http:\n      status: disabled\n"
            "switches:\n- ib:\n    system:\n      ztp:\n        config-save: enabled\n"
            "      dns:\n        server:\n        - 203.0.113.53\n"
            "      date-time:\n        timezone: Asia/Taipei\n"
            "      aaa:\n        user:\n          admin:\n            password: "
            + json.dumps(kat["YESCRYPT"]) + "\n")


@contextmanager
def d7_case(test, *, mode="replace", apply=False, plan=False, failure=None, direct=False,
            yes=True, invalid_yaml=False, mutate_input=False, extra=(), managed=False,
            confirmation_answer="yes", reporting_observations=None):
    """One owned project and real scripts. Runtime is solely Root's future lease."""
    owned = owned_test_root()
    if os.environ.get("TMPDIR") != str(owned):
        raise RuntimeError("FIXTURE HOLD: explicit owned TMPDIR required")
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="d7-workflow-", dir=owned)))
        home, project, service = root / "home", root / "project", root / "ztp/config/nvos"
        for path in (home, project, service / "template"):
            path.mkdir(mode=0o700, parents=True)
        stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
        stack.enter_context(mock.patch.dict(sys.modules))
        app = load_script("d7_main_" + format(id(root), "x"), INITIAL)
        stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
        kat = strict_kat(app)  # Original RAM-only reader/backend, never author-executed.
        world = _ReplaceWorld(test, app, kat, failure=failure, direct=direct)
        generator = load_script("d7_generator_" + format(id(root), "x"), ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py")
        publisher = load_script("d7_publisher_" + format(id(root), "x"), ROOT / "ztp/config/cumulus/d-hostname2mac.py")
        (project / "01-global.yaml").write_text(_global(kat), encoding="utf-8")
        (project / "01-global.yaml").chmod(0o600)
        for name in ("ib.csv", "02-devices_config.csv"):
            (project / name).write_text(CSV, encoding="ascii")
        public_workbook(project / "p2p.xlsx")
        test.assertEqual([(NAMES[0], "eth0", JUMP, "swp1"), (NAMES[1], "eth0", JUMP, "swp2")],
            [(item.left_device, item.left_port, item.right_device, item.right_port)
             for item in app.parse_p2p(project / "p2p.xlsx")])
        (project / "02-dhcp-subnet_config.csv").write_text("PUBLIC subnet authority\n", encoding="ascii")
        (project / "required.pub").write_text(world.required_line + "\n", encoding="ascii")
        neutral = project / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
        neutral.parent.mkdir(parents=True)
        neutral.write_text("DNS=192.0.2.53\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n", encoding="ascii")
        output = project / "99-output-ib_nvl"
        output.mkdir()
        (service / "template/99-output-ib_nvl").symlink_to(output)
        (service / "template/01-global.yaml").symlink_to(project / "01-global.yaml")
        (service / "default.yaml").write_text("- set:\n    system:\n      ztp:\n        config-save: enabled\n", encoding="ascii")
        release = output / "20261118_010203-ib"
        devices = [{"hostname": name, "eth0_ip": f"203.0.113.{index+11}", "eth0_pfx": "24",
                    "eth0_gw": "203.0.113.1", "eth0_mac": MACS[index], "has_eth1": False,
                    "eth1_ip": "", "eth1_pfx": "", "eth1_gw": "", "eth1_mac": ""}
                   for index, name in enumerate(NAMES)]
        cfg = {"system": {"ztp": {"config-save": "enabled"}, "dns": {"server": ["203.0.113.53"]},
                          "date-time": {"timezone": "Asia/Taipei"},
                          "aaa": {"user": {"admin": {"password": kat["YESCRYPT"]}}}}}
        generation_output = io.StringIO()
        with redirect_stdout(generation_output), redirect_stderr(generation_output):
            counts = generator._generate_group_ib(devices, cfg, str(release))
            inventory = publisher.load_csv(project / "02-devices_config.csv", switch_scope="ib")
            context = publisher._nvos_dir_context(str(service / "template/99-output-ib_nvl" / release.name))
            published = publisher._publish_single_nvos(context, inventory, switch_scope="ib")
        test.assertEqual((2, 0), counts)
        test.assertIs(published, True, "real PUBLIC generator/publisher must complete")
        test.assertEqual(release.resolve(), (service / "latest_yaml").resolve(strict=True))
        manifest = json.loads((release / "release-manifest.json").read_text())
        # Preserve the real publisher's manifest BYTES, including its actual
        # formatting. Only the schema2 parent is handwritten by this fixture.
        manifest_bytes = (release / "release-manifest.json").read_bytes()
        test.assertEqual("20261118_010203-nvos", manifest["release_id"])
        test.assertEqual(set(NAMES), {row["hostname"] for row in manifest["devices"]})
        inputs = {"global": "01-global.yaml", "devices": "02-devices_config.csv",
                  "subnet": "02-dhcp-subnet_config.csv", "p2p": "p2p.xlsx"}
        parent = {"schema_version": 2, "release_id": "PUBLIC-parent-71", "validation": "passed",
            "generated_at": "2026-11-18T00:00:00+08:00", "project": project.name,
            "deployment_scope": "all", "switch_scope": "ib", "dhcp_status": "disabled",
            "input_paths": inputs,
            "inputs": {key: hashlib.sha256((project / path).read_bytes()).hexdigest()
                       for key, path in inputs.items()},
            "components": {"nvos": {"release_id": "20261118_010203-nvos",
                "release_dir": "99-output-ib_nvl/20261118_010203-ib",
                "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "published_marker_sha256": hashlib.sha256(
                    (release / ".published-complete").read_bytes()).hexdigest()}}}
        (project / "99-output-ztp").mkdir()
        (project / "99-output-ztp/current-release.json").write_text(json.dumps(parent), encoding="ascii")
        test.assertTrue(hmac.compare_digest(manifest_bytes, (release / "release-manifest.json").read_bytes()))
        for name in NAMES:
            world.payloads[name] = (release / (name + ".yaml")).read_bytes()
            test.assertTrue(("hostname: " + name).encode() in world.payloads[name])
            test.assertTrue(b"203.0.113.53:" in world.payloads[name])
            test.assertFalse(b"ntp:" in world.payloads[name], "NTP is independently absent from this global/YAML")
        if invalid_yaml:
            (release / (NAMES[0] + ".yaml")).unlink()
        if mutate_input:
            with (project / "02-dhcp-subnet_config.csv").open("ab") as stream:
                stream.write(b"PUBLIC changed after release\n")
        report = root / "out/report.log"
        argv = [str(INITIAL), "--project-dir", str(project),
                "--target-cache", str(root / "targets.json"), "--report", str(report),
                "--snapshot-dir", str(root / "snapshots"), "--execution-mode", "management"]
        if mode is not None:
            argv += ["--config-mode", mode]
        if apply:
            argv += ["--apply"] + (["--yes"] if yes else [])
        if plan:
            argv += ["--plan"]
        if direct:
            argv += ["--direct-access", NAMES[0]]
        # FD-mode --apply requires --yes; interactive confirmation cases use
        # only fixed prompt boundaries, preserving the original policy checks.
        if not apply or yes:
            argv += stack.enter_context(credentials_fd(strict_fd_payload(kat)))
        else:
            argv += ["--ib-initial-password-env", "HTTP_TEST_D7_INITIAL_VALUE"]
            stack.enter_context(mock.patch.dict(os.environ, {"HTTP_TEST_D7_INITIAL_VALUE": kat["PASSWORD"]}))
        argv += list(extra)
        original_run = app.subprocess.run
        validator_path = shutil.which("ssh-keygen")
        def local_child(vector, **options):
            vector = list(vector)
            native = [sys.executable, "-I", "-S", "-B", str(INITIAL.resolve()), "--_verify-password"]
            validator = (len(vector) == 6 and vector[0] == validator_path
                         and vector[1:] == ["-l", "-E", "sha256", "-f", "/dev/stdin"])
            if vector == native:
                if (set(options) != {"input", "text", "capture_output", "timeout", "check", "env"}
                        or options.get("text") is not True or options.get("capture_output") is not True
                        or options.get("check") is not False or options.get("timeout") != 8 or options.get("env") != {
                        "PATH": os.defpath, "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"}):
                    return world.deny()
                try:
                    payload = json.loads(options["input"])
                except (TypeError, ValueError):
                    return world.deny()
                if (type(payload) is not dict or set(payload) != {"password", "hash"}
                        or any(type(payload[key]) is not str for key in payload)
                        or not hmac.compare_digest(payload["password"], kat["PASSWORD"])
                        or not hmac.compare_digest(payload["hash"], kat["YESCRYPT"])):
                    return world.deny()
                world.local_children.append("native8")
            elif validator:
                if (set(options) != {"input", "capture_output", "text", "timeout", "check"}
                        or options.get("text") is not True or options.get("capture_output") is not True
                        or options.get("check") is not False or options.get("timeout") != 10
                        or options.get("input") != world.required_line + "\n"):
                    return world.deny()
                world.local_children.append("public-fingerprint10")
            else:
                return world.deny()
            return original_run(vector, **options)
        def prompt(label):
            world.prompts.append(label)
            if label in ("IB target password (admin): ", "Confirm IB target password: "):
                return kat["PASSWORD"]
            if label == "Authorize this change and subsequent eligible IB devices? [y/N]: ":
                visible = console.getvalue()
                heading = visible.rfind("FIRST DEVICE CHANGE:")
                world.confirmation_texts.append(visible[heading:] if heading != -1 else "")
                return confirmation_answer
            return world.deny()
        real_permit, real_ready = app.obtain_write_permit, app.verify_ipv4_login
        real_direct_ready = app._wait_direct_ipv4_readback
        real_authorize = app.RuntimeCoordinator.authorize
        def authorize(coordinator, target, reason):
            world.authorizations.append(reason)
            return real_authorize(coordinator, target, reason)
        def permit(category="nvue"):
            if category not in {"nvue", "public_key", "password", "host_key", "config_backup"}:
                return world.deny()
            world.permits.append(category)
            return real_permit(category)
        def readiness(target, *arguments, **options):
            policy = options["readiness_policy"]
            world.readiness.append((target.ib.hostname, policy.first_delay, policy.interval, policy.attempts))
            world.events.append((target.ib.hostname, "D4"))
            return real_ready(target, *arguments, **options)
        def direct_readiness(target, *arguments, **options):
            policy = options["readiness_policy"]
            world.readiness.append((target.ib.hostname, policy.first_delay, policy.interval, policy.attempts))
            world.events.append((target.ib.hostname, "DIRECT_READY"))
            return real_direct_ready(target, *arguments, **options)
        stack.enter_context(mock.patch.object(sys, "argv", argv))
        stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
        stack.enter_context(mock.patch.object(app, "_new_jump_sessions", legacy_jump_sessions_factory(app)))
        stack.enter_context(mock.patch.object(app, "probe_ethernet_key", return_value="key"))
        stack.enter_context(mock.patch.object(app, "run_on_ethernet", side_effect=world.ethernet))
        stack.enter_context(mock.patch.object(app, "interactive_run", side_effect=world.transport))
        stack.enter_context(mock.patch.object(app, "_read_local_interfaces", return_value=()))
        stack.enter_context(mock.patch.object(app, "obtain_write_permit", side_effect=permit))
        stack.enter_context(mock.patch.object(app.RuntimeCoordinator, "authorize", new=authorize))
        stack.enter_context(mock.patch.object(app, "verify_ipv4_login", side_effect=readiness))
        stack.enter_context(mock.patch.object(app, "_wait_direct_ipv4_readback", side_effect=direct_readiness))
        stack.enter_context(mock.patch.object(app, "getpass", Facade(app.getpass, getpass=prompt)))
        stack.enter_context(mock.patch.object(app, "input", side_effect=prompt, create=True))
        if reporting_observations is not None:
            from copy import deepcopy

            summarize = app.print_initial_setup_summary
            subject = NAMES[1].lower()

            def observe_report(project, args, targets, candidate_count, snapshots_failed,
                               records, *rest, **options):
                before = deepcopy(records[subject])
                status = summarize(project, args, targets, candidate_count, snapshots_failed,
                                   records, *rest, **options)
                reporting_observations.append((before, deepcopy(records[subject])))
                return status

            stack.enter_context(mock.patch.object(app, "print_initial_setup_summary", new=observe_report))
        stack.enter_context(mock.patch.object(app, "time", Facade(time,
            sleep=world.sleep, monotonic=world.monotonic)))
        stack.enter_context(mock.patch.object(app, "subprocess", Facade(subprocess, run=local_child, Popen=world.deny)))
        stack.enter_context(mock.patch.object(app, "os", Facade(os, **{name: world.deny for name in (
            "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe", "execl", "execlp",
            "execlpe", "posix_spawn", "posix_spawnp", "spawnl", "spawnle", "spawnlp", "spawnlpe",
            "spawnv", "spawnve", "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")})))
        stack.enter_context(mock.patch.object(app, "pty", Facade(app.pty, fork=world.deny, openpty=world.deny)))
        stack.enter_context(mock.patch.object(app, "multiprocessing", Facade(app.multiprocessing,
            get_context=world.deny, Process=world.deny)))
        paths = app._import_tools("tools.login_path")
        test.assertEqual((ROOT / "tools/login_path.py").resolve(), Path(paths.__file__).resolve())
        stack.enter_context(mock.patch.object(paths, "subprocess", Facade(subprocess,
            run=world.deny, Popen=world.deny)))
        stack.enter_context(mock.patch.object(app, "socket", Facade(socket, socket=world.deny,
            create_connection=world.deny, gethostname=lambda: "PUBLIC-management",
            getfqdn=lambda: "PUBLIC-management.example.test")))
        stack.callback(lambda: app.REPORT_HANDLE.close() if app.REPORT_HANDLE is not None else None)
        console, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(console), redirect_stderr(errors):
            if managed:
                try:
                    code = app.main(method_cycle=SimpleNamespace(start=world.deny, close=world.deny))
                except app.SetupError:
                    code = 2
            else:
                code = app._standalone_main_with_report_cleanup()
        if world.effects:
            raise RuntimeError("FIXTURE HOLD: unknown D7 IO cannot become a worker/business FAIL")
        summaries = list(report.parent.rglob("summary.json")) if report.parent.exists() else []
        test.assertLessEqual(len(summaries), 1, "one own run cannot create multiple summaries")
        evidence = json.loads(summaries[0].read_text()) if summaries else None
        device_json = ([json.loads(path.read_text()) for path in summaries[0].parent.glob("*.json")
                        if path.name != "summary.json"] if summaries else [])
        report_text = report.read_text() if report.exists() else ""
        if app.REPORT_HANDLE is not None and not managed:
            test.assertTrue(app.REPORT_HANDLE.closed, "real wrapper must close its report before fixture cleanup")
            test.assertEqual(report.resolve(), Path(app.REPORT_HANDLE.name).resolve())
        diagnostics = [console.getvalue(), errors.getvalue(), report_text]
        diagnostics += [json.dumps([evidence, device_json, world.authorizations], ensure_ascii=ascii_only)
                        for ascii_only in (False, True)]
        for secret in (kat["PASSWORD"], kat["YESCRYPT"]):
            variants = {secret, repr(secret), repr(secret)[1:-1]}
            for ascii_only in (False, True):
                quoted = json.dumps(secret, ensure_ascii=ascii_only)
                variants.update((quoted, quoted[1:-1]))
            for value in diagnostics:
                test.assertFalse(any(item in value for item in variants if item),
                                 "private qualification data must be withheld before any field assertion")
        for payload in world.payloads.values():
            encoded = base64.b64encode(payload).decode("ascii")
            for value in diagnostics:
                test.assertFalse(encoded in value, "sealed DATA must not leak private qualification material")
        yield SimpleNamespace(app=app, root=root, project=project, release=release, manifest=manifest,
            code=code, evidence=evidence, device_json=device_json,
            text=console.getvalue() + errors.getvalue() + report_text,
            world=world, argv=argv)
        if app.REPORT_HANDLE is not None:
            app.REPORT_HANDLE.close()


class ReplaceWorkflowTests(unittest.TestCase):
    def records(self, case):
        self.assertIsNotNone(case.evidence, "genuine MAIN must persist its real summary")
        records = case.evidence["records"]
        self.assertEqual(set(NAMES), {row["hostname"] for row in records.values()})
        self.assertEqual(set(NAMES), {row["hostname"] for row in case.device_json})
        return {row["hostname"]: row for row in records.values()}

    def test_declined_replace_keeps_unstarted_direct_record_out_of_display_defaults(self):
        observations = []
        with d7_case(self, apply=True, yes=False, confirmation_answer="no",
                     extra=("--direct-access", NAMES[1]),
                     reporting_observations=observations) as case:
            key = NAMES[1].lower()
            confirmations = [label for label in case.world.prompts
                             if label.startswith("Authorize this change")]
            self.assertEqual(1, len(confirmations))
            self.assertEqual(1, case.code)
            self.assertEqual("FAILED", case.evidence["result"])
            self.assertEqual("device changes were not authorized", case.evidence["batch_stop_reason"])
            self.assertEqual([], case.world.permits)
            self.assertEqual({}, case.world.device_files)
            self.assertFalse(any(name == NAMES[1] for name, _ in case.world.events))
            self.assertEqual(1, len(observations))
            before, after = observations[0]
            self.assertEqual("NOT_ATTEMPTED", before["category"])
            self.assertEqual("direct", before["route"]["path"])
            self.assertNotIn("oob", before, "qualify a genuinely sparse caller record")
            self.assertNotIn("port", before, "qualify a genuinely sparse caller record")
            self.assertTrue(before == after, "rendering must not write display defaults to caller data")
            self.assertTrue(after == case.evidence["records"][key],
                            "persist the caller record, not its display projection")
            self.assertIn(f"  Device facts: {key}", case.text)

    def test_real_publish_then_readonly_and_apply_consume_exact_host_yaml(self):
        for apply in (False, True):
            with self.subTest(apply=apply), d7_case(self, apply=apply) as case:
                records = self.records(case)
                self.assertEqual(0 if apply else 2, case.code)
                self.assertEqual("SUCCESS" if apply else "INCOMPLETE", case.evidence["result"])
                self.assertEqual("replace", case.evidence["config_mode"])
                for name in NAMES:
                    row, body = records[name], case.world.payloads[name]
                    self.assertEqual("replace", row["config_mode"])
                    self.assertIs(row["needs_change"], True)
                    self.assertEqual("REPLACED" if apply else "WOULD_REPLACE", row["replace"]["verdict"])
                    self.assertEqual(str(case.release / (name + ".yaml")), row["replace"]["file"])
                    self.assertTrue(hmac.compare_digest(hashlib.sha256(body).hexdigest(), row["replace"]["sha256"]))
                    self.assertIs(row["verified_complete"], apply)
                    self.assertIs(row["writes_attempted"], apply)
                    if apply:
                        self.assertTrue(hmac.compare_digest(body, case.world.device_files[name]))
                        self.assertEqual(137, row["backup"]["bytes"])
                if not apply:
                    self.assertEqual([], case.world.permits)
                    self.assertEqual({}, case.world.device_files)
                    self.assertIn(WARNING, case.text)
                else:
                    self.assertEqual([], case.world.prompts, "--yes/FD mode must not prompt")
                    self.assertNotIn("FIRST DEVICE CHANGE:", case.text)

    def test_changed_release_input_stops_whole_main_before_any_device_write(self):
        with d7_case(self, apply=True, mutate_input=True) as case:
            self.assertEqual(2, case.code)
            self.assertEqual([], case.world.permits)
            self.assertEqual({}, case.world.device_files)
            self.assertFalse(any(event in {AUTOSAVE, CONFIGSAVE, NTP, "BACKUP", "REPLACE", "APPLY", "SAVE", "KEY", "DETACH"}
                                 for _name, event in case.world.events))
            self.assertIn("load", case.text)

    def test_real_pipeline_order_backup_restore_key_then_final_d4(self):
        with d7_case(self, apply=True) as case:
            self.assertEqual(0, case.code)
            events = [event for name, event in case.world.events if name == NAMES[0]]
            # Independent complete side-effect order, with actual readonly
            # proofs retained between writes rather than filtered from logs.
            expected_writes = ["BACKUP", AUTOSAVE, CONFIGSAVE, "APPLY", "SAVE",
                               "REPLACE", "APPLY", "SAVE", AUTOSAVE, NTP, "APPLY", "SAVE", "KEY"]
            actual_writes = [event for event in events if event in expected_writes or event == "DETACH"]
            self.assertEqual(expected_writes, actual_writes)
            self.assertLess(events.index("O5"), events.index("BACKUP"))
            replacement = events.index("REPLACE")
            self.assertIn("ZTP", events[:replacement])
            self.assertIn("ZTP", events[replacement + 1:events.index("KEY")])
            self.assertLess(events.index("KEY"), events.index("D4"))
            self.assertEqual([(name, 15, 10, 9) for name in NAMES], case.world.readiness)
            self.assertEqual([15, 15], case.world.delays)
            metrics = {key: sum(row["metrics"][key] for row in self.records(case).values())
                       for key in ("config_backup_attempts", "public_key_install_attempts", "nvue_write_commands")}
            self.assertEqual(2, metrics["config_backup_attempts"])
            self.assertEqual(2, metrics["public_key_install_attempts"])
            self.assertEqual(len([event for name, event in case.world.events
                                  if event in {AUTOSAVE, CONFIGSAVE, NTP, "REPLACE", "APPLY", "SAVE", "DETACH"}]),
                             metrics["nvue_write_commands"])

    def test_one_bad_yaml_does_not_fallback_patch_or_stop_second_device(self):
        with d7_case(self, apply=True, invalid_yaml=True) as case:
            records = self.records(case)
            self.assertEqual(2, case.code)
            self.assertEqual("YAML_MISSING_OR_INVALID", records[NAMES[0]]["replace"]["verdict"])
            self.assertFalse(records[NAMES[0]]["writes_attempted"])
            self.assertNotIn(NAMES[0], case.world.device_files)
            self.assertFalse(any(name == NAMES[0] and event == "BACKUP" for name, event in case.world.events))
            self.assertEqual("REPLACED", records[NAMES[1]]["replace"]["verdict"])
            self.assertTrue(records[NAMES[1]]["verified_complete"])

    def test_replace_and_apply_failures_detach_once_and_do_not_replay(self):
        for failure, expected in (("replace", "FAILED_DETACHED"), ("apply", "FAILED_DETACHED"),
                                  ("apply-detach", "FAILED_DETACH_FAILED")):
            with self.subTest(failure=failure), d7_case(self, apply=True, failure=failure) as case:
                row = self.records(case)[NAMES[0]]
                self.assertEqual(2, case.code)
                self.assertEqual(expected, row["replace"]["verdict"])
                self.assertTrue(row["writes_attempted"])
                self.assertFalse(row["verified_complete"])
                self.assertIn(NAMES[0], case.world.device_files)
                events = [event for name, event in case.world.events if name == NAMES[0]]
                self.assertEqual(1, events.count("REPLACE"))
                self.assertEqual(1, events.count("DETACH"))
                self.assertNotIn("KEY", events)
                self.assertEqual("REPLACED", self.records(case)[NAMES[1]]["replace"]["verdict"])

    def test_replace_preparation_failure_is_not_device_replace_failure(self):
        with d7_case(self, apply=True, failure="replace-preparation") as case:
            records = self.records(case)
            row = records[NAMES[0]]
            events = [event for name, event in case.world.events if name == NAMES[0]]
            self.assertEqual(2, case.code)
            self.assertTrue(row["writes_attempted"])
            self.assertFalse(row["verified_complete"])
            self.assertNotIn(row["replace"]["verdict"],
                             {"REPLACED", "FAILED_DETACHED", "FAILED_DETACH_FAILED"})
            self.assertNotIn(NAMES[0], case.world.device_files)
            self.assertEqual(1, events.count("REPLACE_PREPARATION_FAILED"))
            self.assertNotIn("REPLACE", events)
            self.assertFalse(set(events[events.index("REPLACE_PREPARATION_FAILED") + 1:]) & {
                "DETACH", "DEFER", "APPLY", "SAVE", "KEY", "D4", "READ", "ZTP", AUTOSAVE, NTP})
            self.assertEqual("REPLACED", records[NAMES[1]]["replace"]["verdict"])

    def test_save_and_postapply_ztp_failure_remain_written_unverified(self):
        for failure in ("save", "post-ztp"):
            with self.subTest(failure=failure), d7_case(self, apply=True, failure=failure) as case:
                row = self.records(case)[NAMES[0]]
                self.assertEqual(2, case.code)
                self.assertTrue(row["writes_attempted"])
                self.assertFalse(row["verified_complete"])
                events = [event for name, event in case.world.events if name == NAMES[0]]
                self.assertEqual(1, events.count("REPLACE"))
                self.assertNotIn("KEY", events)
                self.assertFalse(row.get("script_error", False))

    def test_replace_restore_readback_and_post_ztp_gate_public_keys(self):
        for failure in (None, "restore-readback", "post-ztp"):
            with self.subTest(failure=failure), d7_case(self, apply=True, failure=failure) as case:
                records = self.records(case)
                row = records[NAMES[0]]
                events = [event for name, event in case.world.events if name == NAMES[0]]
                self.assertEqual(1, events.count("REPLACE"))
                self.assertIn("ZTP", events[:events.index("REPLACE")])
                post = events[events.index("REPLACE") + 1:]
                expected_writes = ["APPLY", "SAVE", AUTOSAVE, NTP, "APPLY", "SAVE"]
                if failure is None:
                    expected_writes.append("KEY")
                self.assertEqual(expected_writes, [event for event in post if event in {
                    "APPLY", "SAVE", AUTOSAVE, CONFIGSAVE, NTP, "KEY", "DETACH", "BACKUP"}])
                saved = max(index for index, event in enumerate(post) if event == "SAVE")
                readback = post.index("READ", saved + 1)
                self.assertTrue(row["writes_attempted"])
                self.assertEqual("REPLACED", records[NAMES[1]]["replace"]["verdict"])
                if failure == "restore-readback":
                    self.assertEqual(1, post.count("RESTORE_READBACK_MISSING"))
                    self.assertEqual("RESTORE_READBACK_MISSING", post[readback + 1])
                    self.assertNotIn("ZTP", post)
                else:
                    self.assertEqual(1, post.count("ZTP"))
                    self.assertLess(readback, post.index("ZTP"))
                    self.assertNotIn("RESTORE_READBACK_MISSING", post)
                if failure is not None:
                    self.assertEqual(2, case.code)
                    self.assertFalse(row["verified_complete"])
                    self.assertNotIn("KEY", post)
                    self.assertNotIn("D4", post)
                else:
                    self.assertEqual(0, case.code)
                    self.assertTrue(row["verified_complete"])
                    self.assertLess(post.index("ZTP"), post.index("KEY"))
                    self.assertLess(post.index("KEY"), post.index("D4"))

    def test_identity_or_backup_failure_cannot_reach_replace(self):
        for failure in ("identity", "backup"):
            with self.subTest(failure=failure), d7_case(self, apply=True, failure=failure) as case:
                row = self.records(case)[NAMES[0]]
                self.assertEqual(2, case.code)
                self.assertEqual("FAILED_IDENTITY_MISMATCH" if failure == "identity" else "FAILED_CONFIG_BACKUP",
                                 row["category"])
                self.assertFalse(any(name == NAMES[0] and event == "REPLACE" for name, event in case.world.events))
                self.assertNotIn(NAMES[0], case.world.device_files)
                self.assertIsNone(row["backup"], "a failed/unreached backup is not successful proof")
                self.assertEqual("REPLACED", self.records(case)[NAMES[1]]["replace"]["verdict"])

    def test_unqualified_success_receipt_or_auth_metadata_is_never_replaced(self):
        for failure in ("receipt-path", "receipt-hash", "receipt-extra", "receipt-auth"):
            with self.subTest(failure=failure), d7_case(self, apply=True, failure=failure) as case:
                row = self.records(case)[NAMES[0]]
                self.assertEqual(2, case.code)
                self.assertNotEqual("REPLACED", row["replace"]["verdict"])
                self.assertTrue(row["writes_attempted"])
                self.assertFalse(row["verified_complete"])
                self.assertFalse(any(name == NAMES[0] and event == "KEY" for name, event in case.world.events))
                self.assertFalse(row.get("script_error", False))

    def test_ipv4_deferred_rc_is_early_and_final_d4_is_after_key(self):
        for failure in (None, "rc"):
            with self.subTest(failure=failure), d7_case(self, apply=True, direct=True, failure=failure) as case:
                row = self.records(case)[NAMES[0]]
                events = [event for name, event in case.world.events if name == NAMES[0]]
                self.assertEqual(1, events.count("REPLACE"))
                self.assertEqual(1, events.count("DEFER"))
                self.assertLess(events.index("DEFER"), events.index("RC_PENDING"))
                if failure is None:
                    self.assertEqual(1, events.count("RC_PENDING"))
                    self.assertEqual(1, events.count("RC_READY"))
                    self.assertLess(events.index("RC_PENDING"), events.index("RC_READY"))
                    self.assertEqual(["O5", "ROUTE", "READ"],
                                     events[events.index("RC_READY") + 1:events.index("RC_READY") + 4])
                    restored = events.index(AUTOSAVE, events.index("REPLACE"))
                    self.assertLess(events.index("READ", events.index("RC_READY")), restored)
                    self.assertLess(events.index("RC_READY"), events.index("KEY"))
                    self.assertLess(events.index("KEY"), events.index("DIRECT_READY", events.index("KEY")))
                    self.assertEqual(1, events.count("DIRECT_READY"), "early rc cannot mint a second D4 loop")
                    self.assertTrue(row["verified_complete"])
                    # Routed and direct groups need not finish in inventory order.
                    self.assertCountEqual([(NAMES[0], 15, 10, 9), (NAMES[1], 15, 10, 9)], case.world.readiness)
                    self.assertCountEqual([10, 15, 15], case.world.delays)
                    for name, expected in ((NAMES[0], [("RC_PENDING", 10), ("DIRECT_READY", 15)]),
                                           (NAMES[1], [("D4", 15)])):
                        self.assertEqual(expected, [(stage, seconds)
                                         for peer, stage, seconds in case.world.sleep_witnesses if peer == name])
                else:
                    self.assertFalse(row["verified_complete"])
                    self.assertNotIn("KEY", events)
                    self.assertNotIn("DIRECT_READY", events)
                    self.assertNotIn("RC_READY", events)
                    self.assertEqual(1, events.count("RC_PENDING"))
                    self.assertEqual(1, events.count("RC_FAILED"))

    def test_direct_replace_same_failure_rc_only_cleans_up_proven_apply_failure(self):
        cases = (
            ("typed-apply7", "RC_APPLY_FAILED", 1),
            ("typed-save7", "RC_SAVE_FAILED", 0),
            ("typed-contradiction", "RC_UNQUALIFIED", 0),
        )
        for failure, label, detach_count in cases:
            with self.subTest(failure=failure), d7_case(self, apply=True, direct=True, failure=failure) as case:
                records = self.records(case)
                row = records[NAMES[0]]
                events = [event for name, event in case.world.events if name == NAMES[0]]
                self.assertEqual(2, case.code)
                self.assertTrue(row["writes_attempted"])
                self.assertFalse(row["verified_complete"])
                self.assertEqual("REPLACED", records[NAMES[1]]["replace"]["verdict"])
                for marker in ("REPLACE", "DEFER", "RC_PENDING", label):
                    self.assertEqual(1, events.count(marker))
                positions = [events.index(marker) for marker in ("REPLACE", "DEFER", "RC_PENDING", label)]
                self.assertEqual(sorted(positions), positions)
                self.assertEqual(detach_count, events.count("DETACH"))
                if detach_count:
                    self.assertGreater(events.index("DETACH"), positions[-1])
                    self.assertEqual("FAILED_DETACHED", row["replace"]["verdict"])
                else:
                    self.assertNotIn(row["replace"]["verdict"], {"FAILED_DETACHED", "FAILED_DETACH_FAILED"})
                if failure == "typed-contradiction":
                    self.assertNotEqual("REPLACED", row["replace"]["verdict"])
                self.assertFalse(set(events[positions[0] + 1:]) & {
                    AUTOSAVE, NTP, "APPLY", "SAVE", "KEY", "D4", "DIRECT_READY", "RC_READY"})

    def test_plan_never_enters_device_pipeline_and_full_replace_confirm_is_once(self):
        with d7_case(self, plan=True) as case:
            self.assertEqual(0, case.code)
            self.assertEqual([], case.world.events)
            self.assertEqual([], case.world.permits)
            for name in NAMES:
                self.assertIn(name + ".yaml", case.text)
            self.assertIn(WARNING, case.text)
        with d7_case(self, apply=True, yes=False) as case:
            self.assertEqual(0, case.code)
            confirmations = [label for label in case.world.prompts if label.startswith("Authorize this change")]
            self.assertEqual(1, len(confirmations))
            self.assertTrue(case.world.authorizations)
            self.assertEqual(1, len(case.world.confirmation_texts))
            self.assertEqual(1, case.world.confirmation_texts[0].count(WARNING),
                             "the FIRST real authorization must visibly warn before input")
            self.assertIn(WARNING, case.text)

    def test_patch_default_and_explicit_patch_preserve_the_original_pipeline(self):
        observed = []
        for mode in (None, "patch"):
            with self.subTest(mode=mode), d7_case(self, mode=mode, apply=False) as case:
                records = self.records(case)
                self.assertEqual(2, case.code)
                self.assertEqual("patch", case.evidence["config_mode"])
                self.assertEqual([], case.world.permits)
                self.assertEqual({}, case.world.device_files)
                self.assertEqual([True, False], [records[name]["needs_change"] for name in NAMES])
                self.assertEqual(["CHECKED_NEEDS_CONFIGURATION", "CHECKED_EXISTING_CONFIGURATION"],
                                 [records[name]["category"] for name in NAMES])
                observed.append(case.world.events)
        self.assertEqual(observed[0], observed[1])

    def test_replace_scope_refuses_leaf_generation_and_managed_before_device_io(self):
        for extra, managed in ((("--execution-mode", "ethernet", "--local-ethernet-hostname", JUMP), False),
                               (("--execution-mode", "auto", "--local-ethernet-hostname", JUMP), False),
                               (("--generate-json",), False), ((), True)):
            with self.subTest(extra=extra, managed=managed), d7_case(self, apply=managed,
                    extra=extra, managed=managed) as case:
                self.assertEqual(2, case.code)
                self.assertEqual([], case.world.events)
                self.assertEqual([], case.world.permits)


class _OwnedProcess(Facade):
    """Witness only; all lifecycle methods delegate to the actual owned child."""
    def __init__(self, process, task_name):
        super().__init__(process)
        self.task_name, self.calls = task_name, []

    def start(self):
        self.calls.append("start")
        return self.original.start()

    def terminate(self):
        self.calls.append("terminate")
        return self.original.terminate()

    def kill(self):
        self.calls.append("kill")
        return self.original.kill()

    def join(self, *args, **kwargs):
        self.calls.append("join")
        return self.original.join(*args, **kwargs)


@contextmanager
def fence_case(test, mode):
    """Finite authority controls, NOT seventeen real device pipelines.

    Actual scheduler/worker/parent/Pipe/Event are retained. The one replaced
    business callback only consumes the real readonly completion fence and
    returns NOT_ATTEMPTED plus PUBLIC observations, never a fabricated PASS.
    """
    owned = owned_test_root()
    if os.environ.get("TMPDIR") != str(owned):
        raise RuntimeError("FIXTURE HOLD: explicit owned TMPDIR required")
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="d7-fence-", dir=owned)))
        home = root / "home"
        home.mkdir(mode=0o700)
        stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
        stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
        stack.enter_context(mock.patch.dict(sys.modules))
        app = load_script("d7_fence_" + format(id(root), "x"), INITIAL)
        # An absent fence is explicit interface ERROR, before any fork/native.
        helper = app._wait_replace_deferred_completion
        paths = app._import_tools("tools.login_path")
        parallel = mode.startswith("parallel-")
        context = multiprocessing.get_context("fork") if parallel else None
        clock = context.RawValue("d", 0.0) if parallel else SimpleNamespace(value=0.0)
        pending = context.Event() if parallel else None
        release = context.Event() if parallel else None
        parent_ready = context.Event() if parallel else None
        fence_password = "example"  # PUBLIC input for the modeled fence transport.
        world = _ReplaceWorld(test, app, {'PASSWORD': fence_password},
                              direct=True, failure="rc-pending" if mode in {"inline-clip", "inline-long", "parallel-timeout"} else
                              "rc" if mode == "inline-fatal" else None)
        original_deny = world.deny
        def denied(*arguments, **options):
            (root / "unknown-effect").write_text("PUBLIC refused external effect\n", encoding="ascii")
            return original_deny(*arguments, **options)
        world.deny = denied
        world.rows[NAMES[0]] = world.complete(NAMES[0], after_replace=True)
        children, prompt_observations = [], []
        after_pause_waits = [0]
        timeout = 15 if parallel else 125 if mode == "inline-long" else 25
        args = SimpleNamespace(apply=True, yes=True, force=False, max_workers=16,
            task_timeout=timeout, run_stamp="20261118-010203", report=root / "report.log",
            execution_mode="management", _on_management_server=True, verbose=False)

        def target(index):
            name = NAMES[index] if index < 2 else "EXAMPLE-CONTROL-%02d" % index
            device = app.Device(name, "ib", "203.0.113.11", "203.0.113.11/24", "203.0.113.1",
                                MACS[0], "", "")
            route = paths.Route(name, "direct", "NO_MGMT_LINK", None, None, None)
            return app.Target(device, None, "", "eth0", route=route)
        tasks = [app.PreparedIBTask(target(index), app.DirectEndpoint("203.0.113.11", None), "", False)
                 for index in range(17 if parallel else 1)]

        def sleep(seconds):
            if parallel and app._WORKER_CONNECTION is None:
                # The parent can yield while reaping a job whose pipe closed.
                test.assertEqual(0.05, seconds)
                time.sleep(seconds)
                return
            world.delays.append(seconds)
            if not parallel:
                clock.value += seconds
                return
            pending.set()
            test.assertTrue(parent_ready.wait(5), "parent must publish both original job deadlines before test time advances")
            if mode == "parallel-pause":
                test.assertTrue(release.wait(5), "own pause barrier must release the actual pending worker")
                clock.value += seconds
            elif mode == "parallel-stop":
                test.assertTrue(app._WORKER_STOP.wait(5), "original parent must set the actual worker stop Event")
            else:
                # Move past the ORIGINAL parent deadline only after this child
                # has reached pending; then keep it alive for actual TERM.
                clock.value = 16.0
                test.assertTrue(release.wait(5), "original parent TERM must interrupt the pending own child")

        def consume(task, _args, _policy, _initial, _services, _keys, _key, _authorized):
            name = task.target.ib.hostname
            result = {"hostname": name, "outcome": "NOT_ATTEMPTED", "reason": "PUBLIC fence control only",
                      "direct_rows": [], "batch_error": ""}
            if parallel and name == NAMES[1] and mode in {"parallel-pause", "parallel-stop"}:
                try:
                    answer = app.worker_request("current-password", "PUBLIC control prompt")
                    if answer != "PUBLIC-current-value-71!":
                        raise AssertionError("only the declared PUBLIC prompt reply is admitted")
                    test.assertTrue(release.wait(5), "own prompt worker remains alive until the parent observes pause")
                    result["prompt_control"] = True
                except app.BatchStopped:
                    result["prompt_stopped"] = True
                return result
            if name != NAMES[0]:
                return result
            before = app._TASK_DEADLINE
            connection = app._WORKER_CONNECTION
            stop = app._WORKER_STOP
            observed = {"before": before, "connection_module": type(connection).__module__,
                        "connection_type": type(connection).__name__, "stop_type": type(stop).__name__}
            if connection is not None:
                descriptor = connection.fileno()
                descriptor_stat = os.fstat(descriptor)
                observed["fd_inode"] = descriptor_stat.st_ino
                observed["fd_mode"] = stat.S_IFMT(descriptor_stat.st_mode)
            details = {}
            try:
                body = helper(task.target, "admin", fence_password, 10,
                    strict=False, policy=None, stamp="20261118-010203", details=details)
                observed.update(ok=True, readback_matches=body == "\n".join(world.rows[name]) + "\n",
                    identity_ok=details.get("identity", {}).get("ok") is True,
                    endpoint=(getattr(details.get("endpoint"), "address", None)))
            except (app.SetupError, app.BatchStopped) as error:
                observed.update(ok=False, error_type=type(error).__name__)
            observed.update(after=app._TASK_DEADLINE, events=[event for peer, event in world.events if peer == name],
                            sleeps=list(world.delays), clock=clock.value)
            result["fence_control"] = observed
            return result

        def prompt(label):
            test.assertEqual("Actual current IB password for EXAMPLE-IB002 (not OOB): ", label)
            test.assertTrue(pending.wait(5), "actual other worker must reach rc pending before a prompt changes time")
            test.assertEqual(2, len(children), "both original scheduler slots must have been started")
            test.assertTrue(all(child.is_alive() for child in children), "the other real worker must remain alive")
            prompt_observations.append((clock.value, sum(child.is_alive() for child in children)))
            if mode == "parallel-stop":
                raise EOFError("PUBLIC controlled cancellation")
            clock.value += 20.0
            return "PUBLIC-current-value-71!"

        real_wait = app.wait_connections
        def wait(connections, timeout):
            parent_ready.set()  # Original active[slot] construction precedes this first wait.
            if mode == "parallel-pause" and clock.value >= 20 and not release.is_set():
                after_pause_waits[0] += 1
                if after_pause_waits[0] >= 2:
                    release.set()
            return real_wait(connections, timeout=min(timeout, 0.02))

        if parallel:
            def process(*arguments, **options):
                test.assertIs(app._worker_entry, options.get("target"))
                worker_args = options.get("args")
                test.assertEqual(11, len(worker_args))
                # These are real context-created endpoints/Event, passed to
                # the unchanged worker_entry producer, not an authority flag.
                test.assertEqual("multiprocessing.connection", type(worker_args[0]).__module__)
                test.assertEqual("Event", type(worker_args[9]).__name__)
                child = _OwnedProcess(context.Process(*arguments, **options), worker_args[1].target.ib.hostname)
                children.append(child)
                return child
            def get_context(method):
                test.assertEqual("fork", method)
                return Facade(context, Process=process)
            stack.enter_context(mock.patch.object(app, "multiprocessing", Facade(multiprocessing, get_context=get_context)))
            stack.enter_context(mock.patch.object(app, "wait_connections", wait))
        else:
            stack.enter_context(mock.patch.object(app, "multiprocessing", Facade(multiprocessing, get_context=world.deny)))
        stack.enter_context(mock.patch.object(app, "time", Facade(time, monotonic=lambda: clock.value, sleep=sleep)))
        stack.enter_context(mock.patch.object(app, "getpass", Facade(app.getpass, getpass=prompt)))
        stack.enter_context(mock.patch.object(app, "subprocess", Facade(subprocess, run=world.deny, Popen=world.deny)))
        stack.enter_context(mock.patch.object(paths, "subprocess", Facade(subprocess, run=world.deny, Popen=world.deny)))
        stack.enter_context(mock.patch.object(app, "os", Facade(os, **{name: world.deny for name in (
            "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe", "execl", "execlp",
            "execlpe", "posix_spawn", "posix_spawnp", "spawnl", "spawnle", "spawnlp", "spawnlpe",
            "spawnv", "spawnve", "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")})))
        stack.enter_context(mock.patch.object(app, "socket", Facade(socket,
            socket=world.deny, create_connection=world.deny)))
        stack.enter_context(mock.patch.object(app, "pty", Facade(app.pty, fork=world.deny, openpty=world.deny)))
        stack.enter_context(mock.patch.object(app, "interactive_run", world.transport))
        stack.enter_context(mock.patch.object(app, "execute_ib_task", consume))
        stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
        stack.enter_context(mock.patch.object(app, "_TASK_DEADLINE", None))
        stack.enter_context(mock.patch.object(app, "_WORKER_CONNECTION", None))
        stack.enter_context(mock.patch.object(app, "_WORKER_STOP", None))
        stack.enter_context(mock.patch.object(app, "_ACTIVE_COORDINATOR", None))
        stack.enter_context(mock.patch.object(app, "_TASK_IB_CONFIG", None))
        capture = io.StringIO()
        try:
            if mode == "orphan":
                with test.assertRaises(app.SetupError):
                    helper(tasks[0].target, "admin", fence_password, 10,
                        strict=False, policy=None, stamp="20261118-010203", details={})
                test.assertEqual([], world.events, "no original deadline/supervisor means no polling IO")
                test.assertEqual([], world.delays)
                result = None
            else:
                with redirect_stdout(capture), redirect_stderr(capture):
                    result = app.run_prepared_tasks(tasks, args, None, fence_password, None, [], None,
                                                   authority=app.RuntimeInputAuthority([]))
            if world.effects or (root / "unknown-effect").exists():
                raise RuntimeError("FIXTURE HOLD: a refused external effect is not fence evidence")
            yield SimpleNamespace(app=app, result=result, children=children, world=world,
                prompt_observations=prompt_observations, after_pause_waits=after_pause_waits[0])
        finally:
            # Fallback is only for our context-created children. Assertions
            # inspect original parent joins BEFORE this cleanup can add any.
            if release is not None:
                release.set()
            for child in children:
                if child.is_alive():
                    child.terminate()
                    child.join(timeout=5)
                    if child.is_alive():
                        child.kill()
                        child.join(timeout=1)


class DeferredReplaceFenceTests(unittest.TestCase):
    def test_inline_original_deadline_pending_zero_fresh_identity_and_readback(self):
        with fence_case(self, "inline-ready") as case:
            self.assertEqual(1, case.result["workers"])
            observed = case.result["records"][NAMES[0].casefold()]["fence_control"]
            self.assertEqual((25, 25), (observed["before"], observed["after"]))
            self.assertTrue(observed["ok"] and observed["identity_ok"] and observed["readback_matches"])
            self.assertEqual("203.0.113.11", observed["endpoint"])
            self.assertEqual(["RC_PENDING", "RC_READY", "O5", "ROUTE", "READ"], observed["events"])
            self.assertEqual([10], observed["sleeps"])
            self.assertEqual([], case.children)

    def test_inline_pending_clips_original_remaining_deadline_without_nine_probe_cap(self):
        with fence_case(self, "inline-clip") as case:
            observed = case.result["records"][NAMES[0].casefold()]["fence_control"]
            self.assertFalse(observed["ok"])
            self.assertEqual((25, 25), (observed["before"], observed["after"]))
            self.assertEqual([10, 10, 5], observed["sleeps"])
            self.assertEqual(["RC_PENDING"] * 3, observed["events"])
            self.assertEqual(25, observed["clock"])

    def test_inline_fatal_rc_does_not_poll_or_read_identity_again(self):
        with fence_case(self, "inline-fatal") as case:
            observed = case.result["records"][NAMES[0].casefold()]["fence_control"]
            self.assertFalse(observed["ok"])
            self.assertEqual(["RC_PENDING", "RC_FAILED"], observed["events"])
            self.assertEqual([10], observed["sleeps"])

    def test_inline_uses_original_task_window_beyond_nine_pending_receipts(self):
        with fence_case(self, "inline-long") as case:
            observed = case.result["records"][NAMES[0].casefold()]["fence_control"]
            self.assertFalse(observed["ok"])
            self.assertEqual((125, 125), (observed["before"], observed["after"]))
            self.assertEqual([10] * 12 + [5], observed["sleeps"])
            self.assertEqual(["RC_PENDING"] * 13, observed["events"])
            self.assertEqual(125, observed["clock"])

    def test_orphan_fence_refuses_before_any_poll_and_never_mints_deadline(self):
        with fence_case(self, "orphan") as case:
            self.assertIsNone(case.app._TASK_DEADLINE)
            self.assertEqual([], case.world.events)
            self.assertEqual([], case.children)

    def test_real_parallel_worker_none_deadline_survives_true_parent_prompt_pause(self):
        with fence_case(self, "parallel-pause") as case:
            self.assertEqual(2, case.result["workers"])
            self.assertEqual(17, len(case.children))
            self.assertEqual([(0, 2)], case.prompt_observations)
            self.assertGreaterEqual(case.after_pause_waits, 2)
            observed = case.result["records"][NAMES[0].casefold()]["fence_control"]
            self.assertIsNone(observed["before"])
            self.assertIsNone(observed["after"])
            self.assertEqual(("multiprocessing.connection", "Connection", "Event"),
                (observed["connection_module"], observed["connection_type"], observed["stop_type"]))
            self.assertIs(type(observed["fd_inode"]), int)
            self.assertIn(observed["fd_mode"], {stat.S_IFIFO, stat.S_IFSOCK})
            self.assertTrue(observed["ok"] and observed["identity_ok"] and observed["readback_matches"])
            self.assertEqual(["RC_PENDING", "RC_READY", "O5", "ROUTE", "READ"], observed["events"])
            self.assertEqual(30, observed["clock"], "20s real prompt accounting plus one original 10s rc wait")
            self.assertEqual([10], observed["sleeps"])
            self.assertTrue(case.result["records"][NAMES[1].casefold()]["prompt_control"])
            for child in case.children:
                self.assertEqual(1, child.calls.count("start"))
                self.assertIn("join", child.calls)
                self.assertNotIn("terminate", child.calls)
                self.assertNotIn("kill", child.calls)
                self.assertIsNotNone(child.exitcode)
                self.assertFalse(child.is_alive())

    def test_real_parallel_parent_timeout_terminates_pending_worker_without_replay(self):
        with fence_case(self, "parallel-timeout") as case:
            self.assertEqual(2, case.result["workers"])
            self.assertEqual(17, len(case.children))
            first = next(child for child in case.children if child.task_name == NAMES[0])
            self.assertEqual(1, first.calls.count("start"))
            self.assertEqual(1, first.calls.count("terminate"))
            self.assertIn("join", first.calls)
            record = case.result["records"][NAMES[0].casefold()]
            self.assertTrue(record["script_error"])
            self.assertEqual("task deadline exceeded; verify any partial writes", record["reason"])
            self.assertFalse(record["writes_attempted"])
            self.assertEqual(0, record["fence_control"]["after"], "original worker TERM handler must actually run")
            self.assertFalse(record["fence_control"]["ok"])
            self.assertEqual(["RC_PENDING"], record["fence_control"]["events"])
            self.assertTrue(all(not child.is_alive() and child.exitcode is not None for child in case.children))

    def test_real_parallel_parent_stop_event_interrupts_pending_and_keeps_unstarted_tasks(self):
        with fence_case(self, "parallel-stop") as case:
            self.assertEqual(2, len(case.children), "cancellation must not start the remaining fifteen controls")
            first = case.result["records"][NAMES[0].casefold()]["fence_control"]
            self.assertFalse(first["ok"])
            self.assertEqual("BatchStopped", first["error_type"])
            self.assertEqual(["RC_PENDING"], first["events"])
            self.assertTrue(case.result["fatal"])
            self.assertEqual(17, len(case.result["outcomes"]))
            for child in case.children:
                self.assertIn("join", child.calls)
                self.assertFalse(child.is_alive())


class CarrierModelTests(unittest.TestCase):
    """PUBLIC DATA controls only; no transport, phase observation or children."""
    @contextmanager
    def model(self, direct):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="d7-carrier-", dir=owned_test_root())))
            home = root / "home"
            home.mkdir(mode=0o700)
            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
            stack.enter_context(mock.patch.dict(sys.modules))
            app = load_script("d7_carrier_" + format(id(root), "x"), INITIAL)
            yield _ReplaceWorld(self, app, {}, direct=direct)

    def literal(self, peer, direct):
        # Independent complete literals, NOT frame()/SSH_OPTIONS or a SUT builder.
        nonce = "0123456789abcdef0123456789abcdef"
        read = (r'printf "\n__HTTP_IB_BEGIN_0123456789abcdef0123456789abcdef__\n"; '
                r'nv config show -o commands; task_rc=$?; '
                r'printf "\n__HTTP_IB_END_0123456789abcdef0123456789abcdef__=%s\n" '
                r'"$task_rc"; exit "$task_rc"')
        if direct:
            inner = ["ssh", "-4", "-tt", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive", peer, shlex.join(["sh", "-c", read])]
        else:
            inner = ["ip", "vrf", "exec", "oob", "ssh", "-6", "-tt", "-o", "ConnectTimeout=10",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", "-o", "ControlMaster=no",
                "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive", "-B", "ib-mgmt1000",
                peer, shlex.join(["sh", "-c", read])]
        begin = r'printf "\n__HTTP_IB_AUTH_0123456789abcdef0123456789abcdef_auth-probe-readonly__=BEGIN\n"; '
        end = (r'; inner_rc=$?; printf "\n__HTTP_IB_AUTH_0123456789abcdef0123456789abcdef_auth-probe-readonly__=EXIT:%s\n" '
               r'"$inner_rc"; exit "$inner_rc"')
        def carrier(program):
            if direct:
                return ["sh", "-c", program]
            return ["ssh", "-tt", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                "-o", "ControlMaster=no", "-o", "ControlPath=none", "cumulus@192.0.2.10",
                shlex.join(["sh", "-c", "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
                            + shlex.join(["sh", "-c", program])])]
        program = begin + shlex.join(inner) + end
        return nonce, inner, begin, end, program, carrier

    def rejected(self, world, cases):
        before = len(world.effects)
        for number, (argv, responder, timeout) in enumerate(cases, 1):
            with self.subTest(near_miss=number), self.assertRaisesRegex(RuntimeError, "FIXTURE HOLD: D7 refused"):
                world._carrier_data(argv, responder, timeout)
            self.assertEqual(before + number, len(world.effects), "every refusal must remain accumulated")

    def metadata_cases(self, world, vector, peer, nonce, direct):
        outer = "" if direct else "cumulus@192.0.2.10"
        def responder(**changes):
            phase = world.app._IBPhase(nonce, "auth-probe-readonly", peer, outer, None)
            for name, value in changes.items():
                setattr(phase, name, value)
            return SimpleNamespace(_phase=phase, ib_destination=peer)
        return [(vector, SimpleNamespace(ib_destination=peer), 60),
                (vector, SimpleNamespace(_phase=SimpleNamespace(), ib_destination=peer), 60),
                (vector, responder(operation="password-change"), 60),
                (vector, responder(nonce=nonce + "0"), 60),
                (vector, responder(nonce="f" * 32), 60),
                (vector, responder(endpoint="admin@192.0.2.99"), 60),
                (vector, responder(outer_endpoint="cumulus@192.0.2.99"), 60),
                (vector, SimpleNamespace(_phase=responder()._phase, ib_destination="admin@192.0.2.99"), 60),
                (vector, responder(), 59)]

    def unchanged_and_empty(self, world, phase, ordinary, peer):
        responder = SimpleNamespace(ib_destination=peer)
        self.assertIs(ordinary, world._carrier_data(ordinary, responder, 60))
        self.assertEqual([], world.events)
        self.assertEqual([], world.permits)
        self.assertEqual({}, world.device_files)
        self.assertEqual([], world.local_children)
        self.assertEqual(0, phase.current_done)

    def test_jump_auth_carrier_projects_only_exact_qualified_data_without_io(self):
        with self.model(False) as world:
            for peer in ("admin@fe80::ff:fe00:11", "admin@fe80::ff:fe00:12"):
                with self.subTest(peer=peer):
                    nonce, inner, begin, end, program, carrier = self.literal(peer, False)
                    vector = carrier(program)
                    phase = world.app._IBPhase(nonce, "auth-probe-readonly", peer, "cumulus@192.0.2.10", None)
                    responder = SimpleNamespace(_phase=phase, ib_destination=peer)
                    projected = world._carrier_data(vector, responder, 60)
                    self.assertEqual(inner, projected)
                    self.assertEqual((nonce, ("nv", "config", "show", "-o", "commands")), world.decode_frame(projected))
                    variants = [carrier("X" + program), carrier(program + "X"), carrier(program + "; true"),
                        carrier(program.replace("exec oob", "exec default")),
                        carrier(program.replace("ib-mgmt1000", "foreign-svi")),
                        carrier(program.replace(peer, "admin@fe80::ff:fe00:99")),
                        carrier(program.replace("PubkeyAuthentication=no", "PubkeyAuthentication=yes")),
                        carrier(program.replace("nv config show -o commands", "nv config save")),
                        carrier(program.replace("__HTTP_IB_BEGIN_" + nonce, "__HTTP_IB_BEGIN_" + "f" * 32)),
                        carrier(program.replace("__HTTP_IB_END_" + nonce, "__HTTP_IB_END_" + "f" * 32)),
                        carrier(begin + shlex.join(inner) + end.replace(nonce, "f" * 32)),
                        [*vector, "extra"],
                        ["ServerAliveCountMax=3" if word == "ServerAliveCountMax=2" else word for word in vector],
                        ["cumulus@192.0.2.99" if word == "cumulus@192.0.2.10" else word for word in vector]]
                    self.assertEqual(14, len(variants))
                    cases = self.metadata_cases(world, vector, peer, nonce, False)
                    cases += [(bad, responder, 60) for bad in variants]
                    self.assertEqual(23, len(cases))
                    self.rejected(world, cases)
                    self.unchanged_and_empty(world, phase, inner, peer)
            self.assertEqual(46, len(world.effects))

    def test_direct_auth_carrier_projects_only_exact_qualified_data_without_io(self):
        with self.model(True) as world:
            peer = "admin@203.0.113.11"
            nonce, inner, begin, end, program, carrier = self.literal(peer, True)
            vector = carrier(program)
            phase = world.app._IBPhase(nonce, "auth-probe-readonly", peer, "", None)
            responder = SimpleNamespace(_phase=phase, ib_destination=peer)
            projected = world._carrier_data(vector, responder, 60)
            self.assertEqual(inner, projected)
            self.assertEqual((nonce, ("nv", "config", "show", "-o", "commands")), world.decode_frame(projected))
            fresh = [*inner[:13], "-o", "ConnectionAttempts=1", *inner[13:]]
            variants = [["bash", "-c", program], [*vector, "extra"], carrier("X" + program),
                carrier(program + "X"), carrier(program + "; true"),
                carrier(program.replace(peer, "admin@203.0.113.12")),
                carrier(program.replace("ProxyJump=none", "ProxyJump=foreign")),
                carrier(program.replace("PubkeyAuthentication=no", "PubkeyAuthentication=yes")),
                carrier(program.replace("nv config show -o commands", "nv config save")),
                carrier(program.replace("__HTTP_IB_BEGIN_" + nonce, "__HTTP_IB_BEGIN_" + "f" * 32)),
                carrier(program.replace("__HTTP_IB_END_" + nonce, "__HTTP_IB_END_" + "f" * 32)),
                carrier(begin + shlex.join(inner) + end.replace(nonce, "f" * 32)), fresh]
            self.assertEqual(13, len(variants))
            cases = self.metadata_cases(world, vector, peer, nonce, True)
            cases += [(bad, responder, 60) for bad in variants]
            self.assertEqual(22, len(cases))
            self.rejected(world, cases)
            self.unchanged_and_empty(world, phase, inner, peer)
            self.assertEqual(22, len(world.effects))


class TypedReplaceFenceTests(unittest.TestCase):
    """New inline protocol controls, not SSH/permit or parallel supervision proof.

    The real fence, shared read helper, cancellation and identity parser run.
    Only the named stage IO boundary returns fixed PUBLIC SessionResults; no
    credential, KAT, native worker, shell or actual clock is consumed here.
    """
    @contextmanager
    def model(self, receipts, *, deadline=25):
        from test_cases.test_initial_setup_config_mode import EXPECTED_D7_READ_RC_SCRIPT

        owned = owned_test_root()
        if os.environ.get("TMPDIR") != str(owned):
            raise RuntimeError("FIXTURE HOLD: explicit owned TMPDIR required")
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="d7-typed-fence-", dir=owned)))
            home = root / "home"
            home.mkdir(mode=0o700)
            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
            stack.enter_context(mock.patch.dict(sys.modules))
            app = load_script("d7_typed_fence_" + format(id(root), "x"), INITIAL)
            paths = app._import_tools("tools.login_path")
            route = paths.Route(NAMES[0], "direct", "NO_MGMT_LINK", None, None, None)
            device = app.Device(NAMES[0], "ib", "203.0.113.11", "203.0.113.11/24", "203.0.113.1",
                                MACS[0], "", "")
            target = app.Target(device, None, "", "eth0", route=route)
            point = app.DirectEndpoint("203.0.113.11", None)
            clock = SimpleNamespace(value=0)
            calls, delays, effects, consumed = [], [], [], []
            details = {}
            readback = "nv set system hostname EXAMPLE-IB001\n"
            reader = ["sh", "-c", EXPECTED_D7_READ_RC_SCRIPT, "--", "20261118-010203"]

            def deny(*_args, **_kwargs):
                effects.append("unknown-effect")
                raise RuntimeError("FIXTURE HOLD: typed fence refused external IO")

            def sleep(seconds):
                if type(seconds) not in (int, float) or seconds not in (5, 10):
                    return deny()
                delays.append(seconds)
                clock.value += seconds

            def stage(actual, endpoint, eth_user, eth_password, ib_user, ib_password,
                      timeout, command, *, local, strict, policy=None):
                if (actual is not target or type(endpoint) is not app.DirectEndpoint or endpoint != point
                        or (eth_user, eth_password, ib_user, ib_password, timeout) != ("", "", "admin", None, 10)
                        or local is not False or strict is not False or policy is not None
                        or type(command) is not list or any(type(word) is not str for word in command)):
                    return deny()
                self.assertLess(len(calls), 40, "finite PUBLIC model read watchdog, not a production polling cap")
                if command == reader:
                    calls.append("RC")
                    body = receipts[min(len(consumed), len(receipts) - 1)]
                    consumed.append(body)
                elif command == ["ip", "addr", "show", "eth0"]:
                    calls.append("O5")
                    body = ("2: eth0: <UP> mtu 1500\n    link/ether 02:00:00:00:00:11\n"
                            "    inet 203.0.113.11/24 scope global eth0\n")
                elif command == ["ip", "route"]:
                    calls.append("ROUTE")
                    body = "default via 203.0.113.1 dev eth0\n"
                elif command == ["nv", "config", "show", "-o", "commands"]:
                    calls.append("READ")
                    body = readback
                else:
                    return deny()
                reply = app.SessionResult(body, 0)
                reply._direct_endpoint = point
                return reply

            for module in (app, paths):
                stack.enter_context(mock.patch.object(module, "subprocess", Facade(subprocess, run=deny, Popen=deny)))
            stack.enter_context(mock.patch.object(app, "socket", Facade(socket,
                socket=deny, create_connection=deny)))
            stack.enter_context(mock.patch.object(app, "os", Facade(os, **{name: deny for name in (
                "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe", "execl", "execlp", "execlpe",
                "posix_spawn", "posix_spawnp", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve",
                "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")})))
            stack.enter_context(mock.patch.object(app, "pty", Facade(app.pty, fork=deny, openpty=deny)))
            stack.enter_context(mock.patch.object(app, "multiprocessing", Facade(multiprocessing,
                get_context=deny, Process=deny)))
            stack.enter_context(mock.patch.object(app, "getpass", Facade(app.getpass, getpass=deny)))
            stack.enter_context(mock.patch.object(app, "input", deny, create=True))
            for name in ("interactive_run", "run_on_ib", "_run_authorized_ib_command",
                         "_run_authorized_ib_direct_command", "_run_direct_key_read"):
                stack.enter_context(mock.patch.object(app, name, deny))
            clocks = {name: deny for name in ("time", "time_ns", "monotonic_ns", "perf_counter",
                "perf_counter_ns", "process_time", "process_time_ns", "thread_time", "thread_time_ns")}
            stack.enter_context(mock.patch.object(app, "time", Facade(time,
                monotonic=lambda: clock.value, sleep=sleep, **clocks)))
            stack.enter_context(mock.patch.object(app, "_TASK_DEADLINE", deadline))
            for name in ("_WORKER_CONNECTION", "_WORKER_STOP", "_ACTIVE_COORDINATOR"):
                stack.enter_context(mock.patch.object(app, name, None))
            stack.enter_context(mock.patch.object(app, "_stage_ib_command", stage))
            try:
                yield SimpleNamespace(app=app, target=target, point=point, clock=clock, calls=calls,
                    delays=delays, effects=effects, consumed=consumed, details=details, readback=readback)
            finally:
                if effects:
                    raise RuntimeError("FIXTURE HOLD: refused IO is not typed completion evidence")

    def consume(self, case, option=True):
        return case.app._wait_replace_deferred_completion(case.target, "admin", None, 10,
            strict=False, policy=None, stamp="20261118-010203", details=case.details,
            _replace_completion=option)

    def test_typed_opt_in_rejects_each_non_bool_before_read_or_sleep(self):
        for value in (None, 0, 1, "true"):
            with self.subTest(value=value), self.model(("rc=\nfailed_operation=pending\n",)) as case:
                with self.assertRaises(case.app.SetupError):
                    self.consume(case, value)
                self.assertEqual([], case.calls)
                self.assertEqual([], case.delays)
                self.assertEqual([], case.effects)
                self.assertEqual(0, case.clock.value)
                self.assertEqual(25, case.app._TASK_DEADLINE)

    def test_typed_pending_completion_keeps_rc_stage_and_only_success_reads_identity(self):
        pending = "rc=\nfailed_operation=pending\n"
        scenarios = (("ready", "rc=0\nfailed_operation=none\n", (0, "none")),
            ("apply7", "rc=7\nfailed_operation=apply\n", (7, "apply")),
            ("save7", "rc=7\nfailed_operation=save\n", (7, "save")),
            ("contradiction", "rc=0\nfailed_operation=apply\n", (None, None)),
            ("extra", "rc=0\nfailed_operation=none\nextra\n", (None, None)))
        self.assertEqual(5, len(scenarios))
        for name, receipt, expected in scenarios:
            with self.subTest(sequence=name), self.model((pending, receipt)) as case:
                if name == "ready":
                    self.assertEqual(case.readback, self.consume(case))
                    self.assertEqual(["RC", "RC", "O5", "ROUTE", "READ"], case.calls)
                    self.assertEqual({"ok": True, "via_ipv4": True,
                        "expected": {"mac": "02:00:00:00:00:11", "ipv4": "203.0.113.11/24", "gateway": "203.0.113.1"},
                        "observed": {"mac": "02:00:00:00:00:11", "ipv4": ["203.0.113.11/24"],
                                     "gateways": ["203.0.113.1"]}, "mismatches": []}, case.details["identity"])
                else:
                    with self.assertRaises(case.app.SetupError):
                        self.consume(case)
                    self.assertEqual(["RC", "RC"], case.calls)
                    self.assertNotIn("identity", case.details)
                self.assertIn("deferred_rc", case.details)
                self.assertIn("deferred_failed_operation", case.details)
                self.assertEqual(expected, (case.details["deferred_rc"], case.details["deferred_failed_operation"]))
                if expected[0] is not None:
                    self.assertIs(type(case.details["deferred_rc"]), int)
                self.assertEqual(case.point, case.details["endpoint"])
                self.assertEqual([pending, receipt], case.consumed)
                self.assertEqual([10], case.delays)
                self.assertEqual(10, case.clock.value)
                self.assertEqual(25, case.app._TASK_DEADLINE)
                self.assertEqual([], case.effects)

    def test_typed_pending_clips_original_windows_without_a_nine_read_cap(self):
        for window, sleeps, reads in ((25, [10, 10, 5], 3), (125, [10] * 12 + [5], 13)):
            with self.subTest(window=window), self.model(("rc=\nfailed_operation=pending\n",), deadline=window) as case:
                with self.assertRaisesRegex(case.app.SetupError, "device task deadline exceeded;"):
                    self.consume(case)
                self.assertEqual(sleeps, case.delays)
                self.assertEqual(["RC"] * reads, case.calls)
                self.assertEqual(["rc=\nfailed_operation=pending\n"] * reads, case.consumed)
                self.assertEqual((window, window), (case.clock.value, case.app._TASK_DEADLINE))
                self.assertEqual((None, "pending"),
                    (case.details["deferred_rc"], case.details["deferred_failed_operation"]))
                self.assertNotIn("identity", case.details)
                self.assertEqual([], case.effects)

    def test_typed_orphan_has_no_deadline_worker_authority_or_poll(self):
        with self.model(("rc=\nfailed_operation=pending\n",), deadline=None) as case:
            with self.assertRaisesRegex(case.app.SetupError, "original task deadline or worker supervisor"):
                self.consume(case)
            self.assertIsNone(case.app._TASK_DEADLINE)
            self.assertIsNone(case.app._WORKER_CONNECTION)
            self.assertIsNone(case.app._WORKER_STOP)
            self.assertEqual([], case.calls)
            self.assertEqual([], case.delays)
            self.assertEqual([], case.effects)
            self.assertEqual(0, case.clock.value)

    def test_typed_success_still_requires_fresh_identity_and_readback(self):
        receipt = "rc=0\nfailed_operation=none\n"
        scenarios = (
            ("route-mismatch", ["RC", "O5", "ROUTE"], r"^IB identity differs from CSV;"),
            ("readback-unverified", ["RC", "O5", "ROUTE", "READ"],
             r"^direct IPv4 readiness outcome is unverified$"),
        )
        for scenario, expected_calls, diagnostic in scenarios:
            with self.subTest(evidence=scenario), self.model((receipt,)) as case:
                original_stage = case.app._stage_ib_command

                def stage(*arguments, **options):
                    result = original_stage(*arguments, **options)
                    if scenario == "route-mismatch" and case.calls[-1] == "ROUTE":
                        result.output = "default via 203.0.113.254 dev eth0\n"
                    elif scenario == "readback-unverified" and case.calls[-1] == "READ":
                        result.output = "PUBLIC configuration evidence unavailable\n"
                        result.exit_code = 1
                    return result

                with mock.patch.object(case.app, "_stage_ib_command", stage):
                    with self.assertRaisesRegex(case.app.SetupError, diagnostic):
                        self.consume(case)

                self.assertEqual(expected_calls, case.calls)
                self.assertEqual([receipt], case.consumed)
                self.assertEqual([], case.delays)
                self.assertEqual([], case.effects)
                self.assertEqual(0, case.clock.value)
                self.assertEqual(25, case.app._TASK_DEADLINE)
                self.assertEqual(case.point, case.details["endpoint"])
                self.assertIs(type(case.details["deferred_rc"]), int)
                self.assertEqual((0, "none"),
                    (case.details["deferred_rc"], case.details["deferred_failed_operation"]))
                identity = case.details["identity"]
                self.assertIs(identity["via_ipv4"], True)
                self.assertEqual("203.0.113.1", identity["expected"]["gateway"])
                if scenario == "route-mismatch":
                    self.assertIs(case.details["identity_failed"], True)
                    self.assertIs(identity["ok"], False)
                    self.assertEqual(["203.0.113.254"], identity["observed"]["gateways"])
                    self.assertEqual([{"field": "gateway", "expected": "203.0.113.1",
                                       "observed": "203.0.113.254"}], identity["mismatches"])
                else:
                    self.assertNotIn("identity_failed", case.details)
                    self.assertIs(identity["ok"], True)
                    self.assertEqual(["203.0.113.1"], identity["observed"]["gateways"])
                    self.assertEqual([], identity["mismatches"])
