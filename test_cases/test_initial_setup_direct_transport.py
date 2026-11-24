"""r660 WP3 tests-first PUBLIC direct-transport contracts (initially NOT RUN).

Expected values are hand-written I-037(7)/K1/K3/K7 vectors, not product output.
The inherited owned world supplies isolation only; no old WP2 test is changed.
SSH/ip/ping/keygen are boundary models, never actual network commands. Real
phase PTY coverage is in direct_transport_workflow; missing new API is a HOLD,
not evidence that any business branch has produced a behavior RED.
"""
from __future__ import annotations

import ast
import hashlib
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, fields
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

from test_cases.test_initial_setup_cable_check import (
    _World, _Facade, HEADER, INITIAL, ROOT, IB1, MAC1, LL1, PUBLIC_REPLY,
)
from test_cases import test_initial_setup_cable_check as _owned_fixture

IP = "192.0.2.10"
IFACE = "en-public7"
SCOPED = LL1 + "%" + IFACE
READ = ["nv", "config", "show", "-o", "commands"]
BODY = "nv set system hostname example-ib01\nnv set service lldp state enabled\n"
NEW_FP = "SHA256:" + "B" * 43
OLD_FP = "SHA256:" + "A" * 43
_NATIVE_POPEN = subprocess.Popen


class PrerequisiteHold(RuntimeError):
    """Explicit missing-interface bucket; never called a business assertion."""


def require_api(app):
    missing = [name for name in ("DirectEndpoint", "direct_ssh_command", "_execute_ib_direct_phase")
               if not callable(getattr(app, name, None))]
    if missing:
        raise PrerequisiteHold("PREREQUISITE HOLD (not behavior RED): " + ",".join(missing))


def ssh_words(case, argv):
    """Accept just SSH or the original phase script's one manager-side SSH."""
    case.assertIs(type(argv), list)
    case.assertTrue(all(type(word) is str for word in argv))
    if argv[:1] == ["ssh"]:
        words = argv
    else:
        case.assertEqual(["sh", "-c"], argv[:2])
        case.assertEqual(3, len(argv))
        match = re.fullmatch(
            r'printf "[^"]*"; (ssh .+); inner_rc=\$\?; printf "[^"]*" "\$inner_rc"; exit "\$inner_rc"',
            argv[2])
        case.assertIsNotNone(match, "only the fixed original manager phase shell grammar")
        words = shlex.split(match.group(1))
    case.assertEqual("ssh", words[0])
    destinations = [word for word in words if word.startswith("admin@")]
    case.assertEqual(1, len(destinations), "one real IB endpoint, no nested/fake Jump")
    return words, destinations[0]


class DirectWorld(_World):
    """Reuse owned-root safety; add only a closed direct external IO model.

    Every attempted SSH endpoint is recorded. Neighbor responses are keyed by
    exact argv and read ordinal. Unexpected subprocess/exec/socket is hard denied
    by the inherited world. No clock/euid/global stdlib mutation is introduced.
    """
    def __init__(self, case):
        super().__init__(case)
        self.neighbors = [IP + " dev " + IFACE + " lladdr " + MAC1 + " REACHABLE\n"]
        self.neighbor_reads = 0
        self.replies = {}
        self.ssh_calls, self.results, self.responders = [], [], []
        self.keygen_state = "old"
        self.keygen_calls = []
        self.real_native_calls = 0
        self.expected_device_prefix = None

    def __enter__(self):
        original_loader = _owned_fixture.load_script
        def observe_loaded(*args, **kwargs):
            app = original_loader(*args, **kwargs)
            self._original_interactive = app.interactive_run
            return app
        with mock.patch.object(_owned_fixture, "load_script", side_effect=observe_loaded):
            super().__enter__()
        master_directory = self.app.tempfile.mkdtemp
        def owned_directory(*args, **kwargs):
            if kwargs.get("prefix") == "isj-":
                return master_directory(*args, **kwargs)
            # Real one-slot scheduler evidence, additional to the original
            # world's D4-only temporary-directory model. No fixed parent.
            self.case.assertEqual((), args)
            self.case.assertEqual({"prefix", "dir"}, set(kwargs))
            self.case.assertRegex(kwargs["prefix"], r"^devices-[0-9]{8}-[0-9]{6}-$")
            self.case.assertEqual(self.expected_device_prefix, kwargs["prefix"], "the observed real scheduler's exact run stamp")
            self.case.assertEqual(self.root, Path(kwargs["dir"]).resolve())
            path = Path(tempfile.mkdtemp(prefix=kwargs["prefix"], dir=self.root))
            self.case.assertEqual(self.root, path.parent)
            self.case.assertEqual(os.geteuid(), path.stat().st_uid)
            self.case.assertEqual(0o700, path.stat().st_mode & 0o777)
            return str(path)
        self.app.tempfile = _Facade(tempfile, mkdtemp=owned_directory)
        self.paths.subprocess = _Facade(subprocess, run=self.control, Popen=self.deny)
        self.local_json = json.dumps([{"ifname": IFACE, "addr_info": [
            {"family": "inet", "local": "192.0.2.1", "prefixlen": 24},
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64}]}])
        self.stack.enter_context(mock.patch.object(self.app, "_read_local_interfaces",
            side_effect=lambda: self.paths.parse_local_interfaces(self.local_json)))
        return self

    def endpoint(self, address=LL1, interface=IFACE):
        require_api(self.app)
        return self.app.DirectEndpoint(address, interface)

    def target(self, *, same_subnet=IFACE):
        ib = self.app.Device(IB1, "ib", IP, IP + "/24", "192.0.2.1", MAC1, "", "")
        route = self.paths.Route(IB1, "direct", "NO_MGMT_LINK", None, None, same_subnet)
        return self.app.Target(ib, None, "", "eth0", route=route)

    def call(self, *, target=None, endpoint=None, command=None, current=PUBLIC_REPLY, **options):
        return self.app.run_on_ib(target or self.target(), endpoint or self.endpoint(),
            "", "", "admin", current, 2, list(READ if command is None else command), **options)

    def control(self, argv, **kwargs):
        self.case.assertIs(type(argv), list)
        if argv == ["ip", "-4", "neigh", "show", IP]:
            self.events.append(("local", tuple(argv)))
            index = self.neighbor_reads
            self.neighbor_reads += 1
            return subprocess.CompletedProcess(argv, 0,
                self.neighbors[min(index, len(self.neighbors) - 1)], "")
        if argv == ["ping", "-c", "1", "-W", "1", IP]:
            self.events.append(("local", tuple(argv)))
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv and argv[0] == "ssh-keygen":
            return self.keygen(argv)
        # Real same-project qualification's original PUBLIC native worker only.
        native = [sys.executable, "-I", "-S", "-B", str(INITIAL.resolve()), "--_verify-password"]
        if argv == native:
            self.case.assertEqual({"input", "text", "capture_output", "timeout", "check", "env"}, set(kwargs))
            self.case.assertIs(kwargs.get("check"), False)
            self.case.assertEqual(8, kwargs.get("timeout"))
            self.case.assertIs(kwargs.get("capture_output"), True)
            self.case.assertIs(kwargs.get("text"), True)
            self.case.assertEqual({"PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
                                   "PYTHONDONTWRITEBYTECODE": "1"}, kwargs.get("env"))
            payload = json.loads(kwargs["input"])
            self.case.assertEqual({"password", "hash"}, set(payload))
            self.case.assertTrue(payload["password"] in (self.kat["PASSWORD"], PUBLIC_REPLY), "PUBLIC worker input binding")
            self.case.assertTrue(self.kat["YESCRYPT"] == payload["hash"], "PUBLIC worker fixed hash binding")
            self.real_native_calls += 1
            # Synchronous original stdlib run; restore the hard refusal before
            # returning. No other repository command/callback is invoked here.
            with mock.patch.object(subprocess, "Popen", _NATIVE_POPEN):
                return subprocess.run(argv, **kwargs)
        raise AssertionError("outside direct PUBLIC command boundary: " + repr(argv))

    def interactive(self, argv, responder, timeout, **kwargs):
        words, destination = ssh_words(self.case, argv)
        self.case.assertIn(destination, ("admin@" + SCOPED, "admin@" + IP))
        self.case.assertNotIn("ip", words[:1])
        self.ssh_calls.append(destination)
        self.responders.append(responder)
        self.events.append(("direct", destination))
        model = self.replies.get(destination, "ok")
        if model == "network":
            return self.app.SessionResult("ssh: connect to host " + destination[6:] +
                                          " port 22: Connection timed out\n", 255)
        if model == "unknown255":
            return self.app.SessionResult("PUBLIC unknown remote exit\n", 255)
        if model == "auth":
            return self.app.SessionResult(destination + ": Permission denied (password).\n", 255,
                                          ib_authentication_rejected=True)
        if model == "identity":
            raise self.app.SetupError("PUBLIC authenticated identity mismatch")
        if model == "hostkey":
            path = self.home / ".ssh" / "known_hosts"
            text = ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
                    "The fingerprint for the ED25519 key sent by the remote host is\n" + NEW_FP + ".\n"
                    "Offending ED25519 key in " + str(path) + ":1\n"
                    "Host key for " + destination[6:] + " has changed\nHost key verification failed.\n")
            return self.app.SessionResult(text, 255)
        marker = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", " ".join(argv))
        self.case.assertTrue(marker, "real closed builder must own a command nonce")
        self.case.assertEqual(1, len(set(marker)))
        output = "__HTTP_IB_BEGIN_" + marker[0] + "__\n" + BODY + "__HTTP_IB_END_" + marker[0] + "__=0\n"
        if model == "expiry":
            output = "You are required to change your password immediately (administrator enforced).\n" + output
        flags = model if type(model) is dict else {}
        result = (SimpleNamespace(output=output, exit_code=0, password_changed=False,
            password_change_required=False, password_change_attempted=False, ib_authentication_rejected=False)
            if model == "fake-result" else self.app.SessionResult(output, 0, **flags))
        self.results.append(result)
        return result

    def framed_command(self, argv):
        words, destination = ssh_words(self.case, argv)
        remote = shlex.split(words[-1])
        self.case.assertEqual(["sh", "-c"], remote[:2])
        self.case.assertEqual(3, len(remote))
        frame = re.search(r'__\\n"; (.*?); task_rc=\$\?;', remote[2], re.DOTALL)
        self.case.assertIsNotNone(frame, "one normal framed IB request")
        return destination, shlex.split(frame.group(1))

    def main_readback(self, argv, responder, timeout, *, nv_config, seen, **kwargs):
        """Supply independent public facts to the original MAIN prefix tests only."""
        destination, command = self.framed_command(argv)
        if command == READ:
            payload = nv_config
        elif command == ["ip", "addr", "show", "eth0"]:
            payload = ("2: eth0: <UP> mtu 1500 state UP\n"
                       f"    link/ether {MAC1} brd ff:ff:ff:ff:ff:ff\n"
                       f"    inet {IP}/24 scope global eth0\n")
        elif command == ["ip", "route"]:
            payload = "default via 192.0.2.1 dev eth0\n"
        elif command == ["nv", "show", "system", "ztp"]:
            payload = ("service disabled\n"
                       "state disabled\n"
                       "status success\n")
        else:
            self.case.fail("unexpected command in readonly MAIN prefix")
        seen.append((destination, command))
        result = self.interactive(argv, responder, timeout, **kwargs)
        self.case.assertEqual(1, result.output.count(BODY), "one owned result frame")
        result.output = result.output.replace(BODY, payload, 1)
        return result

    def policy(self):
        require_api(self.app)
        from test_cases.test_initial_setup_target_password_policy import required_external_kat, project_global
        self.kat = required_external_kat()  # original fixed SHA/REG/no-follow PUBLIC locator
        path = self.project / "01-global.yaml"
        path.write_text(project_global(self.kat["YESCRYPT"]), encoding="utf-8")
        path.chmod(0o600)
        return self.app.ProjectPasswordPolicy(path, "admin", target_password=self.kat["PASSWORD"], interactive=False)

    def make_host_key_change(self, address=SCOPED):
        directory = self.home / ".ssh"
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / "known_hosts"
        path.write_text("PUBLIC owned known-hosts model\n", encoding="utf-8")
        path.chmod(0o600)
        return self.paths.HostKeyChange(address, "ED25519", NEW_FP, str(path), (1,), "local", None)

    def keygen(self, argv):
        own = str(self.home / ".ssh" / "known_hosts")
        self.case.assertEqual(own, str(Path(own).resolve()))
        if argv[:3] == ["ssh-keygen", "-l", "-F"]:
            self.case.assertEqual(["-f", own], argv[4:])
            self.case.assertIn(argv[3], (SCOPED, IP))
            self.keygen_calls.append(("lookup", argv[3]))
            if self.keygen_state == "empty":
                return subprocess.CompletedProcess(argv, 1, "", "")
            fp = OLD_FP if self.keygen_state == "old" else NEW_FP
            return subprocess.CompletedProcess(argv, 0,
                "# Host " + argv[3] + " found: line 1\n256 ED25519 " + fp + "\n", "")
        self.case.assertEqual(["ssh-keygen", "-f", own, "-R"], argv[:4])
        self.case.assertIn(argv[4], (SCOPED, IP))
        self.keygen_calls.append(("remove", argv[4]))
        self.keygen_state = "empty"
        return subprocess.CompletedProcess(argv, 0, "", "")


class DirectTransportTests(unittest.TestCase):
    def test_same_subnet_tries_link_local_then_ipv4_only_on_network_failure(self):
        with DirectWorld(self) as world:
            world.replies["admin@" + SCOPED] = "network"
            result = world.call()
            self.assertEqual(["admin@" + SCOPED, "admin@" + IP], world.ssh_calls)
            self.assertEqual(BODY, result.output)
            self.assertEqual([("direct", "admin@" + SCOPED),
                ("local", ("ip", "-4", "neigh", "show", IP)), ("direct", "admin@" + IP)],
                [event for event in world.events if event[0] in {"local", "direct"}])
            self.assertIs(type(result._direct_endpoint), world.app.DirectEndpoint)
            self.assertEqual((IP, None), (result._direct_endpoint.address, result._direct_endpoint.interface))

    def test_update_notice_with_network_failure_never_replays_address(self):
        with DirectWorld(self) as world:
            world.replies["admin@" + SCOPED] = "network"
            injected = []
            def network_with_notice(argv, responder, timeout, **kwargs):
                result = world.interactive(argv, responder, timeout, **kwargs)
                if world.ssh_calls == ["admin@" + SCOPED]:
                    self.assertEqual(255, result.exit_code)
                    self.assertEqual((False, False, False, False), (
                        result.password_changed, result.password_change_required,
                        result.password_change_attempted, result.ib_authentication_rejected))
                    result.output += "passwd: all authentication tokens updated successfully\n"
                    injected.append(result)
                return result
            # Only the external session result is modeled. A wrongly attempted
            # IPv4 session retains the world's normal valid frame and result.
            with mock.patch.object(world.app, "interactive_run", side_effect=network_with_notice):
                with self.assertRaises(world.app.SetupError):
                    world.call()
            self.assertEqual(1, len(injected))
            self.assertEqual(["admin@" + SCOPED], world.ssh_calls)
            self.assertEqual(0, world.neighbor_reads)
            self.assertEqual([], [event for event in world.events if event[0] == "local"])

    def test_auth_identity_hostkey_and_unknown255_never_switch_address(self):
        for model in ("auth", "identity", "hostkey", "unknown255"):
            with self.subTest(model=model), DirectWorld(self) as world:
                world.replies["admin@" + SCOPED] = model
                with self.assertRaises(world.app.SetupError):
                    world.call()
                self.assertEqual(["admin@" + SCOPED], world.ssh_calls)
                self.assertEqual(0, world.neighbor_reads)

    def test_uncertain_mutating_command_is_not_replayed_on_ipv4(self):
        with DirectWorld(self) as world:
            from test_cases.test_initial_setup_identity_and_backup import EXPECTED_BACKUP_SCRIPT

            app, target, endpoint = world.app, world.target(), world.endpoint()
            address_fact = ("2: eth0: <UP> mtu 1500 state UP\n"
                            f"    link/ether {MAC1} brd ff:ff:ff:ff:ff:ff\n")
            identity = app._check_ib_identity(target, address_fact, "", via_ipv4=False)
            self.assertTrue(identity["ok"])
            stamp = "20261120-143000"
            task = app.PreparedIBTask(target, endpoint, "", False)
            state = app._IBConfigWriteState(task, "admin", "", stamp, True,
                endpoint=endpoint, current_password=PUBLIC_REPLY, identity_verified=identity["ok"])
            issued, backup = [], ["sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", stamp]
            mutation = ["nv", "set", "system", "hostname", IB1]

            def simulate(argv, responder, timeout, **kwargs):
                destination, command = world.framed_command(argv)
                issued.append((destination, command))
                if command == mutation:
                    world.replies[destination] = "network"
                result = world.interactive(argv, responder, timeout, **kwargs)
                if command == backup:
                    self.assertEqual(1, result.output.count(BODY))
                    result.output = result.output.replace(
                        BODY, f"path=/home/PUBLIC/current_{stamp}.yaml\nbytes=137\n", 1)
                return result

            with mock.patch.object(app, "_TASK_IB_CONFIG", state), \
                    mock.patch.object(app, "interactive_run", side_effect=simulate):
                with self.assertRaises(app.SetupError) as caught:
                    world.call(target=target, endpoint=endpoint, command=mutation)
            self.assertEqual("VERIFIED", state.backup_state)
            self.assertEqual([(f"admin@{SCOPED}", backup), (f"admin@{SCOPED}", mutation)], issued)
            self.assertEqual(["admin@" + SCOPED, "admin@" + SCOPED], world.ssh_calls)
            self.assertEqual(app.SshFailureKind.DIRECT_LOGIN_NETWORK, app._ssh_failure_fact(caught.exception).kind)
            self.assertEqual(0, world.neighbor_reads)

    def test_neighbor_mac_mismatch_blocks_ipv4_login(self):
        with DirectWorld(self) as world:
            world.replies["admin@" + SCOPED] = "network"
            world.neighbors = [IP + " dev " + IFACE + " lladdr 02:00:00:00:00:99 REACHABLE\n"]
            with self.assertRaises(world.app.SetupError):
                world.call()
            self.assertEqual(["admin@" + SCOPED], world.ssh_calls)
            self.assertEqual(1, world.neighbor_reads)
            self.assertFalse(any("ping" in event[1] for event in world.events if event[0] == "local"))

    def test_neighbor_without_record_pings_once_then_refuses(self):
        for learned in (False, True):
            with self.subTest(learned=learned), DirectWorld(self) as world:
                world.replies["admin@" + SCOPED] = "network"
                world.neighbors = ["", IP + " dev " + IFACE + " lladdr " + MAC1 + " STALE\n" if learned else ""]
                if learned:
                    self.assertEqual(BODY, world.call().output)
                else:
                    with self.assertRaises(world.app.SetupError) as caught:
                        world.call()
                    self.assertIn(IP, str(caught.exception))
                    self.assertRegex(str(caught.exception), r"(?i)邻居|neigh")
                    fact = world.app._ssh_failure_fact(caught.exception)
                    self.assertIsNotNone(fact)
                    self.assertEqual("direct", fact.hop)
                    self.assertEqual("FAILED_DIRECT_LOGIN_NETWORK", world.app.FAILURE_KIND_CATEGORY[fact.kind.value])
                self.assertEqual(2, world.neighbor_reads)
                self.assertEqual([("local", ("ip", "-4", "neigh", "show", IP)),
                    ("local", ("ping", "-c", "1", "-W", "1", IP)),
                    ("local", ("ip", "-4", "neigh", "show", IP))],
                    [event for event in world.events if event[0] == "local"])
                self.assertEqual(["admin@" + SCOPED] + (["admin@" + IP] if learned else []), world.ssh_calls)

    def test_other_subnet_goes_straight_to_ipv4(self):
        with DirectWorld(self) as world:
            result = world.call(target=world.target(same_subnet=None), endpoint=world.endpoint(IP, None))
            self.assertEqual(["admin@" + IP], world.ssh_calls)
            self.assertEqual(BODY, result.output)
            self.assertEqual(IP, result._direct_endpoint.address)

    def test_jump_failure_never_falls_back_to_direct(self):
        with DirectWorld(self) as world:
            jump = world.app.Device("example-jump-a", "eth_jump", "198.51.100.10", "", "", "", "", "")
            target = world.app.Target(world.target().ib, jump, "swp7", "eth0")
            neighbor = world.app.Neighbor(LL1, "ib-mgmt", MAC1, "default")
            calls = []
            def failed(argv, responder, timeout, **kwargs):
                calls.append(tuple(argv))
                return world.app.SessionResult("ssh: connect to host 198.51.100.10 port 22: Connection timed out\n", 255)
            with mock.patch.object(world.app, "interactive_run", side_effect=failed):
                with self.assertRaises(world.app.SetupError):
                    world.app.run_on_ib(target, neighbor, "cumulus", PUBLIC_REPLY, "admin", PUBLIC_REPLY, 2, READ)
            self.assertEqual(1, len(calls))
            self.assertFalse(world.ssh_calls)
            self.assertEqual(0, world.neighbor_reads)
            guidance = world.app.attention_guidance("FAILED_OOB_JUMP_UNREACHABLE")
            self.assertIn("--direct-access", guidance)

    def test_direct_network_failure_is_not_jump_unreachable(self):
        with DirectWorld(self) as world:
            world.replies["admin@" + IP] = "network"
            with self.assertRaises(world.app.SetupError) as caught:
                world.call(target=world.target(same_subnet=None), endpoint=world.endpoint(IP, None))
            fact = world.app._ssh_failure_fact(caught.exception)
            self.assertIsNotNone(fact)
            self.assertEqual("direct", fact.hop)
            self.assertEqual("FAILED_DIRECT_LOGIN_NETWORK", world.app.FAILURE_KIND_CATEGORY[fact.kind.value])
            gate = world.app.JumpGate()
            self.assertTrue(gate.claim_jump_slot(None, 1.0))
            self.assertEqual("fail", gate.report_jump_outcome(None, fact, writes_attempted=False, now=2.0))
            self.assertEqual({}, gate.jumps)

    def test_direct_command_argv_is_closed(self):
        with DirectWorld(self) as world:
            require_api(world.app)
            for address, interface, destination, family in ((LL1, IFACE, "admin@" + SCOPED, "-6"), (IP, None, "admin@" + IP, "-4")):
                with self.subTest(address=address):
                    argv = world.app.direct_ssh_command(world.target(), world.endpoint(address, interface), "admin", 2, READ)
                    words, actual = ssh_words(self, argv)
                    self.assertEqual(destination, actual)
                    self.assertIn(family, words)
                    for value in ("ConnectTimeout=2", "StrictHostKeyChecking=accept-new", "LogLevel=ERROR"):
                        self.assertIn(value, words)
                    self.assertNotIn(PUBLIC_REPLY, shlex.join(argv))
            for address, interface in (("192.0.2.010", None), (IP + ";echo BAD", None), ("2001:db8::1", IFACE),
                                       (LL1 + "%" + IFACE, IFACE), (LL1, None), (LL1, "en0;echo"), (IP, IFACE)):
                with self.subTest(rejected=(address, interface)), self.assertRaises((world.app.SetupError, ValueError)):
                    point = world.endpoint(address, interface)
                    world.app.direct_ssh_command(world.target(), point, "admin", 2, READ)
            point = world.endpoint()
            for command in ("nv config show", ["nv", "config", "show\nwhoami"], ["sh", "-c", "id"], ["nv", "set", "BAD;id"]):
                with self.subTest(command=command), self.assertRaises(world.app.SetupError):
                    world.app.direct_ssh_command(world.target(), point, "admin", 2, command)
            self.assertEqual([], world.ssh_calls)

    def test_direct_phase_leaves_jump_phase_untouched(self):
        tree = ast.parse(INITIAL.read_bytes())
        callers = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for call in ast.walk(node):
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "_execute_ib_phase":
                        callers.add(node.name)
        self.assertEqual({"run_on_ib", "_authenticate_ib_read"}, callers)
        with DirectWorld(self) as world:
            require_api(world.app)
            import inspect
            signature = inspect.signature(world.app.run_on_ib).parameters
            self.assertTrue({"target", "neighbor", "eth_user", "ethernet_password", "ib_user", "ib_default_password",
                             "timeout", "ib_command", "_phase_operation"} <= set(signature))
            self.assertEqual(["output", "exit_code", "password_changed", "password_change_required",
                "password_change_attempted", "ib_authentication_rejected"], [item.name for item in fields(world.app.SessionResult)])
            self.assertEqual(["target", "neighbor", "ethernet_password", "local"], [item.name for item in fields(world.app.PreparedIBTask)])

    def test_original_phase_class_builder_and_pty_bodies_keep_published_identity(self):
        # Pins are the nonauthor's fixed published v3.1.4 L=26ae34b2 bodies,
        # represented by the approved runtime CLT Python 3.9.6 AST algorithm,
        # not candidate-generated values or a runtime Git lookup. The earlier
        # unapproved Python 3.12 draft literals remain in f68 history (RV180/C).
        expected = {
            "_IBPhase": "32ed1f2d9c8453559da1aadd0ebc2e2e0ae8c0a72c245816b49662cdddaca594",
            "_execute_ib_phase": "304cf1f051cb7b4745d4c90bc32262336c31eba0df8383e3bdec6a0d72c5c5fd",
            "interactive_run": "7ca0995b8786fdbafec0ad629ba1ae621657f9e927c90db29cb35c0a40cf62cf",
            "NestedResponder": "321dbaa9c54869e4fa0eff9256005a5d4d451b20d7c7b20432a13b7aaa56fe4c",
            "nested_ssh_command": "9b939d2c0894a9036d5eaaacedbfd47bc255dfc303c3629cb41dea54dee7031a",
        }
        nodes = {node.name: node for node in ast.parse(INITIAL.read_bytes()).body
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in expected}
        self.assertEqual(set(expected), set(nodes))
        for name, digest in expected.items():
            with self.subTest(body=name):
                self.assertEqual(digest, hashlib.sha256(ast.dump(nodes[name], include_attributes=False).encode()).hexdigest())

    def test_nonphase_responder_replies_only_to_exact_ib_endpoint(self):
        for prompt in ("admin@203.0.113.99's password: ", "admin@fe80::999%en-other's password: ", "'s password: ",
                       "Password for admin@fe80::999%en-other: ", "Password for admin@fe80::ff:fe00:10%en-public7: "):
            with self.subTest(prompt=prompt), DirectWorld(self) as world:
                world.call(password_only=True)
                responder = world.responders[-1]
                try:
                    reply = responder(prompt)
                except world.app.SetupError:
                    reply = None
                self.assertIsNone(reply)
        with DirectWorld(self) as world:
            result = world.call(password_only=True)
            responder = world.responders[-1]
            self.assertEqual(PUBLIC_REPLY, responder("admin@" + SCOPED + "'s password: "))
            self.assertIs(type(result), world.app.SessionResult)
            self.assertEqual({"output", "exit_code", "password_changed", "password_change_required",
                "password_change_attempted", "ib_authentication_rejected"}, set(asdict(result)))

    def test_strict_direct_uses_real_project_but_selected_current_without_rotation(self):
        with DirectWorld(self) as world:
            policy = world.policy()
            result = world.app._stage_ib_command(world.target(), world.endpoint(), "", "", "admin", PUBLIC_REPLY,
                2, READ, local=False, strict=True, policy=policy)
            self.assertIs(type(result), world.app.SessionResult)
            self.assertEqual(BODY, result.output)
            self.assertGreater(world.real_native_calls, 0, "real admitted project target, not a truthy stub")
            responder = world.responders[-1]
            self.assertEqual(PUBLIC_REPLY, responder("admin@" + SCOPED + "'s password: "))
            try:
                pam_reply = responder("\nYou are required to change your password immediately (administrator enforced).\n(current) UNIX password: ")
            except world.app.SetupError:
                pam_reply = None
            self.assertIn(pam_reply, (None, "\x03"), "strict ordinary command cannot send a PAM password")
            self.assertFalse(any((result.password_changed, result.password_change_required,
                                  result.password_change_attempted, result.ib_authentication_rejected)))

    def test_strict_direct_rejects_invalid_command_before_fetching_project(self):
        with DirectWorld(self) as world:
            policy = world.policy()
            before = world.real_native_calls
            with self.assertRaises(world.app.SetupError):
                world.app._stage_ib_command(world.target(), world.endpoint(), "", "", "admin", PUBLIC_REPLY,
                    2, ["sh", "-c", "id"], local=False, strict=True, policy=policy)
            self.assertEqual(before, world.real_native_calls)
            self.assertEqual([], world.ssh_calls)

    def test_strict_direct_rejects_changed_real_project_before_transport(self):
        with DirectWorld(self) as world:
            policy = world.policy()
            with policy.path.open("a") as handle:
                handle.write("\n# PUBLIC changed qualification\n")
            with self.assertRaises(world.app.SetupError):
                world.app._stage_ib_command(world.target(), world.endpoint(), "", "", "admin", PUBLIC_REPLY,
                    2, READ, local=False, strict=True, policy=policy)
            self.assertEqual([], world.ssh_calls)

    def test_strict_direct_rejects_nonexact_result_expiry_and_every_rotation_flag(self):
        cases = ("fake-result", "expiry", {"password_changed": True}, {"password_change_required": True},
                 {"password_change_attempted": True}, {"ib_authentication_rejected": True})
        for model in cases:
            with self.subTest(model=model), DirectWorld(self) as world:
                policy = world.policy()
                world.replies["admin@" + SCOPED] = model
                with self.assertRaises(world.app.SetupError) as caught:
                    world.app._stage_ib_command(world.target(), world.endpoint(), "", "", "admin", PUBLIC_REPLY,
                        2, READ, local=False, strict=True, policy=policy)
                self.assertNotIn(PUBLIC_REPLY, str(caught.exception))
                self.assertTrue(world.kat["PASSWORD"] not in str(caught.exception), "KAT value must not escape in an error")
                self.assertEqual(["admin@" + SCOPED], world.ssh_calls)

    def test_direct_host_key_change_uses_local_editor(self):
        for address in (SCOPED, IP):
            with self.subTest(address=address), DirectWorld(self) as world:
                endpoint = world.endpoint() if address == SCOPED else world.endpoint(IP, None)
                task = world.app.PreparedIBTask(world.target(), endpoint, "", False)
                change, records, retries = world.make_host_key_change(address), [], []
                def retry():
                    self.assertEqual("empty", world.keygen_state)
                    retries.append(address)
                    world.keygen_state = "new"
                world.app.refresh_ib_host_key(change, task, eth_user="", timeout=2, apply=True,
                    read_device_fingerprint=None, retry=retry, operator_forced=True, host_key_records=records)
                self.assertEqual([address], retries)
                self.assertEqual([("remove", address)], [item for item in world.keygen_calls if item[0] == "remove"])
                self.assertEqual(1, len(records))
                self.assertEqual(("local", None, "operator-forced-unverified"),
                    (records[0].location, records[0].jump, records[0].verification))

    def test_direct_host_key_readonly_and_unverified_or_foreign_path_never_remove(self):
        for mode in ("readonly", "unverified", "foreign-path", "wrong-address"):
            with self.subTest(mode=mode), DirectWorld(self) as world:
                change = world.make_host_key_change()
                if mode == "foreign-path":
                    change = world.paths.HostKeyChange(SCOPED, "ED25519", NEW_FP,
                        str(world.root / "foreign-known-hosts"), (1,), "local", None)
                elif mode == "wrong-address":
                    change = world.paths.HostKeyChange("203.0.113.99", "ED25519", NEW_FP,
                        change.known_hosts_path, (1,), "local", None)
                task = world.app.PreparedIBTask(world.target(), world.endpoint(), "", False)
                with self.assertRaises(world.app.SetupError):
                    world.app.refresh_ib_host_key(change, task, eth_user="", timeout=2,
                        apply=mode != "readonly", read_device_fingerprint=None,
                        retry=world.deny, operator_forced=mode != "unverified", host_key_records=[])
                self.assertFalse(any(item[0] == "remove" for item in world.keygen_calls))


if __name__ == "__main__":
    unittest.main()
