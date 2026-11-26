"""WP4 tests-first contracts; static facets, NOT RUN except fixed old27 RED.

Independent PUBLIC values express r660 WP4/O5/O6(b)/O7/O8/O13/I039.
The old27 slice covers pure identity/Network/argv and actual readonly callers.
Later separate commits draft real-policy strict negatives, actual ordinary
backup consumers, deferred/direct endpoint callers, complete no-global MAIN
workflows and direct/key credential callers with an original PUBLIC native
verification boundary. These later facets have NOT RUN and require separate
review/admission; no fake private-phase custody is returned. DirectEndpoint
absence holds only those particular cases, not reachable pure/jump contracts.
The three full script literals were independently frozen before production;
no implementation output creates expected values. Real NVOS shell effects,
strict-cache/PTY success and complete global MAIN workflow remain unproven.
"""
from __future__ import annotations

import builtins
from contextlib import ExitStack, contextmanager
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.native_cpld_physical_io import owned_test_root


ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
MAC = "02:00:00:00:00:17"
HOST = "PUBLIC-IB01"
PROJECT = "PUBLIC-Project-Value-71!"
FACTORY = "PUBLIC-Factory-Value-72!"
CURRENT = "PUBLIC-Current-Value-73!"
READ = ["nv", "config", "show", "-o", "commands"]
FRESH = "nv set system hostname nvos\nnv set service lldp state enabled\n"
READY = (
    "nv set interface eth0-1 link state up\n"
    "nv set interface eth0-1 type eth\n"
    "nv set system hostname PUBLIC-IB01\n"
)
ADDRESS0 = "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
ADDRESS1 = "nv set interface eth1 ipv4 address 198.51.100.2/24\n"
GATEWAY0 = "nv set interface eth0 ipv4 gateway 203.0.113.1\n"
IP_ADDR = (
    "2: eth0: <UP> mtu 1500 state UP\n"
    "    link/ether 02:00:00:00:00:17 brd ff:ff:ff:ff:ff:ff\n"
    "    inet 203.0.113.2/24 scope global eth0\n"
)


# These complete literals were frozen by Root from independent proposal bytes,
# before any WP4 producer implementation; never load them from product constants.
EXPECTED_BACKUP_SCRIPT = (
    'set -eu\n'
    'umask 077\n'
    "fail() { printf '%s\\n' 'IB configuration backup failed' >&2; exit 1; }\n"
    '[ "$#" -eq 1 ] || fail\n'
    'stamp=$1\n'
    'case "$stamp" in\n'
    '    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n'
    '    *) fail ;;\n'
    'esac\n'
    'case "${HOME-}" in /*) ;; *) fail ;; esac\n'
    'backup="$HOME/current_${stamp}.yaml"\n'
    '[ ! -e "$backup" ] && [ ! -L "$backup" ] || fail\n'
    'tmp=\n'
    'trap \'if [ -n "$tmp" ]; then rm -f -- "$tmp"; fi\' EXIT\n'
    "trap 'exit 1' HUP INT TERM\n"
    'tmp=$(mktemp "${backup}.tmp.XXXXXX" 2>/dev/null) || fail\n'
    'chmod 600 "$tmp" || fail\n'
    'nv config show > "$tmp" 2>/dev/null || fail\n'
    '[ -s "$tmp" ] || fail\n'
    'bytes=$(wc -c < "$tmp" | tr -d \'[:space:]\') || fail\n'
    'case "$bytes" in \'\'|*[!0-9]*) fail ;; esac\n'
    '[ "$bytes" -gt 0 ] || fail\n'
    'ln -T -- "$tmp" "$backup" 2>/dev/null || fail\n'
    'rm -f -- "$tmp" || fail\n'
    'tmp=\n'
    'printf \'path=%s\\nbytes=%s\\n\' "$backup" "$bytes"\n'
)

EXPECTED_LAUNCH_SCRIPT = (
    'set -eu\n'
    'umask 077\n'
    "fail() { printf '%s\\n' 'IB deferred configuration launch failed' >&2; exit 1; }\n"
    '[ "$#" -eq 1 ] || fail\n'
    'stamp=$1\n'
    'case "$stamp" in\n'
    '    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n'
    '    *) fail ;;\n'
    'esac\n'
    'case "${HOME-}" in /*) ;; *) fail ;; esac\n'
    'rc_file="$HOME/.initial-setup-${stamp}.rc"\n'
    '[ ! -e "$rc_file" ] && [ ! -L "$rc_file" ] || fail\n'
    '(set -C; : > "$rc_file") 2>/dev/null || fail\n'
    'chmod 600 "$rc_file" || fail\n'
    "setsid nohup sh -c '\n"
    'set -u\n'
    'umask 077\n'
    'rc_file=$1\n'
    'sleep 3 || exit 1\n'
    'nv config apply -y && nv config save\n'
    'status=$?\n'
    'tmp=\n'
    'trap \'\\\'\'if [ -n "$tmp" ]; then rm -f -- "$tmp"; fi\'\\\'\' EXIT\n'
    "trap '\\''exit 1'\\'' HUP INT TERM\n"
    'tmp=$(mktemp "${rc_file}.tmp.XXXXXX" 2>/dev/null) || exit 1\n'
    'printf "%s\\n" "$status" > "$tmp" || exit 1\n'
    'chmod 600 "$tmp" || exit 1\n'
    'mv -fT -- "$tmp" "$rc_file" || exit 1\n'
    'tmp=\n'
    'exit "$status"\n'
    '\' -- "$rc_file" > /dev/null 2>&1 < /dev/null &\n'
    'exit 0\n'
)

EXPECTED_READ_RC_SCRIPT = (
    'set -eu\n'
    "fail() { printf '%s\\n' 'IB deferred configuration result is unverified' >&2; exit 1; }\n"
    '[ "$#" -eq 1 ] || fail\n'
    'stamp=$1\n'
    'case "$stamp" in\n'
    '    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n'
    '    *) fail ;;\n'
    'esac\n'
    'case "${HOME-}" in /*) ;; *) fail ;; esac\n'
    'rc_file="$HOME/.initial-setup-${stamp}.rc"\n'
    '[ ! -L "$rc_file" ] || fail\n'
    'if [ ! -e "$rc_file" ]; then printf \'rc=\\n\'; exit 0; fi\n'
    '[ -f "$rc_file" ] || fail\n'
    'if [ ! -s "$rc_file" ]; then printf \'rc=\\n\'; exit 0; fi\n'
    'IFS= read -r status < "$rc_file" || fail\n'
    'case "$status" in\n'
    '    0|[1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) ;;\n'
    '    *) fail ;;\n'
    'esac\n'
    'bytes=$(wc -c < "$rc_file" | tr -d \'[:space:]\') || fail\n'
    'case "$bytes" in \'\'|*[!0-9]*) fail ;; esac\n'
    '[ "$bytes" -eq "$((${#status} + 1))" ] || fail\n'
    'printf \'rc=%s\\n\' "$status"\n'
)


class _PublicCredentialSource:
    """Readonly selector input only; never a project/permit authority double."""
    def __init__(self, events, value=PROJECT, error=None):
        self._events, self._value, self._error = events, value, error

    def password(self):
        self._events.append(("credential-source", "project"))
        if self._error is not None:
            raise self._error
        return self._value


class IdentityAndBackupTests(unittest.TestCase):
    def setUp(self):
        # No system-temp fallback, host HOME, project inputs or native commands.
        try:
            owned = owned_test_root()
        except (AssertionError, OSError):
            raise RuntimeError("FIXTURE HOLD: explicit canonical owned root is required") from None
        tmp_value = os.environ.get("TMPDIR")
        if (not tmp_value or not Path(tmp_value).is_absolute()
                or Path(tmp_value).resolve() != owned):
            raise RuntimeError("FIXTURE HOLD: TMPDIR must be the explicit owned root")
        self._wp4_stack = ExitStack()
        self.addCleanup(self._wp4_stack.close)
        folder = self._wp4_stack.enter_context(
            tempfile.TemporaryDirectory(prefix="wp4-public-", dir=owned))
        home = Path(folder) / "home"
        home.mkdir(mode=0o700)
        self._wp4_home = home
        self._wp4_stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
        self._wp4_stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
        self._wp4_stack.enter_context(mock.patch.dict(sys.modules))
        self._wp4_app = load_script("wp4_public_" + format(id(self), "x"), INITIAL)
        self._wp4_paths = self._wp4_app._import_tools("tools.login_path")
        if Path(self._wp4_paths.__file__).resolve() != (ROOT / "tools/login_path.py").resolve():
            raise RuntimeError("FIXTURE HOLD: login_path must belong to this clone")
        info = home.lstat()
        if (home.resolve() != home or info.st_uid != os.geteuid()
                or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700):
            raise RuntimeError("FIXTURE HOLD: PUBLIC home is not owned/canonical/0700")

    def _wp4_device(self, *, secondary="", secondary_gateway=""):
        return self._wp4_app.Device(
            HOST, "ib", "203.0.113.2", "203.0.113.2/24", "203.0.113.1", MAC,
            secondary, secondary_gateway)

    def _wp4_no_external(self, callback):
        effects = []

        def forbidden(*_args, **_kwargs):
            effects.append("external-effect")
            raise RuntimeError("FIXTURE HOLD: readonly/pure WP4 entry attempted external IO")

        result = error = None
        with ExitStack() as guard:
            for owner, name in (
                (subprocess, "run"), (subprocess, "Popen"),
                (socket, "socket"), (socket, "create_connection"),
                (os, "open"), (os, "system"), (os, "execv"), (os, "execve"),
                (os, "fork"), (builtins, "open"), (Path, "open"),
                (self._wp4_app.getpass, "getpass"),
            ):
                guard.enter_context(mock.patch.object(owner, name, side_effect=forbidden))
            try:
                result = callback()
            except self._wp4_app.SetupError as caught:
                error = caught
        if effects:
            raise RuntimeError("FIXTURE HOLD: unexpected external IO is not business RED")
        return result, error

    def _wp4_network(self, device, current, expected):
        actual, error = self._wp4_no_external(
            lambda: self._wp4_app._management_network_commands(device, current))
        self.assertIsNone(error, "qualified PUBLIC Network input must be accepted")
        self.assertEqual(expected, actual)

    def _wp4_identity(self, *, address=IP_ADDR, route="", via_ipv4=True):
        facts = self._wp4_paths.parse_ip_addr(address)
        return self._wp4_paths.check_identity(
            MAC, self._wp4_paths.IdentityFacts(
                facts.mac, facts.ipv4, self._wp4_paths.parse_default_routes(route)),
            via_ipv4=via_ipv4, expected_ipv4="203.0.113.2/24",
            expected_gateway="203.0.113.1")

    def test_identity_read_vectors_are_exactly_admitted(self):
        for expected in (["ip", "addr", "show", "eth0"], ["ip", "route"]):
            with self.subTest(command=expected):
                supplied = list(expected)
                actual, error = self._wp4_no_external(
                    lambda: self._wp4_app.ib_command_argv(supplied))
                self.assertIsNone(error, "WP4 identity reads need exact allowlist entries")
                self.assertEqual(expected, actual)
                self.assertEqual(expected, supplied)
                self.assertIsNot(supplied, actual)

    def test_identity_read_near_misses_do_not_open_arbitrary_ip_or_shell(self):
        for supplied in (
            ["ip", "addr", "show", "eth1"], ["ip", "addr", "show"],
            ["ip", "addr", "show", "eth0", "extra"],
            ["ip", "route", "show", "vrf", "PUBLIC"], ["ip", "route;id"],
            ["sh", "-c", "ip addr show eth0"], ["sh", "-c", "printf PUBLIC"],
        ):
            with self.subTest(command=supplied):
                _, error = self._wp4_no_external(
                    lambda: self._wp4_app.ib_command_argv(supplied))
                self.assertIsInstance(error, self._wp4_app.SetupError)

    def _wp4_closed_scripts(self):
        return (("_CONFIG_BACKUP_SCRIPT", EXPECTED_BACKUP_SCRIPT),
                ("_DEFERRED_APPLY_SCRIPT", EXPECTED_LAUNCH_SCRIPT),
                ("_DEFERRED_APPLY_RC_SCRIPT", EXPECTED_READ_RC_SCRIPT))

    def test_closed_script_vectors_bind_the_complete_independent_literals(self):
        for name, expected_script in self._wp4_closed_scripts():
            for stamp in ("20261117-040000", "00000000-000000", "99999999-999999"):
                with self.subTest(script=name, stamp=stamp):
                    # Lexical stamp contract, not a new calendar/timezone policy.
                    supplied = ["sh", "-c", expected_script, "--", stamp]
                    expected = ["sh", "-c", expected_script, "--", stamp]
                    actual, error = self._wp4_no_external(
                        lambda: self._wp4_app.ib_command_argv(supplied))
                    self.assertIsNone(error, "approved complete closed script must reach argv admission")
                    self.assertEqual(expected, actual)
                    self.assertIsNot(actual, supplied)
                    self.assertEqual(expected, supplied)
                    self.assertEqual(expected_script, getattr(self._wp4_app, name, None),
                                     "the producer constant must equal the independently frozen bytes")

    def test_script_byte_mutations_and_extra_arguments_never_gain_authority(self):
        for name, expected_script in self._wp4_closed_scripts():
            original = ["sh", "-c", expected_script, "--", "20261117-040000"]
            for supplied in (
                ["sh", "-c", expected_script + "# PUBLIC changed byte\n", "--", "20261117-040000"],
                ["sh", "-c", expected_script[:-1], "--", "20261117-040000"],
                ["sh", "-c", expected_script, "PUBLIC", "20261117-040000"],
                [*original, "PUBLIC-extra"], original[:-1],
            ):
                with self.subTest(script=name, arguments=len(supplied), mutation=supplied[3:]):
                    _, error = self._wp4_no_external(lambda: self._wp4_app.ib_command_argv(supplied))
                    self.assertIsInstance(error, self._wp4_app.SetupError)

    def test_closed_script_stamp_is_not_a_path_or_shell_input(self):
        for name, expected_script in self._wp4_closed_scripts():
            for stamp in ("", "20261117040000", "20261117-04000", "20261117-0400000",
                          "20261117-040000\n", " 20261117-040000", "../../PUBLIC",
                          "20261117-040000;id", "$(id)", "20261117-040000/../PUBLIC",
                          "２０２６１１１７-０４００００", None, True, 20261117040000):
                with self.subTest(script=name, stamp=stamp):
                    _, error = self._wp4_no_external(lambda: self._wp4_app.ib_command_argv(
                        ["sh", "-c", expected_script, "--", stamp]))
                    self.assertIsInstance(error, self._wp4_app.SetupError)

    def _wp4_real_unverified_policy(self, *, user="admin"):
        # Syntactically valid PUBLIC hash, deliberately NEVER claimed verified.
        # Wrong account/source-change cases must refuse before any hash worker.
        setting = "$" + "6$PUBLICsalt$" + "A" * 86
        path = self._wp4_home / ("PUBLIC-global-" + user + ".yaml")
        path.write_text("schema_version: 2\nswitches:\n- ib:\n    system:\n"
                        "      aaa:\n        user:\n          " + user + ":\n"
                        "            pass" + "word: " + setting + "\n", encoding="utf-8")
        path.chmod(0o600)
        return self._wp4_app.ProjectPasswordPolicy(
            path, user, target_password=PROJECT, interactive=False)

    def _wp4_strict_refusal(self, policy):
        app = self._wp4_app
        device = self._wp4_device()
        jump = app.Device("PUBLIC-JUMP01", "eth_jump", "198.51.100.10", "", "", "", "", "")
        target = app.Target(device, jump, "swp7", "eth0")
        neighbor = app.Neighbor("fe80::17", "ib-mgmt", MAC)
        real_read = app._read_project_password_global
        reads, sessions, forbidden_effects = [], [], []

        def bound_read(path):
            self.assertEqual(policy.path, Path(path))
            self.assertEqual(self._wp4_home, Path(path).parent)
            reads.append(Path(path))
            return real_read(path)  # original FD/name/bytes authority, not a stubbed True

        def forbidden(*_args, **_kwargs):
            forbidden_effects.append("external-effect")
            raise RuntimeError("FIXTURE HOLD: strict refusal attempted native/external IO")

        def session(*_args, **_kwargs):
            sessions.append("IB-session")
            self.fail("invalid same-project authority must refuse before any IB session")

        error = None
        with ExitStack() as guard:
            guard.enter_context(mock.patch.object(app, "_read_project_password_global", new=bound_read))
            guard.enter_context(mock.patch.object(app, "run_on_ib", new=session))
            for owner, name in ((subprocess, "run"), (subprocess, "Popen"),
                                (socket, "socket"), (socket, "create_connection"),
                                (os, "system"), (os, "execv"), (os, "execve"),
                                (os, "fork"), (app.getpass, "getpass")):
                guard.enter_context(mock.patch.object(owner, name, side_effect=forbidden))
            try:
                app._run_authorized_ib_command(
                    target, neighbor, "cumulus", "PUBLIC-Outer-Only", "admin", CURRENT, 5,
                    list(READ), local=False, _password_policy=policy)
            except app.SetupError as caught:
                error = caught
        if forbidden_effects:
            raise RuntimeError("FIXTURE HOLD: forbidden effect is not a qualified strict refusal")
        self.assertIs(type(error), app.SetupError)
        self.assertEqual(("management IB operation failed; device state is UNKNOWN",), error.args)
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertEqual([], sessions)
        self.assertIsNone(policy._password, "failed authority must not become a verified credential")
        return reads

    def test_strict_identity_caller_requires_the_actual_matching_project_account(self):
        policy = self._wp4_real_unverified_policy(user="operator")
        self.assertIs(type(policy), self._wp4_app.ProjectPasswordPolicy)
        # The existing READ reaches the actual account guard even on the old
        # producer; new script/API absence must not hide this protection.
        self.assertEqual([], self._wp4_strict_refusal(policy))

    def test_strict_identity_caller_rechecks_source_bytes_before_any_session(self):
        policy = self._wp4_real_unverified_policy()
        before = policy.path.read_bytes()
        after = before + b"# PUBLIC changed after real policy admission\n"
        policy.path.write_bytes(after)
        self.assertEqual([policy.path], self._wp4_strict_refusal(policy))
        self.assertEqual(after, policy.path.read_bytes(), "refusal must not rewrite its project source")

    def test_link_local_identity_checks_mac_not_ipv4_or_default_route(self):
        address = IP_ADDR.replace("203.0.113.2/24", "198.51.100.88/27")
        result, error = self._wp4_no_external(lambda: self._wp4_identity(
            address=address, route="default via 192.0.2.99 dev eth0\n", via_ipv4=False))
        self.assertIsNone(error)
        self.assertTrue(result.ok)
        self.assertEqual((), result.mismatches)
        bad, error = self._wp4_no_external(lambda: self._wp4_identity(
            address=address.replace(MAC, "02:00:00:00:00:18"), via_ipv4=False))
        self.assertIsNone(error)
        self.assertEqual((("mac", MAC, "02:00:00:00:00:18"),), bad.mismatches)

    def test_ipv4_identity_requires_address_and_mask_membership(self):
        for value in ("203.0.113.2/25", "203.0.113.3/24"):
            with self.subTest(observed=value):
                result, error = self._wp4_no_external(lambda: self._wp4_identity(
                    address=IP_ADDR.replace("203.0.113.2/24", value)))
                self.assertIsNone(error)
                self.assertFalse(result.ok)
                self.assertEqual((("ipv4", "203.0.113.2/24", value),), result.mismatches)

    def test_ipv4_identity_allows_no_default_route_but_refuses_a_foreign_default(self):
        for route in ("", "203.0.113.0/24 dev eth0 scope link\n",
                      "default via 203.0.113.1 dev eth0\n"):
            with self.subTest(route=route):
                result, error = self._wp4_no_external(lambda: self._wp4_identity(route=route))
                self.assertIsNone(error)
                self.assertEqual((True, ()), (result.ok, result.mismatches))
        result, error = self._wp4_no_external(lambda: self._wp4_identity(
            route="default via 203.0.113.1 dev eth0\ndefault via 198.51.100.1 dev eth1\n"))
        self.assertIsNone(error)
        self.assertFalse(result.ok)
        self.assertEqual((("gateway", "203.0.113.1", "203.0.113.1,198.51.100.1"),),
                         result.mismatches)

    def test_no_eth1_sets_only_eth0_gateway_and_keeps_both_reserved_ports(self):
        self._wp4_network(self._wp4_device(), FRESH, [
            ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
            ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
            ["nv", "set", "interface", "eth0-1", "type", "eth"],
            ["nv", "set", "system", "hostname", HOST],
        ])

    def test_eth1_address_without_gateway_adds_address_but_no_eth1_gateway(self):
        self._wp4_network(self._wp4_device(secondary="198.51.100.2/24"), FRESH, [
            ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
            ["nv", "set", "interface", "eth1", "ipv4", "address", "198.51.100.2/24"],
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
            ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
            ["nv", "set", "interface", "eth0-1", "type", "eth"],
            ["nv", "set", "system", "hostname", HOST],
        ])

    def test_both_supplied_equal_gateways_keep_the_range_setter(self):
        self._wp4_network(self._wp4_device(
            secondary="203.0.113.3/24", secondary_gateway="203.0.113.1"), FRESH, [
            ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
            ["nv", "set", "interface", "eth1", "ipv4", "address", "203.0.113.3/24"],
            ["nv", "set", "interface", "eth0-1", "ipv4", "gateway", "203.0.113.1"],
            ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
            ["nv", "set", "interface", "eth0-1", "type", "eth"],
            ["nv", "set", "system", "hostname", HOST],
        ])

    def test_different_supplied_gateways_remain_independent(self):
        self._wp4_network(self._wp4_device(
            secondary="198.51.100.2/24", secondary_gateway="198.51.100.1"), FRESH, [
            ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
            ["nv", "set", "interface", "eth1", "ipv4", "address", "198.51.100.2/24"],
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
            ["nv", "set", "interface", "eth1", "ipv4", "gateway", "198.51.100.1"],
            ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
            ["nv", "set", "interface", "eth0-1", "type", "eth"],
            ["nv", "set", "system", "hostname", HOST],
        ])

    def test_legacy_range_readback_and_unrequested_eth1_are_preserved(self):
        current = (ADDRESS0 + "nv set interface eth0 ipv4 address 203.0.113.99/24\n"
                   + "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                   + "nv set interface eth1 ipv4 address 198.51.100.77/24\n" + READY)
        self._wp4_network(self._wp4_device(), current, [])
        state, error = self._wp4_no_external(
            lambda: self._wp4_app._verify_management_network_state(self._wp4_device(), current))
        self.assertIsNone(error)
        self.assertEqual(("203.0.113.2/24", "203.0.113.99/24"), state.eth0_addresses)
        self.assertEqual(("198.51.100.77/24",), state.eth1_addresses)

    def test_optional_eth1_gateway_is_not_required_by_post_verification(self):
        device = self._wp4_device(secondary="198.51.100.2/24")
        current = ADDRESS0 + ADDRESS1 + GATEWAY0 + READY
        state, error = self._wp4_no_external(
            lambda: self._wp4_app._verify_management_network_state(device, current))
        self.assertIsNone(error, "provided address without gateway is a complete optional eth1 fact")
        self.assertEqual(("198.51.100.2/24",), state.eth1_addresses)
        self.assertEqual((), state.eth1_gateways)

    def test_optional_eth1_gateway_is_not_a_force_missing_fact(self):
        device = self._wp4_device(secondary="198.51.100.2/24")
        state = self._wp4_app.parse_nvue_state(ADDRESS0 + ADDRESS1 + GATEWAY0 + READY)
        needed, error = self._wp4_no_external(lambda: self._wp4_app.force_day0_needed(device, state))
        self.assertIsNone(error)
        self.assertIs(False, needed)

    def test_plan_vectors_do_not_reintroduce_an_unprovided_eth1_gateway(self):
        commands, error = self._wp4_no_external(
            lambda: self._wp4_app.desired_commands(self._wp4_device()))
        self.assertIsNone(error)
        self.assertEqual([
            ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
            ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
            ["nv", "set", "interface", "eth0-1", "type", "eth"],
            ["nv", "set", "system", "hostname", HOST],
            ["nv", "config", "apply", "-y"], ["nv", "config", "save"],
        ], commands)

    def test_pending_does_not_claim_ownership_of_an_unprovided_eth1_gateway(self):
        _, error = self._wp4_no_external(lambda: self._wp4_app._validate_owned_pending(
            self._wp4_device(), "nv set interface eth1 ipv4 gateway 203.0.113.1\n"))
        self.assertIsInstance(error, self._wp4_app.SetupError)

    def test_foreign_pending_is_not_permission_and_supplied_equal_range_stays_owned(self):
        device = self._wp4_device(secondary="203.0.113.3/24", secondary_gateway="203.0.113.1")
        count, error = self._wp4_no_external(lambda: self._wp4_app._validate_owned_pending(
            device, "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"))
        self.assertIsNone(error)
        self.assertEqual(1, count)
        _, error = self._wp4_no_external(lambda: self._wp4_app._validate_owned_pending(
            device, "nv set system dns server 203.0.113.99\n"))
        self.assertIsInstance(error, self._wp4_app.SetupError)

    def _wp4_jump_auth(self, response, *, inspect_layer=False, source_error=None, source=True):
        events = []
        app = self._wp4_app
        ib = self._wp4_device()
        jump = app.Device("PUBLIC-JUMP01", "eth_jump", "198.51.100.10", "", "", "", "", "")
        target = app.Target(ib, jump, "swp7", "eth0")
        neighbor = app.Neighbor("fe80::17", "ib-mgmt", MAC)
        policy = _PublicCredentialSource(events, error=source_error) if source else None

        def boundary(*args, **kwargs):
            self.assertEqual(8, len(args))
            self.assertIs(args[0], target)
            self.assertIs(args[1], neighbor)
            self.assertEqual(READ, args[7])
            self.assertIs(False, kwargs.get("local"))
            self.assertIs(False, kwargs.get("allow_password_change"))
            self.assertIs(True, kwargs.get("password_only"))
            self.assertNotIn("_phase_operation", kwargs)
            events.append(("readonly-session", args[5]))
            return response(args[5])

        def current_input(_hostname):
            events.append(("credential-source", "current"))
            return CURRENT

        def actual_entry():
            if inspect_layer:
                return app.inspect_ib_device(
                    target, neighbor, "cumulus", "PUBLIC-Outer-Only", "admin", FACTORY, 5,
                    policy, apply=False, authorized=False, local=False, strict=False)
            return app._authenticate_ib_read(
                target, neighbor, "cumulus", "PUBLIC-Outer-Only", "admin", FACTORY, 5,
                local=False, _password_policy=policy, strict=False)

        with mock.patch.object(app, "run_on_ib", new=boundary), \
             mock.patch.object(app, "request_current_ib_password", new=current_input), \
             mock.patch.object(app, "confirm_first_device_change",
                               side_effect=AssertionError("readonly cannot authorize PAM/config")), \
             mock.patch.object(app, "log", new=lambda *_a, **_k: None):
            result, error = self._wp4_no_external(actual_entry)
        return events, result, error

    def test_jump_project_is_the_first_known_credential_even_when_factory_would_accept(self):
        events, login, error = self._wp4_jump_auth(
            lambda _password: self._wp4_app.SessionResult(FRESH, 0))
        self.assertIsNone(error)
        self.assertEqual([("credential-source", "project"), ("readonly-session", PROJECT)], events)
        self.assertEqual(PROJECT, login.current_password)

    def test_jump_factory_is_used_only_after_project_authentication_rejection(self):
        def response(password):
            if password == PROJECT:
                raise self._wp4_app.IBAuthenticationError("PUBLIC typed project rejection")
            return self._wp4_app.SessionResult(FRESH, 0)
        events, login, error = self._wp4_jump_auth(response)
        self.assertIsNone(error)
        self.assertEqual([("credential-source", "project"), ("readonly-session", PROJECT),
                          ("readonly-session", FACTORY)], events)
        self.assertEqual(FACTORY, login.current_password)

    def test_non_auth_uncertainty_does_not_try_another_credential(self):
        def response(_password):
            raise self._wp4_app.SetupError("PUBLIC UNKNOWN transport evidence")
        events, _, error = self._wp4_jump_auth(response)
        self.assertIsInstance(error, self._wp4_app.SetupError)
        self.assertNotIsInstance(error, self._wp4_app.IBAuthenticationError)
        self.assertEqual([("credential-source", "project"), ("readonly-session", PROJECT)], events)

    def test_inspect_keeps_one_current_answer_after_both_known_credentials_reject(self):
        def response(password):
            if password != CURRENT:
                raise self._wp4_app.IBAuthenticationError("PUBLIC typed known-value rejection")
            return self._wp4_app.SessionResult(FRESH, 0)
        events, result, error = self._wp4_jump_auth(response, inspect_layer=True)
        self.assertIsNone(error)
        self.assertEqual([("credential-source", "project"), ("readonly-session", PROJECT),
                          ("readonly-session", FACTORY), ("credential-source", "current"),
                          ("readonly-session", CURRENT)], events)
        self.assertEqual((CURRENT, False), result[1:])

    def test_readonly_factory_expiry_never_enters_pam_or_confirmation(self):
        def response(password):
            if password == PROJECT:
                raise self._wp4_app.IBAuthenticationError("PUBLIC typed project rejection")
            return self._wp4_app.SessionResult("", 0, password_change_required=True)
        events, result, error = self._wp4_jump_auth(response, inspect_layer=True)
        self.assertIsNone(error)
        self.assertTrue(result[0].password_change_required)
        self.assertEqual([("credential-source", "project"), ("readonly-session", PROJECT),
                          ("readonly-session", FACTORY)], events)
        self.assertIs(False, result[2])

    def test_missing_global_keeps_the_original_factory_readonly_path(self):
        events, login, error = self._wp4_jump_auth(
            lambda _password: self._wp4_app.SessionResult(FRESH, 0), source=False)
        self.assertIsNone(error)
        self.assertEqual([("readonly-session", FACTORY)], events)
        self.assertEqual(FACTORY, login.current_password)

    def test_unavailable_project_source_stops_before_any_ib_session(self):
        events, _, error = self._wp4_jump_auth(
            lambda _password: self._wp4_app.SessionResult(FRESH, 0),
            source_error=self._wp4_app.SetupError("PUBLIC project target unavailable"))
        self.assertIsInstance(error, self._wp4_app.SetupError)
        self.assertEqual([("credential-source", "project")], events)

    def _wp4_readonly_execution(self, *, observed_mac=MAC):
        """Real task/stages, no global: only the external IB session is a model."""
        app = self._wp4_app
        device = self._wp4_device()
        jump = app.Device("PUBLIC-JUMP01", "eth_jump", "198.51.100.10", "", "", "", "", "")
        target = app.Target(device, jump, "swp7", "eth0")
        task = app.PreparedIBTask(target, app.Neighbor("fe80::17", "ib-mgmt", MAC),
                                  "PUBLIC-Outer-Only", False)
        args = SimpleNamespace(eth_user="cumulus", ib_user="admin", connect_timeout=5,
                               apply=False, force=False, execution_mode="ethernet",
                               _on_management_server=False)
        # Independent known-complete readback: stage 1 skips from real facts,
        # not a replaced Initial/parser/permission routine or ready flag.
        current = (ADDRESS0 + "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n" + READY
                   + "nv set system config auto-save state enabled\n"
                   + "nv set system ztp config-save enabled\n")
        commands = []

        def boundary(*positional, **options):
            self.assertEqual(8, len(positional))
            self.assertIs(target, positional[0])
            self.assertIs(task.neighbor, positional[1])
            self.assertEqual(FACTORY, positional[5])
            self.assertIs(False, options.get("local"))
            # The original _stage_ib_command uses the real run_on_ib default.
            self.assertIs(False, options.get("allow_password_change", False))
            command = tuple(positional[7])
            commands.append(command)
            if command == tuple(READ):
                return app.SessionResult(current, 0)
            if command == ("ip", "addr", "show", "eth0"):
                return app.SessionResult(IP_ADDR.replace(MAC, observed_mac), 0)
            if command == ("ip", "route"):
                return app.SessionResult("default via 203.0.113.1 dev eth0\n", 0)
            if command == ("nv", "show", "system", "ztp"):
                return app.SessionResult("service disabled\nstate disabled\n", 0)
            if command == ("hostname",):
                # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its NVUE hostname.
                return app.SessionResult(HOST + "\n", 0)
            raise RuntimeError("FIXTURE HOLD: unexpected readonly task command")

        with mock.patch.object(app, "run_on_ib", new=boundary), \
             mock.patch.object(app, "log", new=lambda *_a, **_k: None), \
             mock.patch.object(app, "request_current_ib_password",
                               side_effect=AssertionError("known readonly credential must not prompt")), \
             mock.patch.object(app, "confirm_first_device_change",
                               side_effect=AssertionError("readonly task must not authorize writes")):
            result, error = self._wp4_no_external(lambda: app.execute_ib_task(
                task, args, None, FACTORY, None, [], None))
        self.assertIsNone(error)
        return result, commands

    def test_real_readonly_execute_consumes_login_identity_before_initial_stage(self):
        result, commands = self._wp4_readonly_execution()
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        # U4 (v3.1.6 D1d, guide 8.11 steps 1-2): check-only reads the Linux hostname once after the
        # NVUE hostname is verified; a matching name adds no write.
        self.assertEqual([tuple(READ), ("ip", "addr", "show", "eth0"),
                          ("nv", "show", "system", "ztp"), ("hostname",)], commands)
        self.assertIs(False, result["writes_attempted"])
        self.assertEqual("CHECKED", result["stage_status"]["initial"])
        self.assertEqual("NO_KEYS_PROVIDED", result["stage_status"]["public_keys"])
        self.assertEqual("NOT_TESTED", result["stage_status"]["direct_ssh"])

    def test_real_readonly_execute_identity_mismatch_stops_one_task_before_initial(self):
        wrong = "02:00:00:00:00:18"
        failed, refused = self._wp4_readonly_execution(observed_mac=wrong)
        self.assertEqual("FAILED", failed["outcome"])
        self.assertEqual([tuple(READ), ("ip", "addr", "show", "eth0")], refused)
        self.assertIn(MAC, failed["reason"])
        self.assertIn(wrong, failed["reason"])
        self.assertIs(False, failed["writes_attempted"])
        self.assertEqual("NOT_REACHED", failed["stage_status"]["initial"])
        healthy, accepted = self._wp4_readonly_execution()
        self.assertEqual("ALREADY_CONFIGURED", healthy["outcome"])
        self.assertIn(("nv", "show", "system", "ztp"), accepted)

    def _wp4_apply_flow(self, *, backup_output=None, backup_status=0, readonly=False,
                        configured=False, initial_ready=False):
        """Real ordinary task+permission path; only framed external IO is modelled.

        This carrier has no project global and proves NO strict/hash/direct/PTY
        qualification. It deliberately does not replace run_on_ib or a stage.
        """
        app = self._wp4_app
        stamp = "20261117-040000"
        path = "/home/PUBLIC-IB01/current_" + stamp + ".yaml"
        receipt = "path=" + path + "\nbytes=137\n"
        if backup_output is None:
            backup_output = receipt
        device = self._wp4_device()
        jump = app.Device("PUBLIC-JUMP01", "eth_jump", "198.51.100.10", "", "", "", "", "")
        target = app.Target(device, jump, "swp7", "eth0")
        task = app.PreparedIBTask(target, app.Neighbor("fe80::17", "ib-mgmt", MAC),
                                  "PUBLIC-Outer-Only", False)
        args = SimpleNamespace(eth_user="cumulus", ib_user="admin", connect_timeout=5,
                               apply=not readonly, yes=True, force=False, run_stamp=stamp,
                               execution_mode="ethernet", _on_management_server=False)
        authority = app.RuntimeInputAuthority([])
        coordinator = app.RuntimeCoordinator(args, None, FACTORY, [task], authority)
        coordinator.current_target = target
        events = []
        state = (ADDRESS0 + "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n" + READY
                 if configured else FRESH)
        if initial_ready:
            state += ("nv set system config auto-save state enabled\n"
                      "nv set system ztp config-save enabled\n")
        allowed_setters = {
            ("nv", "set", "system", "config", "auto-save", "state", "enabled"),
            ("nv", "set", "system", "ztp", "config-save", "enabled"),
            ("nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"),
            ("nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"),
            ("nv", "set", "interface", "eth0-1", "ipv4", "gateway", "203.0.113.1"),
            ("nv", "set", "interface", "eth0-1", "link", "state", "up"),
            ("nv", "set", "interface", "eth0-1", "type", "eth"),
            ("nv", "set", "system", "hostname", HOST),
        }
        original_permit = app.obtain_write_permit

        def permit(category="nvue"):
            events.append(("permit", category))
            return original_permit(category)

        def interactive(argv, responder, timeout):
            nonlocal state
            # Independent complete original wire grammar. No shell execution,
            # SUT framing helper, or replacement builder supplies expectations.
            self.assertIs(type(argv), list)
            self.assertEqual("ssh", argv[0])
            self.assertEqual("cumulus@198.51.100.10", argv[-2])
            wrapper = shlex.split(argv[-1])
            self.assertEqual(["sh", "-c"], wrapper[:2])
            self.assertEqual(3, len(wrapper))
            safe = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
            self.assertTrue(wrapper[2].startswith(safe))
            nested = shlex.split(wrapper[2][len(safe):])
            self.assertEqual(["ip", "vrf", "exec", "default", "ssh"], nested[:5])
            self.assertIn(nested[-2], ("admin@fe80::17", "admin@203.0.113.2"))
            framed = shlex.split(nested[-1])
            self.assertEqual(["sh", "-c"], framed[:2])
            self.assertEqual(3, len(framed))
            markers = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", framed[2])
            self.assertEqual(1, len(markers))
            nonce = markers[0]
            prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
            suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                      + '__=%s\\n" "$task_rc"; exit "$task_rc"')
            self.assertTrue(framed[2].startswith(prefix))
            self.assertTrue(framed[2].endswith(suffix))
            command_text = framed[2][len(prefix):-len(suffix)]
            command = tuple(shlex.split(command_text))
            self.assertEqual(command_text, shlex.join(command))
            self.assertIs(type(responder), app.NestedResponder)
            self.assertIsNone(getattr(responder, "_phase", None), "ordinary carrier is not a fake strict phase")
            events.append(("command", command))
            status, output = 0, ""
            if command == tuple(READ):
                output = state
            elif command == ("ip", "addr", "show", "eth0"):
                output = IP_ADDR
            elif command == ("ip", "route"):
                output = "default via 203.0.113.1 dev eth0\n"
            elif command == ("nv", "show", "system", "ztp"):
                output = "service disabled\nstate disabled\n"
            elif command == ("nv", "config", "diff", "-o", "commands"):
                output = ""
            elif command == ("hostname",):
                # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its NVUE hostname.
                names = [line.split()[-1] for line in state.splitlines()
                         if line.startswith("nv set system hostname ")]
                output = (names[-1] if names else "nvos") + "\n"
            elif command == ("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", stamp):
                status, output = backup_status, backup_output
            elif command in allowed_setters:
                # Only this PUBLIC device's independently enumerated settings.
                key = command[:-1]
                prior = [line for line in state.splitlines()
                         if tuple(shlex.split(line))[:-1] != key]
                state = "\n".join([*prior, shlex.join(command)]) + "\n"
            elif command not in (("nv", "config", "apply", "-y"), ("nv", "config", "save"), ("true",)):
                raise RuntimeError("FIXTURE HOLD: unmodelled PUBLIC task command")
            return app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + output
                + ("\n" if output and not output.endswith("\n") else "")
                + "__HTTP_IB_END_" + nonce + "__=" + str(status) + "\n", status)

        with mock.patch.object(app, "interactive_run", new=interactive), \
             mock.patch.object(app, "obtain_write_permit", new=permit), \
             mock.patch.object(app, "_ACTIVE_COORDINATOR", coordinator), \
             mock.patch.object(app, "log", new=lambda *_a, **_k: None), \
             mock.patch.object(app, "time", new=SimpleNamespace(
                 sleep=lambda delay: events.append(("sleep", delay)), monotonic=lambda: 0.0)):
            result, error = self._wp4_no_external(lambda: app.execute_ib_task(
                task, args, None, FACTORY, None, [], None))
        self.assertIsNone(error)
        return result, events, coordinator, path

    def test_actual_apply_backs_up_once_before_the_first_initial_or_network_write(self):
        for initial_ready in (False, True):
            with self.subTest(initial_ready=initial_ready):
                result, events, coordinator, _path = self._wp4_apply_flow(initial_ready=initial_ready)
                self.assertEqual("CONFIGURED", result["outcome"])
                commands = [entry[1] for entry in events if entry[0] == "command"]
                backup = ("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", "20261117-040000")
                self.assertEqual(1, commands.count(backup), "one backup across real Initial and Network stages")
                first_nvue = next(index for index, command in enumerate(commands)
                                  if command[:2] == ("nv", "set") or command[:3] in
                                  (("nv", "config", "apply"), ("nv", "config", "save")))
                self.assertEqual(backup, commands[first_nvue - 1], "backup is the last device command before first NVUE write")
                self.assertIn(("ip", "addr", "show", "eth0"), commands)
                self.assertLess(commands.index(("ip", "addr", "show", "eth0")), commands.index(backup))
                backup_event = events.index(("command", backup))
                self.assertGreater(backup_event, 0)
                self.assertEqual("permit", events[backup_event - 1][0])
                self.assertNotIn(events[backup_event - 1][1],
                                 ("public_key", "nvue", "password", "host_key"),
                                 "backup is its own category, not borrowed key/NVUE authority")
                self.assertTrue(coordinator.writes_attempted)
                self.assertGreater(coordinator.metrics.get("nvue_write_commands", 0), 0)

    def test_readonly_and_already_complete_tasks_do_not_create_a_backup(self):
        for readonly, configured in ((True, False), (True, True), (False, True)):
            with self.subTest(readonly=readonly, configured=configured):
                result, events, _coordinator, _path = self._wp4_apply_flow(
                    readonly=readonly, configured=configured, initial_ready=True)
                commands = [entry[1] for entry in events if entry[0] == "command"]
                self.assertIn(result["outcome"], ("CHECK_ONLY", "ALREADY_CONFIGURED"))
                self.assertFalse(any(command[:2] == ("sh", "-c") for command in commands))
                self.assertFalse(any(command[:2] == ("nv", "set") for command in commands))

    def test_failed_or_unqualified_backup_receipt_blocks_every_later_nvue_write(self):
        good = "path=/home/PUBLIC-IB01/current_20261117-040000.yaml\nbytes=137\n"
        invalid = (
            (1, good), (0, ""), (0, "bytes=137\n"),
            (0, "path=/home/PUBLIC-IB01/current_20261117-040000.yaml\n"),
            (0, good + "bytes=137\n"), (0, good + "PUBLIC-DUMP-CONTENT\n"),
            (0, good.replace("20261117-040000", "20261117-040001")),
            (0, good.replace("/home/PUBLIC-IB01/", "../")),
            (0, good.replace("137", "0")), (0, good.replace("137", "-1")),
            (0, good.replace("137", "PUBLIC")),
        )
        for status, output in invalid:
            with self.subTest(status=status, receipt=output):
                result, events, _coordinator, _path = self._wp4_apply_flow(
                    backup_status=status, backup_output=output, initial_ready=True)
                commands = [entry[1] for entry in events if entry[0] == "command"]
                backup = ("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", "20261117-040000")
                self.assertIn(backup, commands, "receipt behavior is not reached without an actual backup call")
                self.assertEqual("FAILED_CONFIG_BACKUP", self._wp4_app.record_category(result))
                self.assertFalse(any(command[:2] == ("nv", "set") or command[:3] in
                    (("nv", "config", "apply"), ("nv", "config", "save")) for command in commands))

    def _wp4_deferred_flow(self, *, replies=("rc=\n", "rc=0\n"), rc_status=0,
                           launch_status=0, fresh_mismatch=False, network_complete=False,
                           refresh_then_fresh_mismatch=False):
        # Import the already reviewed owned-root carrier, not a producer API or
        # new transport engine. This method alone needs the frozen WP3 endpoint.
        from test_cases.test_initial_setup_direct_transport import (
            DirectWorld, PrerequisiteHold, IP, MAC1, IFACE, NEW_FP, _Facade,
        )
        import time as original_time

        with DirectWorld(self) as world:
            app = world.app
            if not callable(getattr(app, "DirectEndpoint", None)):
                raise PrerequisiteHold("WP3 DirectEndpoint is not in this fixed baseline; deferred path NOT REACHED")
            if not callable(getattr(app, "_DirectResponder", None)):
                raise PrerequisiteHold("WP3 _DirectResponder is not in this fixed baseline; deferred path NOT REACHED")
            target = world.target(same_subnet=None)
            point = app.DirectEndpoint(IP, None)
            task = app.PreparedIBTask(target, point, "", False)
            stamp = "20261117-040000"
            args = SimpleNamespace(eth_user="", ib_user="admin", connect_timeout=2,
                apply=True, yes=True, force=False, run_stamp=stamp,
                execution_mode="management", _on_management_server=False)
            warning_path = None
            if refresh_then_fresh_mismatch:
                self.assertTrue(network_complete and fresh_mismatch)
                # Only create the original owned PUBLIC fixture file; its typed
                # helper return never substitutes for the parsed SSH warning.
                world.make_host_key_change(IP)
                warning_path = str(world.home / ".ssh" / "known_hosts")
                args._refresh_host_key_names = app.resolve_host_key_refresh_selector(
                    target.ib.hostname, {app.normalize_name(target.ib.hostname): target.ib})
            coordinator = app.RuntimeCoordinator(args, None, FACTORY, [task], app.RuntimeInputAuthority([]))
            coordinator.current_target = target
            state = ("nv set system hostname nvos\n"
                     "nv set system config auto-save state enabled\n"
                     "nv set system ztp config-save enabled\n")
            if network_complete:
                # Independent complete CSV Network/Initial facts: this run has
                # no address setter or deferred launch to gate the fresh read.
                state = ("nv set system hostname " + target.ib.hostname + "\n"
                    "nv set interface eth0 ipv4 address " + IP + "/24\n"
                    "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
                    "nv set interface eth0-1 link state up\n"
                    "nv set interface eth0-1 type eth\n"
                    "nv set system config auto-save state enabled\n"
                    "nv set system ztp config-save enabled\n")
            services = {"dns": ["192.0.2.53"], "ntp": ["192.0.2.123"], "timezone": "UTC"}
            events, clock, rc_reads, completed = [], [0.0], [], [False]
            identity_reads = []
            warning_issued, retry_started = [False], [False]
            expected_setters = {
                ("nv", "set", "interface", "eth0", "ipv4", "address", IP + "/24"),
                ("nv", "set", "interface", "eth0", "ipv4", "gateway", "192.0.2.1"),
                ("nv", "set", "interface", "eth0-1", "ipv4", "gateway", "192.0.2.1"),
                ("nv", "set", "interface", "eth0-1", "link", "state", "up"),
                ("nv", "set", "interface", "eth0-1", "type", "eth"),
                ("nv", "set", "system", "hostname", target.ib.hostname),
                ("nv", "set", "system", "dns", "server", "192.0.2.53"),
                ("nv", "set", "system", "ntp", "server", "192.0.2.123"),
                ("nv", "set", "system", "date-time", "timezone", "UTC"),
            }

            def sleep(seconds):
                self.assertGreaterEqual(seconds, 0)
                events.append(("sleep", seconds))
                clock[0] += seconds

            def interactive(argv, responder, timeout, **options):
                nonlocal state
                self.assertIs(type(argv), list)
                self.assertEqual("ssh", argv[0], "one direct SSH, never a fake jump")
                self.assertEqual("admin@" + IP, argv[-2])
                self.assertNotIn("cumulus@", " ".join(argv))
                self.assertNotIn("ip vrf exec", " ".join(argv))
                remote = shlex.split(argv[-1])
                self.assertEqual(["sh", "-c"], remote[:2])
                self.assertEqual(3, len(remote))
                nonces = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertEqual(1, len(nonces))
                nonce = nonces[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix))
                self.assertTrue(remote[2].endswith(suffix))
                raw = remote[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(raw))
                self.assertEqual(raw, shlex.join(command))
                self.assertIs(type(responder), app._DirectResponder)
                if getattr(responder, "_phase", None) is not None:
                    raise PrerequisiteHold("deferred caller needs real private-phase carrier; no fabricated custody")
                events.append(("command", command))
                status, output = 0, ""
                if command == tuple(READ):
                    output = state
                elif command == ("ip", "addr", "show", "eth0"):
                    if refresh_then_fresh_mismatch and identity_reads and not warning_issued[0]:
                        warning_issued[0] = True
                        events.append(("host-key-warning", IP))
                        warning = ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
                            "The fingerprint for the ED25519 key sent by the remote host is\n"
                            + NEW_FP + "\nOffending ED25519 key in " + warning_path + ":1\n"
                            "Host key for " + IP + " has changed and you have requested strict checking.\n"
                            "  ssh-keygen -f " + shlex.quote(warning_path) + " -R " + IP + "\n"
                            "Host key verification failed.\n")
                        return app.SessionResult(warning, 255)
                    if refresh_then_fresh_mismatch and warning_issued[0] and not retry_started[0]:
                        self.assertEqual("empty", world.keygen_state,
                                         "the one retry must follow the original modeled removal")
                        retry_started[0] = True
                        world.keygen_state = "new"  # original PUBLIC accepted-key model, not a real key
                        events.append(("host-key-retry-input", IP))
                    changed = (len(identity_reads) >= 1 if network_complete else completed[0])
                    observed = "02:00:00:00:00:99" if fresh_mismatch and changed else MAC1
                    identity_reads.append(observed)
                    if network_complete:
                        events.append(("identity-read", observed))
                    output = ("2: eth0: <UP> mtu 1500 state UP\n    link/ether " + observed
                              + " brd ff:ff:ff:ff:ff:ff\n    inet " + IP + "/24 scope global eth0\n")
                elif command == ("ip", "route"):
                    output = "default via 192.0.2.1 dev eth0\n"
                elif command == ("nv", "show", "system", "ztp"):
                    output = "service disabled\nstate disabled\n"
                elif command == ("nv", "config", "diff", "-o", "commands"):
                    output = ""
                elif command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its NVUE hostname.
                    names = [line.split()[-1] for line in state.splitlines()
                             if line.startswith("nv set system hostname ")]
                    output = (names[-1] if names else "nvos") + "\n"
                elif command == ("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", stamp):
                    output = "path=/home/PUBLIC/current_" + stamp + ".yaml\nbytes=137\n"
                elif command == ("sh", "-c", EXPECTED_LAUNCH_SCRIPT, "--", stamp):
                    status = launch_status
                elif command == ("sh", "-c", EXPECTED_READ_RC_SCRIPT, "--", stamp):
                    index = len(rc_reads)
                    output, status = replies[min(index, len(replies) - 1)], rc_status
                    rc_reads.append(output)
                    if status == 0 and output == "rc=0\n":
                        completed[0] = True
                elif command in expected_setters:
                    key = command[:-1]
                    state = "\n".join([line for line in state.splitlines()
                        if tuple(shlex.split(line))[:-1] != key] + [shlex.join(command)]) + "\n"
                elif command not in (("nv", "config", "apply", "-y"), ("nv", "config", "save"), ("true",)):
                    raise RuntimeError("FIXTURE HOLD: unknown direct deferred PUBLIC command")
                return app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + output
                    + ("\n" if output and not output.endswith("\n") else "")
                    + "__HTTP_IB_END_" + nonce + "__=" + str(status) + "\n", status)

            with mock.patch.object(app, "interactive_run", new=interactive), \
                 mock.patch.object(app, "_ACTIVE_COORDINATOR", coordinator), \
                 mock.patch.object(app, "time", new=_Facade(original_time,
                     sleep=sleep, monotonic=lambda: clock[0])), \
                 mock.patch.object(app, "log", new=lambda *_a, **_k: None):
                previous_profile = sys.getprofile()
                tail_entries = ({app.run_service_stage.__code__: "services",
                    app.run_management_direct_checks.__code__: "final-direct"} if network_complete else {})
                refresh_entries = {}
                if refresh_then_fresh_mismatch:
                    tail_entries[app.run_key_stage.__code__] = "public-keys"
                    refresh_entries = {world.paths.parse_host_key_change.__code__: "parse-warning",
                        app._direct_host_key_task_gate.__code__: "direct-gate",
                        world.paths.LocalKnownHostsEditor.__init__.__code__: "local-editor",
                        world.paths.refresh_target_host_key.__code__: "library-refresh"}
                def observe_tail(frame, event, _value):
                    if (event == "call" and frame.f_globals is app.__dict__
                            and frame.f_code in tail_entries):
                        events.append(("tail-entry", tail_entries[frame.f_code]))
                    if refresh_then_fresh_mismatch and event == "call":
                        if frame.f_code in refresh_entries:
                            events.append(("host-key-caller", refresh_entries[frame.f_code]))
                        if frame.f_globals is app.__dict__:
                            if (frame.f_code is app.obtain_write_permit.__code__
                                    and frame.f_locals.get("category") == "host_key"):
                                events.append(("host-key-permit",))
                            if frame.f_code.co_name == "verify_ready":
                                readiness = frame.f_locals["readiness_policy"]
                                if readiness.attempts == 1:
                                    self.assertIs(type(readiness), app.ReadinessPolicy)
                                    self.assertEqual(0, readiness.first_delay)
                                    events.append(("host-key-retry",))
                try:
                    if network_complete:
                        sys.setprofile(observe_tail)
                    result = app.execute_ib_task(task, args, None, FACTORY, services, [], None)
                finally:
                    if network_complete:
                        sys.setprofile(previous_profile)
                if network_complete:
                    self.assertIs(previous_profile, sys.getprofile())
            if refresh_then_fresh_mismatch:
                events.extend(("keygen", *entry) for entry in world.keygen_calls)
                events.append(("host-key-metric", coordinator.metrics.get("host_key_remove_attempts", 0)))
                events.append(("host-key-write-attempted", coordinator.writes_attempted))
            self.assertFalse(task.local)
            self.assertIsNone(task.target.ethernet)
            self.assertEqual("", task.ethernet_password)
            return result, events, rc_reads

    def test_ipv4_base_launch_waits_for_real_rc_then_fresh_identity_before_services(self):
        result, events, reads = self._wp4_deferred_flow()
        self.assertEqual("CONFIGURED", result["outcome"])
        self.assertEqual(["rc=\n", "rc=0\n"], reads)
        commands = [event[1] for event in events if event[0] == "command"]
        launch = ("sh", "-c", EXPECTED_LAUNCH_SCRIPT, "--", "20261117-040000")
        read = ("sh", "-c", EXPECTED_READ_RC_SCRIPT, "--", "20261117-040000")
        service = ("nv", "set", "system", "dns", "server", "192.0.2.53")
        self.assertEqual(1, commands.count(launch))
        self.assertEqual(2, commands.count(read))
        end = len(commands) - 1 - commands[::-1].index(read)
        self.assertLess(commands.index(launch), commands.index(read))
        self.assertNotIn(("nv", "config", "apply", "-y"), commands[:end + 1])
        self.assertNotIn(("nv", "config", "save"), commands[:end + 1])
        self.assertIn(("ip", "addr", "show", "eth0"), commands[end + 1:])
        self.assertIn(("ip", "route"), commands[end + 1:])
        self.assertIn(service, commands)
        fresh = commands.index(("ip", "addr", "show", "eth0"), end + 1)
        self.assertLess(fresh, commands.index(service))
        self.assertIn(("nv", "config", "apply", "-y"), commands[commands.index(service) + 1:],
                      "Services still use their original in-session apply, not the base deferred script")

    def test_launch_zero_and_empty_rc_never_mean_configuration_completed(self):
        result, events, reads = self._wp4_deferred_flow(replies=("rc=\n",))
        self.assertEqual("FAILED", result["outcome"])
        self.assertTrue(reads, "original rc-wait path must actually be reached")
        self.assertTrue(all(value == "rc=\n" for value in reads))
        self.assertFalse(any(event == ("command", ("nv", "set", "system", "dns", "server", "192.0.2.53"))
                             for event in events))

    def test_deferred_failure_or_bad_rc_stops_before_later_service_writes(self):
        for response, status in (("rc=1\n", 0), ("rc=255\n", 0), ("rc=256\n", 0),
                ("rc=-1\n", 0), ("rc=00\n", 0), ("rc=0\nPUBLIC\n", 0), ("rc=0\n", 1)):
            with self.subTest(receipt=response, status=status):
                result, events, reads = self._wp4_deferred_flow(replies=(response,), rc_status=status)
                self.assertEqual("FAILED", result["outcome"])
                self.assertTrue(reads)
                self.assertFalse(any(event == ("command", ("nv", "set", "system", "dns", "server", "192.0.2.53"))
                                     for event in events))

    def test_failed_launch_does_not_read_old_zero_rc_or_run_services(self):
        result, events, reads = self._wp4_deferred_flow(launch_status=1, replies=("rc=0\n",))
        self.assertEqual("FAILED", result["outcome"])
        self.assertEqual([], reads, "failed launch cannot borrow an old successful rc")
        self.assertFalse(any(event == ("command", ("nv", "set", "system", "dns", "server", "192.0.2.53"))
                             for event in events))

    def test_fresh_identity_mismatch_after_rc_zero_is_fatal_without_retry(self):
        result, events, reads = self._wp4_deferred_flow(replies=("rc=0\n",), fresh_mismatch=True)
        self.assertEqual("FAILED_IDENTITY_MISMATCH", self._wp4_app.record_category(result))
        self.assertEqual(["rc=0\n"], reads)
        commands = [event[1] for event in events if event[0] == "command"]
        read = ("sh", "-c", EXPECTED_READ_RC_SCRIPT, "--", "20261117-040000")
        self.assertIn(read, commands)
        tail = commands[commands.index(read) + 1:]
        self.assertEqual(1, tail.count(("ip", "addr", "show", "eth0")))
        self.assertFalse(any(command[:5] == ("nv", "set", "system", "dns", "server") for command in tail))

    def test_nondeferred_complete_network_fresh_identity_mismatch_stops_all_later_probes(self):
        from test_cases.test_initial_setup_direct_transport import MAC1

        result, events, reads = self._wp4_deferred_flow(
            network_complete=True, fresh_mismatch=True)
        self.assertEqual([MAC1, "02:00:00:00:00:99"],
            [event[1] for event in events if event[0] == "identity-read"],
            "original login identity is valid; only the second fresh identity differs, without retry")
        self.assertEqual([], reads, "an unchanged Network must not depend on any deferred rc")
        self.assertEqual("FAILED", result["outcome"])
        self.assertEqual("FAILED_IDENTITY_MISMATCH", self._wp4_app.record_category(result))
        self.assertEqual("ALREADY_PRESENT", result["stage_status"]["day0"])
        self.assertEqual("FAILED", result["stage_status"]["ipv4_readiness"])
        self.assertEqual("NOT_REACHED", result["stage_status"]["services"])
        self.assertEqual([], [event[1] for event in events if event[0] == "tail-entry"],
            "a fatal fresh identity mismatch must enter neither Services nor the final direct diagnostic")
        self.assertEqual("NOT_REACHED", result["stage_status"]["direct_ssh"])
        commands = [event[1] for event in events if event[0] == "command"]
        self.assertFalse(any(command[:2] in (("sh", "-c"), ("nv", "set"))
            or command[:3] in (("nv", "config", "apply"), ("nv", "config", "save"))
            for command in commands), "this already-complete Network has no configuration write or backup")
        self.assertIs(False, result["writes_attempted"])

    def test_host_key_single_retry_retains_fresh_identity_failure_without_overriding_k4(self):
        from test_cases.test_initial_setup_direct_transport import IP, MAC1

        wrong = "02:00:00:00:00:99"
        result, events, reads = self._wp4_deferred_flow(
            network_complete=True, fresh_mismatch=True, refresh_then_fresh_mismatch=True)
        self.assertEqual([MAC1, wrong], [event[1] for event in events if event[0] == "identity-read"])
        self.assertEqual([("host-key-warning", IP)], [event for event in events if event[0] == "host-key-warning"])
        self.assertEqual([("host-key-retry",)], [event for event in events if event[0] == "host-key-retry"])
        self.assertEqual([("host-key-retry-input", IP)], [event for event in events if event[0] == "host-key-retry-input"])
        self.assertEqual([("keygen", "remove", IP)], [event for event in events if event[:2] == ("keygen", "remove")])
        self.assertEqual([("host-key-permit",)], [event for event in events if event[0] == "host-key-permit"])
        self.assertIn(("host-key-metric", 1), events)
        self.assertIn(("host-key-write-attempted", True), events)
        self.assertTrue({"parse-warning", "direct-gate", "local-editor", "library-refresh"}
                        <= {event[1] for event in events if event[0] == "host-key-caller"})
        commands = [event[1] for event in events if event[0] == "command"]
        self.assertEqual(3, commands.count(("ip", "addr", "show", "eth0")))
        self.assertEqual([], reads)
        self.assertEqual("FAILED", result["outcome"])
        self.assertEqual("TARGET_HOST_KEY_CHANGED", result["failure_kind"])
        self.assertEqual("FAILED_TARGET_HOST_KEY_CHANGED", self._wp4_app.record_category(result))
        self.assertIs(False, result["identity"]["ok"], "the final record must not retain the first successful O5 identity")
        self.assertEqual(MAC1, result["identity"]["expected"]["mac"])
        self.assertEqual(wrong, result["identity"]["observed"]["mac"])
        self.assertIn(MAC1, result["reason"])
        self.assertIn(wrong, result["reason"])
        self.assertEqual([], [event[1] for event in events if event[0] == "tail-entry"])
        for stage in ("services", "public_keys", "direct_ssh"):
            self.assertEqual("NOT_REACHED", result["stage_status"][stage])
        self.assertEqual("FAILED", result["stage_status"]["ipv4_readiness"])
        self.assertEqual([], result["host_key"], "failed retry is not a completed refreshed-success receipt")
        self.assertFalse(any(command[:2] in (("sh", "-c"), ("nv", "set"))
            or command[:3] in (("nv", "config", "apply"), ("nv", "config", "save")) for command in commands))

    def _wp4_whole_main(self, *, failure):
        """No-global MAIN→M4→LP→actual inline worker→summary, with NO sentinel.

        The no-global compatibility case is explicit, not a strict/cache/hash
        permission substitute. Every original stage and coordinator runs.
        """
        from contextlib import redirect_stderr, redirect_stdout
        from test_cases.test_initial_setup_cable_check import (
            _World, _Facade, IB1, IB2, LL1, LL2, MAC1, MAC2, PUBLIC_REPLY,
        )
        case = self

        class WholeWorld(_World):
            def __enter__(world):
                super().__enter__()
                world.wp4_events, world.wp4_entered = [], set()
                world.wp4_modules = {}
                world.wp4_adapter_errors = []
                world.wp4_batch, world.wp4_stamp = None, None
                world.wp4_inputs = set()
                world.wp4_states = {host: ("nv set system hostname nvos\n"
                    "nv set system config auto-save state enabled\n"
                    "nv set system ztp config-save enabled\n") for host in (IB1, IB2)}
                original_mkdir = world.app.tempfile.mkdtemp

                def directory(*args, **kwargs):
                    if kwargs.get("prefix") == "isj-":
                        return original_mkdir(*args, **kwargs)
                    case.assertEqual((), args)
                    case.assertEqual({"prefix", "dir"}, set(kwargs))
                    case.assertEqual("devices-" + world.wp4_stamp + "-", kwargs["prefix"])
                    case.assertEqual(world.root, Path(kwargs["dir"]).resolve())
                    path = Path(tempfile.mkdtemp(prefix=kwargs["prefix"], dir=world.root))
                    case.assertEqual(world.root, path.parent)
                    case.assertEqual(0o700, stat.S_IMODE(path.lstat().st_mode))
                    return str(path)
                world.app.tempfile = _Facade(tempfile, mkdtemp=directory)
                original_interactive = world.interactive

                def external(*args, **kwargs):
                    try:
                        return original_interactive(*args, **kwargs)
                    except BaseException as error:
                        # The real worker may retain a script_error record.
                        # Do not let it relabel an adapter error as business RED.
                        world.wp4_adapter_errors.append(error)
                        raise
                world.stack.enter_context(mock.patch.object(world.app, "interactive_run", new=external))
                return world

            def profile(world, frame, event, value):
                # Observation only: no exception, return substitution, frame
                # locals mutation, dispatch stop or Initial checkpoint.
                if event == "call" and frame.f_code.co_filename.startswith(str(ROOT / "tools") + os.sep):
                    world.wp4_entered.add(Path(frame.f_code.co_filename).name)
                if frame.f_globals is not world.app.__dict__:
                    return
                name = frame.f_code.co_name
                if event == "call":
                    world.wp4_entered.add(name)
                    if name == "run_prepared_tasks":
                        world.prepared = tuple(frame.f_locals["tasks"])
                        world.wp4_stamp = frame.f_locals["args"].run_stamp
                        case.assertRegex(world.wp4_stamp, r"^[0-9]{8}-[0-9]{6}$")
                        case.assertIsNone(frame.f_locals["policy"], "this workflow is the original no-global case")
                        world.wp4_inputs = {entry[0] for entry in frame.f_locals["authority"].entries}
                elif event == "return":
                    if name == "_import_tools":
                        required = {"tools.device_identity": "main", "tools.hostname_ranges": "main",
                                    "tools.login_path": "main", "tools.inventory_subset": "_compare_inventory"}
                        requested, caller = frame.f_locals.get("name"), frame.f_back
                        if (requested in required and caller is not None
                                and caller.f_globals is world.app.__dict__
                                and caller.f_code.co_name == required[requested]):
                            world.wp4_modules.setdefault(requested, []).append(value)
                    elif name == "run_prepared_tasks":
                        world.wp4_batch = value  # actual object, no replacement
                    elif name == "_new_jump_sessions" and value is not None:
                        world.sessions = value

            def interactive(world, argv, responder, timeout, **options):
                if "-M" in argv:
                    return super().interactive(argv, responder, timeout, **options)
                case.assertIs(type(argv), list)
                case.assertEqual("ssh", argv[0])
                direct = argv[-2].startswith("admin@")
                if direct:
                    case.assertIn(argv[-2], ("admin@192.0.2.10", "admin@192.0.2.12"))
                    remote = shlex.split(argv[-1])
                    endpoint = argv[-2]
                else:
                    outer = shlex.split(argv[-1])
                    case.assertEqual(["sh", "-c"], outer[:2])
                    safe = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
                    case.assertTrue(outer[2].startswith(safe))
                    nested = shlex.split(outer[2][len(safe):])
                    if nested[:4] != ["ip", "vrf", "exec", "oob"] or "ssh" not in nested[:6]:
                        return super().interactive(argv, responder, timeout, **options)
                    path = world._scoped_path(argv)
                    case.assertIn(path, world.masters)
                    endpoint, remote = nested[-2], shlex.split(nested[-1])
                hosts = {"admin@" + LL1: IB1, "admin@" + LL2: IB2,
                         "admin@192.0.2.10": IB1, "admin@192.0.2.12": IB2}
                case.assertIn(endpoint, hosts)
                host = hosts[endpoint]
                case.assertEqual(["sh", "-c"], remote[:2])
                case.assertEqual(3, len(remote))
                nonces = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                case.assertEqual(1, len(nonces))
                nonce = nonces[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                case.assertTrue(remote[2].startswith(prefix))
                case.assertTrue(remote[2].endswith(suffix))
                body = remote[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(body))
                case.assertEqual(body, shlex.join(command))
                case.assertIsNone(getattr(responder, "_phase", None), "no fake strict phase receipt")
                case.assertEqual(PUBLIC_REPLY, responder.ib_default_password)
                world.wp4_events.append((host, command))
                address, mac = (("192.0.2.10", MAC1) if host == IB1 else ("192.0.2.12", MAC2))
                output = ""
                if command == tuple(READ):
                    output = world.wp4_states[host]
                elif command == ("ip", "addr", "show", "eth0"):
                    observed = "02:00:00:00:00:99" if host == IB1 and failure == "identity" else mac
                    output = ("2: eth0: <UP> mtu 1500 state UP\n    link/ether " + observed
                              + " brd ff:ff:ff:ff:ff:ff\n    inet " + address + "/24 scope global eth0\n")
                elif command == ("ip", "route"):
                    output = "default via 192.0.2.1 dev eth0\n"
                elif command == ("nv", "show", "system", "ztp"):
                    output = "service disabled\nstate disabled\n"
                elif command == ("nv", "config", "diff", "-o", "commands"):
                    output = ""
                elif command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its NVUE hostname.
                    names = [line.split()[-1] for line in world.wp4_states[host].splitlines()
                             if line.startswith("nv set system hostname ")]
                    output = (names[-1] if names else "nvos") + "\n"
                elif command == ("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", world.wp4_stamp):
                    output = "path=/home/PUBLIC-" + host + "/current_" + world.wp4_stamp + ".yaml\nbytes=137\n"
                    if host == IB1 and failure == "backup":
                        output += "PUBLIC-DUMP-CONTENT-MUST-NOT-LEAVE-DEVICE\n"
                elif command in {
                    ("nv", "set", "interface", "eth0", "ipv4", "address", address + "/24"),
                    ("nv", "set", "interface", "eth0", "ipv4", "gateway", "192.0.2.1"),
                    ("nv", "set", "interface", "eth0-1", "ipv4", "gateway", "192.0.2.1"),
                    ("nv", "set", "interface", "eth0-1", "link", "state", "up"),
                    ("nv", "set", "interface", "eth0-1", "type", "eth"),
                    ("nv", "set", "system", "hostname", host),
                }:
                    key = command[:-1]
                    world.wp4_states[host] = "\n".join([line for line in world.wp4_states[host].splitlines()
                        if tuple(shlex.split(line))[:-1] != key] + [shlex.join(command)]) + "\n"
                elif command not in (("true",), ("nv", "config", "apply", "-y"), ("nv", "config", "save")):
                    raise RuntimeError("FIXTURE HOLD: whole MAIN saw unknown PUBLIC IB command")
                return world.app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + output
                    + ("\n" if output and not output.endswith("\n") else "")
                    + "__HTTP_IB_END_" + nonce + "__=0\n", 0)

        with WholeWorld(self) as world:
            output = io.StringIO()
            argv = [str(INITIAL), "--project-dir", str(world.project), "--ib-csv", str(world.csv),
                "--p2p", str(world.p2p), "--report", str(world.root / "report.log"),
                "--target-cache", str(world.root / "targets.json"), "--snapshot-dir", str(world.root / "snapshots"),
                "--execution-mode", "management", "--apply", "--yes", "--max-workers", "1"]
            previous = sys.getprofile()
            try:
                with mock.patch.object(sys, "argv", argv), redirect_stdout(output), redirect_stderr(output):
                    sys.setprofile(world.profile)
                    code = world.app._standalone_main_with_report_cleanup()
            finally:
                sys.setprofile(previous)
                if world.app.REPORT_HANDLE is not None:
                    world.app.REPORT_HANDLE.close()
                    world.app.REPORT_HANDLE = None
            if world.wp4_adapter_errors:
                raise world.wp4_adapter_errors[0]
            if type(world.wp4_batch) is not dict:
                raise RuntimeError("PREREQUISITE HOLD: MAIN did not complete its actual worker pipeline; "
                                   + output.getvalue())
            if any(record.get("script_error") for record in world.wp4_batch["records"].values()):
                raise RuntimeError("SOURCE/ADAPTER ERROR: worker exception is not identity/backup behavior RED")
            self.assertEqual({IB1, IB2}, {task.target.ib.hostname for task in world.prepared})
            self.assertTrue({world.csv.absolute(), world.p2p.absolute(), INITIAL.absolute()} <= world.wp4_inputs)
            self.assertEqual({"tools.device_identity", "tools.hostname_ranges", "tools.login_path",
                              "tools.inventory_subset"}, set(world.wp4_modules))
            for name, values in world.wp4_modules.items():
                self.assertEqual(1, len(values), "one mandatory real loader return from its fixed caller")
                module = values[0]
                self.assertIs(type(module), type(sys))
                self.assertEqual(name, module.__name__)
                self.assertIs(module, sys.modules[name])
                self.assertEqual((ROOT / "tools" / (name.split(".")[1] + ".py")).resolve(),
                                 Path(module.__file__).resolve())
            self.assertTrue({"inventory_subset.py", "device_identity.py", "login_path.py",
                "execute_ib_task", "run_prepared_tasks", "print_initial_setup_summary"} <= world.wp4_entered)
            summary_path = Path(world.wp4_batch["log_dir"]) / "summary.json"
            self.assertEqual(world.root, summary_path.parent.parent)
            self.assertEqual(0o600, stat.S_IMODE(summary_path.lstat().st_mode))
            summary = json.loads(summary_path.read_text())
            report = (world.root / "report.log").read_text()
            self.assertIsNone(world.app._ACTIVE_COORDINATOR)
            self.assertIsNone(world.app._TASK_DEADLINE)
            self.assertIsNone(world.app._TASK_LOG_BUFFER)
            self.assertIs(previous, sys.getprofile())
            # WP5 consumer-only assertions: keep this ALREADY qualified APPLY
            # model, original stages and five-value interface unchanged.
            expected_body = []
            for hostname, ip, mac, port in (
                    (IB1, "192.0.2.10", MAC1, "swp7"),
                    (IB2, "192.0.2.12", MAC2, "swp8")):
                record = summary["records"][hostname]
                saved = json.loads((summary_path.parent / (hostname + ".json")).read_text())
                for field in ("route", "cable_check", "identity", "input_issues",
                              "eth1_hints", "backup", "outcome", "category",
                              "writes_attempted", "metrics"):
                    self.assertIn(field, saved)
                    self.assertIn(field, record)
                    self.assertEqual(record[field], saved[field],
                                     "actual per-device and summary fields differ: " + field)
                self.assertEqual({"hostname": hostname, "path": "jump", "reason": "JUMP_LINK",
                                  "jump": "example-jump-a", "port": port, "same_subnet": None},
                                 record["route"])
                self.assertEqual({"hostname": hostname, "mac": mac,
                                  "link_local": LL1 if hostname == IB1 else LL2,
                                  "expected": ["example-jump-a", port], "verdict": "MATCH",
                                  "actual": [["example-jump-a", port]], "extra_macs": [],
                                  "login_interface": "ib-mgmt", "after_ping": False,
                                  "ping_ok": None, "ignored": False}, record["cable_check"])
                observed_mac = "02:00:00:00:00:99" if hostname == IB1 and failure == "identity" else mac
                good = hostname == IB2
                self.assertEqual({
                    "ok": observed_mac == mac, "via_ipv4": good,
                    "expected": {"mac": mac, "ipv4": ip + "/24" if good else None,
                                 "gateway": "192.0.2.1" if good else None},
                    "observed": {"mac": observed_mac, "ipv4": [ip + "/24"],
                                 "gateways": ["192.0.2.1"] if good else []},
                    "mismatches": [] if observed_mac == mac else [
                        {"field": "mac", "expected": mac, "observed": observed_mac}],
                }, record["identity"])
                expected_backup = ({"path": "/home/PUBLIC-example-ib02/current_" + world.wp4_stamp + ".yaml",
                                    "bytes": 137} if good else None)
                self.assertEqual(expected_backup, record["backup"])
                self.assertEqual([], record["input_issues"])
                self.assertEqual(1, len(record["eth1_hints"]))
                hint = record["eth1_hints"][0]
                self.assertEqual({"hostname": hostname, "field": "eth1_mac", "value": "", "blocking": False},
                    {key: hint[key] for key in ("hostname", "field", "value", "blocking")})
                self.assertTrue(type(hint["problem"]) is str and bool(hint["problem"].strip()))
                identity_line = (f'    Identity: ok={"yes" if observed_mac == mac else "no"}'
                    f' via_ipv4={"yes" if good else "no"} mac_expected="{mac}" mac_observed="{observed_mac}"')
                if good:
                    identity_line += (f' ipv4_expected="{ip}/24" ipv4_observed=["{ip}/24"]'
                                      ' gateway_expected="192.0.2.1" gateways_observed=["192.0.2.1"]')
                expected_body.extend([
                    "  Device facts: " + hostname,
                    '    Route: path="jump" reason="JUMP_LINK" same_subnet=null',
                    f'    Cable: expected="example-jump-a:{port}" actual=["example-jump-a:{port}"] verdict=MATCH after_ping=no ping_ok=unknown ignored=no',
                    identity_line, ("hint-transport", hostname),
                ])
                if good:
                    expected_body.append('    Backup: path="/home/PUBLIC-example-ib02/current_'
                                         + world.wp4_stamp + '.yaml" bytes=137')
            # The original helper's finally closes/clears REPORT_HANDLE; this
            # checks real report bytes, not a stronger product-finally claim.
            for channel, text in (("console", output.getvalue()), ("report", report)):
                with self.subTest(final_channel=channel):
                    self.assertEqual(1, text.count("  TOTAL: 2\n"))
                    after = text.split("  TOTAL: 2\n", 1)[1]
                    self.assertIn("\n+-- 04 CONFIGURATION STAGES", after)
                    body = after.split("\n+-- 04 CONFIGURATION STAGES", 1)[0].strip("\n").splitlines()
                    self.assertEqual(len(expected_body), len(body), "no missing, injected or duplicated final facts")
                    for expected, line in zip(expected_body, body):
                        if type(expected) is str:
                            self.assertEqual(expected, line)
                        else:
                            hint = summary["records"][expected[1]]["eth1_hints"][0]
                            match = re.fullmatch(r'    eth1 hint: field="eth1_mac" value="" problem=("(?:[^"\\]|\\.)*")', line)
                            self.assertIsNotNone(match)
                            self.assertEqual(hint["problem"], json.loads(match.group(1)))
                    self.assertNotIn("PUBLIC-DUMP-CONTENT-MUST-NOT-LEAVE-DEVICE", text)
                    self.assertEqual(7, len(re.findall(r"(?m)^\+-- \d\d ", text)))
            return code, summary, report, list(world.wp4_events), world.wp4_stamp

    def test_whole_main_identity_failure_is_per_device_and_reaches_actual_summary(self):
        code, summary, report, events, stamp = self._wp4_whole_main(failure="identity")
        # Approved r660 :267: device failures mean INCOMPLETE/2, not a script failure.
        self.assertEqual(2, code)
        records = summary["records"]
        self.assertEqual("FAILED_IDENTITY_MISMATCH", records["example-ib01"]["category"])
        self.assertEqual("CONFIGURED", records["example-ib02"]["outcome"])
        self.assertIs(False, records["example-ib01"]["writes_attempted"])
        bad = [command for host, command in events if host == "example-ib01"]
        good = [command for host, command in events if host == "example-ib02"]
        self.assertEqual(1, bad.count(("ip", "addr", "show", "eth0")))
        self.assertFalse(any(command[:2] == ("nv", "set") for command in bad))
        self.assertEqual(1, good.count(("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", stamp)))
        self.assertEqual("INCOMPLETE", summary["result"])
        self.assertIn("FAILED_IDENTITY_MISMATCH", report)

    def test_whole_main_backup_receipt_failure_keeps_other_device_and_never_reports_content(self):
        code, summary, report, events, stamp = self._wp4_whole_main(failure="backup")
        # Same existing per-device failure contract; another device still completes.
        self.assertEqual(2, code)
        self.assertEqual("INCOMPLETE", summary["result"])
        records = summary["records"]
        self.assertEqual("FAILED_CONFIG_BACKUP", records["example-ib01"]["category"])
        self.assertEqual("CONFIGURED", records["example-ib02"]["outcome"])
        for host in ("example-ib01", "example-ib02"):
            commands = [command for device, command in events if device == host]
            self.assertEqual(1, commands.count(("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", stamp)))
            if host == "example-ib01":
                self.assertFalse(any(command[:2] == ("nv", "set") for command in commands))
        rendered = json.dumps(summary, sort_keys=True)
        self.assertIn("/home/PUBLIC-example-ib02/current_" + stamp + ".yaml", rendered)
        self.assertNotIn("PUBLIC-DUMP-CONTENT-MUST-NOT-LEAVE-DEVICE", rendered + report)

    def _wp4_direct_credentials(self, *, model, apply=False, public_exact_pair=False):
        """Actual execute/inspect/selector plus original real project verifier.

        Only exact PUBLIC native-hash worker and external SSH replies are
        allowed. No producer helper or permission method returns a fake True.
        This is ordinary direct caller coverage, not strict-cache/PTY proof.
        The explicit PUBLIC-pair mode uses only a synthetic verifier boundary;
        its six additional methods do not replace the default native cases.
        """
        from test_cases.test_initial_setup_direct_transport import (
            DirectWorld, PrerequisiteHold, IP, MAC1, _Facade, _NATIVE_POPEN,
        )
        with DirectWorld(self) as world:
            app = world.app
            if not callable(getattr(app, "DirectEndpoint", None)):
                raise PrerequisiteHold("fixed producer lacks WP3 DirectEndpoint; direct credential case NOT REACHED")
            global_file = world.project / "01-global.yaml"
            if public_exact_pair:
                # Deliberately choose this branch before importing or calling
                # the original provider. This is NOT native hash coverage.
                project_value = PROJECT
                public_setting = "$" + "6$PUBLICsalt$" + "A" * 86
                global_file.write_text('schema_version: 2\nswitches:\n- ib:\n    system:\n'
                    '      aaa:\n        user:\n          admin:\n            password: "'
                    + public_setting + '"\n', encoding="utf-8")
            else:
                from test_cases.test_initial_setup_target_password_policy import required_external_kat, project_global
                world.kat = required_external_kat()  # original independent fixed PUBLIC provider/pins
                project_value = world.kat["PASSWORD"]
                global_file.write_text(project_global(world.kat["YESCRYPT"]), encoding="utf-8")
            global_file.chmod(0o600)
            policy = app.ProjectPasswordPolicy(global_file, "admin",
                target_password=project_value, interactive=False)
            keys = world.home / ".ssh"
            keys.mkdir(mode=0o700, exist_ok=True)
            private = keys / "id_ed25519"
            private.write_bytes(b"PUBLIC SYNTHETIC KEY INPUT; NEVER USED BY AN SSH CLIENT\n")
            private.chmod(0o600)
            events, worker_calls = [], []
            public_verifications, native_attempts = [], []
            public_input = global_file.read_bytes() if public_exact_pair else None
            if public_exact_pair:
                self.assertTrue(len({PROJECT, FACTORY, CURRENT}) == 3,
                                "the three independent PUBLIC credential roles must differ")
                for path, mode in ((world.home, 0o700), (world.project, 0o700),
                                   (keys, 0o700), (private, 0o600), (global_file, 0o600)):
                    self.assertTrue(path == path.resolve() and path.lstat().st_uid == os.geteuid()
                                    and stat.S_IMODE(path.lstat().st_mode) == mode,
                                    "PUBLIC input must remain canonical, owned and privately permissioned")
            real_run = subprocess.run
            native_argv = [sys.executable, "-I", "-S", "-B", str(INITIAL.resolve()), "--_verify-password"]

            def public_verify(value, digest):
                self.assertTrue(type(value) is str and value in (PROJECT, FACTORY, CURRENT),
                                "PUBLIC verifier accepts only independently defined credential roles")
                self.assertTrue(type(digest) is str and digest == public_setting,
                                "PUBLIC verifier must bind the owned independent hash shape")
                matched = value == PROJECT
                public_verifications.append(matched)
                return matched

            def public_control(argv, **kwargs):
                if argv == native_argv:
                    native_attempts.append("forbidden-native")
                    raise RuntimeError("FIXTURE HOLD: PUBLIC pair mode must never start a native worker")
                if argv in (["ip", "-4", "neigh", "show", IP], ["ping", "-c", "1", "-W", "1", IP]):
                    return world.control(argv, **kwargs)
                raise RuntimeError("FIXTURE HOLD: PUBLIC pair mode attempted an unmodelled external command")

            def native(argv, **kwargs):
                if argv != native_argv:
                    if argv in (["ip", "-4", "neigh", "show", IP], ["ping", "-c", "1", "-W", "1", IP]):
                        return world.control(argv, **kwargs)
                    # The inherited controller's unknown-vector repr is not a
                    # safe destination for a malformed native request carrying
                    # a credential. Preserve a fixed-message prerequisite.
                    raise PrerequisiteHold("unreviewed native invocation; no argv or credential data emitted")
                self.assertTrue(set(kwargs) == {"input", "text", "capture_output", "timeout", "check", "env"},
                                "native request keyword schema differs from the fixed contract")
                self.assertTrue(type(kwargs["timeout"]) is int and kwargs["timeout"] == 8,
                                "native verification retains the original eight-second budget")
                self.assertTrue(kwargs["text"] is True, "native verification must use text input")
                self.assertTrue(kwargs["capture_output"] is True, "native verification must retain both output streams")
                self.assertTrue(kwargs["check"] is False, "native verification keeps explicit return-code handling")
                self.assertTrue(type(kwargs["env"]) is dict and kwargs["env"] == {
                    "PATH": os.defpath, "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"},
                    "native verification environment differs from the exact minimal contract")
                self.assertTrue(type(kwargs["input"]) is str, "native verification request must be serialized text")
                supplied = json.loads(kwargs["input"])
                self.assertTrue(type(supplied) is dict and set(supplied) == {"password", "hash"},
                                "native request must contain exactly the two protocol fields")
                self.assertTrue(type(supplied["hash"]) is str and supplied["hash"] == world.kat["YESCRYPT"],
                                "native request must bind the exact independent PUBLIC hash")
                self.assertTrue(type(supplied["password"]) is str
                                and supplied["password"] in (world.kat["PASSWORD"], FACTORY, CURRENT),
                                "native request credential role is outside the exact PUBLIC set")
                worker_calls.append("original-native-verification")
                with mock.patch.object(subprocess, "Popen", _NATIVE_POPEN):
                    return real_run(argv, **kwargs)

            target = world.target(same_subnet=None)
            point = app.DirectEndpoint(IP, None)
            task = app.PreparedIBTask(target, point, "", False)
            args = SimpleNamespace(eth_user="", ib_user="admin", connect_timeout=2, apply=apply,
                yes=True, force=False, run_stamp="20261117-040000", execution_mode="management",
                _on_management_server=True)
            coordinator = app.RuntimeCoordinator(args, policy, FACTORY, [task], app.RuntimeInputAuthority([global_file]))
            coordinator.current_target = target
            current = ("nv set interface eth0 ipv4 address " + IP + "/24\n"
                "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n"
                "nv set interface eth0-1 link state up\nnv set interface eth0-1 type eth\n"
                "nv set system hostname " + target.ib.hostname + "\n"
                "nv set system config auto-save state enabled\nnv set system ztp config-save enabled\n")
            scope = {"inspect_ib_device": 0, "_authenticate_ib_read": 0}
            public_codes = {}
            if public_exact_pair:
                scope["execute_ib_task"] = 0
                scope["verify_management_direct_ssh"] = 0
                public_codes = {getattr(app, name).__code__: name for name in scope}

            def authentication_scope(frame, event, value):
                if frame.f_globals is not app.__dict__:
                    return
                name = (public_codes.get(frame.f_code) if public_exact_pair else frame.f_code.co_name)
                if name not in scope:
                    return
                if event == "call":
                    scope[name] += 1
                    events.append(("auth-boundary", name + ":call"))
                elif event == "return":
                    events.append(("auth-boundary", name + ":return"))
                    scope[name] -= 1

            def ask(hostname):
                self.assertTrue(target.ib.hostname == hostname, "current input must bind the actual PUBLIC target")
                events.append(("ask", "current"))
                return CURRENT

            def interactive(argv, responder, timeout, **options):
                self.assertIs(type(argv), list)
                self.assertTrue(len(argv) >= 3 and argv[0] == "ssh", "direct request must use the fixed SSH executable")
                self.assertTrue(argv[-2] == "admin@" + IP, "direct request endpoint differs from the PUBLIC target")
                self.assertTrue("cumulus@" not in " ".join(argv), "direct request cannot contain an outer account")
                if getattr(responder, "_phase", None) is not None:
                    raise PrerequisiteHold("private phase needs original real PTY carrier; no fabricated finish allowed")
                # Ordinary stages may leave public-key negotiation enabled;
                # that alone does not identify an explicit key-only probe.
                if "-i" in argv:
                    self.assertTrue(argv.count("-i") == 1 and argv.index("-i") + 1 < len(argv),
                                    "key probe must bind exactly one management key path")
                    self.assertTrue(argv[argv.index("-i") + 1] == str(private),
                                    "key probe must use only the own PUBLIC fixture path")
                    key_only = ("BatchMode=yes", "PreferredAuthentications=publickey",
                                "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                                "IdentitiesOnly=yes")
                    self.assertTrue(all(argv.count(option) == 1
                                        and argv.index(option) > 0
                                        and argv[argv.index(option) - 1] == "-o"
                                        for option in key_only)
                                    and "PubkeyAuthentication=no" not in argv,
                                    "explicit key probe must preserve all key-only authentication options")
                    if public_exact_pair:
                        self.assertTrue(getattr(responder, "ib_default_password", None) is None,
                                        "key-only login cannot invent a selected current credential")
                    role = "key"
                else:
                    value = responder.ib_default_password
                    role = ("project" if value == project_value else
                            "factory" if value == FACTORY else "current" if value == CURRENT else None)
                    self.assertIsNotNone(role, "selected credential cannot be confused with OOB/key input")
                remote = shlex.split(argv[-1])
                self.assertTrue(remote[:2] == ["sh", "-c"], "direct remote request must use the closed frame carrier")
                self.assertEqual(3, len(remote))
                nonces = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertEqual(1, len(nonces))
                nonce = nonces[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix))
                self.assertTrue(remote[2].endswith(suffix))
                body = remote[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(body))
                self.assertTrue(body == shlex.join(command), "direct frame contains a noncanonical command vector")
                events.append(("session", role, command))
                if scope["inspect_ib_device"]:
                    events.append(("auth-session", role, command))
                if public_exact_pair:
                    if role == "key":
                        events.append(("key-only", command))
                    if command == ("true",) or scope["verify_management_direct_ssh"]:
                        self.assertNotIn("-i", argv, "password verification cannot be satisfied by a key")
                        for option in ("PubkeyAuthentication=no",
                                       "PreferredAuthentications=password,keyboard-interactive"):
                            self.assertTrue(argv.count(option) == 1 and argv[argv.index(option) - 1] == "-o",
                                            "project true and final readback must really be password-only")
                        events.append(("password-only", role, command))
                    if scope["verify_management_direct_ssh"]:
                        self.assertEqual(tuple(READ), command)
                        events.append(("final-read", role, command))
                rejects = (role == "key" and model.startswith("reject-key")
                    or role == "project" and model == "reject-key-project-factory"
                    or role == "factory" and model == "reject-key-project-factory"
                    or role == "project" and command == ("true",) and model == "key-apply-project-reject")
                if rejects:
                    return app.SessionResult("admin@" + IP + ": Permission denied (password).\n", 255,
                                             ib_authentication_rejected=True)
                if command == tuple(READ):
                    output = current
                elif command == ("ip", "addr", "show", "eth0"):
                    output = ("2: eth0: <UP> mtu 1500 state UP\n    link/ether " + MAC1
                        + " brd ff:ff:ff:ff:ff:ff\n    inet " + IP + "/24 scope global eth0\n")
                elif command == ("ip", "route"):
                    output = "default via 192.0.2.1 dev eth0\n"
                elif command == ("nv", "show", "system", "ztp"):
                    output = "service disabled\nstate disabled\n"
                elif command == ("true",):
                    output = ""
                elif command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its NVUE hostname.
                    output = target.ib.hostname + "\n"
                else:
                    raise RuntimeError("FIXTURE HOLD: direct credential case attempted an unrelated command")
                return app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + output
                    + "__HTTP_IB_END_" + nonce + "__=0\n", 0)

            with ExitStack() as guard:
                guard.enter_context(mock.patch.object(app, "subprocess", new=_Facade(
                    subprocess, run=public_control if public_exact_pair else native, Popen=world.deny)))
                guard.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
                guard.enter_context(mock.patch.object(app, "request_current_ib_password", new=ask))
                guard.enter_context(mock.patch.object(app, "_ACTIVE_COORDINATOR", coordinator))
                if public_exact_pair:
                    guard.enter_context(mock.patch.object(app, "verify_password_hash", new=public_verify))
                    guard.enter_context(mock.patch.object(app, "socket", new=_Facade(
                        socket, socket=world.deny, create_connection=world.deny)))
                    guard.enter_context(mock.patch.object(app, "pty", new=_Facade(app.pty, fork=world.deny)))
                    guard.enter_context(mock.patch.object(app, "os", new=_Facade(os,
                        fork=world.deny, execv=world.deny, execve=world.deny, execvp=world.deny,
                        posix_spawn=world.deny, posix_spawnp=world.deny, system=world.deny,
                        kill=world.deny, killpg=world.deny, waitpid=world.deny)))
                    guard.enter_context(mock.patch.object(app.getpass, "getpass", new=world.deny))
                try:
                    selected = policy.password()
                    self.assertTrue(type(selected) is str and selected == project_value,
                                    "actual same-project target qualification must succeed")
                except app.SetupError:
                    if public_exact_pair:
                        raise  # do not mislabel a real PUBLIC policy failure as native unavailability
                    raise PrerequisiteHold("original PUBLIC native provider unavailable; no behavior RED claimed") from None
                if public_exact_pair:
                    self.assertTrue(any(public_verifications), "the real policy must verify its independent PUBLIC pair")
                    self.assertEqual([], worker_calls)
                    self.assertEqual([], native_attempts)
                else:
                    self.assertTrue(worker_calls)
                # A real verified target is a prerequisite here. MAIN's own
                # upstream prefetch is a separate workflow obligation.
                previous = sys.getprofile()
                try:
                    sys.setprofile(authentication_scope)
                    result = app.execute_ib_task(task, args, policy, FACTORY, None, [], private)
                finally:
                    sys.setprofile(previous)
                self.assertIs(previous, sys.getprofile())
            self.assertIs(type(policy), app.ProjectPasswordPolicy)
            if public_exact_pair:
                policy.assert_unchanged()
                self.assertTrue(global_file.read_bytes() == public_input,
                                "PUBLIC read-only/preconfigured scenarios must not rewrite project input")
                self.assertEqual([], native_attempts)
                for name in ("execute_ib_task", "inspect_ib_device", "_authenticate_ib_read"):
                    self.assertEqual(1, events.count(("auth-boundary", name + ":call")))
                    self.assertEqual(1, events.count(("auth-boundary", name + ":return")))
                if result["outcome"] == "ALREADY_CONFIGURED":
                    for command in (("ip", "addr", "show", "eth0"), ("ip", "route"),
                                    ("nv", "show", "system", "ztp")):
                        self.assertTrue(any(event[0] == "session" and event[2] == command for event in events),
                                        "a successful PUBLIC workflow must really read identity and ZTP")
            self.assertTrue(not any(event[0] == "OOB" for event in events), "direct credential flow cannot ask an OOB account")
            self.assertFalse(task.local)
            self.assertIsNone(task.target.ethernet)
            return result, events

    def test_direct_readonly_key_hit_does_not_add_project_password_authentication(self):
        result, events = self._wp4_direct_credentials(model="key-accept")
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        auth = [event[1] for event in events if event[0] == "session" and event[2] == tuple(READ)]
        self.assertTrue(auth)
        self.assertEqual("key", auth[0])
        self.assertFalse(any(event == ("session", "project", ("true",)) for event in events))

    def test_direct_key_rejection_uses_verified_project_before_factory(self):
        result, events = self._wp4_direct_credentials(model="reject-key")
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        auth = [event[1] for event in events if event[0] == "session" and event[2] == tuple(READ)]
        self.assertEqual(["key", "project"], auth[:2])
        self.assertNotIn("factory", auth)
        self.assertNotIn(("ask", "current"), events)

    def test_direct_exhausted_known_credentials_ask_current_once(self):
        result, events = self._wp4_direct_credentials(model="reject-key-project-factory")
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        selected = [event for event in events if event[0] == "ask" or
                    (event[0] == "session" and event[2] == tuple(READ))]
        self.assertEqual([("session", "key", tuple(READ)), ("session", "project", tuple(READ)),
            ("session", "factory", tuple(READ)), ("ask", "current"),
            ("session", "current", tuple(READ))], selected[:5])
        self.assertEqual(1, events.count(("ask", "current")), "current credential is requested exactly once")

    def test_key_apply_requires_project_password_only_true_and_preserves_final_password_readback(self):
        result, events = self._wp4_direct_credentials(model="key-accept", apply=True)
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        self.assertEqual(1, events.count(("session", "project", ("true",))))
        self.assertEqual("VERIFIED", result["stage_status"]["direct_ssh"])
        auth_reads = [event for event in events if event[0] == "session" and event[2] == tuple(READ)]
        self.assertEqual("key", auth_reads[0][1])
        self.assertEqual("project", auth_reads[-1][1], "final direct NVUE+verify_state stays password-only")

    def test_key_apply_project_rejection_stops_without_asking_current_or_configuration(self):
        result, events = self._wp4_direct_credentials(model="key-apply-project-reject", apply=True)
        self.assertEqual("FAILED", result["outcome"])
        self.assertEqual(1, events.count(("session", "project", ("true",))))
        self.assertNotIn(("ask", "current"), events)
        self.assertFalse(any(event[0] == "session" and event[1] in ("factory", "current") for event in events))
        self.assertEqual("NOT_REACHED", result["stage_status"]["initial"])
        self.assertFalse(any(event[0] == "session" and event[2][:2] in (("nv", "set"), ("sh", "-c"))
                             for event in events))

    def test_direct_complete_authentication_scope_does_not_count_final_readback_as_retry(self):
        result, events = self._wp4_direct_credentials(model="reject-key-project-factory")
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        actual = [(event[1], event[2]) for event in events if event[0] == "auth-session" and event[2] == tuple(READ)]
        self.assertEqual([("key", tuple(READ)), ("project", tuple(READ)),
                          ("factory", tuple(READ)), ("current", tuple(READ))], actual)
        self.assertEqual(1, events.count(("ask", "current")))
        self.assertEqual(1, events.count(("auth-boundary", "inspect_ib_device:call")))
        self.assertEqual(1, events.count(("auth-boundary", "_authenticate_ib_read:call")))
        self.assertEqual(1, events.count(("auth-boundary", "inspect_ib_device:return")))
        self.assertEqual(1, events.count(("auth-boundary", "_authenticate_ib_read:return")))
        all_reads = [event for event in events if event[0] == "session" and event[2] == tuple(READ)]
        self.assertGreater(len(all_reads), len(actual), "the legal stage5 password-only read is outside auth scope")
        self.assertEqual("VERIFIED", result["stage_status"]["direct_ssh"])

    def test_public_direct_readonly_key_hit_uses_key_only_without_password_authentication(self):
        result, events = self._wp4_direct_credentials(model="key-accept", public_exact_pair=True)
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        self.assertIs(result["writes_attempted"], False)
        auth = [event for event in events if event[0] == "auth-session"]
        self.assertEqual([("auth-session", "key", tuple(READ))], auth)
        self.assertNotIn(("ask", "current"), events)
        self.assertFalse(any(event[0] == "session" and event[1] != "key" for event in events),
                         "key-only readonly must not substitute a project/current password for unknown current")
        for command in (("ip", "addr", "show", "eth0"), ("ip", "route"), ("nv", "show", "system", "ztp")):
            self.assertIn(("session", "key", command), events)
            self.assertIn(("key-only", command), events)
        self.assertTrue(result["identity"]["ok"])

    def test_public_direct_key_rejection_uses_verified_project_before_factory(self):
        result, events = self._wp4_direct_credentials(model="reject-key", public_exact_pair=True)
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        self.assertEqual([("auth-session", "key", tuple(READ)), ("auth-session", "project", tuple(READ))],
                         [event for event in events if event[0] == "auth-session"])
        self.assertNotIn(("ask", "current"), events)
        self.assertFalse(any(event[0] == "session" and event[1] in ("factory", "current") for event in events))
        self.assertIs(result["writes_attempted"], False)
        self.assertTrue(result["identity"]["ok"])

    def test_public_direct_exhausted_known_credentials_requests_current_once(self):
        result, events = self._wp4_direct_credentials(model="reject-key-project-factory", public_exact_pair=True)
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        observed = [event for event in events if event[0] == "ask" or event[0] == "auth-session"]
        self.assertEqual([("auth-session", "key", tuple(READ)), ("auth-session", "project", tuple(READ)),
            ("auth-session", "factory", tuple(READ)), ("ask", "current"),
            ("auth-session", "current", tuple(READ))], observed)
        self.assertEqual(1, events.count(("ask", "current")))
        self.assertIn(("final-read", "current", tuple(READ)), events)
        self.assertIn(("password-only", "current", tuple(READ)), events)
        self.assertIs(result["writes_attempted"], False)
        self.assertTrue(result["identity"]["ok"])

    def test_public_key_apply_checks_project_password_only_true_and_final_readback(self):
        result, events = self._wp4_direct_credentials(model="key-accept", apply=True, public_exact_pair=True)
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        self.assertEqual([("auth-session", "key", tuple(READ)), ("auth-session", "project", ("true",))],
                         [event for event in events if event[0] == "auth-session"])
        self.assertEqual(1, events.count(("session", "project", ("true",))))
        self.assertEqual(1, events.count(("password-only", "project", ("true",))))
        self.assertEqual("VERIFIED", result["stage_status"]["direct_ssh"])
        self.assertEqual([("final-read", "project", tuple(READ))],
                         [event for event in events if event[0] == "final-read"])
        self.assertIn(("password-only", "project", tuple(READ)), events)
        self.assertLess(events.index(("session", "key", tuple(READ))),
                        events.index(("session", "project", ("true",))))
        self.assertLess(events.index(("session", "project", ("true",))),
                        events.index(("final-read", "project", tuple(READ))))
        self.assertNotIn(("ask", "current"), events)
        self.assertIs(result["writes_attempted"], False)
        self.assertTrue(result["identity"]["ok"])

    def test_public_key_apply_project_drift_stops_without_current_prompt_or_writes(self):
        result, events = self._wp4_direct_credentials(model="key-apply-project-reject", apply=True,
                                                     public_exact_pair=True)
        self.assertEqual("FAILED", result["outcome"])
        self.assertEqual([("auth-session", "key", tuple(READ)), ("auth-session", "project", ("true",))],
                         [event for event in events if event[0] == "auth-session"])
        self.assertEqual(1, events.count(("session", "project", ("true",))))
        self.assertEqual(1, events.count(("password-only", "project", ("true",))))
        self.assertNotIn(("ask", "current"), events)
        self.assertFalse(any(event[0] == "session" and event[1] in ("factory", "current") for event in events))
        self.assertEqual("NOT_REACHED", result["stage_status"]["initial"])
        self.assertEqual("NOT_REACHED", result["stage_status"]["direct_ssh"])
        self.assertEqual([], [event for event in events if event[0] == "final-read"])
        self.assertIs(result["writes_attempted"], False)
        self.assertFalse(any(event[0] == "session" and event[2][:2] in (("nv", "set"), ("sh", "-c"))
                             for event in events))

    def test_public_direct_auth_scope_excludes_final_password_readback(self):
        result, events = self._wp4_direct_credentials(model="reject-key-project-factory", public_exact_pair=True)
        self.assertEqual("ALREADY_CONFIGURED", result["outcome"])
        self.assertEqual([("auth-session", "key", tuple(READ)), ("auth-session", "project", tuple(READ)),
                         ("auth-session", "factory", tuple(READ)), ("auth-session", "current", tuple(READ))],
                         [event for event in events if event[0] == "auth-session"])
        self.assertEqual(1, events.count(("ask", "current")))
        for name in ("inspect_ib_device", "_authenticate_ib_read"):
            self.assertEqual(1, events.count(("auth-boundary", name + ":call")))
            self.assertEqual(1, events.count(("auth-boundary", name + ":return")))
        self.assertEqual([("final-read", "current", tuple(READ))],
                         [event for event in events if event[0] == "final-read"])
        self.assertGreater(len([event for event in events if event[0] == "session" and event[2] == tuple(READ)]),
                           len([event for event in events if event[0] == "auth-session"]))
        self.assertEqual("VERIFIED", result["stage_status"]["direct_ssh"])

    def _wp4_independent_frame(self, command, marker):
        return ('printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; ' + shlex.join(command)
                + '; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                + '__=%s\\n" "$task_rc"; exit "$task_rc"')

    def _wp4_exact_remote_frame(self, remote, command, marker):
        self.assertIs(type(remote), str)
        words = shlex.split(remote)
        self.assertEqual(["sh", "-c"], words[:2])
        self.assertEqual(3, len(words))
        self.assertEqual(self._wp4_independent_frame(command, marker), words[2],
                         "one exact command frame/nonce/status at the remote boundary")

    def _wp4_jump_constructor_inputs(self):
        app = self._wp4_app
        jump = app.Device("PUBLIC-JUMP01", "eth_jump", "198.51.100.10", "", "", "", "", "")
        return app.Target(self._wp4_device(), jump, "swp7", "eth0"), app.Neighbor("fe80::17", "ib-mgmt", MAC)

    def _wp4_direct_constructor_inputs(self):
        app = self._wp4_app
        if not callable(getattr(app, "DirectEndpoint", None)):
            raise RuntimeError("PREREQUISITE HOLD: direct constructor is not in the fixed producer")
        route = self._wp4_paths.Route(HOST, "direct", "NO_MGMT_LINK", None, None, None)
        return app.Target(self._wp4_device(), None, "", "eth0", route=route), app.DirectEndpoint("203.0.113.2", None)

    def test_direct_builder_preserves_each_complete_script_literal_and_exact_frame(self):
        app = self._wp4_app
        target, endpoint = self._wp4_direct_constructor_inputs()
        marker = "0123456789abcdef0123456789abcdef"
        for name, script in self._wp4_closed_scripts():
            with self.subTest(script=name):
                command = ["sh", "-c", script, "--", "20261117-040000"]
                actual, error = self._wp4_no_external(lambda: app.direct_ssh_command(
                    target, endpoint, "admin", 2, command, marker=marker, password_only=True))
                self.assertIsNone(error, "approved multiline literal must survive the real direct constructor")
                expected = ["ssh", "-4", "-tt", "-o", "ConnectTimeout=2", "-o", "ServerAliveInterval=10",
                    "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                    "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                    "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
                    "-o", "PreferredAuthentications=password,keyboard-interactive", "admin@203.0.113.2",
                    shlex.join(["sh", "-c", self._wp4_independent_frame(command, marker)])]
                self.assertEqual(expected, actual)
                self._wp4_exact_remote_frame(actual[-1], command, marker)

    def test_nested_to_outer_builder_preserves_scripts_and_original_legacy_marker_domain(self):
        app = self._wp4_app
        target, neighbor = self._wp4_jump_constructor_inputs()
        for marker in ("X", "old_marker_9", "Z" * 80):
            for name, script in self._wp4_closed_scripts():
                with self.subTest(marker_length=len(marker), script=name):
                    command = ["sh", "-c", script, "--", "20261117-040000"]
                    actual, error = self._wp4_no_external(lambda: app.nested_ssh_command(
                        target, neighbor, "cumulus", "admin", 2, command, marker=marker, password_only=True))
                    self.assertIsNone(error, "closed scripts must traverse actual nested and outer constructors")
                    inner = ["ip", "vrf", "exec", "default", "ssh", "-6", "-tt", "-o", "ConnectTimeout=2",
                        "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", "-o", "ControlMaster=no",
                        "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
                        "-o", "PreferredAuthentications=password,keyboard-interactive", "-B", "ib-mgmt", "admin@fe80::17",
                        shlex.join(["sh", "-c", self._wp4_independent_frame(command, marker)])]
                    carrier = ("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
                               + shlex.join(inner))
                    expected = ["ssh", "-tt", "-o", "ConnectTimeout=2", "-o", "ServerAliveInterval=10",
                        "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                        "-o", "ControlMaster=no", "-o", "ControlPath=none", "cumulus@198.51.100.10",
                        shlex.join(["sh", "-c", carrier])]
                    self.assertEqual(expected, actual)
                    self._wp4_exact_remote_frame(shlex.split(shlex.split(actual[-1])[2].split("; exec ", 1)[1])[-1], command, marker)

    def test_outer_closed_script_refuses_scoped_destination_with_a_different_bound_interface(self):
        app = self._wp4_app
        target, _neighbor = self._wp4_jump_constructor_inputs()
        command = ["sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", "20261117-040000"]
        # Independently fixed legal inner vector, not an expected vector copied
        # from either a producer builder or the proposed outer admission guard.
        legal = ["ip", "vrf", "exec", "default", "ssh", "-6", "-tt", "-o", "ConnectTimeout=2",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", "-o", "ControlMaster=no",
            "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive", "-B", "ib-mgmt", "admin@fe80::17",
            shlex.join(["sh", "-c", self._wp4_independent_frame(command, "old_marker_9")])]
        _, error = self._wp4_no_external(lambda: app.outer_ssh_command(
            target.ethernet, "cumulus", legal, 2, tty=True))
        self.assertIsNone(error, "the legal closed-script carrier must qualify before its scoped near-miss")
        scoped = list(legal)
        scoped[-2] = "admin@fe80::17%other_if"
        self.assertEqual([len(legal) - 2], [index for index, pair in enumerate(zip(legal, scoped))
                                          if pair[0] != pair[1]])
        self.assertEqual("ib-mgmt", scoped[scoped.index("-B") + 1])
        _, error = self._wp4_no_external(lambda: app.outer_ssh_command(
            target.ethernet, "cumulus", scoped, 2, tty=True))
        self.assertIs(type(error), app.SetupError,
                      "a scoped destination cannot contradict the separately bound nested interface")

    def test_both_builders_refuse_unfrozen_script_and_marker_injection(self):
        app = self._wp4_app
        jump, neighbor = self._wp4_jump_constructor_inputs()
        direct, endpoint = self._wp4_direct_constructor_inputs()
        for name, script in self._wp4_closed_scripts():
            for command in (["sh", "-c", script + "# PUBLIC changed\n", "--", "20261117-040000"],
                            ["sh", "-c", script, "--", "20261117-040000", "extra"],
                            ["sh", "-c", script, "--", "20261117-040000;id"],
                            ["sh", "-c", "printf PUBLIC\nid"],
                            ["sh", "-c", 'printf "__HTTP_IB_BEGIN_A__"; true; printf "__HTTP_IB_END_B__=0"']):
                with self.subTest(script=name, vector_length=len(command)):
                    _, error = self._wp4_no_external(lambda: app.direct_ssh_command(
                        direct, endpoint, "admin", 2, command, marker="a" * 32))
                    self.assertIsInstance(error, app.SetupError)
                    _, error = self._wp4_no_external(lambda: app.nested_ssh_command(
                        jump, neighbor, "cumulus", "admin", 2, command, marker="old_marker_9"))
                    self.assertIsInstance(error, app.SetupError)
        for marker in ("a" * 81, "bad-marker", "A;id", "A\nPUBLIC", "A/__END"):
            with self.subTest(nested_marker=marker):
                _, error = self._wp4_no_external(lambda: app.nested_ssh_command(
                    jump, neighbor, "cumulus", "admin", 2, ["true"], marker=marker))
                self.assertIsInstance(error, app.SetupError)
        for marker in ("X", "old_marker_9", "Z" * 80, "g" * 32, "a" * 31, "a" * 33, "a" * 31 + "\n"):
            with self.subTest(direct_marker=marker):
                _, error = self._wp4_no_external(lambda: app.direct_ssh_command(
                    direct, endpoint, "admin", 2, ["true"], marker=marker))
                self.assertIsInstance(error, app.SetupError)

    def test_independent_frame_oracle_rejects_nonce_status_and_extra_command_models(self):
        command, marker = ["true"], "old_marker_9"
        frame = self._wp4_independent_frame(command, marker)
        self._wp4_exact_remote_frame(shlex.join(["sh", "-c", frame]), command, marker)
        bad = (frame.replace("__HTTP_IB_END_old_marker_9__", "__HTTP_IB_END_other__"),
               frame.replace("__HTTP_IB_BEGIN_old_marker_9__", "__HTTP_IB_BEGIN_other__"),
               frame.replace("; task_rc=$?", "; printf PUBLIC; task_rc=$?"),
               frame.replace('exit "$task_rc"', 'exit 0'))
        for changed in bad:
            with self.subTest(model_length=len(changed)), self.assertRaises(AssertionError):
                self._wp4_exact_remote_frame(shlex.join(["sh", "-c", changed]), command, marker)

    def _assert_wp4_strict_carrier(self, source):
        # Exact carrier originally reviewed at 7149281, with the
        # independently checked test-only PTY custody fence at 1bfb9843.
        # Keep one fixed admitted blob and the single-byte mutation rejection.
        self.assertTrue(hashlib.sha256(source).hexdigest()
            == "87b7d194cd5ffad594dc9d0bebc70e7cad2324384a22d1bb9f32f7709dd0fb55",
            "positive carrier must match the admitted exact workflow source")

    def test_wp4_strict_positive_carrier_rejects_a_same_size_change(self):
        from test_cases import test_initial_setup_direct_transport_workflow as carrier
        source = Path(carrier.__file__).read_bytes()
        self._assert_wp4_strict_carrier(source)
        changed = source[:-1] + bytes((source[-1] ^ 1,))
        self.assertEqual(len(source), len(changed))
        with self.assertRaisesRegex(AssertionError, "admitted exact workflow source"):
            self._assert_wp4_strict_carrier(changed)

    @contextmanager
    def _wp4_strict_positive_world(self):
        # Imports happen only in an independently admitted future test method,
        # before the owned world's native refusals are installed.
        import pty as native_pty
        from test_cases import test_initial_setup_direct_transport_workflow as carrier
        from test_cases.test_initial_setup_direct_transport import _Facade, _NATIVE_POPEN, IP, SCOPED
        from test_cases.test_initial_setup_target_password_policy import required_external_kat, project_global
        native_read, native_close = os.read, os.close
        self._assert_wp4_strict_carrier(Path(carrier.__file__).read_bytes())
        with carrier.ActiveReadWorld(self) as world:
            app = world.app
            world.kat = required_external_kat()
            global_file = world.project / "01-global.yaml"
            global_file.write_text(project_global(world.kat["YESCRYPT"]), encoding="utf-8")
            global_file.chmod(0o600)
            neutral_dir = world.project / "infiniband" / "bringup" / "xdr-initial-setup"
            for directory in (neutral_dir.parent.parent, neutral_dir.parent, neutral_dir):
                directory.mkdir(mode=0o700)
            neutral_file = neutral_dir / "infra-neutral.conf"
            neutral_file.write_text(
                "DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=UTC\n", encoding="utf-8")
            neutral_file.chmod(0o600)
            world.wp4_global, world.wp4_attempts, world.wp4_ordinary = global_file, [], []
            world.wp4_inputs, world.wp4_external_errors = [], []
            world.wp4_expected_current = world.kat["PASSWORD"]
            world.wp4_body = ("nv set system hostname example-ib01\n"
                "nv set interface eth0 ipv4 address 192.0.2.10/24\n"
                "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
                "nv set interface eth0-1 link state up\nnv set interface eth0-1 type eth\n"
                "nv set system config auto-save state enabled\nnv set system ztp config-save enabled\n"
                "nv set system dns server 192.0.2.53\nnv set system ntp server 192.0.2.123\n"
                "nv set system date-time timezone UTC\n")
            native_command = [sys.executable, "-I", "-S", "-B", str(INITIAL.resolve()), "--_verify-password"]
            real_run = subprocess.run
            world.wp4_native_calls = []

            def native(argv, **kwargs):
                if argv != native_command:
                    if argv in (["ip", "-4", "neigh", "show", IP], ["ping", "-c", "1", "-W", "1", IP]):
                        return world.control(argv, **kwargs)
                    raise RuntimeError("PREREQUISITE HOLD: unreviewed native boundary, no request data emitted")
                self.assertTrue(set(kwargs) == {"input", "text", "capture_output", "timeout", "check", "env"},
                                "native keyword schema must remain exact")
                self.assertTrue(type(kwargs["timeout"]) is int and kwargs["timeout"] == 8, "original native8s budget")
                self.assertTrue(kwargs["text"] is True and kwargs["capture_output"] is True and kwargs["check"] is False,
                                "original explicit native protocol flags")
                self.assertTrue(kwargs["env"] == {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
                    "PYTHONDONTWRITEBYTECODE": "1"}, "original minimal native environment")
                self.assertTrue(type(kwargs["input"]) is str, "native request must be serialized text")
                value = json.loads(kwargs["input"])
                self.assertTrue(type(value) is dict and set(value) == {"password", "hash"}, "native request schema")
                self.assertTrue(value["hash"] == world.kat["YESCRYPT"], "exact independent native hash binding")
                self.assertTrue(value["password"] in (world.kat["PASSWORD"], FACTORY, CURRENT), "exact PUBLIC native credential set")
                world.wp4_native_calls.append("original-native-worker")
                with mock.patch.object(subprocess, "Popen", _NATIVE_POPEN):
                    return real_run(argv, **kwargs)

            active = None

            def fork():
                pair = active["custody"].fork()
                if pair[0] > 0:
                    active["children"].add(pair[0]); active["fds"].add(pair[1])
                return pair

            def execute(name, argv):
                if active is None or name != "sh" or argv != active["argv"]:
                    os._exit(87)  # only the just-created child reaches this boundary
                carrier._REAL_EXECVE(sys.executable,
                    [sys.executable, "-I", "-S", "-B", str(active["peer"]), str(active["config"])],
                    {"PATH": os.defpath, "HOME": str(world.home), "LC_ALL": "C", "LANG": "C",
                     "PYTHONDONTWRITEBYTECODE": "1"})

            def read(fd, size):
                return native_read(fd, size)  # real reads, including real bound policy FD reads

            def write(fd, raw):
                amount = carrier._REAL_WRITE(fd, raw)
                if active is not None and fd in active["fds"]:
                    active["writes"].append((bytes(raw) == world.kat["PASSWORD"].encode() + b"\n", amount))
                return amount

            def close(fd):
                native_close(fd)
                if active is not None and fd in active["fds"]:
                    active["real_close"] = True

            def wait(pid, flags):
                self.assertTrue(active is not None and pid in active["children"], "wait only for this new owned child")
                result = active["custody"].wait(pid, flags)
                if result[0]:
                    active["reaps"].append(result)
                return result

            def kill(pid, sig):
                self.assertTrue(active is not None and pid in active["children"], "signal only this new owned child")
                return active["custody"].send(pid, sig, group=False)

            def killpg(pid, sig):
                self.assertTrue(active is not None and pid in active["children"], "signal only this new owned group")
                return active["custody"].send(pid, sig, group=True)

            def interactive(argv, responder, timeout, **options):
                nonlocal active
                phase = getattr(responder, "_phase", None)
                if phase is not None:
                    self.assertTrue(type(responder) is app.NestedResponder and type(phase) is app._IBPhase,
                                    "real original private phase types required")
                    self.assertTrue(phase.operation == "auth-probe-readonly", "positive carrier is auth readonly only")
                    binding_failed = False
                    try:
                        carrier.assert_phase_argv_binding(self, argv, nonce=phase.nonce,
                            operation="auth-probe-readonly", endpoint="admin@" + SCOPED)
                    except AssertionError:
                        binding_failed = True
                    if binding_failed:
                        # Same exact independent checks, but a malformed argv
                        # cannot escape through the borrowed helper's repr.
                        raise AssertionError("exact independent management/remote phase binding failed") from None
                    self.assertTrue(phase.endpoint == "admin@" + SCOPED and phase.outer_endpoint == ""
                                    and responder.ethernet_password == "", "one real direct endpoint, no fake OOB")
                    directory = world.root / ("wp4-strict-phase-" + str(len(world.wp4_attempts)))
                    directory.mkdir(mode=0o700)
                    peer, config = directory / "peer.py", directory / "config.json"
                    peer.write_text(carrier.ACTIVE_READ_PEER, encoding="utf-8"); peer.chmod(0o600)
                    config.write_text(json.dumps({"nonce": phase.nonce, "endpoint": "admin@" + SCOPED,
                        "diagnostic": "", "parts": None, "truncated_tail": False,
                        "current": world.kat["PASSWORD"], "body": world.wp4_body}), encoding="utf-8")
                    config.chmod(0o600)
                    active = {"argv": list(argv), "peer": peer, "config": config, "directory": directory,
                              "children": set(), "fds": set(), "reaps": [], "writes": [],
                              "custody": carrier._PtySignalCustody(),
                              "real_close": False, "closed": False, "returned": False}
                    slot = active
                    world.wp4_attempts.append(slot)
                    try:
                        result = world._original_interactive(argv, responder, timeout, **options)
                        slot["returned"] = True
                        return result
                    finally:
                        slot["closed"] = True
                        active = None  # no assertions/signals/reaps that mask the primary error
                self.assertTrue(type(argv) is list and len(argv) >= 3 and argv[0] == "ssh", "ordinary direct vector")
                self.assertTrue(argv[-2] in ("admin@" + IP, "admin@" + SCOPED), "ordinary exact PUBLIC endpoint")
                expected_type = app.NestedResponder if "ConnectionAttempts=1" in argv else app._DirectResponder
                self.assertTrue(type(responder) is expected_type, "exact ordinary/final direct responder")
                self.assertTrue(responder.ib_default_password == world.wp4_expected_current, "selected current, not permission target")
                remote = shlex.split(argv[-1])
                self.assertTrue(len(remote) == 3 and remote[:2] == ["sh", "-c"], "ordinary direct remote frame")
                nonces = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertTrue(len(nonces) == 1, "one actual command nonce")
                nonce = nonces[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix) and remote[2].endswith(suffix), "exact ordinary frame binding")
                body = remote[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(body))
                self.assertTrue(body == shlex.join(command), "canonical ordinary command")
                world.wp4_ordinary.append(command)
                if command == tuple(READ): output = world.wp4_body
                elif command == ("ip", "addr", "show", "eth0"):
                    output = ("2: eth0: <UP> mtu 1500 state UP\n    link/ether 02:00:00:00:00:10\n"
                              "    inet 192.0.2.10/24 scope global eth0\n")
                elif command == ("ip", "route"): output = "default via 192.0.2.1 dev eth0\n"
                elif command == ("nv", "show", "system", "ztp"): output = "service disabled\nstate disabled\n"
                elif command == ("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", "20261117-040000"):
                    output = "path=/home/PUBLIC/current_20261117-040000.yaml\nbytes=137\n"
                elif command == ("true",): output = ""
                elif command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its NVUE hostname.
                    output = [line.split()[-1] for line in world.wp4_body.splitlines()
                              if line.startswith("nv set system hostname ")][-1] + "\n"
                else: raise RuntimeError("FIXTURE HOLD: unrelated strict positive command")
                return app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + output
                    + "__HTTP_IB_END_" + nonce + "__=0\n", 0)

            def observed_external(*args, **kwargs):
                try:
                    return interactive(*args, **kwargs)
                except BaseException as error:
                    world.wp4_external_errors.append(error)
                    raise

            def target_input(*_args, **_kwargs):
                world.wp4_inputs.append("synthetic-target-input")
                return world.kat["PASSWORD"]

            with mock.patch.object(app, "subprocess", new=_Facade(subprocess, run=native, Popen=world.deny)), \
                 mock.patch.object(app, "pty", new=_Facade(native_pty, fork=fork)), \
                 mock.patch.object(app, "os", new=_Facade(os, execvp=execute, read=read, write=write,
                     close=close, waitpid=wait, kill=kill, killpg=killpg)), \
                 mock.patch.object(app, "interactive_run", new=observed_external), \
                 mock.patch.object(app.getpass, "getpass", new=target_input):
                try:
                    self.assertTrue(app.verify_password_hash(world.kat["PASSWORD"], world.kat["YESCRYPT"]),
                                    "independent PUBLIC native pair must really verify")
                except app.SetupError:
                    raise RuntimeError("PREREQUISITE HOLD: original native provider unavailable") from None
                yield world

    def test_global_readonly_main_qualifies_project_before_ib_and_completes_real_strict_phase_summary(self):
        from contextlib import redirect_stdout, redirect_stderr
        from test_cases.test_initial_setup_direct_transport import HEADER, IB1, MAC1, IP
        with self._wp4_strict_positive_world() as world:
            app = world.app
            row = [IB1, "ib", IP, "24", "192.0.2.1", MAC1]
            for path in (world.csv, world.master):
                with path.open("w", newline="") as stream:
                    writer = csv.writer(stream)
                    writer.writerow(HEADER); writer.writerow(row + [""] * (len(HEADER) - len(row)))
            world.p2p.write_text("a-node,a-port,z-node,z-port\nexample-unselected-ib99,eth0,example-unselected-leaf99,swp7\n",
                                 encoding="utf-8")
            observed = {"order": [], "modules": {}, "batch": None}
            required = {"tools.device_identity": "main", "tools.hostname_ranges": "main",
                        "tools.login_path": "main", "tools.inventory_subset": "_compare_inventory"}

            def profile(frame, event, value):
                if frame.f_globals is not app.__dict__:
                    return
                name = frame.f_code.co_name
                if event == "return" and name == "password":
                    policy = frame.f_locals.get("self")
                    if (type(policy) in (app.ProjectPasswordPolicy, app.WorkerPasswordPolicy)
                            and policy.path == world.wp4_global and type(value) is str
                            and value == world.kat["PASSWORD"]):
                        observed["order"].append("verified-project-return")
                elif event == "call" and name == "run_prepared_tasks":
                    observed["order"].append("IB-dispatch")
                    args, policy = frame.f_locals["args"], frame.f_locals["policy"]
                    world.expected_device_prefix = "devices-" + args.run_stamp + "-"
                    observed["prefetched"] = (type(policy) is app.ProjectPasswordPolicy
                        and policy._password == world.kat["PASSWORD"] and len(world.wp4_inputs) == 2)
                    observed["strict_cache"] = args._strict_cache
                    observed["policy"] = policy
                    observed["tasks"] = tuple(frame.f_locals["tasks"])
                    observed["authority"] = frame.f_locals["authority"]
                elif event == "call" and name == "execute_ib_task":
                    observed["order"].append("actual-execute")
                elif event == "return" and name == "run_prepared_tasks":
                    observed["batch"] = value
                elif event == "return" and name == "_import_tools":
                    requested, caller = frame.f_locals.get("name"), frame.f_back
                    if (requested in required and caller is not None and caller.f_globals is app.__dict__
                            and caller.f_code.co_name == required[requested]):
                        observed["modules"].setdefault(requested, []).append(value)

            output, previous = io.StringIO(), sys.getprofile()
            argv = [str(INITIAL), "--project-dir", str(world.project), "--ib-csv", str(world.csv),
                "--p2p", str(world.p2p), "--report", str(world.root / "report.log"),
                "--target-cache", str(world.root / "targets.json"), "--snapshot-dir", str(world.root / "snapshots"),
                "--execution-mode", "management", "--max-workers", "1", "--connect-timeout", "2"]
            try:
                with mock.patch.object(sys, "argv", argv), redirect_stdout(output), redirect_stderr(output):
                    sys.setprofile(profile)
                    code = app._standalone_main_with_report_cleanup()
            finally:
                sys.setprofile(previous)
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close(); app.REPORT_HANDLE = None
            if world.wp4_external_errors:
                raise world.wp4_external_errors[0]
            if type(observed["batch"]) is not dict:
                safe_code = code if type(code) is int and 0 <= code <= 255 else "unknown"
                raise RuntimeError("PREREQUISITE HOLD: global MAIN did not complete its actual worker pipeline; "
                                   "pre-dispatch-qualification return_code=" + str(safe_code))
            if any(record.get("script_error") for record in observed["batch"]["records"].values()):
                raise RuntimeError("SOURCE/ADAPTER ERROR: global worker program error is not business RED")
            self.assertTrue(observed.get("prefetched") is True, "MAIN must really qualify project target before first IB")
            self.assertTrue("verified-project-return" in observed["order"], "actual project verification return is required")
            self.assertTrue(observed["order"].index("verified-project-return") < observed["order"].index("IB-dispatch"),
                            "project prefetch must precede actual dispatch, not occur lazily after rejection")
            self.assertTrue(observed["strict_cache"] is not None, "real management global must retain strict cache authority")
            self.assertTrue({world.csv.absolute(), world.p2p.absolute(), world.wp4_global.absolute(), INITIAL.absolute()}
                <= {entry[0] for entry in observed["authority"].entries}, "real input authority must bind all actual inputs")
            self.assertEqual(set(required), set(observed["modules"]))
            for name, values in observed["modules"].items():
                self.assertEqual(1, len(values))
                self.assertIs(values[0], sys.modules[name])
                self.assertEqual((ROOT / "tools" / (name.split(".")[1] + ".py")).resolve(), Path(values[0].__file__).resolve())
            self.assertTrue(code == 0, "complete global readonly MAIN must reach successful final summary")
            self.assertTrue(len(observed["tasks"]) == 1 and observed["tasks"][0].target.ethernet is None
                            and observed["tasks"][0].local is False, "real direct task, not fake Jump/local")
            self._wp4_assert_real_phase_cleanup(world)
            summary_path = Path(observed["batch"]["log_dir"]) / "summary.json"
            self.assertEqual(world.root, summary_path.parent.parent)
            summary = json.loads(summary_path.read_text())
            self.assertTrue(summary["result"] == "SUCCESS" and summary["records"][IB1]["outcome"] == "ALREADY_CONFIGURED",
                            "actual worker and final summary, not a prefix checkpoint")
            self.assertTrue(summary["source_sha256"] == hashlib.sha256(INITIAL.read_bytes()).hexdigest(),
                            "summary must bind the actually running source")
            rendered = summary_path.read_text() + (world.root / "report.log").read_text() + output.getvalue()
            self.assertTrue(all(value not in rendered for value in
                (world.kat["PASSWORD"], world.kat["YESCRYPT"], world.kat["SHA512"])), "no KAT value in result/report output")
            self.assertIs(previous, sys.getprofile())
            self.assertIsNone(app._ACTIVE_COORDINATOR)
            self.assertIsNone(app._TASK_DEADLINE)
            self.assertIsNone(app._TASK_LOG_BUFFER)

    def test_strict_direct_backup_command_uses_real_project_and_selected_current(self):
        with self._wp4_strict_positive_world() as world:
            app = world.app
            policy = app.ProjectPasswordPolicy(world.wp4_global, "admin",
                target_password=world.kat["PASSWORD"], interactive=False)
            world.wp4_expected_current = CURRENT
            target = world.target(same_subnet=None)
            point = app.DirectEndpoint(target.ib.login_ip, None)
            task = app.PreparedIBTask(target, point, "", False)
            args = SimpleNamespace(apply=True, yes=True)
            coordinator = app.RuntimeCoordinator(args, policy, FACTORY, [task], app.RuntimeInputAuthority([world.wp4_global]))
            coordinator.current_target = target
            error = result = None
            with mock.patch.object(app, "_ACTIVE_COORDINATOR", coordinator):
                try:
                    result = app._run_authorized_ib_direct_command(target, point, "", "", "admin", CURRENT, 2,
                        ["sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", "20261117-040000"], local=False, _password_policy=policy)
                except app.SetupError as caught:
                    error = caught
            if world.wp4_external_errors:
                raise world.wp4_external_errors[0]
            self.assertIsNone(error, "real same-project closed backup command must qualify through the direct strict core")
            self.assertTrue(type(policy) is app.ProjectPasswordPolicy and policy._password == world.kat["PASSWORD"],
                            "actual project permission remains verified and separate from selected current")
            self.assertTrue(type(result) is app.SessionResult and result.exit_code == 0, "actual qualified strict result")
            self.assertEqual("path=/home/PUBLIC/current_20261117-040000.yaml\nbytes=137\n", result.output)
            self.assertEqual([("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", "20261117-040000")], world.wp4_ordinary)
            self.assertTrue(coordinator.writes_attempted, "original coordinator must actually authorize the backup effect")

    def _wp4_assert_real_phase_cleanup(self, world):
        self.assertTrue(bool(world.wp4_attempts), "qualified strict workflow must create a real phase child")
        for slot in world.wp4_attempts:
            self.assertTrue(slot["closed"], "original interactive must return through its finally")
            self.assertTrue(len(slot["children"]) == 1 and len(slot["reaps"]) == 1,
                            "exactly one actual child and one actual product reap")
            self.assertTrue(set(slot["children"]) == {entry[0] for entry in slot["reaps"]},
                            "actual reap belongs to the newly created child")
            self.assertTrue(slot["real_close"], "actual product master close must occur")
            for fd in slot["fds"]:
                try:
                    os.fstat(fd)
                except OSError as error:
                    self.assertTrue(error.errno == 9, "only EBADF proves actual owned master closure")
                else:
                    self.fail("original interactive left its owned master open")
            path = slot["directory"] / "events.jsonl"
            events = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
            self.assertTrue(not any(event["kind"] == "adapter-error" for event in events), "PUBLIC peer qualification failed")
            inputs = [event for event in events if event["kind"] == "current-input"]
            self.assertTrue(len(inputs) == 1 and inputs[0]["complete"] is True and inputs[0]["correct"] is True,
                            "one actual complete independently expected current input must reach the PUBLIC child")

    def test_password_change_flag_cannot_relabel_nvue_writes_on_either_transport(self):
        """O5/O13: the authentication flag cannot lend write/backup authority."""
        app = self._wp4_app
        device = self._wp4_device()
        jump = app.Device("PUBLIC-JUMP01", "eth_jump", "198.51.100.10", "", "", "", "", "")
        commands = (["nv", "set", "system", "hostname", HOST],
                    ["nv", "config", "apply", "-y"], ["nv", "config", "save"])

        class ProhibitedBoundaryReached(Exception):
            pass

        for direct in (False, True):
            route = (self._wp4_paths.Route(HOST, "direct", "NO_MGMT_LINK", None, None, None)
                     if direct else None)
            target = app.Target(device, None if direct else jump, "" if direct else "swp7", "eth0", route=route)
            endpoint = (app.DirectEndpoint("203.0.113.2") if direct
                        else app.Neighbor("fe80::17", "ib-mgmt", MAC))
            if direct:
                admitted, error = self._wp4_no_external(lambda: app._validate_direct_endpoint(target, endpoint))
                self.assertIsNone(error, "the direct scope must already satisfy its independent input contract")
                self.assertIsNone(admitted)
            for command in commands:
                with self.subTest(direct=direct, command=command):
                    # Independent, valid commands: rejection must concern their
                    # incompatible flag, not a malformed argv hiding the branch.
                    self.assertEqual(command, app.ib_command_argv(command))
                    effects = []
                    def permit(category="nvue"):
                        effects.append(("permit", category))
                        raise ProhibitedBoundaryReached()
                    def interactive(*_args, **_kwargs):
                        effects.append(("interactive",))
                        raise ProhibitedBoundaryReached()
                    caught, refusal = None, None
                    with mock.patch.object(app, "obtain_write_permit", new=permit), \
                         mock.patch.object(app, "interactive_run", new=interactive):
                        try:
                            _result, refusal = self._wp4_no_external(lambda: app.run_on_ib(
                                target, endpoint, "" if direct else "cumulus",
                                "" if direct else "PUBLIC-Outer-Only", "admin", FACTORY, 5,
                                list(command), allow_password_change=True))
                        except ProhibitedBoundaryReached as error:
                            caught = error
                    self.assertEqual([], effects, "incompatible authentication/write scope must stop before any permit or PTY")
                    self.assertIsNone(caught)
                    self.assertIs(type(refusal), app.SetupError,
                                  "an incompatible scope must be explicitly refused, not silently accepted")

    def test_ipv4_identity_never_treats_an_unresolved_default_as_no_default(self):
        """O5/O19: default-dev or unreadable default facts are not absence."""
        app = self._wp4_app
        target = app.Target(self._wp4_device(), None, "", "eth0")
        for routes in ("default dev eth0 scope link\n", "default proto dhcp\n",
                       "default via\n", "default dev eth0\ndefault via 203.0.113.1 dev eth0\n",
                       "blackhole default\n", "unreachable default\n"):
            with self.subTest(routes=routes):
                result, error = self._wp4_no_external(lambda: app._check_ib_identity(
                    target, IP_ADDR, routes, via_ipv4=True))
                self.assertTrue(error is not None or (type(result) is dict and result.get("ok") is False),
                                "an existing unresolved default must not produce verified identity")

    def test_ipv4_identity_preserves_genuine_no_default_and_expected_via(self):
        app = self._wp4_app
        target = app.Target(self._wp4_device(), None, "", "eth0")
        for routes in ("", "203.0.113.0/24 dev eth0 proto kernel scope link\n",
                       "203.0.113.0/24 dev default proto kernel scope link\n",
                       "default via 203.0.113.1 dev eth0 proto dhcp metric 100\n"):
            with self.subTest(routes=routes):
                result, error = self._wp4_no_external(lambda: app._check_ib_identity(
                    target, IP_ADDR, routes, via_ipv4=True))
                self.assertIsNone(error)
                self.assertIs(True, result["ok"])

    def test_authentication_read_with_password_change_flag_preserves_both_raw_transports(self):
        """The ordinary auth READ may reach password permission, never NVUE/backup."""
        app = self._wp4_app
        public_body = "nv set system hostname PUBLIC-IB01\nnv set service lldp state enabled\n"
        options = ["-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=10",
                   "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new",
                   "-o", "LogLevel=ERROR"]
        self.assertEqual(["nv", "config", "show", "-o", "commands"], READ)
        for direct in (False, True):
            with self.subTest(direct=direct):
                jump = app.Device("PUBLIC-JUMP01", "eth_jump", "198.51.100.10", "", "", "", "", "")
                route = (self._wp4_paths.Route(HOST, "direct", "NO_MGMT_LINK", None, None, None)
                         if direct else None)
                target = app.Target(self._wp4_device(), None if direct else jump,
                                    "" if direct else "swp7", "eth0", route=route)
                endpoint = (app.DirectEndpoint("203.0.113.2") if direct
                            else app.Neighbor("fe80::17", "ib-mgmt", MAC))
                if direct:
                    admitted, error = self._wp4_no_external(lambda: app._validate_direct_endpoint(target, endpoint))
                    self.assertIsNone(error, "independently qualified direct input")
                    self.assertIsNone(admitted)
                events, responses = [], []

                def permit(category="nvue"):
                    events.append(("permit", category))

                def backup(*_args, **_kwargs):
                    events.append(("backup",))
                    raise AssertionError("authentication READ must not create a configuration backup")

                def interactive(argv, responder, timeout):
                    self.assertIs(type(argv), list)
                    self.assertTrue(all(type(word) is str for word in argv))
                    self.assertEqual(60, timeout)
                    self.assertIs(type(responder), app._DirectResponder if direct else app.NestedResponder)
                    self.assertIsNone(responder._phase, "ordinary auth READ is not a private phase")
                    self.assertIs(responder.allow_password_change, True)
                    self.assertEqual(FACTORY, responder.ib_default_password)
                    self.assertIsNone(responder.ib_new_password)
                    self.assertFalse(responder.password_change_attempted)
                    self.assertFalse(responder.password_change_blocked)
                    if direct:
                        destination = "admin@203.0.113.2"
                        prefix = ["ssh", "-4", "-tt", *options, "-o", "ProxyCommand=none",
                            "-o", "ProxyJump=none", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                            "-o", "NumberOfPasswordPrompts=1", destination]
                        self.assertEqual(prefix, argv[:-1])
                        self.assertEqual("", responder.ethernet_password)
                        framed_word = argv[-1]
                    else:
                        destination = "admin@fe80::17"
                        prefix = ["ssh", "-tt", *options, "-o", "ControlMaster=no",
                                  "-o", "ControlPath=none", "cumulus@198.51.100.10"]
                        self.assertEqual(prefix, argv[:-1])
                        self.assertEqual("PUBLIC-Outer-Only", responder.ethernet_password)
                        wrapper = shlex.split(argv[-1])
                        self.assertEqual(3, len(wrapper))
                        self.assertEqual(["sh", "-c"], wrapper[:2])
                        safe = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
                        self.assertTrue(wrapper[2].startswith(safe))
                        nested = shlex.split(wrapper[2][len(safe):])
                        expected = ["ip", "vrf", "exec", "default", "ssh", "-6", "-tt",
                            "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                            "-o", "ControlMaster=no", "-o", "ControlPath=none",
                            "-o", "NumberOfPasswordPrompts=1", "-B", "ib-mgmt", destination]
                        self.assertEqual(expected, nested[:-1])
                        framed_word = nested[-1]
                    self.assertEqual(destination, responder.ib_destination)
                    framed = shlex.split(framed_word)
                    self.assertEqual(3, len(framed))
                    self.assertEqual(["sh", "-c"], framed[:2])
                    match = re.fullmatch(
                        r'printf "\\n__HTTP_IB_BEGIN_([0-9a-f]{32})__\\n"; '
                        r'nv config show -o commands; task_rc=\$\?; printf "\\n__HTTP_IB_END_\1__=%s\\n" "\$task_rc"; exit "\$task_rc"',
                        framed[2])
                    self.assertIsNotNone(match, "only the complete independent READ frame is modelled")
                    nonce = match.group(1)
                    response = app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + public_body
                        + "__HTTP_IB_END_" + nonce + "__=0\n", 0)
                    responses.append(response)
                    events.append(("interactive",))
                    return response

                with mock.patch.object(app, "obtain_write_permit", new=permit), \
                     mock.patch.object(app, "_ensure_ib_config_backup", new=backup), \
                     mock.patch.object(app, "interactive_run", new=interactive):
                    result, error = self._wp4_no_external(lambda: app.run_on_ib(
                        target, endpoint, "" if direct else "cumulus",
                        "" if direct else "PUBLIC-Outer-Only", "admin", FACTORY, 5,
                        list(READ), allow_password_change=True))
                self.assertIsNone(error, "the original legal auth READ must not be rejected with NVUE writes")
                self.assertEqual([("permit", "password"), ("interactive",)], events)
                self.assertEqual(1, len(responses))
                self.assertIs(result, responses[0], "retain the actual raw transport SessionResult")
                self.assertIs(type(result), app.SessionResult)
                self.assertEqual(0, result.exit_code)
                self.assertEqual(public_body, result.output)
                self.assertFalse(result.password_changed)
                self.assertFalse(result.password_change_attempted)

    def _wp4_strict_timeout_readiness(self, fault):
        """Real policy/core/direct/readiness; only PUBLIC crypto/IO boundaries.

        No private policy authority or timeout fact is synthesized. The clean
        exception is the original interactive timeout shape; the real strict
        core must retain sufficient qualified facts for the real probe.
        """
        from test_cases.test_initial_setup_cable_check import _Facade
        import time as real_time

        app = self._wp4_app
        project_value = "-".join(("PUBLIC", "strict", "target", "Zq7"))
        public_hash = "$" + "6$PUBLICsalt$" + "A" * 86
        project = Path(tempfile.mkdtemp(prefix="strict-timeout-project-", dir=self._wp4_home))
        self.assertEqual(self._wp4_home, project.parent)
        self.assertEqual(project, project.resolve())
        self.assertTrue(project.lstat().st_uid == os.geteuid()
                        and stat.S_IMODE(project.lstat().st_mode) == 0o700)
        global_file = project / "01-global.yaml"
        global_file.write_text(
            'schema_version: 2\nswitches:\n- ib:\n    system:\n'
            '      aaa:\n        user:\n          admin:\n            password: "'
            + public_hash + '"\n', encoding="utf-8")
        global_file.chmod(0o600)
        original_bytes = global_file.read_bytes()
        self.assertEqual(global_file, global_file.resolve())
        self.assertEqual(0o600, stat.S_IMODE(global_file.lstat().st_mode))
        route = self._wp4_paths.Route(HOST, "direct", "NO_MGMT_LINK", None, None, None)
        target = app.Target(self._wp4_device(), None, "", "eth0", route=route)
        point = app.DirectEndpoint("203.0.113.2", None)
        calls, delays, effects, verified = [], [], [], []
        details, clock = {}, [0.0]
        real_open = os.open

        def forbidden(*_args, **_kwargs):
            effects.append("forbidden-external")
            raise RuntimeError("FIXTURE HOLD: strict timeout case attempted an unmodelled external effect")

        def own_policy_open(path, flags, *args, **kwargs):
            self.assertEqual((), args)
            self.assertEqual({}, kwargs)
            self.assertEqual(global_file, Path(path).resolve())
            self.assertEqual(os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, flags)
            return real_open(path, flags)

        def verify_pair(value, digest):
            self.assertTrue(type(value) is str and value == project_value,
                            "the actual policy must verify the independent PUBLIC target, not selected current")
            self.assertTrue(type(digest) is str and digest == public_hash,
                            "the actual policy must consume the owned PUBLIC hash shape")
            verified.append("actual-policy-match")
            return True

        def sleep(delay):
            self.assertGreaterEqual(delay, 0)
            delays.append(delay)
            clock[0] += delay

        def interactive(argv, responder, timeout, **options):
            self.assertEqual({}, options)
            self.assertIs(type(argv), list)
            self.assertEqual(["ssh", "-4", "-tt", "-o", "ConnectTimeout=5",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
                "-o", "ControlMaster=no", "-o", "ControlPath=none",
                "-o", "NumberOfPasswordPrompts=1", "admin@203.0.113.2"], argv[:-1])
            self.assertEqual(60, timeout)
            self.assertIs(type(responder), app._DirectResponder)
            self.assertIsNone(responder._phase)
            self.assertTrue(responder.ib_default_password == CURRENT,
                            "selected current must remain separate from verified target permission")
            self.assertEqual("", responder.ethernet_password)
            self.assertIs(responder.allow_password_change, False)
            self.assertIsNone(responder.ib_new_password)
            self.assertEqual("admin@203.0.113.2", responder.ib_destination)
            framed = shlex.split(argv[-1])
            self.assertEqual(3, len(framed))
            self.assertEqual(["sh", "-c"], framed[:2])
            match = re.fullmatch(
                r'printf "\\n__HTTP_IB_BEGIN_([0-9a-f]{32})__\\n"; '
                r'(ip addr show eth0|ip route|nv config show -o commands); task_rc=\$\?; '
                r'printf "\\n__HTTP_IB_END_\1__=%s\\n" "\$task_rc"; exit "\$task_rc"', framed[2])
            self.assertIsNotNone(match, "only the independent exact fresh-read frames are modelled")
            command = tuple(shlex.split(match.group(2)))
            calls.append(command)
            if len(calls) == 1:
                self.assertEqual(("ip", "addr", "show", "eth0"), command)
                if fault in ("clean-timeout", "uncertain-timeout"):
                    error = app.SetupError("SSH/PAM session timed out; device state may be unknown")
                    if fault == "uncertain-timeout":
                        error.cleanup_uncertain = True
                    raise error
                if fault == "authentication":
                    return app.SessionResult("admin@203.0.113.2: Permission denied (password).\n", 255,
                                             ib_authentication_rejected=True)
                if fault == "unknown":
                    return app.SessionResult("PUBLIC unclassified remote failure\n", 255)
            # A wrong retry in any negative model succeeds here; it cannot be
            # hidden by repeatedly returning the same fatal adapter result.
            if command == ("ip", "addr", "show", "eth0"):
                body = IP_ADDR
            elif command == ("ip", "route"):
                body = "default via 203.0.113.1 dev eth0\n"
            else:
                body = READY + ADDRESS0 + GATEWAY0
            nonce = match.group(1)
            return app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + body
                + "__HTTP_IB_END_" + nonce + "__=0\n", 0)

        output = error = None
        with ExitStack() as guard:
            guard.enter_context(mock.patch.object(app, "verify_password_hash", new=verify_pair))
            guard.enter_context(mock.patch.object(app, "subprocess", new=_Facade(
                subprocess, run=forbidden, Popen=forbidden)))
            guard.enter_context(mock.patch.object(app, "socket", new=_Facade(
                socket, socket=forbidden, create_connection=forbidden)))
            guard.enter_context(mock.patch.object(app, "os", new=_Facade(os, open=own_policy_open,
                fork=forbidden, execv=forbidden, execve=forbidden, execvp=forbidden,
                posix_spawn=forbidden, posix_spawnp=forbidden, system=forbidden,
                kill=forbidden, killpg=forbidden, waitpid=forbidden)))
            guard.enter_context(mock.patch.object(app, "pty", new=_Facade(app.pty, fork=forbidden)))
            guard.enter_context(mock.patch.object(app.getpass, "getpass", new=forbidden))
            guard.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
            guard.enter_context(mock.patch.object(app, "time", new=_Facade(
                real_time, sleep=sleep, monotonic=lambda: clock[0])))
            guard.enter_context(mock.patch.object(app, "log", new=lambda *_a, **_k: None))
            policy = app.ProjectPasswordPolicy(global_file, "admin", target_password=project_value, interactive=False)
            selected = policy.password()
            self.assertTrue(selected == project_value and policy._password == project_value,
                            "original policy must really cache its independently supplied PUBLIC target")
            self.assertTrue(verified, "original policy must reach actual matches and the fixed external pair boundary")
            app._validate_direct_endpoint(target, point)
            if fault == "changed-source":
                global_file.write_bytes(original_bytes + b"# PUBLIC changed source after verification\n")
            try:
                output = app._wait_direct_ipv4_readback(target, "admin", CURRENT, 5,
                    strict=True, policy=policy, readiness_policy=app.ReadinessPolicy(first_delay=0), details=details)
            except app.SetupError as caught:
                error = caught
            if fault != "changed-source":
                policy.assert_unchanged()
                self.assertTrue(global_file.read_bytes() == original_bytes, "readonly probes must not rewrite project input")
            self.assertIs(type(policy), app.ProjectPasswordPolicy)
            self.assertTrue(policy._password == project_value, "target permission must never become selected-current")
        self.assertEqual([], effects)
        return app, output, error, calls, delays, details

    def test_strict_direct_readiness_clean_timeout_retries_once_then_reads_fresh_identity(self):
        app, output, error, calls, delays, details = self._wp4_strict_timeout_readiness("clean-timeout")
        self.assertIsNone(error, "a confirmed-clean original session timeout remains retryable across strict core")
        self.assertEqual([("ip", "addr", "show", "eth0"), ("ip", "addr", "show", "eth0"),
                          ("ip", "route"), ("nv", "config", "show", "-o", "commands")], calls)
        self.assertEqual([10], delays, "only the original next-attempt interval is consumed")
        self.assertEqual(READY + ADDRESS0 + GATEWAY0, output)
        self.assertTrue(details["identity"]["ok"])
        self.assertIs(type(details["endpoint"]), app.DirectEndpoint)
        self.assertEqual(("203.0.113.2", None), (details["endpoint"].address, details["endpoint"].interface))

    def test_strict_direct_readiness_uncertain_authentication_and_unknown_are_not_retried(self):
        for fault in ("uncertain-timeout", "authentication", "unknown"):
            with self.subTest(fault=fault):
                app, output, error, calls, delays, details = self._wp4_strict_timeout_readiness(fault)
                self.assertIsNone(output)
                self.assertIs(type(error), app.SetupError, "real strict safe-error boundary must remain intact")
                self.assertEqual([("ip", "addr", "show", "eth0")], calls)
                self.assertEqual([], delays, "fatal facts may not advance the readiness loop")
                self.assertNotIn("identity", details)
                if fault == "uncertain-timeout":
                    self.assertIs(getattr(error, "cleanup_uncertain", None), True)

    def test_strict_direct_readiness_changed_project_source_stops_before_transport(self):
        app, output, error, calls, delays, details = self._wp4_strict_timeout_readiness("changed-source")
        self.assertIsNone(output)
        self.assertIs(type(error), app.SetupError)
        self.assertEqual([], calls, "actual same-project source guard must run before direct IO")
        self.assertEqual([], delays, "source qualification failure is not network convergence")
        self.assertEqual({}, details)


    @contextmanager
    def _wp4_public_core_timeout_policy(self):
        """Real bound policy, one PUBLIC verifier boundary, no session/native IO."""
        from test_cases.test_initial_setup_cable_check import _Facade
        app = self._wp4_app
        project_value = "-".join(("PUBLIC", "core", "target", "Zq7"))
        setting = "$" + "6$PUBLICsalt$" + "A" * 86
        project = Path(tempfile.mkdtemp(prefix="core-timeout-policy-", dir=self._wp4_home))
        self.assertEqual(self._wp4_home, project.parent)
        self.assertEqual(project, project.resolve())
        self.assertTrue(project.lstat().st_uid == os.geteuid()
                        and stat.S_IMODE(project.lstat().st_mode) == 0o700)
        path = project / "01-global.yaml"
        path.write_text('schema_version: 2\nswitches:\n- ib:\n    system:\n'
            '      aaa:\n        user:\n          admin:\n            password: "' + setting + '"\n', encoding="utf-8")
        path.chmod(0o600)
        before = path.read_bytes()
        effects, verified = [], []
        real_open = os.open

        def forbidden(*_args, **_kwargs):
            effects.append("forbidden-external")
            raise RuntimeError("FIXTURE HOLD: core fact unit attempted an external effect")

        def own_open(value, flags, *args, **kwargs):
            self.assertEqual((), args)
            self.assertEqual({}, kwargs)
            self.assertEqual(path, Path(value).resolve())
            self.assertEqual(os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, flags)
            return real_open(value, flags)

        def verify_pair(value, digest):
            self.assertTrue(type(value) is str and value == project_value and digest == setting,
                            "only the independent PUBLIC target/hash pair qualifies the real policy")
            verified.append("real-policy-match")
            return True

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app, "verify_password_hash", new=verify_pair))
            stack.enter_context(mock.patch.object(app, "subprocess", new=_Facade(subprocess, run=forbidden, Popen=forbidden)))
            stack.enter_context(mock.patch.object(app, "socket", new=_Facade(socket, socket=forbidden, create_connection=forbidden)))
            stack.enter_context(mock.patch.object(app, "pty", new=_Facade(app.pty, fork=forbidden)))
            stack.enter_context(mock.patch.object(app, "os", new=_Facade(os, open=own_open,
                fork=forbidden, execv=forbidden, execve=forbidden, execvp=forbidden,
                posix_spawn=forbidden, posix_spawnp=forbidden, system=forbidden,
                kill=forbidden, killpg=forbidden, waitpid=forbidden)))
            stack.enter_context(mock.patch.object(app.getpass, "getpass", new=forbidden))
            policy = app.ProjectPasswordPolicy(path, "admin", target_password=project_value, interactive=False)
            self.assertTrue(policy.password() == project_value and policy._password == project_value,
                            "real policy must cache its verified PUBLIC input")
            self.assertTrue(verified)
            self.assertEqual(0o600, stat.S_IMODE(path.lstat().st_mode))
            yield app, policy, path, before
            self.assertTrue(type(policy) is app.ProjectPasswordPolicy and policy._password == project_value,
                            "core permission target remains the actual qualified project value")
            self.assertEqual([], effects)

    def test_strict_core_marks_only_qualified_direct_readonly_session_timeouts(self):
        """Fact classification unit, NOT O5/permit/backend or write-flow proof.

        run_on_ib is this unit's sole session boundary. All outer target,
        command, account, actual project qualification and safe-error work is
        real. The expected private bool predicate was frozen before producer
        repair; it is not read from a candidate or incoming error property.
        """
        official = "SSH/PAM session timed out; device state may be unknown"
        cases = ("clean-default", "clean-false", "write", "jump-read", "pre-source",
                 "post-source", "post-result", "forged-unknown", "uncertain-true",
                 "uncertain-zero", "auth-subclass", "source-subclass", "batch-subclass", "ssh-subclass", "os-error")
        for case in cases:
            with self.subTest(case=case), self._wp4_public_core_timeout_policy() as (app, policy, path, before):
                direct = case != "jump-read"
                route = self._wp4_paths.Route(HOST, "direct", "NO_MGMT_LINK", None, None, None) if direct else None
                jump = None if direct else app.Device("PUBLIC-JUMP01", "eth_jump", "198.51.100.10", "", "", "", "", "")
                target = app.Target(self._wp4_device(), jump, "" if direct else "swp7", "eth0", route=route)
                point = app.DirectEndpoint("203.0.113.2", None) if direct else app.Neighbor("fe80::17", "ib-mgmt", MAC)
                supplied = ["nv", "set", "system", "hostname", HOST] if case == "write" else list(READ)
                self.assertEqual(supplied, app.ib_command_argv(supplied))
                calls = []

                def session(*args, **kwargs):
                    self.assertEqual(8, len(args))
                    self.assertIs(target, args[0]); self.assertIs(point, args[1])
                    self.assertEqual(("", "") if direct else ("cumulus", "PUBLIC-Outer-Only"), args[2:4])
                    self.assertTrue(args[4] == "admin" and args[5] == CURRENT and args[6] == 5,
                                    "selected current is not the project permission target")
                    self.assertEqual(supplied, args[7])
                    self.assertEqual({"local": False, "allow_password_change": False}, kwargs)
                    calls.append("actual-core-session-boundary")
                    if case in ("post-source", "post-result"):
                        if case == "post-source":
                            path.write_bytes(before + b"# PUBLIC source changed after session return\n")
                        return app.SessionResult(READY + ADDRESS0 + GATEWAY0, 0,
                            password_change_required=case == "post-result")
                    if case == "forged-unknown":
                        error = app.SetupError("PUBLIC ordinary UNKNOWN, not an official session timeout")
                        error._ib_readonly_session_timeout = True
                    elif case == "auth-subclass":
                        error = app.IBAuthenticationError(official)
                    elif case == "source-subclass":
                        error = app.ProjectInputChanged(official)
                    elif case == "batch-subclass":
                        error = app.BatchStopped(official)
                    elif case == "ssh-subclass":
                        error = app.SshFailure(app.SshFailureKind.DIRECT_LOGIN_NETWORK, "direct", "203.0.113.2")
                        error.args = (official,)  # a typed SSH error cannot become a clean timeout by its text
                    elif case == "os-error":
                        error = OSError(official)
                    else:
                        error = app.SetupError(official)
                        if case == "clean-false":
                            error.cleanup_uncertain = False
                        elif case == "uncertain-true":
                            error.cleanup_uncertain = True
                        elif case == "uncertain-zero":
                            error.cleanup_uncertain = 0  # equal-to-False is not the exact bool False
                    raise error

                if case == "pre-source":
                    path.write_bytes(before + b"# PUBLIC source changed before session admission\n")
                result = error = None
                with mock.patch.object(app, "run_on_ib", new=session):
                    try:
                        if direct:
                            result = app._run_authorized_ib_direct_command(target, point, "", "", "admin", CURRENT, 5,
                                list(supplied), local=False, _password_policy=policy)
                        else:
                            result = app._run_authorized_ib_command(target, point, "cumulus", "PUBLIC-Outer-Only",
                                "admin", CURRENT, 5, list(supplied), local=False, _password_policy=policy)
                    except app.SetupError as caught:
                        error = caught
                self.assertIsNone(result)
                self.assertIs(type(error), app.SetupError, "original exact safe exception type is preserved")
                self.assertEqual(("management IB operation failed; device state is UNKNOWN",), error.args)
                self.assertIsNone(error.__cause__); self.assertIsNone(error.__context__)
                self.assertEqual(0 if case == "pre-source" else 1, len(calls))
                if case in ("clean-default", "clean-false"):
                    self.assertIs(getattr(error, "_ib_readonly_session_timeout", None), True,
                                  "only the qualified direct readonly session may acquire the official timeout fact")
                else:
                    self.assertIsNot(getattr(error, "_ib_readonly_session_timeout", None), True,
                                     "writes/source/auth/uncertainty/UNKNOWN may not lend a readonly retry fact")
                if case == "uncertain-true":
                    self.assertIs(getattr(error, "cleanup_uncertain", None), True)


    def _jump_fresh(self, *, address=IP_ADDR,
                    route="default via 203.0.113.1 dev eth0\n", execute=False):
        """Real Jump/master/readiness/task; only PUBLIC external IO is replaced.

        LL configuration and planned IPv4 reads are different wire endpoints.
        The legacy framed true is answered, but never credited as identity.
        No source API, phase, LP parser, policy or task result is substituted.
        """
        from test_cases.test_initial_setup_cable_check import _World, _Facade, JA, PUBLIC_REPLY
        import time as external_time

        with _World(self) as world:
            app, paths = world.app, world.paths
            for public_file in (world.csv, world.master, world.p2p):
                self.assertEqual(world.project, public_file.parent)
                self.assertEqual(public_file, public_file.resolve())
                info = public_file.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(os.geteuid(), info.st_uid)
                public_file.chmod(0o600)
                self.assertEqual(0o600, stat.S_IMODE(public_file.lstat().st_mode))
            device = app.Device(HOST, "ib", "203.0.113.2", "203.0.113.2/24",
                                "203.0.113.1", MAC, "", "")
            jump = app.Device(JA, "eth_jump", "198.51.100.10", "", "", "", "", "")
            target = app.Target(device, jump, "swp7", "eth0")
            point = app.Neighbor("fe80::17", "ib-mgmt", MAC, "oob")
            task = app.PreparedIBTask(target, point, PUBLIC_REPLY, False)
            stamp = "20261117-040000"
            args = SimpleNamespace(eth_user="cumulus", ib_user="admin", connect_timeout=5,
                apply=True, yes=True, force=False, run_stamp=stamp,
                execution_mode="ethernet", _on_management_server=False)
            coordinator = app.RuntimeCoordinator(args, None, FACTORY, [task], app.RuntimeInputAuthority([]))
            coordinator.current_target = target
            # Initial and Network are already complete. Services deliberately
            # are not: an incorrect legacy true may reach actual later writes.
            state = (ADDRESS0 + GATEWAY0 + READY
                + "nv set system config auto-save state enabled\n"
                + "nv set system ztp config-save enabled\n")
            services = {"dns": ["192.0.2.53"], "ntp": ["192.0.2.123"], "timezone": "UTC"}
            setters = {
                ("nv", "set", "system", "dns", "server", "192.0.2.53"),
                ("nv", "set", "system", "ntp", "server", "192.0.2.123"),
                ("nv", "set", "system", "date-time", "timezone", "UTC"),
            }
            events, clock = [], [0.0]
            original_interactive = world.interactive
            sessions = app.JumpSessions(timeout=5)
            world.sessions = sessions  # original __exit__ owns close/exit/removal

            def sleep(delay):
                self.assertGreaterEqual(delay, 0)
                events.append(("sleep", delay))
                clock[0] += delay

            def interactive(argv, responder, timeout, **options):
                nonlocal state
                self.assertIs(type(argv), list)
                self.assertEqual("ssh", argv[0])
                if "-M" in argv:
                    return original_interactive(argv, responder, timeout, **options)
                path = world._scoped_path(argv)
                self.assertIn(path, world.masters)
                self.assertEqual("198.51.100.10", world.masters[path])
                self.assertEqual("cumulus@198.51.100.10", argv[-2])
                outer = shlex.split(argv[-1])
                self.assertEqual(["sh", "-c"], outer[:2])
                self.assertEqual(3, len(outer))
                safe = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
                self.assertTrue(outer[2].startswith(safe))
                inner = shlex.split(outer[2][len(safe):])
                if inner == ["hostname"]:
                    return original_interactive(argv, responder, timeout, **options)
                self.assertEqual(["ip", "vrf", "exec", "oob", "ssh"], inner[:5])
                self.assertIn("ControlMaster=no", inner)
                self.assertIn("ControlPath=none", inner)
                endpoint = inner[-2]
                self.assertIn(endpoint, ("admin@fe80::17", "admin@203.0.113.2"))
                if endpoint == "admin@fe80::17":
                    self.assertIn("-6", inner)
                    self.assertEqual("ib-mgmt", inner[inner.index("-B") + 1])
                    lane = "link-local"
                else:
                    self.assertNotIn("-6", inner)
                    self.assertNotIn("-B", inner)
                    lane = "fresh-ipv4"
                # Closed options, not an arbitrary ssh/ProxyCommand carrier.
                allowed_options = {
                    "ConnectTimeout=5", "StrictHostKeyChecking=accept-new", "LogLevel=ERROR",
                    "ControlMaster=no", "ControlPath=none", "NumberOfPasswordPrompts=1",
                    "PubkeyAuthentication=no", "PreferredAuthentications=password,keyboard-interactive",
                }
                remaining, seen = inner[5:-2], set()
                while remaining:
                    flag, remaining = remaining[0], remaining[1:]
                    if flag in ("-tt", "-4", "-6"):
                        self.assertNotIn(flag, seen)
                        seen.add(flag)
                    else:
                        self.assertIn(flag, ("-o", "-B"))
                        self.assertTrue(remaining)
                        value, remaining = remaining[0], remaining[1:]
                        self.assertNotIn((flag, value), seen)
                        seen.add((flag, value))
                        if flag == "-B":
                            self.assertEqual(("link-local", "ib-mgmt"), (lane, value))
                        else:
                            self.assertIn(value, allowed_options)
                self.assertIs(type(responder), app.NestedResponder)
                self.assertIsNone(getattr(responder, "_phase", None))
                self.assertEqual(PUBLIC_REPLY, responder.ethernet_password)
                self.assertEqual(FACTORY, responder(endpoint + "'s password: "),
                                 "PUBLIC IB role is distinct from the outer credential")
                framed = shlex.split(inner[-1])
                self.assertEqual(["sh", "-c"], framed[:2])
                self.assertEqual(3, len(framed))
                nonces = re.findall(r"__HTTP_IB_BEGIN_([A-Za-z0-9_]{1,80})__", framed[2])
                self.assertEqual(1, len(nonces))
                nonce = nonces[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(framed[2].startswith(prefix))
                self.assertTrue(framed[2].endswith(suffix))
                text = framed[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(text))
                self.assertEqual(text, shlex.join(command))
                events.append(("command", lane, command, path))
                output = ""
                if command == ("true",):
                    pass  # legacy reachability only; no identity credit
                elif command == ("ip", "addr", "show", "eth0"):
                    output = address if lane == "fresh-ipv4" else IP_ADDR
                elif command == ("ip", "route"):
                    output = route if lane == "fresh-ipv4" else "default via 203.0.113.1 dev eth0\n"
                elif command == tuple(READ):
                    output = state
                elif command == ("nv", "show", "system", "ztp"):
                    output = "service disabled\nstate disabled\n"
                elif command == ("nv", "config", "diff", "-o", "commands"):
                    pass
                elif command == ("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", stamp):
                    self.assertEqual("link-local", lane, "IPv4 reads do not retag LL backup authority")
                    output = "path=/home/PUBLIC/current_" + stamp + ".yaml\nbytes=137\n"
                elif command in setters:
                    self.assertEqual("link-local", lane, "old LL write endpoint must not change")
                    state += shlex.join(command) + "\n"
                elif command in (("nv", "config", "apply", "-y"), ("nv", "config", "save")):
                    self.assertEqual("link-local", lane)
                else:
                    raise RuntimeError("FIXTURE HOLD: unknown Jump fresh PUBLIC command")
                return app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + output
                    + ("\n" if output and not output.endswith("\n") else "")
                    + "__HTTP_IB_END_" + nonce + "__=0\n", 0)

            tails = {app.run_service_stage.__code__: "services",
                     app.run_key_stage.__code__: "public-keys",
                     app.run_management_direct_checks.__code__: "final-direct"}
            def observe(frame, event, value):
                if event == "call" and frame.f_globals is app.__dict__ and frame.f_code in tails:
                    events.append(("tail-entry", tails[frame.f_code]))
                if frame.f_globals is paths.__dict__:
                    if event == "call" and frame.f_code is paths.parse_ip_addr.__code__:
                        events.append(("lp-address", frame.f_locals["text"]))
                    elif event == "call" and frame.f_code is paths.parse_default_routes.__code__:
                        events.append(("lp-route", frame.f_locals["text"]))
                    elif event == "return" and frame.f_code is paths.check_identity.__code__:
                        events.append(("lp-check", frame.f_locals["via_ipv4"], value.ok))

            result = error = None
            old_profile = sys.getprofile()
            denied_os = {name: world.deny for name in (
                "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe",
                "execl", "execlp", "execlpe", "posix_spawn", "posix_spawnp",
                "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe")}
            with mock.patch.object(app, "interactive_run", new=interactive), \
                 mock.patch.object(app, "_JUMP_SESSIONS", sessions), \
                 mock.patch.object(app, "_ACTIVE_COORDINATOR", coordinator), \
                 mock.patch.object(app, "time", new=_Facade(external_time,
                     sleep=sleep, monotonic=lambda: clock[0])), \
                 mock.patch.object(app, "log", new=lambda *_a, **_k: None), \
                 mock.patch.object(app, "getpass", new=_Facade(app.getpass, getpass=world.deny)), \
                 mock.patch.object(app, "os", new=_Facade(os, **denied_os)), \
                 mock.patch.object(app, "socket", new=_Facade(app.socket,
                     socket=world.deny, create_connection=world.deny)), \
                 mock.patch.object(app, "pty", new=_Facade(app.pty, openpty=world.deny, fork=world.deny)):
                try:
                    sessions.open_jump_master(jump, "cumulus", app.ethernet_responder(PUBLIC_REPLY))
                    master_path = sessions.jump_control_path(jump)
                    sys.setprofile(observe)
                    if execute:
                        result = app.execute_ib_task(task, args, None, FACTORY, services, [], None)
                    else:
                        try:
                            result = app.verify_ipv4_login(target, "oob", "cumulus", PUBLIC_REPLY,
                                "admin", 5, local=False, ib_password=FACTORY)
                        except app.SetupError as caught:
                            error = caught
                finally:
                    sys.setprofile(old_profile)
                self.assertIs(old_profile, sys.getprofile())
                self.assertFalse(task.local)
                self.assertIs(type(task.neighbor), app.Neighbor)
                self.assertEqual(("fe80::17", "ib-mgmt", "oob"),
                                 (point.ipv6, point.interface, point.vrf))
                self.assertIsNone(coordinator.policy)
            # Original World closes every actual master before restoring its
            # own patched subprocess boundary. No process was ever started.
            world_events = world.events
        self.assertFalse(world.masters)
        self.assertIsNone(sessions.directory)
        self.assertIn(("control", "exit", "198.51.100.10"), world_events)
        return SimpleNamespace(app=app, result=result, error=error, events=events,
            master_path=master_path, coordinator=coordinator)

    def test_jump_ipv4_readiness_reads_fresh_identity_on_the_original_vrf(self):
        for route in ("default via 203.0.113.1 dev eth0\n", "203.0.113.0/24 dev eth0 scope link\n"):
            with self.subTest(default_route=route.startswith("default")):
                observed = self._jump_fresh(route=route)
                self.assertIsNone(observed.error)
                # Original None is legal; do not prescribe a new metadata API.
                commands = [event[2] for event in observed.events
                            if event[:2] == ("command", "fresh-ipv4")]
                self.assertEqual(1, commands.count(("ip", "addr", "show", "eth0")),
                                 "framed true alone cannot prove planned-IPv4 identity")
                self.assertEqual(1, commands.count(("ip", "route")))
                self.assertIn(("lp-address", IP_ADDR), observed.events)
                self.assertIn(("lp-route", route), observed.events)
                self.assertIn(("lp-check", True, True), observed.events)
                self.assertEqual([15], [event[1] for event in observed.events if event[0] == "sleep"])
                self.assertTrue(all(event[3] == observed.master_path for event in observed.events
                                    if event[0] == "command"))

    def test_jump_ipv4_readiness_identity_mismatch_is_fatal_without_retry(self):
        vectors = (
            ("mac", IP_ADDR.replace(MAC, "02:00:00:00:00:18"), "default via 203.0.113.1 dev eth0\n"),
            ("address", IP_ADDR.replace("203.0.113.2/24", "203.0.113.3/24"), "default via 203.0.113.1 dev eth0\n"),
            ("prefix", IP_ADDR.replace("203.0.113.2/24", "203.0.113.2/25"), "default via 203.0.113.1 dev eth0\n"),
            ("gateway", IP_ADDR, "default via 203.0.113.254 dev eth0\n"),
            ("unparsed-default", IP_ADDR, "default dev eth0 scope link\n"),
        )
        for label, address, route in vectors:
            with self.subTest(fact=label):
                observed = self._jump_fresh(address=address, route=route)
                self.assertIsInstance(observed.error, observed.app.SetupError,
                                      "a valid SSH true is not fresh identity acceptance")
                commands = [event[2] for event in observed.events
                            if event[:2] == ("command", "fresh-ipv4")]
                self.assertEqual(1, commands.count(("ip", "addr", "show", "eth0")))
                self.assertLessEqual(commands.count(("ip", "route")), 1)
                self.assertEqual([15], [event[1] for event in observed.events if event[0] == "sleep"],
                                 "identity mismatch must not consume another readiness attempt")
                self.assertFalse(observed.coordinator.writes_attempted)

    def test_jump_fresh_identity_failure_stops_actual_services_keys_and_final_probes(self):
        wrong = "02:00:00:00:00:18"
        observed = self._jump_fresh(address=IP_ADDR.replace(MAC, wrong), execute=True)
        record, events = observed.result, observed.events
        self.assertIsNone(observed.error)
        self.assertIs(record["identity"]["ok"], False,
                      "the good first LL identity cannot stand in for a bad fresh IPv4 identity")
        self.assertIs(record["identity"]["via_ipv4"], True)
        self.assertEqual({"mac": MAC, "ipv4": "203.0.113.2/24", "gateway": "203.0.113.1"},
                         record["identity"]["expected"])
        self.assertEqual(wrong, record["identity"]["observed"]["mac"])
        self.assertIn({"field": "mac", "expected": MAC, "observed": wrong}, record["identity"]["mismatches"])
        self.assertEqual("FAILED_IDENTITY_MISMATCH", observed.app.record_category(record))
        self.assertEqual("FAILED", record["outcome"])
        self.assertEqual("FAILED", record["stage_status"]["ipv4_readiness"])
        for stage in ("services", "public_keys", "direct_ssh"):
            self.assertEqual("NOT_REACHED", record["stage_status"][stage])
        self.assertFalse(any(event[0] == "tail-entry" for event in events))
        commands = [event[2] for event in events if event[0] == "command"]
        self.assertEqual(2, commands.count(("ip", "addr", "show", "eth0")), "one LL check and one new IPv4 check")
        self.assertTrue(any(event[:3] == ("command", "fresh-ipv4", ("ip", "addr", "show", "eth0"))
                            for event in events))
        self.assertFalse(any(command[:2] == ("nv", "set") or command[:3] in
            (("nv", "config", "apply"), ("nv", "config", "save")) for command in commands))
        self.assertFalse(any(command[:2] == ("sh", "-c") for command in commands), "no pre-failure or duplicate backup")
        self.assertFalse(observed.coordinator.writes_attempted)
        self.assertIsNone(record["backup"])


    def _public_key_point_handoff(self, *, authentication=False, transition=False):
        """PUBLIC actual-point boundaries, not O5/permit/backend proof.

        The stage unit explicitly installs a real already-qualified state as
        its prerequisite. The authentication facet calls actual inspect/auth,
        with a real policy and only the exact PUBLIC native-pair boundary.
        """
        from test_cases.test_initial_setup_direct_transport import (
            DirectWorld, PrerequisiteHold, IP, IFACE, LL1, _Facade,
        )

        with DirectWorld(self) as world:
            app = world.app
            required = ("_stage_ib_command", "_readonly_key_file", "_run_direct_key_read",
                        "_IBConfigWriteState", "inspect_ib_device")
            if any(not callable(getattr(app, name, None)) for name in required):
                raise PrerequisiteHold("RV205/206 fixed source API unavailable; not a business RED")
            target = world.target(same_subnet=IFACE)
            point = app.DirectEndpoint(LL1, IFACE)
            ipv4_point = app.DirectEndpoint(IP, None)
            app._validate_direct_endpoint(target, point)
            app._validate_direct_endpoint(target, ipv4_point)
            task = app.PreparedIBTask(target, point, "", False)
            for path in (world.csv, world.master, world.p2p):
                self.assertEqual(world.project, path.parent)
                self.assertEqual(path, path.resolve())
                self.assertTrue(stat.S_ISREG(path.lstat().st_mode))
                self.assertEqual(os.geteuid(), path.lstat().st_uid)
                path.chmod(0o600)
            ssh_dir = world.home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            key = ssh_dir / "id_ed25519"
            key.write_bytes(b"PUBLIC KEY-POINT MODEL; NEVER OPENED BY AN SSH CLIENT\n")
            key.chmod(0o600)
            self.assertEqual(key, key.resolve())
            key_bytes = key.read_bytes()
            events, controls, verifications = [], [], []
            private_input = None
            policy = None
            setting = "$" + "6$PUBLICsalt$" + "A" * 86
            global_file = world.project / "01-global.yaml"
            if authentication:
                private_input = ('schema_version: 2\nswitches:\n- ib:\n    system:\n'
                    '      aaa:\n        user:\n          admin:\n            password: "'
                    + setting + '"\n').encode("utf-8")
                global_file.write_bytes(private_input)
                global_file.chmod(0o600)
                policy = app.ProjectPasswordPolicy(global_file, "admin",
                    target_password=PROJECT, interactive=False)
            # This is deliberately only a unit prerequisite, not simulated O5.
            state = app._IBConfigWriteState(task, "admin", "", "20261117-040000", False,
                endpoint=point, current_password=None, identity_verified=True,
                readonly_key_file=key)
            complete = ("nv set system hostname example-ib01\n"
                "nv set interface eth0 ipv4 address 192.0.2.10/24\n"
                "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
                "nv set interface eth0-1 link state up\n"
                "nv set interface eth0-1 type eth\n"
                "nv set system config auto-save state enabled\n"
                "nv set system ztp config-save enabled\n")

            def verify(value, digest):
                self.assertTrue(type(value) is str and value in (PROJECT, FACTORY, CURRENT),
                                "only the three independent PUBLIC roles enter the verifier")
                self.assertTrue(type(digest) is str and digest == setting,
                                "real policy must bind the independent PUBLIC hash shape")
                matched = value == PROJECT
                verifications.append(matched)
                return matched

            def control(argv, **options):
                if argv not in (["ip", "-4", "neigh", "show", IP],
                                ["ping", "-c", "1", "-W", "1", IP]):
                    raise RuntimeError("FIXTURE HOLD: unknown key-point external command")
                controls.append(tuple(argv))
                return world.control(argv, **options)

            def ask(hostname):
                self.assertEqual("example-ib01", hostname)
                events.append(("ask", "current"))
                return CURRENT

            def interactive(argv, responder, timeout, **options):
                self.assertIs(type(argv), list)
                self.assertEqual("ssh", argv[0])
                destination = argv[-2]
                scoped = "admin@fe80::ff:fe00:10%en-public7"
                self.assertIn(destination, (scoped, "admin@192.0.2.10"))
                lane = "ll" if destination == scoped else "ipv4"
                self.assertIn("-6" if lane == "ll" else "-4", argv)
                self.assertIn("ControlMaster=no", argv)
                self.assertIn("ControlPath=none", argv)
                self.assertIn("ProxyCommand=none", argv)
                self.assertIn("ProxyJump=none", argv)
                self.assertIsNone(getattr(responder, "_phase", None))
                if "-i" in argv:
                    self.assertEqual(1, argv.count("-i"))
                    self.assertTrue(argv[argv.index("-i") + 1] == str(key),
                                    "only this owned synthetic key is admitted")
                    for value in ("BatchMode=yes", "PreferredAuthentications=publickey",
                                  "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                                  "IdentitiesOnly=yes"):
                        self.assertTrue(argv.count(value) == 1 and argv[argv.index(value) - 1] == "-o",
                                        "key request must retain every exact key-only option")
                    self.assertNotIn("PubkeyAuthentication=no", argv)
                    self.assertIsNone(getattr(responder, "ib_default_password", None))
                    self.assertIsNone(responder("PUBLIC challenge with no input requested"))
                    role = "key"
                else:
                    self.assertIs(type(responder), app._DirectResponder)
                    for value in ("PubkeyAuthentication=no",
                                  "PreferredAuthentications=password,keyboard-interactive"):
                        self.assertTrue(argv.count(value) == 1 and argv[argv.index(value) - 1] == "-o",
                                        "known/current requests must really be password-only")
                    supplied = responder.ib_default_password
                    role = ("project" if supplied == PROJECT else "factory" if supplied == FACTORY
                            else "current" if supplied == CURRENT else None)
                    self.assertIsNotNone(role, "password requests must retain their independent PUBLIC role")
                self.assertEqual(destination, responder.ib_destination)
                remote = shlex.split(argv[-1])
                self.assertEqual(["sh", "-c"], remote[:2])
                self.assertEqual(3, len(remote))
                found = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertEqual(1, len(found))
                marker = found[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix))
                self.assertTrue(remote[2].endswith(suffix))
                text = remote[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(text))
                self.assertEqual(text, shlex.join(command))
                expected = tuple(READ) if authentication else ("nv", "show", "system", "ztp")
                if command != expected:
                    raise RuntimeError("FIXTURE HOLD: key-point model admits only its exact read vector")
                events.append(("request", role, lane, command))
                if transition and role == "key" and lane == "ll":
                    # Explicit original normal-return network classification;
                    # no synthetic UNKNOWN/timeout or cleanup fact grants it.
                    return app.SessionResult("ssh: connect to host fe80::ff:fe00:10%en-public7 port 22: "
                                             "Network is unreachable\n", 255)
                if authentication and role in ("key", "project", "factory"):
                    method = "publickey" if role == "key" else "password"
                    return app.SessionResult(destination + ": Permission denied (" + method + ").\n", 255,
                                             ib_authentication_rejected=True)
                # Both current endpoints deliberately work. The old LL path
                # must reach the business endpoint assertion, not a fixture deny.
                output = complete if authentication else "service disabled\nstate disabled\n"
                return app.SessionResult("__HTTP_IB_BEGIN_" + marker + "__\n" + output
                    + "__HTTP_IB_END_" + marker + "__=0\n", 0)

            def observe(frame, event, _value):
                if event != "call":
                    return
                if frame.f_globals is app.__dict__ and frame.f_code is app.obtain_write_permit.__code__:
                    events.append(("permit", frame.f_locals.get("category")))
                if frame.f_globals is world.paths.__dict__ and frame.f_code is world.paths.credential_order.__code__:
                    events.append(("credential-order", frame.f_locals["path"], frame.f_locals["key_available"]))

            denied_os = {name: world.deny for name in (
                "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe", "execl",
                "execlp", "execlpe", "posix_spawn", "posix_spawnp", "spawnl", "spawnle", "spawnlp",
                "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")}
            old_profile, result, error = sys.getprofile(), None, None
            prior_context = app._TASK_IB_CONFIG
            with ExitStack() as guard:
                guard.enter_context(mock.patch.object(app, "subprocess",
                    new=_Facade(subprocess, run=control, Popen=world.deny)))
                guard.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
                guard.enter_context(mock.patch.object(app, "request_current_ib_password", new=ask))
                guard.enter_context(mock.patch.object(app, "log", new=lambda *_a, **_k: None))
                guard.enter_context(mock.patch.object(app, "os", new=_Facade(os, **denied_os)))
                guard.enter_context(mock.patch.object(app, "socket", new=_Facade(app.socket,
                    socket=world.deny, create_connection=world.deny)))
                guard.enter_context(mock.patch.object(app, "pty", new=_Facade(app.pty,
                    fork=world.deny, openpty=world.deny)))
                guard.enter_context(mock.patch.object(app, "getpass",
                    new=_Facade(app.getpass, getpass=world.deny)))
                if authentication:
                    guard.enter_context(mock.patch.object(app, "verify_password_hash", new=verify))
                    selected = policy.password()
                    self.assertTrue(type(selected) is str and selected == PROJECT and any(verifications),
                                    "actual policy must first verify its independent PUBLIC target")
                else:
                    guard.enter_context(mock.patch.object(app, "_TASK_IB_CONFIG", state))
                try:
                    sys.setprofile(observe)
                    try:
                        if authentication:
                            result = app.inspect_ib_device(target, point, "", "", "admin", FACTORY, 2,
                                policy, apply=False, authorized=False, local=False, strict=False,
                                _management_private_key=key)
                        else:
                            result = app._stage_ib_command(target, point, "", "", "admin", None, 2,
                                ["nv", "show", "system", "ztp"], local=False, strict=False,
                                policy=None, _ib_read_context=state)
                    except app.SetupError as caught:
                        error = caught
                finally:
                    sys.setprofile(old_profile)
                self.assertIs(old_profile, sys.getprofile())
            self.assertIs(prior_context, app._TASK_IB_CONFIG)
            self.assertTrue(key.read_bytes() == key_bytes, "synthetic key content must remain unchanged")
            self.assertEqual(0o600, stat.S_IMODE(key.lstat().st_mode))
            if authentication:
                self.assertIs(type(policy), app.ProjectPasswordPolicy)
                policy.assert_unchanged()
                self.assertTrue(global_file.read_bytes() == private_input,
                                "real bound PUBLIC input may not change during endpoint handoff")
            self.assertEqual([], [event for event in events if event[0] == "permit"],
                             "neither unit nor readonly authentication may request a write/backup permit")
            return SimpleNamespace(app=app, result=result, error=error, events=events,
                controls=controls, original_point=point, ipv4_point=ipv4_point, state=state)

    def test_readonly_key_stage_accepts_the_original_verified_endpoint(self):
        observed = self._public_key_point_handoff()
        self.assertIsNone(observed.error)
        self.assertIs(type(observed.result), observed.app.SessionResult)
        self.assertEqual(observed.original_point, observed.result._direct_endpoint)
        self.assertEqual("service disabled\nstate disabled\n", observed.result.output)
        self.assertEqual([("request", "key", "ll", ("nv", "show", "system", "ztp"))], observed.events)
        self.assertEqual([], observed.controls)
        self.assertIs(observed.state.identity_verified, True, "installed unit prerequisite is retained")

    def test_readonly_key_stage_refuses_a_post_identity_endpoint_transition(self):
        observed = self._public_key_point_handoff(transition=True)
        self.assertEqual([("request", "key", "ll", ("nv", "show", "system", "ztp")),
                          ("request", "key", "ipv4", ("nv", "show", "system", "ztp"))], observed.events)
        self.assertEqual([("ip", "-4", "neigh", "show", "192.0.2.10")], observed.controls)
        self.assertIsInstance(observed.error, observed.app.SetupError,
                              "a successful read at a different point cannot reuse the old O5 context")
        self.assertIsNone(observed.result)
        self.assertEqual(observed.original_point, observed.state.endpoint)

    def test_current_prompt_keeps_the_original_endpoint_without_a_transition(self):
        observed = self._public_key_point_handoff(authentication=True)
        self.assertIsNone(observed.error)
        self.assertEqual([("request", "key", "ll", tuple(READ)),
                          ("request", "project", "ll", tuple(READ)),
                          ("request", "factory", "ll", tuple(READ)),
                          ("ask", "current"), ("request", "current", "ll", tuple(READ))],
                         [event for event in observed.events if event[0] in ("request", "ask")])
        self.assertEqual(1, observed.events.count(("ask", "current")))
        self.assertEqual([("credential-order", "direct", True)],
                         [event for event in observed.events if event[0] == "credential-order"])
        self.assertEqual([], observed.controls)
        result, credential, authorized = observed.result
        self.assertIs(type(result), observed.app.SessionResult)
        self.assertEqual(observed.original_point, result._direct_endpoint)
        self.assertTrue(type(credential) is str and credential == CURRENT, "actual current remains a separate PUBLIC role")
        self.assertIs(authorized, False)

    def test_current_prompt_keeps_the_actual_endpoint_after_key_fallback(self):
        observed = self._public_key_point_handoff(authentication=True, transition=True)
        self.assertIsNone(observed.error)
        actual = [event for event in observed.events if event[0] == "request"]
        self.assertEqual([("request", "key", "ll", tuple(READ)),
                          ("request", "key", "ipv4", tuple(READ)),
                          ("request", "project", "ipv4", tuple(READ)),
                          ("request", "factory", "ipv4", tuple(READ))], actual[:4])
        self.assertEqual(1, observed.events.count(("ask", "current")))
        self.assertEqual([("ip", "-4", "neigh", "show", "192.0.2.10")], observed.controls)
        self.assertEqual([("request", "current", "ipv4", tuple(READ))], actual[4:],
                         "the current-password READ must retain the actual selected IPv4 point")
        self.assertEqual([("credential-order", "direct", True)],
                         [event for event in observed.events if event[0] == "credential-order"])
        result, credential, authorized = observed.result
        self.assertIs(type(result), observed.app.SessionResult)
        self.assertEqual(observed.ipv4_point, result._direct_endpoint)
        self.assertTrue(type(credential) is str and credential == CURRENT, "current may not be synthesized from project")
        self.assertIs(authorized, False)


    def _kg1_public_key_fault(self, *, metadata=None, source=None, strict=False):
        """Actual inspect/auth/key read; mutate only this case's owned PUBLIC files.

        Unlike the unchanged earlier helpers, this carrier deliberately records
        an intentional input change instead of asserting it never happened.
        It models one SSH read, not O5/execute/native/PTY or write permission.
        """
        from inspect import signature
        from test_cases.test_initial_setup_cable_check import _Facade

        app = self._wp4_app
        required = ("inspect_ib_device", "_authenticate_ib_read", "_run_direct_key_read", "DirectEndpoint")
        if (any(not callable(getattr(app, name, None)) for name in required)
                or "_management_private_key" not in signature(app.inspect_ib_device).parameters):
            raise RuntimeError("PREREQUISITE HOLD: KG1 actual key-read API is unavailable")
        self.assertIn(metadata, (None, "replace", "remove", "symlink"))
        self.assertIn(source, (None, "before", "after"))
        self.assertFalse(metadata is not None and source is not None,
                         "KG1 changes exactly one independent custody fact")
        target = app.Target(self._wp4_device(), None, "", "eth0", route=self._wp4_paths.Route(
            HOST, "direct", "NO_MGMT_LINK", None, None, None))
        point = app.DirectEndpoint("203.0.113.2", None)
        app._validate_direct_endpoint(target, point)
        old_profile, old_context = sys.getprofile(), app._TASK_IB_CONFIG
        requests, effects, permits, asks, tails, replies, verified = [], [], [], [], [], [], []
        entered = {name: 0 for name in ("inspect", "auth", "key-helper", "builder")}
        codes = {app.inspect_ib_device.__code__: "inspect", app._authenticate_ib_read.__code__: "auth",
                 app._run_direct_key_read.__code__: "key-helper", app.direct_ssh_command.__code__: "builder"}
        tail_codes = {getattr(app, name).__code__: name for name in
                      ("run_initial_stage", "run_service_stage", "run_key_stage", "run_management_direct_checks")}
        result = error = None
        mutated = []
        body = (READY + ADDRESS0 + GATEWAY0
            + "nv set system config auto-save state enabled\n"
            + "nv set system ztp config-save enabled\n")
        with tempfile.TemporaryDirectory(prefix="kg1-public-", dir=self._wp4_home) as folder:
            root = Path(folder)
            home, project = root / "home", root / "project"
            home.mkdir(mode=0o700); project.mkdir(mode=0o700)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            key, alternate, original = (ssh_dir / name for name in ("id_ed25519", "alternate", "original"))
            key_bytes = b"PUBLIC KG1 SYNTHETIC INPUT; NO SSH CLIENT EVER READS THIS FILE\n"
            key.write_bytes(key_bytes); key.chmod(0o600)
            alternate.write_bytes(key_bytes); alternate.chmod(0o600)
            first_inode = key.lstat().st_ino
            setting = "$" + "6$PUBLICsalt$" + "A" * 86
            global_file = project / "01-global.yaml"
            input_bytes = ('schema_version: 2\nswitches:\n- ib:\n    system:\n'
                '      aaa:\n        user:\n          admin:\n            password: "' + setting + '"\n').encode("utf-8")
            global_file.write_bytes(input_bytes); global_file.chmod(0o600)
            for path, mode in ((root, 0o700), (home, 0o700), (project, 0o700), (ssh_dir, 0o700),
                               (key, 0o600), (alternate, 0o600), (global_file, 0o600)):
                self.assertTrue(path == path.resolve() and path.lstat().st_uid == os.geteuid()
                                and stat.S_IMODE(path.lstat().st_mode) == mode,
                                "KG1 fixtures must be canonical, owned and privately permissioned")
            self.assertEqual(self._wp4_home, root.parent)
            real_open = os.open

            def forbidden(*_args, **_kwargs):
                effects.append("forbidden-external")
                raise RuntimeError("FIXTURE HOLD: KG1 attempted an external effect outside its single read model")

            def policy_open(value, flags, *args, **kwargs):
                self.assertTrue(args == () and kwargs == {}, "KG1 policy open has only the admitted arguments")
                self.assertTrue(global_file == Path(value).resolve(), "only this owned PUBLIC global may be opened")
                self.assertEqual(os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, flags)
                return real_open(value, flags)

            def verify_pair(value, digest):
                self.assertTrue(type(value) is str and value in (PROJECT, FACTORY, CURRENT),
                                "only independent PUBLIC credential roles enter the verifier")
                self.assertTrue(type(digest) is str and digest == setting,
                                "real policy must consume this case's independent PUBLIC hash shape")
                matched = value == PROJECT
                verified.append(matched)
                return matched

            def change_source():
                global_file.write_bytes(input_bytes + b"# PUBLIC KG1 deliberate source change\n")
                self.assertTrue(global_file.read_bytes() != input_bytes,
                                "the deliberate own-source change must actually happen")
                self.assertEqual(0o600, stat.S_IMODE(global_file.lstat().st_mode))
                mutated.append("source-" + source)

            def change_key():
                self.assertEqual(ssh_dir, original.parent)
                self.assertFalse(original.exists())
                key.replace(original)
                if metadata == "replace":
                    alternate.replace(key)
                    self.assertTrue(key.lstat().st_ino != first_inode,
                                    "same PUBLIC bytes must be carried by a different owned file")
                elif metadata == "remove":
                    self.assertFalse(key.exists())
                else:
                    key.symlink_to(alternate)
                    self.assertTrue(key.is_symlink() and key.resolve() == alternate,
                                    "the only symlink target is another owned PUBLIC file")
                mutated.append("metadata-" + metadata)

            def ask(hostname):
                self.assertEqual(HOST, hostname)
                asks.append("current")
                return CURRENT

            def interactive(argv, responder, timeout, **options):
                self.assertTrue(options == {} and type(argv) is list,
                                "KG1 interactive carrier keeps its admitted argument shape")
                if argv[:1] != ["ssh"]:
                    raise RuntimeError("FIXTURE HOLD: KG1 does not simulate a private phase or another carrier")
                self.assertTrue(argv[-2] == "admin@203.0.113.2",
                                "the actual read must bind only the independent CSV endpoint")
                self.assertTrue("ProxyJump=yes" not in argv
                                and all(option in argv for option in ("ProxyCommand=none", "ProxyJump=none",
                                    "ControlMaster=no", "ControlPath=none")),
                                "KG1 keeps the closed direct, non-shared SSH options")
                self.assertTrue(getattr(responder, "_phase", None) is None,
                                "KG1 does not pretend to complete private phase custody")
                self.assertTrue(getattr(responder, "ib_destination", None) == "admin@203.0.113.2",
                                "the no-input/read responder must bind this same PUBLIC endpoint")
                if "-i" in argv:
                    self.assertEqual(1, argv.count("-i"))
                    self.assertTrue(argv[argv.index("-i") + 1] == str(key),
                                    "only the explicit owned synthetic key may be selected")
                    for option in ("BatchMode=yes", "PreferredAuthentications=publickey",
                                   "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "IdentitiesOnly=yes"):
                        self.assertTrue(argv.count(option) == 1 and argv[argv.index(option) - 1] == "-o",
                                        "the actual request must remain explicitly key-only")
                    self.assertTrue("PubkeyAuthentication=no" not in argv,
                                    "an explicit key request must not disable its key authentication")
                    self.assertTrue(getattr(responder, "ib_default_password", None) is None,
                                    "key login cannot synthesize a current credential")
                    role = "key"
                else:
                    current = getattr(responder, "ib_default_password", None)
                    role = ("project" if current == PROJECT else "factory" if current == FACTORY
                            else "current" if current == CURRENT else None)
                    self.assertTrue(role is not None, "an unexpected credential must not be printed or accepted")
                remote = shlex.split(argv[-1])
                self.assertTrue(remote[:2] == ["sh", "-c"] and len(remote) == 3,
                                "KG1 uses one closed remote frame")
                found = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertEqual(1, len(found))
                nonce = found[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix) and remote[2].endswith(suffix))
                command_text = remote[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(command_text))
                self.assertTrue(tuple(READ) == command and shlex.join(READ) == command_text,
                                "KG1 models only the independent canonical NVUE READ")
                requests.append((role, command))
                if role == "key":
                    if metadata is not None:
                        change_key()
                    elif source == "after":
                        change_source()
                reply = app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + body
                    + "__HTTP_IB_END_" + nonce + "__=0\n", 0)
                replies.append(reply)
                return reply

            def observe(frame, event, _value):
                if event != "call" or frame.f_globals is not app.__dict__:
                    return
                if frame.f_code in codes:
                    entered[codes[frame.f_code]] += 1
                if frame.f_code is app.obtain_write_permit.__code__:
                    permits.append("write-permit")
                if frame.f_code in tail_codes:
                    tails.append(tail_codes[frame.f_code])

            denied_os = {name: forbidden for name in (
                "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe", "execl",
                "execlp", "execlpe", "posix_spawn", "posix_spawnp", "spawnl", "spawnle", "spawnlp",
                "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")}
            with ExitStack() as guard:
                guard.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
                guard.enter_context(mock.patch.object(app, "verify_password_hash", new=verify_pair))
                guard.enter_context(mock.patch.object(app, "subprocess", new=_Facade(
                    subprocess, run=forbidden, Popen=forbidden)))
                guard.enter_context(mock.patch.object(app, "os", new=_Facade(os, open=policy_open, **denied_os)))
                guard.enter_context(mock.patch.object(app, "socket", new=_Facade(
                    socket, socket=forbidden, create_connection=forbidden)))
                guard.enter_context(mock.patch.object(app, "pty", new=_Facade(app.pty, fork=forbidden, openpty=forbidden)))
                guard.enter_context(mock.patch.object(app, "getpass", new=_Facade(app.getpass, getpass=forbidden)))
                guard.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
                guard.enter_context(mock.patch.object(app, "request_current_ib_password", new=ask))
                guard.enter_context(mock.patch.object(app, "log", new=lambda *_a, **_k: None))
                policy = app.ProjectPasswordPolicy(global_file, "admin", target_password=PROJECT, interactive=False)
                selected = policy.password()
                self.assertTrue(type(policy) is app.ProjectPasswordPolicy and selected == PROJECT
                                and policy._password == PROJECT and any(verified),
                                "the original policy must really qualify and cache the independent PUBLIC target")
                if source == "before":
                    change_source()
                try:
                    sys.setprofile(observe)
                    try:
                        result = app.inspect_ib_device(target, point, "", "", "admin", FACTORY, 5,
                            policy, apply=False, authorized=False, local=False, strict=strict,
                            _management_private_key=key)
                    except app.SetupError as caught:
                        error = caught
                finally:
                    sys.setprofile(old_profile)
                self.assertIs(old_profile, sys.getprofile())
                self.assertIs(old_context, app._TASK_IB_CONFIG)
                if source is None:
                    policy.assert_unchanged()
                    self.assertTrue(global_file.read_bytes() == input_bytes,
                                    "an unchanged-source case must not rewrite its owned input")
                else:
                    self.assertTrue(global_file.read_bytes() != input_bytes,
                                    "an intentional source change must not be hidden by a cleanup assertion")
                if metadata is None:
                    self.assertTrue(key.read_bytes() == key_bytes and not key.is_symlink()
                                    and key.lstat().st_ino == first_inode,
                                    "unchanged-key cases retain the same owned PUBLIC file")
            self.assertEqual([], effects)
            self.assertEqual([], permits)
            self.assertEqual([], asks)
            self.assertEqual([], tails)
        self.assertIs(old_profile, sys.getprofile())
        self.assertIs(old_context, app._TASK_IB_CONFIG)
        return SimpleNamespace(app=app, result=result, error=error, requests=requests, entered=entered,
            mutated=mutated, replies=replies, body=body, strict=strict)

    def test_kg1_key_metadata_changes_stop_the_actual_read_before_credential_fallback(self):
        baseline = self._kg1_public_key_fault()
        self.assertTrue(baseline.error is None, "the unchanged-key positive must succeed")
        self.assertTrue(baseline.result[0] is baseline.replies[0], "positive returns its real key SessionResult")
        self.assertTrue(baseline.body == baseline.result[0].output, "positive must consume its independent READ body")
        self.assertTrue(baseline.result[1] is None and baseline.result[2] is False,
                        "key success has no selected current and grants no write authorization")
        self.assertEqual([("key", tuple(READ))], baseline.requests)
        self.assertEqual([], baseline.mutated)
        for fault in ("replace", "remove", "symlink"):
            with self.subTest(metadata=fault):
                observed = self._kg1_public_key_fault(metadata=fault)
                self.assertEqual(["metadata-" + fault], observed.mutated, "the actual own-file mutation must be reached")
                self.assertEqual([("key", tuple(READ))], observed.requests)
                self.assertEqual({"inspect": 1, "auth": 1, "key-helper": 1, "builder": 1}, observed.entered)
                self.assertTrue(isinstance(observed.error, observed.app.SetupError),
                                "changing the selected key during the read must be terminal")
                self.assertFalse(isinstance(observed.error, observed.app.IBAuthenticationError),
                                 "metadata failure is not a credential rejection")
                self.assertTrue(observed.result is None, "metadata failure cannot return a successful login")

    def test_kg1_strict_project_source_changes_stop_before_or_after_the_actual_key_read(self):
        baseline = self._kg1_public_key_fault(strict=True)
        self.assertTrue(baseline.error is None, "the unchanged-source positive must succeed")
        self.assertTrue(baseline.result[0] is baseline.replies[0], "strict positive returns its real key SessionResult")
        self.assertTrue(baseline.body == baseline.result[0].output, "strict positive consumes the independent READ body")
        self.assertTrue(baseline.result[1] is None and baseline.result[2] is False,
                        "strict key success does not invent current or write authorization")
        self.assertEqual([("key", tuple(READ))], baseline.requests)
        self.assertEqual([], baseline.mutated)
        for timing in ("before", "after"):
            with self.subTest(source=timing):
                observed = self._kg1_public_key_fault(source=timing, strict=True)
                self.assertEqual(["source-" + timing], observed.mutated)
                self.assertEqual([] if timing == "before" else [("key", tuple(READ))], observed.requests)
                self.assertEqual({"inspect": 1, "auth": 1, "key-helper": 1,
                                  "builder": 0 if timing == "before" else 1}, observed.entered)
                self.assertTrue(isinstance(observed.error, observed.app.SetupError),
                                "real bound project source changes must be terminal")
                self.assertFalse(isinstance(observed.error, observed.app.IBAuthenticationError),
                                 "source changes do not authorize another credential source")
                self.assertTrue(observed.result is None, "source failure cannot return a successful login")


    def _kg2_public_auth_boundary(self, *, fault):
        """Real IPv4 inspect/auth/key read with one independent external fact.

        This owns only PUBLIC files and models complete SSH replies, not private
        phase custody, real authentication, O5/execute, PAM, or cleanup effects.
        Later password requests remain legal model inputs so an erroneous
        credential advance fails the business oracle instead of a fixture HOLD.
        """
        from inspect import signature
        from test_cases.test_initial_setup_cable_check import _Facade

        app = self._wp4_app
        required = ("inspect_ib_device", "_authenticate_ib_read", "_run_direct_key_read",
                    "direct_ssh_command", "DirectEndpoint", "ProjectPasswordPolicy")
        if (any(not callable(getattr(app, name, None)) for name in required)
                or "_management_private_key" not in signature(app.inspect_ib_device).parameters
                or "_key_file" not in signature(app.direct_ssh_command).parameters):
            raise RuntimeError("PREREQUISITE HOLD: KG2 real key-read API is unavailable")
        allowed = ("success", "typed-denial", "network", "host-key", "pam", "expiry",
                   "cleanup", "frame-missing", "frame-duplicate", "frame-status", "update",
                   "changed", "required", "attempted", "auth-conflict", "unknown", "auth-like",
                   "prompt-password", "prompt-passphrase", "prompt-pam")
        self.assertTrue(fault in allowed, "KG2 requires one declared independent reply fact")
        target = app.Target(self._wp4_device(), None, "", "eth0", route=self._wp4_paths.Route(
            HOST, "direct", "NO_MGMT_LINK", None, None, None))
        point = app.DirectEndpoint("203.0.113.2", None)
        app._validate_direct_endpoint(target, point)
        old_profile, old_context = sys.getprofile(), app._TASK_IB_CONFIG
        requests, effects, asks, permits, tails, prompts, verified, replies = ([] for _ in range(8))
        entered = {name: 0 for name in ("inspect", "auth", "key-helper", "builder")}
        codes = {app.inspect_ib_device.__code__: "inspect", app._authenticate_ib_read.__code__: "auth",
                 app._run_direct_key_read.__code__: "key-helper", app.direct_ssh_command.__code__: "builder"}
        tail_codes = {getattr(app, name).__code__: name for name in (
            "execute_ib_task", "run_initial_stage", "run_service_stage", "run_key_stage",
            "run_management_direct_checks", "refresh_ib_host_key", "remove_jump_known_hosts_entries",
            "_refresh_management_host_key", "_refresh_host_key")}
        login = error = None
        body = (READY + ADDRESS0 + GATEWAY0
                + "nv set system config auto-save state enabled\n"
                + "nv set system ztp config-save enabled\n")
        with tempfile.TemporaryDirectory(prefix="kg2-public-", dir=self._wp4_home) as folder:
            root = Path(folder)
            home, project = root / "home", root / "project"
            home.mkdir(mode=0o700); project.mkdir(mode=0o700)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            key = ssh_dir / "explicit-public-key"
            key_bytes = b"PUBLIC KG2 SYNTHETIC FILE; NEVER PARSED BY SSH OR A KEY PROVIDER\n"
            key.write_bytes(key_bytes); key.chmod(0o600)
            key_inode = key.lstat().st_ino
            setting = "$" + "6$PUBLICsalt$" + "A" * 86
            global_file = project / "01-global.yaml"
            input_bytes = ('schema_version: 2\nswitches:\n- ib:\n    system:\n'
                '      aaa:\n        user:\n          admin:\n            password: "' + setting + '"\n').encode("utf-8")
            global_file.write_bytes(input_bytes); global_file.chmod(0o600)
            for path, mode in ((root, 0o700), (home, 0o700), (project, 0o700), (ssh_dir, 0o700),
                               (key, 0o600), (global_file, 0o600)):
                self.assertTrue(path == path.resolve() and path.lstat().st_uid == os.geteuid()
                                and stat.S_IMODE(path.lstat().st_mode) == mode,
                                "KG2 files must be canonical, owned and privately permissioned")
            self.assertTrue(root.parent == self._wp4_home, "KG2 uses only its explicit owned root")
            real_open = os.open

            def forbidden(*_args, **_kwargs):
                effects.append("forbidden-external")
                raise RuntimeError("FIXTURE HOLD: KG2 attempted an effect outside its PUBLIC reply model")

            def policy_open(value, flags, *args, **kwargs):
                self.assertTrue(args == () and kwargs == {} and Path(value).resolve() == global_file,
                                "KG2 permits only its own PUBLIC policy descriptor")
                self.assertEqual(os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, flags)
                return real_open(value, flags)

            def verify_pair(value, digest):
                self.assertTrue(type(value) is str and value in (PROJECT, FACTORY, CURRENT),
                                "KG2 verifier accepts only independent PUBLIC credential roles")
                self.assertTrue(type(digest) is str and digest == setting,
                                "KG2 real policy must consume its own PUBLIC hash shape")
                matched = value == PROJECT
                verified.append(matched)
                return matched

            def ask(hostname):
                self.assertTrue(hostname == HOST, "KG2 current prompt stays on the modeled device")
                asks.append("current")
                return CURRENT

            def interactive(argv, responder, timeout, **options):
                self.assertTrue(type(argv) is list and options == {}, "KG2 carrier has the ordinary IO signature")
                if argv[:1] != ["ssh"] or getattr(responder, "_phase", None) is not None:
                    raise RuntimeError("FIXTURE HOLD: KG2 does not simulate a private phase or unknown carrier")
                self.assertTrue(argv[-2] == "admin@203.0.113.2"
                                and getattr(responder, "ib_destination", None) == "admin@203.0.113.2",
                                "KG2 always starts and stays at its independent CSV IPv4 endpoint")
                self.assertTrue(all(option in argv for option in ("ProxyCommand=none", "ProxyJump=none",
                                    "ControlMaster=no", "ControlPath=none")),
                                "KG2 models only a closed direct, non-shared connection")
                if "-i" in argv:
                    self.assertTrue(argv.count("-i") == 1 and argv[argv.index("-i") + 1] == str(key),
                                    "KG2 uses only its explicitly supplied owned synthetic key")
                    for option in ("BatchMode=yes", "PreferredAuthentications=publickey",
                                   "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "IdentitiesOnly=yes"):
                        self.assertTrue(argv.count(option) == 1 and argv[argv.index(option) - 1] == "-o",
                                        "KG2 key requests remain explicitly key-only")
                    self.assertTrue("PubkeyAuthentication=no" not in argv
                                    and getattr(responder, "ib_default_password", None) is None,
                                    "KG2 key mode must not synthesize or substitute a password")
                    role = "key"
                else:
                    current = getattr(responder, "ib_default_password", None)
                    role = ("project" if current == PROJECT else "factory" if current == FACTORY
                            else "current" if current == CURRENT else None)
                    self.assertTrue(role is not None, "KG2 does not print or accept an unknown credential")
                    self.assertTrue("PubkeyAuthentication=no" in argv,
                                    "KG2 later credential requests must remain password-only")
                remote = shlex.split(argv[-1])
                self.assertTrue(len(remote) == 3 and remote[:2] == ["sh", "-c"],
                                "KG2 recognizes the original closed remote frame")
                found = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertEqual(1, len(found), "KG2 requires exactly one actual request nonce")
                nonce = found[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix) and remote[2].endswith(suffix),
                                "KG2 request framing stays closed")
                raw_command = remote[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(raw_command))
                self.assertTrue(command == tuple(READ) and raw_command == shlex.join(READ),
                                "KG2 supports only the independent NVUE authentication READ")
                requests.append((role, command))
                begin, end = "__HTTP_IB_BEGIN_" + nonce + "__\n", "__HTTP_IB_END_" + nonce + "__=0\n"
                good = begin + body + end
                if role != "key":
                    # Even illegal fallback remains a legal independent reply;
                    # terminal cases must fail their credential-flow assertion.
                    reply = app.SessionResult(good, 0)
                else:
                    prompt_values = {
                        "prompt-password": "admin@203.0.113.2's password: ",
                        "prompt-passphrase": "Enter passphrase for key '/PUBLIC/owned-key': ",
                        "prompt-pam": "(current) UNIX password: ",
                    }
                    if fault in prompt_values:
                        try:
                            answer = responder(prompt_values[fault])
                        except app.SetupError:
                            prompts.append((fault, "terminated"))
                            raise
                        prompts.append((fault, "no-string" if not isinstance(answer, str) else "string"))
                        self.assertFalse(isinstance(answer, str),
                                         "key no-input must never answer a password, passphrase or PAM prompt")
                    reply = app.SessionResult(good, 0)
                    if fault == "typed-denial":
                        reply = app.SessionResult("admin@203.0.113.2: Permission denied (publickey).\n", 255,
                                                  ib_authentication_rejected=True)
                    elif fault == "network":
                        reply = app.SessionResult("ssh: connect to host 203.0.113.2 port 22: Connection refused\n", 255)
                    elif fault == "host-key":
                        # Text only: no known_hosts file exists or editor runs.
                        warning_path = str(ssh_dir / "known_hosts")
                        warning = ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
                            "The fingerprint for the ED25519 key sent by the remote host is\n"
                            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
                            "Offending ED25519 key in " + warning_path + ":1\n"
                            "Host key for 203.0.113.2 has changed and you have requested strict checking.\n"
                            "  ssh-keygen -f " + shlex.quote(warning_path) + " -R 203.0.113.2\n"
                            "Host key verification failed.\n")
                        reply = app.SessionResult(warning, 255)
                    elif fault == "pam":
                        reply = app.SessionResult("PAM account management error: access denied\n", 255)
                    elif fault == "expiry":
                        reply = app.SessionResult(good + "You are required to change your password immediately.\n", 0)
                    elif fault == "cleanup":
                        reply.cleanup_uncertain = True
                    elif fault == "frame-missing":
                        reply = app.SessionResult(body, 0)
                    elif fault == "frame-duplicate":
                        reply = app.SessionResult(good + good, 0)
                    elif fault == "frame-status":
                        reply = app.SessionResult(begin + body + "__HTTP_IB_END_" + nonce + "__=9\n", 0)
                    elif fault == "update":
                        reply = app.SessionResult(good + ("passwd:" + " password updated successfully\n"), 0)
                    elif fault == "changed":
                        reply.password_changed = True
                    elif fault == "required":
                        reply.password_change_required = True
                    elif fault == "attempted":
                        reply.password_change_attempted = True
                    elif fault == "auth-conflict":
                        reply.ib_authentication_rejected = True
                    elif fault == "unknown":
                        reply = app.SessionResult("PUBLIC remote operation did not finish\n", 7)
                    elif fault == "auth-like":
                        # Auth-looking text without typed rejection qualification.
                        reply = app.SessionResult("admin@203.0.113.2: Permission denied (publickey).\n", 255)
                    elif fault in prompt_values:
                        reply = app.SessionResult(good + prompt_values[fault] + "\n", 0)
                replies.append(reply)
                return reply

            def observe(frame, event, _value):
                if event != "call" or frame.f_globals is not app.__dict__:
                    return
                if frame.f_code in codes:
                    entered[codes[frame.f_code]] += 1
                if frame.f_code is app.obtain_write_permit.__code__:
                    permits.append("write-permit")
                if frame.f_code in tail_codes:
                    tails.append(tail_codes[frame.f_code])

            denied_os = {name: forbidden for name in (
                "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe", "execl",
                "execlp", "execlpe", "posix_spawn", "posix_spawnp", "spawnl", "spawnle", "spawnlp",
                "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")}
            with ExitStack() as guard:
                guard.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
                guard.enter_context(mock.patch.object(builtins, "input", new=forbidden))
                guard.enter_context(mock.patch.object(app, "verify_password_hash", new=verify_pair))
                guard.enter_context(mock.patch.object(app, "subprocess", new=_Facade(
                    subprocess, run=forbidden, Popen=forbidden)))
                guard.enter_context(mock.patch.object(self._wp4_paths, "subprocess", new=_Facade(
                    subprocess, run=forbidden, Popen=forbidden)))
                guard.enter_context(mock.patch.object(app, "os", new=_Facade(os, open=policy_open, **denied_os)))
                guard.enter_context(mock.patch.object(app, "socket", new=_Facade(
                    socket, socket=forbidden, create_connection=forbidden)))
                guard.enter_context(mock.patch.object(app, "pty", new=_Facade(app.pty, fork=forbidden, openpty=forbidden)))
                guard.enter_context(mock.patch.object(app, "getpass", new=_Facade(app.getpass, getpass=forbidden)))
                guard.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
                guard.enter_context(mock.patch.object(app, "request_current_ib_password", new=ask))
                guard.enter_context(mock.patch.object(app, "log", new=lambda *_a, **_k: None))
                policy = app.ProjectPasswordPolicy(global_file, "admin", target_password=PROJECT, interactive=False)
                selected = policy.password()
                self.assertTrue(type(policy) is app.ProjectPasswordPolicy and selected == PROJECT
                                and policy._password == PROJECT and any(verified),
                                "KG2 uses the real policy qualification with an independent PUBLIC exact pair")
                try:
                    sys.setprofile(observe)
                    try:
                        login = app.inspect_ib_device(target, point, "", "", "admin", FACTORY, 5,
                            policy, apply=False, authorized=False, local=False, strict=False,
                            _management_private_key=key)
                    except app.SetupError as caught:
                        error = caught
                finally:
                    context_unchanged = app._TASK_IB_CONFIG is old_context
                    app._TASK_IB_CONFIG = old_context
                    sys.setprofile(old_profile)
                self.assertIs(old_profile, sys.getprofile())
                self.assertIs(old_context, app._TASK_IB_CONFIG)
                self.assertTrue(context_unchanged, "KG2 inspect must not install or change a writer context")
                policy.assert_unchanged()
                self.assertTrue(global_file.read_bytes() == input_bytes,
                                "KG2 must preserve its independent policy bytes")
                self.assertTrue(key.read_bytes() == key_bytes and not key.is_symlink()
                                and key.lstat().st_ino == key_inode,
                                "KG2 must preserve its explicit synthetic key")
                self.assertFalse((ssh_dir / "known_hosts").exists(),
                                 "KG2 host-key warnings are text only and cannot create an editor target")
            self.assertEqual([], effects, "KG2 must not execute a native worker or any real external effect")
        self.assertIs(old_profile, sys.getprofile())
        self.assertIs(old_context, app._TASK_IB_CONFIG)
        return SimpleNamespace(app=app, login=login, error=error, requests=requests, entered=entered,
            asks=asks, permits=permits, tails=tails, prompts=prompts, replies=replies, body=body)

    def test_kg2_only_typed_key_authentication_rejection_advances_credentials(self):
        cases = ("success", "typed-denial", "network", "host-key", "pam", "expiry", "cleanup",
                 "frame-missing", "frame-duplicate", "frame-status", "update", "changed", "required",
                 "attempted", "auth-conflict", "unknown", "auth-like",
                 "prompt-password", "prompt-passphrase", "prompt-pam")
        for fault in cases:
            with self.subTest(fault=fault):
                observed = self._kg2_public_auth_boundary(fault=fault)
                expected_roles = ("key", "project") if fault == "typed-denial" else ("key",)
                self.assertEqual([(role, tuple(READ)) for role in expected_roles], observed.requests,
                                 "only typed key denial may advance; terminal facts cannot try another credential")
                self.assertEqual({"inspect": 1, "auth": 1, "key-helper": 1,
                                  "builder": len(expected_roles)}, observed.entered)
                self.assertEqual([], observed.asks, "KG2 never exhausts known credentials or asks CURRENT")
                self.assertEqual([], observed.permits, "authentication reads cannot acquire a write permit")
                self.assertEqual([], observed.tails, "inspect alone must not enter execution, later stages or host-key repair")
                if fault.startswith("prompt-"):
                    self.assertTrue(len(observed.prompts) == 1 and observed.prompts[0][0] == fault
                                    and observed.prompts[0][1] in ("no-string", "terminated"),
                                    "key no-input must refuse this independent PUBLIC input prompt")
                    self.assertEqual(0 if observed.prompts[0][1] == "terminated" else 1,
                                     len(observed.replies), "an early no-input stop does not reach later reply validation")
                else:
                    self.assertEqual([], observed.prompts)
                    self.assertEqual(len(expected_roles), len(observed.replies),
                                     "each non-prompt fact must actually be delivered by the external model")
                if fault in ("success", "typed-denial"):
                    self.assertTrue(observed.error is None, "independent successful and typed-fallback positives must work")
                    self.assertTrue(type(observed.login) is tuple and len(observed.login) == 3,
                                    "real inspect returns its unchanged three-item ABI")
                    self.assertTrue(observed.login[0] is observed.replies[-1]
                                    and observed.login[0].output == observed.body,
                                    "success must return the actual independently framed session body")
                    self.assertTrue(observed.login[1] is None if fault == "success"
                                    else observed.login[1] == PROJECT,
                                    "only the actually authenticated project can replace unknown current")
                    self.assertIs(observed.login[2], False)
                else:
                    self.assertTrue(isinstance(observed.error, observed.app.SetupError),
                                    "a non-authentication fact must terminate as the original business error family")
                    self.assertFalse(isinstance(observed.error, observed.app.IBAuthenticationError),
                                     "terminal facts must not be relabeled as typed credential rejection")
                    self.assertTrue(observed.login is None, "terminal facts cannot yield a successful inspect login")
                    if fault == "host-key":
                        self.assertTrue(isinstance(observed.error, observed.app.SshFailure)
                                        and observed.error.kind is observed.app.SshFailureKind.TARGET_HOST_KEY_CHANGED
                                        and observed.error.address == "203.0.113.2",
                                        "a complete warning must keep its original endpoint-bound host-key fact")


    def _kg4_finite_key_channel(self, command, *, conflict=None, installer=False):
        """Ordinary finite read/builder boundary, no policy or private custody.

        Strict source qualification is deliberately outside this unit. Every
        request, even an incorrectly admitted forbidden vector, gets a complete
        external reply so zero-IO refusal is a business assertion, not a HOLD.
        """
        import base64
        from inspect import signature
        from test_cases.test_initial_setup_cable_check import _Facade

        app = self._wp4_app
        if (not callable(getattr(app, "_run_direct_key_read", None))
                or not callable(getattr(app, "direct_ssh_command", None))
                or "_key_file" not in signature(app.direct_ssh_command).parameters):
            raise RuntimeError("PREREQUISITE HOLD: KG4 finite key helper/builder API is unavailable")
        self.assertTrue(conflict in (None, "password-only", "private-phase"),
                        "KG4 requires one declared builder combination")
        self.assertTrue(type(installer) is bool and not (installer and conflict is not None),
                        "KG4 installer input construction is separate from builder conflicts")
        if installer and not callable(getattr(app, "key_install_command", None)):
            raise RuntimeError("PREREQUISITE HOLD: KG4 original installer input constructor is unavailable")
        self.assertTrue(type(command) is list and all(type(value) is str for value in command),
                        "KG4 command inputs are independent literal string vectors")
        original_command = list(command)
        target = app.Target(self._wp4_device(), None, "", "eth0", route=self._wp4_paths.Route(
            HOST, "direct", "NO_MGMT_LINK", None, None, None))
        point = app.DirectEndpoint("203.0.113.2", None)
        app._validate_direct_endpoint(target, point)
        old_profile, old_context = sys.getprofile(), app._TASK_IB_CONFIG
        requests, effects, permits, replies = [], [], [], []
        entered = {"helper": 0, "builder": 0}
        codes = {app._run_direct_key_read.__code__: "helper", app.direct_ssh_command.__code__: "builder"}
        body = {
            ("nv", "config", "show", "-o", "commands"): "nv set system hostname PUBLIC-IB01\n",
            ("ip", "addr", "show", "eth0"): IP_ADDR,
            ("ip", "route"): "default via 203.0.113.1 dev eth0\n",
            ("nv", "show", "system", "ztp"): "disabled\n",
        }.get(tuple(command), "PUBLIC KG4 forbidden execution would be observable\n")
        result = error = None
        with tempfile.TemporaryDirectory(prefix="kg4-public-", dir=self._wp4_home) as folder:
            root = Path(folder)
            home = root / "home"
            home.mkdir(mode=0o700)
            key = home / "explicit-public-key"
            key_bytes = b"PUBLIC KG4 SYNTHETIC FILE; NO KEY PARSER OR SSH CLIENT READS THIS\n"
            key.write_bytes(key_bytes); key.chmod(0o600)
            key_inode = key.lstat().st_ino
            for path, mode in ((root, 0o700), (home, 0o700), (key, 0o600)):
                self.assertTrue(path == path.resolve() and path.lstat().st_uid == os.geteuid()
                                and stat.S_IMODE(path.lstat().st_mode) == mode,
                                "KG4 uses only owned canonical private fixture files")
            self.assertTrue(root.parent == self._wp4_home, "KG4 has an explicit dynamic owned parent")

            def forbidden(*_args, **_kwargs):
                effects.append("forbidden-external")
                raise RuntimeError("FIXTURE HOLD: KG4 forbids effects outside its complete frame reply model")

            def interactive(argv, responder, timeout, **options):
                self.assertTrue(type(argv) is list and options == {}, "KG4 keeps the ordinary carrier signature")
                if argv[:1] != ["ssh"] or getattr(responder, "_phase", None) is not None:
                    raise RuntimeError("FIXTURE HOLD: KG4 does not fabricate private phase or unknown carrier success")
                self.assertTrue(argv[-2] == "admin@203.0.113.2"
                                and getattr(responder, "ib_destination", None) == "admin@203.0.113.2",
                                "KG4 actual request must bind its one independent IPv4 endpoint")
                self.assertTrue(argv.count("-i") == 1 and argv[argv.index("-i") + 1] == str(key),
                                "KG4 selects only the explicitly supplied owned synthetic key")
                for option in ("BatchMode=yes", "PreferredAuthentications=publickey",
                               "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "IdentitiesOnly=yes",
                               "ProxyCommand=none", "ProxyJump=none", "ControlMaster=no", "ControlPath=none"):
                    self.assertTrue(argv.count(option) == 1 and argv[argv.index(option) - 1] == "-o",
                                    "KG4 requires a closed key-only direct SSH vector")
                self.assertTrue(getattr(responder, "ib_default_password", None) is None,
                                "KG4 finite key reads cannot synthesize a current password")
                remote = shlex.split(argv[-1])
                self.assertTrue(len(remote) == 3 and remote[:2] == ["sh", "-c"],
                                "KG4 models the complete original remote frame only")
                found = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertEqual(1, len(found), "KG4 needs one actual nonce for request/reply correlation")
                nonce = found[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix) and remote[2].endswith(suffix),
                                "KG4 request must retain its complete closed framing")
                raw_command = remote[2][len(prefix):-len(suffix)]
                actual = tuple(shlex.split(raw_command))
                self.assertTrue(actual == tuple(original_command) and raw_command == shlex.join(original_command),
                                "KG4 returns independent replies for the exact requested input, not another vector")
                requests.append(actual)
                reply = app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + body
                    + "__HTTP_IB_END_" + nonce + "__=0\n", 0)
                replies.append(reply)
                return reply

            def observe(frame, event, _value):
                if event == "call" and frame.f_globals is app.__dict__:
                    if frame.f_code in codes:
                        entered[codes[frame.f_code]] += 1
                    if frame.f_code is app.obtain_write_permit.__code__:
                        permits.append("write-permit")

            denied_os = {name: forbidden for name in (
                "open", "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe", "execl",
                "execlp", "execlpe", "posix_spawn", "posix_spawnp", "spawnl", "spawnle", "spawnlp",
                "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")}
            with ExitStack() as guard:
                guard.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
                guard.enter_context(mock.patch.object(builtins, "input", new=forbidden))
                guard.enter_context(mock.patch.object(app, "subprocess", new=_Facade(
                    subprocess, run=forbidden, Popen=forbidden)))
                guard.enter_context(mock.patch.object(self._wp4_paths, "subprocess", new=_Facade(
                    subprocess, run=forbidden, Popen=forbidden)))
                guard.enter_context(mock.patch.object(app, "os", new=_Facade(os, **denied_os)))
                guard.enter_context(mock.patch.object(app, "socket", new=_Facade(
                    socket, socket=forbidden, create_connection=forbidden)))
                guard.enter_context(mock.patch.object(app, "pty", new=_Facade(app.pty, fork=forbidden, openpty=forbidden)))
                guard.enter_context(mock.patch.object(app, "getpass", new=_Facade(app.getpass, getpass=forbidden)))
                guard.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
                guard.enter_context(mock.patch.object(app, "log", new=lambda *_a, **_k: None))
                try:
                    sys.setprofile(observe)
                    try:
                        if installer:
                            # Real pure constructor supplies INPUT, not expected
                            # output: this channel must independently refuse it.
                            algorithm = b"ssh-ed25519"
                            wire = (len(algorithm).to_bytes(4, "big") + algorithm
                                    + (32).to_bytes(4, "big") + bytes([41]) * 32)
                            public_line = ("ssh-ed25519 " + base64.b64encode(wire).decode("ascii")
                                           + " PUBLIC-KG4")
                            fingerprint = ("SHA256:" + base64.b64encode(hashlib.sha256(wire).digest())
                                           .rstrip(b"=").decode("ascii"))
                            try:
                                command = app.key_install_command([{"name": "PUBLIC-KG4.pub",
                                    "line": public_line, "fingerprint": fingerprint}])
                            except app.SetupError:
                                raise RuntimeError("FIXTURE HOLD: KG4 PUBLIC installer input did not qualify") from None
                            self.assertTrue(type(command) is list and len(command) == 5
                                            and command[:2] == ["sh", "-c"] and command[3] == "--"
                                            and app.ib_command_argv(command) == command,
                                            "the original pure installer constructs a valid global input only")
                            original_command = list(command)
                        if conflict is None:
                            result = app._run_direct_key_read(target, point, "admin", key, 5,
                                                             command, strict=False, policy=None)
                        else:
                            options = ({"password_only": True} if conflict == "password-only"
                                       else {"_phase": object()})
                            result = app.direct_ssh_command(target, point, "admin", 5, command,
                                                            _key_file=key, **options)
                    except app.SetupError as caught:
                        error = caught
                finally:
                    context_unchanged = app._TASK_IB_CONFIG is old_context
                    app._TASK_IB_CONFIG = old_context
                    sys.setprofile(old_profile)
                self.assertTrue(context_unchanged, "KG4 may not install a writer context")
                self.assertIs(old_profile, sys.getprofile())
                self.assertTrue(key.read_bytes() == key_bytes and not key.is_symlink()
                                and key.lstat().st_ino == key_inode,
                                "KG4 preserves its explicit owned synthetic key")
                self.assertTrue(command == original_command, "KG4 may not rewrite the independent command input")
            self.assertEqual([], effects, "KG4 must not run any native worker or real external command")
        self.assertIs(old_context, app._TASK_IB_CONFIG)
        self.assertIs(old_profile, sys.getprofile())
        return SimpleNamespace(app=app, result=result, error=error, requests=requests,
            permits=permits, entered=entered, replies=replies, body=body, point=point)

    def test_kg4_key_channel_executes_only_the_four_independent_read_vectors(self):
        reads = (
            ["nv", "config", "show", "-o", "commands"],
            ["ip", "addr", "show", "eth0"],
            ["ip", "route"],
            ["nv", "show", "system", "ztp"],
        )
        for command in reads:
            with self.subTest(read=command[0:3]):
                observed = self._kg4_finite_key_channel(command)
                self.assertTrue(observed.error is None, "each independent finite read must really complete")
                self.assertEqual([tuple(command)], observed.requests)
                self.assertEqual({"helper": 1, "builder": 1}, observed.entered)
                self.assertEqual([], observed.permits)
                self.assertTrue(len(observed.replies) == 1 and observed.result is observed.replies[0]
                                and type(observed.result) is observed.app.SessionResult
                                and observed.result.output == observed.body and observed.result.exit_code == 0,
                                "finite reads return the actual complete independently framed SessionResult")
                self.assertTrue(observed.result._direct_endpoint == observed.point,
                                "the helper must preserve the actual admitted IPv4 point")

    def test_kg4_key_channel_refuses_nonfinite_vectors_and_conflicting_builder_modes(self):
        stamp = "20261117-120000"
        refused = (
            ("true", ["true"]),
            ("readonly-rc", ["sh", "-c", EXPECTED_READ_RC_SCRIPT, "--", stamp]),
            ("nvue-set", ["nv", "set", "system", "hostname", HOST]),
            ("nvue-apply", ["nv", "config", "apply", "-y"]),
            ("nvue-save", ["nv", "config", "save"]),
            ("nvue-replace", ["nv", "config", "replace", "/PUBLIC/owned-plan.yaml"]),
            ("backup", ["sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", stamp]),
            ("deferred-apply", ["sh", "-c", EXPECTED_LAUNCH_SCRIPT, "--", stamp]),
            ("key-install", []),  # Constructed as input inside the hard guards.
            ("arbitrary-cat", ["cat", "/PUBLIC/not-a-key-or-secret"]),
        )
        for label, command in refused:
            with self.subTest(refused=label):
                if label in ("true", "readonly-rc"):
                    self.assertTrue(self._wp4_app.ib_command_argv(command) == command,
                                    "independently specified global readonly positives remain outside this finite key channel")
                observed = self._kg4_finite_key_channel(command, installer=label == "key-install")
                self.assertEqual([], observed.requests, "a nonfinite vector must stop before the first SSH read")
                self.assertEqual([], observed.replies)
                self.assertEqual([], observed.permits)
                self.assertTrue(observed.entered["helper"] == 1,
                                "the actual finite helper, not just a classifier, must be exercised")
                self.assertTrue(isinstance(observed.error, observed.app.SetupError)
                                and not isinstance(observed.error, observed.app.IBAuthenticationError)
                                and observed.result is None,
                                "nonfinite input must be an original business refusal, not successful login or typed auth denial")
        for conflict in ("password-only", "private-phase"):
            with self.subTest(conflict=conflict):
                observed = self._kg4_finite_key_channel(
                    ["nv", "config", "show", "-o", "commands"], conflict=conflict)
                self.assertEqual({"helper": 0, "builder": 1}, observed.entered)
                self.assertEqual([], observed.requests)
                self.assertEqual([], observed.replies)
                self.assertEqual([], observed.permits)
                self.assertTrue(isinstance(observed.error, observed.app.SetupError)
                                and observed.result is None,
                                "explicit key plus password-only or any private phase must be rejected, never fabricated custody")


    @contextmanager
    def _kg3_public_no_global_world(self, *, apply=False):
        """Independent no-global IO, real execute/stages, no fabricated permit.

        Unit callers may install a real context as a declared prerequisite;
        only the separate actual execute case credits its real O5 admission.
        """
        from inspect import signature
        from test_cases.test_initial_setup_cable_check import _Facade

        app = self._wp4_app
        required = ("execute_ib_task", "_readonly_key_file", "_IBConfigWriteState", "_run_direct_key_read")
        consumers = ("_stage_ib_command", "run_initial_stage", "run_service_stage", "run_key_stage")
        if (any(not callable(getattr(app, name, None)) for name in required + consumers)
                or any("_ib_read_context" not in signature(getattr(app, name)).parameters for name in consumers)
                or not {"task", "ib_user", "apply", "endpoint", "current_password", "identity_verified", "readonly_key_file"}
                    .issubset(getattr(app._IBConfigWriteState, "__dataclass_fields__", {}))):
            raise RuntimeError("PREREQUISITE HOLD: KG3 actual key context/consumer API is unavailable")
        target = app.Target(self._wp4_device(), None, "", "eth0", route=self._wp4_paths.Route(
            HOST, "direct", "NO_MGMT_LINK", None, None, None))
        point = app.DirectEndpoint("203.0.113.2", None)
        task = app.PreparedIBTask(target, point, "", False)
        args = SimpleNamespace(eth_user="", ib_user="admin", connect_timeout=5, apply=apply,
            yes=True, force=False, run_stamp="20261117-120000", execution_mode="management",
            _on_management_server=True)
        coordinator = app.RuntimeCoordinator(args, None, FACTORY, [task], app.RuntimeInputAuthority([]))
        coordinator.current_target = target
        requests, effects, asks, permits, snapshots, replies = ([] for _ in range(6))
        watched = ("execute_ib_task", "inspect_ib_device", "_authenticate_ib_read", "_run_direct_key_read",
            "_readonly_key_file", "_stage_ib_command", "run_on_ib", "run_initial_stage", "run_service_stage",
            "run_key_stage", "_ensure_ib_config_backup", "run_management_direct_checks",
            "verify_management_direct_ssh", "_ib_project_value")
        entered = {name: 0 for name in watched}
        codes = {getattr(app, name).__code__: name for name in watched}
        body = (READY + ADDRESS0 + GATEWAY0 + "nv set system config auto-save state enabled\n"
                + "nv set system ztp config-save enabled\n")
        old_profile, old_context = sys.getprofile(), app._TASK_IB_CONFIG
        with tempfile.TemporaryDirectory(prefix="kg3-public-", dir=self._wp4_home) as folder:
            root = Path(folder)
            home, project = root / "home", root / "project"
            home.mkdir(mode=0o700); project.mkdir(mode=0o700)
            key, alternate = home / "explicit-public-key", home / "alternate-public-key"
            key_bytes = b"PUBLIC KG3 SYNTHETIC FILE; NEVER PASSED TO A KEY PARSER OR REAL SSH\n"
            for path in (key, alternate):
                path.write_bytes(key_bytes); path.chmod(0o600)
            self.assertFalse((project / "01-global.yaml").exists(), "KG3 starts with genuinely absent global input")
            for path, mode in ((root, 0o700), (home, 0o700), (project, 0o700), (key, 0o600), (alternate, 0o600)):
                self.assertTrue(path == path.resolve() and path.lstat().st_uid == os.geteuid()
                                and stat.S_IMODE(path.lstat().st_mode) == mode,
                                "KG3 fixtures must be canonical, owned and privately permissioned")

            def forbidden(*_args, **_kwargs):
                effects.append("forbidden-external")
                raise RuntimeError("FIXTURE HOLD: KG3 forbids native, provider or real external effects")

            def ask_current(_hostname):
                asks.append("current")
                return CURRENT

            def ask_initial(*_args, **_kwargs):
                asks.append("initial")
                return FACTORY

            def interactive(argv, responder, timeout, **options):
                self.assertTrue(type(argv) is list and options == {}, "KG3 uses the ordinary complete reply boundary")
                if argv[:1] != ["ssh"] or getattr(responder, "_phase", None) is not None:
                    raise RuntimeError("FIXTURE HOLD: KG3 cannot fabricate private phase custody or unknown carriers")
                self.assertTrue(argv[-2] in ("admin@203.0.113.2", "observer@203.0.113.2")
                                and getattr(responder, "ib_destination", None) == argv[-2],
                                "KG3 replies only to its declared PUBLIC endpoint/accounts")
                if "-i" in argv:
                    self.assertTrue(argv.count("-i") == 1 and argv[argv.index("-i") + 1] == str(key),
                                    "KG3 uses only its explicit synthetic key path")
                    for option in ("BatchMode=yes", "PreferredAuthentications=publickey",
                                   "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "IdentitiesOnly=yes"):
                        self.assertTrue(argv.count(option) == 1 and argv[argv.index(option) - 1] == "-o",
                                        "KG3 key requests remain key-only")
                    self.assertTrue(getattr(responder, "ib_default_password", None) is None,
                                    "key mode cannot invent current credentials")
                    role = "key"
                else:
                    value = getattr(responder, "ib_default_password", None)
                    role = ("current" if value == CURRENT else "factory" if value == FACTORY
                            else "project" if value == PROJECT else "absent" if value is None
                            else "empty" if value == "" else None)
                    # An illegal absent/empty-password attempt still gets a
                    # safe reply: zero-IO/role assertions must detect it.
                    self.assertTrue(role is not None, "KG3 models only declared PUBLIC or deliberately absent credential roles")
                remote = shlex.split(argv[-1])
                self.assertTrue(len(remote) == 3 and remote[:2] == ["sh", "-c"],
                                "KG3 models the original closed remote frame only")
                found = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertEqual(1, len(found), "KG3 needs one actual request nonce")
                nonce = found[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix) and remote[2].endswith(suffix))
                raw_command = remote[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(raw_command))
                self.assertTrue(raw_command == shlex.join(command), "KG3 command vector must remain canonical")
                requests.append((role, command))
                output = {tuple(READ): body, ("ip", "addr", "show", "eth0"): IP_ADDR,
                    ("ip", "route"): "default via 203.0.113.1 dev eth0\n",
                    ("nv", "show", "system", "ztp"): "service disabled\nstate disabled\n",
                    ("true",): ""}.get(command, "")
                if command == ("sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", args.run_stamp):
                    output = "path=/home/PUBLIC/current_" + args.run_stamp + ".yaml\nbytes=7\n"
                reply = app.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + output
                    + "__HTTP_IB_END_" + nonce + "__=0\n", 0)
                replies.append(reply)
                return reply

            def observe(frame, event, _value):
                if event != "call" or frame.f_globals is not app.__dict__:
                    return
                name = codes.get(frame.f_code)
                if name is not None:
                    entered[name] += 1
                if frame.f_code is app.obtain_write_permit.__code__:
                    permits.append("write-permit")
                if name == "run_initial_stage":
                    context = frame.f_locals.get("_ib_read_context")
                    snapshots.append({
                        "exact_state": type(context) is app._IBConfigWriteState,
                        "installed": context is app._TASK_IB_CONFIG,
                        "same_task": getattr(context, "task", None) is task,
                        "same_target": getattr(getattr(context, "task", None), "target", None) is target,
                        "user": getattr(context, "ib_user", None) == "admin",
                        "point": getattr(context, "endpoint", None) == point,
                        "identity": getattr(context, "identity_verified", None) is True,
                        "readonly": getattr(context, "apply", None) is False,
                        "current_none": getattr(context, "current_password", "absent") is None
                                        and frame.f_locals.get("ib_password", "absent") is None,
                        "key": getattr(context, "readonly_key_file", None) == key,
                    })

            denied_os = {name: forbidden for name in (
                "open", "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe", "execl",
                "execlp", "execlpe", "posix_spawn", "posix_spawnp", "spawnl", "spawnle", "spawnlp",
                "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")}
            with ExitStack() as guard:
                guard.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
                guard.enter_context(mock.patch.object(builtins, "input", new=forbidden))
                guard.enter_context(mock.patch.object(app, "subprocess", new=_Facade(subprocess, run=forbidden, Popen=forbidden)))
                guard.enter_context(mock.patch.object(self._wp4_paths, "subprocess", new=_Facade(subprocess, run=forbidden, Popen=forbidden)))
                guard.enter_context(mock.patch.object(app, "os", new=_Facade(os, **denied_os)))
                guard.enter_context(mock.patch.object(app, "socket", new=_Facade(socket, socket=forbidden, create_connection=forbidden)))
                guard.enter_context(mock.patch.object(app, "pty", new=_Facade(app.pty, fork=forbidden, openpty=forbidden)))
                guard.enter_context(mock.patch.object(app, "getpass", new=_Facade(app.getpass, getpass=forbidden)))
                guard.enter_context(mock.patch.object(app, "verify_password_hash", new=forbidden))
                guard.enter_context(mock.patch.object(app, "request_current_ib_password", new=ask_current))
                guard.enter_context(mock.patch.object(app, "_hidden_password_timeout", new=ask_initial))
                guard.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
                guard.enter_context(mock.patch.object(app, "_ACTIVE_COORDINATOR", coordinator))
                guard.enter_context(mock.patch.object(app, "log", new=lambda *_a, **_k: None))
                try:
                    sys.setprofile(observe)
                    yield SimpleNamespace(app=app, target=target, point=point, task=task, args=args,
                        coordinator=coordinator, key=key, alternate=alternate, body=body, requests=requests,
                        entered=entered, asks=asks, permits=permits, snapshots=snapshots, replies=replies,
                        previous_context=old_context)
                finally:
                    app._TASK_IB_CONFIG = old_context
                    sys.setprofile(old_profile)
                self.assertFalse((project / "01-global.yaml").exists(), "KG3 must not manufacture a project global")
            self.assertEqual([], effects, "KG3 cannot execute native, provider, subprocess or network effects")
        self.assertIs(old_context, app._TASK_IB_CONFIG)
        self.assertIs(old_profile, sys.getprofile())

    def test_kg3_no_global_readonly_key_runs_real_identity_initial_and_empty_stages(self):
        with self._kg3_public_no_global_world() as world:
            record = world.app.execute_ib_task(world.task, world.args, None, FACTORY, None, [], world.key)
            self.assertIs(world.previous_context, world.app._TASK_IB_CONFIG,
                          "the actual execute must restore context before fixture cleanup")
            self.assertTrue(type(record) is dict and record["outcome"] == "ALREADY_CONFIGURED",
                            "no-global readonly key access must complete its real preconfigured pipeline")
            self.assertEqual([("key", tuple(READ)), ("key", ("ip", "addr", "show", "eth0")),
                ("key", ("ip", "route")), ("key", ("nv", "show", "system", "ztp"))], world.requests)
            self.assertEqual([{name: True for name in ("exact_state", "installed", "same_task", "same_target", "user",
                "point", "identity", "readonly", "current_none", "key")}], world.snapshots,
                "only actual O5 followed by Initial may witness this task-bound readonly admission")
            for name in ("execute_ib_task", "inspect_ib_device", "_authenticate_ib_read", "run_initial_stage",
                         "run_service_stage", "run_key_stage"):
                self.assertEqual(1, world.entered[name])
            self.assertTrue(record["identity"]["ok"] and record["identity"]["via_ipv4"])
            self.assertFalse(record["writes_attempted"])
            self.assertIsNone(record["backup"])
            self.assertEqual("CHECKED", record["stage_status"]["initial"])
            self.assertEqual("NOT_CONFIGURED", record["stage_status"]["services"])
            self.assertEqual("NO_KEYS_PROVIDED", record["stage_status"]["public_keys"])
            self.assertIn(record["stage_status"]["direct_ssh"], ("NOT_REACHED", "NOT_TESTED"),
                          "without a selected current, an unrun final password check cannot be VERIFIED")
            self.assertEqual([], world.asks)
            self.assertEqual([], world.permits)
            self.assertFalse(world.coordinator.writes_attempted)
            for name in ("run_on_ib", "_ensure_ib_config_backup", "run_management_direct_checks",
                         "verify_management_direct_ssh", "_ib_project_value"):
                self.assertEqual(0, world.entered[name])

    def test_kg3_no_global_key_apply_stops_without_project_password_or_later_stages(self):
        with self._kg3_public_no_global_world(apply=True) as world:
            record = world.app.execute_ib_task(world.task, world.args, None, FACTORY, None, [], world.key)
            self.assertIs(world.previous_context, world.app._TASK_IB_CONFIG,
                          "the failed actual execute must also restore context before fixture cleanup")
            self.assertTrue(type(record) is dict and record["outcome"] == "FAILED"
                            and record["failed_stage"] == "authentication",
                            "key access alone cannot authorize apply without a verified project password")
            self.assertEqual([("key", tuple(READ))], world.requests)
            self.assertEqual("FAILED", record["stage_status"]["authentication"])
            for stage in ("initial", "day0", "ipv4_readiness", "services", "public_keys", "direct_ssh"):
                self.assertEqual("NOT_REACHED", record["stage_status"][stage])
            self.assertIsNone(record["identity"])
            self.assertIsNone(record["backup"])
            self.assertFalse(record["writes_attempted"])
            self.assertFalse(world.coordinator.writes_attempted)
            self.assertEqual([], world.asks)
            self.assertEqual([], world.permits)
            self.assertEqual([], world.snapshots)
            for name in ("run_on_ib", "run_initial_stage", "run_service_stage", "run_key_stage",
                         "_ensure_ib_config_backup", "run_management_direct_checks", "verify_management_direct_ssh"):
                self.assertEqual(0, world.entered[name])

    def test_kg3_readonly_context_refusals_preserve_the_default_password_read(self):
        variants = ("valid", "default-password", "foreign", "copy", "not-current", "other-task-target",
            "other-target", "other-user", "state-endpoint", "identity", "state-apply", "task-local",
            "caller-local", "state-current", "explicit-current", "empty-current", "missing-key", "linked-key",
            "no-key", "no-context", "stage-write", "stage-backup", "backup",
            "initial-valid", "services-valid", "keys-valid", "initial-apply", "services-apply", "keys-apply")
        for variant in variants:
            with self.subTest(context=variant):
                with self._kg3_public_no_global_world() as world:
                    app, target, point = world.app, world.target, world.point
                    state = app._IBConfigWriteState(world.task, "admin", "", world.args.run_stamp, False,
                        endpoint=point, current_password=None, identity_verified=True, readonly_key_file=world.key)
                    app._TASK_IB_CONFIG = state
                    context, current, user, local, applying = state, None, "admin", False, False
                    command = ["nv", "show", "system", "ztp"]
                    if variant == "default-password":
                        context, current, command = None, CURRENT, list(READ)
                    elif variant == "foreign":
                        context = SimpleNamespace(**vars(state))
                    elif variant == "copy":
                        context = app.replace(state)
                    elif variant == "not-current":
                        app._TASK_IB_CONFIG = None
                    elif variant == "other-task-target":
                        state.task = app.PreparedIBTask(app.replace(target), point, "", False)
                    elif variant == "other-target":
                        target = app.replace(target)
                    elif variant == "other-user":
                        user = "observer"
                    elif variant == "state-endpoint":
                        state.endpoint = app.DirectEndpoint("203.0.113.99", None)
                    elif variant == "identity":
                        state.identity_verified = False
                    elif variant == "state-apply":
                        state.apply = True
                    elif variant == "task-local":
                        state.task = app.replace(world.task, local=True)
                    elif variant == "caller-local":
                        local = True
                    elif variant == "state-current":
                        state.current_password = CURRENT
                    elif variant == "explicit-current":
                        current = CURRENT
                    elif variant == "empty-current":
                        current = ""
                    elif variant == "missing-key":
                        world.key.unlink()
                    elif variant == "linked-key":
                        world.key.unlink(); world.key.symlink_to(world.alternate)
                    elif variant == "no-key":
                        state.readonly_key_file = None
                    elif variant == "no-context":
                        context = None
                    elif variant == "stage-write":
                        command = ["nv", "set", "system", "hostname", HOST]
                    elif variant == "stage-backup":
                        command = ["sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", world.args.run_stamp]
                    if variant in ("initial-apply", "services-apply", "keys-apply"):
                        applying = True
                    installed_before = app._TASK_IB_CONFIG
                    result = error = None
                    try:
                        if variant.startswith("initial-"):
                            result = app.run_initial_stage(target, point, "", "", user, 5, world.body,
                                local=local, apply=applying, authorized=False, ib_password=current,
                                _ib_read_context=context)
                        elif variant.startswith("services-"):
                            result = app.run_service_stage(target, point, "", "", user, 5, None, world.body,
                                local=local, apply=applying, authorized=False, ib_password=current,
                                _ib_read_context=context)
                        elif variant.startswith("keys-"):
                            result = app.run_key_stage(target, point, "", "", user, 5, [], local=local,
                                apply=applying, authorized=False, ib_password=current, _ib_read_context=context)
                        elif variant == "backup":
                            result = app._ensure_ib_config_backup(target, point, "", "", user, current, 5, local=local)
                        else:
                            result = app._stage_ib_command(target, point, "", "", user, current, 5, command,
                                local=local, strict=False, policy=None, _ib_read_context=context)
                    except app.SetupError as caught:
                        error = caught
                    self.assertIs(installed_before, app._TASK_IB_CONFIG,
                                  "a context consumer cannot replace the installed task context")
                    positive = variant in ("valid", "default-password", "initial-valid", "services-valid", "keys-valid")
                    if positive:
                        self.assertTrue(error is None, "legal readonly and original default password callers must succeed")
                        expected = ([] if variant in ("services-valid", "keys-valid") else
                                    [("current", tuple(READ))] if variant == "default-password" else
                                    [("key", ("nv", "show", "system", "ztp"))])
                        self.assertEqual(expected, world.requests)
                        if variant == "default-password":
                            self.assertEqual(0, world.entered["_run_direct_key_read"])
                            self.assertEqual(1, world.entered["run_on_ib"])
                            self.assertTrue(result is world.replies[0] and result.output == world.body,
                                            "default CURRENT must use the real old password read, not a key substitute")
                        elif variant == "valid":
                            self.assertTrue(result is world.replies[0] and result.output == "service disabled\nstate disabled\n")
                        elif variant == "initial-valid":
                            self.assertEqual((world.body, False), result)
                        elif variant == "services-valid":
                            self.assertEqual((False, True), result)
                        else:
                            self.assertIs(result, False)
                    else:
                        self.assertTrue(isinstance(error, app.SetupError) and not isinstance(error, app.IBAuthenticationError)
                                        and result is None, "invalid explicit context must stop as an original business refusal")
                        self.assertEqual([], world.requests, "invalid context or readonly write cannot reach the first SSH")
                    self.assertEqual([], world.asks)
                    self.assertEqual([], world.permits)
                    self.assertFalse(world.coordinator.writes_attempted)
                    self.assertTrue(state.backup_state != "VERIFIED" and state.backup_receipt is None,
                                    "a readonly context cannot fabricate a verified backup receipt")



    @contextmanager
    def _v6_public_fresh_point(self, *, fault=None, metadata=None):
        """Real O6(b) reads with PUBLIC wire replies, never a write authority.

        metadata is an explicitly separate inspect-consumer fault model: a
        delegate first completes the real fresh read, then changes only its
        returned endpoint. No wire frame can forge that producer-owned field.
        """
        from test_cases.test_initial_setup_cable_check import _Facade

        app, paths = self._wp4_app, self._wp4_paths
        watched = ("execute_ib_task", "inspect_ib_device", "_authenticate_ib_read",
            "_run_direct_key_read", "_stage_ib_command", "run_initial_stage",
            "run_service_stage", "run_key_stage", "_ensure_ib_config_backup",
            "run_management_direct_checks", "verify_management_direct_ssh", "obtain_write_permit")
        if any(not callable(getattr(app, name, None)) for name in watched):
            raise RuntimeError("PREREQUISITE HOLD: V6 actual key/apply/read pipeline is unavailable")
        allowed_faults = (None, "auth", "exit-one", "missing-end", "duplicate-begin", "wrong-nonce",
            "cleanup", "password_changed", "password_change_required", "password_change_attempted",
            "ib_authentication_rejected")
        self.assertIn(fault, allowed_faults)
        self.assertIn(metadata, (None, "unchanged", "missing", "foreign", "old-ll"))
        self.assertFalse(fault is not None and metadata is not None, "one independent fault per world")
        with tempfile.TemporaryDirectory(prefix="v6-public-", dir=self._wp4_home) as folder:
            root = Path(folder)
            project, home = root / "project", root / "home"
            project.mkdir(mode=0o700); home.mkdir(mode=0o700)
            key = home / "explicit-public-key"
            key_bytes = b"PUBLIC V6 SYNTHETIC FILE; NO REAL SSH OR KEY PARSER\n"
            key.write_bytes(key_bytes); key.chmod(0o600)
            global_file = project / "01-global.yaml"
            setting = "$" + "6$PUBLICsalt$" + "A" * 86
            global_bytes = ('schema_version: 2\nswitches:\n- ib:\n    system:\n'
                '      aaa:\n        user:\n          admin:\n            password: "'
                + setting + '"\n').encode("utf-8")
            global_file.write_bytes(global_bytes); global_file.chmod(0o600)
            for path, mode in ((root, 0o700), (project, 0o700), (home, 0o700),
                               (key, 0o600), (global_file, 0o600)):
                info = path.lstat()
                self.assertTrue(path == path.resolve() and info.st_uid == os.geteuid()
                                and stat.S_IMODE(info.st_mode) == mode,
                                "V6 uses only canonical owned PUBLIC inputs")
            target = app.Target(app.Device("PUBLIC-IB01", "ib", "203.0.113.2",
                "203.0.113.2/24", "203.0.113.1", "02:00:00:00:00:17", "", ""),
                None, "", "eth0", route=paths.Route("PUBLIC-IB01", "direct", "NO_MGMT_LINK",
                                                    None, None, "en-public7"))
            point = app.DirectEndpoint("fe80::ff:fe00:17", "en-public7")
            ipv4 = app.DirectEndpoint("203.0.113.2", None)
            app._validate_direct_endpoint(target, point)
            app._validate_direct_endpoint(target, ipv4)
            task = app.PreparedIBTask(target, point, "", False)
            args = SimpleNamespace(eth_user="", ib_user="admin", connect_timeout=2, apply=True,
                yes=True, force=False, run_stamp="20261117-160000", execution_mode="management",
                _on_management_server=True)
            # Independent complete NVUE bodies differ only in an unrelated
            # service. Neither body is generated by a product parser/builder.
            body_a = ("nv set system hostname PUBLIC-IB01\n"
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0 ipv4 gateway 203.0.113.1\n"
                "nv set interface eth0-1 link state up\nnv set interface eth0-1 type eth\n"
                "nv set system config auto-save state enabled\nnv set system ztp config-save enabled\n"
                "nv set service lldp state enabled\n")
            body_b = ("nv set system hostname PUBLIC-IB01\n"
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0 ipv4 gateway 203.0.113.1\n"
                "nv set interface eth0-1 link state up\nnv set interface eth0-1 type eth\n"
                "nv set system config auto-save state enabled\nnv set system ztp config-save enabled\n"
                "nv set service lldp state disabled\n")
            requests, controls, order, asks, effects, permits = ([] for _ in range(6))
            verified, inspected, initial, edits = ([] for _ in range(4))
            replies = {}
            entered = {name: 0 for name in watched}
            depth = {"inspect_ib_device": 0, "verify_management_direct_ssh": 0}
            real_stage = app._stage_ib_command
            codes = {getattr(app, name).__code__: name for name in watched}
            old_profile, old_context = sys.getprofile(), app._TASK_IB_CONFIG

            def forbidden(*_args, **_kwargs):
                effects.append("forbidden-external")
                raise RuntimeError("FIXTURE HOLD: V6 forbids real external/native/provider effects")

            def verify(value, digest):
                self.assertTrue(type(value) is str and value in (PROJECT, FACTORY, CURRENT)
                                and type(digest) is str and digest == setting,
                                "V6 verifier only binds independent PUBLIC roles and hash shape")
                matched = value == PROJECT
                verified.append(matched)
                return matched

            def open_global(path, flags, *extra, **options):
                self.assertTrue(Path(path) == global_file and path == global_file.resolve()
                                and flags == (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                                and not extra and not options,
                                "real policy may open only this owned PUBLIC global with its original readonly flags")
                return os.open(path, flags)

            def control(argv, **options):
                if argv != ["ip", "-4", "neigh", "show", "203.0.113.2"]:
                    forbidden()
                self.assertEqual({"capture_output": True, "text": True, "timeout": 2, "check": False}, options)
                controls.append(tuple(argv)); order.append(("neighbor",))
                return subprocess.CompletedProcess(argv, 0,
                    "203.0.113.2 dev en-public7 lladdr 02:00:00:00:00:17 REACHABLE\n", "")

            def ask(_hostname):
                asks.append("current")
                return CURRENT  # wrong advancement remains observable, not a fixture denial

            def interactive(argv, responder, timeout, **options):
                self.assertTrue(type(argv) is list and argv[:1] == ["ssh"] and options == {},
                                "V6 admits only its ordinary direct SSH frame carrier")
                self.assertIsNone(getattr(responder, "_phase", None), "no fabricated phase custody")
                destinations = {"admin@fe80::ff:fe00:17%en-public7": "ll", "admin@203.0.113.2": "ipv4"}
                self.assertTrue(argv[-2] in destinations, "only the two independently admitted PUBLIC points")
                lane = destinations[argv[-2]]
                self.assertEqual(argv[-2], responder.ib_destination)
                self.assertIn("-6" if lane == "ll" else "-4", argv)
                for option in ("ProxyCommand=none", "ProxyJump=none", "ControlMaster=no", "ControlPath=none"):
                    self.assertTrue(argv.count(option) == 1 and argv[argv.index(option) - 1] == "-o",
                                    "direct IO cannot acquire an outer/shared transport")
                if "-i" in argv:
                    self.assertTrue(argv.count("-i") == 1 and argv[argv.index("-i") + 1] == str(key),
                                    "V6 key input is the sole owned synthetic file")
                    for option in ("BatchMode=yes", "PreferredAuthentications=publickey",
                                   "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "IdentitiesOnly=yes"):
                        self.assertTrue(argv.count(option) == 1 and argv[argv.index(option) - 1] == "-o",
                                        "the actual first request must be key-only")
                    self.assertIsNone(getattr(responder, "ib_default_password", None))
                    self.assertIsNone(responder("PUBLIC response needing no input"))
                    role = "key"
                else:
                    self.assertIs(type(responder), app._DirectResponder if not depth["verify_management_direct_ssh"]
                                  else app.NestedResponder)
                    value = responder.ib_default_password
                    role = ("project" if value == PROJECT else "factory" if value == FACTORY
                            else "current" if value == CURRENT else None)
                    self.assertIsNotNone(role, "password IO retains a distinct independent PUBLIC role")
                remote = shlex.split(argv[-1])
                self.assertTrue(len(remote) == 3 and remote[:2] == ["sh", "-c"], "closed direct remote frame only")
                found = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                self.assertEqual(1, len(found))
                nonce = found[0]
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(remote[2].startswith(prefix) and remote[2].endswith(suffix), "complete independent frame grammar")
                text = remote[2][len(prefix):-len(suffix)]
                command = tuple(shlex.split(text))
                self.assertEqual(text, shlex.join(command))
                # U4 (v3.1.6 D1d, guide 8.11): the closed Linux hostname read is a modelled reply too.
                if command not in (tuple(READ), ("true",), ("ip", "addr", "show", "eth0"),
                                   ("ip", "route"), ("nv", "show", "system", "ztp"), ("hostname",)):
                    forbidden()
                scope = ("inspect" if depth["inspect_ib_device"] else
                         "final" if depth["verify_management_direct_ssh"] else "stage")
                request = (role, lane, command, scope)
                requests.append(request); order.append(request)
                if command == ("true",) or scope == "final":
                    self.assertNotIn("-i", argv)
                    for option in ("PubkeyAuthentication=no", "PreferredAuthentications=password,keyboard-interactive"):
                        self.assertTrue(argv.count(option) == 1 and argv[argv.index(option) - 1] == "-o",
                                        "O6 true/final retain real password-only authentication")
                # A fresh ordinary READ deliberately retains original ordinary
                # options; no new blanket ban on key negotiation is invented.
                if command == ("true",) and role == "project" and lane == "ll":
                    self.assertEqual(60, timeout)
                    result = app.SessionResult("ssh: connect to host fe80::ff:fe00:17%en-public7 port 22: "
                                               "Network is unreachable\n", 255)
                    replies["network"] = result
                    return result
                output = {tuple(READ): body_a if role == "key" else body_b,
                    ("true",): "", ("ip", "addr", "show", "eth0"): IP_ADDR,
                    ("ip", "route"): "default via 203.0.113.1 dev eth0\n",
                    ("nv", "show", "system", "ztp"): "service disabled\nstate disabled\n",
                    ("hostname",): "PUBLIC-IB01\n"}[command]
                framed ="__HTTP_IB_BEGIN_" + nonce + "__\n" + output + "__HTTP_IB_END_" + nonce + "__=0\n"
                result = app.SessionResult(framed, 0)
                fresh = role == "project" and command == tuple(READ) and scope == "inspect"
                if fresh:
                    if fault == "auth":
                        result = app.SessionResult(argv[-2] + ": Permission denied (password).\n", 255,
                                                   ib_authentication_rejected=True)
                    elif fault == "exit-one":
                        result = app.SessionResult("PUBLIC command refused\n", 1)
                    elif fault == "missing-end":
                        result.output = "__HTTP_IB_BEGIN_" + nonce + "__\n" + output
                    elif fault == "duplicate-begin":
                        result.output = "__HTTP_IB_BEGIN_" + nonce + "__\n" + framed
                    elif fault == "wrong-nonce":
                        other = "0" * 32 if nonce != "0" * 32 else "1" * 32
                        result.output = "__HTTP_IB_BEGIN_" + other + "__\n" + output + "__HTTP_IB_END_" + other + "__=0\n"
                    elif fault == "cleanup":
                        result.cleanup_uncertain = True
                    elif fault in ("password_changed", "password_change_required", "password_change_attempted",
                                   "ib_authentication_rejected"):
                        setattr(result, fault, True)
                    replies["fresh"] = result
                elif role == "key" and command == tuple(READ):
                    replies["key"] = result
                elif command == ("true",):
                    replies["proof"] = result
                elif scope == "final":
                    replies["final"] = result
                return result

            def observe(frame, event, value):
                if frame.f_globals is not app.__dict__:
                    return
                name = codes.get(frame.f_code)
                if name is None:
                    return
                if event == "call":
                    entered[name] += 1
                    if name in depth:
                        depth[name] += 1
                    if name == "obtain_write_permit":
                        permits.append("write-permit")
                    if name == "run_initial_stage":
                        state = app._TASK_IB_CONFIG
                        initial.append({"body_b": frame.f_locals.get("current") == body_b,
                            "project": frame.f_locals.get("ib_password") == PROJECT,
                            "point": frame.f_locals.get("neighbor") == ipv4,
                            "state": type(state) is app._IBConfigWriteState,
                            "task": getattr(state, "task", None) is task,
                            "identity": getattr(state, "identity_verified", None) is True,
                            "endpoint": getattr(state, "endpoint", None) == ipv4,
                            "current": getattr(state, "current_password", None) == PROJECT})
                elif event == "return":
                    if name in depth:
                        depth[name] -= 1
                    if name == "inspect_ib_device":
                        inspected.append(value)

            def metadata_delegate(*positional, **keywords):
                self.assertTrue(len(positional) == 8 and positional[0] is target
                                and positional[1] == ipv4 and positional[4] == "admin"
                                and positional[5] == PROJECT and positional[6] == 2 and positional[7] == READ,
                                "consumer fault injection is restricted to the one actual fresh READ")
                self.assertEqual({"local": False, "strict": False, "policy": policy}, keywords)
                result = real_stage(*positional, **keywords)
                self.assertIs(result, replies.get("fresh"), "first delegate must return the real boundary B object")
                self.assertEqual(ipv4, result._direct_endpoint)
                self.assertEqual(body_b, result.output)
                edits.append(metadata)
                if metadata == "missing":
                    del result._direct_endpoint
                elif metadata == "foreign":
                    result._direct_endpoint = SimpleNamespace(address="203.0.113.2", interface=None)
                elif metadata == "old-ll":
                    result._direct_endpoint = point
                return result

            denied_os = {name: forbidden for name in ("system", "fork", "forkpty", "execv", "execve", "execvp",
                "execvpe", "execl", "execlp", "execlpe", "posix_spawn", "posix_spawnp", "spawnl", "spawnle",
                "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")}
            with ExitStack() as guard:
                guard.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
                guard.enter_context(mock.patch.object(builtins, "input", new=forbidden))
                guard.enter_context(mock.patch.object(app, "subprocess", new=_Facade(subprocess, run=control, Popen=forbidden)))
                guard.enter_context(mock.patch.object(paths, "subprocess", new=_Facade(subprocess, run=control, Popen=forbidden)))
                guard.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
                guard.enter_context(mock.patch.object(app, "os", new=_Facade(os, open=open_global, **denied_os)))
                guard.enter_context(mock.patch.object(app, "socket", new=_Facade(socket, socket=forbidden, create_connection=forbidden)))
                guard.enter_context(mock.patch.object(app, "pty", new=_Facade(app.pty, fork=forbidden, openpty=forbidden)))
                guard.enter_context(mock.patch.object(app, "getpass", new=_Facade(app.getpass, getpass=forbidden)))
                guard.enter_context(mock.patch.object(app, "verify_password_hash", new=verify))
                guard.enter_context(mock.patch.object(app, "request_current_ib_password", new=ask))
                guard.enter_context(mock.patch.object(app, "log", new=lambda *_a, **_k: None))
                policy = app.ProjectPasswordPolicy(global_file, "admin", target_password=PROJECT, interactive=False)
                selected = policy.password()
                self.assertTrue(type(selected) is str and selected == PROJECT and any(verified),
                                "real policy must independently qualify the PUBLIC project target")
                coordinator = app.RuntimeCoordinator(args, policy, FACTORY, [task], app.RuntimeInputAuthority([global_file]))
                coordinator.current_target = target
                guard.enter_context(mock.patch.object(app, "_ACTIVE_COORDINATOR", coordinator))
                if metadata is not None:
                    guard.enter_context(mock.patch.object(app, "_stage_ib_command", new=metadata_delegate))
                try:
                    sys.setprofile(observe)
                    yield SimpleNamespace(app=app, target=target, point=point, ipv4=ipv4, task=task,
                        args=args, policy=policy, coordinator=coordinator, key=key, body_a=body_a, body_b=body_b,
                        requests=requests, controls=controls, order=order, inspected=inspected, initial=initial,
                        replies=replies, entered=entered, asks=asks, permits=permits, edits=edits,
                        previous_context=old_context)
                finally:
                    sys.setprofile(old_profile)
                    app._TASK_IB_CONFIG = old_context
                policy.assert_unchanged()
                self.assertTrue(key.read_bytes() == key_bytes and global_file.read_bytes() == global_bytes,
                                "V6 must not rewrite its PUBLIC project/key inputs")
                self.assertEqual(0o600, stat.S_IMODE(key.lstat().st_mode))
                self.assertEqual([], effects, "V6 cannot execute real external/native/provider effects")
            self.assertIs(old_profile, sys.getprofile())
            self.assertIs(old_context, app._TASK_IB_CONFIG)

    def test_v6_key_apply_fallback_returns_new_ipv4_nvue_body_and_real_pipeline(self):
        with self._v6_public_fresh_point() as world:
            record = world.app.execute_ib_task(world.task, world.args, world.policy, FACTORY, None, [], world.key)
            self.assertIs(world.previous_context, world.app._TASK_IB_CONFIG, "execute must restore before fixture finally")
            self.assertEqual("ALREADY_CONFIGURED", record["outcome"])
            self.assertEqual([("key", "ll", tuple(READ), "inspect"),
                ("project", "ll", ("true",), "inspect"), ("neighbor",),
                ("project", "ipv4", ("true",), "inspect"), ("project", "ipv4", tuple(READ), "inspect"),
                ("project", "ipv4", ("ip", "addr", "show", "eth0"), "stage"),
                ("project", "ipv4", ("ip", "route"), "stage"),
                ("project", "ipv4", ("nv", "show", "system", "ztp"), "stage"),
                ("project", "ipv4", ("ip", "addr", "show", "eth0"), "stage"),
                ("project", "ipv4", ("ip", "route"), "stage"),
                ("project", "ipv4", tuple(READ), "stage"),
                # U4 (v3.1.6 D1d, guide 8.11 steps 1-2): one Linux hostname read after readiness;
                # it matches the NVUE name, so no sudo, permit or backup follows.
                ("project", "ipv4", ("hostname",), "stage"),
                ("project", "ipv4", tuple(READ), "final")], world.order)
            self.assertEqual(1, len(world.inspected))
            result, credential, _authorized = world.inspected[0]
            self.assertIs(result, world.replies["fresh"])
            self.assertIsNot(result, world.replies["key"])
            self.assertIsNot(result, world.replies["proof"])
            self.assertEqual(world.body_b, result.output)
            self.assertEqual(world.ipv4, result._direct_endpoint)
            self.assertTrue(type(credential) is str and credential == PROJECT, "only verified project becomes current")
            self.assertEqual(world.body_a, world.replies["key"].output)
            self.assertEqual(world.point, world.replies["key"]._direct_endpoint)
            self.assertEqual("", world.replies["proof"].output)
            self.assertEqual([{name: True for name in ("body_b", "project", "point", "state", "task",
                                                     "identity", "endpoint", "current")}], world.initial)
            for name in ("execute_ib_task", "inspect_ib_device", "_authenticate_ib_read", "run_initial_stage",
                         "run_service_stage", "run_key_stage", "verify_management_direct_ssh"):
                self.assertEqual(1, world.entered[name], name)
            self.assertTrue(record["identity"]["ok"] and record["identity"]["via_ipv4"])
            self.assertEqual("VERIFIED", record["stage_status"]["initial"])
            self.assertEqual("VERIFIED", record["stage_status"]["ipv4_readiness"])
            self.assertEqual("NOT_CONFIGURED", record["stage_status"]["services"])
            self.assertEqual("NO_KEYS_PROVIDED", record["stage_status"]["public_keys"])
            self.assertEqual("VERIFIED", record["stage_status"]["direct_ssh"])
            self.assertEqual([], world.asks)
            self.assertEqual([], world.permits)
            self.assertEqual(0, world.entered["_ensure_ib_config_backup"])
            self.assertFalse(world.coordinator.writes_attempted)
            self.assertFalse(record["writes_attempted"])
            self.assertIsNone(record["backup"])

    def test_v6_fresh_ipv4_read_failures_cannot_reuse_old_key_nvue_or_continue(self):
        faults = ("auth", "exit-one", "missing-end", "duplicate-begin", "wrong-nonce", "cleanup",
                  "password_changed", "password_change_required", "password_change_attempted",
                  "ib_authentication_rejected")
        for fault in faults:
            with self.subTest(fault=fault), self._v6_public_fresh_point(fault=fault) as world:
                record = world.app.execute_ib_task(world.task, world.args, world.policy, FACTORY, None, [], world.key)
                self.assertIs(world.previous_context, world.app._TASK_IB_CONFIG)
                self.assertEqual("FAILED", record["outcome"])
                self.assertEqual("authentication", record["failed_stage"])
                self.assertEqual("FAILED", record["stage_status"]["authentication"])
                self.assertEqual([("key", "ll", tuple(READ), "inspect"),
                    ("project", "ll", ("true",), "inspect"), ("neighbor",),
                    ("project", "ipv4", ("true",), "inspect"),
                    ("project", "ipv4", tuple(READ), "inspect")], world.order)
                self.assertEqual([None], world.inspected, "failed inspect has no successful return tuple")
                self.assertEqual(world.body_a, world.replies["key"].output)
                self.assertEqual(world.point, world.replies["key"]._direct_endpoint)
                self.assertEqual([], world.initial)
                self.assertIsNone(record["identity"])
                for stage in ("initial", "day0", "ipv4_readiness", "services", "public_keys", "direct_ssh"):
                    self.assertEqual("NOT_REACHED", record["stage_status"][stage])
                for name in ("run_initial_stage", "run_service_stage", "run_key_stage", "_ensure_ib_config_backup",
                             "run_management_direct_checks", "verify_management_direct_ssh"):
                    self.assertEqual(0, world.entered[name], name)
                self.assertEqual([], world.asks)
                self.assertEqual([], world.permits)
                self.assertFalse(world.coordinator.writes_attempted)
                self.assertFalse(record["writes_attempted"])
                self.assertIsNone(record["backup"])

    def test_v6_inspect_consumer_rejects_changed_fresh_read_endpoint_metadata(self):
        for mode in ("unchanged", "missing", "foreign", "old-ll"):
            with self.subTest(metadata=mode), self._v6_public_fresh_point(metadata=mode) as world:
                result = error = None
                try:
                    result = world.app.inspect_ib_device(world.target, world.point, "", "", "admin", FACTORY, 2,
                        world.policy, apply=True, authorized=False, local=False, strict=False,
                        _management_private_key=world.key)
                except world.app.SetupError as caught:
                    error = caught
                self.assertEqual([mode], world.edits, "unit first delegates the real complete fresh READ exactly once")
                self.assertEqual([("key", "ll", tuple(READ), "inspect"),
                    ("project", "ll", ("true",), "inspect"), ("neighbor",),
                    ("project", "ipv4", ("true",), "inspect"),
                    ("project", "ipv4", tuple(READ), "inspect")], world.order)
                if mode == "unchanged":
                    self.assertIsNone(error)
                    self.assertIs(result[0], world.replies["fresh"])
                    self.assertEqual(world.body_b, result[0].output)
                    self.assertEqual(world.ipv4, result[0]._direct_endpoint)
                    self.assertTrue(type(result[1]) is str and result[1] == PROJECT,
                                    "unchanged consumer positive retains verified project")
                else:
                    self.assertIsInstance(error, world.app.SetupError)
                    self.assertNotIsInstance(error, world.app.IBAuthenticationError,
                                             "bad actual-point metadata is not credential exhaustion")
                    self.assertIsNone(result)
                self.assertEqual(world.body_a, world.replies["key"].output)
                self.assertEqual(world.point, world.replies["key"]._direct_endpoint)
                self.assertIs(world.previous_context, world.app._TASK_IB_CONFIG)
                self.assertEqual([], world.asks)
                self.assertEqual([], world.permits)
                self.assertEqual(0, world.entered["execute_ib_task"], "consumer unit is not a full O5 execution proof")
                self.assertEqual([], world.initial)
                self.assertFalse(world.coordinator.writes_attempted)


class I039MainProjectPrefetchWorkflowTests(unittest.TestCase):
    """Real MAIN through owned OOB IO and parent queue, never an IB/PAM body.

    A fixed PUBLIC pair models only the native verifier boundary, as in the
    original BaseAndSubsetTests. Policy parsing/binding/password caching and
    MAIN's input/cache/profile/LP preparation remain original. The profile stop
    is not a successful worker result or a completed MAIN/summary witness.
    """

    def _main_prefetch_boundary(self, *, mode="valid", has_global=True,
                                empty_ready=False, reject_before_policy=False):
        from contextlib import redirect_stderr, redirect_stdout
        from test_cases.test_initial_setup_cable_check import _World, INITIAL, JA, PUBLIC_REPLY

        class ObservedBoundary(BaseException):
            pass

        project_value = "-".join(("PUBLIC", "I039", "verified", "Zq7"))
        # Shape only, not a credential/KAT vector or a real cryptographic hash.
        public_hash = "$" + "6$PUBLICsalt$" + "A" * 86
        previous = sys.getprofile()
        with _World(self) as world:
            app = world.app
            global_file = world.project / "01-global.yaml"
            if has_global:
                global_file.write_text(
                    'schema_version: 2\nswitches:\n- ib:\n    system:\n'
                    '      aaa:\n        user:\n          admin:\n            password: "'
                    + public_hash + '"\n', encoding="utf-8")
                global_file.chmod(0o600)
                neutral = world.project / "infiniband" / "bringup" / "xdr-initial-setup"
                for directory in (neutral.parent.parent, neutral.parent, neutral):
                    directory.mkdir(mode=0o700)
                path = neutral / "infra-neutral.conf"
                path.write_text("DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=UTC\n", encoding="utf-8")
                path.chmod(0o600)
            if empty_ready:
                # Real preparation must discover the missing cable evidence;
                # no fake empty tasks/targets or failed worker is returned.
                links, _fdb, vlans = world.tables[JA]
                world.tables[JA] = (links, [""], vlans)
            observed = {"order": [], "policies": [], "verified": 0, "device": 0,
                        "dispatch": None, "checkpoint": None, "redacted": None,
                        "seeded": False, "cached_before_device": [], "modules": set(), "qualified_cache": False,
                        "verified_pairs": 0, "controls": [], "cleanup_controls": [],
                        "queue_stamp": None, "queue_parent": None}
            original_interactive = app.interactive_run
            original_control = app.subprocess.run
            original_directory = app.tempfile.mkdtemp
            cleanup_code = app.JumpSessions.close_jump_masters.__code__

            def directory(*args, **options):
                if options.get("prefix") == "isj-":
                    return original_directory(*args, **options)
                self.assertEqual((), args)
                self.assertEqual({"prefix", "dir"}, set(options))
                self.assertIs(type(observed["queue_stamp"]), str)
                self.assertEqual("devices-" + observed["queue_stamp"] + "-", options["prefix"])
                self.assertEqual(world.root, observed["queue_parent"])
                self.assertEqual(world.root, Path(options["dir"]).resolve())
                parent_info = world.root.lstat()
                self.assertEqual(world.root, world.root.resolve())
                self.assertTrue(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.geteuid()
                                and stat.S_IMODE(parent_info.st_mode) == 0o700)
                path = Path(tempfile.mkdtemp(prefix=options["prefix"], dir=world.root))
                info = path.lstat()
                self.assertEqual(world.root, path.parent)
                self.assertEqual(path, path.resolve())
                self.assertTrue(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                                and stat.S_IMODE(info.st_mode) == 0o700)
                return str(path)

            def verify_pair(value, digest):
                self.assertTrue(type(value) is str and value == project_value,
                                "only the independently supplied PUBLIC project value may be verified")
                self.assertTrue(type(digest) is str and digest == public_hash,
                                "actual policy must read the independent owned project hash shape")
                observed["order"].append("verifier")
                if mode == "unavailable":
                    raise app.SetupError("PUBLIC verifier unavailable; no device is authorized")
                observed["verified_pairs"] += 1
                return True

            def password_input(prompt=""):
                if prompt.startswith("IB target password (") or prompt == "Confirm IB target password: ":
                    observed["order"].append("project-input")
                    return project_value
                return PUBLIC_REPLY  # unchanged synthetic outer input, never the project value

            def interactive(argv, responder, timeout, **options):
                observed["device"] += 1
                observed["order"].append("device-interactive")
                observed["cached_before_device"].append(any(
                    type(policy) is app.ProjectPasswordPolicy and policy._password == project_value
                    for policy in observed["policies"]))
                return original_interactive(argv, responder, timeout, **options)

            def control(argv, **options):
                # Observe the existing local facade, never stdlib run. The
                # original controller still qualifies every path and reply.
                own_cleanup = (type(argv) is list and len(argv) == 6
                    and all(type(word) is str for word in argv)
                    and argv[:2] == ["ssh", "-o"] and argv[2].startswith("ControlPath=")
                    and argv[3] == "-O" and argv[4] in ("check", "exit"))
                caller = sys._getframe(1)
                in_cleanup = False
                while caller is not None:
                    if caller.f_globals is app.__dict__ and caller.f_code is cleanup_code:
                        in_cleanup = True
                        break
                    caller = caller.f_back
                if own_cleanup and in_cleanup:
                    observed["cleanup_controls"].append(argv[4])
                else:
                    observed["controls"].append(argv[0] if type(argv) is list and argv else "invalid-vector")
                return original_control(argv, **options)

            def profile(frame, event, value):
                if frame.f_globals is not app.__dict__:
                    return
                name = frame.f_code.co_name
                if event == "call" and name == "__init__":
                    policy = frame.f_locals.get("self")
                    if type(policy) is app.ProjectPasswordPolicy:
                        observed["policies"].append(policy)
                        observed["order"].append("policy-construction")
                elif event == "return" and name == "password":
                    policy = frame.f_locals.get("self")
                    if type(policy) is app.ProjectPasswordPolicy and type(value) is str:
                        self.assertTrue(value == project_value and policy._password == project_value,
                                        "the original policy must cache its actual verified PUBLIC input")
                        observed["verified"] += 1
                        observed["order"].append("verified-project-return")
                elif event == "return" and name == "_new_jump_sessions" and value is not None:
                    world.sessions = value
                elif event == "return" and name == "_import_tools":
                    caller = frame.f_back
                    if value is not None and caller is not None and caller.f_globals is app.__dict__:
                        requested = frame.f_locals.get("name")
                        if requested in ("tools.login_path", "tools.device_identity", "tools.hostname_ranges",
                                         "tools.inventory_subset"):
                            self.assertEqual((ROOT / (requested.replace(".", "/") + ".py")).resolve(),
                                             Path(value.__file__).resolve())
                            observed["modules"].add(requested)
                elif event == "call" and name == "run_prepared_tasks":
                    observed["dispatch"] = len(frame.f_locals["tasks"])
                    observed["queue_stamp"] = frame.f_locals["args"].run_stamp
                    observed["queue_parent"] = Path(frame.f_locals["args"].report).resolve().parent
                    observed["qualified_cache"] = getattr(frame.f_locals["args"], "_strict_cache", None) is not None
                    if not frame.f_locals["tasks"]:
                        observed["checkpoint"] = "empty-dispatch"
                        raise ObservedBoundary()
                elif event == "call" and name == "execute_ib_task":
                    coordinator = app._ACTIVE_COORDINATOR
                    self.assertIs(type(coordinator), app.RuntimeCoordinator)
                    policy = coordinator.policy
                    observed["seeded"] = (type(policy) is app.ProjectPasswordPolicy
                        and policy._password == project_value and project_value in coordinator.secrets)
                    # Original parent redactor with its actual secret list;
                    # no test seed, replacement coordinator or fake result.
                    observed["redacted"] = app.redact_data(
                        {"witness": "PUBLIC-prefix:" + project_value + ":PUBLIC-suffix"}, coordinator.secrets)
                    observed["checkpoint"] = "before-ib"
                    raise ObservedBoundary()

            argv = [str(INITIAL), "--project-dir", str(world.project), "--p2p", str(world.p2p),
                "--report", str(world.root / "report.log"), "--target-cache", str(world.root / "targets.json"),
                "--snapshot-dir", str(world.root / "snapshots"), "--execution-mode", "management",
                "--max-workers", "1"]
            if reject_before_policy:
                argv.extend(("--eth-user", "invalid public account"))
            output, code, stopped = io.StringIO(), None, False
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(app, "verify_password_hash", new=verify_pair), \
                 mock.patch.object(app.getpass, "getpass", new=password_input), \
                 mock.patch.object(app, "interactive_run", new=interactive), \
                 mock.patch.object(app.subprocess, "run", new=control), \
                 mock.patch.object(app.tempfile, "mkdtemp", new=directory), \
                 redirect_stdout(output), redirect_stderr(output):
                try:
                    sys.setprofile(profile)
                    code = app._standalone_main_with_report_cleanup()
                except ObservedBoundary:
                    stopped = True
                finally:
                    sys.setprofile(previous)
            observed["code"], observed["stopped"] = code, stopped
            observed["initial_calls"] = world.initial_password.call_count
            self.assertIs(previous, sys.getprofile())
            self.assertIsNone(app._ACTIVE_COORDINATOR)
            self.assertIsNone(app._TASK_DEADLINE)
            self.assertIsNone(app._TASK_LOG_BUFFER)
            if app.REPORT_HANDLE is not None:
                self.assertIs(app.REPORT_HANDLE.closed, True, "real MAIN finally must close its owned report")
                self.assertEqual((world.root / "report.log").resolve(), Path(app.REPORT_HANDLE.name).resolve())
            return observed

    def test_main_verifies_project_before_the_first_oob_session(self):
        observed = self._main_prefetch_boundary()
        self.assertTrue(observed["stopped"] and observed["checkpoint"] == "before-ib",
                        "real MAIN must reach the original parent queue before the IB body")
        self.assertTrue(observed["device"] > 0, "actual owned OOB model must be exercised")
        self.assertTrue(observed["qualified_cache"], "upfront project qualification must not replace strict cache admission")
        self.assertEqual(1, observed["verified_pairs"], "one real upstream qualification of the PUBLIC project pair")
        self.assertGreaterEqual(observed["verified"], 1, "cached password getters may return the verified value again")
        self.assertTrue(all(observed["cached_before_device"]), "no device session may precede real project qualification")
        self.assertLess(observed["order"].index("verified-project-return"),
                        observed["order"].index("device-interactive"))

    def test_main_project_verification_failure_has_zero_device_interactions(self):
        observed = self._main_prefetch_boundary(mode="unavailable")
        self.assertFalse(observed["stopped"], "a failed project target must not reach an IB boundary")
        self.assertEqual(2, observed["code"])
        self.assertEqual(1, observed["order"].count("verifier"))
        self.assertEqual(0, observed["verified"])
        self.assertEqual(0, observed["verified_pairs"])
        self.assertEqual(0, observed["device"], "project failure must precede every OOB and IB session")
        self.assertEqual([], observed["controls"], "failed project qualification permits no SSH/ip/ping control request")
        self.assertIsNone(observed["dispatch"])

    def test_main_prefetch_is_not_conditional_on_later_cable_eligibility(self):
        observed = self._main_prefetch_boundary(empty_ready=True)
        self.assertTrue(observed["stopped"] and observed["checkpoint"] == "empty-dispatch")
        self.assertEqual(0, observed["dispatch"], "real cable preparation must produce no eligible IB task")
        self.assertEqual(1, len(observed["policies"]))
        self.assertEqual(1, observed["verified_pairs"], "a constructed policy still requires upfront qualification")
        self.assertGreaterEqual(observed["verified"], 1, "legitimate cached getters are not repeat verification")
        self.assertTrue(observed["device"] > 0 and all(observed["cached_before_device"]))

    def test_main_parent_redaction_contains_the_actually_verified_project_value(self):
        observed = self._main_prefetch_boundary()
        self.assertTrue(observed["stopped"] and observed["checkpoint"] == "before-ib")
        self.assertTrue(observed["seeded"], "parent authority must retain the actual verified target for redaction")
        self.assertEqual({"witness": "PUBLIC-prefix:[REDACTED]:PUBLIC-suffix"}, observed["redacted"])

    def test_main_without_global_does_not_invent_project_prefetch(self):
        observed = self._main_prefetch_boundary(has_global=False)
        self.assertTrue(observed["stopped"] and observed["checkpoint"] == "before-ib")
        self.assertEqual([], observed["policies"])
        self.assertNotIn("verifier", observed["order"])
        self.assertEqual(0, observed["verified"])
        self.assertEqual(1, observed["initial_calls"], "original initial credential resolution remains reachable")

    def test_main_existing_early_refusal_does_not_construct_or_prefetch_policy(self):
        observed = self._main_prefetch_boundary(reject_before_policy=True)
        self.assertEqual(2, observed["code"])
        self.assertFalse(observed["stopped"])
        self.assertEqual([], observed["policies"])
        self.assertNotIn("verifier", observed["order"])
        self.assertEqual(0, observed["device"])
        self.assertEqual([], observed["controls"])
        self.assertIsNone(observed["dispatch"])
