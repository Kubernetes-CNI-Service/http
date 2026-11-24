"""WP6 pure tests first: independent PUBLIC conflicts and operational ZTP facts.

Sources: guide-v3.1.5-approved-r751, WP6 rows :908/:909/:912,
D67-O1/O2/O3/O9 and R-012 sections 9.1/9.2.  The saved D1 O9 census
(06-落地偏离登记-v3.1.3.md, WP8a-A/2) has 434 suffix-only matches,
so guide 1.4 row 27 requires full-name comparison, NOT the zero-census branch.
Only the pure portion of those rows is covered here.  No result records,
workflow, selector, KEY, native backend, or actual device effects are claimed.
All expected facts and commands below are hand-written, not SUT-derived.
NOT RUN by the author; Root owns later exact runtime and mutation evidence.
"""
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script


INITIAL = (Path(__file__).resolve().parents[1]
           / "infiniband/bringup/xdr-initial-setup/initial-setup.py")
HOST = "EXAMPLE-IB01.example.test"

# R-012 section 9.2 owner's PUBLIC sample; no hostname/private input.
ABORTED = """             operational  applied
-----------  -----------  -------
service      disabled
status       aborted
config-save  enabled      enabled

ZTP stages
=============
No Data
"""
# INFERRED sample: the owner sample has only aborted, not success.
SUCCESS_INFERRED = """             operational  applied
-----------  -----------  -------
service      disabled
status       success
config-save  enabled      enabled

ZTP stages
=============
No Data
"""

# Five independently specified fields x missing/contains/conflict.
# Hostname is scalar: "contains" means the same complete hostname.
CONFLICT_CASES = (
    ("hostname-missing", {"hostname": "nvos"}, []),
    ("hostname-same", {"hostname": HOST}, []),
    ("hostname-different", {"hostname": "OTHER-IB01.example.test"},
     [("hostname", HOST, "OTHER-IB01.example.test")]),
    ("eth0-address-missing", {"eth0_addresses": ()}, []),
    ("eth0-address-contains-extra", {"eth0_addresses": ("203.0.113.2/24", "203.0.113.77/24")}, []),
    ("eth0-address-different", {"eth0_addresses": ("203.0.113.77/24",)},
     [("eth0 address", "203.0.113.2/24", ("203.0.113.77/24",))]),
    ("eth1-address-missing", {"eth1_addresses": ()}, []),
    ("eth1-address-contains-extra", {"eth1_addresses": ("198.51.100.2/24", "198.51.100.77/24")}, []),
    ("eth1-address-different", {"eth1_addresses": ("198.51.100.77/24",)},
     [("eth1 address", "198.51.100.2/24", ("198.51.100.77/24",))]),
    ("eth0-gateway-missing", {"eth0_gateways": ()}, []),
    ("eth0-gateway-contains-extra", {"eth0_gateways": ("203.0.113.1", "203.0.113.254")}, []),
    ("eth0-gateway-different", {"eth0_gateways": ("203.0.113.254",)},
     [("eth0 gateway", "203.0.113.1", ("203.0.113.254",))]),
    ("eth1-gateway-missing", {"eth1_gateways": ()}, []),
    ("eth1-gateway-contains-extra", {"eth1_gateways": ("198.51.100.1", "198.51.100.254")}, []),
    ("eth1-gateway-different", {"eth1_gateways": ("198.51.100.254",)},
     [("eth1 gateway", "198.51.100.1", ("198.51.100.254",))]),
)
FIXED_ERRORS = (
    ("hostname", {"hostname": "OTHER-IB01.example.test"},
     "management Network hostname conflict; device state is UNKNOWN"),
    ("eth0 address", {"eth0_addresses": ("203.0.113.77/24",)},
     "management Network eth0 address conflict; device state is UNKNOWN"),
    ("eth1 address", {"eth1_addresses": ("198.51.100.77/24",)},
     "management Network eth1 address conflict; device state is UNKNOWN"),
    ("eth0 gateway", {"eth0_gateways": ("203.0.113.254",)},
     "management Network eth0 gateway conflict; device state is UNKNOWN"),
    ("eth1 gateway", {"eth1_gateways": ("198.51.100.254",)},
     "management Network eth1 gateway conflict; device state is UNKNOWN"),
)


class BringupResultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_script("wp6_bringup_results_pure_source", INITIAL)

    def device(self):
        return self.app.Device(HOST, "ib", "203.0.113.2", "203.0.113.2/24",
                               "203.0.113.1", "02:00:00:00:00:17",
                               "198.51.100.2/24", "198.51.100.1")

    def state(self, **changes):
        facts = dict(hostname=HOST, eth0_addresses=("203.0.113.2/24",),
                     eth1_addresses=("198.51.100.2/24",),
                     eth0_gateways=("203.0.113.1",), eth1_gateways=("198.51.100.1",))
        facts.update(changes)
        # Serialize only our hand-written facts as input, never as an oracle.
        rows = ["nv set interface eth0-1 link state up", "nv set interface eth0-1 type eth"]
        for field, interface, setting in (
                ("eth0_addresses", "eth0", "address"), ("eth1_addresses", "eth1", "address"),
                ("eth0_gateways", "eth0", "gateway"), ("eth1_gateways", "eth1", "gateway")):
            rows.extend("nv set interface " + interface + " ipv4 " + setting + " " + value
                        for value in facts[field])
        if facts["hostname"]:
            rows.append("nv set system hostname " + facts["hostname"])
        return self.app.DeviceState(**facts, raw_commands="\n".join(rows) + "\n")

    def pure(self, function, *args):
        attempted = []
        def deny(*unused, **ignored):
            attempted.append("external")
            raise AssertionError("pure WP6 function attempted an external effect")
        # Module-local references only: never patch shared subprocess/os/Path.
        with ExitStack() as stack:
            for name in ("interactive_run", "run_on_ib", "_stage_ib_command",
                         "_run_authorized_ib_command", "verify_password_hash",
                         "obtain_write_permit", "_ensure_ib_config_backup",
                         "confirm_first_device_change"):
                stack.enter_context(mock.patch.object(self.app, name, new=deny))
            stack.enter_context(mock.patch.object(self.app, "subprocess", new=SimpleNamespace(
                run=deny, Popen=deny, check_call=deny, check_output=deny, call=deny)))
            stack.enter_context(mock.patch.object(self.app, "os", new=SimpleNamespace(
                open=deny, system=deny, fork=deny, execve=deny, posix_spawn=deny)))
            stack.enter_context(mock.patch.object(self.app, "Path", new=deny))
            try:
                return function(*args)
            finally:
                self.assertEqual([], attempted, "a pure result cannot hide an attempted external effect")

    def safe_error(self, callback, message):
        with self.assertRaises(self.app.SetupError) as caught:
            callback()
        error = caught.exception
        self.assertIs(type(error), self.app.SetupError)
        self.assertEqual((message,), error.args)
        self.assertEqual({}, error.__dict__)
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertFalse(any(raw in str(error) for raw in (
            HOST, "OTHER-IB01", "203.0.113.2/24", "203.0.113.77/24",
            "198.51.100.2/24", "198.51.100.77/24", "203.0.113.1",
            "203.0.113.254", "198.51.100.1", "198.51.100.254", "PUBLIC-RAW-MARKER")))

    def test_conflict_table_per_field(self):
        # D67-O1/O3; R-012 9.1: missing fills, membership preserves extras.
        for label, changes, expected in CONFLICT_CASES:
            with self.subTest(case=label):
                state = self.state(**changes)
                before = replace(state)
                actual = self.pure(self.app.management_conflicts, self.device(), state)
                self.assertIs(type(actual), list)
                self.assertTrue(all(type(item) is tuple for item in actual))
                self.assertEqual(expected, actual)
                self.assertEqual(before, state, "pure conflict calculation cannot mutate observed facts")
        state = self.state(hostname="OTHER-IB01.example.test",
                           eth0_addresses=("203.0.113.77/24",), eth1_addresses=("198.51.100.77/24",),
                           eth0_gateways=("203.0.113.254",), eth1_gateways=("198.51.100.254",))
        self.assertEqual([
            ("hostname", HOST, "OTHER-IB01.example.test"),
            ("eth0 address", "203.0.113.2/24", ("203.0.113.77/24",)),
            ("eth1 address", "198.51.100.2/24", ("198.51.100.77/24",)),
            ("eth0 gateway", "203.0.113.1", ("203.0.113.254",)),
            ("eth1 gateway", "198.51.100.1", ("198.51.100.254",)),
        ], self.pure(self.app.management_conflicts, self.device(), state))

    def test_saved_nonzero_o9_census_requires_complete_hostname(self):
        # Saved WP8a-A: 434 != 0.  Guide 1.4 row 27's zero branch does NOT apply.
        for actual in ("EXAMPLE-IB01", "EXAMPLE-IB01.other.test"):
            with self.subTest(case=actual):
                self.assertEqual([("hostname", HOST, actual)],
                    self.pure(self.app.management_conflicts, self.device(), self.state(hostname=actual)))
        for default in ("", "nvos"):
            with self.subTest(factory=default):
                self.assertEqual([], self.pure(self.app.management_conflicts,
                                              self.device(), self.state(hostname=default)))

    def test_unrequested_or_input_masked_eth1_has_no_conflict(self):
        # Guide 1.4 row 14: invalid CSV eth1 is removed by the input layer;
        # this pure function receives that qualified absent request, not bad CSV.
        for gateway in ("", "198.51.100.1"):
            with self.subTest(requested_eth1=False, leftover_gateway=bool(gateway)):
                device = replace(self.device(), eth1_prefix="", eth1_gateway=gateway)
                state = self.state(eth1_addresses=("192.0.2.77/24",), eth1_gateways=("192.0.2.1",))
                self.assertEqual([], self.pure(self.app.management_conflicts, device, state))

    def test_default_and_force_fill_only_missing_members(self):
        # D67-O2: default patch and --force are synonyms, not overwrite modes.
        missing = (
            ({"hostname": "nvos"}, [["nv", "set", "system", "hostname", HOST]]),
            ({"eth0_addresses": ()}, [["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"]]),
            ({"eth1_addresses": ()}, [["nv", "set", "interface", "eth1", "ipv4", "address", "198.51.100.2/24"]]),
            ({"eth0_gateways": ()}, [["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"]]),
            ({"eth1_gateways": ()}, [["nv", "set", "interface", "eth1", "ipv4", "gateway", "198.51.100.1"]]),
        )
        for changes, expected in missing:
            with self.subTest(missing=tuple(changes)):
                state = self.state(**changes)
                for forced in (False, True):
                    self.assertIs(True, self.pure(self.app.base_stage_needed, self.device(), state, forced))
                self.assertEqual(expected, self.pure(self.app._management_network_commands,
                                                    self.device(), state.raw_commands))
        extra = self.state(eth0_addresses=("203.0.113.2/24", "203.0.113.77/24"),
                           eth1_addresses=("198.51.100.2/24", "198.51.100.77/24"),
                           eth0_gateways=("203.0.113.1", "203.0.113.254"),
                           eth1_gateways=("198.51.100.1", "198.51.100.254"))
        for forced in (False, True):
            self.assertIs(False, self.pure(self.app.base_stage_needed, self.device(), extra, forced))
        self.assertEqual([], self.pure(self.app._management_network_commands,
                                      self.device(), extra.raw_commands))
        for field, changes, unused in FIXED_ERRORS:
            for forced in (False, True):
                with self.subTest(conflict=field, forced=forced), self.assertRaises(self.app.SetupError):
                    self.pure(self.app.base_stage_needed, self.device(), self.state(**changes), forced)

    def test_conflicts_keep_exact_fixed_pure_errors_without_values(self):
        # D67-O3 / existing NetworkDiagnosticDirectTests.safe_error contract.
        # The two address messages are independently frozen NEW literals here.
        for field, changes, message in FIXED_ERRORS:
            with self.subTest(field=field):
                current = self.state(**changes).raw_commands
                self.safe_error(lambda: self.pure(self.app._management_network_commands,
                                                 self.device(), current), message)

    def test_unqualified_readback_keeps_original_fixed_pure_error(self):
        for label, current in (
                ("empty", ""),
                ("bad-token", self.state().raw_commands + "nv set interface eth0 link state up PUBLIC-RAW-MARKER\n"),
                ("unknown-port", self.state().raw_commands + "nv set interface eth0-2 link state up\n")):
            with self.subTest(case=label):
                self.safe_error(lambda: self.pure(self.app._management_network_commands,
                    self.device(), current), "management Network setter plan is not qualified")

    def test_ztp_status_parsing(self):
        # WP6 parser-only portion; provisioned/record facts belong to another slice.
        for label, text, expected in (
                ("owner-aborted", ABORTED, {"service": "disabled", "state": None, "status": "aborted"}),
                ("inferred-success", SUCCESS_INFERRED, {"service": "disabled", "state": None, "status": "success"}),
                ("missing-status", "service disabled\nstate disabled\nconfig-save enabled enabled\n",
                 {"service": "disabled", "state": "disabled", "status": None}),
                ("operational-first-word", "service disabled\nstate disabled\nstatus aborted success\n",
                 {"service": "disabled", "state": "disabled", "status": "aborted"})):
            with self.subTest(case=label):
                self.assertEqual(expected, self.pure(self.app.parse_ztp_status, text))

    def test_ztp_duplicate_operational_rows_are_rejected(self):
        for field in ("service", "state", "status"):
            for duplicate in ("disabled", "enabled") if field != "status" else ("aborted", "success"):
                text = "service disabled\nstate disabled\nstatus aborted\n" + field + " " + duplicate + "\n"
                with self.subTest(field=field, second=duplicate), self.assertRaises(self.app.SetupError):
                    self.pure(self.app.parse_ztp_status, text)

    def test_ztp_stage_history_cannot_supply_or_override_operational_status(self):
        for label, text, expected in (
                ("no-operational-status", "service disabled\nZTP stages\nstatus success\nservice enabled\n",
                 {"service": "disabled", "state": None, "status": None}),
                ("operational-status-wins", "service disabled\nstatus aborted\n  ZTP stages\nstatus success\nstate enabled\n",
                 {"service": "disabled", "state": None, "status": "aborted"})):
            with self.subTest(case=label):
                self.assertEqual(expected, self.pure(self.app.parse_ztp_status, text))
                self.assertIs(True, self.pure(self.app._ztp_disabled, text))

    def test_ztp_original_disabled_and_contradictory_rules_are_preserved(self):
        for text, expected in (
                ("service disabled\n", True), ("service disabled\nstate disabled\n", True),
                ("service inactive\nstate disabled\n", True), ("state disabled\n", True),
                ("service inactive\nstate enabled\n", False), ("state enabled\n", False),
                ("service active\nstate enabled\n", False), ("service running\n", False)):
            with self.subTest(text=text):
                self.assertIs(expected, self.pure(self.app._ztp_disabled, text))
        for text in ("service disabled\nstate enabled\n", "service active\nstate disabled\n"):
            for parser in (self.app.parse_ztp_status, self.app._ztp_disabled):
                with self.subTest(contradictory=text, parser=parser.__name__), self.assertRaises(self.app.SetupError):
                    self.pure(parser, text)


# WP7 independent program-only slice; the complete WP6 prefix above is unchanged.
import base64
import hashlib
import os
import stat
import struct
import subprocess
import tempfile

from test_cases.native_cpld_physical_io import owned_test_root

# Pre-implementation proposed text, 10 lines/3456B, SHA256
# 3727325154970f2da4dc74426e7743a6359b151f6c3fa9e8a83e21050e179cea.
EXPECTED_READONLY_KEY_SCRIPT = "set -eu\nLC_ALL=C\nexport LC_ALL\n[ \"$#\" -eq 1 ] || exit 34\n[ -n \"${HOME:-}\" ] || exit 34\nauth=\"$HOME/.ssh/authorized_keys\"\n[ -f \"$auth\" ] || exit 34\nrequired=$(printf %s \"$1\" | base64 -d 2>/dev/null) || exit 34\n[ -n \"$required\" ] || exit 34\nprintf '%s\\n' \"$required\" | awk 'function stop_invalid() { invalid=1; exit 34; } function hws(c) { return c==\" \" || c==\"\\t\"; } function algorithm(s) { return s ~ /^(ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+$/; } function canonical_blob(s, n,p,v) { n=length(s); if(n<4 || n%4!=0 || s !~ /^[A-Za-z0-9+\\/]+=?=?$/) return 0; p=index(s,\"=\"); if(!p) return 1; if(substr(s,n-1,2)==\"==\") { if(p!=n-1) return 0; v=index(alphabet,substr(s,n-2,1))-1; return v>=0 && v%16==0; } if(p!=n) return 0; v=index(alphabet,substr(s,n-1,1))-1; return v>=0 && v%4==0; } function option_list(s, p,n,start,name,c,closed) { n=length(s); p=1; if(!n) stop_invalid(); while(p<=n) { start=p; while(p<=n && substr(s,p,1)!=\"=\" && substr(s,p,1)!=\",\") p++; name=substr(s,start,p-start); if(name !~ /^[A-Za-z][A-Za-z0-9-]*$/) stop_invalid(); c=substr(s,p,1); if(c==\"=\") { if(!(name in valued)) stop_invalid(); p++; if(substr(s,p,1)!=\"\\\"\") stop_invalid(); p++; closed=0; while(p<=n) { c=substr(s,p,1); if(c==\"\\\\\") { if(p==n || substr(s,p+1,1)!=\"\\\"\") stop_invalid(); p+=2; continue; } if(c==\"\\\"\") { p++; closed=1; break; } p++; } if(!closed) stop_invalid(); if(p<=n && substr(s,p,1)!=\",\") stop_invalid(); } else { if(!(name in flag)) stop_invalid(); } if(p>n) return 1; if(substr(s,p,1)!=\",\") stop_invalid(); p++; if(p>n) stop_invalid(); } return 1; } function identity(line,request, n,p,start,c,quoted,first,alg,blob) { n=length(line); if(request) { if(index(line,\"\\r\")) stop_invalid(); } else if(n && substr(line,n,1)==\"\\r\") { line=substr(line,1,n-1); n--; } if(index(line,\"\\r\")) stop_invalid(); p=1; while(p<=n && hws(substr(line,p,1))) p++; if(p>n || substr(line,p,1)==\"#\") { if(request) stop_invalid(); return \"\"; } start=p; quoted=0; while(p<=n) { c=substr(line,p,1); if(c==\"\\\\\") { if(!quoted || p==n || substr(line,p+1,1)!=\"\\\"\") stop_invalid(); p+=2; continue; } if(c==\"\\\"\") { quoted=!quoted; p++; continue; } if(!quoted && hws(c)) break; p++; } if(quoted) stop_invalid(); first=substr(line,start,p-start); if(algorithm(first)) { alg=first; } else { if(request) stop_invalid(); option_list(first); while(p<=n && hws(substr(line,p,1))) p++; start=p; while(p<=n && !hws(substr(line,p,1))) p++; alg=substr(line,start,p-start); if(!algorithm(alg)) stop_invalid(); } while(p<=n && hws(substr(line,p,1))) p++; start=p; while(p<=n && !hws(substr(line,p,1))) p++; blob=substr(line,start,p-start); if(!canonical_blob(blob)) stop_invalid(); return alg SUBSEP blob; } BEGIN { if(ARGC!=3) stop_invalid(); alphabet=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\"; n=split(\"restrict cert-authority no-agent-forwarding no-port-forwarding no-pty no-user-rc no-X11-forwarding agent-forwarding port-forwarding pty user-rc X11-forwarding no-touch-required verify-required\",names,\" \"); for(i=1;i<=n;i++) flag[names[i]]=1; n=split(\"command environment expiry-time from permitlisten permitopen principals tunnel\",names,\" \"); for(i=1;i<=n;i++) valued[names[i]]=1; } FILENAME==ARGV[1] { k=identity($0,1); wanted[k]=1; requests++; next; } FILENAME==ARGV[2] { k=identity($0,0); if(k!=\"\") found[k]=1; next; } { stop_invalid(); } END { if(invalid || !requests) exit 34; for(k in wanted) if(!(k in found)) exit 34; } ' /dev/stdin \"$auth\" >/dev/null 2>&1 || exit 34\n"
# Frozen approved sourceae0 install program, not a future SUT-derived oracle.
# Original 292-346/438-481 quoted DATA mechanically joined before implementation.
EXPECTED_INSTALL_KEY_SCRIPT = "set -eu; LC_ALL=C; export LC_ALL; command -v tr >/dev/null 2>&1 || exit 34; test -n \"${HOME:-}\" && test -d \"$HOME\" && test ! -L \"$HOME\" || exit 31; ssh_dir=\"$HOME/.ssh\"; if test -L \"$ssh_dir\" || { test -e \"$ssh_dir\" && test ! -d \"$ssh_dir\"; }; then exit 32; fi; umask 077; mkdir -p \"$ssh_dir\"; chmod 700 \"$ssh_dir\"; auth=\"$ssh_dir/authorized_keys\"; if test -L \"$auth\" || { test -e \"$auth\" && test ! -f \"$auth\"; }; then exit 33; fi; tmp=\"\"; required=\"\"; staged=\"\"; appended=\"\"; bytecheck=\"\"; trap 'for task_private in \"$tmp\" \"$required\" \"$staged\" \"$appended\" \"$bytecheck\"; do if test -n \"$task_private\"; then rm -f \"$task_private\" || :; fi; done' EXIT HUP INT TERM; tmp=\"$(mktemp \"$ssh_dir/.authorized_keys.XXXXXX\")\" || exit 34; required=\"$(mktemp \"$ssh_dir/.required_keys.XXXXXX\")\" || exit 34; staged=\"$(mktemp \"$ssh_dir/.staged_keys.XXXXXX\")\" || exit 34; appended=\"$(mktemp \"$ssh_dir/.appended_keys.XXXXXX\")\" || exit 34; bytecheck=\"$(mktemp \"$ssh_dir/.key_bytes.XXXXXX\")\" || exit 34; printf %s \"$1\" | base64 -d >\"$required\" || exit 34; test -s \"$required\" || exit 34; if test -f \"$auth\"; then ( cat \"$auth\" >\"$staged\"; ) || exit 34; fi; for task_input in \"$staged\" \"$required\"; do tr -d '\\011\\012\\015\\040-\\176\\200-\\377' <\"$task_input\" >\"$bytecheck\" || exit 34; test ! -s \"$bytecheck\" || exit 34; done; awk 'function stop_invalid() { invalid=1; exit 34; } function hws(c) { return c==\" \" || c==\"\\t\"; } function algorithm(s) { return s ~ /^(ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+$/; } function canonical_blob(s, n,p,v) { n=length(s); if(n<4 || n%4!=0 || s !~ /^[A-Za-z0-9+\\/]+=?=?$/) return 0; p=index(s,\"=\"); if(!p) return 1; if(substr(s,n-1,2)==\"==\") { if(p!=n-1) return 0; v=index(alphabet,substr(s,n-2,1))-1; return v>=0 && v%16==0; } if(p!=n) return 0; v=index(alphabet,substr(s,n-1,1))-1; return v>=0 && v%4==0; } function option_list(s, p,n,start,name,c,closed) { n=length(s); p=1; if(!n) stop_invalid(); while(p<=n) { start=p; while(p<=n && substr(s,p,1)!=\"=\" && substr(s,p,1)!=\",\") p++; name=substr(s,start,p-start); if(name !~ /^[A-Za-z][A-Za-z0-9-]*$/) stop_invalid(); c=substr(s,p,1); if(c==\"=\") { if(!(name in valued)) stop_invalid(); p++; if(substr(s,p,1)!=\"\\\"\") stop_invalid(); p++; closed=0; while(p<=n) { c=substr(s,p,1); if(c==\"\\\\\") { if(p==n || substr(s,p+1,1)!=\"\\\"\") stop_invalid(); p+=2; continue; } if(c==\"\\\"\") { p++; closed=1; break; } p++; } if(!closed) stop_invalid(); if(p<=n && substr(s,p,1)!=\",\") stop_invalid(); } else { if(!(name in flag)) stop_invalid(); } if(p>n) return 1; if(substr(s,p,1)!=\",\") stop_invalid(); p++; if(p>n) stop_invalid(); } return 1; } function identity(line,request, n,p,start,c,quoted,first,alg,blob) { n=length(line); if(request) { if(index(line,\"\\r\")) stop_invalid(); } else if(n && substr(line,n,1)==\"\\r\") { line=substr(line,1,n-1); n--; } if(index(line,\"\\r\")) stop_invalid(); p=1; while(p<=n && hws(substr(line,p,1))) p++; if(p>n || substr(line,p,1)==\"#\") { if(request) stop_invalid(); return \"\"; } start=p; quoted=0; while(p<=n) { c=substr(line,p,1); if(c==\"\\\\\") { if(!quoted || p==n || substr(line,p+1,1)!=\"\\\"\") stop_invalid(); p+=2; continue; } if(c==\"\\\"\") { quoted=!quoted; p++; continue; } if(!quoted && hws(c)) break; p++; } if(quoted) stop_invalid(); first=substr(line,start,p-start); if(algorithm(first)) { alg=first; } else { if(request) stop_invalid(); option_list(first); while(p<=n && hws(substr(line,p,1))) p++; start=p; while(p<=n && !hws(substr(line,p,1))) p++; alg=substr(line,start,p-start); if(!algorithm(alg)) stop_invalid(); } while(p<=n && hws(substr(line,p,1))) p++; start=p; while(p<=n && !hws(substr(line,p,1))) p++; blob=substr(line,start,p-start); if(!canonical_blob(blob)) stop_invalid(); return alg SUBSEP blob; } BEGIN { if(ARGC!=3) stop_invalid(); alphabet=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\"; n=split(\"restrict cert-authority no-agent-forwarding no-port-forwarding no-pty no-user-rc no-X11-forwarding agent-forwarding port-forwarding pty user-rc X11-forwarding no-touch-required verify-required\",names,\" \"); for(i=1;i<=n;i++) flag[names[i]]=1; n=split(\"command environment expiry-time from permitlisten permitopen principals tunnel\",names,\" \"); for(i=1;i<=n;i++) valued[names[i]]=1; } FILENAME==ARGV[1] { k=identity($0,0); if(k!=\"\") seen[k]=1; next; } FILENAME==ARGV[2] { k=identity($0,1); requests++; if(!(k in seen)) { seen[k]=1; missing[++count]=$0; } next; } { stop_invalid(); } END { if(invalid || !requests) exit 34; for(i=1;i<=count;i++) print missing[i]; } ' \"$staged\" \"$required\" >\"$appended\" || exit 34; cat \"$staged\" >\"$tmp\" || exit 34; if test -s \"$appended\"; then if test -s \"$staged\"; then task_last=\"$(tail -c 1 \"$staged\")\" || exit 34; if test -n \"$task_last\"; then printf '\\n' >>\"$tmp\" || exit 34; fi; fi; cat \"$appended\" >>\"$tmp\" || exit 34; fi; awk 'function stop_invalid() { invalid=1; exit 34; } function hws(c) { return c==\" \" || c==\"\\t\"; } function algorithm(s) { return s ~ /^(ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+$/; } function canonical_blob(s, n,p,v) { n=length(s); if(n<4 || n%4!=0 || s !~ /^[A-Za-z0-9+\\/]+=?=?$/) return 0; p=index(s,\"=\"); if(!p) return 1; if(substr(s,n-1,2)==\"==\") { if(p!=n-1) return 0; v=index(alphabet,substr(s,n-2,1))-1; return v>=0 && v%16==0; } if(p!=n) return 0; v=index(alphabet,substr(s,n-1,1))-1; return v>=0 && v%4==0; } function option_list(s, p,n,start,name,c,closed) { n=length(s); p=1; if(!n) stop_invalid(); while(p<=n) { start=p; while(p<=n && substr(s,p,1)!=\"=\" && substr(s,p,1)!=\",\") p++; name=substr(s,start,p-start); if(name !~ /^[A-Za-z][A-Za-z0-9-]*$/) stop_invalid(); c=substr(s,p,1); if(c==\"=\") { if(!(name in valued)) stop_invalid(); p++; if(substr(s,p,1)!=\"\\\"\") stop_invalid(); p++; closed=0; while(p<=n) { c=substr(s,p,1); if(c==\"\\\\\") { if(p==n || substr(s,p+1,1)!=\"\\\"\") stop_invalid(); p+=2; continue; } if(c==\"\\\"\") { p++; closed=1; break; } p++; } if(!closed) stop_invalid(); if(p<=n && substr(s,p,1)!=\",\") stop_invalid(); } else { if(!(name in flag)) stop_invalid(); } if(p>n) return 1; if(substr(s,p,1)!=\",\") stop_invalid(); p++; if(p>n) stop_invalid(); } return 1; } function identity(line,request, n,p,start,c,quoted,first,alg,blob) { n=length(line); if(request) { if(index(line,\"\\r\")) stop_invalid(); } else if(n && substr(line,n,1)==\"\\r\") { line=substr(line,1,n-1); n--; } if(index(line,\"\\r\")) stop_invalid(); p=1; while(p<=n && hws(substr(line,p,1))) p++; if(p>n || substr(line,p,1)==\"#\") { if(request) stop_invalid(); return \"\"; } start=p; quoted=0; while(p<=n) { c=substr(line,p,1); if(c==\"\\\\\") { if(!quoted || p==n || substr(line,p+1,1)!=\"\\\"\") stop_invalid(); p+=2; continue; } if(c==\"\\\"\") { quoted=!quoted; p++; continue; } if(!quoted && hws(c)) break; p++; } if(quoted) stop_invalid(); first=substr(line,start,p-start); if(algorithm(first)) { alg=first; } else { if(request) stop_invalid(); option_list(first); while(p<=n && hws(substr(line,p,1))) p++; start=p; while(p<=n && !hws(substr(line,p,1))) p++; alg=substr(line,start,p-start); if(!algorithm(alg)) stop_invalid(); } while(p<=n && hws(substr(line,p,1))) p++; start=p; while(p<=n && !hws(substr(line,p,1))) p++; blob=substr(line,start,p-start); if(!canonical_blob(blob)) stop_invalid(); return alg SUBSEP blob; } BEGIN { if(ARGC!=3) stop_invalid(); alphabet=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\"; n=split(\"restrict cert-authority no-agent-forwarding no-port-forwarding no-pty no-user-rc no-X11-forwarding agent-forwarding port-forwarding pty user-rc X11-forwarding no-touch-required verify-required\",names,\" \"); for(i=1;i<=n;i++) flag[names[i]]=1; n=split(\"command environment expiry-time from permitlisten permitopen principals tunnel\",names,\" \"); for(i=1;i<=n;i++) valued[names[i]]=1; } FILENAME==ARGV[1] { k=identity($0,1); wanted[k]=1; requests++; next; } FILENAME==ARGV[2] { k=identity($0,0); if(k!=\"\") found[k]=1; next; } { stop_invalid(); } END { if(invalid || !requests) exit 34; for(k in wanted) if(!(k in found)) exit 34; } ' \"$required\" \"$tmp\" || exit 34; chmod 600 \"$tmp\" || exit 34; if test ! -s \"$appended\"; then test -f \"$auth\" && test ! -L \"$auth\" || exit 33; chmod 600 \"$auth\" || exit 34; rm -f \"$tmp\" \"$required\" \"$staged\" \"$appended\" \"$bytecheck\" || exit 34; trap - EXIT HUP INT TERM; printf 'IBSW_PUBLIC_KEYS_UNCHANGED\\n'; exit 0; fi; if test -L \"$auth\" || { test -e \"$auth\" && test ! -f \"$auth\"; }; then exit 33; fi; mv -f \"$tmp\" \"$auth\" || exit 34; tmp=\"\"; rm -f \"$required\" \"$staged\" \"$appended\" \"$bytecheck\" || exit 34; trap - EXIT HUP INT TERM; printf 'IBSW_PUBLIC_KEYS_UPDATED\\n'"


class ReadonlyPublicKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_script("wp7_readonly_program_source", INITIAL)

    def public_entry(self, number):
        algorithm = b"ssh-ed25519"
        wire = (struct.pack(">I", len(algorithm)) + algorithm
                + struct.pack(">I", 32) + bytes([number]) * 32)
        line = "ssh-ed25519 " + base64.b64encode(wire).decode("ascii") + " PUBLIC-required-" + str(number)
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii").rstrip("=")
        return {"name": "PUBLIC-" + str(number) + ".pub", "line": line, "fingerprint": fingerprint}

    def entries(self):
        return [self.public_entry(1), self.public_entry(2)]

    def payload(self):
        # Independent wire/line inputs above, never _key_payload or a SUT builder.
        return base64.b64encode(("\n".join(entry["line"] for entry in self.entries()) + "\n")
                                .encode("ascii")).decode("ascii")

    def test_readonly_builder_matches_exact_program_vector_and_payload(self):
        expected = ["sh", "-c", EXPECTED_READONLY_KEY_SCRIPT, "--", self.payload()]
        self.assertEqual(3456, len(EXPECTED_READONLY_KEY_SCRIPT.encode("ascii")))
        self.assertEqual("3727325154970f2da4dc74426e7743a6359b151f6c3fa9e8a83e21050e179cea",
                         hashlib.sha256(EXPECTED_READONLY_KEY_SCRIPT.encode("ascii")).hexdigest())
        self.assertEqual(expected, self.app.readonly_key_command(self.entries()))
        self.assertEqual(expected, self.app.ib_command_argv(expected))

    def test_closed_readonly_vectors_reject_near_misses(self):
        script, payload = EXPECTED_READONLY_KEY_SCRIPT, self.payload()
        bad = (
            ["sh", "-c", script + " ", "--", payload],
            ["sh", "-c", script + ":\n", "--", payload],
            ["sh", "-c", script.replace("base64 -d", "base64", 1), "--", payload],
            ["bash", "-c", script, "--", payload],
            ["sh", "-c", script, "not--", payload],
            ["sh", "-c", script, "--"],
            ["sh", "-c", script, "--", payload, "extra"],
            ["sh", "-c", script, "--", ""],
            ["sh", "-c", script, "--", payload + "\n"],
            ["sh", "-c", script, "--", "not%base64"],
            ["sh", "-c", script, "--", "A" * 131073],
        )
        for ordinal, command in enumerate(bad):
            with self.subTest(case=ordinal), self.assertRaises(self.app.SetupError):
                self.app.ib_command_argv(command)

    def test_original_install_builder_keeps_complete_frozen_tuple(self):
        # No install shell is run. This pins the ENTIRE old program and payload.
        expected = ["sh", "-c", EXPECTED_INSTALL_KEY_SCRIPT, "--", self.payload()]
        self.assertEqual(8489, len(EXPECTED_INSTALL_KEY_SCRIPT.encode("ascii")))
        self.assertEqual(expected, self.app.key_install_command(self.entries()))
        self.assertEqual(expected, self.app.ib_command_argv(expected))

    def test_both_builders_keep_original_public_entry_qualification(self):
        first = self.public_entry(1)
        invalid = (
            [],
            [{"name": first["name"], "line": first["line"]}],
            [{**first, "name": "../PUBLIC.pub"}],
            [{**first, "fingerprint": "SHA256:" + "A" * 43}],
            [{**first, "line": first["line"] + "\n"}],
        )
        for ordinal, keys in enumerate(invalid):
            for builder in (self.app.readonly_key_command, self.app.key_install_command):
                with self.subTest(case=ordinal, builder=builder.__name__), self.assertRaises(self.app.SetupError):
                    builder(keys)

    def snapshot(self, root):
        paths = [root, *sorted(root.rglob("*"))]
        result = {}
        for path in paths:
            info = path.lstat()
            self.assertFalse(stat.S_ISLNK(info.st_mode), "PUBLIC shell fixture acquired a symlink")
            self.assertEqual(os.geteuid(), info.st_uid)
            self.assertTrue(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            result[str(path.relative_to(root))] = (
                info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode),
                path.read_bytes() if stat.S_ISREG(info.st_mode) else None)
        return result

    def run_readonly_case(self, authorized, expected_code, *, decoder_fault=False):
        # Build/admit BEFORE any process. Unknown or modified code never executes.
        command = self.app.readonly_key_command(self.entries())
        self.assertEqual(["sh", "-c", EXPECTED_READONLY_KEY_SCRIPT, "--", self.payload()], command)
        self.assertEqual(command, self.app.ib_command_argv(command))
        own = owned_test_root()  # pure explicit Root-issued directory qualification only
        with tempfile.TemporaryDirectory(prefix="wp7-readonly-", dir=own) as directory:
            root = Path(directory)
            self.assertEqual(own, root.parent)
            self.assertEqual(0o700, stat.S_IMODE(root.lstat().st_mode))
            home = root / "home"
            home.mkdir(mode=0o700)
            ssh = home / ".ssh"
            ssh.mkdir(mode=0o700)
            if authorized is not None:
                auth = ssh / "authorized_keys"
                auth.write_bytes(authorized)
                auth.chmod(0o640)  # readonly must not silently chmod this to 0600
            search = os.defpath
            if decoder_fault:
                binaries = root / "bin"
                binaries.mkdir(mode=0o700)
                decoder = binaries / "base64"
                # Fixed PUBLIC helper: valid full output followed by actual nonzero.
                lines = [entry["line"] for entry in self.entries()]
                decoder.write_text("#!/bin/sh\n"
                    "[ \"$#\" -eq 1 ] && [ \"$1\" = \"-d\" ] || exit 97\n"
                    "printf '%s\\n' '" + lines[0] + "' '" + lines[1] + "'\nexit 7\n", encoding="ascii")
                decoder.chmod(0o700)
                search = str(binaries) + os.pathsep + os.defpath
            before = self.snapshot(root)
            result = subprocess.run(["/bin/sh", *command[1:]], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False,
                cwd=home, env={"HOME": str(home), "PATH": search, "LC_ALL": "C", "LANG": "C"})
            self.assertEqual(expected_code, result.returncode)
            self.assertEqual(b"", result.stdout)
            self.assertEqual(b"", result.stderr)
            self.assertEqual(before, self.snapshot(root),
                             "readonly changed bytes/inode/mode or the owned directory listing")

    def test_public_readonly_shell_covers_presence_options_comments_without_writes(self):
        first, second, extra = (self.public_entry(n)["line"] for n in (1, 2, 3))
        options = ('# PUBLIC comment\n\nrestrict,command="echo PUBLIC-not-executed" '
                   + first.rsplit(" ", 1)[0] + ' different-comment\r\n'
                   'from="192.0.2.0/24",no-pty ' + second.rsplit(" ", 1)[0]
                   + " another-comment\n" + extra + "\n")
        for label, authorized, code in (
                ("all-present", (first + "\n" + second + "\n").encode("ascii"), 0),
                ("one-missing", (first + "\n").encode("ascii"), 34),
                ("all-missing", (extra + "\n").encode("ascii"), 34),
                ("empty-authorized", b"", 34),
                ("no-authorized-file", None, 34),
                ("options-extra-comments", options.encode("ascii"), 0)):
            with self.subTest(case=label):
                self.run_readonly_case(authorized, code)

    def test_decoder_valid_output_followed_by_nonzero_cannot_claim_presence(self):
        text = "\n".join(entry["line"] for entry in self.entries()) + "\n"
        self.run_readonly_case(text.encode("ascii"), 34, decoder_fault=True)


# r757 independent managed-selection API slice. Original 440 lines unchanged.
from contextlib import contextmanager

MANAGED_NAMES = ("EXAMPLE-IB01", "EXAMPLE-IB02")
MANAGED_CSV = (
    "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
    "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
    "EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,02:00:00:00:00:02,,,,initial-setup\n"
    "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,,\n"
)


class ManagedSelectionTests(unittest.TestCase):
    """Real producer/cache/M4 on PUBLIC local files; no native/KAT/device I/O.

    Expected selection/order and refusal cases are independent r757 WP6
    literals. No cycle/start/_inputs/profile/qualification is replaced.
    """
    @classmethod
    def setUpClass(cls):
        cls.app = load_script("wp6_managed_selection_direct_initial", INITIAL)
        cls.authority = load_script("wp6_managed_selection_direct_authority",
                                    INITIAL.parents[3] / "ztp/config_sync_authority.py")

    @contextmanager
    def fixture(self, *, strict=False):
        # Only the separately authorized workflow asks the ORIGINAL fixture for
        # strict=True; direct API cases use its PUBLIC non-KAT profile.
        from test_cases import test_req10b_services_keys_workflow as original
        helper = original.Req10BServicesKeysWorkflowTests()
        helper.initial = self.app
        with tempfile.TemporaryDirectory(prefix="wp6-managed-", dir=owned_test_root()) as raw:
            root = Path(raw).resolve()
            values = helper.strict_fixture(str(root)) if strict else helper.fixture(str(root))
            _, tool, global_file, csv_path, p2p, pubdir, cache, laptop, management = values
            csv_path.write_text(MANAGED_CSV, encoding="ascii")
            for master in (root / "02-devices_config.csv", root / "infiniband/02-devices_config.csv"):
                master.write_text(MANAGED_CSV, encoding="ascii")
            p2p.write_text('"EXAMPLE-IB01":"eth0" -- "EXAMPLE-JUMP01":"7";\n'
                           '"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n', encoding="ascii")
            cache.parent.mkdir()
            # These are real read/parse/qualification producers, not hand-made
            # cache or authority admission dictionaries.
            ibs, eths = self.app.load_devices(csv_path)
            links = self.app.parse_p2p(p2p)
            self.app.validate_p2p_links(links)
            targets = self.app.build_targets(links, ibs, eths)
            self.assertEqual(list(MANAGED_NAMES), [target.ib.hostname for target in targets])
            services = self.app._service_profile(tool)
            keys = self.app._public_key_profile(tool, validate_with_ssh_keygen=False)
            inventory = self.app._compare_inventory(csv_path, root)
            self.app.save_target_cache(cache, csv_path, p2p, 2, targets,
                                       global_file=global_file, services=services,
                                       public_keys=keys, inventory_check=inventory)
            accepted = self.app.load_target_cache(cache, csv_path, p2p, public_key_tool=tool)
            self.assertTrue(accepted is not None, "real complete PUBLIC cache must be admitted")
            self.assertEqual(2, accepted[0])
            self.assertEqual(targets, accepted[1])
            cycle = self.authority.ManagedInitialMethodCycle(root, self.app)
            cycle.admit_paths((csv_path, p2p), (root / "out/report.log",))
            f = dict(root=root, tool=tool, global_file=global_file, csv=csv_path, p2p=p2p,
                     pubdir=pubdir, cache=cache, targets=targets, services=services, keys=keys,
                     cycle=cycle, laptop=laptop, management=management)
            f["args"] = (tool, cache, csv_path, p2p, targets, services, keys)
            try:
                yield f
            finally:
                cycle.close()

    @contextmanager
    def authority_events(self):
        events = []
        with ExitStack() as stack:
            for name in ("begin_method", "read_method_current", "read_method_receipt", "revoke_method"):
                original = getattr(self.authority, name)
                def observed(*args, _name=name, _original=original, **kwargs):
                    events.append((_name, args[1]))
                    return _original(*args, **kwargs)
                stack.enter_context(mock.patch.object(self.authority, name, new=observed))
            yield events

    def ledger_images(self, root, hostname):
        # Test-side observation only, outside the recorded product I/O interval.
        paths = sorted((root / ".authority").glob(hostname.casefold() + ".*"))
        return {path.name: (path.stat().st_dev, path.stat().st_ino,
                            stat.S_IMODE(path.stat().st_mode), path.read_bytes()) for path in paths}

    def test_default_and_explicit_selection_keep_full_canonical_targets(self):
        # Original 7 positional args still work; explicit tuple order never
        # changes the full target list's canonical ticket/expected order.
        cases = (("old-positional", None, ["example-ib01", "example-ib02"]),
                 ("explicit-none", None, ["example-ib01", "example-ib02"]),
                 ("one", ("EXAMPLE-IB02",), ["example-ib02"]),
                 ("both", MANAGED_NAMES, ["example-ib01", "example-ib02"]),
                 ("inverse", ("EXAMPLE-IB02", "EXAMPLE-IB01"), ["example-ib01", "example-ib02"]))
        for label, selected, expected in cases:
            with self.subTest(case=label), self.fixture() as f, self.authority_events() as events:
                cycle = f["cycle"]
                if label == "old-positional":
                    cycle.start(*f["args"])
                else:
                    cycle.start(*f["args"], selected_names=selected)
                self.assertEqual(f["targets"], cycle.targets)
                self.assertEqual(expected, list(cycle.tickets))
                self.assertEqual(expected, list(cycle.expected))
                self.assertEqual(expected, [name.casefold() for kind, name in events if kind == "begin_method"])
                self.assertEqual(cycle.images, cycle._inputs())
                cycle.close()
                self.assertTrue(all(name.casefold() in expected for kind, name in events))

    def test_invalid_selected_names_refuse_before_any_begin(self):
        for ordinal, selected in enumerate(((), [], ["EXAMPLE-IB01"], "EXAMPLE-IB01",
                frozenset({"EXAMPLE-IB01"}), (1,), ("",),
                ("EXAMPLE-IB01", "example-ib01"), ("OUTSIDE-IB99",),
                ("EXAMPLE-IB01", "OUTSIDE-IB99"))):
            with self.subTest(case=ordinal), self.fixture() as f, self.authority_events() as events:
                with self.assertRaises(self.authority.AuthorityError):
                    f["cycle"].start(*f["args"], selected_names=selected)
                self.assertEqual([], events, "invalid explicit selection must precede every begin/read/revoke")
                self.assertFalse(f["cycle"].root.exists())
        with self.fixture() as f, self.authority_events() as events:
            with self.assertRaises(TypeError):
                f["cycle"].start(*f["args"], ("EXAMPLE-IB01",))
            self.assertEqual([], events, "selected_names is keyword-only after the original seven positions")

    def test_unselected_old_ledger_and_no_ticket_completion_are_untouched(self):
        with self.fixture() as f:
            cycle = f["cycle"]
            old = self.authority.begin_method(cycle.root, "EXAMPLE-IB02", "old-public-writer",
                                              "old-public-writer:EXAMPLE-IB02", "initial_setup_managed")
            self.authority.revoke_method(cycle.root, "EXAMPLE-IB02", expected=old)
            before = self.ledger_images(cycle.root, "EXAMPLE-IB02")
            self.assertTrue(before)
            observer = self.app.observe_managed_initial_configuration
            with self.authority_events() as events, mock.patch.object(
                    self.app, "observe_managed_initial_configuration", wraps=observer) as watched:
                cycle.start(*f["args"], selected_names=("EXAMPLE-IB01",))
                with self.assertRaises((self.authority.AuthorityError, KeyError)):
                    cycle.complete(f["targets"][1], "admin", None, 2, f["services"], f["keys"])
                cycle.fail_unfinished(f["targets"][1])
                cycle.close()
                cycle.close()
                watched.assert_not_called()
            self.assertFalse(any(name.casefold() == "example-ib02" for kind, name in events))
            self.assertEqual(before, self.ledger_images(cycle.root, "EXAMPLE-IB02"))
            self.assertNotIn("example-ib02", cycle.tickets)

    def test_full_input_recheck_rejects_changed_unselected_inventory(self):
        with self.fixture() as f:
            cycle = f["cycle"]
            cycle.start(*f["args"], selected_names=("EXAMPLE-IB01",))
            self.assertEqual(list(MANAGED_NAMES), [target.ib.hostname for target in cycle.targets])
            self.assertEqual(cycle.images, cycle._inputs())
            original = f["csv"].read_text(encoding="ascii")
            old = "EXAMPLE-IB02,ib,203.0.113.3,24"
            self.assertEqual(1, original.count(old))
            f["csv"].write_text(original.replace(old, "EXAMPLE-IB02,ib,203.0.113.99,24"), encoding="ascii")
            with self.assertRaises(self.authority.AuthorityError):
                cycle._inputs()

    def test_partial_begin_failure_closes_only_minted_canonical_prefix(self):
        with self.fixture() as f:
            original = self.authority.begin_method
            attempted = []
            def first_then_failure(*args, **kwargs):
                attempted.append(args[1])
                if args[1] == "EXAMPLE-IB02":
                    raise self.authority.AuthorityError("PUBLIC second selected begin refused")
                return original(*args, **kwargs)
            with mock.patch.object(self.authority, "begin_method", new=first_then_failure):
                with self.assertRaises(self.authority.AuthorityError):
                    f["cycle"].start(*f["args"], selected_names=("EXAMPLE-IB02", "EXAMPLE-IB01"))
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], attempted)
            self.assertEqual("failed", self.authority.read_method_current(f["cycle"].root, "EXAMPLE-IB01")["state"])
            self.assertIsNone(self.authority.read_method_current(f["cycle"].root, "EXAMPLE-IB02"))
            f["cycle"].close()

    def test_repeated_close_does_not_revoke_a_newer_writer(self):
        with self.fixture() as f:
            cycle = f["cycle"]
            cycle.start(*f["args"], selected_names=("EXAMPLE-IB01",))
            current = self.authority.begin_method(cycle.root, "EXAMPLE-IB01", "new-public-writer",
                                                  "new-public-writer:EXAMPLE-IB01", "initial_setup_managed")
            self.assertEqual(2, current["generation"])
            before = self.ledger_images(cycle.root, "EXAMPLE-IB01")
            with self.authority_events() as events:
                cycle.close()
                cycle.close()
            self.assertFalse(any(kind == "revoke_method" for kind, name in events))
            self.assertFalse(any(name.casefold() == "example-ib02" for kind, name in events))
            self.assertEqual(current, self.authority.read_method_current(cycle.root, "EXAMPLE-IB01"))
            self.assertEqual(before, self.ledger_images(cycle.root, "EXAMPLE-IB01"))

    def test_default_profile_refusal_still_follows_all_pending_begins(self):
        with self.fixture() as f:
            cycle, pending = f["cycle"], []
            original = self.authority.begin_method
            def begin(*args, **kwargs):
                result = original(*args, **kwargs)
                pending.append((args[1], result["state"], result["veto"]))
                return result
            args = (*f["args"][:5], None, f["keys"])
            with mock.patch.object(self.authority, "begin_method", new=begin):
                with self.assertRaises(self.authority.AuthorityError):
                    cycle.start(*args)
            self.assertEqual([("EXAMPLE-IB01", "pending", True), ("EXAMPLE-IB02", "pending", True)], pending)
            for name in MANAGED_NAMES:
                self.assertEqual("failed", self.authority.read_method_current(cycle.root, name)["state"])


class BringupResultsContractTests(unittest.TestCase):
    """D6 output/selector contracts; no new result-constructor API is assumed."""

    @classmethod
    def setUpClass(cls):
        cls.app = load_script("wp6_result_contract_source", INITIAL)
        cls.ranges = cls.app._import_tools("tools.hostname_ranges")

    def parse_devices(self, text):
        import sys
        with mock.patch.object(sys, "argv", ["initial-setup.py", "--devices", text]):
            return self.app.parse_args().devices

    def test_devices_selector_forms_keep_inventory_order(self):
        names = ["EXAMPLE-IB003", "EXAMPLE-IB001", "EXAMPLE-IB002",
                 "EXAMPLE-IBa", "EXAMPLE-IBb", "EXAMPLE-IBz"]
        for selector, expected in (
                ("EXAMPLE-IB001,EXAMPLE-IB003", ["EXAMPLE-IB003", "EXAMPLE-IB001"]),
                ("EXAMPLE-IB00*", ["EXAMPLE-IB003", "EXAMPLE-IB001", "EXAMPLE-IB002"]),
                ("EXAMPLE-IB00[1-3]", ["EXAMPLE-IB003", "EXAMPLE-IB001", "EXAMPLE-IB002"]),
                ("EXAMPLE-IB[a-b]", ["EXAMPLE-IBa", "EXAMPLE-IBb"]),
                ("EXAMPLE-IB002,EXAMPLE-IB[a-b]", ["EXAMPLE-IB002", "EXAMPLE-IBa", "EXAMPLE-IBb"])):
            with self.subTest(selector=selector):
                raw = self.parse_devices(selector)
                self.assertEqual(selector, raw)
                parsed = self.ranges.parse_selector(raw, option="--devices")
                self.assertEqual(expected, self.ranges.select(parsed, names))

    def test_devices_all_is_a_literal_name(self):
        raw = self.parse_devices("all")
        selector = self.ranges.parse_selector(raw, option="--devices")
        self.assertEqual(["all"], self.ranges.select(selector, ["EXAMPLE-IB001", "all"]))
        with self.assertRaisesRegex(self.ranges.SelectorError, "--devices.*all"):
            self.ranges.select(selector, ["EXAMPLE-IB001", "EXAMPLE-IB002"])

    def plan(self, selector, *extra):
        import io
        import sys
        from contextlib import redirect_stderr, redirect_stdout
        attempts = []

        def deny(*unused, **ignored):
            attempts.append("external")
            raise AssertionError("selector PLAN must not contact a device or start a child")

        header = "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
        inventory = (
            "EXAMPLE-IB001,ib,203.0.113.11,24,203.0.113.1,02:00:00:00:00:11,,,\n"
            "EXAMPLE-IB002,ib,203.0.113.12,24,203.0.113.1,02:00:00:00:00:12,,,\n"
            "EXAMPLE-IB003,ib,203.0.113.13,24,203.0.113.1,02:00:00:00:00:13,,,\n"
            "EXAMPLE-IBa,ib,203.0.113.14,24,203.0.113.1,02:00:00:00:00:14,,,\n"
            "EXAMPLE-IBb,ib,203.0.113.15,24,203.0.113.1,02:00:00:00:00:15,,,\n"
            "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n")
        # Independent master input, never copied back from a generated subset.
        master = (
            "EXAMPLE-IB001,ib,203.0.113.11,24,203.0.113.1,02:00:00:00:00:11,,,\n"
            "EXAMPLE-IB002,ib,203.0.113.12,24,203.0.113.1,02:00:00:00:00:12,,,\n"
            "EXAMPLE-IB003,ib,203.0.113.13,24,203.0.113.1,02:00:00:00:00:13,,,\n"
            "EXAMPLE-IBa,ib,203.0.113.14,24,203.0.113.1,02:00:00:00:00:14,,,\n"
            "EXAMPLE-IBb,ib,203.0.113.15,24,203.0.113.1,02:00:00:00:00:15,,,\n"
            "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n")
        with tempfile.TemporaryDirectory(prefix="wp6-selector-contract-") as directory, ExitStack() as stack:
            root = Path(directory)
            (root / "ib.csv").write_text(header + inventory, encoding="ascii")
            (root / "02-devices_config.csv").write_text(header + master, encoding="ascii")
            (root / "p2p.dot").write_text(
                '"EXAMPLE-IB001":"eth0" -- "EXAMPLE-JUMP01":"swp1";\n'
                '"EXAMPLE-IB002":"eth0" -- "EXAMPLE-JUMP01":"swp2";\n'
                '"EXAMPLE-IB003":"eth0" -- "EXAMPLE-JUMP01":"swp3";\n'
                '"EXAMPLE-IBa":"eth0" -- "EXAMPLE-JUMP01":"swp4";\n'
                '"EXAMPLE-IBb":"eth0" -- "EXAMPLE-JUMP01":"swp5";\n', encoding="ascii")
            neutral = root / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
            neutral.parent.mkdir(parents=True)
            neutral.write_text("DNS=192.0.2.53\nNTP=time.example.test\nTIMEZONE=Etc/UTC\n", encoding="ascii")
            home = root / "home"
            home.mkdir(mode=0o700)
            argv = ["initial-setup.py", "--project-dir", str(root), "--ib-csv", str(root / "ib.csv"),
                    "--p2p", str(root / "p2p.dot"), "--target-cache", str(root / "out/targets.json"),
                    "--report", str(root / "out/report.log"), "--snapshot-dir", str(root / "out/snapshots"),
                    "--execution-mode", "management", "--plan", "--devices", selector, *extra]
            for name in ("interactive_run", "run_on_ib", "run_on_ethernet", "verify_password_hash",
                         "prompt_ethernet_passwords", "collect_ethernet_interfaces", "collect_ethernet_network_tables",
                         "_ensure_ib_config_backup", "obtain_write_permit"):
                stack.enter_context(mock.patch.object(self.app, name, new=deny))
            stack.enter_context(mock.patch.object(self.app, "_read_local_interfaces", return_value=()))
            stack.enter_context(mock.patch.object(self.app, "subprocess", new=SimpleNamespace(
                run=deny, Popen=deny, SubprocessError=subprocess.SubprocessError)))
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(self.app, "REPORT_HANDLE", None))
            stack.enter_context(mock.patch.object(Path, "home", return_value=home))
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                try:
                    result = self.app._standalone_main_with_report_cleanup()
                except SystemExit as error:
                    result = error.code
            self.assertEqual([], attempts)
            return result, output.getvalue(), errors.getvalue()

    def test_devices_plan_contains_only_selected_devices(self):
        import re
        result, output, errors = self.plan("EXAMPLE-IB00[1-2]")
        self.assertEqual(0, result, errors)
        self.assertEqual(["EXAMPLE-IB001", "EXAMPLE-IB002"],
                         re.findall(r"(?m)^\s*\[([^]]+)\] Network commands:", output))

    def test_unmatched_devices_exit_two_before_device_io(self):
        self.assertEqual("EXAMPLE-MISSING", self.parse_devices("EXAMPLE-MISSING"))
        result, output, errors = self.plan("EXAMPLE-MISSING")
        self.assertEqual(2, result)
        self.assertIn("--devices", errors + output)
        self.assertIn("EXAMPLE-MISSING", errors + output)

    def test_direct_access_and_refresh_keep_full_csv_scope(self):
        import re
        result, output, errors = self.plan("EXAMPLE-IB001", "--direct-access", "EXAMPLE-IB003",
                                           "--refresh-host-key", "EXAMPLE-IBb")
        self.assertEqual(0, result, errors)
        self.assertEqual(["EXAMPLE-IB001"],
                         re.findall(r"(?m)^\s*\[([^]]+)\] Network commands:", output))

    def test_summary_denominator_uses_selected_csv_count(self):
        records, targets, direct = {}, [], []
        for name, address in (("EXAMPLE-IB001", "203.0.113.11"), ("EXAMPLE-IB002", "203.0.113.12")):
            device = self.app.Device(name, "ib", address, address + "/24", "203.0.113.1",
                                     "02:00:00:00:00:11", "", "")
            targets.append(self.app.Target(device, None, "", "eth0"))
            records[name.casefold()] = {"hostname": name, "outcome": "ALREADY_CONFIGURED", "reason": "",
                "writes_attempted": False, "metrics": {}, "stage_status": {
                    "authentication": "VERIFIED", "initial": "VERIFIED", "day0": "ALREADY_PRESENT",
                    "ipv4_readiness": "VERIFIED", "services": "ALREADY_PRESENT",
                    "public_keys": "NO_KEYS_PROVIDED", "direct_ssh": "VERIFIED"}}
            direct.append({"hostname": name, "interface": "eth0", "ip": address, "status": "PASS", "detail": "PUBLIC"})
        args = SimpleNamespace(apply=True, report=Path("PUBLIC-unused-report.log"))
        for selected_count, expected in ((2, "SUCCESS"), (3, "INCOMPLETE")):
            with self.subTest(selected=selected_count), mock.patch.object(self.app, "log"):
                self.assertEqual(expected, self.app.print_initial_setup_summary(
                    "PUBLIC", args, targets, selected_count, {}, records, direct, 1, ""))

    def test_unobserved_authentication_failure_keeps_unknown_result_fields(self):
        device = self.app.Device("EXAMPLE-IB001", "ib", "203.0.113.11", "203.0.113.11/24",
                                 "203.0.113.1", "02:00:00:00:00:11", "", "")
        jump = self.app.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        target = self.app.Target(device, jump, "swp1", "eth0")
        task = self.app.PreparedIBTask(target, self.app.Neighbor("fe80::11", "vlan1", device.eth0_mac), "", False)
        args = SimpleNamespace(eth_user="cumulus", ib_user="admin", connect_timeout=5,
                               apply=False, force=False, execution_mode="management")
        with ExitStack() as stack:
            for name in ("interactive_run", "run_on_ib", "_stage_ib_command", "verify_password_hash",
                         "_ensure_ib_config_backup", "obtain_write_permit", "run_management_direct_checks"):
                stack.enter_context(mock.patch.object(self.app, name,
                    side_effect=AssertionError("unobserved record must not reach later device or child effects")))
            stack.enter_context(mock.patch.object(self.app, "inspect_ib_device",
                side_effect=self.app.SetupError("PUBLIC authentication model refused")))
            stack.enter_context(mock.patch.object(self.app, "log"))
            record = self.app.execute_ib_task(task, args, None, "PUBLIC-initial", None, [], None)
        self.assertEqual("FAILED", record["outcome"])
        self.assertEqual("authentication", record["failed_stage"])
        self.assertEqual("unknown", record["device_state"])
        self.assertEqual({"read": False, "service": None, "status": None, "provisioned": None}, record["ztp"])
        self.assertEqual([], record["existing_configuration"])
        self.assertEqual([], record["planned_changes"])
        self.assertEqual([], record["conflicts"])
        self.assertIsNone(record["needs_change"])
        self.assertIs(record["verified_complete"], False)
        self.assertEqual("patch", record["config_mode"])

    def test_success_category_and_direct_failure_attention_are_distinct(self):
        record = {"hostname": "EXAMPLE-IB001", "outcome": "ALREADY_CONFIGURED", "reason": "",
                  "writes_attempted": False, "metrics": {}, "stage_status": {"day0": "ALREADY_PRESENT"}}
        rows = [{"hostname": "EXAMPLE-IB001", "interface": "eth0", "ip": "203.0.113.11",
                 "status": "FAIL", "detail": "PUBLIC connection refused"}]
        self.assertEqual("CHECKED_EXISTING_CONFIGURATION", self.app.record_category(record))
        attention = self.app.initial_setup_attention({"example-ib001": record}, rows)
        self.assertEqual(["FAILED_DIRECT_SSH_NETWORK"], [group["category"] for group in attention])
        self.assertEqual(0, self.app.initial_setup_facts({"example-ib001": record}, rows)["setup_and_direct_ssh_verified"])


# WP7 transport/stage tests-first.  The original 440 lines above stay byte-exact.
# No shell/SSH/device is executed by this slice's PUBLIC reply boundary. Strict
# methods alone retain the original KAT reader and real fixed 8-second worker.
from contextlib import contextmanager, redirect_stdout
import io
import json
import re
import shlex
import sys


class _WP7ModuleReferences:
    """Replace one application's references, never shared stdlib attributes."""
    def __init__(self, original, **changes):
        self.original, self.changes = original, changes

    def __getattr__(self, name):
        return self.changes[name] if name in self.changes else getattr(self.original, name)


class _ReadonlyKeyTransportFixture:
    CURRENT = "PUBLIC-selected-current-Zq7!"
    NONCE = "0123456789abcdef0123456789abcdef"
    SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    BAD_RECEIPTS = (
        "missing", "duplicate", "wrong-nonce", "wrong-end", "wrong-code",
        "nonempty-body", "bool-exit", "other-exit", "cleanup-uncertain",
        "password-changed", "password-required", "password-attempted",
        "authentication-rejected", "nonboolean-password-fact", "expired",
        "password-notice", "auth-text", "network-text", "host-key-text",
    )

    @classmethod
    def setUpClass(cls):
        cls.app = load_script("wp7_transport_" + cls.__name__, INITIAL)
        cls.paths = cls.app._import_tools("tools.login_path")

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="wp7-transport-", dir=owned_test_root())
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.assertEqual(0o700, stat.S_IMODE(self.root.lstat().st_mode))
        self.key = self.root / "PUBLIC-metadata-only-key"
        self.key.write_bytes(b"PUBLIC METADATA MODEL; NOT A PRIVATE KEY; NO SSH CLIENT READS THIS\n")
        self.key.chmod(0o600)
        self.policy_path = self.root / "01-global.yaml"
        self.policy = None

    def entries(self):
        return [ReadonlyPublicKeyTests.public_entry(self, 1), ReadonlyPublicKeyTests.public_entry(self, 2)]

    def command(self):
        payload = base64.b64encode(("\n".join(item["line"] for item in self.entries()) + "\n")
                                  .encode("ascii")).decode("ascii")
        return ["sh", "-c", EXPECTED_READONLY_KEY_SCRIPT, "--", payload]

    def target(self, direct):
        app = self.app
        ib = app.Device(HOST, "ib", "203.0.113.2", "203.0.113.2/24", "203.0.113.1",
                        "02:00:00:00:00:17", "", "")
        if direct:
            route = self.paths.Route(HOST, "direct", "NO_MGMT_LINK", None, None, None)
            return app.Target(ib, None, "", "eth0", route=route), app.DirectEndpoint("203.0.113.2")
        jump = app.Device("PUBLIC-JUMP01", "eth", "198.51.100.2", "198.51.100.2/24",
                          "198.51.100.1", "02:00:00:00:01:17", "", "")
        return app.Target(ib, jump, "swp7", "eth0"), app.Neighbor(
            "fe80::17", "vlan1000", "02:00:00:00:00:17", "mgmt")

    def framed_program(self, command, nonce):
        # Independent literal framing ABI, not app._framed_script output.
        return ('printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                + shlex.join(command) + '; task_rc=$?; printf "\\n__HTTP_IB_END_'
                + nonce + '__=%s\\n" "$task_rc"; exit "$task_rc"')

    def nested_prefix(self):
        return ["ip", "vrf", "exec", "mgmt", "ssh", "-6", "-tt",
                "-o", "ConnectTimeout=2", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "LogLevel=ERROR", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                "-o", "NumberOfPasswordPrompts=1", "-B", "vlan1000", "admin@fe80::17"]

    def reply(self, nonce, code, fault, body="", destination="admin@203.0.113.2"):
        frame_nonce = "f" * 32 if fault == "wrong-nonce" else nonce
        ending = "e" * 32 if fault == "wrong-end" else frame_nonce
        framed_code = (0 if code == 34 else 34) if fault == "wrong-code" else code
        raw_code = False if fault == "bool-exit" else 17 if fault == "other-exit" else code
        if fault == "other-exit":
            framed_code = 17  # matching but non-whitelisted, not merely a mismatch
        if fault == "nonempty-body":
            body = "PUBLIC-unexpected-body\n"
        text = ("__HTTP_IB_BEGIN_" + frame_nonce + "__\n" + body
                + "__HTTP_IB_END_" + ending + "__=" + str(framed_code) + "\n")
        if fault == "missing":
            text = "PUBLIC-no-frame\n"
        elif fault == "duplicate":
            text += text
        prefix = {
            "expired": "You are required to change your password immediately (administrator enforced)\n",
            "password-notice": ("passwd:" + " password updated successfully\n"),
            "auth-text": destination + ": Permission denied (publickey).\n",
            "network-text": "ssh: connect to host " + destination.rpartition("@")[2] + " port 22: No route to host\n",
            "host-key-text": "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n",
        }.get(fault, "")
        result = self.app.SessionResult(prefix + text, raw_code)
        field = {"cleanup-uncertain": "cleanup_uncertain", "password-changed": "password_changed",
                 "password-required": "password_change_required", "password-attempted": "password_change_attempted",
                 "authentication-rejected": "ib_authentication_rejected"}.get(fault)
        if field:
            setattr(result, field, True)
        if fault == "nonboolean-password-fact":
            result.password_changed = None
        return result

    @contextmanager
    def boundary(self, command=None, *, code=34, fault=None, strict=False, install_receipt=None):
        app = self.app
        command = self.command() if command is None else list(command)
        observed = SimpleNamespace(requests=[], metrics=[], permits=[], native=[], replies=[], effects=[])
        old_context = app._TASK_IB_CONFIG
        old_profile = sys.getprofile()
        watched = ("run_on_ib", "_run_on_ib_direct", "_run_direct_key_read", "_run_authorized_ib_command_core",
                   "direct_ssh_command", "nested_ssh_command", "outer_ssh_command", "run_key_stage")
        observed.entered = {name: 0 for name in watched}
        codes = {getattr(app, name).__code__: name for name in watched}
        original_metric, original_permit = app.record_metric, app.obtain_write_permit
        actual_run = subprocess.run
        actual_open = os.open
        if strict and not hasattr(self, "kat"):
            # Original bounded FD/two-pass/hash/AST reader, never copied KAT values.
            from test_cases.test_initial_setup_target_password_policy import required_external_kat, project_global
            self.kat = required_external_kat()
            self.policy_path.write_text(project_global(self.kat["YESCRYPT"]), encoding="utf-8")
            self.policy_path.chmod(0o600)

        def deny(*_args, **_kwargs):
            observed.effects.append("forbidden-external")
            raise RuntimeError("WP7 finite boundary refused an unowned external effect")

        def worker(argv, **options):
            expected = [sys.executable, "-I", "-S", "-B", str(INITIAL.resolve()), "--_verify-password"]
            if not strict or argv != expected:
                return deny()
            self.assertTrue(set(options) == {"input", "text", "capture_output", "timeout", "check", "env"},
                            "only the original fixed verifier signature is permitted")
            values = json.loads(options["input"])
            self.assertTrue(values == {"password": self.kat["PASSWORD"], "hash": self.kat["YESCRYPT"]},
                            "only the original reviewed KAT pair may reach native verification")
            self.assertTrue(options["text"] is True and options["capture_output"] is True
                            and options["timeout"] == 8 and options["check"] is False)
            self.assertEqual({"PATH": os.defpath, "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"},
                             options["env"])
            observed.native.append("fixed8-worker")
            return actual_run(argv, **options)

        def own_open(path, flags, *args, **kwargs):
            if (not strict or Path(path).resolve() != self.policy_path or args or kwargs
                    or flags != os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK):
                return deny()
            return actual_open(path, flags)

        def metric(name):
            observed.metrics.append(name)
            return original_metric(name)

        def observe(frame, event, _value):
            if event == "call" and frame.f_globals is app.__dict__ and frame.f_code in codes:
                observed.entered[codes[frame.f_code]] += 1

        def permit(category="nvue"):
            observed.permits.append(category)
            if install_receipt is None:
                return deny()
            self.assertEqual("public_key", category)
            return original_permit(category)

        def interactive(argv, responder, timeout, **options):
            self.assertEqual({}, options)
            self.assertEqual(60, timeout)
            self.assertTrue(type(argv) is list and argv[:1] == ["ssh"])
            self.assertIsNone(getattr(responder, "_phase", None), "this model cannot fabricate a private phase")
            if argv[-2] == "cumulus@198.51.100.2":
                wrapper = shlex.split(argv[-1])
                self.assertEqual(["sh", "-c"], wrapper[:2])
                shell_prefix = "export PATH=" + shlex.quote(self.SAFE_PATH) + "; exec "
                self.assertTrue(wrapper[2].startswith(shell_prefix))
                nested = shlex.split(wrapper[2][len(shell_prefix):])
                self.assertEqual(self.nested_prefix(), nested[:-1])
                remote = shlex.split(nested[-1])
                self.assertEqual("admin@fe80::17", responder.ib_destination)
                self.assertEqual(self.CURRENT, responder.ib_default_password)
                self.assertEqual("PUBLIC-oob-Zq7!", responder.ethernet_password)
            else:
                self.assertEqual("admin@203.0.113.2", argv[-2])
                self.assertEqual("admin@203.0.113.2", responder.ib_destination)
                remote = shlex.split(argv[-1])
                if "-i" in argv:
                    self.assertEqual(str(self.key), argv[argv.index("-i") + 1])
                    for flag in ("BatchMode=yes", "PreferredAuthentications=publickey", "PasswordAuthentication=no",
                                 "KbdInteractiveAuthentication=no", "IdentitiesOnly=yes", "ProxyCommand=none", "ProxyJump=none"):
                        self.assertEqual(1, argv.count(flag))
                    self.assertIsNone(responder("PUBLIC key-only no prompt"))
                else:
                    self.assertEqual(self.CURRENT, responder.ib_default_password)
                    self.assertEqual("", responder.ethernet_password)
            self.assertEqual(["sh", "-c"], remote[:2])
            self.assertEqual(3, len(remote))
            markers = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
            self.assertEqual(1, len(markers))
            nonce = markers[0]
            self.assertEqual(self.framed_program(command, nonce), remote[2])
            observed.requests.append(tuple(command))
            if fault == "key-drift":
                with self.key.open("ab") as handle:
                    handle.write(b"PUBLIC changed metadata\n")
            if fault == "policy-drift":
                with self.policy_path.open("a", encoding="utf-8") as handle:
                    handle.write("\n")
            response = self.reply(nonce, code, fault, install_receipt or "", responder.ib_destination)
            observed.replies.append(response)
            return response

        with ExitStack() as guard:
            guard.enter_context(mock.patch.object(app, "subprocess", new=_WP7ModuleReferences(
                subprocess, run=worker, Popen=deny, check_call=deny, check_output=deny, call=deny)))
            guard.enter_context(mock.patch.object(self.paths, "subprocess", new=_WP7ModuleReferences(
                subprocess, run=deny, Popen=deny)))
            blocked = {name: deny for name in ("system", "fork", "forkpty", "execv", "execve", "execvp",
                       "execvpe", "posix_spawn", "posix_spawnp", "kill", "killpg", "waitpid")}
            guard.enter_context(mock.patch.object(app, "os", new=_WP7ModuleReferences(os, open=own_open, **blocked)))
            guard.enter_context(mock.patch.object(app, "pty", new=_WP7ModuleReferences(app.pty, fork=deny, openpty=deny)))
            guard.enter_context(mock.patch.object(app, "socket", new=_WP7ModuleReferences(app.socket,
                socket=deny, create_connection=deny)))
            guard.enter_context(mock.patch.object(app, "getpass", new=_WP7ModuleReferences(app.getpass, getpass=deny)))
            guard.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
            guard.enter_context(mock.patch.object(app, "record_metric", new=metric))
            guard.enter_context(mock.patch.object(app, "obtain_write_permit", new=permit))
            for name in ("_ensure_ib_config_backup", "confirm_first_device_change", "verify_management_key_possession",
                         "_execute_ib_phase", "_execute_ib_direct_phase", "request_current_ib_password"):
                guard.enter_context(mock.patch.object(app, name, new=deny))
            guard.enter_context(redirect_stdout(io.StringIO()))
            if strict and self.policy is None:
                self.policy = app.ProjectPasswordPolicy(self.policy_path, "admin",
                    target_password=self.kat["PASSWORD"], interactive=False)
            observed.policy = self.policy if strict else None
            try:
                sys.setprofile(observe)
                yield observed
            finally:
                sys.setprofile(old_profile)
                self.assertIs(old_profile, sys.getprofile())
                self.assertIs(old_context, app._TASK_IB_CONFIG, "no writer/key identity context may be fabricated")
                self.assertEqual([], observed.effects, "even swallowed unknown external attempts fail the test")
                if install_receipt is None:
                    self.assertEqual([], observed.permits)

    def invoke(self, mode, observed, command=None):
        app = self.app
        direct = mode != "jump" and mode != "authorized-jump"
        target, point = self.target(direct)
        command = self.command() if command is None else command
        outer = ("", "") if direct else ("cumulus", "PUBLIC-oob-Zq7!")
        if mode == "key":
            return app._run_direct_key_read(target, point, "admin", self.key, 2, command)
        if mode.startswith("authorized-"):
            return app._run_authorized_ib_command_core(target, point, *outer, "admin", self.CURRENT, 2,
                command, direct=direct, _password_policy=observed.policy)
        return app.run_on_ib(target, point, *outer, "admin", self.CURRENT, 2, command)

    def assert_once(self, observed, command=None, *, mode=None):
        self.assertEqual([tuple(self.command() if command is None else command)], observed.requests)
        self.assertEqual(["ib_ssh_attempts"], observed.metrics)
        self.assertEqual([], observed.permits)
        if mode is not None:
            if mode == "key":
                self.assertEqual(1, observed.entered["_run_direct_key_read"])
                self.assertEqual(1, observed.entered["direct_ssh_command"])
            else:
                self.assertEqual(1, observed.entered["run_on_ib"])
                if mode.startswith("authorized-"):
                    self.assertEqual(1, observed.entered["_run_authorized_ib_command_core"])
                if mode.endswith("jump"):
                    self.assertEqual(1, observed.entered["nested_ssh_command"])
                    self.assertEqual(1, observed.entered["outer_ssh_command"])
                else:
                    self.assertEqual(1, observed.entered["_run_on_ib_direct"])


class ReadonlyKeyTransportTests(_ReadonlyKeyTransportFixture, unittest.TestCase):
    def test_real_outer_carrier_admits_only_exact_readonly_program(self):
        app = self.app
        target, point = self.target(False)
        command = self.command()
        expected_nested = [*self.nested_prefix(), shlex.join(["sh", "-c", self.framed_program(command, self.NONCE)])]
        with self.boundary() as seen:
            actual = app.nested_ssh_command(target, point, "cumulus", "admin", 2, command, marker=self.NONCE)
            wrapper = shlex.split(actual[-1])
            self.assertEqual(["sh", "-c", "export PATH=" + shlex.quote(self.SAFE_PATH)
                              + "; exec " + shlex.join(expected_nested)], wrapper)
            self.assertIsNone(app._ib_write_category(command))
            for bad in (["sh", "-c", EXPECTED_READONLY_KEY_SCRIPT + " ", "--", command[4]],
                        ["sh", "-c", "printf PUBLIC\n", "--", command[4]]):
                raw = [*self.nested_prefix(), shlex.join(["sh", "-c", self.framed_program(bad, self.NONCE)])]
                with self.subTest(program="near-miss"), self.assertRaises(app.SetupError):
                    app.outer_ssh_command(target.ethernet, "cumulus", raw, 2)
            single_line = ["sh", "-c", "printf PUBLIC\\n", "--", command[4]]
            with self.subTest(program="single-line-nvos"), self.assertRaises(app.SetupError):
                app.nested_ssh_command(target, point, "cumulus", "admin", 2,
                                       single_line, marker=self.NONCE)
            self.assertEqual([], seen.requests)
            self.assertEqual([], seen.metrics)
            self.assertEqual([], seen.native)

    def test_jump_and_direct_preserve_exact_empty_0_and_34_receipts_once(self):
        for mode in ("jump", "direct"):
            for code in (0, 34):
                with self.subTest(path=mode, code=code), self.boundary(code=code) as seen:
                    result = self.invoke(mode, seen)
                    self.assertIs(result, seen.replies[0])
                    self.assertEqual(code, result.exit_code)
                    self.assertIs(type(result.exit_code), int)
                    self.assertEqual("", result.output)
                    self.assert_once(seen, mode=mode)

    def test_jump_and_direct_reject_bad_frames_and_authentication_metadata(self):
        for mode in ("jump", "direct"):
            for code, fault in ((code, fault) for code in (0, 34) for fault in self.BAD_RECEIPTS):
                with self.subTest(path=mode, code=code, fault=fault), self.boundary(code=code, fault=fault) as seen:
                    with self.assertRaises(self.app.SetupError):
                        self.invoke(mode, seen)
                    self.assert_once(seen, mode=mode)  # refusal must not be an earlier argv/fixture error

    def test_nonzero_other_read_and_near_miss_never_receive_readonly_exception(self):
        for mode in ("jump", "direct", "key"):
            ordinary = ["nv", "show", "system", "ztp"]
            with self.subTest(path=mode), self.boundary(ordinary, code=34) as seen:
                with self.assertRaises(self.app.SetupError):
                    self.invoke(mode, seen, ordinary)
                self.assert_once(seen, ordinary, mode=mode)

    def test_both_key_only_lists_admit_exact_new_program_and_keep_old_refusals(self):
        # Independent WP4 pre-implementation PUBLIC programs are INPUT vectors,
        # never subjects' constants or an executed backup/deferred transaction.
        from test_cases import test_initial_setup_identity_and_backup as frozen_wp4
        app = self.app
        target, point = self.target(True)
        command = self.command()
        with self.boundary() as seen:
            argv = app.direct_ssh_command(target, point, "admin", 2, command,
                marker=self.NONCE, _key_file=self.key)
            self.assertIn(str(self.key), argv)
            self.assertEqual(shlex.join(["sh", "-c", self.framed_program(command, self.NONCE)]), argv[-1])
            forbidden = (["true"], ["nv", "set", "system", "hostname", HOST],
                         ["nv", "config", "apply", "-y"], ["nv", "config", "save"],
                         ["sh", "-c", EXPECTED_INSTALL_KEY_SCRIPT, "--", command[4]],
                         ["sh", "-c", frozen_wp4.EXPECTED_BACKUP_SCRIPT, "--", "20261118-120000"],
                         ["sh", "-c", frozen_wp4.EXPECTED_LAUNCH_SCRIPT, "--", "20261118-120000"],
                         ["sh", "-c", frozen_wp4.EXPECTED_READ_RC_SCRIPT, "--", "20261118-120000"],
                         ["sh", "-c", EXPECTED_READONLY_KEY_SCRIPT + " ", "--", command[4]])
            self.assertEqual([], seen.requests)
        for wrong in forbidden:
            for consumer in ("builder", "helper"):
                # If a known forbidden vector is wrongly admitted, answer that
                # exact vector completely; zero-IO is the business assertion,
                # not a mismatched fixture reply or an external command.
                with self.subTest(vector=wrong[:2], consumer=consumer), self.boundary(wrong, code=0) as seen:
                    with self.assertRaises(app.SetupError):
                        if consumer == "builder":
                            app.direct_ssh_command(target, point, "admin", 2, wrong,
                                marker=self.NONCE, _key_file=self.key)
                        else:
                            app._run_direct_key_read(target, point, "admin", self.key, 2, wrong)
                    self.assertEqual([], seen.requests)
                    self.assertEqual([], seen.metrics)
        for options in ({"password_only": True}, {"_phase": object()}):
            with self.subTest(conflict=tuple(options)), self.boundary() as seen:
                with self.assertRaises(app.SetupError):
                    app.direct_ssh_command(target, point, "admin", 2, command,
                        marker=self.NONCE, _key_file=self.key, **options)
                self.assertEqual([], seen.requests)

    def test_key_only_helper_preserves_0_34_and_metadata_binding_without_writes(self):
        for code in (0, 34):
            with self.subTest(code=code), self.boundary(code=code) as seen:
                fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
                before = (self.key.read_bytes(), tuple(getattr(self.key.lstat(), name) for name in fields))
                result = self.invoke("key", seen)
                self.assertIs(result, seen.replies[0])
                self.assertEqual((code, ""), (result.exit_code, result.output))
                self.assertEqual(before, (self.key.read_bytes(), tuple(getattr(self.key.lstat(), name) for name in fields)))
                self.assertEqual(self.app.DirectEndpoint("203.0.113.2"), result._direct_endpoint)
                self.assert_once(seen, mode="key")

    def test_key_only_rejects_bad_receipts_metadata_and_changed_explicit_file(self):
        for code, fault in ((code, fault) for code in (0, 34) for fault in (*self.BAD_RECEIPTS, "key-drift")):
            with self.subTest(code=code, fault=fault), self.boundary(code=code, fault=fault) as seen:
                with self.assertRaises(self.app.SetupError):
                    self.invoke("key", seen)
                self.assert_once(seen, mode="key")

    def test_direct_endpoint_and_key_type_qualification_precede_any_read(self):
        app = self.app
        target, point = self.target(True)
        bad_key = self.root / "PUBLIC-link"
        bad_key.symlink_to(self.key)
        for endpoint, key in ((app.DirectEndpoint("203.0.113.99"), self.key), (point, bad_key)):
            with self.subTest(kind="foreign-point-or-link"), self.boundary() as seen:
                with self.assertRaises(app.SetupError):
                    app._run_direct_key_read(target, endpoint, "admin", key, 2, self.command())
                self.assertEqual([], seen.requests)
                self.assertEqual([], seen.metrics)

    def test_readonly_stage_reads_once_zero_writes_and_returns_authorized_not_presence(self):
        app = self.app
        for direct in (False, True):
            for code in (0, 34):
                for authorized in (False, True):
                    with self.subTest(direct=direct, code=code, authorized=authorized), self.boundary(code=code) as seen:
                        target, point = self.target(direct)
                        outer = ("", "") if direct else ("cumulus", "PUBLIC-oob-Zq7!")
                        details = {}
                        answer = app.run_key_stage(target, point, *outer, "admin", 2, self.entries(),
                            local=False, apply=False, authorized=authorized, ib_password=self.CURRENT, details=details)
                        self.assertIs(authorized, answer)
                        self.assertIs(code == 0, details.get("present"))
                        self.assertNotIn("content_action", details)
                        self.assertEqual(1, seen.entered["run_key_stage"])
                        self.assert_once(seen, mode="direct" if direct else "jump")

    def test_no_keys_stage_keeps_authorized_and_has_no_extra_device_read(self):
        target, point = self.target(False)
        for authorized in (False, True):
            with self.subTest(authorized=authorized), self.boundary() as seen:
                details = {}
                result = self.app.run_key_stage(target, point, "cumulus", "PUBLIC-oob-Zq7!", "admin", 2, [],
                    local=False, apply=False, authorized=authorized, ib_password=self.CURRENT, details=details)
                self.assertIs(authorized, result)
                self.assertEqual({}, details)
                self.assertEqual([], seen.requests)
                self.assertEqual([], seen.metrics)

    def test_apply_stage_preserves_original_install_receipts_content_action_and_metrics(self):
        command = ["sh", "-c", EXPECTED_INSTALL_KEY_SCRIPT, "--", self.command()[4]]
        for receipt, action, metric in (("IBSW_PUBLIC_KEYS_UPDATED\n", "UPDATED", "public_key_content_updated"),
                                        ("IBSW_PUBLIC_KEYS_UNCHANGED\n", "UNCHANGED", "public_key_content_unchanged")):
            with self.subTest(action=action), self.boundary(command, code=0, install_receipt=receipt) as seen:
                target, point = self.target(True)
                details = {}
                result = self.app.run_key_stage(target, point, "", "", "admin", 2, self.entries(),
                    local=False, apply=True, authorized=True, ib_password=self.CURRENT, details=details)
                self.assertIs(True, result)
                self.assertEqual({"content_action": action, "requested_keys": 2}, details)
                self.assertEqual([tuple(command)], seen.requests)
                self.assertEqual(["public_key"], seen.permits)
                self.assertEqual(["ib_ssh_attempts", "public_key_install_completed", metric], seen.metrics)


class ReadonlyKeyStrictTransportTests(_ReadonlyKeyTransportFixture, unittest.TestCase):
    # Each strict method uses the original external KAT reader and real bound
    # ProjectPasswordPolicy. Only exact original8s native workers are forwarded;
    # no policy/matches/observer/identity result is replaced with PUBLIC/True.
    def setUp(self):
        super().setUp()
        # Backend/fixture failure happens ONCE before any behavioral subcase,
        # rather than masquerading as a negative receipt or repeating timeouts.
        with self.boundary(strict=True) as seen:
            value = seen.policy.password()
            if value != self.kat["PASSWORD"] or not seen.native:
                raise RuntimeError("FIXTURE HOLD: original native project policy did not qualify")

    def test_authorized_jump_and_direct_core_accept_only_exact_0_34_receipts(self):
        for mode in ("authorized-jump", "authorized-direct"):
            for code in (0, 34):
                with self.subTest(path=mode, code=code), self.boundary(code=code, strict=True) as seen:
                    result = self.invoke(mode, seen)
                    self.assertIs(result, seen.replies[0])
                    self.assertEqual((code, ""), (result.exit_code, result.output))
                    self.assert_once(seen, mode=mode)
                    self.assertTrue(seen.native, "the real project policy must reach its original native verifier")

    def test_authorized_core_rejects_every_bad_receipt_and_policy_drift(self):
        for mode in ("authorized-jump", "authorized-direct"):
            for code, fault in ((code, fault) for code in (0, 34) for fault in self.BAD_RECEIPTS):
                with self.subTest(path=mode, code=code, fault=fault), self.boundary(code=code, fault=fault, strict=True) as seen:
                    with self.assertRaises(self.app.SetupError):
                        self.invoke(mode, seen)
                    self.assert_once(seen, mode=mode)
            with self.subTest(path=mode, fault="policy-drift"), self.boundary(code=0, fault="policy-drift", strict=True) as seen:
                with self.assertRaises(self.app.SetupError):
                    self.invoke(mode, seen)
                self.assert_once(seen, mode=mode)
            # Start the next path with a fresh actual bound policy; never repair
            # a binding or cache the subject's expected result after drift.
            self.policy = None
            del self.kat

    def test_authorized_other_command_34_and_unqualified_policy_still_fail_closed(self):
        ordinary = ["nv", "show", "system", "ztp"]
        for mode in ("authorized-jump", "authorized-direct"):
            with self.subTest(path=mode), self.boundary(ordinary, code=34, strict=True) as seen:
                with self.assertRaises(self.app.SetupError):
                    self.invoke(mode, seen, ordinary)
                self.assert_once(seen, ordinary, mode=mode)
            with self.subTest(path=mode, policy="foreign-object"), self.boundary(strict=True) as seen:
                seen.policy = object()
                with self.assertRaises(self.app.SetupError):
                    self.invoke(mode, seen)
                self.assertEqual([], seen.requests)
                self.assertEqual([], seen.metrics)

    def test_strict_readonly_stage_retains_authorized_and_real_policy_zero_write(self):
        for direct in (False, True):
            for code in (0, 34):
                for authorized in (False, True):
                    with self.subTest(direct=direct, code=code, authorized=authorized), self.boundary(code=code, strict=True) as seen:
                        target, point = self.target(direct)
                        outer = ("", "") if direct else ("cumulus", "PUBLIC-oob-Zq7!")
                        details = {}
                        answer = self.app.run_key_stage(target, point, *outer, "admin", 2, self.entries(),
                            local=False, apply=False, authorized=authorized, _ib_current_password=self.CURRENT,
                            _password_policy=seen.policy, details=details)
                        self.assertIs(authorized, answer)
                        self.assertIs(code == 0, details.get("present"))
                        self.assertNotIn("content_action", details)
                        self.assertEqual(1, seen.entered["run_key_stage"])
                        self.assert_once(seen, mode="authorized-direct" if direct else "authorized-jump")

    def test_strict_no_keys_preserves_original_policy_admission_and_zero_reads(self):
        target, point = self.target(False)
        with self.boundary(strict=True) as seen:
            answer = self.app.run_key_stage(target, point, "cumulus", "PUBLIC-oob-Zq7!", "admin", 2, [],
                local=False, apply=False, authorized=False, _ib_current_password=self.CURRENT,
                _password_policy=seen.policy, details={})
            self.assertIs(False, answer)
            self.assertEqual([], seen.requests)
            self.assertEqual([], seen.metrics)
            self.assertEqual([], seen.native, "no-key stage needs binding, not a target-password fetch")

# NOT COVERED here: a readonly _IBConfigWriteState must be produced by genuine
# execute/authentication/identity, never hand-built with identity_verified=True.
# No key-context qualification or execute/UI/needs_change/attention result is
# fabricated by these direct transport/stage tests; those need a later workflow.


class ConfigurationResultSyntaxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_script("wp6_result_syntax_source", INITIAL)

    def test_malformed_service_fact_keeps_fixed_setup_error(self):
        services = {"dns": ["203.0.113.53"], "ntp": ["time.public.example.test"], "timezone": "Etc/UTC"}
        malformed = (
            ("ntp", 'nv set system ntp server "PUBLIC-BAD-NTP'),
            ("dns", 'nv set system dns server "PUBLIC-BAD-DNS'),
            ("timezone", 'nv set system date-time timezone "PUBLIC-BAD-TIMEZONE'),
        )
        for item, line in malformed:
            with self.subTest(item=item):
                current = "nv set system hostname nvos\n" + line + "\n"
                state = self.app.DeviceState((), (), (), (), "nvos", current)
                with self.assertRaises(self.app.SetupError) as caught:
                    BringupResultsTests.pure(self, self.app._configuration_result_facts,
                        BringupResultsTests.device(self), state, services, current)
                error = caught.exception
                self.assertIs(type(error), self.app.SetupError)
                self.assertEqual(("Initial configuration command syntax is UNKNOWN",), error.args)
                self.assertEqual({}, error.__dict__)
                self.assertNotIn(line, str(error))
                self.assertNotIn("PUBLIC-BAD-", str(error))


class ConfigurationResultCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_script("wp6_result_completion_source", INITIAL)

    def test_completion_uses_only_same_device_direct_rows(self):
        # Pure contract vectors, not genuine identity or direct-SSH evidence.
        stages = {"authentication": "VERIFIED", "initial": "CHECKED", "day0": "ALREADY_PRESENT",
                  "ipv4_readiness": "VERIFIED", "services": "ALREADY_PRESENT",
                  "public_keys": "ALREADY_PRESENT", "direct_ssh": "VERIFIED"}
        same = {"hostname": "PUBLIC-IB01", "interface": "eth0", "ip": "203.0.113.2", "status": "PASS"}
        other = {"hostname": "PUBLIC-IB02", "interface": "eth0", "ip": "203.0.113.3", "status": "PASS"}
        for label, rows, expected, ready, attention in (
                ("other-device", [other], False, 0, "DIRECT_SSH_NOT_TESTED"),
                ("same-device", [same], True, 1, None),
                ("no-direct-row", [], False, 0, "DIRECT_SSH_NOT_TESTED")):
            with self.subTest(case=label):
                record = {"hostname": "PUBLIC-IB01", "outcome": "ALREADY_CONFIGURED",
                          "stage_status": dict(stages), "writes_attempted": False, "direct_rows": list(rows)}
                BringupResultsTests.pure(self, self.app._complete_result_fields, record)
                facts = BringupResultsTests.pure(self, self.app.initial_setup_facts,
                                                 {"public-ib01": record}, rows)
                self.assertIs(record["verified_complete"], expected)
                self.assertEqual(attention, record["attention_category"])
                self.assertEqual(ready, facts["setup_and_direct_ssh_verified"])
                self.assertEqual([] if attention is None else ["DIRECT_SSH_NOT_TESTED"],
                                 [group["category"] for group in facts["attention"]])
        # Existing summary records may identify themselves only by dictionary key.
        legacy = {"outcome": "ALREADY_CONFIGURED", "stage_status": dict(stages), "writes_attempted": False}
        facts = BringupResultsTests.pure(self, self.app.initial_setup_facts, {"PUBLIC-IB01": legacy}, [same])
        self.assertNotIn("hostname", legacy)
        self.assertEqual(1, facts["setup_and_direct_ssh_verified"])
        self.assertEqual([], facts["attention"])


# Genuine execute/result slice. The preceding 1370 lines remain byte-exact.
# This is not a MAIN/cache/selector test or a successful final-password probe.
class GenuineReadonlyKeyResultTests(unittest.TestCase):
    READS = (
        ("nv", "config", "show", "-o", "commands"),
        ("ip", "addr", "show", "eth0"),
        ("ip", "route"),
        ("nv", "show", "system", "ztp"),
    )

    def setUp(self):
        # Composition: do not inherit/rediscover the old WP4 test methods.
        from test_cases.test_initial_setup_identity_and_backup import IdentityAndBackupTests
        self.owner = IdentityAndBackupTests(methodName="runTest")
        self.addCleanup(self.owner.doCleanups)
        self.owner.setUp()
        self.app = self.owner._wp4_app

    @contextmanager
    def genuine_case(self, *, code=0, bad_nonce=False, missing_dns=False, no_keys=False):
        with self.owner._kg3_public_no_global_world() as world:
            app = self.app
            entry = ReadonlyPublicKeyTests.public_entry(self, 17)
            payload = base64.b64encode((entry["line"] + "\n").encode("ascii")).decode("ascii")
            key_command = ("sh", "-c", EXPECTED_READONLY_KEY_SCRIPT, "--", payload)
            # Explicit direct-API PUBLIC inputs, not a profile allegedly read
            # from the deliberately absent global or a SUT-produced oracle.
            services = {"dns": ["203.0.113.53"], "ntp": ["time.key.example.test"], "timezone": "Etc/UTC"}
            body = (world.body + "nv set system ntp server time.key.example.test state enabled\n"
                    + "nv set system date-time timezone Etc/UTC\n")
            if not missing_dns:
                body += "nv set system dns server 203.0.113.53\n"
            case = SimpleNamespace(world=world, services=services, keys=[] if no_keys else [entry],
                key_command=key_command, contexts=[], initial_needed=None, unexpected=[])
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
            before = (world.key.read_bytes(), tuple(getattr(world.key.lstat(), name) for name in fields))
            original_io, previous_profile = app.interactive_run, sys.getprofile()
            watched = {app.run_initial_stage.__code__: "initial", app.run_key_stage.__code__: "keys"}

            def profile(frame, event, value):
                if previous_profile is not None:
                    previous_profile(frame, event, value)
                if frame.f_globals is not app.__dict__ or frame.f_code not in watched:
                    return
                if event == "call":
                    context = frame.f_locals.get("_ib_read_context")
                    case.contexts.append((watched[frame.f_code], context, context is app._TASK_IB_CONFIG))
                elif event == "return" and watched[frame.f_code] == "initial":
                    details = frame.f_locals.get("details")
                    case.initial_needed = details.get("needed") if type(details) is dict else None

            def interactive(argv, responder, timeout, **options):
                try:
                    self.assertEqual({}, options)
                    self.assertEqual(60, timeout)
                    self.assertEqual(["ssh", "-4", "-tt", "-o", "ConnectTimeout=5",
                        "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
                        "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                        "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
                        "-o", "ControlMaster=no", "-o", "ControlPath=none",
                        "-o", "NumberOfPasswordPrompts=1", "-i", str(world.key),
                        "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
                        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
                        "-o", "IdentitiesOnly=yes", "admin@203.0.113.2"], argv[:-1])
                    self.assertEqual("admin@203.0.113.2", responder.ib_destination)
                    self.assertIsNone(getattr(responder, "_phase", None))
                    self.assertIsNone(responder("PUBLIC key-only no prompt"))
                    remote = shlex.split(argv[-1])
                    self.assertEqual(["sh", "-c"], remote[:2])
                    self.assertEqual(3, len(remote))
                    markers = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", remote[2])
                    self.assertEqual(1, len(markers))
                    nonce = markers[0]
                    prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                    suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                              + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                    self.assertTrue(remote[2].startswith(prefix) and remote[2].endswith(suffix))
                    command = tuple(shlex.split(remote[2][len(prefix):-len(suffix)]))
                    self.assertEqual(_ReadonlyKeyTransportFixture.framed_program(self, list(command), nonce), remote[2])
                    self.assertIn(command, (*self.READS, key_command), "only five independent PUBLIC vectors are modeled")
                    reply = original_io(argv, responder, timeout, **options)
                    self.assertEqual(("key", command), world.requests[-1])
                    response_body, response_code = (body, 0) if command == self.READS[0] else (None, 0)
                    if command == key_command:
                        response_body, response_code = "", code
                        if bad_nonce:
                            nonce = "f" * 32 if nonce != "f" * 32 else "e" * 32
                    if response_body is not None:
                        reply.output = ("__HTTP_IB_BEGIN_" + nonce + "__\n" + response_body
                                        + "__HTTP_IB_END_" + nonce + "__=" + str(response_code) + "\n")
                        reply.exit_code = response_code
                    return reply
                except Exception:
                    case.unexpected.append("unmodeled-carrier-or-vector")
                    raise RuntimeError("FIXTURE HOLD: genuine KEY model refused an unknown request") from None

            try:
                with mock.patch.object(app, "interactive_run", new=interactive):
                    sys.setprofile(profile)
                    yield case
            finally:
                sys.setprofile(previous_profile)
                # In particular, scheduler's broad worker catch must not turn
                # an unknown model effect into a matching business FAILED row.
                if case.unexpected:
                    raise RuntimeError("FIXTURE HOLD: unknown genuine KEY effect survived the worker")
                self.assertEqual(before, (world.key.read_bytes(),
                    tuple(getattr(world.key.lstat(), name) for name in fields)))
                self.assertIs(world.previous_context, app._TASK_IB_CONFIG)

    def execute(self, case):
        world = case.world
        return self.app.execute_ib_task(world.task, world.args, None, "PUBLIC-Factory-Value-72!",
                                        case.services, case.keys, world.key)

    def assert_genuine_readonly(self, case, record, *, has_keys=True):
        world = case.world
        self.assertEqual([("key", command) for command in self.READS]
                         + ([("key", case.key_command)] if has_keys else []), world.requests)
        self.assertEqual(["initial", "keys"], [label for label, context, installed in case.contexts])
        initial_context = case.contexts[0][1]
        for label, context, installed in case.contexts:
            self.assertIs(type(context), self.app._IBConfigWriteState)
            self.assertIs(context, initial_context)
            self.assertIs(installed, True)
            self.assertIs(context.task, world.task)
            self.assertIs(context.task.target, world.target)
            self.assertIs(context.identity_verified, True)
            self.assertEqual(world.point, context.endpoint)
            self.assertEqual(world.key, context.readonly_key_file)
            self.assertIsNone(context.current_password)
            self.assertIs(context.apply, False)
        self.assertIs(record["identity"]["ok"], True)
        self.assertIs(record["identity"]["via_ipv4"], True)
        self.assertIs(case.initial_needed, False)
        self.assertEqual([], world.asks)
        self.assertEqual([], world.permits)
        self.assertFalse(record["writes_attempted"])
        self.assertIsNone(record["backup"])
        self.assertEqual([], record["direct_rows"])
        self.assertIn(record["stage_status"]["direct_ssh"], ("NOT_REACHED", "NOT_TESTED"))
        self.assertIs(record["verified_complete"], False, "key access/presence is not an unrun final password probe")
        for name in ("run_on_ib", "_ensure_ib_config_backup", "run_management_direct_checks",
                     "verify_management_direct_ssh", "_ib_project_value"):
            self.assertEqual(0, world.entered[name])
        self.assertEqual(1, world.entered["execute_ib_task"])
        self.assertEqual(1, world.entered["run_key_stage"])

    def test_genuine_execute_readonly_keys_present_and_missing(self):
        for code, expected_status, needed in ((0, "ALREADY_PRESENT", False), (34, "PLANNED_NOT_APPLIED", True)):
            with self.subTest(code=code), self.genuine_case(code=code) as case:
                record = self.execute(case)
                self.assert_genuine_readonly(case, record)
                self.assertEqual(expected_status, record["stage_status"]["public_keys"])
                self.assertIs(code == 0, record["public_key_update"]["present"])
                self.assertIs(needed, record["needs_change"])
                if code == 34:
                    self.assertIn("--apply", record["reason"])

    def test_genuine_execute_unknown_key_uses_three_valued_needs_change(self):
        for missing_dns, expected in ((False, None), (True, True)):
            with self.subTest(missing_dns=missing_dns), self.genuine_case(
                    bad_nonce=True, missing_dns=missing_dns) as case:
                record = self.execute(case)
                self.assert_genuine_readonly(case, record)
                self.assertEqual("FAILED", record["outcome"])
                self.assertEqual("public_keys", record["failed_stage"])
                self.assertEqual("FAILED", record["stage_status"]["public_keys"])
                self.assertNotIn("present", record["public_key_update"], "UNKNOWN must not become a missing-key receipt")
                self.assertEqual("ALREADY_PRESENT", record["stage_status"]["day0"])
                self.assertEqual("PLANNED_NOT_APPLIED" if missing_dns else "ALREADY_PRESENT",
                                 record["stage_status"]["services"])
                self.assertIs(expected, record["needs_change"], "known True OR unknown is True, not unknown")

    def test_genuine_execute_no_keys_keeps_zero_extra_read_and_unverified_direct(self):
        with self.genuine_case(no_keys=True) as case:
            record = self.execute(case)
            self.assert_genuine_readonly(case, record, has_keys=False)
            self.assertEqual("NO_KEYS_PROVIDED", record["stage_status"]["public_keys"])
            self.assertEqual({}, record["public_key_update"])
            self.assertIs(record["needs_change"], False)

    def test_inline_finish_persists_genuine_key_result_without_fake_direct_success(self):
        with self.genuine_case() as case:
            world = case.world
            args = SimpleNamespace(**vars(world.args))
            args.report, args.max_workers = world.key.parent / "PUBLIC-report.log", 1
            # Keep the original scheduler's default task deadline, not a new budget.
            args.task_timeout = 1800
            batch = self.app.run_prepared_tasks([world.task], args, None, "PUBLIC-Factory-Value-72!",
                case.services, case.keys, world.key, authority=self.app.RuntimeInputAuthority([]))
            self.assertEqual(1, batch["workers"])
            self.assertEqual("", batch["fatal"])
            directory = Path(batch["log_dir"])
            self.assertEqual(args.report.parent, directory.parent)
            self.assertEqual(directory, directory.resolve())
            self.assertEqual(0o700, stat.S_IMODE(directory.lstat().st_mode))
            self.assertEqual([world.target.ib.hostname + ".json"], sorted(path.name for path in directory.glob("*.json")))
            record = batch["records"][world.target.ib.hostname.casefold()]
            self.assertEqual(record, json.loads((directory / (world.target.ib.hostname + ".json")).read_text(encoding="utf-8")))
            self.assertNotIn("script_error", record)
            self.assert_genuine_readonly(case, record)
            self.assertEqual("ALREADY_PRESENT", record["stage_status"]["public_keys"])
            self.assertIs(record["public_key_update"]["present"], True)
            self.assertIs(record["needs_change"], False)
            self.assertEqual(5, record["metrics"]["ib_ssh_attempts"])
            self.assertEqual([], batch["direct_rows"])
            facts = self.app.initial_setup_facts(batch["records"], batch["direct_rows"])
            self.assertEqual(0, facts["setup_and_direct_ssh_verified"])
            self.assertEqual(["DIRECT_SSH_NOT_TESTED"], [group["category"] for group in facts["attention"]])
            lines = []
            with mock.patch.object(self.app, "log", side_effect=lambda message="": lines.append(message)):
                status = self.app.print_initial_setup_summary("PUBLIC-no-global", args, [world.target], 1,
                    {}, batch["records"], batch["direct_rows"], batch["workers"], batch["fatal"])
            self.assertEqual("INCOMPLETE", status)
            self.assertIn("Result: INCOMPLETE", lines)
