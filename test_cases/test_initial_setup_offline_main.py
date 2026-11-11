"""Direct: initial-setup's real offline main flow (inputs, cache, snapshots, stages, summary).

What: the CLI help, --plan and --generate-json need no device; --max-workers 17 is refused before
any output; and the real main() of a read-only management run, with only SSH replaced, keeps
snapshots, IB selection counts, the worker count, failure isolation, direct-SSH retries, the FDB
EUI-64 candidate, the read-only password-expiry block and the compact console versus full report.
RefusalExitCodeTests (v3.1.3 guide WP-9 :1025-1026, N18): an operator who refuses the first-change
confirmation ends the whole run FAILED with exit 1 and no device write (问题文档 I-050, R-012 design
:589, v3.1.2 guide :1431).

Expectation sources (not derived from the implementation):
- The v15 delivered test test_desktop_initial_setup.py::OfflineMainWorkflowTests (:1465-1779);
  the file's sha256 is bound by 参考/initial-setup-v15/HANDOFF-SHA256SUMS:27.
- 参考/initial-setup-v15/CURRENT-CONTRACT.md:18 (report, cache and snapshots are written where the
  run says, relative to the working directory by default) and :59 (check-only writes no device
  configuration, still reads over SSH and writes a local report).
- Guide table 6-1 row 1 (:744: one failed device stops only itself) and row 11 (:754: exit codes
  0 SUCCESS, 1 FAILED, 2 INCOMPLETE).

Fixture rewrites (guide :835, class 4 of :765; no assertion is weakened):
- public audit: synthetic host names (example-ib…, example-oob-leaf01), documentation IPv4 only,
  02:00:00 MACs, credentials assembled at run time, a synthetic global hash;
- the four CLI tests run main() in this process (v15 used a `__main__` subprocess launcher, which
  takes the fixed runtime lock, guide :835, :1338); external commands, PTY and exec still fail
  closed;
- HOME is a temporary directory; no empty <project>/publickey/ (guide :835); the neutral service
  defaults sit where --project-dir reads them, <project>/infiniband/bringup/xdr-initial-setup/
  (O6, guide :259; WP-8 table 8-1, :923);
- a management run with a project global takes the merged strict path: the fake transport answers
  the IB authentication read as a DEV phase session through the real _IBPhase observer and the
  real responder (modelled on test_initial_setup_strict_stage_skeleton.py, not imported);
- the fake Leaf answers v15's new read-only `ip -j address show` (V15-OOB-SPINE.md:99) with an
  SVI that owns IPv4, so the v15 Leaf path is taken (V15-OOB-SPINE.md:54).
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
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_setup_v15_offline_main", INITIAL)

JUMP = "example-oob-leaf01"
AUTH_RE = re.compile(r"__HTTP_IB_AUTH_([0-9a-f]{32})_(auth-probe-readonly|password-change|post-change-read)__=BEGIN")
FRAME_RE = re.compile(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__")
EXPIRY = "\nYou are required to change your password immediately.\n"


def secret(label: str) -> str:
    # Assembled at run time so no credential literal appears in the source (public audit).
    return "-".join(("PUBLIC", "wp7", label, "Zq7"))


FACTORY = secret("factory")
GLOBAL_HASH = "$" + "6$PUBLICsalt$" + "A" * 86


def global_text() -> str:
    return ("schema_version: 2\ncommon:\n  switch:\n    system:\n"
            "      config:\n        auto-save:\n          state: enabled\n"
            "switches:\n- ib:\n    system:\n      aaa:\n        user:\n"
            "          admin:\n            password: {}\n").format(json.dumps(GLOBAL_HASH))


def host(index: int) -> str:
    return f"example-ib{index:03d}"


class _Session:
    """Feed fake device output to the real responder (and phase observer) as interactive_run does."""

    def __init__(self, responder) -> None:
        self.responder = responder
        self.phase = getattr(responder, "_phase", None)
        self.output = ""
        self.reader, self.writer = os.pipe()

    def feed(self, text: str):
        self.output += text
        if self.phase is not None:
            self.phase.observe(self.output)
        reply = self.responder(app.strip_ansi(self.output))
        if getattr(self.responder, "password_change_blocked", False):
            if self.phase is not None:
                self.phase.cancel_requested = True
            return "\x03"
        if reply is not None and self.phase is not None:
            self.phase.write_reply(self.writer, reply, self.responder, time.monotonic() + 60)
            os.read(self.reader, 65536)
        return reply

    def close(self) -> None:
        # Close once: a second close could hit a descriptor number reused elsewhere.
        fds, self.reader, self.writer = (self.reader, self.writer), None, None
        for fd in fds:
            if fd is not None:
                os.close(fd)

    def result(self, code: int):
        self.close()
        return app.SessionResult(app.strip_ansi(self.output), code,
                                 password_change_required=bool(getattr(self.responder,
                                                                       "password_change_blocked", False)))


class OfflineMainTests(unittest.TestCase):
    """Real input/cache/snapshot/stage/summary flow, with SSH only replaced."""

    def create_project(self, root: Path, count: int = 1) -> list:
        # O6 (guide :259): the neutral defaults are read from one local infra-neutral.conf, under
        # --project-dir the project's infiniband/bringup/xdr-initial-setup/ one (WP-8 table 8-1, :923);
        # no empty publickey/ directory (guide :835).
        neutral = root / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
        neutral.parent.mkdir(parents=True, exist_ok=True)
        neutral.write_text("DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=Etc/UTC\n")
        (root / "01-global.yaml").write_text(global_text())
        with (root / "ib.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["hostname", "type", "eth0_ip", "netmask", "eth0_gw",
                             "eth0_mac", "eth1_ip", "netmask", "eth1_gw"])
            for index in range(count):
                writer.writerow([host(index + 1), "ib", f"192.0.2.{index + 10}",
                                 "24", "192.0.2.1", f"02:00:00:00:00:{index + 10:02x}", "", "", ""])
            writer.writerow([JUMP, "eth_jump", "198.51.100.10", "", "", "", "", "", ""])
        (root / "p2p.dot").write_text("\n".join(
            f'"{host(index + 1)}":"eth0" -- "{JUMP}":"swp{index + 1}"'
            for index in range(count)) + "\n")
        return [str(INITIAL), "--project-dir", str(root), "--ib-csv", str(root / "ib.csv"),
                "--p2p", str(root / "p2p.dot"), "--target-cache", str(root / "tasks.json"),
                "--report", str(root / "report.log"), "--snapshot-dir", str(root / "snapshots"),
                "--execution-mode", "management"]

    def run_cli(self, *options):
        """In-process CLI: v15's launcher made external commands, PTY and exec fail closed."""
        def blocked(*_args, **_kwargs):
            raise RuntimeError("External commands forbidden in offline CLI tests")
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            argv = self.create_project(root) + list(options)
            stack.enter_context(patch.object(sys, "argv", argv))
            stack.enter_context(patch.object(app, "REPORT_HANDLE", None))
            stack.enter_context(patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(patch.object(Path, "home", return_value=home))
            for name in ("Popen", "run"):
                stack.enter_context(patch.object(app.subprocess, name, blocked))
            stack.enter_context(patch("pty.fork", blocked))
            stack.enter_context(patch("os.execvp", blocked))
            stdout = stack.enter_context(redirect_stdout(io.StringIO()))
            stderr = stack.enter_context(redirect_stderr(io.StringIO()))
            try:
                code = app._standalone_main_with_report_cleanup()
            except SystemExit as exc:
                code = exc.code
            cache = json.loads((root / "tasks.json").read_text()) if (root / "tasks.json").is_file() else None
            report_exists = (root / "report.log").exists()
        return code, stdout.getvalue(), stderr.getvalue(), cache, report_exists

    # v15 OfflineMainWorkflowTests.test_cli_help_works_without_any_external_command
    # (test_desktop_initial_setup.py:1504).
    def test_cli_help_works_without_any_external_command(self):
        code, stdout, stderr, cache, _ = self.run_cli("--help")
        self.assertEqual(code, 0, stderr)
        self.assertIn("--max-workers", stdout)
        self.assertIn("--task-timeout", stdout)
        self.assertIsNone(cache)

    # v15 OfflineMainWorkflowTests.test_cli_plan_generates_commands_without_device_access
    # (test_desktop_initial_setup.py:1511); CURRENT-CONTRACT.md:59 (--plan does not SSH).
    def test_cli_plan_generates_commands_without_device_access(self):
        code, stdout, stderr, cache, report = self.run_cli("--plan")
        self.assertEqual(code, 0, stderr)
        self.assertIn("nv config apply -y", stdout)
        self.assertIn("nv set system hostname " + host(1), stdout)
        self.assertIn("Network commands:", stdout)
        self.assertIn("Infra Services commands:", stdout)
        self.assertNotIn("Day-0", stdout)
        self.assertNotIn("nv set system hostname " + JUMP, stdout)
        self.assertIsNotNone(cache)
        self.assertTrue(report)

    # v15 OfflineMainWorkflowTests.test_cli_generate_json_without_device_access
    # (test_desktop_initial_setup.py:1523).
    def test_cli_generate_json_without_device_access(self):
        code, stdout, stderr, cache, report = self.run_cli("--generate-json")
        self.assertEqual(code, 0, stderr)
        self.assertEqual(cache["ib_candidate_count"], 1)
        self.assertEqual(len(cache["targets"]), 1)
        self.assertEqual(cache["targets"][0]["ib"]["hostname"], host(1))
        self.assertFalse(report)

    # v15 OfflineMainWorkflowTests.test_cli_rejects_seventeen_workers_before_creating_outputs
    # (test_desktop_initial_setup.py:1531); CURRENT-CONTRACT.md:64 (--max-workers only lowers 16).
    def test_cli_rejects_seventeen_workers_before_creating_outputs(self):
        code, stdout, stderr, cache, report = self.run_cli("--max-workers", "17")
        self.assertEqual(code, 2)
        self.assertIn("--max-workers", stderr + stdout)
        self.assertIsNone(cache)
        self.assertFalse(report)

    def run_workflow(self, count, link_up, *, nd_missing=False, derived_failure=False, derived_expired=False,
                     real_logging=False, verbose=False, direct_network_failures=0, direct_script_error=False,
                     unmapped_count=0, blocked_ports=()):
        messages = []
        direct_hits = app.multiprocessing.get_context("fork").Array("i", count)
        phase_reads = app.multiprocessing.get_context("fork").Value("i", 0)
        # FX3 second caliber: every IB session the fake transport serves through the jump.
        ib_sessions = app.multiprocessing.get_context("fork").Value("i", 0)
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            argv = self.create_project(root, count + unmapped_count)
            if unmapped_count:
                (root / "p2p.dot").write_text("\n".join(
                    f'"{host(index + 1)}":"eth0" -- "{JUMP}":"swp{index + 1}"'
                    for index in range(count)) + "\n")
            if verbose:
                argv.append("--verbose")

            def ethernet(device, user, password, command, timeout, **kwargs):
                command = tuple(command)
                if command == ("hostname",):
                    return JUMP + "\n"
                if command == ("nv", "show", "interface"):
                    return "\n".join(f"swp{i+1} up {'up' if link_up and i+1 not in blocked_ports else 'down'}"
                                     for i in range(count)) + "\n"
                if command == ("ip", "-d", "link", "show"):
                    return ("\n".join(f"{i+1}: swp{i+1}: <UP> mtu 1500 master br_default" for i in range(count)) +
                            "\n40: br_default: <UP> mtu 1500\n    bridge forward_delay 1500 vlan_filtering 1\n"
                            "41: ib-mgmt1000@br_default: <UP> mtu 1500 master oob\n"
                            "    vlan protocol 802.1Q id 1000 <REORDER_HDR>\n")
                if command == ("bridge", "fdb", "show"):
                    return "\n".join(f"02:00:00:00:00:{i+10:02x} dev swp{i+1} vlan 1000 master br_default"
                                     for i in range(count)) + "\n"
                if command == ("ip", "neighbor"):
                    return "\n".join(f"fe80::{i+10:x} dev ib-mgmt1000 lladdr 02:00:00:00:00:{i+10:02x} REACHABLE"
                                     for i in range(count) if not (nd_missing and i == 0)) + "\n"
                if command == ("ip", "-j", "address", "show"):
                    # v15's read-only address query (V15-OOB-SPINE.md:99): the Leaf SVI owns IPv4,
                    # so the v15 Leaf path is kept (V15-OOB-SPINE.md:54).
                    return json.dumps([{"ifname": "ib-mgmt1000", "flags": ["BROADCAST", "MULTICAST", "UP"],
                                        "operstate": "UP", "addr_info": [
                                            {"family": "inet", "local": "192.0.2.1", "prefixlen": 24,
                                             "scope": "global"},
                                            {"family": "inet6", "local": "fe80::1", "prefixlen": 64,
                                             "scope": "link"}]}])
                if command == ("ifquery", "ib-mgmt1000"):
                    return "iface ib-mgmt1000\n    vrf oob\n"
                raise AssertionError("Unexpected OOB command: " + repr(command))

            def body_for(last):
                if last is None:
                    raise AssertionError("unknown IB device")
                return ("nv set system config auto-save state enabled\n"
                        "nv set system ztp config-save enabled\n"
                        f"nv set interface eth0 ipv4 address 192.0.2.{last}/24\n"
                        "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n"
                        "nv set interface eth0-1 link state up\n"
                        "nv set interface eth0-1 type eth\n"
                        f"nv set system hostname {host(last - 9)}\n"
                        "nv set system dns server 192.0.2.53\n"
                        "nv set system ntp server 192.0.2.123 state enabled\n"
                        "nv set system date-time timezone Etc/UTC\n")

            def phase_session(session, peer, nonce, operation):
                """The strict IB authentication read: a DEV phase session around the framed read."""
                end = f"__HTTP_IB_AUTH_{nonce}_{operation}__=EXIT:"
                if operation != "auth-probe-readonly":
                    raise AssertionError("Unexpected phase operation in check-only: " + operation)
                with phase_reads.get_lock():
                    phase_reads.value += 1
                session.feed(f"\n__HTTP_IB_AUTH_{nonce}_{operation}__=BEGIN\n")
                if peer == "fe80::ff:fe00:a" and derived_failure:
                    session.feed("ssh: connect to host fe80::ff:fe00:a port 22: Network is unreachable\n")
                    session.feed(f"{end}255\n")
                    return session.result(255)
                reply = session.feed(f"admin@{peer}'s password: ")
                if reply != FACTORY:
                    session.feed(f"\nadmin@{peer}: Permission denied (password).\n{end}255\n")
                    return session.result(255)
                if peer == "fe80::ff:fe00:a" and derived_expired:
                    session.feed(EXPIRY)
                    session.feed("(current) UNIX password: ")
                    return session.result(1)
                nonce_body = body_for(addresses.get(peer))
                session.feed(f"\n__HTTP_IB_BEGIN_{nonce}__\n{nonce_body}__HTTP_IB_END_{nonce}__=0\n{end}0\n")
                return session.result(0)

            addresses = {f"fe80::{i+10:x}": i + 10 for i in range(count)}
            addresses["fe80::ff:fe00:a"] = 10

            def transport(argv, responder, timeout, **kwargs):
                if not link_up:
                    raise AssertionError("All blocked: no IB SSH may be attempted")
                text = " ".join(argv)
                auth, frame = AUTH_RE.search(text), FRAME_RE.search(text)
                nested = re.search(r"admin@\[?(fe80::[0-9a-f:]+)", text)
                direct = re.search(r"admin@192\.0\.2\.(\d+)", text)
                if nested:
                    with ib_sessions.get_lock():
                        ib_sessions.value += 1
                if nested and nested.group(1) == "fe80::ff:fe00:a":
                    self.assertIn("-B ib-mgmt1000", text)
                    self.assertIn("ip vrf exec oob", text)
                session = _Session(responder)
                try:
                    if auth is not None:
                        if not nested:
                            raise AssertionError("Expected a nested IB phase session: " + text)
                        return phase_session(session, nested.group(1), *auth.groups())
                    if not frame:
                        raise AssertionError("Expected nonce-framed read command: " + text)
                    if nested:
                        last = addresses[nested.group(1)]
                        peer = nested.group(1)
                    elif direct:
                        last = int(direct.group(1))
                        peer = "192.0.2." + direct.group(1)
                        if last == 10 and direct_script_error:
                            raise ValueError("synthetic unexpected script error")
                        with direct_hits.get_lock():
                            direct_hits[last - 10] += 1
                            attempt = direct_hits[last - 10]
                        if last == 10 and attempt <= direct_network_failures:
                            session.close()
                            return app.SessionResult(
                                "ssh: connect to host 192.0.2.10 port 22: No route to host", 255)
                    else:
                        raise AssertionError("Unexpected synthetic SSH destination: " + text)
                    if responder(f"admin@{peer}'s password: ") != FACTORY:
                        raise AssertionError("the IB read must answer with the selected IB credential")
                    if "nv show system ztp" in text:
                        payload = "service disabled\nstatus aborted\nconfig-save enabled enabled\n"
                    elif "nv config show -o commands" in text:
                        payload = body_for(last)
                    else:
                        raise AssertionError("Unexpected non-read command in check-only: " + text)
                    nonce = frame.group(1)
                    session.close()
                    return app.SessionResult(f"__HTTP_IB_BEGIN_{nonce}__\n{payload}__HTTP_IB_END_{nonce}__=0\n", 0)
                except BaseException:
                    session.close()
                    raise

            stack.enter_context(patch.object(sys, "argv", argv))
            stack.enter_context(patch.object(app, "REPORT_HANDLE", None))
            console = io.StringIO()
            if real_logging:
                stack.enter_context(redirect_stdout(console))
            else:
                stack.enter_context(patch.object(app, "log", lambda message="": messages.append(message)))
            stack.enter_context(patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(patch.object(Path, "home", return_value=home))
            stack.enter_context(patch.object(app, "probe_ethernet_key", return_value="key"))
            stack.enter_context(patch.object(app, "run_on_ethernet", side_effect=ethernet))
            stack.enter_context(patch.object(app, "interactive_run", side_effect=transport))
            stack.enter_context(patch.object(app.subprocess, "run",
                                             side_effect=AssertionError("External commands forbidden")))
            # v15 patched the clock only for the direct-retry cases; every case is patched here
            # (guide :173), and the waits are counted by the retry cases' attempt metrics.
            stack.enter_context(patch.object(app.time, "sleep", return_value=None))
            initial = stack.enter_context(patch.object(app, "resolve_initial_ib_password",
                                                       return_value=FACTORY))
            stack.enter_context(patch.object(getpass, "getpass",
                                             side_effect=AssertionError("No password prompt expected")))
            stack.enter_context(patch.object(builtins, "input",
                                             side_effect=AssertionError("No authorization prompt expected")))
            try:
                code = app.main()
            finally:
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
            summaries = list(root.glob("devices-*/summary.json"))
            self.assertEqual(len(summaries), 1)
            evidence = json.loads(summaries[0].read_text())
            snapshot = root / "snapshots" / (JUMP + ".snapshot.txt")
            self.assertTrue(snapshot.is_file())
            self.assertIn("Device hostname: " + JUMP, snapshot.read_text())
            self.assertEqual(initial.call_count, int(link_up))
            if link_up:
                # Fixture check, not a v15 expectation: with the project global the management run
                # took the merged strict path (IB authentication reads are DEV phase sessions).
                self.assertGreater(phase_reads.value, 0)
            self.workflow_report = (root / "report.log").read_text()
            self.workflow_sessions = (phase_reads.value, ib_sessions.value)
        return code, evidence, console.getvalue() if real_logging else "\n".join(messages)

    @staticmethod
    def record(evidence, index):
        return evidence["records"][host(index)]

    # v15 OfflineMainWorkflowTests.test_all_ports_down_skips_credentials_and_ib_ssh_and_is_incomplete
    # (test_desktop_initial_setup.py:1653).
    def test_all_ports_down_skips_credentials_and_ib_ssh_and_is_incomplete(self):
        code, evidence, output = self.run_workflow(3, False)
        self.assertEqual(code, 2)
        self.assertEqual(evidence["workers"], 0)
        self.assertEqual(evidence["result"], "INCOMPLETE")
        self.assertEqual(len(evidence["records"]), 3)
        self.assertIn("SKIPPED_LINK_DOWN: 3", output)
        self.assertIn("IB IPv6 SSH via OOB: NOT_REACHED=3", output)
        self.assertNotIn("OPERATION COUNTERS", output)
        self.assertIn("No IB switch login was attempted. The current IB configuration remains unknown.", output)
        selection = "IB selection: total-ib=3 filtered-ib=3 ready-ib=0 (prerequisite-blocked=3 unmapped=0)"
        self.assertIn(selection, output)
        self.assertLess(output.index(selection), output.index("Scheduler: ready-ib=0 workers=0"))
        self.assertEqual(sum(row["metrics"].get("ib_ssh_attempts", 0)
                             for row in evidence["records"].values()), 0)

    # v15 OfflineMainWorkflowTests.test_seventeen_existing_devices_flow_through_two_actual_workers_without_writes
    # (test_desktop_initial_setup.py:1669); CURRENT-CONTRACT.md:59, :64.
    def test_seventeen_existing_devices_flow_through_two_actual_workers_without_writes(self):
        code, evidence, output = self.run_workflow(17, True)
        self.assertEqual(code, 0, output)
        self.assertEqual(evidence["workers"], 2)
        self.assertEqual(evidence["result"], "SUCCESS")
        self.assertIn("IB selection: total-ib=17 filtered-ib=0 ready-ib=17 (prerequisite-blocked=0 unmapped=0)", output)
        self.assertEqual(len(evidence["records"]), 17)
        self.assertEqual({row["outcome"] for row in evidence["records"].values()}, {"ALREADY_CONFIGURED"})
        self.assertEqual(sum(row["status"] == "PASS" for row in evidence["direct_rows"]), 17)
        self.assertFalse(any(row["writes_attempted"] for row in evidence["records"].values()))
        self.assertIn("CHECKED_EXISTING_CONFIGURATION: 17", output)
        self.assertFalse(any(row["metrics"].get("nvue_write_commands", 0)
                             for row in evidence["records"].values()))
        self.assertEqual(sum(row["metrics"].get("ib_ssh_attempts", 0)
                             for row in evidence["records"].values()), 34)
        self.assertEqual(sum(row["metrics"].get("direct_ssh_attempts", 0)
                             for row in evidence["records"].values()), 17)

    # v15 OfflineMainWorkflowTests.test_scheduler_selection_counts_csv_total_and_distinguishes_unmapped_from_blocked
    # (test_desktop_initial_setup.py:1687).
    def test_scheduler_selection_counts_csv_total_and_distinguishes_unmapped_from_blocked(self):
        code, evidence, output = self.run_workflow(17, True, unmapped_count=2, blocked_ports=(1, 2))
        self.assertEqual(code, 2, output)
        self.assertEqual(evidence["csv_ib_candidates"], 19)
        self.assertEqual(evidence["p2p_management_targets"], 17)
        self.assertEqual(len(evidence["records"]), 17)
        self.assertEqual(sum(row["outcome"] == "SKIPPED" for row in evidence["records"].values()), 2)
        selection = "IB selection: total-ib=19 filtered-ib=4 ready-ib=15 (prerequisite-blocked=2 unmapped=2)"
        self.assertIn(selection, output)
        self.assertLess(output.index(selection), output.index("Scheduler: ready-ib=15 workers=1"))
        self.assertEqual(sum(row["status"] == "PASS" for row in evidence["direct_rows"]), 15)
        self.assertFalse(any(row["writes_attempted"] for row in evidence["records"].values()))

    # v15 OfflineMainWorkflowTests.test_real_worker_pipeline_recovers_on_third_direct_read_without_device_writes
    # (test_desktop_initial_setup.py:1700).
    def test_real_worker_pipeline_recovers_on_third_direct_read_without_device_writes(self):
        code, evidence, output = self.run_workflow(17, True, direct_network_failures=2)
        self.assertEqual(code, 0, output)
        self.assertEqual(evidence["result"], "SUCCESS")
        self.assertEqual(evidence["workers"], 2)
        self.assertEqual(sum(row["status"] == "PASS" for row in evidence["direct_rows"]), 17)
        self.assertFalse(any(row["writes_attempted"] for row in evidence["records"].values()))
        self.assertEqual(self.record(evidence, 1)["metrics"]["direct_ssh_attempts"], 3)
        self.assertEqual(sum(row["metrics"].get("direct_ssh_attempts", 0)
                             for row in evidence["records"].values()), 19)

    # v15 OfflineMainWorkflowTests.test_exhausted_direct_network_retry_does_not_block_other_worker_tasks
    # (test_desktop_initial_setup.py:1711).
    def test_exhausted_direct_network_retry_does_not_block_other_worker_tasks(self):
        code, evidence, output = self.run_workflow(17, True, direct_network_failures=3)
        self.assertEqual(code, 2, output)
        self.assertEqual(evidence["result"], "INCOMPLETE")
        self.assertEqual(sum(row["status"] == "PASS" for row in evidence["direct_rows"]), 16)
        failed = [row for row in evidence["direct_rows"] if row["status"] == "FAIL"]
        self.assertEqual(len(failed), 1)
        self.assertIn("3 attempts", failed[0]["detail"])
        self.assertIn("No route to host", failed[0]["detail"])
        self.assertEqual(self.record(evidence, 1)["metrics"]["direct_ssh_attempts"], 3)
        self.assertEqual(len(evidence["records"]), 17)
        self.assertFalse(any(row["writes_attempted"] for row in evidence["records"].values()))

    # v15 OfflineMainWorkflowTests.test_unexpected_script_exception_is_failed_but_other_devices_still_finish
    # (test_desktop_initial_setup.py:1724); CURRENT-CONTRACT.md:67 (only a script/common-flow
    # failure is FAILED).
    def test_unexpected_script_exception_is_failed_but_other_devices_still_finish(self):
        code, evidence, output = self.run_workflow(17, True, direct_script_error=True)
        self.assertEqual(code, 1, output)
        self.assertEqual(evidence["result"], "FAILED")
        self.assertTrue(self.record(evidence, 1)["script_error"])
        self.assertEqual(sum(row["status"] == "PASS" for row in evidence["direct_rows"]), 16)
        self.assertIn("FAILED_SCRIPT_EXECUTION", output)
        self.assertFalse(any(row["writes_attempted"] for row in evidence["records"].values()))

    # v15 OfflineMainWorkflowTests.test_missing_nd_derived_candidate_completes_normal_pipeline
    # (test_desktop_initial_setup.py:1733).
    def test_missing_nd_derived_candidate_completes_normal_pipeline(self):
        code, evidence, output = self.run_workflow(17, True, nd_missing=True)
        self.assertEqual(code, 0, output)
        self.assertEqual(evidence["workers"], 2)
        self.assertEqual(evidence["result"], "SUCCESS")
        self.assertEqual(self.record(evidence, 1)["neighbor"]["address_source"], "FDB_EUI64_CANDIDATE")
        self.assertEqual(self.record(evidence, 1)["neighbor"]["ipv6"], "fe80::ff:fe00:a")
        self.assertEqual({row["outcome"] for row in evidence["records"].values()}, {"ALREADY_CONFIGURED"})
        self.assertFalse(any(row["writes_attempted"] for row in evidence["records"].values()))

    # v15 OfflineMainWorkflowTests.test_unreachable_derived_candidate_fails_only_its_own_device
    # (test_desktop_initial_setup.py:1743).
    def test_unreachable_derived_candidate_fails_only_its_own_device(self):
        code, evidence, output = self.run_workflow(17, True, nd_missing=True, derived_failure=True)
        self.assertEqual(code, 2, output)
        self.assertEqual(evidence["result"], "INCOMPLETE")
        self.assertEqual(self.record(evidence, 1)["outcome"], "FAILED")
        self.assertEqual(sum(row["outcome"] == "ALREADY_CONFIGURED" for row in evidence["records"].values()), 16)
        self.assertEqual(self.record(evidence, 1)["neighbor"]["address_source"], "FDB_EUI64_CANDIDATE")
        self.assertFalse(any(row["writes_attempted"] for row in evidence["records"].values()))

    # v15 OfflineMainWorkflowTests.test_derived_ssh_expired_password_is_blocked_in_readonly_without_rotation
    # (test_desktop_initial_setup.py:1752).
    def test_derived_ssh_expired_password_is_blocked_in_readonly_without_rotation(self):
        code, evidence, output = self.run_workflow(1, True, nd_missing=True, derived_expired=True)
        self.assertEqual(code, 2, output)
        self.assertEqual(self.record(evidence, 1)["outcome"], "PASSWORD_CHANGE_REQUIRED")
        self.assertFalse(self.record(evidence, 1)["writes_attempted"])
        self.assertIn("BLOCKED_PASSWORD_CHANGE_REQUIRED", output)

    # v15 OfflineMainWorkflowTests.test_compact_console_and_full_report_and_json_agree_in_real_main_flow
    # (test_desktop_initial_setup.py:1759); CURRENT-CONTRACT.md:21 (summary fields).
    def test_compact_console_and_full_report_and_json_agree_in_real_main_flow(self):
        code, evidence, output = self.run_workflow(17, True, real_logging=True)
        self.assertEqual(code, 0)
        self.assertEqual(output.count("[DONE "), 17)
        self.assertNotIn("DEVICE LOG BEGIN", output)
        self.assertNotIn("Infra Services SKIP: all desired values", output)
        self.assertEqual(self.workflow_report.count("DEVICE LOG BEGIN"), 17)
        self.assertIn("Infra Services SKIP: all desired values", self.workflow_report)
        self.assertLess(len(output), len(self.workflow_report) / 2)
        self.assertIn("07 EVIDENCE & NEXT ACTIONS", output)
        self.assertIn("Result: SUCCESS", self.workflow_report)
        self.assertEqual(evidence["summary"]["categories"], {"CHECKED_EXISTING_CONFIGURATION": 17})
        self.assertEqual(evidence["summary"]["setup_and_direct_ssh_verified"], 17)
        self.assertEqual(evidence["summary"]["direct_ssh"]["ready"], 17)

    # v15 OfflineMainWorkflowTests.test_verbose_main_keeps_full_device_blocks_visible
    # (test_desktop_initial_setup.py:1774).
    def test_verbose_main_keeps_full_device_blocks_visible(self):
        code, evidence, output = self.run_workflow(3, True, real_logging=True, verbose=True)
        self.assertEqual(code, 0)
        self.assertEqual(output.count("DEVICE LOG BEGIN"), 3)
        self.assertIn("Infra Services SKIP: all desired values", output)
        self.assertEqual(evidence["summary"]["categories"], {"CHECKED_EXISTING_CONFIGURATION": 3})

    # FX3 (v3.1.3 integration fix), not ported from v15 (WP-7 review B "FX3 修法" item 2).  Sources:
    # v15 counts each IB SSH session before it starts (参考/initial-setup-v15/
    # initial-setup-20261019-v15_oob-spine.py:2494-2495), the IB authentication read is such a
    # session (v15 :494-496), and the summary says no IB switch login was attempted only when the
    # run's total is 0 (v15 :5341-5342).  Second caliber: the IB sessions this fixture's transport
    # served through the jump (phase and plain) equal the recorded ib_ssh_attempts.
    def test_fx3_strict_authentication_read_is_counted_as_an_ib_ssh_attempt(self):
        def total(evidence):
            return sum(row["metrics"].get("ib_ssh_attempts", 0) for row in evidence["records"].values())

        code, evidence, output = self.run_workflow(1, True, nd_missing=True, derived_expired=True)
        # Fixture check: the one device stops after its strict authentication read (read-only run,
        # password change required), before any other IB session.
        self.assertEqual(self.record(evidence, 1)["outcome"], "PASSWORD_CHANGE_REQUIRED")
        self.assertEqual(self.workflow_sessions, (1, 1))
        with self.subTest(case="one-device-count"):
            self.assertEqual(self.record(evidence, 1)["metrics"].get("ib_ssh_attempts", 0), 1)
        with self.subTest(case="one-device-summary"):
            self.assertEqual(output.count("No IB switch login was attempted"), 0)
        with self.subTest(case="one-device-sessions"):
            self.assertEqual(total(evidence), self.workflow_sessions[1])
        code, evidence, output = self.run_workflow(17, True)
        # Fixture check: each device has one phase authentication read and one plain ZTP read.
        self.assertEqual(self.workflow_sessions, (17, 34))
        with self.subTest(case="seventeen-devices-sessions"):
            self.assertEqual(total(evidence), self.workflow_sessions[1])


class RefusalExitCodeTests(unittest.TestCase):
    """N18 pinned through the real main(): only SSH, the clock and the terminal are replaced."""

    def test_refusing_first_change_exits_nonzero_without_writes(self):
        # 问题文档 I-050 (former N18) 「拒绝 → 非 0」 (its default before the move: non-zero, e.g. 1);
        # R-012 design :589; v3.1.2 guide :1431; v15 RuntimeCoordinator.authorize :4109-4118 and
        # main :5875 (FAILED = 1); guide table 6-1 row 10 (P1: without a global --apply is allowed).
        writes, reads, prompts = [], [], []

        def ethernet(device, user, password, command, timeout, **kwargs):
            answers = {
                ("hostname",): JUMP + "\n",
                ("nv", "show", "interface"): "swp1 up up\n",
                ("ip", "-d", "link", "show"): (
                    "1: swp1: <UP> mtu 1500 master br_default\n40: br_default: <UP> mtu 1500\n"
                    "    bridge forward_delay 1500 vlan_filtering 1\n"
                    "41: ib-mgmt1000@br_default: <UP> mtu 1500 master oob\n"
                    "    vlan protocol 802.1Q id 1000 <REORDER_HDR>\n"),
                ("bridge", "fdb", "show"): "02:00:00:00:00:0a dev swp1 vlan 1000 master br_default\n",
                ("ip", "neighbor"): "fe80::a dev ib-mgmt1000 lladdr 02:00:00:00:00:0a REACHABLE\n",
                ("ip", "-j", "address", "show"): json.dumps([{
                    "ifname": "ib-mgmt1000", "flags": ["BROADCAST", "MULTICAST", "UP"], "operstate": "UP",
                    "addr_info": [{"family": "inet", "local": "192.0.2.1", "prefixlen": 24, "scope": "global"},
                                  {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]}]),
                ("ifquery", "ib-mgmt1000"): "iface ib-mgmt1000\n    vrf oob\n",
            }
            if tuple(command) not in answers:
                raise AssertionError("Unexpected OOB command: " + repr(command))
            return answers[tuple(command)]

        def transport(argv, responder, timeout, **kwargs):
            text = " ".join(argv)
            frame = FRAME_RE.search(text)
            nested = re.search(r"admin@\[?(fe80::[0-9a-f:]+)", text)
            if (frame is None or nested is None
                    or not ("nv show system ztp" in text or "nv config show -o commands" in text)):
                writes.append(text)
                raise AssertionError("Unexpected device command: " + text)
            reads.append(text)
            if responder(f"admin@{nested.group(1)}'s password: ") != FACTORY:
                raise AssertionError("the IB read must answer with the selected IB credential")
            # An unconfigured device: only the factory defaults, ZTP still decides.
            payload = ("service enabled\nstatus in-progress\n" if "nv show system ztp" in text
                       else "nv set system hostname nvos\nnv set service lldp state enabled\n")
            nonce = frame.group(1)
            return app.SessionResult(f"__HTTP_IB_BEGIN_{nonce}__\n{payload}__HTTP_IB_END_{nonce}__=0\n", 0)

        def answer(prompt=""):
            prompts.append(prompt)
            return "n"

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            argv = OfflineMainTests.create_project(self, root) + ["--apply"]
            (root / "01-global.yaml").unlink()
            stack.enter_context(patch.object(sys, "argv", argv))
            stack.enter_context(patch.object(app, "REPORT_HANDLE", None))
            stack.enter_context(patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(patch.object(Path, "home", return_value=home))
            stack.enter_context(patch.object(app, "probe_ethernet_key", return_value="key"))
            stack.enter_context(patch.object(app, "run_on_ethernet", side_effect=ethernet))
            stack.enter_context(patch.object(app, "interactive_run", side_effect=transport))
            stack.enter_context(patch.object(app.subprocess, "run",
                                             side_effect=AssertionError("External commands forbidden")))
            stack.enter_context(patch.object(app.time, "sleep", return_value=None))   # guide :173
            stack.enter_context(patch.object(app, "resolve_initial_ib_password", return_value=FACTORY))
            stack.enter_context(patch.object(getpass, "getpass",
                                             side_effect=AssertionError("No password prompt expected")))
            stack.enter_context(patch.object(builtins, "input", side_effect=answer))
            console = stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            try:
                code = app.main()
            finally:
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
            summaries = list(root.glob("devices-*/summary.json"))
            self.assertEqual(1, len(summaries))
            evidence = json.loads(summaries[0].read_text())
        self.assertTrue(reads, "fixture check: the device was read before the confirmation")
        self.assertEqual(1, len(prompts), "the first-change confirmation was asked once\n" + console.getvalue())
        self.assertEqual("FAILED", evidence["result"])
        self.assertEqual(1, code)
        self.assertEqual([], writes)


if __name__ == "__main__":
    unittest.main()
