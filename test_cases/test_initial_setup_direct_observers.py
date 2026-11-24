"""r660 WP3 independent call-boundary facts; static draft, NOT RUN.

The expected facts come from K1/K3/K7/O14 and the selected-current contract.
Observers retain the real builder, dispatch, editor and policy guards. They do
not turn a lower guard's exception into a behavior RED. External effects use
only the already reviewed owned PUBLIC worlds. No test/control is run here.
"""
from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import csv
import io
import json
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.test_initial_setup_direct_transport import (
    DirectWorld, BODY, HEADER, IB1, IFACE, INITIAL, IP, LL1, MAC1,
    PUBLIC_REPLY, READ, SCOPED, require_api,
)
from test_cases.test_initial_setup_direct_transport_workflow import (
    PhaseWorld, _WP3Checkpoint,
)


@contextmanager
def _profile(functions, observe):
    """Observe exact original Python functions, not arbitrary matching names."""
    previous = sys.getprofile()

    def profile(frame, event, value):
        if event not in ("call", "return"):
            return
        for function in functions:
            if (frame.f_code is function.__code__
                    and frame.f_globals is function.__globals__):
                observe(function, frame, event, value)
                return

    try:
        sys.setprofile(profile)
        yield
    finally:
        sys.setprofile(previous)


def _outcome(call):
    """Retain a primary Exception until the passive fact assertions finish.

    BaseException and cleanup failures are not converted to a success. No
    exception text, password, native vector or argv is copied into a record.
    """
    try:
        return call(), None
    except Exception as error:
        return None, (error, error.__traceback__)


def _reraise(primary):
    if primary is not None:
        raise primary[0].with_traceback(primary[1])


class DirectBoundaryObserverTests(unittest.TestCase):
    def test_phase_builder_entry_has_no_outer_endpoint(self):
        with PhaseWorld(self) as world:
            require_api(world.app)
            builder = world.app.direct_ssh_command
            observed = []

            def observe(function, frame, event, value):
                if event != "call":
                    return
                phase = frame.f_locals.get("_phase")
                observed.append((type(phase) is world.app._IBPhase,
                    getattr(phase, "outer_endpoint", None) == "",
                    getattr(phase, "endpoint", None) == "admin@" + SCOPED))

            with _profile((builder,), observe):
                result, primary = _outcome(world.drive)
            # A nonempty outer is observed BEFORE the real builder refuses it.
            # Do not delete that refusal or require a fictional prefork child.
            self.assertEqual([(True, True, True)], observed,
                "direct phase must enter its real builder with exactly one IB endpoint")
            _reraise(primary)
            self.assertIs(type(result), world.app.SessionResult)
            self.assertEqual(BODY, result.output)
            self.assertEqual(0, result.exit_code)
            self.assertEqual(1, len(world.phase_facts["reaps"]))
            self.assertEqual(["current-input", "finish"],
                [row["kind"] for row in world.phase_facts["events"]])

    def test_real_jump_dispatch_never_enters_a_direct_transport(self):
        with DirectWorld(self) as world:
            require_api(world.app)
            jump = world.app.Device("example-jump-a", "eth_jump",
                "198.51.100.10", "", "", "", "", "")
            target = world.app.Target(world.target().ib, jump, "swp7", "eth0")
            neighbor = world.app.Neighbor(LL1, "ib-mgmt", MAC1, "default")
            ordinary = world.app._run_on_ib_direct
            phase = world.app._execute_ib_direct_phase
            direct_entries, jump_entries = [], []

            def observe(function, frame, event, value):
                if event == "call":
                    direct_entries.append("ordinary" if function is ordinary else "phase")

            def failed_jump(argv, responder, timeout, **kwargs):
                # The real nested builder has already passed all Jump guards.
                # Record only a count; argv can never become a failure repr.
                jump_entries.append(True)
                return world.app.SessionResult(
                    "ssh: connect to host 198.51.100.10 port 22: Connection timed out\n", 255)

            with mock.patch.object(world.app, "interactive_run", side_effect=failed_jump), \
                 _profile((ordinary, phase), observe):
                result, primary = _outcome(lambda: world.app.run_on_ib(
                    target, neighbor, "cumulus", PUBLIC_REPLY, "admin", PUBLIC_REPLY, 2, READ))
            # A wrong direct dispatch still meets its genuine lower rejection;
            # the independent fact is its forbidden entry, not that rejection.
            self.assertEqual([], direct_entries, "a real Jump request must never enter a direct transport")
            self.assertEqual([True], jump_entries)
            self.assertIsNone(result)
            self.assertIsNotNone(primary, "the modeled Jump network failure must remain a failure")
            with self.assertRaises(world.app.SetupError):
                _reraise(primary)
            self.assertEqual([], world.ssh_calls)
            self.assertEqual(0, world.neighbor_reads)
            self.assertIn("--direct-access", world.app.attention_guidance("FAILED_OOB_JUMP_UNREACHABLE"))

    def test_direct_host_key_refresh_selects_only_the_owned_local_editor(self):
        for address in (SCOPED, IP):
            with self.subTest(address=address), DirectWorld(self) as world:
                require_api(world.app)
                endpoint = world.endpoint() if address == SCOPED else world.endpoint(IP, None)
                task = world.app.PreparedIBTask(world.target(), endpoint, "", False)
                change = world.make_host_key_change(address)
                local_init = world.paths.LocalKnownHostsEditor.__init__
                jump_init = world.app.JumpKnownHostsEditor.__init__
                selected, retries, records = [], [], []

                def observe(function, frame, event, value):
                    if event == "call":
                        selected.append("local" if function is local_init else "jump")

                def retry():
                    self.assertEqual("empty", world.keygen_state)
                    retries.append(address)
                    world.keygen_state = "new"

                with _profile((local_init, jump_init), observe):
                    result, primary = _outcome(lambda: world.app.refresh_ib_host_key(
                        change, task, eth_user="", timeout=2, apply=True,
                        read_device_fingerprint=None, retry=retry,
                        operator_forced=True, host_key_records=records))
                # Constructor entry survives a wrong editor's later primary
                # AttributeError; that exception is not accepted as a RED.
                self.assertEqual(["local"], selected,
                    "a management direct task must select only the real local editor")
                _reraise(primary)
                self.assertEqual([address], retries)
                self.assertEqual([("remove", address)],
                    [item for item in world.keygen_calls if item[0] == "remove"])
                self.assertEqual(1, len(records))
                self.assertEqual(("local", None, "operator-forced-unverified"),
                    (records[0].location, records[0].jump, records[0].verification))

    def test_strict_core_preserves_selected_current_by_safe_role_witness(self):
        with DirectWorld(self) as world:
            policy = world.policy()
            self.assertTrue(PUBLIC_REPLY != world.kat["PASSWORD"],
                "the PUBLIC selected and project roles must be distinct")
            original = world.app.run_on_ib
            roles = []

            def observe(function, frame, event, value):
                if event == "call":
                    roles.append(frame.f_locals.get("ib_default_password") == PUBLIC_REPLY)

            with _profile((original,), observe):
                result, primary = _outcome(lambda: world.app._stage_ib_command(
                    world.target(), world.endpoint(), "", "", "admin", PUBLIC_REPLY,
                    2, READ, local=False, strict=True, policy=policy))
            self.assertEqual([True], roles,
                "ordinary direct transport must receive the selected current role, not the project target")
            _reraise(primary)
            self.assertGreater(world.real_native_calls, 0,
                "the real admitted PUBLIC project must be verified before transport")
            self.assertIs(type(result), world.app.SessionResult)
            self.assertEqual(BODY, result.output)
            self.assertFalse(any((result.password_changed, result.password_change_required,
                result.password_change_attempted, result.ib_authentication_rejected)))

    def test_direct_strict_core_rejects_nonexact_result_after_real_qualification(self):
        for exact in (True, False):
            with self.subTest(exact=exact), DirectWorld(self) as world:
                policy = world.policy()
                self.assertTrue(PUBLIC_REPLY != world.kat["PASSWORD"],
                    "the PUBLIC selected and project roles must be distinct")
                result = (world.app.SessionResult(BODY, 0) if exact else SimpleNamespace(
                    output=BODY, exit_code=0, password_changed=False,
                    password_change_required=False, password_change_attempted=False,
                    ib_authentication_rejected=False))
                boundary = []

                def returned(*args, **kwargs):
                    # This is solely the lower return boundary. Typed endpoint,
                    # command, real permission and direct core remain real.
                    self.assertEqual(8, len(args))
                    self.assertIs(type(args[0]), world.app.Target)
                    self.assertIsNone(args[0].ethernet)
                    self.assertIs(type(args[1]), world.app.DirectEndpoint)
                    self.assertTrue(args[2] == "" and args[3] == "",
                        "direct core must retain empty outer roles")
                    self.assertTrue(args[5] == PUBLIC_REPLY, "selected current role must be retained")
                    self.assertEqual(("admin", 2, READ), (args[4], args[6], args[7]))
                    self.assertEqual({"local": False, "allow_password_change": False}, kwargs)
                    boundary.append(True)
                    return result

                with mock.patch.object(world.app, "run_on_ib", side_effect=returned):
                    outcome, primary = _outcome(lambda: world.app._run_authorized_ib_direct_command(
                        world.target(), world.endpoint(), "", "", "admin", PUBLIC_REPLY,
                        2, READ, local=False, _password_policy=policy))
                self.assertEqual([True], boundary, "real typed/core admission must reach one lower return")
                self.assertGreater(world.real_native_calls, 0,
                    "core qualification must not be a truthy policy substitute")
                self.assertEqual([], world.ssh_calls, "this is a return-boundary test, not an SSH claim")
                if exact:
                    _reraise(primary)
                    self.assertIs(result, outcome)
                else:
                    self.assertIsNone(outcome)
                    self.assertIsNotNone(primary, "a nonexact result must be rejected by the real core")
                    error = primary[0]
                    self.assertIs(type(error), world.app.SetupError)
                    self.assertEqual(("management IB operation failed; device state is UNKNOWN",), error.args)
                    self.assertNotIsInstance(error, world.app.IBAuthenticationError)
                    self.assertIsNone(error.__cause__)
                    self.assertIsNone(error.__context__)

    def test_real_other_subnet_main_produces_only_csv_ipv4_direct_read(self):
        with DirectWorld(self) as world:
            require_api(world.app)
            # Independent local fact: LL exists but there is no IPv4 overlap
            # with CSV 192.0.2.10/24. Do not supply a ready Route or endpoint.
            world.local_json = json.dumps([{"ifname": IFACE, "addr_info": [
                {"family": "inet", "local": "198.51.100.1", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::1", "prefixlen": 64}]}])
            main_body = ("nv set system hostname example-ib01\n"
                "nv set service lldp state enabled\n"
                "nv set interface eth0 ipv4 address 192.0.2.10/24\n"
                "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
                "nv set interface eth0-1 link state up\n"
                "nv set interface eth0-1 type eth\n")

            issued = []
            def main_readback(argv, responder, timeout, **kwargs):
                return world.main_readback(argv, responder, timeout, nv_config=main_body,
                                           seen=issued, **kwargs)

            row = [IB1, "ib", IP, "24", "192.0.2.1", MAC1]
            for path in (world.csv, world.master):
                with path.open("w", newline="") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(HEADER)
                    writer.writerow(row + [""] * (len(HEADER) - len(row)))
            world.p2p.write_text("a-node,a-port,z-node,z-port\n"
                "example-unselected-ib99,eth0,example-unselected-leaf99,swp7\n", encoding="utf-8")
            prepare = world.app.run_prepared_tasks
            execute = world.app.execute_ib_task
            read = world.app.run_on_ib
            initial = world.app.run_initial_stage
            observed, reads = {}, []

            def observe(function, frame, event, value):
                if event == "call" and function is prepare:
                    observed["tasks"] = tuple(frame.f_locals["tasks"])
                    world.expected_device_prefix = "devices-" + frame.f_locals["args"].run_stamp + "-"
                elif event == "call" and function is execute:
                    observed["execute"] = frame.f_locals["task"]
                elif (event == "return" and function is read and type(value) is world.app.SessionResult
                      and frame.f_locals["ib_command"] == READ):
                    reads.append(value)
                elif event == "call" and function is initial:
                    observed["consumed"] = frame.f_locals["current"]
                    raise _WP3Checkpoint()

            checkpoint = []
            output = io.StringIO()
            argv = [str(INITIAL), "--project-dir", str(world.project), "--p2p", str(world.p2p),
                "--report", str(world.root / "report.log"), "--target-cache", str(world.root / "targets.json"),
                "--snapshot-dir", str(world.root / "snapshots"), "--execution-mode", "management", "--max-workers", "1"]

            def main_prefix():
                try:
                    return world.app.main()
                except _WP3Checkpoint:
                    checkpoint.append(True)
                    return None

            try:
                with mock.patch.object(sys, "argv", argv), \
                     mock.patch.object(world.app, "interactive_run", side_effect=main_readback), \
                     redirect_stdout(output), redirect_stderr(output), \
                     _profile((prepare, execute, read, initial), observe):
                    outcome, primary = _outcome(main_prefix)
            finally:
                if world.app.REPORT_HANDLE is not None:
                    world.app.REPORT_HANDLE.close()
                    world.app.REPORT_HANDLE = None
            self.assertIn("tasks", observed, "the real MAIN producer must dispatch its actual task")
            self.assertEqual(1, len(observed["tasks"]))
            task = observed["tasks"][0]
            self.assertIsNone(task.target.route.same_subnet)
            self.assertIsNone(task.target.ethernet)
            self.assertIs(type(task.neighbor), world.app.DirectEndpoint)
            self.assertEqual((IP, None), (task.neighbor.address, task.neighbor.interface),
                "the real other-subnet producer must choose CSV IPv4, never LL")
            _reraise(primary)
            self.assertEqual([True], checkpoint, "only the real Initial consumption checkpoint may end this prefix")
            self.assertIs(task, observed["execute"])
            self.assertEqual("", task.ethernet_password)
            self.assertFalse(task.local)
            self.assertEqual([("admin@" + IP, command) for command in
                              (READ, ["ip", "addr", "show", "eth0"], ["ip", "route"],
                               ["nv", "show", "system", "ztp"])], issued)
            self.assertEqual(["admin@" + IP] * 4, world.ssh_calls)
            self.assertEqual(0, world.neighbor_reads)
            self.assertEqual([], [event for event in world.events if event[0] == "local"])
            self.assertEqual(1, len(reads))
            self.assertEqual(main_body, reads[0].output)
            self.assertEqual(main_body, observed["consumed"])
            self.assertEqual((IP, None), (reads[0]._direct_endpoint.address, reads[0]._direct_endpoint.interface))
            self.assertIsNone(world.app._ACTIVE_COORDINATOR)
            self.assertIsNone(world.app._TASK_DEADLINE)
            self.assertIsNone(world.app._TASK_LOG_BUFFER)


if __name__ == "__main__":
    unittest.main()
