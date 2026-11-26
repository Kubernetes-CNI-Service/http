"""Real-script REQ-10-B P1 service/key RED workflow, without device operations."""

from __future__ import annotations

import base64
from contextlib import ExitStack
from contextlib import contextmanager
from contextlib import redirect_stdout
import dataclasses
import hashlib
import inspect
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
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
GENERATOR = ROOT / "ztp/config/nvos/template/90-c2-generate_configs.py"
LOADER = ROOT / "DAY0-Prepare/11-load.py"

STRICT_READ = ("nv", "config", "show", "-o", "commands")
STRICT_DIFF = ("nv", "config", "diff", "-o", "commands")
# Facts owned by later, separately tested requirements (Initial stage:
# test_initial_setup_initial_closed_facts; reserved management ports:
# test_initial_setup_management_network).  The REQ10B device model holds them
# at their verified values so that REQ10B's own Day-0/Services/Keys oracles
# keep measuring the same transactions; the witness proves they stay unwritten.
STRICT_HELD_ROWS = (
    "nv set system config auto-save state enabled",
    "nv set system ztp config-save enabled",
    "nv set interface eth0-1 link state up",
    "nv set interface eth0-1 type eth",
)
HELD_FACT_SETTERS = frozenset({
    "nv set system config auto-save state enabled",
    "nv set system ztp config-save enabled",
    *(f"nv set interface {port} link state up" for port in ("eth0", "eth1", "eth0-1")),
    *(f"nv set interface {port} type eth" for port in ("eth0", "eth1", "eth0-1")),
})
_STRICT_KAT: dict = {}
# T17 (guide :2303): Initial also reads the ZTP operational state.  A device model that
# holds the Initial facts answers it as disabled, in the form the v15 delivery tests use
# (initial-setup-v15-test-cases/test_v15_oob_spine.py:420).
ZTP_SHOW = ("nv", "show", "system", "ztp")
ZTP_DISABLED = "service disabled\n"
ZTP_ENABLED = "service enabled\n"
# Public placeholder IB target for runs without a project global; --credentials-fd
# requires one with --apply (WP-5), and without a global nothing rotates to it.
PUBLIC_FD_TARGET = "public-target-only"


@contextmanager
def credentials_fd(payload: dict):
    """The --credentials-fd argv of one main() run (table 6-1 row 4, guide :747; WP-5).

    One JSON object on an inherited pipe, as test_initial_setup_credentials_fd_workflow
    passes it; main reads and closes the pipe.  It is closed here only while the number
    still names this pipe, so a reused descriptor is never touched.
    """
    reader, writer = os.pipe()
    identity = os.fstat(reader)
    try:
        os.write(writer, json.dumps(payload).encode("utf-8"))
    finally:
        os.close(writer)
    try:
        yield ["--credentials-fd", str(reader)]
    finally:
        try:
            current = os.fstat(reader)
        except OSError:
            current = None
        if current is not None and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
            os.close(reader)


def strict_fd_payload(kat: dict) -> dict:
    """fd credentials of a present-global run whose device already uses the project target.

    The initial credential equals the project target, so the one read-only authentication
    probe succeeds with the target (v15 inspect_ib_device: with --apply the current IB
    password must equal the project global, P3c map 4.5 P1 :356).
    """
    return {"nvos_initial_password": kat["PASSWORD"], "ib_target_password": kat["PASSWORD"]}


def with_held_rows(output: str, held_rows) -> str:
    """A non-empty readback with the device model's held rows present (as the adapter does)."""
    if not held_rows or not output.strip():
        return output
    lines = output.splitlines()
    missing = [row for row in held_rows if row not in lines]
    if not missing:
        return output
    body = output if output.endswith("\n") else output + "\n"
    return body + "\n".join(missing) + "\n"


def held_fact_setters(held_rows) -> frozenset:
    """Setter lines that would rewrite a fact the device model holds.

    A held `eth0-1` range fact also covers the single-port eth0/eth1 setters
    for the same field.  No held rows means no held facts.
    """
    setters = set()
    for row in held_rows:
        setters.add(row)
        tokens = row.split()
        if tokens[:4] == ["nv", "set", "interface", "eth0-1"]:
            for port in ("eth0", "eth1"):
                setters.add(" ".join(["nv", "set", "interface", port, *tokens[4:]]))
    return frozenset(setters)


def held_failure_note(failure, private_values=()) -> str:
    """Name a run failure that was held until the path witness was checked.

    The class name and the failure's fixed text are reported; a text that
    contains any private fixture value is withheld instead.
    """
    if failure is None:
        return ""
    text = str(failure)
    if any(value and value in text for value in private_values):
        text = "message withheld: it contains a private fixture value"
    return f"held run failure {type(failure).__name__}: {text}"


def strict_kat(app) -> dict:
    """The reviewed external KAT through the existing reader, qualified once.

    Values stay in RAM: they are never written to a log, an assertion message
    or a public file.  A missing input or native backend is a FIXTURE HOLD.
    """
    if "values" not in _STRICT_KAT:
        from test_cases import test_initial_setup_target_credentials_workflow as kat_basis

        values = kat_basis.required_external_kat()
        try:
            qualified = app.verify_password_hash(values["PASSWORD"], values["YESCRYPT"]) is True
        except app.SetupError:
            qualified = False
        if not qualified:
            error = RuntimeError("FIXTURE HOLD: native project password backend rejected the reviewed KAT")
            raise error from None
        _STRICT_KAT["values"] = values
    return _STRICT_KAT["values"]


def strict_global_text(kat: dict) -> str:
    """GLOBAL plus the project's IB target hash for the management account."""
    anchor = "        timezone: Asia/Taipei\n- nvl:\n"
    if GLOBAL.count(anchor) != 1:
        raise RuntimeError("FIXTURE HOLD: REQ10B IB global anchor changed")
    # The hash is substituted with %-formatting so that no source line pairs
    # the YAML key with a literal value (public audit cleartext rule).
    block = (
        "        timezone: Asia/Taipei\n"
        "      aaa:\n        user:\n          admin:\n"
        "            password: %s\n"
        "- nvl:\n"
    ) % json.dumps(kat["YESCRYPT"])
    return GLOBAL.replace(anchor, block, 1)


def _public_command(argv, app) -> tuple[str, ...]:
    command = tuple(argv)
    if command[:2] != ("sh", "-c"):
        return command
    if len(command) == 5 and command[3] == "--" and type(command[4]) is str:
        if command[2] == app._KEY_INSTALL_SCRIPT:
            try:
                valid = bool(base64.b64decode(command[4], validate=True))
            except ValueError:
                valid = False
            if valid:
                return ("KEY-SHELL",)
        elif (command[2] == app._CONFIG_BACKUP_SCRIPT
              and re.fullmatch(r"[0-9]{8}-[0-9]{6}", command[4])):
            return ("CONFIG-BACKUP", command[4])
    raise AssertionError("PUBLIC adapter: unknown closed shell command")


@contextmanager
def strict_management_boundary(test, app, *, kat, held_rows=STRICT_HELD_ROWS,
                               empty_pending_diff=True, raw_backup=False):
    """PUBLIC device boundary for the present-global management path of one main() run.

    Since 50efbbd a manual/auto management run with a present project global
    builds a ProjectPasswordPolicy, authenticates each IB through the private
    phase transport (_authenticate_ib_read -> _execute_ib_phase) and sends every
    business command through _run_authorized_ib_command -> run_on_ib.  Policy,
    cache admission, target fetch with native verification, the authorized
    helper and all stage consumers run unchanged.  Only the transport layer is
    replaced: the private phase transport and run_on_ib both reach the test's
    own PUBLIC SessionResult boundary (the run_on_ib mock installed by the
    test).  The manual target prompt answers with the reviewed KAT target.
    Unless the caller passes empty_pending_diff=False, the device model answers
    the read-only pending-diff probe as empty; it holds `held_rows` present in
    every non-empty read and, while it holds rows, answers the ZTP state read as
    disabled (T17).  Only the read-only authentication probe is modeled:
    a run_on_ib request that carries a private phase operation (password
    change, post-change read) fails at the adapter instead of reaching the
    test's boundary.

    Witness records, checked by assert_strict_management_path():
      * policies     - successful ProjectPasswordPolicy constructions;
      * phases       - (IB hostname, operation, policy) per private phase entry;
      * helper       - commands handed to the authorized helper;
      * device       - (command, inside-helper) per request reaching the boundary;
      * transport    - real PTY transport attempts (must stay zero);
      * held_setters - setter lines for the facts this model holds (none for
                       held_rows=()).
      * events      - all real helper/device entries, with separate actual
                      helper and device-stack depth, parent id and policy identity.

    raw_backup=False preserves the original one-to-one model. Only explicit
    raw opt-in admits one CONFIG-BACKUP child of IB01's first DNS helper; its
    parent and full child are retained, not collapsed into the key label.
    """
    if type(raw_backup) is not bool:
        raise AssertionError("PUBLIC adapter: raw backup opt-in must be boolean")
    witness = {"policies": [], "phases": [], "helper": [], "device": [], "transport": 0,
               "held_setters": held_fact_setters(held_rows), "events": [], "raw_backup": raw_backup}
    helper_stack, device_stack = [], []
    real_init = app.ProjectPasswordPolicy.__init__
    real_helper = app._run_authorized_ib_command
    phase_signature = inspect.signature(app._execute_ib_phase)
    positional = tuple(phase_signature.parameters)[:8]
    inner = app.run_on_ib
    target_prompts = ("IB target password (admin): ", "Confirm IB target password: ")

    def prompt(label):
        if label not in target_prompts:
            raise AssertionError("PUBLIC adapter: unexpected interactive credential prompt")
        return kat["PASSWORD"]

    def init(policy, path, user, *args, **kwargs):
        real_init(policy, path, user, *args, **kwargs)
        witness["policies"].append({
            "path": Path(os.path.abspath(path)).resolve(), "user": user,
            "interactive": policy.interactive, "instance": policy,
        })

    def phase(*args, **kwargs):
        bound = phase_signature.bind(*args, **kwargs).arguments
        witness["phases"].append((bound["target"].ib.hostname,
                                  bound.get("_phase_operation"),
                                  bound.get("_password_policy")))
        if (bound.get("_phase_operation") != "auth-probe-readonly"
                or bound.get("local", False) is not False
                or bound.get("allow_password_change", False) is not False
                or bound.get("ib_new_password") is not None):
            raise AssertionError("PUBLIC adapter models only the read-only authentication probe")
        # Same positional request a legacy run_on_ib read carried.
        return app.run_on_ib(*(bound[name] for name in positional))

    def helper(*args, **kwargs):
        command = args[7] if len(args) > 7 else kwargs["ib_command"]
        public = _public_command(command, app)
        target = args[0] if args else kwargs["target"]
        number = len(witness["events"])
        event = {"kind": "helper", "id": number, "command": public,
                 "hostname": getattr(getattr(target, "ib", None), "hostname", None),
                 "policy": kwargs.get("_password_policy"), "helper_id": number,
                 "helper_depth": len(helper_stack) + 1, "device_depth": len(device_stack),
                 "parent_device": device_stack[-1]["id"] if device_stack else None}
        witness["helper"].append(public)
        witness["events"].append(event)
        helper_stack.append(event)
        try:
            return real_helper(*args, **kwargs)
        finally:
            helper_stack.pop()

    def device(*args, **kwargs):
        operation = kwargs.get("_phase_operation")
        if operation is not None:
            # Values such as the new target are never echoed.
            raise AssertionError(
                "PUBLIC adapter models only the read-only authentication probe; "
                f"a private {operation!r} phase request reached the device boundary"
            )
        command = args[7] if len(args) > 7 else kwargs["ib_command"]
        public = _public_command(command, app)
        target = args[0] if args else kwargs["target"]
        parent = helper_stack[-1] if helper_stack else None
        event = {"kind": "device", "id": len(witness["events"]), "command": public,
                 "hostname": getattr(getattr(target, "ib", None), "hostname", None),
                 "policy": parent["policy"] if parent else None,
                 "helper_id": parent["id"] if parent else None, "helper_depth": len(helper_stack),
                 "device_depth": len(device_stack) + 1,
                 "parent_device": device_stack[-1]["id"] if device_stack else None}
        witness["device"].append((public, bool(helper_stack)))
        witness["events"].append(event)
        if public[:1] == ("CONFIG-BACKUP",) or device_stack:
            if not raw_backup:
                raise AssertionError("PUBLIC adapter: recursive backup requires raw opt-in")
            dns = ("nv", "set", "system", "dns", "server", "203.0.113.53")
            dns_helpers = [item for item in witness["events"] if item["kind"] == "helper"
                           and item["hostname"] == "EXAMPLE-IB01" and item["command"] == dns]
            children = [item for item in witness["events"] if item["kind"] == "device"
                        and item["command"][:1] == ("CONFIG-BACKUP",)]
            if not (public[:1] == ("CONFIG-BACKUP",) and event["hostname"] == "EXAMPLE-IB01"
                    and len(helper_stack) == 1 and len(device_stack) == 1
                    and parent["command"] == dns and parent["hostname"] == "EXAMPLE-IB01"
                    and dns_helpers and parent is dns_helpers[0] and len(children) == 1
                    and device_stack[-1]["command"] == dns
                    and device_stack[-1]["hostname"] == "EXAMPLE-IB01"
                    and device_stack[-1]["helper_id"] == parent["id"]
                    and len(witness["policies"]) == 1
                    and parent["policy"] is witness["policies"][0]["instance"]
                    and device_stack[-1]["policy"] is parent["policy"]):
                raise AssertionError("PUBLIC adapter: raw backup child binding refused")
        device_stack.append(event)
        try:
            if tuple(command) == ZTP_SHOW and held_rows:
                # The model holds the Initial facts, so ZTP is disabled (T17, guide :2303).
                return app.SessionResult(ZTP_DISABLED, 0)
            result = inner(*args, **kwargs)
            if tuple(command) == STRICT_DIFF and empty_pending_diff:
                # No pre-existing uncommitted change on the modeled device.
                return app.SessionResult("", 0)
            if (tuple(command) == STRICT_READ and held_rows
                    and type(result.output) is str and result.output.strip()):
                lines = result.output.splitlines()
                missing = [row for row in held_rows if row not in lines]
                if missing:
                    body = result.output if result.output.endswith("\n") else result.output + "\n"
                    result = app.SessionResult(
                        body + "\n".join(missing) + "\n", result.exit_code,
                        result.password_changed, result.password_change_required,
                        result.password_change_attempted, result.ib_authentication_rejected,
                    )
            return result
        finally:
            device_stack.pop()

    def transport(*_args, **_kwargs):
        witness["transport"] += 1
        raise AssertionError("PUBLIC adapter: a real PTY transport was requested")

    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(app.getpass, "getpass", new=prompt))
        stack.enter_context(mock.patch.object(app.ProjectPasswordPolicy, "__init__", new=init))
        stack.enter_context(mock.patch.object(app, "_execute_ib_phase", new=phase))
        stack.enter_context(mock.patch.object(app, "_run_authorized_ib_command", new=helper))
        stack.enter_context(mock.patch.object(app, "run_on_ib", new=device))
        stack.enter_context(mock.patch.object(app, "interactive_run", new=transport))
        yield witness


def assert_strict_management_path(test, witness, *, global_path, devices,
                                  interactive=True, note="", raw_backup=False) -> None:
    """Path witness: strict policy once, phase per device, writes via the adapter.

    `note` (see held_failure_note) is appended to every failure message, so a
    run failure held until this check stays visible when the witness fails.
    """
    suffix = f" [{note}]" if note else ""
    policies = witness["policies"]
    test.assertTrue(
        len(policies) == 1
        and policies[0]["path"] == Path(global_path).resolve()
        and policies[0]["user"] == "admin"
        and policies[0]["interactive"] is interactive,
        "the run must construct exactly one strict ProjectPasswordPolicy from the fixture global"
        + suffix,
    )
    policy = policies[0]["instance"]
    test.assertEqual(list(devices), [entry[0] for entry in witness["phases"]],
                     "every device that reaches IB login must enter phase authentication" + suffix)
    test.assertTrue(
        all(entry[1] == "auth-probe-readonly" and entry[2] is policy
            for entry in witness["phases"]),
        "phase authentication must be the read-only probe bound to the strict policy" + suffix,
    )
    test.assertEqual(0, witness["transport"],
                     "no real PTY transport may run behind the PUBLIC adapter" + suffix)
    writes = [entry for entry in witness["device"]
              if entry[0] not in (STRICT_READ, STRICT_DIFF)]
    test.assertTrue(all(inside for _, inside in writes),
                    "every business command must reach the adapter through the authorized helper"
                    + suffix)
    if not raw_backup:
        test.assertEqual([command for command in witness["helper"] if command != STRICT_READ],
                         [command for command, _ in writes],
                         "authorized business commands and adapter-observed writes must match one to one"
                         + suffix)
    else:
        # Account for EVERY legacy event first. A child is explained below,
        # never removed from either original list or silently folded into KEY.
        test.assertIs(True, witness["raw_backup"], "raw witness requires explicit opt-in" + suffix)
        events = witness["events"]
        test.assertEqual(list(range(len(events))), [event["id"] for event in events])
        helpers = [event for event in events if event["kind"] == "helper"]
        device_events = [event for event in events if event["kind"] == "device"]
        test.assertEqual(len(events), len(helpers) + len(device_events))
        test.assertEqual(witness["helper"], [event["command"] for event in helpers])
        test.assertEqual(witness["device"], [(event["command"], event["helper_depth"] > 0)
                                           for event in device_events])
        test.assertTrue(all(event["helper_depth"] == 1 and event["device_depth"] == 0
                            and event["parent_device"] is None and event["policy"] is policy
                            for event in helpers), "raw helper binding/depth differs" + suffix)
        top, children = [], []
        by_id = {event["id"]: event for event in events}
        for event in device_events:
            if event["device_depth"] == 1:
                test.assertIsNone(event["parent_device"])
                if event["command"] not in (STRICT_READ, STRICT_DIFF):
                    top.append(event)
                    parent = by_id.get(event["helper_id"])
                    test.assertTrue(parent in helpers and event["helper_depth"] == 1
                        and parent["id"] < event["id"] and parent["command"] == event["command"]
                        and parent["hostname"] == event["hostname"] and event["policy"] is policy,
                        "raw top-level helper/device binding differs" + suffix)
            else:
                children.append(event)
        test.assertEqual([command for command in witness["helper"] if command != STRICT_READ],
                         [event["command"] for event in top],
                         "raw top-level helper/device calls must match one to one" + suffix)
        test.assertEqual([event["id"] for event in helpers if event["command"] != STRICT_READ],
                         [event["helper_id"] for event in top],
                         "raw top-level helper/device IDs must match one to one" + suffix)
        test.assertEqual(1, len(children), "raw requires one explicit backup child" + suffix)
        child = children[0]
        dns = ("nv", "set", "system", "dns", "server", "203.0.113.53")
        dns_helpers = [event for event in helpers if event["command"] == dns
                       and event["hostname"] == "EXAMPLE-IB01"]
        test.assertTrue(bool(dns_helpers), "raw DNS parent was not reached" + suffix)
        parent_helper = dns_helpers[0]
        parent_device = by_id.get(child["parent_device"])
        test.assertTrue(child["command"][:1] == ("CONFIG-BACKUP",)
            and len(child["command"]) == 2 and re.fullmatch(r"[0-9]{8}-[0-9]{6}", child["command"][1])
            and child["hostname"] == "EXAMPLE-IB01" and child["helper_depth"] == 1
            and child["device_depth"] == 2 and child["helper_id"] == parent_helper["id"]
            and child["policy"] is policy and parent_device in top
            and parent_device["command"] == dns and parent_device["hostname"] == "EXAMPLE-IB01"
            and parent_device["helper_id"] == parent_helper["id"]
            and parent_helper["id"] < parent_device["id"] < child["id"],
            "raw backup parent/child causal binding differs" + suffix)
    # Only facts this run's device model actually holds (none when held_rows=()).
    test.assertEqual([], [command for command, _ in witness["device"]
                          if " ".join(command) in witness["held_setters"]],
                     "facts held by the device model must never be written" + suffix)

GLOBAL = """\
schema_version: 2
common:
  switch:
    system:
      dns:
        server:
        - 192.0.2.53
        - 198.51.100.53
      ntp:
        server:
        - ntp.ubuntu.com
        - time.common.example.test
      date-time:
        timezone: Etc/UTC
switches:
- ib:
    system:
      dns:
        server:
        - 203.0.113.53
      ntp:
        server:
        - ntp.ubuntu.com
        - time.ib.example.test
      date-time:
        timezone: Asia/Taipei
- nvl:
    system:
      dns:
        server:
        - 203.0.113.54
"""
EXPECTED_IB = {
    "dns": ("203.0.113.53",),
    "ntp": ("ntp.ubuntu.com", "time.ib.example.test"),
    "timezone": "Asia/Taipei",
}


def public_key(seed: int, comment: str) -> str:
    """Build a deterministic valid OpenSSH public line, with no private key."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " " + comment + "\n"


def fingerprint(public_line: str) -> str:
    blob = base64.b64decode(public_line.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode()


def scalar_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for member in value.values():
            yield from scalar_strings(member)
    elif isinstance(value, list):
        for member in value:
            yield from scalar_strings(member)


class Req10BServicesKeysWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("req10b_services_keys_workflow_initial", INITIAL)
        with mock.patch.object(sys, "argv", ["90-c2-generate_configs.py"]):
            cls.generator = load_script("req10b_services_keys_workflow_generator", GENERATOR)
        cls.loader = load_script("req10b_services_keys_workflow_loader", LOADER)

    def test_f02_generated_profile_real_batch_shell_and_local_method_veto(self):
        """Real cache -> stdlib executor/shell -> V2 writer, no SSH/device I/O."""
        authority = load_script("f02_initial_shell_authority", ROOT / "ztp/config_sync_authority.py")
        with tempfile.TemporaryDirectory(prefix="f02-initial-batch-") as directory:
            root, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            root = root.resolve()
            tool, ib_csv, p2p = tool.resolve(), ib_csv.resolve(), p2p.resolve()
            cache = cache.parent.resolve() / cache.name
            ib_csv.write_text(ib_csv.read_text().replace("203.0.113.1,,,,", "203.0.113.1,02:00:00:00:00:01,,,"))
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            candidate = self.initial.load_target_cache(cache, ib_csv, p2p, public_key_tool=tool)
            self.assertIsNotNone(candidate)
            target = candidate[1][0]
            profile = json.loads(cache.read_text())
            self.assertEqual(list(EXPECTED_IB["dns"]), profile["services"]["dns"])
            state = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n")
            remote = root / "remote"
            (remote / ".ssh").mkdir(parents=True)
            (remote / ".ssh/authorized_keys").write_text(laptop + management)
            (remote / "live.commands").write_text(state)
            private = root / "management-key"
            private.write_text("local fixture identity; never a real key")
            private.chmod(0o600)
            executables = root / "fixture-bin"
            executables.mkdir()
            programs = {
                "ssh": "#!" + sys.executable + "\nimport os,shlex,subprocess,sys\n"
                    "a=sys.argv[1:]\nassert 'BatchMode=yes' in a and 'PasswordAuthentication=no' in a\n"
                    "assert a[-2]=='admin@203.0.113.2'\n"
                    "assert open(a[a.index('-i')+1]).read()=='local fixture identity; never a real key'\n"
                    "r=subprocess.run(shlex.split(a[-1]), pass_fds=())\nsys.exit(r.returncode)\n",
                "hostname": "#!/bin/sh\nprintf 'EXAMPLE-IB01\\n'\n",
                "cat": "#!/bin/sh\nif [ \"$1\" = /sys/class/net/eth0/address ]; then "
                    "printf '02:00:00:00:00:01\\n'; else exec /bin/cat \"$@\"; fi\n",
                "nv": "#!/bin/sh\n[ \"$*\" = 'config show -o commands' ] || exit 97\n"
                    "exec /bin/cat \"$HOME/live.commands\"\n",
            }
            for name, source in programs.items():
                path = executables / name
                path.write_text(source)
                path.chmod(0o700)
            storage = root / "configuration-methods"
            for cycle in (1, 2):
                ticket = authority.begin_method(storage, target.ib.hostname, "initial-" + str(cycle),
                                                "own-initial-" + str(cycle), "initial_setup_managed")
                self.assertEqual("pending", authority.read_method_current(storage, target.ib.hostname)["state"])
                if cycle == 2:
                    (remote / ".ssh/authorized_keys").write_text(laptop)
                with mock.patch.dict(os.environ, {"PATH": str(executables) + ":/usr/bin:/bin", "HOME": str(remote)}):
                    observed = self.initial.observe_managed_initial_configuration(
                        target, "admin", private, 5, profile["services"], profile["public_keys"])
                self.assertIs(cycle == 1, observed["config_verified"],
                              "installed-key presence is checked in the actual batch shell, not an old log")
                result = {"schema_version": 2, "record_type": "configuration_method", "hostname": target.ib.hostname,
                          "type": "ib", "config_method": "initial-setup", **{name: ticket[name] for name in (
                            "generation", "source_identity", "operation_id", "trigger_id", "trigger_source")},
                          "state": "success" if cycle == 1 else "failed", "reason": observed["reason"]}
                if cycle == 1:
                    result.update({name: observed[name] for name in ("batch_identity_verified", "config_verified",
                        "interface", "transport_ip", "mac_plain", "live_state_sha256", "input_sha256")})
                    result["source_receipt_sha256"] = observed["observation_sha256"]
                    self.assertEqual(hashlib.sha256(state.encode()).hexdigest(), result["live_state_sha256"])
                authority.finish_method(storage, ticket, result)
                current = authority.read_method_current(storage, target.ib.hostname)
                self.assertEqual((cycle, cycle != 1), (current["generation"], current["veto"]))
                receipt = authority.read_method_receipt(storage, target.ib.hostname)
                self.assertEqual(result if cycle == 1 else None, receipt)
                self.assertNotIn("complete", result, "method proof never supplies missing bootstrap stages")
                if cycle == 1:
                    # Real same-shell observer -> read-only current input binder
                    # -> monitor consumer. No persisted report is an observer.
                    monitor = load_script("f02_initial_real_shell_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
                    reader = authority.InitialMethodMonitorInputs(root, self.initial, tool, cache, ib_csv, p2p)
                    device = {"hostname": "EXAMPLE-IB01", "type": "ib", "config_method": "initial-setup",
                        "ip": "203.0.113.2", "mac_plain": "020000000001", "ssh_user": "admin", "ztp_round": 1,
                        "stages": {name: monitor.stage("pending") for name in monitor.STAGE_NAMES}, "issues": [], "events": []}
                    captured = authority.read_method_current(storage, target.ib.hostname)
                    for drift in (False, True):
                        if drift: (remote / ".ssh/authorized_keys").write_text(laptop)
                        with mock.patch.dict(os.environ, {"PATH": str(executables) + ":/usr/bin:/bin", "HOME": str(remote)}):
                            proof, expected_input = reader.observe(device, private, 5)
                        monitor.apply_current_initial_method_authority(device, storage, captured, proof, expected_input)
                        self.assertEqual("warning" if drift else "success", device["stages"]["config_apply"]["status"])
                        current = authority.read_method_current(storage, target.ib.hostname)
                        self.assertEqual((1, "failed" if drift else "success"), (current["generation"], current["state"]))
                        self.assertFalse(monitor.completion_handoff_device_complete(device))

    def test_f02_monitor_entry_reads_initial_profile_and_rejects_mid_session_changes(self):
        from types import SimpleNamespace
        monitor = load_script("f02_initial_monitor_entry", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        authority = monitor.config_sync_authority
        from test_cases.test_config_sync_authority import ConfigSyncAuthorityTests
        for case in ("positive", "profile-change", "new-writer", "missing-profile", "deep-profile", "observer-error", "inventory-change", "late-receipt-change"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                project, tool, global_path, csv_path, p2p, _, cache, laptop, management = self.fixture(directory)
                project = project.resolve()
                csv_path.write_text("hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                    "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                    "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,,\n")
                master_csv = (
                    "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                    "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                    "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,,\n"
                )
                (project / "infiniband/02-devices_config.csv").write_text(master_csv, encoding="utf-8")
                (project / "02-devices_config.csv").write_text(master_csv, encoding="utf-8")
                self.assertEqual(0, self.run_initial(tool, csv_path, p2p, cache, "--generate-json"))
                (project / "01-global.yaml").write_text(GLOBAL)
                apache, dhcp, air = project / "apache.log", project / "dhcp.log", project / "air.json"
                apache.write_text(""); dhcp.write_text(""); air.write_text('{"nodes": {}}')
                key = project / "management-key"; key.write_text("fixture-only"); key.chmod(0o600)
                args = monitor.parser().parse_args([str(project), "--output-dir", str(project / "reports"),
                    "--apache-log", str(apache), "--dhcp-log", str(dhcp), "--identity", str(key),
                    "--initial-target-cache", str(cache), "--initial-device-csv", str(csv_path),
                    "--initial-p2p", str(p2p), "--initial-tool-inputs", str(tool)])
                expected = {"schema_version": 1, "type": "ib", "config_method": "initial-setup",
                    "hostname": "EXAMPLE-IB01", "eth0": "203.0.113.2/24", "eth0_gateway": "203.0.113.1",
                    "eth1": "", "eth1_gateway": "", "eth0_mac": "02:00:00:00:00:01",
                    "dns": ["203.0.113.53"], "ntp": ["ntp.ubuntu.com", "time.ib.example.test"],
                    "timezone": "Asia/Taipei", "key_fingerprints": sorted([fingerprint(laptop), fingerprint(management)])}
                digest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                storage = project / "99-output-ztp/configuration-methods"
                ticket = authority.begin_method(storage, "EXAMPLE-IB01", "writer-1", "initial-IB01", "initial_setup_managed")
                receipt = ConfigSyncAuthorityTests.method_receipt_v2(ticket, hostname="EXAMPLE-IB01", type="ib",
                    config_method="initial-setup", trigger_source="initial_setup_managed", transport_ip="203.0.113.2",
                    mac_plain="020000000001", live_state_sha256="a" * 64, input_sha256=digest, source_receipt_sha256="c" * 64)
                authority.finish_method(storage, ticket, receipt)
                if case == "missing-profile": cache.unlink()
                if case == "deep-profile": cache.write_text("[" * 1100 + "0" + "]" * 1100)
                def fresh_observer(target, user, private, timeout, services, keys):
                    self.assertEqual("EXAMPLE-IB01", target.ib.hostname)
                    self.assertEqual("admin", user)
                    self.assertEqual(key, private)
                    self.assertEqual(list(EXPECTED_IB["dns"]), services["dns"])
                    self.assertEqual(1, authority.read_method_current(storage, "EXAMPLE-IB01")["generation"])
                    if case == "profile-change": global_path.write_text(GLOBAL.replace("Asia/Taipei", "UTC"))
                    if case == "new-writer": authority.begin_method(storage, "EXAMPLE-IB01", "writer-2", "new-IB01", "initial_setup_managed")
                    if case == "observer-error": raise self.initial.SetupError("independent observer protocol error")
                    if case == "inventory-change":
                        inventory = project / "02-devices_config.csv"
                        inventory.write_text(inventory.read_text().replace("203.0.113.2", "203.0.113.3"))
                    return {"schema_version": 1, "hostname": "EXAMPLE-IB01", "batch_identity_verified": True,
                        "config_verified": True, "interface": "eth0", "transport_ip": "203.0.113.2", "mac_plain": "020000000001",
                        "live_state_sha256": "a" * 64, "input_sha256": digest, "observation_sha256": "c" * 64, "reason": ""}
                original_read = authority.read_method_receipt
                changed_at_read = False
                def held_receipt(*args):
                    nonlocal changed_at_read
                    value = original_read(*args)
                    if case == "late-receipt-change" and not changed_at_read:
                        changed_at_read = True
                        global_path.write_text(GLOBAL.replace("Asia/Taipei", "UTC"))
                    return value
                with mock.patch.object(authority, "load_initial_method_executor", return_value=self.initial), \
                        mock.patch.object(authority, "read_method_receipt", side_effect=held_receipt), \
                        mock.patch.object(self.initial, "observe_managed_initial_configuration", side_effect=fresh_observer) as observe, \
                        mock.patch.object(monitor, "load_release_identity", return_value={"dhcp_status": "disabled", "release_id": "fixture-release", "generated_at": "2026-10-07T07:00:00+08:00"}), \
                        mock.patch.object(monitor, "service_runtime_backend", return_value=SimpleNamespace(name="systemd")), \
                        mock.patch.object(monitor, "service_state", return_value={"active": "fixture", "enabled": "fixture", "error": ""}), \
                        mock.patch.object(monitor, "ACTIVE_AIR_JSON", air), \
                        mock.patch.object(monitor, "run_command", return_value={"returncode": 1, "stdout": "", "stderr": "fixture collection unavailable"}):
                    output = monitor.monitor_once(args, project)
                device = json.loads((output / "report.json").read_text())["devices"][0]
                self.assertEqual(0 if case in {"missing-profile", "deep-profile"} else 1, observe.call_count, device.get("configuration_method_observation"))
                self.assertEqual("success" if case == "positive" else "warning", device["stages"]["config_apply"]["status"])
                current = authority.read_method_current(storage, "EXAMPLE-IB01")
                self.assertEqual("success" if case == "positive" else "pending" if case == "new-writer" else "failed", current["state"])
                self.assertEqual(2 if case == "new-writer" else 1, current["generation"])
                self.assertFalse(monitor.completion_handoff_device_complete(device))

    def fixture(self, directory: str, *, global_text: str = GLOBAL):
        root = Path(directory)
        tool = root / "infiniband/bringup/xdr-initial-setup"
        tool.mkdir(parents=True)
        global_path = tool / "01-global.yaml"
        global_path.write_text(global_text, encoding="utf-8")
        neutral = root / "infra/infra-neutral.conf"
        neutral.parent.mkdir(parents=True)
        neutral.write_text("DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n", encoding="ascii")
        (tool / "infra-neutral.conf").write_text("DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n", encoding="ascii")
        ib_csv = root / "ib.csv"
        ib_csv.write_text(
            "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,"
            "eth1_ip,netmask,eth1_gw\n"
            "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,\n"
            "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n",
            encoding="utf-8",
        )
        master_csv = (
            "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,"
            "eth1_ip,netmask,eth1_gw\n"
            "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,\n"
            "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,\n"
        )
        (root / "infiniband/02-devices_config.csv").write_text(master_csv, encoding="utf-8")
        (root / "02-devices_config.csv").write_text(master_csv, encoding="utf-8")
        p2p = root / "p2p.dot"
        p2p.write_text('"EXAMPLE-IB01":"eth0" -- "EXAMPLE-JUMP01":"7";\n', encoding="utf-8")
        pubdir = root / "infiniband/publickey"
        pubdir.mkdir(parents=True)
        (tool / "publickey").symlink_to("../../publickey")
        laptop = public_key(17, "laptop")
        management = public_key(18, "management")
        (pubdir / "laptop.pub").write_text(laptop, encoding="ascii")
        (pubdir / "mgmt-server.pub").write_text(management, encoding="ascii")
        cache = root / "out/targets.json"
        return root, tool, global_path, ib_csv, p2p, pubdir, cache, laptop, management

    def test_f02_initial_profile_parser_never_reopens_rebound_foreign_inputs(self):
        """A safe snapshot cannot authorize a later unguarded pathname read."""
        authority = load_script("f02_initial_parser_snapshot_boundary", ROOT / "ztp/config_sync_authority.py")
        for case in ("cache", "csv", "p2p", "global", "key", "fifo"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root, tool, global_file, csv_path, p2p, pubdir, cache, _, _ = self.fixture(str(base / "project"))
                self.assertEqual(0, self.run_initial(tool, csv_path, p2p, cache, "--generate-json"))
                paths = {"cache": cache, "csv": csv_path, "p2p": p2p,
                         "global": global_file, "key": pubdir / "mgmt-server.pub", "fifo": csv_path}
                victim = paths[case]
                original_stat = victim.stat()
                foreign = base / "foreign-input"
                foreign_bytes = b"INDEPENDENT FOREIGN INPUT: MUST NOT BE OPENED\n"
                foreign.write_bytes(foreign_bytes)
                # Do not accidentally short-circuit the original parser's
                # freshness checks; the fault is a read after safe capture.
                os.utime(foreign, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                original_parser = self.initial.load_target_cache
                original_open = Path.open
                rebound, forbidden_reads = [], []
                def rebind_then_parse(*args, **kwargs):
                    if not rebound:
                        rebound.append(True)
                        victim.unlink()
                        if case == "fifo":
                            os.mkfifo(victim)
                            os.utime(victim, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                        else:
                            victim.symlink_to(foreign)
                    return original_parser(*args, **kwargs)
                def reject_foreign_open(path, *args, **kwargs):
                    if path.resolve() == foreign or (case == "fifo" and path == victim):
                        forbidden_reads.append(str(path))
                        raise AssertionError("profile parser reopened a foreign input after safe capture")
                    return original_open(path, *args, **kwargs)
                with mock.patch.object(self.initial, "load_target_cache", side_effect=rebind_then_parse), \
                        mock.patch.object(Path, "open", reject_foreign_open), \
                        self.assertRaises((authority.AuthorityError, OSError, ValueError)):
                    authority.InitialMethodMonitorInputs(root.resolve(), self.initial, tool.resolve(),
                                                         cache, csv_path, p2p)
                self.assertTrue(rebound, "the actual cache parser boundary must be exercised")
                self.assertEqual([], forbidden_reads)
                self.assertEqual(foreign_bytes, foreign.read_bytes())
                self.assertFalse((root / "99-output-ztp/configuration-methods").exists())

    def test_f02_managed_main_pending_precedes_writes_and_failed_cycle_revokes(self):
        authority = load_script("f02_managed_initial_main_authority", ROOT / "ztp/config_sync_authority.py")
        cycle_type = getattr(authority, "ManagedInitialMethodCycle", None)
        self.assertTrue(callable(cycle_type), "managed initial main must produce its own causal receipt")
        with tempfile.TemporaryDirectory(prefix="f02-managed-initial-main-") as directory:
            # I18: a present project global must carry the IB target hash, so the
            # managed run takes the present-global strict path (TEST d876330 model).
            root, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.strict_fixture(directory)
            root = root.resolve()
            tool, ib_csv, p2p = tool.resolve(), ib_csv.resolve(), p2p.resolve()
            ib_csv.write_text("hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                              "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                              "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,,\n")
            master_csv = (
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,,\n"
            )
            (root / "infiniband/02-devices_config.csv").write_text(master_csv, encoding="utf-8")
            (root / "02-devices_config.csv").write_text(master_csv, encoding="utf-8")
            private = root / ".ssh/id_ed25519"
            private.parent.mkdir(mode=0o700)
            private.write_text("fixture identity")
            private.chmod(0o600)
            cache = cache.parent.resolve() / cache.name
            state = ("nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                     "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                     "nv set system hostname EXAMPLE-IB01\n"
                     "nv set system dns server 203.0.113.53\n"
                     "nv set system ntp server ntp.ubuntu.com\n"
                     "nv set system ntp server time.ib.example.test\n"
                     "nv set system date-time timezone Asia/Taipei\n")
            storage = root / "99-output-ztp/configuration-methods"
            basis = {"schema_version": 1, "type": "ib", "config_method": "initial-setup", "hostname": "EXAMPLE-IB01",
                     "eth0": "203.0.113.2/24", "eth0_gateway": "203.0.113.1", "eth1": "", "eth1_gateway": "",
                     "eth0_mac": "02:00:00:00:00:01", "dns": ["203.0.113.53"],
                     "ntp": ["ntp.ubuntu.com", "time.ib.example.test"], "timezone": "Asia/Taipei",
                     "key_fingerprints": sorted([fingerprint(laptop), fingerprint(management)])}
            expected_input = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            key_payload = base64.b64encode((laptop + management).encode("ascii")).decode("ascii")
            for cycle in (1, 2, 3, 4, 5):
                if cycle == 4:
                    ib_csv.write_text(ib_csv.read_text().replace("203.0.113.3", "203.0.113.2"))
                executor = cycle_type(root, self.initial)
                current_tool = tool
                if cycle == 5:
                    current_tool = root / "99-output-ib_nvl/bringup/xdr-initial-setup"
                    current_tool.mkdir(parents=True)
                    (current_tool / "01-global.yaml").symlink_to((tool / "01-global.yaml").resolve())
                    (current_tool / "publickey").symlink_to((tool / "publickey").resolve())
                    # Q4: the managed tool root is the only infra-neutral.conf source.
                    (current_tool / "infra-neutral.conf").write_bytes((tool / "infra-neutral.conf").read_bytes())
                def device_boundary(*args, **kwargs):
                    current = authority.read_method_current(storage, "EXAMPLE-IB01")
                    self.assertEqual((cycle, "pending", True), tuple(current[name] for name in ("generation", "state", "veto")))
                    if cycle == 2:
                        raise self.initial.SetupError("independent transport failure")
                    command = tuple(args[7])
                    if args[0].ib.hostname != "EXAMPLE-IB01":
                        raise AssertionError("PUBLIC managed model: unknown IB endpoint")
                    if command == ("ip", "addr", "show", "eth0"):
                        return self.initial.SessionResult(
                            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                            "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n", 0)
                    if command == ("sh", "-c", self.initial._KEY_INSTALL_SCRIPT, "--", key_payload):
                        # The key stage verifies the device's closed install receipt.
                        return self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)
                    if command == STRICT_READ:
                        return self.initial.SessionResult(state, 0)
                    if command == STRICT_DIFF:
                        return self.initial.SessionResult("", 0)
                    if command == ("hostname",):
                        # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its CSV name.
                        return self.initial.SessionResult(args[0].ib.hostname + "\n", 0)
                    raise AssertionError("PUBLIC managed model: unknown IB command")
                def batch_observer(target, user, key, timeout, services, keys):
                    if cycle == 3:
                        ib_csv.write_text(ib_csv.read_text().replace("203.0.113.2", "203.0.113.3"))
                    return {"schema_version": 1, "hostname": "EXAMPLE-IB01", "batch_identity_verified": True,
                            "config_verified": True, "interface": "eth0", "transport_ip": "203.0.113.2",
                            "mac_plain": "020000000001", "live_state_sha256": hashlib.sha256(state.encode()).hexdigest(),
                            "input_sha256": expected_input, "observation_sha256": "b" * 64, "reason": ""}
                with ExitStack() as stack:
                    if cycle in (4, 5):
                        from tools import ib_bringup_runtime_guard as runtime_guard

                        guard_path = root / "private-runtime.lock"
                        original_guard_path = runtime_guard._RUNTIME_GUARD_PATH
                        if cycle == 4:
                            self.assertFalse(os.path.lexists(guard_path))
                        stack.enter_context(mock.patch.object(
                            runtime_guard, "_RUNTIME_GUARD_PATH", guard_path))
                    # The modeled device already uses the project target, which the initial
                    # credential names: with --apply v15 requires the current IB password to
                    # equal the project global (P3c map 4.5 P1 :356; owner Q-035 (a)).
                    stack.enter_context(mock.patch.dict(
                        os.environ, {"NVOS_INITIAL_PASSWORD": strict_kat(self.initial)["PASSWORD"]}))
                    for name, value in (("local_ethernet_keys", set()), ("prompt_ethernet_passwords", {"example-jump01": "fixture"}),
                            ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "table")),
                            ("collect_ethernet_network_tables", (
                                "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                                "8: swp8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
                                "02:00:00:00:00:01 dev swp7 master bridge dynamic\n"
                                "02:00:00:00:00:02 dev swp8 master bridge dynamic\n",
                                "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n")),
                            ("save_ethernet_snapshot", root / "snapshot"), ("interface_status_line", "swp7 up"),
                            ("interface_oper_status", "up"), ("interface_vrf", "default"),
                            # v15 checks IPv4 on every --apply (owner Q-035 (a)); that SSH check
                            # is a transport outside this PUBLIC model.
                            ("verify_ipv4_login", None)):
                        stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                    stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=device_boundary))
                    stack.enter_context(mock.patch.object(self.initial, "verify_management_key_possession"))
                    stack.enter_context(mock.patch.object(self.initial, "observe_managed_initial_configuration", side_effect=batch_observer))
                    witnesses = []
                    if cycle not in (4, 5):
                        witnesses.append(stack.enter_context(strict_management_boundary(
                            self, self.initial, kat=strict_kat(self.initial))))
                    result = self.run_initial(current_tool, ib_csv, p2p, cache, "--apply", "--yes", "--execution-mode", "management",
                                              method_cycle=executor,
                                              managed_entry=authority.managed_initial_main if cycle in (4, 5) else None,
                                              managed_tool_inputs=current_tool if cycle == 5 else None,
                                              managed_strict=witnesses if cycle in (4, 5) else None)
                    if cycle in (4, 5):
                        self.assertTrue(guard_path.is_file())
                        guard_info = guard_path.stat()
                        self.assertEqual((root, os.getuid(), 1),
                                         (guard_path.parent, guard_info.st_uid, guard_info.st_nlink))
                        with runtime_guard._runtime_instance_guard() as descriptor:
                            held = os.fstat(descriptor)
                            self.assertEqual((guard_info.st_dev, guard_info.st_ino),
                                             (held.st_dev, held.st_ino))
                if cycle in (4, 5):
                    self.assertEqual(original_guard_path, runtime_guard._RUNTIME_GUARD_PATH)
                self.assertEqual(1, len(witnesses))
                assert_strict_management_path(self, witnesses[0], global_path=global_path, devices=("EXAMPLE-IB01",))
                current = authority.read_method_current(storage, "EXAMPLE-IB01")
                self.assertEqual((cycle, "success" if cycle in (1, 4, 5) else "failed", cycle not in (1, 4, 5)),
                                 tuple(current[name] for name in ("generation", "state", "veto")))
                # Table 6-1 row 11 (guide :754): cycle 2's device transport failure is INCOMPLETE,
                # exit 2; cycle 3's project input change stops the common flow, FAILED, exit 1
                # (v15 CURRENT-CONTRACT.md「只有脚本/公共流程异常才称 FAILED，正常完成但仍有前提
                # 阻塞用 INCOMPLETE」、「共享输入/证据落盘错误仍应停止公共流程」).
                self.assertEqual({1: 0, 2: 2, 3: 1, 4: 0, 5: 0}[cycle], result)
                receipt = authority.read_method_receipt(storage, "EXAMPLE-IB01")
                self.assertEqual(cycle in (1, 4, 5), receipt is not None)
                if receipt:
                    self.assertEqual("initial_setup_managed", receipt["trigger_source"])
                    self.assertNotIn("complete", receipt)

    def test_f02_managed_input_and_output_scope_is_checked_before_leaf_outputs(self):
        authority = load_script("f02_managed_input_output_scope", ROOT / "ztp/config_sync_authority.py")
        for case in ("csv", "p2p", "cache", "snapshot"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root, tool, _, csv_path, p2p, _, cache, _, _ = self.fixture(str(base / "project"))
                csv_path.write_text(csv_path.read_text().replace("eth1_gw\n", "eth1_gw,config_method\n")
                    .replace("EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,\n",
                             "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n")
                    .replace("192.0.2.10,,,,,,\n", "192.0.2.10,,,,,,,\n"))
                master_csv = (
                    "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                    "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                    "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,,\n"
                )
                (root / "infiniband/02-devices_config.csv").write_text(master_csv, encoding="utf-8")
                (root / "02-devices_config.csv").write_text(master_csv, encoding="utf-8")
                foreign = base / "foreign"
                foreign.mkdir()
                if case == "csv":
                    outside_csv = foreign / "ib.csv"
                    outside_csv.write_bytes(csv_path.read_bytes())
                    csv_path = outside_csv
                if case == "p2p":
                    outside_p2p = foreign / "p2p.dot"
                    outside_p2p.write_bytes(p2p.read_bytes())
                    p2p = outside_p2p
                if case == "cache": cache = foreign / "out/targets.json"
                extra = ["--snapshot-dir", str(foreign / "snapshots")] if case == "snapshot" else []
                expected_foreign = {"csv": foreign / "ib.csv", "p2p": foreign / "p2p.dot",
                                    "cache": foreign / "out/targets.json", "snapshot": foreign / "snapshots"}[case]
                before = {str(path.relative_to(foreign)): path.read_bytes() for path in foreign.rglob("*") if path.is_file()}
                cycle = authority.ManagedInitialMethodCycle(root.resolve(), self.initial)
                with self.assertRaises((self.initial.SetupError, authority.AuthorityError, ValueError)) as rejected, \
                        mock.patch.object(self.initial, "local_ethernet_keys", return_value=set()), \
                        mock.patch.object(cycle, "admit_paths", wraps=cycle.admit_paths) as admit:
                    self.run_initial(tool, csv_path, p2p, cache, "--apply", "--yes", "--execution-mode", "management", *extra,
                                     method_cycle=cycle)
                admit.assert_called_once()
                self.assertIn(str(expected_foreign), str(rejected.exception))
                self.assertFalse((root / "out").exists(), "reject before local report/cache publication")
                self.assertFalse((root / "99-output-ztp").exists(), "reject before minting a method era")
                self.assertEqual(before, {str(path.relative_to(foreign)): path.read_bytes() for path in foreign.rglob("*") if path.is_file()})

    def test_f02_managed_method_admission_rejects_before_outputs(self):
        authority = load_script("f02_managed_initial_admission", ROOT / "ztp/config_sync_authority.py")
        for method in ("ztp", "", "initial-setup"):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                root, tool, _, csv_path, p2p, _, cache, _, _ = self.fixture(directory)
                if method:
                    csv_path.write_text(csv_path.read_text().replace("eth1_gw\n", "eth1_gw,config_method\n")
                        .replace("EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,\n",
                                 "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,," + method + "\n")
                        .replace("192.0.2.10,,,,,,\n", "192.0.2.10,,,,,,,\n"))
                    master_csv = (
                        "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                        "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,," + method + "\n"
                        "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,,\n"
                    )
                    (root / "infiniband/02-devices_config.csv").write_text(master_csv, encoding="utf-8")
                    (root / "02-devices_config.csv").write_text(master_csv, encoding="utf-8")
                # Neither an incompatible/default method nor check-only mode
                # may create the method namespace or ancillary output dirs.
                cycle = authority.ManagedInitialMethodCycle(root.resolve(), self.initial)
                with self.assertRaises(self.initial.SetupError) as rejected, \
                        mock.patch.object(self.initial, "local_ethernet_keys", return_value=set()):
                    self.run_initial(tool, csv_path, p2p, cache, "--plan" if method == "initial-setup" else "--apply", method_cycle=cycle)
                if method == "ztp":
                    self.assertIn("声明 ztp", str(rejected.exception))
                    self.assertIn("与当前 initial-setup 执行者不兼容", str(rejected.exception))
                elif method == "initial-setup":
                    self.assertIn("managed method authority requires management --apply, not plan/generation/ethernet mode",
                                  str(rejected.exception))
                else:
                    self.assertIn("managed initial-setup requires an explicit per-device config_method column",
                                  str(rejected.exception))
                self.assertFalse(cache.parent.exists(), "admission must precede report/cache writes")
                self.assertFalse((root / "99-output-ztp").exists())

    def test_wp8_managed_tool_root_ignores_a_forwarded_project_dir(self):
        """v3.1.3 WP-8 (guide :912; WP-8b, review 中 1): the managed path keeps its tool root under --project-dir.

        managed_initial_main forwards the operator's initial-setup arguments unchanged
        (config_sync_authority.py :1634-1636), so --project-dir can reach main(method_cycle=...).  Guide :912
        「受管路径（`method_cycle` 非空）不在表里，仍取 `tool_input_root`」: with a decoy project D whose global,
        key and neutral defaults all differ, the cache, the report's input-sources line (:913) and the
        public-key input still come from the managed tool root, and no file under D is opened.  The run stops
        at the OOB password prompt (a device boundary), after the cache and the report header exist.
        """
        authority = load_script("wp8_managed_project_dir_authority", ROOT / "ztp/config_sync_authority.py")
        stop = "fixture: stop at the OOB password prompt"
        with tempfile.TemporaryDirectory(prefix="wp8-managed-project-dir-") as directory:
            base = Path(directory).resolve()
            root, tool, global_path, csv_path, p2p, _, cache, laptop, management = self.fixture(str(base / "project"))
            csv_path.write_text(csv_path.read_text().replace("eth1_gw\n", "eth1_gw,config_method\n")
                .replace("EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,\n",
                         "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n")
                .replace("192.0.2.10,,,,,,\n", "192.0.2.10,,,,,,,\n"))
            master = root / "02-devices_config.csv"
            master_csv = (
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,,\n"
            )
            (root / "infiniband/02-devices_config.csv").write_text(master_csv, encoding="utf-8")
            master.write_text(master_csv, encoding="utf-8")
            decoy = base / "decoy"
            (decoy / "infiniband/bringup/xdr-initial-setup").mkdir(parents=True)
            (decoy / "01-global.yaml").write_text(GLOBAL.replace("203.0.113.53", "198.51.100.99"), encoding="utf-8")
            (decoy / "decoy.pub").write_text(public_key(19, "decoy"), encoding="ascii")
            (decoy / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf").write_text(
                "DNS=198.51.100.98\nNTP=time.decoy.example.test\nTIMEZONE=Asia/Tokyo\n", encoding="ascii")
            cycle = authority.ManagedInitialMethodCycle(root, self.initial)
            opened = []
            original_open = Path.open

            def record_open(path, *args, **kwargs):
                opened.append(Path(os.path.realpath(path)))
                return original_open(path, *args, **kwargs)

            # This input-source test stops before device IO. Only its unrelated
            # password prerequisite is modeled; real MAIN still compares the
            # selected global binding against its actual admitted cache.
            policy_calls = {"construct": 0, "password": 0}
            case = self

            class PublicInputSourcePolicy:
                def __init__(policy, path, user, **options):
                    policy_calls["construct"] += 1
                    case.assertEqual(1, policy_calls["construct"])
                    case.assertEqual(global_path.resolve(), Path(path).resolve())
                    case.assertEqual("admin", user)
                    case.assertEqual({}, options)
                    case.assertEqual(GLOBAL.encode("utf-8"), Path(path).read_bytes())
                    policy.binding = (str(global_path.resolve()), None, None,
                                      hashlib.sha256(GLOBAL.encode("utf-8")).hexdigest())

                def password(policy):
                    policy_calls["password"] += 1
                    case.assertEqual(1, policy_calls["password"])
                    return "PUBLIC-WP8-unused-target"

            # Any refusal is caught here so that what was opened is judged first; the stop text is checked last.
            with self.assertRaises((self.initial.SetupError, authority.AuthorityError, ValueError)) as stopped, \
                    mock.patch.object(Path, "open", record_open), \
                    mock.patch.object(self.initial, "ProjectPasswordPolicy", PublicInputSourcePolicy), \
                    mock.patch.object(self.initial, "prompt_ethernet_passwords",
                                      side_effect=self.initial.SetupError(stop)):
                self.run_initial(tool, csv_path, p2p, cache, "--apply", "--yes", "--execution-mode", "management",
                                 "--project-dir", str(decoy), method_cycle=cycle)
            self.assertEqual([], sorted(str(path) for path in opened if path.is_relative_to(decoy)),
                             ":912: no file of the --project-dir project is opened on the managed path")
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual({"status": "compared",
                              "subset_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
                              "master_sha256": hashlib.sha256(master.read_bytes()).hexdigest()},
                             payload["inventory_check"])
            self.assertEqual(str(global_path.resolve()), payload["global"])
            self.assertEqual(hashlib.sha256(global_path.read_bytes()).hexdigest(),
                             payload["cache_authority"]["global_sha256"])
            self.assertEqual({key: list(value) if isinstance(value, tuple) else value
                              for key, value in EXPECTED_IB.items()}, payload["services"])
            self.assertEqual([("laptop.pub", fingerprint(laptop)), ("mgmt-server.pub", fingerprint(management))],
                             [(entry["name"], entry["fingerprint"]) for entry in payload["public_keys"]])
            report = (cache.parent / "report.log").read_text(encoding="utf-8").splitlines()
            sources = [line for line in report if line.startswith("Input sources: ")]
            self.assertEqual(1, len(sources), ":913: one input-sources line")
            self.assertIn(f"; global, public keys and neutral defaults from {tool} ", sources[0] + " ")
            self.assertNotIn(str(decoy), sources[0])
            self.assertIn(f"Public-key input: {tool / 'publickey'}; usable entries=2", report)
            self.assertEqual(stop, str(stopped.exception), "the run got past the cache and the report header")
            self.assertEqual({"construct": 1, "password": 1}, policy_calls)

    def run_initial(self, tool: Path, ib_csv: Path, p2p: Path,
                    cache: Path, *extra: str, method_cycle=None, managed_entry=None, managed_tool_inputs=None,
                    managed_strict=None) -> int:
        argv = [
            "initial-setup.py", "--ib-csv", str(ib_csv), "--p2p", str(p2p),
            "--target-cache", str(cache), "--report", str(cache.parent / "report.log"),
            "--snapshot-dir", str(cache.parent / "snapshots"), *extra,
        ]
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            if method_cycle is None:
                stack.enter_context(mock.patch.object(self.initial, "__file__", str(tool / "initial-setup.py")))
                # Ordinary runs really use a Leaf layout, including D3's three
                # required modules, rather than falling back to repository tools.
                (tool / "tools").mkdir(exist_ok=True)
                for name in ("device_identity", "hostname_ranges", "login_path", "inventory_subset"):
                    shutil.copyfile(ROOT / "tools" / (name + ".py"), tool / "tools" / (name + ".py"))
                stack.enter_context(mock.patch.object(self.initial, "_TOOLS_ROOT", None))
                stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
                stack.enter_context(mock.patch.dict(sys.modules))
                for name in list(sys.modules):
                    if name == "tools" or name.startswith("tools."):
                        del sys.modules[name]
            else:
                self.assertEqual(ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py",
                                 Path(self.initial.__file__), "managed entry executes repository code, not a project copy")
            stack.enter_context(mock.patch.object(Path, "home", return_value=method_cycle.project if method_cycle else tool.parents[2]))
            stack.enter_context(redirect_stdout(io.StringIO()))
            # v15's final management-server -> IB direct read (v15 CURRENT-CONTRACT.md「最终测试由
            # 管理服务器直连 IB eth0」) is a transport outside this PUBLIC model: it answers PASS.
            stack.enter_context(mock.patch.object(self.initial, "verify_management_direct_ssh", return_value=None))
            if "--credentials-fd" in extra:
                if method_cycle is None:
                    # --credentials-fd loads tools/credentials_fd.py beside the script (Leaf layout,
                    # guide :664, O5); the fixture's project copy carries the repository file.
                    (tool / "tools").mkdir(exist_ok=True)
                    shutil.copyfile(ROOT / "tools/credentials_fd.py", tool / "tools/credentials_fd.py")
                # One tools loader state per run: its root, sys.path entry and loaded modules.
                stack.enter_context(mock.patch.object(self.initial, "_TOOLS_ROOT", None))
                stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
                loaded = {name: sys.modules.pop(name) for name in ("tools.credentials_fd", "tools.device_identity")
                          if name in sys.modules}

                def restore_loaded() -> None:
                    for name in ("tools.credentials_fd", "tools.device_identity"):
                        sys.modules.pop(name, None)
                    sys.modules.update(loaded)
                stack.callback(restore_loaded)
            if managed_entry is not None:
                # Execute the real CLI loader and freshly loaded main. Replace
                # ONLY device I/O boundaries, never __file__, profiles or main.
                stack.enter_context(mock.patch.dict(managed_entry.__globals__, {"_HTTP_ROOT": method_cycle.project}))
                from importlib.machinery import SourceFileLoader
                real_exec = SourceFileLoader.exec_module
                def isolated_device_io(loader, module):
                    real_exec(loader, module)
                    if module.__name__ == "_http_managed_initial_setup":
                        for name in ("local_ethernet_keys", "prompt_ethernet_passwords", "collect_ethernet_interfaces",
                                     "collect_ethernet_network_tables", "save_ethernet_snapshot", "interface_status_line",
                                     "interface_oper_status", "interface_vrf",
                                     "run_on_ib", "verify_management_key_possession", "observe_managed_initial_configuration",
                                     "verify_management_direct_ssh", "verify_ipv4_login"):
                            setattr(module, name, getattr(self.initial, name))
                        boundary = module.run_on_ib

                        def fresh_session_result(*args, **kwargs):
                            # The strict management path checks the exact SessionResult type of
                            # the module it runs in; the device answer is re-expressed in the
                            # fresh leaf's own type with every field unchanged.
                            result = boundary(*args, **kwargs)
                            if type(result) is self.initial.SessionResult:
                                result = module.SessionResult(**dataclasses.asdict(result))
                            return result
                        module.run_on_ib = fresh_session_result
                        if managed_strict is not None:
                            # Present-global strict path of the fresh leaf: the same PUBLIC
                            # adapter replaces only its private phase transport (I18).
                            managed_strict.append(stack.enter_context(strict_management_boundary(
                                self, module, kat=strict_kat(self.initial))))
                stack.enter_context(mock.patch.object(SourceFileLoader, "exec_module", isolated_device_io))
            try:
                if managed_entry is not None:
                    profile_args = ["--tool-inputs", str(managed_tool_inputs)] if managed_tool_inputs is not None else []
                    return managed_entry(["--project", str(method_cycle.project), *profile_args, "--", *argv[1:]])
                return self.initial.main() if method_cycle is None else self.initial.main(method_cycle=method_cycle)
            finally:
                report = self.initial.REPORT_HANDLE
                if report is not None:
                    report.close()
                    self.initial.REPORT_HANDLE = None

    def run_strict(self, tool: Path, ib_csv: Path, p2p: Path, cache: Path, *extra: str,
                   global_path: Path, devices: tuple[str, ...],
                   held_rows=STRICT_HELD_ROWS, raw_backup=False) -> int:
        """One present-global management P2 run, then its strict-path witness.

        A SetupError from the run is held until the witness is checked, so a run
        that never reached the strict path fails on that fact first; the held
        error's class name and fixed text are carried in that failure message.
        A test whose own device model states every fact passes held_rows=().
        """
        failure = None
        result = None
        kat = strict_kat(self.initial)
        with strict_management_boundary(self, self.initial, kat=kat,
                                        held_rows=held_rows, raw_backup=raw_backup) as witness:
            try:
                result = self.run_initial(tool, ib_csv, p2p, cache, *extra)
            except self.initial.SetupError as error:
                failure = error
        assert_strict_management_path(
            self, witness, global_path=global_path, devices=devices,
            # --credentials-fd never prompts, so its policy is not interactive (WP-5, R-012 8.3).
            interactive="--credentials-fd" not in extra,
            raw_backup=raw_backup,
            note=held_failure_note(failure, tuple(value for value in kat.values()
                                                 if type(value) is str)),
        )
        if failure is not None:
            raise failure
        return result

    def strict_fixture(self, directory: str):
        """fixture() whose global carries the project's IB target hash (KAT)."""
        return self.fixture(directory, global_text=strict_global_text(strict_kat(self.initial)))

    def drive_one_device(self, first_state: str, verified_state: str,
                         *extra: str, remove_global_before_p1: bool = False,
                         remove_global_before_p2: bool = False,
                         post_service_state: str | None = None):
        """Exercise real P1/cache/P2 control flow with only the network boundary faked."""
        # Default management mode with the project global kept through P2 is
        # the present-global strict path; the other variants stay legacy.
        strict = (not remove_global_before_p1 and not remove_global_before_p2
                  and "ethernet" not in extra)
        with tempfile.TemporaryDirectory(prefix="req10b-device-flow-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, laptop, management = (
                self.strict_fixture(directory) if strict else self.fixture(directory))
            if remove_global_before_p1:
                global_path.unlink()
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            if remove_global_before_p2 and global_path.exists():
                global_path.unlink()
            commands: list[tuple[str, ...]] = []
            shows = 0
            key_payload = base64.b64encode((laptop + management).encode("ascii")).decode("ascii")

            def device_boundary(*args, **_kwargs):
                nonlocal shows
                command = tuple(args[7])
                commands.append(command)
                if args[0].ib.hostname != "EXAMPLE-IB01":
                    raise AssertionError("PUBLIC single-device model: unknown IB endpoint")
                if command == ("ip", "addr", "show", "eth0"):
                    return self.initial.SessionResult(
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n", 0)
                if command == ("nv", "config", "show", "-o", "commands"):
                    shows += 1
                    output = first_state if shows == 1 else verified_state
                    if shows > 2 and post_service_state is not None:
                        output = post_service_state
                    # The legacy (no-adapter) runs hold the same Initial and reserved-port
                    # facts as the strict adapter does (T17: they also enter Initial).
                    return self.initial.SessionResult(
                        output if strict else with_held_rows(output, STRICT_HELD_ROWS), 0)
                if command == ZTP_SHOW:
                    return self.initial.SessionResult(ZTP_DISABLED, 0)
                if command == ("sh", "-c", self.initial._KEY_INSTALL_SCRIPT, "--", key_payload):
                    return self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)
                if command in {
                    STRICT_DIFF,
                    ("nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"),
                    ("nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"),
                    ("nv", "set", "system", "hostname", "EXAMPLE-IB01"),
                    ("nv", "set", "system", "dns", "server", "203.0.113.53"),
                    ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
                    ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
                    ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"),
                    ("nv", "config", "apply", "-y"), ("nv", "config", "save"),
                }:
                    return self.initial.SessionResult("", 0)
                if command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its CSV name.
                    return self.initial.SessionResult(args[0].ib.hostname + "\n", 0)
                raise AssertionError("PUBLIC single-device model: unknown IB command")

            local_jump = {"example-jump01"} if "ethernet" in extra else set()
            payload = (strict_fd_payload(strict_kat(self.initial)) if strict else
                       {"nvos_initial_password": "initial-password", "ib_target_password": PUBLIC_FD_TARGET})
            with ExitStack() as stack:
                fd_argv = stack.enter_context(credentials_fd(payload))
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", local_jump),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", (
                        "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "8: swp8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
                        "02:00:00:00:00:01 dev swp7 master bridge dynamic\n"
                        "02:00:00:00:00:02 dev swp8 master bridge dynamic\n",
                        "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("interface_vrf", "default"),
                    ("verify_ipv4_login", None),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=device_boundary))
                try:
                    if strict:
                        result = self.run_strict(
                            tool, ib_csv, p2p, cache, "--apply", "--yes",
                            *fd_argv, *extra,
                            global_path=global_path, devices=("EXAMPLE-IB01",),
                        )
                    else:
                        result = self.run_initial(
                            tool, ib_csv, p2p, cache, "--apply", "--yes",
                            *fd_argv, *extra,
                        )
                finally:
                    report = self.initial.REPORT_HANDLE
                    if report is not None:
                        report.close()
                        self.initial.REPORT_HANDLE = None
            return result, commands, (cache.parent / "report.log").read_text(encoding="utf-8"), laptop, management

    @staticmethod
    def rewrite_cache_with_matching_sidecar(cache: Path, payload: dict) -> None:
        raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        cache.write_bytes(raw)
        cache.with_name(cache.name + ".sha256").write_text(
            f"{hashlib.sha256(raw).hexdigest()}  {cache.name}\n", encoding="ascii"
        )

    def test_real_generator_and_initial_p1_agree_on_whitelisted_ib_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-service-p1-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            with mock.patch.object(self.generator, "_GLOBAL_FILE", str(global_path)):
                merged = self.generator.load_global("ib")
            self.assertEqual(list(EXPECTED_IB["dns"]), merged["system"]["dns"]["server"])
            self.assertEqual(list(EXPECTED_IB["ntp"]), merged["system"]["ntp"]["server"])
            self.assertEqual(EXPECTED_IB["timezone"], merged["system"]["date-time"]["timezone"])
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            # Table 6-1 row 6 (guide :749): cache version 5 (v15 CURRENT-CONTRACT.md
            # 「cache version 5 只保存有输入校验的静态目标」).
            # v315 r617 WP1 :558 explicitly advances this existing P1 fixture to6.
            self.assertEqual(6, payload["version"])
            values = set(scalar_strings(payload))
            for expected in (*EXPECTED_IB["dns"], *EXPECTED_IB["ntp"], EXPECTED_IB["timezone"]):
                self.assertIn(expected, values)
            for superseded in ("192.0.2.53", "198.51.100.53", "time.common.example.test"):
                self.assertNotIn(superseded, values, "deep merge replaces an entire key, not its members")
            self.assertNotIn("domain", json.dumps(payload))
            self.assertNotIn("search", json.dumps(payload))

    def test_p1_cache_bakes_full_valid_public_lines_and_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-key-p1-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, laptop, management = self.fixture(directory)
            self.loader.validate_pubkey(pubdir / "laptop.pub")
            self.loader.validate_pubkey(pubdir / "mgmt-server.pub")
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            values = set(scalar_strings(json.loads(cache.read_text(encoding="utf-8"))))
            for line in (laptop, management):
                self.assertIn(line.strip(), {value.strip() for value in values})
                self.assertIn(fingerprint(line), values)

    def test_newer_project_public_key_invalidates_management_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-pubkey-freshness-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, laptop, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            old_cache = cache.read_bytes()
            replacement = public_key(25, "rotated-laptop")
            path = pubdir / "laptop.pub"
            path.write_text(replacement, encoding="ascii")
            newer = cache.stat().st_mtime_ns + 2_000_000_000
            os.utime(path, ns=(newer, newer))
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            self.assertNotEqual(old_cache, cache.read_bytes())
            values = set(scalar_strings(json.loads(cache.read_text(encoding="utf-8"))))
            self.assertIn(fingerprint(replacement), values)
            self.assertNotIn(fingerprint(laptop), values)

    def test_management_never_reuses_cache_baked_from_open_ssh_invalid_rsa(self) -> None:
        """A matching v4 checksum and old mtime do not waive P1 key validation."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        for mode in ("management", "auto"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                prefix="req10b-rsa-cached-"
            ) as directory:
                _, tool, _, ib_csv, p2p, pubdir, cache, _, _ = self.fixture(directory)
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
                rogue = pubdir / "other.pub"
                rogue.write_text(malformed, encoding="ascii")
                payload = json.loads(cache.read_text(encoding="utf-8"))
                payload["public_keys"].append({
                    "name": "other.pub", "line": malformed.strip(),
                    "fingerprint": fingerprint(malformed),
                })
                self.rewrite_cache_with_matching_sidecar(cache, payload)
                older = cache.stat().st_mtime_ns - 2_000_000_000
                os.utime(rogue, ns=(older, older))
                before = (cache.stat().st_ino, cache.read_bytes())
                extra = ("--plan", "--execution-mode", "management") if mode == "management" else ("--plan",)
                with mock.patch.object(self.initial.socket, "gethostname", return_value="MGMT-SERVER"), \
                     mock.patch.object(self.initial.socket, "getfqdn", return_value="MGMT-SERVER"):
                    with self.assertRaises(self.initial.SetupError):
                        self.run_initial(tool, ib_csv, p2p, cache, *extra)
                self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_newer_global_invalidates_management_cache_and_rebakes_services(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-global-freshness-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            original = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(str(global_path.resolve()), original["global"])
            global_path.write_text(GLOBAL.replace("203.0.113.53", "203.0.113.66"),
                                   encoding="utf-8")
            newer = cache.stat().st_mtime_ns + 2_000_000_000
            os.utime(global_path, ns=(newer, newer))
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(str(global_path.resolve()), payload["global"])
            self.assertIn("203.0.113.66", set(scalar_strings(payload)))
            self.assertNotIn("203.0.113.53", set(scalar_strings(payload)))

    def test_management_rejects_rechecksummed_cache_with_wrong_global_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-global-binding-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            payload["global"] = str(global_path.with_name("different-global.yaml"))
            self.rewrite_cache_with_matching_sidecar(cache, payload)
            before = cache.read_bytes()
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            self.assertNotEqual(before, cache.read_bytes())
            self.assertEqual(str(global_path.resolve()),
                             json.loads(cache.read_text(encoding="utf-8"))["global"])

    def test_global_retarget_to_older_project_file_invalidates_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-global-retarget-") as directory:
            root, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            replacement = root / "old-project-global.yaml"
            replacement.write_text(GLOBAL.replace("203.0.113.53", "203.0.113.67"),
                                   encoding="utf-8")
            older = cache.stat().st_mtime_ns - 2_000_000_000
            os.utime(replacement, ns=(older, older))
            global_path.unlink()
            global_path.symlink_to(replacement)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(str(replacement.resolve()), payload["global"])
            self.assertIn("203.0.113.67", set(scalar_strings(payload)))

    def test_ethernet_leaf_keeps_baked_keys_when_project_key_link_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-leaf-baked-keys-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            before = (cache.stat().st_ino, cache.read_bytes())
            (tool / "publickey").unlink()
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "ethernet"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: reused", report)
            self.assertIn(fingerprint(laptop), report)
            self.assertIn(fingerprint(management), report)
            self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_ethernet_p2_reuses_baked_keys_without_ssh_keygen_even_if_source_is_visible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-leaf-no-keygen-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            with mock.patch.object(self.initial.subprocess, "run", side_effect=AssertionError(
                "P2 cache consumption must not spawn ssh-keygen"
            )) as external:
                self.assertEqual(0, self.run_initial(
                    tool, ib_csv, p2p, cache, "--plan", "--execution-mode", "ethernet"
                ))
            external.assert_not_called()
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: reused", report)
            self.assertIn(fingerprint(laptop), report)
            self.assertIn(fingerprint(management), report)

    def test_auto_manager_missing_both_sources_rebakes_instead_of_using_stale_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-auto-manager-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            original = cache.read_bytes()
            global_path.unlink()
            (tool / "publickey").unlink()
            with mock.patch.object(self.initial.socket, "gethostname", return_value="MGMT-SERVER"), \
                 mock.patch.object(self.initial.socket, "getfqdn", return_value="MGMT-SERVER"):
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--plan"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            self.assertNotEqual(original, cache.read_bytes())
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertIsNone(payload["global"])
            self.assertIsNone(payload["services"])
            self.assertEqual([], payload["public_keys"])
            self.assertIn("Services SKIP: 01-global.yaml was unavailable", report)

    def test_auto_leaf_missing_both_sources_reuses_baked_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-auto-leaf-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            before = (cache.stat().st_ino, cache.read_bytes())
            global_path.unlink()
            (tool / "publickey").unlink()
            with mock.patch.object(self.initial.socket, "gethostname", return_value="EXAMPLE-JUMP01"), \
                 mock.patch.object(self.initial.socket, "getfqdn", return_value="EXAMPLE-JUMP01"):
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--plan"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: reused", report)
            self.assertIn(fingerprint(laptop), report)
            self.assertIn(fingerprint(management), report)
            self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_p1_rejects_a_public_key_rejected_by_real_loader(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-key-invalid-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, _, _ = self.fixture(directory)
            invalid = pubdir / "other.pub"
            invalid.write_text("ssh-ed25519 invalid!!!\n", encoding="ascii")
            with self.assertRaises(self.loader.LoadError):
                self.loader.validate_pubkey(invalid)
            with self.assertRaises(self.initial.SetupError):
                self.run_initial(tool, ib_csv, p2p, cache, "--generate-json")
            self.assertFalse(cache.exists(), "invalid project key must not publish a target cache")

    def test_p1_refuses_rsa_shape_rejected_by_real_loader_before_cache_publication(self) -> None:
        """Real load acceptance and real P1 publication must agree for RSA."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        with tempfile.TemporaryDirectory(prefix="req10b-rsa-p1-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, _, _ = self.fixture(directory)
            key = pubdir / "other.pub"
            key.write_text(malformed, encoding="ascii")
            with self.assertRaises(self.loader.LoadError):
                self.loader.validate_pubkey(key)
            with self.assertRaises(self.initial.SetupError):
                self.run_initial(tool, ib_csv, p2p, cache, "--generate-json")
            self.assertFalse(cache.exists(), "P1 must not bake a key that load rejects")

    def test_p1_refuses_valid_then_invalid_multiline_key_before_cache_publication(self) -> None:
        """P1 must validate every public line before publishing a shared cache."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        with tempfile.TemporaryDirectory(prefix="req10b-mixed-p1-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, laptop, _ = self.fixture(directory)
            (pubdir / "laptop.pub").write_text(laptop + malformed, encoding="ascii")
            with self.assertRaises(self.initial.SetupError):
                self.run_initial(tool, ib_csv, p2p, cache, "--generate-json")
            self.assertFalse(cache.exists(), "a bad second line must not enter target cache")

    def test_plan_lists_day0_services_and_complete_key_install_without_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-plan-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            # Like the other plan/apply cases here, the workstation is not an Ethernet jump
            # switch: never resolve the real host name (socket.getfqdn() makes macOS libc keep
            # an mDNSResponder socket open for the rest of the process).
            with mock.patch.object(self.initial, "run_on_ib") as network, \
                    mock.patch.object(self.initial, "local_ethernet_keys", return_value=set()):
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--plan"))
            network.assert_not_called()
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            for command in (
                "nv set interface eth0 ipv4 address 203.0.113.2/24",
                "nv set interface eth0 ipv4 gateway 203.0.113.1",
                "nv set system hostname EXAMPLE-IB01",
                "nv set system dns server 203.0.113.53",
                "nv set system ntp server ntp.ubuntu.com",
                "nv set system ntp server time.ib.example.test",
                "nv set system date-time timezone Asia/Taipei",
                "nv config apply -y",
                "nv config save",
            ):
                with self.subTest(command=command):
                    self.assertIn(command, report)
            expected_public_payload = base64.b64encode(
                (laptop + management).encode("utf-8")
            ).decode("ascii")
            self.assertIn("authorized_keys", report)
            self.assertIn(expected_public_payload, report,
                          "the plan must retain both complete public lines, not just fingerprints")

    def test_configured_day0_still_enters_independent_service_transaction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-configured-p2-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.strict_fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            commands: list[tuple[str, ...]] = []
            current = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
            )
            services = (
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )
            key_payload = base64.b64encode((laptop + management).encode("ascii")).decode("ascii")

            def device_boundary(*args, **_kwargs):
                command = tuple(args[7])
                commands.append(command)
                if args[0].ib.hostname != "EXAMPLE-IB01":
                    raise AssertionError("PUBLIC configured model: unknown IB endpoint")
                if command == ("ip", "addr", "show", "eth0"):
                    return self.initial.SessionResult(
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n", 0)
                if command == ("nv", "config", "show", "-o", "commands"):
                    applied = ("nv", "config", "apply", "-y") in commands
                    return self.initial.SessionResult(current + (services if applied else ""), 0)
                if command == ("sh", "-c", self.initial._KEY_INSTALL_SCRIPT, "--", key_payload):
                    return self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)
                if command in {
                    STRICT_DIFF,
                    ("nv", "set", "system", "dns", "server", "203.0.113.53"),
                    ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
                    ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
                    ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"),
                    ("nv", "config", "apply", "-y"), ("nv", "config", "save"),
                }:
                    return self.initial.SessionResult("", 0)
                if command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its CSV name.
                    return self.initial.SessionResult(args[0].ib.hostname + "\n", 0)
                raise AssertionError("PUBLIC configured model: unknown IB command")

            with mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}), \
                 mock.patch.object(self.initial, "local_ethernet_keys", return_value=set()), \
                 mock.patch.object(self.initial, "prompt_ethernet_passwords", return_value={"example-jump01": "eth-password"}), \
                 mock.patch.object(self.initial, "collect_ethernet_interfaces", return_value=("EXAMPLE-JUMP01", "interface table")), \
                 mock.patch.object(self.initial, "collect_ethernet_network_tables", return_value=(
                     "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                     "8: swp8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
                     "02:00:00:00:00:01 dev swp7 master bridge dynamic\n"
                     "02:00:00:00:00:02 dev swp8 master bridge dynamic\n",
                     "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n")), \
                 mock.patch.object(self.initial, "save_ethernet_snapshot", return_value=cache.parent / "snapshot.txt"), \
                 mock.patch.object(self.initial, "interface_status_line", return_value="swp7 up"), \
                 mock.patch.object(self.initial, "interface_oper_status", return_value="up"), \
                 mock.patch.object(self.initial, "interface_vrf", return_value="default"), \
                 mock.patch.object(self.initial, "verify_ipv4_login"), \
                 credentials_fd(strict_fd_payload(strict_kat(self.initial))) as fd_argv, \
                 mock.patch.object(self.initial, "run_on_ib", side_effect=device_boundary):
                try:
                    self.run_strict(
                        tool, ib_csv, p2p, cache, "--apply", "--yes",
                        *fd_argv,
                        global_path=global_path, devices=("EXAMPLE-IB01",),
                    )
                finally:
                    report = self.initial.REPORT_HANDLE
                    if report is not None:
                        report.close()
                        self.initial.REPORT_HANDLE = None
            self.assertNotIn(
                ("nv", "set", "system", "hostname", "EXAMPLE-IB01"), commands,
                "configured Day-0 fields must not be rewritten",
            )
            self.assertIn(
                ("nv", "set", "system", "dns", "server", "203.0.113.53"), commands,
                "configured Day-0 must not skip missing services",
            )
            self.assertIn(("nv", "config", "apply", "-y"), commands)
            self.assertIn(("nv", "config", "save"), commands)
            self.assertIn("day0-skipped=1", (cache.parent / "report.log").read_text(encoding="utf-8"))
            self.assertIn("services-skipped=0", (cache.parent / "report.log").read_text(encoding="utf-8"))

    def _exercise_upgrade_rerun(self, missing_services: tuple[str, ...],
                                *, suppress_service_stage: bool = False,
                                wipe_day0: bool = False,
                                suppress_day0_detection: bool = False,
                                single_base_stage_fault: bool = False) -> None:
        """Run the real setup three times against one isolated device state."""
        with tempfile.TemporaryDirectory(prefix="req10b-upgrade-rerun-") as directory:
            root, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.strict_fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            day0 = [
                "nv set interface eth0 ipv4 address 203.0.113.2/24",
                "nv set interface eth0 ipv4 gateway 203.0.113.1",
                "nv set system hostname EXAMPLE-IB01",
            ]
            day0_argv = [tuple(line.split()) for line in day0]
            service_argv = [
                ("nv", "set", "system", "dns", "server", "203.0.113.53"),
                ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
                ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
                ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"),
            ]
            service_lines = [" ".join(command) for command in service_argv]
            self.assertTrue(set(missing_services) <= set(service_lines))
            running = day0 + service_lines
            pending: list[str] = []
            rounds: list[list[tuple[str, ...]]] = []
            device_home = root / "fake-device-home"
            device_home.mkdir()
            ssh_dir = device_home / ".ssh"
            ssh_dir.mkdir()
            authorized = ssh_dir / "authorized_keys"
            authorized.write_text(laptop + management, encoding="ascii")
            original_keys = (authorized.stat().st_ino, authorized.read_bytes())
            links = (
                "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                "8: swp8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            )
            fdb = (
                "02:00:00:00:00:01 dev swp7 master bridge dynamic\n"
                "02:00:00:00:00:02 dev swp8 master bridge dynamic\n"
            )
            vlans = "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n"
            key_command = (
                "sh", "-c", self.initial._KEY_INSTALL_SCRIPT, "--",
                base64.b64encode((laptop + management).encode("ascii")).decode("ascii"),
            )

            def device_boundary(*args, **_kwargs):
                command = tuple(args[7])
                rounds[-1].append(command)
                if command == ("ip", "addr", "show", "eth0"):
                    return self.initial.SessionResult(
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n", 0)
                if command == ("nv", "config", "show", "-o", "commands"):
                    # A wiped device still has an independently known factory
                    # hostname. Empty transport output is UNKNOWN, not evidence
                    # that these in-memory desired values were removed.
                    output = "\n".join(running) + "\n" if running else "nv set system hostname nvos\n"
                    return self.initial.SessionResult(output, 0)
                if command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its applied NVUE name.
                    names = [line.split()[-1] for line in running if line.startswith("nv set system hostname ")]
                    return self.initial.SessionResult((names[-1] if names else "nvos") + "\n", 0)
                if command in service_argv or command in day0_argv:
                    pending.append(" ".join(command))
                elif command == ("nv", "config", "apply", "-y"):
                    for line in pending:
                        if line not in running:
                            running.append(line)
                    pending.clear()
                elif command[:2] == ("sh", "-c"):
                    self.assertEqual(key_command, command, "only the complete PUBLIC key-install request may run")
                    result = subprocess.run(
                        command, cwd=root,
                        env={"HOME": str(device_home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    return self.initial.SessionResult(result.stdout, result.returncode)
                return self.initial.SessionResult("", 0)

            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                ipv4_verify = stack.enter_context(mock.patch.object(self.initial, "verify_ipv4_login"))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", (links, fdb, vlans)),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("interface_vrf", "default"),
                    ("run_on_ib", mock.DEFAULT),
                ):
                    if name == "run_on_ib":
                        stack.enter_context(mock.patch.object(self.initial, name, side_effect=device_boundary))
                    else:
                        stack.enter_context(mock.patch.object(self.initial, name, return_value=value))

                def invoke() -> str:
                    rounds.append([])
                    with credentials_fd(strict_fd_payload(strict_kat(self.initial))) as fd_argv:
                        self.assertEqual(0, self.run_strict(
                            tool, ib_csv, p2p, cache, "--apply", "--yes",
                            *fd_argv,
                            global_path=global_path, devices=("EXAMPLE-IB01",),
                        ))
                    return (cache.parent / "report.log").read_text(encoding="utf-8")

                first_report = invoke()
                self.assertIn("day0-skipped=1", first_report)
                self.assertIn("services-skipped=1", first_report)
                self.assertFalse(any(command in day0_argv for command in rounds[0]))
                self.assertFalse(any(command in service_argv for command in rounds[0]))
                self.assertNotIn(("nv", "config", "apply"), rounds[0])
                self.assertNotIn(("nv", "config", "apply", "-y"), rounds[0])
                self.assertNotIn(("nv", "config", "save"), rounds[0])
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))

                if wipe_day0:
                    running.clear()
                else:
                    running[:] = [line for line in running if line not in missing_services]
                # The two oracle controls model a product that silently skips the restoration.
                # The v15 skeleton (P3c map D32d :284, 2.3 :121; 04 Q-039) reports a skipped service
                # stage as UNVERIFIED and verifies the CSV Network values on every run, so the silent
                # skip claims a completed service stage, and skips the Network decision and check.
                if suppress_service_stage:
                    with mock.patch.object(self.initial, "run_service_stage", return_value=(True, False)):
                        second_report = invoke()
                elif suppress_day0_detection:
                    with mock.patch.object(self.initial, "base_stage_needed", return_value=False), \
                            mock.patch.object(self.initial, "verify_state", return_value=None):
                        second_report = invoke()
                elif single_base_stage_fault:
                    # Control for the Day-0 oracle (06 WP6-a8): only the Network decision lies;
                    # the CSV Network check still runs, so the fault cannot stay silent.
                    with mock.patch.object(self.initial, "base_stage_needed", return_value=False):
                        second_report = invoke()
                else:
                    second_report = invoke()
                self.assertEqual(day0, running[:len(day0)],
                                 "upgrade rerun did not restore Day-0 state")
                self.assertEqual(
                    set(service_lines), set(running) - set(day0),
                    "upgrade rerun did not restore all desired service state",
                )
                self.assertEqual(len(day0) + len(service_lines), len(running),
                                 "upgrade rerun must not duplicate desired service values")
                self.assertIn(f"day0-skipped={0 if wipe_day0 else 1}", second_report)
                self.assertIn("services-skipped=0", second_report)
                if wipe_day0:
                    self.assertEqual(day0_argv, [command for command in rounds[1]
                                                  if command in day0_argv])
                    transaction_commands = set(day0_argv + service_argv) | {
                        ("nv", "config", "apply", "-y"), ("nv", "config", "save")
                    }
                    self.assertEqual(
                        day0_argv + [("nv", "config", "apply", "-y"), ("nv", "config", "save")]
                        + service_argv + [("nv", "config", "apply", "-y"), ("nv", "config", "save")],
                        [command for command in rounds[1] if command in transaction_commands],
                        "upgrade rerun must commit Day-0 before the separate service transaction",
                    )
                else:
                    self.assertFalse(any(command in day0_argv for command in rounds[1]))
                # IPv4 readiness is checked on every --apply, also when Network writes nothing
                # (owner Q-035 (a), guide :438「每次 `--apply` 核 IPv4」; P3c map D32d :284).
                self.assertEqual(2, ipv4_verify.call_count)
                self.assertEqual(
                    [command for command in service_argv if " ".join(command) in missing_services],
                    [command for command in rounds[1] if command in service_argv],
                    "upgrade rerun must write only missing service values",
                )
                self.assertEqual(2 if wipe_day0 else 1,
                                 rounds[1].count(("nv", "config", "apply", "-y")))
                self.assertEqual(2 if wipe_day0 else 1,
                                 rounds[1].count(("nv", "config", "save")))
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))

                third_report = invoke()
                self.assertIn("day0-skipped=1", third_report)
                self.assertIn("services-skipped=1", third_report)
                self.assertFalse(any(command in day0_argv for command in rounds[2]))
                self.assertFalse(any(command in service_argv for command in rounds[2]))
                self.assertNotIn(("nv", "config", "apply"), rounds[2])
                self.assertNotIn(("nv", "config", "apply", "-y"), rounds[2])
                self.assertNotIn(("nv", "config", "save"), rounds[2])
                self.assertEqual(day0, running[:len(day0)])
                self.assertEqual(set(service_lines), set(running[len(day0):]))
                self.assertEqual(len(day0) + len(service_lines), len(running))
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))
                # One IPv4 readiness check per --apply run (owner Q-035 (a), guide :438).
                self.assertEqual(3, ipv4_verify.call_count)

    def test_upgrade_wipe_then_rerun_restores_only_missing_services_and_keeps_keys(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        for missing in (services, (services[0], services[-1])):
            with self.subTest(missing=missing):
                self._exercise_upgrade_rerun(missing)

    def test_upgrade_rerun_oracle_rejects_skipping_missing_services(self) -> None:
        with self.assertRaisesRegex(AssertionError, "upgrade rerun did not restore"):
            self._exercise_upgrade_rerun(
                ("nv set system dns server 203.0.113.53",),
                suppress_service_stage=True,
            )

    def test_upgrade_full_day0_and_services_wipe_restores_two_transactions_then_is_idempotent(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        self._exercise_upgrade_rerun(services, wipe_day0=True)

    def test_upgrade_full_wipe_oracle_rejects_skipping_day0_restoration(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        with self.assertRaisesRegex(AssertionError, "upgrade rerun did not restore Day-0 state"):
            self._exercise_upgrade_rerun(
                services, wipe_day0=True, suppress_day0_detection=True,
            )

    def test_upgrade_full_wipe_single_base_stage_fault_is_reported(self) -> None:
        # 06 WP6-a8 (WP-6 review A wa-2): with only base_stage_needed answering "no Network work"
        # for the wiped device, the v15 skeleton still checks the CSV Network values (verify_state)
        # on every run (P3c map D32d :284), so that device fails and the run is not SUCCESS: a
        # failed device makes the run INCOMPLETE, exit 2 (table 6-1 rows 1 and 11, guide :744,
        # :754).  The second run's own exit check (0 expected) is what reports it.
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        with self.assertRaisesRegex(AssertionError, r"^0 != 2$"):
            self._exercise_upgrade_rerun(services, wipe_day0=True, single_base_stage_fault=True)

    def test_upgrade_complete_wipe_restores_initial_and_reserved_port_facts_then_is_idempotent(self) -> None:
        """A complete wipe also removes the Initial and reserved-port facts.

        Expected values come from the stage requirements recorded in
        test_cases/REAL_ENVIRONMENT.md, not from the implementation: missing
        Initial values (auto-save, ztp config-save) are set to enabled; a fresh
        single-gateway device gets eth0 address, the eth0 gateway, eth0-1 link
        up, eth0-1 type eth and its CSV hostname; the services are restored; a
        rerun writes nothing.  Only end-state facts are asserted, never how many
        transactions the product uses.  The device model holds no row on the
        device's behalf (held_rows=()): every fact lives in the modeled running
        configuration, a wipe leaves only the factory hostname, and only an
        applied setter restores a fact.
        """
        with tempfile.TemporaryDirectory(prefix="req10b-complete-wipe-") as directory:
            root, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.strict_fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            factory = "nv set system hostname nvos"
            initial = [
                "nv set system config auto-save state enabled",
                "nv set system ztp config-save enabled",
            ]
            network = [
                "nv set interface eth0 ipv4 address 203.0.113.2/24",
                "nv set interface eth0 ipv4 gateway 203.0.113.1",
                "nv set interface eth0-1 link state up",
                "nv set interface eth0-1 type eth",
                "nv set system hostname EXAMPLE-IB01",
            ]
            services = [
                "nv set system dns server 203.0.113.53",
                "nv set system ntp server ntp.ubuntu.com",
                "nv set system ntp server time.ib.example.test",
                "nv set system date-time timezone Asia/Taipei",
            ]
            desired = initial + network + services
            setters = {tuple(line.split()) for line in desired}
            apply = ("nv", "config", "apply", "-y")
            save = ("nv", "config", "save")
            running = list(desired)
            pending: list[str] = []
            rounds: list[list[tuple[str, ...]]] = []
            device_home = root / "fake-device-home"
            (device_home / ".ssh").mkdir(parents=True)
            authorized = device_home / ".ssh/authorized_keys"
            authorized.write_text(laptop + management, encoding="ascii")
            original_keys = (authorized.stat().st_ino, authorized.read_bytes())
            links = (
                "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                "8: swp8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            )
            fdb = (
                "02:00:00:00:00:01 dev swp7 master bridge dynamic\n"
                "02:00:00:00:00:02 dev swp8 master bridge dynamic\n"
            )
            vlans = "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n"
            key_command = (
                "sh", "-c", self.initial._KEY_INSTALL_SCRIPT, "--",
                base64.b64encode((laptop + management).encode("ascii")).decode("ascii"),
            )

            def device_boundary(*args, **_kwargs):
                command = tuple(args[7])
                rounds[-1].append(command)
                if command == ("ip", "addr", "show", "eth0"):
                    return self.initial.SessionResult(
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n", 0)
                if command == STRICT_READ:
                    return self.initial.SessionResult("\n".join(running) + "\n", 0)
                if command == ZTP_SHOW:
                    # T17 (guide :2303): this model holds no row, so ZTP is disabled only
                    # once the applied configuration has ZTP config-save enabled.
                    return self.initial.SessionResult(
                        ZTP_DISABLED if "nv set system ztp config-save enabled" in running
                        else ZTP_ENABLED, 0)
                if command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its applied NVUE name.
                    names = [line.split()[-1] for line in running if line.startswith("nv set system hostname ")]
                    return self.initial.SessionResult((names[-1] if names else "nvos") + "\n", 0)
                if command in setters:
                    pending.append(" ".join(command))
                elif command == apply:
                    for line in pending:
                        if line.startswith("nv set system hostname "):
                            running[:] = [kept for kept in running
                                          if not kept.startswith("nv set system hostname ")]
                        if line not in running:
                            running.append(line)
                    pending.clear()
                elif command[:2] == ("sh", "-c"):
                    self.assertEqual(key_command, command, "only the complete PUBLIC key-install request may run")
                    result = subprocess.run(
                        command, cwd=root,
                        env={"HOME": str(device_home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    return self.initial.SessionResult(result.stdout, result.returncode)
                return self.initial.SessionResult("", 0)

            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                # The IPv4 SSH check is a transport outside this PUBLIC model.
                stack.enter_context(mock.patch.object(self.initial, "verify_ipv4_login"))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", (links, fdb, vlans)),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("interface_vrf", "default"),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=device_boundary))

                def invoke() -> str:
                    rounds.append([])
                    with credentials_fd(strict_fd_payload(strict_kat(self.initial))) as fd_argv:
                        self.assertEqual(0, self.run_strict(
                            tool, ib_csv, p2p, cache, "--apply", "--yes",
                            *fd_argv,
                            global_path=global_path, devices=("EXAMPLE-IB01",), held_rows=(),
                        ))
                    return (cache.parent / "report.log").read_text(encoding="utf-8")

                first_report = invoke()
                self.assertIn("day0-skipped=1", first_report)
                self.assertIn("services-skipped=1", first_report)
                self.assertFalse(any(command in setters for command in rounds[0]))
                self.assertNotIn(apply, rounds[0])
                self.assertNotIn(save, rounds[0])

                running[:] = [factory]
                second_report = invoke()
                self.assertEqual(sorted(desired), sorted(running),
                                 "a complete wipe must be restored to the full desired state")
                self.assertIn("day0-skipped=0", second_report)
                self.assertIn("services-skipped=0", second_report)
                self.assertEqual([], pending, "every restored fact must be applied")

                third_report = invoke()
                self.assertIn("day0-skipped=1", third_report)
                self.assertIn("services-skipped=1", third_report)
                self.assertFalse(any(command in setters for command in rounds[2]),
                                 "a rerun after restoration must write nothing")
                self.assertNotIn(apply, rounds[2])
                self.assertNotIn(save, rounds[2])
                self.assertEqual(sorted(desired), sorted(running))
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))

    def test_day0_verification_failure_never_enters_services(self) -> None:
        _, commands, report, _, _ = self.drive_one_device(
            "nv set system hostname nvos\n", "nv set system hostname nvos\n",
        )
        self.assertIn("post-configuration verification failed", report)
        self.assertFalse(any(command[:4] == ("nv", "set", "system", "dns")
                             for command in commands))
        self.assertFalse(any(command[:4] == ("nv", "set", "system", "ntp")
                             for command in commands))

    def test_fresh_day0_success_flows_into_service_transaction(self) -> None:
        day0 = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, _, _ = self.drive_one_device(
            "nv set system hostname nvos\n", day0, post_service_state=day0 + services,
        )
        self.assertEqual(0, result, report)
        self.assertIn(("nv", "set", "interface", "eth0", "ipv4", "address",
                       "203.0.113.2/24"), commands)
        self.assertIn(("nv", "set", "system", "dns", "server", "203.0.113.53"), commands)
        self.assertIn("Services SUCCESS: desired values verified", report)

    def test_missing_global_permits_day0_and_reports_service_skip(self) -> None:
        verified = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        result, commands, report, _, _ = self.drive_one_device(
            "nv set system hostname nvos\n", verified, remove_global_before_p1=True,
        )
        self.assertEqual(0, result, report)
        self.assertIn("Services SKIP: 01-global.yaml was unavailable", report)
        self.assertIn("services-skipped=1", report)
        self.assertFalse(any(command[:4] == ("nv", "set", "system", "dns")
                             for command in commands))

    def test_unknown_empty_preflight_refuses_day0_services_and_key_writes(self) -> None:
        verified = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        result, commands, report, _, _ = self.drive_one_device("", verified)
        # Table 6-1 row 11 (guide :754): a device that fails is INCOMPLETE, exit 2; FAILED (1)
        # is only a script or common-flow failure (v15 CURRENT-CONTRACT.md「只有脚本/公共流程
        # 异常才称 FAILED，正常完成但仍有前提阻塞用 INCOMPLETE」).
        self.assertEqual(2, result)
        self.assertIn("UNKNOWN", report)
        self.assertFalse(any(command[:2] == ("nv", "set") for command in commands))
        self.assertFalse(any(command[:3] == ("nv", "config", "apply") for command in commands))
        self.assertNotIn(("nv", "config", "save"), commands)
        self.assertFalse(any(command[:2] == ("sh", "-c") for command in commands))

    def test_ethernet_p2_uses_baked_services_without_global_or_yaml_library(self) -> None:
        configured = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, _, _ = self.drive_one_device(
            configured, configured + services,
            "--execution-mode", "ethernet", remove_global_before_p2=True,
        )
        # Owner 04 Q-040 (a) (deadline 2026-11-11 02:19:33 passed without an answer, default taken;
        # 06 WP6-01): a Leaf-local run has no management-server direct SSH check
        # (DIRECT_SSH_NOT_TESTED), so v15 ends the run INCOMPLETE, exit 2 (guide :753 table 6-1 row
        # 10 "a real change goes into row 11", row 11 guide :754); the other assertions are unchanged.
        self.assertEqual(2, result, report)
        self.assertIn(("nv", "set", "system", "dns", "server", "203.0.113.53"), commands)
        self.assertIn("Services SUCCESS: desired values verified", report)
        self.assertIn("Local Ethernet execution: example-jump01", report)

    def test_non_strict_stages_answer_ib_with_the_selected_credential(self) -> None:
        # 06 WP6-a6 (06 D1a-I; v3.1.3 guide 1.3 row 8: the DEV flow that logged in to IB with the
        # Ethernet password is not carried over): in a non-strict main run, here the Leaf-local P2
        # without a project global (table 6-1 row 10, guide :753), the Services, public-key and
        # IPv4 logins answer the IB password prompt with the IB credential the authentication
        # selected, never with the Ethernet password; the two passwords differ.  Only the SSH/PTY
        # transport (interactive_run) is a model: it puts the IB prompt to the product's own
        # responder, records the answer under the task phase it came in, accepts it so that every
        # stage is reached, and serves the device of the Leaf P2 test above.
        initial = self.initial
        ethernet, selected = "PUBLIC-ETHERNET-ONLY", "PUBLIC-IB-SELECTED"
        configured = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        with tempfile.TemporaryDirectory(prefix="req10b-selected-ib-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            global_path.unlink()
            phase = ["before any task"]
            answers: list[tuple[tuple[str, ...], str, str]] = []
            commands: list[tuple[str, ...]] = []
            unexpected: list[list[str]] = []
            shows = 0
            real_phase = initial.task_phase
            real_clock = initial.time
            links = (
                "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                "8: swp8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            )
            fdb = (
                "02:00:00:00:00:01 dev swp7 master bridge dynamic\n"
                "02:00:00:00:00:02 dev swp8 master bridge dynamic\n"
            )
            vlans = "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n"
            address = (
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 203.0.113.2/24 scope global eth0\n"
            )
            key_command = (
                "sh", "-c", initial._KEY_INSTALL_SCRIPT, "--",
                base64.b64encode((laptop + management).encode("ascii")).decode("ascii"),
            )
            # Independent WP4 prechange program, SHA256
            # 7c1a6e279773a41477e0e7a061d8ecf828273157b785aca844361a14ff3344b6.
            # This is compared as text and never executed or read from Desktop at runtime.
            backup_script = (
                "set -eu\n"
                "umask 077\n"
                "fail() { printf '%s\\n' 'IB configuration backup failed' >&2; exit 1; }\n"
                "[ \"$#\" -eq 1 ] || fail\n"
                "stamp=$1\n"
                "case \"$stamp\" in\n"
                "    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n"
                "    *) fail ;;\n"
                "esac\n"
                "case \"${HOME-}\" in /*) ;; *) fail ;; esac\n"
                "backup=\"$HOME/current_${stamp}.yaml\"\n"
                "[ ! -e \"$backup\" ] && [ ! -L \"$backup\" ] || fail\n"
                "tmp=\n"
                "trap 'if [ -n \"$tmp\" ]; then rm -f -- \"$tmp\"; fi' EXIT\n"
                "trap 'exit 1' HUP INT TERM\n"
                "tmp=$(mktemp \"${backup}.tmp.XXXXXX\" 2>/dev/null) || fail\n"
                "chmod 600 \"$tmp\" || fail\n"
                "nv config show > \"$tmp\" 2>/dev/null || fail\n"
                "[ -s \"$tmp\" ] || fail\n"
                "bytes=$(wc -c < \"$tmp\" | tr -d '[:space:]') || fail\n"
                "case \"$bytes\" in ''|*[!0-9]*) fail ;; esac\n"
                "[ \"$bytes\" -gt 0 ] || fail\n"
                "ln -T -- \"$tmp\" \"$backup\" 2>/dev/null || fail\n"
                "rm -f -- \"$tmp\" || fail\n"
                "tmp=\n"
                "printf 'path=%s\\nbytes=%s\\n' \"$backup\" \"$bytes\"\n"
            )

            class LocalClock:
                def sleep(self, delay):
                    return None

                def __getattr__(self, name):
                    return getattr(real_clock, name)

            def task_phase(name):
                phase[0] = name
                return real_phase(name)

            def device_output(command):
                nonlocal shows
                if command == STRICT_READ:
                    shows += 1
                    return with_held_rows(configured if shows == 1 else configured + services,
                                          STRICT_HELD_ROWS)
                if command == ZTP_SHOW:
                    return ZTP_DISABLED
                if command == ("ip", "addr", "show", "eth0"):
                    return address
                if command == ("ip", "route"):
                    return "default via 203.0.113.1 dev eth0\n"
                if command == key_command:
                    return "IBSW_PUBLIC_KEYS_UPDATED\n"
                if (len(command) == 5 and command[:4] == ("sh", "-c", backup_script, "--")
                        and re.fullmatch(r"[0-9]{8}-[0-9]{6}", command[4])):
                    return "path=/home/PUBLIC-EXAMPLE-IB01/current_" + command[4] + ".yaml\nbytes=137\n"
                if command in {
                    STRICT_DIFF,
                    ("nv", "set", "system", "dns", "server", "203.0.113.53"),
                    ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
                    ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
                    ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"),
                    ("nv", "config", "apply", "-y"), ("nv", "config", "save"),
                }:
                    return ""
                if command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its NVUE name.
                    return "EXAMPLE-IB01\n"
                raise AssertionError("PUBLIC non-strict model: unknown IB command")

            def transport(command, responder, timeout, **_kwargs):
                # Leaf-local: sh -c 'export PATH=...; exec <ssh to the IB> <sh -c framed command>'.
                try:
                    self.assertIs(type(command), list)
                    self.assertEqual(3, len(command))
                    self.assertTrue(all(type(word) is str for word in command))
                    self.assertEqual(["sh", "-c"], command[:2])
                    self.assertEqual({}, _kwargs)
                    safe_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
                    self.assertTrue(command[2].startswith(safe_path))
                    nested = shlex.split(command[2][len(safe_path):])
                    self.assertEqual(safe_path + shlex.join(nested), command[2])
                    password_options = ["-o", "PubkeyAuthentication=no", "-o",
                                        "PreferredAuthentications=password,keyboard-interactive"]
                    common = ["ip", "vrf", "exec", "default", "ssh"]
                    options = ["-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
                               "-o", "LogLevel=ERROR", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                               "-o", "NumberOfPasswordPrompts=1"]
                    destination = nested[-2]
                    if destination == "admin@fe80::ff:fe00:1":
                        header = [*common, "-6", "-tt", *options]
                        tail = ["-B", "swp7", destination]
                        self.assertIn(nested[:-1], (header + tail, header + password_options + tail))
                        self.assertEqual(60, timeout)
                    else:
                        self.assertEqual("admin@203.0.113.2", destination)
                        self.assertEqual([*common, "-tt", *options, *password_options, destination], nested[:-1])
                        self.assertEqual(45, timeout)
                    remote = shlex.split(nested[-1])
                    self.assertEqual(3, len(remote))
                    self.assertEqual(["sh", "-c"], remote[:2])
                    self.assertEqual(shlex.join(remote), nested[-1])
                    marker_match = re.match(r'^printf "\\n__HTTP_IB_BEGIN_([0-9a-f]{32})__\\n"; ', remote[2])
                    self.assertIsNotNone(marker_match)
                    marker = marker_match.group(1)
                    prefix = 'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
                    suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                              + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                    self.assertTrue(remote[2].startswith(prefix) and remote[2].endswith(suffix))
                    text = remote[2][len(prefix):-len(suffix)]
                    ib_command = tuple(shlex.split(text))
                    self.assertEqual(shlex.join(ib_command), text)
                    self.assertIs(type(responder), initial.NestedResponder)
                    self.assertIsNone(responder._phase)
                    self.assertEqual(destination, responder.ib_destination)
                    self.assertEqual(ethernet, responder.ethernet_password)
                    self.assertEqual(selected, responder.ib_default_password)
                    self.assertIs(False, responder.allow_password_change)
                    self.assertIsNone(responder.ib_new_password)
                    body = device_output(ib_command)
                    prompt = f"{destination}'s password: "
                    answers.append((ib_command, phase[0], responder(prompt)))
                    commands.append(ib_command)
                    return initial.SessionResult(
                        f"{prompt}\n__HTTP_IB_BEGIN_{marker}__\n{body}"
                        f"__HTTP_IB_END_{marker}__=0\n", 0)
                except BaseException:
                    unexpected.append(list(command))
                    raise

            payload = {"nvos_initial_password": selected, "ib_target_password": PUBLIC_FD_TARGET}
            with ExitStack() as stack:
                fd_argv = stack.enter_context(credentials_fd(payload))
                for name, value in (
                    ("local_ethernet_keys", {"example-jump01"}),
                    ("prompt_ethernet_passwords", {"example-jump01": ethernet}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", (links, fdb, vlans)),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("interface_vrf", "default"),
                ):
                    stack.enter_context(mock.patch.object(initial, name, return_value=value))
                stack.enter_context(mock.patch.object(initial, "interactive_run", new=transport))
                stack.enter_context(mock.patch.object(initial, "task_phase", new=task_phase))
                stack.enter_context(mock.patch.object(initial, "time", new=LocalClock()))
                try:
                    self.run_initial(tool, ib_csv, p2p, cache, "--apply", "--yes", *fd_argv,
                                     "--execution-mode", "ethernet")
                finally:
                    report_handle = initial.REPORT_HANDLE
                    if report_handle is not None:
                        report_handle.close()
                        initial.REPORT_HANDLE = None
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
        self.assertEqual([], unexpected, "every session of this run is a Leaf-local IB login")
        self.assertIn("Local Ethernet execution: example-jump01", report)
        self.assertIn("Services SUCCESS: desired values verified", report)
        self.assertIn(("nv", "set", "system", "dns", "server", "203.0.113.53"), commands)
        self.assertTrue(any(command[:3] == ("sh", "-c", initial._KEY_INSTALL_SCRIPT) for command in commands))
        # Authentication read, O5 and the first ZTP read use the same selected IB
        # credential, in that order, before Initial/Network proceeds (WP-6).
        self.assertEqual(
            [(STRICT_READ, selected), (("ip", "addr", "show", "eth0"), selected), (ZTP_SHOW, selected)],
            [(command, answer) for command, name, answer in answers if name == "IB authentication/readback"],
        )
        for stage, prefix in (("services", "Infra Services"), ("keys", "IB public keys"),
                              ("ipv4", "IPv4 readiness")):
            with self.subTest(stage=stage):
                logins = [answer for command, name, answer in answers if name.startswith(prefix)]
                self.assertTrue(logins, f"the {stage} stage logs in to IB")
                self.assertEqual([selected] * len(logins), logins,
                                 f"the {stage} stage answers IB with the selected IB credential, "
                                 "not the Ethernet password")

    def test_ethernet_mode_names_stale_v3_cache_and_preserves_both_inodes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-leaf-v3-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            payload["version"] = 3
            raw = (json.dumps(payload, sort_keys=True) + "\n").encode()
            cache.write_bytes(raw)
            sidecar = cache.with_name(cache.name + ".sha256")
            sidecar.write_text(f"{hashlib.sha256(raw).hexdigest()}  {cache.name}\n", encoding="ascii")
            before = (cache.stat().st_ino, cache.read_bytes(), sidecar.stat().st_ino, sidecar.read_bytes())
            with self.assertRaisesRegex(self.initial.SetupError, "(?i)version|版本"):
                self.run_initial(tool, ib_csv, p2p, cache, "--plan", "--execution-mode", "ethernet")
            after = (cache.stat().st_ino, cache.read_bytes(), sidecar.stat().st_ino, sidecar.read_bytes())
            self.assertEqual(before, after, "stale cache evidence must not be silently rewritten")

    def test_force_fills_missing_day0_fields_without_rewriting_matching_fields(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        first = "nv set interface eth0 ipv4 address 203.0.113.2/24\n" + services
        verified = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n" + services
        )
        result, commands, report, _, _ = self.drive_one_device(first, verified, "--force")
        self.assertEqual(0, result, report)
        self.assertIn(("nv", "set", "system", "hostname", "EXAMPLE-IB01"), commands)
        self.assertIn(("nv", "config", "apply", "-y"), commands)
        self.assertIn(("nv", "config", "save"), commands)


    def test_force_fills_target_address_without_removing_existing_address(self) -> None:
        # D67-O1: a nonempty address set without the CSV target is a conflict.
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        first = (
            "nv set interface eth0 ipv4 address 198.51.100.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n" + services
        )
        verified = (
            "nv set interface eth0 ipv4 address 198.51.100.2/24\n"
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n" + services
        )
        summaries = []
        real_run_initial = self.run_initial

        def capture_summary(tool, ib_csv, p2p, cache, *extra, **kwargs):
            result = real_run_initial(tool, ib_csv, p2p, cache, *extra, **kwargs)
            if "--generate-json" not in extra:
                paths = list(cache.parent.rglob("summary.json"))
                self.assertEqual(1, len(paths), "one actual per-run structured summary")
                summaries.append(json.loads(paths[0].read_text(encoding="utf-8")))
            return result

        with mock.patch.object(self, "run_initial", side_effect=capture_summary):
            result, commands, report, _, _ = self.drive_one_device(first, verified, "--force")
        self.assertEqual(2, result, report)
        self.assertNotIn(("nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"), commands)
        self.assertEqual(0, commands.count(("nv", "config", "save")))
        self.assertFalse(any(command[:2] in {("nv", "set"), ("sh", "-c")}
                             or command in {("nv", "config", "apply", "-y"), ("nv", "config", "save")}
                             for command in commands), "conflict permits no setter, apply/save or backup shell")
        self.assertEqual(1, len(summaries))
        record = summaries[0]["records"]["example-ib01"]
        self.assertEqual(("FAILED", "BLOCKED_NETWORK_CONFLICT", False),
                         (record["outcome"], record["category"], record["writes_attempted"]))
        self.assertEqual([{"field": "eth0 address", "expected": "203.0.113.2/24",
                           "actual": ["198.51.100.2/24"]}], record["conflicts"])
        self.assertTrue(any(line.lstrip().startswith("CONFLICT") and "eth0 address" in line
                            and "203.0.113.2/24" in line and "198.51.100.2/24" in line
                            for line in report.splitlines()), "explicit conflict facts stay in the CONFLICT line")
        self.assertFalse(any(command[:2] in {("nv", "unset"), ("nv", "reset")}
                             or command[:3] in {("nv", "config", "replace"), ("nv", "config", "reset")}
                             for command in commands))
        self.assertNotRegex(report.lower(), "day-0 skip:.*conflict")

    def test_force_membership_with_extra_and_unrequested_fields_skips_day0(self) -> None:
        state = (
            "nv set interface eth0 ipv4 address 198.51.100.2/24\n"
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth1 ipv4 address 198.51.100.22/24\n"
            "nv set interface eth0 ipv4 gateway 198.51.100.1\n"
            "nv set interface eth0 ipv4 gateway 203.0.113.1\n"
            "nv set interface eth1 ipv4 gateway 198.51.100.21\n"
            "nv set system hostname EXAMPLE-IB01\n"
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, _, _ = self.drive_one_device(state, state, "--force")
        self.assertEqual(0, result, report)
        self.assertFalse(any(command[:3] == ("nv", "set", "interface") for command in commands))
        self.assertNotIn(("nv", "set", "system", "hostname", "EXAMPLE-IB01"), commands)
        self.assertFalse(any(command[:3] == ("nv", "config", "apply") for command in commands))
        self.assertNotIn(("nv", "config", "save"), commands)
        self.assertNotRegex(report.lower(), "mismatch|conflict|differs")

    def test_force_refuses_real_gateway_or_hostname_conflict_without_day0_writes(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        cases = (
            ("gateway", "198.51.100.1", "EXAMPLE-IB01", "eth0 gateway"),
            ("hostname", "203.0.113.1", "OTHER-IB01", "hostname"),
        )
        for name, gateway, hostname, field in cases:
            with self.subTest(case=name):
                state = (
                    "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                    f"nv set interface eth0-1 ipv4 gateway {gateway}\n"
                    f"nv set system hostname {hostname}\n" + services
                )
                _, commands, report, _, _ = self.drive_one_device(state, state, "--force")
                self.assertFalse(any(command[:3] == ("nv", "set", "interface") for command in commands))
                self.assertFalse(any(command[:4] == ("nv", "set", "system", "hostname") for command in commands))
                self.assertNotIn(("nv", "config", "apply"), commands)
                self.assertNotIn(("nv", "config", "apply", "-y"), commands)
                self.assertNotIn(("nv", "config", "save"), commands)
                self.assertRegex(report.lower(), "mismatch|conflict|differs")
                self.assertIn(field, report.lower())


    def test_p2_installs_baked_keys_through_nested_device_boundary(self) -> None:
        state = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, laptop, management = self.drive_one_device(state, state)
        self.assertEqual(0, result, report)
        self.assertTrue(any("authorized_keys" in " ".join(command) for command in commands),
                        "the keys must be installed over the existing nested SSH boundary")
        self.assertIn(fingerprint(laptop), report)
        self.assertIn(fingerprint(management), report)

    def test_key_stage_verifies_only_matching_local_management_private_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-possession-") as directory:
            private = Path(directory) / "id_ed25519"
            private.write_text("test-only private-key placeholder\n", encoding="ascii")
            laptop = public_key(17, "laptop").strip()
            management = public_key(18, "management").strip()
            keys = [
                {"name": "laptop.pub", "line": laptop, "fingerprint": fingerprint(laptop)},
                {"name": "mgmt-server.pub", "line": management,
                 "fingerprint": fingerprint(management)},
            ]
            ib = self.initial.Device("EXAMPLE-IB01", "ib", "203.0.113.2",
                                     "203.0.113.2/24", "203.0.113.1", "", "", "")
            transit = self.initial.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10",
                                          "192.0.2.10", "", "", "", "")
            target = self.initial.Target(ib, transit, "swp7", "eth0")
            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            calls: list[list[str]] = []

            def key_boundary(argv, **_kwargs):
                calls.append(argv)
                if argv[0] == "ssh-keygen":
                    return subprocess.CompletedProcess(argv, 0, management + "\n", "")
                if argv[0] == "ssh":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                self.fail(f"unexpected local command {argv}")

            with mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)) as installer, \
                 mock.patch.object(subprocess, "run", side_effect=key_boundary), \
                 redirect_stdout(io.StringIO()) as output:
                self.assertTrue(self.initial.run_key_stage(
                    target, neighbor, "cumulus", "ethernet-password", "admin", 10,
                    keys, local=False, apply=True, authorized=True,
                    management_private_key=private, ib_password="ethernet-password",
                ))
            installer.assert_called_once()
            self.assertEqual(["ssh-keygen", "ssh"], [call[0] for call in calls])
            ssh = calls[1]
            self.assertIn("BatchMode=yes", ssh)
            self.assertIn("PreferredAuthentications=publickey", ssh)
            self.assertIn("PasswordAuthentication=no", ssh)
            self.assertIn("IdentitiesOnly=yes", ssh)
            self.assertEqual("true", ssh[-1])
            self.assertIn("laptop.pub", output.getvalue())
            self.assertIn("已写入，未验证", output.getvalue())
            self.assertIn("mgmt-server.pub", output.getvalue())
            self.assertIn("已验证", output.getvalue())

            with mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)), \
                 mock.patch.object(subprocess, "run") as local_command, \
                 redirect_stdout(io.StringIO()) as no_private_output:
                self.initial.run_key_stage(
                    target, neighbor, "cumulus", "ethernet-password", "admin", 10,
                    keys, local=False, apply=True, authorized=True,
                    management_private_key=None, ib_password="ethernet-password",
                )
            local_command.assert_not_called()
            self.assertEqual(2, no_private_output.getvalue().count("已写入，未验证"))

            with mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)), \
                 mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(
                     ["ssh-keygen"], 0, laptop + "\n", ""
                 )) as wrong_key:
                with self.assertRaises(self.initial.SetupError):
                    self.initial.run_key_stage(
                        target, neighbor, "cumulus", "ethernet-password", "admin", 10,
                        keys, local=False, apply=True, authorized=True,
                        management_private_key=private, ib_password="ethernet-password",
                    )
            self.assertEqual(1, wrong_key.call_count,
                             "mismatched local private identity must fail before SSH")

    def test_key_failure_on_first_device_does_not_block_second_device(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-key-continue-") as directory:
            root, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.strict_fixture(directory)
            with ib_csv.open("a", encoding="utf-8") as stream:
                stream.write("EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,02:00:00:00:00:02,,,\n")
            with p2p.open("a", encoding="utf-8") as stream:
                stream.write('"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n')
            master_csv = (
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,\n"
                "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,\n"
                "EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,02:00:00:00:00:02,,,\n"
            )
            (root / "infiniband/02-devices_config.csv").write_text(master_csv, encoding="utf-8")
            (root / "02-devices_config.csv").write_text(master_csv, encoding="utf-8")
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            attempted: list[str] = []
            state = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )

            def boundary(target, *_args, **_kwargs):
                command = tuple(_args[6])
                addresses = {
                    "EXAMPLE-IB01": (
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n"),
                    "EXAMPLE-IB02": (
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:02 brd ff:ff:ff:ff:ff:ff\n"),
                }
                if target.ib.hostname not in addresses:
                    raise AssertionError("PUBLIC key-failure model: unknown IB endpoint")
                if command == ("ip", "addr", "show", "eth0"):
                    return self.initial.SessionResult(addresses[target.ib.hostname], 0)
                key_payload = base64.b64encode((laptop + management).encode("ascii")).decode("ascii")
                if command == ("sh", "-c", self.initial._KEY_INSTALL_SCRIPT, "--", key_payload):
                    attempted.append(target.ib.hostname)
                    if target.ib.hostname == "EXAMPLE-IB01":
                        raise self.initial.SetupError("injected key installation failure")
                    return self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)
                if command == STRICT_DIFF:
                    return self.initial.SessionResult("", 0)
                if command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its CSV name.
                    return self.initial.SessionResult(target.ib.hostname + "\n", 0)
                if command != STRICT_READ:
                    raise AssertionError("PUBLIC key-failure model: unknown IB command")
                output = state.replace("203.0.113.2/24", target.ib.eth0_prefix).replace(
                    "EXAMPLE-IB01", target.ib.hostname
                )
                return self.initial.SessionResult(output, 0)

            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", (
                        "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "8: swp8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
                        "02:00:00:00:00:01 dev swp7 master bridge dynamic\n"
                        "02:00:00:00:00:02 dev swp8 master bridge dynamic\n",
                        "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("interface_vrf", "default"),
                    # v15 checks IPv4 on every --apply (owner Q-035 (a)); that SSH check is a
                    # transport outside this PUBLIC model.
                    ("verify_ipv4_login", None),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=boundary))
                fd_argv = stack.enter_context(credentials_fd(strict_fd_payload(strict_kat(self.initial))))
                try:
                    self.run_strict(tool, ib_csv, p2p, cache, "--apply", "--yes",
                                    *fd_argv,
                                    global_path=global_path,
                                    devices=("EXAMPLE-IB01", "EXAMPLE-IB02"))
                finally:
                    report = self.initial.REPORT_HANDLE
                    if report is not None:
                        report.close()
                        self.initial.REPORT_HANDLE = None
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], attempted)

    def test_service_failure_on_first_device_continues_to_second_device(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-service-continue-") as directory:
            root, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.strict_fixture(directory)
            with ib_csv.open("a", encoding="utf-8") as stream:
                stream.write("EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,02:00:00:00:00:02,,,\n")
            with p2p.open("a", encoding="utf-8") as stream:
                stream.write('"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n')
            master_csv = (
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,\n"
                "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,\n"
                "EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,02:00:00:00:00:02,,,\n"
            )
            (root / "infiniband/02-devices_config.csv").write_text(master_csv, encoding="utf-8")
            (root / "02-devices_config.csv").write_text(master_csv, encoding="utf-8")
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            attempted: list[str] = []
            applied: set[str] = set()
            day0 = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
            )
            services = (
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )

            def boundary(target, *_args, **_kwargs):
                command = tuple(_args[6])
                name = target.ib.hostname
                addresses = {
                    "EXAMPLE-IB01": (
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n"),
                    "EXAMPLE-IB02": (
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:02 brd ff:ff:ff:ff:ff:ff\n"),
                }
                if name not in addresses:
                    raise AssertionError("PUBLIC service-failure model: unknown IB endpoint")
                if command == ("ip", "addr", "show", "eth0"):
                    return self.initial.SessionResult(addresses[name], 0)
                key_payload = base64.b64encode((laptop + management).encode("ascii")).decode("ascii")
                if command == ("sh", "-c", self.initial._KEY_INSTALL_SCRIPT, "--", key_payload):
                    return self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)
                if command == STRICT_DIFF:
                    return self.initial.SessionResult("", 0)
                if command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its CSV name.
                    return self.initial.SessionResult(name + "\n", 0)
                if command not in {
                    STRICT_READ,
                    ("nv", "set", "system", "dns", "server", "203.0.113.53"),
                    ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
                    ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
                    ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"),
                    ("nv", "config", "apply", "-y"), ("nv", "config", "save"),
                }:
                    raise AssertionError("PUBLIC service-failure model: unknown IB command")
                if command == ("nv", "set", "system", "dns", "server", "203.0.113.53"):
                    attempted.append(name)
                    if name == "EXAMPLE-IB01":
                        raise self.initial.SetupError("injected service failure")
                if command == ("nv", "config", "apply", "-y"):
                    applied.add(name)
                output = day0.replace("203.0.113.2/24", target.ib.eth0_prefix).replace(
                    "EXAMPLE-IB01", name
                )
                if name in applied:
                    output += services
                return self.initial.SessionResult(output, 0)

            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", (
                        "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "8: swp8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
                        "02:00:00:00:00:01 dev swp7 master bridge dynamic\n"
                        "02:00:00:00:00:02 dev swp8 master bridge dynamic\n",
                        "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("interface_vrf", "default"),
                    # v15 checks IPv4 on every --apply (owner Q-035 (a)); that SSH check is a
                    # transport outside this PUBLIC model.
                    ("verify_ipv4_login", None),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=boundary))
                fd_argv = stack.enter_context(credentials_fd(strict_fd_payload(strict_kat(self.initial))))
                result = self.run_strict(tool, ib_csv, p2p, cache, "--apply", "--yes",
                                         *fd_argv,
                                         global_path=global_path,
                                         devices=("EXAMPLE-IB01", "EXAMPLE-IB02"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            # Table 6-1 rows 1 and 11 (guide :744, :754): the other device continues and the
            # run is INCOMPLETE, exit 2 (v15 RUNBOOK.md「失败设备继续、最终 incomplete 非零」).
            self.assertEqual(2, result, report)
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], attempted)
            self.assertIn("injected service failure", report)
            self.assertIn("[EXAMPLE-IB02]", report)
            self.assertIn("Services SUCCESS: desired values verified", report)

    def test_service_failure_report_never_carries_raw_device_output(self) -> None:
        """A device's own failure text stays out of the report (A1 guard).

        The first device's DNS setter goes through the real run_on_ib with only
        the PTY transport modeled: the device answers exit 1 with a PUBLIC
        marker line.  The report may name the failure with product-written
        text, but the device's raw output (the marker) must never appear, and
        the second device still completes.
        """
        import hmac

        # Frozen PUBLIC program from the independent WP4 preimplementation
        # 7c1a6e27 document, not the current product constant or a desktop read.
        backup_script = (
            "set -eu\n"
            "umask 077\n"
            "fail() { printf '%s\\n' 'IB configuration backup failed' >&2; exit 1; }\n"
            "[ \"$#\" -eq 1 ] || fail\n"
            "stamp=$1\n"
            "case \"$stamp\" in\n"
            "    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n"
            "    *) fail ;;\n"
            "esac\n"
            "case \"${HOME-}\" in /*) ;; *) fail ;; esac\n"
            "backup=\"$HOME/current_${stamp}.yaml\"\n"
            "[ ! -e \"$backup\" ] && [ ! -L \"$backup\" ] || fail\n"
            "tmp=\n"
            "trap 'if [ -n \"$tmp\" ]; then rm -f -- \"$tmp\"; fi' EXIT\n"
            "trap 'exit 1' HUP INT TERM\n"
            "tmp=$(mktemp \"${backup}.tmp.XXXXXX\" 2>/dev/null) || fail\n"
            "chmod 600 \"$tmp\" || fail\n"
            "nv config show > \"$tmp\" 2>/dev/null || fail\n"
            "[ -s \"$tmp\" ] || fail\n"
            "bytes=$(wc -c < \"$tmp\" | tr -d '[:space:]') || fail\n"
            "case \"$bytes\" in ''|*[!0-9]*) fail ;; esac\n"
            "[ \"$bytes\" -gt 0 ] || fail\n"
            "ln -T -- \"$tmp\" \"$backup\" 2>/dev/null || fail\n"
            "rm -f -- \"$tmp\" || fail\n"
            "tmp=\n"
            "printf 'path=%s\\nbytes=%s\\n' \"$backup\" \"$bytes\"\n"
        )
        self.assertEqual(846, len(backup_script.encode("utf-8")))
        self.assertEqual("7c1a6e279773a41477e0e7a061d8ecf828273157b785aca844361a14ff3344b6",
                         hashlib.sha256(backup_script.encode("utf-8")).hexdigest())
        with tempfile.TemporaryDirectory(prefix="req10b-raw-output-guard-") as directory:
            root, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.strict_fixture(directory)
            with ib_csv.open("a", encoding="utf-8") as stream:
                stream.write("EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,02:00:00:00:00:02,,,\n")
            with p2p.open("a", encoding="utf-8") as stream:
                stream.write('"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n')
            master_csv = (
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,\n"
                "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,\n"
                "EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,02:00:00:00:00:02,,,\n"
            )
            (root / "infiniband/02-devices_config.csv").write_text(master_csv, encoding="utf-8")
            (root / "02-devices_config.csv").write_text(master_csv, encoding="utf-8")
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            marker = "PUBLIC-RAW-DEVICE-OUTPUT-" + os.urandom(6).hex()
            real_run_on_ib = self.initial.run_on_ib
            attempted: list[str] = []
            raw_failures: list[str] = []
            applied: set[str] = set()
            day0 = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
            )
            services = (
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )

            key_payload = base64.b64encode((laptop + management).encode("ascii")).decode("ascii")
            backup_frames = []

            def boundary(target, *args, **kwargs):
                command = tuple(args[6])
                name = target.ib.hostname
                addresses = {
                    "EXAMPLE-IB01": "2: eth0: <UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n",
                    "EXAMPLE-IB02": "2: eth0: <UP> mtu 1500 state UP\n"
                        "    link/ether 02:00:00:00:00:02 brd ff:ff:ff:ff:ff:ff\n",
                }
                if name not in addresses:
                    raise AssertionError("PUBLIC raw model: unknown IB endpoint")
                if command == ("ip", "addr", "show", "eth0"):
                    return self.initial.SessionResult(addresses[name], 0)
                if command == ("sh", "-c", self.initial._KEY_INSTALL_SCRIPT, "--", key_payload):
                    return self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)
                if (name == "EXAMPLE-IB01" and len(command) == 5
                        and command[:4] == ("sh", "-c", backup_script, "--")
                        and re.fullmatch(r"[0-9]{8}-[0-9]{6}", command[4])):
                    # Real recursive category/permit/receipt parser, not a
                    # fabricated state or a locally executed backup program.
                    return real_run_on_ib(target, *args, **kwargs)
                dns = ("nv", "set", "system", "dns", "server", "203.0.113.53")
                if command == dns:
                    attempted.append(name)
                    if name == "EXAMPLE-IB01":
                        # Preserve the original failed DNS answer/marker.
                        answer = self.initial.SessionResult("nv: error: " + marker + "\n", 1)

                        def remote(argv, responder, timeout, **options):
                            self.assertIs(type(argv), list)
                            self.assertTrue(all(type(word) is str for word in argv))
                            self.assertEqual({}, options)
                            self.assertEqual(60, timeout)
                            self.assertEqual(["ssh", "-tt", "-o", "ConnectTimeout=10",
                                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
                                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                                "-o", "ControlMaster=no", "-o", "ControlPath=none",
                                "cumulus@192.0.2.10"], argv[:-1])
                            carrier = shlex.split(argv[-1])
                            self.assertEqual(3, len(carrier))
                            self.assertEqual(["sh", "-c"], carrier[:2])
                            self.assertEqual(shlex.join(carrier), argv[-1])
                            safe = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
                            self.assertTrue(carrier[2].startswith(safe))
                            inner_text = carrier[2][len(safe):]
                            inner = shlex.split(inner_text)
                            self.assertEqual(shlex.join(inner), inner_text)
                            framed = shlex.split(inner[-1])
                            self.assertEqual(3, len(framed))
                            self.assertEqual(["sh", "-c"], framed[:2])
                            self.assertEqual(shlex.join(framed), inner[-1])
                            markers = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", framed[2])
                            self.assertEqual(1, len(markers))
                            nonce = markers[0]
                            self.assertEqual([nonce], re.findall(r"__HTTP_IB_END_([0-9a-f]{32})__", framed[2]))
                            prefix = 'printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; '
                            suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
                                      + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                            self.assertTrue(framed[2].startswith(prefix) and framed[2].endswith(suffix))
                            text = framed[2][len(prefix):-len(suffix)]
                            vector = shlex.split(text)
                            backup = (len(vector) == 5 and vector[:4] == ["sh", "-c", backup_script, "--"]
                                      and re.fullmatch(r"[0-9]{8}-[0-9]{6}", vector[4]) is not None)
                            self.assertTrue(backup or vector == list(dns), "PUBLIC raw transport: unknown command")
                            self.assertEqual(shlex.join(vector), text)
                            header = ["ip", "vrf", "exec", "default", "ssh", "-6", "-tt",
                                "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
                                "-o", "LogLevel=ERROR", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                                "-o", "NumberOfPasswordPrompts=1"]
                            if backup:
                                header += ["-o", "PubkeyAuthentication=no", "-o",
                                           "PreferredAuthentications=password,keyboard-interactive"]
                            self.assertEqual(header + ["-B", "swp7", "admin@fe80::ff:fe00:1"], inner[:-1])
                            self.assertIs(type(responder), self.initial.NestedResponder)
                            self.assertIsNone(responder._phase)
                            self.assertEqual("eth-password", responder.ethernet_password)
                            self.assertTrue(hmac.compare_digest(responder.ib_default_password,
                                strict_kat(self.initial)["PASSWORD"]), "selected current credential binding differs")
                            self.assertEqual("admin@fe80::ff:fe00:1", responder.ib_destination)
                            self.assertIs(False, responder.allow_password_change)
                            self.assertIsNone(responder.ib_new_password)
                            if not backup:
                                return answer
                            stamp = vector[4]
                            backup_frames.append(stamp)
                            body = "path=/home/PUBLIC-EXAMPLE-IB01/current_" + stamp + ".yaml\nbytes=137\n"
                            return self.initial.SessionResult("__HTTP_IB_BEGIN_" + nonce + "__\n" + body
                                + "__HTTP_IB_END_" + nonce + "__=0\n", 0)

                        with mock.patch.object(self.initial, "interactive_run", new=remote):
                            try:
                                return real_run_on_ib(target, *args, **kwargs)
                            except self.initial.SetupError as error:
                                raw_failures.append(str(error))
                                raise
                if command == ("hostname",):
                    # U4 (v3.1.6 D1d, guide 8.11): a healthy device's Linux name is its CSV name.
                    return self.initial.SessionResult(name + "\n", 0)
                if command not in {
                    STRICT_READ, STRICT_DIFF,
                    ("nv", "set", "system", "dns", "server", "203.0.113.53"),
                    ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
                    ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
                    ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"),
                    ("nv", "config", "apply", "-y"), ("nv", "config", "save"),
                }:
                    raise AssertionError("PUBLIC raw model: unknown IB command")
                if command == ("nv", "config", "apply", "-y"):
                    applied.add(name)
                output = day0.replace("203.0.113.2/24", target.ib.eth0_prefix).replace(
                    "EXAMPLE-IB01", name
                )
                if name in applied:
                    output += services
                return self.initial.SessionResult(output, 0)

            with ExitStack() as stack:
                from test_cases.initial_setup_jump_fixture import legacy_jump_sessions_factory
                stack.enter_context(mock.patch.object(self.initial, "_new_jump_sessions", legacy_jump_sessions_factory(self.initial)))
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", (
                        "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                        "8: swp8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
                        "02:00:00:00:00:01 dev swp7 master bridge dynamic\n"
                        "02:00:00:00:00:02 dev swp8 master bridge dynamic\n",
                        "port vlan-id\nswp7 1 PVID Egress Untagged\nswp8 1 PVID Egress Untagged\n")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("interface_vrf", "default"),
                    # v15 checks IPv4 on every --apply (owner Q-035 (a)); that SSH check is a
                    # transport outside this PUBLIC model.
                    ("verify_ipv4_login", None),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=boundary))
                fd_argv = stack.enter_context(credentials_fd(strict_fd_payload(strict_kat(self.initial))))
                result = self.run_strict(tool, ib_csv, p2p, cache, "--apply", "--yes",
                                         *fd_argv,
                                         global_path=global_path,
                                         devices=("EXAMPLE-IB01", "EXAMPLE-IB02"), raw_backup=True)
            self.assertEqual(1, len(backup_frames), "the unique raw backup transport was reached")
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            # Table 6-1 rows 1 and 11 (guide :744, :754): INCOMPLETE, exit 2 (v15 RUNBOOK.md
            # 「失败设备继续、最终 incomplete 非零」).
            self.assertEqual(2, result)
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], attempted)
            self.assertTrue(len(raw_failures) == 1 and marker in raw_failures[0],
                            "the real transport failure carrying device output was not reached")
            self.assertNotIn(marker, report, "raw device output reached the report")
            self.assertIn("management IB operation failed; device state is UNKNOWN", report)
            self.assertIn("[EXAMPLE-IB02]", report)
            self.assertIn("Services SUCCESS: desired values verified", report)

    def test_leaf_rejects_rechecksummed_semantically_invalid_v4_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-hostile-cache-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            valid = json.loads(cache.read_text(encoding="utf-8"))
            cases = {
                "key_type_blob_mismatch": lambda value: value["public_keys"][0].update(
                    line=value["public_keys"][0]["line"].replace("ssh-ed25519 ", "ssh-rsa ", 1)
                ),
                "key_comment_nul": lambda value: value["public_keys"][0].update(
                    line=value["public_keys"][0]["line"] + "\x00comment"
                ),
                "dns_control_carrier": lambda value: value["services"].update(
                    dns=["203.0.113.53\nnv set system aaa user admin"]
                ),
                "unexpected_service_category": lambda value: value["services"].update(
                    aaa={"user": "admin"}
                ),
            }
            for label, mutate in cases.items():
                with self.subTest(label=label):
                    payload = json.loads(json.dumps(valid))
                    mutate(payload)
                    self.rewrite_cache_with_matching_sidecar(cache, payload)
                    before = (cache.stat().st_ino, cache.read_bytes())
                    with mock.patch.object(self.initial, "run_on_ib") as network:
                        with self.assertRaises(self.initial.SetupError):
                            self.run_initial(tool, ib_csv, p2p, cache,
                                             "--apply", "--yes", "--execution-mode", "ethernet")
                    network.assert_not_called()
                    self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_ntp_properties_and_quoted_membership_skip_transaction_but_keep_key_stage(self) -> None:
        state = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
            "nv set system dns server 203.0.113.53\n"
            'nv set system ntp server "NTP.UBUNTU.COM." state enabled\n'
            "nv set system ntp server 'TIME.IB.EXAMPLE.TEST.' iburst enabled\n"
            "nv set system ntp server time.ib.example.test association-type pool\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, laptop, management = self.drive_one_device(state, state)
        self.assertFalse(any(command[:5] == ("nv", "set", "system", "ntp", "server")
                             for command in commands))
        self.assertFalse(any(command[:3] == ("nv", "config", "apply") for command in commands))
        self.assertNotIn(("nv", "config", "save"), commands)
        self.assertEqual(0, result, report)
        self.assertIn("services-skipped=1", report)
        key_commands = [command for command in commands if command[:2] == ("sh", "-c")]
        self.assertEqual(1, len(key_commands), "NTP idempotence must not skip the independent key stage")
        self.assertEqual(5, len(key_commands[0]))
        self.assertEqual("--", key_commands[0][3])
        self.assertEqual(laptop + management,
                         base64.b64decode(key_commands[0][4], validate=True).decode("ascii"))


class StrictManagementBoundaryControlTests(unittest.TestCase):
    """Known-true controls for the shared strict-path adapter and witness.

    No KAT is read: the adapter is entered with an empty KAT mapping and no
    run reaches a credential prompt.  The device boundary under the adapter
    is a mock owned by each test.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("req10b_strict_boundary_control_initial", INITIAL)

    @staticmethod
    def _request(app, command, **kwargs):
        # Same eight positional fields a run_on_ib request carries; the adapter
        # reads only the command and passes the rest through unchanged.
        return app.run_on_ib(None, None, "admin", "PUBLIC-OOB", "admin", "PUBLIC-CURRENT",
                             5, list(command), local=False, **kwargs)

    def test_device_boundary_refuses_private_phase_operations(self) -> None:
        app = self.initial
        private_target = os.urandom(8).hex()
        with mock.patch.object(app, "run_on_ib") as inner, \
             strict_management_boundary(self, app, kat={}):
            for operation in ("password-change", "post-change-read", "auth-probe-readonly"):
                with self.subTest(operation=operation):
                    changing = operation == "password-change"
                    with self.assertRaises(AssertionError) as caught:
                        self._request(
                            app, STRICT_READ, allow_password_change=changing,
                            ib_new_password=private_target if changing else None,
                            _phase_operation=operation, _password_policy=None,
                        )
                    self.assertNotIn(private_target, str(caught.exception))
            # An ordinary read-only request still reaches the test's boundary.
            self._request(app, STRICT_READ, allow_password_change=False)
        self.assertEqual(1, inner.call_count,
                         "a private phase request must not reach the test's device boundary")
        self.assertNotIn(private_target, repr(inner.call_args_list))

    def test_never_written_check_covers_exactly_the_held_rows(self) -> None:
        app = self.initial
        with tempfile.TemporaryDirectory(prefix="req10b-held-witness-") as directory:
            global_path = Path(directory) / "01-global.yaml"
            policy = object()

            def witness_for(held_rows, written):
                with strict_management_boundary(self, app, kat={}, held_rows=held_rows) as witness:
                    pass
                witness["policies"].append({"path": global_path.resolve(), "user": "admin",
                                            "interactive": True, "instance": policy})
                witness["phases"].append(("EXAMPLE-IB01", "auth-probe-readonly", policy))
                witness["helper"].append(written)
                witness["device"].append((written, True))
                return witness

            reserved_link = ("nv", "set", "interface", "eth0-1", "link", "state", "up")
            # Nothing held (REQ10C): a reserved-port write is not a held fact.
            assert_strict_management_path(self, witness_for((), reserved_link),
                                          global_path=global_path, devices=("EXAMPLE-IB01",))
            # Rows held (REQ10B): the held rows and single-port forms of a held
            # eth0-1 range fact must never be written.
            for written in (
                reserved_link,
                ("nv", "set", "interface", "eth1", "type", "eth"),
                ("nv", "set", "system", "ztp", "config-save", "enabled"),
            ):
                with self.subTest(written=written):
                    with self.assertRaisesRegex(AssertionError, "must never be written"):
                        assert_strict_management_path(
                            self, witness_for(STRICT_HELD_ROWS, written),
                            global_path=global_path, devices=("EXAMPLE-IB01",),
                        )
            derive = globals().get("held_fact_setters")
            self.assertTrue(callable(derive), "held setters must be derived from the held rows")
            self.assertEqual(HELD_FACT_SETTERS, derive(STRICT_HELD_ROWS))
            self.assertEqual(frozenset(), derive(()))

    def test_pending_diff_rewrite_is_selected_by_the_caller(self) -> None:
        parameters = inspect.signature(strict_management_boundary).parameters
        self.assertIn("empty_pending_diff", parameters,
                      "the empty pending-diff model must be selectable by the caller")
        self.assertIs(True, parameters["empty_pending_diff"].default,
                      "existing callers keep the modeled empty pending diff")
        app = self.initial
        pending = "nv set system hostname PUBLIC-PENDING\n"
        for selected, expected in ((True, ""), (False, pending)):
            with self.subTest(empty_pending_diff=selected):
                with mock.patch.object(app, "run_on_ib", return_value=app.SessionResult(pending, 0)), \
                     strict_management_boundary(self, app, kat={}, empty_pending_diff=selected):
                    result = self._request(app, STRICT_DIFF, allow_password_change=False)
                self.assertEqual(expected, result.output)

    def test_witness_failure_names_the_held_run_failure(self) -> None:
        build_note = globals().get("held_failure_note")
        self.assertTrue(callable(build_note),
                        "a run failure held behind the witness must be reportable")
        self.assertIn("note", inspect.signature(assert_strict_management_path).parameters)
        app = self.initial
        private_value = os.urandom(8).hex()
        fixed = "IB phase project authority failed; device state is UNKNOWN"
        note = build_note(app.SetupError(fixed), (private_value,))
        self.assertIn("SetupError", note)
        self.assertIn(fixed, note)
        withheld = build_note(app.SetupError("fixture " + private_value), (private_value,))
        self.assertIn("SetupError", withheld)
        self.assertNotIn(private_value, withheld)
        self.assertEqual("", build_note(None, (private_value,)))
        with strict_management_boundary(self, app, kat={}) as witness:
            pass
        with self.assertRaises(AssertionError) as caught:
            assert_strict_management_path(self, witness, global_path=Path("/nonexistent/01-global.yaml"),
                                          devices=("EXAMPLE-IB01",), note=note)
        self.assertIn("SetupError", str(caught.exception))
        self.assertIn(fixed, str(caught.exception))


class StrictBackupRecursionModelTests(unittest.TestCase):
    """Pure PUBLIC causal controls; no KAT, policy backend, SSH or shell."""

    @classmethod
    def setUpClass(cls):
        cls.initial = load_script("req10b_backup_recursion_controls", INITIAL)

    def model(self, *, raw_backup=False, hostname="EXAMPLE-IB01",
              parent=("nv", "set", "system", "dns", "server", "203.0.113.53"),
              inside_helper=True, children=1):
        from types import SimpleNamespace

        app = self.initial
        target = SimpleNamespace(ib=SimpleNamespace(hostname=hostname))
        endpoint = object()
        stamp = "20261118-120000"
        backup = ["sh", "-c", app._CONFIG_BACKUP_SCRIPT, "--", stamp]
        prefix = (target, endpoint, "cumulus", "PUBLIC-OOB", "admin", "PUBLIC-CURRENT", 5)

        def public_init(policy, path, user):
            # Explicit model of construction, not a real credential policy.
            policy.interactive = True
            self.assertEqual("admin", user)

        def public_helper(*args, **kwargs):
            self.assertIs(policy, kwargs.get("_password_policy"))
            return app.run_on_ib(*args, local=False)

        def public_device(*args, **kwargs):
            command = tuple(args[7])
            if command == STRICT_READ or command == tuple(backup):
                return app.SessionResult("PUBLIC model response\n", 0)
            if command == parent:
                result = None
                for _ in range(children):
                    result = app.run_on_ib(*prefix, backup, local=False,
                                          allow_password_change=False, password_only=True)
                return result
            raise AssertionError("PUBLIC recursion control: unknown command")

        with tempfile.TemporaryDirectory(prefix="req10b-backup-control-") as directory:
            global_path = Path(directory) / "01-global.yaml"
            with mock.patch.object(app.ProjectPasswordPolicy, "__init__", new=public_init), \
                 mock.patch.object(app, "_run_authorized_ib_command", new=public_helper), \
                 mock.patch.object(app, "run_on_ib", new=public_device), \
                 strict_management_boundary(self, app, kat={}, held_rows=(),
                                            raw_backup=raw_backup) as witness:
                policy = app.ProjectPasswordPolicy(global_path, "admin")
                # This is the adapter's real readonly phase call, not an
                # invented AUTH command or a hand-appended phase record.
                app._execute_ib_phase(*prefix, list(STRICT_READ), local=False,
                    _phase_operation="auth-probe-readonly", _password_policy=policy)
                if inside_helper:
                    app._run_authorized_ib_command(*prefix, list(parent), _password_policy=policy)
                else:
                    app.run_on_ib(*prefix, list(parent), local=False)
            return witness, global_path, policy

    def test_default_adapter_rejects_recursive_backup(self):
        parameters = inspect.signature(strict_management_boundary).parameters
        self.assertIn("raw_backup", parameters)
        self.assertIs(False, parameters["raw_backup"].default)
        with self.assertRaisesRegex(AssertionError, "recursive backup requires raw opt-in"):
            self.model()

    def test_raw_opt_in_keeps_full_parent_child_witness(self):
        witness, global_path, policy = self.model(raw_backup=True)
        dns = ("nv", "set", "system", "dns", "server", "203.0.113.53")
        child = ("CONFIG-BACKUP", "20261118-120000")
        self.assertEqual([dns], witness["helper"])
        self.assertEqual([(STRICT_READ, False), (dns, True), (child, True)], witness["device"])
        keys = ("kind", "id", "command", "hostname", "helper_id", "helper_depth",
                "device_depth", "parent_device")
        self.assertEqual([
            ("device", 0, STRICT_READ, "EXAMPLE-IB01", None, 0, 1, None),
            ("helper", 1, dns, "EXAMPLE-IB01", 1, 1, 0, None),
            ("device", 2, dns, "EXAMPLE-IB01", 1, 1, 1, None),
            ("device", 3, child, "EXAMPLE-IB01", 1, 1, 2, 2),
        ], [tuple(event[key] for key in keys) for event in witness["events"]])
        self.assertIsNone(witness["events"][0]["policy"])
        self.assertTrue(all(event["policy"] is policy for event in witness["events"][1:]),
                        "parent and child retain the same PUBLIC model policy identity")
        assert_strict_management_path(self, witness, global_path=global_path,
                                      devices=("EXAMPLE-IB01",), raw_backup=True)

    def test_raw_opt_in_rejects_wrong_parent_or_extra_child(self):
        cases = (
            {"parent": ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com")},
            {"hostname": "EXAMPLE-IB02"},
            {"inside_helper": False},
            {"children": 2},
        )
        for index, changes in enumerate(cases):
            with self.subTest(case=index), self.assertRaisesRegex(
                AssertionError, "raw backup child binding refused",
            ):
                self.model(raw_backup=True, **changes)

        with self.subTest(case="same-command-helper-id-not-bijective"):
            witness, global_path, policy = self.model(raw_backup=True)
            assert_strict_management_path(self, witness, global_path=global_path,
                                          devices=("EXAMPLE-IB01",), raw_backup=True)
            dns = ("nv", "set", "system", "dns", "server", "203.0.113.53")
            child = ("CONFIG-BACKUP", "20261118-120000")
            # Independent counterexample: both DNS tops name helper 1,
            # while the identical-command helper 4 has no device at all.
            # The original sole backup child remains under device 2/helper 1.
            witness["helper"].append(dns)
            witness["device"].append((dns, True))
            witness["events"].extend([
                {"kind": "helper", "id": 4, "command": dns,
                 "hostname": "EXAMPLE-IB01", "policy": policy, "helper_id": 4,
                 "helper_depth": 1, "device_depth": 0, "parent_device": None},
                {"kind": "device", "id": 5, "command": dns,
                 "hostname": "EXAMPLE-IB01", "policy": policy, "helper_id": 1,
                 "helper_depth": 1, "device_depth": 1, "parent_device": None},
            ])
            self.assertEqual([dns, dns], witness["helper"])
            self.assertEqual([(STRICT_READ, False), (dns, True), (child, True), (dns, True)],
                             witness["device"])
            with self.assertRaisesRegex(
                AssertionError, "raw top-level helper/device IDs must match one to one",
            ):
                assert_strict_management_path(self, witness, global_path=global_path,
                                              devices=("EXAMPLE-IB01",), raw_backup=True)


if __name__ == "__main__":
    unittest.main()
