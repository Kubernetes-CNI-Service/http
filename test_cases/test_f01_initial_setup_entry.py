"""Independent local UFM entry and Bash syntax-only checks; no SDK or SSH."""
import contextlib
import hashlib
import importlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SUBJECT = "tools.ufm_initial_setup"
GLOBAL = b"""common:
  switch:
    password: NEVER_ECHO_THIS_SECRET
servers:
- ufm:
    version: 2.5.1-8
    interfaces:
      alias:
        eth0: eno8303
        eth1: eno8403
"""
CSV = b"""hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac
EXAMPLE-UFM02,ufm,NA,192.0.2.22,24,192.0.2.1,02:00:00:00:00:22
EXAMPLE-UFM01,ufm,NA,192.0.2.21,24,192.0.2.1,02:00:00:00:00:21
"""

def subject(test):
    test.assertIsNotNone(importlib.util.find_spec(SUBJECT),
                         "UFM_RUNNABLE_INITIAL_SETUP_ENTRY_MISSING")
    return importlib.import_module(SUBJECT)

@contextlib.contextmanager
def site():
    with tempfile.TemporaryDirectory() as directory:
        owned = Path(directory).resolve()
        http = owned / "http"
        project = http / "DAY0-Prepare/project"
        project.mkdir(parents=True)
        (http / "monitor").mkdir()
        (project / "01-global.yaml").write_bytes(GLOBAL)
        (project / "02-devices_config.csv").write_bytes(CSV)
        (http / "monitor/02-devices_config.csv").symlink_to(
            "../DAY0-Prepare/project/02-devices_config.csv")
        logs = owned / "private/xdr-initial-setup-logs"
        logs.mkdir(parents=True, mode=0o700)
        yield http, project, logs

class UfmInitialSetupDirectTests(unittest.TestCase):
    def test_four_phases_seven_steps_literal_roles_and_non_deployment(self):
        api = subject(self)
        with site() as (_http, project, _logs):
            plan = api.build_plan(project)
            self.assertEqual("PLANNED_NOT_EXECUTED", plan["state"])
            self.assertFalse(plan["completion"])
            self.assertEqual(
                ["access", "base_trust_upgrade", "ha", "sm_license_activation"],
                [phase["id"] for phase in plan["phases"]])
            self.assertEqual([1, 2, 3, 4, 5, 6, 7],
                             [step["step"] for step in plan["steps"]])
            self.assertEqual(["base", "mutual_trust", "upgrade", "ha",
                              "subnet_manager", "license", "license_activation"],
                             [step["operation"] for step in plan["steps"]])
            self.assertTrue(all(step["state"] == "HOLD" for step in plan["steps"]))
            self.assertEqual({"primary": "EXAMPLE-UFM01", "secondary": "EXAMPLE-UFM02"},
                             plan["installation_roles"])
            self.assertEqual("192.0.2.23", plan["vip"]["candidate"])
            self.assertEqual("2.5.1-8", plan["requested_version"])
            self.assertEqual("CSV_IPV4_FIRST", plan["access"]["policy"])
            self.assertFalse(plan["access"]["dhcp_required"])
            self.assertNotIn("NEVER_ECHO_THIS_SECRET", json.dumps(plan))

    def test_only_explicit_ipv4_unreachable_allows_oob_and_no_claim_of_observation(self):
        api = subject(self)
        expected = {
            "verified": "CONTINUE",
            "unreachable": "OOB_DISCOVERY_REQUIRED",
            "connect_timeout": "OOB_DISCOVERY_REQUIRED",
            "authentication_rejected": "CREDENTIAL_RECOVERY_REQUIRED",
            "host_key_conflict": "STOP",
            "management_mac_mismatch": "STOP",
            "unknown": "STOP",
        }
        for outcome, decision in expected.items():
            with self.subTest(outcome=outcome):
                self.assertEqual(decision, api.classify_ipv4_outcome(outcome))
        with self.assertRaises(api.SetupHold):
            api.classify_ipv4_outcome("arbitrary socket exception")
        with site() as (_http, project, _logs):
            (project / "01-global.yaml").write_bytes(GLOBAL.replace(b"2.5.1-8", b"3.0.0"))
            with self.assertRaises(api.SetupHold):
                api.build_plan(project)

    def test_write_commands_hold_before_sdk_or_prompt_and_unknown_args_are_sanitized(self):
        before_sdk = {name: sys.modules.get(name) for name in ("paramiko", "tools.ufm_bootstrap_auth_adapter")}
        api = subject(self)
        with site() as (_http, project, logs):
            for command in ("execute", "authenticate", "establish-keys"):
                with self.subTest(command=command), contextlib.redirect_stdout(io.StringIO()) as out:
                    code = api.main([command, "--project", str(project),
                                     "--address", "192.0.2.21",
                                     "--private-logs-root", str(logs)])
                    result = json.loads(out.getvalue())
                    self.assertEqual(2, code)
                    self.assertEqual("HOLD", result["state"])
                    self.assertFalse(result["completion"])
            for command in ("stage-readonly",):
                with self.subTest(unintegrated=command), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as rejected:
                        api.main([command, "--project", str(project)])
                    self.assertEqual(2, rejected.exception.code)
            self.assertEqual([], list(logs.iterdir()))
            self.assertEqual(before_sdk, {name: sys.modules.get(name) for name in before_sdk})
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(SystemExit) as exit_status:
                    api.main(["--password=SECRET_ARG_MUST_NOT_ECHO"])
            self.assertEqual(2, exit_status.exception.code)
            self.assertNotIn("SECRET_ARG_MUST_NOT_ECHO", errors.getvalue())

class UfmInitialSetupGenerationWorkflowTests(unittest.TestCase):
    def test_generated_readonly_stage_parses_in_real_bash_without_execution(self):
        api = subject(self)
        from tools import ufm_deployment_script_builder as builder
        with site() as (http, project, logs), mock.patch.object(builder, "HTTP_ROOT", http):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(0, api.main([
                    "generate", "--project", str(project), "--address", "192.0.2.21",
                    "--private-logs-root", str(logs)]))
            artifact = json.loads(output.getvalue())
            script = Path(artifact["script"])
            before = script.read_bytes()
            result = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-n", str(script)],
                cwd=http.parent, env={"PATH": "/usr/bin:/bin", "HOME": str(http.parent)},
                capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("", result.stdout)
            self.assertEqual("", result.stderr)
            self.assertEqual(before, script.read_bytes())
            self.assertEqual("GENERATED_NOT_EXECUTED", artifact["state"])
            self.assertFalse(artifact["completion"])

    def test_actual_input_identity_builder_generation_keeps_sources_and_private_bound_artifact(self):
        before_sdk = {name: sys.modules.get(name) for name in ("paramiko", "tools.ufm_bootstrap_auth_adapter")}
        api = subject(self)
        from tools import ufm_deployment_script_builder as builder
        with site() as (http, project, logs), mock.patch.object(builder, "HTTP_ROOT", http):
            before = {name: (project / name).read_bytes()
                      for name in ("01-global.yaml", "02-devices_config.csv")}
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = api.main(["generate", "--project", str(project),
                                 "--address", "192.0.2.21", "--private-logs-root", str(logs)])
            result = json.loads(output.getvalue())
            self.assertEqual(0, code)
            self.assertEqual("GENERATED_NOT_EXECUTED", result["state"])
            self.assertFalse(result["completion"])
            script = Path(result["script"])
            manifest = json.loads(Path(result["manifest"]).read_bytes())
            raw = script.read_bytes()
            self.assertIn(b"hostname\n", raw)
            self.assertIn(b"ip -j link show dev eno8303\n", raw)
            self.assertIn(b"node=EXAMPLE-UFM01", raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest["script_sha256"])
            self.assertEqual({name: hashlib.sha256(data).hexdigest()
                              for name, data in before.items()}, manifest["input_sha256"])
            self.assertEqual("NOT_RUN", manifest["syntax_check"])
            self.assertFalse(manifest["execution_permitted"])
            self.assertFalse(manifest["completion"])
            self.assertEqual(0o600, script.stat().st_mode & 0o777)
            self.assertEqual(0o600, Path(result["manifest"]).stat().st_mode & 0o777)
            self.assertNotIn(b"NEVER_ECHO_THIS_SECRET", raw + Path(result["manifest"]).read_bytes())
            self.assertEqual(before, {name: (project / name).read_bytes() for name in before})
            self.assertEqual(before_sdk, {name: sys.modules.get(name) for name in before_sdk})

    def test_wrong_active_project_and_unknown_member_leave_no_new_artifact(self):
        api = subject(self)
        from tools import ufm_deployment_script_builder as builder
        with site() as (http, project, logs), mock.patch.object(builder, "HTTP_ROOT", http):
            for address in ("192.0.2.99",):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(2, api.main(["generate", "--project", str(project),
                                                "--address", address, "--private-logs-root", str(logs)]))
                self.assertEqual("HOLD", json.loads(output.getvalue())["state"])
            other = http / "DAY0-Prepare/other"
            other.mkdir()
            (other / "01-global.yaml").write_bytes(GLOBAL)
            (other / "02-devices_config.csv").write_bytes(CSV)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(2, api.main(["generate", "--project", str(other),
                                            "--address", "192.0.2.21", "--private-logs-root", str(logs)]))
            self.assertEqual([], list(logs.iterdir()))

class UfmInitialSetupSupportingDirectTests(unittest.TestCase):
    def test_input_and_identity_declaration_and_original_builder_literal(self):
        from tools import ufm_input_contract as inputs
        from tools import ufm_identity_binding as binding
        from tools import ufm_deployment_script_builder as builder
        from tools.project_contract import safe_load_global_yaml
        document = safe_load_global_yaml(io.StringIO(GLOBAL.decode()))
        self.assertEqual(("2.5.1-8", "REQUESTED"),
                         (inputs.plan_ufm_operation_version(document).version,
                          inputs.plan_ufm_operation_version(document).upgrade))
        absent = safe_load_global_yaml(io.StringIO(
            GLOBAL.decode().replace("    version: 2.5.1-8\n", "")))
        self.assertEqual((None, "SKIPPED"),
                         (inputs.plan_ufm_operation_version(absent).version,
                          inputs.plan_ufm_operation_version(absent).upgrade))
        configured = inputs.plan_ufm_configured_declaration(document, CSV.decode())
        self.assertEqual("NOT_APPROVED", configured.deployment_status)
        self.assertEqual(["EXAMPLE-UFM01", "EXAMPLE-UFM02"],
                         [node.hostname for node in configured.members])
        with site() as (_http, project, _logs):
            actual, interface, sources = binding._project_declaration(project)
            self.assertEqual(configured, actual)
            self.assertEqual("eno8303", interface)
            self.assertEqual(
                [(project / "01-global.yaml", hashlib.sha256(GLOBAL).hexdigest()),
                 (project / "02-devices_config.csv", hashlib.sha256(CSV).hexdigest())],
                list(sources))
        run_id = "20261019T000000Z-" + "1" * 32
        literal = ("#!/usr/bin/env bash\nset -euo pipefail\numask 077\n"
                   "# F01 phase1_readonly_preflight: GENERATED_NOT_EXECUTED; no deployment completion\n"
                   "printf '%s\\n' 'F01_READ_ONLY_PREFLIGHT' 'run-id=" + run_id +
                   "' 'node=EXAMPLE-UFM01' 'phase=phase1_readonly_preflight'\n"
                   "if ! sudo -n -- true; then\n"
                   "  printf '%s\\n' 'F01_BLOCKED_SUDO_CHECK' >&2\n"
                   "  exit 73\nfi\nhostname\nip -j link show dev eno8303\n"
                   "ip -j address show dev eno8303\n").encode()
        self.assertEqual(literal, builder._render_stage_probe("EXAMPLE-UFM01", "eno8303", run_id))
