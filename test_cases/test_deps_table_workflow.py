"""Unified dependency table workflow: infra/deps.py → cron.sh, Dockerfile → activate.py, table ↔ upgrade.py.

Scenarios across real scripts: deps.py installs the cabletracker venv (fake base python, temporary
HOME, no network) and cron.sh's real issue_tracker_sync() then selects it; the image build installs
the engine list before activate.py's engine gate and couples that list to the image; the table's
venv paths are the ones cron.sh and upgrade.py use; the files check of every hard-coded copy is
green on the repository; the new files travel with sync/upload/image. The F01 SDK identity tests
run in the table's venv-ibsw-upgrade when the full proof's /usr/bin/python3 is not a venv, and
fail (never skip) with the deps.py install command when that venv cannot prove the identity.
"""

from __future__ import annotations

import html
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_cases import f01_sdk_venv
from test_cases.module_loader import load_script
from test_cases.test_deps_table import LINUX_312, RETIRED_LISTS, run_deps, write_fake_python
from test_cases.test_issue_tracker_engine_runtime import CONTAINER_PYTHON, cron_function


ROOT = Path(__file__).resolve().parents[1]
ENGINE = "infra/docker/requirements-issue-tracker-engine.txt"
IBSW = "infra/requirements-ibsw-upgrade.txt"
IBSW_MACOS = "infra/requirements-ibsw-upgrade-macos-cp39.txt"
TABLE = "infra/dependencies.json"
NEW_FILES = ("infra/deps.py", TABLE, ENGINE, IBSW, IBSW_MACOS)
INSTALL = ("/opt/http-ztp/venv/bin/python -m pip install --only-binary=:all: --no-deps --require-hashes "
           "-r /opt/http-ztp/source-tree/")
GATE = "/opt/http-ztp/venv/bin/python /opt/http-ztp/source-tree/infra/docker/activate.py "


class DependencyTableWorkflowTests(unittest.TestCase):
    def test_installed_cabletracker_venv_is_the_engine_cron_selects(self):
        with tempfile.TemporaryDirectory(prefix="deps-cron-") as directory:
            base = Path(directory)
            home = base / "home"
            home.mkdir()
            fake = write_fake_python(base)
            env = {"HOME": str(home), "FAKE_PY_IDENTITY": LINUX_312}
            installed = run_deps("install", "--target", "venv-cabletracker", "--python", str(fake), env=env)
            self.assertEqual(0, installed.returncode, installed.stdout + installed.stderr)
            checked = run_deps("check", "--target", "venv-cabletracker", "--json", env=env)
            self.assertEqual(0, checked.returncode, checked.stdout)
            self.assertIs(True, json.loads(checked.stdout)["ok"])

            (base / "bin").mkdir()
            recorder = base / "bin/python3"
            recorder.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_ARGS"\n', encoding="utf-8")
            recorder.chmod(0o755)
            sync = base / "issue-tracker-sync.py"
            sync.write_text("# placeholder\n", encoding="utf-8")
            harness = "\n".join([
                'log() { :; }',
                f'ISSUE_TRACKER_SYNC="{sync}"',
                cron_function().replace(CONTAINER_PYTHON, str(base / "no-image/venv/bin/python")),
                "issue_tracker_sync ib",
            ]) + "\n"
            result = subprocess.run(["/bin/bash", "-c", harness], stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=30,
                                    env={"PATH": f"{base / 'bin'}:/usr/bin:/bin", "HOME": str(home),
                                         "TEST_ARGS": str(base / "args")})
            self.assertEqual(0, result.returncode, result.stderr)
            args = (base / "args").read_text(encoding="utf-8").splitlines()
            self.assertEqual(str(home / ".venvs/http/cabletracker/bin/python"),
                             args[args.index("--engine-python") + 1])

    def test_image_installs_the_engine_list_before_its_gate_and_couples_it(self):
        text = (ROOT / "infra/docker/Dockerfile").read_text(encoding="utf-8")
        lines = text.splitlines()
        engine_install = INSTALL + ENGINE
        engine_gate = GATE + "verify-issue-tracker-engine-runtime"
        for command in (engine_install, engine_gate):
            self.assertEqual(1, text.count(command), command)
            self.assertIn("    && " + command + " \\", lines)
        toplevel = "-r /opt/http-ztp/source-tree/requirements-container-top-level.lock"
        self.assertLess(text.index(toplevel), text.index(engine_install))
        self.assertLess(text.index(engine_install), text.index(GATE + "verify-python-runtime "))
        self.assertLess(text.index(GATE + "verify-python-runtime "), text.index(engine_gate))
        # REQ7 retirement step 3b (2026-10-24): the engine list is the image's only Issue Tracker list; the two
        # old REQ7 locks and their build-time gates are gone from the image and from activate.py.
        for retired in (*RETIRED_LISTS, "verify-req7-python-runtime", "verify-req7-cable-python-runtime"):
            self.assertNotIn(retired, text)
        activate = load_script("deps_workflow_activate", ROOT / "infra/docker/activate.py")
        [action] = [item for item in activate.parser()._actions if item.dest == "action"]
        self.assertIn("verify-issue-tracker-engine-runtime", action.choices)
        self.assertEqual([], sorted(choice for choice in action.choices if "req7" in choice))
        self.assertEqual([], sorted(path for path in activate.IMAGE_COUPLED_SOURCE_PATHS if "req7" in path))
        self.assertEqual(ENGINE, activate.ISSUE_TRACKER_ENGINE_REQUIREMENTS)
        self.assertIn(ENGINE, activate.IMAGE_COUPLED_SOURCE_PATHS)
        # The table itself and the native-only ibsw list are not image-coupled: editing them must not
        # force an image rebuild.
        self.assertNotIn(TABLE, activate.IMAGE_COUPLED_SOURCE_PATHS)
        self.assertNotIn(IBSW, activate.IMAGE_COUPLED_SOURCE_PATHS)
        self.assertNotIn(IBSW_MACOS, activate.IMAGE_COUPLED_SOURCE_PATHS)
        image_paths = set(activate.image_source_paths(ROOT))
        for relative in NEW_FILES:
            self.assertIn(relative, image_paths)

    def test_table_venv_paths_are_the_ones_cron_and_upgrade_use(self):
        deps = load_script("deps_workflow_deps", ROOT / "infra/deps.py")
        table = deps.load_table(ROOT)
        cabletracker = table["targets"]["venv-cabletracker"]
        self.assertEqual(ENGINE, cabletracker["requirements"])
        self.assertIn("$HOME/" + cabletracker["path"][2:] + "/bin/python", cron_function())
        upgrade_paths = deps.module_constant(ROOT / "infiniband/bringup/xdr-upgrade/upgrade.py", "_RUNTIME_VENV_PATHS")
        self.assertEqual(table["targets"]["venv-ibsw-upgrade"]["path"], upgrade_paths[0])
        self.assertEqual(IBSW, table["targets"]["venv-ibsw-upgrade"]["requirements"])

    def test_files_check_covers_every_hard_coded_copy_across_scripts(self):
        result = run_deps("check", "--target", "files", "--json")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        rows = json.loads(result.stdout)["targets"]["files"]["items"]
        items = {row["item"] for row in rows if row["status"] == "ok"}
        self.assertEqual([], sorted(row["item"] for row in rows if "req7" in row["item"]),
                         "the retired REQ7 lists and contracts are no longer checked (step 3b)")
        for expected in (
            "infra/docker/activate.py::ISSUE_TRACKER_ENGINE_IMPORTS",
            "infra/docker/activate.py::CONTAINER_TOPLEVEL_REQUIREMENTS",
            "infra/docker/Dockerfile::apt-get install",
            "infra/infra-setup.py::MGMT_CACHE_PACKAGES",
            "tools/tar-for-upload.py::REQUIRED_OFFLINE_PACKAGES",
            "tools/ibsw_upgrade_observer.py::SSH_RUNTIME_PINS",
            "tools/f01_ssh_dependency_identity.py::_PINS",
            "infiniband/bringup/xdr-upgrade/upgrade.py::_RUNTIME_VENV_PATHS",
            "DAY0-Prepare/11-load.py::MACOS_GENERATION_MODULES",
            ENGINE, IBSW, IBSW_MACOS,
        ):
            self.assertIn(expected, items)

    def test_new_files_travel_with_sync_and_upload(self):
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            from project_contract import path_disposition, transfer_exclude_reason
        finally:
            sys.path.remove(str(ROOT / "tools"))
        for relative in NEW_FILES:
            self.assertEqual("production", path_disposition(relative), relative)
            self.assertIsNone(transfer_exclude_reason(Path(relative)), relative)
        self.assertTrue(os.access(ROOT / "infra/deps.py", os.X_OK))


# The F01 tests that reach the production SDK identity (tools/ufm_bootstrap_auth_adapter.py::
# _factory_sdk_identity via _direct_sdk_identity) without replacing it; every other test of these modules
# refuses before that check and keeps running in-process.
ROUTED_F01_TESTS = {
    "test_cases.test_f01_recovery_project_key_backup_durable_workflow": {
        "F01ProjectKeyBackupDurableWorkflowTests.test_real_new_password_backup_pull_fsync_apply_and_failed_local_fsync_never_applies",
    },
    "test_cases.test_f01_recovery_staging_owner": {
        "F01DeploymentStagingOwnerInputWorkflowTests.test_actual_project_builder_held_original_key_pin_deadline_and_close_do_not_issue_permission",
        "F01DeploymentStagingIssuanceDirectTests.test_cleanup_operator_interrupt_outprioritizes_ordinary_primary_in_both_owned_finally",
    },
    "test_cases.test_f01_recovery_staging_sftp_encrypted_workflow": {
        "F01DeploymentStagingSftpEncryptedWorkflowTests.test_actual_original_source_signed_sftp_normal_existing_and_interrupted_local_staging",
    },
}


class FakeChild:
    """subprocess.Popen stand-in: records the call; replies (returncode, stdout, stderr) or times out once."""

    def __init__(self, command, reply, recorded, **kwargs):
        recorded.append((command, kwargs))
        self.pid = 4242
        self.returncode = None
        self.reply = reply
        self.stdout = self.stderr = None

    def communicate(self, timeout=None):
        if self.reply == "timeout":
            self.reply = (None, "partial stdout", "partial stderr")
            raise subprocess.TimeoutExpired("child", timeout)
        self.returncode, stdout, stderr = self.reply
        return stdout, stderr

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


class F01SdkVenvRoutingWorkflowTests(unittest.TestCase):
    """infra/dependencies.json venv-ibsw-upgrade → test_cases/f01_sdk_venv.py → the F01 identity tests."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="f01-sdk-venv-")
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name)
        self.venv = self.home / ".venvs/http/ibsw-upgrade"
        self.python = self.venv / "bin/python"
        for patcher in (mock.patch.dict(os.environ, {"HOME": str(self.home)}),
                        mock.patch.dict(f01_sdk_venv._PROBED, clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        os.environ.pop(f01_sdk_venv.CHILD_ENV, None)

    def make_venv(self):
        (self.venv / "bin").mkdir(parents=True)
        (self.venv / "pyvenv.cfg").write_text("include-system-site-packages = false\nversion = 3.9.6\n")
        self.python.write_text("#!/bin/sh\nexit 99\n")
        self.python.chmod(0o755)

    def run_routed(self, *, in_target_venv=False, replies=()):
        """Run a decorated probe test; return (result, in-process calls, recorded child calls, killpg calls)."""
        calls, recorded, killed, replies = [], [], [], list(replies)

        class Probe(unittest.TestCase):
            @f01_sdk_venv.sdk_identity_test
            def test_identity(inner):
                calls.append(inner.id())

        def popen(command, **kwargs):
            return FakeChild(command, replies.pop(0), recorded, **kwargs)

        result = unittest.TestResult()
        with mock.patch.object(f01_sdk_venv, "runs_in_target_venv", return_value=in_target_venv), \
                mock.patch.object(f01_sdk_venv.subprocess, "Popen", side_effect=popen), \
                mock.patch.object(f01_sdk_venv.os, "killpg", side_effect=lambda pid, sig: killed.append((pid, sig))):
            Probe("test_identity").run(result)
        self.assertEqual([], replies, "every prepared child reply is consumed")
        self.assertEqual([], result.skipped, "the routing never skips")
        return result, calls, recorded, killed

    def identity(self, **changes):
        value = dict(f01_sdk_venv.interpreter_identity(), prefix=str(self.venv))
        value.update(changes)
        return value

    def probe_ok(self, **changes):
        value = dict(self.identity(**changes), lock_sha256="0" * 64)
        return 0, "\n" + f01_sdk_venv.PROBE_PREFIX + json.dumps(value) + "\n", ""

    def child(self, returncode=0, identity=None, **counts):
        summary = dict(identity or self.identity(), run=1, failures=0, errors=0, skipped=0, expected_failures=0,
                       unexpected_successes=0)
        summary.update(counts)
        return returncode, "\n" + f01_sdk_venv.RESULT_PREFIX + json.dumps(summary) + "\n", "test_identity ... ok\n"

    def failure(self, result) -> str:
        self.assertEqual(1, len(result.failures), result.errors)
        self.assertEqual([], result.errors)
        return result.failures[0][1]

    def test_helper_uses_the_table_venv_and_the_deps_install_command(self):
        deps = load_script("deps_workflow_f01_routing", ROOT / "infra/deps.py")
        table = deps.load_table(ROOT)
        target = table["targets"][f01_sdk_venv.TARGET]
        self.assertEqual("venv", target["kind"])
        self.assertIn("tools/ufm_bootstrap_auth_adapter.py", target["consumers"])
        self.assertEqual(deps.venv_path(target), f01_sdk_venv.venv_path())
        self.assertEqual(self.venv, f01_sdk_venv.venv_path())
        self.assertEqual(deps.venv_variant(target, "macos-cp39-arm64"), ("3.9", IBSW_MACOS))
        self.assertIn(f01_sdk_venv.INSTALL_COMMAND, target["installed_by"])
        self.assertEqual(["python3", "infra/deps.py", "install", "--target", f01_sdk_venv.TARGET],
                         f01_sdk_venv.INSTALL_COMMAND.split())

    def test_only_the_target_venv_itself_runs_the_test_in_process(self):
        for prefix, expected in ((str(self.venv), True), (str(self.home / "other-venv"), False),
                                 (sys.base_prefix, False)):
            with self.subTest(prefix=prefix), mock.patch.object(f01_sdk_venv.sys, "prefix", prefix):
                self.assertIs(expected, f01_sdk_venv.runs_in_target_venv())
        result, calls, recorded, _killed = self.run_routed(in_target_venv=True)
        self.assertTrue(result.wasSuccessful(), result.failures + result.errors)
        self.assertEqual(1, len(calls))
        self.assertTrue(calls[0].endswith(".Probe.test_identity"), calls)
        self.assertEqual([], recorded)

    def test_missing_or_broken_venv_fails_with_the_install_command_and_runs_nothing(self):
        cases = {
            "missing": (lambda: None, str(self.venv) + " is missing"),
            "not a venv": (lambda: self.venv.mkdir(parents=True), "is not a venv"),
            "broken symlink": (self.make_broken_venv, "broken symlink to " + str(self.home / "gone/bin/python3")),
        }
        for label, (prepare, words) in cases.items():
            with self.subTest(case=label):
                if self.venv.exists():
                    shutil.rmtree(self.venv)
                prepare()
                result, calls, recorded, _killed = self.run_routed()
                message = self.failure(result)
                self.assertIn(f01_sdk_venv.INSTALL_COMMAND, message)
                self.assertIn(words, message)
                self.assertEqual(([], []), (calls, recorded))

    def make_broken_venv(self):
        self.make_venv()
        self.python.unlink()
        self.python.symlink_to(self.home / "gone/bin/python3")

    def test_outside_the_target_venv_the_same_test_id_runs_in_the_venv_interpreter(self):
        self.make_venv()
        result, calls, recorded, killed = self.run_routed(replies=[self.probe_ok(), self.child()])
        self.assertTrue(result.wasSuccessful(), result.failures + result.errors)
        self.assertEqual([], calls, "the body runs in the child, not in this interpreter")
        self.assertEqual([], killed)
        (probe, probe_kwargs), (child, child_kwargs) = recorded
        self.assertEqual([str(self.python), "-I", "-B", "-c", f01_sdk_venv.PROBE, str(ROOT)], probe)
        self.assertIn("_factory_sdk_identity()", f01_sdk_venv.PROBE)
        self.assertEqual([str(self.python), "-I", "-B", "-c", f01_sdk_venv.CHILD, str(ROOT)], child[:6])
        self.assertEqual(7, len(child))
        self.assertTrue(child[6].endswith(".Probe.test_identity"), child)
        for kwargs in (probe_kwargs, child_kwargs):
            self.assertEqual(str(ROOT), kwargs["cwd"])
            self.assertEqual(subprocess.DEVNULL, kwargs["stdin"])
            self.assertEqual((subprocess.PIPE, subprocess.PIPE), (kwargs["stdout"], kwargs["stderr"]))
            self.assertEqual(("utf-8", "replace"), (kwargs["encoding"], kwargs["errors"]))
            self.assertIs(True, kwargs["start_new_session"])
            self.assertNotIn("text", kwargs)
        self.assertIsNone(probe_kwargs["env"])
        self.assertEqual("1", child_kwargs["env"][f01_sdk_venv.CHILD_ENV])
        self.assertNotIn(f01_sdk_venv.CHILD_ENV, os.environ)
        # The identity probe ran once for this interpreter; a second routed test reuses it.
        _result, _calls, again, _killed = self.run_routed(replies=[self.child()])
        self.assertEqual(1, len(again))

    def test_a_venv_without_the_identity_or_of_another_interpreter_fails(self):
        self.make_venv()
        mine = f01_sdk_venv.interpreter_identity()
        probes = {
            "refused": (1, "", "tools.ufm_bootstrap_auth_adapter.BootstrapAuthError: "
                               "SSH SDK implementation identity is unproved\n"),
            "other prefix": self.probe_ok(prefix="/elsewhere"),
            "other base interpreter": self.probe_ok(base_prefix="/opt/other-python"),
            "other version": self.probe_ok(version=mine["version"][:2] + [mine["version"][2] + 1]),
            "other cache tag": self.probe_ok(cache_tag="cpython-312"),
            "other machine": self.probe_ok(machine="x86_64" if mine["machine"] != "x86_64" else "arm64"),
            "no result line": (0, "nothing", ""),
            "glued result line": (0, "noise" + f01_sdk_venv.PROBE_PREFIX + json.dumps(self.identity()), ""),
        }
        for label, probe in probes.items():
            with self.subTest(probe=label):
                f01_sdk_venv._PROBED.clear()
                result, calls, recorded, _killed = self.run_routed(replies=[probe])
                message = self.failure(result)
                self.assertIn(f01_sdk_venv.INSTALL_COMMAND, message)
                self.assertIn("does not prove the F01 SDK identity on the proof interpreter", message)
                self.assertEqual([], calls)
                self.assertEqual(1, len(recorded), "the test child is not started")

    def test_any_child_outcome_but_one_clean_pass_on_the_proof_interpreter_fails(self):
        self.make_venv()
        mine = f01_sdk_venv.interpreter_identity()
        outcomes = {
            "assertion failed": self.child(1, failures=1),
            "error": self.child(1, errors=1),
            "skipped": self.child(0, skipped=1),
            "nothing ran": self.child(0, run=0),
            "expected failure": self.child(0, expected_failures=1),
            "unexpected success": self.child(1, unexpected_successes=1),
            "another prefix": self.child(0, identity=self.identity(prefix="/elsewhere")),
            "another base interpreter": self.child(0, identity=self.identity(base_prefix="/opt/other-python")),
            "another version": self.child(0, identity=self.identity(version=[3, 12, 3] if mine["version"][:2] != [3, 12]
                                                                    else [3, 9, 6])),
            "no result line": (0, "Ran 1 test\nOK\n", ""),
            "glued result line": (0, "partial" + f01_sdk_venv.RESULT_PREFIX + json.dumps(dict(
                self.identity(), run=1, failures=0, errors=0, skipped=0, expected_failures=0,
                unexpected_successes=0)), ""),
            "killed": (-9, "", "test_identity ... "),
        }
        for label, reply in outcomes.items():
            with self.subTest(outcome=label):
                result, calls, recorded, _killed = self.run_routed(replies=[self.probe_ok(), reply])
                f01_sdk_venv._PROBED.clear()
                message = self.failure(result)
                self.assertIn(f01_sdk_venv.INSTALL_COMMAND, message)
                for part in reply[1:]:
                    if part.strip():
                        self.assertIn(part.strip()[-30:], message, "the child's own output is shown")
                self.assertEqual([], calls)

    def test_a_child_timeout_kills_its_process_group_and_fails(self):
        self.make_venv()
        result, calls, recorded, killed = self.run_routed(replies=[self.probe_ok(), "timeout"])
        message = self.failure(result)
        self.assertEqual([(4242, signal.SIGKILL)], killed)
        self.assertIn("timed out after", message)
        self.assertIn("partial stderr", message)
        self.assertEqual([], calls)

    def test_timeout_kills_grandchildren_and_output_is_decoded_with_replacement(self):
        """Real processes: the child's own child dies with it; undecodable bytes do not raise."""
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "grandchild.pid"
            program = ("import subprocess, sys, time\n"
                       "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                       "open(sys.argv[1], 'w').write(str(child.pid))\n"
                       "sys.stdout.buffer.write(b'\\xff\\xfe before timeout\\n'); sys.stdout.flush()\n"
                       "time.sleep(120)\n")
            code, stdout, stderr = f01_sdk_venv._run([sys.executable, "-I", "-c", program, str(pidfile)], 5)
            self.assertIsNone(code)
            self.assertIn("timed out after 5 s", stderr)
            self.assertIn("�", stdout)
            self.assertIn("before timeout", stdout)
            grandchild = int(pidfile.read_text())
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    os.kill(grandchild, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                self.fail(f"grandchild {grandchild} survived the child's timeout")

    def test_a_child_marker_outside_the_target_venv_fails_instead_of_recursing(self):
        self.make_venv()
        with mock.patch.dict(os.environ, {f01_sdk_venv.CHILD_ENV: "1"}):
            result, calls, recorded, _killed = self.run_routed()
        self.assertIn("is not " + str(self.venv), self.failure(result))
        self.assertEqual(([], []), (calls, recorded))

    def test_child_program_runs_exactly_the_named_test_and_reports_it(self):
        """The real child program under this interpreter: one passing test, and an unknown id as an error."""
        passing = "test_cases.test_deps_table.TableContractTests.test_table_is_canonical_ascii_json_with_one_version_per_distribution"
        for test_id, returncode, expected in ((passing, 0, {"run": 1, "failures": 0, "errors": 0, "skipped": 0}),
                                              ("test_cases.test_deps_table.NoSuchTests.test_none", 1,
                                               {"run": 1, "failures": 0, "errors": 1, "skipped": 0})):
            with self.subTest(test_id=test_id):
                code, stdout, stderr = f01_sdk_venv._run(
                    [sys.executable, "-I", "-B", "-c", f01_sdk_venv.CHILD, str(ROOT), test_id], 300)
                self.assertEqual(returncode, code, stdout + stderr)
                summary = f01_sdk_venv.tagged(stdout, f01_sdk_venv.RESULT_PREFIX)
                self.assertEqual(expected, {key: summary[key] for key in expected}, stdout + stderr)
                self.assertIsNone(f01_sdk_venv.identity_problem(summary, Path(sys.prefix)))
                self.assertIn("Ran 1 test", stderr)

    def test_exactly_the_identity_tests_of_the_three_f01_modules_are_routed(self):
        for module_name, expected in ROUTED_F01_TESTS.items():
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                routed = set()
                for class_name, value in vars(module).items():
                    if isinstance(value, type) and issubclass(value, unittest.TestCase) \
                            and value.__module__ == module_name:
                        for name, member in vars(value).items():
                            if name.startswith("test") and getattr(member, "f01_sdk_venv_routed", False):
                                self.assertTrue(callable(getattr(member, "__wrapped__", None)))
                                routed.add(f"{class_name}.{name}")
                self.assertEqual(expected, routed)


def section(text: str, heading: str) -> str:
    """From `heading` up to the next heading of the same or a higher level."""
    start = text.index(heading)
    level = len(heading) - len(heading.lstrip("#"))
    following = re.compile(r"^#{1,%d} " % level, re.M).search(text, start + len(heading))
    return text[start:following.start() if following else len(text)]


def manual_hand_written() -> str:
    text = (ROOT / "user-manual.html").read_text(encoding="utf-8")
    for begin, end in re.findall(r"(<!-- BEGIN GENERATED [^>]*-->).*?(<!-- END GENERATED [^>]*-->)", text, re.S):
        text = text[:text.index(begin)] + text[text.index(end) + len(end):]
    return html.unescape(text)


class DependencyDocumentationTests(unittest.TestCase):
    """The operator-facing statements that cron.sh, deps.py and the image actually implement."""

    def setUp(self):
        self.table = json.loads((ROOT / TABLE).read_text(encoding="ascii"))
        self.docker = section((ROOT / "infra/docker/README.md").read_text(encoding="utf-8"), "### 镜像内 Python 依赖")
        self.card = section((ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(encoding="utf-8"),
                            "## TC-REAL-DEPS-ENGINE-IMAGE-001")
        self.issue_tracker = (ROOT / "monitor/issue-tracker/README.md").read_text(encoding="utf-8")
        self.cron = cron_function()

    def test_the_native_engine_venv_belongs_to_the_user_who_runs_11_load(self):
        # S1: setup and load install no crontab; the worker started by 11-load.py runs cron.sh.
        installed_by = self.table["targets"]["venv-cabletracker"]["installed_by"]
        self.assertIn("11-load.py", installed_by)
        self.assertNotIn("crontab", installed_by)
        for label, text in (("issue-tracker README", self.issue_tracker), ("card", self.card)):
            with self.subTest(document=label):
                self.assertIn("执行 11-load.py 的用户", text)
                self.assertNotIn("运行 cron 的那个用户", text)
                self.assertNotIn("crontab 运行", text)
        self.assertIn("11-load.py", self.cron)
        self.assertNotIn("the user this cron runs as", self.cron)

    def test_every_docker_host_rebuilds_the_image_with_pypi_access_before_its_next_load(self):
        # S3: activate.py is image-coupled and changed, so an old image refuses the new release.
        for label, text in (("docker README", self.docker), ("card", self.card)):
            with self.subTest(document=label):
                self.assertIn("每台 Docker 主机", text)
                self.assertIn("deploy.sh build", text)
                self.assertIn("PyPI", text)
                self.assertIn("拒绝", text)
        self.assertNotIn("cron.sh 的在线同步会在 cronjob.log 里记 WARNING", self.docker)
        self.assertNotIn("在此之前构建的镜像没有 httpx/openai，引擎在导入阶段失败，cron 只记 WARNING", self.card)
        self.assertNotIn("older images lack", self.cron)
        self.assertIn("rebuild", self.cron)

    def test_full_proof_machine_needs_the_ibsw_venv_built_with_the_clt_python(self):
        # Owner 2026-10-24: /usr/bin/python3 runs the formal proof, so its F01 SDK identity tests need the venv.
        readme = (ROOT / "test_cases/README.md").read_text(encoding="utf-8")
        for label, text in (("test_cases README", readme), ("user manual", manual_hand_written())):
            for phrase in ("/usr/bin/python3 infra/deps.py install --target venv-ibsw-upgrade",
                           "/usr/bin/python3 infra/deps.py check --target venv-ibsw-upgrade",
                           IBSW_MACOS, "PyPI", "arm64", "全量证明"):
                with self.subTest(document=label, phrase=phrase):
                    self.assertIn(phrase, text)
        for phrase in ("~/.venvs/http/ibsw-upgrade", "test_cases/f01_sdk_venv.py", "@sdk_identity_test", "绝不 skip"):
            self.assertIn(phrase, readme)

    def test_manual_and_docker_readme_carry_the_native_venv_steps(self):
        # S6: the hand-written part of the user manual, not only the generated catalog.
        required = (
            "python3 infra/deps.py check",
            "python3 infra/deps.py install --target venv-cabletracker",
            "python3 infra/deps.py install --target venv-ibsw-upgrade",
            "~/.venvs/http/cabletracker",
            "~/.venvs/http/ibsw-upgrade",
            "11-load.py",
        )
        for label, text in (("user manual", manual_hand_written()), ("docker README", self.docker)):
            for phrase in required:
                with self.subTest(document=label, phrase=phrase):
                    self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
