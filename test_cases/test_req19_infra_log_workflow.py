"""REQ-19: real setup/deploy/check modules on a hermetic temporary tree."""

from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import fcntl
import io
import os
from pathlib import Path
import select
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script("req19_flow_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
DEPLOY = load_script("req19_flow_deploy", ROOT / "infra/deploy_infra.py")
CHECK = load_script("req19_flow_check", ROOT / "infra/check_infra.py")
MAPPING = ("infra/logs", "99-output-infra", "dir")


def hermetic_probe(infra: Path, temporary: Path) -> str:
    """Execute check's real probe with networking/privileged commands stubbed."""
    fake_bin = temporary / "fake-bin"
    fake_bin.mkdir(exist_ok=True)
    for name, script in (
        ("sudo", "#!/bin/sh\nexit 1\n"),
        ("systemctl", "#!/bin/sh\nexit 1\n"),
        ("hostname", "#!/bin/sh\nprintf 'isolated-host\\n'\n"),
        ("wget", "#!/bin/sh\nexit 93\n"),
        ("curl", "#!/bin/sh\nexit 93\n"),
    ):
        path = fake_bin / name
        path.write_text(script, encoding="utf-8")
        path.chmod(0o700)
    env = os.environ.copy()
    env.update(INFRA_BASE=str(infra), PATH=f"{fake_bin}:{os.environ.get('PATH', '')}")
    result = subprocess.run(
        ["bash", "-s"], input=CHECK.remote_probe_script(), cwd=infra,
        env=env, text=True, capture_output=True, check=True, timeout=10,
    )
    if "public.status=not_run" not in result.stdout:
        raise AssertionError("unexpected host/network probe branch")
    return result.stdout


class Req19InfraLogWorkflowTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory) / "http"
        infra = root / "infra"
        infra.mkdir(parents=True)
        template = root / "DAY0-Prepare/template/99-output-infra"
        template.mkdir(parents=True)
        (template / ".gitkeep").write_bytes(b"")
        a, b = (root / "DAY0-Prepare/site-a", root / "DAY0-Prepare/site-b")
        for project in (a, b):
            project.mkdir(parents=True)
            (project / "p2p.xlsx").write_bytes(b"isolated fixture")
            (project / "99-output-infra").mkdir()
        return root, infra, a, b

    def setup_project(self, root, project):
        unrelated = (
            "_initialize_project_from_template", "_prepare_laptop_public_key",
            "_remove_legacy_nvos_output_links", "_process_bin_files",
            "_process_xlsx_files", "_process_bringup_links",
            "_process_analyzer_links", "_process_pubkeys",
            "_process_latest_yaml", "_process_optimize_sample",
            "_process_net_csv_links", "_process_monitor_links",
            "_write_manifest", "_print_next_steps",
        )
        with ExitStack() as patches:
            patches.enter_context(mock.patch.multiple(
                SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                ZTP=str(root / "ztp"), TEMPLATE_DIR=str(root / "DAY0-Prepare/template"),
                MANIFEST_FILE=str(root / "ztp/.setup_manifest"),
                IMAGE_DIR=str(root / "image"), MAPPINGS=[], _NET_CSV_LINKS=[],
                P2P_INPUT_LINKS=[], P2P_OUTPUT_LINKS=[],
                P2P_AIR_JSON_LINK=str(root / "ztp/p2p-air.json"),
                BRINGUP_OUTPUT_MAPPINGS=[], ANALYZER_INPUT_MAPPINGS=[],
                ANALYZER_OUTPUT_MAPPINGS=[], _CSV_DIR=None, _DRY_RUN=False,
                _AUTO_YES=True, _CONFIRM_PROJECT_SWITCH=True, _LINK_TRANSACTION=None,
            ))
            for name in unrelated:
                patches.enter_context(mock.patch.object(SETUP, name))
            patches.enter_context(mock.patch.object(
                SETUP, "_select_p2p_source", return_value=str(project / "p2p.xlsx"),
            ))
            patches.enter_context(mock.patch.object(SETUP, "_validate_project", return_value=True))
            patches.enter_context(mock.patch.object(
                SETUP, "_ensure_project_p2p_link", return_value=str(project / "p2p.xlsx"),
            ))
            patches.enter_context(mock.patch.object(SETUP, "_confirm_overwrite", return_value=True))
            with redirect_stdout(io.StringIO()):
                SETUP.setup(str(project))

    def test_preproject_logs_real_setup_then_real_deploy_and_check(self):
        with tempfile.TemporaryDirectory(prefix="req19-flow-") as tmp:
            root, infra, a, _ = self.fixture(tmp)
            logs = infra / "logs"
            logs.mkdir()
            prior = logs / "infra-setup-20260924_010203.log"
            prior.write_bytes(b"pre-project shell log\n")
            self.setup_project(root, a)
            self.assertTrue(logs.is_symlink())
            self.assertEqual(b"pre-project shell log\n", (logs / prior.name).read_bytes())
            with mock.patch.object(DEPLOY, "SCRIPT_DIR", infra), redirect_stdout(io.StringIO()):
                self.assertEqual(0, DEPLOY.run_with_log("deploy_infra", lambda: 0))
            self.assertEqual(1, len(list((a / "99-output-infra").glob("deploy_infra-*.log"))))
            probe = hermetic_probe(infra, Path(tmp))
            self.assertIn(f"log.file=logs/{prior.name}", probe)
            with mock.patch.object(CHECK, "SCRIPT_DIR", infra), mock.patch.object(
                CHECK.subprocess, "run",
                return_value=subprocess.CompletedProcess(["bash", "-s"], 0, probe, ""),
            ), redirect_stdout(io.StringIO()):
                observed = CHECK.collect_local(Path(tmp) / "collected")
            self.assertIn(f"logs/{prior.name}", observed["logs"])
            self.assertEqual(
                {"kind": "project", "project": str(a.resolve()),
                 "target": str((a / "99-output-infra").resolve())},
                observed["infra_log_ownership"],
            )

    def test_real_probe_follows_managed_link_but_not_foreign_link(self):
        with tempfile.TemporaryDirectory(prefix="req19-probe-") as tmp:
            root, infra, a, _ = self.fixture(tmp)
            target = a / "99-output-infra"
            (target / "infra-setup-20260924_010203.log").write_bytes(b"owned\n")
            logs = infra / "logs"
            logs.symlink_to(os.path.relpath(target, infra))
            self.assertIn(
                "log.file=logs/infra-setup-20260924_010203.log",
                hermetic_probe(infra, Path(tmp)),
            )
            logs.unlink()
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "infra-setup-20260924_010204.log").write_bytes(b"foreign\n")
            logs.symlink_to(os.path.relpath(outside, infra))
            with self.assertRaises(subprocess.CalledProcessError) as rejection:
                hermetic_probe(infra, Path(tmp))
            self.assertNotIn("log.file=logs/infra-setup-20260924_010204.log", rejection.exception.stdout)
            self.assertIn("logs", rejection.exception.stderr)

    def test_preproject_real_log_root_reports_explicitly_unassigned_owner(self):
        with tempfile.TemporaryDirectory(prefix="req19-preproject-") as tmp:
            _root, infra, _a, _b = self.fixture(tmp)
            logs = infra / "logs"
            logs.mkdir()
            (logs / "infra-setup-20260924_010203.log").write_bytes(b"pre-project\n")
            probe = hermetic_probe(infra, Path(tmp))
            self.assertIn("log.file=logs/infra-setup-20260924_010203.log", probe)
            with mock.patch.object(CHECK, "SCRIPT_DIR", infra), mock.patch.object(
                CHECK.subprocess, "run",
                return_value=subprocess.CompletedProcess(["bash", "-s"], 0, probe, ""),
            ), redirect_stdout(io.StringIO()):
                observed = CHECK.collect_local(Path(tmp) / "collected")
            self.assertEqual(
                {"kind": "unassigned", "project": None, "target": str(logs.resolve())},
                observed["infra_log_ownership"],
            )

    def test_local_collector_rejects_foreign_log_leaf_in_managed_owner(self):
        with tempfile.TemporaryDirectory(prefix="req19-leaf-foreign-") as tmp:
            _root, infra, a, _b = self.fixture(tmp)
            output = Path(tmp) / "collected"
            foreign = Path(tmp) / "foreign.log"
            foreign.write_bytes(b"FOREIGN-LOG-CONTENT")
            owned = a / "99-output-infra"
            (owned / "infra-setup-20260924_010203.log").symlink_to(foreign)
            (infra / "logs").symlink_to(os.path.relpath(owned, infra))
            probe = "public.status=not_run\nsystem.hostname=isolated-host\n"
            with mock.patch.object(CHECK, "SCRIPT_DIR", infra), mock.patch.object(
                CHECK.subprocess, "run",
                return_value=subprocess.CompletedProcess(["bash", "-s"], 0, probe, ""),
            ), redirect_stdout(io.StringIO()):
                with self.assertRaises((CHECK.DeployError, OSError, ValueError)):
                    CHECK.collect_local(output)
            self.assertFalse(any(
                b"FOREIGN-LOG-CONTENT" in path.read_bytes()
                for path in output.rglob("*.log")
            ))

    def test_local_collector_rejects_owner_directory_swap_after_probe(self):
        with tempfile.TemporaryDirectory(prefix="req19-local-swap-") as tmp:
            _root, infra, a, _b = self.fixture(tmp)
            output = Path(tmp) / "collected"
            owned = a / "99-output-infra"
            (infra / "logs").symlink_to(os.path.relpath(owned, infra))
            foreign = Path(tmp) / "outside"
            foreign.mkdir()
            (foreign / "infra-setup-20260924_010203.log").write_bytes(b"FOREIGN-SWAP-CONTENT")

            def swap_after_probe(*_args, **_kwargs):
                owned.rename(a / "saved-output-infra")
                owned.symlink_to(foreign)
                return subprocess.CompletedProcess(
                    ["bash", "-s"], 0,
                    "public.status=not_run\nsystem.hostname=isolated-host\n", "",
                )

            with mock.patch.object(CHECK, "SCRIPT_DIR", infra), mock.patch.object(
                CHECK.subprocess, "run", side_effect=swap_after_probe,
            ), redirect_stdout(io.StringIO()):
                with self.assertRaises((CHECK.DeployError, OSError, ValueError)):
                    CHECK.collect_local(output)
            self.assertFalse(any(
                b"FOREIGN-SWAP-CONTENT" in path.read_bytes()
                for path in output.rglob("*.log")
            ))

    def test_remote_collector_never_scps_repointed_foreign_log_after_probe(self):
        with tempfile.TemporaryDirectory(prefix="req19-remote-swap-") as tmp:
            home = Path(tmp) / "home"
            runtime = home / "http-infra"
            runtime.mkdir(parents=True)
            owned = home / "DAY0-Prepare/site-a/99-output-infra"
            owned.mkdir(parents=True)
            name = "infra-setup-20260924_010203.log"
            (owned / name).write_bytes(b"ORIGINAL-OWNER")
            logs = runtime / "logs"
            logs.symlink_to(os.path.relpath(owned, runtime))
            foreign = Path(tmp) / "foreign"
            foreign.mkdir()
            (foreign / name).write_bytes(b"FOREIGN-REMOTE-CONTENT")
            output = Path(tmp) / "collected"
            output.mkdir()

            def fake_remote(command, **_kwargs):
                if command[0] == "scp":
                    source = Path(command[-2].split(":", 1)[1])
                    destination = Path(command[-1])
                    destination.write_bytes(source.read_bytes())
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[-1] == "printf '%s' \"$HOME\"":
                    return subprocess.CompletedProcess(command, 0, str(home), "")
                replacement = runtime / ".logs-test-repoint"
                replacement.symlink_to(foreign)
                os.replace(replacement, logs)
                probe = (
                    "public.status=not_run\nsystem.hostname=isolated-host\n"
                    "log.owner.kind=project\nlog.owner.project=site-a\n"
                    f"log.file=logs/{name}\n"
                )
                return subprocess.CompletedProcess(command, 0, probe, "")

            with mock.patch.object(CHECK, "key_login_works", return_value=True), \
                    mock.patch.object(CHECK.subprocess, "run", side_effect=fake_remote), \
                    redirect_stdout(io.StringIO()):
                try:
                    CHECK.collect_server(
                        {"hostname": "server-a", "address": "192.0.2.3"},
                        "root", None, output,
                    )
                except (CHECK.DeployError, OSError, subprocess.CalledProcessError):
                    pass  # Fail-closed is as valid as copying the pinned old owner.
            self.assertFalse(any(
                b"FOREIGN-REMOTE-CONTENT" in path.read_bytes()
                for path in output.rglob("*.log")
            ))

    def test_python_writer_rejects_foreign_log_link_before_callback_or_write(self):
        with tempfile.TemporaryDirectory(prefix="req19-writer-foreign-") as tmp:
            _root, infra, _a, _b = self.fixture(tmp)
            foreign = Path(tmp) / "foreign"
            foreign.mkdir()
            (infra / "logs").symlink_to(os.path.relpath(foreign, infra))
            invoked = []
            with mock.patch.object(DEPLOY, "SCRIPT_DIR", infra), redirect_stdout(io.StringIO()):
                with self.assertRaises((DEPLOY.DeployError, OSError, ValueError)):
                    DEPLOY.run_with_log("deploy_infra", lambda: invoked.append(True) or 0)
            self.assertEqual([], invoked)
            self.assertEqual([], list(foreign.iterdir()))

    def test_pending_receipt_blocks_writer_and_collector_even_with_managed_link(self):
        with tempfile.TemporaryDirectory(prefix="req19-pending-link-") as tmp:
            _root, infra, a, _b = self.fixture(tmp)
            owned = a / "99-output-infra"
            (infra / "logs").symlink_to(os.path.relpath(owned, infra))
            (infra / ".logs-migration.json").write_text("{}", encoding="utf-8")
            invoked = []
            with mock.patch.object(DEPLOY, "SCRIPT_DIR", infra), redirect_stdout(io.StringIO()):
                with self.assertRaises((DEPLOY.DeployError, OSError, ValueError)):
                    DEPLOY.run_with_log("deploy_infra", lambda: invoked.append(True) or 0)
            self.assertEqual([], invoked)
            self.assertEqual([], list(owned.iterdir()))
            probe = "public.status=not_run\nsystem.hostname=isolated-host\n"
            with mock.patch.object(CHECK, "SCRIPT_DIR", infra), mock.patch.object(
                CHECK.subprocess, "run",
                return_value=subprocess.CompletedProcess(["bash", "-s"], 0, probe, ""),
            ) as run, redirect_stdout(io.StringIO()):
                with self.assertRaises((CHECK.DeployError, OSError, ValueError)):
                    CHECK.collect_local(Path(tmp) / "collected")
                run.assert_not_called()

    def test_orphan_receipt_temp_blocks_writer_local_and_remote_collector(self):
        with tempfile.TemporaryDirectory(prefix="req19-orphan-link-") as tmp:
            _root, infra, a, _b = self.fixture(tmp)
            owned = a / "99-output-infra"
            (infra / "logs").symlink_to(os.path.relpath(owned, infra))
            orphan = infra / ".logs-migration.ABC123"
            orphan.write_bytes(b"unpublished receipt bytes\n")
            orphan_inode = orphan.lstat().st_ino
            invoked = []
            with mock.patch.object(DEPLOY, "SCRIPT_DIR", infra), redirect_stdout(io.StringIO()):
                with self.assertRaises((DEPLOY.DeployError, OSError, ValueError)):
                    DEPLOY.run_with_log("deploy_infra", lambda: invoked.append(True) or 0)
            self.assertEqual([], invoked)
            self.assertEqual([], list(owned.iterdir()))
            with mock.patch.object(CHECK, "SCRIPT_DIR", infra), mock.patch.object(
                CHECK.subprocess, "run",
            ) as run, redirect_stdout(io.StringIO()):
                with self.assertRaises((CHECK.DeployError, OSError, ValueError)):
                    CHECK.collect_local(Path(tmp) / "collected")
                run.assert_not_called()
            with self.assertRaises(subprocess.CalledProcessError) as rejection:
                hermetic_probe(infra, Path(tmp))
            self.assertIn("migration", rejection.exception.stderr)
            self.assertEqual(orphan_inode, orphan.lstat().st_ino)
            self.assertEqual(b"unpublished receipt bytes\n", orphan.read_bytes())

            orphan.unlink()
            (infra / ".logs-migrationx").write_bytes(b"unrelated neighbor\n")
            with mock.patch.object(DEPLOY, "SCRIPT_DIR", infra), redirect_stdout(io.StringIO()):
                self.assertEqual(0, DEPLOY.run_with_log("deploy_infra", lambda: 0))
            self.assertEqual(1, len(list(owned.glob("deploy_infra-*.log"))))
            self.assertIn("public.status=not_run", hermetic_probe(infra, Path(tmp)))

    def test_python_writer_open_log_stays_with_original_project_after_repoint(self):
        with tempfile.TemporaryDirectory(prefix="req19-writer-switch-") as tmp:
            _root, infra, a, b = self.fixture(tmp)
            logs = infra / "logs"
            first = a / "99-output-infra"
            second = b / "99-output-infra"
            logs.symlink_to(os.path.relpath(first, infra))

            def switch_after_open():
                temporary = infra / ".logs-test-repoint"
                temporary.symlink_to(os.path.relpath(second, infra))
                os.replace(temporary, logs)
                print("AFTER-REPOINT-OLD-OWNER")
                return 0

            with mock.patch.object(DEPLOY, "SCRIPT_DIR", infra), redirect_stdout(io.StringIO()):
                self.assertEqual(0, DEPLOY.run_with_log("deploy_infra", switch_after_open))
            original = list(first.glob("deploy_infra-*.log"))
            self.assertEqual(1, len(original))
            self.assertIn(b"AFTER-REPOINT-OLD-OWNER", original[0].read_bytes())
            self.assertEqual([], list(second.iterdir()))

    def test_real_shell_tee_keeps_fd3_owner_after_log_link_repoint(self):
        with tempfile.TemporaryDirectory(prefix="req19-shell-tee-") as tmp:
            _root, infra, a, b = self.fixture(tmp)
            logs = infra / "logs"
            first = a / "99-output-infra"
            second = b / "99-output-infra"
            logs.symlink_to(os.path.relpath(first, infra))
            replacement = infra / ".logs-test-repoint"
            replacement.symlink_to(os.path.relpath(second, infra))
            source = (ROOT / "infra/infra-setup.sh").read_text(encoding="utf-8")
            start = source.index("apt_log() {")
            end = source.index("\n}\n\napt_updated=false", start) + 2
            actual_function = source[start:end]
            log_name = "infra-setup-20260924_010203.log"
            script = "\n".join((
                "set -eu",
                f"log_file={shlex.quote(str(logs / log_name))}",
                'exec 3>>"$log_file"',
                f"python3 -c 'import os,sys;os.replace(sys.argv[1],sys.argv[2])' "
                f"{shlex.quote(str(replacement))} {shlex.quote(str(logs))}",
                'info() { printf "%s\\n" "$*" >&3; }',
                'warn() { printf "%s\\n" "$*" >&3; }',
                'success() { printf "%s\\n" "$*" >&3; }',
                'error() { printf "%s\\n" "$*" >&3; }',
                'apt_lock_timeout=1',
                actual_function,
                "apt_log bash -c 'printf SHELL-TEE-OLD-OWNER'",
            ))
            result = subprocess.run(
                ["bash", "-c", script], cwd=infra, text=True,
                capture_output=True, timeout=10,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn(b"SHELL-TEE-OLD-OWNER", (first / log_name).read_bytes())
            self.assertFalse((second / log_name).exists())

    def test_real_shell_log_open_rejects_foreign_link_and_accepts_managed_owner(self):
        with tempfile.TemporaryDirectory(prefix="req19-shell-owner-") as tmp:
            _root, infra, a, _b = self.fixture(tmp)
            logs = infra / "logs"
            outside = Path(tmp) / "outside"
            outside.mkdir()
            fake_bin = Path(tmp) / "bin"
            fake_bin.mkdir()
            flock = fake_bin / "flock"
            flock.write_text(
                "#!/usr/bin/env python3\n"
                "import fcntl, sys\n"
                "fcntl.flock(int(sys.argv[2]), "
                "fcntl.LOCK_EX if sys.argv[1] == '-x' else fcntl.LOCK_UN)\n",
                encoding="utf-8",
            )
            flock.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            for script_name in ("infra-setup.sh", "infra-teardown.sh"):
                source = (ROOT / "infra" / script_name).read_text(encoding="utf-8")
                start = source.index('log_dir="${runtime_dir}/logs"')
                end = source.index('echo "[$(date', start)
                actual_open = source[start:end]
                logs.symlink_to(os.path.relpath(outside, infra))
                shell = "\n".join((
                    "set -euo pipefail", f"runtime_dir={shlex.quote(str(infra))}",
                    actual_open, "printf '%s\\n' OWNED-ONLY >&3",
                ))
                rejected = subprocess.run(
                    ["bash", "-c", shell], cwd=infra, capture_output=True,
                    text=True, timeout=10, env=env,
                )
                self.assertNotEqual(0, rejected.returncode, script_name)
                self.assertEqual([], list(outside.iterdir()), script_name)
                logs.unlink()
                owned = a / "99-output-infra"
                logs.symlink_to(os.path.relpath(owned, infra))
                accepted = subprocess.run(
                    ["bash", "-c", shell], cwd=infra, capture_output=True,
                    text=True, timeout=10, env=env,
                )
                self.assertEqual(0, accepted.returncode, accepted.stderr)
                self.assertTrue(any(b"OWNED-ONLY" in p.read_bytes() for p in owned.glob("infra-*.log")))
                before_receipt = {p.name: p.read_bytes() for p in owned.glob("infra-*.log")}
                receipt = infra / ".logs-migration.json"
                receipt.write_text("{}", encoding="utf-8")
                try:
                    pending = subprocess.run(
                        ["bash", "-c", shell], cwd=infra, capture_output=True,
                        text=True, timeout=10, env=env,
                    )
                    self.assertNotEqual(0, pending.returncode, script_name)
                    self.assertEqual(
                        before_receipt,
                        {p.name: p.read_bytes() for p in owned.glob("infra-*.log")},
                        script_name,
                    )
                finally:
                    receipt.unlink()
                orphan = infra / ".logs-migration.ABC123"
                orphan.write_bytes(b"unpublished receipt bytes\n")
                try:
                    pending = subprocess.run(
                        ["bash", "-c", shell], cwd=infra, capture_output=True,
                        text=True, timeout=10, env=env,
                    )
                    self.assertNotEqual(0, pending.returncode, script_name)
                    self.assertEqual(
                        before_receipt,
                        {p.name: p.read_bytes() for p in owned.glob("infra-*.log")},
                        script_name,
                    )
                    self.assertEqual(b"unpublished receipt bytes\n", orphan.read_bytes())
                finally:
                    orphan.unlink()
                logs.unlink()

    def test_real_shell_log_open_waits_for_independent_log_root_lock(self):
        with tempfile.TemporaryDirectory(prefix="req19-shell-lock-") as tmp:
            _root, infra, _a, _b = self.fixture(tmp)
            fake_bin = Path(tmp) / "bin"
            fake_bin.mkdir()
            flock = fake_bin / "flock"
            flock.write_text(
                "#!/usr/bin/env python3\n"
                "import fcntl, sys\n"
                "fcntl.flock(int(sys.argv[2]), "
                "fcntl.LOCK_EX if sys.argv[1] == '-x' else fcntl.LOCK_UN)\n",
                encoding="utf-8",
            )
            flock.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            source = (ROOT / "infra/infra-teardown.sh").read_text(encoding="utf-8")
            start = source.index('log_dir="${runtime_dir}/logs"')
            end = source.index('echo "[$(date', start)
            actual_open = source[start:end]
            shell = "\n".join((
                "set -euo pipefail", f"runtime_dir={shlex.quote(str(infra))}",
                "printf 'READY\\n'", actual_open,
            ))
            descriptor = os.open(infra / ".logs.lock", os.O_CREAT | os.O_RDWR, 0o600)
            process = None
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                process = subprocess.Popen(
                    ["bash", "-c", shell], cwd=infra, env=env, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                ready, _, _ = select.select([process.stdout], [], [], 10)
                self.assertTrue(ready)
                self.assertEqual("READY\n", process.stdout.readline())
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.wait(timeout=0.4)
                self.assertEqual([], list(infra.glob("logs/infra-teardown-*.log")))
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
                if process is not None:
                    try:
                        _out, error = process.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=5)
                        raise
                    self.assertEqual(0, process.returncode, error)

    def test_python_writer_waits_for_independent_log_root_lock(self):
        with tempfile.TemporaryDirectory(prefix="req19-writer-lock-") as tmp:
            _root, infra, _a, _b = self.fixture(tmp)
            lock_path = infra / ".logs.lock"
            descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            process = None
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                child_code = "\n".join((
                    "from pathlib import Path",
                    "import sys",
                    f"sys.path.insert(0, {str(ROOT)!r})",
                    "from test_cases.module_loader import load_script",
                    f"module = load_script('req19_lock_child', Path({str(ROOT / 'infra/deploy_infra.py')!r}))",
                    "module.SCRIPT_DIR = Path(sys.argv[1])",
                    "print('READY', flush=True)",
                    "module.run_with_log('deploy_infra', lambda: 0)",
                ))
                process = subprocess.Popen(
                    [sys.executable, "-B", "-c", child_code, str(infra)],
                    cwd=ROOT, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                ready, _, _ = select.select([process.stdout], [], [], 10)
                self.assertTrue(ready, "writer did not reach the lock gate")
                self.assertEqual("READY\n", process.stdout.readline())
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.wait(timeout=0.4)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
                if process is not None:
                    try:
                        _out, error = process.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=5)
                        raise
                    self.assertEqual(0, process.returncode, error)

    def test_client_run_error_log_keeps_original_project_after_switch(self):
        with tempfile.TemporaryDirectory(prefix="req19-client-switch-") as tmp:
            root, infra, a, b = self.fixture(tmp)
            logs = infra / "logs"
            first = a / "99-output-infra"
            second = b / "99-output-infra"
            logs.symlink_to(os.path.relpath(first, infra))
            args = SimpleNamespace(
                teardown=True, prepare_only=False, dry_run=False,
                max_workers=1, devices_file=root / "devices.csv", hosts=None,
                user="root", identity=None, setup_script=ROOT / "infra/infra-setup.sh",
                teardown_script=ROOT / "infra/infra-teardown.sh",
                http_server_ip=None,
            )
            server = {"hostname": "server-a", "address": "192.0.2.3"}

            def switch_and_fail(*_args, **_kwargs):
                replacement = infra / ".logs-test-repoint"
                replacement.symlink_to(os.path.relpath(second, infra))
                os.replace(replacement, logs)
                raise DEPLOY.DeployError("isolated injected client failure")

            with ExitStack() as patches:
                patches.enter_context(mock.patch.object(DEPLOY, "SCRIPT_DIR", infra))
                patches.enter_context(mock.patch.object(DEPLOY, "parse_args", return_value=args))
                patches.enter_context(mock.patch.object(DEPLOY, "load_servers", return_value=[server]))
                patches.enter_context(mock.patch.object(DEPLOY, "confirm_teardown_targets", return_value=True))
                patches.enter_context(mock.patch.object(
                    DEPLOY, "prepare_server_access", return_value=("root", None, False, None),
                ))
                patches.enter_context(mock.patch.object(DEPLOY, "deploy_server", side_effect=switch_and_fail))
                patches.enter_context(mock.patch.object(
                    DEPLOY.subprocess, "run",
                    side_effect=lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""),
                ))
                patches.enter_context(redirect_stdout(io.StringIO()))
                self.assertEqual(1, DEPLOY.main())
            original = list(first.glob("clients/*/*.log"))
            self.assertEqual(1, len(original), "one run must retain its client error log in the old project")
            self.assertIn(b"FINAL ERROR: server-a", original[0].read_bytes())
            self.assertEqual([], list(second.rglob("*.log")))

    def test_two_projects_never_move_the_previous_owners_deploy_log(self):
        with tempfile.TemporaryDirectory(prefix="req19-two-projects-") as tmp:
            root, infra, a, b = self.fixture(tmp)
            self.setup_project(root, a)
            with mock.patch.object(DEPLOY, "SCRIPT_DIR", infra), redirect_stdout(io.StringIO()):
                self.assertEqual(0, DEPLOY.run_with_log("deploy_infra", lambda: 0))
            old = list((a / "99-output-infra").glob("deploy_infra-*.log"))
            self.assertEqual(1, len(old))
            bytes_a = old[0].read_bytes()
            self.setup_project(root, b)
            self.assertEqual((b / "99-output-infra").resolve(), (infra / "logs").resolve())
            self.assertEqual(bytes_a, old[0].read_bytes())
            self.assertFalse((b / "99-output-infra" / old[0].name).exists())


if __name__ == "__main__":
    unittest.main()
