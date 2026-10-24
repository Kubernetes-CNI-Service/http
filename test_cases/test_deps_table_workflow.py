"""Unified dependency table workflow: infra/deps.py → cron.sh, Dockerfile → activate.py, table ↔ upgrade.py.

Scenarios across real scripts: deps.py installs the cabletracker venv (fake base python, temporary
HOME, no network) and cron.sh's real issue_tracker_sync() then selects it; the image build installs
the engine list before activate.py's engine gate and couples that list to the image; the table's
venv paths are the ones cron.sh and upgrade.py use; the files check of every hard-coded copy is
green on the repository; the new files travel with sync/upload/image.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_cases.module_loader import load_script
from test_cases.test_deps_table import LINUX_312, run_deps, write_fake_python
from test_cases.test_issue_tracker_engine_runtime import CONTAINER_PYTHON, cron_function


ROOT = Path(__file__).resolve().parents[1]
ENGINE = "infra/docker/requirements-issue-tracker-engine.txt"
IBSW = "infra/requirements-ibsw-upgrade.txt"
TABLE = "infra/dependencies.json"
NEW_FILES = ("infra/deps.py", TABLE, ENGINE, IBSW)
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
        self.assertLess(text.index(INSTALL + "infra/docker/requirements-req7-cable-sync.txt"), text.index(engine_install))
        for gate in ("verify-python-runtime", "verify-req7-python-runtime", "verify-req7-cable-python-runtime"):
            self.assertLess(text.index(engine_install), text.index(GATE + gate + " "))
            self.assertLess(text.index(GATE + gate + " "), text.index(engine_gate))
        activate = load_script("deps_workflow_activate", ROOT / "infra/docker/activate.py")
        self.assertEqual(ENGINE, activate.ISSUE_TRACKER_ENGINE_REQUIREMENTS)
        self.assertIn(ENGINE, activate.IMAGE_COUPLED_SOURCE_PATHS)
        # The table itself and the native-only ibsw list are not image-coupled: editing them must not
        # force an image rebuild.
        self.assertNotIn(TABLE, activate.IMAGE_COUPLED_SOURCE_PATHS)
        self.assertNotIn(IBSW, activate.IMAGE_COUPLED_SOURCE_PATHS)
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
        for expected in (
            "infra/docker/activate.py::ISSUE_TRACKER_ENGINE_IMPORTS",
            "infra/docker/activate.py::CONTAINER_TOPLEVEL_REQUIREMENTS",
            "infra/docker/Dockerfile::apt-get install",
            "infra/infra-setup.py::MGMT_CACHE_PACKAGES",
            "tools/tar-for-upload.py::REQUIRED_OFFLINE_PACKAGES",
            "tools/ibsw_upgrade_observer.py::SSH_RUNTIME_PINS",
            "tools/f01_ssh_dependency_identity.py::_PINS",
            "tools/req7_cable_dependency_contract.py::PINS",
            "infiniband/bringup/xdr-upgrade/upgrade.py::_RUNTIME_VENV_PATHS",
            "DAY0-Prepare/11-load.py::MACOS_GENERATION_MODULES",
            ENGINE, IBSW,
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


if __name__ == "__main__":
    unittest.main()
