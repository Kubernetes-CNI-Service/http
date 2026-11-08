"""R-016 §4.4 workflow (v3.1.1 WP-6): setup, unsetup, the reader, and setup again, with real scripts.

Each case copies the git-indexed workspace (test_project_link_inputs_workflow.LinkedProjectSandbox: no
test_cases, no project data, no runtime links) and runs, as subprocesses:
1. DAY0-Prepare/01-a-setup.py: activates a synthetic project from examples/public-project;
2. DAY0-Prepare/02-unsetup.py -y;
3. the reader tools/project_contract.py::active_project_dir on the copied tree;
4. DAY0-Prepare/01-a-setup.py again.

Expected values (never read back from the scripts):
- R-016 详细设计 v1.1 §4.4 (Q1-Q7 「好的」, owner 2026-11-03): unsetup unlinks DAY0-Prepare/activate-project
  and deletes .setup_manifest; §5.1: afterwards active_project_dir() reports no active project (None).
- Q7: the fixed links of the table stay as they were; dangling, they mean "no project is active".
- O14 (owner 2026-11-07 「同意你的建议。」 via http dev): the per-key links of the four key directories go.
- 详细工作指导 WP-6 「文档」: running setup once more restores the project: the pointer and every fixed link
  resolve again, with the same text as before.

Depends on WP-3 (setup builds the pointer and pointer-form links, R-016 §4.2) and WP-9b (unsetup's infra/logs
gate accepts the pointer-form link); RED until both land.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest

from test_cases import test_project_link_inputs_workflow as LINKED
from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = load_script("activate_project_unsetup_workflow_contract", ROOT / "tools/project_contract.py")


class ActivateProjectUnsetupWorkflowTests(unittest.TestCase):
    def sandbox(self):
        directory = tempfile.TemporaryDirectory(prefix="activate-project-unsetup-")
        self.addCleanup(directory.cleanup)
        sandbox = LINKED.LinkedProjectSandbox(Path(directory.name).resolve())
        (sandbox.project / "02-devices_config.csv").write_bytes(sandbox.devices)
        LINKED.workbook(sandbox.project / "Site P2P_v1.0.xlsx", "selected")
        return sandbox

    @staticmethod
    def links(root: Path, names) -> dict[str, str]:
        return {name: os.readlink(root / name) for name in names if (root / name).is_symlink()}

    @staticmethod
    def key_links(root: Path) -> set[str]:
        return {os.path.relpath(path, root)
                for pattern in CONTRACT.setup_dynamic_link_patterns()
                for path in glob.glob(os.fspath(root / pattern)) if os.path.islink(path)}

    def assert_active(self, sandbox, run) -> None:
        self.assertEqual(0, run.returncode, run.stdout)
        pointer = sandbox.http / "DAY0-Prepare/activate-project"
        self.assertTrue(pointer.is_symlink(), "R-016 §4.2 step 4: setup activates the project through the pointer")
        self.assertEqual(LINKED.PROJECT, os.readlink(pointer))
        self.assertEqual(sandbox.project.resolve(), CONTRACT.active_project_dir(sandbox.http))

    def test_unsetup_leaves_dangling_fixed_links_and_setup_restores_them(self):
        sandbox = self.sandbox()
        http = sandbox.http
        table = [path for path, _text in CONTRACT.pointer_link_specs()]

        self.assert_active(sandbox, sandbox.setup())
        fixed = self.links(http, table)
        resolving = {name for name in fixed if (http / name).exists()}
        keys = self.key_links(http)
        self.assertIn("monitor/01-global.yaml", resolving, "fixture: setup bound the project")
        self.assertIn("ztp/config/publickey/laptop.pub", keys, "fixture: setup linked the project's key")

        unsetup = sandbox.run([sys.executable, "-B", os.fspath(http / "DAY0-Prepare/02-unsetup.py"), "-y"])
        self.assertEqual(0, unsetup.returncode, unsetup.stdout)
        self.assertFalse(os.path.lexists(http / "DAY0-Prepare/activate-project"), "R-016 §4.4: pointer unlinked")
        self.assertFalse(os.path.lexists(http / "ztp/.setup_manifest"), "R-016 §4.4: manifest deleted")
        # The reader: R-016 §5.1, None means no active project.
        self.assertIsNone(CONTRACT.active_project_dir(http))
        self.assertEqual(fixed, self.links(http, table), "Q7: every fixed link stays as it was")
        for name in sorted(resolving):
            with self.subTest(dangling=name):
                self.assertFalse((http / name).exists(), "Q7: dangling means no project is active")
        self.assertEqual(set(), self.key_links(http), "O14: per-key links go")

        self.assert_active(sandbox, sandbox.setup())
        self.assertEqual(fixed, self.links(http, table), "WP-6: setup again restores the same links")
        for name in sorted(resolving):
            with self.subTest(restored=name):
                self.assertTrue((http / name).exists(), "WP-6: setup again restores the project")
        self.assertEqual(keys, self.key_links(http))
        self.assertTrue((http / "ztp/.setup_manifest").is_file())



class UNLUnloadTeardownAfterUnsetupWorkflowTests(unittest.TestCase):
    """v3.1.1 UNL (owner option A, http dev 2026-11-08), real scripts on a copied workspace:
    01-a-setup.py activates the project; 13-unload.py --dry-run --teardown-infra lists the teardown command (it
    resolves the project before its unsetup step); 02-unsetup.py -y removes the pointer (R-016 Q7: infra/logs
    stays setup's link and dangles); infra/infra-teardown.sh, run through its option parsing and log binding only,
    then takes exactly the arguments 13-unload listed and writes its log into the project's 99-output-infra.
    Without --log-dir in that state it refuses and names the option.  Expected values come from the work order
    and R-016 Q7, not from the scripts.
    """

    MANAGED_LOG_LINK = "../DAY0-Prepare/activate-project/99-output-infra"

    def test_unload_hands_teardown_the_project_log_dir_that_survives_real_unsetup(self):
        from test_cases.test_req19_infra_log_contract import fake_flock_bin, teardown_log_binding

        directory = tempfile.TemporaryDirectory(prefix="activate-project-unl-")
        self.addCleanup(directory.cleanup)
        sandbox = LINKED.LinkedProjectSandbox(Path(directory.name).resolve())
        (sandbox.project / "02-devices_config.csv").write_bytes(sandbox.devices)
        LINKED.workbook(sandbox.project / "Site P2P_v1.0.xlsx", "selected")
        http = sandbox.http
        pointer = http / "DAY0-Prepare/activate-project"
        owned = sandbox.project / "99-output-infra"

        setup = sandbox.setup()
        self.assertEqual(0, setup.returncode, setup.stdout)
        self.assertTrue(pointer.is_symlink(), "fixture: setup activated the project")
        self.assertEqual(self.MANAGED_LOG_LINK, os.readlink(http / "infra/logs"))
        self.assertTrue(owned.is_dir() and not owned.is_symlink(), "fixture: the project's real infra output")

        planned = sandbox.run([sys.executable, "-B", os.fspath(http / "DAY0-Prepare/13-unload.py"),
                               "--dry-run", "--teardown-infra"])
        self.assertEqual(0, planned.returncode, planned.stdout)
        self.assertTrue(pointer.is_symlink(), "a dry-run unload removes nothing")
        listed = [line for line in planned.stdout.splitlines()
                  if line.startswith("[DRY]") and "infra-teardown.sh" in line]
        self.assertEqual(1, len(listed), planned.stdout)
        command = shlex.split(listed[0][len("[DRY]"):])
        teardown = http / "infra/infra-teardown.sh"
        self.assertEqual(["bash", os.fspath(teardown), "--non-interactive", "--yes",
                          "--log-dir", os.fspath(sandbox.project.resolve() / "99-output-infra")], command)

        unsetup = sandbox.run([sys.executable, "-B", os.fspath(http / "DAY0-Prepare/02-unsetup.py"), "-y"])
        self.assertEqual(0, unsetup.returncode, unsetup.stdout)
        self.assertFalse(os.path.lexists(pointer), "R-016 §4.4: unsetup removed the pointer")
        self.assertEqual(self.MANAGED_LOG_LINK, os.readlink(http / "infra/logs"), "Q7: the fixed link stays")

        fake_bin = fake_flock_bin(sandbox.base)
        refused = teardown_log_binding(teardown, http / "infra", fake_bin, "--non-interactive", "--yes")
        self.assertEqual(1, refused.returncode, refused.stdout)
        self.assertIn("--log-dir DAY0-Prepare/<project>/99-output-infra", refused.stderr)
        self.assertEqual([], sorted(owned.glob("infra-teardown-*.log")))

        bound = teardown_log_binding(teardown, http / "infra", fake_bin, *command[2:])
        self.assertEqual(0, bound.returncode, bound.stderr)
        written = sorted(owned.glob("infra-teardown-*.log"))
        self.assertEqual(1, len(written))
        self.assertEqual(written[0].resolve(), Path(bound.stdout.splitlines()[-1]).resolve())
        self.assertIn(b"UNL-BOUND", written[0].read_bytes())
        self.assertFalse(os.path.lexists(pointer), "teardown never reactivates a project")


if __name__ == "__main__":
    unittest.main()
