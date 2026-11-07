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


if __name__ == "__main__":
    unittest.main()
