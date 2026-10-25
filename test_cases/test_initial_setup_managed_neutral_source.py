"""Q4: in a managed run the managed tool root is the only infra-neutral.conf source.

Contract (merge decision Q4, 2026-10-25, pending http test confirmation): the file
must be a regular, non-symlink, single-link file owned by the running user and not
group/other writable, admitted before any leaf output, and unchanged whenever the
managed cycle re-observes its inputs. No fallback (for example the project-level
infra/infra-neutral.conf) may stand in for it. Non-managed runs are unaffected.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "ztp/config_sync_authority.py"
NEUTRAL = b"DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n"


class ManagedNeutralSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = load_script("managed_neutral_source_authority", AUTHORITY)

    def project(self, directory: str):
        project = Path(directory).resolve() / "project"
        tool = project / "infiniband/bringup/xdr-initial-setup"
        (tool / "publickey").mkdir(parents=True)
        for path in (project / "ib.csv", project / "p2p.dot", project / "out/targets.json",
                     project / "out/targets.json.sha256", tool / "01-global.yaml", tool / "publickey/management.pub"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("independent finite fixture bytes\n")
            path.chmod(0o644)
        # A valid project-level copy that must never be borrowed.
        (project / "infra").mkdir()
        (project / "infra/infra-neutral.conf").write_bytes(NEUTRAL)
        return project, tool

    def admit(self, cycle, project):
        cycle.admit_paths((project / "ib.csv", project / "p2p.dot"),
                          (project / "reports/out/targets.json", project / "reports/report.log",
                           project / "reports/snapshots"))

    def test_admission_requires_regular_owned_single_link_neutral_in_tool_root(self):
        cases = ("missing", "symlink", "group-writable", "directory", "hard-link", "regular")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                project, tool = self.project(directory)
                neutral = tool / "infra-neutral.conf"
                if case == "symlink":
                    (tool / "neutral-source.conf").write_bytes(NEUTRAL)
                    neutral.symlink_to("neutral-source.conf")
                elif case == "directory":
                    neutral.mkdir()
                elif case != "missing":
                    neutral.write_bytes(NEUTRAL)
                    neutral.chmod(0o664 if case == "group-writable" else 0o644)
                    if case == "hard-link":
                        os.link(neutral, tool / "second-name.conf")
                cycle = self.authority.ManagedInitialMethodCycle(project, SimpleNamespace())
                if case == "regular":
                    self.admit(cycle, project)
                else:
                    with self.assertRaises(self.authority.AuthorityError):
                        self.admit(cycle, project)
                self.assertFalse((project / "reports").exists(), "admission never creates outputs")
                self.assertFalse((project / "99-output-ztp").exists())
                self.assertEqual(NEUTRAL, (project / "infra/infra-neutral.conf").read_bytes())

    def test_reobservation_requires_the_admitted_neutral_image(self):
        for case in ("unchanged", "replaced", "never-admitted"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                project, tool = self.project(directory)
                neutral = tool / "infra-neutral.conf"
                neutral.write_bytes(NEUTRAL)
                neutral.chmod(0o644)
                target = SimpleNamespace(ib=SimpleNamespace(hostname="EXAMPLE-IB01", dev_type="ib"))
                parser = SimpleNamespace(load_target_cache=lambda *args, **kwargs: (1, [target]))
                cycle = self.authority.ManagedInitialMethodCycle(project, parser)
                cycle.tool, cycle.cache = tool, project / "out/targets.json"
                cycle.csv, cycle.p2p, cycle.targets = project / "ib.csv", project / "p2p.dot", [target]
                if case != "never-admitted":
                    self.admit(cycle, project)
                if case == "replaced":
                    replacement = tool / "replacement.conf"
                    replacement.write_bytes(NEUTRAL)
                    replacement.chmod(0o644)
                    os.replace(replacement, neutral)
                if case == "unchanged":
                    self.assertTrue(cycle._inputs(), "positive control: the admitted image re-observes")
                else:
                    with self.assertRaises(self.authority.AuthorityError):
                        cycle._inputs()


if __name__ == "__main__":
    unittest.main()
