"""Q4: in a managed run the managed tool root is the only infra-neutral.conf source.

Contract (merge decision Q4, confirmed by http test 2026-10-25): the file must be a
regular, non-symlink, single-link file owned by the running user and not group/other
writable, admitted before any leaf output, and unchanged whenever the managed cycle
re-observes its inputs (cache reuse included). Its content must satisfy the leaf's own
self-contained grammar (TEST I15 reader, the stricter rule where TEST is stricter):
UTF-8 KEY=VALUE lines, comments and blank lines skipped, only DNS/NTP/TIMEZONE, no
duplicates, all three present and non-empty. No fallback (for example the
project-level infra/infra-neutral.conf) may stand in for it. Non-managed runs are
unaffected.
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
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
NEUTRAL = b"DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n"


class ManagedNeutralSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = load_script("managed_neutral_source_authority", AUTHORITY)
        cls.initial = load_script("managed_neutral_source_initial", INITIAL)

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
                cycle = self.authority.ManagedInitialMethodCycle(project, self.initial)
                if case == "regular":
                    self.admit(cycle, project)
                else:
                    with self.assertRaises(self.authority.AuthorityError):
                        self.admit(cycle, project)
                self.assertFalse((project / "reports").exists(), "admission never creates outputs")
                self.assertFalse((project / "99-output-ztp").exists())
                self.assertEqual(NEUTRAL, (project / "infra/infra-neutral.conf").read_bytes())

    def test_admission_applies_the_leaf_neutral_grammar(self):
        cases = {
            "commented": (b"# project neutral services\n\n" + NEUTRAL, True),
            "duplicate-key": (NEUTRAL + b"DNS=192.0.2.53\n", False),
            "missing-key": (b"DNS=8.8.8.8\nNTP=ntp.ubuntu.com\n", False),
            "empty-value": (b"DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE= \n", False),
            "unknown-key": (NEUTRAL + b"SYSLOG=192.0.2.10\n", False),
            "no-separator": (NEUTRAL + b"DNS\n", False),
            "not-utf8": (b"DNS=8.8.8.8\nNTP=\xff\nTIMEZONE=Etc/UTC\n", False),
            "empty-file": (b"", False),
        }
        for case, (raw, accepted) in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                project, tool = self.project(directory)
                neutral = tool / "infra-neutral.conf"
                neutral.write_bytes(raw)
                neutral.chmod(0o644)
                cycle = self.authority.ManagedInitialMethodCycle(project, self.initial)
                if accepted:
                    self.admit(cycle, project)
                else:
                    with self.assertRaises(self.authority.AuthorityError):
                        self.admit(cycle, project)
                self.assertFalse((project / "reports").exists(), "admission never creates outputs")
                self.assertEqual(raw, neutral.read_bytes(), "admission never rewrites the source")

    def test_reobservation_requires_the_admitted_neutral_image(self):
        for case in ("unchanged", "replaced", "rewritten-invalid", "never-admitted"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                project, tool = self.project(directory)
                neutral = tool / "infra-neutral.conf"
                neutral.write_bytes(NEUTRAL)
                neutral.chmod(0o644)
                target = SimpleNamespace(ib=SimpleNamespace(hostname="EXAMPLE-IB01", dev_type="ib"))
                parser = SimpleNamespace(load_target_cache=lambda *args, **kwargs: (1, [target]),
                                         _neutral_services=self.initial._neutral_services)
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
                if case == "rewritten-invalid":
                    neutral.write_bytes(NEUTRAL + NEUTRAL)
                if case == "unchanged":
                    self.assertTrue(cycle._inputs(), "positive control: the admitted image re-observes")
                else:
                    with self.assertRaises(self.authority.AuthorityError):
                        cycle._inputs()


    def test_monitor_reader_binds_the_tool_root_neutral_image(self):
        # The read-only monitor binder re-observes the same held inputs as the writer, so it
        # captures the managed tool root's neutral image itself; it never admits outputs.
        import json
        cases = ("unchanged", "explicit-tool-root", "missing", "explicit-root-missing", "rewritten-invalid", "replaced")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                project, tool = self.project(directory)
                if case in ("explicit-tool-root", "explicit-root-missing"):
                    # explicit-tool-root: only the passed root has a neutral file.
                    # explicit-root-missing: only the default root has a qualified one; it never stands in.
                    if case == "explicit-root-missing":
                        (tool / "infra-neutral.conf").write_bytes(NEUTRAL)
                        (tool / "infra-neutral.conf").chmod(0o644)
                    tool = project / "99-output-ib_nvl/bringup/xdr-initial-setup"
                    (tool / "publickey").mkdir(parents=True)
                    for name in ("01-global.yaml", "publickey/management.pub"):
                        (tool / name).write_text("independent finite fixture bytes\n")
                        (tool / name).chmod(0o644)
                neutral = tool / "infra-neutral.conf"
                if case not in ("missing", "explicit-root-missing"):
                    neutral.write_bytes(NEUTRAL)
                    neutral.chmod(0o644)
                cache = project / "out/targets.json"
                cache.write_text(json.dumps({"services": {"dns": ["192.0.2.53"]}, "public_keys": ["key"]}))
                target = SimpleNamespace(ib=SimpleNamespace(hostname="EXAMPLE-IB01", dev_type="ib"))
                parser = SimpleNamespace(load_target_cache=lambda *args, **kwargs: (1, [target]),
                                         desired_service_commands=lambda *args: [],
                                         key_install_command=lambda *args: "",
                                         _neutral_services=self.initial._neutral_services)
                build = lambda: self.authority.InitialMethodMonitorInputs(
                    project, parser, tool, cache, project / "ib.csv", project / "p2p.dot")
                if case in ("missing", "explicit-root-missing"):
                    # No fallback to the default root or to project-level infra/infra-neutral.conf.
                    with self.assertRaisesRegex(self.authority.AuthorityError, "unavailable"):
                        build()
                    continue
                reader = build()
                self.assertEqual(tool, reader.tool_input_root)
                if case in ("unchanged", "explicit-tool-root"):
                    reader.recheck()  # positive control: the captured image re-observes
                    continue
                if case == "replaced":
                    replacement = tool / "replacement.conf"
                    replacement.write_bytes(NEUTRAL)
                    replacement.chmod(0o644)
                    os.replace(replacement, neutral)
                else:
                    neutral.write_bytes(NEUTRAL + NEUTRAL)
                with self.assertRaises(self.authority.AuthorityError):
                    reader.recheck()
                self.assertFalse((project / "99-output-ztp").exists(), "the read-only binder publishes nothing")


if __name__ == "__main__":
    unittest.main()
