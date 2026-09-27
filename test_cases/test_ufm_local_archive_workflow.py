#!/usr/bin/env python3
"""Two-real-script local UFM collection boundary; no remote or vendor call."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import ufm_collection_agent as agent
from tools import ufm_collection_contract as contract


class UfmLocalArchiveWorkflowTests(unittest.TestCase):
    def test_one_run_id_binds_both_exact_archives_and_project_copy_paths(self):
        run_id = contract.make_run_id(
            dt.datetime(2026, 9, 27, 1, 30, tzinfo=dt.timezone.utc),
            "prod", "0123456789abcdef",
        )
        self.assertEqual("20260927-0130-prod-0123456789abcdef", run_id)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "out"
            staging = root / "staging"
            project = root / "project"
            for directory in (output, staging, project):
                directory.mkdir()
            with mock.patch.object(agent.socket, "gethostname", return_value="ufm-a"):
                for kind in ("iblinkinfo", "ibdiagnet"):
                    with self.subTest(kind=kind):
                        plan = contract.collection_plan(kind, run_id)
                        argv_seen = []

                        def fake_vendor(argv):
                            argv_seen.append(tuple(argv))
                            if argv[:2] == ["docker", "cp"]:
                                copied = Path(argv[-1])
                                copied.mkdir()
                                (copied / "ibdiagnet2.net_dump").write_bytes(b"synthetic-network\n")
                            stdout = b"synthetic-links\n" if kind == "iblinkinfo" else b""
                            return agent.InvocationResult(0, stdout, b"")

                        archive = agent.collect_local(
                            plan, output, staging_dir=staging, runner=fake_vendor,
                        )
                        self.assertEqual(output / plan.archive_name, archive)
                        self.assertFalse((output / plan.part_name).exists())
                        self.assertEqual(
                            project / "99-output-ufm" / "runs" / run_id / "ufm-a" / plan.archive_name,
                            contract.project_copy_path(project, plan, "ufm-a"),
                        )
                        self.assertTrue(argv_seen)
                        self.assertFalse(any("*" in part or part == "-it"
                                             for argv in argv_seen for part in argv))
                        with tarfile.open(archive, "r:gz") as bundle:
                            if kind == "iblinkinfo":
                                self.assertEqual(b"synthetic-links\n", bundle.extractfile("artifact").read())
                            else:
                                self.assertEqual(
                                    b"synthetic-network\n",
                                    bundle.extractfile("artifact/ibdiagnet2.net_dump").read(),
                                )

    def test_existing_exact_final_never_invokes_vendor_or_clobbers_archive(self):
        plan = contract.collection_plan(
            "iblinkinfo", "20260927-0130-prod-0123456789abcdef",
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve()
            old = output / plan.archive_name
            old.write_bytes(b"old-exact-name")
            calls = []

            def fake_vendor(argv):
                calls.append(argv)
                return agent.InvocationResult(0, b"new-links\n", b"")

            with mock.patch.object(agent.socket, "gethostname", return_value="ufm-a"):
                with self.assertRaises(agent.AgentError):
                    agent.collect_local(plan, output, runner=fake_vendor)
            self.assertEqual([], calls)
            self.assertEqual(b"old-exact-name", old.read_bytes())
            self.assertFalse((output / plan.part_name).exists())
            self.assertFalse((output / ".ufm-iblinkinfo.lock").exists())

    def test_failed_local_vendor_leaves_no_retrievable_run_product(self):
        plan = contract.collection_plan(
            "iblinkinfo", "20260927-0130-prod-0123456789abcdef",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "out"
            project = root / "project"
            output.mkdir()
            project.mkdir()
            calls = []

            def failed_vendor(argv):
                calls.append(tuple(argv))
                return agent.InvocationResult(7, b"", b"private-vendor-diagnostic")

            with mock.patch.object(agent.socket, "gethostname", return_value="ufm-a"):
                with self.assertRaises(agent.AgentError) as raised:
                    agent.collect_local(plan, output, runner=failed_vendor)
            self.assertEqual([plan.vendor_argv], calls)
            self.assertNotIn("private-vendor-diagnostic", str(raised.exception))
            self.assertFalse((output / plan.archive_name).exists())
            self.assertFalse((output / plan.part_name).exists())
            self.assertFalse((output / ".ufm-iblinkinfo.lock").exists())
            self.assertFalse(contract.project_copy_path(project, plan, "ufm-a").exists())


if __name__ == "__main__":
    unittest.main()
