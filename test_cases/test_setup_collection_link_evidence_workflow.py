"""R0 (2026-10-23): v2 collection evidence through setup's collection output links.

setup makes <network>/monitor/<output> (eth-info, spx-link, ib-info, ib-link, nvsw-info, nvsw-link,
ufm-info, ufm-ibdiagnet) links to ../../DAY0-Prepare/<project>/99-output-monitor/<network>/<output>
(tools/project_contract.py::MONITOR_RUNTIME_MAPPINGS). cron.sh hands the emitter its archives below those
links; the evidence readers refused any symlink on the way, so on a real management server every worker
slot failed v2 publication (checked 2026-10-23 with a probe of collection_v2_emitter.regular_member).
Exactly those links, pointing exactly at their project directory, may now be walked; any other link is
still refused. Evidence bytes stay bound by sha256."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.collection_ib_cycle_binding import IbCycleRoleGap, inspect_completed_ib_cycle_roles
from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError, _safe_child
from test_cases.test_collection_cycle_persistence import WORKER
from test_cases.test_collection_ib_cycle_binding_workflow import ProdCycleFixture
from test_cases.test_collection_v2_emitter_contract import EMITTER
from tools.project_contract import setup_collection_link_hop

OUTPUTS = {"ethernet": ("eth-info", "spx-link"), "infiniband": ("ib-info", "ib-link"),
           "nvlink": ("nvsw-info", "nvsw-link")}


def link_outputs(root: Path, project: str = "site") -> None:
    for network, outputs in OUTPUTS.items():
        for output in outputs:
            real = root / "DAY0-Prepare" / project / "99-output-monitor" / network / output
            real.mkdir(parents=True, exist_ok=True)
            link = root / network / "monitor" / output
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(f"../../DAY0-Prepare/{project}/99-output-monitor/{network}/{output}")


class SetupCollectionLinkHopTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        link_outputs(self.root)

    def test_exactly_the_setup_collection_links_are_walkable(self):
        for network, outputs in OUTPUTS.items():
            for output in outputs:
                with self.subTest(link=f"{network}/monitor/{output}"):
                    self.assertTrue(setup_collection_link_hop(self.root, self.root / network / "monitor" / output))
        ufm = self.root / "DAY0-Prepare/site/99-output-monitor/infiniband/ufm-ibdiagnet"
        ufm.mkdir(parents=True)
        (self.root / "infiniband/monitor/ufm-ibdiagnet").symlink_to(
            "../../DAY0-Prepare/site/99-output-monitor/infiniband/ufm-ibdiagnet")
        self.assertTrue(setup_collection_link_hop(self.root, self.root / "infiniband/monitor/ufm-ibdiagnet"))

    def test_any_other_link_is_refused(self):
        monitor = self.root / "infiniband/monitor"
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        cases = {
            "absolute target": str(self.root / "DAY0-Prepare/site/99-output-monitor/infiniband/ib-info"),
            "other directory": "../../elsewhere",
            "another network's directory": "../../DAY0-Prepare/site/99-output-monitor/nvlink/nvsw-info",
            "a dot project": "../../DAY0-Prepare/./99-output-monitor/infiniband/ib-info",
        }
        for label, target in cases.items():
            with self.subTest(label=label):
                (monitor / "ib-info").unlink()
                (monitor / "ib-info").symlink_to(target)
                self.assertFalse(setup_collection_link_hop(self.root, monitor / "ib-info"))
        (monitor / "ib-info").unlink()
        (monitor / "ib-info").symlink_to("../../DAY0-Prepare/site/99-output-monitor/infiniband/ib-info")
        # a link name setup never makes, and a path that is not a link at all
        (monitor / "notes").symlink_to("../../DAY0-Prepare/site/99-output-monitor/infiniband/ib-info")
        self.assertFalse(setup_collection_link_hop(self.root, monitor / "notes"))
        self.assertFalse(setup_collection_link_hop(self.root, self.root / "DAY0-Prepare"))
        # the project directory behind the link must itself be real
        real_project = self.root / "DAY0-Prepare/site"
        real_project.rename(self.root / "DAY0-Prepare/site-real")
        real_project.symlink_to("site-real")
        self.assertFalse(setup_collection_link_hop(self.root, monitor / "ib-info"))

    def test_the_three_walkers_follow_the_rule(self):
        archive = self.root / "DAY0-Prepare/site/99-output-monitor/infiniband/ib-info/20261023-0110.tar.gz"
        archive.write_bytes(b"archive")
        relative = "infiniband/monitor/ib-info/20261023-0110.tar.gz"
        with mock.patch.object(EMITTER, "ROOT", self.root):
            self.assertEqual((relative, b"archive"),
                             EMITTER.regular_member(self.root / relative, "infiniband", "ib-info", ".tar.gz"))
        self.assertEqual(self.root / relative, _safe_child(self.root, relative))
        self.assertEqual(self.root / relative, WORKER._collection_artifact_path(self.root, relative))
        (self.root / "infiniband/monitor/ib-info").unlink()
        (self.root / "infiniband/monitor/ib-info").symlink_to("../../elsewhere-ib-info")
        (self.root / "elsewhere-ib-info").mkdir()
        (self.root / "elsewhere-ib-info/20261023-0110.tar.gz").write_bytes(b"archive")
        with mock.patch.object(EMITTER, "ROOT", self.root), self.assertRaisesRegex(ValueError, "symlink"):
            EMITTER.regular_member(self.root / relative, "infiniband", "ib-info", ".tar.gz")
        with self.assertRaises(SwitchRuntimeHoldError):
            _safe_child(self.root, relative)
        with self.assertRaisesRegex(ValueError, "symlink"):
            WORKER._collection_artifact_path(self.root, relative)


class SetupLinkedCollectionCycleWorkflowTest(ProdCycleFixture, unittest.TestCase):
    """The real emitter and completion store with every collection output behind its setup link."""

    def setUp(self):
        super().setUp()
        link_outputs(self.root)

    def test_a_cycle_collected_behind_setup_links_completes_and_replays(self):
        identity, artifacts = self._cycle()
        info = artifacts["infiniband/prod"]["info"]
        self.assertTrue((self.root / "infiniband/monitor/ib-info").is_symlink())
        self.assertTrue((self.root / "DAY0-Prepare/site/99-output-monitor/infiniband/ib-info" / info.name).is_file(),
                        "the archive physically lives in the project directory")
        [cycle] = read_completed_cycle_evidence(self.store)
        self.assertTrue(cycle.qualifying)
        gap = inspect_completed_ib_cycle_roles(self.store, http_root=self.root, sequence=identity["sequence"])
        self.assertIsInstance(gap, IbCycleRoleGap, "the IB base roles replay through the links")


if __name__ == "__main__":
    unittest.main()
