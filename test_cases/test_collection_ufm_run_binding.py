"""Direct: monitor/collection_ufm_run_binding.py binds one worker cycle's UFM IB analysis (REQ7 R1,
2026-10-23). The run record of cron.sh's UFM lane and post-collect.py's receipt are written here as the
real scripts write them (UFM-MONITOR.md 13, 14.6); the report provenance reader is replaced by a stand-in
returning what ztp/config/ib_topology_provenance.py would record, since its CVT replay is covered by
test_req7_ib_provenance and the workflow test runs the real converter and analyzer."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor import collection_ufm_run_binding as binding_module
from tools.project_contract import canonical_collection_cycle_json, collection_cycle_project_key

RUN_ID = "20261023-0110-prod-0123456789abcdef"
NODE = "ufm02"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def cycle_identity(project: Path, sequence: int = 7) -> dict:
    body = {"project_key": collection_cycle_project_key(str(project)), "run_token": "0123456789ab4def8123456789abcdef",
            "scope": "prod", "sequence": sequence, "source": "switch_collection"}
    return {**body, "cycle_id": sha(canonical_collection_cycle_json(body))}


class Tree:
    """A project with one successful UFM run as cron.sh and post-collect.py leave it."""

    def __init__(self, root: Path, *, kind: str = "ibdiagnet", outcome: str = "ok", identity=None):
        self.root = root
        self.project = root / "DAY0-Prepare/site"
        self.collected = self.project / "99-output-monitor/infiniband/ufm-ibdiagnet"
        self.reports = self.project / "99-output-p2p"
        self.collected.mkdir(parents=True)
        self.reports.mkdir(parents=True)
        self.identity = identity or cycle_identity(self.project.resolve())
        suffix = {"ibdiagnet": "ibdiagnet2.tgz", "iblinkinfo": "iblinkinfo.log"}[kind]
        self.input = self.collected / f"{RUN_ID}_{NODE}_{suffix}"
        self.input.write_bytes(b"ufm data " + kind.encode())
        self.done = self.collected / f"{RUN_ID}_{NODE}_{suffix.rsplit('.', 1)[0]}.done"
        self.done.write_text("rc=0\nreason=\nhostname=ufm02.example.test\n", encoding="utf-8")
        self.cvt = self.reports / "site-cvt.xlsx"
        self.cvt.write_bytes(b"cvt workbook")
        stem = f"{RUN_ID}_{NODE}-{kind}-topology-validation"
        self.report = self.reports / f"{stem}.xlsx"
        self.report.write_bytes(b"PK report")
        self.provenance = self.reports / f"{stem}.xlsx.provenance.json"
        self.provenance.write_text('{"schema": "ib-report-provenance-v1"}\n', encoding="utf-8")
        receipt = {
            "schema": "ufm-ib-report-receipt-v1", "run_id": RUN_ID, "node": NODE, "kind": kind,
            "degraded": kind == "iblinkinfo",
            "collector": {"rc": "0", "reason": "", "hostname": "ufm02.example.test"},
            "done": self.named(self.done, sized=False), "input": self.named(self.input, sized=False),
            "cvt": self.named(self.cvt, sized=False), "report": self.named(self.report, sized=False),
            "provenance": self.named(self.provenance, sized=False),
            "created_at": "2026-10-23T01:20:00+00:00",
        }
        self.receipt = self.reports / f"{stem}.receipt.json"
        self.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        self.record = self.collected / f"{RUN_ID}.ufm-run.json"
        self.write_record({
            "schema": "ufm-ib-run-record-v1", "cycle": self.identity,
            "recorded_at": "2026-10-23T01:21:00+00:00", "outcome": outcome, "reason": "",
            "run_id": RUN_ID, "node": NODE, "kind": kind,
            "done": self.named(self.done), "input": self.named(self.input),
            "analysis": "ok" if outcome == "ok" else "not_run",
            "report": self.named(self.report), "receipt": self.named(self.receipt),
            "ibdiagnet_failures_in_a_row": 0,
        })

    @staticmethod
    def named(path: Path, *, sized: bool = True) -> dict:
        raw = path.read_bytes()
        return {"name": path.name, "sha256": sha(raw), **({"size": len(raw)} if sized else {})}

    def write_record(self, record: dict) -> None:
        self.record_document = record
        self.record.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def provenance_reader(self, report: Path) -> dict:
        """What ib_topology_provenance.read_report_provenance returns for this report."""
        def identity(path: Path) -> dict:
            real = path.resolve()
            return {"path": str(path), "resolved_path": str(real), "kind": "file",
                    "sha256": sha(real.read_bytes())}
        if report.resolve() != self.report.resolve():
            raise AssertionError(f"provenance read for another report: {report}")
        return {"schema": "ib-report-provenance-v1", "report": identity(self.report),
                "cvt": identity(self.cvt), "expected_topology_sha256": sha(self.cvt.read_bytes()),
                "cvt_provenance_sha256": "0" * 64, "actual": identity(self.input),
                "profile": identity(self.cvt)}


class UfmRunBindingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def tree(self, **kwargs) -> Tree:
        tree = Tree(self.root, **kwargs)
        patcher = mock.patch("ztp.config.ib_topology_provenance.read_report_provenance",
                             side_effect=tree.provenance_reader)
        patcher.start()
        self.addCleanup(patcher.stop)
        return tree

    def derive(self, tree: Tree, record=None):
        return binding_module.derive_ufm_run_roles(tree.identity, record or tree.record, http_root=self.root)

    def assert_hold(self, tree: Tree, message: str, record=None):
        with self.assertRaisesRegex(binding_module.UfmRunBindingHold, message):
            self.derive(tree, record)

    def test_a_successful_run_binds_seven_real_path_roles_and_replays_exactly(self):
        tree = self.tree()
        roles, binding = self.derive(tree)
        self.assertEqual(list(binding_module.UFM_RUN_ROLE_NAMES), [role["role"] for role in roles])
        paths = {role["role"]: role["relative_path"] for role in roles}
        self.assertEqual({
            "ufm_run_record": f"DAY0-Prepare/site/99-output-monitor/infiniband/ufm-ibdiagnet/{RUN_ID}.ufm-run.json",
            "ufm_done": f"DAY0-Prepare/site/99-output-monitor/infiniband/ufm-ibdiagnet/{RUN_ID}_{NODE}_ibdiagnet2.done",
            "ufm_input": f"DAY0-Prepare/site/99-output-monitor/infiniband/ufm-ibdiagnet/{RUN_ID}_{NODE}_ibdiagnet2.tgz",
            "validation_report": f"DAY0-Prepare/site/99-output-p2p/{RUN_ID}_{NODE}-ibdiagnet-topology-validation.xlsx",
            "report_provenance": f"DAY0-Prepare/site/99-output-p2p/{RUN_ID}_{NODE}-ibdiagnet-topology-validation.xlsx.provenance.json",
            "report_receipt": f"DAY0-Prepare/site/99-output-p2p/{RUN_ID}_{NODE}-ibdiagnet-topology-validation.receipt.json",
            "expected_cvt": "DAY0-Prepare/site/99-output-p2p/site-cvt.xlsx",
        }, paths)
        for role in roles:
            raw = (self.root / role["relative_path"]).read_bytes()
            self.assertEqual((role["state"], role["sha256"], role["size_bytes"]), ("present", sha(raw), len(raw)))
        self.assertEqual({
            "run_id": RUN_ID, "node": NODE, "kind": "ibdiagnet", "degraded": False,
            "run_record_sha256": sha(tree.record.read_bytes()), "receipt_sha256": sha(tree.receipt.read_bytes()),
            "expected_topology_sha256": sha(tree.cvt.read_bytes()),
        }, binding)
        self.assertEqual(roles, binding_module.validate_ufm_run_binding(
            tree.identity, binding, copy.deepcopy(roles), http_root=self.root))

    def test_the_degraded_iblinkinfo_run_binds_with_its_own_names(self):
        tree = self.tree(kind="iblinkinfo")
        roles, binding = self.derive(tree)
        self.assertTrue(binding["degraded"])
        self.assertTrue(roles[2]["relative_path"].endswith(f"{RUN_ID}_{NODE}_iblinkinfo.log"))
        self.assertTrue(roles[1]["relative_path"].endswith(f"{RUN_ID}_{NODE}_iblinkinfo.done"))

    def test_a_record_reached_through_the_setup_link_binds_the_real_paths(self):
        tree = self.tree()
        link = self.root / "infiniband/monitor/ufm-ibdiagnet"
        link.parent.mkdir(parents=True)
        link.symlink_to(tree.collected)
        roles, _binding = self.derive(tree, link / tree.record.name)
        self.assertTrue(roles[0]["relative_path"].startswith("DAY0-Prepare/site/"))

    def test_only_this_cycles_successful_run_binds(self):
        tree = self.tree()
        other = cycle_identity(tree.project.resolve(), sequence=8)
        tree.write_record({**tree.record_document, "cycle": other})
        self.assert_hold(tree, "does not name this worker cycle")
        tree.write_record({**tree.record_document, "cycle": None})
        self.assert_hold(tree, "does not name this worker cycle")
        tree.write_record({**tree.record_document, "cycle": tree.identity, "outcome": "failed"})
        self.assert_hold(tree, "did not succeed")
        tree.write_record({**tree.record_document, "outcome": "ok", "analysis": "failed"})
        self.assert_hold(tree, "did not succeed")

    def test_a_record_of_another_project_or_outside_the_collection_directory_never_binds(self):
        tree = self.tree()
        tree.identity = cycle_identity(Path("/elsewhere/DAY0-Prepare/other"))
        tree.write_record({**tree.record_document, "cycle": tree.identity})
        self.assert_hold(tree, "another project")
        stray = self.root / "DAY0-Prepare/site/99-output-p2p" / tree.record.name
        stray.write_bytes(tree.record.read_bytes())
        self.assert_hold(tree, "ufm-ibdiagnet directory", record=stray)

    def test_bytes_that_changed_after_the_record_or_the_receipt_hold(self):
        for field in ("input", "done", "report", "cvt", "provenance"):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as directory:
                    self.root = Path(directory).resolve()
                    tree = self.tree()
                    path = {"input": tree.input, "done": tree.done, "report": tree.report,
                            "cvt": tree.cvt, "provenance": tree.provenance}[field]
                    path.write_bytes(path.read_bytes() + b" changed")
                    self.assert_hold(tree, "differ|provenance")

    def test_a_receipt_of_another_run_or_report_holds(self):
        tree = self.tree()
        receipt = json.loads(tree.receipt.read_text(encoding="utf-8"))
        for change, message in ((dict(node="ufm01"), "does not describe this run"),
                                (dict(degraded=True), "does not describe this run"),
                                (dict(report={"name": "other.xlsx", "sha256": "1" * 64}), "another report"),
                                (dict(cvt={"name": "other.json", "sha256": "1" * 64}), "not a CVT")):
            with self.subTest(change=change):
                tree.receipt.write_text(json.dumps({**receipt, **change}), encoding="utf-8")
                tree.write_record({**tree.record_document, "receipt": tree.named(tree.receipt)})
                self.assert_hold(tree, message)

    def test_a_provenance_that_names_other_inputs_holds(self):
        tree = self.tree()
        real = tree.provenance_reader
        other = self.root / "elsewhere.tgz"
        other.write_bytes(b"other data")

        def moved(report):
            record = real(report)
            record["actual"] = {**record["actual"], "resolved_path": str(other)}
            return record
        with mock.patch("ztp.config.ib_topology_provenance.read_report_provenance", side_effect=moved):
            self.assert_hold(tree, "names other inputs")

    def test_a_replay_holds_on_tampered_evidence_or_a_path_through_a_link(self):
        tree = self.tree()
        roles, binding = self.derive(tree)
        for change in ({"sha256": "f" * 64}, {"size_bytes": 1}):
            tampered = copy.deepcopy(roles)
            tampered[3].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(binding_module.UfmRunBindingHold, "differs"):
                binding_module.validate_ufm_run_binding(tree.identity, binding, tampered, http_root=self.root)
        with self.assertRaisesRegex(binding_module.UfmRunBindingHold, "differs"):
            binding_module.validate_ufm_run_binding(
                tree.identity, {**binding, "degraded": True}, roles, http_root=self.root)
        with self.assertRaisesRegex(binding_module.UfmRunBindingHold, "shape"):
            binding_module.validate_ufm_run_binding(tree.identity, binding, roles[:6], http_root=self.root)
        link = self.root / "linked-site"
        link.symlink_to(tree.project)
        linked = copy.deepcopy(roles)
        linked[0]["relative_path"] = linked[0]["relative_path"].replace("DAY0-Prepare/site", "linked-site")
        with self.assertRaisesRegex(binding_module.UfmRunBindingHold, "unsafe"):
            binding_module.validate_ufm_run_binding(tree.identity, binding, linked, http_root=self.root)
        tree.record.write_bytes(tree.record.read_bytes() + b"\n")
        with self.assertRaisesRegex(binding_module.UfmRunBindingHold, "differs"):
            binding_module.validate_ufm_run_binding(tree.identity, binding, roles, http_root=self.root)

    def test_an_air_cycle_never_binds_ufm_analysis(self):
        tree = self.tree()
        air = dict(tree.identity, scope="air")
        air["cycle_id"] = sha(canonical_collection_cycle_json(
            {key: air[key] for key in ("project_key", "run_token", "scope", "sequence", "source")}))
        with self.assertRaisesRegex(binding_module.UfmRunBindingHold, "prod cycle"):
            binding_module.derive_ufm_run_roles(air, tree.record, http_root=self.root)


if __name__ == "__main__":
    unittest.main()
