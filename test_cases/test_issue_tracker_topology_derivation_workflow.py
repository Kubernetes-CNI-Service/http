#!/usr/bin/env python3
"""Hermetic P2P producer helpers -> worker freeze -> reader -> C24 decision.

The two literal worksheet edges are the oracle; P2P output never supplies an
expected value. This is not a durable collection cycle or AIR qualification.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_activity_source import (
    ActivitySourceHoldError, validate_worker_eth_activity_context,
)
from monitor.issue_tracker_whitelist import (
    evaluate_whitelist, freeze_whitelist_sheet,
)
from test_cases.test_collection_cycle_worker_contract import IDENTITY, WORKER
from test_cases.test_issue_tracker_topology_derivation import (
    EXPECTED, ROLES, _sha, _verify, literal_fixture,
)
from test_cases.test_splitter_profile_breakout_workflow import P2P


def _real_chain(root: Path, *, omit_profile: bool = False):
    p2p = root / "ztp/config/cumulus/template/P2P"
    p2p.mkdir(parents=True)
    paths = literal_fixture(p2p)
    project = root / "DAY0-Prepare/fixture-project"
    project.mkdir(parents=True)
    selected = paths["topology"].rename(project / paths["topology"].name)
    (project / "p2p.xlsx").symlink_to(selected.name)
    (p2p / "p2p.xlsx").symlink_to(os.path.relpath(project / "p2p.xlsx", p2p))

    # Real producer parsing/resolution is checked against the independent
    # literal oracle before its output is published in this private fixture.
    rows = P2P._extract_xlsx_rows(selected)
    self_described_rows = tuple((row["sheet"], row["row"], *row["fields"])
                                for row in rows[:2])
    if self_described_rows != EXPECTED or len(rows) != 3:
        raise AssertionError("P2P parser disagrees with literal sheet/row oracle")
    inv, order = P2P.load_inventory(paths["inventory"])
    direct, switch = P2P.load_port_map(paths["port_mapping"])
    fields = [row["fields"] for row in rows]
    profiles, warnings = P2P.infer_splitter_profiles(
        fields, inv, order, direct, switch,
    )
    if profiles or warnings:
        raise AssertionError("literal unsplit fixture unexpectedly has profiles")
    physical, _ = P2P._resolved_physical_links(
        fields, inv_patterns=inv, type_order=order, port_direct=direct,
        port_switch=switch, splitter_profiles=profiles,
    )
    if tuple(physical) != tuple(edge[2:] for edge in EXPECTED):
        raise AssertionError("P2P physical links disagree with literal oracle")
    output = p2p / "output-p2p"
    output.mkdir()
    dot = output / "selected-fabric-lldpq.dot"
    dot.write_text("graph fabric {\n" + "\n".join(
        f'"{a}":"{ap}" -- "{z}":"{zp}"' for a, ap, z, zp in physical
    ) + "\n}\n", encoding="utf-8")
    sidecar = Path(P2P._write_splitter_profiles(
        dot, profiles, selected, paths["inventory"], paths["port_mapping"],
        expected_hashes=P2P._splitter_source_hashes(
            selected, paths["inventory"], paths["port_mapping"],
        ),
    ))
    paths.update(topology=selected, lldpq=dot, splitter_profiles=sidecar)
    if omit_profile:
        sidecar.unlink()
    aliases = root / "tools/lldp-analyze-tool/04-lldp-device-aliases.json"
    aliases.parent.mkdir(parents=True)
    aliases.write_text("{}\n", encoding="utf-8")

    slot = "ethernet/prod"
    with mock.patch.object(WORKER, "HTTP_ROOT", root.resolve()):
        bindings = WORKER._collection_managed_bindings(IDENTITY, slot)
        activity = WORKER._collection_snapshot_activity_sources(slot, bindings)
    if activity is None:
        raise AssertionError("real worker did not freeze selected P2P sources")
    context = {"identity": IDENTITY, "source_slot": slot,
               "artifacts": bindings, "activity": activity}
    return paths, context


def _frozen_derivation(context: dict) -> tuple[dict[str, Path], dict[str, str]]:
    activity = context["activity"]
    derivation = activity["derivation_sources"]
    sources = {
        "topology": activity["topology"],
        "inventory": activity["sources"]["inventory"],
        "lldpq": activity["sources"]["dot"],
        "port_mapping": derivation["port_mapping"],
        "splitter_profiles": derivation["splitter_profiles"],
    }
    return ({role: Path(sources[role]["path"]) for role in ROLES},
            {role: sources[role]["sha256"] for role in ROLES})


class TopologyDerivationWorkflowTests(unittest.TestCase):
    def test_missing_derivation_sidecar_does_not_upgrade_or_break_legacy_link_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            _paths, context = _real_chain(Path(directory), omit_profile=True)
            self.assertNotIn("derivation_sources", context["activity"])
            validate_worker_eth_activity_context(context)

    def test_real_producer_worker_reader_binds_literal_z_and_c24_any_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, context = _real_chain(Path(directory))
            self.assertEqual(paths["topology"].read_bytes(),
                             Path(context["activity"]["topology"]["path"]).read_bytes())
            self.assertEqual("selected-fabric.xlsx",
                             context["activity"]["selected_workbook_name"])
            validate_worker_eth_activity_context(context)
            frozen, digests = _frozen_derivation(context)
            witness = _verify(
                frozen, expected=digests,
                selected_name=context["activity"]["selected_workbook_name"],
            )
            self.assertEqual(EXPECTED, tuple(
                (edge.sheet, edge.row, edge.a_node, edge.a_port,
                 edge.z_node, edge.z_port) for edge in witness.edges
            ))
            snapshot = freeze_whitelist_sheet((
                ("Submit Date", "Submitor", "Datahalll", "Rack", "Device Name", "Comments"),
                (None, None, None, None, "leaf-z", None),
            ))
            decisions = evaluate_whitelist(snapshot, [
                {"record_id": f"{edge.sheet}:{edge.row}", "source": "Cabling",
                 "a_node": edge.a_node, "z_node": edge.z_node}
                for edge in witness.edges
            ])
            self.assertEqual((True, False), tuple(
                decision.skipped for decision in decisions.decisions
            ))
            self.assertEqual("leaf-z", decisions.decisions[0].matched_rule)

    def test_worker_frozen_basename_disagrees_with_sidecar_even_for_same_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            _paths, context = _real_chain(Path(directory))
            frozen, digests = _frozen_derivation(context)
            from monitor.issue_tracker_topology_derivation import TopologyDerivationHoldError
            with self.assertRaises(TopologyDerivationHoldError):
                _verify(frozen, expected=digests,
                        selected_name="foreign-same-bytes.xlsx")

    def test_worker_frozen_port_mapping_rewrite_holds_before_derivation(self):
        with tempfile.TemporaryDirectory() as directory:
            _paths, context = _real_chain(Path(directory))
            frozen, digests = _frozen_derivation(context)
            mapping = frozen["port_mapping"]
            mapping.write_bytes(mapping.read_bytes() + b"# after freeze\n")
            with self.assertRaises(ActivitySourceHoldError):
                validate_worker_eth_activity_context(context)
            from monitor.issue_tracker_topology_derivation import TopologyDerivationHoldError
            with self.assertRaises(TopologyDerivationHoldError):
                _verify(frozen, expected=digests)


if __name__ == "__main__":
    unittest.main()
