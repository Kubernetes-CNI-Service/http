#!/usr/bin/env python3
"""Workflow contracts for the safe Phase-B ``eth_jump`` stopping point."""

from __future__ import annotations

import csv
import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INITIAL_SETUP = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
LOAD = ROOT / "DAY0-Prepare/11-load.py"
SETUP = ROOT / "DAY0-Prepare/01-a-setup.py"
MANIFEST = ROOT / "test_cases/script_test_manifest.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    old = sys.modules.get(name)
    sys.path.insert(0, str(path.parent))
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if old is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = old
    return module


class EthJumpPhaseBWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.initial_setup = load_module("eth_jump_workflow_initial", INITIAL_SETUP)
        cls.loader = load_module("eth_jump_workflow_loader", LOAD)
        cls.setup = load_module("eth_jump_workflow_setup", SETUP)

    def test_phase_b_admits_transit_independently_of_schema_consumers(self):
        """The Phase-B transit proof remains independent after Phase C opens."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            setup_csv = root / "initial-setup-devices.csv"
            setup_csv.write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,"
                "eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,,,,\n"
                "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n",
                encoding="utf-8",
            )
            ib_devices, transit_devices = self.initial_setup.load_devices(setup_csv)
            self.assertIn(
                "example-jump01",
                transit_devices,
                "Phase-B SP-2 must admit eth_jump to the transit inventory",
            )
            self.assertEqual(
                {"example-jump01"},
                set(transit_devices),
                "Phase B must work when eth_jump is the only transit device",
            )
            targets = self.initial_setup.build_targets(
                [
                    self.initial_setup.Link(
                        "EXAMPLE-IB01", "eth0", "EXAMPLE-JUMP01", "7",
                    )
                ],
                ib_devices,
                transit_devices,
            )
            self.assertEqual("eth_jump", targets[0].ethernet.dev_type)


    def test_manifest_binds_workflow_to_its_three_real_scripts(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        owners = [
            workflow for workflow in manifest["workflows"]
            if "test_cases.test_eth_jump_transport_workflow"
            in workflow.get("tests", [])
        ]
        self.assertEqual(1, len(owners), owners)
        self.assertEqual(
            {
                "infiniband/bringup/xdr-initial-setup/initial-setup.py",
                "DAY0-Prepare/01-a-setup.py",
                "DAY0-Prepare/11-load.py",
            },
            set(owners[0]["members"]),
            "workflow members must be exactly the production scripts exercised",
        )


if __name__ == "__main__":
    unittest.main()
