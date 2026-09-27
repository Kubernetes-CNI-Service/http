#!/usr/bin/env python3
"""Workflow binding between Day-0 transit and UFM file transport contracts."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INITIAL_SETUP = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
UFM_TRANSPORT = ROOT / "infra/ufm_jump_transport.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    old = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if old is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = old
    return module


class UfmJumpTransportWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.initial = load("ufm_initial_setup_contract", INITIAL_SETUP)
        cls.ufm = load("ufm_jump_transport_workflow", UFM_TRANSPORT)

    def test_independent_typed_argv_contract_has_fixed_shared_vectors(self):
        accepted = (
            ["hostname"],
            ["bridge", "fdb", "show"],
            ["ip", "neighbor"],
            ["printf", "%s", "value with spaces"],
        )
        rejected = (
            "hostname",
            [],
            ["hostname", "bad\ncarrier"],
            ["hostname", ""],
            ["hostname", 1],
        )
        for vector in accepted:
            with self.subTest(vector=vector):
                self.assertEqual(
                    self.initial.typed_argv(vector, label="workflow"),
                    self.ufm.typed_argv(vector, label="workflow"),
                )
        for vector in rejected:
            with self.subTest(vector=vector):
                with self.assertRaises(self.initial.SetupError):
                    self.initial.typed_argv(vector, label="workflow")
                with self.assertRaises(self.ufm.TransportError):
                    self.ufm.typed_argv(vector, label="workflow")

    def test_phase_c_handoff_is_not_invented_by_transport_layer(self):
        source = UFM_TRANSPORT.read_text(encoding="utf-8")
        forbidden = (
            "phase_c_payload",
            "ufm_version",
            "certificate_default_path",
            "license_default_path",
        )
        for name in forbidden:
            with self.subTest(name=name):
                self.assertNotIn(name, source)

    def test_workflow_has_real_command_and_bidirectional_file_boundaries(self):
        jump = self.ufm.JumpEndpoint(
            host="192.0.2.10", user="admin", known_hosts=Path("/secure/known_hosts")
        )
        far = self.ufm.BoundFarEndpoint(
            host="203.0.113.20", user="admin", identity_evidence="matched-device",
            jump=jump,
        )
        operations = {
            "jump_read": self.ufm.jump_read(jump, ["hostname"], timeout=10),
            "jump_transit": self.ufm.jump_transit(
                jump, far, ["true"], timeout=10
            ),
            "jump_copy_to": self.ufm.jump_copy_to(
                jump, far, Path("/safe/input"), "/var/tmp/ufm/input", timeout=10
            ),
            "jump_copy_from": self.ufm.jump_copy_from(
                jump, far, "/var/tmp/ufm/output", Path("/safe/output.part"), timeout=10
            ),
        }
        self.assertEqual(
            {"jump_read", "jump_transit", "jump_copy_to", "jump_copy_from"},
            set(operations),
        )
        self.assertEqual("ssh", operations["jump_read"][0])
        self.assertEqual("ssh", operations["jump_transit"][0])
        self.assertEqual("scp", operations["jump_copy_to"][0])
        self.assertEqual("scp", operations["jump_copy_from"][0])
        self.assertTrue(any(
            token.startswith("ProxyCommand=")
            for token in operations["jump_copy_to"]
        ))
        self.assertTrue(any(
            token.startswith("ProxyCommand=")
            for token in operations["jump_copy_from"]
        ))

    def test_day0_action_failure_still_reaches_ufm_retrieval_boundary(self):
        jump = self.ufm.JumpEndpoint(
            host="192.0.2.10", user="admin", known_hosts=Path("/secure/known_hosts")
        )
        far = self.ufm.BoundFarEndpoint(
            host="203.0.113.20", user="admin", identity_evidence="matched-device",
            jump=jump,
        )
        sources = [
            self.ufm.LogSource(
                endpoint=far,
                remote_path="/var/tmp/ufm/run-1.log",
                destination=Path("/safe/run-1.log"),
                provenance="configured-ipv4",
            )
        ]
        attempted = []

        def day0_action():
            self.initial.typed_argv(["hostname", "bad\ncarrier"], label="workflow")

        with self.assertRaises(self.ufm.UfmOperationFailure) as captured:
            self.ufm.run_with_mandatory_retrieval(
                day0_action, sources, lambda source: attempted.append(source.provenance)
            )
        self.assertEqual(["configured-ipv4"], attempted)
        self.assertIn("SetupError", captured.exception.primary_failure)
        self.assertEqual("retrieved", captured.exception.retrieval.status)

    def test_day0_failure_attempts_all_sources_but_raw_log_is_not_backed_up(self):
        jump = self.ufm.JumpEndpoint(
            host="192.0.2.10", user="admin", known_hosts=Path("/secure/known_hosts")
        )
        far = self.ufm.BoundFarEndpoint(
            host="203.0.113.20", user="admin", identity_evidence="synthetic-claim",
            jump=jump,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = [
                self.ufm.LogSource(
                    endpoint=far, remote_path=f"/var/tmp/ufm/{label}.log",
                    destination=root / f"{label}.log", provenance=label,
                )
                for label in ("raw", "structured")
            ]
            attempted = []

            def retrieve(source):
                attempted.append(source.provenance)

                def runner(command):
                    payload = (
                        b"SYNTHETIC-OPAQUE-UNLABELLED-730193\n"
                        if source.provenance == "raw"
                        else b"UFM_EVENT|stage=bootstrap|status=failed|code=remote_error\n"
                    )
                    Path(command[-1]).write_bytes(payload)
                    return self.ufm.CommandResult(0, "", "")

                self.ufm.copy_from_no_overwrite(
                    jump, far, source.remote_path, source.destination,
                    timeout=10, runner=runner,
                )

            def day0_action():
                self.initial.typed_argv(["hostname", "bad\ncarrier"], label="workflow")

            with self.assertRaises(self.ufm.UfmOperationFailure) as captured:
                self.ufm.run_with_mandatory_retrieval(day0_action, sources, retrieve)
            self.assertEqual(["raw", "structured"], attempted)
            self.assertEqual("log_retrieval_partial", captured.exception.retrieval.status)
            self.assertFalse((root / "raw.log").exists())
            self.assertEqual(
                b"UFM_EVENT|stage=bootstrap|status=failed|code=remote_error\n",
                (root / "structured.log").read_bytes(),
            )
            self.assertNotIn(
                "SYNTHETIC-OPAQUE-UNLABELLED-730193", str(captured.exception)
            )


if __name__ == "__main__":
    unittest.main()
