#!/usr/bin/env python3
"""Workflow contract: DAY0 generation stops at a malformed P2P workbook."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


DIRECT = load_module(
    "xlsx_zero_row_direct_helpers",
    ROOT / "test_cases/test_xlsx_zero_row_fail_closed.py",
)
LOAD = load_module("xlsx_zero_row_day0_load", ROOT / "DAY0-Prepare/11-load.py")


class XlsxFailClosedWorkflowTests(unittest.TestCase):
    def test_generate_configs_stops_before_dhcp_generator_and_publication(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            paths = DIRECT.prepare_runtime(root, DIRECT.make_legacy_column_workbook)
            exact_dot, exact_intent, unrelated = DIRECT.stale_artifacts(paths)
            commands: list[list[str]] = []
            resolver = mock.Mock(
                side_effect=DIRECT.LegacyReached("malformed workbook escaped"),
            )

            def run_real_p2p(command, *, cwd, **_kwargs):
                commands.append(list(command))
                self.assertEqual(paths["p2p_dir"], Path(cwd))
                caught, stdout, stderr = DIRECT.invoke_main(
                    paths, list(command[2:]), load_inventory=resolver,
                )
                if caught is not None:
                    raise caught
                self.fail("malformed workbook unexpectedly completed: " + stdout + stderr)

            with mock.patch.object(LOAD, "ZTP_DIR", root / "ztp"), \
                    mock.patch.object(LOAD, "run", side_effect=run_real_p2p):
                caught = None
                try:
                    LOAD.generate_configs(
                        frozenset({"eth"}), install_dhcp=False,
                        eth_version="5.16.4",
                    )
                except BaseException as exc:
                    caught = exc

            self.assertIsInstance(caught, SystemExit)
            self.assertEqual(1, caught.code)
            self.assertEqual(1, len(commands), commands)
            self.assertEqual("b-xlsx_to_dot.py", commands[0][1])
            self.assertFalse(any("c1-generate_dhcp.py" in command for command in commands))
            self.assertFalse(any("90-c2-generate_configs.py" in command for command in commands))
            self.assertFalse(any("d-hostname2mac.py" in command for command in commands))
            resolver.assert_not_called()
            self.assertFalse(exact_dot.exists())
            self.assertFalse(exact_intent.exists())
            self.assertTrue(all(path.is_file() for path in unrelated), unrelated)


if __name__ == "__main__":
    unittest.main()
