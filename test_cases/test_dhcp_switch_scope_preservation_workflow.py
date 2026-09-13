#!/usr/bin/env python3
"""Real 11-load to DHCP workflow for switch-scoped host ownership."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.test_dhcp_switch_scope_preservation import (
    DHCP,
    FAMILY_HOST,
    ScopedDhcpFixture,
)


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    sys.path[:0] = [str(path.parent), str(ROOT / "tools"), str(ROOT)]
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.path[:3]
        if previous is not None:
            sys.modules[name] = previous
    return module


LOAD = load_module(
    "dhcp_switch_scope_workflow_load",
    ROOT / "DAY0-Prepare/11-load.py",
)


class DhcpSwitchScopeWorkflowTests(unittest.TestCase):
    def _run_load_generation(
        self,
        fixture: ScopedDhcpFixture,
        *,
        selected: str,
        manifest_failure: BaseException | None = None,
    ) -> list[list[str]]:
        commands: list[list[str]] = []

        def run_real_boundary(command, **_kwargs):
            command = [str(item) for item in command]
            commands.append(command)
            if len(command) >= 2 and command[1] == "c1-generate_dhcp.py":
                fixture.execute(
                    ["c1-generate_dhcp.py", *command[2:]],
                    manifest_failure=manifest_failure,
                )

        with mock.patch.object(
            LOAD, "ZTP_DIR", fixture.root / "ztp",
        ), mock.patch.object(
            LOAD, "run", side_effect=run_real_boundary,
        ), mock.patch.object(
            LOAD, "newest_directory",
            return_value=fixture.root / "fixture-generated-release",
        ):
            LOAD.generate_configs(
                frozenset({"eth", "ib", "nvl"}),
                install_dhcp=False,
                dry_run=False,
                deployment_scope="prod",
                switch_scope=selected,
            )
        return commands

    def test_real_load_forwards_scope_and_preserves_other_family_hosts(self):
        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as name:
                fixture = ScopedDhcpFixture(Path(name))
                before = fixture.snapshot()
                commands = self._run_load_generation(
                    fixture, selected=selected,
                )

                dhcp_commands = [
                    item for item in commands
                    if len(item) >= 2 and item[1] == "c1-generate_dhcp.py"
                ]
                self.assertEqual(1, len(dhcp_commands), commands)
                command = dhcp_commands[0]
                self.assertEqual(1, command.count("--switch"), command)
                self.assertEqual(selected, command[command.index("--switch") + 1])
                self.assertIn(FAMILY_HOST[selected], fixture.outputs[selected].read_text())
                for family in ("eth", "ib", "nvl"):
                    if family != selected:
                        self.assertEqual(
                            before[family][0], fixture.outputs[family].read_bytes(),
                            f"load --switch {selected} mutated {family}",
                        )

    def test_real_load_propagates_generation_failure_without_partial_outputs(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            before = fixture.snapshot()
            with self.assertRaisesRegex(OSError, "workflow manifest failure"):
                self._run_load_generation(
                    fixture,
                    selected="ib",
                    manifest_failure=OSError("injected workflow manifest failure"),
                )

            for label, path in fixture.outputs.items():
                self.assertEqual(before[label][0], path.read_bytes(), label)


if __name__ == "__main__":
    unittest.main()
