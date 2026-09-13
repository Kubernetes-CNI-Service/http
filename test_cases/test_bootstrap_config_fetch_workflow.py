#!/usr/bin/env python3
"""Workflow contract from DAY0 rendering to required bootstrap config fetch."""

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
    "bootstrap_config_fetch_direct_contract",
    ROOT / "test_cases/test_bootstrap_config_fetch_contract.py",
)
LOAD = load_module("bootstrap_fetch_day0_load", ROOT / "DAY0-Prepare/11-load.py")


class RenderedBootstrapFetchWorkflowTests(unittest.TestCase):
    def render(self, root: Path) -> list[Path]:
        ztp_root = root / "ztp"
        templates = ztp_root / "templates"
        templates.mkdir(parents=True)
        (templates / "ztp-bootstrap.sh").write_bytes(
            (ROOT / "ztp/templates/ztp-bootstrap.sh").read_bytes()
        )
        key = root / "operator.pub"
        key.write_text("ssh-ed25519 AAAAWORKFLOW operator\n", encoding="utf-8")
        settings = LOAD.GlobalSettings(
            dhcp_enabled=True,
            dhcp_package="isc-dhcp-server",
            http_enabled=True,
            http_package="apache2",
            http_root=root,
            ztp_enabled=True,
            ztp_prefix="/ztp",
            ztp_ips={
                "air_oob": ("192.0.2.31",),
                "air_oobofoob": ("198.51.100.31",),
            },
            versions={"eth": "5.16.4"},
        )
        previous = LOAD.ZTP_DIR
        try:
            LOAD.ZTP_DIR = ztp_root
            with mock.patch("builtins.print"):
                LOAD.render_ztp_runtime(settings, (key,), frozenset({"eth"}))
        finally:
            LOAD.ZTP_DIR = previous
        return [
            ztp_root / "ztp-bootstrap_oob.sh",
            ztp_root / "ztp-bootstrap_oobofoob.sh",
        ]

    def test_both_rendered_entrypoints_retry_transient_fetch_then_apply_dedicated(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for index, rendered in enumerate(self.render(root), start=1):
                result, events, _state, _home = DIRECT.run_bootstrap_fetch(
                    root / f"consumer-{index}",
                    response_codes=("503", "200"),
                    template_source=rendered.read_text(encoding="utf-8"),
                )
                self.assertEqual(0, result.returncode, result.stderr + result.stdout)
                self.assertEqual(1, len(DIRECT.dedicated_curl_argv(events)), events)
                DIRECT.assert_exact_fetch_policy(self, events)
                self.assertEqual(2, len(DIRECT.dedicated_fetches(events)), events)
                self.assertTrue(
                    any(
                        event.startswith("nv:config patch ") and DIRECT.MAC_FILE in event
                        for event in events
                    ),
                    events,
                )
                self.assertEqual([], DIRECT.default_mutations(events), events)

    def test_rendered_entrypoint_marks_unpublished_device_as_degraded_default(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rendered = self.render(root)[0]
            result, events, state, _home = DIRECT.run_bootstrap_fetch(
                root / "consumer",
                response_codes=("404",),
                template_source=rendered.read_text(encoding="utf-8"),
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            DIRECT.assert_exact_fetch_policy(self, events)
            self.assertEqual(1, len(DIRECT.dedicated_fetches(events)), events)
            self.assertEqual(1, len(DIRECT.default_mutations(events)), events)
            self.assertIn("[ZTP] PROVISION_DEGRADED", result.stdout + result.stderr)
            self.assertIn(
                "source_kind=default\n",
                (state / "receipt.env").read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
