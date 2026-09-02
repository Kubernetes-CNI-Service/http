#!/usr/bin/env python3
"""Contracts for the generated root README module catalog."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/update-root-readme.py"


def load_script():
    spec = importlib.util.spec_from_file_location("update_root_readme", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DocumentationCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_script()

    def test_discovery_excludes_project_outputs_and_hidden_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            included = (
                root / "tools/README.md",
                root / "infra/policy/README.md",
            )
            excluded = (
                root / "README.md",
                root / ".hidden/README.md",
                root / "DAY0-Prepare/project/README.md",
                root / "module/99-output-run/README.md",
            )
            for path in included + excluded:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"# {path.parent.name}\n", encoding="utf-8")
            self.assertEqual(
                sorted(path.relative_to(root) for path in included),
                [path.relative_to(root) for path in self.catalog.source_readmes(root)],
            )

    def test_render_replaces_only_the_generated_catalog(self):
        current = (
            "# Root\n\nintro\n"
            f"{self.catalog.BEGIN}\n\nold\n{self.catalog.END}\nfooter\n"
        )
        rendered = self.catalog.render_root_readme(
            current, "### `module/README.md`\n\n# Module",
        )
        self.assertEqual(
            "# Root\n\nintro\n"
            f"{self.catalog.BEGIN}\n\n"
            "### `module/README.md`\n\n# Module\n"
            f"{self.catalog.END}\nfooter\n",
            rendered,
        )


if __name__ == "__main__":
    unittest.main()
