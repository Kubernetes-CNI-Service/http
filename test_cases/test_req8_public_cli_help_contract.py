"""Direct public CLI help contracts for REQ-8/H-29."""

import ast
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PublicCliHelpContractTests(unittest.TestCase):
    @staticmethod
    def _direct_python_paths(manual):
        for match in re.finditer(
            r'<details data-script-reference="([^"]+)" class="script-reference">(.*?)</details>',
            manual,
            re.DOTALL,
        ):
            path, body = match.groups()
            direct = re.search(r'<dt>是否直接运行：</dt><dd>(.*?)</dd>', body, re.DOTALL)
            if (path.endswith(".py") and not path.startswith(("test_cases/", "examples/"))
                    and direct and direct.group(1).startswith("是")):
                yield path

    @staticmethod
    def _missing_public_help(source):
        missing = []
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "add_argument":
                continue
            flags = [
                arg.value for arg in node.args
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            ]
            if not flags or not flags[0].startswith("-"):
                continue
            help_value = next((item.value for item in node.keywords if item.arg == "help"), None)
            if isinstance(help_value, ast.Attribute) and help_value.attr == "SUPPRESS":
                continue
            if isinstance(help_value, ast.Constant):
                described = isinstance(help_value.value, str) and bool(help_value.value.strip())
            elif isinstance(help_value, ast.JoinedStr):
                described = any(
                    isinstance(part, ast.Constant) and isinstance(part.value, str)
                    and bool(part.value.strip()) for part in help_value.values
                )
            else:
                described = False
            if not described:
                missing.append((node.lineno, flags[0]))
        return missing

    def test_public_argparse_catalog_has_no_undocumented_options(self):
        manual = (ROOT / "user-manual.html").read_text(encoding="utf-8")
        direct_paths = tuple(self._direct_python_paths(manual))
        self.assertTrue(direct_paths, "Direct-run manual classification is missing")
        failures = {}
        for relative in direct_paths:
            with self.subTest(path=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                missing = self._missing_public_help(source)
                if missing:
                    failures[relative] = missing
        self.assertFalse(failures, repr(failures))

    def test_public_argparse_catalog_negative_control(self):
        self.assertEqual(
            [(2, "--sample")],
            self._missing_public_help(
                "import argparse\np = argparse.ArgumentParser(); p.add_argument('--sample')\n"
            ),
        )

    def assert_described_options(self, script, args, options):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / script), *args, "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        # Only option-list lines count. Usage wrapping must never masquerade as
        # an operator-facing description.
        lines = result.stdout.splitlines()
        section = next(
            (index for index, line in enumerate(lines)
             if line.strip() in ("optional arguments:", "options:")),
            None,
        )
        self.assertIsNotNone(section, result.stdout)
        for option in options:
            with self.subTest(script=script, option=option):
                found = next(
                    ((index, line) for index, line in enumerate(lines[section + 1:], section + 1)
                     if re.match(r"^\s+" + re.escape(option) + r"(?:\s|,|$)", line)),
                    None,
                )
                self.assertIsNotNone(found, result.stdout)
                index, line = found
                inline = re.match(
                    r"^\s+" + re.escape(option) + r"(?:\s+\S+)?\s{2,}\S", line,
                )
                wrapped = (
                    index + 1 < len(lines)
                    and re.match(r"^\s{8,}\S", lines[index + 1])
                    and not lines[index + 1].lstrip().startswith("-")
                )
                self.assertTrue(
                    inline or wrapped,
                    f"{script} {option} has no visible help: {line!r}",
                )

    def test_monitor_public_options_are_described(self):
        self.assert_described_options(
            "DAY0-Prepare/12-ztp-monitor.py", [],
            ("--apache-log", "--ssh-timeout", "--known-hosts"),
        )

    def test_collection_v2_emitter_artifact_options_are_described(self):
        self.assert_described_options(
            "monitor/collection_v2_emitter.py", [],
            ("--context-file", "--legacy-result-file", "--planned-file",
             "--info", "--link", "--csv"),
        )

    def test_monitor_html_scope_options_are_described(self):
        self.assert_described_options(
            "monitor/generate-monitor-html.py", [],
            ("--type", "--air", "--prod"),
        )

    def test_permission_sweep_inventory_options_are_described(self):
        self.assert_described_options(
            "ztp/backup/permission-sweep.py", ["inventory"],
            ("--root", "--state-dir", "--project"),
        )

    def test_permission_sweep_apply_options_are_described(self):
        self.assert_described_options(
            "ztp/backup/permission-sweep.py", ["apply"],
            ("--manifest", "--sha256", "--journal"),
        )

    def test_cumulus_generator_options_are_described(self):
        self.assert_described_options(
            "ztp/config/cumulus/template/90-c2-generate_configs.py", [],
            ("-y", "--csv", "--verify", "--fail-on-diff", "--ref-dir"),
        )

    def test_nvos_validation_inputs_are_described(self):
        self.assert_described_options(
            "ztp/config/nvos/template/P2P/p2p-to-validation.py", [],
            ("--inventory", "--port-map", "--splitter"),
        )


if __name__ == "__main__":
    unittest.main()
