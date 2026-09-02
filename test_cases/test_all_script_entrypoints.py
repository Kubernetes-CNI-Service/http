#!/usr/bin/env python3
"""Repository-wide source-script syntax and non-mutating entrypoint contracts."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
import warnings


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_SUFFIXES = {".py", ".cgi", ".sh"}
SOURCE_DOMAINS = (
    "DAY0-Prepare/",
    "ethernet/monitor/",
    "infiniband/bringup/",
    "infiniband/monitor/",
    "infra/",
    "monitor/",
    "nvlink/monitor/",
    "tools/",
    "ztp/",
)
GENERATED_RUNTIME_SCRIPTS = {
    "ztp/ztp-bootstrap_oob.sh",
    "ztp/ztp-bootstrap_oobofoob.sh",
}
NON_SOURCE_ROOTS = {".git", ".codex", ".agents"}
NON_DEPLOYMENT_DIR_NAMES = {
    "test", "tests", "test_cases", "test-results", "__pycache__",
    ".pytest_cache", "node_modules",
}

# These operator-facing shell entrypoints implement an explicit, non-mutating
# help path.  Keep the list deliberate: invoking an arbitrary collection or
# bootstrap shell script merely to probe its CLI could contact a switch.
SHELL_HELP_ENTRYPOINTS = (
    "ethernet/monitor/cron.sh",
    "infiniband/bringup/ndr/data-collect-IB.sh",
    "infiniband/bringup/ndr/OS-CPLD-upgrade.sh",
    "infiniband/bringup/xdr-upgrade/upgrade.sh",
    "infra/infra-setup.sh",
    "infra/infra-teardown.sh",
)

# A few legacy operator entrypoints deliberately use a small hand-written
# parser instead of argparse.  Their help paths still form part of the same
# non-mutating CLI contract and therefore need explicit coverage.
MANUAL_HELP_ENTRYPOINTS = (
    "tools/lldp-analyze-tool/build_report.py",
    "ztp/backup/yaml-collect.py",
    "ztp/config/cumulus/d-hostname2mac.py",
    "ztp/config/nvos/d-hostname2mac.py",
    "ztp/config/cumulus/template/90-c2-generate_configs.py",
    "ztp/config/nvos/template/90-c2-generate_configs.py",
    "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
    "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
    "ztp/manual-reset.py",
)


def source_scripts() -> list[Path]:
    scripts = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in SCRIPT_SUFFIXES:
            continue
        relative = path.relative_to(ROOT)
        if (
            relative.parts[0] in NON_SOURCE_ROOTS
            or relative.parts[0].startswith(".codex_tmp")
            or any(part in NON_DEPLOYMENT_DIR_NAMES for part in relative.parts)
        ):
            continue
        if any(part.startswith("99-output") for part in relative.parts):
            continue
        if relative.as_posix() in GENERATED_RUNTIME_SCRIPTS:
            continue
        scripts.append(path)
    return sorted(scripts)


class AllScriptEntrypointTests(unittest.TestCase):
    def test_xdr_upgrade_readme_uses_documentation_networks(self):
        readme = (
            ROOT / "infiniband/bringup/xdr-upgrade/README.md"
        ).read_text(encoding="utf-8")
        addresses = {
            ipaddress.ip_address(value)
            for value in re.findall(
                r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", readme,
            )
        }
        documentation_networks = tuple(
            ipaddress.ip_network(cidr)
            for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        )

        self.assertTrue(addresses)
        self.assertTrue(
            all(
                any(address in network for network in documentation_networks)
                for address in addresses
            ),
            sorted(map(str, addresses)),
        )

    def test_every_source_script_is_classified_and_parses(self):
        scripts = source_scripts()
        self.assertGreaterEqual(len(scripts), 90)
        unclassified = []
        failures = []
        for path in scripts:
            relative = path.relative_to(ROOT).as_posix()
            if not relative.startswith(SOURCE_DOMAINS):
                unclassified.append(relative)
            if path.suffix == ".sh":
                result = subprocess.run(
                    ["bash", "-n", str(path)], cwd=ROOT,
                    stdin=subprocess.DEVNULL, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=10, check=False,
                )
                if result.returncode:
                    failures.append(f"{relative}: {result.stdout.strip()}")
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error")
                    compile(path.read_bytes(), str(path), "exec")
            except (SyntaxError, UnicodeError, Warning) as exc:
                failures.append(f"{relative}: {exc}")
        self.assertEqual([], unclassified)
        self.assertEqual([], failures)

    def test_every_argparse_entrypoint_has_safe_help(self):
        candidates = []
        for path in source_scripts():
            if path.suffix not in {".py", ".cgi"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if (
                ("import argparse" in text or "from argparse" in text)
                and re.search(
                    r"__name__\s*==\s*['\"]__main__['\"]", text,
                )
            ):
                candidates.append(path)
        self.assertGreaterEqual(len(candidates), 35)
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        failures = []
        for path in candidates:
            relative = path.relative_to(ROOT).as_posix()
            try:
                result = subprocess.run(
                    [sys.executable, str(path), "--help"], cwd=ROOT,
                    env=environment, stdin=subprocess.DEVNULL, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=15, check=False,
                )
            except subprocess.TimeoutExpired:
                failures.append(f"{relative}: --help timed out")
                continue
            if result.returncode:
                failures.append(
                    f"{relative}: rc={result.returncode}: {result.stdout[-500:]}"
                )
            elif "usage:" not in result.stdout.casefold():
                failures.append(f"{relative}: --help omitted usage text")
        self.assertEqual([], failures)

    def test_operator_shell_entrypoints_have_safe_help(self):
        failures = []
        for relative in SHELL_HELP_ENTRYPOINTS:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            try:
                result = subprocess.run(
                    ["bash", str(path), "--help"], cwd=ROOT,
                    stdin=subprocess.DEVNULL, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=10, check=False,
                )
            except subprocess.TimeoutExpired:
                failures.append(f"{relative}: --help timed out")
                continue
            if result.returncode:
                failures.append(
                    f"{relative}: rc={result.returncode}: {result.stdout[-500:]}"
                )
            elif "usage:" not in result.stdout.casefold():
                failures.append(f"{relative}: --help omitted usage text")
        self.assertEqual([], failures)

    def test_manual_python_entrypoints_have_safe_help(self):
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        failures = []
        for relative in MANUAL_HELP_ENTRYPOINTS:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            try:
                result = subprocess.run(
                    [sys.executable, str(path), "--help"], cwd=ROOT,
                    env=environment, stdin=subprocess.DEVNULL, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=15, check=False,
                )
            except subprocess.TimeoutExpired:
                failures.append(f"{relative}: --help timed out")
                continue
            if result.returncode:
                failures.append(
                    f"{relative}: rc={result.returncode}: {result.stdout[-500:]}"
                )
            elif not result.stdout.strip():
                failures.append(f"{relative}: --help omitted help text")
        self.assertEqual([], failures)

    def test_rendered_bootstraps_are_generated_outputs_not_sources(self):
        template = ROOT / "ztp/templates/ztp-bootstrap.sh"
        self.assertIn(template, source_scripts())
        discovered = {
            path.relative_to(ROOT).as_posix() for path in source_scripts()
        }
        self.assertTrue(GENERATED_RUNTIME_SCRIPTS.isdisjoint(discovered))
        source = template.read_text(encoding="utf-8")
        self.assertIn('ZTP_SERVER="http://127.0.0.1"', source)
        self.assertIn('ZTP_UPGRADE_ENABLED="false"', source)


if __name__ == "__main__":
    unittest.main()
