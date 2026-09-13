#!/usr/bin/env python3
"""Materialize the tracked, sanitized public project for packaging tests."""

from contextlib import contextmanager
from pathlib import Path
import shutil
import tempfile

import openpyxl


PUBLIC_INPUTS = {
    "01-global.yaml.example": "01-global.yaml",
    "02-devices_config.csv.example": "02-devices_config.csv",
    "02-dhcp-subnet_config.csv.example": "02-dhcp-subnet_config.csv",
}
PRIVATE_SITE_PROJECT = "2026-12-vb-gb300"


def _write_sanitized_p2p(path: Path) -> None:
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "TAN Links"
    sheet.append(["Source", "Source", "Dest", "Dest"])
    sheet.append(["name", "port", "name", "port"])
    sheet.append([
        "PUBLIC-TAN-LEAF01", "swp1", "PUBLIC-TAN-SPINE01", "swp1",
    ])
    workbook.save(path)
    workbook.close()


@contextmanager
def materialized_public_project(repository_root: Path):
    """Yield an ignored temporary DAY0 project made only from public inputs."""
    root = repository_root.resolve()
    source = root / "examples/public-project"
    day0 = root / "DAY0-Prepare"
    with tempfile.TemporaryDirectory(
        prefix="public-project-fixture-", dir=day0,
    ) as temporary:
        project = Path(temporary)
        for source_name, destination_name in PUBLIC_INPUTS.items():
            origin = source / source_name
            if not origin.is_file() or origin.is_symlink():
                raise AssertionError(f"public fixture input is not a regular file: {origin}")
            shutil.copyfile(origin, project / destination_name)
        _write_sanitized_p2p(project / "public-p2p.xlsx")
        yield project
