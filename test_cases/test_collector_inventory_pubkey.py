"""Direct contracts for the collectors' management-key binding.

Owner 2026-11-04 (R-016 详细设计 v1.1 §0.1 and §13「公钥（cron.sh）」: 「按照默认处理」; §5.2): cron.sh
reads <type>/publickey/mgmt-server.pub, setup's per-key link through DAY0-Prepare/activate-project
(§3.2), never the directory an inventory link resolves into: an inventory may be a user link to a file
outside the project (R-014 第 3 条; §11 v1.1 fixtures「02-devices_config.csv → 外部文件」and
「ib.csv → p2p/x.csv」).  Each published entrypoint reads its own network's directory, and the
MGMT_PUBKEY_FILE environment value is not trusted.  The link texts come from the spec table's own rule
(project_contract.pointer_link_target), never from cron.sh.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
from typing import Dict, Optional
import unittest

from tools.project_contract import pointer_link_target


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "ethernet/monitor/cron.sh"
INVENTORIES = {
    "ethernet": "eth.csv",
    "infiniband": "ib.csv",
    "nvlink": "nvsw.csv",
}
DEVICE_TYPES = {"ethernet": "eth", "infiniband": "ib", "nvlink": "nvl"}
PROJECT = "site"
OTHER_PROJECT = "site-other"
MISSING_KEY = "active project mgmt-server.pub is missing"


def _preflight_harness_source() -> str:
    """Return the real collector's BASE and public-key preflight with probes."""
    source = COLLECTOR.read_text(encoding="utf-8")
    base_line = next(
        line for line in source.splitlines()
        if line.startswith('BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")"')
    )
    start = source.index("# Shared public key deployed to all switch types.")
    end = source.index("# Compression is enabled for SSH and SCP.", start)
    preflight = source[start:end]
    return (
        "#!/bin/bash\n"
        "set -u\n"
        f"{base_line}\n"
        f"{preflight}"
        "printf 'MGMT_PUBKEY_FILE=%s\\n' \"$MGMT_PUBKEY_FILE\"\n"
        "printf 'SSH_KEY=%s\\n' \"$SSH_KEY\"\n"
    )


def _management_key(root: Path, comment: str) -> str:
    key_base = root / f"fixture-{comment}-management-key"
    generated = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key_base)],
        capture_output=True,
        text=True,
        check=False,
    )
    if generated.returncode != 0:
        raise RuntimeError(generated.stderr)
    return key_base.with_suffix(".pub").read_text(encoding="utf-8")


def stage_collector_tree(root: Path) -> dict[str, Path]:
    """Stage setup's pointer layout around the real preflight: two projects with distinct management
    keys, DAY0-Prepare/activate-project -> site, each network's inventory and public-key links."""
    canonical = root / "ethernet/monitor/cron.sh"
    canonical.parent.mkdir(parents=True)
    canonical.write_text(_preflight_harness_source(), encoding="utf-8")
    canonical.chmod(0o755)
    projects = {}
    for name in (PROJECT, OTHER_PROJECT):
        project = root / "DAY0-Prepare" / name
        project.mkdir(parents=True)
        (project / "02-devices_config.csv").write_text(
            "hostname,type,eth0_ip,netmask\n"
            + "".join(f"EXAMPLE-{area.upper()}01,{kind},192.0.2.10,24\n"
                      for area, kind in DEVICE_TYPES.items()),
            encoding="utf-8",
        )
        (project / "mgmt-server.pub").write_text(_management_key(root, name), encoding="utf-8")
        projects[name] = project
    (root / "DAY0-Prepare/activate-project").symlink_to(PROJECT)
    for area, csv_name in INVENTORIES.items():
        monitor = root / area / "monitor"
        monitor.mkdir(parents=True, exist_ok=True)
        if area != "ethernet":
            (monitor / "cron.sh").symlink_to("../../ethernet/monitor/cron.sh")
        (root / area / csv_name).symlink_to(
            pointer_link_target(f"{area}/{csv_name}", "02-devices_config.csv"))
        (monitor / csv_name).symlink_to(f"../{csv_name}")
        publickey = root / area / "publickey"
        publickey.mkdir()
        (publickey / "mgmt-server.pub").symlink_to(
            pointer_link_target(f"{area}/publickey/mgmt-server.pub", "mgmt-server.pub"))
    # Valid foreign-category inventories beside the entrypoints: the key never follows an inventory.
    (root / "infiniband/monitor/eth.csv").symlink_to("../../ethernet/eth.csv")
    (root / "nvlink/monitor/eth.csv").symlink_to("../../ethernet/eth.csv")
    (root / "nvlink/monitor/ib.csv").symlink_to("../../infiniband/ib.csv")
    return projects


def run_preflight(
    root: Path,
    area: str,
    *,
    environment: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(root / area / "monitor/cron.sh")],
        cwd=root,
        env={**os.environ, "LC_ALL": "C", **(environment or {})},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def preflight_values(completed: subprocess.CompletedProcess[str]) -> dict[str, str]:
    return dict(line.split("=", 1) for line in completed.stdout.splitlines())


def key_fields(project: Path) -> str:
    return " ".join((project / "mgmt-server.pub").read_text(encoding="utf-8").split()[:2])


class CollectorInventoryPubkeyDirectTests(unittest.TestCase):
    def _assert_supported_entrypoint(self, area: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            projects = stage_collector_tree(root)
            completed = run_preflight(root, area)

            self.assertEqual(0, completed.returncode, completed.stderr)
            values = preflight_values(completed)
            self.assertEqual(str(root / area / "publickey/mgmt-server.pub"), values["MGMT_PUBKEY_FILE"])
            self.assertEqual(key_fields(projects[PROJECT]), values["SSH_KEY"])

    def test_ethernet_entrypoint_reads_its_publickey_directory(self):
        self._assert_supported_entrypoint("ethernet")

    def test_infiniband_entrypoint_reads_its_publickey_directory(self):
        self._assert_supported_entrypoint("infiniband")

    def test_nvlink_entrypoint_reads_its_publickey_directory(self):
        self._assert_supported_entrypoint("nvlink")

    def test_foreign_key_environment_cannot_override_active_project_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            projects = stage_collector_tree(root)
            completed = run_preflight(
                root,
                "infiniband",
                environment={"MGMT_PUBKEY_FILE": str(projects[OTHER_PROJECT] / "mgmt-server.pub")},
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            values = preflight_values(completed)
            self.assertEqual(str(root / "infiniband/publickey/mgmt-server.pub"), values["MGMT_PUBKEY_FILE"])
            self.assertEqual(key_fields(projects[PROJECT]), values["SSH_KEY"])

    def test_an_inventory_linked_outside_the_project_does_not_move_the_key(self):
        # R-016 §11 v1.1: the two realpath fixtures; the key stays the active project's.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            projects = stage_collector_tree(root)
            project = projects[PROJECT]
            outside = root / "Work/site-material"
            outside.mkdir(parents=True)
            devices = project / "02-devices_config.csv"
            devices.rename(outside / "devices.csv")
            devices.symlink_to(outside / "devices.csv")
            (project / "p2p").mkdir()
            (project / "p2p/x.csv").write_text(
                "hostname,type,eth0_ip,netmask\nEXAMPLE-INFINIBAND01,ib,192.0.2.11,24\n", encoding="utf-8")
            (project / "ib.csv").symlink_to("p2p/x.csv")
            (root / "infiniband/ib.csv").unlink()
            (root / "infiniband/ib.csv").symlink_to(pointer_link_target("infiniband/ib.csv", "ib.csv"))
            for area in INVENTORIES:
                with self.subTest(area=area):
                    completed = run_preflight(root, area)
                    self.assertEqual(0, completed.returncode, completed.stderr)
                    self.assertEqual(key_fields(project), preflight_values(completed)["SSH_KEY"])

    def test_a_missing_key_link_stops_only_that_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            projects = stage_collector_tree(root)
            (root / "infiniband/publickey/mgmt-server.pub").unlink()
            missing = run_preflight(root, "infiniband")
            self.assertEqual(1, missing.returncode)
            self.assertIn(MISSING_KEY, missing.stderr)
            present = run_preflight(root, "ethernet")
            self.assertEqual(0, present.returncode, present.stderr)
            self.assertEqual(key_fields(projects[PROJECT]), preflight_values(present)["SSH_KEY"])

    def test_without_an_active_project_every_entrypoint_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            stage_collector_tree(root)
            (root / "DAY0-Prepare/activate-project").unlink()
            for area in INVENTORIES:
                with self.subTest(area=area):
                    completed = run_preflight(root, area)
                    self.assertEqual(1, completed.returncode)
                    self.assertIn(MISSING_KEY, completed.stderr)


if __name__ == "__main__":
    unittest.main()
