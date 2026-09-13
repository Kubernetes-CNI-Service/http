"""Direct contracts for collector inventory and management-key binding."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
from typing import Dict, Optional
import unittest


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "ethernet/monitor/cron.sh"
INVENTORIES = {
    "ethernet": "eth.csv",
    "infiniband": "ib.csv",
    "nvlink": "nvsw.csv",
}
DEVICE_TYPES = {"ethernet": "eth", "infiniband": "ib", "nvlink": "nvl"}


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
        "printf 'ACTIVE_INVENTORY=%s\\n' \"$ACTIVE_INVENTORY\"\n"
        "printf 'ACTIVE_PROJECT_DIR=%s\\n' \"$ACTIVE_PROJECT_DIR\"\n"
        "printf 'MGMT_PUBKEY_FILE=%s\\n' \"$MGMT_PUBKEY_FILE\"\n"
        "printf 'SSH_KEY=%s\\n' \"$SSH_KEY\"\n"
    )


def stage_collector_tree(root: Path) -> dict[str, tuple[Path, Path]]:
    """Stage the supported published entrypoints around the real preflight."""
    canonical = root / "ethernet/monitor/cron.sh"
    canonical.parent.mkdir(parents=True)
    canonical.write_text(_preflight_harness_source(), encoding="utf-8")
    canonical.chmod(0o755)
    staged: dict[str, tuple[Path, Path]] = {}
    for area, csv_name in INVENTORIES.items():
        project = root / "DAY0-Prepare" / f"site-{area}"
        project.mkdir(parents=True)
        inventory = project / "02-devices_config.csv"
        inventory.write_text(
            "hostname,type,eth0_ip,netmask\n"
            f"EXAMPLE-{area.upper()}01,{DEVICE_TYPES[area]},192.0.2.10,24\n",
            encoding="utf-8",
        )
        key_base = root / f"fixture-{area}-management-key"
        generated = subprocess.run(
            [
                "ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                "-C", f"{area}-collector", "-f", str(key_base),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if generated.returncode != 0:
            raise RuntimeError(generated.stderr)
        (project / "mgmt-server.pub").write_bytes(
            key_base.with_suffix(".pub").read_bytes()
        )

        monitor = root / area / "monitor"
        monitor.mkdir(parents=True, exist_ok=True)
        entrypoint = monitor / "cron.sh"
        if area != "ethernet":
            entrypoint.symlink_to("../../ethernet/monitor/cron.sh")
        category_inventory = root / area / csv_name
        category_inventory.symlink_to(
            f"../DAY0-Prepare/site-{area}/02-devices_config.csv"
        )
        (monitor / csv_name).symlink_to(f"../{csv_name}")
        staged[area] = project, inventory

    # A supported entrypoint is bound to its category, not to whichever
    # inventory filename happens to sort first.  Stage valid foreign-category
    # decoys so a first-existing-file scan cannot pass this contract.
    (root / "infiniband/monitor/eth.csv").symlink_to(
        "../../ethernet/eth.csv"
    )
    (root / "nvlink/monitor/eth.csv").symlink_to("../../ethernet/eth.csv")
    (root / "nvlink/monitor/ib.csv").symlink_to(
        "../../infiniband/ib.csv"
    )
    return staged


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


class CollectorInventoryPubkeyDirectTests(unittest.TestCase):
    def _assert_supported_entrypoint(self, area: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project, inventory = stage_collector_tree(root)[area]
            completed = run_preflight(root, area)

            self.assertEqual(0, completed.returncode, completed.stderr)
            values = dict(
                line.split("=", 1) for line in completed.stdout.splitlines()
            )
            self.assertEqual(str(inventory), values["ACTIVE_INVENTORY"])
            self.assertEqual(str(project), values["ACTIVE_PROJECT_DIR"])
            self.assertEqual(
                str(project / "mgmt-server.pub"), values["MGMT_PUBKEY_FILE"]
            )
            expected_key = (project / "mgmt-server.pub").read_text(
                encoding="utf-8"
            ).split()
            self.assertEqual(" ".join(expected_key[:2]), values["SSH_KEY"])

    def test_ethernet_entrypoint_uses_eth_inventory_for_pubkey_preflight(self):
        self._assert_supported_entrypoint("ethernet")

    def test_infiniband_entrypoint_uses_ib_inventory_for_pubkey_preflight(self):
        self._assert_supported_entrypoint("infiniband")

    def test_nvlink_entrypoint_uses_nvsw_inventory_for_pubkey_preflight(self):
        self._assert_supported_entrypoint("nvlink")

    def test_foreign_key_environment_cannot_override_active_project_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            staged = stage_collector_tree(root)
            active_project, _inventory = staged["infiniband"]
            foreign_project, _foreign_inventory = staged["ethernet"]
            completed = run_preflight(
                root,
                "infiniband",
                environment={
                    "MGMT_PUBKEY_FILE": str(foreign_project / "mgmt-server.pub")
                },
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            values = dict(
                line.split("=", 1) for line in completed.stdout.splitlines()
            )
            self.assertEqual(
                str(active_project / "mgmt-server.pub"),
                values["MGMT_PUBKEY_FILE"],
            )
            expected_key = (active_project / "mgmt-server.pub").read_text(
                encoding="utf-8"
            ).split()
            self.assertEqual(" ".join(expected_key[:2]), values["SSH_KEY"])


if __name__ == "__main__":
    unittest.main()
