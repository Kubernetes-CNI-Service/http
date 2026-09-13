#!/usr/bin/env python3
"""Direct contracts for switch-scoped DHCP host-file ownership."""

from __future__ import annotations

from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
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
    sys.path[:0] = [str(path.parent), str(ROOT / "tools"), str(ROOT)]
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.path[:3]
        if previous is None:
            # Dataclasses and runtime helpers retain the defining module name.
            pass
        else:
            sys.modules[name] = previous
    return module


DHCP = load_module(
    "dhcp_switch_scope_direct_production",
    ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
)

FAMILY_FILE = {
    "eth": "dhcpd_eth.hosts",
    "ib": "dhcpd_ib.hosts",
    "nvl": "dhcpd_nvl.hosts",
}
FAMILY_HOST = {
    "eth": "EXAMPLE-Leaf01",
    "ib": "EXAMPLE-IB01",
    "nvl": "EXAMPLE-NVL01",
}
FAMILY_MAC = {
    "eth": "02:00:00:00:10:01",
    "ib": "02:00:00:00:20:01",
    "nvl": "02:00:00:00:30:01",
}
AIR_HOST = "EXAMPLE-AIR01"
AIR_MAC = "02:00:00:00:40:01"


def prior_hosts(family: str) -> bytes:
    """Return an independently valid pre-existing family authority."""
    label = f"H30-PREVIOUS-{family.upper()}"
    mac = {
        "eth": "02:00:00:00:a0:01",
        "ib": "02:00:00:00:b0:01",
        "nvl": "02:00:00:00:c0:01",
    }[family]
    return (
        "##### Independently seeded prior authority\n\n"
        f"host {label} {{\n"
        f"        hardware ethernet {mac};\n"
        f"        option host-name \"{label}\";\n"
        "}\n\n"
        "##### Production 1 entries; AIR 0 entries\n"
    ).encode("ascii")


class ScopedDhcpFixture:
    """Independent three-family inputs and pre-existing output authorities."""

    def __init__(self, root: Path):
        self.root = root
        self.dhcp = root / "ztp/config/isc-dhcp-server"
        self.dhcp.mkdir(parents=True)
        self.global_file = self.dhcp / "01-global.yaml"
        self.devices_file = self.dhcp / "02-devices_config.csv"
        self.subnet_file = self.dhcp / "02-subnet_config.csv"
        self.air_file = self.dhcp / "p2p-air.json"
        self.outputs = {
            "conf": self.dhcp / "dhcpd.conf",
            **{
                family: self.dhcp / filename
                for family, filename in FAMILY_FILE.items()
            },
            "manifest": self.dhcp / "dhcp-release-manifest.json",
        }
        self._write_inputs()
        self.seed_outputs()

    def _write_inputs(self) -> None:
        self.global_file.write_text(
            "schema_version: 1\n"
            "common:\n"
            "  mgmt:\n"
            "    ztp:\n"
            "      ztp_url_prefix: /ztp\n",
            encoding="utf-8",
        )
        self.devices_file.write_text(
            "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
            "eth1_ip,netmask,eth1_gw,eth1_mac\n"
            f"{FAMILY_HOST['eth']},eth,leaf,192.0.2.11,24,192.0.2.1,"
            f"{FAMILY_MAC['eth']},NA,NA,NA,NA\n"
            f"{FAMILY_HOST['ib']},ib,leaf,192.0.2.21,24,192.0.2.1,"
            f"{FAMILY_MAC['ib']},NA,NA,NA,NA\n"
            f"{FAMILY_HOST['nvl']},nvl,leaf,192.0.2.31,24,192.0.2.1,"
            f"{FAMILY_MAC['nvl']},NA,NA,NA,NA\n",
            encoding="utf-8",
        )
        self.subnet_file.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
            "192.0.2.1,192.0.2.2,oob,yes\n",
            encoding="utf-8",
        )

    def seed_outputs(self) -> None:
        for label, path in self.outputs.items():
            if label in FAMILY_FILE:
                path.write_bytes(prior_hosts(label))
            else:
                path.write_bytes(f"H30-OLD-{label}\n".encode("ascii"))
            path.chmod(0o640)

    def add_air_inventory(self) -> None:
        with self.devices_file.open("a", encoding="utf-8") as stream:
            stream.write(
                f"{AIR_HOST},air,leaf,192.0.2.41,24,192.0.2.1,"
                f"{AIR_MAC},NA,NA,NA,NA\n"
            )

    def snapshot(self) -> dict[str, tuple[bytes, tuple[int, int, int, int]]]:
        result = {}
        for label, path in self.outputs.items():
            info = path.lstat()
            result[label] = (
                path.read_bytes(),
                (
                    info.st_dev,
                    info.st_ino,
                    stat.S_IMODE(info.st_mode),
                    info.st_mtime_ns,
                ),
            )
        return result

    def execute(
        self,
        argv: list[str],
        *,
        manifest_failure: BaseException | None = None,
    ) -> None:
        bindings = {
            "HTTP_ROOT": str(self.root),
            "SCRIPT_DIR": str(self.dhcp),
            "OUTPUT_ETH": str(self.outputs["eth"]),
            "OUTPUT_IB": str(self.outputs["ib"]),
            "OUTPUT_NVL": str(self.outputs["nvl"]),
            "OUTPUT_CONF": str(self.outputs["conf"]),
            "OUTPUT_MANIFEST": str(self.outputs["manifest"]),
            "SUBNET_CSV": str(self.subnet_file),
            "GLOBAL_YAML": str(self.global_file),
            "P2P_AIR_JSON": str(self.air_file),
            "DEVICES_CSV": str(self.devices_file),
            "_AUTO_YES": False,
        }
        failure = (
            mock.patch.object(
                DHCP, "write_release_manifest", side_effect=manifest_failure,
            )
            if manifest_failure is not None
            else nullcontext()
        )
        with mock.patch.multiple(DHCP, **bindings), mock.patch.object(
            sys, "argv", argv,
        ), failure:
            DHCP.main()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DhcpSwitchScopeDirectTests(unittest.TestCase):
    def test_each_selected_family_rewrites_only_its_owned_host_file(self):
        for selected in FAMILY_FILE:
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as name:
                fixture = ScopedDhcpFixture(Path(name))
                before = fixture.snapshot()
                fixture.execute([
                    "c1-generate_dhcp.py", "-y", "--deployment-scope", "prod",
                    "--switch", selected,
                ])

                selected_bytes = fixture.outputs[selected].read_bytes()
                self.assertNotEqual(before[selected][0], selected_bytes)
                self.assertIn(FAMILY_HOST[selected].encode("ascii"), selected_bytes)
                for family in FAMILY_FILE:
                    if family == selected:
                        continue
                    self.assertEqual(
                        before[family],
                        (
                            fixture.outputs[family].read_bytes(),
                            (
                                fixture.outputs[family].lstat().st_dev,
                                fixture.outputs[family].lstat().st_ino,
                                stat.S_IMODE(fixture.outputs[family].lstat().st_mode),
                                fixture.outputs[family].lstat().st_mtime_ns,
                            ),
                        ),
                        f"--switch {selected} mutated out-of-scope {family}",
                    )

                manifest = json.loads(
                    fixture.outputs["manifest"].read_text(encoding="utf-8")
                )
                self.assertEqual(selected, manifest["switch_scope"])
                self.assertEqual(
                    [FAMILY_HOST[selected]],
                    [item["hostname"] for item in manifest["devices"]],
                )
                self.assertEqual(1, manifest["counts"]["host_declarations"])
                self.assertEqual(
                    {"eth": 1, "ib": 1, "nvl": 1},
                    manifest["counts"]["host_declarations_by_family"],
                )
                for path in fixture.outputs.values():
                    if path == fixture.outputs["manifest"]:
                        continue
                    self.assertEqual(
                        sha256(path), manifest["outputs"][path.name]["sha256"]
                    )

    def test_default_all_scope_remains_a_full_three_family_rebuild(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            before = fixture.snapshot()
            fixture.execute(["c1-generate_dhcp.py", "-y"])

            for family in FAMILY_FILE:
                current = fixture.outputs[family].read_bytes()
                self.assertNotEqual(before[family][0], current)
                self.assertIn(FAMILY_HOST[family].encode("ascii"), current)
            manifest = json.loads(
                fixture.outputs["manifest"].read_text(encoding="utf-8")
            )
            self.assertEqual("all", manifest["switch_scope"])
            self.assertEqual(3, manifest["counts"]["host_declarations"])
            self.assertEqual(
                {"eth": 1, "ib": 1, "nvl": 1},
                manifest["counts"]["host_declarations_by_family"],
            )
            self.assertEqual(
                set(FAMILY_HOST.values()),
                {item["hostname"] for item in manifest["devices"]},
            )

    def test_generation_failure_restores_every_preexisting_output(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            before = fixture.snapshot()
            with self.assertRaisesRegex(OSError, "injected manifest publication"):
                fixture.execute(
                    ["c1-generate_dhcp.py", "-y", "--switch", "ib"],
                    manifest_failure=OSError("injected manifest publication failure"),
                )

            for label, path in fixture.outputs.items():
                self.assertEqual(before[label][0], path.read_bytes(), label)
            for label, path in fixture.outputs.items():
                info = path.lstat()
                self.assertEqual(
                    before[label][1],
                    (
                        info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode),
                        info.st_mtime_ns,
                    ),
                    label,
                )

    def test_air_scope_implicitly_owns_only_eth_and_preserves_ib_nvl(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            fixture.add_air_inventory()
            before = fixture.snapshot()
            fixture.execute([
                "c1-generate_dhcp.py", "-y", "--deployment-scope", "air",
            ])

            self.assertIn(AIR_HOST, fixture.outputs["eth"].read_text())
            for family in ("ib", "nvl"):
                info = fixture.outputs[family].lstat()
                self.assertEqual(
                    before[family],
                    (
                        fixture.outputs[family].read_bytes(),
                        (
                            info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode),
                            info.st_mtime_ns,
                        ),
                    ),
                    family,
                )
            manifest = json.loads(
                fixture.outputs["manifest"].read_text(encoding="utf-8")
            )
            self.assertEqual("air", manifest["deployment_scope"])
            self.assertEqual("eth", manifest["switch_scope"])
            self.assertEqual([AIR_HOST], [item["hostname"] for item in manifest["devices"]])
            self.assertEqual(1, manifest["counts"]["host_declarations"])
            self.assertEqual(
                {"eth": 1, "ib": 1, "nvl": 1},
                manifest["counts"]["host_declarations_by_family"],
            )
            for path in fixture.outputs.values():
                if path != fixture.outputs["manifest"]:
                    self.assertEqual(
                        sha256(path), manifest["outputs"][path.name]["sha256"]
                    )


if __name__ == "__main__":
    unittest.main()
