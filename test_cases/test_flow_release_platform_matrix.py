#!/usr/bin/env python3
"""Isolated producer-to-consumer release flow for every managed ZTP platform.

The fixture deliberately runs the real Cumulus/NVOS YAML generators, the
shared hostname-to-MAC publisher, the ISC DHCP generator, and the parent
release validator.  All logical service paths point into one temporary DAY0
project; no command reaches a switch, /etc, or the repository's project
outputs.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def load_module(name: str, path: Path):
    """Load one production source under an isolated module identity."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    sys.path[:0] = [str(path.parent), str(TOOLS), str(ROOT)]
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.path[:3]
        if previous is None:
            # Dataclasses keep the defining module name.  Leave the module
            # registered for the duration of this test process.
            pass
        else:
            sys.modules[name] = previous
    return module


CUMULUS_GENERATOR = load_module(
    "flow_release_cumulus_generator",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
NVOS_GENERATOR = load_module(
    "flow_release_nvos_generator",
    ROOT / "ztp/config/nvos/template/90-c2-generate_configs.py",
)
PUBLISHER = load_module(
    "flow_release_hostname_publisher",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
DHCP = load_module(
    "flow_release_dhcp_generator",
    ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
)
RUNTIME = load_module(
    "flow_release_dhcp_runtime",
    ROOT / "ztp/dhcp_runtime_inventory.py",
)
LOAD = load_module(
    "flow_release_parent_consumer",
    ROOT / "DAY0-Prepare/11-load.py",
)


TIMESTAMP = "20260901_120000"
PROD_HOST = "Prod-Leaf01"
AIR_HOST = "AIR-Prod-Leaf01"
IB_HOST = "IB-Leaf01"
NVL_HOST = "NVL-Leaf01"

PROD_MAC = "02:00:00:00:00:10"
AIR_MAC = "02:00:00:00:00:11"
IB_MAC0 = "02:00:00:00:00:20"
IB_MAC1 = "02:00:00:00:00:21"
NVL_MAC = "02:00:00:00:00:30"
UNKNOWN_MAC = "02:00:00:00:00:99"


def mac_filename(mac: str) -> str:
    return re.sub(r"[^0-9a-f]", "", mac.casefold()) + ".yaml"


class PlatformReleaseFlowTests(unittest.TestCase):
    """Run one real four-device release and inspect each platform boundary."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        try:
            cls._build_flow(Path(cls.temporary.name))
        except BaseException:
            cls.temporary.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_generic_aaa_user_crosses_generator_and_publisher_yaml_boundary(self):
        global_config = {
            "system": {"aaa": {"user": {
                "cumulus": {
                    "full-name": "cumulus,,,,",
                    "hashed-password": "'$6$existing'",
                },
                "ops-reader": {
                    "full-name": "Operations: read only #1",
                    "hashed-password": "$6$example",
                    "role": "nvue-monitor",
                },
            }}}
        }
        fragment = CUMULUS_GENERATOR.build_env().get_template(
            "_extra_aaa_users.yaml.j2"
        ).render(g=global_config)
        document = (
            "- set:\n"
            "    system:\n"
            "      aaa:\n"
            "        user:\n"
            + fragment
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "Prod-Leaf01.yaml"
            output.write_text(document, encoding="utf-8")
            # Consume the generated file through the real hostname publisher's
            # strict canonical loader, not a test-only YAML parser.
            canonical = PUBLISHER._canonical_yaml(str(output))
        parsed = yaml.safe_load(canonical)
        account = parsed[0]["set"]["system"]["aaa"]["user"]["ops-reader"]
        self.assertEqual("Operations: read only #1", account["full-name"])
        self.assertEqual("$6$example", account["hashed-password"])
        self.assertEqual("nvue-monitor", account["role"])

        malicious = {
            "system": {"aaa": {"user": {
                "cumulus": {"hashed-password": "'$6$existing'"},
                "bad-user:\n          injected": {
                    "hashed-password": "$6$example",
                    "role": "system-admin",
                },
            }}}
        }
        with self.assertRaisesRegex(ValueError, "AAA username"):
            CUMULUS_GENERATOR.build_env().get_template(
                "_extra_aaa_users.yaml.j2"
            ).render(g=malicious)

    @classmethod
    def _build_flow(cls, root: Path) -> None:
        cls.root = root
        cls.project = root / "DAY0-Prepare/demo"
        cls.project.mkdir(parents=True)
        cls.ztp = root / "ztp"
        cls.cumulus = cls.ztp / "config/cumulus"
        cls.nvos = cls.ztp / "config/nvos"
        cls.dhcp = cls.ztp / "config/isc-dhcp-server"
        for directory in (cls.cumulus / "template", cls.nvos / "template", cls.dhcp):
            directory.mkdir(parents=True)

        cls.global_file = cls.project / "01-global.yaml"
        cls.devices_file = cls.project / "02-devices_config.csv"
        cls.subnet_file = cls.project / "02-dhcp-subnet_config.csv"
        cls.p2p_file = cls.project / "p2p.xlsx"
        cls.global_file.write_text(
            """schema_version: 1
common:
  mgmt:
    ztp:
      ztp_url_prefix: /ztp
  switch:
    system:
      date-time:
        timezone: UTC
switches:
  - eth:
      version: 5.16.4
      system: {}
  - ib:
      system: {}
  - nvl:
      system: {}
""",
            encoding="utf-8",
        )
        cls.devices_file.write_text(
            "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
            "eth1_ip,netmask,eth1_gw,eth1_mac\n"
            f"{PROD_HOST},eth,leaf,192.0.2.10,24,192.0.2.1,{PROD_MAC},"
            "NA,NA,NA,NA\n"
            f"{IB_HOST},ib,leaf,192.0.2.20,24,192.0.2.1,{IB_MAC0},"
            f"192.0.3.20,24,192.0.3.1,{IB_MAC1}\n"
            f"{NVL_HOST},nvl,leaf,192.0.2.30,24,192.0.2.1,{NVL_MAC},"
            "NA,NA,NA,NA\n",
            encoding="utf-8",
        )
        cls.subnet_file.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
            "192.0.2.1,192.0.2.2,oob,yes\n"
            "ib-secondary,192.0.3.0,255.255.255.0,192.0.3.100,192.0.3.200,"
            "192.0.3.1,192.0.2.2,none,yes\n",
            encoding="utf-8",
        )
        cls.p2p_file.write_bytes(b"isolated-flow-fixture\n")

        # setup normally creates these project-input and output links.  Keep
        # that ownership boundary in the fixture instead of redirecting a
        # publisher to an arbitrary directory.
        for template in (cls.cumulus / "template", cls.nvos / "template"):
            (template / "01-global.yaml").symlink_to(cls.global_file)
            (template / "02-devices_config.csv").symlink_to(cls.devices_file)
        (cls.dhcp / "01-global.yaml").symlink_to(cls.global_file)
        (cls.dhcp / "02-devices_config.csv").symlink_to(cls.devices_file)
        (cls.dhcp / "02-subnet_config.csv").symlink_to(cls.subnet_file)

        cls.eth_output_root = cls.project / "99-output-eth"
        cls.nvos_output_root = cls.project / "99-output-ib_nvl"
        cls.eth_output_root.mkdir()
        cls.nvos_output_root.mkdir()
        (cls.cumulus / "template/99-output").symlink_to(cls.eth_output_root)
        (cls.nvos / "template/99-output-ib_nvl").symlink_to(cls.nvos_output_root)

        # One AIR topology node is authoritative for its MAC.  DHCP first
        # rebuilds the AIR row by inheriting the Production addressing, exactly
        # as load does before Cumulus AIR YAML generation.
        p2p_output = cls.cumulus / "template/P2P/output-p2p"
        p2p_output.mkdir(parents=True)
        cls.air_json = p2p_output / "demo-air.json"
        cls.air_json.write_text(json.dumps({
            "content": {"nodes": {
                AIR_HOST: {
                    "os": "cumulus-vx-5.16.4",
                    "management_interfaces": {
                        "eth0": {"mac_address": AIR_MAC},
                    },
                },
            }},
        }), encoding="utf-8")
        (cls.dhcp / "p2p-air.json").symlink_to(cls.air_json)

        cls._run_dhcp_generator()
        cls._run_cumulus_generator_and_publisher(p2p_output)
        cls._run_nvos_generator_and_publisher()
        cls._run_parent_consumer()

    @classmethod
    def _run_dhcp_generator(cls) -> None:
        bindings = {
            "SCRIPT_DIR": str(cls.dhcp),
            "OUTPUT_ETH": str(cls.dhcp / "dhcpd_eth.hosts"),
            "OUTPUT_IB": str(cls.dhcp / "dhcpd_ib.hosts"),
            "OUTPUT_NVL": str(cls.dhcp / "dhcpd_nvl.hosts"),
            "OUTPUT_CONF": str(cls.dhcp / "dhcpd.conf"),
            "OUTPUT_MANIFEST": str(cls.dhcp / "dhcp-release-manifest.json"),
            "SUBNET_CSV": str(cls.dhcp / "02-subnet_config.csv"),
            "GLOBAL_YAML": str(cls.dhcp / "01-global.yaml"),
            "P2P_AIR_JSON": str(cls.dhcp / "p2p-air.json"),
            "DEVICES_CSV": str(cls.dhcp / "02-devices_config.csv"),
            "_AUTO_YES": False,
        }
        with mock.patch.multiple(DHCP, **bindings), mock.patch.object(
            sys, "argv", ["c1-generate_dhcp.py", "-y"],
        ):
            DHCP.main()

    @classmethod
    def _run_cumulus_generator_and_publisher(cls, p2p_output: Path) -> None:
        template = cls.cumulus / "template"
        default = cls.cumulus / "default_5.16.4.yaml"
        default.write_text(
            "- set:\n"
            "    system:\n"
            "      date-time:\n"
            "        timezone: UTC\n",
            encoding="utf-8",
        )
        raw_yaml = (
            "- set:\n"
            "    interface:\n"
            "      eth0:\n"
            "        ipv4:\n"
            "          address:\n"
            "            192.0.2.10/24: {}\n"
            "          gateway:\n"
            "            192.0.2.1: {}\n"
            "        type: eth\n"
            "    system:\n"
            f"      hostname: {PROD_HOST}\n"
        )
        encoded = base64.b64encode(raw_yaml.encode()).decode("ascii")
        (template / "91-devices.yaml").write_text(
            yaml.safe_dump({
                "global": {},
                "devices": {PROD_HOST: {
                    "source_yaml_b64": encoded,
                    "source_yaml_sha256": hashlib.sha256(
                        raw_yaml.encode()
                    ).hexdigest(),
                }},
            }, sort_keys=False),
            encoding="utf-8",
        )
        templates = template / "03-templates-j2"
        templates.mkdir()
        production = template / f"99-output/{TIMESTAMP}"
        air = template / f"99-output/{TIMESTAMP}_air"
        with mock.patch.multiple(
            CUMULUS_GENERATOR,
            SCRIPT_DIR=str(template),
            _GLOBAL_FILE=str(template / "01-global.yaml"),
            DEVICES_FILE=str(template / "91-devices.yaml"),
            TEMPLATES_DIR=str(templates),
            P2P_INPUT_DIR=str(p2p_output.parent),
            P2P_OUTPUT_DIR=str(p2p_output),
            OUTPUT_DIR=str(production),
        ):
            CUMULUS_GENERATOR.generate_all()
            CUMULUS_GENERATOR.generate_air_hostname_configs(
                str(production), str(air),
            )

        devices = PUBLISHER.load_csv(cls.devices_file)
        contexts = [
            PUBLISHER._cumulus_dir_context(str(production)),
            PUBLISHER._cumulus_dir_context(str(air)),
        ]
        with mock.patch.object(PUBLISHER, "_AUTO_YES", True):
            published = PUBLISHER._publish_combined_cumulus(contexts, devices)
        if not published:
            raise AssertionError("Cumulus/AIR publisher rejected generated artifacts")
        cls.cumulus_release = (cls.cumulus / "latest_yaml").resolve(strict=True)

    @classmethod
    def _run_nvos_generator_and_publisher(cls) -> None:
        template = cls.nvos / "template"
        ib_dir = template / f"99-output-ib_nvl/{TIMESTAMP}-ib"
        nvl_dir = template / f"99-output-ib_nvl/{TIMESTAMP}-nvl"
        with mock.patch.multiple(
            NVOS_GENERATOR,
            SCRIPT_DIR=str(template),
            _CSV_FILE=str(template / "02-devices_config.csv"),
            _GLOBAL_FILE=str(template / "01-global.yaml"),
            OUTPUT_IB_NVL_ROOT=str(template / "99-output-ib_nvl"),
            OUTPUT_IB_DIR=str(ib_dir),
            OUTPUT_NVL_DIR=str(nvl_dir),
        ):
            generated = NVOS_GENERATOR._generate_all_ib()
        if generated != 2:
            raise AssertionError(f"expected two NVOS configs, generated {generated}")

        devices = PUBLISHER.load_csv(cls.devices_file)
        contexts = [
            PUBLISHER._nvos_dir_context(str(ib_dir)),
            PUBLISHER._nvos_dir_context(str(nvl_dir)),
        ]
        with mock.patch.object(PUBLISHER, "_AUTO_YES", True):
            published = PUBLISHER._publish_combined_nvos(contexts, devices)
        if not published:
            raise AssertionError("NVOS publisher rejected generated IB/NVL artifacts")
        cls.nvos_release = (cls.nvos / "latest_yaml").resolve(strict=True)

    @classmethod
    def _run_parent_consumer(cls) -> None:
        settings = LOAD.GlobalSettings(
            dhcp_enabled=True,
            dhcp_package="isc-dhcp-server",
            http_enabled=True,
            http_package="apache2",
            http_root=cls.root,
            ztp_enabled=True,
            ztp_prefix="/ztp",
            ztp_ips={"prod_oob": ("192.0.2.2",)},
            versions={"cumulus": "5.16.4", "nvos": "25.02"},
        )
        inputs = LOAD.ProjectInputs(
            global_file=cls.global_file,
            devices_file=cls.devices_file,
            subnet_file=cls.subnet_file,
            p2p_file=cls.p2p_file,
            device_types=frozenset({"eth", "air", "ib", "nvl"}),
            pubkeys=(),
            settings=settings,
        )
        with mock.patch.object(LOAD, "ZTP_DIR", cls.ztp):
            cls.parent = LOAD.validate_and_publish_release(
                cls.project, inputs, publish=True,
            )

    def test_cumulus_production_and_air_are_generated_published_and_consumed(self):
        manifest = json.loads(
            (self.cumulus_release / "release-manifest.json").read_text()
        )
        devices = {item["hostname"]: item for item in manifest["devices"]}
        self.assertEqual({PROD_HOST, AIR_HOST}, set(devices))
        self.assertEqual("production", devices[PROD_HOST]["environment"])
        self.assertEqual("air", devices[AIR_HOST]["environment"])
        self.assertEqual("replace", devices[PROD_HOST]["apply_mode"])
        self.assertEqual("replace", devices[AIR_HOST]["apply_mode"])
        for hostname, mac in ((PROD_HOST, PROD_MAC), (AIR_HOST, AIR_MAC)):
            link = self.cumulus_release / mac_filename(mac)
            self.assertTrue(link.is_symlink())
            self.assertEqual(f"{hostname}.yaml", os.readlink(link))
        self.assertEqual(
            manifest["release_id"],
            self.parent["components"]["cumulus"]["release_id"],
        )

    def test_nvos_ib_and_nvl_are_generated_published_and_consumed(self):
        manifest = json.loads(
            (self.nvos_release / "release-manifest.json").read_text()
        )
        devices = {item["hostname"]: item for item in manifest["devices"]}
        self.assertEqual({IB_HOST, NVL_HOST}, set(devices))
        self.assertEqual("ib", devices[IB_HOST]["type"])
        self.assertEqual("nvl", devices[NVL_HOST]["type"])
        self.assertEqual({IB_MAC0, IB_MAC1}, set(devices[IB_HOST]["macs"]))
        for hostname, mac in (
            (IB_HOST, IB_MAC0), (IB_HOST, IB_MAC1), (NVL_HOST, NVL_MAC),
        ):
            link = self.nvos_release / mac_filename(mac)
            self.assertTrue(link.is_symlink())
            self.assertEqual(f"{hostname}.yaml", os.readlink(link))
        self.assertEqual(
            manifest["release_id"],
            self.parent["components"]["nvos"]["release_id"],
        )
        self.assertEqual(
            {"dhcp", "cumulus", "nvos"}, set(self.parent["components"]),
        )

    def test_unknown_platform_gets_a_pool_but_no_url_or_release_identity(self):
        config = (self.dhcp / "dhcpd.conf").read_text(encoding="utf-8")
        self.assertIn("range 192.0.2.100 192.0.2.200;", config)
        self.assertIn('option cumulus-provision-url "http://192.0.2.2/ztp/', config)
        self.assertIn('option bootfile-name "http://192.0.2.2/ztp/ztp.json";', config)
        self.assertNotRegex(config, r"(?m)^\s*else\s*\{")

        lease = self.root / "dhcpd.leases"
        lease.write_text(
            "lease 192.0.2.150 {\n"
            "  starts 1 2026/09/01 04:00:00;\n"
            "  ends 1 2099/09/01 05:00:00;\n"
            "  binding state active;\n"
            f"  hardware ethernet {UNKNOWN_MAC};\n"
            "}\n",
            encoding="utf-8",
        )
        journal = (
            "2026-09-01T04:00:00+00:00 host dhcpd[1]: "
            f"ZTP_DHCP_EVENT_V1 event=packet msg=1 mac={UNKNOWN_MAC} ip=- "
            "known=0 lease_state=observed vendor60_hex=- "
            "client61_hex=- user77_hex=-"
        )
        observed = RUNTIME.unknown_dhcp_devices(
            journal_text=journal,
            lease_path=lease,
            inventory_path=self.devices_file,
        )
        self.assertEqual(1, len(observed))
        self.assertEqual("unknown", observed[0]["platform"])
        self.assertEqual("192.0.2.150", observed[0]["ip"])

        inventory_hosts = {item["hostname"] for item in self.parent["inventory"]}
        self.assertEqual({PROD_HOST, AIR_HOST, IB_HOST, NVL_HOST}, inventory_hosts)
        for name in ("dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"):
            self.assertNotIn(UNKNOWN_MAC, (self.dhcp / name).read_text())


if __name__ == "__main__":
    unittest.main()
