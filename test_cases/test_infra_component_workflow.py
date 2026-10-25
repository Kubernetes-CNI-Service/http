#!/usr/bin/env python3
"""Workflow: LOAD component codec -> deploy_infra.py --prepare-only -> infra-setup.py --apply.

Adaptation of the http-test f384f73 module of the same name (I06) to this tree, where
infra/infra-setup.py replaced infra-setup.sh: the setup child is the real Python entry run in the
test_infra_setup_py sandbox (fake system commands, HOST_ROOT seam; nothing on this machine
changes) instead of a Bash capsule, and deploy_infra.py runs in process through its real argparse.
Covered: the packet the real codec (tools/infra_components.py) encodes is accepted unchanged by
both real children; deploy_infra's runtime block and infra-setup.py's management cache stay the
legacy ones; only the Step 6/7 installs narrow (known-true control: the same chain without the
packet installs both full lists); the setup entry's closed ID order and parser agree with the codec.
The LOAD half (prepare_infra(_load_components=...) and main's finite profile) arrives with the
11-load batch and extends this module then.
Expected values are handwritten literals of the I06 contract, never implementation output.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from itertools import combinations
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_infra_setup_py import GLOBAL, Sandbox


ROOT = Path(__file__).resolve().parents[1]
PACKET = "load-core,http,render-ib,validate-xlsx,init-dns,init-ntp,init-timezone,init-lldp"
COMPONENTS = ("load-core", "http", "render-ib", "validate-xlsx",
              "init-dns", "init-ntp", "init-timezone", "init-lldp")
FULL_WIRE = ("load-core,http,dhcp,ztp-runtime,render-eth,render-ib,render-nvl,validate-xlsx,"
             "password-hash,password-ssh,docker,nfs,power-cycle,analysis,doca,"
             "init-dns,init-ntp,init-timezone,init-lldp")
SETUP_FLAGS = ("--mgmt", "--defer-services", "--install-apache", "--skip-doca")
BASE = ["wget", "lldpd", "tzdata"]
FULL_COMMON = ["ipmitool", "sshpass", "docker.io", "unzip", "nfs-common", "arping", "jq"]
FULL_ZTP = ["python3", "python3-yaml", "python3-jinja2", "python3-openpyxl", "python3-pandas",
            "python3-xlsxwriter", "openssh-client", "curl"]
OPTIONAL = ["apache2", "apache2-utils", "ssl-cert", "isc-dhcp-server"]
SELECTED_ZTP = ["python3", "python3-yaml", "openssh-client", "curl", "python3-openpyxl"]
STEP_UNIVERSE = frozenset(FULL_COMMON + FULL_ZTP + ["whois"])

CODEC = load_script("infra_component_workflow_codec", ROOT / "tools/infra_components.py")
SETUP = load_script("infra_component_workflow_setup", ROOT / "infra/infra-setup.py")
DEPLOY = load_script("infra_component_workflow_deploy", ROOT / "infra/deploy_infra.py")


def apt_lists(calls: list) -> tuple:
    """(install package lists, download-only package lists) from the fake apt-get record."""
    installs, downloads = [], []
    for call in calls:
        args = call["args"]
        if call["tool"] != "apt-get" or "install" not in args:
            continue
        packages = args[args.index("-y") + 1:]
        (downloads if "--download-only" in args else installs).append(packages)
    return installs, downloads


class InfraComponentChainWorkflow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="infra-component-workflow-")
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def deploy_prepare(self, box, packet):
        argv = ["deploy_infra.py", "--prepare-only", "--http-server-ip", "192.0.2.10",
                "--global-file", str(box.infra / "01-global.yaml"),
                "--devices-file", str(box.infra / "02-devices_config.csv"),
                "--setup-script", str(box.infra / "infra-setup.py")]
        if packet is not None:
            argv += ["--load-components-v1", packet]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(DEPLOY, "load_servers", return_value=[]), \
                mock.patch.object(DEPLOY, "_local_ipv4_addresses", return_value={"192.0.2.10"}), \
                mock.patch.object(DEPLOY, "http_service_works", return_value=False), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = DEPLOY.main()
        self.assertEqual((0, ""), (code, stderr.getvalue()), stdout.getvalue())
        return (box.infra / "infra-runtime.conf").read_bytes()

    def chain(self, label, packet):
        box = Sandbox(self.base / label, global_text=GLOBAL, apache=True)
        runtime = self.deploy_prepare(box, packet)
        flags = SETUP_FLAGS + (() if packet is None else ("--load-components-v1", packet))
        result, calls, _spy, _chown = box.apply(*flags, users=("_apt",))
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        installs, downloads = apt_lists(calls)
        return box, runtime, installs, downloads

    def test_codec_packet_drives_both_real_children_and_narrows_only_installs(self):
        selected = CODEC.select_load_components(
            http_enabled=True, dhcp_enabled=False, ztp_enabled=False,
            device_types=("ib",), workbook_selected=True, features=(),
        )
        self.assertEqual(COMPONENTS, selected)
        wire = CODEC.encode_load_components(selected)
        self.assertEqual(PACKET, wire)

        box, runtime, installs, downloads = self.chain("packet", wire)
        legacy_box, legacy_runtime, legacy_installs, legacy_downloads = self.chain("legacy", None)

        # deploy_infra treats the packet as data only: the runtime block is the legacy one.
        self.assertEqual(legacy_runtime, runtime)
        self.assertNotIn(b"load-core", runtime)
        # The management cache keeps its fixed closure in both runs.
        self.assertEqual([BASE + FULL_COMMON + FULL_ZTP + OPTIONAL], downloads)
        self.assertEqual(legacy_downloads, downloads)
        # Known-true control: without the packet both full Step 6/7 lists are installed.
        self.assertEqual([FULL_COMMON, FULL_ZTP],
                         [packages for packages in legacy_installs if STEP_UNIVERSE & set(packages)])
        # With the packet only the selected ZTP dependencies are installed; Step 6 installs nothing.
        self.assertEqual([SELECTED_ZTP],
                         [packages for packages in installs if STEP_UNIVERSE & set(packages)])
        # Every other installation (base, Apache) is identical.
        self.assertEqual([packages for packages in legacy_installs if not STEP_UNIVERSE & set(packages)],
                         [packages for packages in installs if not STEP_UNIVERSE & set(packages)])
        recorded = box.packages()
        for package in SELECTED_ZTP:
            self.assertIn(package, recorded)
        for package in sorted(STEP_UNIVERSE - set(SELECTED_ZTP)):
            with self.subTest(not_installed=package):
                self.assertNotIn(package, recorded)
        for package in FULL_COMMON + FULL_ZTP:
            self.assertIn(package, legacy_box.packages())
        for completed in (box, legacy_box):
            run_info = completed.key_values(completed.root / "var/lib/http-infra/run-info")
            self.assertEqual(("true", "completed"), (run_info["mgmt_mode"], run_info["status"]))


class InfraComponentCodecBinding(unittest.TestCase):
    """The setup entry repeats the closed order (it ships alone to clients); bind it to the codec."""

    def test_closed_order_and_required_ids_match_the_codec_and_the_contract(self):
        self.assertEqual(tuple(FULL_WIRE.split(",")), CODEC.COMPONENT_ORDER)
        self.assertEqual(tuple(FULL_WIRE.split(",")), SETUP.LOAD_COMPONENT_ORDER)
        self.assertEqual(("load-core", "init-dns", "init-ntp", "init-timezone", "init-lldp"),
                         SETUP.LOAD_COMPONENT_REQUIRED)

    def test_every_codec_profile_round_trips_through_the_setup_parser(self):
        families = ("eth", "ib", "nvl")
        features = ("password-hash", "password-ssh", "docker", "nfs", "power-cycle", "analysis", "doca")
        checked = 0
        for flags in range(16):
            http, dhcp, ztp, workbook = (bool(flags & bit) for bit in (1, 2, 4, 8))
            for count in range(len(families) + 1):
                for chosen_families in combinations(families, count):
                    for chosen_features in ((), features[:1], features[3:5], features):
                        selected = CODEC.select_load_components(
                            http_enabled=http, dhcp_enabled=dhcp, ztp_enabled=ztp,
                            device_types=chosen_families, workbook_selected=workbook,
                            features=chosen_features,
                        )
                        wire = CODEC.encode_load_components(selected)
                        self.assertEqual(selected, CODEC.parse_load_components(wire))
                        self.assertEqual(selected, SETUP.parse_load_component_packet(wire))
                        checked += 1
        self.assertEqual(16 * 8 * 4, checked)

    def test_both_parsers_refuse_the_same_non_canonical_packets(self):
        for packet in ("", "load-core", PACKET + ",docker", PACKET + ",http", PACKET + "\n", "x" * 513,
                       "," + PACKET, PACKET.replace("load-core", "LOAD-CORE"), PACKET + ",é",
                       "init-dns,load-core,init-ntp,init-timezone,init-lldp"):
            with self.subTest(packet=repr(packet)):
                with self.assertRaises(ValueError):
                    CODEC.parse_load_components(packet)
                self.assertIsNone(SETUP.parse_load_component_packet(packet))


if __name__ == "__main__":
    unittest.main()
