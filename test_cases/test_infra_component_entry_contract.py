#!/usr/bin/env python3
"""Direct contracts: --load-components-v1 on infra/deploy_infra.py and infra/infra-setup.py.

DAY0-Prepare/11-load.py (prepare_infra) hands one LOAD component packet, encoded by
tools/infra_components.py, to both infra entries.  The packet is data only:
- deploy_infra.py validates it and refuses it outside setup --prepare-only, before any read or write;
- infra-setup.py (the active setup entry; the http-test line carried this contract in infra-setup.sh,
  50efbbd) validates it, requires the default management deferred policy, requires it to agree with
  the explicit action flags, and then only narrows the Step 6/7 install lists.  The management
  cache list and every run without the option are unchanged.
Every expected value below is a handwritten literal of that contract (packet wire, refusal text,
package lists), never read from the implementation.  infra-setup.py runs in the
test_infra_setup_py sandbox (fake system commands, HOST_ROOT seam); nothing on this machine changes.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_infra_setup_py import GLOBAL, Sandbox, mutating_calls


ROOT = Path(__file__).resolve().parents[1]
PACKET = "load-core,http,render-ib,validate-xlsx,init-dns,init-ntp,init-timezone,init-lldp"
COMPONENTS = ("load-core", "http", "render-ib", "validate-xlsx",
              "init-dns", "init-ntp", "init-timezone", "init-lldp")
FULL_WIRE = ("load-core,http,dhcp,ztp-runtime,render-eth,render-ib,render-nvl,validate-xlsx,"
             "password-hash,password-ssh,docker,nfs,power-cycle,analysis,doca,"
             "init-dns,init-ntp,init-timezone,init-lldp")
MINIMAL = ("load-core", "init-dns", "init-ntp", "init-timezone", "init-lldp")
BAD_PACKETS = (
    "", "load-core", PACKET + ",docker", PACKET + ",$(id)", PACKET + ",../../python3",
    PACKET + ",http", PACKET + "\n", "x" * 513, PACKET.replace("load-core", "LOAD-CORE"),
    "init-dns,load-core,init-ntp,init-timezone,init-lldp", "," + PACKET, PACKET + ",",
    PACKET.replace(",http,", ",http,,"), PACKET + ",apt-get", PACKET + ",é",
)
# Management deferred LOAD call that agrees with PACKET (http, no dhcp, no doca, no power cycle).
SETUP_FLAGS = ("--mgmt", "--defer-services", "--install-apache", "--skip-doca")
FULL_COMMON = ["ipmitool", "sshpass", "docker.io", "unzip", "nfs-common", "arping", "jq"]
FULL_ZTP = ["python3", "python3-yaml", "python3-jinja2", "python3-openpyxl", "python3-pandas",
            "python3-xlsxwriter", "openssh-client", "curl"]
SELECTED_ZTP = ["python3", "python3-yaml", "openssh-client", "curl", "python3-openpyxl"]
INVALID = "ERROR: invalid LOAD component packet\n"
POLICY = "ERROR: LOAD components require default management deferred policy\n"
MISMATCH = "ERROR: LOAD component/action mismatch\n"

SETUP = load_script("infra_component_entry_setup", ROOT / "infra/infra-setup.py")
DEPLOY = load_script("infra_component_entry_deploy", ROOT / "infra/deploy_infra.py")


class InfraSetupPacketFunctions(unittest.TestCase):
    def test_canonical_packets_parse_to_their_ids(self):
        self.assertEqual(COMPONENTS, SETUP.parse_load_component_packet(PACKET))
        self.assertEqual(MINIMAL, SETUP.parse_load_component_packet(",".join(MINIMAL)))
        self.assertEqual(tuple(FULL_WIRE.split(",")), SETUP.parse_load_component_packet(FULL_WIRE))

    def test_non_canonical_packets_are_refused(self):
        for packet in BAD_PACKETS + (None, 1, True, PACKET.encode("ascii")):
            with self.subTest(packet=repr(packet)):
                self.assertIsNone(SETUP.parse_load_component_packet(packet))

    def test_each_component_selects_its_literal_install_lists(self):
        base = ["python3", "python3-yaml", "openssh-client", "curl"]
        cases = (
            ((), [], base),
            (("render-eth",), [], base + ["python3-jinja2"]),
            (("render-ib",), [], base),
            (("render-nvl",), [], base),
            (("validate-xlsx",), [], base + ["python3-openpyxl"]),
            (("analysis",), [], base + ["python3-pandas", "python3-xlsxwriter"]),
            (("password-hash",), [], base + ["whois"]),
            (("password-ssh",), ["sshpass"], base),
            (("docker",), ["docker.io"], base),
            (("nfs",), ["nfs-common"], base),
            (("power-cycle",), ["ipmitool"], base),
            (("http", "dhcp", "ztp-runtime", "doca"), [], base),
        )
        for extra, common, ztp in cases:
            with self.subTest(extra=extra):
                selected = SETUP.load_component_packages(MINIMAL + extra)
                self.assertEqual((common, ztp), (list(selected[0]), list(selected[1])))
        everything = SETUP.load_component_packages(tuple(FULL_WIRE.split(",")))
        self.assertEqual(["ipmitool", "sshpass", "docker.io", "nfs-common"], list(everything[0]))
        self.assertEqual(base + ["python3-jinja2", "python3-openpyxl", "python3-pandas", "python3-xlsxwriter",
                                 "whois"], list(everything[1]))

    def test_legacy_package_tuples_are_untouched(self):
        self.assertEqual(FULL_COMMON, list(SETUP.COMMON_PACKAGES))
        self.assertEqual(FULL_ZTP, list(SETUP.ZTP_DEPENDENCY_PACKAGES))


class InfraSetupPacketCommandLine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="infra-component-entry-")
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def refused(self, label, argv, stderr):
        box = Sandbox(self.base / label, apache=True)
        before = box.snapshot()
        result, calls, _spy, chowns = box.run(*argv)
        self.assertEqual((1, "", stderr), (result.returncode, result.stdout, result.stderr))
        self.assertEqual([], calls)
        self.assertEqual([], chowns)
        self.assertEqual(before, box.snapshot())

    def test_bad_missing_and_repeated_packets_refuse_before_any_command(self):
        for index, packet in enumerate(BAD_PACKETS):
            with self.subTest(packet=repr(packet)):
                self.refused(f"bad{index}", (*SETUP_FLAGS, "--load-components-v1", packet), INVALID)
        with self.subTest(case="missing value"):
            self.refused("missing", (*SETUP_FLAGS, "--load-components-v1"), INVALID)
        with self.subTest(case="repeated"):
            self.refused("repeated", (*SETUP_FLAGS, "--load-components-v1", PACKET,
                                      "--load-components-v1", PACKET), INVALID)

    def test_packet_requires_the_default_management_deferred_policy(self):
        cases = (
            ("no-mgmt", ("--defer-services", "--install-apache", "--skip-doca")),
            ("no-defer", ("--mgmt", "--install-apache", "--skip-doca")),
            ("client", (*SETUP_FLAGS, "--client")),
            ("interactive", (*SETUP_FLAGS, "--interactive")),
            ("all", (*SETUP_FLAGS, "--all")),
        )
        for label, flags in cases:
            with self.subTest(case=label):
                self.refused(label, (*flags, "--load-components-v1", PACKET), POLICY)

    def test_packet_must_agree_with_every_explicit_action_flag(self):
        with_doca = PACKET.replace(",validate-xlsx,", ",validate-xlsx,doca,")
        cases = (
            ("no-apache", ("--mgmt", "--defer-services", "--skip-doca"), PACKET),
            ("extra-dhcp", (*SETUP_FLAGS, "--install-dhcp"), PACKET),
            ("extra-power", (*SETUP_FLAGS, "--power-cycle"), PACKET),
            ("doca-not-skipped", ("--mgmt", "--defer-services", "--install-apache"), PACKET),
            ("doca-skipped", SETUP_FLAGS, with_doca),
            ("bluefield", (*SETUP_FLAGS, "--enable-bluefield-nic"), PACKET),
        )
        for label, flags, packet in cases:
            with self.subTest(case=label):
                self.refused(label, (*flags, "--load-components-v1", packet), MISMATCH)

    def test_check_mode_narrows_only_the_install_lists(self):
        def would(flags):
            box = Sandbox(self.base / ("packet" if "--load-components-v1" in flags else "legacy"), apache=True)
            before = box.snapshot()
            result, calls, _spy, chowns = box.run(*flags, users=("_apt",))
            self.assertEqual(3, result.returncode, result.stderr + result.stdout)
            self.assertEqual(before, box.snapshot())
            self.assertEqual([], mutating_calls(calls))
            self.assertEqual([], chowns)
            lines = [line for line in result.stdout.splitlines() if line.startswith("WOULD APPLY: ")]
            # The two sandboxes differ only in their base directory (macOS may report it via /private).
            for spelling in (os.path.realpath(box.base), str(box.base)):
                lines = [line.replace(spelling, "<BASE>") for line in lines]
            return lines

        legacy = would(SETUP_FLAGS)
        selected = would((*SETUP_FLAGS, "--load-components-v1", PACKET))
        self.assertIn("WOULD APPLY: install " + " ".join(FULL_COMMON), legacy)
        self.assertIn("WOULD APPLY: install " + " ".join(FULL_ZTP), legacy)
        self.assertIn("WOULD APPLY: install " + " ".join(SELECTED_ZTP), selected)
        installs = [line for line in selected if line.startswith("WOULD APPLY: install ")]
        for package in FULL_COMMON + ["python3-jinja2", "python3-pandas", "python3-xlsxwriter", "whois"]:
            with self.subTest(absent=package):
                self.assertFalse([line for line in installs if package in line.split()], installs)
        # Everything except the two narrowed install lines is the legacy plan, cache included.
        narrowed = {"WOULD APPLY: install " + " ".join(FULL_COMMON), "WOULD APPLY: install " + " ".join(FULL_ZTP)}
        self.assertEqual([line for line in legacy if line not in narrowed],
                         [line for line in selected if line != "WOULD APPLY: install " + " ".join(SELECTED_ZTP)])
        self.assertTrue(any(line.startswith("WOULD APPLY: refresh APT indexes and cache the offline package "
                                            "closure (22 packages)") for line in selected), selected)


class DeployInfraPacketCommandLine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="infra-component-deploy-")
        self.box = Sandbox(Path(self.tmp.name), global_text=GLOBAL)

    def tearDown(self):
        self.tmp.cleanup()

    def deploy(self, *argv):
        command = ["deploy_infra.py", "--http-server-ip", "192.0.2.10",
                   "--global-file", str(self.box.infra / "01-global.yaml"),
                   "--devices-file", str(self.box.infra / "02-devices_config.csv"),
                   "--setup-script", str(self.box.infra / "infra-setup.py"), *argv]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", command), \
                mock.patch.object(DEPLOY, "load_servers", return_value=[]) as servers, \
                mock.patch.object(DEPLOY, "_local_ipv4_addresses", return_value={"192.0.2.10"}), \
                mock.patch.object(DEPLOY, "http_service_works", return_value=False) as probe, \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = DEPLOY.main()
        return code, stdout.getvalue(), stderr.getvalue(), servers.call_count + probe.call_count

    def test_refusals_happen_before_any_read_or_write(self):
        runtime = self.box.infra / "infra-runtime.conf"
        cases = tuple((f"bad{index}", ("--prepare-only", "--load-components-v1", packet),
                       "[ERROR] invalid LOAD component packet\n")
                      for index, packet in enumerate(BAD_PACKETS)) + (
            ("repeated", ("--prepare-only", "--load-components-v1", PACKET, "--load-components-v1", PACKET),
             "[ERROR] invalid LOAD component packet\n"),
            ("setup-deploy", ("--load-components-v1", PACKET),
             "[ERROR] LOAD components require setup --prepare-only\n"),
            ("dry-run", ("--dry-run", "--load-components-v1", PACKET),
             "[ERROR] LOAD components require setup --prepare-only\n"),
            ("teardown", ("--teardown", "--prepare-only", "--load-components-v1", PACKET),
             "[ERROR] LOAD components require setup --prepare-only\n"),
        )
        for label, argv, stderr in cases:
            with self.subTest(case=label):
                code, out, err, probes = self.deploy(*argv)
                self.assertEqual((1, "", stderr, 0), (code, out, err, probes))
                self.assertFalse(runtime.exists())

    def test_packet_is_data_only_for_prepare(self):
        runtime = self.box.infra / "infra-runtime.conf"
        code, out, err, _probes = self.deploy("--prepare-only")
        self.assertEqual((0, ""), (code, err), out)
        legacy = runtime.read_bytes()
        runtime.unlink()
        code, out, err, _probes = self.deploy("--prepare-only", "--load-components-v1", PACKET)
        self.assertEqual((0, ""), (code, err), out)
        self.assertIn("[OK] prepare-only 完成，未连接任何设备", out)
        self.assertEqual(legacy, runtime.read_bytes())
        for word in ("load-core", "render-ib", "component"):
            self.assertNotIn(word, runtime.read_text(encoding="utf-8"))

    def test_help_does_not_advertise_the_internal_option(self):
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", ["deploy_infra.py", "--help"]), redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as raised:
                DEPLOY.main()
        self.assertEqual(0, raised.exception.code)
        self.assertNotIn("load-components", stdout.getvalue())
        self.assertNotIn("load-components", SETUP.USAGE)


if __name__ == "__main__":
    unittest.main()
