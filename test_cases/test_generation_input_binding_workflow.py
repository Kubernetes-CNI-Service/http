#!/usr/bin/env python3
"""Real setup/load/c2 handoff when a project input changes after validation."""

from __future__ import annotations

import base64
import copy
import csv
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import openpyxl
import yaml

from test_cases.module_loader import load_script
from test_cases.test_v2_generation_flow import (
    BASE_HEADER,
    EVPN_HEADER,
    FIXED_HEADER,
    V2MlagSetupPreflightTests,
    v2_mlag_preflight_global,
)
from test_cases.test_mlag_evpn_generation import border_globals
from test_cases import test_flow_release_platform_matrix as PLATFORM_FLOW


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script(
    "r22_generation_binding_workflow_setup", ROOT / "DAY0-Prepare/01-a-setup.py",
)
LOAD = load_script(
    "r22_generation_binding_workflow_load", ROOT / "DAY0-Prepare/11-load.py",
)
C2 = load_script(
    "r22_generation_binding_workflow_c2",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
ACTIVATE = load_script(
    "r22_generation_binding_workflow_activate", ROOT / "infra/docker/activate.py",
)
PUBLISHER = load_script(
    "r22_generation_binding_workflow_publisher",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
SUBNET_HEADER = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
)

REAL_CHILD_SCRIPTS = (
    "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
    "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
    "ztp/config/cumulus/template/90-c2-generate_configs.py",
    "ztp/config/cumulus/d-hostname2mac.py",
)
DHCP_OUTPUTS = (
    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
    "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
)


def _write_legal_project(project: Path, rows: list[list[str]]) -> None:
    project.mkdir()
    document = v2_mlag_preflight_global()
    document["common"]["mgmt"].update({
        "dhcp-server": {"status": "disabled", "package": "isc-dhcp-server"},
        "http": {
            "status": "disabled", "http_root": "/var/www/html",
            "package": "apache2", "port": 80,
        },
        "ztp": {"status": "disabled", "ztp_url_prefix": "/ztp"},
    })
    document["common"]["switch"] = {
        "system": {"dns": {}, "ntp": {}, "date-time": {}},
    }
    document["switches"][0]["eth"]["system"]["aaa"] = {
        "user": {"cumulus": {"hashed-password": "$6$fixture$safe-value"}},
    }
    (project / "01-global.yaml").write_text(
        yaml.safe_dump(document, sort_keys=False), encoding="utf-8",
    )
    with (project / "02-devices_config.csv").open(
        "w", newline="", encoding="utf-8",
    ) as stream:
        csv.writer(stream).writerows([BASE_HEADER + FIXED_HEADER + EVPN_HEADER, *rows])
    (project / "02-dhcp-subnet_config.csv").write_text(
        SUBNET_HEADER, encoding="utf-8",
    )
    workbook = openpyxl.Workbook()
    try:
        workbook.save(project / "p2p.xlsx")
    finally:
        workbook.close()
    # A literal, structurally valid OpenSSH public key keeps LOAD's real
    # workstation key preflight on the path without touching the real HOME.
    key_type = b"ssh-ed25519"
    wire = (
        struct.pack(">I", len(key_type)) + key_type
        + struct.pack(">I", 32) + b"\x11" * 32
    )
    (project / "operator.pub").write_text(
        "ssh-ed25519 " + base64.b64encode(wire).decode("ascii") + " fixture\n",
        encoding="utf-8",
    )
    (project / ".management-pubkeys").write_text(
        "mgmt-server.pub\n", encoding="utf-8",
    )
    (project / "mgmt-server.pub").write_bytes(b"")


def _private_real_chain(
    root: Path, dns_ip: str, *, http_enabled: bool = False,
) -> tuple[Path, Path]:
    """Build only the files real LOAD/b/c1/c2/d read under a private root."""
    project = root / "DAY0-Prepare/project"
    project.parent.mkdir(parents=True)
    _write_legal_project(project, V2MlagSetupPreflightTests().pair())
    global_file = project / "01-global.yaml"
    document = yaml.safe_load(global_file.read_text(encoding="utf-8"))
    document["common"]["mgmt"]["dhcp-server"]["status"] = "enabled"
    document["common"]["mgmt"]["ztp"]["status"] = "enabled"
    if http_enabled:
        document["common"]["mgmt"]["http"]["status"] = "enabled"
    complete = border_globals()
    eth = document["switches"][0]["eth"]
    eth["bridge"] = complete["bridge"]
    eth["version"] = complete["version"]
    eth["vrf"] = complete["vrf"]
    eth["mlag"].update(complete["mlag"])
    eth["mlag"]["priority"] = [100, 200]
    eth["system"]["date-time"] = complete["system"]["date-time"]
    eth["system"]["ntp"] = complete["system"]["ntp"]
    eth["system"]["dns"] = {"server": [dns_ip], "vrf": "mgmt"}
    eth["system"]["aaa"]["user"]["cumulus"]["full-name"] = "cumulus,,,"
    global_file.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    (project / "02-dhcp-subnet_config.csv").write_text(
        SUBNET_HEADER
        + "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
        "192.0.2.1,192.0.2.20,oob,no\n",
        encoding="utf-8",
    )
    workbook = openpyxl.Workbook()
    try:
        sheet = workbook.active
        sheet.title = "OOB Server-LF"
        sheet.cell(1, 5, "Source")
        sheet.cell(1, 11, "Dest")
        for col, value in ((7, "name"), (8, "HCA/port"), (13, "name"), (14, "port")):
            sheet.cell(2, col, value)
        sheet.cell(3, 7, "Border01")
        sheet.cell(3, 8, "swp53")
        sheet.cell(3, 13, "Border02")
        sheet.cell(3, 14, "swp53")
        workbook.save(project / "selected-p2p.xlsx")
    finally:
        workbook.close()
    (project / "p2p.xlsx").unlink()
    (project / "p2p.xlsx").symlink_to("selected-p2p.xlsx")

    ztp = root / "ztp"
    shutil.copytree(ROOT / "tools", root / "tools")
    resources = (
        "ztp/nvue_normalizer.py",
        "ztp/config/topology_rules.py",
        "ztp/config/cumulus/template/P2P/lldpq-template.dot",
        "ztp/config/cumulus/template/P2P/air-template-no-oob.json",
        "ztp/config/cumulus/default.yaml",
        "ztp/optimize/sample_links.py",
        *REAL_CHILD_SCRIPTS,
    )
    for resource in resources:
        destination = root / resource
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / resource, destination)
    shutil.copytree(
        ROOT / "ztp/config/cumulus/template/03-templates-j2",
        ztp / "config/cumulus/template/03-templates-j2",
    )

    def link(path: Path, target: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(os.path.relpath(target, path.parent))

    p2p = ztp / "config/cumulus/template/P2P"
    link(p2p / "p2p.xlsx", project / "p2p.xlsx")
    (p2p / "01-inventory.log").write_text("[Eth-SW]\nBorder01\nBorder02\n")
    (p2p / "02-port-mapping.log").write_text("[Eth-SW]\nswp53,swp53\n")
    (p2p / "output-p2p").mkdir()
    for directory in (ztp / "config/isc-dhcp-server", ztp / "config/cumulus/template"):
        link(directory / "01-global.yaml", global_file)
        link(directory / "02-devices_config.csv", project / "02-devices_config.csv")
    link(
        ztp / "config/isc-dhcp-server/02-subnet_config.csv",
        project / "02-dhcp-subnet_config.csv",
    )
    # A scoped ETH generation preserves the untouched families' existing
    # host files. Seed empty private files exactly as an installed tree does.
    for filename in ("dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts", "dhcpd.conf"):
        (ztp / "config/isc-dhcp-server" / filename).write_bytes(b"")
    output = project / "99-output-eth"
    output.mkdir()
    link(ztp / "config/cumulus/template/99-output", output)
    (ztp / "config/cumulus/latest_yaml").symlink_to("template/99-output/latest")
    return project, ztp


def _artifact_tree(root: Path) -> dict[str, tuple[str, str]]:
    """Include file bytes and symlink destinations, not volatile directory mtimes."""
    result = {}
    for item in sorted(root.rglob("*")):
        relative = str(item.relative_to(root))
        if item.is_symlink():
            result[relative] = ("link", os.readlink(item))
        elif item.is_file():
            result[relative] = ("file", hashlib.sha256(item.read_bytes()).hexdigest())
        elif item.is_dir():
            result[relative] = ("dir", "")
        else:
            raise AssertionError(f"unexpected artifact type: {item}")
    return result


def _publish_private_dhcp_outputs(project: Path, ztp: Path) -> None:
    """Model setup's canonical project-owned five-output publication."""
    dhcp_dir = ztp / "config/isc-dhcp-server"
    project_dhcp = project / "99-output-dhcp"
    project_dhcp.mkdir()
    for name in DHCP_OUTPUTS:
        public_output = dhcp_dir / name
        project_output = project_dhcp / name
        shutil.copy2(public_output, project_output)
        public_output.unlink()
        public_output.symlink_to(os.path.relpath(project_output, dhcp_dir))


def _write_same_inode(path: Path, data: bytes, original: os.stat_result) -> None:
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise AssertionError("mutation target must be a single-link regular file")
        if current.st_ino != original.st_ino or len(data) != original.st_size:
            raise AssertionError("A/B mutation must preserve inode and size")
        os.lseek(descriptor, 0, os.SEEK_SET)
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.ftruncate(descriptor, len(data))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns), follow_symlinks=False)
    after = path.stat()
    if (after.st_ino, after.st_size, after.st_mtime_ns) != (
        original.st_ino, original.st_size, original.st_mtime_ns,
    ):
        raise AssertionError("A/B mutation unexpectedly changed inode, size or mtime")


class GenerationInputBindingWorkflowTests(unittest.TestCase):
    """LOAD's frozen A authority must survive a real downstream c2 read."""

    def _private_setup_switch_fixture(self, root: Path):
        """Copy the real LOAD/SETUP scripts into a disposable HTTP root."""
        root = root.resolve()
        day0 = root / "DAY0-Prepare"
        day0.mkdir()
        for name in ("11-load.py", "01-a-setup.py"):
            source = ROOT / "DAY0-Prepare" / name
            destination = day0 / name
            shutil.copy2(source, destination)
            self.assertEqual(source.read_bytes(), destination.read_bytes())
        shutil.copytree(ROOT / "DAY0-Prepare/template", day0 / "template")
        shutil.copytree(ROOT / "tools", root / "tools")
        optimize = root / "ztp/optimize"
        optimize.mkdir(parents=True)
        shutil.copy2(ROOT / "ztp/optimize/sample_links.py", optimize / "sample_links.py")
        # Link-only WAL does not cover shared directory creation.  Model an
        # initialized directory skeleton for these link crash witnesses.
        for link_rel, _project_rel, _kind in SETUP.MAPPINGS:
            (root / "ztp" / link_rel).parent.mkdir(parents=True, exist_ok=True)
        for link_rel, _project_rel, _kind in SETUP.WORKSPACE_INPUT_MAPPINGS:
            (root / link_rel).parent.mkdir(parents=True, exist_ok=True)
        for link_path in (*SETUP.P2P_INPUT_LINKS, *SETUP.P2P_OUTPUT_LINKS):
            (root / Path(link_path).relative_to(ROOT)).parent.mkdir(
                parents=True, exist_ok=True,
            )
        for link_path, _target in SETUP.BRINGUP_OUTPUT_MAPPINGS:
            (root / Path(link_path).relative_to(ROOT)).parent.mkdir(
                parents=True, exist_ok=True,
            )
        for link_path, _target in (*SETUP.ANALYZER_INPUT_MAPPINGS,
                                   *SETUP.ANALYZER_OUTPUT_MAPPINGS):
            (root / Path(link_path).relative_to(ROOT)).parent.mkdir(
                parents=True, exist_ok=True,
            )
        for link_path, _target in SETUP._NET_CSV_LINKS:
            (root / Path(link_path).relative_to(ROOT)).parent.mkdir(
                parents=True, exist_ok=True,
            )
        for link_path, _target in SETUP._monitor_inventory_link_pairs():
            (root / Path(link_path).relative_to(ROOT)).parent.mkdir(
                parents=True, exist_ok=True,
            )
        (root / "infra").mkdir(exist_ok=True)
        (root / "image").mkdir(exist_ok=True)
        p, q = day0 / "p", day0 / "q"
        for project in (p, q):
            _write_legal_project(project, V2MlagSetupPreflightTests().pair())
        common = root / "ztp/config/cumulus/template/01-global.yaml"
        p_only = root / "ztp/config/publickey/p-only.pub"
        q_only = root / "ztp/config/publickey/operator.pub"
        for path in (common, p_only, q_only):
            path.parent.mkdir(parents=True, exist_ok=True)
        common.symlink_to(os.path.relpath(p / "01-global.yaml", common.parent))
        p_only.symlink_to(os.path.relpath(p / "operator.pub", p_only.parent))
        manifest = root / "ztp/.setup_manifest"
        manifest.write_bytes(
            (f"# setup manifest — proj: {p}\n{common}\n{p_only}\n").encode("utf-8")
        )
        before = {
            "manifest": manifest.read_bytes(),
            "common": os.readlink(common),
            "p_only": os.readlink(p_only),
        }
        hook = root / "test-hook"
        hook.mkdir()
        barrier = root / "q-first-link.observed"
        (hook / "sitecustomize.py").write_text(
            """
import os
from pathlib import Path
import signal

original_symlink = os.symlink
def kill_after_real_q_link(source, destination, *args, **kwargs):
    result = original_symlink(source, destination, *args, **kwargs)
    prefix = os.environ.get('HTTP_TEST_FIRST_Q_LINK_PREFIX')
    if (os.path.abspath(destination) == os.environ.get('HTTP_TEST_FIRST_Q_LINK')
            or (prefix and os.path.abspath(destination).startswith(prefix))):
        barrier = Path(os.environ['HTTP_TEST_Q_LINK_BARRIER'])
        with barrier.open('wb') as stream:
            stream.write((os.path.abspath(destination) + '\\n').encode()
                         if os.environ.get('HTTP_TEST_BARRIER_RECORD_DEST')
                         else b'first Q managed link written\\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.kill(os.getpid(), signal.SIGKILL)
    return result
os.symlink = kill_after_real_q_link
original_replace = os.replace
def kill_after_infra_repoint(source, destination, *args, **kwargs):
    result = original_replace(source, destination, *args, **kwargs)
    if os.path.abspath(destination) == os.environ.get('HTTP_TEST_KILL_AFTER_REPLACE'):
        barrier = Path(os.environ['HTTP_TEST_Q_LINK_BARRIER'])
        with barrier.open('wb') as stream:
            stream.write(b'infra logs pointer replaced\\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.kill(os.getpid(), signal.SIGKILL)
    return result
os.replace = kill_after_infra_repoint
""", encoding="utf-8",
        )
        home = root / "private-home"
        home.mkdir()
        return root, p, q, common, p_only, q_only, manifest, before, hook, barrier, home

    @staticmethod
    def _run_private_load_setup_switch(
        fixture, *, prepare_journal: bool, corrupt_journal: bool = False,
        first_link: Path | None = None, first_link_prefix: str | None = None,
        kill_after_replace: Path | None = None,
        omit_common_from_wal: bool = False,
    ):
        root, p, q, common, _p_only, q_only, _manifest, _before, hook, barrier, home = fixture
        driver = """
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

root, p, q, common, q_only, prepared, omit_common = sys.argv[1:8]
root, p, q, common, q_only = map(Path, (root, p, q, common, q_only))
spec = importlib.util.spec_from_file_location('private_setup_switch_load', root / 'DAY0-Prepare/11-load.py')
load = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = load
spec.loader.exec_module(load)
load.active_managed_services = lambda *args, **kwargs: ()
descriptor = load.acquire_deployment_lock(exclusive=True)
try:
    if prepared == 'yes':
        expected = {common: q / '01-global.yaml', q_only: q / 'operator.pub'}
        if omit_common == 'yes':
            del expected[common]
        logs = root / 'infra/logs'
        if logs.is_symlink():
            expected[logs] = q / '99-output-infra'
        load.prepare_setup_switch_journal(
            p, q, expected_new_links=expected,
            deployment_lock_descriptor=descriptor, services_quiesced=True,
            runtime_backend=SimpleNamespace(name='supervisor'),
        )
    if prepared == 'corrupt':
        (root / 'ztp/.setup-switch-journal.json').write_bytes(b'{"schema_version":')
    try:
        load.activate_project(
            q, q / 'p2p.xlsx', strict=False, no_upgrade=True,
            deployment_lock_descriptor=descriptor, host_role='workstation',
        )
    except load.LoadError as exc:
        if 'exit=-9' in str(exc):
            raise SystemExit(23)
        print('UNEXPECTED LOAD ERROR:', exc, file=sys.stderr)
        raise SystemExit(24)
    raise SystemExit(25)
finally:
    load.release_deployment_lock(descriptor)
"""
        env = os.environ.copy()
        env["HOME"] = str(home)
        # HOME is private so setup cannot inspect or generate the operator's
        # real key. Preserve the interpreter's pre-existing dependency paths
        # because macOS user-site discovery otherwise follows the new HOME.
        dependency_paths = [
            item for item in sys.path
            if item and item.endswith("site-packages") and Path(item).is_dir()
        ]
        env["PYTHONPATH"] = os.pathsep.join(
            item for item in (str(hook), env.get("PYTHONPATH", ""), *dependency_paths)
            if item
        )
        if first_link_prefix is not None:
            env.pop("HTTP_TEST_FIRST_Q_LINK", None)
            env["HTTP_TEST_FIRST_Q_LINK_PREFIX"] = first_link_prefix
            env["HTTP_TEST_BARRIER_RECORD_DEST"] = "1"
        elif kill_after_replace is not None:
            env.pop("HTTP_TEST_FIRST_Q_LINK", None)
            env.pop("HTTP_TEST_FIRST_Q_LINK_PREFIX", None)
            env.pop("HTTP_TEST_BARRIER_RECORD_DEST", None)
        else:
            env["HTTP_TEST_FIRST_Q_LINK"] = str(first_link or common)
            env.pop("HTTP_TEST_FIRST_Q_LINK_PREFIX", None)
            env.pop("HTTP_TEST_BARRIER_RECORD_DEST", None)
        if kill_after_replace is not None:
            env["HTTP_TEST_KILL_AFTER_REPLACE"] = str(kill_after_replace)
        else:
            env.pop("HTTP_TEST_KILL_AFTER_REPLACE", None)
        env["HTTP_TEST_Q_LINK_BARRIER"] = str(barrier)
        return subprocess.run(
            [sys.executable, "-B", "-c", driver, str(root), str(p), str(q),
             str(common), str(q_only),
             "corrupt" if corrupt_journal else "yes" if prepare_journal else "no",
             "yes" if omit_common_from_wal else "no"],
            cwd=root, env=env, capture_output=True, text=True, check=False,
        )

    def test_real_load_setup_child_sigkill_then_fresh_load_restores_p(self):
        """The real setup child dies after Q's first link, before Q manifest."""
        with tempfile.TemporaryDirectory(prefix="r22-real-setup-kill-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, p, _q, common, p_only, q_only, manifest, before, _hook, barrier, _home = fixture
            first = self._run_private_load_setup_switch(fixture, prepare_journal=True)
            self.assertEqual(23, first.returncode, first.stdout + first.stderr)
            self.assertEqual(b"first Q managed link written\n", barrier.read_bytes())
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertNotEqual(before["common"], os.readlink(common))
            self.assertFalse(os.path.lexists(p_only))
            self.assertFalse(os.path.lexists(q_only))
            journal = root / "ztp/.setup-switch-journal.json"
            self.assertTrue(journal.is_file())

            # A fresh interpreter and new deployment lock must recover from
            # disk alone; no first-LOAD or setup-child Python objects survive.
            recovery = """
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fresh_setup_switch_load', root / 'DAY0-Prepare/11-load.py')
load = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = load
spec.loader.exec_module(load)
load.active_managed_services = lambda *args, **kwargs: ()
descriptor = load.acquire_deployment_lock(exclusive=True)
try:
    outcome = load.recover_setup_switch_journal(
        root / 'ztp/.setup-switch-journal.json',
        deployment_lock_descriptor=descriptor, services_quiesced=True,
        runtime_backend=SimpleNamespace(name='supervisor'),
    )
    if outcome != 'restored-p':
        raise SystemExit('unexpected outcome: ' + repr(outcome))
finally:
    load.release_deployment_lock(descriptor)
"""
            second = subprocess.run(
                [sys.executable, "-B", "-c", recovery, str(root)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))
            self.assertFalse(os.path.lexists(journal))
            self.assertEqual(p / "01-global.yaml", common.resolve())
            self.assertFalse((root / "service-started").exists())

    def test_real_setup_prepare_only_keeps_p_publication_unchanged(self):
        """A separate Q-local preparation pass must not switch P's links."""
        with tempfile.TemporaryDirectory(prefix="r22-setup-prepare-only-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, q, common, p_only, q_only, manifest, before, _hook, barrier, home = fixture
            environment = os.environ.copy()
            environment["HOME"] = str(home)
            dependency_paths = [
                item for item in sys.path
                if item and item.endswith("site-packages") and Path(item).is_dir()
            ]
            environment["PYTHONPATH"] = os.pathsep.join(
                item for item in (environment.get("PYTHONPATH", ""), *dependency_paths)
                if item
            )
            result = subprocess.run(
                [sys.executable, "-B", str(root / "DAY0-Prepare/01-a-setup.py"),
                 "--prepare-only", "--no-upgrade", "--host-role=workstation", str(q)],
                cwd=root, env=environment, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertFalse(barrier.exists())
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))
            self.assertFalse((root / "ztp/.setup-switch-journal.json").exists())
            for output in ("99-output-dhcp", "99-output-eth", "99-output-infra"):
                self.assertTrue((q / output).is_dir(), output)

    def test_real_load_setup_child_requires_durable_wal_before_first_q_link(self):
        """Without a WAL, LOAD/SETUP must not create even one Q managed link."""
        with tempfile.TemporaryDirectory(prefix="r22-real-setup-no-wal-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, _q, common, p_only, q_only, manifest, before, _hook, barrier, _home = fixture
            result = self._run_private_load_setup_switch(fixture, prepare_journal=False)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(barrier.exists(), result.stdout + result.stderr)
            self.assertFalse((root / "ztp/.setup-switch-journal.json").exists())
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))

    def test_real_load_setup_child_rejects_corrupt_wal_before_first_q_link(self):
        """A malformed WAL is not authority to mutate the first Q link."""
        with tempfile.TemporaryDirectory(prefix="r22-real-setup-bad-wal-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, _q, common, p_only, q_only, manifest, before, _hook, barrier, _home = fixture
            result = self._run_private_load_setup_switch(
                fixture, prepare_journal=True, corrupt_journal=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(barrier.exists(), result.stdout + result.stderr)
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))
            self.assertEqual(
                b'{"schema_version":',
                (root / "ztp/.setup-switch-journal.json").read_bytes(),
            )

    def test_real_setup_rejects_forged_same_project_manifest_before_q_link(self):
        """A forged Q header over P links must not bypass the WAL fence."""
        with tempfile.TemporaryDirectory(prefix="r22-real-setup-forged-header-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, p, q, common, p_only, q_only, manifest, _before, _hook, barrier, _home = fixture
            forged = manifest.read_text(encoding="utf-8").replace(
                f"# setup manifest — proj: {p}\n",
                f"# setup manifest — proj: {q}\n", 1,
            )
            manifest.write_text(forged, encoding="utf-8")
            result = self._run_private_load_setup_switch(fixture, prepare_journal=False)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(barrier.exists(), result.stdout + result.stderr)
            self.assertEqual(forged, manifest.read_text(encoding="utf-8"))
            self.assertEqual(p / "01-global.yaml", common.resolve())
            self.assertEqual(p / "operator.pub", p_only.resolve())
            self.assertFalse(os.path.lexists(q_only))

    def test_direct_setup_cli_without_wal_rejects_before_first_q_link(self):
        """Direct setup cannot bypass LOAD's cross-project write fence."""
        with tempfile.TemporaryDirectory(prefix="r22-direct-setup-no-wal-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, p, q, common, p_only, q_only, manifest, before, hook, barrier, home = fixture
            environment = os.environ.copy()
            environment["HOME"] = str(home)
            dependency_paths = [
                item for item in sys.path
                if item and item.endswith("site-packages") and Path(item).is_dir()
            ]
            environment["PYTHONPATH"] = os.pathsep.join(
                item for item in (str(hook), environment.get("PYTHONPATH", ""),
                                  *dependency_paths) if item
            )
            environment["HTTP_TEST_FIRST_Q_LINK"] = str(common)
            environment["HTTP_TEST_Q_LINK_BARRIER"] = str(barrier)
            result = subprocess.run(
                [sys.executable, "-B", str(root / "DAY0-Prepare/01-a-setup.py"),
                 "-y", "--confirm-project-switch", "--no-upgrade",
                 "--host-role=workstation", str(q)],
                cwd=root, env=environment, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(barrier.exists(), result.stdout + result.stderr)
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))
            self.assertFalse((root / "ztp/.setup-switch-journal.json").exists())

    def test_real_setup_wal_refuses_unjournaled_materialized_latest_before_q_link(self):
        """A link-only WAL cannot authorize a real latest-directory rename."""
        with tempfile.TemporaryDirectory(prefix="r22-real-latest-hold-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, q, common, p_only, q_only, manifest, before, _hook, barrier, _home = fixture
            latest = q / "99-output-eth/latest"
            latest.mkdir(parents=True)
            marker = latest / "marker.yaml"
            marker.write_bytes(b"PRESERVE-MATERIALIZED-LATEST\n")
            result = self._run_private_load_setup_switch(fixture, prepare_journal=True)
            self.assertNotEqual(23, result.returncode, result.stdout + result.stderr)
            self.assertFalse(barrier.exists(), result.stdout + result.stderr)
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))
            self.assertEqual(b"PRESERVE-MATERIALIZED-LATEST\n", marker.read_bytes())
            self.assertTrue((root / "ztp/.setup-switch-journal.json").is_file())

    def test_real_setup_wal_refuses_unjournaled_infra_log_directory_before_q_link(self):
        """A link-only WAL cannot authorize moving a real infra logs directory."""
        with tempfile.TemporaryDirectory(prefix="r22-real-infra-hold-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, _q, common, p_only, q_only, manifest, before, _hook, barrier, _home = fixture
            logs = root / "infra/logs"
            logs.mkdir(parents=True)
            marker = logs / "audit.log"
            marker.write_bytes(b"PRESERVE-INFRA-LOGS\n")
            result = self._run_private_load_setup_switch(fixture, prepare_journal=True)
            self.assertNotEqual(23, result.returncode, result.stdout + result.stderr)
            self.assertFalse(barrier.exists(), result.stdout + result.stderr)
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))
            self.assertEqual(b"PRESERVE-INFRA-LOGS\n", marker.read_bytes())
            self.assertTrue((root / "ztp/.setup-switch-journal.json").is_file())

    def test_real_setup_wal_refuses_unjournaled_p_only_cleanup_before_q_link(self):
        """A P-owned legacy link absent from the WAL cannot be deleted silently."""
        with tempfile.TemporaryDirectory(prefix="r22-real-p-only-hold-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, p, _q, common, p_only, q_only, manifest, before, _hook, barrier, _home = fixture
            legacy = root / "ztp/config/publickey/legacy.pub"
            legacy.symlink_to(os.path.relpath(p / "operator.pub", legacy.parent))
            legacy_raw = os.readlink(legacy)
            result = self._run_private_load_setup_switch(fixture, prepare_journal=True)
            self.assertNotEqual(23, result.returncode, result.stdout + result.stderr)
            self.assertFalse(barrier.exists(), result.stdout + result.stderr)
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertEqual(legacy_raw, os.readlink(legacy))
            self.assertFalse(os.path.lexists(q_only))
            self.assertTrue((root / "ztp/.setup-switch-journal.json").is_file())

    def test_real_setup_wal_refuses_unlisted_fixed_q_repoint_before_write(self):
        """P's fixed link cannot be repointed when its WAL row has no Q value."""
        with tempfile.TemporaryDirectory(prefix="r22-real-fixed-q-hold-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, _q, common, p_only, q_only, manifest, before, _hook, barrier, _home = fixture
            result = self._run_private_load_setup_switch(
                fixture, prepare_journal=True, omit_common_from_wal=True,
            )
            self.assertNotEqual(23, result.returncode, result.stdout + result.stderr)
            self.assertFalse(barrier.exists(), result.stdout + result.stderr)
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))
            self.assertTrue((root / "ztp/.setup-switch-journal.json").is_file())

    def test_real_setup_wal_registers_dynamic_q_key_before_child_write(self):
        """A late-discovered Q key must be durable before a killed setup publishes it."""
        with tempfile.TemporaryDirectory(prefix="r22-real-q-key-wal-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, q, _common, _p_only, _q_only, manifest, before, _hook, barrier, _home = fixture
            (q / "late.pub").write_bytes((q / "operator.pub").read_bytes())
            late = root / "ztp/config/publickey/late.pub"
            result = self._run_private_load_setup_switch(
                fixture, prepare_journal=True, first_link=late,
            )
            self.assertEqual(23, result.returncode, result.stdout + result.stderr)
            self.assertEqual(b"first Q managed link written\n", barrier.read_bytes())
            journal = root / "ztp/.setup-switch-journal.json"
            body = json.loads(journal.read_bytes())["body"]
            self.assertIn(str(late), {row["path"] for row in body["links"]})
            self.assertEqual(before["manifest"], manifest.read_bytes())
            recovery = """
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fresh_dynamic_q_recovery', root / 'DAY0-Prepare/11-load.py')
load = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = load
spec.loader.exec_module(load)
load.active_managed_services = lambda *args, **kwargs: ()
descriptor = load.acquire_deployment_lock(exclusive=True)
try:
    outcome = load.recover_setup_switch_journal(
        root / 'ztp/.setup-switch-journal.json',
        deployment_lock_descriptor=descriptor, services_quiesced=True,
        runtime_backend=SimpleNamespace(name='supervisor'),
    )
    if outcome != 'restored-p':
        raise SystemExit('unexpected outcome: ' + repr(outcome))
finally:
    load.release_deployment_lock(descriptor)
"""
            second = subprocess.run(
                [sys.executable, "-B", "-c", recovery, str(root)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertFalse(os.path.lexists(late))
            self.assertFalse(journal.exists())
            self.assertEqual(before["manifest"], manifest.read_bytes())

    def test_real_setup_wal_registers_missing_infra_logs_before_child_write(self):
        """The first infra/logs link needs its own durable Q-only WAL row."""
        with tempfile.TemporaryDirectory(prefix="r22-real-infra-link-wal-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, _q, _common, _p_only, _q_only, manifest, before, _hook, barrier, _home = fixture
            logs = root / "infra/logs"
            self.assertFalse(os.path.lexists(logs))
            result = self._run_private_load_setup_switch(
                fixture, prepare_journal=True, first_link=logs,
            )
            self.assertEqual(23, result.returncode, result.stdout + result.stderr)
            self.assertEqual(b"first Q managed link written\n", barrier.read_bytes())
            journal = root / "ztp/.setup-switch-journal.json"
            body = json.loads(journal.read_bytes())["body"]
            self.assertIn(str(logs), {row["path"] for row in body["links"]})
            self.assertEqual(before["manifest"], manifest.read_bytes())
            recovery = """
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fresh_infra_link_recovery', root / 'DAY0-Prepare/11-load.py')
load = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = load
spec.loader.exec_module(load)
load.active_managed_services = lambda *args, **kwargs: ()
descriptor = load.acquire_deployment_lock(exclusive=True)
try:
    outcome = load.recover_setup_switch_journal(
        root / 'ztp/.setup-switch-journal.json',
        deployment_lock_descriptor=descriptor, services_quiesced=True,
        runtime_backend=SimpleNamespace(name='supervisor'),
    )
    if outcome != 'restored-p':
        raise SystemExit('unexpected outcome: ' + repr(outcome))
finally:
    load.release_deployment_lock(descriptor)
"""
            second = subprocess.run(
                [sys.executable, "-B", "-c", recovery, str(root)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertFalse(os.path.lexists(logs))
            self.assertFalse(journal.exists())
            self.assertEqual(before["manifest"], manifest.read_bytes())

    def test_real_setup_exact_monitor_temp_sigkill_cold_recovers_p(self):
        """An atomic exact-link temp must be WAL-known before SIGKILL."""
        with tempfile.TemporaryDirectory(prefix="r22-real-exact-temp-wal-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, _q, common, p_only, _q_only, manifest, before, _hook, barrier, _home = fixture
            prefix = str(root / "ethernet/monitor/.eth.csv.tmp.")
            result = self._run_private_load_setup_switch(
                fixture, prepare_journal=True, first_link_prefix=prefix,
            )
            self.assertEqual(23, result.returncode, result.stdout + result.stderr)
            temporary = Path(barrier.read_text().strip())
            self.assertTrue(str(temporary).startswith(prefix))
            self.assertTrue(temporary.is_symlink())
            journal = root / "ztp/.setup-switch-journal.json"
            body = json.loads(journal.read_bytes())["body"]
            final = root / "ethernet/monitor/eth.csv"
            self.assertIn(str(temporary), {row["path"] for row in body["links"]})
            self.assertIn(str(final), {row["path"] for row in body["links"]})
            self.assertEqual(before["manifest"], manifest.read_bytes())
            recovery = """
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fresh_exact_temp_recovery', root / 'DAY0-Prepare/11-load.py')
load = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = load
spec.loader.exec_module(load)
load.active_managed_services = lambda *args, **kwargs: ()
descriptor = load.acquire_deployment_lock(exclusive=True)
try:
    outcome = load.recover_setup_switch_journal(
        root / 'ztp/.setup-switch-journal.json',
        deployment_lock_descriptor=descriptor, services_quiesced=True,
        runtime_backend=SimpleNamespace(name='supervisor'),
    )
    if outcome != 'restored-p':
        raise SystemExit('unexpected outcome: ' + repr(outcome))
finally:
    load.release_deployment_lock(descriptor)
"""
            second = subprocess.run(
                [sys.executable, "-B", "-c", recovery, str(root)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertFalse(os.path.lexists(temporary))
            self.assertFalse(journal.exists())
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))

    def test_real_setup_exact_monitor_replace_sigkill_cold_recovers_p(self):
        """A completed exact-link replace is still Q-in-flight before commit."""
        with tempfile.TemporaryDirectory(prefix="r22-real-exact-replace-wal-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, _p, _q, common, p_only, _q_only, manifest, before, _hook, barrier, _home = fixture
            final = root / "ethernet/monitor/eth.csv"
            result = self._run_private_load_setup_switch(
                fixture, prepare_journal=True, kill_after_replace=final,
            )
            self.assertEqual(23, result.returncode, result.stdout + result.stderr)
            self.assertEqual(b"infra logs pointer replaced\n", barrier.read_bytes())
            self.assertTrue(final.is_symlink())
            journal = root / "ztp/.setup-switch-journal.json"
            rows = json.loads(journal.read_bytes())["body"]["links"]
            self.assertIn(str(final), {row["path"] for row in rows})
            self.assertEqual(before["manifest"], manifest.read_bytes())
            recovery = """
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fresh_exact_replace_recovery', root / 'DAY0-Prepare/11-load.py')
load = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = load
spec.loader.exec_module(load)
load.active_managed_services = lambda *args, **kwargs: ()
descriptor = load.acquire_deployment_lock(exclusive=True)
try:
    outcome = load.recover_setup_switch_journal(
        root / 'ztp/.setup-switch-journal.json',
        deployment_lock_descriptor=descriptor, services_quiesced=True,
        runtime_backend=SimpleNamespace(name='supervisor'),
    )
    if outcome != 'restored-p':
        raise SystemExit('unexpected outcome: ' + repr(outcome))
finally:
    load.release_deployment_lock(descriptor)
"""
            second = subprocess.run(
                [sys.executable, "-B", "-c", recovery, str(root)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertFalse(os.path.lexists(final))
            self.assertFalse(journal.exists())
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))

    def test_real_setup_wal_registers_infra_repoint_temp_before_child_write(self):
        """A killed infra/logs re-point leaves only journalled P and temp links."""
        with tempfile.TemporaryDirectory(prefix="r22-real-infra-repoint-wal-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, p, q, common, p_only, q_only, manifest, before, _hook, barrier, _home = fixture
            p_logs = p / "99-output-infra"
            q_logs = q / "99-output-infra"
            p_logs.mkdir(exist_ok=True)
            q_logs.mkdir(exist_ok=True)
            logs = root / "infra/logs"
            logs.symlink_to(os.path.relpath(p_logs, logs.parent))
            old_logs = os.readlink(logs)
            manifest.write_bytes(before["manifest"] + (str(logs) + "\n").encode())
            before["manifest"] = manifest.read_bytes()
            result = self._run_private_load_setup_switch(
                fixture, prepare_journal=True,
                first_link_prefix=str(root / "infra/.logs.setup."),
            )
            self.assertEqual(23, result.returncode, result.stdout + result.stderr)
            self.assertTrue(barrier.read_text().startswith(
                str(root / "infra/.logs.setup.")), barrier.read_text())
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(old_logs, os.readlink(logs))
            journal = root / "ztp/.setup-switch-journal.json"
            body = json.loads(journal.read_bytes())["body"]
            temp_rows = [row for row in body["links"]
                         if row["path"].startswith(str(root / "infra/.logs.setup."))]
            self.assertEqual(1, len(temp_rows), (body["links"], list((root / "infra").iterdir()), result.stdout, result.stderr))
            temporary = Path(temp_rows[0]["path"])
            self.assertTrue(temporary.is_symlink())
            recovery = """
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fresh_infra_repoint_recovery', root / 'DAY0-Prepare/11-load.py')
load = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = load
spec.loader.exec_module(load)
load.active_managed_services = lambda *args, **kwargs: ()
descriptor = load.acquire_deployment_lock(exclusive=True)
try:
    outcome = load.recover_setup_switch_journal(
        root / 'ztp/.setup-switch-journal.json',
        deployment_lock_descriptor=descriptor, services_quiesced=True,
        runtime_backend=SimpleNamespace(name='supervisor'),
    )
    if outcome != 'restored-p':
        raise SystemExit('unexpected outcome: ' + repr(outcome))
finally:
    load.release_deployment_lock(descriptor)
"""
            second = subprocess.run(
                [sys.executable, "-B", "-c", recovery, str(root)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertFalse(os.path.lexists(temporary))
            self.assertEqual(old_logs, os.readlink(logs))
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))
            self.assertFalse(journal.exists())

    def test_real_setup_wal_recovers_after_infra_logs_pointer_replace(self):
        """A killed re-point after replace restores P using the durable WAL."""
        with tempfile.TemporaryDirectory(prefix="r22-real-infra-replaced-wal-") as name:
            fixture = self._private_setup_switch_fixture(Path(name))
            root, p, q, common, p_only, q_only, manifest, before, _hook, barrier, _home = fixture
            p_logs, q_logs = p / "99-output-infra", q / "99-output-infra"
            p_logs.mkdir(exist_ok=True)
            q_logs.mkdir(exist_ok=True)
            logs = root / "infra/logs"
            logs.symlink_to(os.path.relpath(p_logs, logs.parent))
            old_logs = os.readlink(logs)
            manifest.write_bytes(before["manifest"] + (str(logs) + "\n").encode())
            before["manifest"] = manifest.read_bytes()
            result = self._run_private_load_setup_switch(
                fixture, prepare_journal=True, kill_after_replace=logs,
            )
            self.assertEqual(23, result.returncode, result.stdout + result.stderr)
            self.assertEqual(b"infra logs pointer replaced\n", barrier.read_bytes())
            self.assertEqual(q_logs, logs.resolve())
            self.assertEqual(before["manifest"], manifest.read_bytes())
            journal = root / "ztp/.setup-switch-journal.json"
            self.assertTrue(journal.is_file())
            recovery = """
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fresh_infra_replaced_recovery', root / 'DAY0-Prepare/11-load.py')
load = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = load
spec.loader.exec_module(load)
load.active_managed_services = lambda *args, **kwargs: ()
descriptor = load.acquire_deployment_lock(exclusive=True)
try:
    outcome = load.recover_setup_switch_journal(
        root / 'ztp/.setup-switch-journal.json',
        deployment_lock_descriptor=descriptor, services_quiesced=True,
        runtime_backend=SimpleNamespace(name='supervisor'),
    )
    if outcome != 'restored-p':
        raise SystemExit('unexpected outcome: ' + repr(outcome))
finally:
    load.release_deployment_lock(descriptor)
"""
            second = subprocess.run(
                [sys.executable, "-B", "-c", recovery, str(root)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertEqual(old_logs, os.readlink(logs))
            self.assertEqual(before["manifest"], manifest.read_bytes())
            self.assertEqual(before["common"], os.readlink(common))
            self.assertEqual(before["p_only"], os.readlink(p_only))
            self.assertFalse(os.path.lexists(q_only))
            self.assertFalse(journal.exists())

    def test_c2_process_death_between_version_and_pointer_commits(self):
        """Fresh readers reject an orphan but accept only a committed pointer."""
        child = """
import os
from pathlib import Path
import signal
import sys
from unittest import mock
from test_cases.module_loader import load_script

root, base_name, crash_after = sys.argv[1], sys.argv[2], int(sys.argv[3])
c2 = load_script("r22_c2_sigkill_child", Path(root) / "ztp/config/cumulus/template/90-c2-generate_configs.py")
base = Path(base_name)
real_replace = os.replace
replaces = 0

def patch_candidate(_dot, staging, _display, _authority):
    (Path(staging) / "Border01.yaml").write_bytes(b"patched B\\n")

def die_after_replace(src, dst):
    global replaces
    result = real_replace(src, dst)
    replaces += 1
    if replaces == crash_after:
        os.kill(os.getpid(), signal.SIGKILL)
    return result

with mock.patch.object(c2, "_require_csv_input_authority"), mock.patch.object(
    c2, "_patch_descriptions_in_directory", side_effect=patch_candidate,
), mock.patch.object(c2.os, "replace", side_effect=die_after_replace):
    c2._run_patch_descriptions("private-topology.dot", str(base), expected_csv_authority=object())
"""
        for crash_after in (1, 2):
            with self.subTest(crash_after=crash_after), tempfile.TemporaryDirectory(
                prefix="r22-c2-sigkill-",
            ) as name:
                output = Path(name) / "ztp/config/cumulus/template/99-output"
                output.mkdir(parents=True)
                timestamp = "20261002_120000"
                base = output / timestamp
                base.mkdir()
                (base / "Border01.yaml").write_bytes(b"plain base\n")
                legacy = output / f"{timestamp}_with_desc"
                legacy.mkdir()
                (legacy / "Border01.yaml").write_bytes(b"accepted legacy A\n")
                before_legacy = _artifact_tree(legacy)
                result = subprocess.run(
                    [sys.executable, "-B", "-c", child, str(ROOT), str(base),
                     str(crash_after)],
                    cwd=ROOT, capture_output=True, text=True, check=False,
                )
                self.assertEqual(-signal.SIGKILL, result.returncode, result.stderr)
                self.assertEqual(before_legacy, _artifact_tree(legacy))
                pointer = output / f"{timestamp}_with_desc_current"
                context = PUBLISHER._cumulus_dir_context(str(base))
                self.assertIsNotNone(context)
                if crash_after == 1:
                    self.assertFalse(os.path.lexists(pointer))
                    self.assertEqual(
                        "version-residue-no-current",
                        C2._inspect_description_output_recovery(str(legacy))["state"],
                    )
                    with self.assertRaisesRegex(ValueError, "version without a current pointer"):
                        PUBLISHER._preferred_cumulus_contexts([context])
                else:
                    self.assertTrue(pointer.is_symlink())
                    self.assertEqual(pointer, LOAD._select_cumulus_description_publication(base))
                    selected = PUBLISHER._preferred_cumulus_contexts([context])
                    self.assertEqual(str(pointer), selected[0]["path"])
                    self.assertEqual(
                        b"patched B\n", (Path(selected[0]["read_path"]) / "Border01.yaml").read_bytes(),
                    )

    def test_c2_single_pointer_is_the_real_d_input_and_tamper_never_falls_back(self):
        """C2's immutable publish pointer is what the real d resolver consumes."""
        with tempfile.TemporaryDirectory(prefix="r22-description-pointer-") as name:
            output = Path(name) / "ztp/config/cumulus/template/99-output"
            output.mkdir(parents=True)
            timestamp = "20261002_120000"
            base = output / timestamp
            base.mkdir()
            (base / "Border01.yaml").write_bytes(b"plain base\n")
            legacy = output / f"{timestamp}_with_desc"
            legacy.mkdir()
            (legacy / "Border01.yaml").write_bytes(b"complete legacy A\n")
            pointer = output / f"{timestamp}_with_desc_current"

            def patch_staged(_dot, staging, _display, _authority):
                (Path(staging) / "Border01.yaml").write_bytes(b"patched B\n")

            with mock.patch.object(
                C2, "_require_csv_input_authority",
            ), mock.patch.object(
                C2, "_patch_descriptions_in_directory",
                side_effect=patch_staged,
            ):
                C2._run_patch_descriptions(
                    "private-topology.dot", str(base),
                    expected_csv_authority=object(),
                )
            self.assertTrue(pointer.is_symlink())
            self.assertEqual(pointer, LOAD._select_cumulus_description_publication(base))
            self.assertEqual(b"complete legacy A\n",
                             (legacy / "Border01.yaml").read_bytes())
            context = PUBLISHER._cumulus_dir_context(str(base))
            self.assertIsNotNone(context)
            selected = PUBLISHER._preferred_cumulus_contexts([context])
            self.assertEqual(str(pointer), selected[0]["path"])
            version = PUBLISHER._description_current_version(str(pointer), timestamp)
            self.assertEqual(version, selected[0]["read_path"])
            self.assertEqual(b"patched B\n",
                             (Path(version) / "Border01.yaml").read_bytes())
            (Path(version) / "Border01.yaml").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ValueError, "hash|manifest"):
                PUBLISHER._preferred_cumulus_contexts([context])
            self.assertEqual(b"complete legacy A\n",
                             (legacy / "Border01.yaml").read_bytes())

    def test_real_setup_manifest_switch_then_load_restores_previous_project(self):
        """A failed Q generation restores P links and its setup authority."""
        with tempfile.TemporaryDirectory(prefix="r22-project-rollback-") as name:
            root = Path(name)
            p = root / "DAY0-Prepare/p"
            q = root / "DAY0-Prepare/q"
            p.mkdir(parents=True)
            q.mkdir(parents=True)
            for project in (p, q):
                (project / "01-global.yaml").write_text(project.name + "\n")
            ztp = root / "ztp"
            common = ztp / "config/cumulus/template/01-global.yaml"
            p_only = ztp / "p-only"
            q_only = ztp / "q-only"
            for path in (common, p_only, q_only):
                path.parent.mkdir(parents=True, exist_ok=True)
            manifest = ztp / ".setup_manifest"
            lock_path = root / ".deployment.lock"
            with mock.patch.multiple(
                LOAD, HTTP_ROOT=root, ZTP_DIR=ztp, MANIFEST=manifest,
                IMAGE_DIR=root / "image", DEPLOYMENT_LOCK=lock_path,
            ), mock.patch.object(SETUP, "MANIFEST_FILE", str(manifest)):
                SETUP._SetupLinkTransaction._restore_link(
                    str(common), os.path.relpath(p / "01-global.yaml", common.parent),
                )
                SETUP._SetupLinkTransaction._restore_link(
                    str(p_only), os.path.relpath(p, p_only.parent),
                )
                with mock.patch.object(
                    SETUP, "_collect_expected_links",
                    return_value=[str(common), str(p_only)],
                ):
                    SETUP._write_manifest(str(p.resolve()))
                old = LOAD.snapshot_active_setup_state(expected_project=p)
                SETUP._SetupLinkTransaction._restore_link(
                    str(common), os.path.relpath(q / "01-global.yaml", common.parent),
                )
                SETUP._SetupLinkTransaction._restore_link(
                    str(q_only), os.path.relpath(q, q_only.parent),
                )
                fsynced_directories = []
                real_fsync = os.fsync

                def record_fsync(descriptor):
                    metadata = os.fstat(descriptor)
                    if stat.S_ISDIR(metadata.st_mode):
                        fsynced_directories.append(metadata.st_ino)
                    return real_fsync(descriptor)

                with mock.patch.object(
                    SETUP, "_collect_expected_links",
                    return_value=[str(common), str(q_only)],
                ), mock.patch.object(SETUP.os, "fsync", side_effect=record_fsync):
                    SETUP._write_manifest(str(q.resolve()))
                self.assertIn(
                    manifest.parent.stat().st_ino, fsynced_directories,
                    "Q manifest replacement must fsync its parent directory",
                )
                self.assertEqual(q.resolve(), LOAD.active_project())
                descriptor = LOAD.acquire_deployment_lock(exclusive=True)
                try:
                    with mock.patch.object(
                        LOAD, "active_managed_services", return_value=(),
                    ):
                        LOAD.restore_active_setup_state(
                            old, current_project=q,
                            deployment_lock_descriptor=descriptor,
                            services_quiesced=True,
                            runtime_backend=SimpleNamespace(name="supervisor"),
                        )
                finally:
                    LOAD.release_deployment_lock(descriptor)
                self.assertEqual(p.resolve(), LOAD.active_project())
                self.assertEqual(old.manifest, manifest.read_bytes())
                self.assertEqual(old.links[common], os.readlink(common))
                self.assertEqual(old.links[p_only], os.readlink(p_only))
                self.assertFalse(os.path.lexists(q_only))

    def test_c2_crash_residue_blocks_real_publisher_base_fallback(self):
        """C2's cold gap cannot make d publish the unpatched base tree."""
        with tempfile.TemporaryDirectory(prefix="r22-c2-publisher-gap-") as name:
            output = Path(name) / "ztp/config/cumulus/template/99-output"
            output.mkdir(parents=True)
            timestamp = "20261002_120000"
            base = output / timestamp
            base.mkdir()
            (base / "Border01.yaml").write_bytes(b"base without descriptions\n")
            final = output / f"{timestamp}_with_desc"
            old = output / f".{final.name}.tmp.crash.old"
            stage = output / f".{final.name}.tmp.crash"
            old.mkdir()
            stage.mkdir()
            (old / "Border01.yaml").write_bytes(b"complete A descriptions\n")
            (stage / "Border01.yaml").write_bytes(b"incomplete B descriptions\n")
            before = _artifact_tree(output)

            inventory = C2._inspect_description_output_recovery(str(final))
            self.assertEqual("gap-after-old-rename", inventory["state"])
            self.assertEqual(str(old), inventory["old_candidate"])
            context = PUBLISHER._cumulus_dir_context(str(base))
            self.assertIsNotNone(context)
            with self.assertRaisesRegex(ValueError, "unresolved description"):
                PUBLISHER._preferred_cumulus_contexts([context])
            self.assertEqual(before, _artifact_tree(output))

    def test_real_nvos_scoped_generation_parent_remains_activatable(self):
        """Real IB/NVL generation must retain accepted empty unselected hosts."""
        private_parent = os.environ.get("R22_TEST_PRIVATE_ROOT")
        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory(
                prefix=f"r22-nvos-{selected}-activation-", dir=private_parent,
            ) as name:
                private = Path(name)

                class ScopedNVOSFlow(PLATFORM_FLOW.PlatformReleaseFlowTests):
                    selected_scope = selected

                    @classmethod
                    def _run_dhcp_generator(cls):
                        document = yaml.safe_load(cls.global_file.read_text(encoding="utf-8"))
                        document["common"]["mgmt"]["dhcp-server"] = {
                            "status": "enabled", "package": "isc-dhcp-server",
                        }
                        cls.global_file.write_text(
                            yaml.safe_dump(document, sort_keys=False), encoding="utf-8",
                        )
                        for filename in ("dhcpd_eth.hosts", "dhcpd_ib.hosts",
                                         "dhcpd_nvl.hosts", "dhcpd.conf"):
                            (cls.dhcp / filename).write_bytes(b"")
                        executed = []

                        def real_child(command, **_kwargs):
                            script = command[1]
                            executed.append((script, list(command[2:])))
                            if (command[command.index("--switch") + 1]
                                    != cls.selected_scope):
                                raise AssertionError((cls.selected_scope, command))
                            if (command[command.index("--deployment-scope") + 1]
                                    != "prod"):
                                raise AssertionError(command)
                            if script == "c1-generate_dhcp.py":
                                bindings = {
                                    "HTTP_ROOT": str(cls.root),
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
                                with mock.patch.multiple(PLATFORM_FLOW.DHCP, **bindings), \
                                        mock.patch.object(sys, "argv", list(command[1:])):
                                    PLATFORM_FLOW.DHCP.main()
                            elif script == "90-c2-generate_configs.py":
                                template = cls.nvos / "template"
                                ib_dir = template / f"99-output-ib_nvl/{PLATFORM_FLOW.TIMESTAMP}-ib"
                                nvl_dir = template / f"99-output-ib_nvl/{PLATFORM_FLOW.TIMESTAMP}-nvl"
                                with mock.patch.multiple(
                                    PLATFORM_FLOW.NVOS_GENERATOR,
                                    SCRIPT_DIR=str(template),
                                    _CSV_FILE=str(template / "02-devices_config.csv"),
                                    _GLOBAL_FILE=str(template / "01-global.yaml"),
                                    OUTPUT_IB_NVL_ROOT=str(template / "99-output-ib_nvl"),
                                    OUTPUT_IB_DIR=str(ib_dir),
                                    OUTPUT_NVL_DIR=str(nvl_dir),
                                ):
                                    generated = PLATFORM_FLOW.NVOS_GENERATOR._generate_all_ib(
                                        switch_scope=cls.selected_scope,
                                    )
                                if generated != 1:
                                    raise AssertionError((cls.selected_scope, generated))
                            elif script == "d-hostname2mac.py":
                                devices = PLATFORM_FLOW.PUBLISHER.load_csv(
                                    cls.devices_file, switch_scope=cls.selected_scope,
                                )
                                contexts = [
                                    PLATFORM_FLOW.PUBLISHER._nvos_dir_context(path)
                                    for path in command[2:]
                                    if str(path).endswith(f"-{cls.selected_scope}")
                                ]
                                if len(contexts) != 1:
                                    raise AssertionError((cls.selected_scope, command, contexts))
                                with mock.patch.object(PLATFORM_FLOW.PUBLISHER, "_AUTO_YES", True):
                                    published = PLATFORM_FLOW.PUBLISHER._publish_single_nvos(
                                        contexts[0], devices,
                                        deployment_scope="prod",
                                        switch_scope=cls.selected_scope,
                                    )
                                if not published:
                                    raise AssertionError("real scoped NVOS publisher rejected artifacts")
                            else:
                                raise AssertionError(f"unexpected real child: {command!r}")

                        with mock.patch.object(LOAD, "ZTP_DIR", cls.ztp), \
                                mock.patch.object(LOAD, "run", side_effect=real_child), \
                                redirect_stdout(io.StringIO()):
                            LOAD.generate_configs(
                                frozenset({cls.selected_scope}),
                                install_dhcp=False, dry_run=False, dhcp_enabled=True,
                                schema_version=1, deployment_scope="prod",
                                switch_scope=cls.selected_scope,
                            )
                        cls.executed = executed
                        _publish_private_dhcp_outputs(cls.project, cls.ztp)

                    @classmethod
                    def _run_cumulus_generator_and_publisher(cls, _p2p_output):
                        # A selected NVOS run does not execute Cumulus generation.
                        return None

                    @classmethod
                    def _run_nvos_generator_and_publisher(cls):
                        # Already executed by the real LOAD child dispatch above.
                        cls.nvos_release = (cls.nvos / "latest_yaml").resolve(strict=True)

                    @classmethod
                    def _run_parent_consumer(cls):
                        settings = LOAD.GlobalSettings(
                            dhcp_enabled=True, dhcp_package="isc-dhcp-server",
                            http_enabled=True, http_package="apache2",
                            http_root=cls.root, ztp_enabled=True,
                            ztp_prefix="/ztp", ztp_ips={"prod_oob": ("192.0.2.2",)},
                            versions={"cumulus": "5.16.4", "nvos": "25.02"},
                        )
                        inputs = LOAD.ProjectInputs(
                            global_file=cls.global_file, devices_file=cls.devices_file,
                            subnet_file=cls.subnet_file, p2p_file=cls.p2p_file,
                            device_types=frozenset({cls.selected_scope}),
                            pubkeys=(), settings=settings,
                            deployment_scope="prod",
                            switch_scope=cls.selected_scope,
                        )
                        with mock.patch.object(LOAD, "ZTP_DIR", cls.ztp):
                            LOAD.validate_dhcp_output_sources(LOAD.dhcp_file_mappings())
                            cls.parent = LOAD.validate_and_publish_release(
                                cls.project, inputs, publish=True,
                            )

                with redirect_stdout(io.StringIO()):
                    ScopedNVOSFlow._build_flow(private)
                self.assertEqual(
                    ["c1-generate_dhcp.py", "90-c2-generate_configs.py",
                     "d-hostname2mac.py"],
                    [script for script, _ in ScopedNVOSFlow.executed],
                )
                dhcp_dir = ScopedNVOSFlow.dhcp
                selected_hosts = dhcp_dir / f"dhcpd_{selected}.hosts"
                self.assertGreater(selected_hosts.stat().st_size, 0)
                for other in {"eth", "ib", "nvl"} - {selected}:
                    self.assertEqual(0, (dhcp_dir / f"dhcpd_{other}.hosts").stat().st_size)
                parent_path = ScopedNVOSFlow.project / "99-output-ztp/current-release.json"
                self.assertEqual(
                    ScopedNVOSFlow.parent["release_id"],
                    json.loads(parent_path.read_text())["release_id"],
                )
                settings = ACTIVATE.Settings(
                    http_root=private, project_name=ScopedNVOSFlow.project.name,
                    scope="prod", switch_scope=selected,
                )
                before = (_artifact_tree(ScopedNVOSFlow.project),
                          _artifact_tree(ScopedNVOSFlow.ztp))
                identity = ACTIVATE.validate_parent_release(settings, parent_path)
                self.assertEqual(before, (_artifact_tree(ScopedNVOSFlow.project),
                                          _artifact_tree(ScopedNVOSFlow.ztp)))
                self.assertEqual(
                    hashlib.sha256(parent_path.read_bytes()).hexdigest(),
                    identity["parent_release_sha256"],
                )

    def test_scoped_empty_dhcp_hosts_accepted_by_load_remain_activatable(self):
        """A LOAD-accepted zero-host family cannot invalidate its parent."""
        private_parent = os.environ.get("R22_TEST_PRIVATE_ROOT")
        with tempfile.TemporaryDirectory(
            prefix="r22-empty-host-activation-", dir=private_parent,
        ) as name:
            private = Path(name)
            project, ztp = _private_real_chain(private, "192.0.2.53")
            for relative in REAL_CHILD_SCRIPTS:
                self.assertEqual((ROOT / relative).read_bytes(),
                                 (private / relative).read_bytes())
            errors, warnings = SETUP._validate_v2_mlag_project(
                str(project / "01-global.yaml"),
                str(project / "02-devices_config.csv"),
            )
            self.assertEqual(([], []), (errors, warnings))
            args = SimpleNamespace(
                switch_scope="eth", deployment_scope="prod", p2p_file=None,
                no_upgrade=True, mini=None, ssh_dir=None, dry_run=True,
            )
            validated, _ = LOAD.validate_inputs(
                project, args, allow_management_key_generation=False,
                host_role="workstation",
            )
            self.assertEqual(frozenset({"eth"}), validated.device_types)

            original_subprocess = LOAD._run_subprocess
            executed = []

            def real_private_child(command, **kwargs):
                script = command[1] if len(command) > 1 else command[0]
                cwd = kwargs.get("cwd")
                self.assertIsNotNone(cwd)
                child_dir = Path(cwd).resolve(strict=True)
                self.assertTrue(child_dir.is_relative_to(private.resolve()), child_dir)
                self.assertIn(script, {Path(path).name for path in REAL_CHILD_SCRIPTS})
                self.assertTrue((child_dir / script).is_file())
                if not kwargs.get("capture_output"):
                    kwargs = {
                        **kwargs, "stdout": subprocess.PIPE,
                        "stderr": subprocess.STDOUT, "text": True,
                    }
                result = original_subprocess(command, timeout=120, **kwargs)
                executed.append((script, result.returncode))
                self.assertEqual(0, result.returncode, result.stdout)
                return result

            with (
                mock.patch.object(LOAD, "ZTP_DIR", ztp),
                mock.patch.object(LOAD, "_run_subprocess", side_effect=real_private_child),
                redirect_stdout(io.StringIO()),
            ):
                LOAD.generate_configs(
                    validated.device_types, install_dhcp=False, dry_run=False,
                    dhcp_enabled=True, schema_version=validated.settings.schema_version,
                    deployment_scope="prod", switch_scope="eth",
                    source_identities=validated.source_identities,
                )
                self.assertEqual(
                    [Path(path).name for path in REAL_CHILD_SCRIPTS],
                    [script for script, _ in executed],
                )
                _publish_private_dhcp_outputs(project, ztp)
                dhcp_dir = ztp / "config/isc-dhcp-server"
                self.assertEqual(
                    0, (dhcp_dir / "dhcpd_ib.hosts").stat().st_size,
                )
                self.assertEqual(
                    0, (dhcp_dir / "dhcpd_nvl.hosts").stat().st_size,
                )
                LOAD.validate_dhcp_output_sources(LOAD.dhcp_file_mappings())
                parent = LOAD.validate_and_publish_release(project, validated)

            parent_path = project / "99-output-ztp/current-release.json"
            self.assertEqual(parent["release_id"],
                             json.loads(parent_path.read_text())["release_id"])
            settings = ACTIVATE.Settings(
                http_root=private, project_name=project.name,
                scope="prod", switch_scope="eth",
            )
            before = (_artifact_tree(project), _artifact_tree(ztp))
            activation_error = None
            try:
                identity = ACTIVATE.validate_parent_release(settings, parent_path)
            except ACTIVATE.ActivationError as error:
                activation_error = str(error)
            self.assertEqual(before, (_artifact_tree(project), _artifact_tree(ztp)))
            self.assertIsNone(activation_error, activation_error)
            self.assertEqual(
                hashlib.sha256(parent_path.read_bytes()).hexdigest(),
                identity["parent_release_sha256"],
            )

    def test_real_load_child_chain_rejects_same_inode_global_aba_before_publisher(self):
        """A c2-only B read cannot publish B after LOAD validated A."""
        private_parent = os.environ.get("R22_TEST_PRIVATE_ROOT")
        with tempfile.TemporaryDirectory(
            prefix="r22-real-generation-", dir=private_parent,
        ) as name:
            # macOS may report /var for a /private/var subprocess cwd; the
            # candidate API deliberately requires one canonical project path.
            private = Path(name).resolve()
            project, ztp = _private_real_chain(
                private / "A", "192.0.2.53", http_enabled=True,
            )
            project_b, _ = _private_real_chain(
                private / "B", "192.0.2.54", http_enabled=True,
            )
            # Activation currently requires nonempty private includes even
            # when this scoped ETH run does not own IB/NVL.  Valid DHCP
            # comments model pre-existing, unchanged family files; c1 still
            # produces and hashes the complete five-output child receipt.
            for family in ("ib", "nvl"):
                (ztp / "config/isc-dhcp-server" / f"dhcpd_{family}.hosts").write_text(
                    "# no selected hosts for this family\n", encoding="utf-8",
                )
            for relative in REAL_CHILD_SCRIPTS:
                self.assertEqual(
                    (ROOT / relative).read_bytes(),
                    (private / "A" / relative).read_bytes(),
                )
            source = project / "01-global.yaml"
            bytes_a = source.read_bytes()
            bytes_b = (project_b / "01-global.yaml").read_bytes()
            self.assertNotEqual(bytes_a, bytes_b)
            self.assertEqual(len(bytes_a), len(bytes_b))
            self.assertIn(b"192.0.2.53", bytes_a)
            self.assertIn(b"192.0.2.54", bytes_b)

            args = SimpleNamespace(
                switch_scope="eth", deployment_scope="prod", p2p_file=None,
                no_upgrade=True, mini=None, ssh_dir=None, dry_run=True,
            )
            for candidate in (project, project_b):
                errors, warnings = SETUP._validate_v2_mlag_project(
                    str(candidate / "01-global.yaml"),
                    str(candidate / "02-devices_config.csv"),
                )
                self.assertEqual(([], []), (errors, warnings))
                validated, _ = LOAD.validate_inputs(
                    candidate, args, allow_management_key_generation=False,
                    host_role="workstation",
                )
                self.assertEqual(frozenset({"eth"}), validated.device_types)

            original_subprocess = LOAD._run_subprocess
            state = {
                "inject": False, "injected": False, "children": [],
                "post_c1_activation_error": None,
            }
            original = None
            transcript = io.StringIO()

            def real_private_child(command, **kwargs):
                script = command[1] if len(command) > 1 else command[0]
                cwd = kwargs.get("cwd")
                if cwd is None:
                    self.assertEqual("/usr/bin/ssh-keygen", command[0])
                    self.assertEqual("-l", command[1])
                else:
                    child_dir = Path(cwd).resolve()
                    self.assertTrue(child_dir.is_relative_to(private.resolve()), child_dir)
                    self.assertIn(script, {Path(path).name for path in REAL_CHILD_SCRIPTS})
                    self.assertTrue((child_dir / script).is_file())
                    if not kwargs.get("capture_output"):
                        kwargs = {
                            **kwargs, "stdout": subprocess.PIPE,
                            "stderr": subprocess.STDOUT, "text": True,
                        }
                is_c2 = script == "90-c2-generate_configs.py" and state["inject"]
                if is_c2:
                    self.assertFalse(state["injected"])
                    state["injected"] = True
                    _write_same_inode(source, bytes_b, original)
                started = time.monotonic()
                try:
                    result = original_subprocess(command, timeout=120, **kwargs)
                finally:
                    if is_c2:
                        _write_same_inode(source, bytes_a, original)
                state["children"].append((script, result.returncode))
                if cwd is not None and result.stdout:
                    transcript.write(result.stdout)
                if result.returncode and (
                    not state["inject"] or script == "c1-generate_dhcp.py"
                ):
                    self.fail(
                        f"real private child {script} exited {result.returncode}: "
                        f"{result.stdout!r}"
                    )
                if state["inject"] and script == "c1-generate_dhcp.py":
                    try:
                        ACTIVATE.validate_parent_release(settings, parent_path)
                    except ACTIVATE.ActivationError as error:
                        state["post_c1_activation_error"] = str(error)
                self.assertLess(time.monotonic() - started, 120)
                return result

            def run_chain(validated, *, dhcp_candidate_dir=None):
                candidate_options = (
                    {} if dhcp_candidate_dir is None
                    else {"dhcp_candidate_dir": dhcp_candidate_dir}
                )
                return LOAD.generate_configs(
                    validated.device_types, install_dhcp=False, dry_run=False,
                    dhcp_enabled=validated.settings.dhcp_enabled,
                    schema_version=validated.settings.schema_version,
                    deployment_scope="prod", switch_scope="eth",
                    source_identities=validated.source_identities,
                    **candidate_options,
                )

            with (
                mock.patch.object(LOAD, "ZTP_DIR", ztp),
                mock.patch.object(LOAD, "_run_subprocess", side_effect=real_private_child),
                redirect_stdout(transcript),
            ):
                validated_a, _ = LOAD.validate_inputs(
                    project, args, allow_management_key_generation=False,
                    host_role="workstation",
                )
                self.assertEqual(
                    hashlib.sha256(bytes_a).hexdigest(),
                    validated_a.source_identities["global"],
                )
                run_chain(validated_a)

                # Publish the real c1 child manifest through the same
                # project-owned path and canonical public link that Docker
                # activation requires.  No release JSON or hash is forged.
                dhcp_dir = ztp / "config/isc-dhcp-server"
                _publish_private_dhcp_outputs(project, ztp)
                parent = LOAD.validate_and_publish_release(project, validated_a)
                parent_path = project / "99-output-ztp/current-release.json"
                self.assertEqual(parent["release_id"],
                                 json.loads(parent_path.read_text())["release_id"])
                settings = ACTIVATE.Settings(
                    http_root=private / "A", project_name=project.name,
                    scope="prod", switch_scope="eth",
                )
                accepted_parent = ACTIVATE.validate_parent_release(
                    settings, parent_path,
                )
                self.assertEqual(
                    hashlib.sha256(parent_path.read_bytes()).hexdigest(),
                    accepted_parent["parent_release_sha256"],
                )
                # The same preflight LOAD now uses before any B generation
                # must migrate the already committed A while its source bytes
                # and published DHCP child are still independently verifiable.
                self.assertEqual(
                    f"generations/{parent['release_id']}",
                    LOAD.ensure_previous_generation_frozen(project),
                )
                committed_a = (
                    project / "99-output-ztp/generations" / parent["release_id"]
                )
                selector = project / "99-output-ztp/current"
                self.assertEqual(
                    parent["release_id"],
                    ACTIVATE.validate_pinned_generation(
                        settings, selector, expected_release_id=parent["release_id"],
                    )["release_id"],
                )
                # LOAD has selected A, so ACTIVATE's legacy flat-input writer
                # must not publish a runtime plan without binding that selector.
                with mock.patch.object(
                    ACTIVATE, "ensure_runtime_directories",
                ) as runtime_dirs, mock.patch.object(
                    ACTIVATE, "_atomic_write",
                ) as runtime_write:
                    with self.assertRaisesRegex(
                        ACTIVATE.ActivationError, "selector|generation",
                    ):
                        ACTIVATE.prepare_runtime(settings)
                runtime_dirs.assert_not_called()
                runtime_write.assert_not_called()
                frozen_global = committed_a / "inputs/global"
                original_global = frozen_global.read_bytes()
                frozen_global.write_bytes(b"other generation input\n")
                with self.assertRaisesRegex(ACTIVATE.ActivationError, "pinned input"):
                    ACTIVATE.validate_pinned_generation(
                        settings, selector, expected_release_id=parent["release_id"],
                    )
                frozen_global.write_bytes(original_global)

                # The prior release is a real successful publication, not a
                # same-timestamp c2 staging directory or a synthetic marker.
                latest = project / "99-output-eth/latest"
                prior_name = os.readlink(latest)
                prior_release = latest.parent / prior_name
                prior_state = _artifact_tree(prior_release)
                self.assertIn("Border01.yaml", prior_state)
                dhcp_dir = ztp / "config/isc-dhcp-server"
                dhcp_before = {
                    item: (dhcp_dir / item).read_bytes() for item in DHCP_OUTPUTS
                }
                boundary = int(time.time())
                while int(time.time()) == boundary:
                    time.sleep(0.025)

                original = source.stat()
                state["inject"] = True
                private_candidate = (
                    project / "99-output-dhcp" /
                    ".load-dhcp-candidate-0123456789abcdef"
                )
                private_candidate.mkdir(mode=0o700)
                validated_a, _ = LOAD.validate_inputs(
                    project, args, allow_management_key_generation=False,
                    host_role="workstation",
                )
                self.assertEqual(
                    hashlib.sha256(bytes_a).hexdigest(),
                    validated_a.source_identities["global"],
                )
                failure = None
                try:
                    run_chain(validated_a, dhcp_candidate_dir=private_candidate)
                except LOAD.LoadError as error:
                    failure = error

            self.assertTrue(state["injected"], state)
            self.assertEqual(
                parent["release_id"],
                ACTIVATE.validate_pinned_generation(
                    settings, selector, expected_release_id=parent["release_id"],
                )["release_id"],
            )
            self.assertEqual(
                (original.st_ino, original.st_size, original.st_mtime_ns),
                (source.stat().st_ino, source.stat().st_size, source.stat().st_mtime_ns),
            )
            self.assertEqual(bytes_a, source.read_bytes())
            final_name = os.readlink(latest)
            final_yaml = (latest / "Border01.yaml").read_bytes()
            dhcp_after = {item: (dhcp_dir / item).read_bytes() for item in DHCP_OUTPUTS}
            dhcp_changed = [
                key for key in DHCP_OUTPUTS if dhcp_before[key] != dhcp_after[key]
            ]
            detail = (
                f"children={state['children']!r}; prior={prior_name}; final={final_name}; "
                f"new YAML sha256={hashlib.sha256(final_yaml).hexdigest()}; "
                f"DHCP changed={dhcp_changed}; "
                f"post-c1 activation={state['post_c1_activation_error']!r}; "
                f"child output tail={transcript.getvalue()[-1000:]!r}"
            )
            with self.subTest("accepted parent survives completed c1 before c2"):
                self.assertIsNone(state["post_c1_activation_error"], detail)
            with self.subTest("refuse drift from validated A"):
                self.assertIsNotNone(failure, detail)
                self.assertRegex(
                    (str(failure) + transcript.getvalue()).lower(),
                    r"input|source|authority|drift|chang",
                )
            with self.subTest("latest remains the previously published release"):
                self.assertEqual(prior_name, final_name, detail)
            with self.subTest("prior published release bytes are untouched"):
                self.assertEqual(prior_state, _artifact_tree(prior_release), detail)
            with self.subTest("validated A never publishes B"):
                self.assertFalse(b"192.0.2.54" in final_yaml, detail)
            with self.subTest("refusal leaves five prior DHCP outputs untouched"):
                self.assertEqual([], dhcp_changed, detail)
            with self.subTest("c1 wrote private complete candidate before c2 refused B"):
                self.assertEqual(
                    set(DHCP_OUTPUTS),
                    {item.name for item in private_candidate.iterdir()}, detail,
                )
            # The actual LOAD child chain has left the previously committed A
            # selected.  A subsequent, independently legal B edit to the
            # mutable source must not be used when ACTIVATE observes A's plan.
            # This is read-only planning, not a service activation receipt.
            network_links = [{
                "ifindex": 4, "ifname": "eth0",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "address": "02:00:00:00:00:04", "operstate": "UP",
                "link_type": "ether",
            }]
            network_addresses = [{
                "ifindex": 4, "ifname": "eth0",
                "addr_info": [{
                    "family": "inet", "local": "192.0.2.20", "prefixlen": 24,
                    "scope": "global", "flags": [],
                    "valid_life_time": "forever",
                    "preferred_life_time": "forever",
                }],
            }]
            source.write_bytes(bytes_b)
            try:
                with mock.patch.object(
                    ACTIVATE, "capture_stable_network_snapshot",
                    return_value=(network_links, network_addresses),
                ):
                    _plan, _runtime, payload, _apache = (
                        ACTIVATE.observe_pinned_runtime(
                            settings, selector,
                            expected_release_id=parent["release_id"],
                        )
                    )
                self.assertEqual(parent["release_id"],
                                 payload["selected_generation_release_id"])
                self.assertEqual(
                    hashlib.sha256((committed_a / "inputs/subnet").read_bytes()).hexdigest(),
                    payload["subnet_sha256"],
                )
                # Exercise the real ACTIVATE publication boundary after the
                # real LOAD/c1/c2/d chain rejects B.  Keep every destination
                # private and leave service-start authority absent.
                pinned_state = private / "pinned-state"
                pinned_state.mkdir()
                pinned_settings = ACTIVATE.Settings(
                    http_root=private / "A", project_name=project.name,
                    scope="prod", switch_scope="eth",
                    state_root=pinned_state, log_root=private / "pinned-log",
                    apache_listeners=private / "pinned-apache-listeners.conf",
                    dhcp_config=private / "pinned-dhcpd.conf",
                    dhcp_leases=private / "pinned-leases",
                )
                pinned_settings.activation_marker.write_text("old marker\n")
                pinned_settings.precommit_marker.write_text("old precommit\n")
                with mock.patch.object(
                    ACTIVATE, "capture_stable_network_snapshot",
                    return_value=(network_links, network_addresses),
                ), mock.patch.object(ACTIVATE, "ensure_runtime_directories"):
                    _selected, _runtime, published = ACTIVATE.prepare_pinned_runtime(
                        pinned_settings, selector_path=selector,
                        expected_release_id=parent["release_id"],
                    )
                self.assertEqual(parent["release_id"],
                                 published["selected_generation_release_id"])
                self.assertEqual(
                    published,
                    json.loads(pinned_settings.runtime_plan.read_text()),
                )
                self.assertTrue(pinned_settings.apache_listeners.is_file())
                self.assertFalse(pinned_settings.activation_marker.exists())
                self.assertFalse(pinned_settings.precommit_marker.exists())
            finally:
                source.write_bytes(bytes_a)

    def test_load_setup_c2_rejects_same_inode_second_read_and_preserves_existing_same_name_output(self):
        rows_a = V2MlagSetupPreflightTests().pair()
        rows_b = copy.deepcopy(rows_a)
        rows_b[0][0] = "Border03"
        rows_b[1][0] = "Border04"
        with tempfile.TemporaryDirectory(prefix="r22-generation-workflow-") as name:
            private = Path(name)
            project_a = private / "project-a"
            project_b = private / "project-b"
            _write_legal_project(project_a, rows_a)
            _write_legal_project(project_b, rows_b)
            source = project_a / "02-devices_config.csv"
            bytes_a = source.read_bytes()
            bytes_b = (project_b / "02-devices_config.csv").read_bytes()
            self.assertNotEqual(bytes_a, bytes_b)
            self.assertEqual(len(bytes_a), len(bytes_b))

            # Both generations independently pass the actual setup validator.
            for project in (project_a, project_b):
                errors, warnings = SETUP._validate_v2_mlag_project(
                    str(project / "01-global.yaml"),
                    str(project / "02-devices_config.csv"),
                )
                self.assertEqual(([], []), (errors, warnings))

            args = SimpleNamespace(
                switch_scope="all", deployment_scope="prod", p2p_file=None,
                no_upgrade=True, mini=None, ssh_dir=None, dry_run=True,
            )
            inputs_a, images_a = LOAD.validate_inputs(
                project_a, args, allow_management_key_generation=False,
                host_role="workstation",
            )
            inputs_b, images_b = LOAD.validate_inputs(
                project_b, args, allow_management_key_generation=False,
                host_role="workstation",
            )
            self.assertEqual({}, images_a)
            self.assertEqual({}, images_b)
            self.assertEqual(frozenset({"eth"}), inputs_a.device_types)
            self.assertEqual(frozenset({"eth"}), inputs_b.device_types)
            self.assertEqual(
                hashlib.sha256(bytes_a).hexdigest(),
                inputs_a.source_identities["devices"],
            )
            self.assertEqual(
                hashlib.sha256(bytes_b).hexdigest(),
                inputs_b.source_identities["devices"],
            )

            dot = private / "fixture-lldpq.dot"
            dot.write_text("", encoding="utf-8")
            generation = private / "generation"
            generation.mkdir()
            (generation / "new-marker.txt").write_bytes(b"candidate-from-A")
            existing = private / "generation_with_desc"
            existing.mkdir()
            old_artifact = existing / "old-marker.txt"
            old_artifact.write_bytes(b"existing-same-name")
            initial = source.stat()
            real_copytree = C2.shutil.copytree
            observed = {"injected": False}

            def mutate_after_copy(src, dst, *copy_args, **copy_kwargs):
                result = real_copytree(src, dst, *copy_args, **copy_kwargs)
                source.write_bytes(bytes_b)
                os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
                changed = source.stat()
                observed.update({
                    "injected": True,
                    "same_inode": changed.st_ino == initial.st_ino,
                    "same_size": changed.st_size == initial.st_size,
                    "same_mtime": changed.st_mtime_ns == initial.st_mtime_ns,
                })
                return result

            transcript = io.StringIO()
            failure = None
            with (
                mock.patch.object(C2, "_CSV_FILE", str(source)),
                mock.patch.object(C2.shutil, "copytree", side_effect=mutate_after_copy),
                redirect_stdout(transcript),
            ):
                try:
                    C2._run_patch_descriptions(str(dot), str(generation))
                except Exception as error:
                    failure = error

            self.assertTrue(observed["injected"], observed)
            self.assertTrue(observed["same_inode"], observed)
            self.assertTrue(observed["same_size"], observed)
            self.assertTrue(observed["same_mtime"], observed)
            with self.subTest("refuse cross-generation input"):
                self.assertIsNotNone(
                    failure,
                    "c2 accepted project B after setup/load validated and bound A; "
                    f"actual c2 output was: {transcript.getvalue()!r}",
                )
                self.assertRegex(
                    str(failure).lower(), r"input|source|authority|drift|chang",
                )
            with self.subTest("preserve same-name existing output"):
                self.assertTrue(old_artifact.is_file())
                self.assertEqual(
                    b"existing-same-name", old_artifact.read_bytes(),
                )
                self.assertFalse((existing / "new-marker.txt").exists())


if __name__ == "__main__":
    unittest.main()
