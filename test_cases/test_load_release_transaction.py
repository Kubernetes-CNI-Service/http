"""Unified release validation, DHCP installation, and rollback transactions."""

from __future__ import annotations

import base64
import csv
from contextlib import ExitStack, contextmanager, nullcontext
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import inspect
import ipaddress
import io
import json
import os
from pathlib import Path
import signal
import shlex
import shutil
import stat
import subprocess
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest import mock

from test_cases.source_tools_fixture import copy_source_tools
from test_cases.linux_runtime_lock_model import declared_linux_fdinfo_for_darwin_fixture
import zipfile
from urllib.parse import urlsplit

import yaml

from test_cases.splitter_profile_fixture import write_splitter_fixture
from test_cases.module_loader import load_script
from test_cases.test_bootstrap_config_fetch_contract import _await_fixture_ctime_tick


def _fixture_scan_then_mutate(real_scan, descriptor, mutation, custody):
    """Own one returned iterator until mutation succeeds, then transfer it."""
    if custody["unknown"]:
        raise RuntimeError("fixture scandir custody UNKNOWN")
    try:
        entries = real_scan(descriptor)
    except BaseException:
        custody["unknown"] = True
        raise
    try:
        mutation()
    except BaseException:
        try:
            entries.close()
        except BaseException as secondary:
            custody["unknown"] = True
            custody["secondary"].append(secondary)
        raise
    return entries


ROOT = Path(__file__).resolve().parents[1]
H04_SCHEMA_V1_HEADER = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
    "vrf_default", "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac",
    "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "bond_type",
    "bond_mac", "peerlink_ports", "vrl", "evpn_vrf", "evpn_l3vni",
    "evpn_l3vlan", "dhcp_relay", "evpn_l2vni", "evpn_l2vlan", "svi_ip",
    "netmask", "vrr_ip", "vrr_mac", "vlan_ports",
)
H04_COLLISION_HOSTNAME = "COLLIDE-LEAF01"
H04_VRR_MAC = "00:00:5e:00:01:c8"
SPEC = importlib.util.spec_from_file_location(
    "day0_load", ROOT / "DAY0-Prepare/11-load.py"
)
LOAD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
import sys
sys.modules[SPEC.name] = LOAD
SPEC.loader.exec_module(LOAD)

MANUAL_SPEC = importlib.util.spec_from_file_location(
    "manual_ztp_release_contract", ROOT / "ztp/manual-ztp.py"
)
MANUAL = importlib.util.module_from_spec(MANUAL_SPEC)
assert MANUAL_SPEC.loader is not None
sys.modules[MANUAL_SPEC.name] = MANUAL
MANUAL_SPEC.loader.exec_module(MANUAL)

DHCP_SPEC = importlib.util.spec_from_file_location(
    "dhcp_release_contract", ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py"
)
DHCP = importlib.util.module_from_spec(DHCP_SPEC)
assert DHCP_SPEC.loader is not None
sys.modules[DHCP_SPEC.name] = DHCP
DHCP_SPEC.loader.exec_module(DHCP)

TOPOLOGY_SPEC = importlib.util.spec_from_file_location(
    "air_topology_release_contract",
    ROOT / "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
)
TOPOLOGY = importlib.util.module_from_spec(TOPOLOGY_SPEC)
assert TOPOLOGY_SPEC.loader is not None
sys.modules[TOPOLOGY_SPEC.name] = TOPOLOGY
TOPOLOGY_SPEC.loader.exec_module(TOPOLOGY)

GENERATOR_SPEC = importlib.util.spec_from_file_location(
    "cumulus_scope_generation_contract",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
assert GENERATOR_SPEC.loader is not None
sys.modules[GENERATOR_SPEC.name] = GENERATOR
GENERATOR_SPEC.loader.exec_module(GENERATOR)

PUBLISHER_SPEC = importlib.util.spec_from_file_location(
    "cumulus_scope_publication_contract",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
PUBLISHER = importlib.util.module_from_spec(PUBLISHER_SPEC)
assert PUBLISHER_SPEC.loader is not None
sys.modules[PUBLISHER_SPEC.name] = PUBLISHER
PUBLISHER_SPEC.loader.exec_module(PUBLISHER)

SETUP_SPEC = importlib.util.spec_from_file_location(
    "day0_setup_release_contract", ROOT / "DAY0-Prepare/01-a-setup.py"
)
SETUP = importlib.util.module_from_spec(SETUP_SPEC)
assert SETUP_SPEC.loader is not None
sys.modules[SETUP_SPEC.name] = SETUP
SETUP_SPEC.loader.exec_module(SETUP)

UNSETUP_SPEC = importlib.util.spec_from_file_location(
    "day0_unsetup_release_contract", ROOT / "DAY0-Prepare/02-unsetup.py"
)
UNSETUP = importlib.util.module_from_spec(UNSETUP_SPEC)
assert UNSETUP_SPEC.loader is not None
sys.modules[UNSETUP_SPEC.name] = UNSETUP
UNSETUP_SPEC.loader.exec_module(UNSETUP)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_private_dhcp_transaction_retention(
    api, root: Path, project: Path, outcome: str, *, reenter: bool = False,
) -> None:
    """Exercise real LOAD filesystem logic; never execute sudo, dhcpd or live writes."""
    root = root.resolve()
    source_dir = project / "independent-dhcp-B"
    live_dir = root / "private-etc-dhcp"
    source_dir.mkdir()
    live_dir.mkdir()
    names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
    expected_b = {name: f"independent-B:{name}\n".encode() for name in names}
    expected_b["dhcpd.conf"] = b"# independent-B configuration\n" + b"".join(
        f'include "/etc/dhcp/{name}";\n'.encode() for name in names[1:]
    )
    expected_a = {name: f"independent-A:{name}\n".encode() for name in names}
    mappings = {source_dir / name: live_dir / name for name in names}
    for source, destination in mappings.items():
        source.write_bytes(expected_b[source.name])
        destination.write_bytes(expected_a[destination.name])
    if outcome == "precommit-shapes":
        original_link_source = root / "independent-original-A-source"
        original_link_source.write_bytes(expected_a["dhcpd_eth.hosts"])
        (live_dir / "dhcpd_eth.hosts").unlink()
        (live_dir / "dhcpd_eth.hosts").symlink_to("../independent-original-A-source")
        (live_dir / "dhcpd_nvl.hosts").unlink()
    parent_payload = {"schema_version": 1, "release_id": "independent-B"}
    candidate = api.prepare_current_release(project, parent_payload)
    parent_identity = candidate.destination.parent.stat()
    real_open, real_sync = os.open, os.fsync
    injected, warnings, cleanup, restore_phase, sync_events, installed_b = [], [], [], [], [], []
    backup_sync_events = []
    backup_sync_faults = ("backup-file-sync", "backup-dir-sync", "backup-transaction-sync", "backup-runtime-sync")

    def private_destination(value):
        path = Path(value)
        path.parent.resolve().relative_to(root)
        return path

    def private_command(command, **_kwargs):
        operation = command[0]
        if operation == "dhcpd":
            # This is a service/parser port, not a real dhcpd syntax witness.
            return SimpleNamespace(returncode=0)
        target = private_destination(command[-1])
        if operation == "install":
            mode = int(command[command.index("-m") + 1], 8)
            if "-d" in command:
                target.mkdir(parents=True, exist_ok=True)
            else:
                if target in mappings.values():
                    if outcome == "preimage-before-write":
                        receipt = target.parent / next(iter(live_dir.glob(".load-dhcp-transaction-*"))).name / "a-preimage.json"
                        assert receipt.is_file(), "persistent four-file A preimage must precede every B overwrite"
                        assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
                        envelope = json.loads(receipt.read_bytes())
                        body = envelope["body"]
                        assert envelope["sha256"] == hashlib.sha256(
                            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                        ).hexdigest()
                        assert body["schema_version"] == 1 and body["phase"] == "prepared-a"
                        assert body["runtime"]["path"] == str(live_dir)
                        assert set(body["before"]) == set(names)
                        for name in names:
                            row = body["before"][name]
                            assert row["state"] == "file" and row["mode"] == 0o644
                            assert row["sha256"] == hashlib.sha256(expected_a[name]).hexdigest()
                            assert row["size"] == len(expected_a[name])
                        assert body["after_sha256"] == {
                            name: hashlib.sha256(expected_b[name]).hexdigest() for name in names
                        }
                        assert body["parent"]["before"] == {"state": "missing"}
                        assert body["parent"]["destination"] == str(candidate.destination)
                        assert body["parent"]["candidate"]["release_id"] == "independent-B"
                    if outcome == "backup-sync-success":
                        assert backup_sync_events == [*names, "backup", "transaction", "runtime"], \
                            "all A payloads and backup ancestry must sync before any B install"
                    installed_b.append(target)
                if target.is_symlink():
                    target.unlink()
                shutil.copy2(command[-2], target)
            target.chmod(mode)
        elif operation == "cp":
            if (outcome in {"restore-return", "restore-raise"}
                    and target == live_dir / "dhcpd_eth.hosts"):
                injected.append(outcome)
                if outcome == "restore-raise":
                    raise OSError("independent A restore copy fault")
                return SimpleNamespace(returncode=1)
            shutil.copy2(command[-2], target, follow_symlinks=False)
            if (outcome in {"backup-bytes", "backup-mode", "backup-link"}
                    and target.parent.name == "backup" and target.name == "dhcpd_eth.hosts"):
                injected.append(outcome)
                if outcome == "backup-bytes":
                    target.write_bytes(b"independent unaccepted backup bytes\n")
                elif outcome == "backup-mode":
                    target.chmod(0o600)
                else:
                    target.unlink()
                    target.symlink_to("independent-absent-backup-source")
            if (outcome in {"restore-bytes", "restore-mode", "restore-link"}
                    and target == live_dir / "dhcpd_eth.hosts"):
                injected.append(outcome)
                if outcome == "restore-bytes":
                    target.write_bytes(b"independent unaccepted restored bytes\n")
                elif outcome == "restore-mode":
                    target.chmod(0o600)
                else:
                    target.unlink()
                    target.symlink_to("independent-absent-target")
        elif operation == "rm":
            cleanup.append(target)
            target.unlink(missing_ok=True)
        elif operation == "rmdir":
            cleanup.append(target)
            target.rmdir()
        else:
            raise AssertionError("unexpected private command: " + repr(command))
        return SimpleNamespace(returncode=0)

    def sync_parent(descriptor):
        metadata = os.fstat(descriptor)
        for transaction in live_dir.glob(".load-dhcp-transaction-*"):
            receipt = transaction / "a-preimage.json"
            if outcome == "preimage-file-sync" and receipt.exists():
                target = receipt.stat()
                if (metadata.st_dev, metadata.st_ino) == (target.st_dev, target.st_ino):
                    injected.append(outcome)
                    raise OSError("independent A preimage receipt sync fault")
            backup = transaction / "backup"
            paths = [(backup / name, name, "backup-file-sync") for name in names]
            paths += [(backup, "backup", "backup-dir-sync"),
                      (transaction, "transaction", "backup-transaction-sync"),
                      (live_dir, "runtime", "backup-runtime-sync")]
            if not installed_b:
                for path, label, fault in paths:
                    if not os.path.lexists(path) or path.is_symlink():
                        continue
                    target = path.lstat()
                    if (metadata.st_dev, metadata.st_ino) == (target.st_dev, target.st_ino):
                        backup_sync_events.append(label)
                        if outcome == fault:
                            injected.append(outcome)
                            raise OSError("independent A backup durability fault: " + label)
        if restore_phase:
            if stat.S_ISDIR(metadata.st_mode):
                target = live_dir.stat()
                if (metadata.st_dev, metadata.st_ino) == (target.st_dev, target.st_ino):
                    sync_events.append("directory")
            elif stat.S_ISREG(metadata.st_mode):
                for name in names:
                    path = live_dir / name
                    if os.path.lexists(path) and not path.is_symlink():
                        target = path.lstat()
                        if (metadata.st_dev, metadata.st_ino) == (target.st_dev, target.st_ino):
                            sync_events.append(name)
        if outcome == "restore-file-sync" and restore_phase and stat.S_ISREG(metadata.st_mode):
            target = (live_dir / "dhcpd_eth.hosts").stat()
            if (metadata.st_dev, metadata.st_ino) == (target.st_dev, target.st_ino):
                injected.append(outcome)
                raise OSError("independent restored A file sync fault")
        if outcome == "restore-dir-sync" and restore_phase and stat.S_ISDIR(metadata.st_mode):
            target = live_dir.stat()
            if (metadata.st_dev, metadata.st_ino) == (target.st_dev, target.st_ino):
                injected.append(outcome)
                raise OSError("independent restored A directory sync fault")
        if outcome == "fsync" and (metadata.st_dev, metadata.st_ino) == (
            parent_identity.st_dev, parent_identity.st_ino,
        ):
            injected.append("fsync")
            raise OSError("independent DHCP parent directory sync fault")
        return real_sync(descriptor)

    def open_parent(path, flags, *args, **kwargs):
        if outcome == "backup-read" and isinstance(path, (str, os.PathLike)) \
                and Path(path).parent.name == "backup" and Path(path).name == "dhcpd_eth.hosts":
            injected.append(outcome)
            raise PermissionError("independent backup read refusal")
        if outcome == "restore-dir-open" and restore_phase and isinstance(path, (str, os.PathLike)) \
                and Path(path) == live_dir and flags & os.O_DIRECTORY:
            injected.append(outcome)
            raise OSError("independent restored A directory open fault")
        if outcome == "open" and isinstance(path, (str, os.PathLike)) \
                and Path(path) == candidate.destination.parent:
            injected.append("open")
            raise OSError("independent DHCP parent directory open fault")
        return real_open(path, flags, *args, **kwargs)

    if outcome in {"precommit", "precommit-shapes", "restore-return", "restore-raise",
                   "restore-bytes", "restore-mode", "restore-link",
                   "restore-file-sync", "restore-dir-open", "restore-dir-sync"}:
        def fail_precommit():
            restore_phase.append("independent precommit rejection")
            raise api.LoadError("independent precommit rejection")
        candidate.precommit_check = fail_precommit
    try:
        with mock.patch.object(api, "dhcp_file_mappings", return_value=mappings), \
                mock.patch.object(api, "sudo_command", side_effect=lambda *args: list(args)), \
                mock.patch.object(api, "run", side_effect=private_command), \
                mock.patch.object(api, "_run_subprocess", side_effect=private_command), \
                mock.patch.object(api, "warn", side_effect=warnings.append), \
                mock.patch.object(api.os, "open", side_effect=open_parent), \
                mock.patch.object(api.os, "fsync", side_effect=sync_parent):
            try:
                api.mount_and_test_dhcp(parent_candidate=candidate)
            except (api.LoadError, OSError) as exc:
                if outcome in {"open", "fsync"}:
                    assert "持久化" in str(exc) and "未确认" in str(exc), str(exc)
                elif outcome in {"precommit", "precommit-shapes"}:
                    assert "independent precommit rejection" in str(exc), str(exc)
                elif outcome == "restore-return":
                    assert "旧文件未能自动恢复" in str(exc), str(exc)
                elif outcome == "restore-raise":
                    assert "independent A restore copy fault" in str(exc), str(exc)
                elif outcome in {"restore-bytes", "restore-mode", "restore-link"}:
                    assert "DHCP A restore verification failed" in str(exc), str(exc)
                elif outcome in {"restore-file-sync", "restore-dir-open", "restore-dir-sync"}:
                    assert "DHCP A restore durability unconfirmed" in str(exc), str(exc)
                elif outcome in {"backup-bytes", "backup-mode", "backup-link", "backup-read"}:
                    assert "DHCP A backup verification failed" in str(exc), str(exc)
                elif outcome in backup_sync_faults:
                    assert "DHCP A backup durability unconfirmed" in str(exc), str(exc)
                elif outcome == "preimage-file-sync":
                    assert "DHCP A preimage receipt" in str(exc) and "HOLD" in str(exc), str(exc)
                else:
                    raise
            else:
                assert outcome in {"success", "backup-sync-success", "preimage-before-write"}, "failure must propagate before service continuation"
        transactions = list(live_dir.glob(".load-dhcp-transaction-*"))
        if outcome in {"backup-bytes", "backup-mode", "backup-link", "backup-read", "preimage-file-sync", *backup_sync_faults}:
            assert injected == [outcome], injected
            assert installed_b == [], "bad A backup must reject before the first B install"
            assert not candidate.committed and not candidate.directory_synced
            assert not candidate.destination.exists()
            assert {name: (live_dir / name).read_bytes() for name in names} == expected_a
            assert len(transactions) == 1, "bad A backup is retained evidence, not cleanup authority"
            transaction, = transactions
            backup = transaction / "backup"
            assert stat.S_IMODE(backup.stat().st_mode) == 0o700
            bad_backup = backup / "dhcpd_eth.hosts"
            if outcome == "backup-bytes":
                assert bad_backup.read_bytes() == b"independent unaccepted backup bytes\n"
            elif outcome == "backup-mode":
                assert bad_backup.read_bytes() == expected_a["dhcpd_eth.hosts"]
                assert stat.S_IMODE(bad_backup.lstat().st_mode) == 0o600
            elif outcome == "backup-link":
                assert os.readlink(bad_backup) == "independent-absent-backup-source"
            else:
                assert bad_backup.read_bytes() == expected_a["dhcpd_eth.hosts"]
            for name in ("dhcpd.conf", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"):
                assert (backup / name).read_bytes() == expected_a[name]
            assert {p.name for p in (transaction / "staged").iterdir()} == set(names)
            assert not cleanup, "unverified backups must not be silently erased"
            assert any("HOLD" in warning and str(transaction) in warning for warning in warnings)
            assert not any("手工删除" in warning for warning in warnings)
            try:
                api.require_no_pending_dhcp_transaction(live_dir)
            except api.LoadError as exc:
                assert "pending DHCP transaction" in str(exc), str(exc)
            else:
                raise AssertionError("bad backup evidence failed to fence a fresh LOAD")
            return
        if outcome == "precommit-shapes":
            assert not candidate.committed and not candidate.directory_synced
            assert not candidate.destination.exists()
            assert transactions == [], "verified link/missing restore must keep normal cleanup"
            assert sync_events == ["dhcpd.conf", "dhcpd_ib.hosts", "directory"], sync_events
            assert os.readlink(live_dir / "dhcpd_eth.hosts") == "../independent-original-A-source"
            assert original_link_source.read_bytes() == expected_a["dhcpd_eth.hosts"]
            assert not os.path.lexists(live_dir / "dhcpd_nvl.hosts")
            for name in ("dhcpd.conf", "dhcpd_ib.hosts"):
                assert (live_dir / name).read_bytes() == expected_a[name]
            return
        if outcome in {"restore-return", "restore-raise", "restore-bytes",
                       "restore-mode", "restore-link", "restore-file-sync",
                       "restore-dir-open", "restore-dir-sync"}:
            assert injected == [outcome], injected
            assert not candidate.committed and not candidate.directory_synced
            assert not candidate.destination.exists()
            assert len(transactions) == 1, "incomplete A restore must retain original backups"
            transaction, = transactions
            backup = transaction / "backup"
            assert stat.S_IMODE(backup.stat().st_mode) == 0o700
            assert {p.name: p.read_bytes() for p in backup.iterdir()} == expected_a
            assert {p.name for p in (transaction / "staged").iterdir()} == set(names)
            fault_target = live_dir / "dhcpd_eth.hosts"
            if outcome in {"restore-return", "restore-raise"}:
                assert not fault_target.exists(), "fixture must reach partial restore"
            elif outcome == "restore-bytes":
                assert fault_target.read_bytes() == b"independent unaccepted restored bytes\n"
            elif outcome == "restore-mode":
                assert stat.S_IMODE(fault_target.lstat().st_mode) == 0o600
            elif outcome == "restore-link":
                assert os.readlink(fault_target) == "independent-absent-target"
            else:
                assert {name: (live_dir / name).read_bytes() for name in names} == expected_a, \
                    "restore bytes alone do not prove durable A"
            assert not any(path == transaction or transaction in path.parents for path in cleanup), \
                "failed A restore must not delete transaction evidence"
            assert any("HOLD" in warning and str(transaction) in warning for warning in warnings)
            assert not any("手工删除" in warning for warning in warnings)
            try:
                api.require_no_pending_dhcp_transaction(live_dir)
            except api.LoadError as exc:
                assert "pending DHCP transaction" in str(exc), str(exc)
            else:
                raise AssertionError("failed restore evidence did not fence a new LOAD")
            return
        installed = {name: (live_dir / name).read_bytes() for name in names}
        if outcome in {"open", "fsync"}:
            assert injected == [outcome], injected
            assert candidate.committed and not candidate.directory_synced
            assert json.loads(candidate.destination.read_text()) == parent_payload
            assert installed == expected_b, "do not roll DHCP back behind visible B"
            assert len(transactions) == 1, "unconfirmed B must retain the A transaction backup"
            transaction = transactions[0]
            backup = transaction / "backup"
            assert stat.S_IMODE(backup.stat().st_mode) == 0o700
            assert {p.name: p.read_bytes() for p in backup.iterdir()} == expected_a
            assert {p.name for p in (transaction / "staged").iterdir()} == set(names)
            assert not cleanup, "HOLD must not delete staged/backup evidence"
            assert any("HOLD" in warning and str(transaction) in warning for warning in warnings)
            assert not any("手工删除" in warning for warning in warnings)
            if reenter:
                identity = transaction.stat()
                backup_identity = backup.stat()
                for source in mappings:
                    source.write_bytes(expected_b[source.name] + b"# independent unaccepted retry\n")
                commands = []

                def retry_command(command, **kwargs):
                    commands.append(command)
                    return private_command(command, **kwargs)

                with mock.patch.object(api, "dhcp_file_mappings", return_value=mappings), \
                        mock.patch.object(api, "sudo_command", side_effect=lambda *args: list(args)), \
                        mock.patch.object(api, "run", side_effect=retry_command), \
                        mock.patch.object(api, "_run_subprocess", side_effect=retry_command), \
                        mock.patch.object(api, "warn", side_effect=warnings.append):
                    try:
                        api.mount_and_test_dhcp(parent_candidate=candidate)
                    except api.LoadError as exc:
                        assert "持久化" in str(exc) and "未确认" in str(exc), str(exc)
                    else:
                        raise AssertionError("unconfirmed B installation reentry returned success")
                assert commands == [], "HOLD reentry must reject before all DHCP commands"
                assert list(live_dir.glob(".load-dhcp-transaction-*")) == transactions
                assert {name: (live_dir / name).read_bytes() for name in names} == expected_b
                assert {p.name: p.read_bytes() for p in backup.iterdir()} == expected_a
                assert (transaction.stat().st_dev, transaction.stat().st_ino) == (
                    identity.st_dev, identity.st_ino,
                )
                assert (backup.stat().st_dev, backup.stat().st_ino) == (
                    backup_identity.st_dev, backup_identity.st_ino,
                )
                assert json.loads(candidate.destination.read_text()) == parent_payload
        else:
            assert transactions == [], "normal success and precommit rollback still clean up"
            assert installed == (expected_a if outcome == "precommit" else expected_b)
            assert candidate.committed == (outcome in {"success", "backup-sync-success", "preimage-before-write"})
            assert candidate.directory_synced == (outcome in {"success", "backup-sync-success", "preimage-before-write"})
            if outcome == "precommit":
                assert not candidate.destination.exists()
                assert sync_events == list(names) + ["directory"], sync_events
    finally:
        api.discard_prepared_release(candidate)


def prepare_r22_empty_unselected_dhcp_fixture(fixture):
    """Generate a real eth-only child with zero-byte unselected host files."""
    project = fixture.project
    dhcp_dir = fixture.ztp / "config/isc-dhcp-server"
    outputs = project / "99-output-dhcp"
    outputs.mkdir()
    global_document = yaml.safe_load(
        (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
            encoding="utf-8",
        )
    )
    global_document["schema_version"] = 1
    global_document["common"]["mgmt"].pop("issue-tracker", None)
    global_document["common"]["mgmt"]["dhcp-server"]["status"] = "enabled"
    global_document["common"]["mgmt"]["ztp"]["status"] = "enabled"
    global_document["common"]["mgmt"]["ztp"]["ztp_url_prefix"] = "/ztp"
    fixture.global_file.write_text(
        yaml.safe_dump(global_document), encoding="utf-8",
    )
    fixture.subnet_file.write_text(
        "shared_network,subnet,netmask,range_start,range_end,routers,"
        "ztp_service_ip,cumulus_profile,nvos_ztp\n"
        "oob,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
        "192.0.2.1,192.0.2.2,oob,no\n",
        encoding="utf-8",
    )
    names = (
        "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
        "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
    )
    for name in names:
        public = dhcp_dir / name
        public.unlink()
        target = outputs / name
        if name in {"dhcpd_ib.hosts", "dhcpd_nvl.hosts"}:
            target.write_bytes(b"")
        public.symlink_to(os.path.relpath(target, dhcp_dir))
    with mock.patch.object(sys, "argv", [
        "c1-generate_dhcp.py", "-y", "--deployment-scope", "prod",
        "--switch", "eth",
    ]), mock.patch.multiple(
        DHCP, HTTP_ROOT=str(fixture.root), SCRIPT_DIR=str(dhcp_dir),
        OUTPUT_CONF=str(outputs / "dhcpd.conf"),
        OUTPUT_ETH=str(outputs / "dhcpd_eth.hosts"),
        OUTPUT_IB=str(outputs / "dhcpd_ib.hosts"),
        OUTPUT_NVL=str(outputs / "dhcpd_nvl.hosts"),
        OUTPUT_MANIFEST=str(outputs / "dhcp-release-manifest.json"),
        GLOBAL_YAML=str(fixture.global_file),
        DEVICES_CSV=str(fixture.devices_file),
        SUBNET_CSV=str(fixture.subnet_file),
        P2P_AIR_JSON=str(project / "p2p-air.json"), _AUTO_YES=False,
    ), mock.patch.object(DHCP, "stop_native_ztp_monitors"):
        DHCP.main()
    child = json.loads(
        (outputs / "dhcp-release-manifest.json").read_text(encoding="utf-8")
    )
    cumulus_manifest = (
        project / "99-output-eth/20260830_120000_combine/release-manifest.json"
    )
    cumulus = json.loads(cumulus_manifest.read_text(encoding="utf-8"))
    cumulus["deployment_scope"] = "prod"
    cumulus["switch_scope"] = "eth"
    cumulus_manifest.write_text(json.dumps(cumulus), encoding="utf-8")
    return LOAD.replace(
        fixture.inputs, deployment_scope="prod", switch_scope="eth",
    ), outputs, child


def h19_mini_policy(*, unknown_role_action: str = "error") -> dict:
    """Independent, non-GB300 taxonomy for the real load-to-topology workflow."""
    return {
        "node_allowlist": {},
        "link_rewrites": [],
        "mini_sampling": {
            "location_prefix_regex": r"^(?:moon|mars|nova)-(?P<logical>.+)$",
            "unknown_role_action": unknown_role_action,
            "roles": [
                {
                    "name": "orbital-hub",
                    "hostname_regex": r"^orbital-hub-(?P<index>\d+)$",
                    "selection": {"mode": "first", "count": 1},
                },
                {
                    "name": "crystal-edge",
                    "hostname_regex": r"^crystal-edge-(?P<index>\d+)$",
                    "selection": {
                        "mode": "indices", "capture_group": "index",
                        "indices": [1],
                    },
                },
                {
                    "name": "anchor-gateway",
                    "hostname_regex": r"^anchor-gateway-(?P<index>\d+)$",
                    "selection": {
                        "mode": "anchor",
                        "peer_hostname_regex": r"^orbital-hub-.+$",
                        "peer_port_regex": r"^eth0$",
                    },
                },
            ],
        },
    }


def write_valid_nvos_image(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.write(b"#!/bin/sh")
        stream.truncate(1024 * 1024)


def write_shared_receipt_image_fixture(path: Path) -> None:
    """Public image premise for receipt tests; unrelated image attacks stay raw."""
    write_valid_nvos_image(path)
    path.chmod(0o644)


def write_shared_artifact_receipt(
    root: Path, project: Path, inputs, image: Path, *,
    project_name: str | None = None,
    deployment_scope: str | None = None,
    switch_scope: str | None = None,
    global_sha256: str | None = None,
    family: str = "eth",
    version: str = "5.18.1",
    artifact_size: int | None = None,
) -> Path:
    receipt_dir = root / ".shared-artifact-receipts"
    receipt_dir.mkdir(mode=0o755)
    receipt_dir.chmod(0o755)
    input_files = {
        inputs.global_file.name: inputs.global_file,
        inputs.devices_file.name: inputs.devices_file,
    }
    if inputs.mini_devices_file is not None:
        input_files[inputs.mini_devices_file.name] = inputs.mini_devices_file
    identities = {
        name: {
            "sha256": sha256(path),
            "size": path.stat().st_size,
        }
        for name, path in input_files.items()
    }
    if global_sha256 is not None:
        identities[inputs.global_file.name]["sha256"] = global_sha256
    archive_sha = "a" * 64
    receipt = {
        "archive_sha256": archive_sha,
        "artifact_type": "http-ztp-shared-artifact-receipt",
        "artifacts": [{
            "consumers": [{"family": family, "version": version}],
            "kind": "switch-image",
            "platform": None,
            "sha256": sha256(image),
            "size": artifact_size if artifact_size is not None else image.stat().st_size,
            "target": "image/" + image.name,
        }],
        "metadata_sha256": "b" * 64,
        "project": project_name or project.name,
        "schema_version": 1,
        "selection": {
            "deployment_scope": deployment_scope or inputs.deployment_scope,
            "inputs": identities,
            "mini": inputs.mini_devices_file is not None,
            "mini_input": (
                inputs.mini_devices_file.name
                if inputs.mini_devices_file is not None else None
            ),
            "switch_scope": switch_scope or inputs.switch_scope,
            "upgrade_policy": "enabled",
        },
    }
    path = receipt_dir / f"{archive_sha}.json"
    path.write_text(
        json.dumps(receipt, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    path.chmod(0o600)
    return path


# CTMP candidate: retain the macOS system alias and a private effective-gid root.
# Default adoption still requires the paired layout and full qualification gates.
_RELEASE_ROOT_ALIAS = ("/tmp", "private/tmp")

def _release_fixture_temporary():
    """Keep the macOS root-owned alias; never change process TMPDIR."""
    alias, target = _RELEASE_ROOT_ALIAS
    try:
        alias_stat = os.lstat(alias)
    except FileNotFoundError:
        return tempfile.TemporaryDirectory()
    if (not stat.S_ISLNK(alias_stat.st_mode) or alias_stat.st_uid != 0
            or os.readlink(alias) != target):
        return tempfile.TemporaryDirectory()
    temporary = tempfile.TemporaryDirectory(
        prefix="http-rt-", suffix=".noindex", dir=alias,
    )
    try:
        os.chown(temporary.name, -1, os.getegid())
        root_stat = os.lstat(temporary.name)
        if (not stat.S_ISDIR(root_stat.st_mode)
                or stat.S_IMODE(root_stat.st_mode) != 0o700
                or (root_stat.st_uid, root_stat.st_gid)
                != (os.geteuid(), os.getegid())):
            raise RuntimeError(
                "release fixture root is not an own private directory: "
                + temporary.name
            )
    except BaseException:
        temporary.cleanup()
        raise
    return temporary

class ReleaseFixtureRootLayoutTests(unittest.TestCase):
    def setUp(self):
        self.alias_stat = SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=0)
        self.private_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700,
                                            st_uid=os.geteuid(), st_gid=os.getegid())

    def fake_factory(self, *, result_stat=None, chown_error=None):
        temporary = SimpleNamespace(name="/tmp/http-rt-independent.noindex",
                                    cleanup=mock.Mock())
        calls = mock.Mock(return_value=temporary)
        stats = [self.alias_stat, result_stat or self.private_stat]
        stack = __import__("contextlib").ExitStack()
        stack.enter_context(mock.patch.object(sys.modules[__name__].os, "lstat", side_effect=stats))
        stack.enter_context(mock.patch.object(sys.modules[__name__].os, "readlink", return_value="private/tmp"))
        stack.enter_context(mock.patch.object(sys.modules[__name__].os, "chown", side_effect=chown_error))
        stack.enter_context(mock.patch.object(sys.modules[__name__].tempfile, "TemporaryDirectory", calls))
        return stack, calls, temporary

    def test_native_alias_layout_private_identity_and_real_cleanup(self):
        before = os.environ.get("TMPDIR")
        alias = Path("/tmp")
        info = alias.lstat()
        supported = stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and os.readlink(alias) == "private/tmp"
        with sys.modules[__name__]._release_fixture_temporary() as name:
            path = Path(name)
            if supported:
                self.assertRegex(str(path), r"^/tmp/http-rt-[^/]+\.noindex$")
                self.assertEqual("/private" + str(path), os.path.realpath(path))
            else:
                self.assertEqual(Path(tempfile.gettempdir()), path.parent)
            info = path.lstat()
            self.assertTrue(stat.S_ISDIR(info.st_mode))
            self.assertEqual(0o700, stat.S_IMODE(info.st_mode))
            self.assertEqual((os.geteuid(), os.getegid()), (info.st_uid, info.st_gid))
        self.assertFalse(path.exists())
        self.assertEqual(before, os.environ.get("TMPDIR"))

    def test_supported_alias_uses_exact_private_factory_arguments(self):
        stack, factory, temporary = self.fake_factory()
        with stack:
            self.assertIs(temporary, sys.modules[__name__]._release_fixture_temporary())
            factory.assert_called_once_with(prefix="http-rt-", suffix=".noindex", dir="/tmp")
            sys.modules[__name__].os.chown.assert_called_once_with(temporary.name, -1, os.getegid())
            temporary.cleanup.assert_not_called()

    def test_missing_alias_uses_unmodified_fallback(self):
        marker=object()
        with mock.patch.object(sys.modules[__name__].os, "lstat", side_effect=FileNotFoundError), mock.patch.object(sys.modules[__name__].tempfile, "TemporaryDirectory", return_value=marker) as factory:
            self.assertIs(marker, sys.modules[__name__]._release_fixture_temporary())
            factory.assert_called_once_with()

    def test_non_alias_wrong_owner_and_target_use_fallback(self):
        for mode, uid, target in ((stat.S_IFDIR | 0o1777, 0, "private/tmp"),
                                  (stat.S_IFLNK | 0o755, 501, "private/tmp"),
                                  (stat.S_IFLNK | 0o755, 0, "unexpected")):
            with self.subTest(mode=mode, uid=uid, target=target):
                marker=object()
                with mock.patch.object(sys.modules[__name__].os, "lstat", return_value=SimpleNamespace(st_mode=mode,st_uid=uid)), mock.patch.object(sys.modules[__name__].os, "readlink", return_value=target), mock.patch.object(sys.modules[__name__].tempfile, "TemporaryDirectory", return_value=marker) as factory:
                    self.assertIs(marker, sys.modules[__name__]._release_fixture_temporary())
                    factory.assert_called_once_with()

    def test_alias_stat_permission_error_is_not_silent_fallback(self):
        with mock.patch.object(sys.modules[__name__].os, "lstat", side_effect=PermissionError("independent alias denial")), mock.patch.object(sys.modules[__name__].tempfile, "TemporaryDirectory") as factory:
            with self.assertRaisesRegex(PermissionError, "independent alias denial"):
                sys.modules[__name__]._release_fixture_temporary()
            factory.assert_not_called()

    def test_chown_error_cleans_the_exact_new_handle_and_propagates(self):
        stack, factory, temporary = self.fake_factory(chown_error=PermissionError("independent chown denial"))
        with stack:
            with self.assertRaisesRegex(PermissionError, "independent chown denial"):
                sys.modules[__name__]._release_fixture_temporary()
        temporary.cleanup.assert_called_once_with()

    def test_root_stat_error_cleans_and_propagates(self):
        stack, factory, temporary = self.fake_factory()
        with stack:
            sys.modules[__name__].os.lstat.side_effect=[self.alias_stat,OSError("independent root stat denial")]
            with self.assertRaisesRegex(OSError, "independent root stat denial"):
                sys.modules[__name__]._release_fixture_temporary()
        temporary.cleanup.assert_called_once_with()

    def test_non_directory_mode_uid_and_gid_are_each_rejected(self):
        for mode,uid,gid in ((stat.S_IFLNK|0o700,os.geteuid(),os.getegid()),
                             (stat.S_IFDIR|0o755,os.geteuid(),os.getegid()),
                             (stat.S_IFDIR|0o700,os.geteuid()+1,os.getegid()),
                             (stat.S_IFDIR|0o700,os.geteuid(),os.getegid()+1)):
            with self.subTest(mode=mode,uid=uid,gid=gid):
                invalid=SimpleNamespace(st_mode=mode,st_uid=uid,st_gid=gid)
                stack,factory,temporary=self.fake_factory(result_stat=invalid)
                with stack:
                    with self.assertRaisesRegex(RuntimeError,"^release fixture root is not an own private directory"):
                        sys.modules[__name__]._release_fixture_temporary()
                temporary.cleanup.assert_called_once_with()

    def test_cleanup_error_is_not_hidden(self):
        stack,factory,temporary=self.fake_factory(chown_error=PermissionError("independent chown denial"))
        temporary.cleanup.side_effect=OSError("independent cleanup denial")
        with stack:
            with self.assertRaisesRegex(OSError,"independent cleanup denial") as raised:
                sys.modules[__name__]._release_fixture_temporary()
        self.assertIsInstance(raised.exception.__context__,PermissionError)

    def test_native_two_roots_are_distinct_and_tmpdir_unchanged(self):
        before=os.environ.get("TMPDIR")
        with sys.modules[__name__]._release_fixture_temporary() as first, sys.modules[__name__]._release_fixture_temporary() as second:
            self.assertNotEqual(first,second)
            self.assertTrue(Path(first).is_dir())
            self.assertTrue(Path(second).is_dir())
        self.assertFalse(Path(first).exists())
        self.assertFalse(Path(second).exists())
        self.assertEqual(before,os.environ.get("TMPDIR"))

    def test_actual_release_transaction_setup_uses_factory_and_original_cleanup(self):
        before = os.environ.get("TMPDIR")
        fixture = ReleaseTransactionTests("test_pre_mutation_failure_also_reports_exact_full_rerun")
        fixture.setUp()
        path = fixture.root
        try:
            alias_stat = os.lstat("/tmp")
            supported = (stat.S_ISLNK(alias_stat.st_mode) and alias_stat.st_uid == 0
                         and os.readlink("/tmp") == "private/tmp")
            if supported:
                self.assertRegex(str(path), r"^/tmp/http-rt-[^/]+\.noindex$")
            else:
                self.assertEqual(Path(tempfile.gettempdir()), path.parent)
            self.assertTrue(fixture.global_file.is_file())
            self.assertTrue(fixture.p2p_file.is_symlink())
        finally:
            fixture.doCleanups()
            fixture.tearDown()
        self.assertFalse(path.exists())
        self.assertEqual(before, os.environ.get("TMPDIR"))



class ReleaseTransactionTests(unittest.TestCase):
    # P1 (owner 2026-10-25: performance is decided by http test).  Contract: in
    # original A explicit activation every operation has one complete
    # qualification ("Q") immediately before and immediately after it, and a
    # qualification is not repeated when nothing -- not even a read -- ran
    # since the previous complete one.  Pure computation is not an operation
    # (systemd derives its service set without one, so two qualifications stay
    # adjacent there).  Literals are written from that rule and the documented
    # step order, then cross-checked against the per-shape counts (pre +
    # preflight + post): supervisor two services 3+10+6, supervisor HTTP only
    # 3+7+4 (an HTTP-only plan has no ZTP endpoint, so no network gate),
    # systemd two services 3+9+6.  They are not taken from a recording.
    _P1_SUPERVISOR_TWO_SERVICES = (
        "Q", "image", "Q", "report", "Q", "plan",
        "Q", "preflight.plan", "Q", "preflight.availability", "Q", "preflight.control-auth", "Q",
        "preflight.published", "Q", "preflight.boundary", "Q", "preflight.configtest", "Q",
        "preflight.selector", "Q", "preflight.dhcp-sources", "Q", "preflight.dhcpd", "Q",
        "availability", "Q", "network", "Q",
        "start:apache2", "Q", "start:isc-dhcp-server", "Q", "verify-http", "Q", "active", "Q",
    )
    _P1_SUPERVISOR_HTTP_ONLY = (
        "Q", "image", "Q", "report", "Q", "plan",
        "Q", "preflight.plan", "Q", "preflight.availability", "Q", "preflight.control-auth", "Q",
        "preflight.published", "Q", "preflight.boundary", "Q", "preflight.configtest", "Q",
        "availability", "Q",
        "start:apache2", "Q", "verify-http", "Q", "active", "Q",
    )
    _P1_SYSTEMD_TWO_SERVICES = (
        "Q", "image", "Q", "report", "Q", "plan",
        "Q", "preflight.management", "Q", "preflight.control-auth", "Q", "preflight.published", "Q",
        "preflight.boundary", "Q", "preflight.selector", "Q", "preflight.dhcp-sources", "Q",
        "preflight.dhcpd", "Q", "preflight.configtest", "Q",
        "Q", "network", "Q",
        "start:apache2", "Q", "start:isc-dhcp-server", "Q", "verify-http", "Q", "active", "Q",
    )

    def test_native_listener_late_original_rebind_holds_before_backup_or_b_write(self):
        for prior_exists in (True, False):
            with self.subTest(prior_exists=prior_exists), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                destination = root / "http-ztp-listeners.conf"
                original = b"Listen 192.0.2.9:80\n"
                if prior_exists:
                    destination.write_bytes(original)
                    destination.chmod(0o640)
                original_owner = destination.stat() if prior_exists else None
                held_original = root / "independent-held-original-A"
                foreign = original if prior_exists else b"independent foreign listener\n"
                sync = LOAD.os.fsync
                injections = []
                command = mock.Mock(side_effect=AssertionError("source HOLD ran configtest"))

                def rebind_after_candidate_sync(descriptor):
                    result = sync(descriptor)
                    if not injections and stat.S_ISREG(os.fstat(descriptor).st_mode):
                        if prior_exists:
                            destination.rename(held_original)
                        destination.write_bytes(foreign)
                        destination.chmod(0o640)
                        if original_owner is not None:
                            os.utime(destination, ns=(original_owner.st_atime_ns,
                                                     original_owner.st_mtime_ns))
                        injections.append(destination.stat().st_ino)
                    return result

                with mock.patch.object(LOAD.os, "fsync", side_effect=rebind_after_candidate_sync):
                    with self.assertRaisesRegex(LOAD.LoadError, "HOLD"):
                        LOAD.publish_native_apache_listener_config(
                            ("192.0.2.40",), destination=destination, command_runner=command,
                        )
                command.assert_not_called()
                self.assertEqual(1, len(injections), "fault missed candidate synchronization")
                self.assertEqual(injections[0], destination.stat().st_ino)
                self.assertEqual(foreign, destination.read_bytes())
                self.assertEqual([], list(root.glob(f".{destination.name}.*")))
                if original_owner is not None:
                    self.assertEqual(original_owner.st_ino, held_original.stat().st_ino)
                    self.assertEqual(original, held_original.read_bytes())

    def test_native_listener_failed_rollback_retains_original_a_authority(self):
        original = b"Listen 192.0.2.9:80\n"
        for phase in ("configtest", "publication-sync", "retirement-sync"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                destination = root / "http-ztp-listeners.conf"
                destination.write_bytes(original)
                destination.chmod(0o640)
                owner = destination.stat()
                replace = LOAD.os.replace
                sync = LOAD._fsync_parent_directory
                synchronizations = []
                rollback_attempts = []

                def failed_restore(source, target):
                    if Path(source).suffix in (".rollback", ".recovery"):
                        rollback_attempts.append(Path(source))
                        raise OSError("independent rollback rename failure")
                    return replace(source, target)

                def injected_sync(path):
                    synchronizations.append(Path(path))
                    fail_at = {"publication-sync": 1, "retirement-sync": 2}.get(phase)
                    if len(synchronizations) == fail_at:
                        raise OSError("independent publication durability failure")
                    return sync(path)

                def configtest(_command):
                    if phase == "configtest":
                        raise LOAD.LoadError("independent syntax rejection")

                with mock.patch.object(LOAD.os, "replace", side_effect=failed_restore), \
                        mock.patch.object(LOAD, "_fsync_parent_directory", side_effect=injected_sync):
                    with self.assertRaisesRegex(LOAD.LoadError, "旧配置回滚失败"):
                        LOAD.publish_native_apache_listener_config(
                            ("192.0.2.40",), destination=destination,
                            command_runner=configtest,
                        )
                self.assertTrue(rollback_attempts, "fault missed the actual restore")
                authorities = list(root.glob(f".{destination.name}.*.rollback")) + list(
                    root.glob(f".{destination.name}.*.recovery")
                )
                self.assertEqual(1, len(authorities), "failed rollback destroyed the only A copy")
                authority = authorities[0]
                self.assertEqual(original, authority.read_bytes())
                held = authority.stat()
                self.assertEqual(
                    (owner.st_dev, owner.st_ino, owner.st_uid, owner.st_gid, 0o640),
                    (held.st_dev, held.st_ino, held.st_uid, held.st_gid,
                     stat.S_IMODE(held.st_mode)),
                )
                self.assertNotEqual(owner.st_ino, destination.stat().st_ino)
                current = destination.read_bytes()
                command = mock.Mock(side_effect=AssertionError("reentry ran configtest"))
                with self.assertRaisesRegex(LOAD.LoadError, "滞留 rollback/recovery"):
                    LOAD.publish_native_apache_listener_config(
                        ("198.51.100.20",), destination=destination, command_runner=command,
                    )
                command.assert_not_called()
                self.assertEqual(current, destination.read_bytes())
                self.assertEqual(original, authority.read_bytes())

    def test_project_switch_snapshots_materialized_latest_behind_rebound_output_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_project = root / "DAY0-Prepare/old"
            new_project = root / "DAY0-Prepare/new"
            old_output = old_project / "99-output-eth"
            new_output = new_project / "99-output-eth"
            release = new_output / "20260910_103416_combine"
            materialized = new_output / "latest"
            old_output.mkdir(parents=True)
            for directory_path in (release, materialized):
                directory_path.mkdir(parents=True)
                (directory_path / ".published-complete").write_text(
                    "complete\n", encoding="utf-8"
                )
                (directory_path / "leaf.yaml").write_bytes(b"hostname: leaf\n")

            ztp = root / "ztp"
            template = ztp / "config/cumulus/template"
            template.mkdir(parents=True)
            output_alias = template / "99-output"
            output_alias.symlink_to(old_output)

            with mock.patch.multiple(
                SETUP,
                HTTP_BASE=str(root),
                ZTP=str(ztp),
                MAPPINGS=[(
                    "config/cumulus/template/99-output",
                    "99-output-eth",
                    "dir",
                )],
                LATEST_YAML_SPECS=(("cumulus", "99-output"),),
                MANIFEST_FILE=str(ztp / ".setup_manifest"),
                _DRY_RUN=False,
                _LINK_ERRORS=0,
                _LINK_TRANSACTION=None,
            ):
                transaction = SETUP._SetupLinkTransaction(
                    SETUP._setup_transaction_paths(str(new_project))
                )
                SETUP._LINK_TRANSACTION = transaction
                output_alias.unlink()
                output_alias.symlink_to(new_output)
                SETUP._process_latest_yaml(str(new_project))
                transaction.commit()
                SETUP._LINK_TRANSACTION = None

            self.assertTrue(materialized.is_symlink())
            self.assertEqual(release.name, os.readlink(materialized))
            self.assertEqual(release.resolve(), materialized.resolve())

    def test_setup_materialized_latest_rollback_restores_directory_and_old_project_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ztp = root / "ztp"
            output = ztp / "config/cumulus/template/99-output"
            release = output / "20260910_103416_combine"
            materialized = output / "latest"
            for directory_path in (release, materialized):
                directory_path.mkdir(parents=True)
                (directory_path / ".published-complete").write_text(
                    "complete\n", encoding="utf-8"
                )
                (directory_path / "leaf.yaml").write_bytes(b"hostname: leaf\n")
            public = ztp / "config/cumulus/latest_yaml"
            public.parent.mkdir(parents=True, exist_ok=True)
            old_target = "../../../../DAY0-Prepare/old/99-output-eth/latest"
            public.symlink_to(old_target)

            with mock.patch.multiple(
                SETUP,
                HTTP_BASE=str(root),
                ZTP=str(ztp),
                LATEST_YAML_SPECS=(("cumulus", "99-output"),),
                MANIFEST_FILE=str(ztp / ".setup_manifest"),
                _DRY_RUN=False,
                _LINK_ERRORS=0,
                _LINK_TRANSACTION=None,
            ):
                transaction = SETUP._SetupLinkTransaction((str(materialized), str(public)))
                SETUP._LINK_TRANSACTION = transaction
                public.unlink()
                SETUP._process_latest_yaml("unused")
                self.assertTrue(materialized.is_symlink())
                with redirect_stdout(io.StringIO()):
                    transaction.rollback()
                SETUP._LINK_TRANSACTION = None

            self.assertTrue(materialized.is_dir())
            self.assertFalse(materialized.is_symlink())
            self.assertEqual(b"hostname: leaf\n", (materialized / "leaf.yaml").read_bytes())
            self.assertTrue(public.is_symlink())
            self.assertEqual(old_target, os.readlink(public))
            self.assertFalse(any(output.glob(".latest.materialized-*")))

    def test_load_project_switch_authority_is_preserved_during_latest_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_project = root / "DAY0-Prepare/old"
            project = root / "DAY0-Prepare/new"
            old_project.mkdir(parents=True)
            project.mkdir(parents=True)
            p2p = project / "Fabric-P2P.xlsx"
            with zipfile.ZipFile(p2p, "w") as archive:
                archive.writestr("xl/workbook.xml", "<workbook/>")
            (project / "p2p.xlsx").symlink_to(p2p.name)

            ztp = root / "ztp"
            output = ztp / "config/cumulus/template/99-output"
            release = output / "20260910_103416_combine"
            release.mkdir(parents=True)
            (output / "latest").mkdir()
            for directory_path in (release, output / "latest"):
                (directory_path / ".published-complete").write_text(
                    "complete\n", encoding="utf-8"
                )
                (directory_path / "leaf.yaml").write_bytes(b"hostname: leaf\n")
            materialized = output / "latest"
            public = ztp / "config/cumulus/latest_yaml"
            public.parent.mkdir(parents=True, exist_ok=True)
            public.symlink_to(old_project / "99-output-eth/latest")
            calls = []

            def run_setup(command, **_kwargs):
                calls.append(list(command))
                with mock.patch.multiple(
                    SETUP,
                    HTTP_BASE=str(root),
                    HERE=str(root / "DAY0-Prepare"),
                    ZTP=str(ztp),
                    LATEST_YAML_SPECS=(("cumulus", "99-output"),),
                    MANIFEST_FILE=str(ztp / ".setup_manifest"),
                    _DRY_RUN=False,
                    _LINK_ERRORS=0,
                    _LINK_TRANSACTION=None,
                ):
                    transaction = SETUP._SetupLinkTransaction((str(materialized), str(public)))
                    SETUP._LINK_TRANSACTION = transaction
                    with mock.patch.object(
                        SETUP, "_managed_ztp_link_candidates", return_value=[str(public)]
                    ), mock.patch.object(
                        SETUP, "_monitor_link_paths", return_value=[]
                    ), mock.patch.object(
                        SETUP, "_bringup_link_pairs", return_value=[]
                    ), mock.patch.object(
                        SETUP, "_analyzer_input_pairs", return_value=[]
                    ), mock.patch.object(
                        SETUP, "_analyzer_output_pairs", return_value=[]
                    ), mock.patch.object(
                        SETUP, "_monitor_inventory_link_pairs", return_value=[]
                    ), mock.patch.object(
                        SETUP, "_legacy_project_monitor_csv_links", return_value=[]
                    ), mock.patch.object(
                        SETUP, "_authorize_project_switch", return_value=True
                    ):
                        self.assertTrue(SETUP._unsetup_previous(str(project)))
                    SETUP._process_latest_yaml(str(project))
                    transaction.commit()
                    SETUP._LINK_TRANSACTION = None
                (ztp / ".setup_manifest").write_text(
                    f"# proj: {project}\n", encoding="utf-8"
                )

            manifest = ztp / ".setup_manifest"
            def active_project():
                return project if manifest.is_file() else old_project

            with mock.patch.multiple(
                LOAD,
                HERE=root / "DAY0-Prepare",
                SETUP_SCRIPT=root / "DAY0-Prepare/01-a-setup.py",
            ), mock.patch.object(LOAD, "active_project", side_effect=active_project), \
                    mock.patch.object(LOAD, "run", side_effect=run_setup):
                with redirect_stdout(io.StringIO()):
                    LOAD.activate_project(project, p2p, strict=False, host_role="workstation")

            self.assertEqual(1, len(calls))
            self.assertIn("--confirm-project-switch", calls[0])
            self.assertTrue(materialized.is_symlink())
            self.assertEqual(release.name, os.readlink(materialized))
            self.assertEqual(release.resolve(), materialized.resolve())
            self.assertEqual("template/99-output/latest", os.readlink(public))

    def setUp(self) -> None:
        self.temporary = _release_fixture_temporary()
        self.root = Path(self.temporary.name)
        self.project = self.root / "DAY0-Prepare/demo"
        self.project.mkdir(parents=True)
        self.ztp = self.root / "ztp"
        dhcp_dir = self.ztp / "config/isc-dhcp-server"
        dhcp_dir.mkdir(parents=True)
        cumulus_release = self.project / "99-output-eth/20260830_120000_combine"
        cumulus_release.mkdir(parents=True)
        (self.project / "99-output-eth/latest").symlink_to(cumulus_release.name)
        (self.ztp / "config/cumulus").mkdir(parents=True)
        (self.ztp / "config/cumulus/latest_yaml").symlink_to(
            self.project / "99-output-eth/latest"
        )

        self.global_file = self.project / "01-global.yaml"
        self.subnet_file = self.project / "02-dhcp-subnet_config.csv"
        self.p2p_file = self.project / "p2p.xlsx"
        self.p2p_source = self.project / "demo P2P_v1.0.xlsx"
        for path, content in (
            (self.global_file, (
                "schema_version: 1\n"
                "common:\n"
                "  mgmt:\n"
                "    dhcp-server:\n"
                "      status: enabled\n"
                "      package: isc-dhcp-server\n"
                "    http:\n"
                "      status: enabled\n"
                "      address: 192.0.2.2\n"
                "      package: apache2\n"
                f"      http_root: {LOAD.HTTP_ROOT}\n"
                "    ztp:\n"
                "      status: enabled\n"
                "      ztp_url_prefix: /ztp\n"
                "  switch:\n"
                "    system:\n"
                "      dns: {}\n"
                "      ntp: {}\n"
                "      date-time: {}\n"
                "switches:\n"
                "- eth:\n"
                "    system:\n"
                "      aaa:\n"
                "        user:\n"
                "          cumulus:\n"
                "            hashed-password: '$6$fixture$safe-value'\n"
                "- ib:\n"
                "    system:\n"
                "      aaa:\n"
                "        user:\n"
                "          admin:\n"
                "            password: '$y$fixture$ib-safe-value'\n"
                "- nvl:\n"
                "    system:\n"
                "      aaa:\n"
                "        user:\n"
                "          admin:\n"
                "            password: '$y$fixture$nvl-safe-value'\n"
            )),
            (self.subnet_file, "shared_network,subnet\nnet,192.0.2.0\n"),
        ):
            path.write_text(content, encoding="utf-8")
        with zipfile.ZipFile(self.p2p_source, "w") as archive:
            archive.writestr("xl/workbook.xml", "<workbook/>")
        self.p2p_file.symlink_to(self.p2p_source.name)
        self.devices_file = self.project / "02-devices_config.csv"
        with self.devices_file.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow([
                "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
                "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac",
            ])
            writer.writerow([
                "leaf01", "eth", "leaf", "192.0.2.10", "24", "192.0.2.1",
                "02:00:00:00:00:01", "", "", "", "",
            ])

        outputs = {}
        for name in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        ):
            path = dhcp_dir / name
            path.write_text(f"{name}\n", encoding="utf-8")
            outputs[name] = {"sha256": sha256(path)}
        (dhcp_dir / "dhcp-release-manifest.json").write_text(json.dumps({
            "schema_version": 1,
            "release_id": "dhcp-release",
            "outputs": outputs,
            "devices": [{
                "hostname": "leaf01", "type": "eth", "interface": "eth0",
                "mac": "02:00:00:00:00:01", "identity_state": "identified",
            }],
        }), encoding="utf-8")
        (cumulus_release / "leaf01.yaml").write_text("set: {}\n", encoding="utf-8")
        (cumulus_release / "020000000001.yaml").symlink_to("leaf01.yaml")
        (cumulus_release / "default.yaml").write_text("- set: {}\n", encoding="utf-8")
        (cumulus_release / ".published-complete").write_text(
            "complete\n", encoding="utf-8"
        )
        (cumulus_release / "release-manifest.json").write_text(json.dumps({
            "schema_version": 1,
            "release_id": "cumulus-release",
            "effective_default": "default.yaml",
            "effective_default_sha256": sha256(cumulus_release / "default.yaml"),
            "devices": [{
                "hostname": "leaf01", "type": "eth",
                "macs": ["02:00:00:00:00:01"], "identity_state": "managed",
                "config": "leaf01.yaml",
                "config_sha256": sha256(cumulus_release / "leaf01.yaml"),
            }],
        }), encoding="utf-8")
        self.old_ztp_dir = LOAD.ZTP_DIR
        LOAD.ZTP_DIR = self.ztp
        settings = LOAD.GlobalSettings(
            dhcp_enabled=True, dhcp_package="isc-dhcp-server",
            http_enabled=True, http_package="apache2", http_root=self.root,
            http_address="192.0.2.2",
            ztp_enabled=True, ztp_prefix="/ztp", ztp_ips={}, versions={},
        )
        self.inputs = LOAD.ProjectInputs(
            global_file=self.global_file, devices_file=self.devices_file,
            subnet_file=self.subnet_file, p2p_file=self.p2p_source,
            device_types=frozenset({"eth"}), pubkeys=(), settings=settings,
        )

    def tearDown(self) -> None:
        LOAD.ZTP_DIR = self.old_ztp_dir
        self.temporary.cleanup()

    def test_placeholder_password_detector_uses_real_template_shape_and_order(self):
        template = ROOT / "DAY0-Prepare/template/01-global.yaml"
        document = yaml.safe_load(template.read_text(encoding="utf-8"))

        self.assertEqual(
            ("eth", "ib", "nvl"),
            LOAD.find_placeholder_password_sections(document),
        )
        document["switches"] = list(reversed(document["switches"]))
        self.assertEqual(
            ("eth", "ib", "nvl"),
            LOAD.find_placeholder_password_sections(document),
        )

    def test_placeholder_password_detector_is_exact_and_fail_closed_for_schema_drift(self):
        template = ROOT / "DAY0-Prepare/template/01-global.yaml"
        document = yaml.safe_load(template.read_text(encoding="utf-8"))
        switches = {
            next(iter(item)): next(iter(item.values()))
            for item in document["switches"]
        }
        switches["eth"]["system"]["aaa"]["user"]["cumulus"][
            "hashed-password"
        ] = " ** "
        switches["ib"]["system"]["aaa"]["user"]["admin"]["password"] = 7
        switches["nvl"]["system"]["aaa"]["user"]["admin"]["password"] = (
            "$y$j9T$valid-looking-value"
        )
        self.assertEqual((), LOAD.find_placeholder_password_sections(document))

        document["switches"].append({"future": {"system": {}}})
        with self.assertRaisesRegex(LOAD.LoadError, "credential.*future|future.*credential"):
            LOAD.find_placeholder_password_sections(document)

    def test_placeholder_password_detector_accepts_only_one_outer_quote_pair(self):
        template = ROOT / "DAY0-Prepare/template/01-global.yaml"
        for value in ("*", " '*' ", ' "*" '):
            with self.subTest(value=value):
                document = yaml.safe_load(template.read_text(encoding="utf-8"))
                switches = {
                    next(iter(item)): next(iter(item.values()))
                    for item in document["switches"]
                }
                for family, config in switches.items():
                    path = LOAD.SWITCH_CREDENTIAL_PATHS[family]
                    target = config
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = value
                self.assertEqual(
                    ("eth", "ib", "nvl"),
                    LOAD.find_placeholder_password_sections(document),
                )

        for value in ("**", "'*'*", "''*''", "' * '", "prefix*suffix", "", None):
            with self.subTest(near_miss=value):
                document = yaml.safe_load(template.read_text(encoding="utf-8"))
                switches = {
                    next(iter(item)): next(iter(item.values()))
                    for item in document["switches"]
                }
                for family, config in switches.items():
                    path = LOAD.SWITCH_CREDENTIAL_PATHS[family]
                    target = config
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = value
                self.assertEqual(
                    (), LOAD.find_placeholder_password_sections(document),
                )

    def test_placeholder_password_detector_honors_selected_switch_scope(self):
        template = ROOT / "DAY0-Prepare/template/01-global.yaml"
        document = yaml.safe_load(template.read_text(encoding="utf-8"))
        switches = {
            next(iter(item)): next(iter(item.values()))
            for item in document["switches"]
        }

        self.assertEqual(
            ("ib",),
            LOAD.find_placeholder_password_sections(document, switch_scope="ib"),
        )
        del switches["eth"]["system"]["aaa"]
        switches["nvl"]["system"]["aaa"] = "unused-invalid-shape"
        self.assertEqual(
            ("ib",),
            LOAD.find_placeholder_password_sections(document, switch_scope="ib"),
        )
        with self.assertRaisesRegex(LOAD.LoadError, "switch scope"):
            LOAD.find_placeholder_password_sections(document, switch_scope="future")

    def test_service_default_renderer_is_family_specific_and_preserves_neutral_silence(self):
        with tempfile.TemporaryDirectory() as directory:
            service = Path(directory)
            (service / "template").mkdir()
            neutral = ROOT / "ztp/config/nvos/default.yaml"
            shutil.copy2(neutral, service / "default.yaml")
            source_before = (service / "default.yaml").read_bytes()
            global_data = {
                "common": {"switch": {}},
                "switches": [
                    {"nvl": {"system": {
                        "date-time": {"timezone": "Asia/Tokyo"},
                        "dns": {"server": ["192.0.2.71"]},
                        "ntp": {"server": ["192.0.2.71"]},
                        "aaa": {"user": {"admin": {"password": "$y$nvl"}}},
                    }}},
                    {"ib": {"system": {
                        "aaa": {"user": {"admin": {"password": "$y$ib"}}},
                    }}},
                    {"eth": {"system": {
                        "date-time": {"timezone": "Europe/London"},
                        "aaa": {"user": {"cumulus": {"hashed-password": "$y$eth"}}},
                    }}},
                ],
            }
            global_file = service / "template/01-global.yaml"
            global_file.write_text(yaml.safe_dump(global_data, sort_keys=False), encoding="utf-8")

            ib = PUBLISHER._render_service_defaults(service, "ib")["default.yaml"]
            nvl = PUBLISHER._render_service_defaults(service, "nvl")["default.yaml"]
            ib_system = yaml.safe_load(ib)[0]["set"]["system"]
            nvl_system = yaml.safe_load(nvl)[0]["set"]["system"]
            self.assertEqual("$y$ib", ib_system["aaa"]["user"]["admin"]["password"])
            self.assertEqual("Etc/UTC", ib_system["date-time"]["timezone"])
            self.assertNotIn("hashed-password", ib)
            self.assertEqual("$y$nvl", nvl_system["aaa"]["user"]["admin"]["password"])
            self.assertEqual("Asia/Tokyo", nvl_system["date-time"]["timezone"])
            self.assertEqual({"192.0.2.71": {}}, nvl_system["dns"]["server"])
            self.assertEqual({"192.0.2.71": {}}, nvl_system["ntp"]["server"])
            self.assertNotIn("$y$ib", nvl)
            self.assertNotIn("null", ib.casefold())
            self.assertEqual(source_before, (service / "default.yaml").read_bytes())

            self.assertEqual(
                "$y$ib",
                PUBLISHER._global_system(
                    {
                        **global_data,
                        "switches": list(reversed(global_data["switches"])),
                    },
                    "ib",
                )["aaa"]["user"]["admin"]["password"],
            )
            self.assertEqual(
                "$y$eth",
                PUBLISHER._global_system(global_data, "eth")
                ["aaa"]["user"]["cumulus"]["hashed-password"],
            )
            missing = {
                **global_data,
                "switches": (
                    global_data["switches"][:1] + global_data["switches"][2:]
                ),
            }
            with self.assertRaisesRegex(ValueError, "ib"):
                PUBLISHER._global_system(missing, "ib")
            malformed = {**global_data, "switches": [{"ib": "not-a-mapping"}]}
            with self.assertRaisesRegex(ValueError, "ib"):
                PUBLISHER._global_system(malformed, "ib")

            duplicate = dict(global_data)
            duplicate["switches"] = [*global_data["switches"], {"ib": {"system": {}}}]
            with self.assertRaisesRegex(ValueError, "ib"):
                PUBLISHER._global_system(duplicate, "ib")

            cumulus_neutral = yaml.safe_load(
                (ROOT / "ztp/config/cumulus/default.yaml").read_text(encoding="utf-8")
            )
            cumulus_global = {
                "common": {"switch": {"system": {
                    "dns": {"server": ["8.8.8.8", "192.0.2.53"]},
                }}},
                "switches": [
                    {"eth": {"system": {"dns": {"vrf": "mgmt"}}}},
                ],
            }
            normalized = PUBLISHER._default_document_with_global(
                cumulus_neutral,
                PUBLISHER._global_system(cumulus_global, "eth"),
            )[0]["set"]["system"]
            self.assertEqual(
                {"8.8.8.8": {"vrf": "mgmt"}, "192.0.2.53": {"vrf": "mgmt"}},
                normalized["dns"]["server"],
            )
            self.assertEqual(1, tuple(normalized["dns"]["server"]).count("8.8.8.8"))
            self.assertNotIn("vrf", normalized["dns"])

    def test_single_nvos_publish_binds_family_default_and_collision_keeps_latest(self):
        service = self.root / "single-nvos"
        output_root = service / "template/99-output-ib_nvl"
        output_root.mkdir(parents=True)
        shutil.copy2(ROOT / "ztp/config/nvos/default.yaml", service / "default.yaml")
        (service / "template/01-global.yaml").write_text(
            "switches:\n"
            "- ib:\n    system:\n      aaa:\n        user:\n          admin:\n            password: '$y$ib'\n"
            "- nvl:\n    system:\n      aaa:\n        user:\n          admin:\n            password: '$y$nvl'\n"
            "- eth:\n    system: {}\n",
            encoding="utf-8",
        )
        neutral_before = (service / "default.yaml").read_bytes()

        def publish(family, timestamp, hostname, mac):
            directory = output_root / f"{timestamp}-{family}"
            directory.mkdir()
            (directory / f"{hostname}.yaml").write_text(
                "- set:\n"
                "    interface:\n"
                "      eth0:\n"
                "        ipv4:\n"
                "          address:\n"
                "            192.0.2.10/24: {}\n"
                "          gateway:\n"
                "            192.0.2.1: {}\n",
                encoding="utf-8",
            )
            devices = {hostname.casefold(): {
                "hostname": hostname, "dev_type": family,
                "eth0_ip_cidr": "192.0.2.10/24", "eth0_gw": "192.0.2.1",
                "eth0_mac": mac, "eth1_mac": "", "eth1_ip_cidr": "",
                "eth1_gw": "", "identity_pending": False,
            }}
            context = PUBLISHER._nvos_dir_context(str(directory))
            self.assertIsNotNone(context)
            return PUBLISHER._publish_single_nvos(context, devices), directory

        for family, timestamp, hostname, mac, expected in (
            ("ib", "20260902_120000", "IB-one", "02:00:00:00:01:01", "default_ib.yaml"),
            ("nvl", "20260902_120001", "NVL-one", "02:00:00:00:01:02", "default_nvl.yaml"),
        ):
            ok, directory = publish(family, timestamp, hostname, mac)
            self.assertTrue(ok)
            manifest = json.loads((directory / "release-manifest.json").read_text())
            self.assertEqual({family}, set(manifest["effective_defaults"]))
            self.assertEqual(expected, manifest["effective_defaults"][family]["name"])
            self.assertTrue((directory / expected).is_file())

        previous_latest = (service / "latest_yaml").resolve(strict=True)
        ok, _directory = publish(
            "ib", "20260902_120002", "default_ib", "02:00:00:00:01:03",
        )
        self.assertFalse(ok)
        self.assertEqual(previous_latest, (service / "latest_yaml").resolve(strict=True))
        self.assertEqual(neutral_before, (service / "default.yaml").read_bytes())

    def test_placeholder_password_authority_matches_schema_and_password_updater(self):
        password_spec = importlib.util.spec_from_file_location(
            "password_contract_parity", ROOT / "tools/password-update.py",
        )
        password_module = importlib.util.module_from_spec(password_spec)
        assert password_spec.loader is not None
        sys.modules[password_spec.name] = password_module
        password_spec.loader.exec_module(password_module)

        self.assertEqual(
            set(LOAD.SWITCH_SCHEMA_FAMILIES),
            set(LOAD.SWITCH_CREDENTIAL_PATHS),
        )
        self.assertEqual(
            tuple(LOAD.SWITCH_CREDENTIAL_FAMILY_ORDER),
            tuple(password_module.SECTION_ORDER),
        )
        self.assertIs(
            LOAD.SWITCH_CREDENTIAL_PATHS,
            password_module.SWITCH_CREDENTIAL_PATHS,
        )

    def test_placeholder_password_repair_command_binds_declared_linux_role(self):
        project = Path("/tmp/req16-placeholder-demo")
        for role in ("workstation", "management-server"):
            with self.subTest(role=role):
                message = str(LOAD._placeholder_password_error(
                    project, ("eth",), host_role=role,
                ))
                command = next(
                    line.strip().removeprefix("- ")
                    for line in message.splitlines()
                    if line.strip().startswith("- DAY0-Prepare/11-load.py ")
                )
                self.assertEqual(
                    f"DAY0-Prepare/11-load.py {project} --update-passwords "
                    f"--host-role={role}", command,
                )
                parsed = LOAD.parse_args(shlex.split(command)[1:])
                self.assertEqual(role, LOAD.resolve_host_role(parsed.host_role, "Linux"))
                without_role = [
                    token for token in shlex.split(command)[1:]
                    if not token.startswith("--host-role=")
                ]
                with self.assertRaisesRegex(LOAD.LoadError, "explicit --host-role"):
                    LOAD.resolve_host_role(
                        LOAD.parse_args(without_role).host_role, "Linux",
                    )
                self.assertIn(
                    f"python3 tools/password-update.py {project} --platform cumulus",
                    message,
                )

    def test_validate_inputs_placeholder_guidance_preserves_explicit_server_role(self):
        project = self.project.resolve(strict=True)
        (project / "01-global.yaml").write_bytes(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_bytes()
        )
        self._http_main_public_source_fixture()
        args = LOAD.parse_args([str(project), "--host-role=management-server"])
        self.assertFalse(args.dry_run)
        with self._http_linux_public_ancestor_model(), \
                mock.patch.object(LOAD, "HTTP_ROOT", self.root.resolve(strict=True)), \
                mock.patch.object(LOAD, "ZTP_DIR", self.ztp.resolve(strict=True)), \
                mock.patch.object(LOAD, "runtime_os", return_value="Linux"):
            with self.assertRaises(LOAD.LoadError) as caught:
                LOAD.validate_inputs(
                    project, args, allow_management_key_generation=False,
                )
        message = str(caught.exception)
        expected = (
            f"DAY0-Prepare/11-load.py {project} --update-passwords "
            "--host-role=management-server"
        )
        self.assertIn(expected, message)
        parsed = LOAD.parse_args(shlex.split(expected)[1:])
        self.assertEqual(
            "management-server",
            LOAD.resolve_host_role(parsed.host_role, "Linux"),
        )

    def test_validate_inputs_refuses_placeholders_before_downstream_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            global_file = project / "01-global.yaml"
            global_file.write_bytes(
                (ROOT / "DAY0-Prepare/template/01-global.yaml").read_bytes()
            )
            args = SimpleNamespace(host_role="workstation")
            downstream = (
                "apply_subnet_service_ips", "load_device_types", "select_p2p",
                "validate_subnet_file", "project_air_topology_policy",
                "project_mini_air_devices", "prepare_images",
                "validate_shared_artifact_receipts", "prepare_pubkeys",
            )
            patches = [mock.patch.object(LOAD, name) for name in downstream]
            with ExitStack() as stack:
                mocks = [stack.enter_context(patch) for patch in patches]
                with self.assertRaises(LOAD.LoadError) as caught:
                    LOAD.validate_inputs(
                        project, args, allow_management_key_generation=False,
                    )

            message = str(caught.exception)
            self.assertIn("eth, ib, nvl", message)
            self.assertIn(
                f"DAY0-Prepare/11-load.py {project} --update-passwords", message,
            )
            self.assertIn(
                f"python3 tools/password-update.py {project} --platform all",
                message,
            )
            for section, platform in (("eth", "cumulus"), ("ib", "ib"), ("nvl", "nvl")):
                self.assertIn(section, message)
                self.assertIn(f"--platform {platform}", message)
            self.assertNotIn("'*'", message)
            self.assertNotIn("$6$", message)
            self.assertNotIn("$y$", message)
            for downstream_mock in mocks:
                downstream_mock.assert_not_called()

    def test_c2_rejection_keeps_prior_accepted_dhcp_release_activatable(self):
        """A successful c1 must not strand an accepted parent after c2 rejects."""
        activate = load_script(
            "r22_prior_dhcp_activation_after_c2_reject",
            ROOT / "infra/docker/activate.py",
        )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            project = root / "DAY0-Prepare" / "site-a"
            project.mkdir(parents=True)
            global_yaml = project / "01-global.yaml"
            global_yaml.write_text(
                "schema_version: 1\ncommon:\n  mgmt:\n"
                "    dhcp-server:\n      status: enabled\n"
                "    http:\n      status: enabled\n"
                "      address: 192.0.2.2\n"
                "    ztp:\n      status: enabled\n"
                "      ztp_url_prefix: /ztp\n",
                encoding="utf-8",
            )
            devices = project / "02-devices_config.csv"
            devices.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
                "eth1_ip,netmask,eth1_gw,eth1_mac\n"
                "border01,eth,leaf,192.0.2.12,24,192.0.2.1,"
                "02:00:00:00:00:12,,,,\n",
                encoding="utf-8",
            )
            subnet = project / "02-dhcp-subnet_config.csv"
            source_a = (
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "oob,192.0.2.0,255.255.255.0,192.0.2.200,192.0.2.220,"
                "192.0.2.1,192.0.2.2,oob,no\n"
            )
            source_b = source_a.replace("192.0.2.200", "192.0.2.201")
            self.assertEqual(len(source_a), len(source_b))
            subnet.write_text(source_a, encoding="utf-8")
            workbook = project / "site-a P2P.xlsx"
            workbook.write_bytes(b"fixture workbook identity\n")
            (project / "p2p.xlsx").symlink_to(workbook.name)
            dhcp_outputs = project / "99-output-dhcp"
            dhcp_outputs.mkdir()
            public = root / "ztp/config/isc-dhcp-server"
            public.mkdir(parents=True)
            output_names = (
                "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
            )
            for output_name in output_names:
                target = dhcp_outputs / output_name
                (public / output_name).symlink_to(
                    os.path.relpath(target, public),
                )

            def generate_dhcp(candidate_dir=None):
                output_dir = Path(candidate_dir) if candidate_dir else dhcp_outputs
                with mock.patch.object(sys, "argv", ["c1-generate_dhcp.py", "-y"]), \
                     mock.patch.multiple(
                         DHCP, HTTP_ROOT=str(root), SCRIPT_DIR=str(public),
                         OUTPUT_ETH=str(output_dir / "dhcpd_eth.hosts"),
                         OUTPUT_IB=str(output_dir / "dhcpd_ib.hosts"),
                         OUTPUT_NVL=str(output_dir / "dhcpd_nvl.hosts"),
                         OUTPUT_CONF=str(output_dir / "dhcpd.conf"),
                         OUTPUT_MANIFEST=str(output_dir / "dhcp-release-manifest.json"),
                         SUBNET_CSV=str(subnet), GLOBAL_YAML=str(global_yaml),
                         P2P_AIR_JSON=str(project / "p2p-air.json"),
                         DEVICES_CSV=str(devices), _AUTO_YES=False,
                     ):
                    DHCP.main()

            generate_dhcp()
            accepted_outputs = {
                path.name: path.read_bytes() for path in dhcp_outputs.iterdir()
            }
            manifest = json.loads(
                (dhcp_outputs / "dhcp-release-manifest.json").read_text(
                    encoding="utf-8",
                )
            )
            input_paths = {
                "global": global_yaml, "devices": devices,
                "subnet": subnet, "p2p": workbook,
            }
            basis = {
                "project": "site-a", "deployment_scope": "air",
                "switch_scope": "eth",
                "inputs": {
                    key: sha256(path) for key, path in input_paths.items()
                },
                "input_sources": {"p2p": {
                    "path": workbook.name, "sha256": sha256(workbook),
                }},
                "components": {"dhcp": {
                    "release_id": manifest["release_id"],
                    "manifest_sha256": sha256(
                        dhcp_outputs / "dhcp-release-manifest.json"
                    ),
                }},
                "inventory": [{"hostname": "border01", "type": "eth"}],
                "dhcp_status": "enabled",
            }
            release_id = hashlib.sha256(json.dumps(
                basis, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")).hexdigest()[:20]
            current = project / "99-output-ztp/current-release.json"
            current.parent.mkdir()
            current.write_text(json.dumps({
                "schema_version": 2, "validation": "passed",
                "release_id": release_id, **basis,
            }) + "\n", encoding="utf-8")
            settings = activate.Settings(
                project_name="site-a", scope="air", switch_scope="eth",
                http_root=root,
            )
            activate.validate_parent_release(settings, current)
            accepted_parent = current.read_bytes()

            subnet.write_text(source_b, encoding="utf-8")
            reached = []
            pre_c2_observation = {}

            def fail_at_c2(command, **_kwargs):
                script = command[1]
                reached.append(script)
                if script == "c1-generate_dhcp.py":
                    self.assertIn("--candidate-output-dir", command)
                    candidate_dir = command[
                        command.index("--candidate-output-dir") + 1
                    ]
                    generate_dhcp(candidate_dir)
                    pre_c2_observation["changed"] = tuple(sorted(
                        name for name, accepted in accepted_outputs.items()
                        if (dhcp_outputs / name).read_bytes() != accepted
                    ))
                    # Isolate the G2 publication boundary: the accepted
                    # input bytes are A again, while c1's B outputs remain.
                    subnet.write_text(source_a, encoding="utf-8")
                    try:
                        activate.validate_parent_release(settings, current)
                    except activate.ActivationError as exc:
                        pre_c2_observation["activation_error"] = exc
                    finally:
                        subnet.write_text(source_b, encoding="utf-8")
                elif script == "90-c2-generate_configs.py":
                    raise LOAD.LoadError("controlled c2 rejection after c1 success")

            with mock.patch.object(LOAD, "ZTP_DIR", root / "ztp"), \
                 mock.patch.object(LOAD, "run", side_effect=fail_at_c2), \
                 mock.patch.object(
                     LOAD, "_device_types_after_dhcp",
                     return_value=frozenset({"eth"}),
                 ):
                with self.assertRaisesRegex(
                    LOAD.LoadError, "controlled c2 rejection",
                ):
                    LOAD.generate_configs(
                        frozenset({"eth"}), install_dhcp=False,
                        dhcp_enabled=True, switch_scope="eth",
                        defer_dhcp_publication=True,
                    )
            subnet.write_text(source_a, encoding="utf-8")
            self.assertEqual(
                ["b-xlsx_to_dot.py", "c1-generate_dhcp.py",
                 "90-c2-generate_configs.py"],
                reached,
            )
            self.assertEqual(accepted_parent, current.read_bytes())
            self.assertEqual([], list(dhcp_outputs.glob(".load-dhcp-*")))
            with self.subTest(gate="old parent remains accepted before c2"):
                self.assertNotIn(
                    "activation_error", pre_c2_observation,
                    str(pre_c2_observation.get("activation_error")),
                )
            with self.subTest(gate="five fixed DHCP candidates private until commit"):
                self.assertEqual((), pre_c2_observation["changed"])
            with self.subTest(gate="five fixed DHCP candidates roll back"):
                changed = tuple(sorted(
                    name for name, accepted in accepted_outputs.items()
                    if (dhcp_outputs / name).read_bytes() != accepted
                ))
                self.assertEqual(
                    (), changed,
                )
            activation_error = None
            try:
                activate.validate_parent_release(settings, current)
            except activate.ActivationError as exc:
                activation_error = exc
            with self.subTest(gate="accepted parent remains activatable"):
                self.assertIsNone(activation_error, str(activation_error))

    def test_deferred_dhcp_publication_restores_original_inodes_on_rejection(self):
        """The parent rejection restores all prior fixed-output file identities."""
        parent = self.ztp / "config/isc-dhcp-server"
        names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcp-release-manifest.json")
        before = {
            name: ((parent / name).stat().st_ino, (parent / name).read_bytes())
            for name in names
        }
        candidate = LOAD.DeferredDHCPOutput.create(self.ztp, "eth")
        try:
            for name in names:
                (candidate.stage / name).write_bytes(b"candidate " + name.encode())
            candidate.publish()
            self.assertEqual(
                b"candidate dhcpd.conf", (parent / "dhcpd.conf").read_bytes(),
            )
            candidate.rollback()
            for name in names:
                self.assertEqual(
                    before[name],
                    ((parent / name).stat().st_ino, (parent / name).read_bytes()),
                )
        finally:
            candidate.discard()
        self.assertFalse(candidate.stage.exists())

    def test_deferred_dhcp_partial_publish_failure_restores_prior_set(self):
        parent = self.ztp / "config/isc-dhcp-server"
        names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcp-release-manifest.json")
        before = {
            name: ((parent / name).stat().st_ino, (parent / name).read_bytes())
            for name in names
        }
        candidate = LOAD.DeferredDHCPOutput.create(self.ztp, "eth")
        for name in names:
            (candidate.stage / name).write_bytes(b"candidate " + name.encode())
        replace = os.replace
        failed = False

        def fail_second_install(source, destination, **kwargs):
            nonlocal failed
            if (not failed and source == destination == "dhcpd_eth.hosts"
                    and kwargs.get("src_dir_fd") is not None):
                failed = True
                raise OSError("controlled second DHCP publish failure")
            return replace(source, destination, **kwargs)

        try:
            with mock.patch.object(LOAD.os, "replace", side_effect=fail_second_install):
                with self.assertRaisesRegex(OSError, "controlled second DHCP publish failure"):
                    candidate.publish()
            self.assertTrue(failed)
            for name in names:
                self.assertEqual(
                    before[name],
                    ((parent / name).stat().st_ino, (parent / name).read_bytes()),
                )
        finally:
            candidate.discard()
        self.assertFalse(candidate.stage.exists())

    def test_deferred_dhcp_rejects_backup_name_collision_without_overwrite(self):
        parent = self.ztp / "config/isc-dhcp-server"
        names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcp-release-manifest.json")
        before = {
            name: ((parent / name).stat().st_ino, (parent / name).read_bytes())
            for name in names
        }
        candidate = LOAD.DeferredDHCPOutput.create(self.ztp, "eth")
        collision = candidate.stage / "backup-dhcpd_eth.hosts"
        collision.write_bytes(b"independent stage sentinel")
        for name in names:
            (candidate.stage / name).write_bytes(b"candidate " + name.encode())
        try:
            with self.assertRaisesRegex(LOAD.LoadError, "backup name collision"):
                candidate.publish()
            self.assertEqual(b"independent stage sentinel", collision.read_bytes())
            for name in names:
                self.assertEqual(
                    before[name],
                    ((parent / name).stat().st_ino, (parent / name).read_bytes()),
                )
        finally:
            collision.unlink(missing_ok=True)
            candidate.rollback()
            candidate.discard()

    def test_deferred_dhcp_copy_rejects_source_rebind_before_open(self):
        source = self.ztp / "config/isc-dhcp-server/dhcpd.conf"
        previous = source.lstat()
        alternate = source.with_name("dhcpd.conf.alternate")
        alternate.write_bytes(b"X" * previous.st_size)
        os.utime(alternate, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        destination = self.root / "copied.conf"
        open_file = os.open
        rebound = False

        def swap_before_open(path, *args, **kwargs):
            nonlocal rebound
            if not rebound and os.fspath(path) == os.fspath(source):
                rebound = True
                os.replace(alternate, source)
            return open_file(path, *args, **kwargs)

        with mock.patch.object(LOAD.os, "open", side_effect=swap_before_open):
            with self.assertRaisesRegex(LOAD.LoadError, "changed before copy"):
                LOAD.DeferredDHCPOutput._copy_prior_output(
                    source, destination, previous,
                )
        self.assertTrue(rebound)
        self.assertFalse(destination.exists())

    def test_deferred_dhcp_accept_cleans_backups_only_after_commit(self):
        parent = self.ztp / "config/isc-dhcp-server"
        candidate = LOAD.DeferredDHCPOutput.create(self.ztp, "eth")
        names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcp-release-manifest.json")
        for name in names:
            (candidate.stage / name).write_bytes(b"accepted " + name.encode())
        candidate.publish()
        with self.assertRaisesRegex(LOAD.LoadError, "cannot discard"):
            candidate.discard()
        candidate.accept_committed()
        self.assertFalse(candidate.stage.exists())
        for name in names:
            self.assertEqual(b"accepted " + name.encode(),
                             (parent / name).read_bytes())

    def test_deferred_dhcp_parent_rebind_never_publishes_foreign_outputs(self):
        parent = self.ztp / "config/isc-dhcp-server"
        candidate = LOAD.DeferredDHCPOutput.create(self.ztp, "eth")
        for name in ("dhcpd.conf", "dhcpd_eth.hosts", "dhcp-release-manifest.json"):
            (candidate.stage / name).write_bytes(b"candidate " + name.encode())
        held_parent = parent.with_name("held-isc-dhcp-server")
        parent.rename(held_parent)
        parent.mkdir()
        sentinel = parent / "dhcpd.conf"
        sentinel.write_bytes(b"foreign sentinel")
        foreign_identity = (sentinel.stat().st_ino, sentinel.read_bytes())
        with self.assertRaisesRegex(LOAD.LoadError, "directory changed"):
            candidate.publish()
        self.assertEqual(foreign_identity,
                         (sentinel.stat().st_ino, sentinel.read_bytes()))
        candidate.discard()
        self.assertEqual([], list(held_parent.glob(".load-dhcp-*")))
        self.assertEqual(b"dhcpd.conf\n", (held_parent / "dhcpd.conf").read_bytes())

    def test_c1_private_candidate_flag_keeps_five_public_outputs_unchanged(self):
        """The real C1 CLI writes only the load-owned sibling candidate."""
        _inputs, outputs, _child = prepare_r22_empty_unselected_dhcp_fixture(self)
        before = {
            name: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
            for name in LOAD._DHCP_OUTPUT_NAMES
            for path in (outputs / name,)
        }
        candidate = outputs / ".load-dhcp-direct-proof"
        candidate.mkdir(mode=0o700)
        for name in LOAD._DHCP_OUTPUT_NAMES:
            shutil.copy2(outputs / name, candidate / name)
        with mock.patch.object(sys, "argv", [
            "c1-generate_dhcp.py", "-y", "--deployment-scope", "prod",
            "--switch", "eth", "--candidate-output-dir", str(candidate),
        ]), mock.patch.multiple(
            DHCP, HTTP_ROOT=str(self.root),
            SCRIPT_DIR=str(self.ztp / "config/isc-dhcp-server"),
            OUTPUT_CONF=str(outputs / "dhcpd.conf"),
            OUTPUT_ETH=str(outputs / "dhcpd_eth.hosts"),
            OUTPUT_IB=str(outputs / "dhcpd_ib.hosts"),
            OUTPUT_NVL=str(outputs / "dhcpd_nvl.hosts"),
            OUTPUT_MANIFEST=str(outputs / "dhcp-release-manifest.json"),
            GLOBAL_YAML=str(self.global_file),
            DEVICES_CSV=str(self.devices_file),
            SUBNET_CSV=str(self.subnet_file),
            P2P_AIR_JSON=str(self.project / "p2p-air.json"), _AUTO_YES=False,
        ), mock.patch.object(DHCP, "stop_native_ztp_monitors"):
            DHCP.main()
        for name, expected in before.items():
            path = outputs / name
            self.assertEqual(
                expected, (path.stat().st_ino, path.stat().st_mtime_ns,
                           path.read_bytes()),
            )
        self.assertTrue((candidate / "dhcp-release-manifest.json").is_file())
        self.assertTrue((candidate / "dhcpd.conf").is_file())

    def test_c1_private_candidate_flag_rejects_foreign_directory_before_writes(self):
        foreign = self.root / ".load-dhcp-foreign"
        foreign.mkdir(mode=0o700)
        public = self.ztp / "config/isc-dhcp-server/dhcpd.conf"
        before = (public.stat().st_ino, public.read_bytes())
        with mock.patch.object(sys, "argv", [
            "c1-generate_dhcp.py", "-y", "--candidate-output-dir", str(foreign),
        ]), mock.patch.object(DHCP, "OUTPUT_CONF", str(public)):
            with self.assertRaises(SystemExit) as caught:
                DHCP.main()
        self.assertEqual(2, caught.exception.code)
        self.assertEqual(before, (public.stat().st_ino, public.read_bytes()))
        self.assertEqual([], list(foreign.iterdir()))

    def test_c2_description_aba_source_rejects_without_replacing_same_name_output(self):
        """A restored path digest cannot authorize a mid-command B consumer."""
        work = self.root / "c2-aba"
        work.mkdir()
        csv_path = work / "02-devices_config.csv"
        source_a = "hostname,type\nborder01,eth\n"
        source_b = "hostname,type\nborder02,eth\n"
        self.assertEqual(len(source_a), len(source_b))
        csv_path.write_text(source_a, encoding="utf-8")
        before = csv_path.stat()
        output = work / "20261002_020000"
        output.mkdir()
        prior = work / "20261002_020000_with_desc"
        prior.mkdir()
        marker = prior / "old-marker.txt"
        marker.write_bytes(b"old healthy description output\n")
        prior_identity = (
            marker.read_bytes(), marker.stat().st_ino, marker.stat().st_mtime_ns,
        )
        copytree = GENERATOR.shutil.copytree
        read_hostnames = GENERATOR._load_csv_hostnames
        consumed = None

        def change_after_copy(*args, **kwargs):
            result = copytree(*args, **kwargs)
            csv_path.write_text(source_b, encoding="utf-8")
            os.utime(csv_path, ns=(before.st_atime_ns, before.st_mtime_ns))
            return result

        def restore_after_read():
            nonlocal consumed
            consumed = read_hostnames()
            csv_path.write_text(source_a, encoding="utf-8")
            os.utime(csv_path, ns=(before.st_atime_ns, before.st_mtime_ns))
            return consumed

        caught = None
        with mock.patch.object(GENERATOR, "_CSV_FILE", os.fspath(csv_path)), mock.patch.object(
            GENERATOR, "_load_description_intent", return_value={},
        ), mock.patch.object(
            GENERATOR, "_load_dot_lines", return_value=[],
        ), mock.patch.object(
            GENERATOR, "_load_dot_devices", return_value=set(),
        ), mock.patch.object(
            GENERATOR.shutil, "copytree", side_effect=change_after_copy,
        ), mock.patch.object(
            GENERATOR, "_load_csv_hostnames", side_effect=restore_after_read,
        ):
            try:
                GENERATOR._run_patch_descriptions(
                    os.fspath(work / "unused.dot"), os.fspath(output),
                )
            except ValueError as exc:
                caught = exc

        after = csv_path.stat()
        self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns),
                         (after.st_ino, after.st_size, after.st_mtime_ns))
        self.assertEqual(source_a.encode("utf-8"), csv_path.read_bytes())
        self.assertEqual({"border02"}, consumed)
        with self.subTest(gate="mixed-generation rejection"):
            self.assertIsNotNone(caught, "c2 consumed B while source returned to A")
        with self.subTest(gate="old same-name output preservation"):
            self.assertTrue(marker.is_file())
            if marker.is_file():
                self.assertEqual(
                    prior_identity,
                    (marker.read_bytes(), marker.stat().st_ino, marker.stat().st_mtime_ns),
                )

    def test_c2_description_publish_failure_restores_prior_output(self):
        """A failed final rename must leave the last accepted description tree."""
        work = self.root / "c2-publish-rollback"
        work.mkdir()
        output = work / "generated"
        output.mkdir()
        prior = work / "generated_with_desc"
        prior.mkdir()
        marker = prior / "old-marker.txt"
        marker.write_bytes(b"previous accepted description\n")
        original_identity = (marker.stat().st_ino, marker.read_bytes())
        original_replace = os.replace
        failed = False

        def fail_once(source, destination):
            nonlocal failed
            if os.fspath(destination) == os.fspath(prior) and not failed:
                failed = True
                raise OSError("controlled description publish failure")
            return original_replace(source, destination)

        with mock.patch.object(GENERATOR, "_load_description_intent", return_value={}), \
             mock.patch.object(GENERATOR, "_load_dot_lines", return_value=[]), \
             mock.patch.object(GENERATOR, "_load_dot_devices", return_value=set()), \
             mock.patch.object(GENERATOR, "_load_csv_hostnames", return_value=set()), \
             mock.patch.object(GENERATOR.os, "replace", side_effect=fail_once):
            with self.assertRaisesRegex(OSError, "controlled description publish failure"):
                GENERATOR._run_patch_descriptions(
                    os.fspath(work / "unused.dot"), os.fspath(output),
                )
        self.assertTrue(failed)
        self.assertEqual(original_identity, (marker.stat().st_ino, marker.read_bytes()))
        self.assertEqual([], list(work.glob(".description-stage-*")))

    def _prepare_h04_schema_v1_collision_generator(self) -> tuple[Path, Path]:
        template_dir = self.ztp / "config/cumulus/template"
        template_dir.mkdir(parents=True, exist_ok=True)
        tools_dir = self.root / "tools"
        tools_dir.mkdir(exist_ok=True)
        shutil.copy2(
            ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
            template_dir / "90-c2-generate_configs.py",
        )
        shutil.copy2(ROOT / "tools/project_contract.py", tools_dir)
        shutil.copy2(ROOT / "ztp/nvue_normalizer.py", self.ztp)
        shutil.copy2(
            ROOT / "ztp/config/cumulus/d-hostname2mac.py",
            template_dir.parent / "d-hostname2mac.py",
        )
        shutil.copy2(
            ROOT / "ztp/config/cumulus/default.yaml", template_dir.parent,
        )
        shutil.copytree(
            ROOT / "ztp/config/cumulus/template/03-templates-j2",
            template_dir / "03-templates-j2",
        )
        global_document = {
            "schema_version": 1,
            "bridge": {"domain": {"br_default": {"stp": {"priority": 4096}}}},
            "mlag": {"init-delay": 180},
            "version": "5.18.1",
            "vrf": {"default": {"router": {"bfd": {"profile": {
                "bgp-underlay-bfd": {
                    "detect-multiplier": 3,
                    "min-rx-interval": 300,
                    "min-tx-interval": 300,
                },
            }}}}},
            "system": {
                "aaa": {"user": {"cumulus": {
                    "full-name": "cumulus,,,,", "hashed-password": "'*'",
                }}},
                "date-time": {"timezone": "UTC"},
                "dns": {"server": ["192.0.2.53"], "vrf": "mgmt"},
                "ntp": {"server": ["192.0.2.123"], "vrf": "mgmt"},
            },
        }
        self.global_file.write_text(
            yaml.safe_dump(global_document, sort_keys=False), encoding="utf-8",
        )
        row = ["NA"] * len(H04_SCHEMA_V1_HEADER)
        for index, value in {
            0: H04_COLLISION_HOSTNAME, 1: "eth", 2: "tan-leaf",
            3: "192.0.2.10", 4: "24", 5: "192.0.2.1",
            6: "02:00:00:00:00:10", 11: "198.51.100.10",
            12: "default", 19: "65101", 20: "swp49",
            21: "bond1s0|bond10", 22: "evpn_multihoming",
            23: "02:00:00:00:10:10", 26: "BLUE", 27: "4000",
            28: "4000", 29: "false", 30: "100200", 31: "200",
            32: "192.0.2.2", 33: "24", 34: "192.0.2.1",
            35: H04_VRR_MAC, 36: "bond1s0/bond10",
        }.items():
            row[index] = value
        with self.devices_file.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows((H04_SCHEMA_V1_HEADER, row))
        for name, target in (
            ("01-global.yaml", self.global_file),
            ("02-devices_config.csv", self.devices_file),
        ):
            (template_dir / name).symlink_to(target)
        devices = self.project / "99-output-eth/91-devices.yaml"
        devices.write_bytes(b"workflow-91-before-collision\n")
        devices.chmod(0o640)
        os.utime(devices, ns=(1_650_000_000_000_000_000,) * 2)
        (template_dir / "91-devices.yaml").symlink_to(devices)
        (template_dir / "99-output").symlink_to(self.project / "99-output-eth")
        (template_dir / "P2P").mkdir()
        write_splitter_fixture(template_dir / "P2P", {
            H04_COLLISION_HOSTNAME: {"swp1": "1to2"},
        })
        return template_dir, devices

    def _exercise_main_transaction_failure(
        self, failure: BaseException, argv: list[str] | None = None,
        *, lifecycle_events: list[str] | None = None,
        authority_failure: BaseException | None = None,
        parent_schema_version: int = 1,
        failure_at: str = "dhcp",
        observe_template_mutation: bool = False,
        active_project_value: Path | None = None,
        activation_calls: list[dict] | None = None,
        activation_action=None,
        after_parent_commit=None,
        start_services: bool = False,
        publication_routing: bool = False,
    ):
        self._http_main_public_source_fixture()
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=start_services,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
            host_role="management-server",
        )
        # Keep the deliberately minimal parent: this fixture tests load's
        # transaction cleanup, not generation-report schema validation.
        fake_parent = (
            LOAD.validate_and_publish_release(
                self.project, self.inputs, publish=False,
            ) if parent_schema_version == 2 else {
                "schema_version": 1,
                "release_id": "failure-candidate",
            }
        )
        candidate = LOAD.prepare_current_release(self.project, fake_parent)
        report_payload = mock.sentinel.generation_report_payload
        staged_report = mock.sentinel.staged_generation_report
        transaction_events: list[str] = []
        quiesce = mock.Mock()
        restore_links = mock.Mock()
        restore_prefix = mock.Mock()
        release_lock = mock.Mock()
        runtime_backend = SimpleNamespace(name="supervisor")
        runtime_plan = SimpleNamespace(
            listener_names=("eno2",), endpoint_ips=("192.0.2.10",),
        )
        caught = None
        result = None
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "HTTP_ROOT", self.root))
            stack.enter_context(self._http_linux_public_ancestor_model())
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "active_project",
                return_value=(active_project_value or self.project).resolve(),
            ))
            stack.enter_context(mock.patch.object(LOAD, "acquire_deployment_lock", return_value=91))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock", release_lock))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(LOAD, "supports_local_ztp_services", return_value=True))
            stack.enter_context(mock.patch.object(
                LOAD, "service_runtime_backend", return_value=runtime_backend,
            ))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(LOAD, "resolve_project", return_value=self.project))
            stack.enter_context(mock.patch.object(
                LOAD, "initialize_from_template",
                side_effect=(
                    (lambda *_args: (_ for _ in ()).throw(failure))
                    if failure_at == "template" else
                    (lambda *_args: lifecycle_events.append("template-mutation"))
                    if observe_template_mutation and lifecycle_events is not None
                    else None
                ),
            ))
            stack.enter_context(mock.patch.object(LOAD, "validate_inputs", return_value=(self.inputs, {})))
            stack.enter_context(mock.patch.object(LOAD, "validate_management_host", return_value=True))
            stack.enter_context(mock.patch.object(
                LOAD, "plan_local_dhcp_runtime",
                return_value=runtime_plan,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "confirm_ztp_monitor_start", return_value=False,
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services", quiesce))
            def activate_fixture(*_args, **kwargs):
                if activation_calls is not None:
                    activation_calls.append(kwargs)
                if activation_action is not None:
                    activation_action()
            stack.enter_context(mock.patch.object(
                LOAD, "activate_project", side_effect=activate_fixture,
            ))
            stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication",
                return_value=mock.sentinel.prefix_snapshot,
            ))
            stack.enter_context(mock.patch.object(LOAD, "configure_ztp_prefix_publication"))
            def attest_monitor_authority(*_args, **_kwargs):
                if lifecycle_events is not None:
                    lifecycle_events.append("monitor-authority-attest")
                if authority_failure is not None:
                    raise authority_failure

            stack.enter_context(mock.patch.object(
                LOAD, "verify_monitor_authority",
                side_effect=attest_monitor_authority,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links",
                return_value={self.project / "99-output-eth/latest": "old-release"},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs",
                side_effect=(
                    (lambda *_args, **_kwargs: lifecycle_events.append("generate"))
                    if lifecycle_events is not None else None
                ),
            ))
            def validate_parent(*_args, **_kwargs):
                transaction_events.append("parent-validate")
                return fake_parent

            def stage_parent(*_args, **_kwargs):
                transaction_events.append("parent-stage")
                return candidate

            def build_report(*_args, **_kwargs):
                transaction_events.append("report-build")
                return report_payload

            def stage_report(*_args, **_kwargs):
                transaction_events.append("report-stage")
                return staged_report

            def discard_report(*_args, **_kwargs):
                transaction_events.append("report-discard")

            parent_validate = stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release", side_effect=validate_parent,
            ))
            parent_stage = stack.enter_context(mock.patch.object(
                LOAD, "prepare_current_release", side_effect=stage_parent,
            ))
            report_build = stack.enter_context(mock.patch.object(
                LOAD.generation_report, "build_report", side_effect=build_report,
            ))
            report_stage = stack.enter_context(mock.patch.object(
                LOAD.generation_report, "prepare_generation_report",
                side_effect=stage_report,
            ))
            report_commit = stack.enter_context(mock.patch.object(
                LOAD.generation_report, "commit_prepared_generation_report",
                side_effect=(
                    (lambda *_args: lifecycle_events.append("report-commit"))
                    if lifecycle_events is not None else None
                ),
            ))
            report_discard = stack.enter_context(mock.patch.object(
                LOAD.generation_report, "discard_prepared_generation_report",
                side_effect=discard_report,
            ))
            def fail_dhcp_transaction(*_args, **_kwargs):
                transaction_events.append("dhcp-transaction")
                if lifecycle_events is not None:
                    lifecycle_events.append("dhcp-transaction")
                if failure_at == "dhcp":
                    raise failure
                if failure_at == "parent_sync":
                    parent_identity = candidate.destination.parent.stat()
                    real_fsync = LOAD.os.fsync

                    def fail_parent_sync(descriptor):
                        identity = os.fstat(descriptor)
                        if (identity.st_dev, identity.st_ino) == (
                            parent_identity.st_dev, parent_identity.st_ino,
                        ):
                            raise failure
                        return real_fsync(descriptor)

                    with mock.patch.object(LOAD.os, "fsync", side_effect=fail_parent_sync):
                        LOAD.commit_prepared_release(candidate)
                    self.fail("unconfirmed parent durability must not return success")
                if failure_at == "completion":
                    LOAD.commit_prepared_release(candidate)
                    if after_parent_commit is not None:
                        after_parent_commit()
                else:
                    candidate.committed = True

            stack.enter_context(mock.patch.object(
                LOAD, "mount_and_test_dhcp", side_effect=fail_dhcp_transaction,
            ))
            if failure_at == "preflight":
                def fail_service_preflight(*_args, **_kwargs):
                    if parent_schema_version == 2:
                        self.assertEqual(fake_parent, _kwargs.get("committed_dhcp_parent"))
                    if lifecycle_events is not None:
                        lifecycle_events.append("service-preflight")
                    raise failure

                stack.enter_context(mock.patch.object(
                    LOAD, "preflight_services", side_effect=fail_service_preflight,
                ))
            stack.enter_context(mock.patch.object(
                LOAD, "restore_release_links", restore_links,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "restore_ztp_prefix_publication", restore_prefix,
            ))
            try:
                result = LOAD.main([] if argv is None else argv)
            except BaseException as exc:  # Assert propagation after cleanup below.
                caught = exc
            if failure_at in {"dhcp", "template", "parent_sync", "publication"}:
                report_commit.assert_not_called()
            elif publication_routing:
                report_commit.assert_called_once()
                self.assertEqual((staged_report,), report_commit.call_args.args)
                self.assertEqual({"require_authority"}, set(report_commit.call_args.kwargs))
                self.assertTrue(callable(report_commit.call_args.kwargs["require_authority"]))
            else:
                report_commit.assert_called_once_with(staged_report)
            if authority_failure is None and failure_at != "template":
                parent_validate.assert_called_once()
                private_dhcp = parent_validate.call_args.kwargs["dhcp_candidate_dir"]
                self.assertEqual(
                    (self.project / "99-output-dhcp").resolve(),
                    private_dhcp.parent,
                )
                parent_stage.assert_called_once_with(
                    self.project, fake_parent, dhcp_candidate_dir=private_dhcp,
                )
                report_build.assert_called_once_with(
                    self.project, fake_parent,
                    published_dir=LOAD.ZTP_DIR / "config/publickey",
                )
                report_stage.assert_called_once_with(self.project, report_payload)
                if failure_at == "publication" or publication_routing:
                    report_discard.assert_not_called()
                else:
                    report_discard.assert_called_once_with(staged_report)
                expected = [
                    "parent-validate", "parent-stage", "report-build",
                    "report-stage", "dhcp-transaction", "report-discard",
                ]
                if publication_routing:
                    expected.remove("report-discard")
                if failure_at == "publication":
                    expected = ["parent-validate", "parent-stage", "report-build", "report-stage"]
                self.assertEqual(expected, transaction_events)
            else:
                parent_validate.assert_not_called()
                parent_stage.assert_not_called()
                report_build.assert_not_called()
                report_stage.assert_not_called()
                report_discard.assert_called_once_with(None)
                self.assertEqual(["report-discard"], transaction_events)
        return (
            result, caught, candidate, quiesce, restore_links,
            restore_prefix, release_lock, runtime_backend, runtime_plan,
        )

    def _selected_pinned_b_consumer_fixture(self):
        # Literal A/B payloads are independent expectations, not producer output.
        self.project = self.project.resolve()
        flat = self.project / "99-output-dhcp"
        flat.mkdir(mode=0o700)
        runtime = self.ztp / "config/isc-dhcp-server"
        names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                 "dhcpd_nvl.hosts", "dhcp-release-manifest.json")
        for name in names:
            (flat / name).write_bytes((runtime / name).read_bytes())
            (runtime / name).unlink()
            (runtime / name).symlink_to(flat / name)
        before = {name: ((flat / name).stat().st_ino, (flat / name).read_bytes())
                  for name in names}
        candidate = flat / ".load-dhcp-candidate-0123456789abcdef"
        candidate.mkdir(mode=0o700)
        child = json.loads((flat / "dhcp-release-manifest.json").read_text())
        child["release_id"] = "independent-consumer-dhcp-B"
        for name in names[:-1]:
            payload = before[name][1]
            if name == "dhcpd.conf":
                payload += b"# independently specified selected B\n"
            (candidate / name).write_bytes(payload)
            child["outputs"][name]["sha256"] = hashlib.sha256(payload).hexdigest()
        (candidate / names[-1]).write_text(json.dumps(child), encoding="utf-8")
        parent = LOAD.validate_and_publish_release(
            self.project, self.inputs, publish=False, dhcp_candidate_dir=candidate,
        )
        prepared = LOAD.prepare_current_release(
            self.project, parent, dhcp_candidate_dir=candidate,
        )
        generation = LOAD.stage_pinned_generation(
            self.project, prepared.temporary, candidate,
        )
        LOAD.commit_prepared_release(prepared)
        LOAD.commit_pinned_generation(self.project, generation, expected_current=None)
        device = {"hostname": "leaf01", "type": "eth", "mac_plain": "020000000001",
                  "identity_macs": {"eth0": "020000000001"}}
        return parent, generation, flat, before, device

    def _service_selected_fixture(self):
        parent, generation, flat, before, _ = self._selected_pinned_b_consumer_fixture()
        # Formal LOAD supplies canonical inputs; /var is a macOS alias, not
        # permission for the shared no-follow reader to relax its authority.
        self.inputs = LOAD.replace(self.inputs, global_file=self.global_file.resolve(strict=True))
        installed = self.root.resolve() / "etc/dhcp"
        installed.mkdir(parents=True, mode=0o755)
        paths = {}
        for name in before:
            (flat / name).write_bytes(b"")
            if name != "dhcp-release-manifest.json":
                paths[name] = installed / name
                paths[name].write_bytes((generation / "dhcp" / name).read_bytes())
                paths[name].chmod(0o644)
        return parent, generation, flat, paths

    def _service_gate(self, backend, paths, run_action=None, committed_parent=None):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "ZTP_DIR", self.ztp))
            stack.enter_context(mock.patch.object(LOAD, "_runtime_installed_dhcp_paths", return_value=paths))
            for name in ("verify_control_auth", "verify_published_files", "verify_apache_publication_boundary"):
                stack.enter_context(mock.patch.object(LOAD, name))
            stack.enter_context(mock.patch.object(LOAD, "validate_management_host", return_value=True))
            stack.enter_context(mock.patch.object(LOAD, "supervisor_service_availability", return_value=(True, True)))
            stack.enter_context(mock.patch.object(LOAD, "sudo_command", side_effect=lambda *argv: list(argv)))
            commands = stack.enter_context(mock.patch.object(LOAD, "run", side_effect=run_action))
            LOAD.preflight_services(self.inputs, {}, runtime_backend=SimpleNamespace(name=backend),
                                    dhcp_runtime_plan=mock.sentinel.plan,
                                    **({"committed_dhcp_parent": committed_parent} if committed_parent is not None else {}))
            return commands

    def test_service_gate_reads_selected_dhcp_not_empty_setup_placeholders(self):
        _, _, flat, paths = self._service_selected_fixture()
        before = {path.name: (path.stat().st_ino, path.read_bytes()) for path in flat.iterdir() if path.is_file()}
        for backend in ("systemd", "supervisor"):
            with self.subTest(backend=backend):
                commands = self._service_gate(backend, paths)
                self.assertIn(mock.call(["dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"], dry_run=False), commands.call_args_list)
                self.assertIn(mock.call(["apache2ctl", "configtest"], dry_run=False), commands.call_args_list)
        self.assertEqual(before, {path.name: (path.stat().st_ino, path.read_bytes()) for path in flat.iterdir() if path.is_file()})

    def test_service_gate_selected_dhcp_rejects_installed_drift_and_unsafe_owner(self):
        _, _, _, paths = self._service_selected_fixture()
        conf = paths["dhcpd.conf"]
        payload = conf.read_bytes()
        for backend in ("systemd", "supervisor"):
            for fault in ("bytes", "symlink", "permissions"):
                with self.subTest(backend=backend, fault=fault):
                    if fault == "bytes":
                        conf.write_bytes(b"# wrong installed generation\n")
                    elif fault == "symlink":
                        conf.unlink()
                        conf.symlink_to(paths["dhcpd_eth.hosts"])
                    else:
                        conf.chmod(0o666)
                    with self.assertRaisesRegex(LOAD.LoadError, "installed DHCP|已安装 DHCP"):
                        self._service_gate(backend, paths)
                    if conf.is_symlink():
                        conf.unlink()
                    conf.write_bytes(payload)
                    conf.chmod(0o644)

    def test_service_gate_corrupt_selector_never_falls_back_to_legacy(self):
        _, generation, flat, paths = self._service_selected_fixture()
        for name in paths:
            (flat / name).write_bytes((generation / "dhcp" / name).read_bytes())
        selector = self.project / "99-output-ztp/current"
        selector.unlink()
        selector.symlink_to("generations/missing")
        for backend in ("systemd", "supervisor"):
            with self.subTest(backend=backend), self.assertRaisesRegex(LOAD.LoadError, "selected DHCP|已提交 DHCP"):
                self._service_gate(backend, paths)

    def test_service_gate_rejects_another_expected_committed_parent(self):
        parent, _, _, paths = self._service_selected_fixture()
        wrong_parent = dict(parent, release_id="another-committed-release")
        for backend in ("systemd", "supervisor"):
            with self.subTest(backend=backend), self.assertRaisesRegex(LOAD.LoadError, "selected DHCP"):
                self._service_gate(backend, paths, committed_parent=wrong_parent)

    def test_service_gate_selector_read_error_is_not_legacy_absence(self):
        _, generation, flat, paths = self._service_selected_fixture()
        for name in paths:
            (flat / name).write_bytes((generation / "dhcp" / name).read_bytes())
        selector = self.project / "99-output-ztp/current"
        original = os.lstat
        original_stat = os.stat
        original_path_lstat = Path.lstat
        for backend in ("systemd", "supervisor"):
            for fault in (PermissionError("selector denied"), OSError(5, "selector I/O error")):
                def lstat(path, *args, **kwargs):
                    if isinstance(path, (str, os.PathLike)) and os.fspath(path) == str(selector):
                        raise fault
                    return original(path, *args, **kwargs)
                def stat_call(path, *args, **kwargs):
                    if isinstance(path, (str, os.PathLike)) and os.fspath(path) == str(selector):
                        raise fault
                    return original_stat(path, *args, **kwargs)
                def path_lstat(path, *args, **kwargs):
                    if path == selector:
                        raise fault
                    return original_path_lstat(path, *args, **kwargs)
                with self.subTest(backend=backend, fault=type(fault).__name__), \
                     mock.patch.object(LOAD.os, "lstat", side_effect=lstat), \
                     mock.patch.object(LOAD.os, "stat", side_effect=stat_call), \
                     mock.patch.object(LOAD.Path, "lstat", new=path_lstat), \
                     self.assertRaisesRegex(LOAD.LoadError, "selected DHCP"):
                    self._service_gate(backend, paths)

    def test_service_gate_rechecks_selected_and_installed_after_syntax_check(self):
        _, generation, _, paths = self._service_selected_fixture()
        for backend in ("systemd", "supervisor"):
            for target in (generation / "dhcp/dhcpd.conf", paths["dhcpd.conf"]):
                with self.subTest(backend=backend, target=str(target)):
                    payload = target.read_bytes()
                    syntax_seen = []
                    def changed(command, **kwargs):
                        if command[0] == "dhcpd":
                            syntax_seen.append(command)
                            target.write_bytes(payload + b"# drift after syntax\n")
                    with self.assertRaisesRegex(LOAD.LoadError, "DHCP"):
                        self._service_gate(backend, paths, changed)
                    self.assertEqual(1, len(syntax_seen))
                    target.write_bytes(payload)

    def test_real_load_manual_selected_workflow_ignores_unrelated_exterior_sibling_creation(self):
        import project_contract as selected_authority
        parent, generation, flat, flat_before, device = self._selected_pinned_b_consumer_fixture()
        outer = self.project.parent
        outer_before = outer.stat()
        leaf_before = (generation / "dhcp/dhcpd.conf").stat()
        original_read, original_stat, original_fstat = os.read, os.stat, os.fstat
        namespace = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
        injected = []
        def changed(value):
            if not injected or (value.st_dev, value.st_ino) != (outer_before.st_dev, outer_before.st_ino):
                return value
            fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
            fields.update(st_nlink=outer_before.st_nlink + 1, st_size=outer_before.st_size + 1,
                          st_mtime_ns=outer_before.st_mtime_ns + 1, st_ctime_ns=outer_before.st_ctime_ns + 1)
            return SimpleNamespace(**fields)
        def read(descriptor, limit):
            payload = original_read(descriptor, limit)
            observed = original_fstat(descriptor)
            if (observed.st_dev, observed.st_ino) == (leaf_before.st_dev, leaf_before.st_ino) and not injected:
                sibling = outer / "independent-other-project-work"
                sibling.mkdir(mode=0o700)
                injected.append(sibling)
            return payload
        namespace.read = read
        namespace.stat = lambda *args, **kwargs: changed(original_stat(*args, **kwargs))
        namespace.fstat = lambda *args, **kwargs: changed(original_fstat(*args, **kwargs))
        with mock.patch.object(selected_authority, "os", namespace), \
             mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST", self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"):
            binding = MANUAL.validate_parent_release_binding(self.project, device)
            self.assertEqual("pinned", binding["selected_dhcp_authority_binding"]["mode"])
            self.assertEqual(parent["release_id"], binding["selected_dhcp_authority_binding"]["release_id"])
            MANUAL.verify_prepared_release_binding(binding)
        self.assertEqual([outer / "independent-other-project-work"], injected)
        self.assertEqual(flat_before, {name: ((flat / name).stat().st_ino, (flat / name).read_bytes()) for name in flat_before})
        # Full governed identities still reject an independent same-byte leaf
        # replacement; exterior child bookkeeping is not permission to rebind.
        leaf = generation / "dhcp/dhcpd.conf"
        payload = leaf.read_bytes()
        leaf.rename(leaf.with_name(".independent-original-selected-leaf"))
        leaf.write_bytes(payload)
        with self.assertRaises(MANUAL.ManualZtpError):
            MANUAL.verify_prepared_release_binding(binding)

    def test_selected_load_manual_vm_use_pinned_b_and_keep_old_flat_a(self):
        from test_cases.test_vm_validation_runner import VM
        parent, generation, flat, before, device = self._selected_pinned_b_consumer_fixture()
        with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST",
                               self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"):
            binding = MANUAL.validate_parent_release_binding(self.project, device)
            self.assertEqual("independent-consumer-dhcp-B", binding["dhcp_release_id"])
            self.assertEqual(str(generation / "dhcp/dhcp-release-manifest.json"),
                             binding["dhcp_manifest_path"])
            self.assertEqual("pinned", binding["selected_dhcp_authority_binding"]["mode"])
            MANUAL.verify_prepared_release_binding(binding)
        errors, checked = VM.component_artifact_errors(self.project, parent)
        self.assertEqual([], errors)
        self.assertEqual(1, checked)
        self.assertEqual([], VM.runtime_pointer_errors(self.root, self.project, parent))
        installed = self.root / "private-installed-dhcp"
        installed.mkdir()
        for name in ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"):
            (installed / name).write_bytes((generation / "dhcp" / name).read_bytes())
            self.assertNotEqual((installed / name).stat().st_ino,
                                (generation / "dhcp" / name).stat().st_ino)
        self.assertEqual([], VM.installed_dhcp_errors(self.project, parent, installed))
        self.assertEqual(before, {name: ((flat / name).stat().st_ino,
                                       (flat / name).read_bytes()) for name in before})

    def test_selected_manual_prepared_rejects_same_target_selector_replacement(self):
        _parent, _generation, _flat, _before, device = self._selected_pinned_b_consumer_fixture()
        binding = MANUAL.validate_parent_release_binding(self.project, device)
        selector = self.project / "99-output-ztp/current"
        target = os.readlink(selector)
        old = selector.with_name(".independent-old-selector")
        selector.rename(old)
        selector.symlink_to(target)
        with self.assertRaises(MANUAL.ManualZtpError):
            MANUAL.verify_prepared_release_binding(binding)

    def test_selected_manual_prepared_rejects_removed_selector_without_legacy_fallback(self):
        _parent, _generation, _flat, _before, device = self._selected_pinned_b_consumer_fixture()
        binding = MANUAL.validate_parent_release_binding(self.project, device)
        (self.project / "99-output-ztp/current").unlink()
        with self.assertRaises(MANUAL.ManualZtpError):
            MANUAL.verify_prepared_release_binding(binding)

    def test_selected_consumers_reject_dangling_selector_without_old_flat_fallback(self):
        from test_cases.test_vm_validation_runner import VM
        parent, _generation, _flat, _before, device = self._selected_pinned_b_consumer_fixture()
        selector = self.project / "99-output-ztp/current"
        selector.unlink()
        selector.symlink_to("generations/ffffffffffffffffffff")
        with self.assertRaises(MANUAL.ManualZtpError):
            MANUAL.validate_parent_release_binding(self.project, device)
        self.assertTrue(VM.component_artifact_errors(self.project, parent)[0])
        self.assertTrue(VM.runtime_pointer_errors(self.root, self.project, parent))
        self.assertTrue(VM.installed_dhcp_errors(self.project, parent, self.root))

    def test_selected_vm_installed_each_of_four_files_must_match_pinned_not_old_flat(self):
        from test_cases.test_vm_validation_runner import VM
        parent, generation, flat, _before, _device = self._selected_pinned_b_consumer_fixture()
        installed = self.root / "private-installed-dhcp"
        installed.mkdir()
        names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
        for name in names:
            (installed / name).write_bytes((generation / "dhcp" / name).read_bytes())
        for name in names:
            with self.subTest(name=name):
                (installed / name).write_bytes(b"independent installed mismatch\n")
                errors = VM.installed_dhcp_errors(self.project, parent, installed)
                self.assertEqual(1, len(errors))
                self.assertIn(name, errors[0])
                (installed / name).write_bytes((generation / "dhcp" / name).read_bytes())
        (installed / "dhcpd.conf").write_bytes((flat / "dhcpd.conf").read_bytes())
        errors = VM.installed_dhcp_errors(self.project, parent, installed)
        self.assertEqual(1, len(errors))
        self.assertIn("dhcpd.conf", errors[0])

    def test_selected_manual_confirmation_ignores_old_flat_drift_but_rejects_pinned_leaf_rebind(self):
        _parent, generation, flat, _before, device = self._selected_pinned_b_consumer_fixture()
        binding = MANUAL.validate_parent_release_binding(self.project, device)
        (flat / "dhcpd.conf").write_bytes(b"unselected A standalone edit\n")
        MANUAL.verify_prepared_release_binding(binding)
        leaf = generation / "dhcp/dhcpd.conf"
        payload = leaf.read_bytes()
        leaf.rename(leaf.with_name(".independent-old-leaf"))
        leaf.write_bytes(payload)
        with self.assertRaises(MANUAL.ManualZtpError):
            MANUAL.verify_prepared_release_binding(binding)


    def test_selected_disabled_parent_manual_and_vm_ignore_stale_flat_dhcp(self):
        from test_cases.test_vm_validation_runner import VM
        _parent, _generation, flat, _before, device = self._selected_pinned_b_consumer_fixture()
        previous = os.readlink(self.project / "99-output-ztp/current")
        global_value = yaml.safe_load(self.global_file.read_text())
        global_value["common"]["mgmt"]["dhcp-server"]["status"] = "disabled"
        self.global_file.write_text(yaml.safe_dump(global_value), encoding="utf-8")
        inputs = LOAD.replace(self.inputs, settings=LOAD.replace(self.inputs.settings, dhcp_enabled=False))
        parent = LOAD.validate_and_publish_release(self.project, inputs, publish=False)
        prepared = LOAD.prepare_current_release(self.project, parent)
        generation = LOAD.stage_pinned_generation(self.project, prepared.temporary, None)
        LOAD.commit_prepared_release(prepared)
        LOAD.commit_pinned_generation(self.project, generation, expected_current=previous)
        (flat / "dhcpd.conf").write_bytes(b"stale deliberately invalid DHCP\n")
        binding = MANUAL.validate_parent_release_binding(self.project, device)
        self.assertEqual("disabled", binding["dhcp_status"])
        self.assertEqual("disabled", binding["selected_dhcp_authority_binding"]["mode"])
        self.assertNotIn("dhcp_manifest_path", binding)
        MANUAL.verify_prepared_release_binding(binding)
        self.assertEqual([], VM.component_artifact_errors(self.project, parent)[0])
        self.assertEqual([], VM.runtime_pointer_errors(self.root, self.project, parent))

    def _runtime_schema4_selected_fixture(self):
        parent, generation, flat, before, _device = self._selected_pinned_b_consumer_fixture()
        installed = self.root.resolve() / "private-schema4-installed"
        installed.mkdir(mode=0o700)
        for name in ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"):
            (installed / name).write_bytes((generation / "dhcp" / name).read_bytes())
        mapping = {generation / "dhcp" / name: installed / name
                   for name in ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")}
        patcher = mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mapping)
        patcher.start(); self.addCleanup(patcher.stop)
        return parent, generation, flat, before, installed

    def test_schema4_capture_binds_selected_b_and_installed_b_not_flat_a(self):
        parent, generation, flat, before, installed = self._runtime_schema4_selected_fixture()
        qualification = LOAD._capture_runtime_selected_dhcp(self.project, generation)
        self.assertEqual(str(generation), qualification["generation"]["path"])
        expected = hashlib.sha256(
            before["dhcpd.conf"][1] + b"# independently specified selected B\n").hexdigest()
        self.assertEqual(expected, qualification["installed"]["leaves"]["dhcpd.conf"]["state"]["sha256"])
        self.assertNotEqual(before["dhcpd.conf"][1], (installed / "dhcpd.conf").read_bytes())
        self.assertNotEqual((installed / "dhcpd.conf").stat().st_ino,
                            (generation / "dhcp/dhcpd.conf").stat().st_ino)
        self.assertEqual(before, {name: ((flat / name).stat().st_ino,
                                       (flat / name).read_bytes()) for name in before})

    def test_schema4_capture_rejects_installed_old_flat_a(self):
        _parent, generation, flat, _before, installed = self._runtime_schema4_selected_fixture()
        (installed / "dhcpd.conf").write_bytes((flat / "dhcpd.conf").read_bytes())
        with self.assertRaisesRegex(LOAD.LoadError, "installed DHCP"):
            LOAD._capture_runtime_selected_dhcp(self.project, generation)

    def test_schema4_capture_rejects_dangling_current_without_flat_fallback(self):
        _parent, generation, _flat, _before, _installed = self._runtime_schema4_selected_fixture()
        selector = self.project / "99-output-ztp/current"
        selector.unlink(); selector.symlink_to("generations/ffffffffffffffffffff")
        with self.assertRaises(LOAD.LoadError):
            LOAD._capture_runtime_selected_dhcp(self.project, generation)

    def test_schema4_active_verify_rejects_same_bytes_installed_rebind(self):
        parent, generation, _flat, _before, installed = self._runtime_schema4_selected_fixture()
        receipt = dict(schema_version=4, release_id=parent["release_id"],
                       selector_target="generations/" + generation.name,
                       dhcp_status="enabled",
                       selected_dhcp=LOAD._capture_runtime_selected_dhcp(self.project, generation))
        leaf = installed / "dhcpd.conf"
        payload = leaf.read_bytes()
        held = installed / ".independent-held-owner"
        leaf.rename(held); leaf.write_bytes(payload)
        with self.assertRaisesRegex(LOAD.LoadError, "changed"):
            LOAD._verify_active_selected_dhcp(self.project, receipt)

    def test_schema4_parser_closed_inventory_boolean_owner_and_external_runtime_hold(self):
        parent, generation, _flat, _before, _installed = self._runtime_schema4_selected_fixture()
        base = dict(schema_version=4, release_id=parent["release_id"],
                    selector_target="generations/" + generation.name, dhcp_status="enabled",
                    selected_dhcp=LOAD._capture_runtime_selected_dhcp(self.project, generation))
        for fault in ("extra", "missing", "boolean", "external"):
            with self.subTest(fault=fault):
                receipt = json.loads(json.dumps(base))
                row = receipt["selected_dhcp"]["installed"]
                if fault == "extra": row["leaves"]["independent-extra"] = row["leaves"]["dhcpd.conf"]
                elif fault == "missing": row["leaves"].pop("dhcpd_ib.hosts")
                elif fault == "boolean": row["leaves"]["dhcpd.conf"]["identity"][0] = True
                else: row["directory"]["path"] = str(self.root / "unregistered-runtime")
                with self.assertRaises(LOAD.LoadError):
                    LOAD._validate_runtime_selected_dhcp(self.project, receipt)

    def _schema4_real_receipt_fixture(self):
        # Qualify the actual private deployment root before producing and
        # freezing any parent/input snapshot, never rewrite selected proof.
        document = yaml.safe_load(self.global_file.read_text())
        document["common"]["mgmt"]["http"]["http_root"] = str(self.root.resolve())
        self.global_file.write_text(yaml.safe_dump(document, sort_keys=False))
        self.inputs = LOAD.replace(self.inputs, settings=LOAD.load_global(self.global_file))
        parent, generation, flat, before, installed = self._runtime_schema4_selected_fixture()
        # Production-compatible lexical aliases are qualified before capture.
        published = self.ztp / "config/isc-dhcp-server"
        for name in before:
            alias = published / name
            alias.unlink()
            alias.symlink_to(os.path.relpath(flat / name, published.resolve()))
        for name, payload in {
            "ztp-bootstrap_oob.sh": b'A oob bootstrap\nZTP_UPGRADE_ENABLED="false"\n',
            "ztp-bootstrap_oobofoob.sh": b'A oobofoob bootstrap\nZTP_UPGRADE_ENABLED="false"\n',
            "ztp.json": b'{"release":"A"}\n',
        }.items():
            (self.ztp / name).write_bytes(payload)
        keys = self.ztp / "config/publickey"
        keys.mkdir(parents=True, exist_ok=True)
        (keys / "laptop.pub").write_bytes(b"A laptop key\n")
        (keys / "mgmt-server.pub").write_bytes(b"A management key\n")
        patcher = mock.patch.object(LOAD, "HTTP_ROOT", self.root.resolve())
        patcher.start(); self.addCleanup(patcher.stop)
        return parent, generation, flat, before, installed

    def test_schema4_real_prepare_parser_keeps_selected_installed_and_flat_distinct(self):
        parent, generation, flat, before, installed = self._schema4_real_receipt_fixture()
        receipt_path = LOAD.prepare_runtime_rollback_receipt(
            self.project, generation, capture_selected_dhcp=True)
        receipt = LOAD._load_runtime_rollback_receipt(self.project, receipt_path)
        self.assertEqual(4, receipt["schema_version"])
        expected = hashlib.sha256(
            before["dhcpd.conf"][1] + b"# independently specified selected B\n").hexdigest()
        self.assertEqual(expected,
                         receipt["selected_dhcp"]["installed"]["leaves"]["dhcpd.conf"]["state"]["sha256"])
        self.assertEqual(hashlib.sha256(before["dhcpd.conf"][1]).hexdigest(),
                         receipt["unchanged_authorities"]["dhcp"]["dhcpd.conf"]["sha256"])
        self.assertEqual(parent["release_id"], receipt["release_id"])
        LOAD._verify_active_runtime_receipt(self.project, receipt_path, receipt)
        self.assertEqual(before, {name: ((flat / name).stat().st_ino,
                                       (flat / name).read_bytes()) for name in before})

    def test_schema4_real_prepare_reuse_keeps_original_receipt_owner_and_bytes(self):
        _parent, generation, _flat, _before, _installed = self._schema4_real_receipt_fixture()
        path = LOAD.prepare_runtime_rollback_receipt(
            self.project, generation, capture_selected_dhcp=True)
        original = ((path / "receipt.json").stat().st_ino, (path / "receipt.json").read_bytes())
        self.assertEqual(path, LOAD.prepare_runtime_rollback_receipt(
            self.project, generation, capture_selected_dhcp=True))
        self.assertEqual(original, ((path / "receipt.json").stat().st_ino,
                                   (path / "receipt.json").read_bytes()))

    def test_schema4_real_capture_existing_schema3_holds_without_upgrading_proof(self):
        _parent, generation, _flat, _before, _installed = self._schema4_real_receipt_fixture()
        path = LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        original = ((path / "receipt.json").stat().st_ino, (path / "receipt.json").read_bytes())
        self.assertEqual(3, LOAD._load_runtime_rollback_receipt(self.project, path)["schema_version"])
        with self.assertRaisesRegex(LOAD.LoadError, "schema4"):
            LOAD.prepare_runtime_rollback_receipt(self.project, generation, capture_selected_dhcp=True)
        with mock.patch.object(LOAD, "active_project", return_value=self.project.resolve()):
            with self.assertRaisesRegex(LOAD.LoadError, "schema4"):
                LOAD.prepare_active_runtime_rollback_receipt(self.project, "generations/" + generation.name)
        self.assertEqual(original, ((path / "receipt.json").stat().st_ino,
                                   (path / "receipt.json").read_bytes()))
        self.assertEqual(3, LOAD._load_runtime_rollback_receipt(self.project, path)["schema_version"])

    def test_schema4_real_parser_rejects_duplicate_top_level_authority(self):
        _parent, generation, _flat, _before, _installed = self._schema4_real_receipt_fixture()
        path = LOAD.prepare_runtime_rollback_receipt(
            self.project, generation, capture_selected_dhcp=True)
        file = path / "receipt.json"
        payload = file.read_bytes()
        self.assertTrue(payload.lstrip().startswith(b"{"))
        file.write_bytes(b'{"schema_version":3,' + payload.lstrip()[1:])
        with self.assertRaisesRegex(LOAD.LoadError, "duplicate|JSON|receipt"):
            LOAD._load_runtime_rollback_receipt(self.project, path)

    def test_schema4_real_parser_closed_selected_inventory_rejects_external_path(self):
        _parent, generation, _flat, _before, _installed = self._schema4_real_receipt_fixture()
        path = LOAD.prepare_runtime_rollback_receipt(
            self.project, generation, capture_selected_dhcp=True)
        file = path / "receipt.json"
        receipt = json.loads(file.read_bytes())
        receipt["selected_dhcp"]["installed"]["directory"]["path"] = str(self.root / "not-an-installer-runtime")
        file.write_text(json.dumps(receipt), encoding="ascii")
        with self.assertRaises(LOAD.LoadError):
            LOAD._load_runtime_rollback_receipt(self.project, path)

    def test_schema4_frozen_parent_does_not_rebind_when_canonical_parent_becomes_q(self):
        parent, generation, _flat, _before, _installed = self._schema4_real_receipt_fixture()
        path = LOAD.prepare_runtime_rollback_receipt(
            self.project, generation, capture_selected_dhcp=True)
        receipt = LOAD._load_runtime_rollback_receipt(self.project, path)
        canonical = self.project / "99-output-ztp/current-release.json"
        canonical.write_bytes(b'{"release_id":"independent-Q-canonical-parent"}\n')
        # Disk qualification resolves A's immutable parent, not Q or the live selector.
        LOAD._validate_runtime_selected_dhcp(self.project, receipt)
        self.assertEqual(parent["release_id"], receipt["release_id"])
        self.assertEqual(receipt["selected_dhcp"], LOAD._load_runtime_rollback_receipt(
            self.project, path)["selected_dhcp"])
        with self.assertRaises(LOAD.LoadError):
            LOAD._verify_active_runtime_receipt(self.project, path, receipt)

    def test_schema4_mutable_installed_directory_times_do_not_rebind_frozen_authority(self):
        _parent, generation, _flat, _before, installed = self._schema4_real_receipt_fixture()
        path = LOAD.prepare_runtime_rollback_receipt(
            self.project, generation, capture_selected_dhcp=True)
        receipt = LOAD._load_runtime_rollback_receipt(self.project, path)
        marker = installed / ".authorized-transaction-reservation"
        marker.mkdir(mode=0o700); marker.rmdir()
        LOAD._validate_runtime_selected_dhcp(self.project, receipt)
        LOAD._verify_active_selected_dhcp(self.project, receipt)
        self.assertEqual({"path", "dev", "ino"}, set(receipt["selected_dhcp"]["installed"]["directory"]))

    def _selected_manual_preflight_lifecycle(self, *, reserve_operation=False, invalid_selector=False):
        _parent, _generation, _flat, _before, device = self._selected_pinned_b_consumer_fixture()
        device["ip"] = "192.0.2.10"
        target = self.project / "99-output-ztp/manual-ztp/20261009_010000/leaf01"
        if reserve_operation:
            # Same ordering as main: authorized run reservation precedes qualification.
            target.parent.mkdir(parents=True, mode=0o700)
        if invalid_selector:
            selector = self.project / "99-output-ztp/current"
            selector.unlink(); selector.symlink_to("generations/ffffffffffffffffffff")
        client = mock.Mock()
        client.args.command_timeout = 10
        client.run.return_value = SimpleNamespace(returncode=0, stdout="set: {}\n", stderr="")
        applied = {"trusted": False, "reason": "independent no prior device receipt",
                   "fingerprint": "a" * 64}
        with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST",
                               self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"), \
                mock.patch.object(MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0")), \
                mock.patch.object(MANUAL, "collect_applied_config", return_value=applied):
            if invalid_selector:
                with self.assertRaises(MANUAL.ManualZtpError):
                    MANUAL.preflight_one(client, self.project, device, target)
                self.assertFalse(os.path.lexists(target))
                self.assertFalse(os.path.lexists(target.parents[1]))
                client.run.assert_not_called()
                return
            evidence = MANUAL.preflight_one(client, self.project, device, target)
            self.assertTrue((target / "preflight.json").is_file())
            self.assertEqual("pinned", evidence["selected_dhcp_authority_binding"]["mode"])
            # Confirm must accept its own authorized evidence writes, still
            # using exact selected/leaf owners; do not weaken full9 assertions.
            MANUAL.verify_prepared_release_binding(evidence)
            selector = self.project / "99-output-ztp/current"
            selector.unlink(); selector.symlink_to("generations/ffffffffffffffffffff")
            with self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.verify_prepared_release_binding(evidence)

    def test_selected_real_load_manual_first_preflight_then_confirm(self):
        self._selected_manual_preflight_lifecycle()

    def test_selected_real_load_manual_main_reserved_stage_preflight_then_confirm(self):
        self._selected_manual_preflight_lifecycle(reserve_operation=True)

    def test_selected_real_load_manual_invalid_preflight_does_not_reserve_output(self):
        self._selected_manual_preflight_lifecycle(invalid_selector=True)

    @contextmanager
    def _schema4_real_receipt_producer_for_existing_workflow(self, *, runtime_directory="private-schema4-installed"):
        self.root, self.ztp = self.root.resolve(), self.ztp.resolve()
        installed = self.root / runtime_directory
        installed.mkdir(mode=0o700)
        names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
        mapping = {self.ztp / "config/isc-dhcp-server" / name: installed / name for name in names}
        producer = LOAD.prepare_runtime_rollback_receipt
        captured = []

        def real_schema4_receipt(project, generation, **options):
            # Seed the original installed namespace once, before qualification.
            # These are independent fixture literals from setUp, not hashes
            # synthesized from the implementation being asserted.
            for name in names:
                leaf = installed / name
                if not leaf.exists():
                    leaf.write_bytes((name + "\n").encode("ascii"))
                self.assertEqual((name + "\n").encode("ascii"), leaf.read_bytes())
            options["capture_selected_dhcp"] = True
            path = producer(project, generation, **options)
            record = LOAD._load_runtime_rollback_receipt(project, path)
            self.assertEqual(4, record["schema_version"])
            captured.append((project, path))
            return path

        with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mapping), \
                mock.patch.object(LOAD, "prepare_runtime_rollback_receipt", side_effect=real_schema4_receipt):
            yield
            self.assertEqual(1, len(captured), "workflow must actually create one new schema4 receipt")
            project, receipt = captured[0]
            self.assertEqual(4, LOAD._load_runtime_rollback_receipt(project, receipt)["schema_version"])

    def _copied_vm_selected_contract_workflow(self, fault=None):
        parent, generation, _flat, _before, _device = self._selected_pinned_b_consumer_fixture()
        deployment = self.root / "private-deployed-source"
        deployment.mkdir(mode=0o700)
        copy_source_tools(deployment / "tools")
        copied = self.root / "copied-verifier.py"
        shutil.copy2(ROOT / "test_cases/run_vm_validation.py", copied)
        working = self.root / "unrelated-working-directory"
        working.mkdir(mode=0o700)
        if fault == "missing-contract":
            (deployment / "tools/project_contract.py").unlink()
        operation = r'''
import importlib.util, json, sys, types
from pathlib import Path
copied, deployment, project = map(Path, sys.argv[1:4])
spec = importlib.util.spec_from_file_location("private_copied_validator", copied)
vm = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = vm
spec.loader.exec_module(vm)
args = vm.parse_args([str(project), "--root", str(deployment)])
vm.configure_validation_deployment_root(args.root)
if sys.argv[4] == "foreign-cache":
    foreign = types.ModuleType("tools")
    foreign.__path__ = [str(copied.parent / "unrelated-working-directory/tools")]
    sys.modules["tools"] = foreign
parent = json.loads((project / "99-output-ztp/current-release.json").read_bytes())
selected = vm.selected_dhcp_authority(project, parent)
assert selected.mode == "pinned"
assert selected.manifest["release_id"] == "independent-consumer-dhcp-B"
assert vm.validated_parent_dhcp_status(project, parent) == "enabled"
vm._recheck_selected_dhcp_authority(project, selected)
assert Path(vm.deployment_project_contract().__file__).resolve() == deployment.resolve() / "tools/project_contract.py"
print("actual-copied-validator-selected-B")
'''
        result = subprocess.run([sys.executable, "-B", "-c", operation,
            str(copied), str(deployment.resolve()), str(self.project), fault or "none"],
            cwd=working, capture_output=True, text=True, timeout=30)
        if fault:
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertNotIn("actual-copied-validator-selected-B", result.stdout)
            expected_reason = "project_contract.py" if fault == "missing-contract" else "foreign cached deployment tools package"
            self.assertIn(expected_reason, result.stderr)
            self.assertNotIn("the following arguments are required", result.stderr)
        else:
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual("actual-copied-validator-selected-B\n", result.stdout)
        self.assertEqual(parent["release_id"], generation.name)

    def test_real_load_copied_vm_cli_root_from_unrelated_cwd_selects_pinned_b(self):
        self._copied_vm_selected_contract_workflow()

    def test_real_load_copied_vm_cli_root_missing_contract_does_not_fallback_repo(self):
        self._copied_vm_selected_contract_workflow("missing-contract")

    def test_real_load_copied_vm_cli_root_foreign_cached_tools_fails_closed(self):
        self._copied_vm_selected_contract_workflow("foreign-cache")

    def test_schema4_capture_rejects_writable_installed_leaf_even_matching_selected_bytes(self):
        _parent, generation, _flat, _before, installed = self._runtime_schema4_selected_fixture()
        (installed / "dhcpd.conf").chmod(0o666)
        with self.assertRaisesRegex(LOAD.LoadError, "owner|permissions|unsafe"):
            LOAD._capture_runtime_selected_dhcp(self.project, generation)

    def test_schema4_capture_rejects_foreign_installed_uid_not_calling_euid(self):
        _parent, generation, _flat, _before, installed = self._runtime_schema4_selected_fixture()
        reader = LOAD._setup_switch_dhcp_owned_leaf
        foreign_uid = installed.stat().st_uid + 1
        def foreign_owner(path):
            row = reader(path)
            row["identity"][3] = foreign_uid
            row["state"]["uid"] = foreign_uid
            return row
        with mock.patch.object(LOAD, "_setup_switch_dhcp_owned_leaf", side_effect=foreign_owner):
            with self.assertRaisesRegex(LOAD.LoadError, "owner|permissions|unsafe"):
                LOAD._capture_runtime_selected_dhcp(self.project, generation)

    def test_schema4_parser_rejects_self_consistent_writable_or_foreign_installed_owner(self):
        parent, generation, _flat, _before, installed = self._runtime_schema4_selected_fixture()
        original = dict(schema_version=4, release_id=parent["release_id"],
                        selector_target="generations/" + generation.name, dhcp_status="enabled",
                        selected_dhcp=LOAD._capture_runtime_selected_dhcp(self.project, generation))
        for fault in ("writable", "foreign"):
            with self.subTest(fault=fault):
                receipt = json.loads(json.dumps(original))
                row = receipt["selected_dhcp"]["installed"]["leaves"]["dhcpd.conf"]
                if fault == "writable":
                    row["identity"][2] = stat.S_IFREG | 0o666
                    row["state"]["mode"] = 0o666
                else:
                    row["identity"][3] = installed.stat().st_uid + 1
                    row["state"]["uid"] = installed.stat().st_uid + 1
                with self.assertRaisesRegex(LOAD.LoadError, "owner|permissions|unsafe"):
                    LOAD._validate_runtime_selected_dhcp(self.project, receipt)

    def test_schema4_parser_strict_numeric_generation_and_directory_identity(self):
        parent, generation, _flat, _before, _installed = self._runtime_schema4_selected_fixture()
        original = dict(schema_version=4, release_id=parent["release_id"],
                        selector_target="generations/" + generation.name, dhcp_status="enabled",
                        selected_dhcp=LOAD._capture_runtime_selected_dhcp(self.project, generation))
        for fault in ("tree-float", "tree-bool", "generation-parent-float", "runtime-directory-float"):
            with self.subTest(fault=fault):
                receipt = json.loads(json.dumps(original))
                row = receipt["selected_dhcp"]
                if fault == "tree-float":
                    entry = next(iter(row["generation"]["tree"].values()))
                    entry["uid"] = float(entry["uid"])
                elif fault == "tree-bool":
                    entry = next(iter(row["generation"]["tree"].values()))
                    # Boolean identity must be rejected even where True/False
                    # happens to compare equal to an integer kernel identity.
                    entry["uid"] = bool(entry["uid"])
                elif fault == "generation-parent-float":
                    entry = row["generation"]["parent"]
                    entry["dev"] = float(entry["dev"])
                else:
                    entry = row["installed"]["directory"]
                    entry["dev"] = float(entry["dev"])
                with self.assertRaises(LOAD.LoadError):
                    LOAD._validate_runtime_selected_dhcp(self.project, receipt)

    def _real_load_cumulus_upgrade_policy_fixture(self, enabled):
        from test_cases.test_vm_validation_runner import VM
        document = yaml.safe_load(self.global_file.read_text())
        document["common"]["mgmt"]["http"]["http_root"] = str(self.root.resolve())
        self.global_file.write_text(yaml.safe_dump(document, sort_keys=False))
        self.subnet_file.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,192.0.2.1,"
            "192.0.2.40,oob,no\n")
        settings = LOAD.apply_subnet_service_ips(LOAD.load_global(self.global_file), self.subnet_file)
        self.inputs = LOAD.replace(self.inputs, settings=settings)
        parent, generation, _flat, _before, _device = self._selected_pinned_b_consumer_fixture()
        templates = self.ztp / "templates"
        templates.mkdir()
        shutil.copy2(ROOT / "ztp/templates/ztp-bootstrap.sh", templates / "ztp-bootstrap.sh")
        shutil.copy2(ROOT / "ztp/templates/ztp.json", templates / "ztp.json")
        keys = self.ztp / "config/publickey"
        keys.mkdir(parents=True)
        from test_cases.test_ssh_key_preparation_contract import public_line
        key = keys / "laptop.pub"
        key.write_bytes(public_line("ssh-ed25519", 31, "independent-upgrade-policy-key"))
        LOAD.render_ztp_runtime(settings, (key,), frozenset({"eth"}), upgrade_enabled=enabled)
        return VM, parent, generation, self.ztp / "ztp-bootstrap_oob.sh"

    def test_real_render_vm_no_upgrade_cannot_waive_image_after_executable_body_drift(self):
        VM, parent, _generation, script = self._real_load_cumulus_upgrade_policy_fixture(False)
        payload = script.read_bytes()
        guard = b' && "${ZTP_UPGRADE_ENABLED}" == "true"'
        self.assertEqual(1, payload.count(guard), "independent real executable upgrade boundary")
        policy = b'ZTP_UPGRADE_ENABLED="false"\n'
        for fault, candidate in (
            ("removed-upgrade-guard", payload.replace(guard, b'')),
            ("extra-image-command", payload + b'onie-install -fa -i "${USE_IMG_URL}"\n'),
            ("heredoc-policy", payload.replace(policy, b"cat <<'INDEPENDENT_POLICY'\n" + policy + b'INDEPENDENT_POLICY\n')),
        ):
            with self.subTest(fault=fault):
                script.write_bytes(candidate); script.chmod(0o755)
                self.assertIn(policy, script.read_bytes())
                with self.assertRaises(ValueError):
                    VM.cumulus_runtime_image_required(self.root.resolve(), self.project, parent)
        script.write_bytes(payload); script.chmod(0o755)

    def test_real_render_vm_no_upgrade_requires_safe_exact_template_authority(self):
        VM, parent, _generation, script = self._real_load_cumulus_upgrade_policy_fixture(False)
        template = self.ztp / "templates/ztp-bootstrap.sh"
        original = template.read_bytes()
        for fault in ("writable", "symlink", "hardlink", "body-drift"):
            with self.subTest(fault=fault):
                sentinel = template.with_name("independent-template-preimage-" + fault)
                if fault == "writable": template.chmod(0o777)
                elif fault == "symlink":
                    template.rename(sentinel); template.symlink_to(sentinel.name)
                elif fault == "hardlink": os.link(template, sentinel)
                else: template.write_bytes(original + b'# independent template body changed\n')
                try:
                    with self.assertRaises((ValueError, OSError)):
                        VM.cumulus_runtime_image_required(self.root.resolve(), self.project, parent)
                finally:
                    if fault == "symlink": template.unlink(); sentinel.rename(template)
                    elif fault == "hardlink": sentinel.unlink()
                    template.write_bytes(original); template.chmod(0o644)
        self.assertIn(b'ZTP_UPGRADE_ENABLED="false"\n', script.read_bytes())

    def test_real_render_vm_bootstrap_template_hash_recheck_rejects_same_identity_byte_collision(self):
        VM, parent, _generation, _script = self._real_load_cumulus_upgrade_policy_fixture(False)
        template = (self.ztp / "templates/ztp-bootstrap.sh").resolve()
        original_reader = VM.read_regular_bytes
        reads = []
        def collision_reader(path, **kwargs):
            value = original_reader(path, **kwargs)
            if Path(path) == template:
                reads.append(Path(path))
                # Deterministic independent collision model: retain original
                # namespace identities, return different same-length bytes on
                # the second read; never depend on filesystem clock granularity.
                if len(reads) > 1: return value.replace(b'set -euo pipefail', b'set -euO pipefail', 1)
            return value
        with mock.patch.object(VM, "read_regular_bytes", side_effect=collision_reader):
            with self.assertRaisesRegex(ValueError, "bytes|owner"):
                VM.cumulus_runtime_image_required(self.root.resolve(), self.project, parent)
        self.assertEqual(2, len(reads), "original template SHA must be rechecked, not copied from metadata")

    def test_real_render_vm_no_upgrade_fifo_bootstrap_cannot_hang_or_waive_image(self):
        from test_cases.test_vm_validation_runner import VmRegularByteReaderRaceContracts
        VM, parent, _generation, script = self._real_load_cumulus_upgrade_policy_fixture(False)
        original = script.read_bytes()
        with VmRegularByteReaderRaceContracts.owned_fifo_rebind(script.resolve(), self.root) as (attempts, opened, closed, injected):
            # Run the actual VM policy path: parent/selected authority and
            # original template qualification remain real, not mocked passes.
            with self.assertRaisesRegex(ValueError, "打开期间文件发生变化"):
                VM.cumulus_runtime_image_required(self.root.resolve(), self.project, parent)
            self.assertEqual(1, len(attempts)); self.assertTrue(attempts[0] & os.O_NONBLOCK)
            self.assertEqual(1, len(opened)); self.assertEqual(opened, closed)
            self.assertEqual(1, len(injected))
        self.assertEqual(original, script.read_bytes())

    def test_real_load_render_false_vm_cumulus_policy_needs_no_image(self):
        VM, parent, _generation, script = self._real_load_cumulus_upgrade_policy_fixture(False)
        self.assertIn(b'ZTP_UPGRADE_ENABLED="false"\n', script.read_bytes())
        self.assertFalse((self.ztp / "image/cumulus").exists())
        self.assertIs(False, VM.cumulus_runtime_image_required(self.root.resolve(), self.project, parent))

    def test_real_load_render_true_vm_cumulus_policy_still_requires_image(self):
        VM, parent, _generation, script = self._real_load_cumulus_upgrade_policy_fixture(True)
        self.assertIn(b'ZTP_UPGRADE_ENABLED="true"\n', script.read_bytes())
        self.assertIs(True, VM.cumulus_runtime_image_required(self.root.resolve(), self.project, parent))

    def test_real_load_vm_no_upgrade_rejects_selected_bootstrap_binding_faults(self):
        VM, parent, _generation, script = self._real_load_cumulus_upgrade_policy_fixture(False)
        payload = script.read_bytes()
        for fault in ("duplicate-policy", "wrong-host", "wrong-prefix", "writable", "foreign-inode-link"):
            with self.subTest(fault=fault):
                script.write_bytes(payload); script.chmod(0o755)
                if fault == "duplicate-policy": script.write_bytes(payload + b'ZTP_UPGRADE_ENABLED="false"\n')
                elif fault == "wrong-host":
                    script.write_bytes(payload.replace(b'ZTP_SERVER_HOST="192.0.2.40"', b'ZTP_SERVER_HOST="192.0.2.99"'))
                elif fault == "wrong-prefix":
                    script.write_bytes(payload.replace(b'ZTP_URL_PREFIX="/ztp"', b'ZTP_URL_PREFIX="/other"'))
                elif fault == "writable": script.chmod(0o777)
                else:
                    held = script.with_name("independent-operator-held-bootstrap")
                    script.rename(held); script.symlink_to(held.name)
                with self.assertRaises((ValueError, OSError)):
                    VM.cumulus_runtime_image_required(self.root.resolve(), self.project, parent)
                if fault == "foreign-inode-link":
                    script.unlink(); held.rename(script)
        script.write_bytes(payload); script.chmod(0o755)
        self.global_file.write_bytes(self.global_file.read_bytes() + b"\n# independent out-of-band input\n")
        with self.assertRaises((ValueError, OSError)):
            VM.cumulus_runtime_image_required(self.root.resolve(), self.project, parent)

    def test_writes_parent_release_after_all_components_match(self) -> None:
        result = LOAD.validate_and_publish_release(self.project, self.inputs)
        self.assertEqual(result["validation"], "passed")
        self.assertEqual(set(result["components"]), {"dhcp", "cumulus"})
        current = self.project / "99-output-ztp/current-release.json"
        self.assertEqual(json.loads(current.read_text())["release_id"], result["release_id"])

    def test_parent_validation_binds_private_dhcp_candidate_not_old_flat_a(self) -> None:
        dhcp_dir = self.ztp / "config/isc-dhcp-server"
        old_manifest = dhcp_dir / "dhcp-release-manifest.json"
        old_bytes = {
            path.name: path.read_bytes()
            for path in dhcp_dir.iterdir() if path.is_file()
        }
        candidate = self.project / "99-output-dhcp/.load-dhcp-candidate-0123456789abcdef"
        candidate.mkdir(parents=True, mode=0o700)
        manifest = json.loads(old_manifest.read_text(encoding="utf-8"))
        manifest["release_id"] = "dhcp-candidate-b"
        for filename in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        ):
            content = old_bytes[filename]
            if filename == "dhcpd.conf":
                content += b"# independently expected B candidate\n"
            (candidate / filename).write_bytes(content)
            manifest["outputs"][filename]["sha256"] = sha256(candidate / filename)
        (candidate / "dhcp-release-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8",
        )

        parent = LOAD.validate_and_publish_release(
            self.project, self.inputs, publish=False,
            dhcp_candidate_dir=candidate,
        )
        self.assertEqual("dhcp-candidate-b", parent["components"]["dhcp"]["release_id"])
        self.assertEqual(
            sha256(candidate / "dhcp-release-manifest.json"),
            parent["components"]["dhcp"]["manifest_sha256"],
        )
        self.assertEqual(
            old_bytes,
            {path.name: path.read_bytes() for path in dhcp_dir.iterdir() if path.is_file()},
        )

    def test_prepared_parent_rechecks_candidate_not_changed_old_flat_files(self) -> None:
        dhcp_dir = self.ztp / "config/isc-dhcp-server"
        candidate = self.project / "99-output-dhcp/.load-dhcp-candidate-0123456789abcdef"
        candidate.mkdir(parents=True, mode=0o700)
        for filename in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        ):
            (candidate / filename).write_bytes((dhcp_dir / filename).read_bytes())
        manifest = json.loads(
            (dhcp_dir / "dhcp-release-manifest.json").read_text(encoding="utf-8")
        )
        (candidate / "dhcp-release-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8",
        )
        parent = LOAD.validate_and_publish_release(
            self.project, self.inputs, publish=False, dhcp_candidate_dir=candidate,
        )
        prepared = LOAD.prepare_current_release(
            self.project, parent, dhcp_candidate_dir=candidate,
        )
        try:
            (dhcp_dir / "dhcpd.conf").write_bytes(b"old flat A changed\n")
            LOAD.recheck_prepared_dhcp_child(
                prepared, LOAD.dhcp_file_mappings(candidate),
            )
            (candidate / "dhcpd.conf").write_bytes(b"candidate B changed\n")
            with self.assertRaisesRegex(LOAD.LoadError, "DHCP child"):
                LOAD.recheck_prepared_dhcp_child(
                    prepared, LOAD.dhcp_file_mappings(candidate),
                )
        finally:
            LOAD.discard_prepared_release(prepared)

    def test_dhcp_install_reads_prepared_private_candidate_not_old_flat_a(self) -> None:
        dhcp_dir = self.ztp / "config/isc-dhcp-server"
        private = self.project / "99-output-dhcp/.load-dhcp-candidate-0123456789abcdef"
        private.mkdir(parents=True, mode=0o700)
        for filename in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
            "dhcp-release-manifest.json",
        ):
            (private / filename).write_bytes((dhcp_dir / filename).read_bytes())
        parent = LOAD.validate_and_publish_release(
            self.project, self.inputs, publish=False, dhcp_candidate_dir=private,
        )
        prepared = LOAD.prepare_current_release(
            self.project, parent, dhcp_candidate_dir=private,
        )
        try:
            with mock.patch.object(LOAD, "validate_dhcp_output_sources") as validate, \
                    mock.patch.object(LOAD, "run"), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)):
                LOAD.mount_and_test_dhcp(True, parent_candidate=prepared)
            sources = validate.call_args.args[0]
            self.assertEqual(
                {path.parent.resolve() for path in sources}, {private.resolve()},
            )
        finally:
            LOAD.discard_prepared_release(prepared)

    def test_versioned_snapshot_keeps_old_a_when_flat_dhcp_changes(self) -> None:
        parent = LOAD.validate_and_publish_release(self.project, self.inputs)
        parent_path = self.project / "99-output-ztp/current-release.json"
        flat = self.ztp / "config/isc-dhcp-server"
        old_conf = (flat / "dhcpd.conf").read_bytes()
        generation = LOAD.stage_pinned_generation(
            self.project, parent_path, flat,
        )
        self.assertEqual(parent["release_id"], generation.name)
        frozen_inputs = {
            name: (generation / "inputs" / name).read_bytes()
            for name in ("global", "devices", "subnet", "p2p")
        }
        self.assertEqual(self.global_file.read_bytes(), frozen_inputs["global"])
        self.assertEqual(self.devices_file.read_bytes(), frozen_inputs["devices"])
        self.assertEqual(self.subnet_file.read_bytes(), frozen_inputs["subnet"])
        self.assertEqual(self.p2p_source.read_bytes(), frozen_inputs["p2p"])
        self.assertFalse((self.project / "99-output-ztp/current").exists())
        (flat / "dhcpd.conf").write_bytes(b"new B in legacy flat output\n")
        self.global_file.write_bytes(b"B global after A snapshot\n")
        self.subnet_file.write_bytes(b"shared_network,subnet\nnet,198.51.100.0\n")
        for name, original in frozen_inputs.items():
            self.assertEqual(original, (generation / "inputs" / name).read_bytes())
        self.assertEqual(old_conf, (generation / "dhcp/dhcpd.conf").read_bytes())
        LOAD.commit_pinned_generation(
            self.project, generation, expected_current=None,
        )
        self.assertEqual(
            f"generations/{parent['release_id']}",
            os.readlink(self.project / "99-output-ztp/current"),
        )
        self.assertEqual(old_conf, (generation / "dhcp/dhcpd.conf").read_bytes())

    def test_existing_a_must_be_frozen_before_b_can_replace_legacy_flat_inputs(self) -> None:
        parent_a = LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project / "99-output-ztp"
        flat = self.ztp / "config/isc-dhcp-server"
        a_global = self.global_file.read_bytes()
        b_global = a_global + b"\n# independently valid B edit\n"
        self.global_file.write_bytes(b_global)
        with self.assertRaises(LOAD.LoadError):
            LOAD.ensure_previous_generation_frozen(self.project)
        self.assertFalse(os.path.lexists(output / "current"))
        self.global_file.write_bytes(a_global)

        selector_target = LOAD.ensure_previous_generation_frozen(self.project)
        self.assertEqual(f"generations/{parent_a['release_id']}", selector_target)
        self.assertEqual(selector_target, os.readlink(output / "current"))
        generation_a = output / selector_target
        self.assertEqual(a_global, (generation_a / "inputs/global").read_bytes())
        self.assertEqual(
            (flat / "dhcpd.conf").read_bytes(),
            (generation_a / "dhcp/dhcpd.conf").read_bytes(),
        )
        self.global_file.write_bytes(b_global)
        self.assertEqual(
            selector_target, LOAD.ensure_previous_generation_frozen(self.project),
        )
        self.assertEqual(a_global, (generation_a / "inputs/global").read_bytes())

    def test_previous_generation_preflight_rejects_dangling_output_authority(self) -> None:
        output = self.project / "99-output-ztp"
        output.symlink_to("missing-authority")
        with self.assertRaises(LOAD.LoadError):
            LOAD.ensure_previous_generation_frozen(self.project)
        self.assertEqual("missing-authority", os.readlink(output))

    def test_previous_generation_preflight_rejects_same_target_selector_replacement(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project / "99-output-ztp"
        flat = self.ztp / "config/isc-dhcp-server"
        generation = LOAD.stage_pinned_generation(
            self.project, output / "current-release.json", flat,
        )
        LOAD.commit_pinned_generation(
            self.project, generation, expected_current=None,
        )
        selector = output / "current"
        old_identity = (selector.lstat().st_dev, selector.lstat().st_ino)
        real_validate = LOAD._pinned_generation_payloads

        def replace_after_validation(*args):
            result = real_validate(*args)
            replacement = output / ".current-same-target-replacement"
            replacement.symlink_to(os.readlink(selector))
            os.replace(replacement, selector)
            return result

        with mock.patch.object(
            LOAD, "_pinned_generation_payloads", side_effect=replace_after_validation,
        ):
            with self.assertRaisesRegex(LOAD.LoadError, "selector changed"):
                LOAD.ensure_previous_generation_frozen(self.project)
        self.assertNotEqual(
            old_identity, (selector.lstat().st_dev, selector.lstat().st_ino),
        )

    def test_generation_commit_rejects_same_target_selector_aba_during_candidate_check(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project / "99-output-ztp"
        flat = self.ztp / "config/isc-dhcp-server"
        generation = LOAD.stage_pinned_generation(
            self.project, output / "current-release.json", flat,
        )
        LOAD.commit_pinned_generation(
            self.project, generation, expected_current=None,
        )
        selector = output / "current"
        target = os.readlink(selector)
        real_validate = LOAD._pinned_generation_payloads

        def replace_during_candidate_check(*args):
            result = real_validate(*args)
            replacement = output / ".current-same-target-replacement"
            replacement.symlink_to(target)
            os.replace(replacement, selector)
            return result

        with mock.patch.object(
            LOAD, "_pinned_generation_payloads",
            side_effect=replace_during_candidate_check,
        ):
            with self.assertRaisesRegex(LOAD.LoadError, "selector changed"):
                LOAD.commit_pinned_generation(
                    self.project, generation, expected_current=target,
                )
        self.assertEqual(target, os.readlink(selector))

    def test_versioned_snapshot_can_freeze_prepared_b_without_selecting_it(self) -> None:
        flat = self.ztp / "config/isc-dhcp-server"
        private = self.project / "99-output-dhcp/.load-dhcp-candidate-0123456789abcdef"
        private.mkdir(parents=True, mode=0o700)
        for name in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
            "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
        ):
            (private / name).write_bytes((flat / name).read_bytes())
        parent = LOAD.validate_and_publish_release(
            self.project, self.inputs, publish=False, dhcp_candidate_dir=private,
        )
        prepared = LOAD.prepare_current_release(
            self.project, parent, dhcp_candidate_dir=private,
        )
        try:
            generation = LOAD.stage_pinned_generation(
                self.project, prepared.temporary, private,
            )
            self.assertEqual(parent["release_id"], generation.name)
            self.assertEqual(
                prepared.temporary.read_bytes(),
                (generation / "current-release.json").read_bytes(),
            )
            self.assertFalse((self.project / "99-output-ztp/current").exists())
            (generation / "dhcp/dhcpd.conf").write_bytes(b"corrupt B snapshot\n")
            with self.assertRaisesRegex(LOAD.LoadError, "pinned DHCP output"):
                LOAD.commit_pinned_generation(
                    self.project, generation, expected_current=None,
                )
            self.assertFalse((self.project / "99-output-ztp/current").exists())
        finally:
            LOAD.discard_prepared_release(prepared)

    def _publish_a_with_runtime_rollback_receipt(self, *, prepare_receipt=True, original_upgrade_policy=None,
                                                qualified_health=False):
        parent = LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project / "99-output-ztp"
        if qualified_health:
            from test_cases.test_ssh_key_preparation_contract import public_line
            published = self.ztp / "config/publickey"
            published.mkdir(parents=True)
            for name, seed in (("laptop.pub", 31), ("mgmt-server.pub", 47)):
                source = self.project / name
                source.write_bytes(public_line("ssh-ed25519", seed, name)); source.chmod(0o644)
                (published / name).symlink_to(os.path.relpath(source.resolve(), published.resolve()))
            record = LOAD.generation_report.build_report(self.project.resolve(), parent,
                published_dir=published.resolve())
            report = LOAD.generation_report.prepare_generation_report(self.project.resolve(), record)
            LOAD.generation_report.commit_prepared_generation_report(report)
        generation = LOAD.stage_pinned_generation(
            self.project, output / "current-release.json",
            self.ztp / "config/isc-dhcp-server" if parent["dhcp_status"] == "enabled" else None,
        )
        LOAD.commit_pinned_generation(
            self.project, generation, expected_current=None,
        )
        runtime_payloads = {
            "ztp-bootstrap_oob.sh": b"A oob bootstrap\n",
            "ztp-bootstrap_oobofoob.sh": b"A oobofoob bootstrap\n",
            "ztp.json": b'{"release":"A"}\n',
        }
        if original_upgrade_policy is not None:
            # Independent literal fixture policies, before receipt publication.
            policies = {
                "disabled": (b'ZTP_UPGRADE_ENABLED="false"\n',) * 2,
                "enabled": (b'ZTP_UPGRADE_ENABLED="true"\n',) * 2,
                "mixed": (b'ZTP_UPGRADE_ENABLED="true"\n', b'ZTP_UPGRADE_ENABLED="false"\n'),
                "duplicate": (b'ZTP_UPGRADE_ENABLED="false"\nZTP_UPGRADE_ENABLED="false"\n',) * 2,
            }
            for name, policy in zip(("ztp-bootstrap_oob.sh", "ztp-bootstrap_oobofoob.sh"),
                                    policies[original_upgrade_policy]):
                runtime_payloads[name] += policy
        for name, content in runtime_payloads.items():
            (self.ztp / name).write_bytes(content)
        publickeys = self.ztp / "config/publickey"
        if not qualified_health:
            publickeys.mkdir(parents=True)
            (publickeys / "laptop.pub").write_bytes(b"A laptop key\n")
            (publickeys / "mgmt-server.pub").write_bytes(b"A management key\n")
        receipt = (LOAD.prepare_runtime_rollback_receipt(self.project, generation)
                   if prepare_receipt else None)
        return parent, generation, receipt

    def _publish_a_with_managed_dhcp_receipt(self):
        root_patch = mock.patch.object(LOAD, "HTTP_ROOT", self.root.resolve())
        root_patch.start()
        self.addCleanup(root_patch.stop)
        document = yaml.safe_load(self.global_file.read_text())
        document["common"]["mgmt"]["http"]["http_root"] = str(self.root.resolve())
        self.global_file.write_text(yaml.safe_dump(document, sort_keys=False))
        _parent, generation, _receipt = self._publish_a_with_runtime_rollback_receipt(prepare_receipt=False)
        published = self.ztp / "config/isc-dhcp-server"
        source = self.project / "99-output-dhcp"
        source.mkdir(exist_ok=True)
        for name in ("dhcp-release-manifest.json", "dhcpd.conf", "dhcpd_eth.hosts",
                     "dhcpd_ib.hosts", "dhcpd_nvl.hosts"):
            leaf = published / name
            (source / name).write_bytes(leaf.read_bytes())
            leaf.unlink()
            leaf.symlink_to(os.path.relpath(source / name, published))
        return generation, LOAD.prepare_runtime_rollback_receipt(self.project, generation)

    def test_runtime_receipt_accepts_only_project_bound_dhcp_publication_links(self):
        generation, receipt = self._publish_a_with_managed_dhcp_receipt()
        record = LOAD._load_runtime_rollback_receipt(self.project, receipt)
        LOAD._verify_rollback_authorities(self.project, record)
        for name, binding in record["unchanged_authorities"]["dhcp"].items():
            self.assertEqual("link", binding["state"])
            self.assertEqual(os.readlink(self.ztp / "config/isc-dhcp-server" / name), binding["target"])
            self.assertEqual(hashlib.sha256((generation / "dhcp" / name).read_bytes()).hexdigest(),
                             binding["sha256"])

    def test_runtime_dhcp_link_same_bytes_new_source_inode_holds(self):
        generation, receipt = self._publish_a_with_managed_dhcp_receipt()
        record = LOAD._load_runtime_rollback_receipt(self.project, receipt)
        source = self.project / "99-output-dhcp/dhcp-release-manifest.json"
        source.rename(source.with_name("operator-retained-manifest"))
        source.write_bytes(source.with_name("operator-retained-manifest").read_bytes())
        before = (receipt / "receipt.json").read_bytes()
        with self.assertRaises(LOAD.LoadError):
            LOAD._verify_rollback_authorities(self.project, record)
        live = self.ztp / "ztp.json"
        live.write_bytes(b"independent partial B must survive DHCP authority HOLD\n")
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", self.root / ".deployment.lock"), \
                mock.patch.object(LOAD, "active_project", return_value=self.project.resolve()), \
                mock.patch.object(LOAD, "active_managed_services", return_value=()):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaises(LOAD.LoadError):
                    LOAD.restore_runtime_rollback_receipt(self.project, receipt,
                        expected_current=f"generations/{generation.name}",
                        deployment_lock_descriptor=descriptor, services_quiesced=True,
                        runtime_backend=SimpleNamespace(name="supervisor"))
            finally:
                LOAD.release_deployment_lock(descriptor)
        self.assertEqual(b"independent partial B must survive DHCP authority HOLD\n", live.read_bytes())
        self.assertEqual(before, (receipt / "receipt.json").read_bytes())

    def test_runtime_dhcp_link_same_target_new_publication_inode_holds(self):
        _generation, receipt = self._publish_a_with_managed_dhcp_receipt()
        record = LOAD._load_runtime_rollback_receipt(self.project, receipt)
        leaf = self.ztp / "config/isc-dhcp-server/dhcpd.conf"
        target = os.readlink(leaf)
        leaf.rename(leaf.with_name("operator-retained-link"))
        leaf.symlink_to(target)
        with self.assertRaises(LOAD.LoadError):
            LOAD._verify_rollback_authorities(self.project, record)

    def test_runtime_dhcp_link_foreign_same_bytes_source_is_not_authority(self):
        _generation, receipt = self._publish_a_with_managed_dhcp_receipt()
        record = LOAD._load_runtime_rollback_receipt(self.project, receipt)
        leaf = self.ztp / "config/isc-dhcp-server/dhcpd.conf"
        foreign = self.root / "foreign-dhcpd.conf"
        foreign.write_bytes(leaf.read_bytes())
        leaf.unlink()
        leaf.symlink_to(os.path.relpath(foreign, leaf.parent))
        with self.assertRaises(LOAD.LoadError):
            LOAD._verify_rollback_authorities(self.project, record)
        self.assertTrue(foreign.is_file())

    def test_runtime_dhcp_source_rebound_during_held_read_holds(self):
        self._assert_runtime_dhcp_source_rebound_during_held_read_holds()

    def test_runtime_dhcp_source_rebound_from_explicit_alias_injects_and_holds(self):
        self._assert_runtime_dhcp_source_rebound_during_held_read_holds(explicit_alias=True)

    def _assert_runtime_dhcp_source_rebound_during_held_read_holds(self, *, explicit_alias=False):
        _generation, receipt = self._publish_a_with_managed_dhcp_receipt()
        record = LOAD._load_runtime_rollback_receipt(self.project, receipt)
        source = self.project / "99-output-dhcp/dhcp-release-manifest.json"
        if explicit_alias:
            alias = self.root / "fixture-project-alias"
            alias.symlink_to(self.project.resolve(strict=True), target_is_directory=True)
            source = alias / "99-output-dhcp/dhcp-release-manifest.json"
            self.assertNotEqual(source, source.resolve(strict=True))
        # The real reader uses the canonical project owner. Resolve only this
        # trusted fixture target before the mutation, so filesystem aliases
        # cannot silently prevent the original new-inode fault injection.
        source = source.resolve(strict=True)
        original = source.stat()
        original_bytes = source.read_bytes()
        real_read = LOAD._read_rollback_regular
        injected = []
        def rebind(path, **kwargs):
            opened = real_read(path, **kwargs)
            if path == source and not injected:
                source.rename(source.with_name("operator-held-original"))
                source.write_bytes(opened[0])
                injected.append(True)
            return opened
        with mock.patch.object(LOAD, "_read_rollback_regular", side_effect=rebind):
            with self.assertRaises(LOAD.LoadError):
                LOAD._verify_rollback_authorities(self.project, record)
        self.assertEqual([True], injected)
        self.assertTrue(source.with_name("operator-held-original").is_file())
        held = source.with_name("operator-held-original")
        self.assertEqual((original.st_dev, original.st_ino),
                         (held.stat().st_dev, held.stat().st_ino))
        self.assertNotEqual(original.st_ino, source.stat().st_ino)
        self.assertEqual(original_bytes, held.read_bytes())
        self.assertEqual(original_bytes, source.read_bytes())

    def test_runtime_dhcp_typed_receipt_rejects_boolean_identity_and_foreign_target(self):
        _generation, receipt = self._publish_a_with_managed_dhcp_receipt()
        path = receipt / "receipt.json"
        original = path.read_bytes()
        for bad in ("boolean", "absolute", "parent", "legacy", "extra"):
            with self.subTest(bad=bad):
                payload = json.loads(original)
                row = payload["unchanged_authorities"]["dhcp"]["dhcpd.conf"]
                if bad == "boolean":
                    row["source_identity"][0] = True
                elif bad == "absolute":
                    row["target"] = str(self.project / "99-output-dhcp/dhcpd.conf")
                elif bad == "parent":
                    row["source_parent_identity"]["path"] = str(self.root)
                elif bad == "legacy":
                    payload["schema_version"] = 2
                else:
                    row["unexpected"] = "not ignored"
                path.write_text(json.dumps(payload))
                with self.assertRaises(LOAD.LoadError):
                    LOAD._load_runtime_rollback_receipt(self.project, receipt)
        path.write_bytes(original)

    def _publish_a_with_managed_key_receipt(self):
        _parent, generation, _receipt = self._publish_a_with_runtime_rollback_receipt(prepare_receipt=False)
        for name, payload in (("laptop.pub", b"A laptop key\n"), ("mgmt-server.pub", b"A management key\n")):
            source = self.project / name
            source.write_bytes(payload)
            leaf = self.ztp / "config/publickey" / name
            leaf.unlink()
            leaf.symlink_to(os.path.relpath(source.resolve(), leaf.parent.resolve()))
        return generation, LOAD.prepare_runtime_rollback_receipt(self.project, generation)

    def test_runtime_receipt_preserves_managed_project_key_link_on_restore(self) -> None:
        generation, receipt = self._publish_a_with_managed_key_receipt()
        leaf = self.ztp / "config/publickey/laptop.pub"
        target = os.readlink(leaf)
        source = self.project / "laptop.pub"
        identity = (source.stat().st_ino, source.read_bytes())
        leaf.unlink()
        leaf.write_bytes(b"partial B flat key\n")
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", self.root / ".deployment.lock"), \
                mock.patch.object(LOAD, "active_project", return_value=self.project.resolve()), \
                mock.patch.object(LOAD, "active_managed_services", return_value=()):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                LOAD.restore_runtime_rollback_receipt(self.project, receipt,
                    expected_current=f"generations/{generation.name}", deployment_lock_descriptor=descriptor,
                    services_quiesced=True, runtime_backend=SimpleNamespace(name="supervisor"))
            finally:
                LOAD.release_deployment_lock(descriptor)
        self.assertTrue(leaf.is_symlink(), "runtime restore flattened SETUP's project key publication")
        self.assertEqual(target, os.readlink(leaf))
        self.assertEqual(identity, (source.stat().st_ino, source.read_bytes()))
        self.assertEqual(b"A laptop key\n", (receipt / "publickeys/laptop.pub").read_bytes())

    def test_runtime_managed_key_source_aba_holds_before_first_restore_write(self) -> None:
        generation, receipt = self._publish_a_with_managed_key_receipt()
        source = self.project / "laptop.pub"
        original = source.stat()
        if sys.platform.startswith("linux"):
            with tempfile.TemporaryDirectory(prefix="load-ctime-7712-") as _ctime_probe_dir:
                _await_fixture_ctime_tick(Path(_ctime_probe_dir) / "probe", original.st_ctime_ns)
        source.write_bytes(b"B laptop key\n")
        source.write_bytes(b"A laptop key\n")
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertEqual(original.st_ino, source.stat().st_ino)
        self.assertNotEqual(original.st_ctime_ns, source.stat().st_ctime_ns)
        live = self.ztp / "ztp.json"
        live.write_bytes(b"partial B must survive source drift\n")
        evidence = (receipt / "receipt.json").read_bytes()
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", self.root / ".deployment.lock"), \
                mock.patch.object(LOAD, "active_project", return_value=self.project.resolve()), \
                mock.patch.object(LOAD, "active_managed_services", return_value=()):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "public key.*source|publickey.*source"):
                    LOAD.restore_runtime_rollback_receipt(self.project, receipt,
                        expected_current=f"generations/{generation.name}", deployment_lock_descriptor=descriptor,
                        services_quiesced=True, runtime_backend=SimpleNamespace(name="supervisor"))
            finally:
                LOAD.release_deployment_lock(descriptor)
        self.assertEqual(b"partial B must survive source drift\n", live.read_bytes())
        self.assertEqual(evidence, (receipt / "receipt.json").read_bytes())

    def test_runtime_receipt_refuses_key_link_outside_owning_project(self) -> None:
        _parent, generation, _receipt = self._publish_a_with_runtime_rollback_receipt(prepare_receipt=False)
        outside = self.root / "foreign.pub"
        outside.write_bytes(b"operator-owned outside key\n")
        leaf = self.ztp / "config/publickey/laptop.pub"
        leaf.unlink()
        leaf.symlink_to(os.path.relpath(outside, leaf.parent))
        with self.assertRaises(LOAD.LoadError):
            LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        self.assertEqual(b"operator-owned outside key\n", outside.read_bytes())
        self.assertTrue(leaf.is_symlink())
        self.assertFalse((self.project / "99-output-ztp/rollback-receipts" / generation.name).exists())

    def test_runtime_receipt_refuses_managed_key_source_alias(self) -> None:
        _parent, generation, _receipt = self._publish_a_with_runtime_rollback_receipt(prepare_receipt=False)
        foreign = self.root / "operator-key.pub"
        foreign.write_bytes(b"operator key must not become rollback authority\n")
        source = self.project / "laptop.pub"
        source.symlink_to(foreign)
        leaf = self.ztp / "config/publickey/laptop.pub"
        leaf.unlink()
        leaf.symlink_to(os.path.relpath(source, leaf.parent))
        with self.assertRaisesRegex(LOAD.LoadError, "public key source"):
            LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        self.assertEqual(b"operator key must not become rollback authority\n", foreign.read_bytes())
        self.assertTrue(source.is_symlink())
        self.assertFalse((self.project / "99-output-ztp/rollback-receipts" / generation.name).exists())

    def test_runtime_managed_key_parent_rebind_holds_before_flat_restore(self) -> None:
        generation, receipt = self._publish_a_with_managed_key_receipt()
        publickeys = self.ztp / "config/publickey"
        original_identity = publickeys.stat().st_ino
        publickeys.rename(publickeys.with_name("original-publickey"))
        publickeys.mkdir()
        (publickeys / "laptop.pub").write_bytes(b"unrelated replacement directory key\n")
        self.assertNotEqual(original_identity, publickeys.stat().st_ino)
        live = self.ztp / "ztp.json"
        live.write_bytes(b"keep partial B before parent rejection\n")
        evidence = (receipt / "receipt.json").read_bytes()
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", self.root / ".deployment.lock"), \
                mock.patch.object(LOAD, "active_project", return_value=self.project.resolve()), \
                mock.patch.object(LOAD, "active_managed_services", return_value=()):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "public key parent"):
                    LOAD.restore_runtime_rollback_receipt(self.project, receipt,
                        expected_current=f"generations/{generation.name}", deployment_lock_descriptor=descriptor,
                        services_quiesced=True, runtime_backend=SimpleNamespace(name="supervisor"))
            finally:
                LOAD.release_deployment_lock(descriptor)
        self.assertEqual(b"keep partial B before parent rejection\n", live.read_bytes())
        self.assertEqual(b"unrelated replacement directory key\n", (publickeys / "laptop.pub").read_bytes())
        self.assertEqual(evidence, (receipt / "receipt.json").read_bytes())

    def test_runtime_plain_key_parent_rebind_holds_before_any_restore_write(self) -> None:
        _parent, generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        keys = self.ztp / "config/publickey"
        original = keys.stat().st_ino
        keys.rename(keys.with_name("original-publickey"))
        keys.mkdir()
        foreign = keys / "operator.pub"
        foreign.write_bytes(b"unrelated directory must not become A restore authority\n")
        self.assertNotEqual(original, keys.stat().st_ino)
        live = self.ztp / "ztp.json"
        live.write_bytes(b"partial B must survive parent rejection\n")
        evidence = (receipt / "receipt.json").read_bytes()
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", self.root / ".deployment.lock"), \
                mock.patch.object(LOAD, "active_project", return_value=self.project.resolve()), \
                mock.patch.object(LOAD, "active_managed_services", return_value=()):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "publickey parent|public key parent"):
                    LOAD.restore_runtime_rollback_receipt(self.project, receipt,
                        expected_current=f"generations/{generation.name}", deployment_lock_descriptor=descriptor,
                        services_quiesced=True, runtime_backend=SimpleNamespace(name="supervisor"))
            finally:
                LOAD.release_deployment_lock(descriptor)
        self.assertEqual(b"partial B must survive parent rejection\n", live.read_bytes())
        self.assertEqual(["operator.pub"], sorted(path.name for path in keys.iterdir()))
        self.assertEqual(b"unrelated directory must not become A restore authority\n", foreign.read_bytes())
        self.assertEqual(evidence, (receipt / "receipt.json").read_bytes())

    def test_runtime_plain_key_receipt_freezes_parent_and_legacy_restore_holds(self) -> None:
        _parent, generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        metadata = receipt / "receipt.json"
        record = json.loads(metadata.read_text())
        keys = (self.ztp / "config/publickey").resolve()
        self.assertEqual(3, record["schema_version"])
        self.assertEqual({"path": str(keys), "dev": keys.stat().st_dev, "ino": keys.stat().st_ino},
                         record["publickey_parent"])
        record["schema_version"] = 1
        record.pop("publickey_parent")
        metadata.write_text(json.dumps(record))
        evidence = metadata.read_bytes()
        live = self.ztp / "ztp.json"
        live.write_bytes(b"legacy receipt does not license restore\n")
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", self.root / ".deployment.lock"), \
                mock.patch.object(LOAD, "active_project", return_value=self.project.resolve()), \
                mock.patch.object(LOAD, "active_managed_services", return_value=()):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "publickey parent|public key parent"):
                    LOAD.restore_runtime_rollback_receipt(self.project, receipt,
                        expected_current=f"generations/{generation.name}", deployment_lock_descriptor=descriptor,
                        services_quiesced=True, runtime_backend=SimpleNamespace(name="supervisor"))
            finally:
                LOAD.release_deployment_lock(descriptor)
        self.assertEqual(b"legacy receipt does not license restore\n", live.read_bytes())
        self.assertEqual(evidence, metadata.read_bytes())

    def test_runtime_plain_key_receipt_parent_reader_rejects_extended_or_invalid_identity(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        metadata = receipt / "receipt.json"
        original = json.loads(metadata.read_text())
        live = self.ztp / "ztp.json"
        live.write_bytes(b"reader cannot authorize a restore write\n")
        for boundary in ("missing", "boolean", "extended"):
            with self.subTest(boundary=boundary):
                record = json.loads(json.dumps(original))
                if boundary == "missing":
                    record.pop("publickey_parent")
                elif boundary == "boolean":
                    record["publickey_parent"]["ino"] = True
                else:
                    record["publickey_parent"]["future_owner"] = "not authority"
                metadata.write_text(json.dumps(record))
                evidence = metadata.read_bytes()
                with self.assertRaises(LOAD.LoadError):
                    LOAD._load_runtime_rollback_receipt(self.project, receipt)
                self.assertEqual(evidence, metadata.read_bytes())
                self.assertEqual(b"reader cannot authorize a restore write\n", live.read_bytes())

    def test_runtime_receipt_creation_parent_rebind_never_publishes_mixed_key_authority(self) -> None:
        _parent, generation, _receipt = self._publish_a_with_runtime_rollback_receipt(prepare_receipt=False)
        keys = self.ztp / "config/publickey"
        payloads = {p.name: p.read_bytes() for p in keys.iterdir()}
        real_write = LOAD._write_rollback_receipt_payload
        injected = []

        def rebind_after_payload(path, payload, mode):
            result = real_write(path, payload, mode)
            if path.parent.name == "publickeys" and not injected:
                injected.append(True)
                keys.rename(keys.with_name("original-publickey"))
                keys.mkdir()
                for name, content in payloads.items():
                    (keys / name).write_bytes(content)
            return result

        with mock.patch.object(LOAD, "_write_rollback_receipt_payload", side_effect=rebind_after_payload):
            with self.assertRaisesRegex(LOAD.LoadError, "public key parent"):
                LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        self.assertTrue(injected)
        self.assertEqual(payloads, {p.name: p.read_bytes() for p in keys.iterdir()})
        self.assertFalse((self.project / "99-output-ztp/rollback-receipts" / generation.name).exists())

    def test_runtime_plain_key_receipt_reuse_refuses_rebound_parent_or_legacy_evidence(self) -> None:
        _parent, generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        metadata = receipt / "receipt.json"
        original = metadata.read_bytes()
        keys = self.ztp / "config/publickey"
        payloads = {p.name: p.read_bytes() for p in keys.iterdir()}
        keys.rename(keys.with_name("original-publickey"))
        keys.mkdir()
        for name, content in payloads.items():
            (keys / name).write_bytes(content)
        with self.assertRaisesRegex(LOAD.LoadError, "public key parent"):
            LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        self.assertEqual(original, metadata.read_bytes())
        record = json.loads(original)
        record["schema_version"] = 1
        record.pop("publickey_parent")
        metadata.write_text(json.dumps(record))
        evidence = metadata.read_bytes()
        with self.assertRaisesRegex(LOAD.LoadError, "public key parent"):
            LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        self.assertEqual(evidence, metadata.read_bytes())

    def test_runtime_managed_key_receipt_rejects_schema_downgrade(self) -> None:
        _generation, receipt = self._publish_a_with_managed_key_receipt()
        metadata = receipt / "receipt.json"
        record = json.loads(metadata.read_text())
        self.assertEqual(3, record["schema_version"])
        record["schema_version"] = 1
        record.pop("publickey_parent")
        metadata.write_text(json.dumps(record))
        evidence = metadata.read_bytes()
        with self.assertRaisesRegex(LOAD.LoadError, "public key binding"):
            LOAD._load_runtime_rollback_receipt(self.project, receipt)
        self.assertEqual(evidence, metadata.read_bytes())

    def test_runtime_key_disappearance_race_never_publishes_incomplete_receipt(self) -> None:
        _parent, generation, _receipt = self._publish_a_with_runtime_rollback_receipt(prepare_receipt=False)
        leaf = self.ztp / "config/publickey/laptop.pub"
        physical_leaf = leaf.resolve()
        real_lstat = Path.lstat
        raced = []

        def replaced_after_missing(path, *args, **kwargs):
            if path == physical_leaf and not raced:
                raced.append(True)
                raise FileNotFoundError("old key leaf disappeared before name was rebound")
            return real_lstat(path, *args, **kwargs)

        with mock.patch.object(LOAD.Path, "lstat", replaced_after_missing):
            with self.assertRaises(LOAD.LoadError):
                LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        self.assertTrue(raced)
        self.assertEqual(b"A laptop key\n", leaf.read_bytes())
        self.assertFalse((self.project / "99-output-ztp/rollback-receipts" / generation.name).exists(),
                         "publication must not precede missing/rebound-key rejection")

    def test_runtime_receipt_snapshot_syncs_payload_and_final_mode(self) -> None:
        source = self.root / "A-input"
        source.write_bytes(b"independent frozen A bytes\n")
        source.chmod(0o640)
        snapshot = self.root / "private-receipt/payload"
        observed = []
        real_fsync = os.fsync

        def observe(descriptor):
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                observed.append((metadata.st_ino, stat.S_IMODE(metadata.st_mode)))
            return real_fsync(descriptor)

        with mock.patch.object(LOAD.os, "fsync", side_effect=observe):
            record = LOAD._snapshot_receipt_file(source, snapshot)
        self.assertEqual([(snapshot.stat().st_ino, 0o640)], observed)
        self.assertEqual(b"independent frozen A bytes\n", snapshot.read_bytes())
        self.assertEqual({"state": "file", "sha256": hashlib.sha256(b"independent frozen A bytes\n").hexdigest(),
                          "mode": 0o640}, record)

    def test_runtime_receipt_root_name_is_synced_before_publication(self) -> None:
        _parent, generation, _receipt = self._publish_a_with_runtime_rollback_receipt(prepare_receipt=False)
        output = (self.project / "99-output-ztp").resolve()
        parent_identity = (output.stat().st_dev, output.stat().st_ino)
        observed = []
        real_fsync, real_rename = os.fsync, os.rename

        def observe(descriptor):
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == parent_identity:
                observed.append("receipt root name durable")
            return real_fsync(descriptor)

        def publish(source, destination):
            if Path(destination).parent == output / "rollback-receipts":
                self.assertEqual(["receipt root name durable"], observed,
                                 "fsync(receipts) alone cannot persist its parent's new name")
            return real_rename(source, destination)

        with mock.patch.object(LOAD.os, "fsync", side_effect=observe), \
                mock.patch.object(LOAD.os, "rename", side_effect=publish):
            receipt = LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        self.assertTrue(receipt.is_dir())

    def test_runtime_receipt_payload_sync_failure_blocks_publication(self) -> None:
        _parent, generation, _receipt = self._publish_a_with_runtime_rollback_receipt(prepare_receipt=False)
        selector = self.project / "99-output-ztp/current"
        before = (selector.lstat().st_ino, os.readlink(selector))
        observed = []
        real_fsync = os.fsync

        def reject_payload(descriptor):
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                observed.append(True)
                raise OSError("independent receipt payload sync fault")
            return real_fsync(descriptor)

        with mock.patch.object(LOAD.os, "fsync", side_effect=reject_payload):
            with self.assertRaisesRegex(OSError, "receipt payload sync fault"):
                LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        self.assertTrue(observed)
        self.assertEqual(before, (selector.lstat().st_ino, os.readlink(selector)))
        receipts = self.project / "99-output-ztp/rollback-receipts"
        self.assertFalse(os.path.lexists(receipts / generation.name))
        self.assertEqual([], list(receipts.iterdir()))

    def test_runtime_file_restore_holds_preexisting_orphan_stage(self):
        target = self.ztp / "independent-runtime-file"
        target.write_bytes(b"independent partial B file\n")
        orphan = target.parent / f".{target.name}.rollback-independent-orphan"
        orphan.symlink_to("independent-absent-evidence")
        before = (target.lstat().st_ino, target.read_bytes(), orphan.lstat().st_ino)
        payload = b"independent frozen A file\n"
        record = {"state": "file", "mode": 0o640, "sha256": hashlib.sha256(payload).hexdigest()}
        with mock.patch.object(os, "replace", wraps=os.replace) as replace:
            with self.assertRaises(LOAD.LoadError):
                LOAD._restore_receipt_file(target, record, payload)
            replace.assert_not_called()
        self.assertEqual(before, (target.lstat().st_ino, target.read_bytes(), orphan.lstat().st_ino))
        self.assertEqual("independent-absent-evidence", os.readlink(orphan))

    def test_runtime_receipt_file_preserves_foreign_stage_before_publish_or_cleanup(self):
        # AP-b (owner 11-03 Q6): the "hold" kind exercised the removed WAL authority guard.
        for kind in ("inode", "bytes"):
            with self.subTest(kind=kind):
                parent = self.root / f"independent-runtime-stage-{kind}"
                parent.mkdir()
                target = parent / "runtime.conf"
                target.write_bytes(b"independent partial B runtime\n")
                before = (target.lstat().st_ino, target.read_bytes())
                payload = b"independent frozen A runtime\n"
                record = {"state": "file", "mode": 0o640,
                          "sha256": hashlib.sha256(payload).hexdigest()}
                sync, injected = os.fsync, []
                held = parent / "independent-held-stage"
                def foreign_stage(fd):
                    result = sync(fd)
                    info = os.fstat(fd)
                    if not injected and stat.S_ISREG(info.st_mode):
                        for stage in parent.glob(f".{target.name}.rollback-*"):
                            if stage.lstat().st_ino == info.st_ino:
                                if kind != "bytes":
                                    stage.rename(held)
                                stage.write_bytes(b"independent foreign stage evidence\n")
                                stage.chmod(0o640)
                                injected.append((stage, stage.lstat().st_ino))
                    return result
                caught = None
                with mock.patch.object(os, "fsync", side_effect=foreign_stage):
                    try:
                        LOAD._restore_receipt_file(target, record, payload)
                    except LOAD.LoadError as exc:
                        caught = exc
                self.assertEqual(1, len(injected), "runtime stage injection boundary not reached")
                self.assertIsInstance(caught, LOAD.LoadError, "foreign runtime stage must HOLD")
                self.assertEqual(before, (target.lstat().st_ino, target.read_bytes()))
                stage, owner = injected[0]
                self.assertTrue(os.path.lexists(stage), "cleanup consumed foreign runtime stage")
                self.assertEqual(owner, stage.lstat().st_ino)
                self.assertEqual(b"independent foreign stage evidence\n", stage.read_bytes())
                if kind != "bytes":
                    self.assertEqual(payload, held.read_bytes())

    def test_runtime_receipt_restore_syncs_mode_and_parent_before_return(self) -> None:
        target = self.root / "runtime-restore.pub"
        payload = b"independent A runtime bytes\n"
        record = {"state": "file", "sha256": hashlib.sha256(payload).hexdigest(), "mode": 0o640}
        observed = []
        real_fsync = os.fsync

        def observe(descriptor):
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                observed.append(("file", stat.S_IMODE(metadata.st_mode)))
            elif (metadata.st_dev, metadata.st_ino) == (target.parent.stat().st_dev, target.parent.stat().st_ino):
                observed.append(("parent", target.exists()))
            return real_fsync(descriptor)

        with mock.patch.object(LOAD.os, "fsync", side_effect=observe):
            LOAD._restore_receipt_file(target, record, payload)
        self.assertEqual([("file", 0o640), ("parent", True)], observed)
        self.assertEqual(payload, target.read_bytes())
        observed.clear()
        with mock.patch.object(LOAD.os, "fsync", side_effect=observe):
            LOAD._restore_receipt_file(target, {"state": "missing"}, None)
        self.assertEqual([("parent", False)], observed)
        observed.clear()
        with mock.patch.object(LOAD.os, "fsync", side_effect=observe):
            LOAD._restore_receipt_file(target, {"state": "missing"}, None)
        self.assertEqual([("parent", False)], observed, "an absent-name retry still needs directory sync")

    def test_runtime_receipt_restore_parent_sync_error_never_reports_success(self) -> None:
        target = self.root / "runtime-sync-error.pub"
        for state in ("file", "missing"):
            with self.subTest(state=state):
                target.write_bytes(b"partial B\n")
                payload = b"A\n" if state == "file" else None
                record = ({"state": "file", "sha256": hashlib.sha256(payload).hexdigest(), "mode": 0o644}
                          if payload is not None else {"state": "missing"})
                real_fsync = os.fsync

                def reject_parent(descriptor):
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        raise OSError("independent parent fsync fault")
                    return real_fsync(descriptor)

                with mock.patch.object(LOAD.os, "fsync", side_effect=reject_parent):
                    with self.assertRaisesRegex(OSError, "parent fsync fault"):
                        LOAD._restore_receipt_file(target, record, payload)

    def test_runtime_receipt_payload_same_inode_aba_is_rejected_before_restore(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        payload = receipt / "files/ztp.json"
        original = payload.stat()
        evidence = payload.read_bytes()
        live = self.ztp / "ztp.json"
        live.write_bytes(b'{"release":"partial-B"}\n')
        before = live.read_bytes()
        real_read = os.read
        observed = []

        def mutate_after_read(descriptor, count):
            result = real_read(descriptor, count)
            opened = os.fstat(descriptor)
            if not observed and (opened.st_dev, opened.st_ino) == (original.st_dev, original.st_ino):
                observed.append(True)
                if sys.platform.startswith("linux"):
                    with tempfile.TemporaryDirectory(prefix="load-ctime-8257-") as _ctime_probe_dir:
                        _await_fixture_ctime_tick(Path(_ctime_probe_dir) / "probe", original.st_ctime_ns)
                payload.write_bytes(b"!" + evidence[1:])
                payload.write_bytes(evidence)
                os.utime(payload, ns=(original.st_atime_ns, original.st_mtime_ns))
                changed = payload.stat()
                self.assertEqual((original.st_ino, original.st_size, original.st_mtime_ns),
                                 (changed.st_ino, changed.st_size, changed.st_mtime_ns))
                self.assertNotEqual(original.st_ctime_ns, changed.st_ctime_ns)
            return result

        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", self.root / ".deployment.lock"), \
                mock.patch.object(LOAD, "active_project", return_value=self.project.resolve()), \
                mock.patch.object(LOAD, "active_managed_services", return_value=()):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with mock.patch.object(LOAD.os, "read", side_effect=mutate_after_read):
                    with self.assertRaisesRegex(LOAD.LoadError, "changed while reading"):
                        LOAD.restore_runtime_rollback_receipt(
                            self.project, receipt,
                            expected_current=os.readlink(self.project / "99-output-ztp/current"),
                            deployment_lock_descriptor=descriptor, services_quiesced=True,
                            runtime_backend=SimpleNamespace(name="supervisor"),
                        )
            finally:
                LOAD.release_deployment_lock(descriptor)
        self.assertTrue(observed, "the actual immutable receipt payload was not read")
        self.assertEqual(evidence, payload.read_bytes())
        self.assertEqual(before, live.read_bytes(), "untrusted receipt authorized a restore write")

    def test_failed_b_generation_can_restore_and_verify_complete_a_runtime_receipt(self) -> None:
        _parent, generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        selector = self.project / "99-output-ztp/current"
        expected_selector = os.readlink(selector)
        old_latest = os.readlink(self.project / "99-output-eth/latest")
        receipt_snapshot = receipt / "files/ztp-bootstrap_oob.sh"
        receipt_identity = (
            receipt_snapshot.lstat().st_dev, receipt_snapshot.lstat().st_ino,
            receipt_snapshot.read_bytes(),
        )

        (self.ztp / "ztp-bootstrap_oob.sh").write_bytes(b"partial B bootstrap\n")
        (self.ztp / "ztp.json").write_bytes(b'{"release":"partial-B"}\n')
        (self.ztp / "config/publickey/laptop.pub").write_bytes(b"partial B key\n")
        (self.ztp / "config/publickey/partial-b.pub").write_bytes(b"partial B extra key\n")
        replacement = self.project / "99-output-eth/.partial-b"
        replacement.mkdir()
        latest = self.project / "99-output-eth/latest"
        latest.unlink()
        latest.symlink_to(replacement.name)

        lock_path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", lock_path), \
                mock.patch.object(
                    LOAD, "active_project", return_value=self.project.resolve(),
                ), mock.patch.object(
                    LOAD, "active_managed_services", return_value=(),
                ):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                LOAD.restore_runtime_rollback_receipt(
                    self.project, receipt, expected_current=expected_selector,
                    deployment_lock_descriptor=descriptor,
                    services_quiesced=True,
                    runtime_backend=SimpleNamespace(name="supervisor"),
                )
            finally:
                LOAD.release_deployment_lock(descriptor)

        self.assertEqual(expected_selector, os.readlink(selector))
        self.assertEqual(old_latest, os.readlink(latest))
        self.assertEqual(
            b"A oob bootstrap\n",
            (self.ztp / "ztp-bootstrap_oob.sh").read_bytes(),
        )
        self.assertEqual(
            b'{"release":"A"}\n', (self.ztp / "ztp.json").read_bytes(),
        )
        self.assertEqual(
            b"A laptop key\n",
            (self.ztp / "config/publickey/laptop.pub").read_bytes(),
        )
        self.assertFalse((self.ztp / "config/publickey/partial-b.pub").exists())
        self.assertEqual(
            (generation / "current-release.json").resolve(),
            (self.project / "99-output-ztp" / expected_selector
             / "current-release.json").resolve(),
        )
        self.assertEqual(
            receipt_identity,
            (receipt_snapshot.lstat().st_dev, receipt_snapshot.lstat().st_ino,
             receipt_snapshot.read_bytes()),
            "post-verify must never rewrite the immutable A receipt",
        )

    def test_incomplete_a_runtime_receipt_fails_before_restoring_or_switching_selector(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        selector = self.project / "99-output-ztp/current"
        expected_selector = os.readlink(selector)
        current = b"partial B bootstrap must remain for audit\n"
        runtime = self.ztp / "ztp-bootstrap_oob.sh"
        runtime.write_bytes(current)
        (receipt / "files/ztp-bootstrap_oob.sh").unlink()

        lock_path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", lock_path), \
                mock.patch.object(
                    LOAD, "active_project", return_value=self.project.resolve(),
                ), mock.patch.object(
                    LOAD, "active_managed_services", return_value=(),
                ):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "rollback receipt.*incomplete"):
                    LOAD.restore_runtime_rollback_receipt(
                        self.project, receipt, expected_current=expected_selector,
                        deployment_lock_descriptor=descriptor,
                        services_quiesced=True,
                        runtime_backend=SimpleNamespace(name="supervisor"),
                    )
            finally:
                LOAD.release_deployment_lock(descriptor)

        self.assertEqual(expected_selector, os.readlink(selector))
        self.assertEqual(current, runtime.read_bytes())

    def test_tampered_a_yaml_tree_blocks_restore_before_runtime_write(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        selector = self.project / "99-output-ztp/current"
        expected_selector = os.readlink(selector)
        runtime = self.ztp / "ztp-bootstrap_oob.sh"
        partial_b = b"partial B remains for audit\n"
        runtime.write_bytes(partial_b)
        release = (self.project / "99-output-eth/latest").resolve(strict=True)
        (release / "leaf01.yaml").write_text("set:\n  tampered: true\n", encoding="utf-8")

        lock_path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", lock_path), \
                mock.patch.object(
                    LOAD, "active_project", return_value=self.project.resolve(),
                ), mock.patch.object(
                    LOAD, "active_managed_services", return_value=(),
                ):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "YAML hash|hash.*YAML"):
                    LOAD.restore_runtime_rollback_receipt(
                        self.project, receipt, expected_current=expected_selector,
                        deployment_lock_descriptor=descriptor,
                        services_quiesced=True,
                        runtime_backend=SimpleNamespace(name="supervisor"),
                    )
            finally:
                LOAD.release_deployment_lock(descriptor)

        self.assertEqual(partial_b, runtime.read_bytes())
        self.assertEqual(expected_selector, os.readlink(selector))

    def test_runtime_rollback_refuses_after_parent_has_advanced_to_b(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        selector = self.project / "99-output-ztp/current"
        expected_selector = os.readlink(selector)
        parent = self.project / "99-output-ztp/current-release.json"
        parent.write_bytes(b'{"schema_version":2,"release_id":"B"}\n')
        before = (self.ztp / "ztp-bootstrap_oob.sh").read_bytes()

        lock_path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", lock_path), \
                mock.patch.object(
                    LOAD, "active_project", return_value=self.project.resolve(),
                ), mock.patch.object(
                    LOAD, "active_managed_services", return_value=(),
                ):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "parent.*A|A.*parent"):
                    LOAD.restore_runtime_rollback_receipt(
                        self.project, receipt, expected_current=expected_selector,
                        deployment_lock_descriptor=descriptor,
                        services_quiesced=True,
                        runtime_backend=SimpleNamespace(name="supervisor"),
                    )
            finally:
                LOAD.release_deployment_lock(descriptor)

        self.assertEqual(expected_selector, os.readlink(selector))
        self.assertEqual(before, (self.ztp / "ztp-bootstrap_oob.sh").read_bytes())

    def test_disabled_dhcp_a_can_be_frozen_and_receipted_without_dhcp_payload(self) -> None:
        disabled = LOAD.replace(
            self.inputs,
            settings=LOAD.replace(self.inputs.settings, dhcp_enabled=False),
        )
        parent = LOAD.validate_and_publish_release(
            self.project, disabled, publish=False,
        )
        self.assertEqual("disabled", parent["dhcp_status"])
        candidate = LOAD.prepare_current_release(self.project, parent)
        try:
            generation = LOAD.stage_pinned_generation(
                self.project, candidate.temporary, None,
            )
        finally:
            LOAD.discard_prepared_release(candidate)
        self.assertFalse((generation / "dhcp").exists())
        LOAD.commit_pinned_generation(
            self.project, generation, expected_current=None,
        )
        for name in (
            "ztp-bootstrap_oob.sh", "ztp-bootstrap_oobofoob.sh", "ztp.json",
        ):
            (self.ztp / name).write_text("disabled A runtime\n", encoding="utf-8")
        publickeys = self.ztp / "config/publickey"
        publickeys.mkdir(parents=True)
        (publickeys / "laptop.pub").write_text("A key\n", encoding="utf-8")
        receipt = LOAD.prepare_runtime_rollback_receipt(
            self.project, generation,
        )
        payload = json.loads((receipt / "receipt.json").read_text())
        self.assertEqual("disabled", payload["dhcp_status"])
        self.assertNotIn("dhcp", payload["unchanged_authorities"])

    def test_runtime_receipt_uses_frozen_a_global_not_mutated_project_b(self) -> None:
        original = yaml.safe_load(self.global_file.read_text(encoding="utf-8"))
        original["common"]["mgmt"]["http"]["http_root"] = str(LOAD.HTTP_ROOT)
        original["common"]["mgmt"]["ztp"]["ztp_url_prefix"] = "/a-prefix"
        self.global_file.write_text(
            yaml.safe_dump(original, sort_keys=False), encoding="utf-8",
        )
        parent = LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project / "99-output-ztp"
        generation = LOAD.stage_pinned_generation(
            self.project, output / "current-release.json",
            self.ztp / "config/isc-dhcp-server",
        )
        LOAD.commit_pinned_generation(
            self.project, generation, expected_current=None,
        )
        for name in LOAD._ROLLBACK_RUNTIME_FILES:
            (self.ztp / name).write_text("A runtime\n", encoding="utf-8")
        publickeys = self.ztp / "config/publickey"
        publickeys.mkdir(parents=True)
        (publickeys / "laptop.pub").write_text("A key\n", encoding="utf-8")

        mutated = yaml.safe_load(self.global_file.read_text(encoding="utf-8"))
        mutated["common"]["mgmt"]["ztp"]["ztp_url_prefix"] = "/partial-b"
        self.global_file.write_text(
            yaml.safe_dump(mutated, sort_keys=False), encoding="utf-8",
        )
        captured = []
        with mock.patch.object(
            LOAD, "snapshot_ztp_prefix_publication",
            side_effect=lambda settings: captured.append(settings.ztp_prefix)
            or LOAD.ZtpPrefixPublicationSnapshot(marker=None, links={}),
        ):
            LOAD.prepare_runtime_rollback_receipt(self.project, generation)

        self.assertEqual(["/a-prefix"], captured)
        self.assertEqual(parent["release_id"], generation.name)

    def test_runtime_receipt_rejects_bad_existing_generation_report(self) -> None:
        _parent, generation, _receipt = self._publish_a_with_runtime_rollback_receipt()
        receipts = self.project / "99-output-ztp/rollback-receipts"
        shutil.rmtree(receipts)
        report = self.project / "99-output-ztp" / LOAD.generation_report.REPORT_NAME
        report.write_text(
            json.dumps({"release_id": "ffffffffffffffffffff"}), encoding="utf-8",
        )

        with self.assertRaisesRegex(LOAD.LoadError, "generation report|report.*A"):
            LOAD.prepare_runtime_rollback_receipt(self.project, generation)
        self.assertFalse(receipts.exists())

    def test_unactivated_prepared_a_does_not_create_runtime_receipt(self) -> None:
        generation = self.project / "99-output-ztp/generations/aaaaaaaaaaaaaaaaaaaa"
        with mock.patch.object(LOAD, "active_project", return_value=None), \
                mock.patch.object(LOAD, "prepare_runtime_rollback_receipt") as prepare:
            receipt = LOAD.prepare_active_runtime_rollback_receipt(
                self.project, "generations/aaaaaaaaaaaaaaaaaaaa",
            )
        self.assertIsNone(receipt)
        prepare.assert_not_called()

    def test_active_other_project_never_reuses_target_receipt(self) -> None:
        other = self.root / "other-project"
        other.mkdir()
        with mock.patch.object(LOAD, "active_project", return_value=other.resolve()), \
                mock.patch.object(LOAD, "prepare_runtime_rollback_receipt") as prepare:
            receipt = LOAD.prepare_active_runtime_rollback_receipt(
                self.project, "generations/aaaaaaaaaaaaaaaaaaaa",
            )
        self.assertIsNone(receipt)
        prepare.assert_not_called()

    def _http_main_public_source_fixture(self):
        """Opt-in positive admission prerequisites, never blanket negative repair.

        Preserve lexical fixture paths and all existing public key bytes/inodes.
        The private Mac exterior stays untouched; only this fixture's explicit
        public directories are prepared before the workflow captures its state.
        """
        root = self.root.resolve(strict=True)
        project = self.project.resolve(strict=True)
        ztp = self.ztp.resolve(strict=True)
        if not project.is_relative_to(root) or ztp.parent != root:
            raise AssertionError("positive HTTP fixture escaped its private root")
        directories = {root, project}
        directories.update(parent for parent in project.parents if parent.is_relative_to(root))
        for path in (ztp, ztp / "config", ztp / "config/publickey",
                     root / "infiniband", root / "infiniband/publickey", root / "image"):
            if os.path.lexists(path):
                directories.add(path)
                directories.update(parent for parent in path.parents if parent.is_relative_to(root))
        for path in sorted(directories, key=lambda value: len(value.parts)):
            before = path.lstat()
            if not stat.S_ISDIR(before.st_mode) or path.resolve(strict=True) != path:
                raise AssertionError("positive HTTP fixture directory is not an actual contained directory")
            path.chmod(0o755)
        from test_cases.test_ssh_key_preparation_contract import public_line
        for name, seed in (("laptop.pub", 31), ("mgmt-server.pub", 47)):
            path = project / name
            if not os.path.lexists(path):
                path.write_bytes(public_line("ssh-ed25519", seed, name))
                path.chmod(0o644)
            before = path.lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != 0o644):
                raise AssertionError("positive HTTP fixture key must already be regular single-link 0644")

    @staticmethod
    def _http_fixture_listxattr():
        """Real local no-follow enumeration for a Linux-shaped test namespace.

        Darwin Python 3.9 may omit os.listxattr. The SDK's actual ABI is
        ssize_t listxattr(const char *, char *, size_t, int), with
        XATTR_NOFOLLOW=0x0001. This is fixture-only, not production ACL support.
        """
        native = getattr(os, "listxattr", None)
        if callable(native):
            return native
        import ctypes
        import errno
        import sys
        if sys.platform != "darwin":
            raise NotImplementedError("real local xattr introspection unavailable")
        operation = ctypes.CDLL(None, use_errno=True).listxattr
        operation.argtypes = (ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
        operation.restype = ctypes.c_ssize_t

        def enumerate_local(path, *, follow_symlinks=True):
            encoded = os.fsencode(path)
            options = 0 if follow_symlinks else 0x0001
            for _attempt in range(4):
                size = operation(encoded, None, 0, options)
                if size < 0:
                    value = ctypes.get_errno()
                    raise OSError(value, os.strerror(value), os.fspath(path))
                if size > 65536:
                    raise OSError(errno.E2BIG, "fixture xattr inventory exceeds bound", os.fspath(path))
                if size == 0:
                    return []
                buffer = ctypes.create_string_buffer(size)
                count = operation(encoded, buffer, size, options)
                if count < 0:
                    value = ctypes.get_errno()
                    if value == errno.ERANGE:
                        continue
                    raise OSError(value, os.strerror(value), os.fspath(path))
                payload = buffer.raw[:count]
                if count > size or not payload.endswith(b"\0"):
                    raise OSError(errno.EIO, "invalid fixture xattr enumeration", os.fspath(path))
                return [os.fsdecode(name) for name in payload[:-1].split(b"\0")]
            raise OSError(errno.ERANGE, "fixture xattr inventory changed repeatedly", os.fspath(path))

        return enumerate_local

    def _http_public_source_fixture(self):
        # The public namespace is real and inside a private fixture; only its
        # exterior ancestors are modelled as Linux root-owned 0755 below.
        self.root = self.root.resolve(strict=True)
        self.project = self.project.resolve(strict=True)
        self.ztp = self.ztp.resolve(strict=True)
        for path in (self.root, self.project.parent, self.project):
            path.chmod(0o755)
        # Independently specified synthetic wire format; never an operator key.
        key_type = b"ssh-ed25519"
        wire = len(key_type).to_bytes(4, "big") + key_type + (32).to_bytes(4, "big") + bytes([31]) * 32
        payload = key_type + b" " + base64.b64encode(wire) + b" fixture\n"
        for name in ("laptop.pub", "mgmt-server.pub"):
            path = self.project / name
            path.write_bytes(payload)
            path.chmod(0o644)
        return payload

    @contextmanager
    def _http_linux_public_ancestor_model(self, *, listxattr=None, module=LOAD):
        # Not Linux/root evidence: model only exterior public ancestor metadata
        # and exterior ACL-free Linux namespace; all interior xattrs stay real.
        namespace = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
        original_lstat, original_fstat, original_open = os.lstat, os.fstat, os.open
        original_close = os.close
        original_listxattr = ReleaseTransactionTests._http_fixture_listxattr()
        exterior_fds = set()
        root = self.root.resolve(strict=True)
        exterior_ancestors = frozenset(root.parents)
        def exterior(path):
            # Only the exact canonical public ancestors visited by the HTTP
            # gate are Linux-shaped. A /var lexical interior, repo directory,
            # foreign sibling, relative dir_fd leaf or fd remains real. Do
            # not resolve an unknown path or assign all outsiders root owner.
            return isinstance(path, (str, os.PathLike)) and Path(path) in exterior_ancestors
        def ancestor(metadata):
            result = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
            result.update(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
            return SimpleNamespace(**result)
        def lstat(path, *args, **kwargs):
            value = original_lstat(path, *args, **kwargs)
            return ancestor(value) if exterior(path) else value
        def open_file(path, *args, **kwargs):
            descriptor = original_open(path, *args, **kwargs)
            if exterior(path): exterior_fds.add(descriptor)
            else: exterior_fds.discard(descriptor)
            return descriptor
        def close_file(descriptor):
            # Never transfer an ancestor label to a subsequently recycled fd,
            # including a later Path/io open outside this module namespace.
            exterior_fds.discard(descriptor)
            return original_close(descriptor)
        namespace.lstat = lstat
        namespace.open = open_file
        namespace.close = close_file
        namespace.fstat = lambda fd: ancestor(original_fstat(fd)) if fd in exterior_fds else original_fstat(fd)
        def attributes(path, *args, **kwargs):
            if exterior(path):
                return []
            return original_listxattr(path, *args, **kwargs)
        namespace.listxattr = listxattr if listxattr is not None else attributes
        # runpy returns a copied dict: use the real gate's __globals__ when
        # modelling a freshly loaded API, not merely its returned api['os'].
        patcher = (mock.patch.dict(module, {"os": namespace}) if isinstance(module, dict)
                   else mock.patch.object(module, "os", namespace))
        with patcher:
            yield namespace

    def test_http_outer_model_preserves_interior_acl_refusal(self):
        self._http_main_public_source_fixture()
        original_listxattr = self._http_fixture_listxattr()
        project = self.project.resolve(strict=True)
        before = (project.lstat().st_ino, project.lstat().st_mode, project.lstat().st_ctime_ns)
        def real_interior_acl(path, *args, **kwargs):
            if Path(path) == project:
                return ["system.posix_acl_access"]
            return original_listxattr(path, *args, **kwargs)
        with mock.patch.object(os, "listxattr", side_effect=real_interior_acl, create=True), \
                self._http_linux_public_ancestor_model():
            with self.assertRaisesRegex(LOAD.LoadError, "ACL requires an explicit"):
                LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
        self.assertEqual(before, (project.lstat().st_ino, project.lstat().st_mode, project.lstat().st_ctime_ns))

    def test_http_outer_model_does_not_grant_root_metadata_to_nonancestor_directory(self):
        self._http_main_public_source_fixture()
        with tempfile.TemporaryDirectory(prefix="http-unrelated-authority-") as temporary:
            unrelated = Path(temporary).resolve(strict=True)
            unrelated.chmod(0o700)
            self.assertNotIn(unrelated, self.root.resolve(strict=True).parents)
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_ctime_ns")
            before = tuple(getattr(unrelated.lstat(), field) for field in fields)
            with self._http_linux_public_ancestor_model() as namespace:
                named = namespace.lstat(unrelated)
                self.assertEqual(0o700, stat.S_IMODE(named.st_mode))
                self.assertEqual(before, tuple(getattr(named, field) for field in fields))
                descriptor = namespace.open(unrelated, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    self.assertEqual(before, tuple(getattr(namespace.fstat(descriptor), field) for field in fields))
                finally:
                    namespace.close(descriptor)
            self.assertEqual(before, tuple(getattr(unrelated.lstat(), field) for field in fields))

    def _http_isolated_public_fixture(self):
        # Own the exterior test ancestor too: never inject into shared /tmp.
        outer = self.root.resolve(strict=True)
        document = yaml.safe_load(self.global_file.read_text())
        self.root = outer / "document-root"
        self.project = self.root / "DAY0-Prepare/customer"
        self.ztp = self.root / "ztp"
        self.project.mkdir(parents=True)
        self.ztp.mkdir()
        self.global_file = self.project / "01-global.yaml"
        document["common"]["mgmt"]["http"]["http_root"] = str(self.root)
        self.global_file.write_text(yaml.safe_dump(document, sort_keys=False))
        self._http_public_source_fixture()
        return outer

    @contextmanager
    def _http_owned_exterior_mutation_model(self, outer, *, security_change=None):
        before = outer.stat()
        injected, acl_reads = [], []
        sibling = outer / ("unrelated-http-sibling-" + str(security_change or "children"))
        with self._http_linux_public_ancestor_model() as namespace:
            old_named, old_held = namespace.lstat, namespace.fstat
            def changed(metadata, *, named):
                if not injected or (metadata.st_dev, metadata.st_ino) != (before.st_dev, before.st_ino):
                    return metadata
                fields = {key: getattr(metadata, key) for key in dir(metadata) if key.startswith("st_")}
                fields.update(st_nlink=before.st_nlink + 1, st_size=before.st_size + 1,
                              st_mtime_ns=before.st_mtime_ns + 1, st_ctime_ns=before.st_ctime_ns + 1)
                if security_change == "owner": fields["st_uid"] = metadata.st_uid + 1000
                if security_change == "group": fields["st_gid"] = metadata.st_gid + 1000
                if security_change == "mode": fields["st_mode"] = metadata.st_mode ^ 0o100
                if security_change == "name-rebind" and named: fields["st_ino"] = before.st_ino + 1
                return SimpleNamespace(**fields)
            def attributes(path, **_kwargs):
                if Path(path) == outer:
                    acl_reads.append(path)
                    if not injected:
                        sibling.mkdir(mode=0o700)
                        injected.append(sibling)
                    elif security_change == "acl":
                        return ["system.posix_acl_access"]
                return []
            namespace.lstat = lambda *args, **kwargs: changed(old_named(*args, **kwargs), named=True)
            namespace.fstat = lambda *args, **kwargs: changed(old_held(*args, **kwargs), named=False)
            namespace.listxattr = attributes
            yield injected, acl_reads

    def test_http_source_exterior_sibling_creation_is_not_permission_or_inode_change(self):
        outer = self._http_isolated_public_fixture()
        with self._http_owned_exterior_mutation_model(outer) as (injected, acl_reads):
            LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
        self.assertEqual([outer / "unrelated-http-sibling-children"], injected)
        self.assertGreaterEqual(len(acl_reads), 2, "exterior ACL absence must be checked twice")
        self.assertEqual(0o755, stat.S_IMODE(self.project.stat().st_mode))

    def test_http_source_exterior_owner_group_mode_name_and_late_acl_changes_still_hold(self):
        outer = self._http_isolated_public_fixture()
        for fault in ("owner", "group", "mode", "name-rebind", "acl"):
            with self.subTest(fault=fault):
                with self._http_owned_exterior_mutation_model(outer, security_change=fault) as (injected, _reads):
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
                self.assertEqual([outer / ("unrelated-http-sibling-" + fault)], injected)

    def test_real_native_load_http_source_sibling_creation_reaches_original_freeze_boundary(self):
        outer = self._http_isolated_public_fixture()
        stdout, stderr = io.StringIO(), io.StringIO()
        with self._http_owned_exterior_mutation_model(outer) as (injected, acl_reads), ExitStack() as stack:
            stack.enter_context(mock.patch.multiple(LOAD, HTTP_ROOT=self.root, ZTP_DIR=self.ztp, MANIFEST=self.ztp / ".setup_manifest", DEPLOYMENT_LOCK=self.root / ".deployment.lock"))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(LOAD, "service_runtime_backend", return_value=SimpleNamespace(name="systemd")))
            stack.enter_context(mock.patch.object(LOAD, "validate_runtime_options"))
            stack.enter_context(mock.patch.object(LOAD, "require_no_pending_dhcp_transaction"))
            stack.enter_context(mock.patch.object(LOAD, "resolve_project", return_value=self.project))
            stack.enter_context(mock.patch.object(LOAD, "sync_marker_present", return_value=False))
            stack.enter_context(mock.patch.object(LOAD, "active_project", return_value=None))
            monitor = stack.enter_context(mock.patch.object(LOAD, "stop_native_ztp_monitors"))
            freeze = stack.enter_context(mock.patch.object(LOAD, "ensure_previous_generation_frozen", side_effect=RuntimeError("independent original freeze boundary reached")))
            later = {name: stack.enter_context(mock.patch.object(LOAD, name, side_effect=AssertionError("beyond independent freeze oracle")))
                     for name in ("initialize_from_template", "prepare_pubkeys", "ensure_management_key", "activate_project", "configure_ztp_prefix_publication", "generate_configs")}
            stack.enter_context(redirect_stdout(stdout)); stack.enter_context(redirect_stderr(stderr))
            result = LOAD.main([str(self.project), "--host-role", "management-server", "--no-upgrade", "--skip-infra"])
        self.assertEqual(1, result, "the independent freeze oracle intentionally ends this safe private workflow")
        self.assertIn("independent original freeze boundary reached", stderr.getvalue())
        self.assertNotIn("held release namespace changed", stderr.getvalue())
        monitor.assert_called_once_with(self.root)
        freeze.assert_called_once_with(self.project)
        for oracle in later.values(): oracle.assert_not_called()
        self.assertEqual([outer / "unrelated-http-sibling-children"], injected)
        self.assertGreaterEqual(len(acl_reads), 2)

    def test_http_source_first_fstat_failure_closes_new_fd_without_losing_reason(self):
        self._http_public_source_fixture()
        opened, closed = [], []
        with self._http_linux_public_ancestor_model() as namespace:
            old_open, old_close = namespace.open, namespace.close
            def open_fd(*args, **kwargs):
                descriptor = old_open(*args, **kwargs); opened.append(descriptor); return descriptor
            def close_fd(descriptor):
                closed.append(descriptor); old_close(descriptor)
            namespace.open, namespace.close = open_fd, close_fd
            namespace.fstat = mock.Mock(side_effect=OSError("independent first fstat failure"))
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "independent first fstat failure"):
                    LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
                self.assertEqual(1, len(opened))
                self.assertEqual(opened, closed)
            finally:
                # Exact private cleanup if the original RED leaks its new FD.
                for descriptor in opened:
                    if descriptor not in closed: os.close(descriptor)

    def test_http_source_close_failure_attempts_every_owned_fd_once_and_preserves_primary_failure(self):
        self._http_public_source_fixture()
        for primary in (False, True):
            with self.subTest(primary=primary):
                opened, closed = [], []
                with self._http_linux_public_ancestor_model() as namespace:
                    old_open, old_close = namespace.open, namespace.close
                    def open_fd(*args, **kwargs):
                        descriptor = old_open(*args, **kwargs); opened.append(descriptor); return descriptor
                    def close_fd(descriptor):
                        closed.append(descriptor); old_close(descriptor)
                        if len(closed) == 1: raise OSError("independent close consumed descriptor")
                    namespace.open, namespace.close = open_fd, close_fd
                    if primary: namespace.listxattr = lambda *_args, **_kwargs: ["system.posix_acl_access"]
                    try:
                        with self.assertRaisesRegex(LOAD.LoadError, "ACL" if primary else "close"):
                            LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
                        self.assertGreater(len(opened), 2)
                        self.assertEqual(list(reversed(opened)), closed)
                        self.assertEqual(len(closed), len(set(closed)), "never retry a consumed descriptor number")
                    finally:
                        for descriptor in opened:
                            if descriptor not in closed: os.close(descriptor)

    def test_http_source_gate_accepts_public_posix_namespace_without_mode_or_byte_writes(self):
        payload = self._http_public_source_fixture()
        paths = [self.root, self.project.parent, self.project, self.project / "laptop.pub", self.project / "mgmt-server.pub"]
        private = self.project / "id_ed25519"
        private.write_bytes(b"private key must not be opened by source admission\n")
        # Establish the full fixture before freezing directory ctime; creating
        # the private sentinel is fixture work, not a mutation by the gate.
        baseline = {p: (p.lstat().st_ino, p.lstat().st_mode, p.lstat().st_ctime_ns) for p in paths}
        with self._http_linux_public_ancestor_model() as namespace:
            namespace.fchmod = mock.Mock(side_effect=AssertionError("no chmod authority"))
            namespace.chown = mock.Mock(side_effect=AssertionError("no chown authority"))
            namespace.read = mock.Mock(side_effect=AssertionError("no private/public bytes needed"))
            LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
            namespace.fchmod.assert_not_called()
            namespace.chown.assert_not_called()
            namespace.read.assert_not_called()
        self.assertEqual(baseline, {p: (p.lstat().st_ino, p.lstat().st_mode, p.lstat().st_ctime_ns) for p in paths})
        self.assertEqual(payload, (self.project / "laptop.pub").read_bytes())
        self.assertEqual(b"private key must not be opened by source admission\n", private.read_bytes())

    def test_http_source_gate_unavailable_acl_introspection_holds_without_permission_repair(self):
        self._http_public_source_fixture()
        paths = (self.root, self.project, self.project / "laptop.pub", self.project / "mgmt-server.pub")
        baseline = {p: (p.lstat().st_ino, p.lstat().st_mode, p.lstat().st_ctime_ns) for p in paths}
        for unavailable in ("missing", "noncallable", "unsupported"):
            with self.subTest(unavailable=unavailable):
                with self._http_linux_public_ancestor_model() as namespace:
                    if unavailable == "missing":
                        del namespace.listxattr
                    elif unavailable == "noncallable":
                        namespace.listxattr = None
                    else:
                        namespace.listxattr = mock.Mock(side_effect=NotImplementedError("ACL introspection unsupported"))
                    namespace.fchmod = mock.Mock(side_effect=AssertionError("no permission repair"))
                    namespace.chown = mock.Mock(side_effect=AssertionError("no owner repair"))
                    with self.assertRaisesRegex(LOAD.LoadError, "ACL|introspection"):
                        LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
                    namespace.fchmod.assert_not_called()
                    namespace.chown.assert_not_called()
                self.assertEqual(baseline, {p: (p.lstat().st_ino, p.lstat().st_mode, p.lstat().st_ctime_ns) for p in paths})

    def test_http_source_gate_rejects_post_acl_directory_ctime_change_with_same_mode(self):
        self._http_public_source_fixture()
        # Deterministic POSIX ACL-race model: changing a named-user ACL can
        # preserve mode bits while changing the directory's inode ctime.
        # It is not an actual Linux setfacl or root witness.
        project_stat = self.project.stat()
        observed_project, injected = [], []
        with self._http_linux_public_ancestor_model() as namespace:
            old_lstat, old_fstat = namespace.lstat, namespace.fstat
            def changed(metadata):
                fields = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
                if injected and (metadata.st_dev, metadata.st_ino) == (project_stat.st_dev, project_stat.st_ino):
                    fields["st_ctime_ns"] = project_stat.st_ctime_ns + 1
                return SimpleNamespace(**fields)
            def acl(path, **_kwargs):
                if Path(path) == self.project:
                    observed_project.append(True)
                    return ["system.posix_acl_access"] if injected else []
                if Path(path) == self.project.parent and not injected:
                    self.assertTrue(observed_project, "establish project ACL read before injection")
                    injected.append(True)
                return []
            namespace.lstat = lambda *args, **kwargs: changed(old_lstat(*args, **kwargs))
            namespace.fstat = lambda *args, **kwargs: changed(old_fstat(*args, **kwargs))
            namespace.listxattr = acl
            with self.assertRaisesRegex(LOAD.LoadError, "changed|rebound|ACL"):
                LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
        self.assertEqual([True], injected)
        self.assertEqual((project_stat.st_ino, project_stat.st_mode, project_stat.st_ctime_ns),
                         (self.project.stat().st_ino, self.project.stat().st_mode, self.project.stat().st_ctime_ns))

    def test_http_source_gate_refuses_private_project_and_public_key_without_repair(self):
        self._http_public_source_fixture()
        for path, mode in ((self.project, 0o700), (self.project / "laptop.pub", 0o600), (self.project / "mgmt-server.pub", 0o600)):
            with self.subTest(path=path.name, mode=mode):
                path.chmod(mode)
                baseline = (path.lstat().st_ino, path.lstat().st_mode, path.lstat().st_ctime_ns)
                with self._http_linux_public_ancestor_model():
                    with self.assertRaisesRegex(LOAD.LoadError, "traversable|0644"):
                        LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
                self.assertEqual(baseline, (path.lstat().st_ino, path.lstat().st_mode, path.lstat().st_ctime_ns))
                path.chmod(0o755 if path.is_dir() else 0o644)

    def test_http_source_gate_refuses_private_or_writable_interior_ancestor(self):
        self._http_public_source_fixture()
        for mode in (0o750, 0o777):
            with self.subTest(mode=mode):
                self.project.parent.chmod(mode)
                with self._http_linux_public_ancestor_model():
                    with self.assertRaisesRegex(LOAD.LoadError, "traversable|writable"):
                        LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
                self.assertEqual(mode, stat.S_IMODE(self.project.parent.stat().st_mode))
        self.project.parent.chmod(0o755)

    def test_http_source_gate_refuses_public_alias_hardlink_and_acl_ambiguity(self):
        payload = self._http_public_source_fixture()
        target = self.project / "laptop.pub"
        target.unlink()
        foreign = self.root / "unrelated.pub"
        foreign.write_bytes(payload)
        foreign.chmod(0o644)
        target.symlink_to(foreign)
        with self._http_linux_public_ancestor_model():
            with self.assertRaisesRegex(LOAD.LoadError, "single-link"):
                LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
        target.unlink()
        os.link(foreign, target)
        with self._http_linux_public_ancestor_model():
            with self.assertRaisesRegex(LOAD.LoadError, "single-link"):
                LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
        target.unlink()
        target.write_bytes(payload)
        target.chmod(0o644)
        with self._http_linux_public_ancestor_model(listxattr=lambda *_a, **_kw: ["system.posix_acl_access"]):
            with self.assertRaisesRegex(LOAD.LoadError, "ACL"):
                LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
        self.assertEqual(payload, foreign.read_bytes())
        self.assertEqual(0o644, stat.S_IMODE(foreign.stat().st_mode))

    def test_http_source_gate_detects_project_permission_change_before_return(self):
        self._http_public_source_fixture()
        injected = []
        def observe(path, **_kwargs):
            if Path(path) == self.project and not injected:
                self.project.chmod(0o700)
                injected.append(True)
            return []
        with self._http_linux_public_ancestor_model(listxattr=observe):
            with self.assertRaisesRegex(LOAD.LoadError, "permission changed"):
                LOAD.require_http_project_source_access(self.project, http_root=self.root, ztp_dir=self.ztp)
        self.assertEqual([True], injected)
        self.assertEqual(0o700, stat.S_IMODE(self.project.stat().st_mode))

    def test_real_native_load_private_http_source_rejects_before_monitor_freeze_or_keys(self):
        self._http_public_source_fixture()
        self.project.chmod(0o700)
        stdout, stderr = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.multiple(LOAD, HTTP_ROOT=self.root, ZTP_DIR=self.ztp, MANIFEST=self.ztp / ".setup_manifest", DEPLOYMENT_LOCK=self.root / ".deployment.lock"))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(LOAD, "service_runtime_backend", return_value=SimpleNamespace(name="systemd")))
            stack.enter_context(mock.patch.object(LOAD, "validate_runtime_options"))
            stack.enter_context(mock.patch.object(LOAD, "require_no_pending_dhcp_transaction"))
            stack.enter_context(mock.patch.object(LOAD, "resolve_project", return_value=self.project))
            stack.enter_context(mock.patch.object(LOAD, "sync_marker_present", return_value=False))
            oracles = {name: stack.enter_context(mock.patch.object(LOAD, name, side_effect=AssertionError("shared/source mutation before admission: " + name)))
                       for name in ("stop_native_ztp_monitors", "ensure_previous_generation_frozen", "initialize_from_template", "prepare_pubkeys", "ensure_management_key", "activate_project", "configure_ztp_prefix_publication", "generate_configs")}
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            result = LOAD.main([str(self.project), "--host-role", "management-server", "--no-upgrade", "--skip-infra"])
        self.assertEqual(1, result)
        self.assertIn("HTTP public source access prewrite gate", stderr.getvalue())
        self.assertIn("traversable", stderr.getvalue())
        for oracle in oracles.values(): oracle.assert_not_called()
        self.assertEqual(0o700, stat.S_IMODE(self.project.stat().st_mode))

    def test_setup_link_restore_preserves_foreign_stage_before_publish_or_cleanup(self):
        # AP-b (owner 11-03 Q6): the "hold" kind exercised the removed WAL authority guard.
        for kind in ("publish",):
            with self.subTest(kind=kind):
                path = self.ztp / f"private-managed-link-{kind}"
                path.symlink_to("independent-Q-target")
                before = (path.lstat().st_ino, os.readlink(path))
                original = Path.symlink_to
                injected = []

                def stage_replaced(stage, raw, *args, **kwargs):
                    result = original(stage, raw, *args, **kwargs)
                    if stage.name.startswith(f".{path.name}.setup-rollback.") and not injected:
                        held = stage.with_name(f"held-original-link-stage-{kind}")
                        stage.rename(held)
                        if kind == "publish":
                            original(stage, "independent-foreign-target")
                        else:
                            stage.write_bytes(b"independent foreign stage evidence\n")
                        injected.append((stage, stage.lstat().st_ino, held))
                    return result

                caught = None
                with mock.patch.object(Path, "symlink_to", stage_replaced):
                    try:
                        LOAD._atomic_restore_setup_link(path, "independent-P-target")
                    except LOAD.LoadError as exc:
                        caught = exc
                self.assertEqual(1, len(injected), "link staging injection was not reached")
                self.assertIsInstance(caught, LOAD.LoadError)
                self.assertEqual(before, (path.lstat().st_ino, os.readlink(path)))
                stage, inode, held = injected[0]
                self.assertTrue(os.path.lexists(stage), "cleanup consumed the foreign stage")
                self.assertEqual(inode, stage.lstat().st_ino)
                self.assertEqual("independent-P-target", os.readlink(held))
                if kind == "publish":
                    self.assertEqual("independent-foreign-target", os.readlink(stage))
                else:
                    self.assertEqual(b"independent foreign stage evidence\n", stage.read_bytes())
                stage.unlink()
                held.unlink()
                path.unlink()  # Only independently identified private fixture objects.

    def test_setup_link_restore_holds_preexisting_orphan_stage(self):
        target = self.ztp / "independent-managed-link"
        target.symlink_to("independent-Q-target")
        orphan = target.parent / f".{target.name}.setup-rollback.independent-orphan"
        orphan.symlink_to("independent-absent-operator-object")
        before = (target.lstat().st_ino, os.readlink(target), orphan.lstat().st_ino)
        with mock.patch.object(LOAD.os, "replace", wraps=os.replace) as replace:
            with self.assertRaises(LOAD.LoadError):
                LOAD._atomic_restore_setup_link(target, "independent-P-target")
            replace.assert_not_called()
        self.assertEqual(before, (target.lstat().st_ino, os.readlink(target), orphan.lstat().st_ino))
        self.assertEqual("independent-absent-operator-object", os.readlink(orphan))

    def test_systemd_service_query_unknown_is_not_stopped(self) -> None:
        for status in (1, 4, 127, -9):
            with self.subTest(status=status):
                runner = mock.Mock(return_value=SimpleNamespace(
                    returncode=status, stdout="", stderr="status unavailable",
                ))
                backend = LOAD.service_runtime_backend(
                    {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=runner,
                )
                with mock.patch.object(LOAD, "runtime_os", return_value="Linux"), \
                        mock.patch.object(LOAD.shutil, "which", return_value="/fixture/systemctl"), \
                        mock.patch.object(LOAD, "_run_subprocess", runner):
                    with self.assertRaisesRegex(LOAD.LoadError, "服务.*cannot determine"):
                        LOAD.active_managed_services(backend, host_role="management-server")
                self.assertEqual("show", runner.call_args.args[0][1])
                self.assertIn("--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job",
                              runner.call_args.args[0])

    def test_systemd_missing_command_is_not_stopped(self) -> None:
        runner = mock.Mock(side_effect=FileNotFoundError("systemctl unavailable"))
        backend = LOAD.service_runtime_backend(
            {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=runner,
        )
        with mock.patch.object(LOAD, "runtime_os", return_value="Linux"), \
                mock.patch.object(LOAD.shutil, "which", return_value=None), \
                mock.patch.object(LOAD, "_run_subprocess", runner):
            with self.assertRaisesRegex(LOAD.LoadError, "服务.*systemctl unavailable"):
                LOAD.active_managed_services(backend, host_role="management-server")

    def test_systemd_service_query_preserves_active_and_inactive_contract(self) -> None:
        runner = mock.Mock(side_effect=[
            SimpleNamespace(returncode=0, stdout="LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\n", stderr=""),
            SimpleNamespace(returncode=0, stdout="LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=23\nControlPID=0\nJob=\n", stderr=""),
        ])
        backend = LOAD.service_runtime_backend(
            {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=runner,
        )
        with mock.patch.object(LOAD, "runtime_os", return_value="Linux"), \
                mock.patch.object(LOAD.shutil, "which", return_value="/fixture/systemctl"), \
                mock.patch.object(LOAD, "_run_subprocess", runner):
            self.assertEqual(("apache2",), LOAD.active_managed_services(
                backend, host_role="management-server",
            ))
        self.assertEqual(["isc-dhcp-server", "apache2"], [
            call.args[0][-1] for call in runner.call_args_list
        ])

    def test_setup_publickey_without_wal_preserves_public_umask_permissions(self) -> None:
        self._exercise_publickey_without_wal_permissions(0o022, 0o755)

    def test_setup_publickey_without_wal_does_not_relax_restrictive_umask(self) -> None:
        self._exercise_publickey_without_wal_permissions(0o077, 0o700)

    def _exercise_publickey_without_wal_permissions(self, mask, mode):
        parent = self.root / "infiniband"
        parent.mkdir(exist_ok=True)
        key = self.project / "operator.pub"
        key.write_bytes(b"independent public key\n")
        original_umask = os.umask(mask)
        try:
            with mock.patch.multiple(SETUP, HTTP_BASE=str(self.root), ZTP=str(self.ztp),
                                     _DRY_RUN=False, _AUTO_YES=True, _LINK_ERRORS=0,
                                     _LINK_TRANSACTION=SETUP._SetupLinkTransaction([]),
                                     _SETUP_SWITCH_WAL_CONTEXT=None):
                SETUP._process_pubkeys(str(self.project))
                for directory in (self.ztp / "config/publickey", parent / "publickey"):
                    self.assertEqual(mode, stat.S_IMODE(directory.stat().st_mode))
        finally:
            os.umask(original_umask)

    def test_existing_receipt_is_not_reused_after_flat_a_drift(self) -> None:
        with self._schema4_real_receipt_producer_for_existing_workflow():
            self._existing_receipt_is_not_reused_after_flat_a_drift()

    def _existing_receipt_is_not_reused_after_flat_a_drift(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        selector_target = os.readlink(self.project / "99-output-ztp/current")
        runtime = self.ztp / "ztp-bootstrap_oob.sh"
        runtime.write_bytes(b"unexpected drift before next load\n")

        with mock.patch.object(
            LOAD, "active_project", return_value=self.project.resolve(),
        ):
            with self.assertRaisesRegex(LOAD.LoadError, "no longer matches A runtime"):
                LOAD.prepare_active_runtime_rollback_receipt(
                    self.project, selector_target,
                )
        self.assertTrue(receipt.is_dir())
        self.assertEqual(b"unexpected drift before next load\n", runtime.read_bytes())

    def test_extended_receipt_tree_is_rejected_before_restore(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        (receipt / "unexpected").write_text("not governed\n", encoding="utf-8")
        runtime = self.ztp / "ztp-bootstrap_oob.sh"
        before = runtime.read_bytes()

        with self.assertRaisesRegex(LOAD.LoadError, "tree.*unknown|unknown.*entries"):
            LOAD._load_runtime_rollback_receipt(self.project, receipt)
        self.assertEqual(before, runtime.read_bytes())

    def test_runtime_rollback_refuses_writes_without_lock_and_quiesced_services(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        selector = self.project / "99-output-ztp/current"
        expected_selector = os.readlink(selector)
        runtime = self.ztp / "ztp-bootstrap_oob.sh"
        runtime.write_bytes(b"partial B remains\n")

        with self.assertRaisesRegex(LOAD.LoadError, "lock.*quiesced|quiesced.*lock"):
            LOAD.restore_runtime_rollback_receipt(
                self.project, receipt, expected_current=expected_selector,
                deployment_lock_descriptor=None, services_quiesced=False,
                runtime_backend=None,
            )

        self.assertEqual(b"partial B remains\n", runtime.read_bytes())
        self.assertEqual(expected_selector, os.readlink(selector))

    def test_runtime_lock_guard_shared_lock_is_not_exclusive_restore_authority(self):
        import fcntl
        path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", path):
            descriptor = LOAD.acquire_deployment_lock(exclusive=False)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                    LOAD._require_runtime_lock_guard(descriptor)
                # A rejected shared descriptor may not be silently upgraded.
                probe = os.open(path, os.O_RDWR)
                try:
                    fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
                finally:
                    os.close(probe)
            finally:
                LOAD.release_deployment_lock(descriptor)

    def test_runtime_lock_guard_foreign_descriptor_cannot_borrow_another_exclusive_owner(self):
        path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", path):
            owner = LOAD.acquire_deployment_lock(exclusive=True)
            foreign = os.open(path, os.O_RDWR)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                    LOAD._require_runtime_lock_guard(foreign)
                LOAD._require_runtime_lock_guard(owner)
                duplicate = os.dup(owner)
                try:
                    LOAD._require_runtime_lock_guard(duplicate)
                finally:
                    os.close(duplicate)
            finally:
                os.close(foreign)
                LOAD.release_deployment_lock(owner)

    def test_runtime_lock_guard_foreign_owner_release_between_probes_is_not_authority(self):
        import fcntl
        import select
        import subprocess
        path = self.root / ".deployment.lock"
        path.write_bytes(b"independent rendezvous lock\n")
        owner = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", "\n".join((
                "import fcntl, os, sys",
                "fd = os.open(sys.argv[1], os.O_RDWR)",
                "fcntl.flock(fd, fcntl.LOCK_EX)",
                "print('HELD', flush=True)",
                "assert sys.stdin.readline().strip() == 'RELEASE'",
                "fcntl.flock(fd, fcntl.LOCK_UN)",
                "print('RELEASED', flush=True)",
                "assert sys.stdin.readline().strip() == 'FINISH'",
                "os.close(fd)",
            )), str(path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        def receive(expected):
            self.assertTrue(select.select([owner.stdout], [], [], 10)[0], expected)
            self.assertEqual(expected + "\n", owner.stdout.readline())
        original_flock = fcntl.flock
        caller = os.open(path, os.O_RDWR)
        rendezvous = []
        def observe_then_release(fd, operation):
            try:
                return original_flock(fd, operation)
            except BlockingIOError:
                if fd != caller and operation == (fcntl.LOCK_SH | fcntl.LOCK_NB):
                    self.assertEqual([], rendezvous)
                    rendezvous.append("foreign EX observed")
                    owner.stdin.write("RELEASE\n")
                    owner.stdin.flush()
                    receive("RELEASED")
                raise
        def observe_current_fd_then_release(fd):
            self.assertEqual(caller, fd)
            payload = original_fdinfo(fd)
            self.assertNotIn(b"lock:", payload, "unlocked caller must not borrow foreign EX row")
            self.assertEqual([], rendezvous)
            rendezvous.append("foreign EX observed")
            owner.stdin.write("RELEASE\n")
            owner.stdin.flush()
            receive("RELEASED")
            return payload
        try:
            receive("HELD")
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(LOAD, "DEPLOYMENT_LOCK", path))
                if LOAD.runtime_os().casefold() == "linux":
                    original_fdinfo = LOAD._read_runtime_lock_fdinfo
                    stack.enter_context(mock.patch.object(LOAD, "_read_runtime_lock_fdinfo", side_effect=observe_current_fd_then_release))
                else:
                    stack.enter_context(mock.patch.object(LOAD.fcntl, "flock", side_effect=observe_then_release))
                with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                    LOAD._require_runtime_lock_guard(caller)
            self.assertEqual(["foreign EX observed"], rendezvous)
            # Rejection must not turn this previously unlocked FD into an EX owner.
            witness = os.open(path, os.O_RDWR)
            try:
                original_flock(witness, fcntl.LOCK_SH | fcntl.LOCK_NB)
            finally:
                os.close(witness)
        finally:
            os.close(caller)
            if owner.poll() is None:
                owner.stdin.write("FINISH\n")
                owner.stdin.flush()
            try:
                owner.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                owner.kill()
                owner.communicate()

    def test_runtime_lock_guard_closed_wrong_inode_and_rebound_name_fail_closed(self):
        path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", path):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                foreign_path = self.root / "not-the-deployment-lock"
                foreign = os.open(foreign_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                        LOAD._require_runtime_lock_guard(foreign)
                finally:
                    os.close(foreign)
                held = self.root / "held-original-deployment-lock"
                payload = path.read_bytes()
                path.rename(held)
                path.write_bytes(payload)
                self.assertNotEqual(held.stat().st_ino, path.stat().st_ino)
                with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                    LOAD._require_runtime_lock_guard(descriptor)
            finally:
                LOAD.release_deployment_lock(descriptor)
            with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                LOAD._require_runtime_lock_guard(descriptor)

    def test_runtime_lock_guard_late_probe_name_rebind_retains_both_owners(self):
        import fcntl
        path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", path):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            original_flock = fcntl.flock
            held = self.root / "held-late-original-lock"
            original_bytes = path.read_bytes()
            fired = []
            def flock(fd, operation):
                try:
                    return original_flock(fd, operation)
                finally:
                    if fd != descriptor and operation == (fcntl.LOCK_SH | fcntl.LOCK_NB) and not fired:
                        fired.append(True)
                        path.rename(held)
                        path.write_bytes(b"independent new lock object\n")
            def fdinfo(fd):
                self.assertEqual(descriptor, fd)
                payload = original_fdinfo(fd)
                if not fired:
                    fired.append(True)
                    path.rename(held)
                    path.write_bytes(b"independent new lock object\n")
                return payload
            try:
                with ExitStack() as stack:
                    if LOAD.runtime_os().casefold() == "linux":
                        original_fdinfo = LOAD._read_runtime_lock_fdinfo
                        stack.enter_context(mock.patch.object(LOAD, "_read_runtime_lock_fdinfo", side_effect=fdinfo))
                    else:
                        stack.enter_context(mock.patch.object(LOAD.fcntl, "flock", side_effect=flock))
                    with self.assertRaisesRegex(LOAD.LoadError, "deployment lock changed"):
                        LOAD._require_runtime_lock_guard(descriptor)
                self.assertEqual([True], fired)
                self.assertEqual(b"independent new lock object\n", path.read_bytes())
                self.assertEqual(os.fstat(descriptor).st_ino, held.stat().st_ino)
                self.assertEqual(original_bytes, held.read_bytes())
                witness = os.open(held, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError): original_flock(witness, fcntl.LOCK_SH | fcntl.LOCK_NB)
                finally:
                    os.close(witness)
            finally:
                LOAD.release_deployment_lock(descriptor)

    def test_runtime_safety_backend_missing_or_nonboolean_quiescence_is_not_inactive(self):
        for backend in (SimpleNamespace(name="supervisor", is_active=lambda _n: False),
                        SimpleNamespace(name="supervisor", is_quiesced=lambda _n: 1)):
            with self.subTest(backend=backend), mock.patch.object(LOAD, "runtime_os", return_value="Linux"):
                with self.assertRaisesRegex(LOAD.LoadError, "stopped-state authority"):
                    LOAD.active_managed_services(backend, host_role="management-server")

    def test_supervisor_quiesce_transitional_processes_requires_post_stop_confirmation(self):
        for initial in ("STARTING", "STOPPING", "BACKOFF", "EXITED", "FATAL"):
            for finish in ("STOPPED", "STOPPING"):
                with self.subTest(initial=initial, finish=finish), mock.patch.object(LOAD, "runtime_os", return_value="Linux"):
                    current = {"apache2": initial}
                    actions = []
                    def command(argv, **kwargs):
                        action, program = argv[1:]
                        if action == "status":
                            observed = current.get(program, "STOPPED")
                            return SimpleNamespace(returncode=0, stdout=program + " " + observed + " witness\n", stderr="")
                        self.assertEqual("stop", action)
                        actions.append(program)
                        current[program] = finish
                        return SimpleNamespace(returncode=0, stdout="stopped request\n", stderr="")
                    backend = LOAD.service_runtime_backend({"HTTP_ZTP_RUNTIME_BACKEND": "supervisor"},
                                                          command_runner=command)
                    if finish == "STOPPED":
                        LOAD.quiesce_services(False, runtime_backend=backend, host_role="management-server")
                    else:
                        with self.assertRaisesRegex(LOAD.LoadError, "not confirmed stopped.*HOLD"):
                            LOAD.quiesce_services(False, runtime_backend=backend, host_role="management-server")
                    self.assertEqual(["apache2"], actions)

    def test_native_quiescence_missing_manager_refuses_before_query_or_service_change(self):
        runner = mock.Mock(side_effect=AssertionError("missing manager may not be queried"))
        backend = LOAD.service_runtime_backend({"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=runner)
        with mock.patch.object(LOAD, "runtime_os", return_value="Linux"), \
                mock.patch.object(LOAD.shutil, "which", return_value=None):
            with self.assertRaisesRegex(LOAD.LoadError, "systemctl.*HOLD"):
                LOAD.quiesce_services(False, runtime_backend=backend, host_role="management-server",
                                      native_monitor_already_quiesced=True)
        runner.assert_not_called()

    def test_runtime_rollback_refuses_while_any_managed_service_is_active(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        selector = self.project / "99-output-ztp/current"
        expected_selector = os.readlink(selector)
        runtime = self.ztp / "ztp-bootstrap_oob.sh"
        runtime.write_bytes(b"partial B remains\n")
        lock_path = self.root / ".deployment.lock"

        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", lock_path), \
                mock.patch.object(
                    LOAD, "active_managed_services", return_value=("apache2",),
                ):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "service.*stopped"):
                    LOAD.restore_runtime_rollback_receipt(
                        self.project, receipt, expected_current=expected_selector,
                        deployment_lock_descriptor=descriptor,
                        services_quiesced=True,
                        runtime_backend=SimpleNamespace(name="supervisor"),
                    )
            finally:
                LOAD.release_deployment_lock(descriptor)

        self.assertEqual(b"partial B remains\n", runtime.read_bytes())

    def test_runtime_rollback_rejects_symlinked_receipt_before_any_write(self) -> None:
        _parent, _generation, receipt = self._publish_a_with_runtime_rollback_receipt()
        selector = self.project / "99-output-ztp/current"
        expected_selector = os.readlink(selector)
        alias = receipt.parent / "ffffffffffffffffffff"
        alias.symlink_to(receipt.name)
        runtime = self.ztp / "ztp-bootstrap_oob.sh"
        before = runtime.read_bytes()
        lock_path = self.root / ".deployment.lock"

        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", lock_path), \
                mock.patch.object(
                    LOAD, "active_project", return_value=self.project.resolve(),
                ), mock.patch.object(
                    LOAD, "active_managed_services", return_value=(),
                ):
            descriptor = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "real directory"):
                    LOAD.restore_runtime_rollback_receipt(
                        self.project, alias, expected_current=expected_selector,
                        deployment_lock_descriptor=descriptor,
                        services_quiesced=True,
                        runtime_backend=SimpleNamespace(name="supervisor"),
                    )
            finally:
                LOAD.release_deployment_lock(descriptor)

        self.assertEqual(before, runtime.read_bytes())
        self.assertEqual(expected_selector, os.readlink(selector))

    def test_selector_explicitly_returns_from_b_to_unchanged_a(self) -> None:
        flat = self.ztp / "config/isc-dhcp-server"
        parent_a = LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project / "99-output-ztp"
        generation_a = LOAD.stage_pinned_generation(
            self.project, output / "current-release.json", flat,
        )
        LOAD.commit_pinned_generation(
            self.project, generation_a, expected_current=None,
        )
        a_conf = (generation_a / "dhcp/dhcpd.conf").read_bytes()

        private_b = self.project / "99-output-dhcp/.load-dhcp-candidate-0123456789abcdef"
        private_b.mkdir(parents=True, mode=0o700)
        for name in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
            "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
        ):
            (private_b / name).write_bytes((flat / name).read_bytes())
        (private_b / "dhcpd.conf").write_bytes(a_conf + b"# B candidate\n")
        manifest_b = json.loads(
            (private_b / "dhcp-release-manifest.json").read_text(encoding="utf-8")
        )
        manifest_b["release_id"] = "candidate-b-child"
        manifest_b["outputs"]["dhcpd.conf"]["sha256"] = sha256(
            private_b / "dhcpd.conf"
        )
        (private_b / "dhcp-release-manifest.json").write_text(
            json.dumps(manifest_b), encoding="utf-8",
        )
        parent_b = LOAD.validate_and_publish_release(
            self.project, self.inputs, publish=False, dhcp_candidate_dir=private_b,
        )
        self.assertNotEqual(parent_a["release_id"], parent_b["release_id"])
        prepared_b = LOAD.prepare_current_release(
            self.project, parent_b, dhcp_candidate_dir=private_b,
        )
        try:
            generation_b = LOAD.stage_pinned_generation(
                self.project, prepared_b.temporary, private_b,
            )
        finally:
            LOAD.discard_prepared_release(prepared_b)
        selector_a = f"generations/{parent_a['release_id']}"
        selector_b = f"generations/{parent_b['release_id']}"
        LOAD.commit_pinned_generation(
            self.project, generation_b, expected_current=selector_a,
        )
        self.assertEqual(selector_b, os.readlink(output / "current"))
        LOAD.commit_pinned_generation(
            self.project, generation_a, expected_current=selector_b,
        )
        self.assertEqual(selector_a, os.readlink(output / "current"))
        self.assertEqual(a_conf, (generation_a / "dhcp/dhcpd.conf").read_bytes())
        self.assertEqual(a_conf, (flat / "dhcpd.conf").read_bytes())

    def test_generation_stage_rebound_directory_is_retained_after_publish(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project.resolve(strict=True) / "99-output-ztp"
        original_parent = (output / "current-release.json").read_bytes()
        real_rename = os.rename
        foreign = []

        def publish_then_rebind(source, destination):
            real_rename(source, destination)
            source = Path(source)
            self.assertEqual(output / "generations", source.parent)
            source.mkdir()
            (source / "foreign-evidence").write_bytes(b"independent staging evidence\n")
            foreign.append((source, source.lstat().st_ino, Path(destination)))

        with mock.patch.object(LOAD.os, "rename", side_effect=publish_then_rebind):
            with self.assertRaises(LOAD.LoadError):
                LOAD.stage_pinned_generation(self.project, output / "current-release.json",
                                             self.ztp / "config/isc-dhcp-server")
        self.assertEqual(1, len(foreign))
        path, inode, installed = foreign[0]
        self.assertTrue(path.is_dir(), "generation cleanup removed a foreign directory")
        self.assertEqual(inode, path.lstat().st_ino)
        self.assertEqual(b"independent staging evidence\n", (path / "foreign-evidence").read_bytes())
        self.assertEqual(original_parent, (installed / "current-release.json").read_bytes())
        self.assertEqual(original_parent, (output / "current-release.json").read_bytes())
        self.assertFalse(os.path.lexists(output / "current"))

    def test_generation_stage_failed_sync_preserves_rebound_directory(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project.resolve(strict=True) / "99-output-ztp"
        real_mkdtemp = tempfile.mkdtemp
        real_sync = os.fsync
        stages = []
        foreign = []

        def capture_stage(*args, **kwargs):
            path = Path(real_mkdtemp(*args, **kwargs))
            stages.append(path)
            return str(path)

        def fail_payload_sync(descriptor):
            if not foreign and stages and stat.S_ISREG(os.fstat(descriptor).st_mode):
                stage = stages[0]
                stage.rename(stage.with_name("independent-held-generation"))
                stage.mkdir()
                (stage / "foreign-evidence").write_bytes(b"independent failed-sync evidence\n")
                foreign.append(stage.lstat().st_ino)
                raise OSError("independent payload sync failure")
            return real_sync(descriptor)

        with mock.patch.object(LOAD.tempfile, "mkdtemp", side_effect=capture_stage), \
                mock.patch.object(LOAD.os, "fsync", side_effect=fail_payload_sync):
            with self.assertRaises((LOAD.LoadError, OSError)):
                LOAD.stage_pinned_generation(self.project, output / "current-release.json",
                                             self.ztp / "config/isc-dhcp-server")
        self.assertEqual(1, len(foreign))
        self.assertTrue(stages[0].is_dir(), "failed staging cleaned up a foreign directory")
        self.assertEqual(foreign[0], stages[0].lstat().st_ino)
        self.assertEqual(b"independent failed-sync evidence\n",
                         (stages[0] / "foreign-evidence").read_bytes())
        self.assertTrue(stages[0].with_name("independent-held-generation").is_dir())
        self.assertFalse(os.path.lexists(output / "current"))

    def test_generation_selector_temp_collision_preserves_foreign_object(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project / "99-output-ztp"
        generation = LOAD.stage_pinned_generation(
            self.project, output / "current-release.json",
            self.ztp / "config/isc-dhcp-server",
        )
        temporary = output / (".current-" + "d" * 32)
        for kind in ("regular", "symlink"):
            with self.subTest(kind=kind):
                if kind == "regular":
                    temporary.write_bytes(b"independent foreign selector evidence\n")
                else:
                    temporary.symlink_to("independent-foreign-target")
                before = temporary.lstat()
                with mock.patch.object(LOAD.secrets, "token_hex", return_value="d" * 32):
                    with self.assertRaises((OSError, LOAD.LoadError)):
                        LOAD.commit_pinned_generation(self.project, generation, expected_current=None)
                self.assertTrue(os.path.lexists(temporary), "collision cleanup deleted a foreign object")
                self.assertEqual((before.st_dev, before.st_ino),
                                 (temporary.lstat().st_dev, temporary.lstat().st_ino))
                if kind == "regular":
                    self.assertEqual(b"independent foreign selector evidence\n", temporary.read_bytes())
                else:
                    self.assertEqual("independent-foreign-target", os.readlink(temporary))
                self.assertFalse(os.path.lexists(output / "current"))
                temporary.unlink()  # Only this test's independently created fixture.

    def test_generation_selector_failed_replace_preserves_rebound_temp(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        output = self.project.resolve(strict=True) / "99-output-ztp"
        generation = LOAD.stage_pinned_generation(
            self.project, output / "current-release.json",
            self.ztp / "config/isc-dhcp-server",
        )
        temporary = output / (".current-" + "e" * 32)
        original = output / "independent-held-selector"
        foreign = []

        def fail_after_rebind(source, destination):
            self.assertEqual(temporary, Path(source))
            self.assertEqual(output / "current", Path(destination))
            temporary.rename(original)
            temporary.write_bytes(b"independent late foreign evidence\n")
            foreign.append(temporary.lstat().st_ino)
            raise OSError("independent publication refused")

        with mock.patch.object(LOAD.secrets, "token_hex", return_value="e" * 32), \
                mock.patch.object(LOAD.os, "replace", side_effect=fail_after_rebind):
            with self.assertRaises((OSError, LOAD.LoadError)):
                LOAD.commit_pinned_generation(self.project, generation, expected_current=None)
        self.assertEqual(1, len(foreign))
        self.assertTrue(os.path.lexists(temporary), "finally deleted a rebound temporary name")
        self.assertEqual(foreign[0], temporary.lstat().st_ino)
        self.assertEqual(b"independent late foreign evidence\n", temporary.read_bytes())
        self.assertEqual(f"generations/{generation.name}", os.readlink(original))
        self.assertFalse(os.path.lexists(output / "current"))

    def test_pinned_generation_final_payload_mode_precedes_file_sync(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        parent_path = self.project / "99-output-ztp/current-release.json"
        flat = self.ztp / "config/isc-dhcp-server"
        synced_modes = []
        real_sync = os.fsync

        def observe_sync(descriptor):
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                synced_modes.append(stat.S_IMODE(metadata.st_mode))
            return real_sync(descriptor)

        original_umask = os.umask(0o077)
        try:
            with mock.patch.object(LOAD.os, "fsync", side_effect=observe_sync):
                generation = LOAD.stage_pinned_generation(self.project, parent_path, flat)
        finally:
            os.umask(original_umask)
        self.assertGreater(len(synced_modes), 1, "real staged payloads were not synced")
        self.assertEqual({0o644}, set(synced_modes), "final payload mode was set only after file sync")
        self.assertFalse(os.path.lexists(self.project / "99-output-ztp/current"))
        self.assertEqual(0o644, stat.S_IMODE((generation / "current-release.json").stat().st_mode))

    def test_pinned_generation_rejects_same_byte_symlink_replacement(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        parent_path = self.project / "99-output-ztp/current-release.json"
        flat = self.ztp / "config/isc-dhcp-server"
        generation = LOAD.stage_pinned_generation(self.project, parent_path, flat)
        selected = generation / "dhcp/dhcpd.conf"
        selected.unlink()
        selected.symlink_to(flat / "dhcpd.conf")
        with self.assertRaisesRegex(LOAD.LoadError, "generation|DHCP child"):
            LOAD.stage_pinned_generation(self.project, parent_path, flat)
        with self.assertRaisesRegex(LOAD.LoadError, "generation|DHCP child"):
            LOAD.commit_pinned_generation(
                self.project, generation, expected_current=None,
            )
        self.assertFalse((self.project / "99-output-ztp/current").exists())

    def test_pinned_generation_rejects_extra_empty_directory(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        parent_path = self.project / "99-output-ztp/current-release.json"
        flat = self.ztp / "config/isc-dhcp-server"
        generation = LOAD.stage_pinned_generation(self.project, parent_path, flat)
        (generation / "unowned-empty").mkdir()
        with self.assertRaisesRegex(LOAD.LoadError, "generation"):
            LOAD.stage_pinned_generation(self.project, parent_path, flat)
        with self.assertRaisesRegex(LOAD.LoadError, "generation"):
            LOAD.commit_pinned_generation(
                self.project, generation, expected_current=None,
            )
        self.assertFalse((self.project / "99-output-ztp/current").exists())

    def _assert_parent_visible_commit_sync_failure_is_not_success(self, boundary):
        parent = self.project / "99-output-ztp/current-release.json"
        parent.parent.mkdir(parents=True, exist_ok=True)
        parent.write_bytes(b'{"release_id":"independent-A"}\n')
        temporary = parent.with_name(".independent-parent-B.json")
        payload = b'{"release_id":"independent-B"}\n'
        temporary.write_bytes(payload)
        candidate = LOAD.PreparedParentRelease(parent, temporary, "independent-B")
        original_open, original_sync = os.open, os.fsync
        parent_inode = parent.parent.stat().st_ino
        injected = []

        def fail_open(path, flags, *args, **kwargs):
            if boundary == "open" and Path(path) == parent.parent:
                injected.append("open")
                raise OSError("independent parent directory open fault")
            return original_open(path, flags, *args, **kwargs)

        def fail_sync(descriptor):
            metadata = os.fstat(descriptor)
            if boundary == "fsync" and stat.S_ISDIR(metadata.st_mode) and metadata.st_ino == parent_inode:
                injected.append("fsync")
                raise OSError("independent parent directory fsync fault")
            return original_sync(descriptor)

        with mock.patch.object(LOAD.os, "open", side_effect=fail_open), \
             mock.patch.object(LOAD.os, "fsync", side_effect=fail_sync):
            with self.assertRaisesRegex(LOAD.LoadError, "持久化.*未确认"):
                LOAD.commit_prepared_release(candidate)
        self.assertEqual([boundary], injected)
        self.assertTrue(candidate.committed, "visible B must not be described as uncommitted A")
        self.assertEqual(payload, parent.read_bytes())
        self.assertFalse(os.path.lexists(temporary))
        LOAD.discard_prepared_release(candidate)
        self.assertEqual(payload, parent.read_bytes(), "cleanup must retain visible B")
        with self.assertRaisesRegex(LOAD.LoadError, "持久化.*未确认"):
            LOAD.commit_prepared_release(candidate)

    def test_parent_visible_commit_directory_open_failure_remains_hold(self):
        self._assert_parent_visible_commit_sync_failure_is_not_success("open")

    def test_parent_visible_commit_directory_fsync_failure_remains_hold(self):
        self._assert_parent_visible_commit_sync_failure_is_not_success("fsync")

    def test_parent_visible_commit_success_returns_only_after_directory_sync(self):
        parent = self.project / "99-output-ztp/current-release.json"
        parent.parent.mkdir(parents=True, exist_ok=True)
        temporary = parent.with_name(".independent-parent-B.json")
        payload = b'{"release_id":"independent-B"}\n'
        temporary.write_bytes(payload)
        candidate = LOAD.PreparedParentRelease(parent, temporary, "independent-B")
        events = []
        real_sync = os.fsync

        def observe_sync(descriptor):
            self.assertTrue(stat.S_ISDIR(os.fstat(descriptor).st_mode))
            self.assertEqual(payload, parent.read_bytes())
            self.assertTrue(candidate.committed)
            events.append("parent-synced")
            return real_sync(descriptor)

        with mock.patch.object(LOAD.os, "fsync", side_effect=observe_sync), \
             mock.patch.object(LOAD, "ok", side_effect=lambda *args: events.append("success")):
            self.assertEqual(parent, LOAD.commit_prepared_release(candidate))
        self.assertEqual(["parent-synced", "success"], events)
        with mock.patch.object(LOAD.os, "replace", side_effect=AssertionError("second replace")), \
             mock.patch.object(LOAD.os, "fsync", side_effect=AssertionError("second sync")):
            self.assertEqual(parent, LOAD.commit_prepared_release(candidate))

    def test_parent_binds_source_and_effective_inventory_independently(self) -> None:
        private = Path(tempfile.mkdtemp(prefix=".load-inventory-", dir=self.project))
        derived = private / "02-devices_config.csv"
        derived.write_bytes(self.devices_file.read_bytes() + b"\n")
        derived.chmod(0o600)
        inputs = LOAD.replace(self.inputs, effective_devices_file=derived,
                              effective_devices_sha256=sha256(derived))
        parent = LOAD.validate_and_publish_release(self.project, inputs, publish=False)
        self.assertEqual(sha256(self.devices_file), parent["inputs"]["devices"])
        self.assertEqual({"path": derived.relative_to(self.project).as_posix(),
                          "sha256": sha256(derived)},
                         parent["generated_inputs"]["effective_devices"])
        candidate = LOAD.prepare_current_release(self.project, parent)
        try:
            self.assertIsNone(candidate.splitter_provenance)
            derived.write_bytes(derived.read_bytes() + b"\n")
            with self.assertRaisesRegex(LOAD.LoadError, "derived inventory.*commit"):
                LOAD.commit_prepared_release(candidate)
            self.assertFalse(candidate.committed)
        finally:
            LOAD.discard_prepared_release(candidate)

    def test_manual_consumes_real_derived_parent_and_rejects_derived_drift(self) -> None:
        private = Path(tempfile.mkdtemp(prefix=".load-inventory-", dir=self.project))
        derived = private / "02-devices_config.csv"
        original = self.devices_file.read_bytes() + b"\n"
        derived.write_bytes(original)
        derived.chmod(0o600)
        inputs = LOAD.replace(self.inputs, effective_devices_file=derived,
                              effective_devices_sha256=sha256(derived))
        LOAD.validate_and_publish_release(self.project, inputs)
        device = {"hostname": "leaf01", "type": "eth", "mac_plain": "020000000001",
                  "identity_macs": {"eth0": "020000000001"}}
        with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST",
                               self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"):
            binding = MANUAL.validate_parent_release_binding(self.project, device)
            self.assertEqual(sha256(derived), binding["effective_devices_sha256"])
            derived.write_bytes(original + b"\n")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "derived inventory"):
                MANUAL.validate_parent_release_binding(self.project, device)
            with self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.verify_prepared_release_binding(binding)
            derived.unlink()
            derived.symlink_to(self.devices_file)
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "derived inventory"):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_manual_derived_authority_rejects_unsafe_paths_before_release_id(self) -> None:
        parent = LOAD.validate_and_publish_release(self.project, self.inputs)
        destination = self.project / "99-output-ztp/current-release.json"
        for path in ("../outside.csv", "/tmp/outside.csv", "./devices.csv"):
            with self.subTest(path=path):
                parent["generated_inputs"] = {"effective_devices": {"path": path, "sha256": "0" * 64}}
                destination.write_text(json.dumps(parent))
                with self.assertRaisesRegex(MANUAL.ManualZtpError, "derived inventory"):
                    MANUAL.validate_parent_release_binding(self.project, {})

    def test_manual_derived_authority_direct_rejects_alias_hardlink_and_writable_file(self) -> None:
        private = self.project / ".load-inventory-direct"
        private.mkdir(mode=0o700)
        source = private / "02-devices_config.csv"
        source.write_bytes(b"independent authority fixture\n")
        source.chmod(0o600)
        declaration = {"effective_devices": {
            "path": ".load-inventory-direct/02-devices_config.csv", "sha256": sha256(source)}}
        self.assertEqual((source.resolve(), sha256(source)),
                         MANUAL.validate_derived_inventory(self.project, declaration))
        source.chmod(0o666)
        with self.assertRaisesRegex(MANUAL.ManualZtpError, "derived inventory"):
            MANUAL.validate_derived_inventory(self.project, declaration)
        source.chmod(0o600)
        hardlink = private / "second-link"
        os.link(source, hardlink)
        with self.assertRaisesRegex(MANUAL.ManualZtpError, "derived inventory"):
            MANUAL.validate_derived_inventory(self.project, declaration)
        hardlink.unlink()
        alias = self.project / ".load-inventory-alias"
        alias.symlink_to(private, target_is_directory=True)
        declaration["effective_devices"]["path"] = ".load-inventory-alias/02-devices_config.csv"
        with self.assertRaisesRegex(MANUAL.ManualZtpError, "derived inventory"):
            MANUAL.validate_derived_inventory(self.project, declaration)

    def test_manual_derived_inventory_exact_producer_contract_direct(self) -> None:
        cases = (
            ("unmanaged/02-devices_config.csv", 0o700, 0o600, b"header\n"),
            (".load-inventory-/02-devices_config.csv", 0o700, 0o600, b"header\n"),
            (".load-inventory-a/inventory.csv", 0o700, 0o600, b"header\n"),
            (".load-inventory-b/02-devices_config.csv", 0o755, 0o600, b"header\n"),
            (".load-inventory-c/02-devices_config.csv", 0o700, 0o644, b"header\n"),
            (".load-inventory-d/02-devices_config.csv", 0o700, 0o400, b"header\n"),
            (".load-inventory-e/02-devices_config.csv", 0o700, 0o600, b""),
        )
        for relative, directory_mode, file_mode, payload in cases:
            with self.subTest(relative=relative):
                source = self.project / relative
                source.parent.mkdir()
                source.parent.chmod(directory_mode)
                source.write_bytes(payload)
                source.chmod(file_mode)
                declaration = {"effective_devices": {"path": relative, "sha256": sha256(source)}}
                with self.assertRaisesRegex(MANUAL.ManualZtpError, "derived inventory"):
                    MANUAL.validate_derived_inventory(self.project, declaration)

    def test_manual_real_parent_rejects_derived_permissions_and_empty_content(self) -> None:
        private = Path(tempfile.mkdtemp(prefix=".load-inventory-", dir=self.project))
        source = private / "02-devices_config.csv"
        source.write_bytes(self.devices_file.read_bytes())
        source.chmod(0o600)
        inputs = LOAD.replace(self.inputs, effective_devices_file=source,
                              effective_devices_sha256=sha256(source))
        LOAD.validate_and_publish_release(self.project, inputs)
        device = {"hostname": "leaf01", "type": "eth", "mac_plain": "020000000001",
                  "identity_macs": {"eth0": "020000000001"}}
        with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST",
                               self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"):
            MANUAL.validate_parent_release_binding(self.project, device)
            for directory_mode, file_mode in ((0o755, 0o600), (0o700, 0o644)):
                with self.subTest(directory_mode=directory_mode, file_mode=file_mode):
                    private.chmod(directory_mode)
                    source.chmod(file_mode)
                    with self.assertRaisesRegex(MANUAL.ManualZtpError, "derived inventory"):
                        MANUAL.validate_parent_release_binding(self.project, device)
            private.chmod(0o700)
            source.chmod(0o600)
            source.write_bytes(b"")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "derived inventory"):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_all_customer_inputs_rechecked_without_derived_or_splitter(self) -> None:
        for key, path in (("global", self.inputs.global_file),
                          ("devices", self.inputs.devices_file),
                          ("subnet", self.inputs.subnet_file),
                          ("p2p", self.inputs.p2p_file)):
            with self.subTest(input=key):
                parent = LOAD.validate_and_publish_release(self.project, self.inputs, publish=False)
                candidate = LOAD.prepare_current_release(self.project, parent)
                self.assertIsNone(candidate.generated_inventory)
                self.assertIsNone(candidate.splitter_provenance)
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"\n")
                    with self.assertRaisesRegex(LOAD.LoadError, "input authority.*before parent commit"):
                        LOAD.commit_prepared_release(candidate)
                    self.assertFalse(candidate.committed)
                finally:
                    path.write_bytes(original)
                    LOAD.discard_prepared_release(candidate)

    def test_optional_air_inputs_rechecked_at_commit_and_new_load_can_rebind(self) -> None:
        policy = self.project / "03-air-topology-policy.json"
        policy.write_text(json.dumps(h19_mini_policy()) + "\n")
        mini = self.project / "04-air-mini-devices.txt"
        mini.write_text("[minimum-required]\nleaf01\n\n[customer-provided]\nleaf01\n")
        inputs = LOAD.replace(self.inputs, air_topology_policy=policy, mini_devices_file=mini)
        previous = LOAD.validate_and_publish_release(self.project, inputs)
        destination = self.project / "99-output-ztp/current-release.json"
        previous_bytes = destination.read_bytes()
        for path in (policy, mini):
            for mutation in ("append", "delete"):
                with self.subTest(path=path.name, mutation=mutation):
                    parent = LOAD.validate_and_publish_release(self.project, inputs, publish=False)
                    candidate = LOAD.prepare_current_release(self.project, parent)
                    original = path.read_bytes()
                    try:
                        if mutation == "delete":
                            path.unlink()
                        else:
                            path.write_bytes(original + b"\n")
                        with self.assertRaisesRegex(LOAD.LoadError, "input authority.*before parent commit"):
                            LOAD.commit_prepared_release(candidate)
                        self.assertEqual(previous_bytes, destination.read_bytes())
                    finally:
                        path.write_bytes(original)
                        LOAD.discard_prepared_release(candidate)
        # Independent next invocation may legitimately accept new customer bytes.
        policy.write_bytes(policy.read_bytes() + b"\n")
        current = LOAD.validate_and_publish_release(self.project, inputs)
        self.assertNotEqual(previous["release_id"], current["release_id"])
        device = {"hostname": "leaf01", "type": "eth", "mac_plain": "020000000001",
                  "identity_macs": {"eth0": "020000000001"}}
        with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST",
                               self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"):
            MANUAL.validate_parent_release_binding(self.project, device)

    def test_component_validation_cannot_adopt_a_new_global_snapshot(self) -> None:
        original_hash = sha256(self.inputs.global_file)
        original_inventory = LOAD._release_inventory
        def mutate_after_snapshot(path):
            result = original_inventory(path)
            with self.inputs.global_file.open("a") as stream:
                stream.write("\n")
            return result
        with mock.patch.object(LOAD, "_release_inventory", side_effect=mutate_after_snapshot):
            parent = LOAD.validate_and_publish_release(self.project, self.inputs, publish=False)
        self.assertEqual(original_hash, parent["inputs"]["global"])
        candidate = LOAD.prepare_current_release(self.project, parent)
        try:
            with self.assertRaisesRegex(LOAD.LoadError, "input authority global.*before parent commit"):
                LOAD.commit_prepared_release(candidate)
        finally:
            LOAD.discard_prepared_release(candidate)

    def test_schema2_parent_requires_complete_input_authority_map_before_prepare(self) -> None:
        parent = LOAD.validate_and_publish_release(self.project, self.inputs, publish=False)
        for kind in ("missing", "empty", "partial", "extra", "wrong_type", "bad_digest"):
            with self.subTest(kind=kind):
                altered = json.loads(json.dumps(parent))
                if kind == "missing":
                    del altered["input_paths"]
                elif kind == "empty":
                    altered["input_paths"] = {}
                elif kind == "partial":
                    del altered["input_paths"]["global"]
                elif kind == "extra":
                    altered["input_paths"]["unexpected"] = "other.csv"
                elif kind == "wrong_type":
                    altered["input_paths"] = []
                else:
                    altered["inputs"]["global"] = "not-a-sha256"
                with self.assertRaisesRegex(LOAD.LoadError, "input authority map"):
                    LOAD.prepare_current_release(self.project, altered)

    def test_source_edit_after_parent_validation_still_blocks_commit(self) -> None:
        private = Path(tempfile.mkdtemp(prefix=".load-inventory-", dir=self.project))
        derived = private / "02-devices_config.csv"
        derived.write_bytes(self.devices_file.read_bytes())
        derived.chmod(0o600)
        inputs = LOAD.replace(self.inputs, effective_devices_file=derived,
                              effective_devices_sha256=sha256(derived))
        parent = LOAD.validate_and_publish_release(self.project, inputs, publish=False)
        candidate = LOAD.prepare_current_release(self.project, parent)
        try:
            with self.devices_file.open("a") as stream:
                stream.write("\n")
            with self.assertRaisesRegex(LOAD.LoadError, "customer source inventory changed"):
                LOAD.commit_prepared_release(candidate)
            self.assertFalse(candidate.committed)
        finally:
            LOAD.discard_prepared_release(candidate)

    def test_parent_commit_rechecks_dhcp_child_manifest_and_outputs(self) -> None:
        previous = LOAD.validate_and_publish_release(self.project, self.inputs)
        destination = self.project / "99-output-ztp/current-release.json"
        previous_bytes = destination.read_bytes()
        dhcp_dir = self.ztp / "config/isc-dhcp-server"
        manifest_path = dhcp_dir / "dhcp-release-manifest.json"
        host_path = dhcp_dir / "dhcpd_eth.hosts"
        for changed in (manifest_path, host_path):
            with self.subTest(changed=changed.name):
                parent = LOAD.validate_and_publish_release(
                    self.project, self.inputs, publish=False,
                )
                candidate = LOAD.prepare_current_release(self.project, parent)
                original = changed.read_bytes()
                try:
                    changed.write_bytes(original + b"\n")
                    with self.assertRaisesRegex(LOAD.LoadError, "DHCP.*(manifest|output|changed)"):
                        LOAD.commit_prepared_release(candidate)
                    self.assertFalse(candidate.committed)
                    self.assertEqual(previous_bytes, destination.read_bytes())
                finally:
                    changed.write_bytes(original)
                    LOAD.discard_prepared_release(candidate)

    def test_dhcp_source_edit_after_staged_syntax_never_installs_or_commits(self) -> None:
        source_dir = self.ztp / "config/isc-dhcp-server"
        live_dir = self.root / "etc-dhcp-source-drift"
        live_dir.mkdir()
        names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
        mappings = {source_dir / name: live_dir / name for name in names}
        original_conf = "".join(
            f'include "/etc/dhcp/{name}";\n' for name in names[1:]
        ).encode("ascii")
        mappings_source = source_dir / "dhcpd.conf"
        mappings_source.write_bytes(original_conf)
        manifest_path = source_dir / "dhcp-release-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["outputs"] = {
            name: {"sha256": sha256(source_dir / name)} for name in names
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        before_live = {}
        for destination in mappings.values():
            destination.write_bytes(f"old:{destination.name}\n".encode("ascii"))
            before_live[destination.name] = destination.read_bytes()
        parent = LOAD.validate_and_publish_release(
            self.project, self.inputs, publish=False,
        )
        candidate = LOAD.prepare_current_release(self.project, parent)
        target = source_dir / "dhcpd_eth.hosts"
        original_host = target.read_bytes()
        checks = []

        def fake_run(command, **_kwargs):
            operation = command[0]
            if operation == "install":
                if "-d" in command:
                    mode = int(command[command.index("-m") + 1], 8)
                    for item in command[command.index("--") + 1:]:
                        Path(item).mkdir(parents=True, exist_ok=True)
                        Path(item).chmod(mode)
                else:
                    shutil.copy2(command[-2], command[-1])
                return
            if operation == "cp":
                shutil.copy2(command[-2], command[-1])
                return
            if operation == "dhcpd":
                checks.append(command[-1])
                if len(checks) == 1:
                    target.write_bytes(original_host + b"# changed after staged syntax\n")
                return
            raise AssertionError(command)

        def fake_cleanup(command, **_kwargs):
            target_path = Path(command[-1])
            if command[0] == "rm":
                target_path.unlink(missing_ok=True)
            elif command[0] == "cp":
                shutil.copy2(command[-2], command[-1])
            elif command[0] == "rmdir":
                target_path.rmdir()
            else:
                raise AssertionError(command)
            return SimpleNamespace(returncode=0)

        try:
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                    mock.patch.object(LOAD, "run", side_effect=fake_run), \
                    mock.patch.object(LOAD, "_run_subprocess", side_effect=fake_cleanup), \
                    self.assertRaises(LOAD.LoadError):
                LOAD.mount_and_test_dhcp(parent_candidate=candidate)
            self.assertFalse(candidate.committed)
            self.assertFalse(candidate.destination.exists())
            self.assertEqual(before_live, {
                destination.name: destination.read_bytes() for destination in mappings.values()
            })
        finally:
            target.write_bytes(original_host)
            LOAD.discard_prepared_release(candidate)

    def test_source_yaml_backed_breakout_needs_no_generator_sidecar(self) -> None:
        """A lossless CSV source receipt bypasses the template splitter input."""
        source = (
            b"- set:\n"
            b"    interface:\n"
            b"      swp9:\n"
            b"        link:\n"
            b"          breakout:\n"
            b"            8x:\n"
            b"              lanes-per-port: 1\n"
        )
        header = list(H04_SCHEMA_V1_HEADER) + [
            "source_yaml_b64", "source_yaml_sha256", "source_fields_sha256",
        ]
        row = [
            "leaf01", "eth", "leaf", "192.0.2.10", "24", "192.0.2.1",
            "02:00:00:00:00:01", "", "", "", "", "198.51.100.10",
        ]
        row += [""] * (len(H04_SCHEMA_V1_HEADER) - len(row))
        fields_digest = hashlib.sha256(json.dumps(
            row, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        row += [
            base64.b64encode(source).decode("ascii"),
            hashlib.sha256(source).hexdigest(), fields_digest,
        ]
        context = GENERATOR._device_csv_header_context(header, 1)
        errors = []
        device = {}
        self.assertTrue(GENERATOR._apply_source_yaml_metadata(
            row, "leaf01", device, context, errors,
        ))
        self.assertEqual([], errors)
        self.assertEqual(source.decode("utf-8"), GENERATOR.render(
            None, {}, "leaf01", device,
        ))
        with self.devices_file.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows([header, row])

        release = (self.project / "99-output-eth/latest").resolve()
        config = release / "leaf01.yaml"
        config.write_bytes(source)
        manifest_path = release / "release-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["devices"][0]["config_sha256"] = sha256(config)
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n",
                                 encoding="utf-8")
        self.assertFalse((self.ztp / "config/cumulus/template/P2P/output-p2p").exists())

        result = LOAD.validate_and_publish_release(self.project, self.inputs)
        self.assertEqual("passed", result["validation"])
        self.assertEqual(source, config.read_bytes())
        current = self.project / "99-output-ztp/current-release.json"
        last_good = current.read_bytes()
        config.write_bytes(source.replace(b"8x:", b"4x:"))
        manifest["devices"][0]["config_sha256"] = sha256(config)
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n",
                                 encoding="utf-8")
        with self.assertRaises(LOAD.LoadError):
            LOAD.validate_and_publish_release(self.project, self.inputs)
        self.assertEqual(last_good, current.read_bytes())

    def test_parent_rejects_splitter_source_changed_after_child_yaml(self) -> None:
        """A valid-looking current sidecar must still agree with published 8x YAML."""
        p2p = self.ztp / "config/cumulus/template/P2P"
        output = p2p / "output-p2p"
        output.mkdir(parents=True)
        (p2p / "p2p.xlsx").symlink_to(self.p2p_source)
        inventory = p2p / "01-inventory.log"
        port_map = p2p / "02-port-mapping.log"
        inventory.write_bytes(b"[Eth-SW]\nleaf01\n")
        port_map.write_bytes(b"1to8#/2/4,swp#s7\n")
        lldpq = output / f"{self.p2p_source.stem}-lldpq.dot"
        lldpq.write_bytes(b'graph "fixture" {}\n')
        sidecar = output / f"{self.p2p_source.stem}-splitter-profiles.json"
        authority = {
            "schema_version": 1,
            "source_workbook": self.p2p_source.name,
            "workbook_sha256": sha256(self.p2p_source),
            "inventory_sha256": sha256(inventory),
            "port_mapping_sha256": sha256(port_map),
            "lldpq_sha256": sha256(lldpq),
            "profiles": [{"device": "leaf01", "parent": "swp9",
                          "profile": "1to8"}],
        }
        sidecar.write_text(json.dumps(authority, sort_keys=True) + "\n",
                           encoding="utf-8")

        release = (self.project / "99-output-eth/latest").resolve()
        config = release / "leaf01.yaml"
        config.write_text(yaml.safe_dump([{"set": {"interface": {"swp9": {
            "link": {"breakout": {"8x": {"lanes-per-port": "1"}}},
        }}}}], sort_keys=True), encoding="utf-8")
        manifest_path = release / "release-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["devices"][0]["config_sha256"] = sha256(config)
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n",
                                 encoding="utf-8")

        positive = LOAD.validate_and_publish_release(self.project, self.inputs)
        self.assertEqual("passed", positive["validation"])
        current = self.project / "99-output-ztp/current-release.json"
        last_good = current.read_bytes()
        sidecar_before = sidecar.read_bytes()
        dot_before = lldpq.read_bytes()
        child_before = config.read_bytes()
        for mutation in ("profile-1to4", "missing-lldpq", "changed-lldpq"):
            with self.subTest(mutation=mutation):
                sidecar.write_bytes(sidecar_before)
                lldpq.write_bytes(dot_before)
                if mutation == "profile-1to4":
                    changed = dict(authority, profiles=[{
                        "device": "leaf01", "parent": "swp9", "profile": "1to4",
                    }])
                    sidecar.write_text(json.dumps(changed, sort_keys=True) + "\n",
                                       encoding="utf-8")
                elif mutation == "missing-lldpq":
                    lldpq.unlink()
                else:
                    lldpq.write_bytes(dot_before + b"changed-after-generator\n")
                with self.assertRaises(LOAD.LoadError):
                    LOAD.validate_and_publish_release(self.project, self.inputs)
                self.assertEqual(last_good, current.read_bytes())
                self.assertEqual(child_before, config.read_bytes())

    def test_setup_publishes_every_nvos_name_that_load_can_select(self) -> None:
        filenames = (
            "nvos-amd64-25.03.1010.bin",
            "nvosv25-03-1010amd64.bin",
        )
        settings = LOAD.replace(
            self.inputs.settings, versions={"ib": "25.03.1010"},
        )
        for filename in filenames:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = root / "DAY0-Prepare/project"
                shared = root / "image"
                ztp = root / "ztp"
                project.mkdir(parents=True)
                image = shared / filename
                write_valid_nvos_image(image)

                with mock.patch.multiple(
                    SETUP,
                    HTTP_BASE=str(root),
                    IMAGE_DIR=str(shared),
                    ZTP=str(ztp),
                    _DRY_RUN=False,
                ), mock.patch.object(LOAD, "IMAGE_DIR", shared):
                    SETUP._process_bin_files()
                    resolved = LOAD.prepare_images(
                        project,
                        LOAD.expected_images(settings, frozenset({"ib"})),
                        quiet=True,
                    )

                published = ztp / "image/nvos" / filename
                self.assertTrue(published.is_symlink())
                self.assertEqual(image.resolve(), published.resolve())
                self.assertEqual(image, resolved["ib"])

    def test_rejects_stale_cumulus_latest(self) -> None:
        manifest = self.project / (
            "99-output-eth/20260830_120000_combine/release-manifest.json"
        )
        data = json.loads(manifest.read_text())
        data["devices"][0]["hostname"] = "old-leaf"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(LOAD.LoadError, "设备清单漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_parent_release_rejects_aliased_manifest_and_marker(self) -> None:
        release = self.project / "99-output-eth/20260830_120000_combine"
        manifest = release / "release-manifest.json"
        manifest_copy = self.root / "manifest-copy.json"
        manifest_copy.write_bytes(manifest.read_bytes())
        manifest.unlink()
        manifest.symlink_to(manifest_copy)
        with self.assertRaisesRegex(LOAD.LoadError, "非符号链接"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        manifest.unlink()
        manifest.write_bytes(manifest_copy.read_bytes())
        marker = release / ".published-complete"
        os.link(marker, self.root / "marker-second-name")
        with self.assertRaisesRegex(LOAD.LoadError, "单硬链接"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_rejects_dhcp_output_modified_after_manifest(self) -> None:
        (self.ztp / "config/isc-dhcp-server/dhcpd.conf").write_text(
            "modified\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(LOAD.LoadError, "输出 hash 漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_parent_rejects_tampered_child_yaml_or_effective_default(self) -> None:
        release = self.project / "99-output-eth/20260830_120000_combine"
        (release / "leaf01.yaml").write_text("set:\n  changed: true\n", encoding="utf-8")
        with self.assertRaisesRegex(LOAD.LoadError, "专属 YAML hash 漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        (release / "leaf01.yaml").write_text("set: {}\n", encoding="utf-8")
        (release / "default.yaml").write_text(
            "- set:\n    changed: true\n", encoding="utf-8",
        )
        with self.assertRaisesRegex(LOAD.LoadError, "effective default hash 漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_parent_rejects_missing_wrong_or_extra_mac_yaml_links(self) -> None:
        release = self.project / "99-output-eth/20260830_120000_combine"
        link = release / "020000000001.yaml"

        link.unlink()
        with self.assertRaisesRegex(LOAD.LoadError, "MAC YAML 链接缺失"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        link.symlink_to("default.yaml")
        with self.assertRaisesRegex(LOAD.LoadError, "MAC YAML 链接目标错误"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        link.unlink()
        link.symlink_to("leaf01.yaml")
        (release / "020000000099.yaml").symlink_to("leaf01.yaml")
        with self.assertRaisesRegex(LOAD.LoadError, "链接集合漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        (release / "020000000099.yaml").unlink()
        (release / "020000000099.yaml").write_text("set: {}\n", encoding="utf-8")
        with self.assertRaisesRegex(LOAD.LoadError, "MAC YAML 入口不是软链接"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_non_dry_skip_generate_is_rejected_before_any_mutation(self) -> None:
        output = mock.mock_open()
        with mock.patch.object(LOAD, "acquire_deployment_lock") as lock, \
                mock.patch.object(LOAD, "quiesce_services") as quiesce, \
                mock.patch.object(LOAD, "activate_project") as activate, \
                mock.patch("builtins.print", output):
            result = LOAD.main([
                str(self.project), "--host-role=workstation", "--skip-generate",
            ])
        self.assertEqual(1, result)
        lock.assert_not_called()
        quiesce.assert_not_called()
        activate.assert_not_called()
        rendered = "\n".join(
            " ".join(str(part) for part in call.args)
            for call in output.mock_calls if call.args
        )
        self.assertIn("--skip-generate 已禁止用于实际 load", rendered)

    def test_air_only_json_identity_is_part_of_parent_release(self) -> None:
        air_json = self.ztp / "config/isc-dhcp-server/p2p-air.json"
        air_json.write_text(json.dumps({
            "content": {"nodes": {
                "AIR-FW01": {
                    "os": "cumulus-vx",
                    "management_interfaces": {
                        "eth0": {"mac_address": "02:00:00:00:00:aa"},
                    },
                },
            }},
        }), encoding="utf-8")
        dhcp_manifest = self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"
        dhcp = json.loads(dhcp_manifest.read_text())
        dhcp["devices"].append({
            "hostname": "AIR-FW01", "type": "air", "interface": "eth0",
            "mac": "02:00:00:00:00:aa", "identity_state": "identified",
        })
        dhcp_manifest.write_text(json.dumps(dhcp), encoding="utf-8")

        release = self.project / "99-output-eth/20260830_120000_combine/release-manifest.json"
        cumulus = json.loads(release.read_text())
        air_yaml = release.parent / "AIR-FW01.yaml"
        air_yaml.write_text(
            "- set:\n    system:\n      hostname: AIR-FW01\n", encoding="utf-8",
        )
        (release.parent / "0200000000aa.yaml").symlink_to("AIR-FW01.yaml")
        cumulus["devices"].append({
            "hostname": "AIR-FW01", "environment": "air",
            "profile": "baseline", "macs": ["02:00:00:00:00:aa"],
            "identity_state": "managed", "config": "AIR-FW01.yaml",
            "config_sha256": sha256(air_yaml),
        })
        release.write_text(json.dumps(cumulus), encoding="utf-8")

        result = LOAD.validate_and_publish_release(self.project, self.inputs)
        identities = {item["hostname"]: item for item in result["inventory"]}
        self.assertEqual(identities["AIR-FW01"]["identity_source"], "air_json")
        self.assertEqual(identities["AIR-FW01"]["eth0_mac"], "02:00:00:00:00:aa")

    def test_manual_preflight_binds_parent_to_the_exact_current_child(self) -> None:
        parent = LOAD.validate_and_publish_release(self.project, self.inputs)
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        with mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST",
            self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
        ):
            binding = MANUAL.validate_parent_release_binding(self.project, device)
            self.assertEqual(parent["release_id"], binding["parent_release_id"])
            self.assertEqual("cumulus-release", binding["child_release_id"])

            # Even a no-content re-publication changes the parent file hash,
            # so an old GUI preview cannot be confirmed across load runs.
            parent_path = self.project / "99-output-ztp/current-release.json"
            republished = json.loads(parent_path.read_text(encoding="utf-8"))
            republished["generated_at"] = "2026-08-30T13:00:00+00:00"
            parent_path.write_text(json.dumps(republished), encoding="utf-8")
            rebound = MANUAL.validate_parent_release_binding(self.project, device)
            self.assertNotEqual(binding["binding_sha256"], rebound["binding_sha256"])

            old_release = self.project / "99-output-eth/20260830_120000_combine"
            other_release = self.project / "99-output-eth/20260830_130000_combine"
            shutil.copytree(old_release, other_release)
            latest = self.project / "99-output-eth/latest"
            latest.unlink()
            latest.symlink_to(other_release.name)
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "不属于同一代"):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_manual_preflight_rejects_inputs_changed_after_parent_commit(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        self.p2p_file.write_text("changed after load\n", encoding="utf-8")
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        with mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST",
            self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
        ), self.assertRaisesRegex(MANUAL.ManualZtpError, "p2p.xlsx 已变化"):
            MANUAL.validate_parent_release_binding(self.project, device)

    def test_manual_preflight_binds_optional_air_policy_from_parent_release(self) -> None:
        policy = self.project / "03-air-topology-policy.json"
        policy.write_text("{}\n", encoding="utf-8")
        inputs = LOAD.replace(self.inputs, air_topology_policy=policy)
        LOAD.validate_and_publish_release(self.project, inputs)
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        with mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST",
            self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
        ):
            MANUAL.validate_parent_release_binding(self.project, device)
            policy.write_text('{"changed": true}\n', encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "AIR.*已变化"):
                MANUAL.validate_parent_release_binding(self.project, device)
            policy.unlink()
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "AIR.*无法读取"):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_parent_and_manual_preflight_bind_mini_air_device_file(self) -> None:
        policy = self.project / "03-air-topology-policy.json"
        policy.write_text(
            json.dumps(h19_mini_policy()) + "\n", encoding="utf-8",
        )
        mini_devices = self.project / "04-air-mini-devices.txt"
        mini_devices.write_text(
            "[minimum-required]\nleaf01\n\n[customer-provided]\nleaf01\n",
            encoding="utf-8",
        )
        inputs = LOAD.replace(
            self.inputs,
            air_topology_policy=policy,
            mini_devices_file=mini_devices,
        )
        parent = LOAD.validate_and_publish_release(self.project, inputs)
        self.assertEqual(
            sha256(policy), parent["inputs"]["air_topology_policy"],
        )
        self.assertEqual(
            sha256(mini_devices), parent["inputs"]["mini_air_devices"],
        )
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        with mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST",
            self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
        ):
            MANUAL.validate_parent_release_binding(self.project, device)
            mini_devices.write_text(
                "[minimum-required]\nleaf01\n\n"
                "[customer-provided]\nleaf02\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MANUAL.ManualZtpError, "mini AIR.*已变化",
            ):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_mini_release_without_project_policy_fails_before_basis_or_publish(self) -> None:
        mini_devices = self.project / "04-air-mini-devices.txt"
        mini_devices.write_text(
            "[minimum-required]\nleaf01\n\n[customer-provided]\nleaf01\n",
            encoding="utf-8",
        )
        current = self.project / "99-output-ztp/current-release.json"
        current.parent.mkdir(parents=True, exist_ok=True)
        original = b'{"release_id":"last-good"}\n'
        current.write_bytes(original)
        inputs = LOAD.replace(
            self.inputs, air_topology_policy=None,
            mini_devices_file=mini_devices,
        )
        basis_serialization_calls = []

        def reject_release_basis_serialization(*args, **kwargs):
            basis_serialization_calls.append((args, kwargs))
            raise AssertionError("release_basis serialization reached")

        with mock.patch.object(
            LOAD.json, "dumps", side_effect=reject_release_basis_serialization,
        ), mock.patch.object(LOAD, "publish_current_release") as publish:
            with self.assertRaisesRegex(
                LOAD.LoadError,
                r"03-air-topology-policy\.json.*mini_sampling",
            ):
                LOAD.validate_and_publish_release(self.project, inputs)
        self.assertEqual([], basis_serialization_calls)
        publish.assert_not_called()
        self.assertEqual(original, current.read_bytes())

        with mock.patch.object(LOAD, "run") as runner:
            with self.assertRaisesRegex(
                LOAD.LoadError,
                r"--mini.*03-air-topology-policy\.json.*mini_sampling",
            ):
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=True,
                    mini_air=True, mini_devices_file=mini_devices,
                    air_topology_policy=None,
                )
        runner.assert_not_called()

    def test_validated_customer_source_allows_canonical_refresh_and_rejects_drift(self) -> None:
        policy = self.project / "03-air-topology-policy.json"
        policy.write_text(
            json.dumps(h19_mini_policy()) + "\n", encoding="utf-8",
        )
        customer = self.project / "customer-mini.txt"
        customer.write_text("moon-crystal-edge-02\n", encoding="utf-8")
        canonical = self.project / "04-air-mini-devices.txt"
        canonical.write_text(
            "[minimum-required]\nstale-node\n\n[customer-provided]\n",
            encoding="utf-8",
        )
        args = SimpleNamespace(
            mini=customer.name, no_upgrade=True, p2p_file=None,
            deployment_scope="all", switch_scope="all",
            ssh_dir=Path("/root/.ssh"), dry_run=True,
            host_role="workstation",
        )
        with mock.patch.object(
            LOAD, "load_global", return_value=self.inputs.settings,
        ), mock.patch.object(
            LOAD, "apply_subnet_service_ips", return_value=self.inputs.settings,
        ), mock.patch.object(
            LOAD, "load_device_types", return_value=frozenset({"eth"}),
        ), mock.patch.object(
            LOAD, "select_p2p", return_value=self.p2p_file,
        ), mock.patch.object(
            LOAD, "validate_subnet_file",
        ), mock.patch.object(
            LOAD, "validate_shared_artifact_receipts",
        ), mock.patch.object(
            LOAD, "prepare_pubkeys", return_value=(),
        ):
            inputs, images = LOAD.validate_inputs(
                self.project, args, allow_management_key_generation=False,
            )
        self.assertEqual({}, images)
        self.assertNotIn("mini_air_devices", inputs.source_identities)
        self.assertEqual(
            sha256(customer),
            inputs.source_identities["mini_air_customer_source"],
        )

        refreshed = (
            "[minimum-required]\nmoon-crystal-edge-01\n\n"
            "[customer-provided]\nmoon-crystal-edge-02\n"
        )

        def refresh_canonical(command, **_kwargs):
            if len(command) > 1 and command[1] == "b-xlsx_to_dot.py":
                canonical.write_text(refreshed, encoding="utf-8")

        with mock.patch.object(
            LOAD, "run", side_effect=refresh_canonical,
        ), mock.patch.object(
            LOAD, "_device_types_after_dhcp", return_value=frozenset(),
        ):
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=False, dry_run=True,
                air_topology_policy=policy, mini_air=True,
                mini_devices_file=customer,
                deployment_scope="air", switch_scope="eth",
                source_identities=inputs.source_identities,
            )
        parent = LOAD.validate_and_publish_release(self.project, inputs)
        self.assertEqual(
            sha256(canonical), parent["inputs"]["mini_air_devices"],
        )

        stable = (
            self.project / "99-output-ztp/current-release.json"
        ).read_bytes()
        customer.write_text("moon-crystal-edge-99\n", encoding="utf-8")
        with self.assertRaisesRegex(
            LOAD.LoadError, r"customer.*changed|customer.*变化",
        ):
            LOAD.validate_and_publish_release(self.project, inputs)
        self.assertEqual(
            stable,
            (self.project / "99-output-ztp/current-release.json").read_bytes(),
        )

    def test_manual_preflight_rejects_aliased_child_release_controls(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        release = self.project / "99-output-eth/20260830_120000_combine"
        manifest = release / "release-manifest.json"
        outside = self.root / "outside-release-manifest.json"
        outside.write_bytes(manifest.read_bytes())
        manifest.unlink()
        manifest.symlink_to(outside)
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        with mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST",
            self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
        ), self.assertRaisesRegex(MANUAL.ManualZtpError, "非符号链接"):
            MANUAL.validate_parent_release_binding(self.project, device)

    def test_manual_preflight_rejects_child_yaml_or_dhcp_output_drift(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        dhcp_manifest = self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"
        with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST", dhcp_manifest):
            yaml_path = self.project / (
                "99-output-eth/20260830_120000_combine/leaf01.yaml"
            )
            yaml_path.write_text("set:\n  changed: true\n", encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "专属 YAML.*未绑定"):
                MANUAL.validate_parent_release_binding(self.project, device)

            yaml_path.write_text("set: {}\n", encoding="utf-8")
            dhcp_conf = dhcp_manifest.parent / "dhcpd.conf"
            dhcp_conf.write_text("out-of-band edit\n", encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "dhcpd.conf.*hash 不一致"):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_preflight_fingerprint_contains_parent_binding_and_rechecks_it(self) -> None:
        parent = LOAD.validate_and_publish_release(self.project, self.inputs)
        device = {
            "hostname": "leaf01", "type": "eth", "ip": "192.0.2.10",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        client = mock.Mock()
        client.args.command_timeout = 10
        client.run.return_value = SimpleNamespace(
            returncode=0, stdout="set: {}\n", stderr="",
        )
        dhcp_manifest = self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"
        with tempfile.TemporaryDirectory() as evidence_dir, mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST", dhcp_manifest,
        ), mock.patch.object(
            MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
        ):
            evidence = MANUAL.preflight_one(
                client, self.project, device, Path(evidence_dir),
            )
            self.assertEqual(parent["release_id"], evidence["parent_release_id"])
            self.assertNotEqual(
                evidence["expected_sha256"], evidence["expected_yaml_sha256"],
            )
            current = self.project / "99-output-ztp/current-release.json"
            changed = json.loads(current.read_text(encoding="utf-8"))
            changed["generated_at"] = "2026-08-30T14:00:00+00:00"
            current.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "绑定文件已变化"):
                MANUAL.verify_prepared_release_binding(evidence)

    def test_global_deployment_lock_excludes_load_and_manual_operations(self) -> None:
        lock_path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", lock_path), mock.patch.object(
            MANUAL, "DEPLOYMENT_LOCK", lock_path,
        ):
            load_lock = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(MANUAL.ManualZtpError, "load 正在切换"):
                    MANUAL.acquire_deployment_lock()
            finally:
                LOAD.release_deployment_lock(load_lock)

            manual_lock = MANUAL.acquire_deployment_lock()
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "另一个 load"):
                    LOAD.acquire_deployment_lock(exclusive=True)
            finally:
                MANUAL.release_deployment_lock(manual_lock)

    def test_visible_parent_sync_failure_retains_private_dhcp_transaction_evidence(self) -> None:
        for boundary in ("open", "fsync"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                project = root / "project"
                project.mkdir()
                assert_private_dhcp_transaction_retention(LOAD, root, project, boundary)

    def test_unconfirmed_parent_reentry_refuses_dhcp_commands_and_retains_first_evidence(self) -> None:
        for boundary in ("open", "fsync"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                project = root / "project"
                project.mkdir()
                assert_private_dhcp_transaction_retention(
                    LOAD, root, project, boundary, reenter=True,
                )

    def test_confirmed_parent_success_cleans_private_dhcp_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            project = root / "project"
            project.mkdir()
            assert_private_dhcp_transaction_retention(LOAD, root, project, "success")

    def test_precommit_rejection_restores_a_and_cleans_private_dhcp_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            project = root / "project"
            project.mkdir()
            assert_private_dhcp_transaction_retention(LOAD, root, project, "precommit")

    def test_failed_dhcp_a_restore_retains_transaction_evidence_and_fences_retry(self) -> None:
        for boundary in ("restore-return", "restore-raise"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as name:
                root, project = Path(name), Path(name) / "project"
                project.mkdir()
                assert_private_dhcp_transaction_retention(LOAD, root, project, boundary)

    def test_successful_copy_with_wrong_a_state_retains_evidence(self) -> None:
        for boundary in ("restore-bytes", "restore-mode", "restore-link"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as name:
                root, project = Path(name), Path(name) / "project"
                project.mkdir()
                assert_private_dhcp_transaction_retention(LOAD, root, project, boundary)

    def test_verified_dhcp_a_restore_preserves_old_link_and_missing_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root, project = Path(name), Path(name) / "project"
            project.mkdir()
            assert_private_dhcp_transaction_retention(LOAD, root, project, "precommit-shapes")

    def test_verified_dhcp_a_restore_sync_failure_retains_evidence(self) -> None:
        for boundary in ("restore-file-sync", "restore-dir-open", "restore-dir-sync"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as name:
                root, project = Path(name), Path(name) / "project"
                project.mkdir()
                assert_private_dhcp_transaction_retention(LOAD, root, project, boundary)

    def test_unverified_dhcp_a_backup_rejects_before_first_b_install(self) -> None:
        for boundary in ("backup-bytes", "backup-mode", "backup-link", "backup-read"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as name:
                root, project = Path(name), Path(name) / "project"
                project.mkdir()
                assert_private_dhcp_transaction_retention(LOAD, root, project, boundary)

    def test_dhcp_a_backup_sync_failure_rejects_before_first_b_install(self) -> None:
        for boundary in ("backup-file-sync", "backup-dir-sync", "backup-transaction-sync", "backup-runtime-sync"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as name:
                root, project = Path(name), Path(name) / "project"
                project.mkdir()
                assert_private_dhcp_transaction_retention(LOAD, root, project, boundary)

    def test_dhcp_persistent_a_preimage_precedes_first_b_write(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root, project = Path(name), Path(name) / "project"
            project.mkdir()
            assert_private_dhcp_transaction_retention(LOAD, root, project, "preimage-before-write")

    def test_dhcp_a_preimage_receipt_sync_failure_holds_original_a(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root, project = Path(name), Path(name) / "project"
            project.mkdir()
            assert_private_dhcp_transaction_retention(LOAD, root, project, "preimage-file-sync")

    def test_dhcp_preimage_receipt_rejects_same_transaction_in_rebound_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            runtime = Path(name).resolve() / "runtime"
            transaction = runtime / ".load-dhcp-transaction-independent"
            backup = transaction / "backup"
            backup.mkdir(parents=True, mode=0o700)
            names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
            states = {}
            for leaf in names:
                path = runtime / leaf
                path.write_bytes(b"independent original A\n")
                shutil.copy2(path, backup / leaf)
                meta = path.stat()
                states[path] = {"state": "file", "mode": stat.S_IMODE(meta.st_mode),
                                "uid": meta.st_uid, "gid": meta.st_gid, "mtime_ns": meta.st_mtime_ns,
                                "size": 23, "sha256": hashlib.sha256(b"independent original A\n").hexdigest()}
            receipt = LOAD._prepare_dhcp_a_preimage_receipt(
                runtime, transaction, states,
                {leaf: hashlib.sha256(b"independent B\n").hexdigest() for leaf in names}, None,
            )
            held = runtime.with_name("held-original-runtime")
            runtime.rename(held)
            runtime.mkdir()
            (held / transaction.name).rename(transaction)
            # Moving its entire containing transaction leaves the receipt file
            # untouched; neither bytes nor inode authorize a new runtime parent.
            with self.assertRaisesRegex(LOAD.LoadError, "preimage.*HOLD"):
                LOAD._verify_dhcp_a_preimage_receipt(receipt)
            self.assertEqual(b"independent original A\n", (held / "dhcpd.conf").read_bytes())
            self.assertEqual(b"independent original A\n", (transaction / "backup/dhcpd.conf").read_bytes())
            self.assertEqual(receipt[1], (transaction / "a-preimage.json").read_bytes())

    def test_dhcp_a_backup_syncs_payloads_and_ancestry_before_b_install(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root, project = Path(name), Path(name) / "project"
            project.mkdir()
            assert_private_dhcp_transaction_retention(LOAD, root, project, "backup-sync-success")

    def test_dhcp_a_backup_sync_rejects_rebound_ancestors_and_closes_fds(self) -> None:
        for boundary in ("runtime", "transaction", "backup"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                live = root / "runtime"
                transaction = live / ".load-dhcp-transaction-independent"
                backup = transaction / "backup"
                backup.mkdir(parents=True, mode=0o700)
                original = live / "dhcpd.conf"
                original.write_bytes(b"independent original A\n")
                shutil.copy2(original, backup / original.name)
                metadata = original.stat()
                expected = {"state": "file", "mode": stat.S_IMODE(metadata.st_mode),
                            "uid": metadata.st_uid, "gid": metadata.st_gid,
                            "mtime_ns": metadata.st_mtime_ns, "size": 23,
                            "sha256": hashlib.sha256(b"independent original A\n").hexdigest()}
                target = {"runtime": live, "transaction": transaction, "backup": backup}[boundary]
                retained = target.with_name(target.name + "-retained")
                real_open, opened, injected = os.open, [], []

                def rebound_open(path, flags, *args, **kwargs):
                    if not injected and ((boundary == "runtime" and Path(path) == target)
                                         or (boundary != "runtime" and Path(path) == Path(target.name))):
                        target.rename(retained)
                        target.mkdir(mode=0o700)
                        (target / "operator-sentinel").write_bytes(b"unknown replacement\n")
                        injected.append(boundary)
                    descriptor = real_open(path, flags, *args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                with mock.patch.object(LOAD.os, "open", side_effect=rebound_open), \
                        mock.patch.object(LOAD.os, "fsync") as sync:
                    with self.assertRaisesRegex(LOAD.LoadError, "DHCP A backup durability unconfirmed"):
                        LOAD._sync_verified_dhcp_a_backup(live, backup, {original: expected})
                self.assertEqual([boundary], injected)
                sync.assert_not_called()
                self.assertEqual(b"unknown replacement\n", (target / "operator-sentinel").read_bytes())
                for descriptor in opened:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_dhcp_a_backup_sync_rechecks_payload_after_runtime_directory_sync(self) -> None:
        live = self.root / "private-backup-sync-runtime"
        transaction = live / ".load-dhcp-transaction-independent"
        backup = transaction / "backup"
        backup.mkdir(parents=True, mode=0o700)
        original = live / "dhcpd.conf"
        original.write_bytes(b"independent original A\n")
        target = backup / original.name
        shutil.copy2(original, target)
        metadata = original.stat()
        expected = {"state": "file", "mode": stat.S_IMODE(metadata.st_mode),
                    "uid": metadata.st_uid, "gid": metadata.st_gid,
                    "mtime_ns": metadata.st_mtime_ns, "size": 23,
                    "sha256": hashlib.sha256(b"independent original A\n").hexdigest()}
        runtime_identity, real_sync, injected = live.stat(), os.fsync, []

        def drift_after_sync(descriptor):
            real_sync(descriptor)
            held = os.fstat(descriptor)
            if (held.st_dev, held.st_ino) == (runtime_identity.st_dev, runtime_identity.st_ino):
                target.write_bytes(b"independent unknown backup drift\n")
                injected.append("after-runtime-sync")

        with mock.patch.object(LOAD.os, "fsync", side_effect=drift_after_sync):
            with self.assertRaisesRegex(LOAD.LoadError, "DHCP A backup durability unconfirmed"):
                LOAD._sync_verified_dhcp_a_backup(live, backup, {original: expected})
        self.assertEqual(["after-runtime-sync"], injected)
        self.assertEqual(b"independent original A\n", original.read_bytes())
        self.assertEqual(b"independent unknown backup drift\n", target.read_bytes())

    def test_restored_dhcp_sync_rejects_directory_rebind_before_file_sync(self) -> None:
        live, retained = self.root / "private-restored-A", self.root / "retained-restored-A"
        live.mkdir()
        target = live / "dhcpd.conf"
        target.write_bytes(b"independent restored A\n")
        real_open = os.open
        opened = []

        def swapped_open(path, flags, *args, **kwargs):
            if Path(path) == live:
                live.rename(retained)
                live.mkdir()
                (live / "operator-sentinel").write_bytes(b"independent unknown directory\n")
            descriptor = real_open(path, flags, *args, **kwargs)
            opened.append(descriptor)
            return descriptor

        with mock.patch.object(LOAD.os, "open", side_effect=swapped_open), \
                mock.patch.object(LOAD.os, "fsync", side_effect=AssertionError("no unknown sync")), \
                self.assertRaisesRegex(LOAD.LoadError, "durability unconfirmed.*directory changed while opening"):
            LOAD._sync_verified_dhcp_a_restore(live, {})
        self.assertEqual(1, len(opened))
        with self.assertRaises(OSError):
            os.fstat(opened[0])
        self.assertEqual(b"independent restored A\n", (retained / "dhcpd.conf").read_bytes())
        self.assertEqual(b"independent unknown directory\n", (live / "operator-sentinel").read_bytes())

    def test_restored_dhcp_sync_postcheck_rejects_drift_after_directory_sync(self) -> None:
        live = self.root / "private-restored-A"
        live.mkdir()
        target, timestamp = live / "dhcpd.conf", 1600000000123456789
        payload = b"independent restored A\n"
        target.write_bytes(payload)
        target.chmod(0o640)
        os.utime(target, ns=(timestamp, timestamp))
        expected = {target: {
            "state": "file", "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload), "mode": 0o640, "uid": os.getuid(),
            "gid": os.getgid(), "mtime_ns": timestamp,
        }}
        real_sync, events = os.fsync, []

        def drifting_sync(descriptor):
            is_directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
            events.append("directory" if is_directory else "file")
            real_sync(descriptor)
            if is_directory:
                target.write_bytes(b"independent unaccepted after-sync bytes\n")

        with mock.patch.object(LOAD.os, "fsync", side_effect=drifting_sync), \
                self.assertRaisesRegex(LOAD.LoadError, "durability unconfirmed.*preimage changed during sync"):
            LOAD._sync_verified_dhcp_a_restore(live, expected)
        self.assertEqual(["file", "directory"], events)
        self.assertEqual(b"independent unaccepted after-sync bytes\n", target.read_bytes())

    def test_dhcp_a_leaf_state_preserves_missing_regular_and_raw_link_contracts(self) -> None:
        path = self.root / "private-a-leaf"
        self.assertEqual({"state": "missing"}, LOAD._dhcp_restore_leaf_state(path))
        payload = b"independent original A leaf\n"
        timestamp = 1600000000123456789
        path.write_bytes(payload)
        path.chmod(0o640)
        os.utime(path, ns=(timestamp, timestamp))
        self.assertEqual({
            "state": "file", "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload), "mode": 0o640, "uid": os.getuid(),
            "gid": os.getgid(), "mtime_ns": timestamp,
        }, LOAD._dhcp_restore_leaf_state(path))
        path.unlink()
        path.symlink_to("independent-dangling-A-source")
        with mock.patch.object(LOAD.os, "open", side_effect=AssertionError("must not follow A link")):
            record = LOAD._dhcp_restore_leaf_state(path)
        self.assertEqual("link", record["state"])
        self.assertEqual("independent-dangling-A-source", record["target"])
        self.assertEqual(os.getuid(), record["uid"])
        self.assertEqual(os.getgid(), record["gid"])
        self.assertNotIn("sha256", record)

    def test_dhcp_a_leaf_state_rejects_unsupported_and_read_rebind_without_mutation(self) -> None:
        path = self.root / "private-a-leaf"
        for shape in ("directory", "fifo"):
            with self.subTest(shape=shape):
                if shape == "directory":
                    path.mkdir()
                else:
                    os.mkfifo(path, 0o600)
                before = path.lstat()
                with self.assertRaisesRegex(LOAD.LoadError, "neither a regular file nor link"):
                    LOAD._dhcp_restore_leaf_state(path)
                self.assertEqual(before, path.lstat())
                if shape == "directory":
                    path.rmdir()
                else:
                    path.unlink()
        path.write_bytes(b"independent original\n")
        retained = path.with_name("independent-retained-original")
        real_open = os.open
        calls = []

        def swapped_open(name, flags, *args, **kwargs):
            if Path(name) == path:
                calls.append(flags)
                path.rename(retained)
                path.write_bytes(b"independent replacement\n")
            return real_open(name, flags, *args, **kwargs)

        with mock.patch.object(LOAD.os, "open", side_effect=swapped_open), \
                self.assertRaisesRegex(LOAD.LoadError, "changed while opening"):
            LOAD._dhcp_restore_leaf_state(path)
        self.assertEqual(1, len(calls))
        self.assertTrue(calls[0] & os.O_NOFOLLOW)
        self.assertEqual(b"independent original\n", retained.read_bytes())
        self.assertEqual(b"independent replacement\n", path.read_bytes())

    def test_pending_dhcp_guard_preserves_every_occupied_evidence_shape(self) -> None:
        live = self.root / "private-dhcp-guard"
        live.mkdir()
        pending = live / ".load-dhcp-transaction-independent"
        for shape in ("regular", "directory", "dangling-symlink", "fifo"):
            with self.subTest(shape=shape):
                if shape == "regular":
                    pending.write_bytes(b"independent partial evidence\n")
                elif shape == "directory":
                    pending.mkdir()
                elif shape == "dangling-symlink":
                    pending.symlink_to("independent-absent-target")
                else:
                    os.mkfifo(pending, 0o600)
                before = pending.lstat()
                with self.assertRaisesRegex(LOAD.LoadError, "pending DHCP transaction.*HOLD"):
                    LOAD.require_no_pending_dhcp_transaction(live)
                after = pending.lstat()
                fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
                self.assertEqual(tuple(getattr(before, f) for f in fields),
                                 tuple(getattr(after, f) for f in fields))
                if shape == "regular":
                    self.assertEqual(b"independent partial evidence\n", pending.read_bytes())
                if shape == "directory":
                    pending.rmdir()
                else:
                    pending.unlink()

    def test_pending_dhcp_guard_missing_and_clean_directory_are_read_only(self) -> None:
        live = self.root / "private-dhcp-guard"
        LOAD.require_no_pending_dhcp_transaction(live)
        self.assertFalse(live.exists())
        live.mkdir()
        unrelated = live / "operator-retained-file"
        unrelated.write_bytes(b"independent unrelated bytes\n")
        before = unrelated.stat()
        LOAD.require_no_pending_dhcp_transaction(live)
        self.assertEqual(b"independent unrelated bytes\n", unrelated.read_bytes())
        self.assertEqual(before, unrelated.stat())

    def test_pending_dhcp_guard_refuses_unsafe_runtime_directory_shapes(self) -> None:
        live, actual = self.root / "private-dhcp-guard", self.root / "actual-private-dhcp"
        actual.mkdir()
        for shape in ("regular", "symlink", "fifo"):
            with self.subTest(shape=shape):
                if shape == "regular":
                    live.write_bytes(b"not a directory\n")
                elif shape == "symlink":
                    live.symlink_to(actual)
                else:
                    os.mkfifo(live, 0o600)
                before = live.lstat()
                with self.assertRaisesRegex(LOAD.LoadError, "not a regular directory.*HOLD"):
                    LOAD.require_no_pending_dhcp_transaction(live)
                self.assertEqual(before, live.lstat())
                live.unlink()

    def test_pending_dhcp_guard_scan_errors_and_limit_fail_closed(self) -> None:
        live = self.root / "private-dhcp-guard"
        live.mkdir()
        before = live.stat()
        with mock.patch.object(LOAD.os, "scandir", side_effect=PermissionError("independent refusal")):
            with self.assertRaisesRegex(LOAD.LoadError, "scan failed.*HOLD"):
                LOAD.require_no_pending_dhcp_transaction(live)
        entries = mock.MagicMock()
        entries.__enter__.return_value = iter(
            SimpleNamespace(name=f"independent-name-{n}") for n in range(4097)
        )
        with mock.patch.object(LOAD.os, "scandir", return_value=entries):
            with self.assertRaisesRegex(LOAD.LoadError, "scan limit exceeded.*HOLD"):
                LOAD.require_no_pending_dhcp_transaction(live)
        self.assertEqual(before, live.stat())

    def test_pending_dhcp_guard_detects_directory_rebind_and_name_set_aba(self) -> None:
        for mutation in ("rebind", "same-inode-aba"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as name:
                root, live = Path(name), Path(name) / "private-dhcp"
                live.mkdir()
                before = live.stat()
                real_scan = os.scandir
                _ctime_probe_serial = 0

                custody = {"unknown": False, "secondary": []}

                def scan_then_mutate(descriptor):
                    def mutate_before_transfer():
                        if mutation == "rebind":
                            live.rename(root / "retained-original-directory")
                            live.mkdir()
                        else:
                            if sys.platform.startswith("linux"):
                                nonlocal _ctime_probe_serial
                                _ctime_probe_serial += 1
                                _await_fixture_ctime_tick(
                                    Path(_ctime_probe_dir) / f"probe-{_ctime_probe_serial}",
                                    before.st_ctime_ns,
                                )
                            inserted = live / "independent-late-name"
                            inserted.write_bytes(b"independent transient evidence\n")
                            inserted.unlink()
                            os.utime(live, ns=(before.st_atime_ns, before.st_mtime_ns))
                            self.assertNotEqual(before.st_ctime_ns, live.stat().st_ctime_ns)
                    return _fixture_scan_then_mutate(
                        real_scan, descriptor, mutate_before_transfer, custody,
                    )

                _ctime_context = (
                    tempfile.TemporaryDirectory(prefix="load-ctime-18205-")
                    if sys.platform.startswith("linux") and mutation == "same-inode-aba"
                    else nullcontext(None)
                )
                with _ctime_context as _ctime_probe_dir, mock.patch.object(
                    LOAD.os, "scandir", side_effect=scan_then_mutate,
                ):
                    with self.assertRaisesRegex(LOAD.LoadError, "changed during scan.*HOLD"):
                        LOAD.require_no_pending_dhcp_transaction(live)
                self.assertTrue(live.is_dir())
                if mutation == "rebind":
                    self.assertEqual(before.st_ino, (root / "retained-original-directory").stat().st_ino)

    def test_parent_publish_failure_rolls_back_installed_dhcp_files(self) -> None:
        source_dir = self.root / "generated-dhcp"
        destination_dir = self.root / "etc-dhcp"
        source_dir.mkdir()
        destination_dir.mkdir()
        mappings = {}
        for name in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        ):
            source = source_dir / name
            destination = destination_dir / name
            source.write_text(f"new:{name}\n", encoding="utf-8")
            destination.write_text(f"old:{name}\n", encoding="utf-8")
            mappings[source] = destination
        # Keep the staged include-rewrite path exercised.
        (source_dir / "dhcpd.conf").write_text(
            "\n".join(
                f'include "/etc/dhcp/{name}";'
                for name in ("dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
            ) + "\n",
            encoding="utf-8",
        )
        candidate = LOAD.prepare_current_release(
            self.project,
            {"schema_version": 1, "release_id": "candidate", "validation": "passed"},
        )

        def fake_run(command, **_kwargs):
            operation = command[0]
            if operation == "dhcpd":
                return
            if operation == "install":
                if "-d" in command:
                    mode = int(command[command.index("-m") + 1], 8)
                    for item in command[command.index("--") + 1:]:
                        Path(item).mkdir(parents=True, exist_ok=True)
                        Path(item).chmod(mode)
                    return
                shutil.copy2(command[-2], command[-1])
                return
            if operation == "cp":
                shutil.copy2(command[-2], command[-1])
                return
            raise AssertionError(command)

        def fake_subprocess_run(command, **_kwargs):
            if command[0] == "rm":
                target = Path(command[-1])
                if "-rf" in command:
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink(missing_ok=True)
            elif command[0] == "cp":
                shutil.copy2(command[-2], command[-1])
            elif command[0] == "rmdir":
                Path(command[-1]).rmdir()
            else:
                raise AssertionError(command)
            return SimpleNamespace(returncode=0)

        try:
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                    mock.patch.object(LOAD, "run", side_effect=fake_run), \
                    mock.patch.object(LOAD.subprocess, "run", side_effect=fake_subprocess_run), \
                    mock.patch.object(
                        LOAD, "commit_prepared_release",
                        side_effect=OSError("injected parent replace failure"),
                    ):
                with self.assertRaisesRegex(OSError, "injected parent replace failure"):
                    LOAD.mount_and_test_dhcp(parent_candidate=candidate)
            for destination in mappings.values():
                self.assertEqual(
                    f"old:{destination.name}\n", destination.read_text(encoding="utf-8")
                )
            self.assertFalse(candidate.committed)
            self.assertFalse(candidate.destination.exists())
        finally:
            LOAD.discard_prepared_release(candidate)

    def test_dhcp_preflight_uses_apparmor_readable_unpublished_staging(self) -> None:
        source_dir = self.root / "permission-source-dhcp"
        destination_dir = self.root / "etc-dhcp-permission-contract"
        source_dir.mkdir()
        destination_dir.mkdir()
        names = (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        )
        mappings = {}
        for name in names:
            source = source_dir / name
            destination = destination_dir / name
            source.write_text(f"new:{name}\n", encoding="utf-8")
            destination.write_text(f"old:{name}\n", encoding="utf-8")
            mappings[source] = destination
        (source_dir / "dhcpd.conf").write_text(
            "\n".join(
                f'include "/etc/dhcp/{name}";'
                for name in names[1:]
            ) + "\n",
            encoding="utf-8",
        )

        syntax_checks = []

        def fake_run(command, **_kwargs):
            operation = command[0]
            if operation == "install":
                mode = int(command[command.index("-m") + 1], 8)
                if "-d" in command:
                    for item in command[command.index("--") + 1:]:
                        path = Path(item)
                        path.mkdir(parents=True, exist_ok=True)
                        path.chmod(mode)
                    return
                source = Path(command[-2])
                destination = Path(command[-1])
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                destination.chmod(mode)
                return
            if operation == "cp":
                shutil.copy2(command[-2], command[-1])
                return
            if operation != "dhcpd":
                raise AssertionError(command)

            syntax_checks.append(command)
            config = Path(command[-1])
            if len(syntax_checks) == 1:
                staged_dir = config.parent
                transaction_dir = staged_dir.parent
                self.assertEqual(destination_dir, transaction_dir.parent)
                self.assertTrue(transaction_dir.name.startswith(
                    ".load-dhcp-transaction-"
                ))
                self.assertEqual(0o755, transaction_dir.stat().st_mode & 0o777)
                self.assertEqual(0o755, staged_dir.stat().st_mode & 0o777)
                self.assertEqual(0o644, config.stat().st_mode & 0o777)
                text = config.read_text(encoding="utf-8")
                for name in names[1:]:
                    staged_host = staged_dir / name
                    self.assertEqual(0o644, staged_host.stat().st_mode & 0o777)
                    self.assertIn(f'include "{staged_host}";', text)
                    self.assertNotIn(f'include "/etc/dhcp/{name}";', text)
                for destination in mappings.values():
                    self.assertEqual(
                        f"old:{destination.name}\n",
                        destination.read_text(encoding="utf-8"),
                    )
            else:
                self.assertEqual(Path("/etc/dhcp/dhcpd.conf"), config)
                for destination in mappings.values():
                    self.assertTrue(
                        destination.read_text(encoding="utf-8").startswith("new:")
                        or destination.name == "dhcpd.conf"
                    )

        with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                mock.patch.object(LOAD, "run", side_effect=fake_run):
            LOAD.mount_and_test_dhcp()

        self.assertEqual(2, len(syntax_checks))
        self.assertEqual([], list(destination_dir.glob(".load-dhcp-transaction-*")))

    def test_dhcp_staging_rewrite_requires_each_canonical_include_once(self) -> None:
        names = ("dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
        original = "\n".join(
            f'include "/etc/dhcp/{name}";' for name in names
        ) + "\n"
        staged = self.root / "etc/dhcp/.load-dhcp-transaction-test/staged"
        rewritten = LOAD._rewrite_dhcp_staging_includes(original, staged)
        for name in names:
            self.assertIn(f'include "{staged / name}";', rewritten)
            self.assertNotIn(f'include "/etc/dhcp/{name}";', rewritten)

        with self.assertRaisesRegex(LOAD.LoadError, "必须且只能包含一次"):
            LOAD._rewrite_dhcp_staging_includes(
                original.replace(f'include "/etc/dhcp/{names[0]}";\n', ""),
                staged,
            )
        with self.assertRaisesRegex(LOAD.LoadError, "必须且只能包含一次"):
            LOAD._rewrite_dhcp_staging_includes(
                original + f'include "/etc/dhcp/{names[1]}";\n', staged,
            )

    def test_subnet_gate_rejects_router_inside_dynamic_range(self) -> None:
        subnet = self.root / "router-in-range.csv"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.110,198.51.100.10,oob,no\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LOAD.LoadError, "routers=.*落入动态 range"):
            LOAD.validate_subnet_file(subnet, self.inputs.settings)

    def test_subnet_gate_rejects_in_subnet_service_ip_inside_dynamic_range(self) -> None:
        subnet = self.root / "service-in-range.csv"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.110,oob,no\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LOAD.LoadError, "service_ip=.*落入动态 range"):
            LOAD.validate_subnet_file(subnet, self.inputs.settings)

    def test_custom_ztp_prefix_publication_is_idempotent_and_cleans_on_default(self) -> None:
        root = self.root / "http-prefix"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        custom = LOAD.replace(
            self.inputs.settings,
            http_root=root,
            ztp_prefix="/day0/ztp",
        )
        builtin = LOAD.replace(custom, ztp_prefix="/ztp")
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            destination = LOAD.configure_ztp_prefix_publication(custom)
            self.assertTrue(destination.is_symlink())
            self.assertEqual(ztp_dir.resolve(), destination.resolve())
            marker_before = marker.read_bytes()

            # A repeated load preserves the same link and marker content.
            self.assertEqual(
                destination,
                LOAD.configure_ztp_prefix_publication(custom),
            )
            self.assertEqual(marker_before, marker.read_bytes())

            # Returning to the built-in /ztp path removes only the link that
            # this loader recorded; the real ZTP directory remains untouched.
            self.assertEqual(
                ztp_dir,
                LOAD.configure_ztp_prefix_publication(builtin),
            )
            self.assertFalse(destination.exists())
            self.assertFalse(destination.is_symlink())
            self.assertFalse(marker.exists())
            self.assertTrue(ztp_dir.is_dir())

    def test_custom_ztp_prefix_publication_rejects_existing_path_conflict(self) -> None:
        root = self.root / "http-prefix-conflict"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        destination = root / "day0/ztp"
        destination.mkdir(parents=True)
        settings = LOAD.replace(
            self.inputs.settings,
            http_root=root,
            ztp_prefix="/day0/ztp",
        )
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            with self.assertRaisesRegex(LOAD.LoadError, "发布路径已被占用"):
                LOAD.configure_ztp_prefix_publication(settings)
        self.assertTrue(destination.is_dir())
        self.assertFalse(marker.exists())

    def test_custom_prefix_rejects_untracked_same_target_symlink(self) -> None:
        root = self.root / "http-prefix-untracked"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        destination = root / "day0/ztp"
        destination.parent.mkdir(parents=True)
        destination.symlink_to(Path("../ztp"))
        settings = LOAD.replace(
            self.inputs.settings, http_root=root, ztp_prefix="/day0/ztp",
        )
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            with self.assertRaisesRegex(LOAD.LoadError, "ownership marker"):
                LOAD.configure_ztp_prefix_publication(settings)
        self.assertTrue(destination.is_symlink())
        self.assertEqual(ztp_dir.resolve(), destination.resolve())
        self.assertFalse(marker.exists())

    def test_custom_prefix_rejects_broken_or_drifted_marker(self) -> None:
        root = self.root / "http-prefix-marker"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        settings = LOAD.replace(
            self.inputs.settings, http_root=root, ztp_prefix="/day0/ztp",
        )
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            marker.symlink_to("missing-marker.json")
            with self.assertRaisesRegex(LOAD.LoadError, "不是普通文件"):
                LOAD.configure_ztp_prefix_publication(settings)
            marker.unlink()

            destination = LOAD.configure_ztp_prefix_publication(settings)
            valid = json.loads(marker.read_text(encoding="utf-8"))
            drifted_path = dict(valid, path=str(root / "other"))
            marker.write_text(json.dumps(drifted_path), encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "prefix/path"):
                LOAD.configure_ztp_prefix_publication(settings)

            drifted_target = dict(valid, target=str(root / "other-target"))
            marker.write_text(json.dumps(drifted_target), encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "target"):
                LOAD.configure_ztp_prefix_publication(settings)

        self.assertTrue(destination.is_symlink())

    def test_prefix_snapshot_restores_old_link_after_precommit_failure(self) -> None:
        root = self.root / "http-prefix-rollback"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        old = LOAD.replace(
            self.inputs.settings, http_root=root, ztp_prefix="/legacy/ztp",
        )
        new = LOAD.replace(old, ztp_prefix="/day0/ztp")
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            old_path = LOAD.configure_ztp_prefix_publication(old)
            marker_before = marker.read_bytes()
            snapshot = LOAD.snapshot_ztp_prefix_publication(new)
            new_path = LOAD.configure_ztp_prefix_publication(new)
            self.assertFalse(old_path.is_symlink())
            self.assertTrue(new_path.is_symlink())

            # This is the same rollback invoked by main's catch block whenever
            # generation/DHCP/parent publication fails before parent commit.
            LOAD.restore_ztp_prefix_publication(snapshot)

            self.assertTrue(old_path.is_symlink())
            self.assertEqual(ztp_dir.resolve(), old_path.resolve())
            self.assertFalse(new_path.is_symlink())
            self.assertEqual(marker_before, marker.read_bytes())

    def test_prefix_rejects_percent_encoded_path_segments(self) -> None:
        with self.assertRaisesRegex(LOAD.LoadError, "安全绝对 URL path"):
            LOAD._validate_ztp_prefix("/safe/%2e%2e/ztp")
        global_yaml = self.root / "encoded-prefix.yaml"
        global_yaml.write_text(
            "common:\n  mgmt:\n    ztp:\n      ztp_url_prefix: /safe/%2f/ztp\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MANUAL.ManualZtpError, "安全绝对 URL path"):
            MANUAL.global_ztp_url_prefix(global_yaml)

    def test_off_link_subnet_ztp_ip_does_not_replace_explicit_http_url_ip(self) -> None:
        subnet = self.root / "off-link-service.csv"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "clients,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,198.51.100.10,oob,no\n",
            encoding="utf-8",
        )
        settings = LOAD.replace(
            self.inputs.settings,
            ztp_ips={"prod_oob": ("198.51.100.10",)},
            http_address="198.51.100.20",
        )
        inputs = LOAD.replace(
            self.inputs, subnet_file=subnet, settings=settings,
        )
        self.assertEqual((), LOAD.service_ip_bindings(inputs))
        self.assertEqual(
            ["198.51.100.20"],
            LOAD.missing_service_ip_addresses(settings.http_listener_ips, {}),
        )
        # The independent HTTP address may use any real local prefix. The
        # subnet ZTP address alone does not satisfy the URL network gate.
        assignments = {"198.51.100.20": {("eth9", 30)}}
        self.assertEqual(
            [],
            LOAD.missing_service_ip_addresses(settings.http_listener_ips, assignments),
        )

        noninteractive = mock.Mock()
        noninteractive.isatty.return_value = False
        with mock.patch.object(
            LOAD, "_local_ipv4_assignments", return_value={},
        ), mock.patch.object(LOAD.sys, "stdin", noninteractive):
            with self.assertRaisesRegex(LOAD.LoadError, "非交互模式"):
                LOAD.ensure_ztp_url_network_ready(inputs)

    def test_prepare_infra_explicitly_defers_service_activation(self) -> None:
        with mock.patch.object(LOAD, "run") as run_command, mock.patch.object(
            LOAD, "select_http_ip", return_value="192.0.2.1",
        ):
            LOAD.prepare_infra(self.inputs, skip_doca=True)
        commands = [call.args[0] for call in run_command.call_args_list]
        setup = next(
            command for command in commands
            if any(str(item).endswith("infra-setup.py") for item in command)
        )
        script_at = [str(item) for item in setup].index(str(LOAD.INFRA_DIR / "infra-setup.py"))
        self.assertEqual([LOAD.sys.executable, "-B"], [str(item) for item in setup[script_at - 2:script_at]])
        self.assertIn("--mgmt", setup)
        self.assertIn("--defer-services", setup)
        self.assertIn("--install-apache", setup)
        self.assertIn("--install-dhcp", setup)
        # load is the authorized, non-interactive apply step for infra-setup.py.
        self.assertEqual(["--apply", "--yes"], [str(item) for item in setup if str(item) in ("--apply", "--yes")])

    def test_service_start_failure_restores_entry_enabled_and_active_state(self) -> None:
        states = {
            "apache2": LOAD.ServiceRuntimeState(enabled=True, active=False),
            "isc-dhcp-server": LOAD.ServiceRuntimeState(enabled=False, active=True),
        }
        events = []
        restart_failed = False

        def fake_run(command, **_kwargs):
            nonlocal restart_failed
            normalized = command[-3:]
            events.append(tuple(normalized))
            if normalized == ["systemctl", "restart", "isc-dhcp-server"] and not restart_failed:
                restart_failed = True
                raise LOAD.LoadError("injected DHCP restart failure")

        with mock.patch.object(
            LOAD, "ensure_ztp_url_network_ready", side_effect=lambda *_a, **_k: events.append("gate"),
        ), mock.patch.object(
            LOAD, "plan_local_dhcp_runtime",
            return_value=SimpleNamespace(listener_names=("eno2",)),
        ), mock.patch.object(
            LOAD, "snapshot_service_states",
            side_effect=lambda *_a, **_k: (events.append("snapshot") or states),
        ), mock.patch.object(LOAD, "run", side_effect=fake_run), mock.patch.object(
            LOAD, "verify_http_publication",
        ):
            with self.assertRaisesRegex(LOAD.LoadError, "injected DHCP restart failure"):
                LOAD.start_services(self.inputs, {})

        self.assertEqual(events[:2], ["gate", "snapshot"])
        self.assertIn(("systemctl", "stop", "apache2"), events)
        self.assertIn(("systemctl", "stop", "isc-dhcp-server"), events)
        self.assertIn(("systemctl", "enable", "apache2"), events)
        self.assertIn(("systemctl", "disable", "isc-dhcp-server"), events)
        self.assertIn(("systemctl", "start", "isc-dhcp-server"), events)

    def test_supervisor_quiesce_plans_listeners_before_any_service_change(self) -> None:
        """The host-network listener gate must run before Supervisor is touched."""
        events = []
        stopped = set()
        expected_plan = SimpleNamespace(listener_names=("eno2", "eno3"))

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                events.append(("status", service))
                return True

            @staticmethod
            def is_quiesced(service):
                events.append(("quiesced", service))
                return service in stopped

            @staticmethod
            def stop(service):
                events.append(("stop", service))
                stopped.add(service)

        with mock.patch.object(
            LOAD, "plan_local_dhcp_runtime",
            side_effect=lambda *_a, **_k: (
                events.append(("plan",)) or expected_plan
            ),
        ), mock.patch.object(
            LOAD, "supports_local_ztp_services", return_value=True,
        ), mock.patch.object(
            LOAD, "runtime_os", return_value="Linux",
        ), mock.patch.object(
            LOAD.subprocess, "run",
            side_effect=AssertionError("supervisor path must not invoke systemctl"),
        ):
            actual = LOAD.quiesce_services(
                False, inputs=self.inputs, runtime_backend=Backend(),
                host_role="management-server",
            )

        self.assertIs(expected_plan, actual)
        self.assertEqual(("plan",), events[0])
        self.assertEqual(
            [
                ("stop", "ztp-monitor"),
                ("stop", "switch-collection"),
                ("stop", "manual-ztp"),
                ("stop", "isc-dhcp-server"),
                ("stop", "apache2"),
            ],
            [event for event in events if event[0] == "stop"],
        )

    def test_supervisor_start_never_activates_dhcp_with_empty_listener_plan(self) -> None:
        events = []

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                events.append(("status", service))
                return False

            @staticmethod
            def is_enabled(_service):
                return None

            @staticmethod
            def start(service):
                events.append(("start", service))

            @staticmethod
            def stop(service):
                events.append(("stop", service))

            @staticmethod
            def restart(service):
                events.append(("restart", service))

        plan = SimpleNamespace(listener_names=(), endpoint_ips=())
        with mock.patch.object(
            LOAD, "ensure_ztp_url_network_ready",
        ), mock.patch.object(
            LOAD, "verify_http_publication",
        ), mock.patch.object(
            LOAD.subprocess, "run",
            side_effect=AssertionError("supervisor path must not invoke systemctl"),
        ):
            LOAD.start_services(
                self.inputs, {}, dhcp_runtime_plan=plan,
                runtime_backend=Backend(),
            )

        self.assertNotIn(("start", "apache2"), events)
        self.assertNotIn(("start", "isc-dhcp-server"), events)
        self.assertNotIn(("restart", "isc-dhcp-server"), events)

    def test_supervisor_dhcp_only_starts_dhcp_and_stops_stale_apache(self) -> None:
        """A relay-ingress DHCP plan must not invent an HTTP endpoint."""
        events = []
        active = {"apache2": True, "isc-dhcp-server": False}

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                events.append(("status", service))
                return active[service]

            @staticmethod
            def start(service):
                events.append(("start", service))
                active[service] = True

            @staticmethod
            def stop(service):
                events.append(("stop", service))
                active[service] = False

            @staticmethod
            def restart(service):
                events.append(("restart", service))
                active[service] = True

        plan = SimpleNamespace(
            listener_names=("eno7",), listener_ifindexes=(17,),
            endpoint_ips=(),
        )
        with mock.patch.object(
            LOAD, "ensure_ztp_url_network_ready",
            side_effect=AssertionError(
                "DHCP-only service start must not gate nonexistent HTTP endpoints"
            ),
        ), mock.patch.object(
            LOAD, "verify_http_publication",
            side_effect=AssertionError(
                "DHCP-only service start must not perform HTTP URL checks"
            ),
        ), mock.patch.object(
            LOAD.subprocess, "run",
            side_effect=AssertionError("supervisor path must not invoke systemctl"),
        ):
            LOAD.start_services(
                self.inputs, {}, dhcp_runtime_plan=plan,
                runtime_backend=Backend(),
            )

        self.assertEqual(
            [
                ("status", "apache2"),
                ("status", "isc-dhcp-server"),
                ("stop", "apache2"),
                ("start", "isc-dhcp-server"),
            ],
            events,
        )
        self.assertFalse(active["apache2"])
        self.assertTrue(active["isc-dhcp-server"])

    def test_supervisor_dhcp_only_main_installs_current_release_without_http(self) -> None:
        """The child load must install the DHCP release before hostctl converges it."""
        # main now reads the actual global before validate_inputs. This case
        # independently declares DHCP-only, so the real fixture must too.
        document = yaml.safe_load(self.global_file.read_text(encoding="utf-8"))
        document["common"]["mgmt"]["http"]["status"] = "disabled"
        document["common"]["mgmt"]["ztp"]["status"] = "disabled"
        self.global_file.write_text(yaml.safe_dump(document), encoding="utf-8")
        private_mode = stat.S_IMODE(self.root.lstat().st_mode)
        (self.project / "99-output-dhcp").mkdir(exist_ok=True)
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=True,
            start_ztp_monitor=True, ztp_monitor_scope="air",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
            host_role="management-server",
        )
        settings = LOAD.replace(
            self.inputs.settings,
            http_enabled=False, ztp_enabled=False, ztp_ips={}, boot_ips=(),
        )
        inputs = LOAD.replace(self.inputs, settings=settings)
        backend = SimpleNamespace(name="supervisor")
        plan = SimpleNamespace(
            listener_names=("eno7",), listener_ifindexes=(17,),
            endpoint_ips=(),
        )
        quiesce = mock.Mock()
        generate = mock.Mock()
        mount = mock.Mock()
        preflight = mock.Mock()
        start = mock.Mock()
        monitor = mock.Mock()
        switch = mock.Mock()
        manual = mock.Mock()
        prefix_snapshot = mock.Mock()
        prefix_publish = mock.Mock()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=93,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "active_project", return_value=self.project.resolve(),
            ))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock"))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=True,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "service_runtime_backend", return_value=backend,
            ))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(inputs, {}),
            ))
            validate_http = stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host",
                side_effect=AssertionError(
                    "DHCP-only plan must not depend on HTTP service_ip availability"
                ),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "plan_local_dhcp_runtime", return_value=plan,
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services", quiesce))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", prefix_snapshot,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "configure_ztp_prefix_publication", prefix_publish,
            ))
            stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links", return_value={},
            ))
            stack.enter_context(mock.patch.object(LOAD, "generate_configs", generate))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release", return_value=None,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "mount_and_test_dhcp", mount,
            ))
            stack.enter_context(mock.patch.object(LOAD, "preflight_services", preflight))
            stack.enter_context(mock.patch.object(LOAD, "start_services", start))
            stack.enter_context(mock.patch.object(LOAD, "start_ztp_monitor", monitor))
            stack.enter_context(mock.patch.object(
                LOAD, "start_switch_collection_worker", switch,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "start_manual_ztp_worker", manual,
            ))

            self.assertEqual(0, LOAD.main([]))

        self.assertEqual(0o700, private_mode)
        self.assertEqual(private_mode, stat.S_IMODE(self.root.lstat().st_mode))
        validate_http.assert_not_called()
        quiesce.assert_called_once_with(
            False, dhcp_runtime_plan=plan, runtime_backend=backend,
            native_monitor_already_quiesced=False,
            host_role="management-server",
        )
        generate.assert_called_once_with(
            inputs.device_types,
            deployment_lock_descriptor=93,
            source_identities=inputs.source_identities,
            inventory_directory=mock.ANY,
            dhcp_candidate_dir=mock.ANY,
            install_dhcp=True,
            dry_run=False,
            schema_version=inputs.settings.schema_version,
            eth_version=None,
            air_topology_policy=None,
            deployment_scope="all",
            switch_scope="all",
        )
        private_candidate = generate.call_args.kwargs["dhcp_candidate_dir"]
        self.assertEqual(
            (self.project / "99-output-dhcp").resolve(), private_candidate.parent,
        )
        self.assertTrue(private_candidate.name.startswith(".load-dhcp-candidate-"))
        self.assertFalse(private_candidate.exists())  # no parent was committed
        mount.assert_called_once_with(False, parent_candidate=None)
        # Setup keeps the selected project-local P2P source as a lexical path;
        # macOS may spell the same temporary inode as /var or /private/var.
        self.assertEqual(self.p2p_source.name, os.readlink(self.p2p_file))
        expected_runtime_inputs = LOAD.replace(
            inputs, p2p_file=self.project / self.p2p_source.name,
        )
        preflight.assert_called_once_with(
            expected_runtime_inputs, {}, False, dhcp_runtime_plan=plan,
            runtime_backend=backend,
        )
        start.assert_called_once_with(
            expected_runtime_inputs, {}, False, dhcp_runtime_plan=plan,
            runtime_backend=backend,
        )
        prefix_snapshot.assert_not_called()
        prefix_publish.assert_not_called()
        monitor.assert_not_called()
        switch.assert_not_called()
        manual.assert_not_called()

    def test_parent_load_is_the_only_dhcp_runtime_publication_owner(self) -> None:
        generator_main = inspect.getsource(DHCP.main)
        parent_generation = (
            inspect.getsource(LOAD.generate_configs)
            + inspect.getsource(LOAD._generate_configs_impl)
        )
        parent_install = inspect.getsource(LOAD.mount_and_test_dhcp)

        self.assertNotIn("subprocess.run", generator_main)
        self.assertNotIn("是否复制配置文件到 /etc/dhcp", generator_main)
        self.assertIn("DHCP 安装已延后到统一 release 验证通过之后", parent_generation)
        self.assertIn("dhcpd -t", parent_install)
        self.assertIn('"install", "-m", "0644"', parent_install)
        self.assertIn("commit_prepared_release", parent_install)

    def test_supervisor_backend_rejects_host_infra_setup_path(self) -> None:
        args = SimpleNamespace(skip_infra=False)
        with self.assertRaisesRegex(LOAD.LoadError, "--skip-infra"):
            LOAD.validate_runtime_options(
                args, SimpleNamespace(name="supervisor"),
            )

        # The default systemd deployment keeps its established infra behavior.
        LOAD.validate_runtime_options(
            args, SimpleNamespace(name="systemd"),
        )

    def test_local_dhcp_runtime_plan_uses_ip_json_and_no_fixed_nic_count(self) -> None:
        subnet = self.root / "dynamic-listeners.csv"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "first,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no\n"
            "second,198.51.100.0,255.255.255.0,198.51.100.100,198.51.100.120,"
            "198.51.100.1,198.51.100.10,oob,no\n",
            encoding="utf-8",
        )
        inputs = LOAD.replace(self.inputs, subnet_file=subnet)
        links = [
            {
                "ifindex": 7, "ifname": "eno2", "link_type": "ether",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "operstate": "UP",
            },
            {
                "ifindex": 8, "ifname": "eno3", "link_type": "ether",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "operstate": "UP",
            },
        ]
        addresses = [
            {"ifindex": 7, "ifname": "eno2", "addr_info": [{
                "family": "inet", "local": "192.0.2.10", "prefixlen": 24,
                "scope": "global",
            }]},
            {"ifindex": 8, "ifname": "eno3", "addr_info": [{
                "family": "inet", "local": "198.51.100.10", "prefixlen": 24,
                "scope": "global",
            }]},
        ]

        plan = LOAD.plan_local_dhcp_runtime(
            inputs, link_snapshot=links, address_snapshot=addresses,
            environment={},
        )

        self.assertEqual(("eno2", "eno3"), plan.listener_names)
        self.assertEqual((7, 8), plan.listener_ifindexes)

    def test_local_runtime_snapshot_requests_detailed_link_kind(self) -> None:
        commands = []

        def runner(command, **kwargs):
            commands.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")

        self.assertEqual(
            ("[]", "[]"),
            LOAD._local_ip_json_snapshots(command_runner=runner),
        )
        self.assertEqual(
            [
                ["ip", "-d", "-j", "link", "show"],
                ["ip", "-j", "-4", "address", "show"],
            ],
            [command for command, _kwargs in commands],
        )
        for _command, kwargs in commands:
            self.assertEqual(
                {"capture_output": True, "text": True, "check": False},
                kwargs,
            )

    def test_listener_plan_failure_precedes_quiesce_and_cleanup_stop(self) -> None:
        self._http_main_public_source_fixture()
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
            host_role="management-server",
        )
        backend = SimpleNamespace(name="supervisor")
        quiesce = mock.Mock()
        release_lock = mock.Mock()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "HTTP_ROOT", self.root))
            stack.enter_context(self._http_linux_public_ancestor_model())
            # This listener-failure fixture has no foreign active project.
            # Bind A to its own root instead of reading the checkout manifest
            # after HTTP_ROOT has been scoped to the private publication.
            stack.enter_context(mock.patch.object(
                LOAD, "active_project", return_value=self.project.resolve(),
            ))
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=92,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "release_deployment_lock", release_lock,
            ))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=True,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "service_runtime_backend", return_value=backend,
            ))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(self.inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host", return_value=True,
            ))
            listener_plan = stack.enter_context(mock.patch.object(
                LOAD, "plan_local_dhcp_runtime",
                side_effect=LOAD.LoadError("ambiguous listener fixture"),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "quiesce_services", quiesce,
            ))
            activate = stack.enter_context(mock.patch.object(LOAD, "activate_project"))

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(1, LOAD.main([]))

        listener_plan.assert_called_once()
        self.assertIn("ambiguous listener fixture", stderr.getvalue())
        quiesce.assert_not_called()
        activate.assert_not_called()
        release_lock.assert_called_once_with(92)

    def test_monitor_scope_failure_precedes_quiesce_activation_and_generation(self) -> None:
        self._http_main_public_source_fixture()
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=True,
            start_ztp_monitor=True, ztp_monitor_scope="auto",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
            host_role="management-server",
        )
        backend = SimpleNamespace(name="supervisor")
        plan = SimpleNamespace(
            listener_names=("eno2",), endpoint_ips=("192.0.2.10",),
        )
        quiesce = mock.Mock()
        activate = mock.Mock()
        generate = mock.Mock()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "HTTP_ROOT", self.root))
            stack.enter_context(self._http_linux_public_ancestor_model())
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=94,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "active_project", return_value=self.project.resolve(),
            ))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock"))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=True,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "service_runtime_backend", return_value=backend,
            ))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(self.inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "plan_local_dhcp_runtime", return_value=plan,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "supervisor_service_availability", return_value=(True, True),
            ))
            scope = stack.enter_context(mock.patch.object(
                LOAD, "resolve_ztp_monitor_scope",
                side_effect=LOAD.LoadError("scope required before mutation"),
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services", quiesce))
            stack.enter_context(mock.patch.object(LOAD, "activate_project", activate))
            stack.enter_context(mock.patch.object(LOAD, "generate_configs", generate))

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(1, LOAD.main([]))

        quiesce.assert_not_called()
        activate.assert_not_called()
        generate.assert_not_called()
        scope.assert_called_once()
        self.assertIn("scope required before mutation", stderr.getvalue())

    def test_transaction_failure_reports_phase_safe_state_and_full_rerun(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = self._exercise_main_transaction_failure(
                ValueError("injected value error"),
                argv=["demo", "--start-services", "--ztp-monitor-scope", "air"],
            )[0]

        self.assertEqual(1, result)
        output = stderr.getvalue()
        self.assertIn("[FAILED] load 阶段失败：统一 release 一致性与 DHCP 事务安装", output)
        self.assertIn("[SAFE] 受管服务保持停止", output)
        self.assertIn("[SAFE] 未提交 release 的发布状态已回滚", output)
        self.assertIn("[NEXT] 修复上述错误后完整重跑：", output)
        self.assertIn("11-load.py", output)
        self.assertIn("--ztp-monitor-scope air", output)

    def test_main_stages_schema2_b_before_dhcp_install_and_keeps_a_selected_on_failure(self) -> None:
        selector = self.project / "99-output-ztp/current"
        selector.parent.mkdir(parents=True, exist_ok=True)
        selector.symlink_to("generations/aaaaaaaaaaaaaaaaaaaa")
        staged_b = self.project / "99-output-ztp/generations/bbbbbbbbbbbbbbbbbbbb"
        lifecycle_events: list[str] = []

        def stage_candidate(*_args):
            lifecycle_events.append("stage-b")
            return staged_b

        def freeze_previous(*_args):
            lifecycle_events.append("freeze-a")
            return "generations/aaaaaaaaaaaaaaaaaaaa"

        receipt = self.project / "99-output-ztp/rollback-receipts/aaaaaaaaaaaaaaaaaaaa"

        def prepare_receipt(*_args):
            lifecycle_events.append("receipt-a")
            return receipt

        def restore_receipt(*_args, **kwargs):
            self.assertEqual(91, kwargs["deployment_lock_descriptor"])
            self.assertTrue(kwargs["services_quiesced"])
            self.assertEqual("supervisor", kwargs["runtime_backend"].name)
            lifecycle_events.append("restore-a")

        with mock.patch.object(
            LOAD, "ensure_previous_generation_frozen", side_effect=freeze_previous,
        ) as freeze, mock.patch.object(
            LOAD, "stage_pinned_generation", side_effect=stage_candidate,
        ) as stage, mock.patch.object(
            LOAD, "prepare_active_runtime_rollback_receipt", side_effect=prepare_receipt,
        ) as prepare_receipt_mock, mock.patch.object(
            LOAD, "restore_runtime_rollback_receipt", side_effect=restore_receipt,
        ) as restore_receipt_mock, mock.patch.object(
            LOAD, "commit_pinned_generation",
        ) as commit:
            result = self._exercise_main_transaction_failure(
                ValueError("injected DHCP install failure"),
                lifecycle_events=lifecycle_events,
                parent_schema_version=2,
                observe_template_mutation=True,
            )[0]

        self.assertEqual(1, result)
        freeze.assert_called_once_with(self.project)
        stage.assert_called_once()
        self.assertEqual(self.project, stage.call_args.args[0])
        self.assertEqual(
            ["freeze-a", "receipt-a", "template-mutation",
             "monitor-authority-attest", "generate",
             "stage-b", "dhcp-transaction", "restore-a"],
            lifecycle_events,
        )
        self.assertEqual("generations/aaaaaaaaaaaaaaaaaaaa", os.readlink(selector))
        commit.assert_not_called()
        prepare_receipt_mock.assert_called_once()
        restore_receipt_mock.assert_called_once()

    def test_main_does_not_restore_receipt_when_failure_precedes_quiesce_and_mutation(self) -> None:
        receipt = self.project / "99-output-ztp/rollback-receipts/aaaaaaaaaaaaaaaaaaaa"
        with mock.patch.object(
            LOAD, "ensure_previous_generation_frozen",
            return_value="generations/aaaaaaaaaaaaaaaaaaaa",
        ), mock.patch.object(
            LOAD, "prepare_active_runtime_rollback_receipt",
            return_value=receipt,
        ) as prepare, mock.patch.object(
            LOAD, "restore_runtime_rollback_receipt",
        ) as restore:
            result = self._exercise_main_transaction_failure(
                LOAD.LoadError("template preflight failed before quiesce"),
                failure_at="template",
            )[0]

        self.assertEqual(1, result)
        prepare.assert_called_once_with(
            self.project, "generations/aaaaaaaaaaaaaaaaaaaa",
        )
        restore.assert_not_called()

    def test_main_pending_dhcp_transaction_blocks_before_project_resolution(self) -> None:
        live = self.root / "private-etc-dhcp"
        live.mkdir()
        pending = live / ".load-dhcp-transaction-independent-orphan"
        payload = b"independent retained A/B evidence\n"
        pending.write_bytes(payload)
        before = pending.lstat()
        args = LOAD.parse_args([
            str(self.project), "--host-role=management-server", "--no-upgrade",
            "--ssh-dir=/root/.ssh",
        ])
        resolve = mock.Mock(side_effect=LOAD.LoadError("unsafe project edge reached"))
        release_lock, stderr = mock.Mock(), io.StringIO()
        with mock.patch.object(LOAD, "parse_args", return_value=args), mock.patch.object(
            LOAD, "runtime_os", return_value="Linux",
        ), mock.patch.object(LOAD, "service_runtime_backend", return_value=SimpleNamespace(name="supervisor")), \
                mock.patch.object(LOAD, "validate_runtime_options"), \
                mock.patch.object(LOAD, "acquire_deployment_lock", return_value=91), \
                mock.patch.object(LOAD, "release_deployment_lock", release_lock), \
                mock.patch.object(LOAD, "MANIFEST", self.ztp / ".setup_manifest"), \
                mock.patch.object(LOAD, "dhcp_file_mappings", return_value={self.project / "dhcpd.conf": live / "dhcpd.conf"}), \
                mock.patch.object(LOAD, "resolve_project", resolve), redirect_stderr(stderr):
            self.assertEqual(1, LOAD.main([]))
        resolve.assert_not_called()
        self.assertIn("pending DHCP transaction", stderr.getvalue())
        self.assertIn("HOLD", stderr.getvalue())
        self.assertEqual(payload, pending.read_bytes())
        after = pending.lstat()
        self.assertEqual((before.st_dev, before.st_ino, before.st_mode, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns, after.st_ctime_ns))
        release_lock.assert_called_once_with(91)

    def test_main_freezes_existing_a_before_any_template_mutation(self) -> None:
        events: list[str] = []
        with mock.patch.object(
            LOAD, "ensure_previous_generation_frozen",
            side_effect=lambda _project: events.append("freeze-a") or None,
        ):
            result = self._exercise_main_transaction_failure(
                ValueError("stop after ordered workflow"),
                lifecycle_events=events,
                observe_template_mutation=True,
            )[0]

        self.assertEqual(1, result)
        self.assertLess(events.index("freeze-a"), events.index("template-mutation"))

    def test_main_without_pending_wal_preserves_requested_service_start(self):
        stdout = io.StringIO()
        with mock.patch.object(LOAD, "MANIFEST", self.ztp / ".setup_manifest"), \
                mock.patch.object(LOAD, "preflight_services"), \
                mock.patch.object(LOAD, "start_services") as start, \
                redirect_stdout(stdout):
            result, caught, candidate, quiesce, *_rest = self._exercise_main_transaction_failure(
                LOAD.LoadError("unused completion fixture failure"), failure_at="completion",
                start_services=True,
            )
        self.assertEqual(0, result)
        self.assertIsNone(caught)
        self.assertTrue(candidate.committed and candidate.directory_synced)
        start.assert_called_once()
        self.assertEqual(1, quiesce.call_count)
        self.assertIn("load 流程完成", stdout.getvalue())

    def test_main_without_pending_wal_keeps_existing_normal_success(self):
        stdout = io.StringIO()
        with mock.patch.object(LOAD, "MANIFEST", self.ztp / ".setup_manifest"), \
                mock.patch.object(LOAD, "preflight_services"), \
                mock.patch.object(LOAD, "confirm_service_start", return_value=False), \
                redirect_stdout(stdout):
            result, caught, candidate, quiesce, *_rest = self._exercise_main_transaction_failure(
                LOAD.LoadError("unused completion fixture failure"), failure_at="completion",
            )
        self.assertEqual(0, result)
        self.assertIsNone(caught)
        self.assertTrue(candidate.committed and candidate.directory_synced)
        self.assertEqual(1, quiesce.call_count)
        self.assertIn("load 流程完成", stdout.getvalue())

    def test_main_visible_parent_sync_failure_stops_without_claiming_durable_commit(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(LOAD, "preflight_services") as preflight, \
                mock.patch.object(LOAD, "start_services") as start, \
                mock.patch.object(LOAD, "commit_pinned_generation") as select, \
                redirect_stderr(stderr):
            result, caught, candidate, quiesce, restore_links, restore_prefix, \
                release_lock, _backend, _plan = self._exercise_main_transaction_failure(
                    OSError("independent main parent directory sync fault"),
                    failure_at="parent_sync",
                )

        self.assertEqual(1, result)
        self.assertIsNone(caught)
        self.assertTrue(candidate.committed)
        self.assertFalse(candidate.directory_synced)
        self.assertEqual(
            {"schema_version": 1, "release_id": "failure-candidate"},
            json.loads(candidate.destination.read_text(encoding="utf-8")),
        )
        self.assertFalse(candidate.temporary.exists())
        self.assertEqual(2, quiesce.call_count)
        restore_links.assert_not_called()
        restore_prefix.assert_not_called()
        release_lock.assert_called_once_with(91)
        preflight.assert_not_called()
        start.assert_not_called()
        select.assert_not_called()
        self.assertIn("[STATE] release B 已可见，目录持久化未确认", stderr.getvalue())
        self.assertNotIn("[STATE] release 已提交", stderr.getvalue())
        self.assertNotIn("未提交 release 的发布状态已回滚", stderr.getvalue())

    def test_main_selects_b_after_report_before_service_preflight(self) -> None:
        events: list[str] = []
        generation_b = self.project / "99-output-ztp/generations/bbbbbbbbbbbbbbbbbbbb"
        with mock.patch.object(
            LOAD, "ensure_previous_generation_frozen",
            side_effect=lambda _project: events.append("freeze-a")
            or "generations/aaaaaaaaaaaaaaaaaaaa",
        ), mock.patch.object(
            LOAD, "prepare_active_runtime_rollback_receipt",
            side_effect=lambda *_args: events.append("receipt-a")
            or self.project / "99-output-ztp/rollback-receipts/aaaaaaaaaaaaaaaaaaaa",
        ), mock.patch.object(
            LOAD, "stage_pinned_generation",
            side_effect=lambda *_args: events.append("stage-b") or generation_b,
        ), mock.patch.object(
            LOAD, "commit_pinned_generation",
            side_effect=lambda *_args, **_kwargs: events.append("select-b"),
        ) as commit:
            result = self._exercise_main_transaction_failure(
                LOAD.LoadError("injected service preflight failure"),
                lifecycle_events=events, parent_schema_version=2,
                failure_at="preflight",
            )[0]

        self.assertEqual(1, result)
        self.assertEqual(
            ["freeze-a", "receipt-a", "monitor-authority-attest", "generate", "stage-b",
             "dhcp-transaction", "report-commit", "select-b", "service-preflight"],
            events,
        )
        commit.assert_called_once_with(
            self.project, generation_b,
            expected_current="generations/aaaaaaaaaaaaaaaaaaaa",
        )

    def test_failed_b_selector_commit_never_claims_b_success_or_starts_service(self) -> None:
        selector = self.project / "99-output-ztp/current"
        selector.parent.mkdir(parents=True, exist_ok=True)
        selector.symlink_to("generations/aaaaaaaaaaaaaaaaaaaa")
        generation_b = self.project / "99-output-ztp/generations/bbbbbbbbbbbbbbbbbbbb"
        stderr = io.StringIO()
        with mock.patch.object(
            LOAD, "ensure_previous_generation_frozen",
            return_value="generations/aaaaaaaaaaaaaaaaaaaa",
        ), mock.patch.object(
            LOAD, "prepare_active_runtime_rollback_receipt",
            return_value=self.project / "99-output-ztp/rollback-receipts/aaaaaaaaaaaaaaaaaaaa",
        ), mock.patch.object(
            LOAD, "stage_pinned_generation", return_value=generation_b,
        ), mock.patch.object(
            LOAD, "commit_pinned_generation",
            side_effect=LOAD.LoadError("selector changed before B commit"),
        ), mock.patch.object(LOAD, "preflight_services") as preflight, \
                redirect_stderr(stderr):
            result = self._exercise_main_transaction_failure(
                LOAD.LoadError("DHCP step should not fail"),
                parent_schema_version=2, failure_at="select",
            )[0]

        self.assertEqual(1, result)
        self.assertEqual("generations/aaaaaaaaaaaaaaaaaaaa", os.readlink(selector))
        preflight.assert_not_called()
        self.assertIn("[FAILED] load 阶段失败：提交本轮已封存代次指针", stderr.getvalue())
        self.assertNotIn("load 流程完成", stderr.getvalue())

    def test_skip_infra_real_main_attests_monitor_authority_before_generation(self) -> None:
        lifecycle_events: list[str] = []
        result = self._exercise_main_transaction_failure(
            ValueError("stop after ordered workflow"),
            lifecycle_events=lifecycle_events,
        )[0]

        self.assertEqual(1, result)
        self.assertEqual(
            [
                "monitor-authority-attest",
                "generate",
                "dhcp-transaction",
            ],
            lifecycle_events,
        )

    def test_unsafe_monitor_authority_keeps_native_apache_path_stopped(self) -> None:
        lifecycle_events: list[str] = []
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result, _caught, _candidate, quiesce, *_rest = (
                self._exercise_main_transaction_failure(
                    ValueError("DHCP transaction must remain unreachable"),
                    lifecycle_events=lifecycle_events,
                    authority_failure=LOAD.LoadError("unsafe fixed authority"),
                )
            )

        self.assertEqual(1, result)
        self.assertEqual(["monitor-authority-attest"], lifecycle_events)
        self.assertEqual(2, quiesce.call_count)
        self.assertIn("只读校验 Monitor cache authority", stderr.getvalue())

    def test_pre_mutation_failure_also_reports_exact_full_rerun(self) -> None:
        stderr = io.StringIO()
        argv = [
            "demo", "--skip-doca", "--download-doca", "--no-upgrade",
            "--ztp-monitor-scope", "prod", "--host-role=management-server",
        ]
        with mock.patch.object(LOAD, "runtime_os", return_value="Linux"), \
                redirect_stderr(stderr):
            result = LOAD.main(argv)

        self.assertEqual(1, result)
        output = stderr.getvalue()
        self.assertIn("[FAILED] load 阶段失败：启动前参数检查", output)
        self.assertIn("[NEXT] 修复上述错误后完整重跑：", output)
        self.assertIn("11-load.py", output)
        self.assertIn("--skip-doca --download-doca --no-upgrade", output)
        self.assertIn("--ztp-monitor-scope prod", output)
        self.assertNotIn("[SAFE] 受管服务保持停止", output)

    def test_main_value_error_rolls_back_links_parent_temp_and_services(self) -> None:
        (
            result, caught, candidate, quiesce, restore, restore_prefix,
            release_lock, runtime_backend, runtime_plan,
        ) = (
            self._exercise_main_transaction_failure(ValueError("injected value error"))
        )
        self.assertEqual(result, 1)
        self.assertIsNone(caught)
        self.assertFalse(candidate.temporary.exists())
        restore.assert_called_once()
        restore_prefix.assert_called_once_with(mock.sentinel.prefix_snapshot)
        self.assertEqual(quiesce.call_count, 2)
        for call in quiesce.call_args_list:
            self.assertIs(runtime_backend, call.kwargs["runtime_backend"])
            self.assertIs(runtime_plan, call.kwargs["dhcp_runtime_plan"])
        release_lock.assert_called_once_with(91)

    def test_main_keyboard_interrupt_cleans_up_then_propagates(self) -> None:
        (
            result, caught, candidate, quiesce, restore, restore_prefix,
            release_lock, runtime_backend, runtime_plan,
        ) = (
            self._exercise_main_transaction_failure(KeyboardInterrupt())
        )
        self.assertIsNone(result)
        self.assertIsInstance(caught, KeyboardInterrupt)
        self.assertFalse(candidate.temporary.exists())
        restore.assert_called_once()
        restore_prefix.assert_called_once_with(mock.sentinel.prefix_snapshot)
        self.assertEqual(quiesce.call_count, 2)
        for call in quiesce.call_args_list:
            self.assertIs(runtime_backend, call.kwargs["runtime_backend"])
            self.assertIs(runtime_plan, call.kwargs["dhcp_runtime_plan"])
        release_lock.assert_called_once_with(91)

    def test_transaction_failure_fixture_never_enters_optional_monitor_prompt(self) -> None:
        with mock.patch.object(
            LOAD, "confirm_ztp_monitor_start", return_value=False,
        ) as prompt:
            result, caught, *_rest = self._exercise_main_transaction_failure(
                ValueError("injected failure after the prompt boundary"),
            )

        self.assertEqual(1, result)
        self.assertIsNone(caught)
        prompt.assert_not_called()

    def test_generate_configs_passes_global_eth_version_to_air_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LOAD, "ZTP_DIR", Path(directory),
        ), mock.patch.object(LOAD, "run") as runner:
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=False, dry_run=True,
                eth_version="5.18",
            )

        self.assertEqual(
            [
                sys.executable, "b-xlsx_to_dot.py", "-y",
                "--os-version", "5.18",
            ],
            runner.call_args_list[0].args[0],
        )

    def test_deployment_scope_defaults_all_and_specific_scope_is_explicit(self) -> None:
        default = LOAD.parse_args(["example-project"])
        air = LOAD.parse_args(["example-project", "--air"])
        prod = LOAD.parse_args(["example-project", "--prod"])

        self.assertEqual("all", default.deployment_scope)
        self.assertEqual("air", air.deployment_scope)
        self.assertEqual("prod", prod.deployment_scope)
        self.assertEqual("auto", default.ztp_monitor_scope)
        self.assertEqual("auto", air.ztp_monitor_scope)
        self.assertEqual("auto", prod.ztp_monitor_scope)

    def test_switch_scope_defaults_all_and_air_defaults_eth(self) -> None:
        default = LOAD.parse_args(["example-project"])
        eth = LOAD.parse_args(["example-project", "--switch", "eth"])
        ib = LOAD.parse_args(["example-project", "--switch", "ib"])
        nvl = LOAD.parse_args(["example-project", "--switch", "nvl"])
        air = LOAD.parse_args(["example-project", "--air"])

        self.assertEqual(
            "all", LOAD.validate_switch_scope_options(default, "all"),
        )
        self.assertEqual("eth", LOAD.validate_switch_scope_options(eth, "all"))
        self.assertEqual("ib", LOAD.validate_switch_scope_options(ib, "all"))
        self.assertEqual("nvl", LOAD.validate_switch_scope_options(nvl, "all"))
        self.assertEqual("eth", LOAD.validate_switch_scope_options(air, "air"))

        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), self.assertRaisesRegex(
                LOAD.LoadError, "AIR.*--switch eth",
            ):
                LOAD.validate_switch_scope_options(
                    LOAD.parse_args([
                        "example-project", "--air", "--switch", selected,
                    ]),
                    "air",
                )

    def test_ib_scope_ignores_unselected_eth_vrr_policy(self) -> None:
        document = {
            "schema_version": 2,
            "common": {
                "mgmt": {
                    "dhcp-server": {"status": "enabled", "package": "isc-dhcp-server"},
                    "http": {"status": "enabled", "package": "apache2", "http_root": "/var/www/html",
                             "address": "192.0.2.2"},
                    "ztp": {"status": "enabled", "ztp_url_prefix": "/ztp"},
                },
                "switch": {"system": {"dns": {}, "ntp": {}, "date-time": {}}},
            },
            "switches": [
                {"eth": {"version": "5.16.4", "system": {}}},
                {"ib": {"version": "25-02-8008", "system": {}}},
            ],
        }
        with self.assertRaisesRegex(LOAD.LoadError, "switches.eth.vrr"):
            LOAD.load_global(Path("unused"), global_data=document)

        settings = LOAD.load_global(
            Path("unused"), global_data=document, switch_scope="ib",
        )
        self.assertEqual("25-02-8008", settings.versions["ib"])

    def test_scoped_activation_forwards_switch_to_setup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            project.mkdir()
            p2p = project / "p2p.xlsx"
            p2p.write_bytes(b"xlsx")
            with mock.patch.object(LOAD, "active_project", return_value=project), \
                    mock.patch.object(LOAD, "run") as runner:
                LOAD.activate_project(
                    project, p2p, strict=False, dry_run=True,
                    host_role="workstation", switch_scope="ib",
                )
        command = runner.call_args.args[0]
        self.assertIn("--switch=ib", command)

    def test_switch_scope_filters_platform_families_and_upgrade_images(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings,
            versions={"eth": "5.18.1", "ib": "25.03.1010", "nvl": "25.02.4282"},
        )
        device_types = frozenset({"eth", "eth_spx", "spx", "ib", "nvl", "air"})
        self.assertEqual(
            frozenset({"eth", "eth_spx", "spx", "air"}),
            LOAD.filter_device_types_for_switch_scope(device_types, "eth"),
        )
        self.assertEqual(
            frozenset({"ib"}),
            LOAD.filter_device_types_for_switch_scope(device_types, "ib"),
        )
        self.assertEqual(
            frozenset({"nvl"}),
            LOAD.filter_device_types_for_switch_scope(device_types, "nvl"),
        )
        self.assertEqual(
            {"ib": "nvosv25-03-1010amd64.bin"},
            LOAD.expected_images(
                settings, device_types, deployment_scope="all", switch_scope="ib",
            ),
        )
        self.assertEqual(
            {"eth": "cumulus-linux-5.18.1-mlx-amd64.bin"},
            LOAD.expected_images(
                settings, device_types, deployment_scope="air", switch_scope="eth",
            ),
        )

    def test_shared_receipt_fixture_modes_are_explicit_under_private_umask(self) -> None:
        image = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        previous = os.umask(0o077)
        try:
            write_shared_receipt_image_fixture(image)
            self.assertEqual(0o644, stat.S_IMODE(image.stat().st_mode))
            receipt = write_shared_artifact_receipt(
                self.root, self.project, self.inputs, image,
            )
            self.assertEqual(0o755, stat.S_IMODE(receipt.parent.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(receipt.stat().st_mode))
        finally:
            os.umask(previous)

    def test_shared_artifact_receipt_binds_selected_image_and_project_inputs(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings, versions={"eth": "5.18.1"},
        )
        inputs = LOAD.replace(
            self.inputs, settings=settings,
            deployment_scope="air", switch_scope="eth",
        )
        self.root.chmod(0o755)
        image = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        write_shared_receipt_image_fixture(image)

        # Legacy/manual shared files remain supported when no receipt namespace
        # has ever been installed on this management server.
        self.assertIsNone(LOAD.validate_shared_artifact_receipts(
            self.project, inputs, {"eth": image},
            upgrade_enabled=True, root=self.root.resolve(),
        ))

        receipt = write_shared_artifact_receipt(
            self.root, self.project, inputs, image,
        )
        self.assertEqual(
            receipt.resolve(),
            LOAD.validate_shared_artifact_receipts(
                self.project, inputs, {"eth": image},
                upgrade_enabled=True, root=self.root.resolve(),
            ),
        )

    def test_shared_artifact_receipt_rejects_stale_or_misattributed_image(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings, versions={"eth": "5.18.1"},
        )
        inputs = LOAD.replace(
            self.inputs, settings=settings,
            deployment_scope="air", switch_scope="eth",
        )
        self.root.chmod(0o755)
        image = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        write_shared_receipt_image_fixture(image)

        cases = (
            {"project_name": "other-project"},
            {"deployment_scope": "prod"},
            {"switch_scope": "all"},
            {"global_sha256": "0" * 64},
            {"family": "ib", "version": "25.03.1010"},
        )
        for index, arguments in enumerate(cases):
            with self.subTest(arguments=arguments):
                receipt_dir = self.root / ".shared-artifact-receipts"
                if receipt_dir.exists():
                    shutil.rmtree(receipt_dir)
                write_shared_artifact_receipt(
                    self.root, self.project, inputs, image, **arguments,
                )
                with self.assertRaisesRegex(
                    LOAD.LoadError,
                    "共享制品.*(receipt|项目|范围|输入|consumer|版本)",
                ):
                    LOAD.validate_shared_artifact_receipts(
                        self.project, inputs, {"eth": image},
                        upgrade_enabled=True, root=self.root.resolve(),
                    )

        receipt_dir = self.root / ".shared-artifact-receipts"
        shutil.rmtree(receipt_dir)
        write_shared_artifact_receipt(self.root, self.project, inputs, image)
        with image.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(LOAD.LoadError, "共享制品.*(hash|大小)"):
            LOAD.validate_shared_artifact_receipts(
                self.project, inputs, {"eth": image},
                upgrade_enabled=True, root=self.root.resolve(),
            )

    def test_input_validation_checks_shared_receipt_before_key_or_image_write(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings, versions={"eth": "5.18.1"},
        )
        args = SimpleNamespace(
            deployment_scope="air", switch_scope="eth", mini=None,
            p2p_file=None, no_upgrade=False, ssh_dir=self.root / "ssh",
            dry_run=False, host_role="workstation",
        )
        selected_image = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        write_valid_nvos_image(selected_image)
        prepare_pubkeys = mock.Mock(return_value=())
        with mock.patch.object(LOAD, "load_global", return_value=settings), \
             mock.patch.object(LOAD, "apply_subnet_service_ips", return_value=settings), \
             mock.patch.object(LOAD, "load_device_types", return_value=frozenset({"eth"})), \
             mock.patch.object(LOAD, "select_p2p", return_value=self.p2p_file), \
             mock.patch.object(LOAD, "validate_subnet_file"), \
             mock.patch.object(LOAD, "project_air_topology_policy", return_value=None), \
             mock.patch.object(LOAD, "project_mini_air_devices", return_value=(None, None)), \
             mock.patch.object(LOAD, "prepare_images", return_value={"eth": selected_image}), \
             mock.patch.object(LOAD, "prepare_pubkeys", prepare_pubkeys), \
             mock.patch.object(
                 LOAD, "validate_shared_artifact_receipts",
                 side_effect=LOAD.LoadError("共享制品 receipt stale"),
             ) as receipt_gate:
            with self.assertRaisesRegex(LOAD.LoadError, "共享制品 receipt stale"):
                LOAD.validate_inputs(
                    self.project, args, allow_management_key_generation=False,
                )

        receipt_gate.assert_called_once()
        prepare_pubkeys.assert_not_called()

    def test_no_upgrade_skips_receipts_and_one_receipt_must_cover_all_images(self) -> None:
        unsafe = self.root / ".shared-artifact-receipts"
        unsafe.write_text("not a directory", encoding="ascii")
        self.assertIsNone(LOAD.validate_shared_artifact_receipts(
            self.project, self.inputs, {},
            upgrade_enabled=False, root=self.root.resolve(),
        ))
        unsafe.unlink()

        self.root.chmod(0o755)
        settings = LOAD.replace(
            self.inputs.settings,
            versions={"eth": "5.18.1", "ib": "25.03.1010"},
        )
        inputs = LOAD.replace(
            self.inputs, settings=settings,
            deployment_scope="prod", switch_scope="all",
        )
        eth = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        ib = self.root / "image/nvos-amd64-25.03.1010.bin"
        write_shared_receipt_image_fixture(eth)
        write_shared_receipt_image_fixture(ib)
        write_shared_artifact_receipt(
            self.root, self.project, inputs, eth,
            deployment_scope="prod", switch_scope="all",
        )
        with self.assertRaisesRegex(LOAD.LoadError, "共享制品 receipt.*不一致"):
            LOAD.validate_shared_artifact_receipts(
                self.project, inputs, {"eth": eth, "ib": ib},
                upgrade_enabled=True, root=self.root.resolve(),
            )

    def test_shared_artifact_receipt_rejects_installer_impossible_size(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings, versions={"eth": "5.18.1"},
        )
        inputs = LOAD.replace(
            self.inputs, settings=settings,
            deployment_scope="air", switch_scope="eth",
        )
        self.root.chmod(0o755)
        image = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        write_shared_receipt_image_fixture(image)
        write_shared_artifact_receipt(
            self.root, self.project, inputs, image,
            artifact_size=16 * 1024 * 1024 * 1024 + 1,
        )
        with self.assertRaisesRegex(LOAD.LoadError, "receipt artifact"):
            LOAD.validate_shared_artifact_receipts(
                self.project, inputs, {"eth": image},
                upgrade_enabled=True, root=self.root.resolve(),
            )
    def test_upgrade_image_requirements_follow_deployment_scope(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings,
            versions={"eth": "5.18.1", "ib": "25.03.1010", "nvl": "25.02.4282"},
        )
        device_types = frozenset({"eth", "ib", "nvl", "air"})

        self.assertEqual(
            {
                "eth": "cumulus-linux-5.18.1-mlx-amd64.bin",
                "ib": "nvosv25-03-1010amd64.bin",
                "nvl": "nvosv25-02-4282amd64.bin",
            },
            LOAD.expected_images(
                settings, device_types, deployment_scope="all",
            ),
        )
        self.assertEqual(
            {"eth": "cumulus-linux-5.18.1-mlx-amd64.bin"},
            LOAD.expected_images(
                settings, device_types, deployment_scope="air",
            ),
        )
        self.assertEqual(
            {
                "eth": "cumulus-linux-5.18.1-mlx-amd64.bin",
                "ib": "nvosv25-03-1010amd64.bin",
                "nvl": "nvosv25-02-4282amd64.bin",
            },
            LOAD.expected_images(
                settings, device_types, deployment_scope="prod",
            ),
        )
        with self.assertRaisesRegex(LOAD.LoadError, "deployment scope"):
            LOAD.expected_images(
                settings, device_types, deployment_scope="invalid",
            )

    def test_monitor_scope_inherits_specific_deployment_scope_and_rejects_conflict(self) -> None:
        project = Path("/tmp/example-project")
        self.assertEqual(
            "air",
            LOAD.resolve_ztp_monitor_scope(
                project, "auto", deployment_scope="air",
            ),
        )
        self.assertEqual(
            "prod",
            LOAD.resolve_ztp_monitor_scope(
                project, "auto", deployment_scope="prod",
            ),
        )
        self.assertEqual(
            "air",
            LOAD.resolve_ztp_monitor_scope(
                project, "air", deployment_scope="air",
            ),
        )
        with self.assertRaisesRegex(LOAD.LoadError, "部署范围.*监控范围.*冲突"):
            LOAD.resolve_ztp_monitor_scope(
                project, "prod", deployment_scope="air",
            )

    def test_mini_implies_air_scope_and_rejects_explicit_prod(self) -> None:
        implicit = LOAD.parse_args(["example-project", "--mini"])
        explicit = LOAD.parse_args(["example-project", "--air", "--mini"])

        for args in (implicit, explicit):
            with self.subTest(argv=args):
                deployment_scope = LOAD.validate_deployment_scope_options(args)
                self.assertEqual("air", deployment_scope)
                self.assertEqual(
                    "eth",
                    LOAD.validate_switch_scope_options(args, deployment_scope),
                )

        with self.assertRaisesRegex(LOAD.LoadError, "--mini.*AIR|--prod"):
            LOAD.validate_deployment_scope_options(
                LOAD.parse_args(["example-project", "--prod", "--mini"]),
            )

    def test_main_propagates_implicit_mini_scope_before_input_validation(self) -> None:
        observed: dict[str, str] = {}
        stderr = io.StringIO()

        def capture_selection(
            _project: Path, args, *, allow_management_key_generation: bool,
            host_role: str,
        ) -> tuple[object, object]:
            observed["deployment_scope"] = args.deployment_scope
            observed["switch_scope"] = args.switch_scope
            observed["host_role"] = host_role
            observed["allow_management_key_generation"] = (
                allow_management_key_generation
            )
            raise LOAD.LoadError("stop after normalized selection")

        with mock.patch.object(
            LOAD, "runtime_os", return_value="Linux",
        ), mock.patch.object(
            LOAD, "supports_local_ztp_services", return_value=False,
        ), mock.patch.object(
            LOAD, "resolve_project", return_value=self.project,
        ), mock.patch.object(
            LOAD, "initialize_from_template",
        ), mock.patch.object(
            LOAD, "validate_inputs", side_effect=capture_selection,
        ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            result = LOAD.main([
                str(self.project), "--mini", "--dry-run",
                "--host-role=workstation",
            ])

        self.assertEqual(1, result)
        self.assertEqual(
            {
                "deployment_scope": "air",
                "switch_scope": "eth",
                "host_role": "workstation",
                "allow_management_key_generation": False,
            },
            observed,
            stderr.getvalue(),
        )

    def test_invalid_deployment_scope_stops_main_before_lock_or_project_write(self) -> None:
        invalid_argv = (
            ["example-project", "--prod", "--mini"],
            ["example-project", "--air", "--switch", "ib"],
            ["example-project", "--air", "--switch", "nvl"],
            [
                "example-project", "--air",
                "--ztp-monitor-scope", "prod",
            ],
        )
        for argv in invalid_argv:
            with self.subTest(argv=argv), mock.patch.object(
                LOAD, "acquire_deployment_lock",
                side_effect=AssertionError("invalid scope must not acquire lock"),
            ), mock.patch.object(
                LOAD, "initialize_from_template",
                side_effect=AssertionError("invalid scope must not touch project"),
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(1, LOAD.main(argv))

    def test_dhcp_records_are_filtered_by_deployment_scope(self) -> None:
        records = [
            {"hostname": "leaf01", "type": "eth", "iface": "eth0"},
            {"hostname": "ib01", "type": "ib", "iface": "eth0"},
            {"hostname": "AIR-leaf01", "type": "air", "iface": "eth0"},
        ]
        self.assertEqual(
            ["leaf01", "ib01", "AIR-leaf01"],
            [item["hostname"] for item in DHCP.records_for_deployment_scope(
                records, "all",
            )],
        )
        self.assertEqual(
            ["leaf01", "ib01"],
            [item["hostname"] for item in DHCP.records_for_deployment_scope(
                records, "prod",
            )],
        )
        self.assertEqual(
            ["AIR-leaf01"],
            [item["hostname"] for item in DHCP.records_for_deployment_scope(
                records, "air",
            )],
        )

    def test_device_csv_validates_platform_fields_only_for_selected_switch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow([
                    "hostname", "type", "template", "eth0_ip", "netmask",
                    "eth0_gw", "eth0_mac", "eth1_ip", "netmask",
                    "eth1_gw", "eth1_mac",
                ])
                writer.writerow([
                    "leaf01", "eth", "leaf", "192.0.2.10", "24",
                    "192.0.2.1", "02:00:00:00:00:01", "", "", "", "",
                ])
                writer.writerow([
                    "ib01", "ib", "", "not-an-ip", "", "", "", "",
                    "", "", "",
                ])

            self.assertEqual(
                frozenset({"eth"}),
                LOAD.load_device_types(path, switch_scope="eth"),
            )
            with self.assertRaisesRegex(LOAD.LoadError, "eth0_ip"):
                LOAD.load_device_types(path, switch_scope="ib")

    def test_publisher_validates_platform_fields_only_for_selected_switch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow([
                    "hostname", "type", "template", "eth0_ip", "netmask",
                    "eth0_gw", "eth0_mac", "eth1_ip", "netmask",
                    "eth1_gw", "eth1_mac",
                ])
                writer.writerow([
                    "leaf01", "eth", "leaf", "", "24", "192.0.2.1",
                    "02:00:00:00:00:01", "", "", "", "",
                ])
                writer.writerow([
                    "ib01", "ib", "", "192.0.2.20", "24", "192.0.2.1",
                    "02:00:00:00:00:02", "", "", "", "",
                ])

            selected = PUBLISHER.load_csv(str(path), switch_scope="ib")
            self.assertEqual(["ib01"], [item["hostname"] for item in selected.values()])
            with self.assertRaisesRegex(ValueError, "必填字段"):
                PUBLISHER.load_csv(str(path), switch_scope="eth")

    def test_dhcp_records_are_filtered_by_environment_and_switch_scope(self) -> None:
        records = [
            {"hostname": "leaf01", "type": "eth", "iface": "eth0"},
            {"hostname": "spx01", "type": "eth_spx", "iface": "eth0"},
            {"hostname": "ib01", "type": "ib", "iface": "eth0"},
            {"hostname": "nvl01", "type": "nvl", "iface": "eth0"},
            {"hostname": "AIR-leaf01", "type": "air", "iface": "eth0"},
        ]
        self.assertEqual(
            ["leaf01", "spx01"],
            [item["hostname"] for item in DHCP.records_for_release_scope(
                records, deployment_scope="prod", switch_scope="eth",
            )],
        )
        self.assertEqual(
            ["ib01"],
            [item["hostname"] for item in DHCP.records_for_release_scope(
                records, deployment_scope="all", switch_scope="ib",
            )],
        )
        self.assertEqual(
            ["AIR-leaf01"],
            [item["hostname"] for item in DHCP.records_for_release_scope(
                records, deployment_scope="air", switch_scope="eth",
            )],
        )

    def test_switch_scope_is_forwarded_and_only_selected_generator_runs(self) -> None:
        def commands_for(selected: str) -> list[list[str]]:
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                LOAD, "ZTP_DIR", Path(directory),
            ), mock.patch.object(
                LOAD, "_device_types_after_dhcp",
                return_value=frozenset({selected}),
            ), mock.patch.object(LOAD, "run") as runner:
                LOAD.generate_configs(
                    frozenset({"eth", "ib", "nvl"}),
                    install_dhcp=False,
                    dry_run=True,
                    eth_version="5.18.1",
                    deployment_scope="prod",
                    switch_scope=selected,
                )
                return [call.args[0] for call in runner.call_args_list]

        eth_commands = commands_for("eth")
        ib_commands = commands_for("ib")
        nvl_commands = commands_for("nvl")

        self.assertTrue(any("b-xlsx_to_dot.py" in command for command in eth_commands))
        self.assertFalse(any("b-xlsx_to_dot.py" in command for command in ib_commands))
        self.assertFalse(any("b-xlsx_to_dot.py" in command for command in nvl_commands))
        # The IB counterpart of b-xlsx_to_dot.py (owner 2026-10-21): only IB runs it.
        self.assertTrue(any("p2p-to-validation.py" in command for command in ib_commands))
        self.assertFalse(any("p2p-to-validation.py" in command for command in eth_commands))
        self.assertFalse(any("p2p-to-validation.py" in command for command in nvl_commands))
        for selected, commands in (
            ("eth", eth_commands), ("ib", ib_commands), ("nvl", nvl_commands),
        ):
            with self.subTest(selected=selected):
                self.assertTrue(commands)
                self.assertTrue(all(
                    "--switch" in command
                    and command[command.index("--switch") + 1] == selected
                    for command in commands
                    if command[1] not in {"b-xlsx_to_dot.py", "p2p-to-validation.py"}
                ), commands)
                branches = [
                    command[command.index("--branch") + 1]
                    for command in commands if "--branch" in command
                ]
                self.assertEqual(
                    ["eth"] if selected == "eth" else ["ib"], branches,
                )

    def test_nvos_generator_validates_only_the_selected_switch_family(self) -> None:
        devices = [
            {"hostname": "ib01", "type": "ib"},
            {"hostname": "nvl01", "type": "nvl"},
        ]

        def validate(selected):
            return ["nvl invalid"] if any(
                item["type"] == "nvl" for item in selected
            ) else []

        with mock.patch.object(
            GENERATOR, "_load_csv_ib", return_value=(devices, []),
        ), mock.patch.object(
            GENERATOR, "_validate_fields_ib", side_effect=validate,
        ), mock.patch.object(
            GENERATOR, "_check_duplicates_ib", return_value=[],
        ), mock.patch.object(
            GENERATOR, "load_global", return_value={},
        ), mock.patch.object(
            GENERATOR, "_generate_group_ib", return_value=(1, 0),
        ) as generate, redirect_stdout(io.StringIO()):
            self.assertEqual(
                1, GENERATOR._generate_all_ib(switch_scope="ib"),
            )

        selected_devices = generate.call_args.args[0]
        self.assertEqual(["ib01"], [item["hostname"] for item in selected_devices])

    def test_dhcp_child_manifest_records_switch_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = tuple(root / name for name in (
                "dhcpd.conf", "dhcpd_eth.hosts",
                "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
            ))
            for output in outputs:
                output.write_text(f"{output.name}\n", encoding="utf-8")
            manifest = root / "dhcp-release-manifest.json"
            DHCP.write_release_manifest(
                manifest,
                [{
                    "hostname": "ib01", "type": "ib", "iface": "eth0",
                    "mac_norm": "02:00:00:00:00:11", "ip": "192.0.2.11",
                    "netmask": "24", "identity_pending": False,
                    "dhcp_assignment": "fixed", "served_subnet": "192.0.2.0/24",
                    "src": "fixture.csv",
                }],
                [{
                    "shared_network": "clients",
                    "_network": ipaddress.ip_network("192.0.2.0/24"),
                    "range_start": "192.0.2.100", "range_end": "192.0.2.200",
                    "routers": "192.0.2.1", "ztp_service_ip": "192.0.2.2",
                    "cumulus_profile": "oob", "nvos_ztp": "yes",
                    "cumulus_provision_url": "", "bootfile_name": "nvos-amd64.bin",
                }],
                outputs,
                deployment_scope="prod",
                switch_scope="ib",
            )
            document = json.loads(manifest.read_text(encoding="utf-8"))

        self.assertEqual("prod", document["deployment_scope"])
        self.assertEqual("ib", document["switch_scope"])
        self.assertEqual(["ib01"], [item["hostname"] for item in document["devices"]])

    def test_switch_scope_retires_unselected_latest_links_transactionally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            eth = project / "99-output-eth/latest"
            nvos = project / "99-output-ib_nvl/latest"
            eth.parent.mkdir(parents=True)
            nvos.parent.mkdir(parents=True)
            eth.symlink_to("eth-release")
            nvos.symlink_to("nvos-release")

            snapshot = LOAD.snapshot_release_links(project)
            LOAD.retire_unselected_release_links(project, "eth", dry_run=False)
            self.assertTrue(eth.is_symlink())
            self.assertFalse(os.path.lexists(nvos))
            LOAD.restore_release_links(snapshot)
            self.assertEqual("eth-release", os.readlink(eth))
            self.assertEqual("nvos-release", os.readlink(nvos))

    def test_parent_release_rejects_child_from_another_switch_scope(self) -> None:
        inputs = LOAD.replace(self.inputs, switch_scope="eth")
        inventory = [{
            "hostname": "leaf01", "hostname_key": "leaf01", "type": "eth",
            "eth0_mac": "02:00:00:00:00:01", "eth1_mac": "",
            "identity_state": "managed", "identity_source": "devices_config",
        }]
        with mock.patch.object(
            LOAD, "_release_inventory", return_value=inventory,
        ), mock.patch.object(
            LOAD, "_augment_air_json_inventory", return_value=inventory,
        ), mock.patch.object(
            LOAD, "_load_release_json",
            return_value={"deployment_scope": "all", "switch_scope": "ib"},
        ):
            with self.assertRaisesRegex(
                LOAD.LoadError, "DHCP release switch scope",
            ):
                LOAD.validate_and_publish_release(
                    self.project, inputs, publish=False,
                )

    def test_dhcp_release_manifest_binds_scope_and_excludes_other_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = tuple(root / name for name in (
                "dhcpd.conf", "dhcpd_eth.hosts",
                "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
            ))
            for output in outputs:
                output.write_text(f"{output.name}\n", encoding="utf-8")
            manifest = root / "dhcp-release-manifest.json"
            records = [{
                "hostname": "AIR-leaf01", "type": "air", "iface": "eth0",
                "mac_norm": "02:00:00:00:00:01", "ip": "192.0.2.10",
                "netmask": "24", "identity_pending": False,
                "dhcp_assignment": "fixed", "served_subnet": "192.0.2.0/24",
                "src": "fixture.csv",
            }]
            subnets = [{
                "shared_network": "clients",
                "_network": ipaddress.ip_network("192.0.2.0/24"),
                "range_start": "192.0.2.100", "range_end": "192.0.2.200",
                "routers": "192.0.2.1", "ztp_service_ip": "192.0.2.2",
                "cumulus_profile": "oob", "nvos_ztp": "no",
                "cumulus_provision_url": "http://192.0.2.2/ztp/bootstrap",
                "bootfile_name": "",
            }]

            DHCP.write_release_manifest(
                manifest, records, subnets, outputs,
                deployment_scope="air",
            )
            document = json.loads(manifest.read_text(encoding="utf-8"))

        self.assertEqual("air", document["deployment_scope"])
        self.assertEqual(["AIR-leaf01"], [
            item["hostname"] for item in document["devices"]
        ])

    def test_scope_is_forwarded_to_every_generator_branch(self) -> None:
        def commands_for(scope: str) -> list[list[str]]:
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                LOAD, "ZTP_DIR", Path(directory),
            ), mock.patch.object(
                LOAD, "_device_types_after_dhcp",
                return_value=(
                    frozenset({"air"}) if scope == "air"
                    else frozenset({"eth", "ib", "nvl"})
                ),
            ), mock.patch.object(LOAD, "run") as runner:
                LOAD.generate_configs(
                    frozenset({"eth", "ib", "nvl"}),
                    install_dhcp=False, dry_run=True,
                    eth_version="5.18.1", deployment_scope=scope,
                )
                return [call.args[0] for call in runner.call_args_list]

        all_commands = commands_for("all")
        prod_commands = commands_for("prod")
        air_commands = commands_for("air")
        self.assertTrue(all(
            "--deployment-scope" not in command for command in all_commands
        ))
        # The IB expected-topology converter (owner 2026-10-21) has no environment axis: IB is
        # Production-only, so it runs in all/prod and never in air.
        converter = [sys.executable, "p2p-to-validation.py"]
        self.assertIn(converter, all_commands)
        self.assertIn(converter, prod_commands)
        self.assertNotIn(converter, air_commands)
        prod_commands = [command for command in prod_commands if command != converter]
        for command in prod_commands:
            self.assertEqual(
                "prod", command[command.index("--deployment-scope") + 1],
                command,
            )
        for command in air_commands:
            self.assertEqual(
                "air", command[command.index("--deployment-scope") + 1],
                command,
            )
        self.assertTrue(any(
            "--branch" in command
            and command[command.index("--branch") + 1] == "ib"
            for command in all_commands
        ))
        self.assertTrue(any(
            "--branch" in command
            and command[command.index("--branch") + 1] == "ib"
            for command in prod_commands
        ))
        self.assertFalse(any(
            "--branch" in command
            and command[command.index("--branch") + 1] == "ib"
            for command in air_commands
        ))

    def test_cumulus_air_scope_renders_only_required_production_sources(self) -> None:
        devices = {
            "leaf01": {"hostname": "leaf01"},
            "leaf02": {"hostname": "leaf02"},
            "leaf03": {"hostname": "leaf03"},
        }
        selected = GENERATOR.select_cumulus_generation_devices(
            devices,
            deployment_scope="air",
            air_source_hostnames={"leaf01", "leaf03"},
        )
        self.assertEqual(["leaf01", "leaf03"], list(selected))
        self.assertEqual(
            devices,
            GENERATOR.select_cumulus_generation_devices(
                devices, deployment_scope="all", air_source_hostnames=set(),
            ),
        )
        self.assertEqual(
            devices,
            GENERATOR.select_cumulus_generation_devices(
                devices, deployment_scope="prod", air_source_hostnames=set(),
            ),
        )
        with self.assertRaisesRegex(ValueError, "AIR.*来源设备.*missing"):
            GENERATOR.select_cumulus_generation_devices(
                devices,
                deployment_scope="air",
                air_source_hostnames={"leaf01", "missing"},
            )

    def test_air_mini_scope_is_forwarded_and_skips_nvos_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "03-air-topology-policy.json"
            policy.write_text(
                json.dumps(h19_mini_policy()) + "\n", encoding="utf-8",
            )
            with mock.patch.object(
                LOAD, "ZTP_DIR", root,
            ), mock.patch.object(
                LOAD, "_device_types_after_dhcp",
                return_value=frozenset({"air"}),
            ), mock.patch.object(
                LOAD, "newest_directory", return_value=Path("run"),
            ), mock.patch.object(LOAD, "run") as runner:
                LOAD.generate_configs(
                    frozenset({"eth", "ib", "nvl"}),
                    install_dhcp=False,
                    dry_run=True,
                    eth_version="5.18.1",
                    air_topology_policy=policy,
                    mini_air=True,
                    mini_devices_file=root / "04-air-mini-devices.txt",
                    deployment_scope="air",
                )

        commands = [call.args[0] for call in runner.call_args_list]
        self.assertIn(
            [sys.executable, "c1-generate_dhcp.py", "-y", "--preserve-input-csv", "--deployment-scope", "air"],
            commands,
        )
        self.assertTrue(any(
            command[1:] == [
                "90-c2-generate_configs.py", "--branch", "eth", "-y",
                "--presentation-context", "load-parent",
                "--deployment-scope", "air",
            ]
            for command in commands
        ), commands)
        self.assertFalse(any(
            len(command) > 2 and command[1] == "90-c2-generate_configs.py"
            and command[command.index("--branch") + 1] == "ib"
            for command in commands
        ), commands)

    def test_cumulus_load_prefers_current_description_pointer_over_legacy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r22-load-description-") as name:
            root = Path(name)
            output = root / "config/cumulus/template/99-output"
            output.mkdir(parents=True)
            base = output / "20261002_120000"
            base.mkdir()
            legacy = output / f"{base.name}_with_desc"
            legacy.mkdir()
            version = output / f".{base.name}_with_desc.version.{('a' * 32)}"
            version.mkdir()
            pointer = output / f"{base.name}_with_desc_current"
            pointer.symlink_to(version.name)
            with mock.patch.object(LOAD, "ZTP_DIR", root), mock.patch.object(
                LOAD, "_device_types_after_dhcp", return_value=frozenset({"eth"}),
            ), mock.patch.object(
                LOAD, "newest_directory", return_value=base,
            ), mock.patch.object(LOAD, "run") as runner:
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dhcp_enabled=False,
                )
            publisher = [
                call.args[0] for call in runner.call_args_list
                if call.args[0][1] == "d-hostname2mac.py"
            ]
            self.assertEqual(1, len(publisher))
            self.assertEqual(str(pointer), publisher[0][-1])

    def test_cumulus_load_rejects_invalid_current_pointer_without_legacy_fallback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r22-load-description-bad-") as name:
            root = Path(name)
            output = root / "config/cumulus/template/99-output"
            output.mkdir(parents=True)
            base = output / "20261002_120000"
            base.mkdir()
            (output / f"{base.name}_with_desc").mkdir()
            pointer = output / f"{base.name}_with_desc_current"
            pointer.symlink_to("../outside")
            with mock.patch.object(LOAD, "ZTP_DIR", root), mock.patch.object(
                LOAD, "_device_types_after_dhcp", return_value=frozenset({"eth"}),
            ), mock.patch.object(
                LOAD, "newest_directory", return_value=base,
            ), mock.patch.object(LOAD, "run") as runner:
                with self.assertRaisesRegex(LOAD.LoadError, "description|pointer"):
                    LOAD.generate_configs(
                        frozenset({"eth"}), install_dhcp=False,
                        dhcp_enabled=False,
                    )
            self.assertFalse(any(
                call.args[0][1] == "d-hostname2mac.py"
                for call in runner.call_args_list
            ))

    def test_schema_v1_bond_collision_stops_load_before_child_or_parent_publish(self) -> None:
        template_dir, devices = self._prepare_h04_schema_v1_collision_generator()
        current = self.project / "99-output-ztp/current-release.json"
        current.parent.mkdir(parents=True)
        current.write_bytes(b"parent-release-before-collision\n")
        current.chmod(0o640)
        os.utime(current, ns=(1_640_000_000_000_000_000,) * 2)
        latest = self.project / "99-output-eth/latest"

        def regular_identity(path: Path) -> tuple[bytes, int, int, int, int]:
            metadata = path.stat()
            return (
                path.read_bytes(), metadata.st_dev, metadata.st_ino,
                stat.S_IMODE(metadata.st_mode), metadata.st_mtime_ns,
            )

        devices_before = regular_identity(devices)
        current_before = regular_identity(current)
        latest_before = (os.readlink(latest), latest.lstat())
        release_entries_before = tuple(sorted(
            path.name for path in (self.project / "99-output-eth").iterdir()
        ))
        commands = []

        def run_child(command, *, cwd=None, dry_run=False, **_kwargs):
            self.assertFalse(dry_run)
            commands.append(tuple(command))
            if len(command) > 1 and command[1] == "90-c2-generate_configs.py":
                completed = subprocess.run(
                    command,
                    cwd=cwd,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=30,
                    check=False,
                )
                if completed.returncode:
                    raise LOAD.LoadError(completed.stdout)

        messages = []
        newest = mock.Mock(side_effect=AssertionError("child publish is unreachable"))
        with mock.patch.object(LOAD, "run", side_effect=run_child), mock.patch.object(
            LOAD, "_device_types_after_dhcp", return_value=frozenset({"eth"}),
        ), mock.patch.object(LOAD, "newest_directory", newest), mock.patch.object(
            LOAD, "info", side_effect=messages.append,
        ), self.assertRaises(LOAD.LoadError) as raised:
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=True, schema_version=1,
            )

        diagnostic = str(raised.exception)
        self.assertIn(H04_COLLISION_HOSTNAME, diagnostic)
        self.assertIn("bond1s0", diagnostic)
        self.assertIn("bond10", diagnostic)
        self.assertEqual(
            ["b-xlsx_to_dot.py", "c1-generate_dhcp.py", "90-c2-generate_configs.py"],
            [command[1] for command in commands],
        )
        self.assertFalse(any(
            "d-hostname2mac.py" in command for command in commands
        ))
        newest.assert_not_called()
        self.assertFalse(any("DHCP 安装已延后" in message for message in messages))
        self.assertEqual(devices_before, regular_identity(devices))
        self.assertEqual(current_before, regular_identity(current))
        latest_after = latest.lstat()
        self.assertEqual(latest_before[0], os.readlink(latest))
        self.assertEqual(latest_before[1].st_dev, latest_after.st_dev)
        self.assertEqual(latest_before[1].st_ino, latest_after.st_ino)
        self.assertEqual(latest_before[1].st_mtime_ns, latest_after.st_mtime_ns)
        self.assertEqual(
            release_entries_before,
            tuple(sorted(
                path.name for path in (self.project / "99-output-eth").iterdir()
            )),
        )
        self.assertEqual([], list(template_dir.glob("91-devices.yaml.tmp.*")))

    def test_scope_selection_workflow_agrees_across_dhcp_generation_and_publication(self) -> None:
        records = [
            {"hostname": "leaf01", "type": "eth"},
            {"hostname": "leaf02", "type": "eth"},
            {"hostname": "AIR-leaf01", "type": "air"},
        ]
        generator_devices = {
            "leaf01": {"hostname": "leaf01"},
            "leaf02": {"hostname": "leaf02"},
        }
        publisher_devices = {
            "leaf01": {"hostname": "leaf01", "dev_type": "eth"},
            "leaf02": {"hostname": "leaf02", "dev_type": "eth"},
            "air-leaf01": {"hostname": "AIR-leaf01", "dev_type": "air"},
        }
        profiles = {
            "air-leaf01": {
                "hostname": "AIR-leaf01", "source_hostname": "leaf01",
                "profile": "full", "apply_mode": "replace",
            },
        }

        dhcp = DHCP.records_for_deployment_scope(records, "air")
        generated = GENERATOR.select_cumulus_generation_devices(
            generator_devices,
            deployment_scope="air",
            air_source_hostnames={"leaf01"},
        )
        published_devices, published_profiles = (
            PUBLISHER.scope_cumulus_publish_inventory(
                publisher_devices, profiles, deployment_scope="air",
            )
        )

        self.assertEqual(["AIR-leaf01"], [item["hostname"] for item in dhcp])
        self.assertEqual(["leaf01"], list(generated))
        self.assertEqual(["air-leaf01"], list(published_devices))
        self.assertEqual(["air-leaf01"], list(published_profiles))

    def test_description_patch_reports_unused_breakout_fillers_as_info(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "generated"
            output.mkdir()
            (output / "leaf01.yaml").write_text(
                "- set:\n"
                "    interface:\n"
                "      swp13:\n"
                "        link:\n"
                "          breakout:\n"
                "            8x:\n"
                "              lanes-per-port: '1'\n"
                "        type: swp\n"
                "      swp13s0:\n"
                "        type: swp\n"
                "      swp13s2:\n"
                "        type: swp\n"
                "      swp13s3:\n"
                "        type: swp\n"
                "        qos:\n"
                "          pfc-watchdog:\n"
                "            state: enable\n"
                "      swp13s4:\n"
                "        type: swp\n"
                "      swp99:\n"
                "        bridge:\n"
                "          domain:\n"
                "            br_default: {}\n"
                "        type: swp\n"
                "    router:\n"
                "      bgp:\n"
                "        autonomous-system:\n"
                "          '65000':\n"
                "            address-family:\n"
                "              ipv4-unicast:\n"
                "                redistribute:\n"
                "                  connected: {}\n"
                "            interface:\n"
                "              swp13s4:\n"
                "                type: unnumbered\n",
                encoding="utf-8",
            )
            dot = root / "topology-lldpq.dot"
            dot.write_text(
                '"site-leaf01":"swp13s0" -- "peer01":"swp1"\n',
                encoding="utf-8",
            )
            source_csv = root / "02-devices_config.csv"
            source_csv.write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            output_text = io.StringIO()
            with mock.patch.object(
                GENERATOR, "_load_csv_hostnames", return_value={"leaf01"},
            ), mock.patch.object(GENERATOR, "_CSV_FILE", str(source_csv)), \
                    redirect_stdout(output_text):
                GENERATOR._run_patch_descriptions(str(dot), str(output))

        report = output_text.getvalue()
        self.assertIn(
            "[INFO] breakout 模式自动补齐的未使用子端口",
            report,
        )
        self.assertIn("P2P 无记录，未添加 description", report)
        self.assertIn("leaf01: swp13s2, swp13s3", report)
        self.assertIn(
            "[WARNING] yaml 中有此接口但 dot 中无连接记录，未添加 description",
            report,
        )
        self.assertIn("leaf01: swp99, swp13s4", report)

    def test_p2p_endpoint_states_accept_historical_empty_forms_only(self) -> None:
        empty_forms = (
            ("", ""),
            ("Empty", ""),
            ("empty", "Empty"),
            ("NA", "N/A"),
            ("None", "null"),
            ("-", ""),
        )
        for device, port in empty_forms:
            with self.subTest(device=device, port=port):
                self.assertEqual(
                    "empty",
                    TOPOLOGY._classify_p2p_endpoint(
                        device, port, context="TAN Links row 3 source",
                    ),
                )
        self.assertEqual(
            "real",
            TOPOLOGY._classify_p2p_endpoint(
                "leaf01", "1/1", context="TAN Links row 4 source",
            ),
        )
        for device, port in (
            ("leaf01", ""),
            ("", "1/1"),
            ("Empty", "1/1"),
            ("leaf01", "Empty"),
        ):
            with self.subTest(invalid=(device, port)):
                with self.assertRaisesRegex(ValueError, "端点只填写了一部分"):
                    TOPOLOGY._classify_p2p_endpoint(
                        device, port, context="TAN Links row 5 destination",
                    )

    def test_p2p_extraction_preserves_blank_and_placeholder_peer_intent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workbook_path = Path(directory) / "p2p.xlsx"
            workbook = TOPOLOGY.openpyxl.Workbook()
            sheet = workbook.active
            sheet.title = "TAN Links"
            sheet.append([None] * 6 + ["Source", None, None, None, None, None, "Dest", None])
            sheet.append([None] * 6 + ["name", "port", None, None, None, None, "name", "port"])
            sheet.append([None] * 6 + ["leaf01", "1/1", None, None, None, None, "peer01", "2/1"])
            sheet.append([None] * 6 + ["Empty", None, None, None, None, None, "leaf01", "1/2"])
            sheet.append([None] * 6 + [None, None, None, None, None, None, "leaf01", "1/3"])
            sheet.append([None] * 6 + ["leaf01", "1/4", None, None, None, None, "Empty", "Empty"])
            fallback = workbook.create_sheet("OOB Plan")
            fallback.cell(row=2, column=7, value="leaf99")
            fallback.cell(row=2, column=8, value="1/9")
            fallback.cell(row=2, column=13, value="Empty")
            workbook.save(workbook_path)
            workbook.close()

            source_rows = TOPOLOGY._extract_xlsx_rows(
                str(workbook_path), legacy_columns=True,
            )

        self.assertEqual(
            [
                ("leaf01", "1/1", "peer01", "2/1"),
                ("Empty", "", "leaf01", "1/2"),
                ("", "", "leaf01", "1/3"),
                ("leaf01", "1/4", "Empty", "Empty"),
            ],
            [row["fields"] for row in source_rows],
        )
        self.assertEqual([3, 4, 5, 6], [row["row"] for row in source_rows])
        self.assertEqual({"TAN Links"}, {row["sheet"] for row in source_rows})

    def test_p2p_empty_intent_is_bound_and_conflicts_with_real_peer(self) -> None:
        dot_bytes = b'graph "example" {\n"leaf01":"swp1" -- "peer01":"swp2"\n}\n'
        rows = [
            {"sheet": "TAN Links", "row": 3,
             "fields": ("leaf01", "swp1", "peer01", "swp2")},
            {"sheet": "TAN Links", "row": 4,
             "fields": ("leaf01", "swp3", "Empty", "")},
        ]
        document = TOPOLOGY._build_description_intent_document(
            rows,
            inv_patterns={"Eth-SW": ["leaf*"]}, type_order=["Eth-SW"],
            port_direct={}, port_switch={},
            splitter_profiles={}, lldpq_bytes=dot_bytes,
            source_workbook="p2p.xlsx",
        )
        self.assertEqual(1, document["schema_version"])
        self.assertEqual(hashlib.sha256(dot_bytes).hexdigest(), document["lldpq_sha256"])
        self.assertEqual(
            [{
                "device": "leaf01", "port": "swp3", "source_port": "swp3",
                "sheet": "TAN Links", "row": 4,
            }],
            document["empty_endpoints"],
        )
        physical, _ztp_bmc = TOPOLOGY._resolved_physical_links(
            [row["fields"] for row in rows],
            inv_patterns={"Eth-SW": ["leaf*"]}, type_order=["Eth-SW"],
            port_direct={}, port_switch={}, splitter_profiles={},
        )
        self.assertEqual(
            [("leaf01", "swp1", "peer01", "swp2")], physical,
        )

        conflicting = rows + [{
            "sheet": "TAN Links", "row": 5,
            "fields": ("leaf01", "swp3", "peer02", "swp4"),
        }]
        with self.assertRaisesRegex(
            ValueError, r"leaf01:swp3.*row 4.*row 5",
        ):
            TOPOLOGY._build_description_intent_document(
                conflicting,
                inv_patterns={"Eth-SW": ["leaf*"]}, type_order=["Eth-SW"],
                port_direct={}, port_switch={},
                splitter_profiles={}, lldpq_bytes=dot_bytes,
                source_workbook="p2p.xlsx",
            )

    def test_p2p_empty_intent_patches_description_and_keeps_fallback_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "generated"
            output.mkdir()
            (output / "leaf01.yaml").write_text(
                "- set:\n"
                "    interface:\n"
                "      swp13:\n"
                "        link:\n"
                "          breakout:\n"
                "            8x:\n"
                "              lanes-per-port: '1'\n"
                "        type: swp\n"
                "      swp13s0:\n"
                "        type: swp\n"
                "      swp13s1:\n"
                "        type: swp\n"
                "      swp13s2:\n"
                "        type: swp\n"
                "      swp13s3:\n"
                "        bridge:\n"
                "          domain:\n"
                "            br_default: {}\n"
                "        type: swp\n",
                encoding="utf-8",
            )
            dot = root / "topology-lldpq.dot"
            dot_bytes = (
                'graph "example" {\n'
                '"site-leaf01":"swp13s0" -- "peer01":"swp1"\n'
                '}\n'
            ).encode("utf-8")
            dot.write_bytes(dot_bytes)
            intent = TOPOLOGY._build_description_intent_document(
                [
                    {
                        "sheet": "TAN Links", "row": 9,
                        "fields": ("site-leaf01", "swp13s1", "Empty", ""),
                    },
                    {
                        "sheet": "TAN Links", "row": 10,
                        "fields": ("site-leaf01", "swp13s4", "", ""),
                    },
                    {
                        "sheet": "TAN Links", "row": 11,
                        "fields": ("site-missing01", "swp1", "Empty", "Empty"),
                    },
                ],
                inv_patterns={"Eth-SW": ["site-*"]},
                type_order=["Eth-SW"], port_direct={}, port_switch={},
                splitter_profiles={}, lldpq_bytes=dot_bytes,
                source_workbook="p2p.xlsx",
            )
            TOPOLOGY._write_description_intent(dot, intent)

            source_csv = root / "02-devices_config.csv"
            source_csv.write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            output_text = io.StringIO()
            with mock.patch.object(
                GENERATOR, "_load_csv_hostnames", return_value={"leaf01"},
            ), mock.patch.object(GENERATOR, "_CSV_FILE", str(source_csv)), \
                    redirect_stdout(output_text):
                GENERATOR._run_patch_descriptions(str(dot), str(output))

            pointer = root / "generated_with_desc_current"
            self.assertTrue(pointer.is_symlink())
            self.assertRegex(
                os.readlink(pointer), r"^\.generated_with_desc\.version\.[0-9a-f]{32}$",
            )
            version = pointer.resolve(strict=True)
            self.assertEqual(root.resolve(), version.parent)
            manifest = json.loads(
                (version / ".description-version.json").read_text(encoding="utf-8")
            )
            self.assertEqual(1, manifest["schema_version"])
            self.assertEqual("generated", manifest["timestamp"])
            self.assertEqual(
                hashlib.sha256((version / "leaf01.yaml").read_bytes()).hexdigest(),
                manifest["files"]["leaf01.yaml"],
            )
            generated = GENERATOR._load_generated_yaml(
                (version / "leaf01.yaml").read_text(encoding="utf-8")
            )

        interfaces = generated[0]["set"]["interface"]
        self.assertEqual(
            "P2P:----UNUSED-----NO-PEER",
            interfaces["swp13s1"]["description"],
        )
        self.assertNotIn("description", interfaces["swp13s2"])
        report = output_text.getvalue()
        self.assertIn("breakout 模式自动补齐的未使用子端口", report)
        self.assertIn("P2P 空对端，已添加 description", report)
        self.assertIn("leaf01: swp13s1", report)
        self.assertIn("P2P 无记录，未添加 description", report)
        self.assertIn("leaf01: swp13s2", report)
        self.assertIn(
            "[WARNING] yaml 中有此接口但 dot 中无连接记录",
            report,
        )
        self.assertIn("leaf01: swp13s3", report)
        self.assertIn(
            "[WARNING] P2P 标记为空的接口未出现在 yaml 中",
            report,
        )
        self.assertIn("leaf01: swp13s4", report)
        self.assertIn("site-missing01: swp1", report)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dot = root / "stale-lldpq.dot"
            original = b'graph "example" {\n}\n'
            dot.write_bytes(original)
            intent = TOPOLOGY._build_description_intent_document(
                [], inv_patterns={}, type_order=[], port_direct={},
                port_switch={}, splitter_profiles={}, lldpq_bytes=original,
                source_workbook="p2p.xlsx",
            )
            TOPOLOGY._write_description_intent(dot, intent)
            dot.write_bytes(b'graph "changed" {\n}\n')
            with self.assertRaisesRegex(
                ValueError, "does not match current LLDPQ DOT",
            ):
                GENERATOR._load_description_intent(str(dot))

    def test_parent_release_rejects_child_from_another_deployment_scope(self) -> None:
        inputs = LOAD.replace(self.inputs, deployment_scope="air")
        air_inventory = [{
            "hostname": "AIR-leaf01", "hostname_key": "air-leaf01",
            "type": "air", "eth0_mac": "02:00:00:00:00:01",
            "eth1_mac": "", "identity_state": "identified",
        }]
        with mock.patch.object(
            LOAD, "_release_inventory", return_value=[],
        ), mock.patch.object(
            LOAD, "_augment_air_json_inventory", return_value=air_inventory,
        ), mock.patch.object(
            LOAD, "_load_release_json",
            return_value={"deployment_scope": "prod"},
        ):
            with self.assertRaisesRegex(
                LOAD.LoadError, "DHCP release deployment scope",
            ):
                LOAD.validate_and_publish_release(
                    self.project, inputs, publish=False,
                )

    def test_load_mini_reaches_real_air_dot_and_json_generation(self) -> None:
        self.assertEqual(
            "04-air-mini-devices.txt",
            LOAD.parse_args(["example-project", "--mini"]).mini,
        )
        self.assertEqual(
            "customer-devices.txt",
            LOAD.parse_args([
                "example-project", "--mini", "customer-devices.txt",
            ]).mini,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            mini_source = project / "customer-devices.txt"
            mini_devices = project / "04-air-mini-devices.txt"
            policy_path = project / "03-air-topology-policy.json"
            policy = {
                "node_allowlist": {},
                "link_rewrites": [],
                "mini_sampling": {
                    "location_prefix_regex": r"^[a-z]\d+-(?P<logical>.+)$",
                    "unknown_role_action": "error",
                    "roles": [
                        {
                            "name": "tan-spine",
                            "hostname_regex": r"^tan-spine(?P<index>\d+)$",
                            "selection": {"mode": "first", "count": 1},
                        },
                        {
                            "name": "tan-leaf",
                            "hostname_regex": (
                                r"^tan-pod(?P<zone>\d+)-leaf(?P<index>\d+)$"
                            ),
                            "selection": {"mode": "first", "count": 2},
                        },
                        {
                            "name": "anchored-oob-leaf",
                            "hostname_regex": (
                                r"^oob-pod(?P<zone>\d+)-leaf(?P<index>\d+)$"
                            ),
                            "selection": {
                                "mode": "anchor",
                                "peer_hostname_regex": r"^(?:tan|ib)(?:-|.+)$",
                                "peer_port_regex": r"^eth0$",
                            },
                        },
                        {
                            "name": "oob-spine",
                            "hostname_regex": (
                                r"^oob-pod(?P<zone>\d+)-spine(?P<index>\d+)$"
                            ),
                            "selection": {
                                "mode": "indices", "capture_group": "index",
                                "indices": [1, 3], "group_by": ["zone"],
                            },
                        },
                        {
                            "name": "rack-tor",
                            "hostname_regex": (
                                r"^oob-pod(?P<zone>\d+)r(?P<rack>\d+)-"
                                r"tor(?P<index>\d+)$"
                            ),
                            "selection": {
                                "mode": "match_fields",
                                "fields": {"rack": [1], "index": [1]},
                                "group_by": ["zone"],
                            },
                        },
                    ],
                },
            }
            policy_path.write_text(
                json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8",
            )
            mini_source.write_text(
                "tan-spine02\n"
                "tan-spine02\n",
                encoding="utf-8",
            )
            lldpq = root / "source-lldpq.dot"
            lldpq.write_text(
                "graph synthetic {\n"
                '"a01-tan-spine01":"swp1" -- '
                '"a03-tan-pod1-leaf01":"swp1"\n'
                '"b01-tan-spine02":"swp1" -- '
                '"a03-tan-pod1-leaf01":"swp2"\n'
                '"c01-tan-spine03":"swp1" -- '
                '"a03-tan-pod1-leaf01":"swp3"\n'
                '"a01-tan-spine01":"swp2" -- '
                '"b03-tan-pod1-leaf02":"swp1"\n'
                '"b01-tan-spine02":"swp2" -- '
                '"c03-tan-pod1-leaf03":"swp1"\n'
                '"a01-tan-spine01":"eth0" -- '
                '"b05-oob-pod1-leaf07":"swp49"\n'
                '"b01-tan-spine02":"swp3" -- '
                '"a05-oob-pod1-leaf01":"swp48"\n'
                '"c05-oob-pod1-leaf03":"swp1" -- '
                '"c14-ib-pod1rail1-leaf01":"eth0"\n'
                '"c05-oob-pod1-leaf03":"swp49" -- '
                '"a06-oob-pod1-spine01":"swp1"\n'
                '"c05-oob-pod1-leaf03":"swp2" -- '
                '"z01-x86-mgmt-server01(ztp-server)":"eth1"\n'
                '"b05-oob-pod1-leaf07":"swp51" -- '
                '"c06-oob-pod1-spine03":"swp1"\n'
                '"a05-oob-pod1-leaf01":"swp49" -- '
                '"b06-oob-pod1-spine02":"swp1"\n'
                '"a07-oob-pod1r01-tor01":"swp49" -- '
                '"a06-oob-pod1-spine01":"swp2"\n'
                '"b07-oob-pod1r01-tor02":"swp49" -- '
                '"b06-oob-pod1-spine02":"swp2"\n'
                "}\n",
                encoding="utf-8",
            )
            air_dot = root / "air.dot"
            air_json = root / "air.json"

            def run_and_materialize_air(command, **_kwargs):
                if len(command) < 2 or command[1] != "b-xlsx_to_dot.py":
                    return
                TOPOLOGY.generate_air_dot(
                    lldpq, air_dot,
                    {"Eth-SW": [
                        "*tan-spine*", "*tan-pod*-leaf*", "*oob-pod*-leaf*",
                        "*oob-pod*-spine*", "*oob-pod*r*-tor*",
                    ]},
                    ["Eth-SW"],
                    os_version=command[command.index("--os-version") + 1],
                    template_file=TOPOLOGY.AIR_JSON_TEMPLATE,
                    air_topology_policy=TOPOLOGY.load_air_topology_policy(
                        Path(command[command.index("--air-link-policy") + 1]),
                        project_root=project,
                    ),
                    mini="--mini" in command,
                    mini_devices_file=Path(command[command.index("--mini") + 1]),
                )
                TOPOLOGY.generate_air_json(
                    air_dot, air_json, TOPOLOGY.AIR_JSON_TEMPLATE,
                    lldpq_file=lldpq,
                )

            with mock.patch.object(
                LOAD, "ZTP_DIR", root / "ztp",
            ), mock.patch.object(
                LOAD, "run", side_effect=run_and_materialize_air,
            ) as runner:
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=True,
                    eth_version="5.18", mini_air=True,
                    air_topology_policy=policy_path,
                    mini_devices_file=mini_source,
                )

            command = runner.call_args_list[0].args[0]
            self.assertEqual([
                sys.executable, "b-xlsx_to_dot.py", "-y",
                "--os-version", "5.18",
                "--air-link-policy", str(policy_path),
                "--mini", str(mini_source),
            ], command)
            nodes = json.loads(
                air_json.read_text(encoding="utf-8")
            )["content"]["nodes"]
            self.assertEqual({
                "AIR-a01-tan-spine01",
                "AIR-b01-tan-spine02",
                "AIR-a03-tan-pod1-leaf01",
                "AIR-b03-tan-pod1-leaf02",
                "AIR-c05-oob-pod1-leaf03",
                "AIR-b05-oob-pod1-leaf07",
                "AIR-a06-oob-pod1-spine01",
                "AIR-c06-oob-pod1-spine03",
                "AIR-a07-oob-pod1r01-tor01",
                "ztp-server",
            }, set(nodes))
            dot_nodes, _links = TOPOLOGY._parse_air_dot(air_dot)
            self.assertTrue(dot_nodes)
            self.assertTrue(
                all(int(attributes["memory"]) >= 4096
                    for _name, attributes in dot_nodes),
                dot_nodes,
            )
            self.assertTrue(
                all(node["memory"] >= 4096 for node in nodes.values()),
                nodes,
            )
            self.assertEqual(
                {"cpu": 8, "memory": 8192, "storage": 80},
                {
                    field: nodes["ztp-server"][field]
                    for field in ("cpu", "memory", "storage")
                },
            )
            positions = {
                name: node["positioning"] for name, node in nodes.items()
            }
            self.assertEqual(len(positions), len({
                (position["x"], position["y"])
                for position in positions.values()
            }))
            tan = [name for name in nodes if "-tan-" in name]
            oob = [name for name in nodes if "-oob-" in name]
            self.assertTrue(tan)
            self.assertTrue(oob)
            self.assertLess(
                max(positions[name]["x"] for name in tan),
                min(positions[name]["x"] for name in oob),
            )
            for zone in (tan, oob):
                spines = [name for name in zone if "spine" in name]
                leaves = [
                    name for name in zone
                    if "leaf" in name or "tor" in name
                ]
                self.assertTrue(spines)
                self.assertTrue(leaves)
                self.assertLess(
                    max(positions[name]["y"] for name in spines),
                    min(positions[name]["y"] for name in leaves),
                )
            self.assertIn("[minimum-required]", mini_devices.read_text())
            self.assertEqual(2, mini_devices.read_text().count("tan-spine02"))
            self.assertTrue(mini_source.is_symlink())
            self.assertEqual("04-air-mini-devices.txt", os.readlink(mini_source))

    def test_load_to_real_air_mini_policy_binds_inputs_and_rolls_back_drift(self) -> None:
        policy_path = self.project / "03-air-topology-policy.json"
        policy_path.write_text(
            json.dumps(
                h19_mini_policy(unknown_role_action="keep"), sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        mini_source = self.project / "customer-mini.txt"
        mini_source.write_text("moon-crystal-edge-02\n", encoding="utf-8")
        canonical = self.project / "04-air-mini-devices.txt"
        lldpq = self.root / "heterogeneous-lldpq.dot"
        lldpq.write_text(
            "graph synthetic {\n"
            '"moon-orbital-hub-01":"swp1" -- '
            '"moon-crystal-edge-01":"swp1"\n'
            '"mars-orbital-hub-02":"swp1" -- '
            '"moon-crystal-edge-02":"swp1"\n'
            '"nova-anchor-gateway-01":"swp1" -- '
            '"moon-orbital-hub-01":"eth0"\n'
            '"comet-unclassified-switch":"swp1" -- '
            '"moon-crystal-edge-01":"swp2"\n'
            '"moon-crystal-edge-01":"swp3" -- '
            '"nova-x86-mgmt-server01(ztp-server)":"eth1"\n'
            "}\n",
            encoding="utf-8",
        )
        air_dot = self.root / "heterogeneous-air.dot"
        air_json = self.root / "heterogeneous-air.json"

        def run_real_topology(command, **_kwargs):
            if len(command) < 2 or command[1] != "b-xlsx_to_dot.py":
                return
            policy_argument = Path(
                command[command.index("--air-link-policy") + 1]
            )
            loaded_policy = TOPOLOGY.load_air_topology_policy(
                policy_argument, project_root=self.project,
            )
            TOPOLOGY.generate_air_dot(
                lldpq, air_dot,
                {"Eth-SW": [
                    "*orbital-hub*", "*crystal-edge*",
                    "*anchor-gateway*", "*unclassified-switch*",
                ]},
                ["Eth-SW"], os_version="5.18",
                template_file=TOPOLOGY.AIR_JSON_TEMPLATE,
                air_topology_policy=loaded_policy,
                mini=True,
                mini_devices_file=Path(command[command.index("--mini") + 1]),
            )
            TOPOLOGY.generate_air_json(
                air_dot, air_json, TOPOLOGY.AIR_JSON_TEMPLATE,
                lldpq_file=lldpq, air_topology_policy=loaded_policy,
            )

        with mock.patch.object(
            LOAD, "ZTP_DIR", self.root / "ztp-workflow",
        ), mock.patch.object(
            LOAD, "run", side_effect=run_real_topology,
        ) as runner:
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=False, dry_run=True,
                eth_version="5.18", air_topology_policy=policy_path,
                mini_air=True, mini_devices_file=mini_source,
            )

            topology_command = runner.call_args_list[0].args[0]
            self.assertIn("--air-link-policy", topology_command)
            self.assertEqual(
                str(policy_path),
                topology_command[topology_command.index("--air-link-policy") + 1],
            )
            nodes = set(json.loads(air_json.read_text(encoding="utf-8"))[
                "content"
            ]["nodes"])
            self.assertEqual({
                "AIR-moon-orbital-hub-01",
                "AIR-moon-crystal-edge-01",
                "AIR-moon-crystal-edge-02",
                "AIR-nova-anchor-gateway-01",
                "AIR-comet-unclassified-switch",
                "ztp-server",
            }, nodes)
            selection_report = json.loads(
                air_dot.with_name(
                    "heterogeneous-air-mini-selection.json"
                ).read_text(encoding="utf-8")
            )
            explicit_reason = next(
                item for item in selection_report["selection_reasons"]
                if item["hostname"] == "moon-crystal-edge-02"
            )
            self.assertEqual({
                "hostname": "moon-crystal-edge-02",
                "role": "crystal-edge",
                "selected": True,
                "reason": "explicit 04-air-mini-devices.txt selection",
            }, explicit_reason)
            self.assertTrue(mini_source.is_symlink())
            self.assertEqual(canonical.name, os.readlink(mini_source))

            # Generation above deliberately uses a hermetic script tree;
            # parent validation consumes the real setUp child manifests.
            LOAD.ZTP_DIR = self.ztp
            inputs = LOAD.replace(
                self.inputs, air_topology_policy=policy_path,
                mini_devices_file=canonical, mini_source_file=mini_source,
            )
            parent = LOAD.validate_and_publish_release(self.project, inputs)
            self.assertEqual(
                sha256(policy_path), parent["inputs"]["air_topology_policy"],
            )
            self.assertEqual(
                sha256(canonical), parent["inputs"]["mini_air_devices"],
            )
            current = self.project / "99-output-ztp/current-release.json"
            stable_current = current.read_bytes()
            stable_outputs = {
                path: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                for path in (air_dot, air_json)
            }

            changed = h19_mini_policy(unknown_role_action="exclude")
            policy_path.write_text(
                json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(
                LOAD.LoadError, r"AIR.*policy.*changed|AIR.*策略.*变化",
            ):
                LOAD.validate_and_publish_release(self.project, inputs)
            self.assertEqual(stable_current, current.read_bytes())
            for path, expected in stable_outputs.items():
                self.assertEqual(expected, (
                    path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns,
                ))

            policy_path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid AIR topology policy JSON"):
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=True,
                    eth_version="5.18", air_topology_policy=policy_path,
                    mini_air=True, mini_devices_file=mini_source,
                )
            self.assertEqual(stable_current, current.read_bytes())
            for path, expected in stable_outputs.items():
                self.assertEqual(expected, (
                    path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns,
                ))

    def test_load_mini_list_is_confined_to_project_and_aliases_only_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            customer = project / "customer.txt"
            customer.write_text("tan-spine02\n", encoding="utf-8")
            canonical = project / "04-air-mini-devices.txt"

            source, destination = LOAD.project_mini_air_devices(
                project, customer.name,
            )
            self.assertEqual(customer.resolve(), source)
            self.assertEqual(canonical.resolve(), destination)
            self.assertEqual(
                (canonical.resolve(), canonical.resolve()),
                LOAD.project_mini_air_devices(project, canonical.name),
            )

            outside = root / "outside.txt"
            outside.write_text("tan-spine03\n", encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "项目根目录"):
                LOAD.project_mini_air_devices(project, str(outside))

            customer.unlink()
            customer.symlink_to(outside)
            with self.assertRaisesRegex(LOAD.LoadError, "相对指向"):
                LOAD.project_mini_air_devices(project, customer.name)

    def test_global_eth_version_reaches_oobofoob_air_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            global_file.write_text(
                "schema_version: 2\n"
                "common:\n"
                "  mgmt:\n"
                "    dhcp-server: {status: enabled, package: isc-dhcp-server}\n"
                "    http: {status: enabled, package: apache2, http_root: /srv/http, address: 203.0.113.80}\n"
                "    ztp: {status: enabled, ztp_url_prefix: /ztp}\n"
                "  switch:\n"
                "    system:\n"
                "      dns: {}\n"
                "      ntp: {}\n"
                "      date-time: {}\n"
                "switches:\n"
                "  - eth:\n"
                "      version: '5.18'\n"
                "      vrr: {base_mac: '02:00:5e:01:00:00'}\n",
                encoding="utf-8",
            )
            settings = LOAD.load_global(global_file)
            lldpq = root / "source-lldpq.dot"
            lldpq.write_text(
                'graph synthetic {\n'
                '"example-oobofoob-leaf10":"swp1" -- '
                '"example-oob-core01":"swp1"\n'
                '}\n',
                encoding="utf-8",
            )
            air_dot = root / "air.dot"
            air_json = root / "air.json"

            def run_and_materialize_air(command, **_kwargs):
                if len(command) < 2 or command[1] != "b-xlsx_to_dot.py":
                    return
                version = command[command.index("--os-version") + 1]
                patterns = {"Eth-SW": ["example-*"]}
                order = ["Eth-SW"]
                TOPOLOGY.generate_air_dot(
                    lldpq, air_dot, patterns, order,
                    os_version=version,
                    template_file=TOPOLOGY.AIR_JSON_TEMPLATE,
                )
                TOPOLOGY.generate_air_json(
                    air_dot, air_json, TOPOLOGY.AIR_JSON_TEMPLATE,
                    lldpq_file=lldpq,
                )

            with mock.patch.object(
                LOAD, "ZTP_DIR", root / "ztp",
            ), mock.patch.object(
                LOAD, "run", side_effect=run_and_materialize_air,
            ) as runner:
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=True,
                    eth_version=settings.versions["eth"],
                )

            self.assertEqual(
                "5.18",
                runner.call_args_list[0].args[0][
                    runner.call_args_list[0].args[0].index("--os-version") + 1
                ],
            )
            nodes = json.loads(
                air_json.read_text(encoding="utf-8")
            )["content"]["nodes"]
            self.assertEqual(
                {"cumulus-vx-5.18"},
                {node["os"] for node in nodes.values()},
            )

    def test_load_dhcp_workflow_uses_most_specific_air_production_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ztp = root / "ztp"
            dhcp_dir = ztp / "config/isc-dhcp-server"
            dhcp_dir.mkdir(parents=True)
            global_file = dhcp_dir / "01-global.yaml"
            global_file.write_text(
                "common:\n"
                "  mgmt:\n"
                "    http:\n"
                "      status: enabled\n"
                "      address: 198.51.100.20\n"
                "    ztp:\n"
                "      ztp_url_prefix: /ztp\n",
                encoding="utf-8",
            )
            devices_file = dhcp_dir / "02-devices_config.csv"
            devices_file.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
                "eth1_ip,netmask,eth1_gw,eth1_mac\n"
                "oob-pod3-leaf03,eth,leaf,192.0.2.10,24,192.0.2.1,"
                "02:00:00:00:00:10,,,,\n"
                "oobofoob-pod3-leaf03,eth,leaf,192.0.2.11,24,192.0.2.1,"
                "02:00:00:00:00:11,,,,\n"
                "border01,eth,leaf,192.0.2.12,24,192.0.2.1,"
                "02:00:00:00:00:12,,,,\n"
                "AIR-example-site-stale01,air,leaf,192.0.2.10,24,192.0.2.1,"
                "02:00:00:00:01:13,,,,\n",
                encoding="utf-8",
            )
            subnet_file = dhcp_dir / "02-subnet_config.csv"
            subnet_file.write_text(
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "oob,192.0.2.0,255.255.255.0,192.0.2.200,192.0.2.220,"
                "192.0.2.1,192.0.2.2,oob,no\n",
                encoding="utf-8",
            )
            air_json = dhcp_dir / "p2p-air.json"
            air_json.write_text(json.dumps({
                "content": {"nodes": {
                    "AIR-example-site-oobofoob-pod3-leaf03": {
                        "os": "cumulus-vx-5.18",
                        "management_interfaces": {
                            "eth0": {"mac_address": "02:00:00:00:01:11"},
                        },
                    },
                    "AIR-evilborder01": {
                        "os": "cumulus-vx-5.18",
                        "management_interfaces": {
                            "eth0": {"mac_address": "02:00:00:00:01:12"},
                        },
                    },
                }},
            }), encoding="utf-8")
            manifest = dhcp_dir / "dhcp-release-manifest.json"

            def run_real_dhcp(command, **_kwargs):
                if len(command) < 2 or command[1] != "c1-generate_dhcp.py":
                    return
                with mock.patch.object(
                    sys, "argv", ["c1-generate_dhcp.py", "-y"],
                ):
                    DHCP.main()

            with mock.patch.object(
                LOAD, "ZTP_DIR", ztp,
            ), mock.patch.object(
                LOAD, "run", side_effect=run_real_dhcp,
            ), mock.patch.multiple(
                DHCP,
                HTTP_ROOT=str(root),
                SCRIPT_DIR=str(dhcp_dir),
                OUTPUT_ETH=str(dhcp_dir / "dhcpd_eth.hosts"),
                OUTPUT_IB=str(dhcp_dir / "dhcpd_ib.hosts"),
                OUTPUT_NVL=str(dhcp_dir / "dhcpd_nvl.hosts"),
                OUTPUT_CONF=str(dhcp_dir / "dhcpd.conf"),
                OUTPUT_MANIFEST=str(manifest),
                SUBNET_CSV=str(subnet_file),
                GLOBAL_YAML=str(global_file),
                P2P_AIR_JSON=str(air_json),
                DEVICES_CSV=str(devices_file),
                _AUTO_YES=False,
            ):
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=True,
                )

            devices = json.loads(
                manifest.read_text(encoding="utf-8")
            )["devices"]
            production_hostnames = [
                "oob-pod3-leaf03", "oobofoob-pod3-leaf03", "border01",
            ]
            self.assertTrue(SETUP._is_matching_production_air_pair(
                "oobofoob-pod3-leaf03", "eth",
                "AIR-example-site-oobofoob-pod3-leaf03", "air",
                production_hostnames,
            ))
            self.assertFalse(SETUP._is_matching_production_air_pair(
                "oob-pod3-leaf03", "eth",
                "AIR-example-site-oobofoob-pod3-leaf03", "air",
                production_hostnames,
            ))
            self.assertFalse(SETUP._is_matching_production_air_pair(
                "border01", "eth", "AIR-evilborder01", "air",
                production_hostnames,
            ))
            air_device = next(
                item for item in devices
                if item["hostname"] == "AIR-example-site-oobofoob-pod3-leaf03"
            )
            self.assertEqual("192.0.2.11", air_device["planned_ip"])
            self.assertEqual("fixed", air_device["dhcp_assignment"])
            boundary_device = next(
                item for item in devices
                if item["hostname"] == "AIR-evilborder01"
            )
            self.assertIsNone(boundary_device["planned_ip"])
            self.assertIsNone(boundary_device["fixed_address"])
            self.assertEqual("dynamic_known", boundary_device["dhcp_assignment"])
            self.assertNotIn(
                "AIR-example-site-stale01",
                {item["hostname"] for item in devices},
            )
            with devices_file.open(newline="", encoding="utf-8") as stream:
                refreshed_rows = list(csv.DictReader(stream))
            self.assertNotIn(
                "AIR-example-site-stale01",
                {item["hostname"] for item in refreshed_rows},
            )

    def test_generate_configs_passes_project_air_topology_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LOAD, "ZTP_DIR", Path(directory),
        ), mock.patch.object(LOAD, "run") as runner:
            policy = Path(directory) / "03-air-topology-policy.json"
            policy.write_text("{}\n", encoding="utf-8")
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=False, dry_run=True,
                eth_version="5.18", air_topology_policy=policy,
            )

        self.assertEqual(
            [
                sys.executable, "b-xlsx_to_dot.py", "-y",
                "--os-version", "5.18",
                "--air-link-policy", str(policy),
            ],
            runner.call_args_list[0].args[0],
        )

    def test_project_air_topology_policy_uses_fixed_optional_filename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.assertIsNone(LOAD.project_air_topology_policy(project))
            policy = project / "03-air-topology-policy.json"
            policy.write_text("{}\n", encoding="utf-8")
            self.assertEqual(policy, LOAD.project_air_topology_policy(project))
            policy.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "大小为 0"):
                LOAD.project_air_topology_policy(project)

    def test_macos_requirements_print_before_password_preflight_and_any_lock(self) -> None:
        events = []
        original_validator = LOAD.validate_macos_client_requirements
        status = LOAD.MacOSClientRequirementStatus(
            python_version="3.9.6",
            python_supported=True,
            missing_generation_modules=(),
            missing_commands=(),
            missing_validation_modules=(),
            password_backend="Homebrew libxcrypt (/opt/homebrew/libcrypt.dylib)",
            homebrew="/opt/homebrew/bin/brew",
        )

        def show_requirements(**kwargs):
            self.assertTrue(kwargs["update_passwords"])
            events.append("requirements")
            return status

        def validate_requirements(received):
            self.assertIs(received, status)
            events.append("dependency-gate")
            original_validator(received)

        def reject_backend():
            events.append("password-backend")
            raise LOAD.LoadError("stop after macOS prerequisite order")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            LOAD, "runtime_os", return_value="Darwin",
        ), mock.patch.object(
            LOAD, "print_macos_client_requirements", side_effect=show_requirements,
        ), mock.patch.object(
            LOAD, "validate_macos_client_requirements",
            side_effect=validate_requirements,
        ), mock.patch.object(
            LOAD, "preflight_password_update_backend", side_effect=reject_backend,
        ), mock.patch.object(
            LOAD, "acquire_deployment_lock",
        ) as acquire, redirect_stdout(stdout), redirect_stderr(stderr):
            result = LOAD.main(["demo", "--update-passwords"])

        self.assertEqual(1, result)
        self.assertEqual(
            ["requirements", "dependency-gate", "password-backend"], events,
        )
        acquire.assert_not_called()
        self.assertIn("stop after macOS prerequisite order", stderr.getvalue())

    def test_macos_missing_generation_dependency_stops_before_password_and_lock(
        self,
    ) -> None:
        status = LOAD.MacOSClientRequirementStatus(
            python_version="3.9.6",
            python_supported=True,
            missing_generation_modules=("openpyxl",),
            missing_commands=("rsync",),
            missing_validation_modules=("XlsxWriter",),
            password_backend=None,
            homebrew=None,
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            LOAD, "runtime_os", return_value="Darwin",
        ), mock.patch.object(
            LOAD, "print_macos_client_requirements", return_value=status,
        ), mock.patch.object(
            LOAD, "preflight_password_update_backend",
        ) as password_backend, mock.patch.object(
            LOAD, "acquire_deployment_lock",
        ) as acquire, redirect_stdout(stdout), redirect_stderr(stderr):
            result = LOAD.main(["demo", "--update-passwords"])

        self.assertEqual(1, result)
        password_backend.assert_not_called()
        acquire.assert_not_called()
        self.assertRegex(stderr.getvalue(), r"openpyxl.*先安装")

    def test_macos_preparation_does_not_publish_runtime_ztp_prefix(self) -> None:
        self._assert_macos_preparation_runtime_boundary()

    def test_main_forwards_explicit_p2p_legacy_columns_to_generation(self) -> None:
        self._assert_macos_preparation_runtime_boundary(p2p_legacy_columns=True)

    def test_p2p_legacy_columns_cli_is_explicit_and_repeats_coalesce(self) -> None:
        self.assertFalse(LOAD.parse_args(["example-project"]).p2p_legacy_columns)
        for flags in (["--p2p-legacy-columns"], ["--p2p-legacy-columns"] * 2):
            with self.subTest(flags=flags):
                self.assertTrue(LOAD.parse_args(["example-project", *flags]).p2p_legacy_columns)

    def _assert_macos_preparation_runtime_boundary(self, *, p2p_legacy_columns=False) -> None:
        """Remote Linux HTTP paths are declarative input on a macOS workstation."""
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30,
            host_role="workstation",
            p2p_legacy_columns=p2p_legacy_columns,
        )
        remote_settings = LOAD.replace(
            self.inputs.settings,
            http_root=Path("/var/www/html"),
            ztp_prefix="/day0/project-ztp",
            versions={"eth": "5.18"},
        )
        air_policy = self.project / "03-air-topology-policy.json"
        remote_inputs = LOAD.replace(
            self.inputs,
            settings=remote_settings,
            air_topology_policy=air_policy,
        )
        configure_prefix = mock.Mock()
        snapshot_prefix = mock.Mock()
        render_runtime = mock.Mock()
        generate_configs = mock.Mock()
        validate_host = mock.Mock(side_effect=AssertionError(
            "macOS preparation must not validate Linux service endpoints"
        ))
        release_lock = mock.Mock()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=73,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "release_deployment_lock", release_lock,
            ))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Darwin"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=False,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(remote_inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host", validate_host,
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services"))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", snapshot_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "configure_ztp_prefix_publication", configure_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "render_ztp_runtime", render_runtime,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links", return_value={},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs", generate_configs,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release", return_value=None,
            ))

            result = LOAD.main([])

        self.assertEqual(0, result)
        validate_host.assert_not_called()
        snapshot_prefix.assert_not_called()
        configure_prefix.assert_not_called()
        render_runtime.assert_called_once()
        generate_configs.assert_called_once_with(
            remote_inputs.device_types,
            deployment_lock_descriptor=73,
            source_identities=remote_inputs.source_identities,
            inventory_directory=mock.ANY,
            dhcp_candidate_dir=mock.ANY,
            install_dhcp=False,
            dry_run=False,
            schema_version=remote_inputs.settings.schema_version,
            eth_version="5.18",
            air_topology_policy=air_policy,
            deployment_scope="all",
            switch_scope="all",
            **({"p2p_legacy_columns": True} if p2p_legacy_columns else {}),
        )
        release_lock.assert_called_once_with(73)

    def test_linux_without_local_service_does_not_publish_runtime_ztp_prefix(self) -> None:
        """A Linux workstation never touches host services or publishes aliases."""
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30,
            host_role="workstation",
        )
        remote_settings = LOAD.replace(
            self.inputs.settings,
            http_root=Path("/var/www/html"),
            ztp_prefix="/day0/project-ztp",
        )
        remote_inputs = LOAD.replace(self.inputs, settings=remote_settings)
        validate_host = mock.Mock(return_value=False)
        snapshot_prefix = mock.Mock()
        configure_prefix = mock.Mock()
        render_runtime = mock.Mock()
        generate_configs = mock.Mock()
        release_lock = mock.Mock()
        require_inactive = mock.Mock()
        quiesce = mock.Mock()
        stop_monitor = mock.Mock()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=74,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "release_deployment_lock", release_lock,
            ))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=True,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "stop_native_ztp_monitors", stop_monitor,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(remote_inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host", validate_host,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "require_artifact_builder_services_inactive",
                require_inactive,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "quiesce_services", quiesce,
            ))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", snapshot_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "configure_ztp_prefix_publication", configure_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "render_ztp_runtime", render_runtime,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links", return_value={},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs", generate_configs,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release", return_value=None,
            ))

            result = LOAD.main([])

        self.assertEqual(0, result)
        validate_host.assert_not_called()
        require_inactive.assert_not_called()
        quiesce.assert_not_called()
        stop_monitor.assert_not_called()
        snapshot_prefix.assert_not_called()
        configure_prefix.assert_not_called()
        render_runtime.assert_called_once()
        generate_configs.assert_called_once()
        release_lock.assert_called_once_with(74)

    def test_linux_artifact_builder_rejects_active_services_without_stopping(self) -> None:
        with mock.patch.object(
            LOAD, "active_managed_services",
            return_value=("apache2", "isc-dhcp-server"),
        ), mock.patch.object(LOAD, "run") as runner:
            with self.assertRaisesRegex(
                LOAD.LoadError, "service_ip.*服务正在运行",
            ):
                LOAD.require_artifact_builder_services_inactive(False)
        runner.assert_not_called()

    def test_macos_preparation_links_dhcp_manifest_and_commits_parent_release(self) -> None:
        """The configuration-only path still publishes a complete child/parent release."""
        manifest_rel = "config/isc-dhcp-server/dhcp-release-manifest.json"
        mapped = {
            ztp_rel: (project_rel, kind)
            for ztp_rel, project_rel, kind in SETUP.MAPPINGS
        }
        self.assertEqual(
            ("99-output-dhcp/dhcp-release-manifest.json", "output"),
            mapped.get(manifest_rel),
        )

        names = (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
            "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
        )
        runtime_paths = {}
        for name in names:
            ztp_rel = f"config/isc-dhcp-server/{name}"
            project_rel, kind = mapped[ztp_rel]
            self.assertEqual("output", kind)
            runtime_path = self.ztp / ztp_rel
            project_path = self.project / project_rel
            if name == "dhcp-release-manifest.json":
                runtime_path.unlink(missing_ok=True)
                project_path.unlink(missing_ok=True)
                with mock.patch.object(SETUP, "_DRY_RUN", False), mock.patch.object(
                    SETUP, "_LINK_ERRORS", 0,
                ):
                    result = SETUP._process_mapping(
                        str(self.project), ztp_rel, project_rel, kind,
                        link_root=str(self.ztp),
                    )
                self.assertEqual("linked", result)
            else:
                content = runtime_path.read_bytes() if runtime_path.is_file() else b""
                runtime_path.unlink(missing_ok=True)
                project_path.parent.mkdir(parents=True, exist_ok=True)
                project_path.write_bytes(content)
                runtime_path.symlink_to(project_path)
            runtime_paths[name] = runtime_path

        records = [{
            "hostname": "leaf01", "type": "eth", "iface": "eth0",
            "mac_norm": "02:00:00:00:00:01", "ip": "192.0.2.10",
            "netmask": "24", "identity_pending": False,
            "dhcp_assignment": "fixed", "served_subnet": "192.0.2.0/24",
            "src": str(self.devices_file),
        }]
        subnets = [{
            "shared_network": "clients", "subnet": "192.0.2.0",
            "netmask": "255.255.255.0", "range_start": "192.0.2.100",
            "range_end": "192.0.2.200", "routers": "192.0.2.1",
            "ztp_service_ip": "", "cumulus_profile": "none",
            "nvos_ztp": "no", "cumulus_provision_url": "",
            "bootfile_name": "", "_network": ipaddress.ip_network("192.0.2.0/24"),
        }]

        def generate_dhcp(
            _device_types, *, install_dhcp, dry_run, schema_version,
            eth_version, air_topology_policy, deployment_scope, switch_scope,
            deployment_lock_descriptor, source_identities, inventory_directory,
            dhcp_candidate_dir,
        ):
            self.assertIsNone(source_identities)
            self.assertEqual(self.project, inventory_directory.parent)
            self.assertTrue(inventory_directory.name.startswith(".load-inventory-"))
            self.assertEqual(0o700, inventory_directory.stat().st_mode & 0o777)
            self.assertFalse(install_dhcp)
            self.assertFalse(dry_run)
            self.assertEqual(1, schema_version)
            self.assertIsNone(eth_version)
            self.assertIsNone(air_topology_policy)
            self.assertEqual("all", deployment_scope)
            self.assertEqual("all", switch_scope)
            self.assertEqual(75, deployment_lock_descriptor)
            self.assertEqual(
                (self.project / "99-output-dhcp").resolve(),
                dhcp_candidate_dir.parent,
            )
            self.assertEqual(0o700, dhcp_candidate_dir.stat().st_mode & 0o777)
            candidate_paths = {
                name: dhcp_candidate_dir / name for name in names
            }
            DHCP.write_dhcpd_conf(candidate_paths["dhcpd.conf"], subnets)
            DHCP.write_hosts(candidate_paths["dhcpd_eth.hosts"], records)
            DHCP.write_hosts(candidate_paths["dhcpd_ib.hosts"], [])
            DHCP.write_hosts(candidate_paths["dhcpd_nvl.hosts"], [])
            output_manifest = candidate_paths["dhcp-release-manifest.json"]
            DHCP.write_release_manifest(
                output_manifest, records, subnets,
                tuple(candidate_paths[name] for name in names[:4]),
                deployment_scope=deployment_scope,
                switch_scope=switch_scope,
            )

        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30,
            host_role="workstation",
        )
        remote_inputs = LOAD.replace(
            self.inputs,
            settings=LOAD.replace(
                self.inputs.settings, http_root=Path("/var/www/html"),
                ztp_prefix="/day0/project-ztp",
            ),
        )
        mount_dhcp = mock.Mock(side_effect=AssertionError(
            "macOS preparation must not install files under /etc/dhcp"
        ))
        configure_prefix = mock.Mock()
        snapshot_prefix = mock.Mock()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=75,
            ))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock"))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Darwin"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=False,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(remote_inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host",
                side_effect=AssertionError("Darwin must not validate local service IPs"),
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services"))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", snapshot_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "configure_ztp_prefix_publication", configure_prefix,
            ))
            stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs", side_effect=generate_dhcp,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "mount_and_test_dhcp", mount_dhcp,
            ))

            result = LOAD.main([])

        self.assertEqual(0, result)
        snapshot_prefix.assert_not_called()
        configure_prefix.assert_not_called()
        mount_dhcp.assert_not_called()
        runtime_manifest = runtime_paths["dhcp-release-manifest.json"]
        project_manifest = self.project / mapped[manifest_rel][0]
        self.assertTrue(runtime_manifest.is_symlink())
        self.assertEqual(project_manifest.resolve(), runtime_manifest.resolve())
        self.assertEqual(0, project_manifest.stat().st_size)
        parent = json.loads(
            (self.project / "99-output-ztp/current-release.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("passed", parent["validation"])
        self.assertEqual({"dhcp", "cumulus"}, set(parent["components"]))
        retained = self.project / "99-output-dhcp"
        private_dirs = list(retained.glob(".load-dhcp-candidate-*"))
        self.assertEqual(1, len(private_dirs))
        self.assertEqual(
            sha256(private_dirs[0] / "dhcp-release-manifest.json"),
            parent["components"]["dhcp"]["manifest_sha256"],
        )

        with mock.patch.object(UNSETUP, "ZTP", str(self.ztp)):
            self.assertIn(
                str(runtime_manifest), UNSETUP._known_ztp_project_links()
            )

    def test_constructor_EX_then_UN_foreign_release_records_rejection_and_SH_witness(self):
        import errno
        import fcntl
        import select

        real_flock = fcntl.flock
        path = self.root / '.deployment.lock'
        finish_root = self.root / 'PUBLIC-owned-absent-finish-state'
        deployment_generator = LOAD.deployment_lock.__wrapped__
        deployment_module = sys.modules[deployment_generator.__module__]
        self.assertEqual(ROOT / 'tools/deployment_lock.py',
                         Path(deployment_module.__file__))
        self.assertIs(deployment_generator.__globals__, vars(deployment_module))
        self.assertIs(deployment_module.deployment_lock, LOAD.deployment_lock)
        finish_guard = deployment_generator.__globals__['assert_writer_allowed']
        finish_module = sys.modules[finish_guard.__module__]
        self.assertEqual(ROOT / 'tools/finished_project_state.py',
                         Path(finish_module.__file__))
        self.assertIs(finish_guard.__globals__, vars(finish_module))
        original_finish_root = finish_guard.__globals__['FINISH_STATE_ROOT']
        host = LOAD.runtime_os().casefold()
        self.assertIn(host, ('darwin', 'linux'), 'unsupported fixture platform')
        self.assertFalse(os.path.lexists(path))
        self.assertFalse(os.path.lexists(finish_root))
        existing_contexts = dict(LOAD._DEPLOYMENT_LOCK_CONTEXTS)
        original_environment = dict(os.environ)
        environment = dict(original_environment)
        environment.pop('HTTP_DEPLOYMENT_LOCK_FD', None)

        def nine(metadata):
            return (metadata.st_dev, metadata.st_ino, metadata.st_mode,
                    metadata.st_uid, metadata.st_gid, metadata.st_nlink,
                    metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)

        def snapshot():
            result = {}
            for candidate in [self.root] + sorted(self.root.rglob('*')):
                before = candidate.lstat()
                if stat.S_ISLNK(before.st_mode):
                    body = os.readlink(os.fsencode(candidate))
                elif stat.S_ISREG(before.st_mode):
                    body = candidate.read_bytes()
                else:
                    body = None
                after = candidate.lstat()
                if nine(before) != nine(after):
                    raise RuntimeError('PUBLIC fixture changed while recording evidence')
                result[str(candidate.relative_to(self.root))] = (nine(before), body)
            return result

        def observe_guard(descriptor):
            result = {'returned': False, 'value': None, 'error': None}
            try:
                result['value'] = LOAD._require_runtime_lock_guard(descriptor)
                result['returned'] = True
            except Exception as exc:
                result['error'] = exc
            return result

        def shared_witness():
            result = {'acquired': False, 'error': None, 'close_error': None}
            descriptor = None
            try:
                descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                real_flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                result['acquired'] = True
            except Exception as exc:
                result['error'] = exc
            finally:
                if descriptor is not None:
                    to_close, descriptor = descriptor, None
                    try:
                        os.close(to_close)
                    except Exception as exc:
                        result['close_error'] = exc
            return result

        def report(label, guard, witness):
            def error(value):
                if value is None:
                    return None
                return {'type': type(value).__name__, 'message': str(value),
                        'errno': getattr(value, 'errno', None)}
            print('LOAD_CURRENT_OFD_STRENGTHENED_OBSERVATION=' + json.dumps({
                'label': label, 'guard_returned': guard['returned'],
                'guard_value_is_none': guard['value'] is None,
                'guard_error': error(guard['error']),
                'witness_acquired': witness['acquired'],
                'witness_error': error(witness['error']),
                'witness_close_error': error(witness['close_error']),
            }, sort_keys=True), flush=True)

        def check_positive(label, guard, witness):
            # The real witness is already recorded before these assertions.
            with self.subTest(label=label, observation='positive-guard'):
                self.assertTrue(guard['returned'])
                self.assertIsNone(guard['error'])
                self.assertIsNone(guard['value'])
            with self.subTest(label=label, observation='positive-SH-witness'):
                self.assertFalse(witness['acquired'])
                self.assertIsInstance(witness['error'], BlockingIOError)
                self.assertIn(witness['error'].errno, (errno.EAGAIN, errno.EWOULDBLOCK))
                self.assertIsNone(witness['close_error'])
            # Do not label a later race if these actual constructor controls
            # failed. Both observations have nevertheless already been emitted.
            if (not guard['returned'] or guard['value'] is not None or guard['error'] is not None
                    or not isinstance(witness['error'], BlockingIOError)
                    or witness['acquired'] or witness['close_error'] is not None):
                self.fail('PUBLIC_CONSTRUCTOR_EX_POSITIVE_PREREQUISITE_FAILED')

        with ExitStack() as bindings:
            bindings.enter_context(mock.patch.object(LOAD, 'DEPLOYMENT_LOCK', path))
            bindings.enter_context(mock.patch.object(
                finish_module, 'FINISH_STATE_ROOT', finish_root,
            ))
            bindings.enter_context(mock.patch.dict(os.environ, environment, clear=True))
            self.assertIs(finish_root, finish_guard.__globals__['FINISH_STATE_ROOT'])
            caller = LOAD.acquire_deployment_lock(exclusive=True)
            duplicate = None
            owner = None
            owner_collected = False
            observations = {}
            cleanup_errors = []
            primary = None
            baseline = None
            handshake = []
            try:
                first = nine(path.lstat())
                self.assertEqual(first, nine(os.fstat(caller)))
                self.assertTrue(stat.S_ISREG(first[2]))
                self.assertEqual(1, first[5])
                self.assertEqual(b'', path.read_bytes())
                self.assertFalse(os.path.lexists(finish_root))
                self.assertIsNotNone(LOAD._DEPLOYMENT_LOCK_CONTEXTS.get(caller))
                duplicate = os.dup(caller)
                for label, descriptor in (('constructor', caller), ('dup', duplicate)):
                    positive = observe_guard(descriptor)
                    positive_witness = shared_witness()
                    report(label, positive, positive_witness)
                    check_positive(label, positive, positive_witness)
                baseline = snapshot()
                # Constructor history remains in its cleanup registry, but
                # this actual syscall removes the OFD's current EX authority.
                real_flock(caller, fcntl.LOCK_UN)
                owner = subprocess.Popen(
                    [sys.executable, '-I', '-B', '-c', '\n'.join((
                        'import fcntl, os, sys',
                        'fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW)',
                        'fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)',
                        "print('HELD', flush=True)",
                        "assert sys.stdin.readline().strip() == 'RELEASE'",
                        'fcntl.flock(fd, fcntl.LOCK_UN)',
                        "print('RELEASED', flush=True)",
                        "assert sys.stdin.readline().strip() == 'FINISH'",
                        'os.close(fd)',
                    )), str(path)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                )
                handshake = []

                def receive(expected):
                    if not select.select([owner.stdout], [], [], 10)[0]:
                        raise RuntimeError('PUBLIC foreign-owner handshake timed out')
                    actual = owner.stdout.readline()
                    handshake.append(actual)
                    if actual != expected + '\n':
                        raise RuntimeError('PUBLIC foreign-owner handshake mismatched')

                receive('HELD')
                events = []
                frames = []
                original_reader = LOAD._read_runtime_lock_fdinfo

                def release_foreign():
                    owner.stdin.write('RELEASE\n')
                    owner.stdin.flush()
                    receive('RELEASED')
                    events.append('foreign-EX-released')

                def probe_then_release(descriptor, operation):
                    try:
                        return real_flock(descriptor, operation)
                    except BlockingIOError:
                        if (not events and descriptor not in (caller, duplicate)
                                and operation == (fcntl.LOCK_SH | fcntl.LOCK_NB)):
                            metadata = os.fstat(descriptor)
                            if (metadata.st_dev, metadata.st_ino) == first[:2]:
                                events.append('real-SH-blocked')
                                release_foreign()
                        raise

                def read_current_then_release(descriptor):
                    frame = original_reader(descriptor)
                    frames.append((descriptor, frame))
                    if descriptor == caller and not events:
                        events.append('real-current-FD-read')
                        release_foreign()
                    return frame

                with ExitStack() as observer:
                    if host == 'linux':
                        observer.enter_context(mock.patch.object(
                            LOAD, '_read_runtime_lock_fdinfo',
                            side_effect=read_current_then_release,
                        ))
                    else:
                        observer.enter_context(mock.patch.object(
                            LOAD.fcntl, 'flock', side_effect=probe_then_release,
                        ))
                    guard = observe_guard(caller)
                # No early assertRaises; in particular a wrongly accepted
                # caller still receives the independently executed SH witness.
                witness = shared_witness()
                report('constructor-UN-foreign-release', guard, witness)
                observations.update(guard=guard, witness=witness,
                                    events=list(events), frames=list(frames),
                                    handshake=list(handshake),
                                    caller9=nine(os.fstat(caller)),
                                    path9=nine(path.lstat()),
                                    path_bytes=path.read_bytes(), after=snapshot(),
                                    first9=first)
            except BaseException as exc:
                primary = exc
                raise
            finally:
                # Record cleanup faults independently; never replace a body
                # exception or close a stale FD integer a second time.
                if duplicate is not None:
                    to_close, duplicate = duplicate, None
                    try:
                        os.close(to_close)
                    except Exception as exc:
                        cleanup_errors.append(exc)
                to_release, caller = caller, None
                try:
                    LOAD.release_deployment_lock(to_release)
                except Exception as exc:
                    cleanup_errors.append(exc)
                # First operation after creator release: no FD allocation can
                # turn a reused integer into a spurious EBADF result.
                try:
                    os.fstat(to_release)
                except OSError as exc:
                    observations['released_errno'] = exc.errno
                except Exception as exc:
                    cleanup_errors.append(exc)
                else:
                    observations['released_errno'] = None
                if owner is not None and not owner_collected:
                    try:
                        if primary is None:
                            # Creator release and its immediate EBADF check
                            # above precede FINISH/communicate, avoiding any FD
                            # allocation/reuse before the close witness.
                            owner.stdin.write('FINISH\n')
                            owner.stdin.flush()
                        elif owner.stdin is not None and not owner.stdin.closed:
                            owner.stdin.close()
                            owner.stdin = None
                        stdout, stderr = owner.communicate(timeout=10)
                        owner_collected = True
                        observations.update(owner_returncode=owner.returncode,
                                            owner_stdout=stdout, owner_stderr=stderr)
                        observations['cleanup_child_stdout'] = stdout
                        observations['cleanup_child_stderr'] = stderr
                        observations['cleanup_child_returncode'] = owner.returncode
                    except Exception as exc:
                        cleanup_errors.append(exc)
                        child_running = False
                        try:
                            child_running = owner.poll() is None
                        except Exception as poll_error:
                            cleanup_errors.append(poll_error)
                        if child_running:
                            try:
                                owner.kill()
                            except Exception as kill_error:
                                cleanup_errors.append(kill_error)
                        try:
                            stdout, stderr = owner.communicate(timeout=10)
                            owner_collected = True
                            observations['cleanup_child_stdout'] = stdout
                            observations['cleanup_child_stderr'] = stderr
                            observations['cleanup_child_returncode'] = owner.returncode
                        except Exception as reap_error:
                            cleanup_errors.append(reap_error)
                try:
                    for exc in cleanup_errors:
                        print('LOAD_CURRENT_OFD_CLEANUP_ERROR=' + type(exc).__name__, flush=True)
                    # The pipe protocol is observed as decoded text, not as a
                    # purported byte-for-byte binary child-stream recording.
                    print('LOAD_CURRENT_OFD_CHILD_TEXT_OBSERVATION=' + json.dumps({
                        'transport': 'Popen text=True; decoded text, not binary raw',
                        'child_started': owner is not None,
                        'handshake_text_consumed': list(handshake),
                        'communicate_stdout': observations.get(
                            'owner_stdout', observations.get('cleanup_child_stdout')),
                        'communicate_stderr': observations.get(
                            'owner_stderr', observations.get('cleanup_child_stderr')),
                        'actual_returncode': observations.get(
                            'owner_returncode', observations.get('cleanup_child_returncode')),
                        'collected': owner_collected,
                    }, sort_keys=True), flush=True)
                except Exception as evidence_error:
                    cleanup_errors.append(evidence_error)
                if primary is None and cleanup_errors:
                    raise cleanup_errors[0]

            # Both kernel observations and the complete child exit exist before
            # the first target assertion. A guard failure cannot hide witness.
            guard = observations['guard']
            witness = observations['witness']
            with self.subTest(observation='guard-rejection'):
                self.assertFalse(guard['returned'])
                self.assertIs(type(guard['error']), LOAD.LoadError)
                self.assertIn('deployment lock', str(guard['error']))
            with self.subTest(observation='post-release-SH-witness'):
                self.assertTrue(witness['acquired'])
                self.assertIsNone(witness['error'])
                self.assertIsNone(witness['close_error'])
            expected = ('real-current-FD-read' if host == 'linux' else 'real-SH-blocked')
            self.assertEqual([expected, 'foreign-EX-released'], observations['events'])
            self.assertEqual(['HELD\n', 'RELEASED\n'], observations['handshake'])
            self.assertEqual(0, observations['owner_returncode'])
            self.assertEqual('', observations['owner_stdout'])
            self.assertEqual('', observations['owner_stderr'])
            if host == 'linux':
                self.assertGreaterEqual(len(observations['frames']), 1)
                self.assertEqual(to_release, observations['frames'][0][0])
                self.assertIsInstance(observations['frames'][0][1], bytes)
                self.assertNotIn(b'lock:', observations['frames'][0][1])
            else:
                self.assertEqual([], observations['frames'])
            self.assertEqual(observations['first9'], observations['caller9'])
            self.assertEqual(observations['first9'], observations['path9'])
            self.assertEqual(b'', observations['path_bytes'])
            self.assertEqual(baseline, observations['after'])
            self.assertEqual(baseline, snapshot())
            self.assertEqual(errno.EBADF, observations['released_errno'])
            self.assertEqual(existing_contexts, LOAD._DEPLOYMENT_LOCK_CONTEXTS)
            self.assertFalse(os.path.lexists(finish_root))

        self.assertIs(original_finish_root, finish_guard.__globals__['FINISH_STATE_ROOT'])
        self.assertEqual(original_environment, dict(os.environ))


class InfraNeutralFallbackWorkflowTests(unittest.TestCase):
    def test_global_key_replacement_flows_to_bash_and_family_defaults(self):
        spec = importlib.util.spec_from_file_location(
            "infra_neutral_workflow_deploy", ROOT / "infra/deploy_infra.py",
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        deploy = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = deploy
        spec.loader.exec_module(deploy)
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            global_file = temp / "01-global.yaml"
            global_file.write_text(
                "common:\n  switch:\n    system:\n"
                "      dns:\n"
                "        server: [8.8.8.8, 192.0.2.53]\n"
                "      ntp:\n"
                "        server: [ntp.ubuntu.com, ntp.site.example]\n",
                encoding="utf-8",
            )
            dns, ntp, timezone_name = deploy.load_common(global_file)
            self.assertEqual(["8.8.8.8", "192.0.2.53"], dns)
            self.assertEqual(1, dns.count("8.8.8.8"))
            self.assertEqual(["ntp.ubuntu.com", "ntp.site.example"], ntp)
            self.assertEqual(1, ntp.count("ntp.ubuntu.com"))
            self.assertEqual("Etc/UTC", timezone_name)
            runtime = temp / "infra-runtime.conf"
            deploy.update_runtime_config(
                runtime,
                deploy.render_managed_block(
                    "192.0.2.10", dns, ntp, timezone_name,
                    local_http_enabled=False,
                ),
            )
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; printf "%s|%s|%s\\n" '
                    '"${dns_servers[*]}" "${ntp_servers[*]}" "$time_zone"',
                    "bash", str(runtime),
                ],
                check=True, text=True, capture_output=True,
            )
            self.assertEqual(
                "8.8.8.8 192.0.2.53|ntp.ubuntu.com ntp.site.example|Etc/UTC\n",
                result.stdout,
            )

        for relative in (
            "ztp/config/cumulus/default.yaml",
            "ztp/config/cumulus/default_5.16.5.yaml",
            "ztp/config/nvos/default.yaml",
        ):
            rendered = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("null", rendered.casefold(), relative)
            system = yaml.safe_load(rendered)[0]["set"]["system"]
            self.assertEqual("Etc/UTC", system["date-time"]["timezone"], relative)
            self.assertEqual(["8.8.8.8"], list(system["dns"]["server"]), relative)
            self.assertEqual(["ntp.ubuntu.com"], list(system["ntp"]["server"]), relative)




# I03 independent PUBLIC literals, not captured manager output or SUT-derived data.
_I03_SNAPSHOT_DEAD = "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\n"
_I03_SNAPSHOT_ABSENT = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\n"


class NativeRequiredSnapshotContractTests(unittest.TestCase):
    def _i03_snapshot(self, *, absent=False, refused=None):
        calls = []

        def query(command, **_kwargs):
            argv = tuple(str(part) for part in command)
            calls.append(argv)
            self.assertIn(argv[0], ("systemctl", "/fixture/systemctl"))
            self.assertEqual("apache2", argv[-1])
            if argv[1:] == ("show", "--all", "--no-pager",
                            "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job", "apache2"):
                return SimpleNamespace(
                    returncode=0 if refused is None else refused,
                    stdout="" if refused is not None else (_I03_SNAPSHOT_ABSENT if absent else _I03_SNAPSHOT_DEAD),
                    stderr="independent manager refusal" if refused is not None else "",
                )
            if argv[1:] == ("is-active", "--quiet", "apache2"):
                code = refused if refused is not None else (4 if absent else 3)
            elif argv[1:] == ("is-enabled", "--quiet", "apache2"):
                code = refused if refused is not None else (4 if absent else 1)
            else:
                self.fail(("unexpected external query", argv))
            return SimpleNamespace(returncode=code, stdout="", stderr="")

        # Real backend + real LOAD snapshot. Only the external command boundary
        # is a finite adapter; no snapshot/parser/quiesce implementation patch.
        backend = LOAD.service_runtime_backend(
            {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=query,
        )
        with mock.patch.object(LOAD.shutil, "which", return_value="/fixture/systemctl"), \
                mock.patch.object(LOAD, "_run_subprocess", side_effect=query), \
                mock.patch.object(LOAD, "run") as mutate:
            try:
                return LOAD.snapshot_service_states(("apache2",), runtime_backend=backend)
            finally:
                mutate.assert_not_called()
                self.assertTrue(calls, "the real snapshot must reach its external read boundary")

    def test_required_snapshot_query_failure_cannot_be_two_false_bits(self):
        for code in (1, 4, 127, -9):
            with self.subTest(code=code):
                positive = self._i03_snapshot()
                self.assertEqual(
                    {"apache2": LOAD.ServiceRuntimeState(enabled=False, active=False)}, positive,
                )
                with self.assertRaises(LOAD.LoadError):
                    self._i03_snapshot(refused=code)

    def test_required_snapshot_absence_cannot_mint_rollback_state(self):
        self.assertEqual(
            {"apache2": LOAD.ServiceRuntimeState(enabled=False, active=False)},
            self._i03_snapshot(),
        )
        # Existing rollback schema remains bool/bool. Required absence must
        # refuse before returning a mapping, not mint False/False for restore.
        with self.assertRaises(LOAD.LoadError):
            self._i03_snapshot(absent=True)

    def test_loaded_active_snapshot_keeps_bool_codec_after_six_property_qualification(self):
        manager = _I03LiteralManager({"apache2": "active", "isc-dhcp-server": "dead"})
        manager.enabled["apache2"] = True
        backend = LOAD.service_runtime_backend(
            {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=manager.query,
        )
        with mock.patch.object(LOAD.shutil, "which", return_value="/fixture/systemctl"), \
                mock.patch.object(LOAD, "_run_subprocess", side_effect=manager.query), \
                mock.patch.object(LOAD, "run") as mutate:
            states = LOAD.snapshot_service_states(("apache2",), runtime_backend=backend)
        self.assertEqual([], manager.adapter_errors)
        mutate.assert_not_called()
        self.assertEqual([], manager.actions)
        self.assertEqual({"apache2": LOAD.ServiceRuntimeState(enabled=True, active=True)}, states)
        self.assertIs(True, states["apache2"].enabled)
        self.assertIs(True, states["apache2"].active)
        show = ("show", "--all", "--no-pager",
                "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job", "apache2")
        tails = [argv[1:] for argv in manager.query_argv]
        self.assertIn(show, tails)
        self.assertLess(tails.index(show), tails.index(("is-active", "--quiet", "apache2")))
        self.assertLess(tails.index(show), tails.index(("is-enabled", "--quiet", "apache2")))



# I03 PUBLIC manager model. These literals never come from SUT output.
_I03_SHOW_DEAD = "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\n"
_I03_SHOW_ABSENT = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\n"
_I03_SHOW_ACTIVE = "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=23\nControlPID=0\nJob=\n"
_I03_BAD_SHOW = (
    ("empty", 0, "", ""),
    ("missing-job", 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\n", ""),
    ("duplicate-job", 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\nJob=\n", ""),
    ("unknown-property", 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\nUnknown=0\n", ""),
    ("bad-line", 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob\n", ""),
    ("not-found-active", 0, "LoadState=not-found\nActiveState=active\nSubState=running\nMainPID=23\nControlPID=0\nJob=\n", ""),
    ("not-found-main-pid", 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=23\nControlPID=0\nJob=\n", ""),
    ("not-found-control-pid", 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=19\nJob=\n", ""),
    ("not-found-job", 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=7\n", ""),
    ("invented-zero-job", 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=0\n", ""),
    ("show-rc4", 4, "", "independent manager unavailable"),
    ("show-EACCES", 1, "", "independent permission denied"),
    ("nonzero-complete", 4, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\n", ""),
)


class _I03LiteralManager:
    """Finite external command adapter; no copied service-policy function."""

    def __init__(self, states, *, bad_show=None, bad_query_code=None, fault_point="installer"):
        if fault_point not in {"prepare-only", "installer"}:
            raise AssertionError("unsupported PUBLIC fault point")
        self.fault_point = fault_point
        self.states = dict(states)
        self.enabled = {"apache2": False, "isc-dhcp-server": False}
        self.bad_show = bad_show
        self.bad_query_code = bad_query_code
        self.phase = "preinstall"
        self.events = []
        self.actions = []
        self.query_argv = []
        self.adapter_errors = []

    def query(self, command, **_kwargs):
        argv = tuple(str(part) for part in command)
        if not argv or Path(argv[0]).name != "systemctl":
            self.adapter_errors.append(("query", "program", argv))
            raise AssertionError(("unexpected external query", argv))
        unit = argv[-1]
        if unit not in {"apache2", "isc-dhcp-server"}:
            self.adapter_errors.append(("query", "foreign-unit", argv))
            raise AssertionError(("foreign service queried", argv))
        self.events.append(("query", self.phase, unit, argv[1]))
        self.query_argv.append(argv)
        if argv[1:] == ("show", "--all", "--no-pager",
                        "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job", unit):
            if self.bad_show is not None and unit == "apache2":
                _label, code, raw, diagnostic = self.bad_show
                return SimpleNamespace(returncode=code, stdout=raw, stderr=diagnostic)
            raw = {"absent": _I03_SHOW_ABSENT, "dead": _I03_SHOW_DEAD,
                   "active": _I03_SHOW_ACTIVE}[self.states[unit]]
            return SimpleNamespace(returncode=0, stdout=raw, stderr="")
        if argv[1:] in (("is-active", "--quiet", unit), ("is-enabled", "--quiet", unit)):
            if self.bad_query_code is not None:
                return SimpleNamespace(returncode=self.bad_query_code, stdout="", stderr="independent query refusal")
            if self.states[unit] == "absent":
                return SimpleNamespace(returncode=4, stdout="", stderr="")
            if argv[1] == "is-active":
                code = 0 if self.states[unit] == "active" else 3
            else:
                code = 0 if self.enabled[unit] else 1
            return SimpleNamespace(returncode=code, stdout="", stderr="")
        self.adapter_errors.append(("query", "unsupported-form", argv))
        raise AssertionError(("unsupported systemctl query", argv))

    def external_run(self, command, **_kwargs):
        argv = tuple(str(part) for part in command)
        if "systemctl" in argv:
            index = argv.index("systemctl")
            tail = argv[index + 1:]
            if tail == ("enable", "--now", "apache2"):
                action, unit = "enable", "apache2"
            elif len(tail) == 2 and tail[0] in {"stop", "start", "restart", "enable", "disable"}:
                action, unit = tail
            else:
                self.adapter_errors.append(("external-run", "unsupported-control", argv))
                raise AssertionError(("unexpected service action", argv))
            if unit not in {"apache2", "isc-dhcp-server"}:
                self.adapter_errors.append(("external-run", "foreign-unit", argv))
                raise AssertionError(("foreign service action", argv))
            self.actions.append((self.phase, action, unit))
            self.events.append(("action", self.phase, unit, action))
            # Absent unit is not silently installed by a control request.
            if self.states[unit] == "absent":
                raise LOAD.LoadError("independent absent unit control refusal")
            if action == "stop":
                self.states[unit] = "dead"
            elif action in {"start", "restart"}:
                self.states[unit] = "active"
            else:
                self.enabled[unit] = action == "enable"
                if tail == ("enable", "--now", "apache2"):
                    self.states[unit] = "active"
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if any(part.endswith("/deploy_infra.py") for part in argv):
            self.events.append(("infra-prepare", self.phase, argv))
            # The first prepare command may already write managed files.
            # Cleanup is required from entry, not from successful installation.
            self.phase = "install-attempted"
            if self.fault_point == "prepare-only":
                raise LOAD.LoadError("I03_OWNED_PREPARE_SENTINEL")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if any(part.endswith("/infra-setup.sh") for part in argv):
            self.events.append(("infra-attempt", self.phase, argv))
            self.phase = "install-attempted"
            raise LOAD.LoadError("I03_OWNED_INSTALLER_SENTINEL")
        self.adapter_errors.append(("external-run", "unsupported-command", argv))
        raise AssertionError(("unexpected external execution", argv))


class NativePreinstallPresenceWorkflowTests(unittest.TestCase):
    def _i03_main(self, manager, *, dhcp=True, skip_infra=False,
                  explicit_http_only=False, expected_postinfra=False):
        # Fresh real PUBLIC filesystem per call/subTest; no old fixture adoption.
        fixture = ReleaseTransactionTests(methodName="runTest")
        fixture.setUp()
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            fixture._http_main_public_source_fixture()
            if not dhcp:
                fixture.inputs = LOAD.replace(
                    fixture.inputs,
                    settings=LOAD.replace(fixture.inputs.settings, dhcp_enabled=False, ztp_enabled=False),
                )
            if explicit_http_only:
                self.assertFalse(dhcp)
                fixture.inputs = LOAD.replace(
                    fixture.inputs,
                    settings=LOAD.replace(fixture.inputs.settings, http_address="192.0.2.1"),
                )
            proc = fixture.root / "i03-empty-proc"
            proc.mkdir()
            plan = SimpleNamespace(listener_names=("eno2",), endpoint_ips=("192.0.2.10",))
            backend = LOAD.service_runtime_backend(
                {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=manager.query,
            )
            native_monitor = LOAD.stop_native_ztp_monitors

            def systemctl_path(program):
                if program != "systemctl":
                    manager.adapter_errors.append(("which", "unsupported-program", str(program)))
                self.assertEqual("systemctl", program)
                return "/fixture/systemctl"

            def monitor(root, **kwargs):
                if Path(root) != fixture.root:
                    manager.adapter_errors.append(("monitor", "wrong-public-root"))
                self.assertEqual(fixture.root, Path(root))
                manager.events.append(("monitor-quiesce", manager.phase))
                def no_signal(*_args):
                    manager.adapter_errors.append(("monitor", "unexpected-signal"))
                    self.fail("empty PUBLIC proc may not signal")
                return native_monitor(root, proc_root=proc, kill=no_signal, **kwargs)

            def shared_setup(*_args, **_kwargs):
                manager.events.append(("shared-setup", manager.phase))

            def forbidden_postinfra(*_args, **_kwargs):
                if expected_postinfra:
                    manager.events.append(("owned-postinfra", manager.phase))
                    raise LOAD.LoadError("I06_OWNED_POSTINFRA_SENTINEL")
                manager.events.append(("forbidden-postinfra", manager.phase))
                manager.adapter_errors.append(("postinfra", "forbidden"))
                raise LOAD.LoadError("I03_FORBIDDEN_POSTINFRA")

            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(LOAD, "HTTP_ROOT", fixture.root))
                stack.enter_context(fixture._http_linux_public_ancestor_model())
                stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
                stack.enter_context(mock.patch.object(LOAD, "service_runtime_backend", return_value=backend))
                stack.enter_context(mock.patch.object(LOAD, "resolve_project", return_value=fixture.project))
                stack.enter_context(mock.patch.object(LOAD, "active_project", return_value=fixture.project.resolve()))
                stack.enter_context(mock.patch.object(LOAD, "acquire_deployment_lock", return_value=91))
                stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock"))
                stack.enter_context(mock.patch.object(LOAD, "require_no_pending_dhcp_transaction"))
                stack.enter_context(mock.patch.object(LOAD, "sync_marker_present", return_value=False))
                stack.enter_context(mock.patch.object(LOAD, "ensure_previous_generation_frozen", return_value=None))
                stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
                stack.enter_context(mock.patch.object(LOAD, "validate_inputs", return_value=(fixture.inputs, {})))
                stack.enter_context(mock.patch.object(LOAD, "validate_management_host", return_value=True))
                stack.enter_context(mock.patch.object(LOAD, "plan_local_dhcp_runtime", return_value=plan))
                stack.enter_context(mock.patch.object(LOAD, "confirm_ztp_monitor_start", return_value=False))
                stack.enter_context(mock.patch.object(LOAD, "stop_native_ztp_monitors", side_effect=monitor))
                # Off-scope shared setup/render are event boundaries, not policy stand-ins.
                stack.enter_context(mock.patch.object(LOAD, "activate_project", side_effect=shared_setup))
                stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
                stack.enter_context(mock.patch.object(LOAD, "snapshot_ztp_prefix_publication", return_value=None))
                stack.enter_context(mock.patch.object(LOAD, "configure_ztp_prefix_publication"))
                stack.enter_context(mock.patch.object(LOAD, "select_http_ip", return_value="192.0.2.1"))
                stack.enter_context(mock.patch.object(LOAD, "run", side_effect=manager.external_run))
                stack.enter_context(mock.patch.object(LOAD, "_run_subprocess", side_effect=manager.query))
                stack.enter_context(mock.patch.object(LOAD.shutil, "which", side_effect=systemctl_path))
                # First post-infra real main call under this PUBLIC HTTP fixture.
                # A missing-unit admission regression must stop here, not run
                # Monitor/generation/network descendants after --skip-infra.
                stack.enter_context(mock.patch.object(
                    LOAD, "verify_monitor_authority", side_effect=forbidden_postinfra,
                ))
                requested = [
                    str(fixture.project), "--host-role=management-server", "--prod",
                    "--switch=eth", "--no-upgrade", "--skip-doca",
                ]
                if skip_infra:
                    requested.append("--skip-infra")
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = LOAD.main(requested)
            # Outside main's broad catch and all command mock scopes: adapter
            # assertion errors swallowed by main must not count as policy RED.
            self.assertEqual([], manager.adapter_errors)
            return result, stdout.getvalue(), stderr.getvalue()
        finally:
            fixture.tearDown()




    def test_first_install_absence_reaches_deferred_infra_then_cleanup_is_required(self):
        with self.subTest(control="loaded-main-to-prepare"):
            positive = _I03LiteralManager(
                {"apache2": "dead", "isc-dhcp-server": "dead"}, fault_point="prepare-only",
            )
            result, _stdout, stderr = self._i03_main(positive)
            self.assertEqual(1, result)
            self.assertIn("I03_OWNED_PREPARE_SENTINEL", stderr)
            prepares = [event for event in positive.events if event[0] == "infra-prepare"]
            self.assertEqual(1, len(prepares), stderr)
            self.assertIn("--prepare-only", prepares[0][2])
            self.assertIn("--http-server-ip", prepares[0][2])
            self.assertIn("192.0.2.1", prepares[0][2])
            self.assertEqual([], [event for event in positive.events if event[0] == "infra-attempt"])
            before = positive.events[:positive.events.index(prepares[0])]
            self.assertEqual({"apache2", "isc-dhcp-server"},
                             {event[2] for event in before if event[0] == "query"})
            self.assertNotIn("服务停止清理失败", stderr)
        for fault_point in ("prepare-only", "installer"):
            with self.subTest(fault_point=fault_point):
                manager = _I03LiteralManager(
                    {"apache2": "absent", "isc-dhcp-server": "absent"}, fault_point=fault_point,
                )
                result, _stdout, stderr = self._i03_main(manager)
                self.assertEqual(1, result, "owned sentinel is the expected failure, not LOAD success")
                prepares = [event for event in manager.events if event[0] == "infra-prepare"]
                self.assertEqual(1, len(prepares), stderr)
                self.assertIn("--prepare-only", prepares[0][2])
                attempts = [event for event in manager.events if event[0] == "infra-attempt"]
                if fault_point == "installer":
                    # Retain the original second-command sentinel assertions.
                    self.assertEqual(1, len(attempts), stderr)
                    self.assertIn("--defer-services", attempts[0][2])
                    self.assertIn("--install-apache", attempts[0][2])
                    self.assertIn("--install-dhcp", attempts[0][2])
                    self.assertIn("I03_OWNED_INSTALLER_SENTINEL", stderr)
                else:
                    self.assertEqual([], attempts)
                    self.assertIn("I03_OWNED_PREPARE_SENTINEL", stderr)
                before = manager.events[:manager.events.index(prepares[0])]
                self.assertEqual({"apache2", "isc-dhcp-server"},
                                 {event[2] for event in before if event[0] == "query"})
                self.assertEqual([], [action for action in manager.actions if action[0] == "preinstall"])
                self.assertTrue(any(event[0] == "monitor-quiesce" for event in before))
                # Both fault points are after exemption ends: before the first
                # prepare command, not merely before the second bash command.
                self.assertTrue(any(event[:2] == ("query", "install-attempted")
                                    for event in manager.events))
                self.assertIn("服务停止清理失败", stderr)
                self.assertEqual([], manager.actions, "required missing units may not receive cleanup control requests")

    def test_first_install_stops_existing_isc_with_new_dhcp_disabled_and_never_kea(self):
        manager = _I03LiteralManager({"apache2": "absent", "isc-dhcp-server": "active"})
        result, _stdout, stderr = self._i03_main(manager, dhcp=False)
        self.assertEqual(1, result)
        attempts = [event for event in manager.events if event[0] == "infra-attempt"]
        self.assertEqual(1, len(attempts), stderr)
        self.assertIn("--install-apache", attempts[0][2])
        self.assertNotIn("--install-dhcp", attempts[0][2])
        self.assertIn("--defer-services", attempts[0][2])
        before = manager.events[:manager.events.index(attempts[0])]
        stop = ("action", "preinstall", "isc-dhcp-server", "stop")
        self.assertEqual(1, before.count(stop))
        self.assertEqual({"apache2", "isc-dhcp-server"},
                         {event[2] for event in before[:before.index(stop)] if event[0] == "query"})
        self.assertTrue(any(event[:3] == ("query", "preinstall", "isc-dhcp-server")
                            for event in before[before.index(stop) + 1:]))
        self.assertEqual("dead", manager.states["isc-dhcp-server"])
        self.assertEqual([("preinstall", "stop", "isc-dhcp-server")],
                         [action for action in manager.actions if action[0] == "preinstall"])
        self.assertIn("I03_OWNED_INSTALLER_SENTINEL", stderr)
        self.assertIn("服务停止清理失败", stderr)
        self.assertFalse(any("kea" in str(event).casefold() for event in manager.events))

    def test_preinstall_bad_query_cannot_stop_first_unit_or_enter_shared_setup(self):
        for case in _I03_BAD_SHOW:
            with self.subTest(case=case[0]):
                manager = _I03LiteralManager(
                    {"apache2": "absent", "isc-dhcp-server": "active"}, bad_show=case,
                )
                result, _stdout, stderr = self._i03_main(manager)
                self.assertEqual(1, result)
                self.assertTrue(any(event[:3] == ("query", "preinstall", "apache2")
                                    for event in manager.events), stderr)
                self.assertEqual([], manager.actions)
                self.assertEqual([], [event for event in manager.events
                                      if event[0] in {"shared-setup", "infra-prepare", "infra-attempt"}])
                # This does NOT assert zero whole-LOAD writes or zero Monitor work.
                self.assertTrue(any(event[0] == "monitor-quiesce" for event in manager.events))
                self.assertEqual("preinstall", manager.phase)

    def test_required_postinstall_missing_refuses_before_activation(self):
        for missing in (None, "apache2", "isc-dhcp-server"):
            with self.subTest(missing=missing):
                fixture = ReleaseTransactionTests(methodName="runTest")
                fixture.setUp()
                try:
                    states = {"apache2": "dead", "isc-dhcp-server": "dead"}
                    if missing is not None:
                        states[missing] = "absent"
                    manager = _I03LiteralManager(states)
                    manager.phase = "install-attempted"
                    backend = LOAD.service_runtime_backend(
                        {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=manager.query,
                    )
                    with mock.patch.object(LOAD.shutil, "which", return_value="/fixture/systemctl"), \
                            mock.patch.object(LOAD, "_run_subprocess", side_effect=manager.query), \
                            mock.patch.object(LOAD, "run", side_effect=manager.external_run), \
                            mock.patch.object(LOAD, "ensure_ztp_url_network_ready"), \
                            mock.patch.object(LOAD, "verify_http_publication"), \
                            redirect_stdout(io.StringIO()):
                        if missing is None:
                            LOAD.start_services(
                                fixture.inputs, {}, dhcp_runtime_plan=SimpleNamespace(listener_names=("eno2",)),
                                runtime_backend=backend,
                            )
                        else:
                            with self.assertRaises(LOAD.LoadError):
                                LOAD.start_services(
                                    fixture.inputs, {}, dhcp_runtime_plan=SimpleNamespace(listener_names=("eno2",)),
                                    runtime_backend=backend,
                                )
                    self.assertEqual([], manager.adapter_errors)
                    if missing is None:
                        first_action = next(i for i, event in enumerate(manager.events)
                                            if event[0] == "action")
                        before_action = manager.events[:first_action]
                        for unit in ("apache2", "isc-dhcp-server"):
                            self.assertIn(("query", "install-attempted", unit, "show"), before_action)
                            self.assertIn(
                                ("show", "--all", "--no-pager",
                                 "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job", unit),
                                [argv[1:] for argv in manager.query_argv],
                            )
                        self.assertEqual(
                            [("install-attempted", "enable", "apache2"),
                             ("install-attempted", "enable", "isc-dhcp-server"),
                             ("install-attempted", "restart", "isc-dhcp-server")],
                            manager.actions,
                        )
                    else:
                        self.assertIn(("query", "install-attempted", missing, "show"), manager.events)
                        self.assertIn(
                            ("show", "--all", "--no-pager",
                             "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job", missing),
                            [argv[1:] for argv in manager.query_argv],
                        )
                        self.assertEqual([], manager.actions)
                finally:
                    fixture.tearDown()

    def test_skip_infra_absence_cannot_reach_shared_setup_or_preparation(self):
        with self.subTest(control="normal-loaded-main"):
            positive = _I03LiteralManager(
                {"apache2": "dead", "isc-dhcp-server": "dead"}, fault_point="prepare-only",
            )
            result, _stdout, stderr = self._i03_main(positive)
            self.assertEqual(1, result)
            self.assertIn("I03_OWNED_PREPARE_SENTINEL", stderr)
            self.assertEqual(1, len([event for event in positive.events if event[0] == "infra-prepare"]))
        with self.subTest(target="skip-infra-exact-absent"):
            manager = _I03LiteralManager({"apache2": "absent", "isc-dhcp-server": "absent"})
            result, _stdout, stderr = self._i03_main(manager, skip_infra=True)
            self.assertEqual(1, result)
            self.assertTrue(any(event[0] == "query" for event in manager.events))
            self.assertTrue(any(event[0] == "monitor-quiesce" for event in manager.events))
            self.assertEqual([], manager.actions)
            self.assertEqual([], [event for event in manager.events if event[0] in {
                "shared-setup", "infra-prepare", "infra-attempt", "forbidden-postinfra",
            }])
            self.assertEqual("preinstall", manager.phase)
            self.assertNotIn("I03_OWNED_PREPARE_SENTINEL", stderr)
            self.assertNotIn("I03_OWNED_INSTALLER_SENTINEL", stderr)

# I06 stage 2: tests-only PUBLIC command-boundary model; NOTRUN.
# Intended append to test_cases/test_load_release_transaction.py.
# No service-policy function is copied. Existing LOAD/start/snapshot/main run
# only under the finite external adapters below after future Root issuance.

class _I06HttpOnlyManager(_I03LiteralManager):
    def __init__(self, states, *, bad_isc_show=None, activate_at_prepare=False,
                 fault_point="installer"):
        super().__init__(states, fault_point=fault_point)
        self.bad_isc_show = bad_isc_show
        self.activate_at_prepare = activate_at_prepare

    def query(self, command, **kwargs):
        result = super().query(command, **kwargs)
        argv = tuple(str(part) for part in command)
        if (argv[1:] == ("show", "--all", "--no-pager",
                        "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job",
                        "isc-dhcp-server")
                and self.bad_isc_show is not None):
            _label, code, raw, diagnostic = self.bad_isc_show
            return SimpleNamespace(returncode=code, stdout=raw, stderr=diagnostic)
        return result

    def external_run(self, command, **kwargs):
        argv = tuple(str(part) for part in command)
        if self.activate_at_prepare and any(
                part.endswith("/deploy_infra.py") for part in argv):
            # Independent partial-install fixture, not a production-state claim.
            self.states["apache2"] = "active"
            self.events.append(("public-partial-install", self.phase))
        return super().external_run(command, **kwargs)


class NativeHttpOnlyOptionalIscContractTests(unittest.TestCase):
    # Reuse only the real-main PUBLIC fixture helper; do not inherit its tests.
    _i03_main = NativePreinstallPresenceWorkflowTests._i03_main

    def _i06_start(self, manager, *, health_failure=False, dhcp=False,
                   ztp=False, independent_http=True):
        fixture = ReleaseTransactionTests(methodName="runTest")
        fixture.setUp()
        error = None
        try:
            settings = LOAD.replace(
                fixture.inputs.settings, dhcp_enabled=dhcp, ztp_enabled=ztp,
                http_address="192.0.2.1" if independent_http else None,
            )
            inputs = LOAD.replace(fixture.inputs, settings=settings)
            plan = SimpleNamespace(listener_names=("eno2",),
                                   endpoint_ips=("192.0.2.1",))
            backend = LOAD.service_runtime_backend(
                {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"},
                command_runner=manager.query,
            )

            def which(program):
                if program != "systemctl":
                    manager.adapter_errors.append(("which", "unsupported", str(program)))
                self.assertEqual("systemctl", program)
                return "/fixture/systemctl"

            def health(*_args, **_kwargs):
                manager.events.append(("http-health", manager.phase))
                if health_failure:
                    raise LOAD.LoadError("I06_PUBLIC_HTTP_HEALTH_SENTINEL")

            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
                stack.enter_context(mock.patch.object(LOAD.shutil, "which", side_effect=which))
                stack.enter_context(mock.patch.object(LOAD, "_run_subprocess", side_effect=manager.query))
                stack.enter_context(mock.patch.object(LOAD, "run", side_effect=manager.external_run))
                stack.enter_context(mock.patch.object(LOAD, "ensure_ztp_url_network_ready"))
                stack.enter_context(mock.patch.object(LOAD, "verify_http_publication", side_effect=health))
                try:
                    LOAD.start_services(inputs, {}, dhcp_runtime_plan=plan,
                                        runtime_backend=backend)
                except LOAD.LoadError as exc:
                    error = exc
            # Outside every production exception handler and command adapter.
            self.assertEqual([], manager.adapter_errors)
            return error
        finally:
            fixture.tearDown()

    def _assert_both_show_before_first_action(self, manager):
        events = manager.events
        action_indexes = [i for i, row in enumerate(events) if row[0] == "action"]
        self.assertTrue(action_indexes)
        for unit in ("apache2", "isc-dhcp-server"):
            indexes = [i for i, row in enumerate(events)
                       if row[:1] == ("query",) and row[2:] == (unit, "show")]
            self.assertTrue(indexes, unit)
            self.assertLess(indexes[0], action_indexes[0])

    def _assert_absent_isc_not_treated_as_quiet_false(self, manager):
        self.assertFalse([row for row in manager.actions
                          if row[2] == "isc-dhcp-server"])
        self.assertFalse([argv for argv in manager.query_argv
                          if argv[-1] == "isc-dhcp-server"
                          and argv[1] in ("is-active", "is-enabled")])

    def test_http_only_loaded_pair_and_absent_isc_start_through_real_api(self):
        with self.subTest(case="loaded-pair-positive"):
            manager = _I06HttpOnlyManager({"apache2": "dead", "isc-dhcp-server": "active"})
            manager.enabled["isc-dhcp-server"] = True
            self.assertIsNone(self._i06_start(manager))
            self._assert_both_show_before_first_action(manager)
            self.assertEqual([
                ("preinstall", "stop", "isc-dhcp-server"),
                ("preinstall", "disable", "isc-dhcp-server"),
                ("preinstall", "enable", "apache2"),
            ], manager.actions)
            self.assertEqual("dead", manager.states["isc-dhcp-server"])
            self.assertIs(False, manager.enabled["isc-dhcp-server"])
            self.assertEqual(1, sum(row[0] == "http-health" for row in manager.events))
        with self.subTest(case="strict-absent-optional-positive"):
            manager = _I06HttpOnlyManager({"apache2": "dead", "isc-dhcp-server": "absent"})
            self.assertIsNone(self._i06_start(manager))
            self._assert_both_show_before_first_action(manager)
            self.assertEqual([("preinstall", "enable", "apache2")], manager.actions)
            self._assert_absent_isc_not_treated_as_quiet_false(manager)
            self.assertEqual(1, sum(row[0] == "http-health" for row in manager.events))

    def test_http_only_required_apache_and_bad_optional_wire_refuse_before_control(self):
        with self.subTest(case="loaded-pair-positive"):
            manager = _I06HttpOnlyManager({"apache2": "dead", "isc-dhcp-server": "dead"})
            self.assertIsNone(self._i06_start(manager))
            self._assert_both_show_before_first_action(manager)
        # These are existing independently literal six-field negative wires,
        # not a list derived from read_unit_state or its returned record.
        cases = [("apache-absent", None)] + [
            (label, row) for row in _I03_BAD_SHOW for label in (row[0],)
        ]
        for label, bad_wire in cases:
            with self.subTest(case=label):
                manager = _I06HttpOnlyManager(
                    {"apache2": "absent" if bad_wire is None else "dead",
                     "isc-dhcp-server": "absent"},
                    bad_isc_show=bad_wire,
                )
                self.assertIsInstance(self._i06_start(manager), LOAD.LoadError)
                self.assertEqual([], manager.actions)
                self.assertFalse(any(row[0] == "http-health" for row in manager.events))
                unit = "apache2" if bad_wire is None else "isc-dhcp-server"
                self.assertIn(("query", "preinstall", unit, "show"), manager.events)

    def test_http_health_failure_preserves_primary_and_never_revives_disabled_dhcp(self):
        for isc in ("active", "absent"):
            with self.subTest(isc=isc):
                manager = _I06HttpOnlyManager({"apache2": "dead", "isc-dhcp-server": isc})
                manager.enabled["isc-dhcp-server"] = isc == "active"
                error = self._i06_start(manager, health_failure=True)
                self.assertIsInstance(error, LOAD.LoadError)
                self.assertIn("I06_PUBLIC_HTTP_HEALTH_SENTINEL", str(error))
                self.assertEqual(1, sum(row[0] == "http-health" for row in manager.events))
                self.assertEqual("dead", manager.states["apache2"])
                self.assertIs(False, manager.enabled["apache2"])
                self.assertFalse([row for row in manager.actions
                                  if row[2] == "isc-dhcp-server"
                                  and row[1] in ("start", "restart", "enable")])
                if isc == "absent":
                    self._assert_absent_isc_not_treated_as_quiet_false(manager)
                    self.assertEqual([
                        ("preinstall", "enable", "apache2"),
                        ("preinstall", "stop", "apache2"),
                        ("preinstall", "disable", "apache2"),
                    ], manager.actions)
                else:
                    self.assertEqual("dead", manager.states["isc-dhcp-server"])
                    self.assertIs(False, manager.enabled["isc-dhcp-server"])
                last_action = max(i for i, row in enumerate(manager.events) if row[0] == "action")
                for unit in ("apache2", "isc-dhcp-server"):
                    self.assertTrue(any(
                        i > last_action and row == ("query", "preinstall", unit, "show")
                        for i, row in enumerate(manager.events)
                    ), "cleanup must freshly verify both fixed units")

    def test_main_prepare_fault_stops_loaded_apache_despite_optional_isc_absence(self):
        for isc, point, sentinel in (
                ("dead", "prepare-only", "I03_OWNED_PREPARE_SENTINEL"),
                ("dead", "installer", "I03_OWNED_INSTALLER_SENTINEL"),
                ("absent", "prepare-only", "I03_OWNED_PREPARE_SENTINEL"),
                ("absent", "installer", "I03_OWNED_INSTALLER_SENTINEL")):
            with self.subTest(isc=isc, point=point):
                manager = _I06HttpOnlyManager(
                    {"apache2": "dead", "isc-dhcp-server": isc},
                    activate_at_prepare=True, fault_point=point,
                )
                result, _stdout, stderr = self._i03_main(
                    manager, dhcp=False, explicit_http_only=True,
                )
                self.assertEqual(1, result)
                self.assertIn(sentinel, stderr)
                self.assertNotIn("服务停止清理失败", stderr)
                self.assertEqual([("install-attempted", "stop", "apache2")], manager.actions)
                self.assertEqual("dead", manager.states["apache2"])
                if isc == "absent":
                    self._assert_absent_isc_not_treated_as_quiet_false(manager)
                self.assertEqual(1, sum(row[0] == "infra-prepare" for row in manager.events))
                self.assertEqual(int(point == "installer"),
                                 sum(row[0] == "infra-attempt" for row in manager.events))
                self.assertFalse(any(row[0] == "forbidden-postinfra" for row in manager.events))
                stop = manager.events.index(("action", "install-attempted", "apache2", "stop"))
                for unit in ("apache2", "isc-dhcp-server"):
                    self.assertTrue(any(
                        i > stop and row == ("query", "install-attempted", unit, "show")
                        for i, row in enumerate(manager.events)
                    ))
                self.assertEqual([], manager.adapter_errors)

    def test_http_only_skip_infra_requires_apache_but_not_absent_isc(self):
        with self.subTest(case="loaded-pair-main-positive"):
            manager = _I06HttpOnlyManager({"apache2": "dead", "isc-dhcp-server": "dead"})
            result, _stdout, stderr = self._i03_main(
                manager, dhcp=False, skip_infra=True, explicit_http_only=True,
                expected_postinfra=True,
            )
            self.assertEqual(1, result)
            self.assertIn("I06_OWNED_POSTINFRA_SENTINEL", stderr)
            self.assertEqual(1, sum(row[0] == "shared-setup" for row in manager.events))
            self.assertEqual(1, sum(row[0] == "owned-postinfra" for row in manager.events))
            self.assertEqual([], manager.actions)
            self.assertFalse(any(row[0] in ("infra-prepare", "infra-attempt", "forbidden-postinfra")
                                 for row in manager.events))
        with self.subTest(case="apache-loaded-isc-absent"):
            manager = _I06HttpOnlyManager({"apache2": "dead", "isc-dhcp-server": "absent"})
            result, _stdout, stderr = self._i03_main(
                manager, dhcp=False, skip_infra=True, explicit_http_only=True,
                expected_postinfra=True,
            )
            self.assertEqual(1, result)  # Owned boundary sentinel, not full main success.
            self.assertIn("I06_OWNED_POSTINFRA_SENTINEL", stderr)
            self.assertNotIn("服务停止清理失败", stderr)
            self.assertEqual(1, sum(row[0] == "shared-setup" for row in manager.events))
            self.assertEqual(1, sum(row[0] == "owned-postinfra" for row in manager.events))
            self.assertFalse(any(row[0] in ("infra-prepare", "infra-attempt", "forbidden-postinfra")
                                 for row in manager.events))
            self.assertEqual([], manager.actions)
            self._assert_absent_isc_not_treated_as_quiet_false(manager)
        with self.subTest(case="both-missing-still-required-apache"):
            manager = _I06HttpOnlyManager({"apache2": "absent", "isc-dhcp-server": "absent"})
            result, _stdout, stderr = self._i03_main(
                manager, dhcp=False, skip_infra=True, explicit_http_only=True,
                expected_postinfra=True,
            )
            self.assertEqual(1, result)
            self.assertNotIn("I06_OWNED_POSTINFRA_SENTINEL", stderr)
            self.assertFalse(any(row[0] in ("shared-setup", "owned-postinfra",
                                          "infra-prepare", "infra-attempt", "forbidden-postinfra")
                                 for row in manager.events))
            self.assertEqual([], manager.actions)

    def test_optional_presence_cannot_escape_into_required_snapshot_or_other_modes(self):
        for mode in ("snapshot", "quiesce", "dual-service", "ztp-still-enabled",
                     "no-independent-http"):
            with self.subTest(mode=mode):
                manager = _I06HttpOnlyManager({"apache2": "dead", "isc-dhcp-server": "absent"})
                backend = LOAD.service_runtime_backend(
                    {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=manager.query,
                )
                if mode in ("snapshot", "quiesce"):
                    with mock.patch.object(LOAD.shutil, "which", return_value="/fixture/systemctl"), \
                            mock.patch.object(LOAD, "_run_subprocess", side_effect=manager.query), \
                            mock.patch.object(LOAD, "run", side_effect=manager.external_run), \
                            mock.patch.object(LOAD, "stop_native_ztp_monitors"):
                        with self.assertRaises(LOAD.LoadError):
                            if mode == "snapshot":
                                LOAD.snapshot_service_states(("apache2", "isc-dhcp-server"),
                                                             runtime_backend=backend)
                            else:
                                LOAD.quiesce_services(False, runtime_backend=backend,
                                                      host_role="management-server")
                else:
                    error = self._i06_start(
                        manager, dhcp=mode == "dual-service",
                        ztp=mode != "no-independent-http",
                        independent_http=mode != "no-independent-http",
                    )
                    self.assertIsInstance(error, LOAD.LoadError)
                self.assertEqual([], manager.actions)
                self.assertEqual([], manager.adapter_errors)

    def test_http_only_loaded_transitional_quiet_three_cannot_advance_without_quiescence(self):
        with self.subTest(case="loaded-quiescent-main-positive"):
            manager = _I06HttpOnlyManager({"apache2": "dead", "isc-dhcp-server": "dead"})
            result, _stdout, stderr = self._i03_main(
                manager, dhcp=False, skip_infra=True, explicit_http_only=True,
                expected_postinfra=True,
            )
            self.assertEqual(1, result)
            self.assertIn("I06_OWNED_POSTINFRA_SENTINEL", stderr)
            self.assertEqual(1, sum(row[0] == "owned-postinfra" for row in manager.events))
            self.assertEqual([], manager.actions)
        wires = (
            ("activating-auto-restart",
             "LoadState=loaded\nActiveState=activating\nSubState=auto-restart\nMainPID=0\nControlPID=0\nJob=\n"),
            ("nonzero-main-pid",
             "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=23\nControlPID=0\nJob=\n"),
            ("nonzero-control-pid",
             "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=19\nJob=\n"),
            ("nonempty-job",
             "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=7\n"),
        )
        for unit in ("apache2", "isc-dhcp-server"):
            for label, raw in wires:
                for mode in ("settle-after-stop", "persistent-after-stop"):
                    with self.subTest(unit=unit, state=label, mode=mode):
                        replacement = (label, 0, raw, "")
                        manager = _I06HttpOnlyManager(
                            {"apache2": "dead", "isc-dhcp-server": "dead"},
                            bad_isc_show=replacement if unit == "isc-dhcp-server" else None,
                        )
                        if unit == "apache2":
                            manager.bad_show = replacement
                        # Independent adapter positive; quiet3 is not stopped
                        # authority, nor a production query requirement.
                        quiet = manager.query(("systemctl", "is-active", "--quiet", unit))
                        self.assertIs(int, type(quiet.returncode))
                        self.assertEqual(3, quiet.returncode)
                        original_external_run = manager.external_run

                        def external_run(command, **kwargs):
                            # Original finite adapter validates/records first.
                            # Only its successful target stop may settle show.
                            answer = original_external_run(command, **kwargs)
                            argv = tuple(str(part) for part in command)
                            if "systemctl" in argv:
                                tail = argv[argv.index("systemctl") + 1:]
                                if tail == ("stop", unit) and mode == "settle-after-stop":
                                    if unit == "apache2":
                                        manager.bad_show = None
                                    else:
                                        manager.bad_isc_show = None
                            return answer

                        manager.external_run = external_run
                        result, _stdout, stderr = self._i03_main(
                            manager, dhcp=False, skip_infra=True, explicit_http_only=True,
                            expected_postinfra=True,
                        )
                        self.assertEqual(1, result)
                        self._assert_both_show_before_first_action(manager)
                        self.assertIn(("preinstall", "stop", unit), manager.actions)
                        self.assertFalse([row for row in manager.actions
                                          if row[1] != "stop" or row[2] != unit])
                        stop = max(i for i, row in enumerate(manager.events)
                                   if row == ("action", "preinstall", unit, "stop"))
                        for fixed_unit in ("apache2", "isc-dhcp-server"):
                            self.assertTrue(any(
                                i > stop and row == ("query", "preinstall", fixed_unit, "show")
                                for i, row in enumerate(manager.events)
                            ), "fresh complete pair is required after target stop")
                        if mode == "settle-after-stop":
                            self.assertEqual([("preinstall", "stop", unit)], manager.actions)
                            self.assertIn("I06_OWNED_POSTINFRA_SENTINEL", stderr)
                            self.assertNotIn("服务停止清理失败", stderr)
                            shared = [i for i, row in enumerate(manager.events)
                                      if row[0] == "shared-setup"]
                            self.assertEqual(1, len(shared))
                            owned = [i for i, row in enumerate(manager.events)
                                     if row[0] == "owned-postinfra"]
                            self.assertEqual(1, len(owned))
                            for fixed_unit in ("apache2", "isc-dhcp-server"):
                                self.assertTrue(any(
                                    stop < i < shared[0] < owned[0]
                                    and row == ("query", "preinstall", fixed_unit, "show")
                                    for i, row in enumerate(manager.events)
                                ), "must freshly confirm before advancing")
                        else:
                            self.assertNotIn("I06_OWNED_POSTINFRA_SENTINEL", stderr)
                            self.assertFalse(any(row[0] in ("shared-setup", "owned-postinfra")
                                                 for row in manager.events))
                        self.assertFalse(any(row[0] in ("infra-prepare", "infra-attempt",
                                                       "forbidden-postinfra")
                                             for row in manager.events))
                        self.assertEqual([], manager.adapter_errors)


class FixtureScandirTransferContractTests(unittest.TestCase):
    """Independent finite ownership model; no filesystem or SUT operations."""

    def test_success_transfers_same_iterator_without_closing(self):
        entries = SimpleNamespace(close=mock.Mock())
        descriptor = object()
        scan, mutation = mock.Mock(return_value=entries), mock.Mock()
        custody = {"unknown": False, "secondary": []}
        result = _fixture_scan_then_mutate(scan, descriptor, mutation, custody)
        self.assertIs(entries, result)
        scan.assert_called_once_with(descriptor)
        mutation.assert_called_once_with()
        entries.close.assert_not_called()
        self.assertEqual({"unknown": False, "secondary": []}, custody)

    def test_scan_failure_has_no_returned_owner_and_preserves_primary(self):
        primary = OSError("independent scan failure")
        descriptor = object()
        scan, mutation = mock.Mock(side_effect=primary), mock.Mock()
        custody = {"unknown": False, "secondary": []}
        with self.assertRaises(OSError) as caught:
            _fixture_scan_then_mutate(scan, descriptor, mutation, custody)
        self.assertIs(primary, caught.exception)
        scan.assert_called_once_with(descriptor)
        mutation.assert_not_called()
        self.assertEqual({"unknown": True, "secondary": []}, custody)

    def test_mutation_failure_closes_once_and_preserves_same_primary(self):
        primary = KeyboardInterrupt("independent mutation failure")
        entries = SimpleNamespace(close=mock.Mock())
        descriptor = object()
        scan, mutation = mock.Mock(return_value=entries), mock.Mock(side_effect=primary)
        custody = {"unknown": False, "secondary": []}
        with self.assertRaises(KeyboardInterrupt) as caught:
            _fixture_scan_then_mutate(scan, descriptor, mutation, custody)
        self.assertIs(primary, caught.exception)
        scan.assert_called_once_with(descriptor)
        mutation.assert_called_once_with()
        entries.close.assert_called_once_with()
        self.assertEqual({"unknown": False, "secondary": []}, custody)

    def test_close_failure_is_secondary_unknown_without_retry_or_new_scan(self):
        primary = KeyboardInterrupt("independent mutation primary")
        secondary = OSError("independent iterator close failure")
        entries = SimpleNamespace(close=mock.Mock(side_effect=secondary))
        descriptor = object()
        scan, mutation = mock.Mock(return_value=entries), mock.Mock(side_effect=primary)
        custody = {"unknown": False, "secondary": []}
        with self.assertRaises(KeyboardInterrupt) as caught:
            _fixture_scan_then_mutate(scan, descriptor, mutation, custody)
        self.assertIs(primary, caught.exception)
        self.assertTrue(custody["unknown"])
        self.assertEqual(1, len(custody["secondary"]))
        self.assertIs(secondary, custody["secondary"][0])
        with self.assertRaisesRegex(RuntimeError, "^fixture scandir custody UNKNOWN$"):
            _fixture_scan_then_mutate(scan, descriptor, mutation, custody)
        scan.assert_called_once_with(descriptor)
        mutation.assert_called_once_with()
        entries.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
