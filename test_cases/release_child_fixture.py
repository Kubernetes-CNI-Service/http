"""Unified release validation, DHCP installation, and rollback transactions."""

from __future__ import annotations

import base64
import csv
from contextlib import ExitStack, contextmanager, nullcontext
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import http.server
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
    setup_guard=None, a_shapes=False, publication_candidates=None, a_metadata=False,
    require_staged_inventory=False, preserve_selected_a=False,
    prepared_source=None,
) -> None:
    """Exercise real LOAD filesystem logic; never execute sudo, dhcpd or live writes."""
    root = root.resolve()
    source_dir = prepared_source or project / "independent-dhcp-B"
    live_dir = root / "private-etc-dhcp"
    if prepared_source is None:
        source_dir.mkdir()
    else:
        assert publication_candidates is not None
        assert source_dir == publication_candidates[0].dhcp_source_dir
    live_dir.mkdir(exist_ok=preserve_selected_a)
    names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
    expected_b = {name: f"independent-B:{name}\n".encode() for name in names}
    expected_b["dhcpd.conf"] = b"# independent-B configuration\n" + b"".join(
        f'include "/etc/dhcp/{name}";\n'.encode() for name in names[1:]
    )
    if preserve_selected_a and (a_shapes or a_metadata or outcome == "precommit-shapes"):
        raise AssertionError("schema4 original selected owners cannot be rewritten into another fixture shape")
    expected_a = {name: ((name + "\n").encode() if preserve_selected_a
                         else f"independent-A:{name}\n".encode()) for name in names}
    mappings = {source_dir / name: live_dir / name for name in names}
    for source, destination in mappings.items():
        if prepared_source is None:
            source.write_bytes(expected_b[source.name])
        else:
            assert source.read_bytes() == expected_b[source.name], "sealed independent B bytes changed"
        if preserve_selected_a:
            assert destination.read_bytes() == expected_a[destination.name], "original selected A bytes were not installed"
        else:
            destination.write_bytes(expected_a[destination.name])
    if outcome == "precommit-shapes" or a_shapes:
        original_link_source = root / "independent-original-A-source"
        original_link_source.write_bytes(expected_a["dhcpd_eth.hosts"])
        (live_dir / "dhcpd_eth.hosts").unlink()
        (live_dir / "dhcpd_eth.hosts").symlink_to("../independent-original-A-source")
        (live_dir / "dhcpd_nvl.hosts").unlink()
    if a_metadata:
        (live_dir / "dhcpd.conf").chmod(0o640)
        os.utime(live_dir / "dhcpd.conf", ns=(1700000000123456789,) * 2)
    owner_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                    "st_size", "st_mtime_ns", "st_ctime_ns")
    initial_live_owners = {name: ([getattr((live_dir / name).lstat(), field) for field in owner_fields]
        if os.path.lexists(live_dir / name) else None) for name in names}
    first_install_inventory = []
    parent_payload = {"schema_version": 1, "release_id": "independent-B"}
    candidate = (api.prepare_current_release(project, parent_payload)
                 if publication_candidates is None else publication_candidates[0])
    setup_wal = root / "ztp/.setup-switch-journal.json"
    setup_wal_bytes = None
    if outcome in {"success-setup-wal", "success-setup-wal-probe-error"}:
        if not os.path.lexists(setup_wal):
            setup_wal.parent.mkdir(parents=True, exist_ok=True)
            setup_wal.write_bytes(b"independent unresolved SETUP evidence\n")
            setup_wal.chmod(0o600)
    if os.path.lexists(setup_wal):
        # Independent fixture authority: a real SETUP workflow already has
        # this WAL before DHCP. Parent-only success is not whole B success.
        setup_wal_bytes = setup_wal.read_bytes()
    wal_probe = setup_wal
    if outcome == "success-setup-wal-probe-error":
        wal_probe = SimpleNamespace(lstat=mock.Mock(side_effect=PermissionError(
            "independent SETUP WAL namespace denial",
        )))
    parent_identity = candidate.destination.parent.stat()
    real_open, real_sync, real_replace = os.open, os.fsync, os.replace
    injected, warnings, cleanup, restore_phase, sync_events, installed_b = [], [], [], [], [], []
    backup_sync_events = []
    backup_sync_faults = ("backup-file-sync", "backup-dir-sync", "backup-transaction-sync", "backup-runtime-sync")
    binding_faults = {"bound-setup-register-wal", "bound-setup-register-receipt", "bound-setup-register-backup", "bound-setup-late-wal",
                      "bound-setup-parent-wal", "bound-setup-candidate-sync", "bound-setup-candidate-register",
                      "bound-setup-candidate-live-a", "bound-setup-installed-b-owner",
                      "bound-setup-staged-register", "bound-setup-staged-aba"}

    def replace_bound_authority(path):
        held = root / ("independent-original-" + path.name)
        payload = path.read_bytes()
        mode = stat.S_IMODE(path.lstat().st_mode)
        original = path.lstat().st_ino
        path.rename(held)
        path.write_bytes(payload)
        path.chmod(mode)
        assert original != path.lstat().st_ino and path.read_bytes() == payload
        injected.append(outcome)

    if outcome == "bound-setup-parent-wal":
        candidate.precommit_check = lambda: replace_bound_authority(setup_wal)

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
                    if outcome in {"bound-setup-before-write", "bound-setup-precommit", "bound-setup-kill-first", "bound-setup-kill-last"}:
                        transaction, = live_dir.glob(".load-dhcp-transaction-*")
                        receipt = transaction / "a-preimage.json"
                        envelope = json.loads(setup_wal.read_bytes())
                        binding = envelope["body"].get("dhcp_transaction")
                        assert binding is not None, "original SETUP WAL must bind DHCP A before first B write"
                        assert binding["receipt"] == str(receipt)
                        assert binding["sha256"] == hashlib.sha256(receipt.read_bytes()).hexdigest()
                        metadata = receipt.lstat()
                        assert binding["identity"] == [getattr(metadata, field) for field in (
                            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                            "st_size", "st_mtime_ns", "st_ctime_ns",
                        )]
                        assert binding["body"] == json.loads(receipt.read_bytes())["body"]
                        inventory = binding["backup_inventory"]
                        backup_directory = receipt.parent / "backup"
                        owner = backup_directory.stat()
                        assert inventory["directory"] == dict(path=str(backup_directory),
                            dev=owner.st_dev, ino=owner.st_ino)
                        for backup_name in names:
                            original = backup_directory / backup_name
                            metadata = original.lstat() if os.path.lexists(original) else None
                            assert inventory["leaves"][backup_name] == (None if metadata is None else
                                [getattr(metadata, field) for field in ("st_dev", "st_ino", "st_mode",
                                 "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")])
                        for name in names:
                            if a_shapes and name == "dhcpd_eth.hosts":
                                assert binding["body"]["before"][name]["state"] == "link"
                                assert binding["body"]["before"][name]["target"] == "../independent-original-A-source"
                            elif a_shapes and name == "dhcpd_nvl.hosts":
                                assert binding["body"]["before"][name] == {"state": "missing"}
                            else:
                                assert binding["body"]["before"][name]["sha256"] == hashlib.sha256(expected_a[name]).hexdigest()
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
            if outcome == "bound-setup-late-wal" and target == live_dir / "dhcpd.conf" and not injected:
                replace_bound_authority(setup_wal)
            if outcome == "bound-setup-kill-first" and target == live_dir / "dhcpd.conf":
                os.kill(os.getpid(), signal.SIGKILL)
            if outcome == "bound-setup-kill-last" and target == live_dir / "dhcpd_nvl.hosts":
                os.kill(os.getpid(), signal.SIGKILL)
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
        if outcome in {"bound-setup-candidate-sync", "bound-setup-candidate-live-a"} and not injected:
            for transaction in live_dir.glob(".load-dhcp-transaction-*"):
                stage = transaction / "live-candidates/dhcpd.conf"
                if stage.exists() and (metadata.st_dev, metadata.st_ino) == (stage.stat().st_dev, stage.stat().st_ino):
                    path = live_dir / "dhcpd.conf" if outcome == "bound-setup-candidate-live-a" else stage
                    old = path.lstat()
                    replace_bound_authority(path)
                    os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
                    assert path.read_bytes() == (expected_a["dhcpd.conf"] if path.parent == live_dir
                                                else expected_b["dhcpd.conf"])
                    break
        if outcome in {"bound-setup-register-wal", "bound-setup-register-receipt", "bound-setup-register-backup",
                       "bound-setup-candidate-register", "bound-setup-staged-register",
                       "bound-setup-staged-aba"} and not injected:
            for temporary in setup_wal.parent.glob(".setup-switch-journal.*"):
                if temporary == setup_wal:
                    continue
                staged = temporary.lstat()
                if (metadata.st_dev, metadata.st_ino) == (staged.st_dev, staged.st_ino):
                    transaction = next(live_dir.glob(".load-dhcp-transaction-*"))
                    if outcome in {'bound-setup-staged-register', 'bound-setup-staged-aba'}:
                        authority = transaction / 'staged/dhcpd_ib.hosts'
                        original_metadata, original_payload = authority.lstat(), authority.read_bytes()
                        if outcome == 'bound-setup-staged-register': replace_bound_authority(authority)
                        else:
                            if sys.platform.startswith("linux"):
                                with tempfile.TemporaryDirectory(prefix="load-ctime-391-") as _ctime_probe_dir:
                                    _await_fixture_ctime_tick(Path(_ctime_probe_dir) / "probe", original_metadata.st_ctime_ns)
                            authority.write_bytes(b'independent staged file ABA\n')
                            authority.write_bytes(original_payload)
                            injected.append(outcome)
                            assert authority.lstat().st_ino == original_metadata.st_ino
                            assert authority.lstat().st_ctime_ns != original_metadata.st_ctime_ns
                        os.utime(authority, ns=(original_metadata.st_atime_ns, original_metadata.st_mtime_ns))
                        assert authority.read_bytes() == original_payload
                        break
                    authority = (setup_wal if outcome == "bound-setup-register-wal" else
                                 transaction / "backup/dhcpd.conf" if outcome == "bound-setup-register-backup"
                                 else transaction / "live-candidates/dhcpd.conf" if outcome == "bound-setup-candidate-register"
                                 else transaction / "a-preimage.json")
                    original_metadata = authority.lstat()
                    replace_bound_authority(authority)
                    if outcome in {"bound-setup-register-backup", "bound-setup-candidate-register"}:
                        os.utime(authority, ns=(original_metadata.st_atime_ns, original_metadata.st_mtime_ns))
                        assert api._dhcp_restore_leaf_state(authority) == api._dhcp_restore_leaf_state(
                            root / ("independent-original-" + authority.name))
                    break
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

    def replace_bound_dhcp(source, destination, *args, **kwargs):
        source, destination = Path(source), Path(destination)
        owned_b = source.parent == next(iter(live_dir.glob(".load-dhcp-transaction-*")), root) / "live-candidates"
        if owned_b and destination in mappings.values():
            private_destination(source)
            private_destination(destination)
            binding = json.loads(setup_wal.read_bytes())["body"]["dhcp_transaction"]
            inventory = binding["live_inventory"]
            if not installed_b:
                first_install_inventory.append(inventory)
                if require_staged_inventory:
                    assert 'staged_inventory' in binding, 'original four staged owners must be registered before first B rename'
                    staged_inventory = binding['staged_inventory']
                    assert set(staged_inventory) == {'directory', 'parent', 'leaves'}
                    staged = source.parent.parent / 'staged'
                    assert staged_inventory['directory'] == dict(path=str(staged),
                        identity=[getattr(staged.lstat(), field) for field in owner_fields])
                    assert staged_inventory['parent'] == dict(path=str(staged.parent), dev=staged.parent.lstat().st_dev, ino=staged.parent.lstat().st_ino)
                    assert set(staged_inventory['leaves']) == set(names)
                    for name in names:
                        original = staged / name
                        payload = expected_b[name]
                        if name == 'dhcpd.conf':
                            for included in names[1:]:
                                payload = payload.replace(('/etc/dhcp/' + included).encode(), str(staged / included).encode())
                        assert original.read_bytes() == payload
                        expected_leaf = dict(identity=[getattr(original.lstat(), field) for field in owner_fields],
                            state=dict(state='file', mode=0o644, uid=os.getuid(), gid=os.getgid(),
                                mtime_ns=original.lstat().st_mtime_ns, size=len(payload), sha256=hashlib.sha256(payload).hexdigest()))
                        assert staged_inventory['leaves'][name] == expected_leaf
                assert set(inventory) == {"directory", "restore_directory", "parent", "before", "after", "restore"}
                receipt = source.parent.parent / "a-preimage.json"
                assert binding["receipt"] == str(receipt)
                assert binding["sha256"] == hashlib.sha256(receipt.read_bytes()).hexdigest()
                assert binding["identity"] == [getattr(receipt.lstat(), field) for field in owner_fields]
                for name in names:
                    original = inventory["before"][name]
                    assert (None if original is None else original["identity"]) == initial_live_owners[name]
                    candidate_stage = Path(inventory["after"][name]["path"])
                    assert candidate_stage == source.parent / name
                    assert inventory["after"][name]["file"]["identity"] == [
                        getattr(candidate_stage.lstat(), field) for field in owner_fields]
                    assert candidate_stage.read_bytes() == expected_b[name]
                    assert stat.S_IMODE(candidate_stage.lstat().st_mode) == 0o644
                    restore = inventory["restore"][name]
                    if initial_live_owners[name] is None:
                        assert original is None and restore is None
                    else:
                        restore_path = Path(restore["path"])
                        assert restore_path == source.parent.parent / "restore-candidates" / name
                        assert restore["file"]["identity"] == [getattr(restore_path.lstat(), field) for field in owner_fields]
                        if a_shapes and name == "dhcpd_eth.hosts":
                            assert os.readlink(restore_path) == "../independent-original-A-source"
                            assert original["state"]["target"] == "../independent-original-A-source"
                        else:
                            assert restore_path.read_bytes() == expected_a[name]
                            assert original["state"]["sha256"] == hashlib.sha256(expected_a[name]).hexdigest()
                        assert restore["file"]["state"] == original["state"]
            row = inventory["after"][destination.name]
            assert row["path"] == str(source)
            assert row["file"]["identity"] == [getattr(source.lstat(), field) for field in (
                "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")]
            assert source.read_bytes() == expected_b[destination.name]
            backup = Path(binding["body"]["backup"]["path"])
            assert binding["backup_inventory"]["leaves"]["dhcpd.conf"] == [getattr((backup / "dhcpd.conf").lstat(), field)
                for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")]
        result = real_replace(source, destination, *args, **kwargs)
        if owned_b and destination in mappings.values():
            installed_b.append(destination)
            if outcome == "bound-setup-late-wal" and destination == live_dir / "dhcpd.conf" and not injected:
                replace_bound_authority(setup_wal)
            if outcome == "bound-setup-installed-b-owner" and destination == live_dir / "dhcpd.conf" and not injected:
                old = destination.lstat()
                replace_bound_authority(destination)
                os.utime(destination, ns=(old.st_atime_ns, old.st_mtime_ns))
            if (outcome == "bound-setup-kill-first" and destination == live_dir / "dhcpd.conf"
                    or outcome == "bound-setup-kill-last" and destination == live_dir / "dhcpd_nvl.hosts"):
                os.kill(os.getpid(), signal.SIGKILL)
        return result

    if outcome in {"precommit", "precommit-shapes", "bound-setup-precommit", "restore-return", "restore-raise",
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
                mock.patch.object(api, "_setup_switch_journal_path", return_value=wal_probe), \
                mock.patch.object(api.os, "open", side_effect=open_parent), \
                mock.patch.object(api.os, "replace", side_effect=replace_bound_dhcp), \
                mock.patch.object(api.os, "fsync", side_effect=sync_parent):
            try:
                kwargs = {} if setup_guard is None else {"setup_switch_guard": setup_guard}
                if publication_candidates is not None:
                    kwargs["setup_publication_token"] = publication_candidates[3]
                api.mount_and_test_dhcp(parent_candidate=candidate, **kwargs)
            except (api.LoadError, OSError) as exc:
                if outcome in {"open", "fsync"}:
                    assert "持久化" in str(exc) and "未确认" in str(exc), str(exc)
                elif outcome in {"precommit", "precommit-shapes", "bound-setup-precommit"}:
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
                elif outcome == "success-setup-wal-probe-error":
                    assert "cleanup cannot confirm SETUP WAL absence" in str(exc) and "HOLD" in str(exc), str(exc)
                elif outcome in binding_faults:
                    assert "HOLD" in str(exc) and ("WAL" in str(exc) or "receipt" in str(exc)
                        or "DHCP" in str(exc)), str(exc)
                else:
                    raise
            else:
                assert outcome in {"success", "backup-sync-success", "preimage-before-write", "success-setup-wal", "bound-setup-before-write"}, "failure must propagate before service continuation"
        transactions = list(live_dir.glob(".load-dhcp-transaction-*"))
        if outcome in binding_faults:
            assert injected == [outcome], injected
            transaction, = transactions
            assert not candidate.committed and not candidate.directory_synced
            assert not candidate.destination.exists()
            assert {p.name: p.read_bytes() for p in (transaction / "backup").iterdir()} == expected_a
            assert {name: (live_dir / name).read_bytes() for name in names} == {
                name: (expected_b[name] if outcome == "bound-setup-parent-wal" or (
                    outcome in {"bound-setup-late-wal", "bound-setup-installed-b-owner"}
                    and name == "dhcpd.conf") else expected_a[name])
                for name in names
            }
            assert installed_b == (list(mappings.values()) if outcome == "bound-setup-parent-wal" else
                                   [live_dir / "dhcpd.conf"] if outcome in {"bound-setup-late-wal", "bound-setup-installed-b-owner"} else [])
            assert not cleanup, "lost grouped authority must not trigger an eager A rollback or evidence deletion"
            return
        if outcome in {"bound-setup-before-write", "bound-setup-precommit"}:
            transaction, = transactions
            inventory, = first_install_inventory
            assert list((transaction / "live-candidates").iterdir()) == []
            if outcome == "bound-setup-precommit":
                assert list((transaction / "restore-candidates").iterdir()) == []
                for name in names:
                    restore = inventory["restore"][name]
                    if restore is None:
                        assert not os.path.lexists(live_dir / name)
                    else:
                        assert restore["file"]["identity"][:8] == [getattr((live_dir / name).lstat(), field)
                            for field in owner_fields[:8]], "rollback must consume the original registered A candidate"
            else:
                for name in names:
                    assert inventory["after"][name]["file"]["identity"][:8] == [getattr((live_dir / name).lstat(), field)
                        for field in owner_fields[:8]], "B must consume the original registered candidate"
                    restore = inventory["restore"][name]
                    if restore is not None:
                        assert restore["file"]["identity"] == [getattr(Path(restore["path"]).lstat(), field)
                            for field in owner_fields]
            if a_shapes:
                assert os.readlink(transaction / "backup/dhcpd_eth.hosts") == "../independent-original-A-source"
                assert not os.path.lexists(transaction / "backup/dhcpd_nvl.hosts")
                for name in ("dhcpd.conf", "dhcpd_ib.hosts"):
                    assert (transaction / "backup" / name).read_bytes() == expected_a[name]
            else:
                assert {p.name: p.read_bytes() for p in (transaction / "backup").iterdir()} == expected_a
            assert set(p.name for p in (transaction / "staged").iterdir()) == set(names)
            assert json.loads(setup_wal.read_bytes())["body"]["dhcp_transaction"]["receipt"] == str(transaction / "a-preimage.json")
            assert setup_wal.read_bytes() != setup_wal_bytes
            if a_shapes and outcome == "bound-setup-precommit":
                assert os.readlink(live_dir / "dhcpd_eth.hosts") == "../independent-original-A-source"
                assert not os.path.lexists(live_dir / "dhcpd_nvl.hosts")
                for name in ("dhcpd.conf", "dhcpd_ib.hosts"):
                    assert (live_dir / name).read_bytes() == expected_a[name]
            else:
                assert {name: (live_dir / name).read_bytes() for name in names} == (
                    expected_a if outcome == "bound-setup-precommit" else expected_b
                )
            assert candidate.committed == (outcome == "bound-setup-before-write")
            assert candidate.directory_synced == candidate.committed
            if not candidate.committed:
                assert not candidate.destination.exists()
            assert not any(path == transaction or transaction in path.parents for path in cleanup), \
                "even successful A rollback cannot retire a still-bound grouped obligation"
            return
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
        elif (outcome in {"success", "backup-sync-success", "preimage-before-write", "success-setup-wal",
                          "success-setup-wal-probe-error"} and setup_wal_bytes is not None):
            assert candidate.committed and candidate.directory_synced
            assert json.loads(candidate.destination.read_text()) == parent_payload
            assert installed == expected_b
            assert len(transactions) == 1, "parent-only success deleted A before whole LOAD B health acceptance"
            transaction, = transactions
            backup = transaction / "backup"
            assert stat.S_IMODE(backup.stat().st_mode) == 0o700
            assert {path.name: path.read_bytes() for path in backup.iterdir()} == expected_a
            assert {path.name for path in (transaction / "staged").iterdir()} == set(names)
            record = transaction / "a-preimage.json"
            assert stat.S_IMODE(record.stat().st_mode) == 0o600
            assert set(json.loads(record.read_bytes())["body"]["before"]) == set(names)
            assert not cleanup, "unresolved SETUP WAL must defer DHCP evidence deletion"
            assert setup_wal.read_bytes() == setup_wal_bytes
            if outcome != "success-setup-wal-probe-error":
                assert any("HOLD" in warning and "B" in warning for warning in warnings)
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


def assert_private_dhcp_preimage_disk_inspection(api, root: Path, project: Path, invalid=None) -> None:
    """Inspect only retained private evidence; never restore or start services."""
    live = root.resolve() / "private-etc-dhcp"
    transaction, = live.glob(".load-dhcp-transaction-*")
    receipt = transaction / "a-preimage.json"
    # Preserve the literal parent name supplied to the original preparation;
    # /var and /private/var aliases do not transfer pathname authority.
    parent = project / "99-output-ztp/current-release.json"
    names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
    if invalid in {"inventory", "escaped-runtime", "checksum"}:
        envelope = json.loads(receipt.read_bytes())
        if invalid == "inventory":
            del envelope["body"]["before"]["dhcpd_nvl.hosts"]
        elif invalid == "escaped-runtime":
            envelope["body"]["runtime"]["path"] = str(root.resolve() / "unknown-runtime")
        else:
            envelope["sha256"] = "0" * 64
        if invalid != "checksum":
            envelope["sha256"] = hashlib.sha256(json.dumps(
                envelope["body"], sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode()).hexdigest()
        receipt.write_text(json.dumps(envelope) + "\n")
    elif invalid == "backup":
        (transaction / "backup/dhcpd_ib.hosts").write_bytes(b"unaccepted A backup\n")
    elif invalid == "backup-extra":
        (transaction / "backup/unknown-operator-file").write_bytes(b"unknown retained bytes\n")
    elif invalid == "parent":
        parent.write_bytes(b"unaccepted parent state\n")
    elif invalid == "mode":
        receipt.chmod(0o644)
    observed = [live, transaction, transaction / "backup", receipt, parent]
    observed += [live / name for name in names] + [transaction / "backup" / name for name in names]
    if invalid == "backup-extra":
        observed.append(transaction / "backup/unknown-operator-file")

    def snapshot():
        return {str(path): ((path.lstat().st_dev, path.lstat().st_ino, path.lstat().st_mode,
                            path.lstat().st_uid, path.lstat().st_gid, path.lstat().st_nlink,
                            path.lstat().st_size, path.lstat().st_mtime_ns, path.lstat().st_ctime_ns),
                           path.read_bytes() if path.is_file() else None) for path in observed}

    before = snapshot()
    commands = []
    def forbidden(*args, **kwargs):
        commands.append(args)
        raise AssertionError("disk inspection attempted an external write/service command")
    with mock.patch.object(api, "run", side_effect=forbidden), \
            mock.patch.object(api, "_run_subprocess", side_effect=forbidden):
        if invalid:
            try:
                api.inspect_dhcp_a_preimage(transaction, runtime_directory=live, parent_destination=parent)
            except api.LoadError as exc:
                assert "HOLD" in str(exc), str(exc)
                expected_error = {"inventory": "four-file inventory", "escaped-runtime": "directory authority",
                                  "checksum": "checksum", "backup": "backup differs", "parent": "parent is neither",
                                  "mode": "receipt is not", "backup-extra": "backup inventory"}[invalid]
                assert expected_error in str(exc), str(exc)
            else:
                raise AssertionError("unknown disk preimage was accepted: " + invalid)
        else:
            result = api.inspect_dhcp_a_preimage(transaction, runtime_directory=live, parent_destination=parent)
            assert result["parent_visibility"] == "b-visible", "visibility is not confirmed durability"
            assert result["runtime_visibility"] == {name: "b" for name in names}
            assert set(result["body"]["before"]) == set(names)
            for name in names:
                row = result["body"]["before"][name]
                assert row["state"] == "file"
                assert row["sha256"] == hashlib.sha256(f"independent-A:{name}\n".encode()).hexdigest()
    assert not commands
    assert before == snapshot(), "inspection changed retained A/B/receipt/name authority"


def assert_private_dhcp_inspection_parent_rebind_hold(api, root: Path, project: Path) -> None:
    """A matching parent leaf cannot transfer its containing directory authority."""
    live = root.resolve() / "private-etc-dhcp"
    transaction, = live.glob(".load-dhcp-transaction-*")
    parent = project / "99-output-ztp/current-release.json"
    original_directory = parent.parent.lstat()
    original_leaf = parent.lstat()
    original_bytes = parent.read_bytes()
    retained = parent.parent.with_name("operator-retained-parent-directory")
    verifier = api._verify_dhcp_a_preimage_receipt
    injected = []
    commands = []

    def evidence_snapshot():
        paths = [live, transaction, transaction / "backup", transaction / "a-preimage.json", parent.parent, parent]
        paths += list((transaction / "backup").iterdir())
        paths += [live / leaf for leaf in ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")]
        paths += [retained]
        return {str(path): ((path.lstat().st_dev, path.lstat().st_ino, path.lstat().st_mode,
                            path.lstat().st_nlink, path.lstat().st_size,
                            path.lstat().st_mtime_ns, path.lstat().st_ctime_ns),
                           path.read_bytes() if path.is_file() else None) for path in paths}

    def replace_parent_after_leaf_verification(*args, **kwargs):
        verifier(*args, **kwargs)
        assert not injected, "injection must occur only at final receipt verification"
        parent.parent.rename(retained)
        parent.parent.mkdir()
        (retained / parent.name).rename(parent)
        injected.append(evidence_snapshot())

    def forbidden(*args, **kwargs):
        commands.append(args)
        raise AssertionError("read-only inspection attempted an external command")

    with mock.patch.object(api, "_verify_dhcp_a_preimage_receipt", side_effect=replace_parent_after_leaf_verification), \
            mock.patch.object(api, "run", side_effect=forbidden), \
            mock.patch.object(api, "_run_subprocess", side_effect=forbidden):
        try:
            api.inspect_dhcp_a_preimage(transaction, runtime_directory=live, parent_destination=parent)
        except api.LoadError as exc:
            assert "HOLD" in str(exc) and "authority changed" in str(exc), str(exc)
        else:
            raise AssertionError("DHCP disk inspection accepted a replaced parent directory")
    assert len(injected) == 1, "test did not reach the final directory authority boundary"
    assert commands == []
    assert evidence_snapshot() == injected[0], "inspection changed evidence after the injected replacement"
    assert retained.lstat().st_ino == original_directory.st_ino
    assert parent.parent.lstat().st_ino != original_directory.st_ino
    assert parent.lstat().st_ino == original_leaf.st_ino
    assert parent.read_bytes() == original_bytes


def assert_private_dhcp_cold_pending_hold(api, root: Path, project: Path, *, inspect_preimage=False,
                                        inspect_parent_rebind=False) -> None:
    """A fresh candidate has no memory of the first HOLD; disk evidence must fence it."""
    source, live = project / "independent-dhcp-B", root / "private-etc-dhcp"
    names = ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
    expected_b = {name: f"independent-B:{name}\n".encode() for name in names}
    expected_b["dhcpd.conf"] = b"# independent-B configuration\n" + b"".join(
        f'include "/etc/dhcp/{name}";\n'.encode() for name in names[1:]
    )
    transactions = list(live.glob(".load-dhcp-transaction-*"))
    assert len(transactions) == 1
    transaction, = transactions
    backup = transaction / "backup"
    identities = [(path, path.lstat()) for path in (transaction, backup)]
    if inspect_parent_rebind:
        assert_private_dhcp_inspection_parent_rebind_hold(api, root, project)
        return
    if inspect_preimage:
        assert_private_dhcp_preimage_disk_inspection(api, root, project)
    for name in names:
        (source / name).write_bytes(expected_b[name] + b"# independent-C input\n")
    candidate = api.prepare_current_release(
        project, {"schema_version": 1, "release_id": "independent-C"},
    )
    assert not candidate.committed and not candidate.directory_synced
    commands = []

    def forbidden(command, **kwargs):
        commands.append(command)
        raise AssertionError("new LOAD reached installer before pending evidence guard")

    try:
        with mock.patch.object(api, "dhcp_file_mappings", return_value={
            source / name: live / name for name in names
        }), mock.patch.object(api, "sudo_command", side_effect=lambda *args: list(args)), \
                mock.patch.object(api, "run", side_effect=forbidden), \
                mock.patch.object(api, "_run_subprocess", side_effect=forbidden):
            try:
                api.mount_and_test_dhcp(parent_candidate=candidate)
            except api.LoadError as exc:
                assert "pending DHCP transaction" in str(exc) and "HOLD" in str(exc), str(exc)
            else:
                raise AssertionError("fresh LOAD ignored retained DHCP transaction")
        assert commands == [], "pending disk evidence must reject before all commands"
        assert not candidate.committed and not candidate.directory_synced
        assert json.loads(candidate.destination.read_text()) == {
            "schema_version": 1, "release_id": "independent-B",
        }
        assert {name: (live / name).read_bytes() for name in names} == expected_b
        assert {p.name: p.read_bytes() for p in backup.iterdir()} == {
            name: f"independent-A:{name}\n".encode() for name in names
        }
        assert list(live.glob(".load-dhcp-transaction-*")) == transactions
        for path, before in identities:
            after = path.lstat()
            assert (before.st_dev, before.st_ino, before.st_mode,
                    before.st_mtime_ns, before.st_ctime_ns) == (
                after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns, after.st_ctime_ns,
            )
    finally:
        api.discard_prepared_release(candidate)


def private_publication_candidates(api, project, *, dhcp_candidate=None):
    """Independent four-input schema-2 fixture; no service/runtime commands."""
    project = project.resolve()
    sources = {"global": "01-global.yaml", "devices": "02-devices_config.csv",
               "subnet": "02-dhcp-subnet_config.csv", "p2p": "publication-p2p.xlsx"}
    selected_p2p = project / "p2p.xlsx"
    if selected_p2p.exists():
        sources["p2p"] = selected_p2p.resolve(strict=True).relative_to(project).as_posix()
    for key, relative in sources.items():
        path = project / relative
        if not path.exists():
            if key == "p2p":
                workbook = TOPOLOGY.openpyxl.Workbook()
                workbook.active.append(["independent publication workbook"])
                workbook.save(path)
                workbook.close()
            else:
                path.write_bytes(("independent publication " + key + "\n").encode())
    if not os.path.lexists(selected_p2p):
        selected_p2p.symlink_to(sources["p2p"])
    hashes = {key: hashlib.sha256((project / relative).read_bytes()).hexdigest()
              for key, relative in sources.items()}
    basis = dict(project=project.name, deployment_scope="all", switch_scope="all",
                 dhcp_status="disabled", inputs=hashes,
                 input_sources={"p2p": {"path": sources["p2p"], "sha256": hashes["p2p"]}},
                 components={}, inventory=[])
    if dhcp_candidate is not None:
        child_path = dhcp_candidate / "dhcp-release-manifest.json"
        child = json.loads(child_path.read_bytes())
        basis["dhcp_status"] = "enabled"
        basis["components"] = {"dhcp": {
            "release_id": child["release_id"], "manifest_sha256": sha256(child_path),
        }}
    release_id = hashlib.sha256(json.dumps(basis, sort_keys=True, ensure_ascii=False,
                                          separators=(",", ":")).encode()).hexdigest()[:20]
    parent = dict(basis, schema_version=2, release_id=release_id, validation="passed",
                  generated_at="2026-10-07T12:00:00+08:00", input_paths=sources)
    parent_candidate = api.prepare_current_release(project, parent, dhcp_candidate_dir=dhcp_candidate)
    generation = api.stage_pinned_generation(project, parent_candidate.temporary, dhcp_candidate)
    report = dict(schema_version=3, record_type="http-v3-public-key-generation-report",
                  project=project.name, release_id=release_id,
                  generated_at="2026-10-07T12:00:00+08:00", public_keys=[
                      dict(role="laptop", name="laptop.pub", algorithm="ssh-ed25519",
                           fingerprint="SHA256:MiTPEMIPDeIyBsV88xw/beaNZDfLZ3+t8BcYvmzNQqk"),
                      dict(role="management", name="mgmt-server.pub", algorithm="ssh-ed25519",
                           fingerprint="SHA256:I+cLpWGbiZDeDs5PZ1FV1vPBwzgMEST7Wjs4BUYKywU")])
    report_candidate = api.generation_report.prepare_generation_report(project, report)
    return parent_candidate, report_candidate, generation


@contextmanager
def private_a_health_ports(api, root, *, http_status=None, publication_prefix='r22-prefix'):
    """Private command/network ports, not Linux/root auth or daemon witnesses.

    Genuine preflight helpers still inspect helper bytes, boundary SHA, wire
    keys and publication files. Only OS command/host addresses are adapted.
    HTTP probes reach a real local server, never the declared external IP.
    """
    root = root.resolve()
    ports = Path(tempfile.mkdtemp(prefix="private-a-health-ports-", dir=root))
    helper = ports / "control-auth.py"
    helper.write_bytes((ROOT / "tools/control-auth.py").read_bytes())
    boundary = ports / "apache-ztp.conf"
    boundary.write_bytes((ROOT / "infra/docker/apache-ztp.conf").read_bytes())
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs): super().__init__(*args, directory=str(root), **kwargs)
        def log_message(self, *args): pass
        def do_HEAD(self):
            if http_status is None:
                return super().do_HEAD()
            self.send_response(http_status); self.end_headers()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    # Bound idle teardown latency without replacing real HEAD requests or any
    # production health, curl, cleanup or child deadline.
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    calls = []
    def command(argv, *, dry_run=False, **kwargs):
        assert not dry_run, "A qualification cannot be dry-run"
        argv = list(argv); calls.append(argv)
        if (argv == [str(helper), "validate"] or argv == ["apache2ctl", "configtest"]
                or argv == ["dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"]):
            return None  # Explicit OS command port; no real auth/daemon claim.
        if argv[:4] == ["curl", "-fsSI", "--max-time", "5"] and len(argv) == 5:
            url = urlsplit(argv[4])
            assert url.scheme == "http" and url.hostname == "192.0.2.2" and url.path.startswith('/' + publication_prefix + '/'), argv
            result = subprocess.run(argv[:4] + [f"http://127.0.0.1:{server.server_port}" + url.path],
                capture_output=True, text=True, timeout=8, check=False)
            if result.returncode: raise api.LoadError("private original A HTTP probe failed: " + result.stderr)
            return None
        raise AssertionError("unexpected host command: " + repr(argv))
    links = [{"ifindex": 2, "ifname": "eth-test", "flags": ["UP", "BROADCAST", "MULTICAST", "LOWER_UP"],
              "operstate": "UP", "link_type": "ether"}]
    addresses = [{"ifindex": 2, "ifname": "eth-test", "addr_info": [{"family": "inet",
        "local": "192.0.2.2", "prefixlen": 24, "scope": "global"}]}]
    try:
        with ExitStack() as stack:
            stack.enter_context(declared_linux_fdinfo_for_darwin_fixture(api))
            for name, value in (("CONTROL_AUTH_SOURCE", ROOT / "tools/control-auth.py"),
                                ("CONTROL_AUTH_CONTAINER_HELPER", helper),
                                ("APACHE_PUBLIC_BOUNDARY_CONF", boundary)):
                stack.enter_context(mock.patch.object(api, name, value))
            stack.enter_context(mock.patch.object(api, "run", side_effect=command))
            stack.enter_context(mock.patch.object(api, "sudo_command", side_effect=lambda *args: list(args)))
            stack.enter_context(mock.patch.object(api, "local_ipv4_addresses", return_value={"192.0.2.2"}))
            stack.enter_context(mock.patch.object(api, "_local_ipv4_assignments", return_value={"192.0.2.2": {("eth-test", 24)}}))
            stack.enter_context(mock.patch.object(api, "_local_ip_json_snapshots", return_value=(links, addresses)))
            yield calls
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
        assert not thread.is_alive(), "private HTTP thread did not stop"
