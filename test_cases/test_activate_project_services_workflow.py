#!/usr/bin/env python3
"""R-016 AP-a (v3.1.1 WP-9a) workflow: resident services and project readers follow DAY0-Prepare/activate-project.

Every case runs two or more real production scripts against one synthetic HTTP root that the test builds in
setup's pointer layout (R-016 §2): two projects, DAY0-Prepare/activate-project, every row of the link
specification table with its canonical text (project_contract.pointer_link_specs, the table's own rule --
no literal rule here) and the four public-key directories with one link per key (§3.2).  The expected values
come from the design, never from the implementation:

- R-016 详细设计 v1.1 §5.1: project_contract.active_project_dir is the one way to name the active project; a
  run resolves it once and reads through the returned real path.
- §5.2 and §11 (v1.1): readers that took the parent directory of a resolved project file switch to the
  pointer; with 「02-devices_config.csv → 外部文件」 and 「ib.csv → p2p/x.csv」 they still name the right project.
  Class 1 readers require setup's canonical text; class 2 readers resolve the pointer first and check the real
  project directory.
- §6: the collection worker resolves the pointer once per cycle and that cycle uses only that project; without
  a pointer it skips the cycle with the status 「没有激活的项目」.  12-ztp-monitor checks the pointer every round
  and logs and exits when it names another project or is gone (Q3: owner 2026-11-03 「好的」); the next load
  starts it again.  The manual-ztp worker resolves once per request.
- owner 2026-11-04: cron.sh reads <type>/publickey/mgmt-server.pub.
- 问题文档 I-030: the AIR json link is resolved to its real file before the no-follow read; a project without
  an AIR json is skipped.

The last class runs the real setup (v3.1.1 WP-3: it creates the pointer, the canonical links and the per-key
links) and then the readers and the collector key preflight.
"""

from __future__ import annotations

import base64
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_collection_cycle_persistence import WORKER
from test_cases.test_collection_v2_emitter_contract import EMITTER
from test_cases.test_collector_inventory_pubkey import (
    _preflight_harness_source, preflight_values, run_preflight,
)
from tools.project_contract import (
    PUBLICKEY_DIRECTORIES, SETUP_COLLECTION_LINKS, pointer_link_specs, pointer_link_target,
)


ROOT = Path(__file__).resolve().parents[1]
MONITOR = load_script("activate_services_ztp_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
ISSUE_SYNC = load_script("activate_services_issue_tracker_sync", ROOT / "monitor/issue-tracker/issue-tracker-sync.py")
SWITCH_STATUS = load_script("activate_services_switch_status", ROOT / "monitor/issue-tracker/switch-status.py")
MANUAL_WORKER = load_script("activate_services_manual_ztp_worker", ROOT / "monitor/manual-ztp-worker.py")
MANUAL = load_script("activate_services_manual_ztp", ROOT / "ztp/manual-ztp.py")

PROJECT_P = "site-p"
PROJECT_Q = "site-q"
NO_ACTIVE_PROJECT = "没有激活的项目"
NETWORK_AREAS = ("ethernet", "infiniband", "nvlink")


def synthetic_key(seed: int, comment: str) -> str:
    """A valid synthetic OpenSSH Ed25519 public line; no private key exists."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " " + comment + "\n"


def release_document(project: Path, global_text: str) -> dict:
    """A current-release.json load_release_identity accepts (12-ztp-monitor, schema 1)."""
    payload = {
        "schema_version": 1, "project": project.name,
        "deployment_scope": "all", "switch_scope": "all",
        "inputs": {"global": hashlib.sha256(global_text.encode("utf-8")).hexdigest()},
        "input_sources": {"p2p": {"sha256": "0" * 64}},
        "components": {"dhcp": {"release_id": "legacy-dhcp", "manifest_sha256": "0" * 64}},
        "inventory": [],
        "generated_at": "2026-11-08T08:00:00+08:00",
        "validation": "passed",
    }
    basis = ("project", "deployment_scope", "switch_scope", "inputs", "input_sources", "components",
             "inventory")
    payload["release_id"] = hashlib.sha256(json.dumps(
        {key: payload[key] for key in basis}, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()[:20]
    return payload


class PointerTree:
    """A synthetic HTTP root in setup's pointer layout (R-016 §2, §3.2), built by the test itself."""

    GLOBAL = ("schema_version: 1\ncommon:\n  mgmt:\n    dhcp-server:\n      status: enabled\n"
              "timezone: Asia/Shanghai\n")

    def __init__(self, base: Path):
        self.root = base / "http"
        self.day0 = self.root / "DAY0-Prepare"
        self.projects = {name: self._project(name, seed)
                         for name, seed in ((PROJECT_P, 31), (PROJECT_Q, 47))}
        for path, text in pointer_link_specs():
            link = self.root / path
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(text)
        for directory in PUBLICKEY_DIRECTORIES:
            (self.root / directory).mkdir(parents=True, exist_ok=True)
            for key in ("laptop.pub", "mgmt-server.pub"):
                (self.root / directory / key).symlink_to(pointer_link_target(f"{directory}/{key}", key))
        (self.root / "ztp/.setup_manifest").write_text("# setup manifest (derived record, R-016 Q5)\n",
                                                       encoding="utf-8")
        self.point(PROJECT_P)

    def _project(self, name: str, seed: int) -> Path:
        project = self.day0 / name
        for directory in ("99-output-ztp", "99-output-p2p",
                          *(f"99-output-monitor/{network}/{output}"
                            for network, output in SETUP_COLLECTION_LINKS.values())):
            (project / directory).mkdir(parents=True, exist_ok=True)
        (project / "01-global.yaml").write_text(self.GLOBAL, encoding="utf-8")
        (project / "02-devices_config.csv").write_text(
            "hostname,type,eth0_ip\n"
            f"{name}-leaf,eth,192.0.2.10\n{name}-ib,ib,192.0.2.11\n{name}-nvl,nvl,192.0.2.12\n",
            encoding="utf-8")
        (project / "02-dhcp-subnet_config.csv").write_text("subnet,netmask\n192.0.2.0,255.255.255.0\n",
                                                           encoding="utf-8")
        (project / "laptop.pub").write_text(synthetic_key(seed, f"{name}-laptop"), encoding="ascii")
        (project / "mgmt-server.pub").write_text(synthetic_key(seed + 1, f"{name}-mgmt"), encoding="ascii")
        (project / "99-output-ztp/current-release.json").write_text(
            json.dumps(release_document(project, self.GLOBAL)) + "\n", encoding="utf-8")
        return project

    def real(self, name: str) -> Path:
        return Path(os.path.realpath(self.projects[name]))

    def point(self, name: str) -> None:
        """R-016 §4.2 第 4 步: a temporary link renamed over the pointer."""
        temporary = self.day0 / f".activate-project.{os.getpid()}.tmp"
        temporary.symlink_to(name)
        os.replace(temporary, self.day0 / "activate-project")

    def unpoint(self) -> None:
        (self.day0 / "activate-project").unlink()

    def link_inputs_outside(self, name: str) -> None:
        """R-016 §11 v1.1: 02-devices_config.csv -> an outside file, ib.csv -> p2p/x.csv."""
        project = self.projects[name]
        outside = self.root.parent / f"Work-{name}"
        outside.mkdir()
        devices = project / "02-devices_config.csv"
        devices.rename(outside / "devices.csv")
        devices.symlink_to(outside / "devices.csv")
        (project / "p2p").mkdir()
        (project / "p2p/x.csv").write_text(f"hostname,type,eth0_ip\n{name}-ib,ib,192.0.2.11\n", encoding="utf-8")
        (project / "ib.csv").symlink_to("p2p/x.csv")
        ib_link = self.root / "infiniband/ib.csv"   # R-016 §2: infiniband/ib.csv -> activate-project/ib.csv
        ib_link.unlink()
        ib_link.symlink_to(pointer_link_target("infiniband/ib.csv", "ib.csv"))

    def stage_collector_probes(self) -> None:
        """The real cron.sh public-key preflight at every published entrypoint (as in
        test_collector_inventory_pubkey)."""
        canonical = self.root / "ethernet/monitor/cron.sh"
        canonical.write_text(_preflight_harness_source(), encoding="utf-8")
        canonical.chmod(0o755)
        for area in NETWORK_AREAS[1:]:
            (self.root / area / "monitor/cron.sh").symlink_to("../../ethernet/monitor/cron.sh")


class ActivateProjectServicesWorkflowTests(unittest.TestCase):
    def tree(self) -> PointerTree:
        directory = tempfile.TemporaryDirectory(prefix="wp9a-services-")
        self.addCleanup(directory.cleanup)
        return PointerTree(Path(directory.name))

    @contextmanager
    def worker(self, tree: PointerTree, coordinator):
        status = tree.root / "monitor/status"
        status.mkdir(parents=True, exist_ok=True)
        with mock.patch.multiple(
            WORKER, HTTP_ROOT=tree.root, STATUS_DIR=status,
            STATUS_FILE=status / "switch-collection.status.json",
            YAML_BACKUP_STATUS_FILE=status / "yaml-backup.status.json",
            CONTINUOUS_STATUS_FILE=status / "continuous-collection.status.json",
            CONTINUOUS_BACKUP_STATUS_FILE=status / "continuous-backup.status.json",
            run_collection_cycle_coordinator=coordinator,
        ):
            yield status

    def test_worker_cycles_across_a_switch_each_use_one_project(self):
        tree = self.tree()
        cycles = []

        def coordinator(gate, *, artifact_bindings, timeout, lock_wait):
            cycles.append((gate.project, WORKER.project_inventory_targets(gate.project, gate.scope)))
            if len(cycles) == 1:
                tree.point(PROJECT_Q)   # the operator switches while this cycle runs
            return {"identity": {}, "outcomes": [], "summary": None}

        with self.worker(tree, coordinator):
            WORKER.collect("prod", 60, 0)
            WORKER.collect("prod", 60, 0)
        # R-016 §6: each cycle resolved the pointer once, at its start, and used only that project.
        self.assertEqual(
            [(str(tree.real(PROJECT_P)), (f"{PROJECT_P}-leaf", f"{PROJECT_P}-ib", f"{PROJECT_P}-nvl")),
             (str(tree.real(PROJECT_Q)), (f"{PROJECT_Q}-leaf", f"{PROJECT_Q}-ib", f"{PROJECT_Q}-nvl"))],
            cycles,
        )

    def test_worker_skips_a_cycle_without_a_pointer_and_resumes_after_setup(self):
        tree = self.tree()
        tree.unpoint()
        coordinator = mock.Mock(return_value={"identity": {}, "outcomes": [], "summary": None})
        with self.worker(tree, coordinator) as status:
            self.assertFalse(WORKER.collect("prod", 60, 0))
            collection = json.loads((status / "switch-collection.status.json").read_text(encoding="utf-8"))
            self.assertFalse(WORKER.run_yaml_backup("unused", "prod", 60, 0))
            backup = json.loads((status / "yaml-backup.status.json").read_text(encoding="utf-8"))
            coordinator.assert_not_called()
            tree.point(PROJECT_Q)
            WORKER.collect("prod", 60, 0)
        for document in (collection, backup):
            self.assertEqual(("skipped", NO_ACTIVE_PROJECT), (document["state"], document["reason"]))
        self.assertEqual(str(tree.real(PROJECT_Q)), coordinator.call_args.args[0].project)

    @contextmanager
    def live_monitor(self, tree: PointerTree, on_sleep):
        """The real 12-ztp-monitor main loop in load's live watch mode on the pointer tree."""
        project = tree.projects[PROJECT_P]
        args = MONITOR.parser().parse_args([str(project), "--watch", "7", "--scope", "prod"])
        parser = mock.Mock()
        parser.parse_args.return_value = args
        monitor_once = mock.Mock(side_effect=[project / "99-output-ztp/round-1",
                                              AssertionError("a round ran after the switch")])
        log = mock.Mock()
        with mock.patch.multiple(
            MONITOR,
            HERE=tree.day0, SETUP_MANIFEST=tree.root / "ztp/.setup_manifest",
            ACTIVE_INVENTORY=tree.root / "ztp/config/isc-dhcp-server/02-devices_config.csv",
            ACTIVE_AIR_JSON=tree.root / "ztp/config/isc-dhcp-server/p2p-air.json",
            ZTP_STATUS_DIR=tree.root / "ztp/status",
            parser=mock.Mock(return_value=parser),
            resolve_project=mock.Mock(return_value=project),
            load_completion_handoff_signatures=mock.Mock(return_value={}),
            monitor_control_state=mock.Mock(return_value="running"),
            monitor_once=monitor_once,
            read_report=mock.Mock(return_value={"project": PROJECT_P, "scope": "prod", "devices": []}),
            print_environment_summary=mock.Mock(),
            generate_monitor_html=mock.Mock(return_value=True),
            process_ready_completion_handoffs=mock.Mock(return_value=({}, {}, {})),
            controlled_sleep=mock.Mock(side_effect=on_sleep),
            remove_own_pid_file=mock.Mock(),
            log=log,
        ), mock.patch.object(MONITOR.signal, "signal"):
            yield monitor_once, log

    def test_monitor_exits_when_the_pointer_names_another_project_or_is_gone(self):
        state_name = ".ztp-monitor-watch-state.json"
        for change, expected in (("switch", f"activate-project 已指向其他项目：{PROJECT_Q}"),
                                 ("unsetup", NO_ACTIVE_PROJECT)):
            with self.subTest(change=change):
                tree = self.tree()
                with self.live_monitor(
                    tree, lambda _seconds: tree.point(PROJECT_Q) if change == "switch" else tree.unpoint(),
                ) as (monitor_once, log):
                    self.assertEqual(0, MONITOR.main([]))
                self.assertEqual(1, monitor_once.call_count, "no round after the pointer moved")
                messages = " ".join(str(call.args[0]) for call in log.call_args_list)
                self.assertIn(expected, messages)
                # The first round's state is P's; nothing was written into Q through ztp/status.
                first = json.loads((tree.projects[PROJECT_P] / "99-output-ztp" / state_name).read_text())
                self.assertEqual("healthy", first["state"])
                self.assertFalse((tree.projects[PROJECT_Q] / "99-output-ztp" / state_name).exists())

    def test_monitor_exit_clears_its_own_pid_record_and_leaves_the_new_project_untouched(self):
        # 第三轮审查 A2 (R-016 §5.1: a run resolves the pointer once and then uses the real project path; §6, Q3):
        # load records the monitor's PID through ztp/status while the pointer selects P.  When the pointer moves
        # -- to Q, gone after unsetup, or to Q while a round is running -- the monitor exits; its exit removes
        # P's PID record (a stale one makes every later stop_native_ztp_monitors fail closed), and nothing --
        # no lock, no watch state, no PID -- appears in Q's 99-output-ztp.  remove_own_pid_file is the real one.
        from tools.ztp_service_runtime import monitor_pid_lock, write_monitor_pid_record_locked

        state_name = ".ztp-monitor-watch-state.json"
        real_remove = MONITOR.remove_own_pid_file
        for change in ("switch", "unsetup", "switch during a round"):
            with self.subTest(change=change):
                tree = self.tree()
                own = tree.projects[PROJECT_P] / "99-output-ztp"
                new = tree.projects[PROJECT_Q] / "99-output-ztp"
                status = tree.root / "ztp/status"
                with monitor_pid_lock(status / "ztp-monitor.pid"):
                    write_monitor_pid_record_locked(status / "ztp-monitor.pid", os.getpid())
                self.assertTrue((own / "ztp-monitor.pid").is_file(), "fixture: load's record is P's")
                untouched = sorted(entry.name for entry in new.iterdir())
                move = tree.unpoint if change == "unsetup" else (lambda: tree.point(PROJECT_Q))
                with self.live_monitor(
                    tree, (lambda _seconds: None) if change == "switch during a round" else (lambda _seconds: move()),
                ) as (monitor_once, _log), mock.patch.object(MONITOR, "remove_own_pid_file", real_remove):
                    if change == "switch during a round":
                        def during_round(*_args):
                            if monitor_once.call_count > 1:
                                raise AssertionError("a round ran after the switch")
                            move()
                            return own / "round-1"

                        monitor_once.side_effect = during_round
                    self.assertEqual(0, MONITOR.main([]))
                self.assertFalse((own / "ztp-monitor.pid").exists(), "the exit removed P's own PID record")
                self.assertEqual(untouched, sorted(entry.name for entry in new.iterdir()))
                self.assertEqual("healthy", json.loads((own / state_name).read_text())["state"])

    def test_every_reader_names_the_pointer_project_not_where_a_linked_input_resolves(self):
        for fixture in ("plain", "inputs linked elsewhere"):
            with self.subTest(fixture=fixture):
                tree = self.tree()
                tree.stage_collector_probes()
                if fixture != "plain":
                    for name in (PROJECT_P, PROJECT_Q):
                        tree.link_inputs_outside(name)
                for active in (PROJECT_P, PROJECT_Q):
                    tree.point(active)
                    self.assert_readers_name(tree, active)
                tree.unpoint()
                self.assert_readers_find_no_project(tree)

    def readers(self, tree: PointerTree) -> ExitStack:
        stack = ExitStack()
        for module in (ISSUE_SYNC, SWITCH_STATUS, MANUAL_WORKER, MANUAL):
            stack.enter_context(mock.patch.object(module, "HTTP_ROOT", tree.root))
        return stack

    def assert_readers_name(self, tree: PointerTree, active: str) -> None:
        real = tree.real(active)
        with self.readers(tree):
            self.assertEqual(str(real), WORKER.active_project_identity(tree.root))          # gate (class 6)
            self.assertEqual(real, ISSUE_SYNC.project_directory(None))                     # class 6
            self.assertEqual(real, SWITCH_STATUS.project_directory(None))                  # class 6
            self.assertEqual(real, MANUAL_WORKER.active_project())                         # class 6
            self.assertEqual(real, Path(MANUAL.resolve_project(None)))                     # class 6
        for area in NETWORK_AREAS:                                                          # cron.sh
            completed = run_preflight(tree.root, area)
            self.assertEqual(0, completed.returncode, completed.stderr)
            key = (tree.projects[active] / "mgmt-server.pub").read_text(encoding="ascii").split()[:2]
            self.assertEqual(" ".join(key), preflight_values(completed)["SSH_KEY"])
        if (tree.projects[active] / "02-devices_config.csv").is_symlink():
            return   # the live monitor runs on the server, where tar/sync made every input a file (WP-11)
        with mock.patch.multiple(                                                           # class 1 and 5
            MONITOR, HERE=tree.day0, SETUP_MANIFEST=tree.root / "ztp/.setup_manifest",
            ACTIVE_INVENTORY=tree.root / "ztp/config/isc-dhcp-server/02-devices_config.csv",
            ZTP_STATUS_DIR=tree.root / "ztp/status",
        ):
            MONITOR.require_active_project(tree.projects[active])
            other = PROJECT_Q if active == PROJECT_P else PROJECT_P
            with self.assertRaisesRegex(ValueError, "active-project"):
                MONITOR.require_active_project(tree.projects[other])

    def assert_readers_find_no_project(self, tree: PointerTree) -> None:
        with self.readers(tree):
            with self.assertRaisesRegex(WORKER.NoActiveProjectError, NO_ACTIVE_PROJECT):
                WORKER.active_project_identity(tree.root)
            with self.assertRaisesRegex(ISSUE_SYNC.SyncError, "no active project"):
                ISSUE_SYNC.project_directory(None)
            with self.assertRaisesRegex(SWITCH_STATUS.InputError, "no active project"):
                SWITCH_STATUS.project_directory(None)
            self.assertIsNone(MANUAL_WORKER.active_project())
            with self.assertRaisesRegex(MANUAL.ManualZtpError, NO_ACTIVE_PROJECT):
                MANUAL.resolve_project(None)
        for area in NETWORK_AREAS:
            completed = run_preflight(tree.root, area)
            self.assertEqual(1, completed.returncode)
            self.assertIn("active project mgmt-server.pub is missing", completed.stderr)

    def test_collection_evidence_and_p2p_selection_walk_into_the_pointer_project(self):
        tree = self.tree()
        name = "20261108-0100.tar.gz"
        relative = f"infiniband/monitor/ib-info/{name}"
        for project in (PROJECT_P, PROJECT_Q):
            (tree.projects[project] / "99-output-monitor/infiniband/ib-info" / name).write_bytes(
                f"{project} archive".encode())
            workbook = tree.projects[project] / f"{project} P2P.xlsx"
            workbook.write_bytes(f"{project} workbook".encode())
            (tree.projects[project] / "p2p.xlsx").symlink_to(workbook.name)
        fixed = tree.root / "ztp/config/cumulus/template/P2P/p2p.xlsx"
        for active in (PROJECT_P, PROJECT_Q):
            tree.point(active)
            with mock.patch.object(EMITTER, "ROOT", tree.root), mock.patch.object(WORKER, "HTTP_ROOT", tree.root):
                self.assertEqual((relative, f"{active} archive".encode()),             # emitter (class 2)
                                 EMITTER.regular_member(tree.root / relative, "infiniband", "ib-info", ".tar.gz"))
                self.assertEqual(f"{active} archive".encode(),                         # worker (class 2)
                                 WORKER._collection_artifact_path(tree.root, relative).read_bytes())
                selected, stem, _binding = WORKER._collection_activity_selected_workbook(fixed)
            self.assertEqual((tree.real(active) / f"{active} P2P.xlsx", f"{active} P2P"),
                             (selected, stem))
        tree.unpoint()
        with mock.patch.object(WORKER, "HTTP_ROOT", tree.root):
            with self.assertRaisesRegex(ValueError, "no active project"):
                WORKER._collection_artifact_path(tree.root, relative)

    def test_air_json_link_is_read_through_its_real_file_and_skipped_when_absent(self):
        # I-030: P is an AIR project, Q is not (its link dangles).
        tree = self.tree()
        air = b'{"nodes":{}}\n'
        (tree.projects[PROJECT_P] / "99-output-p2p/p2p-air.json").write_bytes(air)
        helper = tree.root / "ztp/dynamic_air_inventory.py"
        shutil.copy2(ROOT / "ztp/dynamic_air_inventory.py", helper)
        leases = tree.root.parent / "dhcpd.leases"
        leases.write_text("", encoding="utf-8")
        inputs = tree.root.parent / "inputs"
        inputs.mkdir()
        inventory = inputs / "ethernet-air.csv"
        inventory.write_text("hostname,type,eth0_ip\nair-leaf,air,192.0.2.20\n", encoding="utf-8")
        snapshots = {}
        with mock.patch.object(WORKER, "HTTP_ROOT", tree.root), \
                mock.patch.dict("os.environ", {"DHCP_LEASES_FILE": str(leases)}), \
                mock.patch.multiple(MONITOR, ACTIVE_AIR_JSON=tree.root / "ztp/config/isc-dhcp-server/p2p-air.json"):
            for active in (PROJECT_P, PROJECT_Q):
                tree.point(active)
                snapshots[active] = (WORKER._collection_snapshot_runtime(
                    "ethernet/air", {"input_inventory": str(inventory)}), MONITOR.active_air_json(MONITOR.ACTIVE_AIR_JSON))
        worker_p, monitor_p = snapshots[PROJECT_P]
        self.assertNotIn("v2_unavailable", worker_p)
        self.assertEqual(hashlib.sha256(air).hexdigest(), worker_p["runtime_input_hashes"]["air_json"])
        self.assertEqual(tree.real(PROJECT_P) / "99-output-p2p/p2p-air.json", monitor_p)
        worker_q, monitor_q = snapshots[PROJECT_Q]
        self.assertEqual("resolver_unavailable", worker_q["v2_unavailable"])
        self.assertIsNone(monitor_q)

    def test_manual_ztp_finds_the_air_json_in_the_pointer_project_not_beside_a_linked_inventory(self):
        # 详细工作指导 WP-9 class 6 (handed over from WP-9c, P4) and 问题文档 I-031: manual-ztp's AIR json is the
        # project's fixed 99-output-p2p/p2p-air.json, found from the project the pointer names -- not from the
        # directory the inventory link resolves into (02-devices_config.csv -> an outside file, R-016 §11 v1.1).
        tree = self.tree()
        project = tree.projects[PROJECT_P]
        (project / "02-devices_config.csv").write_text(
            "hostname,type,template,eth0_ip,netmask,eth0_mac\n"
            "AIR-EXAMPLE-Leaf01,air,oob-leaf,192.0.2.10,24,02:00:00:00:00:10\n", encoding="utf-8")
        node = lambda mac: {"os": "cumulus-vx-5.16.4", "management_interfaces": {"eth0": {"mac_address": mac}}}
        (project / "99-output-p2p/p2p-air.json").write_text(json.dumps({"content": {"nodes": {
            "AIR-EXAMPLE-Leaf01": node("02:00:00:00:00:10"), "AIR-EXAMPLE-FW01": node("02:00:00:00:00:21"),
        }}}), encoding="utf-8")
        leases = tree.root.parent / "dhcpd.leases"
        leases.write_text("lease 192.0.2.21 {\n  binding state active;\n  hardware ethernet 02:00:00:00:00:21;\n  }\n",
                          encoding="utf-8")
        tree.link_inputs_outside(PROJECT_P)
        with mock.patch.object(MANUAL, "HTTP_ROOT", tree.root):
            selected = MANUAL.resolve_project(None)
            rows = MANUAL.read_devices(selected / "02-devices_config.csv", dhcp_leases=leases)
        self.assertEqual({"AIR-EXAMPLE-FW01": [("192.0.2.21", "eth0")]},
                         {row["hostname"]: row["candidates"] for row in rows if row.get("dynamic_dhcp")})

    def test_manual_ztp_worker_reads_one_project_for_the_whole_request(self):
        tree = self.tree()
        searched = []
        real_accepted = MANUAL_WORKER.accepted_result

        def accepted(trigger_id, **kwargs):
            searched.append(kwargs.get("project"))
            return real_accepted(trigger_id, **kwargs)

        def switch_during_the_command(*_args, **_kwargs):
            tree.point(PROJECT_Q)
            return subprocess.CompletedProcess(["manual-ztp"], 0, stdout="accepted\n", stderr="")

        with mock.patch.object(MANUAL_WORKER, "HTTP_ROOT", tree.root), \
                mock.patch.object(MANUAL_WORKER, "write_device_status"), \
                mock.patch.object(MANUAL_WORKER, "latest_device_state", return_value=None), \
                mock.patch.object(MANUAL_WORKER, "command_for", return_value=["manual-ztp"]), \
                mock.patch.object(MANUAL_WORKER.subprocess, "run", side_effect=switch_during_the_command), \
                mock.patch.object(MANUAL_WORKER, "accepted_result", side_effect=accepted):
            MANUAL_WORKER.execute("site-p-leaf", "prod", 30, 30, 1, operation_id="op-1", trigger_id="trigger-1")
        # R-016 §6: the request started under P; its result is looked up in P although Q is active now.
        self.assertEqual([tree.real(PROJECT_P)], searched)


class SetupActivatesServicesWorkflowTests(unittest.TestCase):
    """Real setup subprocesses (v3.1.1 WP-3 creates DAY0-Prepare/activate-project, the canonical links and the
    per-key public-key links), then the reader and the collector key preflight follow each switch."""

    def test_setup_switch_moves_every_reader_and_the_collector_key(self):
        from test_cases import test_project_link_inputs_workflow as LINKS

        directory = tempfile.TemporaryDirectory(prefix="wp9a-setup-")
        self.addCleanup(directory.cleanup)
        sandbox = LINKS.LinkedProjectSandbox(Path(directory.name).resolve())
        (sandbox.project / "02-devices_config.csv").write_bytes(sandbox.devices)
        LINKS.workbook(sandbox.project / "Site P2P_v1.0.xlsx", "selected")
        other = sandbox.project.parent / "site-q"
        shutil.copytree(sandbox.project, other, symlinks=True)
        for project, seed in ((sandbox.project, 61), (other, 67)):
            (project / "mgmt-server.pub").write_text(synthetic_key(seed, f"{project.name}-mgmt"), encoding="ascii")
        probe = sandbox.http / "ethernet/monitor/wp9a-key-probe.sh"
        probe.write_text(_preflight_harness_source(), encoding="utf-8")
        probe.chmod(0o755)
        for project in (sandbox.project, other):
            completed = sandbox.run([
                sys.executable, "-B", os.fspath(sandbox.http / "DAY0-Prepare/01-a-setup.py"),
                "-y", "--host-role=workstation", "--no-upgrade", os.fspath(project),
            ])
            self.assertEqual(0, completed.returncode, completed.stdout)
            with self.subTest(project=project.name):
                pointer = sandbox.http / "DAY0-Prepare/activate-project"
                self.assertTrue(pointer.is_symlink(), "R-016 §4.2: setup activates the project with the pointer")
                self.assertEqual(project.name, os.readlink(pointer))
                self.assertEqual(str(Path(os.path.realpath(project))), WORKER.active_project_identity(sandbox.http))
                key = subprocess.run(["bash", os.fspath(probe)], capture_output=True, text=True, timeout=10,
                                     check=False)
                self.assertEqual(0, key.returncode, key.stderr)
                self.assertEqual(" ".join((project / "mgmt-server.pub").read_text(encoding="ascii").split()[:2]),
                                 preflight_values(key)["SSH_KEY"])


if __name__ == "__main__":
    unittest.main()
