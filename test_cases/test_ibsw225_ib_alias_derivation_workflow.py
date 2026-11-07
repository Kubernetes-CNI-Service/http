"""Handwritten IB alias producer/derived-consumer contracts; SOURCE only.

This exercises real narrow setup alias helpers, not public setup/unsetup,
receipt publication, activation transactions, or a live managed IB reader.
"""
import ast
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
GLOBAL_NAME = "infiniband/bringup/xdr-upgrade/01-global.yaml"
CSV_NAME = "infiniband/bringup/xdr-upgrade/ib.csv"
GLOBAL_MAPPING = (GLOBAL_NAME, "01-global.yaml", "file")
OLD_WORKSPACE = {
    ("infra/01-global.yaml", "01-global.yaml", "file"),
    ("infra/02-devices_config.csv", "02-devices_config.csv", "file_csv"),
    ("infra/logs", "99-output-infra", "dir"),
    ("monitor/01-global.yaml", "01-global.yaml", "file"),
    ("infiniband/01-global.yaml", "01-global.yaml", "file"),
}
NETWORK_CSV = (
    ("ethernet/eth.csv", "02-devices_config.csv"),
    # R-016 §10.2 decision E (owner 2026-11-04「按照默认处理」; v3.1.1 WP-12, O4 左列): the project's ib.csv.
    ("infiniband/ib.csv", "ib.csv"),
    ("nvlink/nvsw.csv", "02-devices_config.csv"),
)
INVENTORY_LINKS = (
    ("ethernet/monitor/eth.csv", "ethernet/eth.csv"),
    ("infiniband/monitor/ib.csv", "infiniband/ib.csv"),
    ("nvlink/monitor/nvsw.csv", "nvlink/nvsw.csv"),
    (CSV_NAME, "infiniband/ib.csv"),
)
# R-016 §2 (O4 左列): project links name DAY0-Prepare/activate-project; aliases keep their text.
GLOBAL_TARGET = "../../../DAY0-Prepare/activate-project/01-global.yaml"
TOP_CSV_TARGET = "../DAY0-Prepare/activate-project/ib.csv"  # decision E (owner 2026-11-04), WP-12
LOCAL_CSV_TARGET = "../../ib.csv"


class IbAliasProducerDerivationTests(unittest.TestCase):
    def test_literal_producer_registries_precede_all_eager_derived_consumers(self):
        contract = load_script("ibsw_alias_contract_direct", ROOT / "tools/project_contract.py")
        self.assertTrue(OLD_WORKSPACE.issubset(set(contract.SETUP_WORKSPACE_INPUT_MAPPINGS)))
        self.assertIn(GLOBAL_MAPPING, contract.SETUP_WORKSPACE_INPUT_MAPPINGS)
        self.assertEqual(tuple(contract.NETWORK_CSV_MAPPINGS), NETWORK_CSV)
        self.assertEqual(tuple(contract.NETWORK_INVENTORY_LINKS), INVENTORY_LINKS)
        runtime = dict(contract.pointer_link_specs())
        self.assertEqual(runtime.get(GLOBAL_NAME), GLOBAL_TARGET)
        self.assertEqual(runtime.get(CSV_NAME), LOCAL_CSV_TARGET)
        self.assertEqual(runtime.get("infiniband/ib.csv"), TOP_CSV_TARGET)
        self.assertIn(GLOBAL_NAME, contract.IMAGE_HOST_STATE_PATHS)
        self.assertIn(CSV_NAME, contract.IMAGE_HOST_STATE_PATHS)
        self.assertIn("infiniband/bringup", contract.IMAGE_HOST_STATE_SUBTREES)
        published = {name: (target, source)
                     for name, target, source in contract.published_runtime_link_specs()}
        self.assertEqual(published.get(CSV_NAME), (LOCAL_CSV_TARGET, "ib.csv"))
        self.assertNotIn(GLOBAL_NAME, published, "nonmonitor workspace global is NOT implicitly published")
        tree = ast.parse((ROOT / "tools/project_contract.py").read_text())
        positions = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        positions.setdefault(target.id, []).append(node.lineno)
        for name in ("SETUP_WORKSPACE_INPUT_MAPPINGS", "NETWORK_INVENTORY_LINKS", "IMAGE_HOST_STATE_PATHS"):
            self.assertEqual(len(positions.get(name, [])), 1, "do not repair producers with EOF reassignment")
        self.assertLess(positions["SETUP_WORKSPACE_INPUT_MAPPINGS"][0], positions["IMAGE_HOST_STATE_PATHS"][0])
        self.assertLess(positions["NETWORK_INVENTORY_LINKS"][0], positions["IMAGE_HOST_STATE_PATHS"][0])

    def test_real_setup_alias_helpers_feed_runtime_and_activation_consumers(self):
        contract = load_script("ibsw_alias_contract_workflow", ROOT / "tools/project_contract.py")
        setup = load_script("ibsw_alias_actual_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
        with tempfile.TemporaryDirectory(prefix="ibsw-alias-derived-") as folder:
            workspace = Path(folder).resolve()
            project = workspace / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            global_bytes = b"schema_version: 2\nproject: synthetic-alias-only\n"
            csv_bytes = b"hostname,type\nsynthetic-ib,ib\n"
            (project / "01-global.yaml").write_bytes(global_bytes)
            (project / "02-devices_config.csv").write_bytes(csv_bytes)
            # The template's default ib.csv -> 02-devices_config.csv (R-016 §3.3, decision E).
            (project / "ib.csv").symlink_to("02-devices_config.csv")
            # Setup's switch step selects the project; these producers only write the links (R-016 §4.2).
            (workspace / "DAY0-Prepare/activate-project").symlink_to("site-a")
            # Relocate actual fixed producer names, not producer results.
            net_paths = [(str(workspace / name), target)
                         for name, target in setup.NETWORK_CSV_MAPPINGS]
            with patch.multiple(setup, HTTP_BASE=str(workspace), HERE=str(workspace),
                                ZTP=str(workspace / "ztp"), _DRY_RUN=False,
                                _LINK_ERRORS=0, _NET_CSV_LINKS=net_paths), redirect_stdout(io.StringIO()):
                # The reconcile engine writes the table rows (WP-3 §2.7: _process_mapping and
                # _process_net_csv_links are gone).
                setup._reconcile_links([(str(workspace / row.path), setup._spec_link_text(row))
                                        for row in setup.SETUP_LINK_SPECS
                                        if row.path == GLOBAL_NAME or row.view == "network-csv"])
                for name, target in setup._monitor_inventory_link_pairs():
                    setup._make_exact_link(name, target)
                self.assertEqual(setup._LINK_ERRORS, 0)
            # Literal lexical text and original bytes, not resolve-only ownership.
            self.assertTrue((workspace / GLOBAL_NAME).is_symlink(), "real producer missed IB global alias")
            self.assertEqual(os.readlink(workspace / GLOBAL_NAME),
                             "../../../DAY0-Prepare/activate-project/01-global.yaml")
            self.assertEqual(os.readlink(workspace / "infiniband/ib.csv"),
                             "../DAY0-Prepare/activate-project/ib.csv")
            self.assertTrue((workspace / CSV_NAME).is_symlink(), "real producer missed local CSV alias")
            self.assertEqual(os.readlink(workspace / CSV_NAME), LOCAL_CSV_TARGET)
            self.assertEqual((workspace / GLOBAL_NAME).read_bytes(), global_bytes)
            self.assertEqual((workspace / CSV_NAME).read_bytes(), csv_bytes)
            self.assertEqual((project / "01-global.yaml").read_bytes(), global_bytes)
            self.assertEqual((project / "02-devices_config.csv").read_bytes(), csv_bytes)
            runtime = dict(contract.pointer_link_specs())
            self.assertEqual(runtime.get(GLOBAL_NAME), GLOBAL_TARGET)
            self.assertEqual(runtime.get(CSV_NAME), LOCAL_CSV_TARGET)
            self.assertIn(GLOBAL_NAME, contract.IMAGE_HOST_STATE_PATHS)
            self.assertIn(CSV_NAME, contract.IMAGE_HOST_STATE_PATHS)
            self.assertTrue(contract.is_image_host_state_path(GLOBAL_NAME))
            self.assertTrue(contract.is_image_host_state_path(CSV_NAME))
            activate = load_script("ibsw_alias_actual_activate_consumer",
                                   ROOT / "infra/docker/activate.py")
            self.assertEqual(Path(activate.hostlock.__file__).resolve(),
                             ROOT / "infra/docker/hostlock.py")
            self.assertEqual(Path(activate.published_runtime_link_specs.__globals__["__file__"]).resolve(),
                             ROOT / "tools/project_contract.py")
            published = {str(name): (target, str(source))
                         for name, target, source in activate.PUBLISHED_RUNTIME_LINKS}
            self.assertEqual(published.get(CSV_NAME), (LOCAL_CSV_TARGET, "ib.csv"))
            self.assertNotIn(GLOBAL_NAME, published)
            for name, target in INVENTORY_LINKS[:3]:
                self.assertTrue((workspace / name).is_symlink())
                self.assertEqual((workspace / name).read_bytes(), csv_bytes)

    def test_unsetup_fallback_literal_inventory_keeps_both_upgrade_aliases(self):
        # Direct path inventory only: no public unsetup/cron/PID or cleanup claim.
        # Contract changed by G12 and O14 (v3.1.1 WP-6; O4 right column, owner 2026-11-07 「同意你的建议。」 via
        # http dev): the fallback is the table's dynamic links plus the legacy names.  Both upgrade aliases are
        # fixed table rows, so unsetup keeps them (Q7) and they are never fallback candidates.
        unsetup = load_script("ibsw_alias_fallback_inventory", ROOT / "DAY0-Prepare/02-unsetup.py")
        contract = load_script("ibsw_alias_fallback_contract", ROOT / "tools/project_contract.py")
        aliases = {GLOBAL_NAME, CSV_NAME}
        self.assertLessEqual(aliases, {row.path for row in contract.SETUP_LINK_SPECS})
        legacy = {"ztp/config/nvos/template/" + name for name in ("99-output-ib", "99-output-nvl", "99-output-published")}
        legacy.add("ztp/config/cumulus/template/AIR/output-p2p")
        legacy.add("monitor/99-output-ufm")  # the fifth legacy name: WP-8 待决 1, settled by http dev 2026-11-08
        dynamic = {pattern.replace("*-sample/*", "site-a-sample/01-global.yaml").replace("*", "laptop")
                   for pattern in contract.setup_dynamic_link_patterns()}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in sorted(aliases | legacy | dynamic):
                (base / name).parent.mkdir(parents=True, exist_ok=True)
                (base / name).symlink_to("synthetic-target")
            with patch.object(unsetup, "HTTP_BASE", str(base)), patch.object(unsetup, "ZTP", str(base / "ztp")):
                found = {os.path.relpath(path, base)
                         for path in (*unsetup._known_ztp_project_links(), *unsetup._known_workspace_links())}
        self.assertEqual(legacy | dynamic, found)
        self.assertEqual(set(), aliases & found)
