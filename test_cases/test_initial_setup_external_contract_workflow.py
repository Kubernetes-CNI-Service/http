#!/usr/bin/env python3
"""v3.1.3 WP-3 workflow: the merged initial-setup keeps its external library contract.

Two real repository callers load infiniband/bringup/xdr-initial-setup/initial-setup.py as a library:
ztp/config_sync_authority.py (the 12-ztp-monitor and managed entry) and tools/fleet_distribution.py
(the IB upgrade v2 P2P reader).  The test goes through each caller's own loader and its own objects.

Expected values come from the sources, never from the implementation under test:
- 开发计划 :255 「对外合同……签名不能变」, :314 「必须合并进来，签名不变」;
  v3.1.3 详细工作指导 1.3 第 2 行 and 表 3-3: the names the callers use, the four signatures
  (main(*, method_cycle=None); load_target_cache(..., input_snapshot=, _admission_out=);
  initial_method_input_digest and observe_managed_initial_configuration as the authority calls them)
  and one semantic (_neutral_services reads only the managed tool root's own file).
- config_sync_authority.py::ManagedInitialMethodCycle._neutral_image docstring: "The managed tool root is
  the only infra-neutral.conf source; no fallback lookup"; v3.1.2 指导 :1425.
- parse_p2p: the P2P fixture below is written by hand; the expected links are its rows.
- O5: library loading imports no tools/yaml module, adds nothing to sys.path and creates no file.
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path
import sys
import tempfile
import unittest

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
INITIAL_SOURCE = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
AUTHORITY = load_script("initial_external_contract_authority", ROOT / "ztp/config_sync_authority.py")
FLEET = load_script("initial_external_contract_fleet", ROOT / "tools/fleet_distribution.py")

# 表 3-3: names each caller reads from the loaded module.
FLEET_NAMES = ("clean", "IB_PORT_ALIASES", "names_match", "normalize_name", "parse_p2p", "Link")
MONITOR_NAMES = ("initial_method_input_digest", "observe_managed_initial_configuration",
                 "desired_service_commands", "key_install_command", "normalize_mac",
                 "load_target_cache", "_neutral_services")
MANAGED_NAMES = ("main", "SetupError", "REPORT_HANDLE")

LOCAL_CONF = "DNS=192.0.2.53\nNTP=ntp-local.example.test\nTIMEZONE=Etc/UTC\n"
ANCESTOR_CONF = "DNS=198.51.100.53\nNTP=ntp-ancestor.example.test\nTIMEZONE=Asia/Taipei\n"


class InitialSetupExternalContractWorkflowTests(unittest.TestCase):
    def fresh_fleet_module(self):
        """fleet_distribution caches the loaded module; give each test its own load."""
        name = "fleet_initial_setup_p2p"
        previous = sys.modules.pop(name, None)

        def restore():
            sys.modules.pop(name, None)
            if previous is not None:
                sys.modules[name] = previous
        self.addCleanup(restore)
        return FLEET._p2p_module()

    def test_monitor_loader_finds_every_name_with_unchanged_signatures(self):
        initial = AUTHORITY.load_initial_method_executor()
        self.assertEqual(INITIAL_SOURCE.resolve(), Path(initial.__file__).resolve())
        missing = [name for name in (*FLEET_NAMES, *MONITOR_NAMES, *MANAGED_NAMES) if not hasattr(initial, name)]
        self.assertEqual([], missing, "names used by config_sync_authority / fleet_distribution")
        parameters = inspect.signature(initial.main).parameters
        self.assertEqual(("method_cycle",), tuple(parameters))
        self.assertIs(inspect.Parameter.KEYWORD_ONLY, parameters["method_cycle"].kind)
        self.assertIsNone(parameters["method_cycle"].default)
        cache = inspect.signature(initial.load_target_cache)
        # config_sync_authority.py :215-216 and :330-331 call it exactly this way.
        cache.bind(Path("cache.json"), Path("ib.csv"), Path("p2p.xlsx"),
                   public_key_tool=Path("tool"), input_snapshot={})
        cache.bind(Path("cache.json"), Path("ib.csv"), Path("p2p.xlsx"), public_key_tool=Path("tool"),
                   validate_public_keys_with_ssh_keygen=True, allow_baked_missing_global=False,
                   _admission_out={})
        for keyword in ("input_snapshot", "_admission_out"):
            self.assertIsNone(cache.parameters[keyword].default)
        # :249 / :362 and :262 / :363-364 positional calls.
        inspect.signature(initial.initial_method_input_digest).bind(object(), {}, [])
        inspect.signature(initial.observe_managed_initial_configuration).bind(
            object(), "admin", Path("id_ed25519"), 10, {}, [])
        self.assertTrue(issubclass(initial.SetupError, Exception))

    def test_managed_neutral_image_and_parser_read_the_same_local_file(self):
        initial = AUTHORITY.load_initial_method_executor()
        with tempfile.TemporaryDirectory(prefix="initial-external-neutral-") as raw:
            project = Path(raw).resolve() / "project"
            tool = project / "infiniband/bringup/xdr-initial-setup"
            tool.mkdir(parents=True, mode=0o755)
            os.chmod(project, 0o755)
            (tool / "infra-neutral.conf").write_text(LOCAL_CONF, encoding="ascii")
            # A different valid conf where an ancestor lookup would find one first.
            (project / "infra").mkdir(mode=0o755)
            (project / "infra/infra-neutral.conf").write_text(ANCESTOR_CONF, encoding="ascii")
            (tool / "infra").mkdir(mode=0o755)
            (tool / "infra/infra-neutral.conf").write_text(ANCESTOR_CONF, encoding="ascii")
            cycle = AUTHORITY.ManagedInitialMethodCycle(project, initial)
            image = cycle._neutral_image()
            self.assertEqual(str((tool / "infra-neutral.conf").resolve()), image[0])
            self.assertEqual({"DNS": "192.0.2.53", "NTP": "ntp-local.example.test", "TIMEZONE": "Etc/UTC"},
                             initial._neutral_services(cycle.tool_input_root),
                             "the parser must read the same managed tool-root file the image binds")

    def test_fleet_distribution_parses_p2p_through_merged_file(self):
        module = self.fresh_fleet_module()
        self.assertEqual(INITIAL_SOURCE.resolve(), Path(module.__file__).resolve())
        with tempfile.TemporaryDirectory(prefix="initial-external-p2p-") as raw:
            p2p = Path(raw) / "p2p.csv"
            p2p.write_text(
                "SrcDevice,SrcPort,DstDevice,DstPort\n"
                "EXAMPLE-IB01,eth0,EXAMPLE-LEAF01,swp1\n"
                "EXAMPLE-LEAF01,swp2,EXAMPLE-IB02,mgmt\n"
                "EXAMPLE-IB01,ib1,EXAMPLE-IB02,ib1\n",
                encoding="ascii")
            links = module.parse_p2p(p2p)
        self.assertEqual(
            [("EXAMPLE-IB01", "eth0", "EXAMPLE-LEAF01", "swp1"),
             ("EXAMPLE-LEAF01", "swp2", "EXAMPLE-IB02", "mgmt"),
             ("EXAMPLE-IB01", "ib1", "EXAMPLE-IB02", "ib1")],
            [(link.left_device, link.left_port, link.right_device, link.right_port) for link in links])
        self.assertTrue(all(type(link) is module.Link for link in links))

    def test_library_load_has_no_side_effects(self):
        script_dir_before = sorted(path.name for path in INITIAL_SOURCE.parent.iterdir())
        path_before = list(sys.path)
        foreign_before = {name for name in sys.modules
                          if name == "yaml" or name == "tools" or name.startswith(("yaml.", "tools."))}
        previous_cwd = os.getcwd()
        with tempfile.TemporaryDirectory(prefix="initial-external-load-") as raw:
            os.chdir(raw)
            try:
                AUTHORITY.load_initial_method_executor()
                self.fresh_fleet_module()
                created = sorted(os.listdir(raw))
            finally:
                os.chdir(previous_cwd)
        foreign_after = {name for name in sys.modules
                         if name == "yaml" or name == "tools" or name.startswith(("yaml.", "tools."))}
        self.assertEqual([], created)
        self.assertEqual(path_before, sys.path)
        self.assertEqual(set(), foreign_after - foreign_before)
        self.assertEqual(script_dir_before, sorted(path.name for path in INITIAL_SOURCE.parent.iterdir()))


if __name__ == "__main__":
    unittest.main()
