"""Self-contained neutral authority: tests first; no actor/native admission.

Production code is copied exactly. Only own PUBLIC data/config trees are made.
C2 is a development-side real reader, not a production bundle dependency.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
C2 = ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py"
BUNDLE_NEUTRAL = b"DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n"
LOCAL_PUBLIC = b"DNS=192.0.2.53\nNTP=time.bundle.example.test\nTIMEZONE=Etc/UTC\n"
ANCESTOR_POISON = b"DNS=198.51.100.53\nNTP=time.poison.example.test\nTIMEZONE=Asia/Taipei\n"
EXPECTED_FALLBACK = {"dns": ["8.8.8.8"], "ntp": ["ntp.ubuntu.com"], "timezone": "Etc/UTC"}
EXPECTED_EXPLICIT = {
    "dns": ["203.0.113.53"], "ntp": ["time.explicit.example.test"], "timezone": "Asia/Taipei",
}
PUBLIC_CSV = (
    "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
    "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:17,,,\n"
    "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n"
)
PUBLIC_P2P = '"EXAMPLE-IB01":"eth0" -- "EXAMPLE-JUMP01":"7";\n'
# Table 6-1 row 6 (guide :749): a v15 cache-version-5 target record carries login_interface
# (v15 CURRENT-CONTRACT.md:20); both rows log in through their CSV eth0 address (RUNBOOK.md:22).
EXPECTED_TARGETS = [{
    "ib": {"hostname": "EXAMPLE-IB01", "dev_type": "ib", "login_ip": "203.0.113.2",
           "eth0_prefix": "203.0.113.2/24", "eth0_gateway": "203.0.113.1",
           "eth0_mac": "02:00:00:00:00:17", "eth1_prefix": "", "eth1_gateway": "",
           "login_interface": "eth0"},
    "ethernet": {"hostname": "EXAMPLE-JUMP01", "dev_type": "eth_jump", "login_ip": "192.0.2.10",
                 "eth0_prefix": "192.0.2.10", "eth0_gateway": "", "eth0_mac": "",
                 "eth1_prefix": "", "eth1_gateway": "", "login_interface": "eth0"},
    "ethernet_port": "swp7", "ib_port_alias": "eth0",
}]


def public_global(explicit):
    # Independently authored PUBLIC documents; no credential or native hash.
    system = (
        "      dns:\n        server:\n        - 203.0.113.53\n"
        "      ntp:\n        server:\n        - time.explicit.example.test\n"
        "      date-time:\n        timezone: Asia/Taipei\n"
        if explicit else
        "      dns:\n        server: []\n"
        "      ntp:\n        server: []\n"
        '      date-time:\n        timezone: ""\n'
    )
    return ("schema_version: 2\ncommon:\n  switch:\n    system:\n"
            "      date-time:\n        timezone: Etc/UTC\nswitches:\n- ib:\n    system:\n") + system


class _NeutralFixture:
    def fixture(self, folder, *, explicit=False, local=LOCAL_PUBLIC, global_present=True):
        root = Path(folder)
        tool = root / "relocated/nested/bundle"
        tool.mkdir(parents=True)
        day0 = root / "DAY0-Prepare"
        day0.mkdir()
        cwd = root / "unrelated-cwd"
        cwd.mkdir()
        poison = root / "infra/infra-neutral.conf"
        poison.parent.mkdir()
        poison.write_bytes(ANCESTOR_POISON)
        source = tool / "initial-setup.py"
        source_bytes = INITIAL.read_bytes()
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        # r508 WP4 requires the real three-file Leaf layout for every run,
        # including generation. Neutral authority and its independent oracles stay local.
        (tool / "tools").mkdir()
        for name in ("login_path", "hostname_ranges", "device_identity"):
            (tool / "tools" / (name + ".py")).write_bytes(
                (ROOT / "tools" / (name + ".py")).read_bytes())
        if local is not None:
            (tool / "infra-neutral.conf").write_bytes(local)
        (day0 / "ib.csv").write_text(PUBLIC_CSV, encoding="ascii")
        (day0 / "p2p.dot").write_text(PUBLIC_P2P, encoding="ascii")
        qualification = root / "management-inputs"
        qualification.mkdir()
        (qualification / "02-devices_config.csv").write_text(PUBLIC_CSV, encoding="ascii")
        if global_present:
            (day0 / "01-global.yaml").write_text(public_global(explicit), encoding="ascii")
        for name in ("ib.csv", "p2p.dot", "01-global.yaml"):
            if name != "01-global.yaml" or global_present:
                (tool / name).symlink_to(os.path.relpath(day0 / name, tool))
        app = load_script("neutral_bundle_" + root.name.replace("-", "_"), source)
        actual_profile = app._service_profile
        actual_neutral = app._neutral_services
        actual_read_text = Path.read_text
        profile_records = []
        def qualified_profile(tool_argument):
            neutral_calls, neutral_paths = [], []
            def neutral(value):
                neutral_calls.append(value)
                return actual_neutral(value)
            def read_text(path, *args, **kwargs):
                if path.name == "infra-neutral.conf":
                    neutral_paths.append(path)
                return actual_read_text(path, *args, **kwargs)
            failure = None
            result = None
            with mock.patch.object(app, "_neutral_services", new=neutral), \
                 mock.patch.object(Path, "read_text", new=read_text):
                try:
                    result = actual_profile(tool_argument)
                except app.SetupError as error:
                    failure = error
            profile_records.append((tuple(neutral_calls), tuple(neutral_paths)))
            self.assertEqual([tool] if global_present else [], neutral_calls)
            self.assertEqual([tool / "infra-neutral.conf"] if global_present else [], neutral_paths)
            if failure is not None:
                raise failure
            return result
        app._service_profile = qualified_profile
        return dict(root=root, tool=tool, day0=day0, cwd=cwd, poison=poison,
                    qualification=qualification,
                    profile_records=profile_records,
                    source=source, source_bytes=source_bytes, app=app)

    def assert_inputs_unchanged(self, f, before):
        for name, expected in before.items():
            self.assertEqual(expected, (f["day0"] / name).read_bytes())
            link = f["tool"] / name
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.path.relpath(f["day0"] / name, f["tool"]), os.readlink(link))
        self.assertEqual(ANCESTOR_POISON, f["poison"].read_bytes())
        self.assertEqual(f["source_bytes"], f["source"].read_bytes())

    def before(self, f):
        return {p.name: p.read_bytes() for p in f["day0"].iterdir()}

class SelfContainedNeutralAuthorityTests(_NeutralFixture, unittest.TestCase):
    def test_plain_nested_management_without_inventory_authority_refuses_before_output(self):
        with tempfile.TemporaryDirectory(prefix="neutral-plain-management-") as directory:
            f = self.fixture(directory)
            before = self.before(f)
            app = f["app"]
            argv = [str(f["source"]), "--generate-json", "--execution-mode", "management",
                "--ib-csv", str(f["day0"] / "ib.csv"), "--p2p", str(f["day0"] / "p2p.dot"),
                "--target-cache", str(f["root"] / "out/targets.json"),
                "--report", str(f["root"] / "out/report.log")]
            with ExitStack() as scope:
                scope.enter_context(mock.patch.dict(sys.modules))
                for name in list(sys.modules):
                    if name == "tools" or name.startswith("tools."):
                        del sys.modules[name]
                scope.enter_context(mock.patch.object(sys, "path", [str(f["tool"]), *sys.path]))
                scope.enter_context(mock.patch.object(sys, "argv", argv))
                profile = scope.enter_context(mock.patch.object(app, "_service_profile"))
                sessions = scope.enter_context(mock.patch.object(app, "_new_jump_sessions"))
                scope.enter_context(mock.patch.object(app.subprocess, "Popen", side_effect=AssertionError("no child")))
                scope.enter_context(mock.patch.object(app, "interactive_run", side_effect=AssertionError("no transport")))
                with self.assertRaisesRegex(app.SetupError, "repository inventory master is unavailable.*use --project-dir"):
                    app.main()
                profile.assert_not_called()
                sessions.assert_not_called()
            self.assertFalse((f["root"] / "out").exists())
            self.assert_inputs_unchanged(f, before)

    def test_local_authority_and_fallback_ignore_valid_ancestor_poison(self):
        with tempfile.TemporaryDirectory(prefix="neutral-direct-local-") as directory:
            f = self.fixture(directory)
            before = self.before(f)
            self.assertEqual({"DNS": "192.0.2.53", "NTP": "time.bundle.example.test",
                              "TIMEZONE": "Etc/UTC"}, f["app"]._neutral_services(f["tool"]))
            self.assertEqual({"dns": ["192.0.2.53"], "ntp": ["time.bundle.example.test"],
                              "timezone": "Etc/UTC"}, f["app"]._service_profile(f["tool"]))
            self.assert_inputs_unchanged(f, before)

    def test_missing_local_does_not_borrow_ancestor_even_with_explicit_services(self):
        with tempfile.TemporaryDirectory(prefix="neutral-direct-missing-") as directory:
            f = self.fixture(directory, explicit=True, local=None)
            before = self.before(f)
            with self.assertRaises(f["app"].SetupError) as caught:
                f["app"]._service_profile(f["tool"])
            self.assertEqual(("neutral service authority unavailable: " +
                              str(f["tool"] / "infra-neutral.conf"),), caught.exception.args)
            self.assertFalse((f["tool"] / "infra-neutral.conf").exists())
            self.assert_inputs_unchanged(f, before)

    def test_explicit_services_still_require_complete_valid_local_authority(self):
        invalid = (
            b"DNS=192.0.2.53\nNTP=time.bundle.example.test\n",
            b"DNS=192.0.2.53\nDNS=203.0.113.53\nNTP=time.bundle.example.test\nTIMEZONE=Etc/UTC\n",
            b"DNS=192.0.2.53\nNTP=time.bundle.example.test\nTIMEZONE=Etc/UTC\nOTHER=PUBLIC\n",
        )
        reasons = (
            "infra-neutral.conf lacks a service fallback",
            "infra-neutral.conf has invalid or duplicate service entry",
            "infra-neutral.conf has invalid or duplicate service entry",
        )
        for number, raw in enumerate(invalid):
            with self.subTest(case=number), tempfile.TemporaryDirectory(prefix="neutral-direct-invalid-") as directory:
                f = self.fixture(directory, explicit=True, local=raw)
                before = self.before(f)
                with self.assertRaises(f["app"].SetupError) as caught:
                    f["app"]._service_profile(f["tool"])
                self.assertEqual((reasons[number],), caught.exception.args)
                self.assertEqual(raw, (f["tool"] / "infra-neutral.conf").read_bytes())
                self.assert_inputs_unchanged(f, before)

    def test_missing_global_keeps_none_without_demanding_neutral_authority(self):
        with tempfile.TemporaryDirectory(prefix="neutral-direct-noglobal-") as directory:
            f = self.fixture(directory, local=b"INVALID-PUBLIC\n", global_present=False)
            before = self.before(f)
            self.assertIsNone(f["app"]._service_profile(f["tool"]))
            self.assertFalse((f["tool"] / "01-global.yaml").exists())
            self.assert_inputs_unchanged(f, before)


class SelfContainedNeutralWorkflowTests(_NeutralFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The real C2 development reader requires PyYAML/project helpers.
        # It is not copied into, or imported by, the production bundle.
        with mock.patch.object(sys, "argv", [str(C2), "--branch=ib"]), \
             mock.patch.object(sys, "path", list(sys.path)):
            cls.c2 = load_script("neutral_bundle_actual_c2", C2)

    def test_qualified_caller_binds_real_master_without_changing_nested_authority(self):
        with tempfile.TemporaryDirectory(prefix="neutral-qualified-caller-") as directory:
            f = self.fixture(directory, local=BUNDLE_NEUTRAL)
            before = self.before(f)
            try:
                code = self.p1(f, False)
            except (f["app"].SetupError, AssertionError) as error:
                self.fail("qualified PUBLIC caller must preserve the real nested P1/profile: " + str(error))
            self.assertEqual(0, code)
            payload = json.loads((f["root"] / "out/targets.json").read_text())
            self.assertEqual({"status": "checked_by_caller"}, payload["inventory_check"])
            self.assertEqual(EXPECTED_FALLBACK, payload["services"])
            self.assert_inputs_unchanged(f, before)

    def test_mismatched_caller_master_stops_before_nested_main(self):
        with tempfile.TemporaryDirectory(prefix="neutral-caller-mismatch-") as directory:
            f = self.fixture(directory, local=BUNDLE_NEUTRAL)
            master = f["qualification"] / "02-devices_config.csv"
            master.write_text(PUBLIC_CSV.replace("203.0.113.2,", "203.0.113.99,"), encoding="ascii")
            with mock.patch.object(f["app"], "main", wraps=f["app"].main) as main:
                with self.assertRaisesRegex(f["app"].SetupError,
                                            r"\APUBLIC caller inventory mismatch before nested main\Z"):
                    self.p1(f, False)
            main.assert_not_called()
            self.assertFalse((f["root"] / "out").exists())
            self.assertEqual(ANCESTOR_POISON, f["poison"].read_bytes())

    def p1(self, f, explicit):
        app = f["app"]
        # A real management-side caller qualifies these exact PUBLIC inputs.
        # This scope is gone before the original three-file Leaf is entered;
        # the production bundle never borrows the caller's M4 module.
        inventory_source = ROOT / "tools/inventory_subset.py"
        identity_source = ROOT / "tools/device_identity.py"
        bound_sources = [(path, path.read_bytes()) for path in (inventory_source, identity_source)]
        with mock.patch.object(sys, "path", [str(ROOT), *sys.path]), mock.patch.dict(sys.modules):
            for name in list(sys.modules):
                if name == "tools" or name.startswith("tools."):
                    del sys.modules[name]
            package = importlib.import_module("tools")
            self.assertIn(str(ROOT / "tools"), list(package.__path__))
            with mock.patch.object(package, "__path__", [str(ROOT / "tools")]):
                inventory = importlib.import_module("tools.inventory_subset")
                identity = importlib.import_module("tools.device_identity")
                self.assertEqual(inventory_source, Path(inventory.__file__).resolve())
                self.assertEqual(identity_source, Path(identity.__file__).resolve())
                differences = inventory.compare(f["day0"] / "ib.csv",
                    f["qualification"] / "02-devices_config.csv")
            for path, expected in bound_sources:
                self.assertEqual(expected, path.read_bytes(), "caller input library changed during qualification")
        if differences:
            raise app.SetupError("PUBLIC caller inventory mismatch before nested main")
        effects = []
        profile_entries = []
        actual_profile = app._service_profile
        def profile(tool):
            self.assertEqual(f["tool"], tool)
            profile_entries.append("PROFILE_ENTRY")
            return actual_profile(tool)
        def forbidden(*args, **kwargs):
            effects.append(True)
            raise AssertionError("PUBLIC generate-json must not reach a process/transport/native boundary")
        argv = [str(f["source"]), "--generate-json", "--execution-mode", "management", "--inventory-checked",
                "--ib-csv", str(f["tool"] / "ib.csv"), "--p2p", str(f["tool"] / "p2p.dot"),
                "--target-cache", str(f["root"] / "out/targets.json"),
                "--report", str(f["root"] / "out/report.log"),
                "--snapshot-dir", str(f["root"] / "out/snapshots")]
        with ExitStack() as stack:
            # A previous repository or copied Leaf must not supply this bundle's tools.
            stack.enter_context(mock.patch.dict(sys.modules))
            for name in list(sys.modules):
                if name == "tools" or name.startswith("tools."):
                    del sys.modules[name]
            stack.enter_context(mock.patch.object(sys, "path", [str(f["tool"]), *sys.path]))
            stack.enter_context(mock.patch.dict(os.environ, {
                "PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
            }, clear=True))
            for owner, name in (
                    (app.subprocess, "run"), (app.subprocess, "Popen"),
                    (app.os, "fork"), (app.os, "forkpty"), (app.os, "execvp"),
                    (app.pty, "fork"), (app, "interactive_run"),
                    (app, "verify_password_hash"), (app.getpass, "getpass")):
                stack.enter_context(mock.patch.object(owner, name, new=forbidden))
            stack.enter_context(mock.patch.object(app, "_service_profile", new=profile))
            with mock.patch.object(self.c2, "_GLOBAL_FILE", str(f["tool"] / "01-global.yaml")):
                selected = self.c2.load_global("ib")
            expected_system = (
                {"dns": {"server": ["203.0.113.53"]},
                 "ntp": {"server": ["time.explicit.example.test"]},
                 "date-time": {"timezone": "Asia/Taipei"}}
                if explicit else
                {"dns": {"server": []}, "ntp": {"server": []}, "date-time": {"timezone": ""}}
            )
            # An independent literal oracle for the real first-script result.
            self.assertEqual(expected_system, selected["system"])
            self.assertEqual(2, selected["_project_schema_version"])
            self.assertEqual([], effects)
            previous_cwd = Path.cwd()
            output = io.StringIO()
            errors = io.StringIO()
            domain = None
            result = None
            try:
                os.chdir(f["cwd"])
                with mock.patch.object(sys, "argv", argv), \
                     redirect_stdout(output), redirect_stderr(errors):
                    try:
                        result = app.main()
                    except app.SetupError as error:
                        domain = error
            finally:
                os.chdir(previous_cwd)
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
                    app.REPORT_HANDLE = None
            self.assertEqual([], effects)
            self.assertEqual(["PROFILE_ENTRY"], profile_entries)
            self.assertEqual("", errors.getvalue())
            if domain is not None:
                raise domain
            return result

    def test_real_c2_then_p1_from_unrelated_cwd_preserves_day0_links_and_profile(self):
        for explicit in (False, True):
            with self.subTest(explicit=explicit), tempfile.TemporaryDirectory(prefix="neutral-workflow-match-") as directory:
                f = self.fixture(directory, explicit=explicit, local=BUNDLE_NEUTRAL)
                before = self.before(f)
                self.assertEqual(0, self.p1(f, explicit))
                cache_path = f["root"] / "out/targets.json"
                raw = cache_path.read_bytes()
                payload = json.loads(raw)
                self.assertEqual(EXPECTED_EXPLICIT if explicit else EXPECTED_FALLBACK, payload["services"])
                self.assertEqual([], payload["public_keys"])
                self.assertEqual(1, payload["ib_candidate_count"])
                self.assertEqual(EXPECTED_TARGETS, payload["targets"])
                self.assertEqual(str((f["day0"] / "ib.csv").resolve()), payload["ib_csv"])
                self.assertEqual(str((f["day0"] / "p2p.dot").resolve()), payload["p2p"])
                self.assertEqual(str((f["day0"] / "01-global.yaml").resolve()), payload["global"])
                self.assertEqual(hashlib.sha256(raw).hexdigest() + "  targets.json\n",
                                 cache_path.with_name("targets.json.sha256").read_text(encoding="ascii"))
                self.assertEqual(BUNDLE_NEUTRAL, (f["tool"] / "infra-neutral.conf").read_bytes())
                self.assert_inputs_unchanged(f, before)

    def test_real_c2_then_p1_missing_bundle_authority_rejects_without_ancestor_reuse(self):
        with tempfile.TemporaryDirectory(prefix="neutral-workflow-missing-") as directory:
            f = self.fixture(directory, explicit=True, local=None)
            before = self.before(f)
            # C2 successful literal assertions run before actual P1 rejection.
            with self.assertRaises(f["app"].SetupError) as caught:
                self.p1(f, True)
            self.assertEqual(("neutral service authority unavailable: " +
                              str(f["tool"] / "infra-neutral.conf"),), caught.exception.args)
            self.assertFalse((f["root"] / "out/targets.json").exists())
            self.assertFalse((f["root"] / "out/targets.json.sha256").exists())
            self.assertFalse((f["tool"] / "infra-neutral.conf").exists())
            self.assert_inputs_unchanged(f, before)


BUNDLED_NEUTRAL_DATA = ROOT / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"


class BundledNeutralDataTests(unittest.TestCase):
    def test_bundle_data_change_selects_direct_and_real_c2_workflow(self):
        relative = "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
        module = "test_cases.test_initial_setup_selfcontained_neutral"
        initial = "infiniband/bringup/xdr-initial-setup/initial-setup.py"
        c2 = "ztp/config/cumulus/template/90-c2-generate_configs.py"
        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(encoding="utf-8")
        )
        self.assertIn(relative, manifest["tracked_support"])
        self.assertTrue(any(
            relative in rule["paths"] and module in rule.get("tests", [])
            for rule in manifest["path_rules"]
        ), "bundled neutral data needs its own change-aware path rule")
        self.assertTrue(any(
            relative in rule["paths"] and initial in rule["paths"]
            and module in rule["tests"]
            for rule in manifest["test_rules"]
        ))
        self.assertTrue(any(
            initial in flow["members"] and c2 in flow["members"]
            and module in flow["tests"]
            for flow in manifest["workflows"]
        ))

    def test_actual_bundled_neutral_is_regular_and_exact_fixed_authority(self):
        # Canonical production DATA, not a copy made by _NeutralFixture.
        self.assertEqual(0o100000, BUNDLED_NEUTRAL_DATA.lstat().st_mode & 0o170000)
        self.assertEqual(
            b"DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n",
            BUNDLED_NEUTRAL_DATA.read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
