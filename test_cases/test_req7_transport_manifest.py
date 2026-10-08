"""Independent promotion graph checks; no partial-tree approval or full proof."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = {
    "monitor/issue_tracker_sdk_authentication.py": "test_cases.test_req7_sdk_authentication",
    "monitor/issue_tracker_tls_inputs.py": "test_cases.test_req7_tls_inputs",
    "monitor/issue_tracker_attempt_supervision.py": "test_cases.test_req7_attempt_supervision",
    "monitor/issue_tracker_token_launcher.py": "test_cases.test_req7_token_launcher",
    "monitor/issue_tracker_history_read_launcher.py": "test_cases.test_req7_history_read_launcher",
    "monitor/issue_tracker_mutation_launcher.py": "test_cases.test_req7_mutation_launcher",
    "monitor/issue_tracker_sheets_read_plan.py": "test_cases.test_req7_sheets_read_plan",
    "monitor/issue_tracker_sheets_read_decode.py": "test_cases.test_req7_sheets_read_decode",
    "monitor/issue_tracker_online_whitelist_read.py": "test_cases.test_req7_online_whitelist_read",
    "monitor/issue_tracker_mutation_rejection.py": "test_cases.test_req7_mutation_rejection",
    "monitor/issue_tracker_attempt_journal.py": "test_cases.test_req7_attempt_journal",
    "monitor/issue_tracker_metadata_capacity.py": "test_cases.test_req7_metadata_capacity",
    "monitor/issue_tracker_send_unit.py": "test_cases.test_req7_send_unit",
    "monitor/issue_tracker_send_intent.py": "test_cases.test_req7_send_intent",
    "monitor/issue_tracker_spreadsheet_owner.py": "test_cases.test_req7_spreadsheet_owner",
    "monitor/issue_tracker_global_attempt_journal.py": "test_cases.test_req7_global_attempt_journal",
    "monitor/issue_tracker_settings_audit_allocation.py": "test_cases.test_req7_settings_audit_allocation",
    "monitor/issue_tracker_enrollment_journal.py": "test_cases.test_req7_enrollment_journal",
    "monitor/issue_tracker_history_preread_journal.py": "test_cases.test_req7_history_preread_journal",
    "monitor/issue_tracker_remote_history_match.py": "test_cases.test_req7_remote_history_match",
    "monitor/issue_tracker_nv_reservation.py": "test_cases.test_req7_nv_reservation",
    "monitor/issue_tracker_metadata_reservation.py": "test_cases.test_req7_metadata_reservation",
}


class Req7TransportManifestCandidateTests(unittest.TestCase):
    def test_original_fd_mutation_workflow_includes_durable_claim_and_total_supervision(self):
        manifest = json.loads((ROOT/'test_cases/script_test_manifest.json').read_text())
        required = {'monitor/issue_tracker_global_attempt_journal.py','monitor/issue_tracker_spreadsheet_owner.py',
                    'monitor/issue_tracker_send_unit.py','monitor/issue_tracker_send_intent.py',
                    'monitor/issue_tracker_local_commit.py','monitor/issue_tracker_tls_inputs.py',
                    'monitor/issue_tracker_attempt_supervision.py','monitor/issue_tracker_mutation_rejection.py'}
        self.assertTrue(any(required <= set(rule['members']) and
                            'test_cases.test_req7_native_supervised_workflow' in rule['tests']
                            for rule in manifest['workflows']))

    def test_isolated_original_wire_coherence_needs_no_yaml_or_workbook_dependency(self):
        # A fixed mutation child checks original ACTION/WIRE, never compiles
        # sources. Its isolated graph must not require parent-only dependencies.
        code = ('import sys; sys.path.insert(0,'+repr(str(ROOT))+'); '
                'from monitor.issue_tracker_send_unit import FrozenSendUnit; '
                'from monitor.issue_tracker_send_intent import _projection; '
                '\ntry: _projection(None)\n'
                'except ValueError: pass\n'
                'else: raise AssertionError("incoherent original accepted")\n'
                'assert "yaml" not in sys.modules\n'
                'assert "openpyxl" not in sys.modules\n'
                'assert "monitor.issue_tracker_manifest" not in sys.modules\n')
        result = subprocess.run([sys.executable,'-I','-B','-c',code],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
        self.assertEqual(0,result.returncode,result.stderr)

    def test_isolated_read_transport_does_not_import_the_heavy_mutation_composer(self):
        # Existing fixed token/read children expose only their governed SDK
        # closure. A new write shape must not add YAML/workbook imports to them.
        code = ('import sys; sys.path.insert(0,'+repr(str(ROOT))+'); '
                'from unittest import mock; from monitor import issue_tracker_tls_inputs as tls; '
                'plan=tls.PreparedTokenRequest("oauth2.googleapis.com","/token","POST",b"x",(),30.0); '
                '\nwith mock.patch.object(tls,"controlled_tls_context",side_effect=ValueError("owned stop before CA/network")) as ca:\n'
                '    try: tls._native_complete_read(plan)\n'
                '    except tls.TlsInputHold: pass\n'
                '    ca.assert_called_once_with()\n'
                'assert "monitor.issue_tracker_send_unit" not in sys.modules\n')
        result = subprocess.run([sys.executable,'-I','-B','-c',code],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
        self.assertEqual(0,result.returncode,result.stderr)

    def test_fixed_native_mutation_workflow_binds_original_composer_coherence_and_error_decoder(self):
        manifest = json.loads((ROOT/'test_cases/script_test_manifest.json').read_text())
        members = {'monitor/issue_tracker_send_unit.py','monitor/issue_tracker_send_intent.py',
                   'monitor/issue_tracker_sheets_read_plan.py','monitor/issue_tracker_sdk_authentication.py',
                   'monitor/issue_tracker_tls_inputs.py','monitor/issue_tracker_mutation_rejection.py'}
        self.assertTrue(any(members <= set(rule['members'])
                            and 'test_cases.test_req7_native_tls_wire' in rule['tests']
                            for rule in manifest['workflows']), 'actual immutable batch/native HTTP/rejection workflow missing')

    def test_owned_read_gate_fixture_uses_current_canonical_journal_registries(self):
        import monitor
        from test_cases.test_req7_global_attempt_journal import load as global_load
        from test_cases.test_req7_enrollment_journal import load as enrollment_load
        from test_cases.test_req7_remote_history_match import load as gate_load
        global_module = global_load(); enrollment_module = enrollment_load()
        gate = gate_load()
        self.assertIs(gate, getattr(monitor, 'issue_tracker_remote_history_match', None))
        self.assertIs(gate.global_journal, global_module)
        self.assertIs(gate.enrollment, enrollment_module)
        self.assertIs(gate.ownership, monitor.issue_tracker_spreadsheet_owner)

    def test_original_count_workflow_covers_actual_owned_read_gates(self):
        manifest = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        required = {'monitor/issue_tracker_global_attempt_journal.py',
                    'monitor/issue_tracker_history_preread_journal.py',
                    'monitor/issue_tracker_remote_history_match.py',
                    'monitor/issue_tracker_history_read_launcher.py',
                    'monitor/issue_tracker_online_whitelist_read.py',
                    'monitor/issue_tracker_attempt_supervision.py',
                    'monitor/issue_tracker_tls_inputs.py'}
        workflow = next(item for item in manifest['workflows']
                        if item['id'] == 'req7_protected_original_receipt_business_count')
        self.assertTrue(required <= set(workflow['members']))
        self.assertIn('test_cases.test_issue_tracker_stage_l_consumer_workflow', workflow['tests'])
        self.assertIn('test_cases.test_req7_global_attempt_journal', workflow['tests'])
        matching = next(item for item in manifest['workflows']
                        if item['id'] == 'req7_native_history_nonce_fence_actual_journal_match')
        self.assertIn('monitor/issue_tracker_online_whitelist_read.py', matching['members'])
        self.assertIn('monitor/issue_tracker_history_preread_journal.py', matching['members'])
        self.assertIn('monitor/issue_tracker_history_read_launcher.py', matching['members'])

    def test_durable_fixture_package_aliases_track_current_owner_and_journal_modules(self):
        import monitor
        from test_cases.test_req7_spreadsheet_owner import load as owner_load
        from test_cases.test_req7_global_attempt_journal import load as global_load
        from test_cases.test_req7_enrollment_journal import load as nonce_load
        from test_cases.test_req7_history_preread_journal import load as before_load
        owner = owner_load(); global_module = global_load(); nonce_module = nonce_load(); before_module = before_load()
        self.assertIs(global_module, getattr(monitor, 'issue_tracker_global_attempt_journal', None))
        self.assertIs(nonce_module, getattr(monitor, 'issue_tracker_enrollment_journal', None))
        self.assertIs(before_module, getattr(monitor, 'issue_tracker_history_preread_journal', None))
        self.assertIs(owner, global_module.ownership)
        self.assertIs(global_module, before_module.global_journal)
        self.assertIs(owner, before_module.ownership)

    def test_composer_fixture_keeps_canonical_class_identity_across_repeated_loads(self):
        from test_cases.test_req7_send_unit import load, inputs
        first = load(); unit = first.freeze_send_unit(**inputs())
        second = load()
        self.assertIs(first, second, 'fixture reload must not split the canonical dataclass used by journal checks')
        self.assertIs(type(unit), second.FrozenSendUnit)
        from monitor.issue_tracker_send_intent import _projection
        self.assertEqual(unit.action_digest, _projection(unit)['action_digest'])

    def test_template_header_workflow_binds_real_local_format_authority(self):
        manifest = json.loads((ROOT / "test_cases/script_test_manifest.json").read_text())
        self.assertTrue(any({"monitor/issue_tracker_sheets_read_decode.py", "monitor/issue_tracker_sheets_read_plan.py",
                             "monitor/issue_tracker_tls_inputs.py", "monitor/issue_tracker_local_workbook.py"} <= set(rule["members"])
                            and "test_cases.test_req7_sheets_read_decode" in rule["tests"] for rule in manifest["workflows"]),
                        "new cross-script header validator must bind its actual local format dependency")
        card = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text()
        for text in ("十四表身份", "Update_History", "非原子", "不是发送许可"):
            self.assertIn(text, card)

    def test_native_scope_has_explicit_not_run_cards_without_online_or_release_authority(self):
        path = ROOT / "test_cases/REAL_ENVIRONMENT.md"
        self.assertTrue(path.is_file(), "native transport obligations must be registered before promotion")
        source = path.read_text()
        for case in ("TC-REAL-REQ7-SDK-AUTH-TRANSPORT-001", "TC-REAL-REQ7-TOTAL-ATTEMPT-LOCK-001",
                     "TC-REAL-REQ7-NATIVE-READ-WHITELIST-001"):
            with self.subTest(case=case):
                start = source.index("## " + case)
                end = source.find("\n## ", start + 1)
                card = source[start:] if end < 0 else source[start:end]
                self.assertIn("NOT RUN / REAL_ENV REQUIRED", card)
                for required in ("前置条件", "owner", "证据", "清理", "stat/inode", "Stage O"):
                    self.assertIn(required, card)
        for script in SCRIPTS:
            self.assertIn(script, source)
        for required in ("30/30/60", "无法确认", "10000", "不重筛本地 manifest", "普通发布证明"):
            self.assertIn(required, source)

    def test_shared_fixtures_resolve_the_owning_package_not_a_developer_checkout(self):
        for name in ("test_req7_sdk_authentication.py", "test_req7_tls_inputs.py", "test_req7_sheets_read_plan.py"):
            with self.subTest(module=name):
                source = (ROOT / "test_cases" / name).read_text()
                tree = ast.parse(source)
                self.assertFalse(any(isinstance(node, ast.Constant) and isinstance(node.value, str)
                                     and node.value.startswith(("/Users/", "/home/", "/private/tmp/"))
                                     for node in ast.walk(tree)), "fixture must survive independent formal clones")
                roots = [node.value for node in tree.body if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == "ROOT" for target in node.targets)]
                self.assertEqual(1, len(roots))
                self.assertEqual("Path(test_cases.__file__).resolve().parents[1]", ast.unparse(roots[0]))

    def test_new_modules_import_in_a_clean_canonical_package_without_discovery_path_side_effects(self):
        import test_cases
        main_root = Path(test_cases.__file__).resolve().parents[1]
        code = ("import sys, importlib; "
                + "sys.path.insert(0," + repr(str(main_root)) + "); "
                + "sys.path.insert(0," + repr(str(main_root / 'tools')) + "); "
                + "import test_cases; test_cases.__path__.insert(0," + repr(str(ROOT / 'test_cases')) + "); "
                + "[importlib.import_module(name) for name in "
                + repr(["test_cases.test_req7_sheets_read_decode", "test_cases.test_req7_online_whitelist_read",
                        "test_cases.test_req7_native_tls_wire", "test_cases.test_req7_sheets_read_plan",
                        "test_cases.test_req7_tls_inputs", "test_cases.test_req7_sdk_authentication",
                        "test_cases.test_req7_attempt_supervision", "test_cases.test_req7_native_supervised_workflow"])
                + "]")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_each_canonical_library_has_direct_real_multi_script_workflow_and_one_primary_suite(self):
        path = ROOT / "test_cases/script_test_manifest.json"
        self.assertTrue(path.is_file(), "REQ7 reviewed candidate manifest missing")
        manifest = json.loads(path.read_text())
        for script, direct in SCRIPTS.items():
            with self.subTest(script=script):
                self.assertEqual(script, manifest["scripts"].get(script))
                self.assertTrue(any(script in rule["paths"] and direct in rule["tests"] for rule in manifest["test_rules"]))
                workflows = [rule for rule in manifest["workflows"] if script in rule["members"]]
                self.assertTrue(workflows)
                self.assertTrue(any(len({manifest["scripts"].get(member) for member in rule["members"] if member in manifest["scripts"]}) >= 2
                                    for rule in workflows))
                self.assertEqual(["issue-tracker-local"], [suite["id"] for suite in manifest["test_suites"] if direct in suite["tests"]])
        self.assertTrue(any({"monitor/issue_tracker_attempt_supervision.py", "monitor/issue_tracker_tls_inputs.py"} <= set(rule["members"])
                            and "test_cases.test_req7_native_supervised_workflow" in rule["tests"] for rule in manifest["workflows"]))
        self.assertTrue(any({"monitor/issue_tracker_online_whitelist_read.py", "monitor/issue_tracker_whitelist_workbook.py"} <= set(rule["members"])
                            and "test_cases.test_req7_online_whitelist_read" in rule["tests"] for rule in manifest["workflows"]))
        for name in ("test_cases.test_req7_native_tls_wire", "test_cases.test_req7_native_supervised_workflow",
                     "test_cases.test_req7_auth_documentation_candidate", "test_cases.test_req7_transport_manifest"):
            self.assertEqual(1, sum(name in suite["tests"] for suite in manifest["test_suites"]))


if __name__ == "__main__": unittest.main()
