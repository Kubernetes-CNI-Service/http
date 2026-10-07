"""Independent auth-library documentation expectations; no runtime/CLI permission."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Req7AuthDocumentationCandidateTests(unittest.TestCase):
    def test_test_readme_preserves_uninstalled_scope_and_intent_not_wire_attempt_distinction(self):
        path=Path(__file__).resolve().parents[1]/"test_cases/README.md"
        self.assertTrue(path.is_file(),"new REQ7 contracts require testcase documentation")
        text=path.read_text()
        for required in ("test_req7_sdk_authentication", "test_req7_native_tls_wire", "test_req7_attempt_supervision",
                         "test_req7_sheets_read_decode", "test_req7_online_whitelist_read", "test_req7_mutation_rejection",
                         "test_req7_attempt_journal", "未安装", "六次意图", "真实尝试", "NOT RUN", "REQ7 整体"):
            self.assertIn(required,text)

    def test_sdk_profile_is_uninstalled_library_not_an_operator_cli_or_online_proof(self):
        spec = importlib.util.spec_from_file_location("req7_auth_manual_candidate", ROOT / "tools/update-user-manual.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        profile = module.script_profile(ROOT, "monitor/issue_tracker_sdk_authentication.py")
        self.assertTrue(profile["direct"].startswith("否"))
        self.assertIn("未安装", profile["environment"]); self.assertIn("未启用", profile["environment"])
        self.assertIn("公共 SDK", profile["scenario"]); self.assertIn("一次", profile["scenario"])
        self.assertIn("held-FD", profile["inputs"]); self.assertIn("固定 Sheets scope", profile["inputs"])
        self.assertIn("无", profile["parameters"]); self.assertIn("CLI", profile["parameters"])
        self.assertIn("不授予", profile["success"]); self.assertIn("完整传输", profile["success"])
        self.assertIn("整个 REQ7", profile["success"])
        self.assertIn("非 200", profile["recovery"]); self.assertIn("第二次回调", profile["recovery"])
        self.assertIn("test_cases.test_req7_sdk_authentication", profile["example"])
        self.assertNotIn("sudo ", profile["example"])

    def test_controlled_transport_supervisor_and_read_helpers_are_uninstalled_libraries_not_online_entries(self):
        spec = importlib.util.spec_from_file_location("req7_transport_manual_candidate", ROOT / "tools/update-user-manual.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        cases = (("monitor/issue_tracker_tls_inputs.py", "受控 CA", "test_cases.test_req7_tls_inputs"),
                 ("monitor/issue_tracker_attempt_supervision.py", "隔离子进程", "test_cases.test_req7_attempt_supervision"),
                 ("monitor/issue_tracker_sheets_read_plan.py", "精确", "test_cases.test_req7_sheets_read_plan"),
                 ("monitor/issue_tracker_sheets_read_decode.py", "userEnteredValue", "test_cases.test_req7_sheets_read_decode"),
                 ("monitor/issue_tracker_online_whitelist_read.py", "冻结本地", "test_cases.test_req7_online_whitelist_read"),
                 ("monitor/issue_tracker_mutation_rejection.py", "UNKNOWN", "test_cases.test_req7_mutation_rejection"),
                 ("monitor/issue_tracker_attempt_journal.py", "六次", "test_cases.test_req7_attempt_journal"))
        for path, scenario, test_module in cases:
            with self.subTest(path=path):
                profile = module.script_profile(ROOT, path)
                self.assertTrue(profile["direct"].startswith("否"))
                self.assertIn("未安装", profile["environment"]); self.assertIn("未启用", profile["environment"])
                self.assertIn(scenario, profile["scenario"])
                self.assertIn("CLI", profile["parameters"]); self.assertIn("无", profile["parameters"])
                self.assertIn("不授予", profile["success"]); self.assertIn("整个 REQ7", profile["success"])
                self.assertIn("HOLD", profile["recovery"])
                self.assertIn(test_module, profile["example"]); self.assertNotIn("sudo ", profile["example"])


if __name__ == "__main__": unittest.main()
