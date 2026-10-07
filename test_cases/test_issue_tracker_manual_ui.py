"""REQ7 manual controls are local-only and never enabled by production HTML."""

import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
for import_root in (ROOT, ROOT / "tools", ROOT / "monitor"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))
SPEC = importlib.util.spec_from_file_location(
    "req7_manual_ui_html", ROOT / "monitor/generate-monitor-html.py"
)
HTML = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HTML
SPEC.loader.exec_module(HTML)


def page(*, local_ui=False):
    stats = {"changed": 0, "new": 0, "removed": 0, "same": 0}
    return HTML.build_html(
        {}, "", 0, "", "", 0, {}, "",
        "", "", stats, None, 0,
        "", "", stats, None, 0,
        "", "", 0, "",
        "", "", stats, None, 0,
        {}, {}, {}, {},
        {"available": False, "counts": {}, "environment_updates": {},
         "devices": []},
        issue_tracker_local_ui=local_ui,
    )


def browser_settings_script(body):
    """Execute generated JavaScript against private DOM/fetch fixtures.

    Missing Node is a failed prerequisite, never an optional skip. Production
    CGI, network, browser profile and service state are not touched.
    """
    bundled = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"
    node = os.environ.get("HTTP_TEST_NODE") or shutil.which("node") or str(bundled)
    if not Path(node).is_file():
        raise AssertionError("REQ7 browser contract requires an available Node interpreter")
    fixture = r'''
const assert = require('node:assert/strict');
const elements = {};
for (const id of ['eth', 'etop', 'itop']) {
  for (const kind of ['k', 'k-save', 'k-load'])
    elements[`issue-tracker-${id}-${kind}`] = {value: '', disabled: true};
}
for (const id of ['tabs', 'issue-tracker-confirm', 'issue-tracker-preview-detail',
    'issue-tracker-preview-state', 'issue-tracker-manual-dialog'])
  elements[id] = {disabled: true, textContent: '', open: false,
    addEventListener(){}, close(){this.open=false}, showModal(){this.open=true}};
const notice = {textContent: ''};
const document = {getElementById: id => elements[id], querySelector: () => notice};
const crypto = {getRandomValues: bytes => bytes.fill(171)};
const calls = [], replies = [];
async function fetch(url, options) {
  calls.push({url, body: options.body.toString(), headers: options.headers});
  const reply = replies.shift();
  if (reply instanceof Error) throw reply;
  return {ok: true, async json(){return reply}};
}
function settings(k, revision, state='current') {
  const value = {settings: state, k, revision, event_sha256: 'd'.repeat(64),
    online: 'disabled_no_send_authority'};
  if (state === 'committed') value.replay = false;
  return value;
}
'''
    completed = subprocess.run(
        [node, "-e", fixture + HTML._ISSUE_TRACKER_MANUAL_SCRIPT +
         "\n(async () => {\n" + body +
         "\n})().catch(error => {console.error(error); process.exitCode=1});"],
        text=True, capture_output=True, timeout=10, check=False,
    )
    if completed.returncode:
        raise AssertionError(completed.stdout + completed.stderr)
    return json.loads(completed.stdout)


class ManualUiTests(unittest.TestCase):
    def test_generated_settings_query_and_save_keep_exact_decimal_and_revision(self):
        rendered = page(local_ui=True)
        self.assertIn('onclick="issueTrackerSettingsRead(', rendered)
        self.assertIn('onclick="issueTrackerSettingsSave(', rendered)
        self.assertNotIn('type="number" min="1" value="3" disabled', rendered)
        result = browser_settings_script(r'''
replies.push(settings('5000', '12'));
await issueTrackerSettingsRead('Switch Status');
for (const id of ['eth','etop','itop']) {
  assert.equal(elements[`issue-tracker-${id}-k`].value, '5000');
  assert.equal(elements[`issue-tracker-${id}-k-save`].disabled, false);
}
pendingIssueTrackerPreview = {panel:'Switch Status', token:'old'};
elements['issue-tracker-eth-k'].value = '9007199254740993';
replies.push(settings('9007199254740993', '13', 'committed'));
await issueTrackerSettingsSave('Switch Status');
assert.equal(pendingIssueTrackerPreview, null);
assert.equal(elements['issue-tracker-confirm'].disabled, true);
assert.equal(elements['issue-tracker-eth-k'].value, '9007199254740993');
assert.equal(calls.length, 2);
console.log(JSON.stringify({calls, notice:notice.textContent}));
''')
        self.assertEqual("action=settings&panel=Switch+Status", result["calls"][0]["body"])
        self.assertEqual("application/vnd.http.issue-tracker.settings+json",
                         result["calls"][0]["headers"]["Accept"])
        self.assertEqual("action=set_k&panel=Switch+Status&new_k=9007199254740993"
                         "&expected_revision=12&request_id=" + "ab" * 16,
                         result["calls"][1]["body"])

    def test_invalid_input_or_lost_reply_never_retries_or_keeps_old_settings_authority(self):
        result = browser_settings_script(r'''
replies.push(settings('3','0'));
await issueTrackerSettingsRead('Switch Status');
for (const value of ['0','01','1.0','-1','true','',' 5']) {
  elements['issue-tracker-eth-k'].value=value;
  await issueTrackerSettingsSave('Switch Status');
}
assert.equal(calls.length,1);
elements['issue-tracker-eth-k'].value='7';
replies.push(new Error('response lost after worker commit'));
await issueTrackerSettingsSave('Switch Status');
await issueTrackerSettingsSave('Switch Status');
assert.equal(calls.length,2);
for (const id of ['eth','etop','itop']) {
  assert.equal(elements[`issue-tracker-${id}-k-save`].disabled,true);
  assert.equal(elements[`issue-tracker-${id}-k`].disabled,true);
}
console.log(JSON.stringify({notice:notice.textContent}));
''')
        self.assertIn("未知", result["notice"])
        self.assertIn("勿重试", result["notice"])

    def test_malformed_settings_query_cannot_enable_any_save_or_default_k(self):
        result = browser_settings_script(r'''
for (const bad of [settings(3,0), settings('03','0'), settings('3',true),
    {...settings('3','0'), online:'sent'}, {...settings('3','0'), credential:'secret'}]) {
  replies.push(bad);
  await issueTrackerSettingsRead('Switch Status');
  assert.equal(elements['issue-tracker-eth-k-save'].disabled,true);
  assert.equal(elements['issue-tracker-eth-k'].value,'');
}
console.log(JSON.stringify({queries:calls.length}));
''')
        self.assertEqual(5, result["queries"])

    def test_wrong_commit_receipt_or_cancelled_query_never_restores_write_authority(self):
        result = browser_settings_script(r'''
for (const bad of [settings('8','1','committed'), settings('7','0','committed'),
    {...settings('7','1','committed'), replay:'false'},
    {...settings('7','1','committed'), secret:'sentinel'}]) {
  replies.push(settings('3','0'));
  await issueTrackerSettingsRead('Switch Status');
  elements['issue-tracker-eth-k'].value='7';
  replies.push(bad);
  await issueTrackerSettingsSave('Switch Status');
  assert.equal(elements['issue-tracker-eth-k-save'].disabled,true);
  assert.equal(elements['issue-tracker-eth-k'].value,'');
}
let release;
fetch = async () => ({ok:true, json: () => new Promise(resolve => {release=resolve})});
const pending = issueTrackerSettingsRead('Switch Status');
await Promise.resolve();
issueTrackerManualCancel();
release(settings('9','4'));
await pending;
assert.equal(elements['issue-tracker-eth-k-save'].disabled,true);
assert.equal(elements['issue-tracker-eth-k'].value,'');
console.log(JSON.stringify({calls:calls.length}));
''')
        self.assertEqual(8, result["calls"])

    def test_production_entrypoint_cannot_opt_in_or_expose_a_cli_flag(self):
        tree = ast.parse((ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8"))
        generator = next(node for node in tree.body if isinstance(
            node, ast.FunctionDef) and node.name == "_generate_monitor_html")
        calls = [node for node in ast.walk(generator) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name)
                 and node.func.id == "build_html"]
        self.assertEqual(1, len(calls))
        self.assertNotIn("issue_tracker_local_ui",
                         [keyword.arg for keyword in calls[0].keywords])
        parser = next(node for node in tree.body if isinstance(
            node, ast.FunctionDef) and node.name == "parse_args")
        self.assertNotIn("issue_tracker_local_ui", ast.unparse(parser))

    def test_default_page_contains_no_manual_ui_or_manual_route(self):
        rendered = page()
        self.assertNotIn('data-issue-tracker-panel=', rendered)
        self.assertNotIn('id="issue-tracker-manual-dialog"', rendered)
        self.assertNotIn('/monitor/control/issue-tracker', rendered)
        self.assertNotIn('issueTrackerManualPreview(', rendered)

    def test_only_three_exact_panels_have_local_controls(self):
        rendered = page(local_ui=True)
        for panel_id, panel in (
            ("eth", "Switch Status"),
            ("etop", "Eth Link Validation"),
            ("itop", "IB Link Validation"),
        ):
            self.assertIn(f'data-issue-tracker-panel="{panel}"', rendered)
            self.assertIn(f'id="issue-tracker-{panel_id}-preview"', rendered)
            self.assertIn(f'id="issue-tracker-{panel_id}-k"', rendered)
        self.assertEqual(3, rendered.count('>发布到 Issue Tracker</button>'))
        self.assertEqual(3, rendered.count('合格窗口 K'))
        self.assertEqual(1, rendered.count('id="issue-tracker-manual-dialog"'))
        self.assertIn('id="issue-tracker-confirm"', rendered)
        self.assertIn('id="issue-tracker-cancel"', rendered)
        self.assertIn('Stage O 在线发布未启用', rendered)

    def test_incomplete_preview_and_wrong_panel_cannot_enable_confirmation(self):
        rendered = page(local_ui=True)
        self.assertIn('function validIssueTrackerPreview(payload, panel)', rendered)
        self.assertIn('payload.panel !== panel', rendered)
        self.assertIn('payload.online !== "disabled_no_send_authority"', rendered)
        self.assertIn('Array.isArray(payload.source_files)', rendered)
        self.assertIn('Array.isArray(payload.row_digests)', rendered)
        self.assertIn('Number.isInteger(payload.new_count)', rendered)
        self.assertIn('Number.isInteger(payload.update_count)', rendered)
        self.assertIn('Number.isInteger(payload.skip_count)', rendered)
        self.assertIn('if (!validIssueTrackerPreview(payload, panel))', rendered)
        self.assertIn('confirmation: "publish_local"', rendered)
        self.assertIn('pendingIssueTrackerPreview = null;', rendered)
        self.assertIn('textContent =', rendered)
        self.assertNotIn('innerHTML = payload', rendered)


if __name__ == "__main__":
    unittest.main()
