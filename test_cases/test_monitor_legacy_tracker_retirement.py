"""The old online / Stage L Issue Tracker surface is retired (codex REQ7 retirement, batch 1, 2026-10-23).

REQ7, the online Issue Tracker, is now monitor/issue-tracker/issue-tracker-sync.py driving the verbatim
CableTracker engine; it reports through its own log and keeps no worker status file. So:

* the collection worker imports no Issue Tracker module other than issue_tracker_activity_source (the ETH
  activity evidence that the v2 emitter and the worker still bind) and names neither
  issue-tracker-online.status.json nor issue-tracker-stage-l.status.json;
* the Switch control CGI answers view=issue_tracker_online and view=issue_tracker_stage_l like any unknown
  view (400), even when an old status file is still lying in the status directory of a deployed host;
* the monitor page shows no Issue Tracker status, fetches no issue_tracker view and has no local Issue
  Tracker UI switch.

The workflow counterpart (a real worker cycle, then the CGI and the page) is
test_monitor_legacy_tracker_retirement_workflow.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "monitor/switch-collection-worker.py"
CGI_PATH = ROOT / "monitor/switch-collection-control.cgi"
PAGE_PATH = ROOT / "monitor/generate-monitor-html.py"
RETIRED_VIEWS = ("issue_tracker_online", "issue_tracker_stage_l")
RETIRED_STATUS_FILES = ("issue-tracker-online.status.json", "issue-tracker-stage-l.status.json")
KEPT_TRACKER_MODULE = "monitor.issue_tracker_activity_source"
CGI_PATH_NAMES = (
    "STATUS_DIR", "REQUEST_FILE", "STATUS_FILE", "PID_FILE", "YAML_BACKUP_STATUS_FILE",
    "CONTINUOUS_STATUS_FILE", "CONTINUOUS_BACKUP_STATUS_FILE", "YAML_BACKUP_SOCKET",
)


def imported_modules(tree: ast.AST) -> set:
    """Every module an import statement names, at any depth (function-level imports included).

    ``from monitor import issue_tracker_x as y`` imports the submodule monitor.issue_tracker_x, so an
    imported name that is itself an Issue Tracker module name counts as a module too."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names
                         if alias.name.startswith("issue_tracker"))
    return names


def string_constants(tree: ast.AST) -> list:
    return [node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)]


def get_view(cgi, status_dir: Path, query: str) -> mock.Mock:
    """One authenticated GET against the CGI with every state path inside status_dir."""
    environment = {
        "REQUEST_METHOD": "GET", "CONTROL_REQUIRE_AUTH": "1", "AUTH_TYPE": "Basic",
        "REMOTE_USER": "nvis", "PATH_INFO": "", "SCRIPT_NAME": "/monitor/control/switch-collection",
        "QUERY_STRING": query,
    }
    with mock.patch.dict(os.environ, environment, clear=True), \
            mock.patch.object(cgi, "respond") as respond:
        patches = [mock.patch.object(cgi, name, status_dir / getattr(cgi, name).name)
                   for name in CGI_PATH_NAMES if name != "STATUS_DIR"]
        patches.append(mock.patch.object(cgi, "STATUS_DIR", status_dir))
        for patch in patches:
            patch.start()
        try:
            cgi.main()
        finally:
            for patch in reversed(patches):
                patch.stop()
    return respond


def page_html(page, **keywords) -> str:
    stats = {"changed": 0, "new": 0, "removed": 0, "same": 0}
    return page.build_html(
        {}, "", 0, "", "", 0, {}, "",
        "", "", stats, None, 0,
        "", "", stats, None, 0,
        "", "", 0, "",
        "", "", stats, None, 0,
        {}, {}, {}, {},
        {"available": False, "counts": {}, "environment_updates": {}, "devices": []},
        **keywords,
    )


def polled_views(html: str) -> set:
    return set(re.findall(r"SWITCH_COLLECTION_URL\}\?view=([A-Za-z0-9_]+)", html))


class WorkerHasNoTrackerLaneTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(WORKER_PATH.read_text(encoding="utf-8"))

    def test_the_import_census_sees_every_import_form(self):
        sample = ast.parse(
            "import monitor.issue_tracker_a\n"
            "from monitor import issue_tracker_b as remote\n"
            "def lane():\n"
            "    from monitor.issue_tracker_c import thing, other\n"
            "from monitor.issue_tracker_activity_source import load_eth_activity_evidence\n")
        self.assertEqual(
            {"monitor.issue_tracker_a", "monitor.issue_tracker_b", "monitor.issue_tracker_c",
             KEPT_TRACKER_MODULE},
            {name for name in imported_modules(sample) if "issue_tracker" in name})

    def test_the_worker_imports_only_the_kept_activity_source(self):
        tracker = {name for name in imported_modules(self.tree) if "issue_tracker" in name}
        self.assertEqual({KEPT_TRACKER_MODULE}, tracker)

    def test_the_worker_names_no_retired_status_file_or_tracker_module(self):
        for value in string_constants(self.tree):
            for name in RETIRED_STATUS_FILES:
                self.assertNotIn(name, value)
            self.assertNotIn("issue-tracker-stage-l", value)
            self.assertNotIn("issue-tracker-online", value)
            if value.startswith("monitor.issue_tracker_"):
                self.assertEqual(KEPT_TRACKER_MODULE, value)


class ControlCgiRefusesRetiredViewsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cgi = load_script("legacy_tracker_retirement_switch_cgi", CGI_PATH)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.status = Path(temporary.name) / "status"
        self.status.mkdir(mode=0o755)

    def test_the_retired_views_are_unknown_views_even_with_old_status_files_present(self):
        # What a deployed host may still hold from the old lanes (plan 5.5); nothing may serve it.
        for name in RETIRED_STATUS_FILES:
            (self.status / name).write_text(
                '{"schema_version": 1, "state": "hold", "updated_at": "2026-10-23T00:00:00+00:00"}\n',
                encoding="utf-8")
        for view in RETIRED_VIEWS:
            with self.subTest(view=view):
                respond = get_view(self.cgi, self.status, f"view={view}")
                respond.assert_called_once_with({"error": "invalid status view"}, "400 Bad Request")

    def test_the_status_views_the_page_polls_are_still_served(self):
        for query in ("", "view=switch", "view=yaml_backup", "view=continuous",
                      "view=continuous_collection", "view=continuous_backup"):
            with self.subTest(query=query):
                respond = get_view(self.cgi, self.status, query)
                respond.assert_called_once()
                arguments = respond.call_args[0]
                self.assertEqual(1, len(arguments), "served with the default 200 OK")
                self.assertIn("process_alive", arguments[0])

    def test_the_cgi_names_no_retired_status_file(self):
        values = string_constants(ast.parse(CGI_PATH.read_text(encoding="utf-8")))
        for value in values:
            for name in (*RETIRED_STATUS_FILES, *RETIRED_VIEWS):
                self.assertNotIn(name, value)


class PageShowsNoTrackerStatusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = load_script("legacy_tracker_retirement_page", PAGE_PATH)
        cls.html = page_html(cls.page)

    def test_the_page_has_no_tracker_status_and_fetches_no_tracker_view(self):
        for marker in ("issue-tracker-online-state", "-stage-l-state", "view=issue_tracker",
                       "IssueTrackerOnlineStatus", "IssueTrackerStageLStatus", "issue-tracker-manual",
                       "Issue Tracker 在线状态", "Issue Tracker 本地状态"):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.html)
        views = polled_views(self.html)
        self.assertIn("yaml_backup", views, "the view extraction sees the page's polled views")
        self.assertEqual(set(), {view for view in views if "issue_tracker" in view})

    def test_the_page_has_no_local_tracker_ui_switch(self):
        with self.assertRaises(TypeError):
            page_html(self.page, issue_tracker_local_ui=True)


if __name__ == "__main__":
    unittest.main()
