"""v3.1.6 C1 V2-V5 Switch Status view: independent PUBLIC direct contracts.

Every expected literal below is written from the approved v3.1.6 guide
(guide-v3.1.6-approved-r839, sections 8.13 and 8.15-8.17) and the owner
decisions it cites (page issue file sections 13, 16, 17 and 20); none is
derived from the page generator's output.  The generated page is parsed with
the standard-library ``html.parser``; no page JavaScript is executed (8.13:
the interactions are witnessed by the REAL_ENVIRONMENT cards instead).
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import os
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.native_cpld_physical_io import owned_test_root

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "monitor/generate-monitor-html.py"
STATS = {"changed": 0, "new": 0, "removed": 0, "same": 0}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}
# The page module's log() appends to LOG_FILE, by default the repository's own
# monitor/generate-monitor.log.  A test that reaches log() must neither create nor
# change that file (v3.1.6 full run v316-full-96c2ca2-20261128-01, lane w3 leftover).
REPOSITORY_PAGE_LOG = PAGE.parent / "generate-monitor.log"


def repository_page_log_state():
    """(inode, size, mtime_ns) of the repository's page log, or None while it is absent."""
    try:
        status = os.lstat(REPOSITORY_PAGE_LOG)
    except FileNotFoundError:
        return None
    return status.st_ino, status.st_size, status.st_mtime_ns


def load_page(name="_switch_status_view_page"):
    spec = importlib.util.spec_from_file_location(name, PAGE)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    before = list(sys.path)
    sys.modules[name] = module
    sys.path.insert(0, str(PAGE.parent))
    try:
        with mock.patch.dict(os.environ, {"MONITOR_TIMEZONE": "UTC"}):
            spec.loader.exec_module(module)
    finally:
        sys.path[:] = before
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


class Node:
    def __init__(self, tag, attrs, parent=None):
        self.tag, self.attrs, self.parent, self.children = tag, dict(attrs), parent, []

    def classes(self):
        return (self.attrs.get("class") or "").split()

    def text(self):
        return "".join(child if isinstance(child, str) else child.text()
                       for child in self.children)

    def iter(self):
        for child in self.children:
            if isinstance(child, Node):
                yield child
                yield from child.iter()

    def find_all(self, tag=None, cls=None, **attrs):
        return [node for node in self.iter()
                if (tag is None or node.tag == tag)
                and (cls is None or cls in node.classes())
                and all(node.attrs.get(key.replace("_", "-")) == value
                        for key, value in attrs.items())]

    def find(self, *args, **kwargs):
        found = self.find_all(*args, **kwargs)
        return found[0] if found else None


class Tree(HTMLParser):
    """A small standard-library DOM: enough to read attributes and text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", {})
        self.current = self.root

    def handle_starttag(self, tag, attrs):
        node = Node(tag, attrs, self.current)
        self.current.children.append(node)
        if tag not in VOID:
            self.current = node

    def handle_startendtag(self, tag, attrs):
        self.current.children.append(Node(tag, attrs, self.current))

    def handle_endtag(self, tag):
        node = self.current
        while node is not self.root and node.tag != tag:
            node = node.parent
        if node is not self.root:
            self.current = node.parent

    def handle_data(self, data):
        self.current.children.append(data)


def parse_html(text):
    tree = Tree()
    tree.feed(text)
    tree.close()
    return tree.root


def section(command, body):
    return ("\n####################################################\n"
            "# Execute Command: " + command +
            "\n####################################################\n" + body + "\n")


def info_text(kind="IB", *, health="OK", interfaces="", firmware="", system="PUBLIC-MODEL",
              extra=""):
    text = "Switch Type: " + kind + " (" + system + ")\nCollect Time: 2026-01-02 03:04:05\n"
    if health is not None:
        text += section("nv show system health", "status  " + health)
    if interfaces:
        text += section("nv show interface", interfaces)
    if firmware:
        text += section("nv show platform firmware", firmware)
    return text + extra


def page_html(page, *, eth=None, ib=(), nv=(), unbound=None, eth_notice="", ib_notice="",
              nv_notice="", **keywords):
    """Render the real page; Switch Status lists are passed as device lists."""
    eth_devices = {env: list(items) for env, items in (eth or {}).items()}
    for env, items in (unbound or {}).items():
        eth_devices["unbound_" + env] = list(items)
    eth_count = sum(len(items) for env, items in (eth or {}).items())
    return page.build_html(
        {"error": eth_notice} if eth_notice else {}, "", eth_count,
        ib_notice, "", len(ib), eth_devices, list(ib),
        "", "", STATS, None, 0,
        "", "", STATS, None, 0,
        nv_notice, "", len(nv), list(nv),
        "", "", STATS, None, 0,
        {}, {}, {}, {},
        {"available": False, "counts": {}, "environment_updates": {}, "devices": []},
        **keywords,
    )


def rows_of(document):
    return document.find_all("tr", cls="lst-row")


def row_for(document, hostname):
    matches = [row for row in rows_of(document) if row.attrs.get("data-hn") == hostname.lower()]
    if len(matches) != 1:
        raise AssertionError("expected one list row for %s, got %d" % (hostname, len(matches)))
    return matches[0]


def badge_of(row):
    badges = [node for node in row.iter() if node.tag == "span" and "h-badge" in node.classes()]
    if len(badges) != 1:
        raise AssertionError("expected one Health badge, got %d" % len(badges))
    css = [name for name in badges[0].classes() if name != "h-badge"]
    return css[0], badges[0].text(), badges[0].parent


def pies_of(document, group):
    return {figure.attrs["data-cat"]: figure for figure in document.find_all("figure", cls="pie")
            if figure.attrs.get("data-group") == group}


def pie_counts(figure):
    return tuple(int(figure.attrs["data-" + bucket]) for bucket in ("ok", "notok", "offline"))


def buttons_of(document, group):
    return [button for button in document.find_all("button", cls="grp-btn")
            if button.attrs.get("data-group") == group]


def button_number(button, cls="grp-num"):
    found = [node for node in button.iter() if cls in node.classes()]
    if len(found) != 1:
        raise AssertionError("button number %s missing in %r" % (cls, button.text()))
    return int(found[0].text())


def make_switch(page, hostname, kind, health="OK", **fields):
    """A parsed ordinary switch: kind is the collector header word."""
    family = {"ETH": "ETH", "IB": "IB", "NVLINK": "NVL"}[kind]
    device = page.parse_info_file(hostname, info_text(kind, health=health))
    device["sw_type"] = family
    device.update(fields)
    return device


def make_missing(page, hostname, sw_type, **fields):
    device = page.make_missing_switch(hostname, sw_type)
    device.update(fields)
    return device


def ufm_server(page, hostname, health="ok"):
    device = page.make_missing_switch(hostname, "UFM")
    device.update(device_kind="ufm", health=health, version="PUBLIC-UFM")
    return device


class SwitchStatusV2Tests(unittest.TestCase):
    """8.13 C1/V2 (R-027): three buckets, CSV classification, pies and list."""

    @classmethod
    def setUpClass(cls):
        cls.page = load_page()

    def test_list_health_label_and_three_bucket_keep_raw_facts(self):
        # Guide :2216 / issue 13.4 item 2: ok -> green; missing -> yellow;
        # every other collected value (FATAL, unknown, N/A, empty) -> red.
        host = "public-switch.example.test"
        for kind in ("ETH", "IB", "NVLINK"):
            for source, raw, css, label, bucket in (
                    ("OK", "ok", "h-ok", "OK", "ok"), ("ok", "ok", "h-ok", "OK", "ok"),
                    ("Not OK", "not ok", "h-err", "NOT OK", "notok"),
                    ("FATAL", "not ok", "h-err", "NOT OK", "notok"),
                    ("DEGRADED", "not ok", "h-err", "NOT OK", "notok"),
                    ("", "unknown", "h-unk", "NOT OK", "notok"),
                    ("unknown", "unknown", "h-unk", "NOT OK", "notok"),
                    ("N/A", "n/a", "h-unk", "NOT OK", "notok"),
                    (None, "unknown", "h-unk", "NOT OK", "notok")):
                with self.subTest(kind=kind, source=source):
                    device = self.page.parse_info_file(host, info_text(kind, health=source))
                    self.assertEqual(raw, device["health"], "C4 normalised health is unchanged")
                    before = copy.deepcopy(device)
                    row = row_for(parse_html(self.page.render_sw_list_row(device)), host)
                    self.assertEqual(before, device, "display never rewrites raw facts")
                    self.assertEqual(bucket, row.attrs.get("data-bucket"))
                    self.assertEqual((css, label), badge_of(row)[:2])
                    if source and bucket == "notok":
                        # Guide :2206: the red Health shows the collected original value.
                        self.assertEqual(source, device.get("health_raw"))
                        self.assertIn(source, badge_of(row)[2].attrs.get("title", ""))
            for attempted in (True, False):
                with self.subTest(kind=kind, source="missing", attempted=attempted):
                    device = make_missing(self.page, host, {"NVLINK": "NVL"}.get(kind, kind),
                                          collection_attempted=attempted,
                                          collection_error="PUBLIC collection evidence")
                    rendered = self.page.render_sw_list_row(device)
                    row = row_for(parse_html(rendered), host)
                    self.assertEqual("offline", row.attrs.get("data-bucket"))
                    self.assertEqual(("h-miss", "NOT OK"), badge_of(row)[:2])
                    self.assertIn("lst-row-miss", row.classes())
                    self.assertIn("collect-fail" if attempted else "collect-pending", rendered)
                    self.assertIn("PUBLIC collection evidence", rendered)
        for raw, css, label, bucket in (("ok", "h-ok", "OK", "ok"),
                                        ("warning", "h-warn", "WARNING", "notok"),
                                        ("error", "h-err", "ERROR", "notok"),
                                        ("unknown", "h-unk", "UNKNOWN", "notok"),
                                        ("", "h-unk", "N/A", "notok"),
                                        ("missing", "h-miss", "MISSING", "offline")):
            with self.subTest(kind="UFM", raw=raw):
                device = ufm_server(self.page, "public-ufm.example.test", raw)
                row = row_for(parse_html(self.page.render_sw_list_row(device)),
                              "public-ufm.example.test")
                self.assertEqual((css, label), badge_of(row)[:2], "UFM keeps its own label")
                self.assertEqual(bucket, row.attrs.get("data-bucket"))

    def test_collected_unknown_and_uncollected_share_a_label_not_a_bucket(self):
        # Guide :2200: the same NOT OK text never merges the red and yellow buckets.
        unknown = make_switch(self.page, "public-a.example.test", "IB", "unknown")
        missing = make_missing(self.page, "public-b.example.test", "IB")
        html = parse_html(self.page.render_sw_list_row(unknown) +
                          self.page.render_sw_list_row(missing))
        first, second = row_for(html, "public-a.example.test"), row_for(html, "public-b.example.test")
        self.assertEqual(badge_of(first)[1], badge_of(second)[1])
        self.assertEqual(("notok", "offline"),
                         (first.attrs.get("data-bucket"), second.attrs.get("data-bucket")))

    def test_family_comes_from_the_csv_list_not_the_collection_header(self):
        # Guide :2202: a CSV ib device whose collector header says NVLINK is IB
        # and counts sw* ports, not acp* ports.
        self.assertIn("family", inspect.signature(self.page.parse_info_file).parameters)
        interfaces = ("sw1p1 up 800G 4096 ib Active LinkUp\n"
                      "sw2p1 down 800G 4096 ib Down Disabled\n"
                      "acp1 up 400G 256 nvl Active LinkUp\n")
        device = self.page.parse_info_file(
            "public-ib-leaf01.example.test",
            info_text("NVLINK", health="FATAL", interfaces=interfaces), family="IB")
        self.assertEqual("IB", device["sw_type"])
        self.assertEqual((1, 2, 1), (device["interfaces_up"], device["interfaces_total"],
                                     device["interfaces_down_count"]))
        row = row_for(parse_html(self.page.render_sw_list_row(device)),
                      "public-ib-leaf01.example.test")
        self.assertEqual(("ib", "ib-leaf"), (row.attrs.get("data-family"), row.attrs.get("data-cat")))
        self.assertEqual("notok", row.attrs.get("data-bucket"))

    def test_subclass_from_csv_template_or_hostname_without_other_or_missing_group(self):
        # Guide :2202: Ethernet by template; InfiniBand Spine/Leaf and NVLink POD by
        # hostname; a missing device stays in its CSV subclass; no "other" group.
        cases = (
            ("ETH", "public-a01.example.test", {"template": "oobofoob-leaf"}, "oob2"),
            ("ETH", "public-a02.example.test", {"template": "oob-su-leaf"}, "oob"),
            ("ETH", "public-a03.example.test", {"template": "border"}, "oob"),
            ("ETH", "public-a04.example.test", {"template": "tan-cp-leaf"}, "tan"),
            ("ETH", "public-a05.example.test", {"template": "", "csv_type": "spx"}, "spx"),
            ("ETH", "public-oob-tan-cl.example.test", {"template": ""}, None),
            ("IB", "public-spine01.example.test", {}, "ib-spine"),
            ("IB", "public-leaf01.example.test", {}, "ib-leaf"),
            ("IB", "public-core01.example.test", {}, None),
            ("NVL", "pod7-nvsw01", {}, "nv-group-pod7"),
            ("NVL", "public-nvl.example.test", {}, None),
        )
        for sw_type, host, fields, expected in cases:
            for missing in (False, True):
                with self.subTest(host=host, missing=missing):
                    if missing:
                        device = make_missing(self.page, host, sw_type, **fields)
                    else:
                        device = make_switch(self.page, host,
                                             {"NVL": "NVLINK"}.get(sw_type, sw_type), **fields)
                    row = row_for(parse_html(self.page.render_sw_list_row(device)), host)
                    family = {"ETH": "eth", "IB": "ib", "NVL": "nvl"}[sw_type]
                    if expected is None:
                        self.assertIsNone(row.attrs.get("data-group"), "unclassified rows are not counted")
                        self.assertNotEqual("other", row.attrs.get("data-cat"))
                    else:
                        self.assertEqual(expected, row.attrs.get("data-cat"))
                        self.assertEqual("production-" + family, row.attrs.get("data-group"))
                    self.assertNotEqual("missing", row.attrs.get("data-cat"))
        dynamic = make_missing(self.page, "AIR-EXAMPLE-Unknown01", "ETH", environment="air",
                               dynamic_dhcp=True, template="oob-leaf",
                               collection_attempted=False)
        row = row_for(parse_html(self.page.render_sw_list_row(dynamic)), "AIR-EXAMPLE-Unknown01")
        self.assertIsNone(row.attrs.get("data-group"), "a device outside the CSV is not counted")
        self.assertEqual("offline", row.attrs.get("data-bucket"))

    def issue_13_2_devices(self):
        """Issue 13.2 shape: UFM 2; Spine 35 OK + 1 missing; Leaf 62 OK + 2 FATAL + 4 missing."""
        devices = [ufm_server(self.page, "public-ufm%02d.example.test" % n) for n in (1, 2)]
        devices += [make_switch(self.page, "public-spine%03d.example.test" % n, "IB")
                    for n in range(1, 36)]
        devices.append(make_missing(self.page, "public-spine036.example.test", "IB"))
        devices += [make_switch(self.page, "public-leaf%03d.example.test" % n, "IB")
                    for n in range(1, 63)]
        for n in (63, 64):
            # CSV ib, collector header NVLINK, health FATAL (issue 13.2 second bullet).
            devices.append(self.page.parse_info_file(
                "public-leaf%03d.example.test" % n, info_text("NVLINK", health="FATAL"),
                family="IB"))
        devices += [make_missing(self.page, "public-leaf%03d.example.test" % n, "IB")
                    for n in range(65, 69)]
        return devices

    def test_issue_13_2_shape_pies_buttons_and_rows_share_one_source(self):
        self.assertIn("family", inspect.signature(self.page.parse_info_file).parameters)
        devices = self.issue_13_2_devices()
        document = parse_html(page_html(self.page, ib=devices))
        pies = pies_of(document, "production-ib")
        self.assertEqual({"ib-ufm": (2, 0, 0), "ib-spine": (35, 0, 1), "ib-leaf": (62, 2, 4)},
                         {key: pie_counts(figure) for key, figure in pies.items()})
        self.assertEqual("IB · Leaf（68）", pies["ib-leaf"].find("figcaption").text().strip())
        self.assertEqual("IB · Spine（36）", pies["ib-spine"].find("figcaption").text().strip())
        self.assertEqual("IB · UFM（2）", pies["ib-ufm"].find("figcaption").text().strip())
        rows = [row for row in rows_of(document) if row.attrs.get("data-group") == "production-ib"]
        self.assertEqual(106, len(rows))
        for key, figure in pies.items():
            sub_rows = [row for row in rows if row.attrs.get("data-cat") == key]
            for bucket, count in zip(("ok", "notok", "offline"), pie_counts(figure)):
                self.assertEqual(count, sum(row.attrs.get("data-bucket") == bucket for row in sub_rows),
                                 (key, bucket))
        # Red frame when a red or yellow device exists (guide :2206).
        self.assertIn("pie-alert", pies["ib-leaf"].classes())
        self.assertIn("pie-alert", pies["ib-spine"].classes())
        self.assertNotIn("pie-alert", pies["ib-ufm"].classes())
        # A single-state subclass draws one complete ring (guide :2206, issue 16.5).
        segments = pies["ib-ufm"].find_all("circle", cls="pie-seg")
        self.assertEqual(1, len(segments))
        self.assertNotIn("stroke-dasharray", segments[0].attrs)
        self.assertEqual("ok", segments[0].attrs.get("data-bucket"))
        self.assertEqual(3, len(pies["ib-leaf"].find_all("circle", cls="pie-seg")))
        buttons = buttons_of(document, "production-ib")
        self.assertEqual(["all", "sw", "bios", "ssd", "cpld", "upgrade", "check"],
                         [button.attrs.get("data-button") for button in buttons])
        by_name = {button.attrs["data-button"]: button for button in buttons}
        self.assertEqual(106, button_number(by_name["all"]))
        self.assertEqual(7, button_number(by_name["check"]))
        self.assertEqual((5, 2), (button_number(by_name["check"], "grp-nodata"),
                                  button_number(by_name["check"], "grp-notok")))
        # Red + yellow of each pie == that subclass's share of the group's check count.
        self.assertEqual(button_number(by_name["check"]),
                         sum(sum(pie_counts(figure)[1:]) for figure in pies.values()))
        self.assertIn("grp-warn", by_name["all"].classes())
        self.assertIn("grp-warn", by_name["check"].classes())
        header = [node for node in document.find_all("tr", cls="lst-grp")
                  if node.attrs.get("data-group") == "production-ib"]
        self.assertEqual(1, len(header))
        self.assertEqual("Production / InfiniBand（106）", header[0].text().strip())
        subheads = [node.text().strip() for node in document.find_all("tr", cls="lst-cat")
                    if node.attrs.get("data-group") == "production-ib"]
        self.assertEqual(["UFM Servers（2）", "Spine（36）", "Leaf（68）"], subheads)
        self.assertNotIn("未采集 · 可能掉线", page_html(self.page, ib=devices))

    def test_group_buttons_fixed_order_grey_targets_and_zero_counts(self):
        # Guide :2206 / 8.16: without targets the component and upgrade buttons are
        # grey and disabled, not hidden; check writes both kinds even when 0.
        devices = [make_switch(self.page, "public-leaf%02d.example.test" % n, "IB") for n in (1, 2)]
        document = parse_html(page_html(self.page, ib=devices))
        buttons = {button.attrs["data-button"]: button for button in buttons_of(document, "production-ib")}
        self.assertEqual(["all", "sw", "bios", "ssd", "cpld", "upgrade", "check"], list(buttons))
        for name in ("sw", "bios", "ssd", "cpld", "upgrade"):
            self.assertIn("disabled", buttons[name].attrs, name)
            self.assertIn("grp-off", buttons[name].classes(), name)
        for name in ("all", "check"):
            self.assertNotIn("disabled", buttons[name].attrs, name)
            self.assertIn("grp-ok", buttons[name].classes(), name)
        self.assertEqual((2, 0, 0, 0), (button_number(buttons["all"]), button_number(buttons["check"]),
                                        button_number(buttons["check"], "grp-nodata"),
                                        button_number(buttons["check"], "grp-notok")))
        self.assertIn("NO DATA", buttons["check"].text())
        self.assertIn("NOT OK", buttons["check"].text())

    def test_empty_groups_hidden_and_uncounted_devices_stay_in_the_list(self):
        # Guide :2200/:2202: devices outside the current CSV and rows the CSV cannot
        # classify are listed but never enter a pie or a group denominator; the
        # unclassifiable host names are listed in red above the pies.
        tan = make_switch(self.page, "public-tan01.example.test", "ETH", template="tan-leaf",
                          environment="production")
        broken = make_switch(self.page, "public-broken01.example.test", "ETH", template="",
                             environment="production")
        dynamic = make_missing(self.page, "DISCOVERED-CUMULUS-020000000099", "ETH",
                               environment="production", dynamic_dhcp=True,
                               template="tan-leaf", collection_attempted=False)
        unbound = make_missing(self.page, "DISCOVERED-NVOS-020000000098", "NVOS",
                               environment="production", dynamic_dhcp=True,
                               collection_attempted=False)
        html = page_html(self.page, eth={"production": [tan, broken, dynamic]},
                         unbound={"production": [unbound]})
        document = parse_html(html)
        self.assertEqual({"tan": (1, 0, 0)},
                         {key: pie_counts(figure)
                          for key, figure in pies_of(document, "production-eth").items()})
        self.assertEqual([], [figure for figure in document.find_all("figure", cls="pie")
                              if figure.attrs.get("data-group") != "production-eth"])
        notice = document.find("div", cls="pie-unclassified")
        self.assertIsNotNone(notice, "unclassifiable CSV rows are listed in red above the pies")
        self.assertEqual(["public-broken01.example.test"],
                         [node.text() for node in notice.find_all("span", cls="pie-unclassified-host")])
        for host in ("public-broken01.example.test", "DISCOVERED-CUMULUS-020000000099",
                     "DISCOVERED-NVOS-020000000098"):
            self.assertIsNone(row_for(document, host).attrs.get("data-group"), host)
        self.assertEqual(1, button_number({b.attrs["data-button"]: b for b in
                                           buttons_of(document, "production-eth")}["all"]))
        groups = {node.attrs.get("data-group") for node in document.find_all("tr", cls="lst-grp")}
        self.assertEqual({"production-eth"}, groups, "a group without devices is not shown")
        for text in ("其他（", "未采集 · 可能掉线"):
            self.assertNotIn(text, "".join(node.text() for node in document.find_all("tr", cls="lst-cat")))

    def test_hash_keys_and_switch_scripts_are_generated_from_python_constants(self):
        keys = getattr(self.page, "SWITCH_HASH_KEYS", None)
        self.assertIsNotNone(keys, "hash keys are a Python constant (guide :2209)")
        # Guide :2206: the view, each group's button, the pie tag and the search
        # are all restorable from the address hash.
        self.assertEqual({"view", "btn", "pie", "q"}, set(keys))
        html = page_html(self.page, ib=[make_switch(self.page, "public-leaf01.example.test", "IB")])
        declared = re.search(r"const SWITCH_HASH_KEYS = (\[[^\]]*\]);", html)
        self.assertIsNotNone(declared)
        self.assertEqual(list(keys), json.loads(declared.group(1)))
        for name, constant in (("SWITCH_VIEWS", ["pie", "list"]),
                               ("SWITCH_GROUP_BUTTONS",
                                ["all", "sw", "bios", "ssd", "cpld", "upgrade", "check"]),
                               ("SWITCH_BUCKETS", ["ok", "notok", "offline"])):
            found = re.search(r"const " + name + r" = (\[[^\]]*\]);", html)
            self.assertIsNotNone(found, name)
            self.assertEqual(constant, json.loads(found.group(1)), name)
            self.assertEqual(constant, list(getattr(self.page, name)), name)
        for handler in ("setView", "applySwitchFilters", "selectPieSlice", "selectGroupButton",
                        "clearSwitchFilters", "copyVisibleHostnames", "toggleProblemsFirst",
                        "parseSwitchHash", "switchHashSuffix"):
            self.assertRegex(html, r"function " + handler + r"\(")
        reload_body = html.split("function reloadActiveTab()", 1)[1].split("\n}", 1)[0]
        self.assertIn("switchHashSuffix()", reload_body, "refresh keeps the Switch Status state")
        location_body = html.split("function tabFromLocation()", 1)[1].split("\n}", 1)[0]
        self.assertIn("split('?')", location_body)
        # An old 'card' preference falls back to the pie view (guide :2206).
        self.assertIn("=== 'list' ? 'list' : 'pie'", html)
        self.assertNotIn("setView('card')", html)

    def test_card_view_is_removed(self):
        self.assertFalse(hasattr(self.page, "render_eth_card"))
        self.assertFalse(hasattr(self.page, "build_switch_cards_html"))
        html = page_html(self.page, ib=[make_switch(self.page, "public-leaf01.example.test", "IB")])
        for fragment in ('class="sw-card', 'id="card-grid"', 'id="btn-card"', "card-env",
                         "toggleCardSection", "filterCards"):
            self.assertNotIn(fragment, html)
        document = parse_html(html)
        toggles = document.find_all("button", cls="vtbtn")
        self.assertEqual([("btn-pie", "饼图"), ("btn-list", "列表")],
                         [(node.attrs.get("id"), node.text().strip()) for node in toggles])

    def test_list_top_controls_and_left_aligned_toolbars(self):
        html = page_html(self.page, ib=[make_switch(self.page, "public-leaf01.example.test", "IB")])
        document = parse_html(html)
        controls = document.find("div", id="switch-list-controls")
        self.assertIsNotNone(controls)
        found = [(node.tag, node.attrs.get("id"), node.attrs.get("type"))
                 for node in controls.iter() if node.tag in {"input", "button", "select"}]
        self.assertEqual([("input", "eth-search", "text"),
                          ("input", "switch-problems-first", "checkbox"),
                          ("button", "switch-clear", "button"),
                          ("button", "switch-copy-hosts", "button")], found)
        self.assertNotIn("checked", controls.find("input", id="switch-problems-first").attrs)
        self.assertIsNotNone(document.find("div", id="switch-pie-tag"))
        # Guide :2206: flex 1 -> flex 0 1 auto; the ZTP page loses min-width:360px.
        eth_meta = re.search(r"#eth-toolbar \.eth-meta \{([^}]*)\}", html)
        ztp_meta = re.search(r"\.ztp-toolbar \.ztp-meta \{([^}]*)\}", html)
        self.assertIsNotNone(eth_meta)
        self.assertIsNotNone(ztp_meta)
        for rule in (eth_meta.group(1), ztp_meta.group(1)):
            self.assertIn("flex: 0 1 auto", rule)
            self.assertNotRegex(rule, r"flex:\s*1\s*;")
        self.assertNotIn("min-width:360px", ztp_meta.group(1))
        self.assertNotIn("min-width: 360px", ztp_meta.group(1))

    def test_display_values_are_escaped(self):
        hostile = 'public-<b>&"x.example.test'
        broken = make_switch(self.page, hostile, "ETH", template="", environment="production")
        html = page_html(self.page, eth={"production": [broken]})
        self.assertFalse("<b>&" in html, "a hostile hostname reached the page unescaped")
        notice = parse_html(html).find("div", cls="pie-unclassified")
        self.assertIsNotNone(notice)
        self.assertEqual([hostile], [node.text() for node in
                                     notice.find_all("span", cls="pie-unclassified-host")])


def firmware_rows(rows, *, width=30, header=True, swapped=False):
    """A PUBLIC `nv show platform firmware` table: Name / Actual FW / Part Number / FW Source."""
    if swapped:
        head = "Name      " + "Part Number".ljust(width) + "Actual FW          FW Source\n"
    else:
        head = "Name      " + "Actual FW".ljust(width) + "Part Number        FW Source\n"
    rule = "--------  " + ("-" * (width - 2)).ljust(width) + "-----------------  ---------\n"
    body = "".join(name.ljust(10) + actual.ljust(width) + part.ljust(19) + source + "\n"
                   for name, actual, part, source in rows)
    return (head + rule if header else "") + body


OWNER_SIX = ("CPLD000232_REV0900", "CPLD000383_REV1001", "CPLD000389_REV0600",
             "CPLD000368_REV0300", "CPLD000389_REV0600", "CPLD000368_REV0300")


def cpld_table(values, *, order=None, extra=(), **keywords):
    rows = [("ASIC", "PUBLIC-ASIC-FW", "N/A", "N/A"), ("BIOS", "PUBLIC-BIOS-FW", "N/A", "N/A")]
    slots = [("CPLD%d" % (index + 1), value, "N/A", "N/A") for index, value in enumerate(values)]
    if order is not None:
        slots = [slots[index] for index in order]
    rows += slots + [("SSD", "PUBLIC-SSD-FW", "N/A", "N/A"),
                     ("transceiver", "N/A", "N/A", "N/A")] + list(extra)
    return firmware_rows(rows, **keywords)


def cpld_short(cell):
    """The CPLD short string of one cell; a missing one is an assertion failure, not a crash."""
    node = cell.find("span", cls="cpld-short")
    if node is None:
        raise AssertionError("no CPLD short string in %r" % cell.text())
    return node.text()


def cpld_cell(row):
    """The CPLD cell: the td directly after the SSD column."""
    cells = [node for node in row.children if not isinstance(node, str) and node.tag == "td"]
    return cells[6]


class SwitchStatusV3CpldTests(unittest.TestCase):
    """8.15 C1/V3 (R-028): CPLD per slot, short string, detail and full copy."""

    @classmethod
    def setUpClass(cls):
        cls.page = load_page("_switch_status_v3_page")

    def parsed(self, firmware, host="public-ib-leaf01.example.test"):
        device = self.page.parse_info_file(host, info_text("IB", firmware=firmware), family="IB")
        return device, row_for(parse_html(self.page.render_sw_list_row(device)), host)

    def test_owner_six_slot_example_and_full_slot_facts(self):
        # Issue :1118/:1420 owner example; guide :2240.
        device, row = self.parsed(cpld_table(OWNER_SIX))
        self.assertEqual([(n, value) for n, value in enumerate(OWNER_SIX, 1)],
                         [(slot["slot"], slot["actual"]) for slot in device.get("cpld_slots", [])])
        cell = cpld_cell(row)
        self.assertEqual("232_0900/383_1001/389_0600/368_0300",
                         cpld_short(cell))
        full = cell.attrs.get("data-cpld-full")
        self.assertEqual(" ".join("CPLD%d=%s" % (n, value) for n, value in enumerate(OWNER_SIX, 1)), full)
        detail = cell.find("div", cls="cpld-detail")
        self.assertIsNotNone(detail)
        self.assertEqual([("CPLD%d" % n, value) for n, value in enumerate(OWNER_SIX, 1)],
                         [(node.attrs.get("data-slot"), node.attrs.get("data-actual"))
                          for node in detail.find_all("div", cls="cpld-slot")])
        # The old triple and its consumers are unchanged (guide :2234, :2247).
        self.assertEqual(("PUBLIC-BIOS-FW", "PUBLIC-SSD-FW", "PUBLIC-ASIC-FW"),
                         self.page.parse_firmware_versions(cpld_table(OWNER_SIX)))

    def test_four_slots_leading_zero_versions_and_numeric_slot_order(self):
        values = ["CPLD000120_REV0012", "CPLD000121_REV0001", "CPLD000120_REV0012",
                  "CPLD000122_REV0100", "CPLD000123_REV0200", "CPLD000124_REV0300",
                  "CPLD000125_REV0400", "CPLD000126_REV0500", "CPLD000127_REV0600",
                  "CPLD000128_REV0700"]
        # The table lists CPLD10 before CPLD2: slot 2 still precedes slot 10.
        order = [0, 9, 1, 2, 3, 4, 5, 6, 7, 8]
        device, row = self.parsed(cpld_table(values, order=order))
        self.assertEqual(list(range(1, 11)), [slot["slot"] for slot in device["cpld_slots"]])
        self.assertEqual("120_0012/121_0001/122_0100/123_0200/124_0300/125_0400/"
                         "126_0500/127_0600/128_0700",
                         cpld_short(cpld_cell(row)))
        four = ["CPLD000010_REV0009", "CPLD000011_REV0010", "CPLD000010_REV0011", "CPLD000012_REV0001"]
        _, row = self.parsed(cpld_table(four))
        # Same model, other version: both kept; versions keep their leading zeros.
        self.assertEqual("10_0009/11_0010/10_0011/12_0001",
                         cpld_short(cpld_cell(row)))

    def test_partial_na_slot_is_written_with_its_slot_number(self):
        values = ["CPLD000232_REV0900", "CPLD000232_REV0900", "N/A", "CPLD000368_REV0300"]
        device, row = self.parsed(cpld_table(values))
        self.assertEqual(["CPLD000232_REV0900", "CPLD000232_REV0900", "N/A", "CPLD000368_REV0300"],
                         [slot["actual"] for slot in device["cpld_slots"]])
        cell = cpld_cell(row)
        self.assertEqual("232_0900/CPLD3=N/A/368_0300", cpld_short(cell))
        self.assertIn("CPLD3=N/A", cell.attrs.get("data-cpld-full", ""))
        self.assertEqual(4, len(cell.find("div", cls="cpld-detail").find_all("div", cls="cpld-slot")))

    def test_no_cpld_rows_missing_header_and_wrong_columns_show_dash(self):
        for label, firmware in (
                ("no CPLD rows", firmware_rows([("BIOS", "PUBLIC-BIOS-FW", "N/A", "N/A")])),
                ("no header", cpld_table(OWNER_SIX, header=False)),
                ("wrong columns", cpld_table(OWNER_SIX, swapped=True))):
            with self.subTest(label=label):
                device, row = self.parsed(firmware)
                self.assertEqual([], device.get("cpld_slots"))
                cell = cpld_cell(row)
                self.assertEqual("—", cell.text().strip())
                self.assertIsNone(cell.find("div", cls="cpld-detail"))
        missing = make_missing(self.page, "public-ib-leaf09.example.test", "IB")
        self.assertNotIn("cpld-short", self.page.render_sw_list_row(missing))
        ufm = ufm_server(self.page, "public-ufm01.example.test")
        cell = cpld_cell(row_for(parse_html(self.page.render_sw_list_row(ufm)), "public-ufm01.example.test"))
        self.assertEqual("—", cell.text().strip())

    def test_multiword_actual_fw_is_kept_whole(self):
        values = ["PUBLIC CPLD BUILD 7", "CPLD000232_REV0900"]
        device, row = self.parsed(cpld_table(values, width=30))
        self.assertEqual("PUBLIC CPLD BUILD 7", device["cpld_slots"][0]["actual"])
        cell = cpld_cell(row)
        self.assertEqual("PUBLIC CPLD BUILD 7/232_0900", cpld_short(cell))
        self.assertIn("CPLD1=PUBLIC CPLD BUILD 7", cell.attrs.get("data-cpld-full"))

    def test_cpld_column_follows_ssd_and_values_are_escaped(self):
        html = page_html(self.page, ib=[self.parsed(cpld_table(OWNER_SIX))[0]])
        heads = [node.text() for node in parse_html(html).find_all("th")]
        index = heads.index("SSD 版本")
        self.assertEqual("CPLD 版本", heads[index + 1])
        hostile = ['CPLD000232_REV<b>"&']
        device, row = self.parsed(cpld_table(hostile))
        rendered = self.page.render_sw_list_row(device)
        self.assertFalse('<b>"&' in rendered)
        self.assertEqual("CPLD1=" + hostile[0], cpld_cell(row).attrs.get("data-cpld-full"))
        self.assertRegex(html, r"function toggleCpldDetail\(")
        self.assertRegex(html, r"function copyCpld\(")


OWNER_CPLD_FILE = ("FUI000643_BURN_BM_CPLD000232_REV0900_CPLD000383_REV1001_CPLD000389_REV0600_"
                   "CPLD000368_REV0300_CPLD000389_REV0600_CPLD000368_REV0300_OPN.vme")


def global_yaml(*, eth="5.18.1", ib='"25.03.1014"', nvl="25.02.4347", ufm='"2.6.1-5"',
                bios="0ACQF_06.01.009", ssd="CE00A474", cpld=OWNER_CPLD_FILE,
                upgrade=True, extra_switch=""):
    """A PUBLIC 01-global.yaml in the template's list-of-one-key-families shape (issue 20.2)."""
    text = "common:\n  mgmt:\n    timezone: UTC\nswitches:\n"
    if eth is not None:
        text += "- eth:\n    version: %s\n" % eth
    if ib is not None:
        text += "- ib:\n    version: %s\n" % ib
        if upgrade:
            text += "    upgrade:\n      packages:\n"
            if bios is not None:
                text += "        bios:\n          file: PUBLIC-BIOS.bin\n          version: %s\n" % bios
            if ssd is not None:
                text += "        ssd:\n          version: %s\n" % ssd
            if cpld is not None:
                text += "        cpld:\n          burn:\n            file: %s\n" % cpld
    if nvl is not None:
        text += "- nvl:\n    version: %s\n" % nvl
    text += extra_switch
    if ufm is not None:
        text += "servers:\n- ufm:\n    version: %s\n" % ufm
    return text


def ib_switch(page, host, *, version="25.03.1014", bios="0ACQF_06.01.009", ssd="CE00A474",
              cpld=OWNER_SIX, health="OK"):
    firmware = cpld_table(list(cpld)) if cpld is not None else ""
    text = info_text("IB", health=health, firmware=firmware)
    text += section("nv show system version", "product-release  " + version)
    device = page.parse_info_file(host, text, family="IB")
    device["bios_version"], device["ssd_version"] = bios, ssd
    return device


def upgrade_cell(row):
    cells = [node for node in row.children if not isinstance(node, str) and node.tag == "td"]
    heads = [cell for cell in cells if "upg-cell" in cell.classes()]
    if len(heads) != 1:
        raise AssertionError("expected one 组件需升级 cell, got %d" % len(heads))
    return heads[0]


def upgrade_tags(row):
    return [(node.text(), [name for name in node.classes() if name != "upg-tag"][0])
            for node in upgrade_cell(row).find_all("span", cls="upg-tag")]


class SwitchStatusV4VersionTests(unittest.TestCase):
    """8.16 C1/V4 (R-029, Q-080): optional targets, component differences, unknown."""

    @classmethod
    def setUpClass(cls):
        cls.page = load_page("_switch_status_v4_page")

    def targets(self, text=None, **keywords):
        loader = getattr(self.page, "load_version_targets", None)
        self.assertIsNotNone(loader, "targets come from one named reader (guide :2259-2269)")
        before = repository_page_log_state()
        with tempfile.TemporaryDirectory(prefix="v4-global-", dir=owned_test_root()) as folder:
            path = Path(folder) / "01-global.yaml"
            if text is not False:
                path.write_text(global_yaml(**keywords) if text is None else text, encoding="utf-8")
            # The page's own log goes to this test's folder, not the repository (lane leftover).
            with mock.patch.object(self.page, "LOG_FILE", Path(folder) / "generate-monitor.log"):
                targets = loader(path)
        self.assertEqual(before, repository_page_log_state(),
                         "the target reader never creates or changes %s" % REPOSITORY_PAGE_LOG)
        return targets

    def test_unreadable_targets_never_write_the_repository_page_log(self):
        # A missing or unparsable 01-global.yaml is logged by the page (guide :2259-2269);
        # that log line stays inside the test's own folder (targets() checks the file).
        self.assertEqual({}, self.targets(text=False))
        self.assertEqual({}, self.targets(text="switches: [unclosed\n"))

    def row(self, device, family, targets):
        return row_for(parse_html(self.page.render_sw_list_row(device, family, targets)),
                       device["hostname"])

    def test_targets_follow_each_family_and_keep_cpld_slot_order(self):
        targets = self.targets()
        six = [segment for segment in OWNER_SIX]
        self.assertEqual({"eth": {"sw": "5.18.1"},
                          "ib": {"sw": "25.03.1014", "bios": "0ACQF_06.01.009", "ssd": "CE00A474",
                                 "cpld": six},
                          "nvl": {"sw": "25.02.4347"}, "ufm": {"sw": "2.6.1-5"}}, targets)
        # A missing package does not block another; a missing family stays absent.
        self.assertEqual({"sw": "25.03.1014", "ssd": "CE00A474"},
                         self.targets(bios=None, cpld=None)["ib"])
        self.assertNotIn("nvl", self.targets(nvl=None))
        self.assertEqual({"sw": "25.03.1014"}, self.targets(upgrade=False)["ib"])
        # A duplicated family (guide :2267) disables only that family.
        doubled = self.targets(extra_switch="- eth:\n    version: 9.9.9\n")
        self.assertNotIn("eth", doubled)
        self.assertEqual("25.03.1014", doubled["ib"]["sw"])
        self.assertEqual({}, self.targets(text=False))
        self.assertEqual({}, self.targets(text="switches: [unclosed\n"))

    def test_component_matrix_unknown_mismatch_and_upgrade_once(self):
        targets = self.targets(ib='"25-03-1014"')
        host = "public-ib-leaf01.example.test"
        cases = (
            # label, device keywords, expected tags, diff, upgrade
            ("all equal", {}, [("NA", "upg-ok")], "", "0"),
            ("older target only differs", {"version": "25.04.0001"}, [("SW", "upg-warn")], "sw", "1"),
            ("partial CPLD N/A, SW same", {"cpld": OWNER_SIX[:2] + ("N/A",) + OWNER_SIX[3:]},
             [("CPLD Unknown", "upg-warn")], "", "0"),
            ("partial CPLD N/A, SW differs", {"version": "25.01.0001",
                                              "cpld": OWNER_SIX[:2] + ("N/A",) + OWNER_SIX[3:]},
             [("SW", "upg-warn"), ("CPLD Unknown", "upg-warn")], "sw", "1"),
            ("CPLD revision differs", {"cpld": OWNER_SIX[:1] + ("CPLD000383_REV1002",) + OWNER_SIX[2:]},
             [("CPLD", "upg-warn")], "cpld", "1"),
            ("CPLD slot count differs", {"cpld": OWNER_SIX[:4]}, [("NA", "upg-ok")], "", "0"),
            ("CPLD slot model differs", {"cpld": ("CPLD000999_REV0900",) + OWNER_SIX[1:]},
             [("NA", "upg-ok")], "", "0"),
            ("no CPLD rows", {"cpld": None}, [("CPLD Unknown", "upg-warn")], "", "0"),
            ("BIOS not specified", {"bios": "NA"}, [("BIOS Unknown", "upg-warn")], "", "0"),
            ("BIOS and SSD differ", {"bios": "0ACQF_06.01.008", "ssd": "CE00A473"},
             [("BIOS", "upg-warn"), ("SSD", "upg-warn")], "bios ssd", "1"),
        )
        for label, fields, tags, diff, upgrade in cases:
            with self.subTest(label=label):
                device = ib_switch(self.page, host, **fields)
                before = copy.deepcopy(device)
                row = self.row(device, "ib", targets)
                self.assertEqual(before, device, "comparison never rewrites raw facts")
                self.assertEqual(tags, upgrade_tags(row))
                self.assertEqual(diff, row.attrs.get("data-diff"))
                self.assertEqual(upgrade, row.attrs.get("data-upgrade"))
                self.assertEqual("ok", row.attrs.get("data-bucket"), "versions never change health")
                self.assertEqual(upgrade, row.attrs.get("data-problem"),
                                 "only a known difference or a health check makes a problem")
                self.assertEqual(upgrade == "1", "hn-problem" in row.find("td").classes())
                if "mismatch" in label or "count" in label:
                    self.assertIn("型号与包不匹配", row.text())
        # A known difference is shown inverted with the target on hover, no arrow.
        row = self.row(ib_switch(self.page, host, version="25.04.0001"), "ib", targets)
        marked = row.find("span", cls="ver-diff")
        self.assertIsNotNone(marked)
        self.assertEqual("25.04.0001", marked.text())
        # The hover shows the target as written in 01-global.yaml (guide :2278).
        self.assertIn("25-03-1014", marked.attrs.get("title", ""))
        self.assertNotIn("→", row.text())

    def test_missing_ufm_source_and_families_without_targets(self):
        targets = self.targets()
        missing = make_missing(self.page, "public-ib-leaf09.example.test", "IB")
        row = self.row(missing, "ib", targets)
        self.assertEqual([("Unknown", "upg-warn")], upgrade_tags(row))
        self.assertEqual(("0", "1", "offline"), (row.attrs.get("data-upgrade"),
                         row.attrs.get("data-problem"), row.attrs.get("data-bucket")))
        for release, tags in (("UFM_APPLIANCE=2.6.1-5\nUFM_ENTERPRISE=6.26.1-5", [("NA", "upg-ok")]),
                              ("UFM_APPLIANCE=2.6.1-4\nUFM_ENTERPRISE=6.26.1-5", [("SW", "upg-warn")]),
                              ("UFM_ENTERPRISE=2.6.1-5", [("SW Unknown", "upg-warn")])):
            with self.subTest(release=release):
                ufm = self.page.parse_ufm_info_file(
                    "public-ufm01.example.test", section("cat /etc/ufm-release", release))
                self.assertEqual(tags, upgrade_tags(self.row(ufm, "ib", targets)))
        eth = make_switch(self.page, "public-tan01.example.test", "ETH", template="tan-leaf")
        eth["version"] = "5.18.0"
        self.assertEqual([("SW", "upg-warn")], upgrade_tags(self.row(eth, "eth", targets)))
        nvl = make_switch(self.page, "pod1-nvsw01", "NVLINK")
        nvl["version"] = "25-02-4347"
        self.assertEqual([("NA", "upg-ok")], upgrade_tags(self.row(nvl, "nvl", targets)))
        # No target anywhere: the whole column is "—" (guide :2278).
        for device, family in ((ib_switch(self.page, "public-ib-leaf02.example.test"), "ib"),
                               (missing, "ib"), (eth, "eth")):
            row = self.row(device, family, {})
            self.assertEqual("—", upgrade_cell(row).text().strip())
            self.assertEqual("0", row.attrs.get("data-upgrade"))

    def test_group_buttons_count_devices_once_and_grey_without_targets(self):
        targets = self.targets()
        unknown_only = OWNER_SIX[:2] + ("N/A",) + OWNER_SIX[3:]
        devices = [
            ib_switch(self.page, "public-leaf01.example.test", version="25.01.0001",
                      cpld=OWNER_SIX[:1] + ("CPLD000383_REV1002",) + OWNER_SIX[2:]),
            ib_switch(self.page, "public-leaf02.example.test", version="25.01.0001"),
            ib_switch(self.page, "public-leaf03.example.test", bios="0ACQF_06.01.008"),
            ib_switch(self.page, "public-leaf04.example.test", cpld=unknown_only),
            make_missing(self.page, "public-leaf05.example.test", "IB"),
            ib_switch(self.page, "public-leaf06.example.test", health="FATAL"),
            ib_switch(self.page, "public-leaf07.example.test"),
        ]
        eth = make_switch(self.page, "public-tan01.example.test", "ETH", template="tan-leaf",
                          environment="production")
        eth["version"] = "5.18.1"
        document = parse_html(page_html(self.page, ib=devices, eth={"production": [eth]},
                                        version_targets=targets))
        buttons = {b.attrs["data-button"]: b for b in buttons_of(document, "production-ib")}
        counts = {name: button_number(button) for name, button in buttons.items()}
        self.assertEqual({"all": 7, "sw": 2, "bios": 1, "ssd": 0, "cpld": 1, "upgrade": 3, "check": 2},
                         counts)
        self.assertEqual((1, 1), (button_number(buttons["check"], "grp-nodata"),
                                  button_number(buttons["check"], "grp-notok")))
        for name in ("all", "sw", "bios", "cpld", "upgrade", "check"):
            self.assertIn("grp-warn", buttons[name].classes(), name)
        self.assertIn("grp-ok", buttons["ssd"].classes())
        for name in buttons:
            self.assertNotIn("disabled", buttons[name].attrs, name)
        problems = {row.attrs["data-hn"]: row.attrs.get("data-problem") for row in rows_of(document)
                    if row.attrs.get("data-group") == "production-ib"}
        self.assertEqual({"public-leaf01.example.test": "1", "public-leaf02.example.test": "1",
                          "public-leaf03.example.test": "1", "public-leaf04.example.test": "0",
                          "public-leaf05.example.test": "1", "public-leaf06.example.test": "1",
                          "public-leaf07.example.test": "0"}, problems)
        for host, problem in problems.items():
            row = row_for(document, host)
            self.assertEqual(problem == "1", "hn-problem" in row.find("td").classes(), host)
        # The orange bar follows the same data-problem attribute (guide :2279).
        self.assertIn('tr.lst-row[data-problem="1"] td:first-child',
                      page_html(self.page, ib=devices, version_targets=targets))
        # Ethernet has only a SW target: BIOS/SSD/CPLD stay grey and disabled.
        eth_buttons = {b.attrs["data-button"]: b for b in buttons_of(document, "production-eth")}
        for name in ("bios", "ssd", "cpld"):
            self.assertIn("disabled", eth_buttons[name].attrs, name)
        for name in ("sw", "upgrade", "check"):
            self.assertNotIn("disabled", eth_buttons[name].attrs, name)
        # No target at all: every comparison and the upgrade button are grey; check stays.
        bare = parse_html(page_html(self.page, ib=devices, version_targets={}))
        bare_buttons = {b.attrs["data-button"]: b for b in buttons_of(bare, "production-ib")}
        for name in ("sw", "bios", "ssd", "cpld", "upgrade"):
            self.assertIn("disabled", bare_buttons[name].attrs, name)
        self.assertNotIn("disabled", bare_buttons["check"].attrs)
        heads = [node.text() for node in document.find_all("th")]
        self.assertEqual("组件需升级", heads[heads.index("健康") - 1])

    def test_same_hostname_in_two_environments_counts_in_each_group_once(self):
        targets = self.targets()
        devices = {}
        for env in ("air", "production"):
            device = make_switch(self.page, "public-tan01.example.test", "ETH",
                                 template="tan-leaf", environment=env)
            device["version"] = "5.18.0"
            devices[env] = [device]
        document = parse_html(page_html(self.page, eth=devices, version_targets=targets))
        for group in ("air-eth", "production-eth"):
            buttons = {b.attrs["data-button"]: b for b in buttons_of(document, group)}
            self.assertEqual((1, 1, 1), (button_number(buttons["all"]), button_number(buttons["sw"]),
                                         button_number(buttons["upgrade"])), group)

    def test_cpld_detail_carries_target_and_match_per_slot(self):
        targets = self.targets()
        device = ib_switch(self.page, "public-leaf01.example.test",
                           cpld=OWNER_SIX[:1] + ("CPLD000383_REV1002",) + OWNER_SIX[2:])
        cell = cpld_cell(self.row(device, "ib", targets))
        slots = cell.find("div", cls="cpld-detail").find_all("div", cls="cpld-slot")
        self.assertEqual([(target, "same" if index != 1 else "diff")
                          for index, target in enumerate(OWNER_SIX)],
                         [(node.attrs.get("data-target"), node.attrs.get("data-match")) for node in slots])
        self.assertIn("ver-diff", cell.find("span", cls="cpld-short").classes())


def interface_cell(row):
    cells = [node for node in row.iter() if node.tag == "td" and "if-cell" in node.classes()]
    if len(cells) != 1:
        raise AssertionError("expected one interface cell, got %d" % len(cells))
    return cells[0]


def interface_numbers(cell):
    available = cell.find("span", cls="if-a")
    rest = cell.find("span", cls="if-pt")
    if available is None or rest is None:
        raise AssertionError("interface cell lacks the A / P / T parts: %r" % cell.text())
    colour = [name for name in available.classes() if name in {"i-ok", "i-mid", "i-warn"}]
    return available.text() + rest.text(), colour


def eth_ports(up, admin_down=0, oper_down=0):
    lines = ["swp%d up up 400G 9216 swp" % n for n in range(1, up + 1)]
    lines += ["swp%d down down 400G 9216 swp" % n for n in range(up + 1, up + admin_down + 1)]
    start = up + admin_down + 1
    lines += ["swp%d up down 400G 9216 swp" % n for n in range(start, start + oper_down)]
    return "\n".join(lines) + "\n"


def ib_ports(active, disabled):
    lines = ["sw%dp1 up 800G 4096 ib Active LinkUp" % n for n in range(1, active + 1)]
    lines += ["sw%dp1 down 800G 4096 ib Down Disabled" % n
              for n in range(active + 1, active + disabled + 1)]
    return "\n".join(lines) + "\n"


class SwitchStatusV5InterfaceTests(unittest.TestCase):
    """8.17 C1/V5 (R-030): interface available / planned / total."""

    @classmethod
    def setUpClass(cls):
        cls.page = load_page("_switch_status_v5_page")

    def counts(self, endpoints, family):
        counter = getattr(self.page, "planned_port_counts", None)
        self.assertIsNotNone(counter, "the planned count is one Python function (guide :2327)")
        return counter(endpoints, family)

    def render(self, device, family, plans):
        return row_for(parse_html(self.page.render_sw_list_row(device, family, None, plans)),
                       device["hostname"])

    def test_planned_ports_count_both_ends_once_and_only_business_ports(self):
        ib = [("Leaf01.example.test", "sw1p1"), ("spine01", "sw3p1"),
              ("leaf01", "sw1p1"), ("LEAF01", "sw2p2"), ("leaf01", "fnm1"),
              ("leaf01", "eth0"), ("gpu01", "mlx5_0"), ("spine01", "sw3p2"),
              ("spine01.example.test", "SW3P1")]
        self.assertEqual({"leaf01": 2, "spine01": 2, "gpu01": None}, self.counts(ib, "ib"))
        eth = [("oob01", "swp1s0"), ("oob01", "swp2"), ("oob01", "eth0"), ("oob01", "mgmt"),
               ("oob01", "bmc"), ("oob01", "come"), ("host1", "eth1"), ("OOB01", "swp1s0")]
        self.assertEqual({"oob01": 2, "host1": None}, self.counts(eth, "eth"))
        # A raw P2P port name the converter did not map is not a business port.
        self.assertEqual({"ib-unknown01": None}, self.counts([("ib-unknown01", "1/1")], "ib"))

    def test_three_numbers_colours_down_priority_and_hover(self):
        host = "public-oob01.example.test"
        plan = {"eth": {"counts": {"public-oob01": 2}, "reason": "DOT public-lldpq.dot"}}
        cases = (
            ("A=P green", eth_ports(2, admin_down=1), 2, "2/2/3", ["i-ok"]),
            ("A<P yellow", eth_ports(2, admin_down=1), 3, "2/3/3", ["i-mid"]),
            ("A>P yellow", eth_ports(2, admin_down=1), 1, "2/1/3", ["i-mid"]),
            ("down first", eth_ports(2, oper_down=1), 2, "2/2/3", ["i-warn"]),
        )
        for label, interfaces, planned, text, colour in cases:
            with self.subTest(label=label):
                device = self.page.parse_info_file(host, info_text("ETH", interfaces=interfaces),
                                                   family="ETH")
                plan["eth"]["counts"]["public-oob01"] = planned
                cell = interface_cell(self.render(device, "eth", plan))
                self.assertEqual((text, colour), interface_numbers(cell))
                total = text.split("/")[2]
                self.assertIn("实际可用 %s，P2P 规划 %d，设备总口数 %s" % (text.split("/")[0], planned, total),
                              cell.attrs.get("title", ""))
                self.assertEqual("down first" in label, "(1↓)" in cell.text())
        # Owner 2026-11-20 item 1 (a): 112 Active, 32 Down/Disabled, planned 120.
        device = self.page.parse_info_file("public-ib-spine01.example.test",
                                           info_text("IB", interfaces=ib_ports(112, 32)), family="IB")
        cell = interface_cell(self.render(device, "ib", {"ib": {"counts": {"public-ib-spine01": 120},
                                                                  "reason": "CVT"}}))
        self.assertEqual(("112/120/144", ["i-warn"]), interface_numbers(cell))
        self.assertIn("(32↓)", cell.text())
        self.assertIn("实际可用 112，P2P 规划 120，设备总口数 144", cell.attrs.get("title", ""))
        self.assertIn("Down接口", "".join(node.attrs.get("title", "") for node in cell.iter()))
        self.assertEqual("ok", self.render(device, "ib", None).attrs.get("data-bucket"),
                         "an interface fault never changes the health bucket")

    def test_unknown_plan_is_a_dash_with_its_reason_never_zero(self):
        host = "public-oob01.example.test"
        device = self.page.parse_info_file(host, info_text("ETH", interfaces=eth_ports(2, 1)), family="ETH")
        for plans, reason in (
                (None, ""),
                ({"eth": {"counts": None, "reason": "未找到当前 P2P 的 DOT（*-lldpq.dot）"}}, "DOT"),
                ({"eth": {"counts": {"other01": 4}, "reason": "DOT"}}, "设备不在 P2P 里"),
                ({"eth": {"counts": {"public-oob01": None}, "reason": "DOT"}}, "设备未在01-inventory归类")):
            with self.subTest(reason=reason):
                cell = interface_cell(self.render(device, "eth", plans))
                self.assertEqual(("2/—/3", ["i-ok"]), interface_numbers(cell))
                self.assertIn(reason, cell.attrs.get("title", ""))
        ufm = ufm_server(self.page, "public-ufm01.example.test")
        ufm.update(interfaces_up=3, interfaces_total=4)
        cell = interface_cell(self.render(ufm, "ib", {"ib": {"counts": {"public-ufm01": 9}, "reason": "CVT"}}))
        self.assertEqual("3/—/4", interface_numbers(cell)[0])
        nvl = self.page.parse_info_file("pod1-nvsw01", info_text("NVLINK", interfaces=(
            "acp1 up 400G 256 nvl Active LinkUp\nacp2 up 400G 256 nvl Active LinkUp\n")), family="NVL")
        cell = interface_cell(self.render(nvl, "nvl", {"ib": {"counts": {"pod1-nvsw01": 2}, "reason": "CVT"}}))
        self.assertEqual(("2/—/2", ["i-ok"]), interface_numbers(cell))

    def test_same_short_name_in_two_networks_does_not_share_counts(self):
        plans = {"ib": {"counts": {"dup01": 4}, "reason": "CVT"},
                 "eth": {"counts": {"dup01": 9}, "reason": "DOT"}}
        ib = self.page.parse_info_file("dup01.example.test", info_text("IB", interfaces=ib_ports(4, 0)),
                                       family="IB")
        eth = self.page.parse_info_file("DUP01", info_text("ETH", interfaces=eth_ports(9)), family="ETH")
        self.assertEqual("4/4/4", interface_numbers(interface_cell(self.render(ib, "ib", plans)))[0])
        self.assertEqual("9/9/9", interface_numbers(interface_cell(self.render(eth, "eth", plans)))[0])
        html = page_html(self.page, ib=[ib])
        heads = [node.text() for node in parse_html(html).find_all("th")]
        self.assertIn("接口 可用/规划/总数", heads)
        self.assertNotIn("接口", heads)


class SwitchStatusV5SourceTests(unittest.TestCase):
    """8.17 sources: only valid existing products are read; nothing is converted or written."""

    @classmethod
    def setUpClass(cls):
        cls.page = load_page("_switch_status_v5_source_page")

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="v5-plan-", dir=owned_test_root())
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.project = root / "project"
        self.output = self.project / "99-output-p2p"
        self.output.mkdir(parents=True)
        (self.project / "fabric-a.xlsx").write_bytes(b"PUBLIC P2P WORKBOOK A\n")
        self.p2p = self.project / "p2p.xlsx"
        self.p2p.symlink_to("fabric-a.xlsx")

    def load(self):
        loader = getattr(self.page, "load_planned_ports", None)
        self.assertIsNotNone(loader, "the planned-count sources are one named reader")
        with mock.patch.object(self.page, "P2P_INPUT_LINK", self.p2p):
            before = sorted(path.name for path in self.output.iterdir())
            result = loader(self.output, self.p2p)
            self.assertEqual(before, sorted(path.name for path in self.output.iterdir()),
                             "reading the planned counts writes nothing")
        return result

    def write_dot(self, stem="fabric-a", *, workbook=None, lldpq=None):
        dot = self.output / (stem + "-lldpq.dot")
        dot.write_text('graph "public" {\n"oob01":"swp1" -- "leaf01":"swp49"\n'
                       '"oob01":"swp2" -- "host01":"eth0"\n}\n', encoding="utf-8")
        sidecar = {
            "schema_version": 1, "source_workbook": "fabric-a.xlsx", "profiles": [],
            "lldpq_sha256": lldpq or hashlib.sha256(dot.read_bytes()).hexdigest(),
            "workbook_sha256": workbook or hashlib.sha256(self.p2p.read_bytes()).hexdigest(),
            "inventory_sha256": "0" * 64, "port_mapping_sha256": "0" * 64,
        }
        (self.output / (stem + "-splitter-profiles.json")).write_text(json.dumps(sidecar), encoding="utf-8")
        return dot

    def write_cvt(self, *, provenance=True, p2p=None):
        import xlsxwriter

        cvt = self.output / "fabric-a-cvt.xlsx"
        book = xlsxwriter.Workbook(str(cvt))
        sheet = book.add_worksheet("Links")
        rows = [("Protocol", "A-Node", "A-Port", "", "", "", "Z-Node", "Z-Port", "", ""),
                ("ib", "leaf01", "sw1p1", "", "", "", "spine01", "sw1p1", "", ""),
                ("ib", "leaf01", "sw2p1", "", "", "", "spine01", "sw2p1", "", ""),
                ("ib", "leaf01", "fnm1", "", "", "", "ufm01", "ib0", "", ""),
                ("unknown", "mystery01", "1/1", "", "", "", "mystery02", "1/2", "", "")]
        for number, row in enumerate(rows):
            for column, value in enumerate(row):
                sheet.write(number, column, value)
        book.close()
        if provenance:
            sys.path.insert(0, str(ROOT / "ztp/config"))
            try:
                import ib_topology_provenance as provenance_api
            finally:
                sys.path.remove(str(ROOT / "ztp/config"))
            sources = {}
            for role in ("inventory", "port_map", "splitter", "converter", "topology_rules"):
                path = self.project / ("source-" + role + ".txt")
                path.write_text("PUBLIC " + role + "\n", encoding="utf-8")
                sources[role] = path
            sources["p2p"] = p2p or self.p2p
            provenance_api.write_cvt_provenance(cvt, sources)
            self.sources = sources
        return cvt

    def test_valid_dot_is_read_and_any_drift_gives_a_dash(self):
        self.write_dot()
        plans = self.load()
        self.assertEqual({"oob01": 2, "leaf01": 1, "host01": None}, plans["eth"]["counts"])
        self.write_dot(lldpq="1" * 64)
        self.assertIsNone(self.load()["eth"]["counts"])
        self.write_dot(workbook="2" * 64)
        self.assertIsNone(self.load()["eth"]["counts"])
        # Only the current P2P stem counts; another stem's DOT is ignored.
        (self.output / "fabric-a-lldpq.dot").rename(self.output / "fabric-old-lldpq.dot")
        self.assertIsNone(self.load()["eth"]["counts"])

    def test_cvt_needs_provenance_bound_to_this_projects_p2p(self):
        self.write_cvt(provenance=False)
        self.assertIsNone(self.load()["ib"]["counts"])
        self.write_cvt()
        self.assertEqual({"leaf01": 2, "spine01": 2, "ufm01": None, "mystery01": None,
                          "mystery02": None}, self.load()["ib"]["counts"])
        # Any recorded source changing makes the CVT stale (ib_topology_provenance decides).
        self.sources["inventory"].write_text("PUBLIC inventory changed\n", encoding="utf-8")
        self.assertIsNone(self.load()["ib"]["counts"])
        # A record of another project's P2P never passes for this project.
        other = self.project / "other-project.xlsx"
        other.write_bytes(b"PUBLIC OTHER P2P\n")
        self.write_cvt(p2p=other)
        self.assertIsNone(self.load()["ib"]["counts"])

    def test_a_changed_device_list_alone_keeps_the_planned_ib_count(self):
        # v3.1.6 DEVHASH (owner 2026-11-27, 04 Q-115 (c)): 02-devices_config.csv never binds a CVT, whether
        # the sidecar names it as a pre-v3.1.6 source role or in the advisory fields; the planned count stays.
        cvt = self.write_cvt()
        expected = self.load()["ib"]["counts"]
        self.assertIsNotNone(expected)
        devices = self.project / "02-devices_config.csv"
        devices.write_text("hostname,type\nleaf01,ib\n", encoding="utf-8")
        original = devices.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        sidecar = Path(f"{cvt}.provenance.json")
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        legacy = copy.deepcopy(record)
        legacy["sources"]["devices"] = {"path": str(devices), "resolved_path": str(devices.resolve()),
                                        "kind": "file", "sha256": digest}
        advisory = copy.deepcopy(record)
        advisory["advisory"] = {"devices_path": str(devices), "devices_sha256": digest,
                                "name_column": "hostname", "verified": False}
        for label, variant in (("legacy devices role", legacy), ("advisory fields", advisory)):
            with self.subTest(sidecar=label):
                sidecar.write_text(json.dumps(variant, sort_keys=True), encoding="utf-8")
                devices.write_bytes(original)
                self.assertEqual(expected, self.load()["ib"]["counts"], label + ", list unchanged")
                devices.write_bytes(original + b"spine01,ib\n")
                self.assertEqual(expected, self.load()["ib"]["counts"], label + ", only the list changed")

    def test_missing_products_give_reasons_and_no_generation(self):
        plans = self.load()
        self.assertIsNone(plans["ib"]["counts"])
        self.assertIsNone(plans["eth"]["counts"])
        self.assertIn("CVT", plans["ib"]["reason"])
        self.assertIn("DOT", plans["eth"]["reason"])
        source = PAGE.read_text(encoding="utf-8")
        for converter in ("b-xlsx_to_dot.py", "p2p-to-validation.py", "deployment_lock"):
            self.assertNotIn(converter, source, "the page never runs a P2P converter (guide :2312)")


if __name__ == "__main__":
    unittest.main()
