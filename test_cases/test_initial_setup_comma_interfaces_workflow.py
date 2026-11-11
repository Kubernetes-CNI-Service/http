"""Workflow: comma-merged and fnm interfaces through the real C2, P1 and initial-setup MAIN.

What (v3.1.3 WP-12, I-005): the real C2 global generation, the P1 target cache and the
initial-setup MAIN (management execution, strict phase reads, authorized helper reads, pending
diff, Network stage, IPv4 readiness and the final direct SSH readback) run against an owned SSH
peer whose device returns the problem-document sample A (``eth0-1,fnm1 link state up`` and
``fnm1 type fnm``) or sample B (the same device without fnm1).  The per-device results of the two
must be the same; an unknown comma member fails only that device and the report carries a
separate location line (line number, interface name) without raw values.

Expectation sources (not derived from the implementation):
- 问题文档 I-005 (:158-216 at doc tag guide-v3.1.3-approved-r328): samples :163-196, 期望 1-4
  :204-207, 验收 :211-215 (workflow: check-only and apply results equal the device without fnm1).
- v3.1.3 guide (tag guide-v3.1.3-approved-r328) WP-12 :1185-1192; O15 :268; O16 :269; table 6-1
  row 11 (:754, v15 exit codes) for the plain device's successful --apply run.

Fixture: test_initial_setup_main_caller_precommit (the same real C2/P1 chain as workflow
initial_setup_target_outcome_c2_p1_manual_reporting) with one peer layer appended before the
peer's unique run(); it only replaces the device's Network block with a sample.  Public keys are
blanked before the real P1 (fixture precondition) so the runs make no key writes.  Documentation
addresses and anonymized host names only.
"""
from __future__ import annotations

import json
import re
import tempfile
import unittest

from test_cases import test_initial_setup_main_caller_precommit as caller

base = caller.base
WRITES = ("mutation", "apply-y", "save", "key-shell", "pam-target")
# The inherited peer's Network block (test_initial_setup_target_credentials_workflow show_state).
ANCHOR = (
    "nv set interface eth0 ipv4 address 203.0.113.2/24",
    "nv set interface eth0-1 ipv4 gateway 203.0.113.1",
    "nv set interface eth0-1 link state up",
    "nv set interface eth0-1 type eth",
    "nv set system hostname EXAMPLE-IB01",
)
# 问题文档 :182-193 (with fnm1) and :194 (without fnm1, same structure), on the fixture device.
LOOPBACK = (
    "nv set interface lo acl acl-default-loopback inbound control-plane",
    "nv set interface lo acl acl-default-loopback-ipv6 inbound control-plane",
    "nv set interface lo type loopback",
)
SAMPLE_B = (
    "nv set interface eth0 ipv4 address 203.0.113.2/24",
    "nv set interface eth0-1 ipv4 gateway 203.0.113.1",
    "nv set interface eth0-1 type eth",
    "nv set interface eth0-1 link state up",
    *LOOPBACK,
    "nv set system hostname EXAMPLE-IB01",
)
SAMPLE_A = (
    "nv set interface eth0 ipv4 address 203.0.113.2/24",
    "nv set interface eth0-1 ipv4 gateway 203.0.113.1",
    "nv set interface eth0-1 type eth",
    "nv set interface eth0-1,fnm1 link state up",
    "nv set interface fnm1 type fnm",
    *LOOPBACK,
    "nv set system hostname EXAMPLE-IB01",
)
UNKNOWN_ROW = "nv set interface eth0-1,xyz1 link state up"
SAMPLE_UNKNOWN = tuple(UNKNOWN_ROW if row == "nv set interface eth0-1,fnm1 link state up" else row
                       for row in SAMPLE_A if row != "nv set interface fnm1 type fnm")

# Appended to the owned peer's RAM program before its unique run(); C["comma_rows"] selects the
# sample that replaces the configured device's Network block.
COMMA_PEER = r'''
_comma_original_show = show_state
_COMMA_ANCHOR = %r
def show_state(S):
    body = _comma_original_show(S)
    rows = C.get("comma_rows")
    if rows is None or not S["network"]:
        return body
    lines = body.splitlines()
    if tuple(lines[:5]) != _COMMA_ANCHOR:
        raise ValueError("comma peer anchor")
    return "\n".join(list(rows) + lines[5:]) + "\n"
''' % (ANCHOR,)


class CommaInterfaceMainWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        caller.MainCallerPrecommitDraftTests.setUpClass.__func__(cls)

    fixed_hold = caller.MainCallerPrecommitDraftTests.fixed_hold
    fixture = caller.MainCallerPrecommitDraftTests.fixture
    events = caller.MainCallerPrecommitDraftTests.events
    invoke = caller.MainCallerPrecommitDraftTests.invoke
    p1 = caller.MainCallerPrecommitDraftTests.p1

    def comma_fixture(self, folder, rows, *, network):
        # Owner Q-035 (a) item 4 (guide :438): an --apply run needs the device's current IB
        # password to equal the project target, so the modeled device uses the target
        # (fixture precondition, not an expectation).
        f = self.fixture(folder, case="comma-interfaces", network=network, services=True,
                         credential="target")
        program = f["stub"].read_text(encoding="utf-8")
        marker = "def run():\n"
        if program.count(marker) != 1:
            self.fixed_hold()
        f["stub"].write_text(program.replace(marker, COMMA_PEER + "\n" + marker, 1),
                             encoding="utf-8")
        f["stub"].chmod(0o600)
        config = json.loads(f["config"].read_text())
        config["comma_rows"] = list(rows)
        f["config"].write_text(json.dumps(config), encoding="utf-8")
        f["config"].chmod(0o600)
        for name in ("laptop.pub", "mgmt-server.pub"):
            (f["root"] / "infiniband/publickey" / name).write_text("", encoding="ascii")
        self.p1(f)
        return f

    def run_main(self, f, *options):
        start, summaries = len(self.events(f)), set(f["root"].rglob("summary.json"))
        result = self.invoke(f, *options)
        fresh = sorted(set(f["root"].rglob("summary.json")) - summaries)
        self.assertEqual(1, len(fresh), "one summary.json per run")
        summary = json.loads(fresh[0].read_text(encoding="utf-8"))
        records = {name: {key: record.get(key) for key in (
                       "outcome", "stage_status", "needs_configuration", "writes_attempted",
                       "failed_stage", "reason")}
                   for name, record in summary["records"].items()}
        legacy = [line for line in result["stdout"].splitlines() if line.startswith("Summary: targets=")]
        writes = [(event["kind"], event.get("command")) for event in self.events(f)[start:]
                  if event["kind"] in WRITES]
        report = (f["root"] / "out/report.log").read_text(encoding="utf-8")
        return dict(rc=result["rc"], error=result["error"], records=records, legacy=legacy,
                    writes=writes, stdout=result["stdout"], report=report)

    def test_check_only_and_apply_match_plain_device(self):
        # 问题文档 :215 (验收, workflow): a device with fnm1 gets the same check-only and apply
        # results as the device without fnm1; guide :1189: neither writes base nor applies.
        observed = {}
        for label, rows in (("A-with-fnm1", SAMPLE_A), ("B-without-fnm1", SAMPLE_B)):
            with tempfile.TemporaryDirectory(prefix="comma-interface-configured-") as folder:
                f = self.comma_fixture(folder, rows, network=True)
                observed[label] = (self.run_main(f), self.run_main(f, "--apply", "--yes"))
        for label, runs in observed.items():
            for mode, run in zip(("check-only", "apply"), runs):
                with self.subTest(sample=label, mode=mode):
                    self.assertIsNone(run["error"])
                    self.assertEqual([], run["writes"], "no base, apply, save or key write")
                    self.assertNotIn("FAILED", [r["outcome"] for r in run["records"].values()])
            # Table 6-1 row 11 (guide :754): configured, no work, direct SSH PASS -> 0.
            self.assertEqual(0, runs[1]["rc"])
        plain, comma = observed["B-without-fnm1"], observed["A-with-fnm1"]
        for index, mode in enumerate(("check-only", "apply")):
            with self.subTest(compare=mode):
                self.assertEqual({key: plain[index][key] for key in ("rc", "records", "legacy")},
                                 {key: comma[index][key] for key in ("rc", "records", "legacy")})

    def test_apply_on_unconfigured_device_verifies_comma_readback_like_plain_device(self):
        # 问题文档 :215 (验收, workflow) and guide :1158 ("再交给所有下游"): after the missing
        # setters are applied, the post-configuration readback of the device with fnm1 shows the
        # comma line and is verified the same as the device without fnm1.
        observed = {}
        for label, rows in (("A-with-fnm1", SAMPLE_A), ("B-without-fnm1", SAMPLE_B)):
            with tempfile.TemporaryDirectory(prefix="comma-interface-unconfigured-") as folder:
                f = self.comma_fixture(folder, rows, network=False)
                observed[label] = self.run_main(f, "--apply", "--yes")
        plain, comma = observed["B-without-fnm1"], observed["A-with-fnm1"]
        self.assertTrue(plain["error"] is None and plain["rc"] == 0,
                        "fixture: the plain unconfigured device must be configured by --apply")
        self.assertTrue(bool(plain["writes"]), "fixture: the plain device received the Network setters")
        self.assertEqual({key: plain[key] for key in ("rc", "records", "legacy", "writes")},
                         {key: comma[key] for key in ("rc", "records", "legacy", "writes")})

    def test_unknown_member_reports_line_and_name_without_values(self):
        # 问题文档 :206 (期望 3) and :212 (验收): an unknown member in a comma list is refused and
        # the report names that line and that interface; O15 :268 / guide :1166, :1190: the error
        # keeps its fixed text and a separate line carries the location, never an address value.
        with tempfile.TemporaryDirectory(prefix="comma-interface-unknown-") as folder:
            f = self.comma_fixture(folder, SAMPLE_UNKNOWN, network=True)
            run = self.run_main(f)
        line_number = SAMPLE_UNKNOWN.index(UNKNOWN_ROW) + 1
        self.assertIsNone(run["error"])
        self.assertEqual(["FAILED"], [record["outcome"] for record in run["records"].values()])
        self.assertEqual([], run["writes"])
        self.assertNotIn("xyz1", run["stdout"], "the console reason stays the fixed literal (O15)")
        report = run["report"].splitlines()
        self.assertFalse(any("ERROR:" in line and "xyz1" in line for line in report),
                         "the error text must stay the fixed literal (O15)")
        located = [line for line in report if "xyz1" in line]
        self.assertEqual(1, len(located), "one separate location line names the interface")
        self.assertTrue(re.search(r"\bline " + str(line_number) + r"\b", located[0]),
                        "the location line names the readback line number")
        self.assertFalse(any(value in located[0] for value in ("203.0.113.", "/24", "EXAMPLE-IB01")),
                         "the location line carries no address or other raw value")


if __name__ == "__main__":
    unittest.main()
