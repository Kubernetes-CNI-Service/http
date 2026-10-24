"""The D-70 UFM collection pipeline is retired (codex REQ7 retirement, batch 2, 2026-10-24).

D-70 was a second IB analysis lane: with a root-installed authority record
(/var/lib/http-ztp-container/ib-producer-authority/<project>.json) the collection worker put an
``ib_analysis`` binding into the slot context, the v2 emitter minted six more evidence roles (nine in all)
and an ``ib_analysis_binding`` envelope, and monitor/collection_ib_producer.py vouched for them at
publication and at replay; the monitor page showed the pipeline's receipts in a UFM tab. The IB analysis
now comes only from the cron.sh UFM lane's run record (REQ7 R1, monitor/collection_ufm_run_binding.py,
ten roles). So:

* the emitter refuses a worker context that carries ``ib_analysis`` and refuses to publish a nine-role
  evidence, even when a stale monitor/collection_ib_producer module is still importable on a deployed
  host (a sync without delete leaves a retired file in place) and would vouch for it; the stale module
  is never consulted;
* the worker imports no D-70 module, names neither the authority nor the attestation directory, has no
  D-70 preparation step left, and its replay refuses the D-70 roles;
* the monitor page has no UFM evidence panel, no UFM tab and no ``ufm_panel`` input, and imports no
  tools.ufm_collection_* module;
* ztp/config/ib_topology_provenance.py never borrows a tools.ufm_collection_pipeline read scope, even from
  a loaded stale module with an active scope.

The workflow counterpart (a real completed IB prod cycle through the worker store and the emitter) is
test_collection_d70_retirement_workflow.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_collection_cycle_persistence import WORKER
# Imported as a module, not by class name: a TestCase class bound in this module would be collected here too.
import test_cases.test_collection_v2_emitter_contract as emitter_contract
from test_cases.test_monitor_legacy_tracker_retirement import imported_modules, page_html, string_constants

EMITTER = emitter_contract.EMITTER

ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "monitor/switch-collection-worker.py"
EMITTER_PATH = ROOT / "monitor/collection_v2_emitter.py"
PAGE_PATH = ROOT / "monitor/generate-monitor-html.py"
PROVENANCE_PATH = ROOT / "ztp/config/ib_topology_provenance.py"
PRODUCER = "monitor.collection_ib_producer"
PIPELINE = "tools.ufm_collection_pipeline"
RETIRED_MODULES = (PRODUCER, PIPELINE, "tools.ufm_collection_agent", "tools.ufm_remote_producer")
# The six roles D-70 appended after the three base roles (written out from 7d5518d, not imported).
D70_ROLE_NAMES = ("ufm_actual_archive", "ufm_actual_log", "expected_cvt",
                  "validation_report", "report_provenance", "ufm_completion_receipt")
D70_BINDING_KEYS = ("run_id", "node", "authority_sha256", "expected_topology_sha256", "attestation_sha256")
BASE_ROLE_NAMES = ["info_archive", "link_archive", "link_csv"]


def d70_roles() -> list:
    return [{"role": name, "state": "present",
             "relative_path": f"infiniband/monitor/ib-link/{name}.bin",
             "sha256": hashlib.sha256(name.encode()).hexdigest(), "size_bytes": len(name)}
            for name in D70_ROLE_NAMES]


def d70_binding() -> dict:
    binding = {key: hashlib.sha256(key.encode()).hexdigest() for key in D70_BINDING_KEYS}
    binding.update(run_id="20261024-0100-prod-0123456789abcdef", node="EXAMPLE-UFM01", roles=d70_roles())
    return binding


class StaleModule:
    """Put a stand-in for a retired module into sys.modules for the duration of a block.

    A deployed host may still hold the retired file (a sync without delete), so ``import`` would still
    find it. The stand-in vouches for whatever it is asked about and records every call: retained code
    must never consult it. Restores the previous sys.modules entry (or its absence) on exit."""

    def __init__(self, name: str, **attributes):
        self.name = name
        self.calls = []
        self.module = types.ModuleType(name)
        for attribute, value in attributes.items():
            if callable(value) and not isinstance(value, type):
                value = self._recording(attribute, value)
            setattr(self.module, attribute, value)
        self._missing = object()
        self._previous = self._missing

    def _recording(self, attribute, function):
        def recorded(*args, **kwargs):
            self.calls.append(attribute)
            return function(*args, **kwargs)
        return recorded

    def __enter__(self):
        self._previous = sys.modules.get(self.name, self._missing)
        sys.modules[self.name] = self.module
        return self

    def __exit__(self, *_exc):
        if self._previous is self._missing:
            sys.modules.pop(self.name, None)
        else:
            sys.modules[self.name] = self._previous
        return False


def stale_producer() -> StaleModule:
    class IbProducerHold(ValueError):
        pass

    def vouch(_identity, binding, *, http_root):
        return [dict(role) for role in binding["roles"]]

    def no_snapshot(*_args, **_kwargs):
        return None

    return StaleModule(
        PRODUCER, IB_ROLE_NAMES=D70_ROLE_NAMES, IbProducerHold=IbProducerHold,
        validate_ib_completion_attestation=vouch, recheck_ib_producer_authority=no_snapshot,
        load_ib_producer_authority=no_snapshot, produce_worker_ib_analysis=no_snapshot,
    )


class EmitterRefusesD70Test(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="d70-retired-emitter-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.args = emitter_contract.CollectionV2EmitterContractTests(
            "test_exact_members_publish_atomically_and_bind_identity").fixture(self.root)

    def test_a_worker_context_with_ib_analysis_is_refused_and_the_stale_producer_is_not_consulted(self):
        context = json.loads(self.args.context_file.read_bytes())
        context["ib_analysis"] = d70_binding()
        self.args.context_file.write_bytes(EMITTER.canonical(context))
        with stale_producer() as stale, mock.patch.object(EMITTER, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "worker context shape is invalid"):
                EMITTER.build_result(self.args)
        self.assertEqual([], stale.calls)
        self.assertFalse(Path(context["artifacts"]["evidence"]).exists())

    def test_a_nine_role_evidence_is_never_published(self):
        with mock.patch.object(EMITTER, "ROOT", self.root):
            _child, evidence, envelope, sidecar_dir = EMITTER.build_result(self.args)
        roles = json.loads(evidence)["roles"]
        self.assertEqual(BASE_ROLE_NAMES, [role["role"] for role in roles], "control: the base roles")
        binding = d70_binding()
        forged_evidence = EMITTER.canonical({"roles": roles + binding.pop("roles")})
        forged_envelope = json.loads(envelope)
        forged_envelope["ib_analysis_context_sha256"] = hashlib.sha256(b"d70 context").hexdigest()
        forged_envelope["ib_analysis_binding"] = binding
        with stale_producer() as stale, mock.patch.object(EMITTER, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "collection evidence role count is invalid"):
                EMITTER.publish(sidecar_dir, forged_evidence, EMITTER.canonical(forged_envelope))
        self.assertEqual([], stale.calls)
        self.assertFalse(sidecar_dir.exists(), "nothing was published")
        self.assertEqual([], [path.name for path in sidecar_dir.parent.iterdir()
                              if path.name.startswith(".v2-evidence-")], "the private stage was removed")

    def test_the_emitter_imports_no_retired_module(self):
        tree = ast.parse(EMITTER_PATH.read_text(encoding="utf-8"))
        self.assertEqual(set(), imported_modules(tree) & set(RETIRED_MODULES))
        self.assertEqual([], [value for value in string_constants(tree) if "ib_analysis" in value])


class WorkerHasNoD70LaneTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(WORKER_PATH.read_text(encoding="utf-8"))

    def test_the_worker_imports_no_retired_module(self):
        modules = imported_modules(self.tree)
        self.assertIn("monitor.collection_ufm_run_binding", modules, "control: the census sees the R1 import")
        self.assertEqual(set(), modules & set(RETIRED_MODULES))

    def test_the_worker_names_no_d70_authority_attestation_or_context_key(self):
        for value in string_constants(self.tree):
            for retired in ("ib-producer-authority", "ib-producer-attestations", "ib_analysis"):
                self.assertNotIn(retired, value)

    def test_the_worker_has_no_d70_preparation_step(self):
        for name in ("_collection_prepare_ib_analysis", "_collection_ib_authority_installed"):
            self.assertFalse(hasattr(WORKER, name), name)

    def test_the_worker_role_check_refuses_the_d70_roles_with_or_without_a_stale_producer(self):
        evidence = {"roles": [{"role": name} for name in BASE_ROLE_NAMES] + d70_roles()}
        child = {"source_slot": "infiniband/prod", "planned": 1}
        context = {"ib_analysis": d70_binding(), "target_plan": {"ib": ["leaf-ib|192.0.2.11"]}}
        for label, stale in (("absent", None), ("stale module present", stale_producer())):
            with self.subTest(producer=label):
                if stale is None:
                    self.assertFalse(WORKER._collection_validate_artifact_roles(
                        evidence, root=ROOT, child=child, inventory=b"", context=context))
                    continue
                with stale:
                    self.assertFalse(WORKER._collection_validate_artifact_roles(
                        evidence, root=ROOT, child=child, inventory=b"", context=context))
                self.assertEqual([], stale.calls)


class PageHasNoUfmEvidencePanelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = load_script("d70_retirement_page", PAGE_PATH)
        cls.html = page_html(cls.page)

    def test_the_page_has_no_ufm_evidence_panel_and_no_ufm_tab(self):
        for marker in ('id="panel-ufm"', 'id="ufm-collection-panel"', "UFM 独立证据", "switchTab('ufm')",
                       "没有已验证的 UFM 采集回执"):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.html)
        [names] = re.findall(r"const TAB_NAMES = \[([^\]]*)\];", self.html)
        tabs = re.findall(r"'([a-z0-9]+)'", names)
        self.assertIn("air", tabs, "control: the tab list is read")
        self.assertNotIn("ufm", tabs)

    def test_build_html_takes_no_ufm_panel(self):
        with self.assertRaisesRegex(TypeError, "ufm_panel"):
            page_html(self.page, ufm_panel='<div id="panel-ufm" class="panel"></div>')
        for name in ("render_ufm_evidence_panel", "render_ufm_candidate_panel", "_render_ufm_evidence_panel"):
            self.assertFalse(hasattr(self.page, name), name)

    def test_the_page_imports_no_ufm_collection_module(self):
        tree = ast.parse(PAGE_PATH.read_text(encoding="utf-8"))
        modules = imported_modules(tree)
        self.assertIn("tools.log_rotation", modules, "control: the census sees the page's tools imports")
        self.assertEqual([], sorted(name for name in modules if name.startswith("tools.ufm_collection")))


class ProvenanceBorrowsNoPipelineScopeTest(unittest.TestCase):
    def test_a_loaded_pipeline_module_with_an_active_scope_is_never_borrowed(self):
        from ztp.config import ib_topology_provenance as provenance

        class ActiveScope:
            def get(self):
                return object()

        def refuse(*_args, **_kwargs):
            raise AssertionError("the retired pipeline read scope was borrowed")

        stale = StaleModule(
            PIPELINE, _HELD_DIRECTORY_READS=ActiveScope(), _HELD_SOURCE_READS=ActiveScope(),
            _hold_real_dir_chain=refuse, _borrow_current_source_file=refuse,
            _borrow_current_source_originals=refuse,
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / "independent-input"
            source.write_bytes(b"independent input bytes")
            with stale:
                digest = provenance._regular_digest(source)
            self.assertEqual(hashlib.sha256(b"independent input bytes").hexdigest(), digest)
        self.assertEqual([], stale.calls)

    def test_the_provenance_module_does_not_look_up_any_pipeline_module(self):
        tree = ast.parse(PROVENANCE_PATH.read_text(encoding="utf-8"))
        self.assertEqual([], [value for value in string_constants(tree) if "ufm_collection" in value])
        lookups = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                   and node.attr == "modules" and isinstance(node.value, ast.Name) and node.value.id == "sys"]
        self.assertEqual([], lookups, "no sys.modules lookup is left")


if __name__ == "__main__":
    unittest.main()
