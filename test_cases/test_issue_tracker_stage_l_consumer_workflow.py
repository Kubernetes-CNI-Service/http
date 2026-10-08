"""Real protected Stage-L source, C5/C6 and fail-closed workflow contracts."""

from __future__ import annotations

from dataclasses import asdict, replace
import datetime as dt
import hashlib
import json
from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock
import zipfile

import xlsxwriter

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_ib_runtime import IbBoundCycleReport, IbReportLink
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_issue_tracker_local_workbook import fake_workbook
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx

from test_cases.test_issue_tracker_stage_l_consumer import ProdStageLFixture


class ProdStageLConsumerWorkflowTests(ProdStageLFixture):
    def _exercise_timed_out_boot_probe(self, **options):
        from test_cases.test_collection_cycle_persistence import WORKER

        original_run = subprocess.run
        original_is_file = Path.is_file
        timed_out_probes = []

        def bounded_probe(command, *args, **kwargs):
            if command == ["/usr/sbin/sysctl", "-n", "kern.boottime"]:
                timed_out_probes.append(command)
                raise subprocess.TimeoutExpired(command, 2)
            return original_run(command, *args, **kwargs)

        def no_linux_boot_file(path):
            return False if str(path) == "/proc/sys/kernel/random/boot_id" \
                else original_is_file(path)

        with mock.patch.object(WORKER.subprocess, "run", side_effect=bounded_probe), \
                mock.patch.object(WORKER.Path, "is_file", autospec=True,
                                  side_effect=no_linux_boot_file):
            self._exercise_real_protected_three_panel_fixture(
                skip_history=False, **options,
            )
        self.assertTrue(timed_out_probes, "the workflow must execute the injected fault")

    def test_boot_probe_timeout_does_not_admit_n_two_local_c6(self):
        self._exercise_timed_out_boot_probe(
            automatic_first=True, automatic_not_due=True,
        )

    def test_boot_probe_timeout_does_not_auto_readmit_manual_receipt(self):
        self._exercise_timed_out_boot_probe(replayed_auto=True)

    def test_real_nine_role_ib_and_eth_fourth_role_qualify_and_c5_reject_drift(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False)

    def test_real_protected_three_panel_sources_compile_literal_units_and_refuse_invented_values(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, source_unit_probe=True)

    def test_actual_protected_workbook_receipt_admission_bind_all_source_units_and_reject_drift(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, receipted_source_probe=True)

    def test_actual_receipt_source_and_full_row_images_derive_all_update_coordinates_and_preread(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_source_probe=True)

    def test_actual_source_receipt_global_owner_and_original_enrollment_derive_switch_inserts(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_switch_insert_probe=True)

    def test_actual_source_receipt_and_original_two_sheet_nv_derive_mixed_cabling_units(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True)

    def test_actual_receipted_cabling_unit_retains_original_business_images_across_unknown(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True, business_preread_probe=True)

    def test_actual_receipted_cabling_original_chain_dominates_reserved_count(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True, business_preread_probe=True, original_reserved_probe=True)

    def test_actual_original_c6_receipt_dominates_every_business_count_and_post_count_drift_holds(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True, business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True)

    def test_two_real_cycles_keep_keys_and_commit_latest_business_values(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, two_cycle_changed_latest=True,
        )

    def test_authenticated_k_relay_persists_replays_and_invalidates_real_preview(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, settings_channel_probe=True,
        )

    def test_k_relay_interrupted_commit_retains_unknown_claim_not_success_or_retry(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, settings_channel_fault=True,
        )

    def _verify_authenticated_settings_channel(self, project, *, fault=False):
        from monitor.issue_tracker_manual_channel import DurableManualQueue, ManualQueueWorker
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        from monitor.issue_tracker_state_owner import current_k, tracker_writer
        from test_cases.test_issue_tracker_manual_channel import cgi, valid_env

        root = project / ".tracker/manual-k-fixture"
        root.mkdir(mode=0o700)
        queue = DurableManualQueue(root, boot_id="settings-fixture")
        broker = make_protected_stage_l_broker(
            self.store, http_root=self.root, project=project,
            publication=self.publication, template_path=self.template,
            boot_id="settings-fixture", clock=lambda: 1000.0,
        )
        worker = ManualQueueWorker(queue, broker)
        jobs = []

        def submit(request):
            job = queue.enqueue(request)
            jobs.append(job)
            claimed, result = worker.process_job(job)
            self.assertEqual(job, claimed)
            self.assertEqual("done", queue.status(job)["state"])
            return result

        body = b"action=settings&panel=Switch+Status"
        status, initial = cgi.handle(valid_env(body), body, submit=submit)
        self.assertEqual("200 OK", status)
        self.assertEqual((1, 1), (initial["revision"], initial["k"]))
        preview = broker.preview("nvis", "Switch Status")
        generations = tuple((project / ".tracker/generations").iterdir())
        template = self.template.read_bytes()
        change = (b"action=set_k&panel=Eth+Link+Validation&new_k=5000"
                  b"&expected_revision=1&request_id=" + b"d" * 32)
        if fault:
            # Failure after immutable event/outbox installation, before the
            # current-pointer barrier: preserve the tail and this claimed job.
            with mock.patch("monitor.issue_tracker_k_store._replace_current",
                            side_effect=OSError("injected pointer barrier failure")):
                status, result = cgi.handle(valid_env(change), change, submit=submit)
            self.assertEqual(("503 Service Unavailable", {"error": "manual_worker_unavailable"}),
                             (status, result))
            self.assertEqual("unknown_after_claim", queue.status(jobs[-1])["state"])
            self.assertTrue((project / ".tracker/settings/events/2.json").is_file())
            self.assertTrue((project / ".tracker/settings/outbox/2.json").is_file())
            status, result = cgi.handle(valid_env(body), body, submit=submit)
            self.assertEqual("503 Service Unavailable", status)
            self.assertEqual("unknown_after_claim", queue.status(jobs[-1])["state"])
            self.assertEqual(generations, tuple((project / ".tracker/generations").iterdir()))
            self.assertEqual(template, self.template.read_bytes())
            return
        status, result = cgi.handle(valid_env(change), change, submit=submit)
        self.assertEqual("200 OK", status)
        self.assertEqual(("committed", 2, 5000, False),
                         (result["settings"], result["revision"], result["k"], result["replay"]))
        event_path = project / ".tracker/settings/events/2.json"
        event = json.loads(event_path.read_bytes())
        self.assertEqual(("operator:nvis", 1, 5000, "d" * 32),
                         (event["actor"], event["old_k"], event["new_k"], event["request_id"]))
        self.assertEqual(hashlib.sha256(event_path.read_bytes()).hexdigest(), result["event_sha256"])
        self.assertTrue((project / ".tracker/settings/outbox/2.json").is_file())
        restart = make_protected_stage_l_broker(
            self.store, http_root=self.root, project=project,
            publication=self.publication, template_path=self.template,
            boot_id="new-worker", clock=lambda: 1000.0,
        )
        self.assertEqual((2, 5000), (restart.settings("cumulus", "IB Link Validation")["revision"],
                                     restart.settings("cumulus", "IB Link Validation")["k"]))
        status, replay = cgi.handle(valid_env(change), change, submit=submit)
        self.assertEqual("200 OK", status)
        self.assertEqual({**result, "replay": True}, replay)
        for altered, environment in (
            (change.replace(b"new_k=5000", b"new_k=6"), None),
            (change.replace(b"d" * 32, b"e" * 32), None),
            (change, {**valid_env(change), "REMOTE_USER": "cumulus"}),
        ):
            status, refused = cgi.handle(environment or valid_env(altered), altered, submit=submit)
            self.assertEqual(("409 Conflict", {"error": "manual_hold"}), (status, refused))
        with tracker_writer(project, self.publication) as token:
            self.assertEqual((2, 5000), (current_k(token).revision, current_k(token).k))
        from monitor.issue_tracker_publish_runtime import inspect_stage_l
        status = inspect_stage_l(self.store, http_root=self.root, project=project,
                                 publication=self.publication, template_path=self.template)
        self.assertEqual((2, 5000), (status["k_revision"], status["k"]))
        self.assertEqual("pending", status["state"])
        self.assertEqual("disabled_no_send_authority", status["online"])
        from monitor.issue_tracker_manual_preview import ManualPreviewHold
        with self.assertRaises(ManualPreviewHold):
            broker.confirm("nvis", "Switch Status", preview["token"], confirmation="publish_local")
        self.assertEqual(generations, tuple((project / ".tracker/generations").iterdir()))
        self.assertEqual(template, self.template.read_bytes())


    def test_real_protected_eth_and_switch_skips_have_local_audit_history(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=True)

    def test_real_protected_first_due_cycle_auto_commits_local_receipt(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True,
        )

    def test_real_protected_second_due_cycle_auto_commits_distinct_local_receipt(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, automatic_second_due=True,
        )

    def test_manual_c6_cannot_bypass_prior_automatic_shared_admission(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, manual_second_probe=True,
        )

    def test_automatic_c6_then_manual_c6_uses_one_shared_admission_chain(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, manual_second_admit=True,
        )

    def test_invalid_auto_clock_refuses_before_local_c6_receipt(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, invalid_auto_clock=True,
        )

    def test_one_completed_cycle_cannot_admit_n_two_local_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, automatic_not_due=True,
        )

    def test_replayed_completion_after_manual_receipt_cannot_auto_readmit(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, replayed_auto=True,
        )

    def test_first_manual_c6_records_shared_admission_for_later_automatic_lane(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, require_first_manual_admission=True,
        )

    def test_manual_c6_then_manual_c6_does_not_inherit_automatic_n(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, require_first_manual_admission=True,
            manual_after_manual=True,
        )

    def test_crash_after_c6_receipt_before_admission_is_terminal_visible_hold(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, terminal_orphan_probe=True,
        )

    def test_manual_switch_only_c5_to_c6_receipt_preserves_other_sheet_bytes(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, selected_manual_panel="Switch Status",
        )

    def test_manual_empty_switch_panel_creates_no_receipt_or_workbook_change(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, selected_manual_panel="Switch Status",
            selected_panel_empty=True,
        )

    def test_manual_queue_broker_requalifies_selected_panel_before_real_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, selected_manual_panel="Switch Status",
            manual_channel_bridge=True,
        )

    def test_real_three_panel_source_paths_times_hashes_reopen_or_hold(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, source_identity_probe=True,
        )

    def test_real_protected_three_panel_preview_classifies_workbook_without_committing(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, panel_counts_probe=True,
        )

    def test_complete_manual_preview_binds_source_files_and_workbook_before_real_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, complete_preview_probe=True,
        )

    def test_complete_manual_preview_source_stat_race_before_c6_never_receipts(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, complete_preview_probe=True, complete_preview_source_race=True,
        )

    def test_complete_manual_browser_confirm_crosses_real_cgi_queue_and_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, complete_preview_probe=True, complete_preview_cgi=True,
        )

    def _verify_manual_queue_protected_commit(
        self, project, original_template, before_generations, qualified,
    ):
        from monitor.issue_tracker_manual_channel import (
            DurableManualQueue, ManualChannelHold, ManualQueueWorker,
        )
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        from monitor.issue_tracker_manifest import selected_panel_decision_sha256
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, commit_qualified_prod_local,
        )
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook

        queue_root = project / ".tracker/manual-fixture"
        queue_root.mkdir(mode=0o700)
        queue = DurableManualQueue(queue_root, boot_id="synthetic-boot")
        broker = make_protected_stage_l_broker(
            self.store, http_root=self.root, project=project,
            publication=self.publication, template_path=self.template,
            boot_id="synthetic-boot", monotonic_ns=time.monotonic_ns,
            clock=lambda: 1000.0,
        )
        worker = ManualQueueWorker(queue, broker)
        preview_request = {"action": "preview", "panel": "Switch Status",
                           "principal": "nvis"}

        def preview():
            job = queue.enqueue(preview_request)
            completed, result = worker.process_job(job)
            self.assertEqual(job, completed)
            self.assertEqual("done", queue.status(job)["state"])
            self.assertEqual(
                selected_panel_decision_sha256(qualified, "Switch Status"),
                result["selected_decision_sha256"],
            )
            return result["token"]

        def confirm(token, *, principal="nvis"):
            return queue.enqueue({
                "action": "confirm", "panel": "Switch Status",
                "principal": principal, "token": token,
                "confirmation": "publish_local",
            })

        generation_root = project / ".tracker/generations"

        def no_receipt():
            self.assertEqual(before_generations,
                             tuple(sorted(generation_root.iterdir())))
            self.assertFalse(any(generation_root.glob("*/RECEIPT")))

        token = preview()
        with self.assertRaises(ManualChannelHold):
            queue.enqueue({**preview_request, "principal": ""})
        wrong_job = confirm(token, principal="cumulus")
        self.assertEqual({"error": "manual_hold"}, worker.process_job(wrong_job)[1])
        self.assertEqual("done", queue.status(wrong_job)["state"])
        no_receipt()

        # The same preview is consumed before a failed source refresh.
        self.template.write_bytes(b"corrupt-source")
        drift_job = confirm(token)
        with self.assertRaises(StageLHold):
            worker.process_job(drift_job)
        self.assertEqual("unknown_after_claim", queue.status(drift_job)["state"])
        self.assertTrue((queue_root / f"claimed-{drift_job}.json").is_file())
        no_receipt()
        self.template.write_bytes(original_template)
        replay_job = confirm(token)
        self.assertEqual({"error": "manual_hold"}, worker.process_job(replay_job)[1])
        no_receipt()

        # A fresh status is valid, but a different selected C5 decision is
        # injected only when the protected writer requalifies under LK-P.
        token = preview()
        real_commit = commit_qualified_prod_local

        def changed_decision(*args, **kwargs):
            with mock.patch(
                "monitor.issue_tracker_publish_runtime.selected_panel_decision_sha256",
                return_value="0" * 64,
            ):
                return real_commit(*args, **kwargs)

        changed_job = confirm(token)
        with mock.patch(
            "monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
            side_effect=changed_decision,
        ), self.assertRaises(StageLHold):
            worker.process_job(changed_job)
        self.assertEqual("unknown_after_claim", queue.status(changed_job)["state"])
        no_receipt()

        token = preview()
        error_job = confirm(token)
        with mock.patch(
            "monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
            side_effect=RuntimeError("synthetic worker exception"),
        ), self.assertRaises(RuntimeError):
            worker.process_job(error_job)
        self.assertEqual("unknown_after_claim", queue.status(error_job)["state"])
        no_receipt()

        token = preview()
        real_results = []

        def capture_commit(*args, **kwargs):
            result = real_commit(*args, **kwargs)
            real_results.append(result)
            return result

        success_job = confirm(token)
        with mock.patch(
            "monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
            side_effect=capture_commit,
        ):
            completed, public = worker.process_job(success_job)
        self.assertEqual(success_job, completed)
        self.assertEqual("done", queue.status(success_job)["state"])
        self.assertEqual(1, len(real_results))
        committed = real_results[0]
        self.assertIsInstance(committed, CommittedProdWorkbook)
        self.assertEqual("committed", public["local"])
        self.assertEqual(committed.receipt.manifest_id, public["manifest_id"])
        self.assertEqual(committed.generation.generation_id,
                         public["generation_id"])
        self.assertIs(public["local_applied"], True)
        self.assertEqual("disabled_no_send_authority", public["online"])
        generation = generation_root / public["generation_id"]
        persisted = json.loads((generation / "MANIFEST").read_bytes())
        self.assertEqual("Switch Status",
                         persisted["qualified_source"]["selected_panel"])
        self.assertTrue((generation / "RECEIPT").is_file())
        with zipfile.ZipFile(BytesIO(original_template)) as before, \
             zipfile.ZipFile(BytesIO(committed.prepared.xlsx_bytes)) as after:
            for other in ("sheet3.xml", "sheet4.xml"):
                path = "xl/worksheets/" + other
                self.assertEqual(before.read(path), after.read(path), other)
        retry_job = confirm(token)
        self.assertEqual({"error": "manual_hold"}, worker.process_job(retry_job)[1])
        self.assertEqual(1, len(real_results))

    def _exercise_real_protected_three_panel_fixture(
        self, *, skip_history, automatic_first=False, replayed_auto=False,
        invalid_auto_clock=False, automatic_not_due=False,
        automatic_second_due=False, manual_second_probe=False,
        manual_second_admit=False,
        require_first_manual_admission=False, manual_after_manual=False,
        terminal_orphan_probe=False, selected_manual_panel=None,
        selected_panel_empty=False, manual_channel_bridge=False,
        source_identity_probe=False, two_cycle_changed_latest=False,
        settings_channel_probe=False, settings_channel_fault=False,
        panel_counts_probe=False, source_unit_probe=False, receipted_source_probe=False, observed_source_probe=False,
        observed_switch_insert_probe=False, observed_cabling_insert_probe=False, business_preread_probe=False, original_reserved_probe=False, receipted_intent_probe=False,
        complete_preview_probe=False,
        complete_preview_source_race=False,
        complete_preview_cgi=False,
    ):
        from monitor.collection_ib_producer import (
            IbProducerAuthoritySnapshot, parse_ib_producer_authority,
            produce_worker_ib_analysis,
        )
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, commit_qualified_prod_local, inspect_stage_l,
            local_publish_interval,
            read_auto_local_admission,
        )
        from monitor.issue_tracker_ib_runtime import read_prod_ib_k_window
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, ProdWorkbookNoop,
            commit_prod_stage_l_workbook,
        )
        from monitor.issue_tracker_local_commit import LocalCommitHold
        from monitor.issue_tracker_local_workbook import _read_bound_source
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, qualify_prod_stage_l,
        )
        from monitor.issue_tracker_state_owner import (
            current_k, initialize_tracker_state, set_k, tracker_writer,
        )
        from test_cases.test_collection_cycle_persistence import WORKER, TOKEN_1, TOKEN_2
        from test_cases.test_collection_ib_producer import _record
        from test_cases.test_issue_tracker_ib_runtime_workflow import ROOT
        from tools.project_contract import (
            MIN_CONTINUOUS_INTERVAL_MINUTES, build_collection_cycle_identity,
        )
        from tools.ufm_collection_contract import publish_local_archive
        from tools.ufm_remote_producer import (
            RemoteCollectionObservation, VerifiedRetrievedObservation,
        )

        project = self.root / "DAY0-Prepare/fabric-a"
        project.mkdir(parents=True)
        self.gate.__exit__(None, None, None)
        protected_gate = WORKER.CollectionGate(
            str(project), "prod", status_dir=self.root / "monitor/status",
            enforce_cooldown=False, lane="collection",
        )
        held_gate = protected_gate.__enter__()
        self.addCleanup(lambda: protected_gate.__exit__(None, None, None))
        self.store = WORKER.CollectionCycleStore(gate=held_gate)
        self.project = project
        setup = self.root / "ztp/config/nvos/template/P2P"
        setup.mkdir(parents=True)
        selected = project / "fabric-blue.xlsx"
        with xlsxwriter.Workbook(str(selected)) as book:
            sheet = book.add_worksheet("CL links")
            for col, item in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, col, item)
            for col, item in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, col, item)
            if observed_cabling_insert_probe:
                for col, item in enumerate(("leaf01", "sw1p2", "server03", "mlx5_2")):
                    sheet.write(2, col, item)
        (project / "p2p.xlsx").symlink_to(selected.name)
        (setup / "p2p.xlsx").symlink_to(
            "../../../../../DAY0-Prepare/fabric-a/p2p.xlsx")
        for name, body in (("01-inventory.log", "[ib-sw]\n*leaf*\n\n[server]\n*server*\n"),
                           ("02-port-mapping.log", ""), ("03-splitter.log", "")):
            (setup / name).write_text(body, encoding="utf-8")
        output = setup / "output-p2p"
        output.mkdir()
        cvt = output / "fabric-blue-cvt.xlsx"
        converted = subprocess.run(
            [sys.executable, "-B", str(ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"),
             "--output", str(cvt), "--inventory", str(setup / "01-inventory.log"),
             "--port-map", str(setup / "02-port-mapping.log"),
             "--splitter", str(setup / "03-splitter.log")],
            cwd=setup, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                            "XLSX_TO_CSV_BASE_DIR": str(setup)},
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(0, converted.returncode, converted.stdout + converted.stderr)
        incoming = project / "99-output-ufm/incoming"
        incoming.mkdir(parents=True)
        identity = build_collection_cycle_identity(str(project), "prod", 1, TOKEN_1)
        record = _record()
        record.update({
            "project_key": identity["project_key"], "project_root": str(project),
            "retrieval_dir": str(incoming),
            "p2p_sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
            "cvt_sha256": hashlib.sha256(cvt.read_bytes()).hexdigest(),
            "cvt_provenance_sha256": hashlib.sha256(
                Path(f"{cvt}.provenance.json").read_bytes()).hexdigest(),
        })
        authority = IbProducerAuthoritySnapshot(
            parse_ib_producer_authority(
                record, project_key=identity["project_key"], project_root=project),
            "b" * 64, (1, 2, 3),
        )
        vendor = self.root / "vendor-iblinkinfo.txt"
        vendor.write_text(
            "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
            ' 1 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
            '20 1[  ] "server02 mlx5_1"\n' + (
                ' 1 2[  ] ==( 4X 200 Gbps Active / LinkUp )==> 21 2[  ] "server04 mlx5_3"\n'
                if observed_cabling_insert_probe else ''), encoding="utf-8",
        )
        protected = self.root / "synthetic-root-attestation"
        protected.mkdir(mode=0o700)

        def retrieved(plan, **_kwargs):
            archive = publish_local_archive(plan, vendor, incoming)
            sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            return VerifiedRetrievedObservation(
                RemoteCollectionObservation("EXAMPLE-UFM01", plan.run_id,
                                            "iblinkinfo", plan.ufm_remote_path, sha),
                archive, sha, sha, sha, "b" * 64, "b" * 64,
            )

        with mock.patch("monitor.collection_ib_producer._ROOT_UID", os.getuid()), \
             mock.patch("monitor.collection_ib_producer._open_protected_attestation_dir",
                        side_effect=lambda _key: os.open(protected, os.O_RDONLY)), \
             mock.patch("monitor.collection_ib_producer.load_ib_producer_authority",
                        return_value=authority), \
             mock.patch("monitor.collection_ib_producer.recheck_ib_producer_authority"), \
             mock.patch("monitor.collection_ib_producer.observe_and_retrieve_remote_producer",
                        side_effect=retrieved):
            binding = produce_worker_ib_analysis(
                identity, project_root=project, http_root=self.root,
                clock=lambda: dt.datetime(2026, 9, 26, 4, 20,
                                          tzinfo=dt.timezone.utc),
                runner=lambda _argv: self.fail("transport is supplied by fixture"),
            )
            if selected_panel_empty:
                from test_cases.test_issue_tracker_switch_info_source import (
                    _info as healthy_info, _nvl_info as healthy_nvl_info,
                )
                switch_inputs = (
                    mock.patch(
                        "test_cases.test_issue_tracker_switch_runtime_workflow._info",
                        side_effect=lambda host, **_kwargs: healthy_info(
                            host, fan_state="ok"),
                    ),
                    mock.patch(
                        "test_cases.test_issue_tracker_switch_runtime_workflow._nvl_info",
                        side_effect=lambda host, **_kwargs: healthy_nvl_info(
                            host, asic_current="30"),
                    ),
                )
                with switch_inputs[0], switch_inputs[1]:
                    cycle, artifacts = self._cycle(
                        activity=True, derivation=True, ib_analysis=binding,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"},
                    )
            else:
                cycle, artifacts = self._cycle(
                    activity=True, derivation=True, ib_analysis=binding,
                    fabric_templates={"ethernet/prod": "tan-leaf",
                                      "nvlink/prod": "border-leaf"},
                    additional_eth_activity=observed_cabling_insert_probe,
                )
            self.assertEqual(identity["cycle_id"], cycle["cycle_id"])
            self.publication = project / "99-output-monitor"
            self.publication.mkdir()
            initialize_tracker_state(
                project, self.publication, initialized_at="2026-09-25T00:00:00Z",
                acquisition_id="req7-three-panel-protected-fixture",
            )
            self.template = self.publication / "local.xlsx"
            self.template.write_bytes(fake_workbook(reserved_switch_rows=4))
            if manual_channel_bridge or complete_preview_probe:
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(self.template.read_bytes())
                self.template = root_template
            self.snapshot = read_whitelist_workbook(self.template)
            with tracker_writer(project, self.publication) as token:
                set_k(token, new_k=2 if two_cycle_changed_latest else 1,
                      actor="operator:fixture",
                      recorded_at="2026-09-25T00:01:00Z",
                      request_id=("req7-three-panel-k2" if two_cycle_changed_latest
                                  else "req7-three-panel-k1"), expected_revision=0)
                self.settings = current_k(token)
            args = {"http_root": self.root, "settings": self.settings,
                    "whitelist_snapshot": self.snapshot,
                    "whitelist_path": self.template}
            if skip_history:
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n",
                    encoding="utf-8",
                )
                self._verify_protected_skip_commit(project, args)
                return
            if two_cycle_changed_latest:
                second_identity = build_collection_cycle_identity(
                    str(project), "prod", 2, TOKEN_2,
                )
                vendor.write_text(
                    "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                    ' 1 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                    '20 1[  ] "server03 mlx5_1"\n', encoding="utf-8",
                )
                second_binding = produce_worker_ib_analysis(
                    second_identity, project_root=project, http_root=self.root,
                    clock=lambda: dt.datetime(2026, 9, 26, 4, 31,
                                              tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail("transport is supplied by fixture"),
                )
                from test_cases.test_issue_tracker_switch_info_source import _nvl_info
                with mock.patch(
                    "test_cases.test_issue_tracker_switch_runtime_workflow._nvl_info",
                    side_effect=lambda host, **_kwargs: _nvl_info(host, asic_current="81"),
                ):
                    second_cycle, _ = self._cycle(
                        activity=True, derivation=True,
                        ib_analysis=second_binding, observed_peer="changed-peer",
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"},
                    )
                self.assertEqual(second_identity["cycle_id"], second_cycle["cycle_id"])
                self._verify_two_cycle_latest_local_commit(
                    project, args, (cycle["cycle_id"], second_cycle["cycle_id"]),
                )
                return
            qualified = qualify_prod_stage_l(self.store, **args)
            self.assertTrue(qualified.qualified)
            self.assertEqual("prod-runtime-protected-v1", qualified.mode)
            self.assertEqual((cycle["cycle_id"],), qualified.cycle_ids)
            expected_panels = ({"Eth Link Validation", "IB Link Validation"}
                               if selected_panel_empty else
                               {"Switch Status", "Eth Link Validation",
                                "IB Link Validation"})
            expected_count = 2 if selected_panel_empty else (6 if observed_cabling_insert_probe else 4)
            self.assertEqual(expected_panels,
                             {item.panel for item in qualified.candidates})
            self.assertEqual(expected_count, len(qualified.candidates))
            if complete_preview_probe:
                from monitor import issue_tracker_manual_preview as manual
                from test_cases.test_issue_tracker_manual_ui import browser_settings_script
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n", encoding="utf-8")
                broker = manual.make_complete_protected_stage_l_broker(
                    self.store, http_root=self.root, project=project,
                    publication=self.publication, template_path=self.template,
                    boot_id="complete-preview-fixture", monotonic_ns=time.monotonic_ns,
                    clock=lambda: 1000.0,
                )
                generated_confirm = {}
                if complete_preview_cgi:
                    from urllib.parse import urlencode
                    from monitor.issue_tracker_manual_channel import DurableManualQueue, ManualQueueWorker
                    from test_cases.test_issue_tracker_manual_ui_workflow import CGI, environ
                    queue_root = project / ".tracker/complete-preview-queue"
                    queue_root.mkdir(mode=0o700)
                    queue = DurableManualQueue(queue_root, boot_id="complete-preview-fixture")
                    worker = ManualQueueWorker(queue, broker)
                    def cgi(body):
                        def submit(request):
                            job = queue.enqueue(request)
                            done, result = worker.process_job(job)
                            self.assertEqual(job, done)
                            self.assertEqual("done", queue.status(job)["state"])
                            return result
                        return CGI.handle(environ(body), body, submit=submit)
                previews = {}
                for panel, count, files in (("Switch Status", 2, 2),
                                            ("Eth Link Validation", 1, 1),
                                            ("IB Link Validation", 1, 1)):
                    if complete_preview_cgi:
                        body = urlencode({"action": "preview", "panel": panel}).encode("ascii")
                        status, preview = cgi(body)
                        self.assertEqual("200 OK", status)
                    else:
                        preview = broker.preview("nvis", panel)
                    previews[panel] = preview
                    self.assertEqual((count, count, 0, 0), tuple(preview[key] for key in (
                        "qualified_operation_count", "new_count", "update_count", "skip_count")))
                    self.assertEqual(files, len(preview["source_files"]))
                    self.assertEqual(count, len(preview["row_digests"]))
                    for item in preview["source_files"]:
                        self.assertEqual(hashlib.sha256((self.root / item["path"]).read_bytes()).hexdigest(),
                                         item["sha256"])
                    browser = browser_settings_script(
                        "console.log(JSON.stringify({valid:validIssueTrackerPreview(" +
                        json.dumps(preview) + "," + json.dumps(panel) + ")}));")
                    self.assertEqual({"valid": True}, browser)
                    if complete_preview_cgi:
                        browser = browser_settings_script(
                            "replies.push(" + json.dumps(preview) + ");\n"
                            "await issueTrackerManualPreview(" + json.dumps(panel) + ");\n"
                            "replies.push({local_applied:false});\n"
                            "await issueTrackerManualConfirm();\n"
                            "console.log(JSON.stringify({calls}));")
                        self.assertEqual(body.decode("ascii"), browser["calls"][0]["body"])
                        generated_confirm[panel] = browser["calls"][1]["body"].encode("ascii")
                if complete_preview_source_race:
                    real_commit = broker._commit_local
                    def change_after_confirm_read(panel, fingerprint):
                        path = artifacts["ethernet/prod"]["info"]
                        stamp = path.stat().st_mtime_ns
                        os.utime(path, ns=(stamp + 2_000_000_000, stamp + 2_000_000_000))
                        return real_commit(panel, fingerprint)
                    broker._commit_local = change_after_confirm_read
                    with self.assertRaises(StageLHold):
                        broker.confirm("nvis", "Switch Status", previews["Switch Status"]["token"],
                                       confirmation="publish_local")
                    self.assertFalse(any((project / ".tracker/generations").glob("*/RECEIPT")))
                    with self.assertRaises(manual.ManualPreviewHold):
                        broker.confirm("nvis", "Switch Status", previews["Switch Status"]["token"],
                                       confirmation="publish_local")
                    return
                if complete_preview_cgi:
                    status, committed = cgi(generated_confirm["Switch Status"])
                    self.assertEqual("200 OK", status)
                else:
                    committed = broker.confirm("nvis", "Switch Status", previews["Switch Status"]["token"],
                                               confirmation="publish_local")
                self.assertTrue(committed["local_applied"])
                receipts = tuple((project / ".tracker/generations").glob("*/RECEIPT"))
                self.assertEqual(1, len(receipts))
                # Even an untouched ETH source cannot reuse counts computed
                # against the pre-Switch local workbook image.
                if complete_preview_cgi:
                    status, held = cgi(generated_confirm["Eth Link Validation"])
                    self.assertEqual(("409 Conflict", {"error": "manual_hold"}), (status, held))
                else:
                    with self.assertRaises(manual.ManualPreviewHold):
                        broker.confirm("nvis", "Eth Link Validation",
                                       previews["Eth Link Validation"]["token"],
                                       confirmation="publish_local")
                self.assertEqual(receipts, tuple((project / ".tracker/generations").glob("*/RECEIPT")))
                return
            if panel_counts_probe:
                from monitor.issue_tracker_local_workbook_commit import (
                    project_manual_panel_image, project_manual_panel_preview,
                )
                source = self.template.read_bytes()
                generation_root = project / ".tracker/generations"
                before_generations = tuple(generation_root.iterdir())
                for panel, count in (("Switch Status", 2),
                                     ("Eth Link Validation", 1),
                                     ("IB Link Validation", 1)):
                    _, manifest_id = freeze_prod_stage_l_manifest(
                        qualified, self.store, metadata={
                            "project_id": str(project), "schema_version": 1,
                            "producer_version": "stage-l-runtime-v1",
                            "template_contract_version": "local-xlsx-v1",
                            "template_sha256": self.snapshot.workbook_sha256,
                        }, expected_template_sha256=self.snapshot.workbook_sha256,
                        selected_panel=panel, **args,
                    )
                    preview = project_manual_panel_preview(source, qualified, panel, manifest_id)
                    self.assertEqual((count, count, 0, 0), tuple(preview[key] for key in (
                        "qualified_operation_count", "new_count", "update_count", "skip_count")))
                    self.assertEqual(count, len(preview["row_digests"]))
                    image = project_manual_panel_image(source, qualified, panel, manifest_id)
                    noop = project_manual_panel_preview(image, qualified, panel, manifest_id)
                    self.assertEqual((0, 0, count), tuple(noop[key] for key in (
                        "new_count", "update_count", "skip_count")))
                self.assertEqual(source, self.template.read_bytes())
                self.assertEqual(before_generations, tuple(generation_root.iterdir()))
                return
            if source_identity_probe:
                from monitor.issue_tracker_stage_l_consumer import (
                    read_prod_stage_l_panel_source_files,
                    validate_prod_stage_l_panel_source_files,
                )
                expected = {
                    "Switch Status": {
                        artifacts["ethernet/prod"]["info"],
                        artifacts["nvlink/prod"]["info"],
                    },
                    "Eth Link Validation": {
                        artifacts["ethernet/prod"]["activity"],
                    },
                    "IB Link Validation": {
                        project / "99-output-ufm/runs" / binding["run_id"] /
                        "EXAMPLE-UFM01" /
                        f"iblinkinfo_{binding['run_id']}-topology-validation.xlsx",
                    },
                }
                witnessed_by_panel = {}
                for panel, source_paths in expected.items():
                    witnessed = read_prod_stage_l_panel_source_files(
                        qualified, self.store, panel=panel, **args,
                    )
                    witnessed_by_panel[panel] = witnessed
                    self.assertEqual(
                        {str(path.relative_to(self.root)) for path in source_paths},
                        {item.path for item in witnessed},
                    )
                    self.assertTrue(all(item.recorded_at_utc and
                                        item.sha256 == hashlib.sha256(
                                            (self.root / item.path).read_bytes()
                                        ).hexdigest() for item in witnessed))
                    self.assertEqual(witnessed,
                        validate_prod_stage_l_panel_source_files(
                            witnessed, qualified, self.store, panel=panel,
                            **args,
                        ))
                altered = artifacts["ethernet/prod"]["info"]
                prior_ns = altered.stat().st_mtime_ns
                os.utime(altered, ns=(prior_ns + 2_000_000_000,
                                      prior_ns + 2_000_000_000))
                with self.assertRaises(StageLConsumerHold):
                    validate_prod_stage_l_panel_source_files(
                        witnessed_by_panel["Switch Status"], qualified, self.store,
                        panel="Switch Status", **args,
                    )
                altered.write_bytes(b"changed after protected preview")
                with self.assertRaises(StageLConsumerHold):
                    validate_prod_stage_l_panel_source_files(
                        witnessed_by_panel["Switch Status"], qualified, self.store,
                        panel="Switch Status", **args,
                    )
                return
            stage_status = inspect_stage_l(
                self.store, http_root=self.root, project=project,
                publication=self.publication, template_path=self.template,
            )
            self.assertEqual("qualified", stage_status["state"])
            self.assertEqual(expected_count, stage_status["qualified_operation_count"])
            self.assertEqual(0, stage_status["whitelist_skip_count"])
            self.assertEqual("disabled_no_send_authority", stage_status["online"])
            self.assertNotIn("receipt", stage_status)
            if settings_channel_probe or settings_channel_fault:
                self._verify_authenticated_settings_channel(project, fault=settings_channel_fault)
                return
            protected_time = read_prod_ib_k_window(self.store, **args).recorded_at_utc
            self.assertTrue(protected_time)
            self.assertEqual(protected_time, qualified.recorded_at_utc)
            self.assertEqual({protected_time},
                             {item.recorded_at_utc for item in qualified.candidates})
            observations = json.dumps({
                "candidates": [asdict(item) for item in qualified.candidates],
                "whitelist_skips": [asdict(item) for item in qualified.whitelist_skips],
                "hostname_fallback_count": sum(
                    item.fabric_source == "hostname-fallback"
                    for item in qualified.candidates
                ),
                "recorded_at_utc": protected_time,
            }, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode("utf-8") + b"\n"
            self.assertEqual(hashlib.sha256(observations).hexdigest(),
                             qualified.observations_sha256)
            with tracker_writer(project, self.publication) as token:
                self.assertEqual(
                    qualified,
                    qualify_prod_stage_l(self.store, writer_token=token, **args),
                )
            metadata = {
                "project_id": str(project), "schema_version": 1,
                "producer_version": "req7-test-producer",
                "template_contract_version": "v1",
                "template_sha256": self.snapshot.workbook_sha256,
            }
            before_publication = tuple(sorted(self.publication.iterdir()))
            body, digest = freeze_prod_stage_l_manifest(
                qualified, self.store, metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                **args,
            )
            self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
            self.assertEqual(
                protected_time,
                json.loads(body)["qualified_source"]["recorded_at_utc"],
            )
            self.assertEqual(before_publication,
                             tuple(sorted(self.publication.iterdir())))
            generation_root = project / ".tracker/generations"
            before_generations = tuple(sorted(generation_root.iterdir()))
            original_template = self.template.read_bytes()
            if source_unit_probe:
                from monitor.issue_tracker_send_unit import freeze_prod_source_unit, SendUnitHold
                for sheet, family, sid in (('ETH&IB Switch', 'switch', 101), ('ETH Cabling', 'eth_cabling', 102),
                                           ('IB Cabling', 'ib_cabling', 103)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    self.assertTrue(candidates, 'all three real protected families must be exercised')
                    placements = tuple({'operation_id': item.operation_id, 'action': 'update' if family == 'switch' else 'insert',
                        'row_index': index + 2 if family == 'switch' else None, 'observed_values': {'L': {}} if family == 'switch' else None,
                        'reserved_id': None if family == 'switch' else 'NV%05d' % (41001 + index)}
                        for index, item in enumerate(candidates))
                    options = dict(generation_id='a' * 64, publish_id='b' * 64,
                        spreadsheet_id='synthetic_spreadsheet_id_0001', sheet=sheet, sheet_id=sid, history_sheet_id=105,
                        target_nonce='c' * 64, history_nonce='d' * 64, preread_sha256='e' * 64,
                        audits=(), occupied_metadata_ids=())
                    with tracker_writer(project, self.publication) as token:
                        value = freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                            expected_template_sha256=self.snapshot.workbook_sha256, placements=placements, writer_token=token,
                            **args, **options)
                        image = json.loads(value.action_preimage)
                        self.assertEqual(digest, image['manifest_id'])
                        self.assertEqual([item.operation_id for item in candidates], [item['operation_id'] for item in image['business']])
                        self.assertEqual([list(item.activity_key) for item in candidates], [item['activity_key'] for item in image['business']])
                        self.assertEqual([item.recorded_at_utc for item in candidates], [item['recorded_at_utc'] for item in image['business']])
                        for item, candidate in zip(image['business'], candidates):
                            if family == 'switch':
                                self.assertEqual({'stringValue': '[MONITOR][%s][%s] [fabric_source=%s] %s' %
                                    (candidate.activity_key[2], candidate.activity_key[3], candidate.fabric_source, candidate.evidence_description)},
                                    item['requests'][0]['updateCells']['rows'][0]['values'][0]['userEnteredValue'])
                            else:
                                cells = item['requests'][0]['appendCells']['rows'][0]['values']
                                self.assertEqual({'stringValue': 'ETH' if family == 'eth_cabling' else 'IB'}, cells[4]['userEnteredValue'])
                                self.assertEqual({'stringValue': 'New'}, cells[20]['userEnteredValue'])
                                self.assertEqual({'stringValue': candidate.activity_key[3]}, cells[5]['userEnteredValue'])
                        invented = tuple({**item, 'values': {'L': 'caller invented text'}} for item in placements)
                        with self.assertRaises(SendUnitHold):
                            freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=invented, writer_token=token, **args, **options)
                        altered = replace(qualified, candidates=tuple(replace(item, evidence_description='caller invented text')
                                                                      for item in qualified.candidates))
                        with self.assertRaises(SendUnitHold):
                            freeze_prod_source_unit(altered, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=placements, writer_token=token, **args, **options)
                        if family == 'switch':
                            noop_placements = tuple({**placement, 'observed_values': {'L': {
                                'stringValue': '[MONITOR][%s][%s] [fabric_source=%s] %s' %
                                    (candidate.activity_key[2], candidate.activity_key[3], candidate.fabric_source,
                                     candidate.evidence_description)}}}
                                for placement, candidate in zip(placements, candidates))
                            noop = freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=noop_placements,
                                writer_token=token, **args, **options)
                            self.assertEqual('NO_SEND', noop.outcome)
                            self.assertEqual(b'', noop.wire_bytes)
                            self.assertEqual(0, noop.history_rows_expected)
                            source_path = artifacts['ethernet/prod']['info']
                            source_before = source_path.read_bytes()
                            from monitor.issue_tracker_online_cells import source_tool_values as real_values
                            def drift_after_source_values(*values_args, **values_kwargs):
                                result = real_values(*values_args, **values_kwargs)
                                source_path.write_bytes(source_before + b'\nchanged during source compilation\n')
                                return result
                            try:
                                with mock.patch('monitor.issue_tracker_online_cells.source_tool_values',
                                                side_effect=drift_after_source_values), self.assertRaises(SendUnitHold):
                                    freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                                        expected_template_sha256=self.snapshot.workbook_sha256, placements=placements,
                                        writer_token=token, **args, **options)
                            finally:
                                source_path.write_bytes(source_before)
                    self.assertEqual(before_publication, tuple(sorted(self.publication.iterdir())))
                    self.assertEqual(before_generations, tuple(sorted(generation_root.iterdir())))
                    self.assertEqual(original_template, self.template.read_bytes())
                return
            if selected_manual_panel is not None:
                selected_body, selected_id = freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    selected_panel=selected_manual_panel, **args,
                )
                scoped = json.loads(selected_body)
                self.assertEqual("Switch Status",
                                 scoped["qualified_source"]["selected_panel"])
                if selected_panel_empty:
                    self.assertEqual([], scoped["operations"])
                    self.assertEqual([], scoped["qualified_source"]["whitelist_skips"])
                    evaluations = scoped["qualified_source"]["panel_evaluation"]
                    self.assertEqual(
                        {"state": "evaluated", "whitelist_skips": "no-skips"},
                        evaluations["Switch Status"],
                    )
                    for other in ("Eth Link Validation", "IB Link Validation"):
                        self.assertEqual(
                            {"state": "not-evaluated-in-this-manifest"},
                            evaluations[other],
                        )
                    self.assertEqual(
                        qualified.source_authority_sha256,
                        scoped["qualified_source"]["source_authority_sha256"],
                    )
                    self.assertEqual(
                        qualified.observations_sha256,
                        scoped["qualified_source"]["observations_sha256"],
                    )
                self.assertEqual(set() if selected_panel_empty else {"Switch Status"},
                                 {item.panel for item in qualified.candidates
                                  if item.operation_id in {operation["operation_id"]
                                      for operation in scoped["operations"]}})
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n",
                    encoding="utf-8",
                )
                if manual_channel_bridge:
                    self._verify_manual_queue_protected_commit(
                        project, original_template, before_generations,
                        qualified,
                    )
                    return
                interval, policy_sha = local_publish_interval(project)
                witness = (policy_sha, interval, "fixture-boot", time.monotonic_ns())
                with tracker_writer(project, self.publication) as token:
                    committed = commit_prod_stage_l_workbook(
                        token, qualified, self.store,
                        template_path=self.template, metadata=metadata,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        manual_admission=witness,
                        selected_panel=selected_manual_panel, **args,
                    )
                if selected_panel_empty:
                    self.assertIsInstance(committed, ProdWorkbookNoop)
                    self.assertEqual("no_candidates", committed.status)
                    self.assertEqual(selected_id, committed.manifest_id)
                    self.assertEqual(before_generations,
                                     tuple(sorted(generation_root.iterdir())))
                    self.assertFalse(any(generation_root.glob("*/RECEIPT")))
                    self.assertEqual(original_template, self.template.read_bytes())
                    with zipfile.ZipFile(BytesIO(original_template)) as before, \
                         zipfile.ZipFile(BytesIO(self.template.read_bytes())) as after:
                        for other in ("sheet3.xml", "sheet4.xml"):
                            path = "xl/worksheets/" + other
                            self.assertEqual(before.read(path), after.read(path))
                    return
                self.assertIsInstance(committed, CommittedProdWorkbook)
                self.assertEqual(3, committed.prepared.source_family_count)
                self.assertEqual(selected_id, committed.receipt.manifest_id)
                generation = (project / ".tracker/generations" /
                              committed.generation.generation_id)
                self.assertEqual(selected_body, (generation / "MANIFEST").read_bytes())
                self.assertTrue((generation / "RECEIPT").is_file())
                persisted_manifest = json.loads((generation / "MANIFEST").read_bytes())
                self.assertEqual(selected_manual_panel,
                                 persisted_manifest["qualified_source"]["selected_panel"])
                evaluations = persisted_manifest["qualified_source"]["panel_evaluation"]
                self.assertEqual({"state": "evaluated", "whitelist_skips": "no-skips"},
                                 evaluations["Switch Status"])
                for other in ("Eth Link Validation", "IB Link Validation"):
                    self.assertEqual({"state": "not-evaluated-in-this-manifest"},
                                     evaluations[other])
                persisted_receipt = json.loads((generation / "RECEIPT").read_bytes())
                self.assertEqual(selected_id, persisted_receipt["manifest_id"])
                self.assertEqual(1 + len(before_generations),
                                 len(tuple(generation_root.iterdir())))
                with zipfile.ZipFile(BytesIO(original_template)) as before, \
                     zipfile.ZipFile(BytesIO(committed.prepared.xlsx_bytes)) as after:
                    for other in ("sheet3.xml", "sheet4.xml"):
                        path = "xl/worksheets/" + other
                        self.assertEqual(before.read(path), after.read(path), other)
                    self.assertNotEqual(before.read("xl/worksheets/sheet2.xml"),
                                        after.read("xl/worksheets/sheet2.xml"))
                    self.assertNotEqual(before.read("xl/worksheets/sheet6.xml"),
                                        after.read("xl/worksheets/sheet6.xml"))
                return
            if automatic_first:
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(original_template)
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n"
                    + ("      publish_every_cycles: 2\n"
                       if automatic_not_due else ""),
                    encoding="utf-8",
                )
                stage_status_path = (
                    self.root / "monitor/status/issue-tracker-stage-l.status.json"
                )
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value="" if invalid_auto_clock
                                        else WORKER._current_boot_identity())):
                    result = WORKER._publish_stage_l_local_after_completion(self.store)
                if automatic_not_due:
                    self.assertIsNone(result)
                    self.assertEqual("qualified", json.loads(
                        stage_status_path.read_bytes())["state"])
                    self.assertEqual("not_due", json.loads(
                        stage_status_path.read_bytes())["local"])
                    self.assertEqual(before_generations,
                                     tuple(sorted(generation_root.iterdir())))
                    self.assertFalse((project / ".tracker/admissions").exists())
                    return
                if invalid_auto_clock:
                    self.assertIsNone(result)
                    self.assertEqual("hold", json.loads(
                        stage_status_path.read_bytes())["state"])
                    self.assertEqual(before_generations,
                                     tuple(sorted(generation_root.iterdir())))
                    self.assertFalse((project / ".tracker/admissions").exists())
                    return
                self.assertIsInstance(result, CommittedProdWorkbook)
                self.assertEqual("local_applied", json.loads(
                    stage_status_path.read_bytes())["state"])
                self.assertEqual("disabled_no_send_authority", json.loads(
                    stage_status_path.read_bytes())["online"])
                self.assertEqual(
                    hashlib.sha256(result.prepared.xlsx_bytes).hexdigest(),
                    result.receipt.published_sha256,
                )
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                admission_files = tuple(sorted((project / ".tracker/admissions").iterdir()))
                self.assertEqual(1, len(admission_files))
                admission = json.loads(admission_files[0].read_bytes())
                self.assertEqual(result.receipt.generation_id,
                                 admission["generation_id"])
                self.assertEqual(result.receipt.published_sha256,
                                 admission["published_sha256"])
                self.assertEqual(self.store.project_key, admission["project_key"])
                self.assertEqual("prod", admission["scope"])
                self.assertEqual(1, admission["schema_version"])
                with tracker_writer(project, self.publication) as token:
                    self.assertEqual(admission, read_auto_local_admission(
                        token, self.store, self.snapshot.workbook_sha256,
                    ))
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value=admission["boot_id"])):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                self.assertEqual("qualified", json.loads(
                    stage_status_path.read_bytes())["state"])
                self.assertEqual("not_due", json.loads(
                    stage_status_path.read_bytes())["local"])
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                if automatic_second_due or manual_second_probe or manual_second_admit:
                    second_identity = build_collection_cycle_identity(
                        str(project), "prod", 2, TOKEN_2,
                    )
                    second_binding = produce_worker_ib_analysis(
                        second_identity, project_root=project, http_root=self.root,
                        clock=lambda: dt.datetime(2026, 9, 26, 4, 31,
                                                  tzinfo=dt.timezone.utc),
                        runner=lambda _argv: self.fail(
                            "transport is supplied by fixture"),
                    )
                    second_cycle, _ = self._cycle(
                        activity=True, derivation=True,
                        observed_peer="changed-peer", ib_analysis=second_binding,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"},
                    )
                    self.assertEqual(second_identity["cycle_id"],
                                     second_cycle["cycle_id"])
                    if manual_second_probe:
                        with self.assertRaises(StageLHold):
                            commit_qualified_prod_local(
                                self.store, http_root=self.root,
                                project=project, publication=self.publication,
                                template_path=self.root /
                                "monitor/Issue_Tracker_Template_v1.xlsx",
                            )
                        # The lower C6 helper is also callable with a real
                        # qualified set. It must not mint a second generation
                        # without the same shared admission proof.
                        with tracker_writer(project, self.publication) as token:
                            second_qualified = qualify_prod_stage_l(
                                self.store, writer_token=token, **args,
                            )
                            with self.assertRaisesRegex(
                                LocalCommitHold, "shared admission",
                            ):
                                commit_prod_stage_l_workbook(
                                    token, second_qualified, self.store,
                                    template_path=self.template,
                                    metadata=metadata,
                                    expected_template_sha256=(
                                        self.snapshot.workbook_sha256),
                                    **args,
                                )
                        self.assertEqual(1, len(tuple(
                            (project / ".tracker/admissions").iterdir())))
                        self.assertEqual(len(before_generations) + 1,
                                         len(tuple(generation_root.iterdir())))
                        return
                    later_ns = (admission["monotonic_ns"]
                                + MIN_CONTINUOUS_INTERVAL_MINUTES * 60
                                * 1_000_000_000 + 1)
                    if manual_second_admit:
                        manual_witness = (
                            admission["policy_sha256"],
                            admission["publish_every_cycles"],
                            admission["boot_id"], later_ns,
                        )
                        with mock.patch.object(WORKER.time, "monotonic_ns",
                                               return_value=later_ns):
                            manual_result = commit_qualified_prod_local(
                                self.store, http_root=self.root, project=project,
                                publication=self.publication,
                                template_path=root_template,
                                manual_admission=manual_witness,
                            )
                        self.assertIsInstance(manual_result, CommittedProdWorkbook)
                        with tracker_writer(project, self.publication) as token:
                            manual_event = read_auto_local_admission(
                                token, self.store, self.snapshot.workbook_sha256)
                        self.assertEqual("manual", manual_event["lane"])
                        self.assertEqual(second_cycle["cycle_id"],
                                         manual_event["cycle_id"])
                        self.assertEqual(manual_result.receipt.generation_id,
                                         manual_event["generation_id"])
                        self.assertEqual(2, len(tuple(
                            (project / ".tracker/admissions").iterdir())))
                        self.assertEqual(len(before_generations) + 2,
                                         len(tuple(generation_root.iterdir())))
                        with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                              mock.patch.object(WORKER, "STATUS_DIR",
                                                stage_status_path.parent),
                              mock.patch.object(WORKER,
                                                "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                                stage_status_path),
                              mock.patch.object(WORKER, "_current_boot_identity",
                                                return_value=admission["boot_id"]),
                              mock.patch.object(WORKER.time, "monotonic_ns",
                                                return_value=later_ns)):
                            self.assertIsNone(
                                WORKER._publish_stage_l_local_after_completion(
                                    self.store))
                        held_status = json.loads(stage_status_path.read_bytes())
                        self.assertEqual("not_due", held_status.get("local"),
                                         held_status)
                        self.assertEqual(len(before_generations) + 2,
                                         len(tuple(generation_root.iterdir())))
                        return
                    with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                          mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                          mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                            stage_status_path),
                          mock.patch.object(WORKER, "_current_boot_identity",
                                            return_value=admission["boot_id"]),
                          mock.patch.object(WORKER.time, "monotonic_ns",
                                            return_value=later_ns)):
                        second_result = WORKER._publish_stage_l_local_after_completion(
                            self.store)
                    self.assertIsInstance(second_result, CommittedProdWorkbook)
                    self.assertNotEqual(result.receipt.generation_id,
                                        second_result.receipt.generation_id)
                    self.assertEqual("local_applied", json.loads(
                        stage_status_path.read_bytes())["state"])
                    second_admissions = tuple(sorted(
                        (project / ".tracker/admissions").iterdir()))
                    self.assertEqual(2, len(second_admissions))
                    self.assertEqual(len(before_generations) + 2,
                                     len(tuple(generation_root.iterdir())))
                    with tracker_writer(project, self.publication) as token:
                        latest_admission = read_auto_local_admission(
                            token, self.store, self.snapshot.workbook_sha256)
                    self.assertEqual(second_cycle["cycle_id"],
                                     latest_admission["cycle_id"])
                    self.assertEqual(second_result.receipt.generation_id,
                                     latest_admission["generation_id"])
                    tampered = json.loads(second_admissions[1].read_bytes())
                    tampered["monotonic_ns"] = admission["monotonic_ns"] + 1
                    second_admissions[1].write_bytes(
                        json.dumps(tampered, sort_keys=True,
                                   separators=(",", ":")).encode() + b"\n"
                    )
                    with tracker_writer(project, self.publication) as token:
                        with self.assertRaises(StageLHold):
                            read_auto_local_admission(
                                token, self.store,
                                self.snapshot.workbook_sha256,
                            )
                    return
                # A new boot has no proved elapsed interval from this event.
                # It must remain a visible HOLD, not infer the time floor from
                # completed-cycle count or replay the first C6 image.
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value="fixture-new-boot")):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                self.assertEqual("hold", json.loads(
                    stage_status_path.read_bytes())["state"])
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                admission_files[0].write_bytes(b"{}\n")
                with tracker_writer(project, self.publication) as token:
                    with self.assertRaises(StageLHold):
                        read_auto_local_admission(
                            token, self.store, self.snapshot.workbook_sha256,
                        )
                return

            def drift_after_bound_read(path, snapshot):
                source_bytes = _read_bound_source(path, snapshot)
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("leaf-z",), reserved_switch_rows=4,
                ))
                return source_bytes

            try:
                with tracker_writer(project, self.publication) as token, \
                     mock.patch(
                         "monitor.issue_tracker_local_workbook_commit._read_bound_source",
                         side_effect=drift_after_bound_read,
                     ):
                    with self.assertRaisesRegex(
                        LocalCommitHold,
                        "C-6 workbook source changed before generation",
                    ):
                        commit_prod_stage_l_workbook(
                            token, qualified, self.store,
                            template_path=self.template, metadata=metadata,
                            expected_template_sha256=self.snapshot.workbook_sha256,
                            **args,
                        )
            finally:
                self.template.write_bytes(original_template)
            self.assertEqual(before_generations,
                             tuple(sorted(generation_root.iterdir())))
            (project / "01-global.yaml").write_text(
                "schema_version: 2\ncommon:\n  mgmt:\n"
                "    issue-tracker:\n      status: disabled\n"
                + ("      publish_every_cycles: 3\n"
                   if manual_after_manual else ""),
                encoding="utf-8",
            )
            interval, policy_sha = local_publish_interval(project)
            manual_witness = (policy_sha, interval, "fixture-boot",
                              time.monotonic_ns())
            with tracker_writer(project, self.publication) as token:
                if terminal_orphan_probe:
                    with (mock.patch("monitor.issue_tracker_admission._mkdir",
                                     side_effect=OSError(
                                         "injected post-receipt admission failure")),
                          self.assertRaisesRegex(
                              OSError, "injected post-receipt admission failure")):
                        commit_prod_stage_l_workbook(
                            token, qualified, self.store, template_path=self.template,
                            metadata=metadata,
                            expected_template_sha256=self.snapshot.workbook_sha256,
                            manual_admission=manual_witness,
                            **args,
                        )
                else:
                    committed = commit_prod_stage_l_workbook(
                        token, qualified, self.store, template_path=self.template,
                        metadata=metadata,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        manual_admission=manual_witness,
                        **args,
                    )
            if terminal_orphan_probe:
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                self.assertTrue(any((generation / "RECEIPT").is_file()
                                    for generation in generation_root.iterdir()))
                self.assertFalse((project / ".tracker/admissions").exists())
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(self.template.read_bytes())
                stage_status_path = (
                    self.root / "monitor/status/issue-tracker-stage-l.status.json"
                )
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value="fixture-boot")):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                terminal_status = json.loads(stage_status_path.read_bytes())
                self.assertEqual("hold", terminal_status["state"])
                self.assertEqual("local_c6_terminal_admission_state",
                                 terminal_status["reason"])
                self.assertEqual("C6 RECEIPT has no admission evidence",
                                 terminal_status["terminal_detail"])
                self.assertEqual("disabled_no_send_authority",
                                 terminal_status["online"])
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                return
            self.assertIsInstance(committed, CommittedProdWorkbook)
            self.assertEqual(digest, committed.receipt.manifest_id)
            self.assertEqual(hashlib.sha256(committed.prepared.xlsx_bytes).hexdigest(),
                             committed.receipt.published_sha256)
            if observed_cabling_insert_probe:
                import tempfile
                import monitor.issue_tracker_send_unit as compiler
                from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read, prepare_insertion_sheet_read, prepare_sheets_read, prepare_history_tail_read, prepare_template_identity_read
                from monitor.issue_tracker_sheets_read_decode import decode_template_identity
                from monitor.issue_tracker_online_target import OnlineTargetBinding
                from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                from test_cases.test_req7_activity_discovery import sheet_document, insertion_document, exact_row_document, cabling_row, literal
                from test_cases.test_req7_sheets_read_decode import identity_response, response
                from test_cases.test_req7_spreadsheet_owner import load as load_owner, scoped_fixture
                from test_cases.test_req7_enrollment_journal import load as load_enrollment
                from test_cases.test_req7_nv_reservation import load as load_nv
                self.assertTrue(hasattr(compiler, 'freeze_observed_receipted_cabling_unit'), 'Cabling compiler must bind original source/receipt and durable IDs')
                binding = OnlineTargetBinding('synthetic_spreadsheet_id_0001', 'a'*64, 'b'*64)
                credential = AuthenticatedToken('synthetic.private-token', time.time()+3600)
                identity = decode_template_identity(prepare_template_identity_read(binding, credential), response(identity_response()))
                history_plan = prepare_history_tail_read(binding, credential)
                history_raw = response({'spreadsheetId': binding.spreadsheet_id, 'sheets': [{'properties': {'sheetId': 105,
                    'title': 'Update_History', 'sheetType': 'GRID', 'gridProperties': {'rowCount': 100, 'columnCount': 5}},
                    'data': [{'startRow': 2, 'startColumn': 0}]}]})
                for sheet, family, sid, other_sheet, other_sid in (('ETH Cabling', 'eth_cabling', 102, 'IB Cabling', 103),
                                                                  ('IB Cabling', 'ib_cabling', 103, 'ETH Cabling', 102)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    self.assertGreater(len(candidates), 1)
                    row = cabling_row('NV30016'); key = candidates[0].activity_key
                    row.update({column: literal(value) for column, value in zip(('K', 'L', 'F'), key[1:])})
                    closed = cabling_row('NV30017', 'Closed'); key = candidates[-1].activity_key
                    closed.update({column: literal(value) for column, value in zip(('K', 'L', 'F'), key[1:])})
                    rows = [row, closed, {'V': {'boolValue': False}}]
                    discovery = sheet_document(sheet, rows, 100); discovery['sheets'][0]['properties']['sheetId'] = sid
                    occupancy = insertion_document(sheet, rows, 100); occupancy['sheets'][0]['properties']['sheetId'] = sid
                    other = cabling_row('NV39999', 'Closed'); other['K'] = literal('unrelated-original-seed')
                    other_raw = sheet_document(other_sheet, [other], 100); other_raw['sheets'][0]['properties']['sheetId'] = other_sid
                    discovery_plan = prepare_activity_sheet_read(binding, credential, sheet=sheet)
                    occupancy_plan = prepare_insertion_sheet_read(binding, credential, sheet=sheet)
                    other_plan = prepare_activity_sheet_read(binding, credential, sheet=other_sheet)
                    original_read = response(discovery); other_read = response(other_raw)
                    reads = []
                    for offset, candidate in enumerate(candidates):
                        exact = exact_row_document(sheet, rows[0], 2); exact['sheets'][0]['properties']['sheetId'] = sid
                        reads.append({'operation_id': candidate.operation_id, 'discovery_plan': discovery_plan,
                            'discovery_response': original_read, 'occupancy_plan': occupancy_plan, 'occupancy_response': response(occupancy),
                            'row_plan': prepare_sheets_read(binding, credential, mode='row_rectangle', sheet=sheet, first_row=3) if offset == 0 else None,
                            'row_response': response(exact) if offset == 0 else None})
                    requested = tuple(item.activity_key for item in candidates[1:])
                    expected = tuple((key, 'NV%05d' % (40000+index)) for index, key in enumerate(sorted(requested)))
                    with tempfile.TemporaryDirectory(prefix='req7-real-cabling-unit-') as directory:
                        global_root = Path(directory).resolve(); state = global_root/'var/lib/http-ztp-container/issue-tracker'
                        state.mkdir(parents=True, mode=0o700); owner_module = load_owner(); enrollment_module = load_enrollment(); nv_module = load_nv()
                        with tracker_writer(project, self.publication) as writer_token, scoped_fixture(global_root, owner_module), owner_module.spreadsheet_owner(binding) as spreadsheet_token:
                            original = enrollment_module.prepare_enrollment_journal(spreadsheet_token, binding, identity)
                            nv_args = dict(generation_id=committed.receipt.generation_id, publish_id=committed.receipt.published_sha256,
                                sheet=sheet, requested_keys=requested)
                            pair = (discovery_plan, original_read, other_plan, other_read) if sheet == 'ETH Cabling' else (other_plan, other_read, discovery_plan, original_read)
                            reservation = nv_module.prepare_nv_reservation(spreadsheet_token, binding, identity, *pair, **nv_args)
                            self.assertEqual(expected, reservation.reservations)
                            def compile_cabling(**changes):
                                options = dict(local_generation_id=committed.receipt.generation_id, sheet=sheet, business_reads=tuple(reads),
                                    history_plan=history_plan, history_response=history_raw, spreadsheet_token=spreadsheet_token, binding=binding, identity=identity)
                                options.update(changes)
                                return compiler.freeze_observed_receipted_cabling_unit(qualified, self.store, metadata=metadata,
                                    expected_template_sha256=self.snapshot.workbook_sha256, writer_token=writer_token, **args, **options)
                            before = {path.name: path.read_bytes() for path in (state/(hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+'.nv')).iterdir()}
                            unit = compile_cabling(); action = json.loads(unit.action_preimage)
                            self.assertEqual(['update']+['insert']*(len(candidates)-1), [item['action'] for item in action['business']])
                            self.assertEqual(committed.receipt.generation_id, action['identity']['generation_id'])
                            self.assertEqual(committed.receipt.published_sha256, action['identity']['publish_id'])
                            nonces = {title: nonce for title, _sid, nonce in original.nonces}
                            self.assertEqual(nonces[sheet], action['target_nonce']); self.assertEqual(nonces['Update_History'], action['history_nonce'])
                            independent_read_image = {'schema_version': 1, 'spreadsheet_id': binding.spreadsheet_id, 'sheet': sheet,
                                'sheet_id': sid, 'history_sheet_id': 105, 'history_path': history_plan.path,
                                'history_sha256': hashlib.sha256(history_raw.data).hexdigest(), 'nv_journal_sha256': reservation.journal_sha256,
                                'business': [{'operation_id': candidate.operation_id, 'discovery_path': discovery_plan.path,
                                    'discovery_sha256': hashlib.sha256(original_read.data).hexdigest(), 'occupancy_path': occupancy_plan.path,
                                    'occupancy_sha256': hashlib.sha256(reads[index]['occupancy_response'].data).hexdigest(),
                                    'row_path': reads[index]['row_plan'].path if index == 0 else None,
                                    'row_sha256': hashlib.sha256(reads[index]['row_response'].data).hexdigest() if index == 0 else None,
                                    'append_start_row_index': None if index == 0 else 5}
                                    for index, candidate in enumerate(candidates)]}
                            self.assertEqual(hashlib.sha256((json.dumps(independent_read_image, ensure_ascii=False, sort_keys=True,
                                separators=(',', ':'))+'\n').encode()).hexdigest(), action['preread_sha256'])
                            requests = json.loads(unit.wire_bytes)['requests']
                            appends = [item['appendCells'] for item in requests if 'appendCells' in item and item['appendCells']['sheetId'] == sid]
                            self.assertEqual(len(candidates)-1, len(appends))
                            self.assertEqual([dict(expected)[item.activity_key] for item in candidates[1:]],
                                [item['rows'][0]['values'][0]['userEnteredValue']['stringValue'] for item in appends])
                            for item in appends:
                                self.assertEqual({'sheetId', 'rows', 'fields'}, set(item))
                                for index in (7, 8, 9, 14, 15): self.assertEqual({}, item['rows'][0]['values'][index])
                            for item in requests:
                                if 'updateCells' in item:
                                    self.assertEqual(2, item['updateCells']['start']['rowIndex']); self.assertNotEqual(0, item['updateCells']['start']['columnIndex'])
                            self.assertEqual(reservation, nv_module.require_unit_nv_reservation(spreadsheet_token, binding, identity, unit))
                            for claims in ({'reserved_ids': ('NV99999',)}, {'placements': ()}, {'target_nonce': 'c'*64}, {'business_reads': tuple(reads[:-1])}, {'sheet': 'ETH&IB Switch'}):
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling(**claims)
                            saved = reads[-1]['discovery_response']; changed = json.loads(saved.data)
                            changed['sheets'][0]['data'][0]['rowData'][0]['values'][0] = {'userEnteredValue': literal('Closed')}
                            reads[-1]['discovery_response'] = response(changed)
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally: reads[-1]['discovery_response'] = saved
                            saved_occupancy = tuple(reading['occupancy_response'] for reading in reads)
                            full = json.loads(saved_occupancy[0].data)
                            for grid in full['sheets'][0]['data']:
                                if grid['startColumn'] == 21:
                                    grid['rowData'] = [{}, {}, {'values': [{'userEnteredValue': {'boolValue': False}}]}] + [{}]*94 + [
                                        {'values': [{'userEnteredValue': literal('operator at capacity boundary')}]}]
                            for reading in reads: reading['occupancy_response'] = response(full)
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally:
                                for reading, original_response in zip(reads, saved_occupancy): reading['occupancy_response'] = original_response
                            real_freeze = compiler.freeze_receipted_prod_source_unit
                            drift = json.loads(saved_occupancy[-1].data)
                            for grid in drift['sheets'][0]['data']:
                                if grid['startColumn'] == 21: grid['rowData'][2]['values'][0] = {'userEnteredValue': literal('changed during compile')}
                            def change_occupancy_during_freeze(*freeze_args, **freeze_kwargs):
                                result = real_freeze(*freeze_args, **freeze_kwargs)
                                reads[-1]['occupancy_response'] = response(drift)
                                return result
                            try:
                                with mock.patch.object(compiler, 'freeze_receipted_prod_source_unit', side_effect=change_occupancy_during_freeze):
                                    with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally: reads[-1]['occupancy_response'] = saved_occupancy[-1]
                            stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                            ids_path = state/(stem+'.nv')/'RESERVATIONS'; saved_ids = ids_path.read_bytes()
                            ids_path.write_bytes(saved_ids.replace(b'NV40000', b'NV99999'))
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally: ids_path.write_bytes(saved_ids)
                            stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                            if business_preread_probe:
                                from test_cases.test_req7_global_attempt_journal import load as load_global
                                from test_cases.test_req7_history_preread_journal import load as load_preread
                                # Mirror canonical imports after this fixture's
                                # owner reload; never relax real owner registries.
                                global_journal = load_global(); preread = load_preread()
                                self.assertIs(global_journal.ownership, owner_module)
                                self.assertIs(preread.ownership, owner_module)
                                self.assertTrue(hasattr(preread, 'prepare_business_preread'), 'original C5/C6 business images must survive cold/UNKNOWN')
                                global_journal.prepare_global_unit(spreadsheet_token, binding, unit)
                                preread.prepare_history_preread(spreadsheet_token, binding, unit, history_plan, history_raw)
                                preread.prepare_business_preread(spreadsheet_token, binding, identity, unit, manifest=body, business_reads=tuple(reads))
                                seen = preread.inspect_business_preread(spreadsheet_token, binding, identity, unit)
                                self.assertEqual((len(candidates), 0, action['preread_sha256']), (seen.operations_retained, seen.noop_operations, seen.preread_sha256))
                                retained = {path.name: path.read_bytes() for path in (state/(stem+'.business')).iterdir()}
                                if original_reserved_probe:
                                    from test_cases.test_req7_metadata_reservation import load as load_quota
                                    from monitor.issue_tracker_metadata_capacity import prepare_metadata_capacity_read
                                    quota_module = load_quota()
                                    quota_raw = response({'matchedDeveloperMetadata': [
                                        {'developerMetadata': {'metadataId': index+1, 'metadataKey': 'http-ztp-enrollment-v1',
                                            'metadataValue': nonce, 'visibility': 'DOCUMENT',
                                            'location': {'locationType': 'SHEET', 'sheetId': sheet_id}}}
                                        for index, (_title, sheet_id, nonce) in enumerate(original.nonces)]})
                                    quota = quota_module.prepare_metadata_reservation(spreadsheet_token, binding, identity, unit,
                                        prepare_metadata_capacity_read(binding, credential), quota_raw)
                                    self.assertTrue(hasattr(global_journal, 'record_original_business_reserved_attempt_intent'), 'complete original chain must dominate counted intent')
                                    record = lambda: global_journal.record_original_business_reserved_attempt_intent(spreadsheet_token, binding, identity, unit)
                                    if receipted_intent_probe:
                                        self.assertTrue(hasattr(global_journal, 'record_receipted_original_attempt_intent'), 'protected original C6 chain must dominate each counted intent')
                                        self.assertTrue(hasattr(preread, 'inspect_business_source_projection'), 'replayed C5 source values must bind ALL original wire and NOOP decisions')
                                        from monitor.issue_tracker_local_workbook_commit import _source_rows
                                        cabling_source, switch_source = _source_rows(qualified)
                                        source_rows = (*cabling_source, *switch_source)
                                        self.assertEqual(seen, preread.inspect_business_source_projection(spreadsheet_token, binding, identity, unit, source_rows))
                                        changed_rows = tuple(replace(row, evidence_description='caller invented original values') for row in source_rows)
                                        with self.assertRaises(preread.HistoryPrereadHold):
                                            preread.inspect_business_source_projection(spreadsheet_token, binding, identity, unit, changed_rows)
                                        self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                        def record(**changes):
                                            options = dict(qualified_source=qualified, store=self.store, writer_token=writer_token,
                                                settings=args['settings'], whitelist_snapshot=self.snapshot,
                                                expected_template_sha256=self.snapshot.workbook_sha256,
                                                http_root=self.root, whitelist_path=self.template)
                                            options.update(changes)
                                            return global_journal.record_receipted_original_attempt_intent(spreadsheet_token, binding, identity, unit, **options)
                                        for changes in ({'writer_token': None}, {'qualified_source': replace(qualified, observations_sha256='f'*64)},
                                                        {'expected_template_sha256': 'f'*64}):
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record(**changes)
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                        generation_path = project/'.tracker/generations'/committed.receipt.generation_id
                                        c6_original = {name: (generation_path/name).read_bytes() for name in ('STATE', 'MANIFEST', 'INTENT', 'RECEIPT')}
                                        for name, raw in c6_original.items():
                                            path = generation_path/name; path.write_bytes(b'foreign C6 original')
                                            try:
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                                self.assertEqual(b'foreign C6 original', path.read_bytes())
                                            finally: path.write_bytes(raw)  # undo this owned fixture fault only
                                        source_path = artifacts['ethernet/prod']['info']
                                        source_before = source_path.read_bytes()
                                        source_path.write_bytes(source_before+b'\nchanged original producer source\n')
                                        try:
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(source_before+b'\nchanged original producer source\n', source_path.read_bytes())
                                        finally: source_path.write_bytes(source_before)  # owned producer fault only
                                        actual_business_inspect = preread.inspect_business_preread
                                        def change_source_after_business(*inspect_args, **inspect_kwargs):
                                            result = actual_business_inspect(*inspect_args, **inspect_kwargs)
                                            source_path.write_bytes(source_before+b'\nchanged during original barrier\n')
                                            return result
                                        try:
                                            with mock.patch.object(preread, 'inspect_business_preread', side_effect=change_source_after_business):
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(source_before+b'\nchanged during original barrier\n', source_path.read_bytes())
                                        finally: source_path.write_bytes(source_before)  # owned fixture only
                                    for count in range(1, 7):
                                        if receipted_intent_probe and count in (3, 4):
                                            original_observe = global_journal._observe
                                            fault_path = generation_path/'RECEIPT' if count == 3 else source_path
                                            original_bytes = c6_original['RECEIPT'] if count == 3 else source_before
                                            def change_after_count(*observe_args, **observe_kwargs):
                                                result = original_observe(*observe_args, **observe_kwargs)
                                                if observe_args[3]: fault_path.write_bytes(b'changed after durable count')
                                                return result
                                            try:
                                                with mock.patch.object(global_journal, '_observe', side_effect=change_after_count):
                                                    with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                intent = global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
                                                self.assertEqual(b'changed after durable count', fault_path.read_bytes())
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual(count, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            finally: fault_path.write_bytes(original_bytes)  # fault fixture only, no production recovery
                                        else: intent = record()
                                        self.assertEqual((count, 'UNKNOWN'), (intent.attempt_count, intent.outcome))
                                        self.assertFalse(hasattr(intent, 'permit')); self.assertFalse(hasattr(intent, 'complete'))
                                        self.assertEqual(seen, preread.inspect_business_preread(spreadsheet_token, binding, identity, unit))
                                        self.assertEqual(quota, quota_module.inspect_metadata_reservation(spreadsheet_token, binding, identity, unit))
                                    with self.assertRaises(global_journal.GlobalAttemptHold):
                                        record()
                                    if receipted_intent_probe:
                                        self.assertEqual(c6_original, {name: (generation_path/name).read_bytes() for name in c6_original})
                                else:
                                    global_journal.record_global_attempt_intent(spreadsheet_token, binding, unit)
                                self.assertEqual(seen, preread.inspect_business_preread(spreadsheet_token, binding, identity, unit))
                                with self.assertRaises(preread.HistoryPrereadHold):
                                    preread.prepare_business_preread(spreadsheet_token, binding, identity, unit, manifest=body, business_reads=tuple(reads))
                                self.assertEqual(retained, {path.name: path.read_bytes() for path in (state/(stem+'.business')).iterdir()})
                                self.assertEqual(before, {path.name: path.read_bytes() for path in (state/(stem+'.nv')).iterdir()})
                                continue
                            blocked = state/(stem+'.journal'); blocked.mkdir(mode=0o700)
                            with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            self.assertEqual([], list(blocked.iterdir()))
                            self.assertEqual(before, {path.name: path.read_bytes() for path in (state/(stem+'.nv')).iterdir()})
                self.assertEqual(original_template, self.template.read_bytes())
                self.assertFalse((project/'.tracker/remote-actions').exists()); self.assertFalse((project/'.tracker/remote-attempts').exists())
                return
            if observed_switch_insert_probe:
                import tempfile
                import monitor.issue_tracker_send_unit as compiler
                from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read, prepare_insertion_sheet_read, prepare_sheets_read, prepare_history_tail_read, prepare_template_identity_read
                from monitor.issue_tracker_sheets_read_decode import decode_template_identity
                from monitor.issue_tracker_online_target import OnlineTargetBinding
                from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                from test_cases.test_req7_activity_discovery import sheet_document, insertion_document, exact_row_document, reserved_switch_row, literal
                from test_cases.test_req7_sheets_read_decode import response, identity_response
                from test_cases.test_req7_spreadsheet_owner import load as load_owner, scoped_fixture
                from test_cases.test_req7_enrollment_journal import load as load_enrollment
                self.assertTrue(hasattr(compiler,'freeze_observed_receipted_switch_unit'),'original receipt, owner and enrollment must derive Switch inserts')
                binding = OnlineTargetBinding('synthetic_spreadsheet_id_0001','a'*64,'b'*64)
                credential = AuthenticatedToken('synthetic.private-token',time.time()+3600)
                identity = decode_template_identity(prepare_template_identity_read(binding,credential),response(identity_response()))
                candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == 'switch')
                self.assertGreater(len(candidates),1)
                rows = [reserved_switch_row(index) for index in range(2,len(candidates)+5)]
                rows[0]['M'] = {'boolValue':False}
                key = candidates[0].activity_key
                rows[1].update({'F':literal(key[1]),'L':literal('[MONITOR][%s][%s] old evidence'%key[2:]),'N':literal('New')})
                source = sheet_document('ETH&IB Switch',rows,len(rows)+2); source['sheets'][0]['properties']['sheetId'] = 101
                occupancy = insertion_document('ETH&IB Switch',rows,len(rows)+2); occupancy['sheets'][0]['properties']['sheetId'] = 101
                discovery_plan = prepare_activity_sheet_read(binding,credential,sheet='ETH&IB Switch')
                occupancy_plan = prepare_insertion_sheet_read(binding,credential,sheet='ETH&IB Switch')
                reads = []
                for offset,candidate in enumerate(candidates):
                    index = offset+3
                    exact = exact_row_document('ETH&IB Switch',rows[index-2],index); exact['sheets'][0]['properties']['sheetId'] = 101
                    reads.append({'operation_id':candidate.operation_id,'discovery_plan':discovery_plan,'discovery_response':response(source),
                        'occupancy_plan':occupancy_plan,'occupancy_response':response(occupancy),
                        'row_plan':prepare_sheets_read(binding,credential,mode='row_rectangle',sheet='ETH&IB Switch',first_row=index+1),
                        'row_response':response(exact)})
                history_plan = prepare_history_tail_read(binding,credential)
                history_response = response({'spreadsheetId':binding.spreadsheet_id,'sheets':[{'properties':{'sheetId':105,'title':'Update_History',
                    'sheetType':'GRID','gridProperties':{'rowCount':100,'columnCount':5}},'data':[{'startRow':2,'startColumn':0}]}]})
                with tempfile.TemporaryDirectory(prefix='req7-real-switch-insert-') as directory:
                    global_root = Path(directory).resolve(); state = global_root/'var/lib/http-ztp-container/issue-tracker'
                    state.mkdir(parents=True,mode=0o700); owner_module = load_owner(); enrollment_module = load_enrollment()
                    with tracker_writer(project,self.publication) as writer_token, scoped_fixture(global_root,owner_module), owner_module.spreadsheet_owner(binding) as spreadsheet_token:
                        original = enrollment_module.prepare_enrollment_journal(spreadsheet_token,binding,identity)
                        def compile_switch(**changes):
                            options = dict(local_generation_id=committed.receipt.generation_id,business_reads=tuple(reads),history_plan=history_plan,
                                history_response=history_response,spreadsheet_token=spreadsheet_token,binding=binding,identity=identity,audits=(),occupied_metadata_ids=())
                            options.update(changes)
                            return compiler.freeze_observed_receipted_switch_unit(qualified,self.store,metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256,writer_token=writer_token,**args,**options)
                        unit = compile_switch(); action = json.loads(unit.action_preimage)
                        self.assertEqual(committed.receipt.generation_id,action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256,action['identity']['publish_id'])
                        nonces = {title:nonce for title,sid,nonce in original.nonces}
                        self.assertEqual(nonces['ETH&IB Switch'],action['target_nonce']); self.assertEqual(nonces['Update_History'],action['history_nonce'])
                        self.assertEqual(['update']+['insert']*(len(candidates)-1),[item['action'] for item in action['business']])
                        updates = [item['updateCells'] for item in json.loads(unit.wire_bytes)['requests'] if 'updateCells' in item]
                        self.assertEqual(set(range(3,len(candidates)+3)),{item['start']['rowIndex'] for item in updates})
                        for item in updates:
                            self.assertEqual(101,item['start']['sheetId']); self.assertNotIn(item['start']['columnIndex'],(0,3,4,6,7,8,12,14,15,16,17,18,19,20))
                        for claim in ({'target_nonce':'c'*64},{'placements':()},{'sheet_id':101},{'preread_sha256':'e'*64},{'business_reads':tuple(reads[:-1])}):
                            with self.assertRaises(compiler.SendUnitHold): compile_switch(**claim)
                        with self.assertRaises(compiler.SendUnitHold): compile_switch(spreadsheet_token=object())
                        changed_identity = replace(identity,sheet_ids=tuple((title,150 if title=='ETH&IB Switch' else sid) for title,sid in identity.sheet_ids))
                        with self.assertRaises(compiler.SendUnitHold): compile_switch(identity=changed_identity)
                        saved = reads[1]['row_response']; drift = json.loads(saved.data)
                        drift['sheets'][0]['data'][0]['rowData'][0]['values'][12] = {'userEnteredValue':literal('operator drift')}
                        reads[1]['row_response'] = response(drift)
                        try:
                            with self.assertRaises(compiler.SendUnitHold): compile_switch()
                        finally: reads[1]['row_response'] = saved
                        real_freeze = compiler.freeze_receipted_prod_source_unit
                        def change_row_during_compilation(*freeze_args,**freeze_kwargs):
                            result = real_freeze(*freeze_args,**freeze_kwargs)
                            reads[1]['row_response'] = response(drift)
                            return result
                        try:
                            with mock.patch.object(compiler,'freeze_receipted_prod_source_unit',side_effect=change_row_during_compilation):
                                with self.assertRaises(compiler.SendUnitHold): compile_switch()
                        finally: reads[1]['row_response'] = saved
                        stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                        blocked = state/(stem+'.journal'); blocked.mkdir(mode=0o700)
                        with self.assertRaises(compiler.SendUnitHold): compile_switch()
                        self.assertEqual([],list(blocked.iterdir()))
                        self.assertEqual({stem+'.lock',stem+'.enrollment',stem+'.journal'},{path.name for path in state.iterdir()})
                self.assertEqual(original_template,self.template.read_bytes())
                self.assertFalse((project/'.tracker/remote-actions').exists()); self.assertFalse((project/'.tracker/remote-attempts').exists())
                return
            if observed_source_probe:
                import monitor.issue_tracker_send_unit as compiler
                from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read, prepare_sheets_read, prepare_history_tail_read
                from monitor.issue_tracker_online_target import OnlineTargetBinding
                from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                from test_cases.test_req7_activity_discovery import sheet_document, exact_row_document, switch_row, cabling_row, literal
                from test_cases.test_req7_sheets_read_decode import response
                self.assertTrue(hasattr(compiler, 'freeze_observed_receipted_source_updates'), 'protected receipt/source must derive rows from original read images')
                binding = OnlineTargetBinding('synthetic_spreadsheet_id_0001', 'a' * 64, 'b' * 64)
                credential = AuthenticatedToken('synthetic.private-token', time.time() + 3600)
                history_plan = prepare_history_tail_read(binding, credential)
                history_raw = response({'spreadsheetId': binding.spreadsheet_id, 'sheets': [{
                    'properties': {'sheetId': 105, 'title': 'Update_History', 'sheetType': 'GRID',
                        'gridProperties': {'rowCount': 100, 'columnCount': 5}},
                    'data': [{'startRow': 2, 'startColumn': 0}]}]})
                before_generations_observed = tuple(sorted(generation_root.iterdir()))
                for sheet, family, sid in (('ETH&IB Switch', 'switch', 101), ('ETH Cabling', 'eth_cabling', 102), ('IB Cabling', 'ib_cabling', 103)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    rows = []
                    for index, candidate in enumerate(candidates):
                        key = candidate.activity_key
                        row = switch_row('NV%05d' % (43001 + index)) if family == 'switch' else cabling_row('NV%05d' % (43001 + index))
                        if family == 'switch':
                            row['F'] = literal(key[1]); row['L'] = literal('[MONITOR][%s][%s] old independent evidence' % key[2:])
                        else:
                            for column, value in zip(('K', 'L', 'F'), key[1:]): row[column] = literal(value)
                        rows.append(row)
                    source = sheet_document(sheet, rows, row_count=len(rows) + 4)
                    source['sheets'][0]['properties']['sheetId'] = sid
                    discovery_plan = prepare_activity_sheet_read(binding, credential, sheet=sheet)
                    raw_discovery = response(source)
                    reads = []
                    for index, candidate in enumerate(candidates):
                        exact = exact_row_document(sheet, rows[index], index + 2)
                        exact['sheets'][0]['properties']['sheetId'] = sid
                        reads.append({'operation_id': candidate.operation_id, 'discovery_plan': discovery_plan,
                            'discovery_response': raw_discovery, 'row_plan': prepare_sheets_read(binding, credential,
                                mode='row_rectangle', sheet=sheet, first_row=index + 3), 'row_response': response(exact)})
                    options = dict(local_generation_id=committed.receipt.generation_id, spreadsheet_id=binding.spreadsheet_id,
                        sheet=sheet, sheet_id=sid, history_sheet_id=105, target_nonce='c' * 64, history_nonce='d' * 64,
                        audits=(), occupied_metadata_ids=())
                    with tracker_writer(project, self.publication) as token:
                        def compile_observed(**changes):
                            return compiler.freeze_observed_receipted_source_updates(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, writer_token=token, **args,
                                **{**options, 'business_reads': tuple(reads), 'history_plan': history_plan, 'history_response': history_raw, **changes})
                        unit = compile_observed()
                        action = json.loads(unit.action_preimage)
                        self.assertEqual(committed.receipt.generation_id, action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256, action['identity']['publish_id'])
                        self.assertNotEqual('e' * 64, action['preread_sha256'])
                        requests = json.loads(unit.wire_bytes)['requests']
                        updates = [item['updateCells'] for item in requests if 'updateCells' in item]
                        self.assertEqual(set(range(2, len(rows) + 2)), {item['start']['rowIndex'] for item in updates})
                        for item in updates:
                            self.assertEqual(sid, item['start']['sheetId'])
                            self.assertEqual('userEnteredValue', item['fields'])
                            self.assertNotEqual(0, item['start']['columnIndex'])
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(preread_sha256='e' * 64)
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(placements=())
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(business_reads=tuple(reads[:-1]))
                        foreign_history = json.loads(history_raw.data)
                        foreign_history['spreadsheetId'] = 'foreign_spreadsheet_id_0002'
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(history_response=response(foreign_history))
                        full_history = json.loads(history_raw.data)
                        full_history['sheets'][0]['properties']['gridProperties']['rowCount'] = 3
                        full_history['sheets'][0]['data'][0]['rowData'] = [{'values': [{'userEnteredValue': literal('occupied original tail')}]}]
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(history_response=response(full_history))
                        original_row = reads[0]['row_response']
                        drift = json.loads(original_row.data)
                        drift['sheets'][0]['data'][0]['rowData'][0]['values'][0] = {'userEnteredValue': literal('NV99999')}
                        reads[0]['row_response'] = response(drift)
                        try:
                            with self.assertRaises(compiler.SendUnitHold): compile_observed()
                        finally: reads[0]['row_response'] = original_row
                        def change_row_during_freeze(*freeze_args, **freeze_kwargs):
                            result = real_freeze(*freeze_args, **freeze_kwargs)
                            reads[0]['row_response'] = response(drift)
                            return result
                        real_freeze = compiler.freeze_receipted_prod_source_unit
                        try:
                            with mock.patch.object(compiler, 'freeze_receipted_prod_source_unit', side_effect=change_row_during_freeze):
                                with self.assertRaises(compiler.SendUnitHold): compile_observed()
                        finally: reads[0]['row_response'] = original_row
                self.assertEqual(before_generations_observed, tuple(sorted(generation_root.iterdir())))
                self.assertEqual(original_template, self.template.read_bytes())
                self.assertFalse((project / '.tracker/remote-actions').exists())
                self.assertFalse((project / '.tracker/remote-attempts').exists())
                return
            if receipted_source_probe:
                import monitor.issue_tracker_send_unit as compiler
                generation_id = committed.receipt.generation_id
                original_publications = tuple(sorted(self.publication.iterdir()))
                original_generations = tuple(sorted(generation_root.iterdir()))
                receipt_path = generation_root / generation_id / 'RECEIPT'
                receipt_bytes = receipt_path.read_bytes()
                publication_path = self.publication / (generation_id + '.xlsx')
                published_bytes = publication_path.read_bytes()
                for sheet, family, sid in (('ETH&IB Switch', 'switch', 101), ('ETH Cabling', 'eth_cabling', 102),
                                           ('IB Cabling', 'ib_cabling', 103)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    self.assertTrue(candidates)
                    placements = tuple({'operation_id': item.operation_id, 'action': 'update' if family == 'switch' else 'insert',
                        'row_index': index + 2 if family == 'switch' else None, 'observed_values': {'L': {}} if family == 'switch' else None,
                        'reserved_id': None if family == 'switch' else 'NV%05d' % (42001 + index)}
                        for index, item in enumerate(candidates))
                    options = dict(local_generation_id=generation_id,
                        spreadsheet_id='synthetic_spreadsheet_id_0001', sheet=sheet, sheet_id=sid, history_sheet_id=105,
                        target_nonce='c' * 64, history_nonce='d' * 64, preread_sha256='e' * 64,
                        audits=(), occupied_metadata_ids=())
                    with tracker_writer(project, self.publication) as token:
                        def compile_unit(**changes):
                            return compiler.freeze_receipted_prod_source_unit(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=placements,
                                writer_token=token, **args, **{**options, **changes})
                        unit = compile_unit()
                        action = json.loads(unit.action_preimage)
                        self.assertEqual(generation_id, action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256, action['identity']['publish_id'])
                        self.assertEqual(committed.receipt.manifest_id, action['manifest_id'])
                        with self.assertRaises(compiler.SendUnitHold): compile_unit(publish_id='f' * 64)
                        with self.assertRaises(compiler.SendUnitHold):
                            compile_unit(local_generation_id='gen-00000000000000000002-' + '1' * 32)
                        if family == 'switch':
                            forged = json.loads(receipt_bytes); forged['sequence'] = True
                            receipt_path.write_bytes(json.dumps(forged).encode())
                            bad_receipt = receipt_path.read_bytes()
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertEqual(bad_receipt, receipt_path.read_bytes())
                            finally:
                                receipt_path.write_bytes(receipt_bytes)
                            admission_path = next((project / '.tracker/admissions').iterdir())
                            admission_bytes = admission_path.read_bytes()
                            try:
                                admission_path.write_bytes(b'{}\n')
                                with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertEqual(b'{}\n', admission_path.read_bytes())
                            finally:
                                admission_path.write_bytes(admission_bytes)
                            real_compile = compiler.freeze_prod_source_unit
                            def change_publication_after_freeze(*freeze_args, **freeze_options):
                                result = real_compile(*freeze_args, **freeze_options)
                                publication_path.write_bytes(b'changed after source unit freeze')
                                return result
                            try:
                                with mock.patch.object(compiler, 'freeze_prod_source_unit', side_effect=change_publication_after_freeze):
                                    with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertEqual(b'changed after source unit freeze', publication_path.read_bytes())
                            finally:
                                publication_path.write_bytes(published_bytes)
                            preserved_receipt = project / 'preserved-original-receipt'
                            def replace_receipt_inode_after_freeze(*freeze_args, **freeze_options):
                                result = real_compile(*freeze_args, **freeze_options)
                                receipt_path.rename(preserved_receipt)
                                receipt_path.write_bytes(receipt_bytes)
                                receipt_path.chmod(0o600)
                                return result
                            try:
                                with mock.patch.object(compiler, 'freeze_prod_source_unit', side_effect=replace_receipt_inode_after_freeze):
                                    with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertNotEqual(preserved_receipt.stat().st_ino, receipt_path.stat().st_ino)
                                self.assertEqual(receipt_bytes, receipt_path.read_bytes())
                            finally:
                                if preserved_receipt.exists():
                                    receipt_path.unlink()
                                    preserved_receipt.rename(receipt_path)
                self.assertEqual(original_publications, tuple(sorted(self.publication.iterdir())))
                self.assertEqual(original_generations, tuple(sorted(generation_root.iterdir())))
                self.assertEqual(original_template, self.template.read_bytes())
                self.assertEqual(receipt_bytes, receipt_path.read_bytes())
                self.assertEqual(published_bytes, publication_path.read_bytes())
                self.assertFalse((project / '.tracker/remote-actions').exists())
                self.assertFalse((project / '.tracker/remote-attempts').exists())
                return
            if require_first_manual_admission:
                self.assertTrue((project / ".tracker/admissions").is_dir())
                admission_files = tuple(sorted(
                    (project / ".tracker/admissions").iterdir()))
                self.assertEqual(1, len(admission_files))
                with tracker_writer(project, self.publication) as token:
                    shared = read_auto_local_admission(
                        token, self.store, self.snapshot.workbook_sha256)
                self.assertEqual(committed.receipt.generation_id,
                                 shared["generation_id"])
                self.assertEqual(committed.receipt.published_sha256,
                                 shared["published_sha256"])
                self.assertEqual("manual", shared["lane"])
                self.assertEqual(cycle["cycle_id"], shared["cycle_id"])
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(self.template.read_bytes())
                stage_status_path = (
                    self.root / "monitor/status/issue-tracker-stage-l.status.json"
                )
                before_second_cycle = tuple(sorted(generation_root.iterdir()))
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value=shared["boot_id"])):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                self.assertEqual(before_second_cycle,
                                 tuple(sorted(generation_root.iterdir())))
                self.assertEqual("not_due", json.loads(
                    stage_status_path.read_bytes())["local"])
                second_identity = build_collection_cycle_identity(
                    str(project), "prod", 2, TOKEN_2,
                )
                second_binding = produce_worker_ib_analysis(
                    second_identity, project_root=project, http_root=self.root,
                    clock=lambda: dt.datetime(2026, 9, 26, 4, 31,
                                              tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail(
                        "transport is supplied by fixture"),
                )
                second_cycle, _ = self._cycle(
                    activity=True, derivation=True,
                    observed_peer="changed-peer", ib_analysis=second_binding,
                    fabric_templates={"ethernet/prod": "tan-leaf",
                                      "nvlink/prod": "border-leaf"},
                )
                self.assertEqual(second_identity["cycle_id"],
                                 second_cycle["cycle_id"])
                later_ns = (shared["monotonic_ns"]
                            + MIN_CONTINUOUS_INTERVAL_MINUTES * 60
                            * 1_000_000_000 + 1)
                if manual_after_manual:
                    second_witness = (
                        shared["policy_sha256"],
                        shared["publish_every_cycles"],
                        shared["boot_id"], later_ns,
                    )
                    with mock.patch.object(WORKER.time, "monotonic_ns",
                                           return_value=later_ns):
                        second_result = commit_qualified_prod_local(
                            self.store, http_root=self.root, project=project,
                            publication=self.publication,
                            template_path=root_template,
                            manual_admission=second_witness,
                        )
                    self.assertIsInstance(second_result, CommittedProdWorkbook)
                    self.assertNotEqual(committed.receipt.generation_id,
                                        second_result.receipt.generation_id)
                    with tracker_writer(project, self.publication) as token:
                        latest = read_auto_local_admission(
                            token, self.store, self.snapshot.workbook_sha256)
                    self.assertEqual("manual", latest["lane"])
                    self.assertEqual(3, latest["publish_every_cycles"])
                    self.assertEqual(second_cycle["cycle_id"], latest["cycle_id"])
                    self.assertEqual(second_result.receipt.generation_id,
                                     latest["generation_id"])
                    self.assertEqual(2, len(tuple(
                        (project / ".tracker/admissions").iterdir())))
                    with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                          mock.patch.object(WORKER, "STATUS_DIR",
                                            stage_status_path.parent),
                          mock.patch.object(WORKER,
                                            "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                            stage_status_path),
                          mock.patch.object(WORKER, "_current_boot_identity",
                                            return_value=shared["boot_id"]),
                          mock.patch.object(WORKER.time, "monotonic_ns",
                                            return_value=later_ns)):
                        self.assertIsNone(
                            WORKER._publish_stage_l_local_after_completion(
                                self.store))
                    self.assertEqual("not_due", json.loads(
                        stage_status_path.read_bytes())["local"])
                    self.assertEqual(2, len(tuple(
                        (project / ".tracker/generations").iterdir())))
                    return
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value=shared["boot_id"]),
                      mock.patch.object(WORKER.time, "monotonic_ns",
                                        return_value=later_ns)):
                    second_result = WORKER._publish_stage_l_local_after_completion(
                        self.store)
                self.assertIsInstance(second_result, CommittedProdWorkbook)
                self.assertNotEqual(committed.receipt.generation_id,
                                    second_result.receipt.generation_id)
                with tracker_writer(project, self.publication) as token:
                    latest = read_auto_local_admission(
                        token, self.store, self.snapshot.workbook_sha256)
                self.assertEqual("automatic", latest["lane"])
                self.assertEqual(second_cycle["cycle_id"], latest["cycle_id"])
                self.assertEqual(second_result.receipt.generation_id,
                                 latest["generation_id"])
                self.assertEqual(2, len(tuple(
                    (project / ".tracker/admissions").iterdir())))
                return
            root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
            root_template.parent.mkdir(parents=True, exist_ok=True)
            root_template.write_bytes(self.template.read_bytes())
            before_runtime_entry = tuple(sorted(generation_root.iterdir()))
            runtime_noop = commit_qualified_prod_local(
                self.store, http_root=self.root, project=project,
                publication=self.publication, template_path=root_template,
                manual_admission=manual_witness,
            )
            self.assertIsInstance(runtime_noop, ProdWorkbookNoop)
            self.assertEqual("no_change", runtime_noop.status)
            self.assertEqual(before_runtime_entry,
                             tuple(sorted(generation_root.iterdir())))
            stage_status_path = self.root / "monitor/status/issue-tracker-stage-l.status.json"
            with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                  mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                  mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                    stage_status_path)):
                lane_result = WORKER._publish_stage_l_local_after_completion(self.store)
            if replayed_auto:
                self.assertIsNone(lane_result)
                self.assertEqual("hold", json.loads(stage_status_path.read_bytes())["state"])
                self.assertEqual(before_runtime_entry,
                                 tuple(sorted(generation_root.iterdir())))
                return
            # Direct C6 image replay remains a no-op above; an automatic lane
            # must not treat that prior manual RECEIPT as a new admission.
            self.assertIsNone(lane_result)
            self.assertEqual("hold", json.loads(stage_status_path.read_bytes())["state"])
            self.assertEqual(before_runtime_entry,
                             tuple(sorted(generation_root.iterdir())))
            try:
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("leaf-z",), reserved_switch_rows=4,
                ))
                skipped_snapshot = read_whitelist_workbook(self.template)
                skipped_args = {**args, "whitelist_snapshot": skipped_snapshot}
                eth_skipped = qualify_prod_stage_l(self.store, **skipped_args)
                self.assertEqual(protected_time, eth_skipped.recorded_at_utc)
                self.assertEqual(
                    (("eth_cabling", ("leaf-a", "swp1", "leaf-z", "swp2"),
                      "leaf-z"),),
                    tuple((skip.source, skip.endpoints, skip.matched_rule)
                          for skip in eth_skipped.whitelist_skips),
                )
                self.assertTrue(all(skip.activity_key is None
                                    and skip.record_id is None
                                    for skip in eth_skipped.whitelist_skips))
                eth_metadata = {
                    **metadata,
                    "template_sha256": skipped_snapshot.workbook_sha256,
                }
                eth_body, eth_digest = freeze_prod_stage_l_manifest(
                    eth_skipped, self.store, metadata=eth_metadata,
                    expected_template_sha256=skipped_snapshot.workbook_sha256,
                    **skipped_args,
                )
                self.assertEqual(hashlib.sha256(eth_body).hexdigest(), eth_digest)
                self.assertEqual([{
                    "source": "eth_cabling",
                    "endpoints": ["leaf-a", "swp1", "leaf-z", "swp2"],
                    "matched_rule": "leaf-z",
                }], json.loads(eth_body)["qualified_source"]["whitelist_skips"])
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("leaf-a",), reserved_switch_rows=4,
                ))
                switch_snapshot = read_whitelist_workbook(self.template)
                switch_args = {**args, "whitelist_snapshot": switch_snapshot}
                switch_skipped = qualify_prod_stage_l(self.store, **switch_args)
                self.assertEqual(protected_time, switch_skipped.recorded_at_utc)
                self.assertEqual({
                    ("switch", "switch:leaf-a", None, "leaf-a"),
                    ("eth_cabling", None,
                     ("leaf-a", "swp1", "leaf-z", "swp2"), "leaf-a"),
                }, {
                    (skip.source, skip.record_id, skip.endpoints,
                     skip.matched_rule)
                    for skip in switch_skipped.whitelist_skips
                })
                self.assertTrue(all(skip.activity_key is None
                                    for skip in switch_skipped.whitelist_skips))
                with self.assertRaises((StageLConsumerHold, ValueError)):
                    freeze_prod_stage_l_manifest(
                        eth_skipped, self.store, metadata=eth_metadata,
                        expected_template_sha256=skipped_snapshot.workbook_sha256,
                        **skipped_args,
                    )
                switch_metadata = {
                    **metadata,
                    "template_sha256": switch_snapshot.workbook_sha256,
                }
                switch_body, switch_digest = freeze_prod_stage_l_manifest(
                    switch_skipped, self.store, metadata=switch_metadata,
                    expected_template_sha256=switch_snapshot.workbook_sha256,
                    **switch_args,
                )
                self.assertEqual(hashlib.sha256(switch_body).hexdigest(),
                                 switch_digest)
                self.assertEqual({
                    ("eth_cabling", "leaf-a", None),
                    ("switch", "leaf-a", "switch:leaf-a"),
                }, {
                    (item["source"], item["matched_rule"],
                     item.get("record_id"))
                    for item in json.loads(switch_body)["qualified_source"]
                    ["whitelist_skips"]
                })
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("re:^leaf-a$",), reserved_switch_rows=4,
                ))
                regex_snapshot = read_whitelist_workbook(self.template)
                regex_args = {**args, "whitelist_snapshot": regex_snapshot}
                regex_skipped = qualify_prod_stage_l(self.store, **regex_args)
                self.assertEqual(
                    {(skip.source, skip.record_id, skip.endpoints)
                     for skip in switch_skipped.whitelist_skips},
                    {(skip.source, skip.record_id, skip.endpoints)
                     for skip in regex_skipped.whitelist_skips},
                )
                self.assertEqual({"re:^leaf-a$"},
                                 {skip.matched_rule for skip in
                                  regex_skipped.whitelist_skips})
                with self.assertRaises((StageLConsumerHold, ValueError)):
                    freeze_prod_stage_l_manifest(
                        switch_skipped, self.store, metadata=switch_metadata,
                        expected_template_sha256=switch_snapshot.workbook_sha256,
                        **switch_args,
                    )
            finally:
                self.template.write_bytes(original_template)
            self.template.write_bytes(fake_workbook(
                whitelist_rules=("leaf-z",), reserved_switch_rows=4,
            ))
            with self.assertRaises((StageLConsumerHold, ValueError)):
                freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    **args,
                )
            self.template.write_bytes(fake_workbook(reserved_switch_rows=4))
            latest = artifacts["ethernet/prod"]["info"]
            original = latest.read_bytes()
            latest.write_bytes(original + b"late byte drift")
            with self.assertRaises((StageLConsumerHold, ValueError)):
                freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    **args,
                )
            latest.write_bytes(original)
            with tracker_writer(project, self.publication) as token:
                set_k(token, new_k=2, actor="operator:fixture",
                      recorded_at="2026-09-25T00:02:00Z",
                      request_id="req7-three-panel-k2", expected_revision=1)
            with self.assertRaises((StageLConsumerHold, ValueError)):
                freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    **args,
                )

    def _verify_protected_skip_commit(self, project, args):
        from monitor.issue_tracker_publish_runtime import local_publish_interval
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, ProdWorkbookNoop,
            commit_prod_stage_l_workbook,
        )
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
        from monitor.issue_tracker_state_owner import tracker_writer

        self.template.write_bytes(fake_workbook(
            whitelist_rules=("leaf-a",), reserved_switch_rows=4,
        ))
        self.snapshot = read_whitelist_workbook(self.template)
        args = {**args, "whitelist_snapshot": self.snapshot}
        qualified = qualify_prod_stage_l(self.store, **args)
        self.assertEqual({"eth_cabling", "switch"},
                         {skip.source for skip in qualified.whitelist_skips})
        metadata = {
            "project_id": str(project), "schema_version": 1,
            "producer_version": "req7-test-producer",
            "template_contract_version": "v1",
            "template_sha256": self.snapshot.workbook_sha256,
        }
        body, manifest_id = freeze_prod_stage_l_manifest(
            qualified, self.store, metadata=metadata,
            expected_template_sha256=self.snapshot.workbook_sha256,
            **args,
        )
        self.assertEqual(hashlib.sha256(body).hexdigest(), manifest_id)
        interval, policy_sha = local_publish_interval(project)
        manual_witness = (policy_sha, interval, "fixture-boot",
                          time.monotonic_ns())
        with tracker_writer(project, self.publication) as token:
            committed = commit_prod_stage_l_workbook(
                token, qualified, self.store, template_path=self.template,
                metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                manual_admission=manual_witness,
                **args,
            )
        self.assertIsInstance(committed, CommittedProdWorkbook)
        self.assertEqual(manifest_id, committed.receipt.manifest_id)
        with zipfile.ZipFile(BytesIO(self.template.read_bytes())) as before, \
             zipfile.ZipFile(BytesIO(committed.prepared.xlsx_bytes)) as after:
            history = after.read("xl/worksheets/sheet6.xml")
            self.assertIn(b"Whitelist Skip", history)
            self.assertIn(manifest_id.encode("ascii"), history)
            self.assertIn(qualified.recorded_at_utc.encode("ascii"), history)
            self.assertIn(b"switch:leaf-a", history)
            self.assertIn(b"leaf-z", history)
            self.assertIn(b"matched_rule=leaf-a", history)
            self.assertEqual(before.read("xl/worksheets/sheet3.xml"),
                             after.read("xl/worksheets/sheet3.xml"))
            self.assertNotIn(b"leaf-a", after.read("xl/worksheets/sheet2.xml"))
        with tracker_writer(project, self.publication) as token:
            no_op = commit_prod_stage_l_workbook(
                token, qualified, self.store, template_path=self.template,
                metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                **args,
            )
        self.assertIsInstance(no_op, ProdWorkbookNoop)
        self.assertEqual("no_change", no_op.status)

    def _verify_two_cycle_latest_local_commit(self, project, args, cycle_ids):
        from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, commit_prod_stage_l_workbook,
        )
        from monitor.issue_tracker_publish_runtime import local_publish_interval
        from monitor.issue_tracker_state_owner import tracker_writer
        import xml.etree.ElementTree as ET

        qualified = qualify_prod_stage_l(self.store, **args)
        self.assertTrue(qualified.qualified)
        self.assertEqual(cycle_ids, qualified.cycle_ids)
        self.assertEqual(2, self.settings.k)
        self.assertEqual(4, len(qualified.candidates))
        by_key = {item.activity_key: item for item in qualified.candidates}
        self.assertEqual({
            ("eth_cabling", "leaf-a", "swp1", "Mis-wiring"),
            ("ib_cabling", "leaf01", "sw1p1", "Mis-wiring"),
            ("switch", "leaf-a", "fan", "PSU1/FAN1"),
            ("switch", "nvsw01", "asic_temp", "ASIC1"),
        }, set(by_key))
        eth = by_key[("eth_cabling", "leaf-a", "swp1", "Mis-wiring")]
        ib = by_key[("ib_cabling", "leaf01", "sw1p1", "Mis-wiring")]
        self.assertEqual(("leaf-a", "swp1", "leaf-z", "swp2"), eth.expected_endpoints)
        self.assertEqual(("changed-peer", "swp9", "leaf-a", "swp1"), eth.actual_endpoints)
        # Match the literal planned P2P switch port, not the raw vendor ordinal.
        self.assertEqual(("leaf01", "sw1p1", "server01", "mlx5_0"), ib.expected_endpoints)
        self.assertEqual(("leaf01", "sw1p1", "server03", "mlx5_1"), ib.actual_endpoints)
        asic = by_key[("switch", "nvsw01", "asic_temp", "ASIC1")]
        self.assertIn("81", asic.evidence_description)
        self.assertNotIn("75", asic.evidence_description)
        original_template = self.template.read_bytes()
        metadata = {
            "project_id": str(project), "schema_version": 1,
            "producer_version": "req7-test-producer",
            "template_contract_version": "v1",
            "template_sha256": self.snapshot.workbook_sha256,
        }
        before = tuple(sorted(self.publication.iterdir()))
        body, digest = freeze_prod_stage_l_manifest(
            qualified, self.store, metadata=metadata,
            expected_template_sha256=self.snapshot.workbook_sha256, **args,
        )
        self.assertEqual(before, tuple(sorted(self.publication.iterdir())))
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        (project / "01-global.yaml").write_text(
            "schema_version: 2\ncommon:\n  mgmt:\n"
            "    issue-tracker:\n      status: disabled\n", encoding="utf-8",
        )
        interval, policy_sha = local_publish_interval(project)
        witness = (policy_sha, interval, "fixture-boot", time.monotonic_ns())
        with tracker_writer(project, self.publication) as token:
            committed = commit_prod_stage_l_workbook(
                token, qualified, self.store, template_path=self.template,
                metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                manual_admission=witness, **args,
            )
        self.assertIsInstance(committed, CommittedProdWorkbook)
        self.assertEqual(3, committed.prepared.source_family_count)
        self.assertEqual(digest, committed.receipt.manifest_id)
        self.assertEqual(hashlib.sha256(committed.prepared.xlsx_bytes).hexdigest(),
                         committed.receipt.published_sha256)
        generation = project / ".tracker/generations" / committed.generation.generation_id
        self.assertEqual(body, (generation / "MANIFEST").read_bytes())
        receipt = json.loads((generation / "RECEIPT").read_bytes())
        self.assertEqual(digest, receipt["manifest_id"])
        self.assertEqual(committed.receipt.published_sha256, receipt["published_sha256"])
        published_bytes = (self.publication / receipt["published"]).read_bytes()
        self.assertEqual(committed.prepared.xlsx_bytes, published_bytes)
        self.assertEqual(hashlib.sha256(published_bytes).hexdigest(),
                         committed.receipt.published_sha256)
        self.assertEqual(original_template, self.template.read_bytes())
        ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

        def cells(archive, sheet):
            root = ET.fromstring(archive.read("xl/worksheets/" + sheet))
            return {node.attrib["r"]: node for node in root.findall(".//s:c", ns)}

        def text_value(node):
            return "".join(node.itertext())

        with zipfile.ZipFile(BytesIO(original_template)) as template, \
             zipfile.ZipFile(BytesIO(published_bytes)) as published:
            for sheet, expected in (
                ("sheet3.xml", {"M3": "changed-peer", "N3": "swp9",
                                "S3": "leaf-a", "T3": "swp1"}),
                ("sheet4.xml", {"M3": "leaf01", "N3": "sw1p1",
                                "S3": "server03", "T3": "mlx5_1"}),
            ):
                actual_cells = cells(published, sheet)
                for address, expected_value in expected.items():
                    self.assertEqual(expected_value, text_value(actual_cells[address]), address)
            old_switch, new_switch = cells(template, "sheet2.xml"), cells(published, "sheet2.xml")
            for address in ("D3", "E3", "G3", "H3", "I3", "O3", "U3"):
                self.assertEqual(ET.tostring(old_switch[address]),
                                 ET.tostring(new_switch[address]), address)
            for row in range(4, 8):
                for column in "DEGH":
                    address = f"{column}{row}"
                    self.assertEqual(ET.tostring(old_switch[address]),
                                     ET.tostring(new_switch[address]), address)
            asic_rows = [address[1:] for address, node in new_switch.items()
                         if address.startswith("F") and text_value(node) == "nvsw01"]
            self.assertEqual(1, len(asic_rows))
            description = text_value(new_switch["L" + asic_rows[0]])
            self.assertIn("81", description)
            self.assertNotIn("75", description)

    def test_frozen_template_fabric_is_projected_with_strict_type_precedence(self):
        from monitor.issue_tracker_stage_l_consumer import (
            inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
        )

        self.two_cycles(activity=True, derivation=True,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"})
        cycles = read_completed_cycle_evidence(self.store)
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        fabrics = {(item.activity_key[1], item.fabric, item.fabric_source)
                   for item in projection.candidates
                   if item.panel == "Switch Status"}
        self.assertEqual({("leaf-a", "Inband", "template"),
                          ("nvsw01", "Compute", "type")}, fabrics)
        self.assertEqual("qualification_not_implemented", projection.reason)
        self.assertEqual(0, projection.hostname_fallback_count)
        self.assertFalse(projection.qualified)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_source_projection_displays_eth_w1_skip_without_issue_or_permit(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_source_projection,
        )

        self.template.write_bytes(literal_xlsx(rules=("leaf-z",)))
        self.snapshot = read_whitelist_workbook(self.template)
        self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertFalse(projection.qualified)
        self.assertEqual("hold", projection.state)
        self.assertFalse(any(item.panel == "Eth Link Validation"
                             for item in projection.candidates))
        self.assertEqual(1, len(projection.whitelist_skips))
        self.assertEqual(("eth_cabling", ("leaf-a", "swp1", "leaf-z", "swp2")),
                         (projection.whitelist_skips[0].source,
                          projection.whitelist_skips[0].endpoints))
        self.assertEqual("leaf-z", projection.whitelist_skips[0].matched_rule)
        self.template.write_bytes(literal_xlsx(rules=("leaf-a",)))
        changed_snapshot = read_whitelist_workbook(self.template)
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            with self.assertRaisesRegex(
                StageLConsumerHold, "changed|disagree|unsafe",
            ):
                validate_prod_stage_l_source_projection(
                    projection, source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=changed_snapshot,
                    whitelist_path=self.template,
                )
            changed_source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=changed_snapshot,
                whitelist_path=self.template,
            )
            changed = project_prod_stage_l_source_candidates(
                changed_source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=changed_snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual(projection.whitelist_skips[0].endpoints,
                         changed.whitelist_skips[0].endpoints)
        self.assertEqual("leaf-a", changed.whitelist_skips[0].matched_rule)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_source_projection_reopens_w1_and_latest_completed_source_bytes(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_source_projection,
        )

        _, _, artifacts = self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        row = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (row,),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
            self.assertFalse(projection.qualified)
            self.template.write_bytes(literal_xlsx(rules=("leaf-z",)))
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            with self.assertRaises(StageLConsumerHold):
                validate_prod_stage_l_source_projection(
                    projection, source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            self.template.write_bytes(literal_xlsx())
            latest = artifacts["ethernet/prod"]["info"]
            latest.write_bytes(latest.read_bytes() + b"late byte drift")
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_source_projection_preserves_switch_device_level_w1_record_id(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_source_projection,
        )

        self.template.write_bytes(literal_xlsx(rules=("leaf-a",)))
        self.snapshot = read_whitelist_workbook(self.template)
        self.two_cycles(activity=True, derivation=True,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"})
        cycles = read_completed_cycle_evidence(self.store)
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
            switch_skips = tuple(skip for skip in projection.whitelist_skips
                                 if skip.source == "switch")
            self.assertEqual(1, len(switch_skips))
            self.assertEqual(("switch:leaf-a", "leaf-a", None),
                             (switch_skips[0].record_id,
                              switch_skips[0].matched_rule,
                              switch_skips[0].endpoints))
            self.assertFalse(projection.qualified)
            self.template.write_bytes(literal_xlsx(rules=("re:^leaf-a$",)))
            changed_snapshot = read_whitelist_workbook(self.template)
            with self.assertRaises(StageLConsumerHold):
                validate_prod_stage_l_source_projection(
                    projection, source, self.store, http_root=self.root,
                    settings=self.settings,
                    whitelist_snapshot=changed_snapshot,
                    whitelist_path=self.template,
                )

    def test_prod_three_source_domains_join_exact_k_without_qualification(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold,
            inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_composed_sources,
            validate_prod_stage_l_source_projection,
        )

        self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        row = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (row,),
            ) for cycle in cycles
        }
        # Only the protected IB report decoder is substituted. This tests
        # composition, not true nine-role IB provenance or Stage-L acceptance.
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            self.assertEqual(tuple(cycle.cycle_id for cycle in cycles),
                             source.eth_link_source.cycle_ids)
            self.assertEqual(source.switch_ib_source.switch_source.cycle_ids,
                             source.eth_link_source.cycle_ids)
            self.assertEqual("WRONG_PEER",
                             source.eth_link_source.persistent_links[0].status)
            self.assertEqual(("Miswired_Links", "Mis-wiring"),
                             (source.eth_issue_rows[0].source_sheet,
                              source.eth_issue_rows[0].issue_type))
            self.assertFalse(source.eth_issue_rows[0].qualified)
            self.assertEqual((row,), source.switch_ib_source.ib_source.kept_rows)
            self.assertFalse(source.qualified)
            self.assertEqual("hold", source.state)
            self.assertEqual("qualification_not_implemented", source.reason)
            self.assertEqual(source, validate_prod_stage_l_composed_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            ))
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
            self.assertFalse(projection.qualified)
            self.assertEqual("hold", projection.state)
            self.assertEqual("fabric_identity_unresolved", projection.reason)
            self.assertEqual({"Switch Status", "Eth Link Validation",
                              "IB Link Validation"},
                             {item.panel for item in projection.candidates})
            eth = [item for item in projection.candidates
                   if item.panel == "Eth Link Validation"]
            self.assertEqual(1, len(eth))
            self.assertEqual(("leaf-a", "swp1", "leaf-z", "swp2"),
                             eth[0].expected_endpoints)
            self.assertEqual(("foreign-z", "swp9", "leaf-a", "swp1"),
                             eth[0].actual_endpoints)
            self.assertEqual(("Miswired_Links", "Mis-wiring"),
                             (eth[0].source_sheet, eth[0].issue_type))
            self.assertEqual(
                "stl-" + hashlib.sha256(
                    b'["eth_cabling","leaf-a","swp1","Mis-wiring"]'
                ).hexdigest(),
                eth[0].operation_id,
            )
            self.assertFalse(any(item.qualified for item in projection.candidates))
            fabrics = {(item.activity_key[1], item.fabric, item.fabric_source)
                       for item in projection.candidates
                       if item.panel == "Switch Status"}
            self.assertIn(("nvsw01", "Compute", "type"), fabrics)
            self.assertIn(("leaf-a", None, None), fabrics)
            self.assertEqual(projection, validate_prod_stage_l_source_projection(
                projection, source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            ))
            with self.assertRaises(StageLConsumerHold):
                validate_prod_stage_l_source_projection(
                    replace(projection, qualified=True), source, self.store,
                    http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    replace(source, qualified=True), self.store,
                    http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    replace(source, eth_link_source=replace(
                        source.eth_link_source,
                        cycle_ids=("foreign-cycle", *source.eth_link_source.cycle_ids[1:]),
                    )), self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_real_cycles_and_durable_k_combine_switch_families_and_ib_only(self):
        from monitor.issue_tracker_stage_l_consumer import (
            inspect_prod_stage_l_bound_sources,
            validate_prod_stage_l_bound_sources,
        )

        self.two_cycles()
        cycles = read_completed_cycle_evidence(self.store)
        first = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        latest = IbReportLink(
            "Mis-wiring", first.expected_endpoints,
            ("server03", "mlx5_2"), "Miswired_Links", 3,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64,
                (first if index == 0 else latest,),
            ) for index, cycle in enumerate(cycles)
        }
        # This composition seam replaces protected IB report replay only;
        # it cannot be counted as real report-role or Stage-L acceptance.
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_bound_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            self.assertEqual(tuple(cycle.cycle_id for cycle in cycles),
                             source.switch_source.cycle_ids)
            self.assertEqual((latest,), source.ib_source.kept_rows)
            self.assertFalse(source.qualified)
            self.assertEqual("hold", source.state)
            self.assertEqual("qualification_not_implemented", source.reason)
            self.assertEqual(source, validate_prod_stage_l_bound_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            ))
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_real_prod_worker_emitter_cycles_with_unbound_ib_stay_read_only(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_sources,
            require_complete_stage_l_sources,
        )

        first, second, _artifacts = self.two_cycles()
        source = inspect_prod_stage_l_sources(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.snapshot, whitelist_path=self.template,
        )
        self.assertEqual((first["cycle_id"], second["cycle_id"]), source.cycle_ids)
        self.assertEqual("hold", source.state)
        self.assertEqual("ib_report_not_bound_to_completed_cycle", source.reason)
        self.assertFalse(source.qualified)
        self.assertEqual({"ethernet/prod", "nvlink/prod"},
                         {row.source_slot for row in source.switch_rows})
        with self.assertRaisesRegex(StageLConsumerHold,
                                    "IB report.*completed cycle"):
            require_complete_stage_l_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))


if __name__ == "__main__":
    unittest.main()
