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
        panel_counts_probe=False, source_unit_probe=False,
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
            '20 1[  ] "server02 mlx5_1"\n', encoding="utf-8",
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
            expected_count = 2 if selected_panel_empty else 4
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
