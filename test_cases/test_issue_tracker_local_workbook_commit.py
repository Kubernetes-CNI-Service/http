"""W1a fake XLSX INTENT/RECEIPT durability and old blob isolation."""

from __future__ import annotations

from io import BytesIO
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

from monitor import issue_tracker_local_commit as durable
from monitor.issue_tracker_local_workbook import LocalWorkbookHold
from monitor.issue_tracker_local_workbook_commit import commit_fake_workbook
from test_cases.test_issue_tracker_local_workbook import (
    KEY, SwitchDescriptionEdit, fake_workbook, fixture_manifest,
)


MANIFEST = b'{"operations":[],"schema_version":1}\n'


def large_fake_workbook():
    """One valid, C24-readable 14-sheet fake package larger than real source."""
    original = fake_workbook()
    result = BytesIO()
    with zipfile.ZipFile(BytesIO(original)) as source, zipfile.ZipFile(result, "w") as target:
        for info in source.infolist():
            target.writestr(info, source.read(info.filename))
        target.writestr("fixture/opaque.bin", bytes(range(256)) * 14_000,
                        compress_type=zipfile.ZIP_STORED)
    assert len(result.getvalue()) > 3_516_072
    return result.getvalue()


class LocalWorkbookCommitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="tracker-w1a-")
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name).resolve(strict=True)
        self.publication = self.project / "publication"
        self.publication.mkdir(mode=0o700)
        durable.create_local_commit_store(self.project, self.publication)

    def test_valid_large_xlsx_has_derived_name_and_genuine_receipt(self):
        body = large_fake_workbook()
        with durable.writer_owner(self.project, self.publication) as token:
            generation = durable.begin_generation(token, MANIFEST)
            witness = durable.record_intent(token, generation, body, kind="xlsx")
            self.assertEqual(len(body), witness.size)
            intent = self.project / ".tracker" / "generations" / generation.generation_id / "INTENT"
            self.assertIn(b'"kind":"xlsx"', intent.read_bytes())
            receipt = durable.commit(token, generation)
            published = self.publication / (generation.generation_id + ".xlsx")
            self.assertEqual(body, published.read_bytes())
            self.assertEqual(hashlib.sha256(body).hexdigest(), receipt.published_sha256)
            self.assertFalse((self.publication / (generation.generation_id + ".bin")).exists())
            self.assertEqual("RECEIPT-PRESENT-NOT-ELIGIBILITY",
                             durable.inspect_local_generation(
                                 self.project, self.publication, generation, token=token).status)

    def test_nonempty_w1_authority_reaches_preparer_before_any_generation(self):
        authority = object()
        template = self.project / "unused-template.xlsx"
        with durable.writer_owner(self.project, self.publication) as token:
            with mock.patch(
                "monitor.issue_tracker_local_workbook_commit.prepare_fake_local_workbook",
                side_effect=LocalWorkbookHold("forged frozen W1"),
            ) as prepare:
                with self.assertRaises(LocalWorkbookHold):
                    commit_fake_workbook(
                        token, template, MANIFEST, [],
                        expected_template_sha256="a" * 64,
                        qualified_set=authority, expected_manifest_id="b" * 64,
                    )
            prepare.assert_called_once_with(
                template, MANIFEST, [], expected_template_sha256="a" * 64,
                qualified_set=authority, expected_manifest_id="b" * 64,
            )
        self.assertEqual([], list((self.project / ".tracker" / "generations").iterdir()))

    def test_prod_commit_rejects_synthetic_qualified_set_before_generation(self):
        from monitor.issue_tracker_local_workbook_commit import commit_prod_stage_l_workbook
        from test_cases.test_issue_tracker_manifest import METADATA, QUALIFIED

        with durable.writer_owner(self.project, self.publication) as token:
            with self.assertRaises(durable.LocalCommitHold):
                commit_prod_stage_l_workbook(
                    token, QUALIFIED, object(), http_root=object(),
                    settings=object(), whitelist_snapshot=object(),
                    whitelist_path=object(), template_path=object(),
                    metadata=METADATA, expected_template_sha256="b" * 64,
                )
        self.assertEqual([], list((self.project / ".tracker" / "generations").iterdir()))

    def test_second_changed_prod_c6_requires_shared_admission_before_generation(self):
        from monitor.issue_tracker_local_workbook_commit import commit_prod_stage_l_workbook
        from monitor.issue_tracker_stage_l_consumer import ProdStageLQualifiedSet
        from test_cases.test_issue_tracker_manifest import METADATA

        prod_project = self.project / "prod"
        prod_project.mkdir()
        prod_publication = prod_project / "99-output-monitor"
        prod_publication.mkdir()
        durable.create_local_commit_store(prod_project, prod_publication)
        qualified = ProdStageLQualifiedSet(
            operations_json=b"{}", candidates=(), whitelist_skips=(),
            cycle_ids=("cycle-2",), completion_sha256=("b" * 64,),
            source_authority_sha256="c" * 64,
            observations_sha256="d" * 64, k_event_sha256="e" * 64,
            whitelist_sha256="f" * 64, template_sha256="a" * 64,
            project_key="fixture-project", scope="prod", k=1,
            recorded_at_utc="2026-09-27T00:00:00Z",
        )
        snapshot = SimpleNamespace(workbook_sha256="a" * 64)
        store = SimpleNamespace(project_identity=str(prod_project))
        with durable.writer_owner(prod_project, prod_publication) as token, \
             mock.patch("monitor.issue_tracker_local_workbook_commit.require_current_k"), \
             mock.patch("monitor.issue_tracker_local_workbook_commit.read_whitelist_workbook",
                        return_value=snapshot), \
             mock.patch("monitor.issue_tracker_local_workbook_commit.freeze_prod_stage_l_manifest",
                        return_value=(MANIFEST, hashlib.sha256(MANIFEST).hexdigest())), \
             mock.patch("monitor.issue_tracker_local_workbook_commit._latest_receipted_prod_xlsx",
                        return_value=b"prior"), \
             mock.patch("monitor.issue_tracker_local_workbook_commit.project_cabling_workbook_image",
                        return_value=b"changed"), \
             mock.patch("monitor.issue_tracker_local_workbook_commit.project_switch_workbook_image",
                        side_effect=lambda image, _rows: image), \
             mock.patch("monitor.issue_tracker_local_workbook_commit.project_whitelist_skip_history_image",
                        side_effect=lambda image, _skips, **_kwargs: image):
            with self.assertRaisesRegex(durable.LocalCommitHold, "shared admission"):
                commit_prod_stage_l_workbook(
                    token, qualified, store, http_root=prod_project,
                    settings=object(), whitelist_snapshot=snapshot,
                    whitelist_path=prod_project / "template.xlsx",
                    template_path=prod_project / "template.xlsx",
                    metadata=METADATA, expected_template_sha256="a" * 64,
                )
        self.assertEqual([], list((prod_project / ".tracker" / "generations").iterdir()))

    def test_prod_replay_refuses_unresolved_or_fake_prior_generation(self):
        from monitor.issue_tracker_local_workbook_commit import _latest_receipted_prod_xlsx

        with durable.writer_owner(self.project, self.publication) as token:
            self.assertIsNone(_latest_receipted_prod_xlsx(token, "a" * 64))
            generation = durable.begin_generation(token, MANIFEST)
            with self.assertRaises(durable.LocalCommitHold):
                _latest_receipted_prod_xlsx(token, "a" * 64)
            durable.record_intent(token, generation, fake_workbook(), kind="xlsx")
            durable.commit(token, generation)
            with self.assertRaises(durable.LocalCommitHold):
                _latest_receipted_prod_xlsx(token, "a" * 64)

    def test_old_blob_name_and_one_megabyte_limit_remain_unchanged(self):
        with durable.writer_owner(self.project, self.publication) as token:
            blob = durable.begin_generation(token, MANIFEST)
            with self.assertRaises(durable.LocalCommitHold):
                durable.record_intent(token, blob, b"x" * (1024 * 1024 + 1))
            durable.record_intent(token, blob, b"old-blob")
            durable.commit(token, blob)
            self.assertEqual(b"old-blob", (self.publication / (blob.generation_id + ".bin")).read_bytes())
            self.assertFalse((self.publication / (blob.generation_id + ".xlsx")).exists())

    def test_xlsx_kind_and_32_mib_bound_are_fail_closed_before_intent(self):
        body = fake_workbook()
        self.assertEqual(32 * 1024 * 1024, durable._MAX_XLSX)
        with durable.writer_owner(self.project, self.publication) as token:
            for invalid, kind in ((b"not a ZIP", "xlsx"), (body, "arbitrary")):
                generation = durable.begin_generation(token, MANIFEST)
                with self.assertRaises(durable.LocalCommitHold):
                    durable.record_intent(token, generation, invalid, kind=kind)
                self.assertFalse((self.project / ".tracker" / "generations" /
                                  generation.generation_id / "INTENT").exists())
            generation = durable.begin_generation(token, MANIFEST)
            with mock.patch.object(durable, "_MAX_XLSX", len(body) - 1):
                with self.assertRaises(durable.LocalCommitHold):
                    durable.record_intent(token, generation, body, kind="xlsx")
            self.assertFalse((self.project / ".tracker" / "generations" /
                              generation.generation_id / "INTENT").exists())

    def test_failed_xlsx_commit_and_restart_never_mint_receipt(self):
        body = large_fake_workbook()
        with durable.writer_owner(self.project, self.publication) as token:
            generation = durable.begin_generation(token, MANIFEST)
            durable.record_intent(token, generation, body, kind="xlsx")
            with mock.patch.object(durable.os, "fsync", side_effect=OSError(errno.EIO, "barrier")):
                with self.assertRaises(durable.LocalCommitHold):
                    durable.commit(token, generation)
            receipt = self.project / ".tracker" / "generations" / generation.generation_id / "RECEIPT"
            self.assertFalse(receipt.exists())
        self.assertEqual("UNRESOLVED", durable.inspect_local_generation(
            self.project, self.publication, generation).status)
        self.assertFalse(receipt.exists())

    def test_xlsx_intent_restart_and_quarantine_remain_receipt_absent(self):
        body = fake_workbook()
        with durable.writer_owner(self.project, self.publication) as token:
            generation = durable.begin_generation(token, MANIFEST)
            durable.record_intent(token, generation, body, kind="xlsx")
        self.assertEqual(("UNRESOLVED", "PREPARED-PRESENT"),
                         (durable.inspect_local_generation(self.project, self.publication,
                                                           generation).status,
                          durable.inspect_local_generation(self.project, self.publication,
                                                           generation).prepared_observation))
        with durable.writer_owner(self.project, self.publication) as token:
            self.assertEqual("QUARANTINED-OBSERVATION",
                             durable.quarantine_unresolved(token, generation))
        quarantine = self.project / ".tracker" / "quarantine" / (generation.generation_id + ".xlsx")
        self.assertEqual(body, quarantine.read_bytes())
        self.assertEqual("QUARANTINED-PRESENT",
                         durable.inspect_local_generation(self.project, self.publication,
                                                          generation).prepared_observation)
        self.assertFalse((self.project / ".tracker" / "generations" /
                          generation.generation_id / "RECEIPT").exists())

    def test_tampered_xlsx_intent_kind_cannot_mint_receipt(self):
        with durable.writer_owner(self.project, self.publication) as token:
            generation = durable.begin_generation(token, MANIFEST)
            durable.record_intent(token, generation, fake_workbook(), kind="xlsx")
            intent = self.project / ".tracker" / "generations" / generation.generation_id / "INTENT"
            document = json.loads(intent.read_bytes())
            document["prepared"]["kind"] = "blob"
            intent.write_bytes(json.dumps(document, sort_keys=True,
                                          separators=(",", ":")).encode() + b"\n")
            with self.assertRaises(durable.LocalCommitHold):
                durable.commit(token, generation)
            self.assertFalse((intent.parent / "RECEIPT").exists())

    def test_xlsx_destination_race_and_source_swap_do_not_receipt(self):
        for sabotage in ("destination", "source"):
            with self.subTest(sabotage=sabotage), durable.writer_owner(self.project, self.publication) as token:
                generation = durable.begin_generation(token, MANIFEST)
                body = fake_workbook()
                witness = durable.record_intent(token, generation, body, kind="xlsx")
                foreign = b"foreign XLSX bytes"
                source = ".prepared-" + generation.generation_id + ".xlsx"
                published = generation.generation_id + ".xlsx"
                injected = []
                real_listdir = os.listdir

                def race(fd):
                    result = real_listdir(fd)
                    if (isinstance(fd, int) and not injected and
                            (os.fstat(fd).st_dev, os.fstat(fd).st_ino) ==
                            (self.publication.stat().st_dev, self.publication.stat().st_ino)):
                        if sabotage == "source":
                            os.rename(source, source + ".preserved",
                                      src_dir_fd=fd, dst_dir_fd=fd)
                        name = source if sabotage == "source" else published
                        output = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=fd)
                        try:
                            os.write(output, foreign)
                            os.fsync(output)
                            injected.append(os.fstat(output).st_ino)
                        finally:
                            os.close(output)
                        os.fsync(fd)
                    return result

                with mock.patch.object(durable.os, "listdir", side_effect=race):
                    with self.assertRaises(durable.LocalCommitHold):
                        durable.commit(token, generation)
                self.assertEqual(1, len(injected))
                if sabotage == "destination":
                    self.assertEqual((foreign, injected[0]),
                                     ((self.publication / published).read_bytes(),
                                      (self.publication / published).stat().st_ino))
                    self.assertEqual(witness.ino, (self.publication / source).stat().st_ino)
                else:
                    self.assertEqual(body, (self.publication / (source + ".preserved")).read_bytes())
                    # A successful rename can be visible, but must not produce a receipt.
                    self.assertEqual(foreign, (self.publication / published).read_bytes())
                receipt = self.project / ".tracker" / "generations" / generation.generation_id / "RECEIPT"
                self.assertFalse(receipt.exists())


if __name__ == "__main__":
    unittest.main()
