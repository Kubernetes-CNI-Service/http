"""Frozen workbook preparation and C-6 local receipt bridge.

The caller must own the single C-6/LK-P writer token. This bridge performs no
runtime qualification, network action, or online eligibility decision. A
failure may leave durable INTENT evidence; it never repairs or deletes it.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

from monitor.issue_tracker_local_commit import (
    Generation, LocalCommitHold, LocalReceipt, _GEN, _directory, _intent,
    _json, _owner, _prepared_limit, _published_name, _read,
    begin_generation, commit, record_intent,
)
from monitor.issue_tracker_local_workbook import (
    CablingSourceRow, PreparedLocalWorkbook, SwitchSourceWorkbookRow,
    _read_bound_source, prepare_fake_local_workbook,
    project_cabling_workbook_image, project_switch_workbook_image,
    project_whitelist_skip_history_image,
    validate_operator_edited_workbook,
)
from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
from monitor.issue_tracker_state_owner import require_current_k
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook


@dataclass(frozen=True)
class CommittedFakeWorkbook:
    generation: Generation
    receipt: LocalReceipt
    prepared: PreparedLocalWorkbook


@dataclass(frozen=True)
class PreparedProdWorkbook:
    xlsx_bytes: bytes
    sha256: str
    source_sha256: str
    manifest_id: str
    source_family_count: int
    candidate_panel_count: int
    hostname_fallback_count: int
    operator_input_sha256: str | None = None


@dataclass(frozen=True)
class CommittedProdWorkbook:
    """A local durable receipt, never online publication authority."""

    generation: Generation
    receipt: LocalReceipt
    prepared: PreparedProdWorkbook


@dataclass(frozen=True)
class ProdWorkbookNoop:
    """Source replay changed no business row; no generation was created."""

    status: str
    existing_published_sha256: str | None
    manifest_id: str


def commit_fake_workbook(token, template_path, manifest_body, edits, *,
                         expected_template_sha256, qualified_set=None,
                         expected_manifest_id=None):
    """Prepare then durably commit one fake XLSX; never infer remote eligibility."""
    prepared = prepare_fake_local_workbook(
        template_path, manifest_body, edits,
        expected_template_sha256=expected_template_sha256,
        qualified_set=qualified_set, expected_manifest_id=expected_manifest_id,
    )
    if (prepared.manifest_id != hashlib.sha256(manifest_body).hexdigest()
            or prepared.source_sha256 != expected_template_sha256
            or prepared.sha256 != hashlib.sha256(prepared.xlsx_bytes).hexdigest()):
        raise LocalCommitHold("fake workbook and frozen manifest identity differ")
    # All byte/source checks precede generation creation. Once INTENT exists,
    # any later failure is an unresolved journal event, never a fake success.
    generation = begin_generation(token, manifest_body)
    record_intent(token, generation, prepared.xlsx_bytes, kind="xlsx")
    receipt = commit(token, generation)
    if (receipt.manifest_id != prepared.manifest_id
            or receipt.published_sha256 != prepared.sha256):
        raise LocalCommitHold("local receipt did not bind prepared fake XLSX")
    return CommittedFakeWorkbook(generation, receipt, prepared)


def _latest_receipted_prod_xlsx(token, expected_template_sha256):
    """Read last durable image, refusing any unresolved prior generation."""
    owner = _owner(token)
    generations = _directory(owner.root_fd, "generations")
    try:
        names = os.listdir(generations)
        if any(_GEN.fullmatch(name) is None for name in names):
            raise LocalCommitHold("unexplained prior generation entry")
        ordered = sorted(names, key=lambda name: int(_GEN.fullmatch(name).group(1)))
        if tuple(int(_GEN.fullmatch(name).group(1)) for name in ordered) != tuple(
                range(1, len(ordered) + 1)):
            raise LocalCommitHold("prior generation sequence has a gap")
        latest = None
        for name in ordered:
            directory = _directory(generations, name)
            try:
                if set(os.listdir(directory)) != {"STATE", "MANIFEST", "INTENT", "RECEIPT"}:
                    raise LocalCommitHold("prior generation is unresolved or unexplained")
                state = _json(_read(directory, "STATE")[0], {
                    "schema_version", "generation_id", "sequence", "manifest_id",
                })
                sequence = int(_GEN.fullmatch(name).group(1))
                if (type(state["schema_version"]) is not int
                        or state["schema_version"] != 1
                        or state["generation_id"] != name
                        or type(state["sequence"]) is not int
                        or state["sequence"] != sequence):
                    raise LocalCommitHold("prior generation state is invalid")
                manifest = _read(directory, "MANIFEST", 1024 * 1024)[0]
                if hashlib.sha256(manifest).hexdigest() != state["manifest_id"]:
                    raise LocalCommitHold("prior manifest identity changed")
                parsed = _json(manifest)
                source = parsed.get("qualified_source")
                if (parsed.get("template_sha256") != expected_template_sha256
                        or not isinstance(source, dict)
                        or source.get("mode") != "prod-runtime-protected-v1"):
                    raise LocalCommitHold("prior workbook has different source authority")
                generation = Generation(name, sequence, state["manifest_id"], token)
                witness = _intent(owner, generation, directory)
                if witness.get("kind") != "xlsx":
                    raise LocalCommitHold("prior generation is not an XLSX")
                receipt = _json(_read(directory, "RECEIPT")[0])
                published_name = _published_name(name, "xlsx")
                if (set(receipt) != {
                        "schema_version", "generation_id", "sequence", "manifest_id",
                        "published", "published_dev", "published_ino", "published_size",
                        "published_sha256", "kind",
                    } or type(receipt["schema_version"]) is not int
                        or receipt["schema_version"] != 1
                        or receipt["generation_id"] != name
                        or receipt["sequence"] != sequence
                        or receipt["manifest_id"] != state["manifest_id"]
                        or receipt["kind"] != "xlsx"
                        or receipt["published"] != published_name
                        or (receipt["published_dev"], receipt["published_ino"],
                            receipt["published_size"], receipt["published_sha256"])
                        != (witness["dev"], witness["ino"], witness["size"],
                            witness["sha256"])):
                    raise LocalCommitHold("prior XLSX RECEIPT does not match INTENT")
                raw, info = _read(owner.publication_fd, published_name,
                                  _prepared_limit("xlsx"))
                if (info.st_dev, info.st_ino, info.st_size,
                        hashlib.sha256(raw).hexdigest()) != (
                            witness["dev"], witness["ino"], witness["size"],
                            witness["sha256"]):
                    raise LocalCommitHold("prior published XLSX differs from RECEIPT")
                latest = raw
            finally:
                os.close(directory)
        return latest
    finally:
        os.close(generations)


def _controlled_operator_edit(token, prior_source):
    """Read same-owner edit bound to last immutable RECEIPT, without mutating it."""
    if prior_source is None:
        raise LocalCommitHold("operator edit needs a prior committed workbook")
    owner = _owner(token)
    try:
        witness_body, witness_stat = _read(owner.root_fd, "OPERATOR_EDIT.json")
    except OSError as exc:
        raise LocalCommitHold("operator edit witness is missing or unsafe") from exc
    witness = _json(witness_body, {
        "schema_version", "base_published_sha256", "edited_sha256",
    })
    if (type(witness["schema_version"]) is not int
            or witness["schema_version"] != 1
            or witness["base_published_sha256"] != hashlib.sha256(prior_source).hexdigest()
            or type(witness["edited_sha256"]) is not str
            or len(witness["edited_sha256"]) != 64):
        raise LocalCommitHold("operator edit is not bound to latest RECEIPT")
    try:
        edited, edited_stat = _read(
            owner.root_fd, "OPERATOR_EDIT.xlsx", _prepared_limit("xlsx"))
    except OSError as exc:
        raise LocalCommitHold("operator edited workbook is missing or unsafe") from exc
    if hashlib.sha256(edited).hexdigest() != witness["edited_sha256"]:
        raise LocalCommitHold("operator edited workbook differs from witness")
    validate_operator_edited_workbook(
        prior_source, edited, disallow_unproved_closure=True)
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                             info.st_mtime_ns, info.st_ctime_ns)
    return edited, (witness_body, identity(witness_stat), identity(edited_stat))


def commit_prod_stage_l_workbook(
    token, qualified, store, *, http_root, settings, whitelist_snapshot,
    whitelist_path, template_path, metadata, expected_template_sha256,
    apply_operator_edit=False, auto_admission=None, manual_admission=None,
) -> CommittedProdWorkbook | ProdWorkbookNoop:
    """Requalify protected C-5 and commit its XLSX locally under one writer.

    This never grants Stage O or network publication authority. Existing
    operator-owned Priority values are preserved by the projection helpers.
    """
    if type(apply_operator_edit) is not bool:
        raise LocalCommitHold("operator edit request must be an explicit boolean")
    # The qualification type is imported only on this path so fake-only users
    # remain available while the protected-source integration is assembled.
    from monitor.issue_tracker_stage_l_consumer import ProdStageLQualifiedSet

    owner = _owner(token)
    if type(qualified) is not ProdStageLQualifiedSet:
        raise LocalCommitHold("C-6 qualified type is invalid")
    project = Path(store.project_identity)
    publication = project / "99-output-monitor"
    if (owner.project != project or owner.publication != publication
            or Path(whitelist_path) != Path(template_path)):
        raise LocalCommitHold("C-6 owner, template or qualified type is invalid")
    require_current_k(token, project, publication, settings)
    snapshot = read_whitelist_workbook(template_path)
    if (snapshot != whitelist_snapshot
            or snapshot.workbook_sha256 != expected_template_sha256):
        raise LocalCommitHold("C-6 template or Whitelist changed")
    manifest, manifest_id = freeze_prod_stage_l_manifest(
        qualified, store, http_root=http_root, settings=settings,
        whitelist_snapshot=snapshot, whitelist_path=whitelist_path,
        metadata=metadata, expected_template_sha256=expected_template_sha256,
        writer_token=token,
    )
    prior_source = _latest_receipted_prod_xlsx(token, expected_template_sha256)
    operator_witness = None
    if apply_operator_edit:
        source, operator_witness = _controlled_operator_edit(token, prior_source)
    else:
        source = (prior_source if prior_source is not None else
                  _read_bound_source(template_path, snapshot))
    source_sha = hashlib.sha256(source).hexdigest()
    cabling = []
    switch = []
    for candidate in qualified.candidates:
        if candidate.panel in {"Eth Link Validation", "IB Link Validation"}:
            sheet = ("ETH Cabling" if candidate.panel == "Eth Link Validation"
                     else "IB Cabling")
            actual = (() if sheet == "IB Cabling"
                      and candidate.source_status == "Link Down"
                      else candidate.actual_endpoints)
            cabling.append(CablingSourceRow(
                sheet=sheet, activity_key=candidate.activity_key,
                expected_endpoints=candidate.expected_endpoints,
                actual_endpoints=actual,
                source_status=candidate.source_status,
                evidence_description=candidate.evidence_description,
                recorded_at_utc=candidate.recorded_at_utc,
            ))
        elif candidate.panel == "Switch Status":
            switch.append(SwitchSourceWorkbookRow(
                activity_key=candidate.activity_key,
                evidence_description=candidate.evidence_description,
                fabric=candidate.fabric, fabric_source=candidate.fabric_source,
                priority="P2", recorded_at_utc=candidate.recorded_at_utc,
            ))
        else:
            raise LocalCommitHold("qualified C-6 candidate panel is unknown")
    image = project_cabling_workbook_image(source, tuple(cabling))
    image = project_switch_workbook_image(image, tuple(switch))
    image = project_whitelist_skip_history_image(
        image, qualified.whitelist_skips,
        recorded_at_utc=qualified.recorded_at_utc,
        manifest_id=manifest_id,
    )
    prepared = PreparedProdWorkbook(
        image, hashlib.sha256(image).hexdigest(), source_sha, manifest_id,
        3, len({candidate.panel for candidate in qualified.candidates}),
        sum(item.fabric_source == "hostname-fallback" for item in switch),
        source_sha if apply_operator_edit else None,
    )
    # Recheck source and policy while ACTIVE, before creating a generation.
    require_current_k(token, project, publication, settings)
    if (read_whitelist_workbook(template_path) != snapshot
            or _latest_receipted_prod_xlsx(token, expected_template_sha256)
            != prior_source
            or (prior_source is None
                and _read_bound_source(template_path, snapshot) != source)):
        raise LocalCommitHold("C-6 workbook source changed before generation")
    if apply_operator_edit:
        replay_edit, replay_witness = _controlled_operator_edit(token, prior_source)
        if (replay_edit, replay_witness) != (source, operator_witness):
            raise LocalCommitHold("operator edit changed before generation")
    replay, replay_id = freeze_prod_stage_l_manifest(
        qualified, store, http_root=http_root, settings=settings,
        whitelist_snapshot=snapshot, whitelist_path=whitelist_path,
        metadata=metadata, expected_template_sha256=expected_template_sha256,
        writer_token=token,
    )
    if (replay, replay_id) != (manifest, manifest_id):
        raise LocalCommitHold("C-6 source changed before generation")
    if prepared.xlsx_bytes == (prior_source if prior_source is not None else source):
        if prior_source is None:
            if qualified.candidates:
                raise LocalCommitHold("C-6 has no changed row or prior local RECEIPT")
            return ProdWorkbookNoop("no_candidates", None, manifest_id)
        return ProdWorkbookNoop(
            "no_change", hashlib.sha256(prior_source).hexdigest(), manifest_id)
    from monitor.issue_tracker_admission import (
        AdmissionHold, prepare_shared_local_admission,
        read_shared_local_admission, record_shared_local_admission,
        local_publish_interval,
    )

    if (auto_admission is None) == (manual_admission is None):
        raise LocalCommitHold("C-6 new generation lacks one shared admission")
    lane = "automatic" if auto_admission is not None else "manual"
    witness = auto_admission if auto_admission is not None else manual_admission
    if (type(witness) is not tuple or len(witness) != 4
            or local_publish_interval(project)
            != (witness[1], witness[0])):
        raise AdmissionHold("C-6 shared admission policy is invalid")
    policy_sha, interval, boot_id, now_ns = witness
    prior_admission = read_shared_local_admission(token, store, prior_source)
    admission_prepared = prepare_shared_local_admission(
        token, store, prior_admission, lane=lane,
        policy_sha256=policy_sha, publish_every_cycles=interval,
        boot_id=boot_id, monotonic_ns=now_ns,
    )
    generation = begin_generation(token, manifest)
    record_intent(token, generation, prepared.xlsx_bytes, kind="xlsx")
    receipt = commit(token, generation)
    if (receipt.manifest_id != manifest_id
            or receipt.published_sha256 != prepared.sha256):
        raise LocalCommitHold("C-6 local RECEIPT differs from prepared XLSX")
    result = CommittedProdWorkbook(generation, receipt, prepared)
    record_shared_local_admission(
        token, result.receipt.generation_id,
        result.receipt.published_sha256, admission_prepared,
    )
    return result
