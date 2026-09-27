"""Cold, read-only C-6 generation discovery under the one Stage-L writer lock.

This module is an observation seam, not a recovery writer or an online
eligibility issuer. It does not reconstruct an ACTIVE generation handle for
``record_intent`` or ``commit``. A copied state tree whose inode witnesses no
longer match must HOLD; physical offline restore requires a separate contract.
"""

from __future__ import annotations

from dataclasses import dataclass
import os

from monitor.issue_tracker_local_commit import (
    Generation, LocalCommitHold, _GEN, _SHA, _directory, _generation_fd,
    _json, _owner, _read, inspect_local_generation,
)
from monitor.issue_tracker_state_owner import TrackerStateHold, tracker_writer


class LocalRecoveryHold(ValueError):
    """Cold journal state is incomplete or unsafe; no conclusion is issued."""


@dataclass(frozen=True)
class RecoveredGeneration:
    generation_id: str
    sequence: int
    manifest_id: str
    status: str
    prepared_observation: str


def _ordered_names(names):
    sequences = {}
    for name in names:
        match = _GEN.fullmatch(name)
        if match is None:
            raise LocalRecoveryHold("unexplained generation entry")
        sequence = int(match.group(1))
        if sequence < 1 or sequence in sequences:
            raise LocalRecoveryHold("duplicate or invalid generation sequence")
        sequences[sequence] = name
    if set(sequences) != set(range(1, len(sequences) + 1)):
        raise LocalRecoveryHold("generation sequence has a missing entry")
    return tuple(sequences[sequence] for sequence in sorted(sequences))


def _require_empty_quarantine(owner):
    quarantine = _directory(owner.root_fd, "quarantine")
    try:
        # A quarantine observation is not a verified publication or recovery
        # result. This bounded reader cannot attribute even a known-looking
        # quarantine name to a generation, so any entry stops the whole scan.
        if os.listdir(quarantine):
            raise LocalRecoveryHold("quarantine evidence is not validated")
    finally:
        os.close(quarantine)


def inspect_recovered_generations(project, publication):
    """Return only literal local observations from an intact locked journal.

    Every generation is validated against its disk STATE/MANIFEST and by the
    existing C-6 inspector. Unknown tails and unvalidated quarantine records
    HOLD the entire scan; this function never repairs or promotes them.
    """
    try:
        with tracker_writer(project, publication) as token:
            owner = _owner(token)
            _require_empty_quarantine(owner)
            generations = _directory(owner.root_fd, "generations")
            try:
                names = _ordered_names(os.listdir(generations))
                observations = []
                for name in names:
                    directory = _directory(generations, name)
                    try:
                        entries = set(os.listdir(directory))
                        if (not {"STATE", "MANIFEST"}.issubset(entries)
                                or entries - {"STATE", "MANIFEST", "INTENT", "RECEIPT"}
                                or ("RECEIPT" in entries and "INTENT" not in entries)):
                            raise LocalRecoveryHold("unexplained generation evidence")
                        state = _json(_read(directory, "STATE")[0], {
                            "schema_version", "generation_id", "sequence", "manifest_id",
                        })
                        match = _GEN.fullmatch(name)
                        if (type(state["schema_version"]) is not int
                                or state["schema_version"] != 1
                                or state["generation_id"] != name
                                or type(state["sequence"]) is not int
                                or state["sequence"] != int(match.group(1))
                                or not isinstance(state["manifest_id"], str)
                                or _SHA.fullmatch(state["manifest_id"]) is None):
                            raise LocalRecoveryHold("generation STATE does not bind directory")
                        # This handle is never registered in owner.handles and is
                        # never returned. C-6's write hooks require that registry.
                        generation = Generation(name, state["sequence"],
                                                state["manifest_id"], object())
                        verified = _generation_fd(owner, generation)
                        os.close(verified)
                        observation = inspect_local_generation(
                            project, publication, generation, token=token,
                        )
                        if set(os.listdir(directory)) != entries:
                            raise LocalRecoveryHold("generation changed during observation")
                        observations.append(RecoveredGeneration(
                            name, generation.sequence, generation.manifest_id,
                            observation.status, observation.prepared_observation,
                        ))
                    finally:
                        os.close(directory)
                if _ordered_names(os.listdir(generations)) != names:
                    raise LocalRecoveryHold("generation set changed during observation")
                _require_empty_quarantine(owner)
                return tuple(observations)
            finally:
                os.close(generations)
    except (LocalCommitHold, TrackerStateHold, OSError, TypeError, KeyError, ValueError) as exc:
        if isinstance(exc, LocalRecoveryHold):
            raise
        raise LocalRecoveryHold("cold local journal observation refused") from exc
