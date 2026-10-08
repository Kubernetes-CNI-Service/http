"""One Stage-L local writer owner for C-6 generations and C-25 settings.

This is a local-only seam. It neither qualifies runtime observations nor
grants online eligibility. Existing standalone fixture APIs are retained for
their direct tests; this module is the combined production boundary.
"""

from contextlib import ExitStack, contextmanager
from pathlib import Path

from monitor.issue_tracker_k_chain import KChainHoldError
from monitor.issue_tracker_k_store import (
    apply_local_k_change, initialize_local_k_store, read_local_k_store,
)
from monitor.issue_tracker_local_commit import (
    LocalCommitHold, _owner, create_local_commit_store, writer_owner,
)


_COMPLETED_READ_CONTEXT = {}


class TrackerStateHold(ValueError):
    """A shared local state authority is missing, incomplete, or unsafe."""


def _root(project):
    return Path(project) / ".tracker"


def initialize_tracker_state(project, publication, *, initialized_at, acquisition_id):
    """Initialize one NEW root and both subtrees; interrupted first use STOPS.

    A preexisting root is never interpreted as a new default K authority.
    The caller must establish trusted first-use project freshness separately.
    """
    try:
        create_local_commit_store(project, publication)
        with writer_owner(project, publication) as token:
            return initialize_local_k_store(
                _root(project), initialized_at=initialized_at,
                acquisition_id=acquisition_id, token=token,
            )
    except (LocalCommitHold, KChainHoldError, OSError, TypeError, ValueError) as exc:
        raise TrackerStateHold("shared tracker initialization incomplete or unsafe") from exc


@contextmanager
def tracker_writer(project, publication, *, completed_binding=None, completed_unit=None):
    """Acquire project THEN spreadsheet for an explicit original completed unit.

    Context is scoped to this actual owner, revalidated on each K read and
    revoked before either owner closes. No cleanup or extra settings-write
    permission by itself; the existing local C6 capability is not online admission.
    """
    with ExitStack() as stack:
        try:
            token = stack.enter_context(writer_owner(project, publication))
            if completed_binding is None and completed_unit is None:
                read_local_k_store(_root(project), token=token)
            else:
                if completed_binding is None or completed_unit is None:
                    raise TrackerStateHold("incomplete original completed-unit context")
                from monitor.issue_tracker_spreadsheet_owner import spreadsheet_owner
                sheet = stack.enter_context(spreadsheet_owner(completed_binding))
                current_k(token, spreadsheet_token=sheet, binding=completed_binding,
                          completed_unit=completed_unit)
                _COMPLETED_READ_CONTEXT[token] = (sheet,completed_binding,completed_unit)
        except (LocalCommitHold, KChainHoldError, OSError, TypeError, ValueError) as exc:
            raise TrackerStateHold("shared tracker writer is incomplete or unsafe") from exc
        # ExitStack closes/revokes on every body exit, but never relabels the
        # caller's exception as a tracker-state failure.
        try:
            yield token
            if token in _COMPLETED_READ_CONTEXT:
                current_k(token)  # Final revalidation, not a cached successful K.
        finally:
            _COMPLETED_READ_CONTEXT.pop(token,None)


def current_k(token, *, spreadsheet_token=None, binding=None, completed_unit=None):
    """Read highest K; missing delivered projections require the actual paired owners.

    No context keeps the ordinary strict contract. Partial/fake/expired context
    cannot authorize missing projections. This is not an online send permission.
    """
    try:
        owner = _owner(token)
        context=(spreadsheet_token,binding,completed_unit)
        if all(item is None for item in context):
            context=_COMPLETED_READ_CONTEXT.get(token,context)
            spreadsheet_token,binding,completed_unit=context
        if any(item is not None for item in context):
            if any(item is None for item in context):
                raise TrackerStateHold("incomplete original delivery context")
            from monitor.issue_tracker_settings_audit_allocation import read_current_k_after_completed_unit
            return read_current_k_after_completed_unit(token,spreadsheet_token,binding,completed_unit)
        return read_local_k_store(_root(owner.project), token=token)
    except (LocalCommitHold, KChainHoldError, OSError, TypeError, ValueError) as exc:
        raise TrackerStateHold("shared settings read refused") from exc


def require_current_k(token, project, publication, expected):
    """Verify K through this exact ACTIVE writer; never reacquire its lock."""
    try:
        owner = _owner(token)
        if (owner.project != Path(project)
                or owner.publication != Path(publication)):
            raise TrackerStateHold("writer token belongs to another project")
        if current_k(token) != expected:
            raise TrackerStateHold("K setting changed under writer ownership")
    except (LocalCommitHold, OSError, TypeError, ValueError) as exc:
        if isinstance(exc, TrackerStateHold):
            raise
        raise TrackerStateHold("shared settings owner is invalid") from exc


def set_k(token, *, new_k, actor, recorded_at, request_id, expected_revision):
    """Commit a K event under the same LK-P token; actor trust is external."""
    try:
        owner = _owner(token)
        context = _COMPLETED_READ_CONTEXT.get(token)
        if context is not None:
            from monitor.issue_tracker_settings_audit_allocation import apply_completed_k_change
            return apply_completed_k_change(token,*context,new_k=new_k,actor=actor,
                recorded_at=recorded_at,request_id=request_id,expected_revision=expected_revision)
        return apply_local_k_change(
            _root(owner.project), new_k=new_k, actor=actor,
            recorded_at=recorded_at, request_id=request_id,
            expected_revision=expected_revision, token=token,
        )
    except (LocalCommitHold, KChainHoldError, OSError, TypeError, ValueError) as exc:
        raise TrackerStateHold("shared settings change refused") from exc
