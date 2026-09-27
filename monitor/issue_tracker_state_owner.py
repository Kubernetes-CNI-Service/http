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
def tracker_writer(project, publication):
    """Hold the C-6 owner and validate K authority before exposing its token."""
    with ExitStack() as stack:
        try:
            token = stack.enter_context(writer_owner(project, publication))
            read_local_k_store(_root(project), token=token)
        except (LocalCommitHold, KChainHoldError, OSError, TypeError, ValueError) as exc:
            raise TrackerStateHold("shared tracker writer is incomplete or unsafe") from exc
        # ExitStack closes/revokes on every body exit, but never relabels the
        # caller's exception as a tracker-state failure.
        yield token


def current_k(token):
    """Read highest complete K while the caller's single LK-P token is live."""
    try:
        owner = _owner(token)
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
        return apply_local_k_change(
            _root(owner.project), new_k=new_k, actor=actor,
            recorded_at=recorded_at, request_id=request_id,
            expected_revision=expected_revision, token=token,
        )
    except (LocalCommitHold, KChainHoldError, OSError, TypeError, ValueError) as exc:
        raise TrackerStateHold("shared settings change refused") from exc
