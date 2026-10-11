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
_COMPLETED_ORIGINAL_GUARDS = {}
_LOCAL_C6_READ_CONTEXT = {}


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


def _verify_settings_originals(token):
    try:
        from monitor import issue_tracker_settings_audit_allocation as allocation
        context=_COMPLETED_READ_CONTEXT.get(token)
        if type(context) is allocation._NativeCompletedSettingsContext:
            allocation._native_settings_packet(token,context)
        elif any(packet['token'] is token for packet in allocation._LIVE_NATIVE_SETTINGS_CONTEXTS.values()):
            # Revoked/rebound public enrollment must not fall back to ordinary
            # K merely because its projection currently happens to be present.
            raise TrackerStateHold('native settings enrollment changed')
        verify = _COMPLETED_ORIGINAL_GUARDS.get(token)
        if verify is not None:
            verify()
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise TrackerStateHold("settings held original changed") from exc


@contextmanager
def _settings_original_scope():
    """Always finish ALL holders; no ACK after teardown or hidden body failure.

    Revocation is performed by the settings factory before this stack closes.
    A caller's original interruption survives a simultaneous original-finalizer
    failure (which remains its explicit cause). Internal refusal alone is a
    typed state HOLD, not a raw error accidentally escaping the factory.
    """
    stack=ExitStack(); primary=None
    try:
        yield stack
    except BaseException as exc:
        primary=exc
        raise
    finally:
        try:
            stack.close()
        except BaseException as exc:
            if primary is not None:
                raise primary from exc
            if isinstance(exc,(LocalCommitHold,KChainHoldError,OSError,TypeError,ValueError,KeyError)):
                raise TrackerStateHold('settings original finalization refused') from exc
            raise


@contextmanager
def tracker_settings_writer(project, publication):
    """Reopen local settings through actual originals, never caller delivery flags.

    Acquire LK-P first, and only a durable delivery claim can trigger discovery
    of the actual spreadsheet owner and original COMPLETE/DELIVERED pair.
    No claim preserves the ordinary strict K contract. This does not initialize
    missing state, grant online authority or replace publication/source owners.
    """
    with _settings_original_scope() as stack:
        token = None
        try:
            try:
                token = stack.enter_context(writer_owner(project, publication))
                from monitor.issue_tracker_settings_audit_allocation import _hold_discovered_completed_settings
                context, verify = stack.enter_context(_hold_discovered_completed_settings(token))
                _COMPLETED_ORIGINAL_GUARDS[token] = verify
                if context is not None:
                    _COMPLETED_READ_CONTEXT[token] = context
                current_k(token)
            except (LocalCommitHold, KChainHoldError, OSError, TypeError, ValueError, KeyError) as exc:
                raise TrackerStateHold("settings original discovery refused") from exc
            yield token
            current_k(token)
        finally:
            # Revoke before the original pair and project owner close, on every
            # exit, including interruption during the FIRST K read. Caller
            # exceptions are not relabeled as ownership failures.
            _COMPLETED_ORIGINAL_GUARDS.pop(token, None)
            _COMPLETED_READ_CONTEXT.pop(token, None)


@contextmanager
def tracker_local_c6_writer(project, publication):
    """Fixed local C6 continuation after legitimate original audit archive."""
    with _settings_original_scope() as scope:
        token=None
        try:
            try:
                token=scope.enter_context(writer_owner(project,publication))
                from monitor.issue_tracker_settings_audit_allocation import _hold_completed_local_c6
                context,verify=scope.enter_context(_hold_completed_local_c6(token))
                if context is not None:_LOCAL_C6_READ_CONTEXT[token]=context
                current_k(token); verify()
            except (LocalCommitHold,KChainHoldError,OSError,TypeError,ValueError,KeyError) as exc:
                raise TrackerStateHold('local C6 original handoff refused') from exc
            yield token
            current_k(token); verify()
        finally:
            _LOCAL_C6_READ_CONTEXT.pop(token,None)


def current_k(token, *, spreadsheet_token=None, binding=None, completed_unit=None):
    """Read highest K; missing delivered projections require the actual paired owners.

    No context keeps the ordinary strict contract. Partial/fake/expired context
    cannot authorize missing projections. This is not an online send permission.
    """
    try:
        from monitor import issue_tracker_settings_audit_allocation as allocation
        local_c6=_LOCAL_C6_READ_CONTEXT.get(token)
        if local_c6 is not None:
            if any(item is not None for item in (spreadsheet_token,binding,completed_unit)):
                raise TrackerStateHold('local C6 cannot borrow another delivery context')
            return allocation._read_completed_local_c6_k(token,local_c6)
        if any(packet['token'] is token for packet in allocation._LIVE_LOCAL_C6_CONTEXTS.values()):
            raise TrackerStateHold('local C6 enrollment changed')
        _verify_settings_originals(token)
        owner = _owner(token)
        context=(spreadsheet_token,binding,completed_unit)
        if all(item is None for item in context):
            context=_COMPLETED_READ_CONTEXT.get(token,context)
            from monitor import issue_tracker_settings_audit_allocation as allocation
            if type(context) is allocation._NativeCompletedSettingsContext:
                result=allocation._read_native_completed_k(token,context)
                _verify_settings_originals(token)
                return result
            spreadsheet_token,binding,completed_unit=context
        if any(item is not None for item in context):
            if any(item is None for item in context):
                raise TrackerStateHold("incomplete original delivery context")
            from monitor.issue_tracker_settings_audit_allocation import read_current_k_after_completed_unit
            result = read_current_k_after_completed_unit(token,spreadsheet_token,binding,completed_unit)
        else:
            result = read_local_k_store(_root(owner.project), token=token)
        _verify_settings_originals(token)
        return result
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
        from monitor import issue_tracker_settings_audit_allocation as allocation
        if token in _LOCAL_C6_READ_CONTEXT or any(
                packet['token'] is token for packet in allocation._LIVE_LOCAL_C6_CONTEXTS.values()):
            raise TrackerStateHold('fixed local C6 enrollment is read-only')
        _verify_settings_originals(token)
        owner = _owner(token)
        context = _COMPLETED_READ_CONTEXT.get(token)
        from monitor import issue_tracker_settings_audit_allocation as allocation
        if type(context) is allocation._NativeCompletedSettingsContext:
            result=allocation._apply_native_completed_k_change(token,context,new_k=new_k,actor=actor,
                recorded_at=recorded_at,request_id=request_id,expected_revision=expected_revision)
        elif context is not None:
            from monitor.issue_tracker_settings_audit_allocation import apply_completed_k_change
            result = apply_completed_k_change(token,*context,new_k=new_k,actor=actor,
                recorded_at=recorded_at,request_id=request_id,expected_revision=expected_revision)
        else:
            result = apply_local_k_change(
                _root(owner.project), new_k=new_k, actor=actor,
                recorded_at=recorded_at, request_id=request_id,
                expected_revision=expected_revision, token=token,
            )
        _verify_settings_originals(token)
        return result
    except (LocalCommitHold, KChainHoldError, OSError, TypeError, ValueError) as exc:
        raise TrackerStateHold("shared settings change refused") from exc
