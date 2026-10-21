"""SOURCE NOT RUN. Real private owners; only module-local close IO fault.

Unknown cleanup remains in a fixed owned cold child; no numeric FD rescue.
"""
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock

import test_cases
from test_cases import test_req7_spreadsheet_owner as existing_sheet

ROOT = Path(test_cases.__file__).resolve().parents[1]
CHILD_METHODS = (
    '_exercise_actual_sheet_owner_body_ni_close_eio',
    '_exercise_tracker_writer_local_owner_body_ni_close_eio',
)
CHILD_PROGRAM = (
    "import sys, unittest\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from test_cases.test_req7_owner_ni_cleanup import OwnerNICleanupTests\n"
    "from test_cases.owner_ni_cleanup_fixture import CHILD_METHODS\n"
    "name=sys.argv[2]\n"
    "if name not in CHILD_METHODS: raise SystemExit(64)\n"
    "result=unittest.TextTestRunner(verbosity=2).run(\n"
    "    unittest.TestSuite([OwnerNICleanupTests(name)]))\n"
    "print('OWNER_NI_CHILD_END='+name+';success='+str(result.wasSuccessful()), flush=True)\n"
    "raise SystemExit(0 if result.wasSuccessful() else 1)\n")


def capture(call):
    try:
        return call(), None
    except BaseException as error:
        return None, error


def interruption():
    error = KeyboardInterrupt('private owner body interruption')
    cause = RuntimeError('private original owner body cause')
    error.__cause__ = cause
    error.__suppress_context__ = True
    return error, cause


def new_root():
    root = Path(tempfile.mkdtemp(prefix='req7-owner-ni-owned-')).resolve()
    root.chmod(0o700)
    print('OWNER_NI_OWNED_ROOT=' + str(root), flush=True)
    return root


class CloseIO:
    """No success/checker replacement: delegates the real module OS namespace."""
    def __init__(self, base, registry, token, descriptors, *, fault_fd=None):
        self.base, self.registry, self.token = base, registry, token
        self.slots = tuple((fd, os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                           for fd in descriptors)
        self.fault_fd = fault_fd
        self.calls = []
        self.revoked = []
        self.closed_errno = []
        self.faults = 0

    def __getattr__(self, name):
        return getattr(self.base, name)

    def close(self, fd):
        matches = [slot for slot in self.slots if slot[0] == fd]
        if not matches:
            return self.base.close(fd)
        slot = matches[0]
        if fd in self.calls:
            raise AssertionError('fixture saw repeat close of known original slot')
        before = os.fstat(fd)
        if (before.st_dev, before.st_ino) != slot[1:]:
            raise AssertionError('fixture refuses changed original close slot')
        self.calls.append(fd)
        self.revoked.append(self.token not in self.registry)
        self.base.close(fd)  # ORIGINAL actual close, exactly once.
        try:
            os.fstat(fd)
        except OSError as error:
            self.closed_errno.append(error.errno)
        else:
            raise AssertionError('original close did not close actual fd')
        if fd == self.fault_fd:
            self.faults += 1
            raise OSError(errno.EIO, 'private actual owner close tail')

    def snapshot(self):
        live = []
        for fd, device, inode in self.slots:
            try:
                current = os.fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
            else:
                live.append((fd, current.st_dev, current.st_ino,
                             (device, inode) == (current.st_dev, current.st_ino)))
        return dict(slots=len(self.slots), calls=len(self.calls),
            revoked=list(self.revoked), closed_errno=list(self.closed_errno),
            faults=self.faults, remaining=live)


def sheet_case(root, *, fault=False):
    from monitor import issue_tracker_spreadsheet_owner as sheet
    locks = root / 'var/lib/http-ztp-container/issue-tracker'
    locks.mkdir(parents=True, mode=0o700)
    locks.chmod(0o700)
    bound = existing_sheet.binding()
    body_error, cause = interruption()
    token = view = None
    body_ready = False

    def operation():
        nonlocal token, view, body_ready
        with existing_sheet.scoped_fixture(root, sheet):
            with ExitStack() as patches:
                with sheet.spreadsheet_owner(bound) as token:
                    owner = sheet._validated_owner(token, bound)
                    lock_fd = sheet.owner_lock_fd(token, bound)
                    if owner.lock_fd != lock_fd:
                        raise AssertionError('real owner lock does not match real borrow')
                    view = CloseIO(sheet.os, sheet._ACTIVE, token, owner.descriptors,
                                  fault_fd=lock_fd if fault else None)
                    # Patch lifetime includes the genuine owner __exit__.
                    patches.enter_context(mock.patch.object(sheet, 'os', view))
                    sheet.owner_lock_fd(token, bound)  # actual healthy guard
                    body_ready = True
                    if fault:
                        raise body_error

    _unused, error = capture(operation)
    snapshot = view.snapshot() if view is not None else None
    _unused, revoked_error = capture(lambda: sheet.owner_lock_fd(token, bound))
    return dict(error=error, ni=body_error, cause=cause, ready=body_ready,
                view=view, snapshot=snapshot, token_revoked=token not in sheet._ACTIVE,
                revoked_error=revoked_error, hold=sheet.SpreadsheetOwnerHold)


def tracker_case(project, publication, *, fault=False):
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_state_owner as state
    body_error, cause = interruption()
    token = view = None
    body_ready = False
    observed_k = None

    def operation():
        nonlocal token, view, body_ready, observed_k
        with ExitStack() as patches:
            with state.tracker_writer(project, publication) as token:
                owner = local._owner(token)
                current = state.current_k(token)
                observed_k = (current.revision, current.k)
                descriptors = (owner.project_fd, owner.root_fd,
                               owner.publication_fd, owner.lock_fd)
                view = CloseIO(local.os, local._ACTIVE, token, descriptors,
                              fault_fd=owner.lock_fd if fault else None)
                patches.enter_context(mock.patch.object(local, 'os', view))
                local._owner(token)  # real guard, not a mocked result
                body_ready = True
                if fault:
                    raise body_error

    _unused, error = capture(operation)
    # Immediately inspect only the four recorded originals; no open/scans/rescue.
    snapshot = view.snapshot() if view is not None else None
    _unused, revoked_error = capture(lambda: local._owner(token))
    return dict(error=error, ni=body_error, cause=cause, ready=body_ready,
                observed_k=observed_k, view=view, snapshot=snapshot,
                token_revoked=token not in local._ACTIVE,
                context_revoked=token not in state._COMPLETED_READ_CONTEXT,
                revoked_error=revoked_error, hold=local.LocalCommitHold)


def diagnostic(label, outcome):
    # Fixed synthetic metadata only, before any behavior assertion can fail.
    print('OWNER_NI_CLEANUP_FACTS=' + json.dumps(dict(
        label=label, body_ready=outcome['ready'], snapshot=outcome['snapshot'],
        token_revoked=outcome['token_revoked'],
        error_type=type(outcome['error']).__name__ if outcome['error'] is not None else None,
        original_ni=outcome['error'] is outcome['ni'],
        original_cause=(outcome['error'] is not None
                        and outcome['error'].__cause__ is outcome['cause'])),
        sort_keys=True), flush=True)


def run_owned(case, name):
    if name not in CHILD_METHODS:
        raise AssertionError('unknown owned child selector')
    process = subprocess.Popen((sys.executable, '-B', '-c', CHILD_PROGRAM,
        str(ROOT), name), cwd=str(ROOT), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        close_fds=True, env={'LC_ALL': 'C', 'HOME': os.path.expanduser('~')})
    try:
        try:
            output, errors = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            # This fixture starts no descendants. Only this retained original
            # Popen is supervised, never a scanned/reported PID or FD rescue.
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
            case.fail('OWNED_OWNER_CHILD_TIMEOUT_UNKNOWN')
        case.assertLessEqual(len(output) + len(errors), 65536)
        print(output.decode('utf-8', 'replace'), end='', flush=True)
        if process.returncode != 0:
            print(errors.decode('utf-8', 'replace'), end='', flush=True)
        case.assertEqual(0, process.returncode, 'OWNED_OWNER_CHILD_ASSERTIONS_FAILED')
        marker = ('OWNER_NI_CHILD_END=' + name + ';success=True\n').encode('ascii')
        case.assertEqual(1, output.count(marker))
    finally:
        for stream in (process.stdout, process.stderr):
            stream.close()
