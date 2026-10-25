"""Darwin kernel unlock witness (KWV) for the existing current-EX helper.

Tests-first DRAFT by the W2 agent on 2026-10-23.  NOT RUN.

Independent expectation sources (never the implementation under test):
* DARWIN-LOCK-CONTRACT-APPROVAL-v2-20261023.md D1/D2: VERIFY_PREHELD checks the
  exact caller FD's current EX; owner and real dup accepted; unlocked, SH,
  foreign OFD and close/rebind rejected; a rejection must not convert the
  caller into an EX owner; no acquisition may stand in for that proof.
* macOS SDK (MacOSX15.5.sdk) usr/include/sys/event.h: NOTE_FUNLOCK 0x00000100
  "vnode was unlocked by flock(2)"; kqueue(2): "unlocked by calling flock(2)
  or close(2)"; usr/include/sys/fcntl.h: O_EVTONLY 0x00008000.
* XNU FWASLOCKED 0x00004000 "has or has had an advisory lock" (sticky,
  F_GETFL), also observed by the 2026-10-23 native mechanism probe.  Used only
  as the negative fact "never flocked", never as ownership evidence.
* 2026-10-24 owner-confirmed revision of APPROVAL v2 line 24 (owner: "同意 1";
  test_cases/PERFORMANCE_VALIDATION_HANDOVER.md "2026-10-24 owner 确认的合同修订"):
  in the Darwin R-alpha window only, a witnessed rejection may leave EX on the
  caller's own description until its last reference closes; every later
  verification through that description (same FD, dup, fork+exec child,
  deployment_lock() inherited branch) is rejected before any EX call; the
  empty lock file stays 0 bytes with an unchanged nine-tuple.  POSIX
  dup(2)/fork(2)/execve(2)/lseek(2) (MacOSX15.5.sdk man2) for offset sharing.
  Refinement (same evening, http dev review adopted by the main thread):
  exact offset intervals -- 0 clean; >= 2^44 tainted; [2^40, 2^44) reserved
  for Phase 2 signatures and "not enabled"; 0 < off < 2^40 violates the
  no read/write/seek invariant (TR-1c measured the offset semantics).

No skip decorators: every method asserts the Darwin contract on Darwin and the
unchanged Linux /proc current-FD contract on Linux.
"""
from contextlib import ExitStack, contextmanager
import errno
import fcntl
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tools import deployment_lock as locks


ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink")
SDK_NOTE_FUNLOCK = 0x00000100
SDK_O_EVTONLY = 0x00008000
XNU_FWASLOCKED = 0x00004000
IS_DARWIN = sys.platform == "darwin"


def identity(metadata):
    return tuple(getattr(metadata, name) for name in FIELDS)


def nine(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


@contextmanager
def private_lock(payload=b""):
    root = Path(tempfile.mkdtemp(
        prefix="public-kwv-", dir=os.environ.get("R22_TEST_PRIVATE_ROOT"),
    )).resolve()
    path = root / ".deployment.lock"
    path.write_bytes(payload)
    try:
        yield root, path
    finally:
        print("KWV_PUBLIC_FIXTURE_RETAINED=" + str(root), flush=True)


def open_fd(path):
    return os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)


def shared_witness(path, real_flock=fcntl.flock):
    descriptor = open_fd(path)
    try:
        real_flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    finally:
        os.close(descriptor)


class PeerHolder:
    """A real foreign process holding EX on its own open file description."""

    CODE = "\n".join((
        "import fcntl, os, sys",
        "fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW)",
        "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)",
        "print('HELD', flush=True)",
        "assert sys.stdin.readline().strip() == 'RELEASE'",
        "fcntl.flock(fd, fcntl.LOCK_UN)",
        "print('RELEASED', flush=True)",
        "assert sys.stdin.readline().strip() == 'FINISH'",
        "os.close(fd)",
    ))

    def __init__(self, path):
        # -S: the peer program imports only fcntl/os/sys, so it needs no
        # site-packages on any interpreter (isolated-child dependency rule).
        self.process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", "-c", self.CODE, str(path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        self._expect("HELD")

    def _expect(self, word):
        ready = select.select([self.process.stdout], [], [], 10)[0]
        if not ready or self.process.stdout.readline() != word + "\n":
            raise RuntimeError("PUBLIC peer holder handshake failed: " + word)

    def release(self):
        self.process.stdin.write("RELEASE\n")
        self.process.stdin.flush()
        self._expect("RELEASED")

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write("FINISH\n")
                self.process.stdin.flush()
            except (BrokenPipeError, ValueError):
                pass
        try:
            self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()


def reverify(verify, descriptor, real_flock=fcntl.flock):
    """Verify ``descriptor`` again; return (error or None, EX attempts on it)."""
    attempts = []

    def flock(fd, operation):
        if fd == descriptor and operation & fcntl.LOCK_EX:
            attempts.append(operation)
        return real_flock(fd, operation)
    error = None
    with mock.patch.object(locks.fcntl, "flock", side_effect=flock):
        try:
            verify(descriptor)
        except Exception as exc:  # recorded and asserted by the caller
            error = exc
    return error, attempts


# A real fork+exec child that inherits the caller's description through
# pass_fds and HTTP_DEPLOYMENT_LOCK_FD, then verifies it with the helper and
# (Darwin) with deployment_lock()'s inherited branch.  It counts EX calls on
# the inherited FD.  The finish-state root is a PUBLIC absent path, as in the
# workflow module's hermetic LOAD binding, so no host state is consulted.
EXEC_REVERIFY_CHILD = "\n".join((
    "import fcntl, os, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from tools import deployment_lock as locks",
    "finish = sys.modules[locks.assert_writer_allowed.__module__]",
    "finish.FINISH_STATE_ROOT = locks.Path(sys.argv[2]).parent / 'PUBLIC-owned-absent-finish-state'",
    "path, fd = sys.argv[2], int(sys.argv[3])",
    "real, attempts = fcntl.flock, []",
    "def flock(descriptor, operation):",
    "    if descriptor == fd and operation & fcntl.LOCK_EX:",
    "        attempts.append(operation)",
    "    return real(descriptor, operation)",
    "fcntl.flock = flock",
    "words = []",
    "try:",
    "    locks.require_current_exclusive_lock_descriptor(path, fd)",
    "    words.append('helper=ACCEPTED')",
    "except locks.DeploymentLockError:",
    "    words.append('helper=REJECTED')",
    "if sys.platform == 'darwin':",
    "    try:",
    "        with locks.deployment_lock(os.path.dirname(path)):",
    "            words.append('inherited=ACCEPTED')",
    "    except locks.DeploymentLockError:",
    "        words.append('inherited=REJECTED')",
    "words.append('ex_attempts=%d' % len(attempts))",
    "print(' '.join(words), flush=True)",
))
EXEC_REVERIFY_EXPECTED = ("helper=REJECTED inherited=REJECTED ex_attempts=0" if IS_DARWIN
                          else "helper=REJECTED ex_attempts=0")


def run_exec_reverify_child(path, descriptor):
    environment = dict(os.environ)
    environment[locks.LOCK_FD_ENV] = str(descriptor)
    # -S: the child imports tools/deployment_lock.py and tools/finished_project_state.py
    # from the repository root it inserts; both import only the standard library,
    # so the child needs no site-packages on any interpreter (isolated-child rule).
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", EXEC_REVERIFY_CHILD, str(ROOT), str(path), str(descriptor)],
        pass_fds=(descriptor,), env=environment, capture_output=True, text=True, timeout=60,
    )


class PosixPeerHolder(PeerHolder):
    """A real foreign process holding a whole-file POSIX record lock (lockf)."""

    CODE = "\n".join((
        "import fcntl, os, sys",
        "fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW)",
        "fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)",
        "print('HELD', flush=True)",
        "assert sys.stdin.readline().strip() == 'RELEASE'",
        "fcntl.lockf(fd, fcntl.LOCK_UN)",
        "print('RELEASED', flush=True)",
        "assert sys.stdin.readline().strip() == 'FINISH'",
        "os.close(fd)",
    ))


class DarwinKernelWitnessConstantsTests(unittest.TestCase):
    def test_pinned_constants_equal_public_sdk_literals(self):
        self.assertEqual(ROOT / "tools/deployment_lock.py", Path(locks.__file__))
        self.assertEqual(SDK_NOTE_FUNLOCK, locks._DARWIN_NOTE_FUNLOCK)
        self.assertEqual(SDK_O_EVTONLY, locks._DARWIN_O_EVTONLY)
        self.assertEqual(XNU_FWASLOCKED, locks._DARWIN_FWASLOCKED)


class DarwinKernelWitnessPrimitiveTests(unittest.TestCase):
    """Properties the KWV design relies on, measured on the real kernel."""

    def _witness(self, path):
        return locks._open_darwin_unlock_witness(path, FIELDS, identity(path.lstat()))

    def test_release_paths_are_witnessed_on_darwin_and_witness_absent_on_linux(self):
        if IS_DARWIN:
            self.assertTrue(hasattr(select, "kqueue"))
            return self._darwin_release_paths_are_witnessed()
        with private_lock() as (_root, path):
            with self.assertRaisesRegex(locks.DeploymentLockError, "deployment lock.*HOLD"):
                self._witness(path)
            owner = locks.acquire_lock_path_descriptor(path)
            try:
                with mock.patch.object(locks, "_open_darwin_unlock_witness",
                                       side_effect=AssertionError("Linux used a Darwin witness")):
                    self.assertIsNone(locks.require_current_exclusive_lock_descriptor(path, owner))
            finally:
                locks.release_lock_descriptor(owner)

    def _darwin_release_paths_are_witnessed(self):
        def explicit_unlock(path):
            fd = open_fd(path)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return (lambda: fcntl.flock(fd, fcntl.LOCK_UN)), (lambda: os.close(fd))

        def last_close(path):
            fd = open_fd(path)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return (lambda: os.close(fd)), (lambda: None)

        def peer_unlock(path):
            peer = PeerHolder(path)
            return peer.release, peer.close

        def peer_sigkill(path):
            peer = PeerHolder(path)

            def kill():
                peer.process.send_signal(signal.SIGKILL)
                peer.process.wait(10)
            return kill, peer.close

        def rename(path):
            return (lambda: path.rename(path.with_name("renamed-lock"))), (lambda: None)

        for label, scenario in (("same-process-LOCK_UN", explicit_unlock),
                                ("last-close", last_close),
                                ("peer-process-LOCK_UN", peer_unlock),
                                ("peer-SIGKILL", peer_sigkill),
                                ("rename", rename)):
            with self.subTest(release=label), private_lock() as (_root, path):
                trigger, cleanup = scenario(path)
                witness = self._witness(path)
                try:
                    quiet = locks._darwin_witness_disturbed(witness)
                    trigger()
                    disturbed = locks._darwin_witness_disturbed(witness)
                finally:
                    locks._close_darwin_unlock_witness(witness)
                    cleanup()
                self.assertFalse(quiet)
                self.assertTrue(disturbed)

    def test_non_releasing_operations_are_not_witnessed(self):
        with private_lock() as (_root, path):
            owner = locks.acquire_lock_path_descriptor(path)
            duplicate = os.dup(owner)
            probe = open_fd(path)
            try:
                if not IS_DARWIN:
                    # Linux: the helper's real /proc path accepts the owner and
                    # never consults the Darwin-only witness.
                    with mock.patch.object(locks, "_open_darwin_unlock_witness",
                                           side_effect=AssertionError("Linux used a Darwin witness")):
                        self.assertIsNone(locks.require_current_exclusive_lock_descriptor(path, owner))
                    return
                witness = self._witness(path)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)  # idempotent owner re-assertion
                    os.close(duplicate)                                # non-last close
                    duplicate = None
                    disturbed = locks._darwin_witness_disturbed(witness)
                finally:
                    locks._close_darwin_unlock_witness(witness)
                self.assertFalse(disturbed)
                self.assertFalse(shared_witness(path))
            finally:
                os.close(probe)  # closed only after the witness, see N5
                if duplicate is not None:
                    os.close(duplicate)
                locks.release_lock_descriptor(owner)

    def test_invalid_kernel_event_fails_closed(self):
        if not IS_DARWIN:
            self.assertFalse(hasattr(select, "kqueue") and sys.platform.startswith("linux"))
            return
        wrong = select.kevent(987654, filter=select.KQ_FILTER_VNODE, fflags=SDK_NOTE_FUNLOCK)
        fake = SimpleNamespace(watch=123456, queue=SimpleNamespace(control=lambda *a: [wrong]))
        with self.assertRaisesRegex(locks.DeploymentLockError, "deployment lock.*invalid.*HOLD"):
            locks._darwin_witness_disturbed(fake)
        errored = select.kevent(123456, filter=select.KQ_FILTER_VNODE,
                                flags=select.KQ_EV_ERROR, data=errno.EBADF)
        fake = SimpleNamespace(watch=123456, queue=SimpleNamespace(control=lambda *a: [errored]))
        with self.assertRaisesRegex(locks.DeploymentLockError, "deployment lock.*invalid.*HOLD"):
            locks._darwin_witness_disturbed(fake)

    def test_fwaslocked_is_a_sticky_never_flocked_negative_fact(self):
        with private_lock() as (_root, path):
            fd = open_fd(path)
            try:
                if not IS_DARWIN:
                    owner = locks.acquire_lock_path_descriptor(path)
                    try:
                        with mock.patch.object(locks.fcntl, "fcntl",
                                               side_effect=AssertionError("Linux consulted F_GETFL")):
                            self.assertIsNone(locks.require_current_exclusive_lock_descriptor(path, owner))
                    finally:
                        locks.release_lock_descriptor(owner)
                    return
                observed = [bool(fcntl.fcntl(fd, fcntl.F_GETFL) & XNU_FWASLOCKED)]
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                observed.append(bool(fcntl.fcntl(fd, fcntl.F_GETFL) & XNU_FWASLOCKED))
                fcntl.flock(fd, fcntl.LOCK_UN)
                observed.append(bool(fcntl.fcntl(fd, fcntl.F_GETFL) & XNU_FWASLOCKED))
                self.assertEqual([False, True, True], observed)
            finally:
                os.close(fd)


class DarwinKernelWitnessGuardTests(unittest.TestCase):
    """The original helper with the witness: same original accept/reject set."""

    def test_witness_registered_before_probe_and_released_before_probe_close(self):
        with private_lock() as (_root, path):
            owner = locks.acquire_lock_path_descriptor(path)
            order = []
            real_open, real_close = locks._open_darwin_unlock_witness, locks._close_darwin_unlock_witness
            real_flock = fcntl.flock

            def opened(*args):
                order.append("witness-open")
                return real_open(*args)

            def closed(witness):
                order.append("witness-close")
                return real_close(witness)

            def flock(fd, operation):
                if fd != owner and operation == (fcntl.LOCK_SH | fcntl.LOCK_NB):
                    order.append("SH-probe")
                elif fd == owner and operation == (fcntl.LOCK_EX | fcntl.LOCK_NB):
                    order.append("caller-EX-reassertion")
                return real_flock(fd, operation)

            fds_before = sorted(os.listdir("/dev/fd"))
            try:
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.object(locks, "_open_darwin_unlock_witness", side_effect=opened))
                    stack.enter_context(mock.patch.object(locks, "_close_darwin_unlock_witness", side_effect=closed))
                    stack.enter_context(mock.patch.object(locks.fcntl, "flock", side_effect=flock))
                    self.assertIsNone(locks.require_current_exclusive_lock_descriptor(path, owner))
                fds_after = sorted(os.listdir("/dev/fd"))
            finally:
                locks.release_lock_descriptor(owner)
            if IS_DARWIN:
                self.assertEqual(["witness-open", "SH-probe", "caller-EX-reassertion", "witness-close"], order)
            else:
                self.assertEqual([], order)
            self.assertEqual(fds_before, fds_after)

    def test_never_flocked_candidate_gets_no_EX_attempt_and_stays_unlocked(self):
        with private_lock() as (_root, path):
            owner = locks.acquire_lock_path_descriptor(path)
            candidate = open_fd(path)
            attempts = []
            real_flock = fcntl.flock

            def flock(fd, operation):
                if fd == candidate and operation & fcntl.LOCK_EX:
                    attempts.append(operation)
                return real_flock(fd, operation)
            try:
                with mock.patch.object(locks.fcntl, "flock", side_effect=flock):
                    with self.assertRaisesRegex(locks.DeploymentLockError, "deployment lock"):
                        locks.require_current_exclusive_lock_descriptor(path, candidate)
            finally:
                locks.release_lock_descriptor(owner)
            try:
                self.assertEqual([], attempts)
                self.assertTrue(shared_witness(path, real_flock))
            finally:
                os.close(candidate)

    def test_release_after_probe_before_reassertion_is_rejected_without_conversion(self):
        """Contract: APPROVAL v2 line 24 and its 2026-10-24 owner-confirmed revision ("同意 1").

        never-locked (every platform) and every Linux variant: rejection and no
        conversion, unchanged.  Darwin locked-then-UN (residual R-alpha window):
        the rejection is triggered by the kernel witness; a possible EX residue
        stays only on the caller's own description; reuse of that description
        through the same FD or a dup is rejected before any EX call; closing its
        last reference releases the residue; the empty lock file stays 0 bytes
        with an unchanged nine-tuple.
        """
        real_flock = fcntl.flock
        for variant in ("never-locked", "locked-then-UN"):
            with self.subTest(caller=variant), private_lock() as (_root, path):
                first = nine(path.lstat())
                caller = open_fd(path)
                caller_open = True
                if variant == "locked-then-UN":
                    real_flock(caller, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    real_flock(caller, fcntl.LOCK_UN)
                peer = PeerHolder(path)
                released = []

                def flock(fd, operation):
                    if fd == caller and operation == (fcntl.LOCK_EX | fcntl.LOCK_NB) and not released:
                        released.append("before-caller-EX")
                        peer.release()
                    return real_flock(fd, operation)

                def fdinfo(fd):
                    frame = original_reader(fd)
                    if fd == caller and not released:
                        released.append("after-current-FD-read")
                        peer.release()
                    return frame
                original_reader = locks._read_current_lock_fdinfo
                guard = {"error": None}
                reuse = {}
                try:
                    with ExitStack() as stack:
                        if IS_DARWIN:
                            stack.enter_context(mock.patch.object(locks.fcntl, "flock", side_effect=flock))
                        else:
                            stack.enter_context(mock.patch.object(locks, "_read_current_lock_fdinfo", side_effect=fdinfo))
                        try:
                            locks.require_current_exclusive_lock_descriptor(path, caller)
                        except Exception as exc:
                            guard["error"] = exc
                    if not released:
                        peer.release()
                    witness_acquired = shared_witness(path, real_flock)
                    if variant == "locked-then-UN":
                        def helper(fd):
                            return locks.require_current_exclusive_lock_descriptor(path, fd)
                        reuse["same-FD"] = reverify(helper, caller, real_flock)
                        duplicate = os.dup(caller)
                        try:
                            reuse["dup"] = reverify(helper, duplicate, real_flock)
                        finally:
                            os.close(duplicate)
                        reuse["bytes"] = path.read_bytes()
                        reuse["nine"] = nine(path.lstat())
                        os.close(caller)
                        caller_open = False
                        reuse["after-last-close-SH-witness"] = shared_witness(path, real_flock)
                finally:
                    peer.close()
                    if caller_open:
                        os.close(caller)
                with self.subTest(caller=variant, observation="guard-rejection"):
                    self.assertIs(type(guard["error"]), locks.DeploymentLockError)
                    self.assertIn("deployment lock", str(guard["error"]))
                if variant == "never-locked" or not IS_DARWIN:
                    with self.subTest(caller=variant, observation="no-conversion-SH-witness"):
                        self.assertTrue(witness_acquired)
                else:
                    # Revision clause 2 replaces the Darwin no-conversion check here.
                    with self.subTest(caller=variant, observation="kernel-witnessed-rejection"):
                        self.assertIn("kernel witness", str(guard["error"]))
                if variant == "locked-then-UN":
                    for label in ("same-FD", "dup"):
                        with self.subTest(caller=variant, observation="reuse-" + label + "-rejected-before-EX"):
                            error, attempts = reuse[label]
                            self.assertIs(type(error), locks.DeploymentLockError)
                            self.assertIn("deployment lock", str(error))
                            self.assertEqual([], attempts)
                    with self.subTest(caller=variant, observation="lock-file-still-empty"):
                        self.assertEqual(b"", reuse["bytes"])
                        self.assertEqual(first, reuse["nine"])
                    with self.subTest(caller=variant, observation="residue-released-after-last-close"):
                        self.assertTrue(reuse["after-last-close-SH-witness"])

    def test_rejected_description_stays_rejected_for_a_fork_exec_child(self):
        """Revision clause 6 ("同意 1", 2026-10-24): after the R-alpha rejection the
        same open file description, inherited by a real fork+exec child through
        pass_fds, is rejected by the helper and (Darwin) by deployment_lock()'s
        inherited branch, before any EX call on it."""
        real_flock = fcntl.flock
        with private_lock() as (_root, path):
            caller = open_fd(path)
            real_flock(caller, fcntl.LOCK_EX | fcntl.LOCK_NB)
            real_flock(caller, fcntl.LOCK_UN)
            peer = PeerHolder(path)
            released = []

            def flock(fd, operation):
                if fd == caller and operation == (fcntl.LOCK_EX | fcntl.LOCK_NB) and not released:
                    released.append("before-caller-EX")
                    peer.release()
                return real_flock(fd, operation)

            def fdinfo(fd):
                frame = original_reader(fd)
                if fd == caller and not released:
                    released.append("after-current-FD-read")
                    peer.release()
                return frame
            original_reader = locks._read_current_lock_fdinfo
            error = None
            try:
                with ExitStack() as stack:
                    if IS_DARWIN:
                        stack.enter_context(mock.patch.object(locks.fcntl, "flock", side_effect=flock))
                    else:
                        stack.enter_context(mock.patch.object(locks, "_read_current_lock_fdinfo", side_effect=fdinfo))
                    try:
                        locks.require_current_exclusive_lock_descriptor(path, caller)
                    except Exception as exc:
                        error = exc
                if not released:
                    peer.release()
                child = run_exec_reverify_child(path, caller)
            finally:
                peer.close()
                os.close(caller)
            self.assertIs(type(error), locks.DeploymentLockError)
            self.assertEqual(0, child.returncode, child.stderr[-2000:])
            self.assertEqual(EXEC_REVERIFY_EXPECTED, child.stdout.strip())
            self.assertTrue(shared_witness(path, real_flock))

    def test_posix_record_lock_blocker_is_rejected_before_any_EX_attempt(self):
        """A POSIX record-lock release posts no NOTE_FUNLOCK, so a POSIX blocker
        released in the window could otherwise promote a previously flocked
        caller (residual R-gamma, POSIX form).  Expected: rejection, no EX
        attempt on the caller, and the caller is not an EX owner afterwards.
        On Linux POSIX and flock locks are independent; the /proc current-FD
        check rejects the unlocked caller without any EX attempt as well.
        """
        real_flock = fcntl.flock
        with private_lock() as (_root, path):
            caller = open_fd(path)
            real_flock(caller, fcntl.LOCK_EX | fcntl.LOCK_NB)
            real_flock(caller, fcntl.LOCK_UN)
            peer = PosixPeerHolder(path)
            attempts = []

            def flock(fd, operation):
                if fd == caller and operation & fcntl.LOCK_EX:
                    attempts.append(operation)
                    peer.release()
                return real_flock(fd, operation)
            error = None
            try:
                with mock.patch.object(locks.fcntl, "flock", side_effect=flock):
                    try:
                        locks.require_current_exclusive_lock_descriptor(path, caller)
                    except Exception as exc:
                        error = exc
                if not attempts:
                    peer.release()
                witness_acquired = shared_witness(path, real_flock)
            finally:
                peer.close()
                os.close(caller)
            self.assertIs(type(error), locks.DeploymentLockError)
            self.assertIn("deployment lock", str(error))
            self.assertEqual([], attempts)
            self.assertTrue(witness_acquired)

    def test_witness_registration_failure_fails_closed_before_any_probe(self):
        with private_lock() as (_root, path):
            owner = locks.acquire_lock_path_descriptor(path)
            calls = []
            real_flock = fcntl.flock

            def flock(fd, operation):
                calls.append((fd, operation))
                return real_flock(fd, operation)
            try:
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.object(
                        locks, "_open_darwin_unlock_witness",
                        side_effect=OSError(errno.EMFILE, "PUBLIC injected kqueue exhaustion"),
                    ))
                    stack.enter_context(mock.patch.object(locks.fcntl, "flock", side_effect=flock))
                    if IS_DARWIN:
                        with self.assertRaisesRegex(locks.DeploymentLockError, "deployment lock.*HOLD"):
                            locks.require_current_exclusive_lock_descriptor(path, owner)
                    else:
                        self.assertIsNone(locks.require_current_exclusive_lock_descriptor(path, owner))
                self.assertEqual([], calls)
                self.assertFalse(shared_witness(path, real_flock))
            finally:
                locks.release_lock_descriptor(owner)
            self.assertTrue(shared_witness(path, real_flock))


class DarwinLockDescriptionOffsetPartitionTests(unittest.TestCase):
    """Revision clause 6 refinement: one test per offset interval (with boundaries).

    Darwin: the helper (whose check the LOAD guard shares), the public
    require_clean_lock_description and deployment_lock()'s inherited branch
    reject every non-zero interval before any EX call on the descriptor, each
    naming its interval; resetting the offset to 0 is accepted again, and the
    empty lock file keeps its bytes and nine-tuple.  Linux: the /proc
    current-FD contract is unchanged and the public check is a no-op (the
    taint is a Darwin-only mechanism).
    """

    def _observe(self, offset):
        observed = {}
        with private_lock() as (root, path):
            observed["first"] = nine(path.lstat())
            owner = locks.acquire_lock_path_descriptor(path)
            try:
                os.lseek(owner, offset, os.SEEK_SET)

                def helper(fd):
                    return locks.require_current_exclusive_lock_descriptor(path, fd)
                observed["helper"] = reverify(helper, owner)
                try:
                    observed["public"] = ("returned", locks.require_clean_lock_description(owner))
                except Exception as exc:  # asserted below
                    observed["public"] = ("raised", exc)
                if IS_DARWIN and offset:
                    attempts = []
                    real_flock = fcntl.flock

                    def flock(fd, operation):
                        if fd == owner and operation & fcntl.LOCK_EX:
                            attempts.append(operation)
                        return real_flock(fd, operation)
                    finish = sys.modules[locks.assert_writer_allowed.__module__]
                    with ExitStack() as stack:
                        stack.enter_context(mock.patch.dict(os.environ, {locks.LOCK_FD_ENV: str(owner)}))
                        stack.enter_context(mock.patch.object(
                            finish, "FINISH_STATE_ROOT", root / "PUBLIC-owned-absent-finish-state"))
                        stack.enter_context(mock.patch.object(locks.fcntl, "flock", side_effect=flock))
                        try:
                            with locks.deployment_lock(root):
                                observed["inherited"] = ("entered", None)
                        except Exception as exc:  # asserted below
                            observed["inherited"] = ("raised", exc)
                    observed["inherited_attempts"] = attempts
                os.lseek(owner, 0, os.SEEK_SET)
                observed["control"] = reverify(helper, owner)
                observed["bytes"] = path.read_bytes()
                observed["nine"] = nine(path.lstat())
            finally:
                locks.release_lock_descriptor(owner)
        return observed

    def _assert_rejected_interval(self, offsets, keywords):
        for offset in offsets:
            with self.subTest(offset=offset):
                observed = self._observe(offset)
                error, attempts = observed["helper"]
                kind, public = observed["public"]
                self.assertIsNone(observed["control"][0])
                self.assertEqual(b"", observed["bytes"])
                self.assertEqual(observed["first"], observed["nine"])
                if not IS_DARWIN:
                    self.assertIsNone(error)
                    self.assertEqual(("returned", None), (kind, public))
                    continue
                inherited_kind, inherited = observed["inherited"]
                for label, raised in (("helper", error), ("public", public), ("inherited", inherited)):
                    self.assertIs(type(raised), locks.DeploymentLockError, label)
                    self.assertIn("deployment lock", str(raised), label)
                    for keyword in keywords:
                        self.assertIn(keyword, str(raised), label)
                self.assertEqual(("raised", "raised"), (kind, inherited_kind))
                self.assertEqual([], attempts)
                self.assertEqual([], observed["inherited_attempts"])

    def test_offset_zero_is_clean_and_accepted(self):
        observed = self._observe(0)
        self.assertIsNone(observed["helper"][0])
        self.assertEqual(("returned", None), observed["public"])
        self.assertIsNone(observed["control"][0])
        self.assertEqual(b"", observed["bytes"])
        self.assertEqual(observed["first"], observed["nine"])

    def test_offset_at_or_above_2_44_is_tainted(self):
        self._assert_rejected_interval((1 << 44, (1 << 44) + 1, 1 << 62), ("tainted",))

    def test_offset_in_reserved_phase2_range_is_rejected_as_not_enabled(self):
        self._assert_rejected_interval((1 << 40, (1 << 40) + 4096, (1 << 44) - 1), ("reserved", "not enabled"))

    def test_other_nonzero_offset_violates_the_no_read_write_seek_invariant(self):
        self._assert_rejected_interval((1, 4096, (1 << 40) - 1), ("invariant",))


if __name__ == "__main__":
    unittest.main()
