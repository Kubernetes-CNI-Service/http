"""I-029 (v3.1.2 WP-9, M6): the collection lock ``cron.lock`` belongs to the operator.

Expectations come from the requirement texts, never from the implementation:
- 问题文档 I-029 期望的修复: after the Switch collection worker opens ``cron.lock`` it sets the lock's owner to the
  operator (the worker is root, so the new owner does not stop it opening the lock later); once K4 runs the worker
  as the tree owner the step is no longer needed.
- 问题文档 I-029 测试: after the worker creates the lock, or opens an existing root lock, the owner is the
  operator; a cron.sh then run as the operator takes the lock.
- design `设计/I-006与R-005实现计划.md` §4.2 and v3.1.2 guide O7 ①: the operator is the owner of the project
  directory; guide O9: the group is the operator's passwd primary group (pw_gid).
- v3.1.2 guide WP-9: only the owner changes (fchown, never chmod); with no project, or a worker that is not root,
  nothing happens.
- v3.1.2 guide O14 and 问题文档 I-006 :350 (what the operator's tools write in the code tree is 「由 load 预先建好
  并交给操作员」): before the worker starts, load pre-creates ``{ethernet,infiniband,nvlink}/monitor/cron.lock``
  with O_CREAT|O_NOFOLLOW and mode 0600 (an existing one is only opened) and hands them to the operator, on a
  Linux management server where root acts for a non-root operator.
- Docker is frozen (开发计划 :112; owner 11-02: Docker behaviour and tests must not regress; http dev 2026-11-09 for
  every M6 package): in a container (the Supervisor backend; compose.yaml and deploy.sh set
  HTTP_ZTP_RUNTIME_BACKEND=supervisor for every process in it) the worker and load keep v3.1.1 exactly: no
  operator rule is consulted, nothing is refused, nothing is chowned or pre-created, even when the project
  owner's uid has no passwd entry in the container.

No real uid switch happens (guide 2.2 item 6).  Root is played by giving the worker module a view of ``os`` whose
``geteuid`` is 0, or by feeding ``operator_identity.resolve_operator`` euid 0; ``os.geteuid`` itself is never
mocked.  A chown to another user is recorded, not made.  The handoff test runs the real load pre-creation, the
real worker lock code and the real cron.sh lock section in one private tree, the current user standing in for the
operator; the cross-uid run belongs to the REAL_ENVIRONMENT card of WP-13.
"""

from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_load_collection_worker_contract as M3
from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))
import operator_identity  # noqa: E402  (after the tools path, as the production callers do)

WORKER = load_script(
    "collection_lock_owner_worker", ROOT / "monitor/switch-collection-worker.py",
)
LOAD = M3.LOAD
AREAS = ("ethernet", "infiniband", "nvlink")
PINNED_PATH = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
SUDO_NAMES = ("SUDO_USER", "SUDO_UID", "SUDO_GID", operator_identity.ROOT_PARENT_MARKER)

# flock(1) is absent on macOS.  The stand-in locks the inherited descriptor the way util-linux does (-n, -w
# SECONDS) and records which file it locked, so the test can tell cron.sh really took the operator's lock.
FLOCK = r'''#!{python}
import fcntl, json, os, sys, time
args, blocking, wait = sys.argv[1:], True, None
while len(args) > 1:
    option = args.pop(0)
    if option == "-n":
        blocking = False
    elif option == "-w":
        wait = float(args.pop(0))
descriptor = int(args[0])
deadline = None if wait is None else time.monotonic() + wait
while True:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        break
    except BlockingIOError:
        if not blocking or (deadline is not None and time.monotonic() >= deadline):
            sys.exit(1)
        time.sleep(0.05)
metadata = os.fstat(descriptor)
with open(os.environ["FIXTURE_FLOCK_RECORD"], "w") as stream:
    json.dump({"dev": metadata.st_dev, "ino": metadata.st_ino}, stream)
'''


def cycle_identity(scope: str) -> dict:
    body = {
        "project_key": hashlib.sha256(b"/fixture-project").hexdigest(),
        "run_token": "12345678123442348123456789abcdef",
        "scope": scope,
        "sequence": 7,
        "source": "switch_collection",
    }
    body["cycle_id"] = hashlib.sha256(json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return body


def identity_of(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino


class _WorkerOs:
    """The worker module's view of ``os``: the real module except ``geteuid`` (0 plays root) and ``fchown``.

    ``fchown`` records (file identity, uid, gid); it also makes the call when ``really_chown`` is set (only
    ever to the current user, which needs no privilege).
    """

    def __init__(self, *, euid: int | None, chowns: list, really_chown: bool = False) -> None:
        self._euid = euid
        self._chowns = chowns
        self._really_chown = really_chown

    def __getattr__(self, name):
        return getattr(os, name)

    def geteuid(self) -> int:
        return os.geteuid() if self._euid is None else self._euid

    def fchown(self, descriptor: int, uid: int, gid: int) -> None:
        metadata = os.fstat(descriptor)
        self._chowns.append(((metadata.st_dev, metadata.st_ino), uid, gid))
        if self._really_chown:
            os.fchown(descriptor, uid, gid)


class _LockTree:
    """A private code tree: three monitor directories, a project and (optionally) the activate-project pointer."""

    def make_tree(self, *, pointer: bool = True) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()   # macOS /var alias
        (root / "DAY0-Prepare/site").mkdir(parents=True)
        if pointer:
            (root / "DAY0-Prepare/activate-project").symlink_to("site")
        for area in AREAS:
            (root / area / "monitor").mkdir(parents=True)
        (root / "monitor/status").mkdir(parents=True)
        # the worker takes the lock only for a collector that exists and has its inventory
        (root / "ethernet/monitor/cron.sh").write_text("#!/bin/bash\nexit 99\n", encoding="utf-8")
        (root / "ethernet/monitor/eth.csv").write_text("hostname,type,eth0_ip\n", encoding="utf-8")
        return root

    def project_operator(self, root: Path) -> tuple[int, int]:
        # design §4.2: the operator is the project directory's owner; O9: its group is pw_gid.
        entry = pwd.getpwuid((root / "DAY0-Prepare/site").stat().st_uid)
        return entry.pw_uid, entry.pw_gid

    def start_worker(self, root: Path, project: Path | None, *, events: list,
                     dry_run: bool = False, record_chown: bool = False, backend=None) -> str:
        """The real ``start_switch_collection_worker`` (native, no page endpoint) with its launch recorded."""

        def chown(descriptor, uid, gid):
            metadata = os.fstat(descriptor)
            events.append(("fchown", (metadata.st_dev, metadata.st_ino), uid, gid))

        def popen(command, **_kwargs):
            events.append(("popen", Path(command[2]).name))
            return M3._FakeProcess()

        output = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "HTTP_ROOT", root))
            stack.enter_context(mock.patch.object(LOAD, "sudo_command", side_effect=lambda *c: list(c)))
            stack.enter_context(mock.patch.object(
                LOAD, "run", side_effect=lambda command, **_k: events.append(("run", command[0]))))
            stack.enter_context(mock.patch.object(LOAD, "_popen_subprocess", side_effect=popen))
            if record_chown:
                stack.enter_context(mock.patch.object(LOAD.os, "fchown", side_effect=chown))
            stack.enter_context(redirect_stdout(output))
            LOAD.start_switch_collection_worker(
                "prod", dry_run=dry_run,
                runtime_backend=backend or LOAD.SystemdRuntimeBackend(
                    command_runner=mock.Mock(side_effect=AssertionError("systemctl")),
                ),
                control_endpoint=False, operator_project=project,
            )
        return output.getvalue()

    def as_root_for(self, operator: tuple[int, int] | None = None, *, missing_owner: bool = False):
        """resolve_operator fed euid 0 and no sudo, wherever it is called with only the project.

        ``operator`` (uid, gid) replaces the project's owner; ``missing_owner`` makes the owner's uid absent from
        passwd, as a host uid inside a container usually is.
        """
        real = operator_identity.resolve_operator

        def resolve(directory, **given):
            given.pop("euid", None)
            if missing_owner:
                def getpwuid(wanted):
                    raise KeyError(f"getpwuid(): uid not found: {wanted}")
                return real(directory, euid=0, environ={}, getpwuid=getpwuid)
            if operator is None:
                return real(directory, euid=0, environ={})
            uid, gid = operator
            entry = SimpleNamespace(pw_name="fixture-op", pw_uid=uid, pw_gid=gid, pw_dir="/home/fixture-op")
            return real(directory, euid=0, environ={}, stat=lambda _path: SimpleNamespace(st_uid=uid),
                        getpwuid=lambda wanted: entry if wanted == uid else pwd.getpwuid(wanted))

        return mock.patch.object(operator_identity, "resolve_operator", side_effect=resolve)

    def run_worker_slot(self, root: Path, view: _WorkerOs, environment: dict | None = None) -> dict:
        """The real ``run_collection_slots`` for one AIR slot, stopped right after it holds the lock.

        Bindings that are not the three artifact paths end the slot as ``worker_error`` after the lock is taken
        and before any collector starts; the slot's ``finally`` unlocks and closes the lock as in production.
        """
        scripts = {area: root / area / "monitor/cron.sh" for area in AREAS}
        launch = mock.Mock(side_effect=AssertionError("no collector may start in this fixture"))
        with mock.patch.object(WORKER, "HTTP_ROOT", root), \
                mock.patch.object(WORKER, "SCRIPTS", scripts), \
                mock.patch.object(WORKER, "os", view), \
                mock.patch.object(WORKER, "run_interruptible", launch), \
                mock.patch.dict(os.environ):
            for name in (*SUDO_NAMES, "HTTP_ZTP_RUNTIME_BACKEND"):
                os.environ.pop(name, None)
            os.environ.update(environment or {})
            result = WORKER.run_collection_slots(
                cycle_identity("air"), artifact_bindings={"ethernet/air": {}},
                timeout=10, lock_wait=0,
            )
        launch.assert_not_called()
        self.assertEqual(["worker_error"], [item["outcome"] for item in result["outcomes"]])
        return result


class CollectionLockOwnerTests(_LockTree, unittest.TestCase):
    """The worker hands ``cron.lock`` to the operator; the operator's cron.sh takes it afterwards."""

    def test_root_worker_hands_new_lock_to_operator(self) -> None:
        # 问题文档 I-029 期望的修复 / 测试: the lock a root worker creates belongs to the operator.
        root = self.make_tree()
        chowns: list = []
        self.run_worker_slot(root, _WorkerOs(euid=0, chowns=chowns))
        lock = root / "ethernet/monitor/cron.lock"
        self.assertTrue(stat.S_ISREG(lock.lstat().st_mode))
        self.assertEqual([(identity_of(lock), *self.project_operator(root))], chowns)

    def test_root_worker_hands_existing_root_lock_to_operator(self) -> None:
        # 问题文档 I-029 测试「打开已有的 root 锁之后，属主是操作员」; guide WP-9: only fchown, never chmod.
        root = self.make_tree()
        lock = root / "ethernet/monitor/cron.lock"
        lock.write_bytes(b"")   # what a root `exec 200>` left behind: umask mode, not 0600
        lock.chmod(0o644)
        before = lock.lstat()
        chowns: list = []
        self.run_worker_slot(root, _WorkerOs(euid=0, chowns=chowns))
        after = lock.lstat()
        self.assertEqual([(identity_of(lock), *self.project_operator(root))], chowns)
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual(0o644, stat.S_IMODE(after.st_mode))

    def test_non_root_worker_or_no_project_does_not_chown(self) -> None:
        # 问题文档 I-029「K4 让 worker 以树属主身份运行之后，这一步自然不再需要」; guide WP-9: no project, or
        # euid not 0: nothing.  The lock itself is still opened (created) as before.
        for case, euid, pointer in (("worker not root", None, True), ("no project", 0, False)):
            with self.subTest(case):
                root = self.make_tree(pointer=pointer)
                chowns: list = []
                with mock.patch.object(operator_identity, "resolve_operator",
                                       wraps=operator_identity.resolve_operator) as resolve:
                    self.run_worker_slot(root, _WorkerOs(euid=euid, chowns=chowns))
                self.assertEqual([], chowns)
                self.assertTrue(stat.S_ISREG((root / "ethernet/monitor/cron.lock").lstat().st_mode))
                if euid is None:
                    resolve.assert_not_called()   # a non-root worker never consults the project

    def test_container_worker_keeps_v311_lock_even_when_owner_uid_is_unknown(self) -> None:
        # Docker frozen (开发计划 :112; owner 11-02; http dev 2026-11-09): a root worker in a container behaves as
        # in v3.1.1 - the lock is opened (created 0600) and used, no operator rule is consulted, nothing is
        # chowned and nothing is refused - whether or not the host owner's uid exists in the container's passwd.
        # An unrecognised backend value is treated the same way (pending point, default: keep v3.1.1).
        for case, backend, missing_owner in (("supervisor, owner uid unknown", "supervisor", True),
                                             ("supervisor, owner uid known", "supervisor", False),
                                             ("unrecognised backend", "podman", False)):
            with self.subTest(case):
                root = self.make_tree()
                chowns: list = []
                with self.as_root_for(missing_owner=missing_owner) as resolve:
                    self.run_worker_slot(root, _WorkerOs(euid=0, chowns=chowns),
                                         {"HTTP_ZTP_RUNTIME_BACKEND": backend})
                resolve.assert_not_called()
                self.assertEqual([], chowns)
                metadata = (root / "ethernet/monitor/cron.lock").lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(0o600, stat.S_IMODE(metadata.st_mode))

    def test_operator_cron_sh_takes_lock_after_worker_released_it(self) -> None:
        # 问题文档 I-029 测试「之后以操作员身份运行的 cron.sh 能拿到锁」, through the three real writers of the
        # lock: load pre-creates it for the operator (O14), the root worker opens it, hands it over, uses and
        # releases it (I-029), then the operator's own cron.sh opens and locks the same file.
        root = self.make_tree()
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        self.assertEqual(1, source.count(PINNED_PATH))
        fixture_bin = root / "fixture-bin"
        fixture_bin.mkdir()
        (fixture_bin / "flock").write_text(FLOCK.replace("{python}", sys.executable), encoding="utf-8")
        (fixture_bin / "flock").chmod(0o755)
        (root / "ethernet/monitor/cron.sh").write_text(
            source.replace(PINNED_PATH, PINNED_PATH.replace("PATH=", f"PATH={fixture_bin}:")),
            encoding="utf-8",
        )
        # A tree with a pointer carries the operator rule modules cron.sh's identity step reads (WP-11).
        (root / "tools").mkdir()
        for name in ("operator_identity.py", "project_contract.py"):
            shutil.copy2(ROOT / "tools" / name, root / "tools" / name)
        with self.as_root_for():
            self.start_worker(root, root / "DAY0-Prepare/site", events=[])
        chowns: list = []
        self.run_worker_slot(root, _WorkerOs(euid=0, chowns=chowns, really_chown=True))
        lock = root / "ethernet/monitor/cron.lock"
        metadata = lock.lstat()
        self.assertEqual(self.project_operator(root), (metadata.st_uid, metadata.st_gid))
        self.assertEqual(0o600, stat.S_IMODE(metadata.st_mode))
        self.assertEqual([(identity_of(lock), *self.project_operator(root))], chowns)

        private_tmp = root / "fixture-tmp"
        private_tmp.mkdir(mode=0o700)
        record = root / "fixture-flock.json"

        def run_cron() -> subprocess.CompletedProcess:
            return subprocess.run(
                ["/bin/bash", str(root / "ethernet/monitor/cron.sh"), "--air"],
                cwd=root, capture_output=True, text=True, timeout=60, check=False,
                env={"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", str(root)),
                     "LANG": "en_US.UTF-8", "TMPDIR": str(private_tmp),
                     "FIXTURE_FLOCK_RECORD": str(record)},
            )

        # Control: while the worker still holds it, cron.sh reports the previous round (the stand-in locks).
        with open(lock, "rb") as holder:
            fcntl.flock(holder, fcntl.LOCK_EX)
            busy = run_cron()
        self.assertEqual(1, busy.returncode, busy.stdout + busy.stderr)
        self.assertIn("上一轮采集仍在运行", busy.stderr)
        self.assertFalse(record.exists())

        result = run_cron()
        self.assertNotIn("上一轮采集仍在运行", result.stderr)
        # The fixture project has no mgmt-server.pub: cron.sh stops at the step right after the lock.
        self.assertIn("mgmt-server.pub is missing or empty", result.stderr)
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        locked = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(identity_of(lock), (locked["dev"], locked["ino"]))


class LoadCollectionLockPrecreateTests(M3.SystemdLoadMainFixture, _LockTree, unittest.TestCase):
    """load pre-creates the three locks for the operator before the worker starts (O14)."""

    def test_load_precreates_three_cron_locks_owned_by_operator(self) -> None:
        # O14; 问题文档 I-006 :350; guide WP-9: O_CREAT|O_NOFOLLOW, 0600, an existing lock only opened, all
        # handed to the operator before the worker starts.  The operator is a third party (uid + 1).
        root = self.make_tree()
        existing = root / "infiniband/monitor/cron.lock"
        existing.write_bytes(b"left by an earlier root run\n")
        existing.chmod(0o644)
        before = existing.lstat()
        third = (os.getuid() + 1, os.getgid() + 1)
        events: list = []
        with self.as_root_for(third):
            self.start_worker(root, root / "DAY0-Prepare/site", events=events, record_chown=True)
        chowns = [event for event in events if event[0] == "fchown"]
        self.assertEqual(
            sorted(("fchown", identity_of(root / area / "monitor/cron.lock"), *third) for area in AREAS),
            sorted(chowns),
        )
        names = [event[0] for event in events]
        self.assertEqual(["switch-collection-worker.py"], [e[1] for e in events if e[0] == "popen"])
        self.assertLess(max(i for i, name in enumerate(names) if name == "fchown"), names.index("popen"))
        for area in ("ethernet", "nvlink"):
            metadata = (root / area / "monitor/cron.lock").lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(0o600, stat.S_IMODE(metadata.st_mode))
        after = existing.lstat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual(0o644, stat.S_IMODE(after.st_mode))
        self.assertEqual(b"left by an earlier root run\n", existing.read_bytes())

    def test_supervisor_start_keeps_v311_even_when_owner_uid_is_unknown(self) -> None:
        # Docker frozen (开发计划 :112; owner 11-02; http dev 2026-11-09): under the Supervisor backend the start
        # is v3.1.1's - no operator rule, no refusal, no lock created or chowned - even when the project owner's
        # uid has no passwd entry in the container.
        for missing_owner in (True, False):
            with self.subTest(missing_owner=missing_owner):
                root = self.make_tree()
                events: list = []
                supervisor_start = mock.Mock(return_value=True)
                with self.as_root_for(missing_owner=missing_owner) as resolve, \
                        mock.patch.object(LOAD, "_start_supervisor_program", supervisor_start):
                    self.start_worker(root, root / "DAY0-Prepare/site", events=events,
                                      record_chown=True, backend=SimpleNamespace(name="supervisor"))
                resolve.assert_not_called()
                supervisor_start.assert_called_once()
                self.assertNotIn("fchown", [event[0] for event in events])
                self.assertNotIn("popen", [event[0] for event in events])
                for area in AREAS:
                    self.assertFalse(os.path.lexists(root / area / "monitor/cron.lock"), area)

    def test_symlinked_cron_lock_is_refused_without_following_it(self) -> None:
        # guide WP-9: O_NOFOLLOW.  A link in place of a lock stops the start; nothing is created at its target.
        root = self.make_tree()
        target = root / "outside-target"
        (root / "ethernet/monitor/cron.lock").symlink_to(target)
        events: list = []
        with self.as_root_for((os.getuid() + 1, os.getgid() + 1)), self.assertRaises(OSError):
            self.start_worker(root, root / "DAY0-Prepare/site", events=events, record_chown=True)
        self.assertFalse(os.path.lexists(target))
        self.assertNotIn("popen", [event[0] for event in events])
        self.assertNotIn("fchown", [event[0] for event in events])

    def test_operator_running_load_or_dry_run_or_no_project_creates_no_lock(self) -> None:
        # Regression: the operator running load itself (resolve_operator on the real, non-root process), a dry
        # run, and a caller that names no project keep today's start: no lock is created or handed over.
        for case, project_given, dry_run in (("operator runs load", True, False),
                                             ("dry run", True, True),
                                             ("no project", False, False)):
            with self.subTest(case):
                root = self.make_tree()
                events: list = []
                context = self.as_root_for() if case != "operator runs load" else ExitStack()
                with context:
                    self.start_worker(root, root / "DAY0-Prepare/site" if project_given else None,
                                      events=events, dry_run=dry_run, record_chown=True)
                self.assertNotIn("fchown", [event[0] for event in events])
                for area in AREAS:
                    self.assertFalse(os.path.lexists(root / area / "monitor/cron.lock"), area)
                self.assertEqual(not dry_run, ("popen", "switch-collection-worker.py") in events)

    def test_main_hands_locks_over_only_where_root_acts_for_a_non_root_operator(self) -> None:
        # O14 + guide WP-9 (Linux management server, root, operator not root) through the real main(): native
        # systemd with root acting for the operator pre-creates; the operator running load does not; the
        # Supervisor backend (Docker frozen) keeps v3.1.1 even when the owner's uid is unknown in the container.
        cases = (
            ("systemd, root for the operator", "systemd", True),
            ("systemd, the operator runs load", "systemd", False),
            ("supervisor, root, owner uid unknown in the container", "supervisor", True),
        )
        for case, backend, as_root in cases:
            with self.subTest(case):
                root = self.make_tree(pointer=False)
                chowns: list = []
                patches = {"HTTP_ROOT": root}
                supervisor = backend == "supervisor"
                if supervisor:
                    patches["_start_supervisor_program"] = mock.Mock(return_value=True)
                resolve = None
                with ExitStack() as stack:
                    if as_root:
                        resolve = stack.enter_context(self.as_root_for(missing_owner=supervisor))
                    stack.enter_context(mock.patch.object(
                        LOAD.os, "fchown",
                        side_effect=lambda descriptor, uid, gid: chowns.append(
                            (os.fstat(descriptor).st_ino, uid, gid)),
                    ))
                    result = self.run_load_main(
                        self.main_args(deployment_scope="prod", start_ztp_monitor=supervisor),
                        self.main_inputs(http=supervisor, dhcp=supervisor),
                        backend=backend, patches=patches,
                    )
                self.assertEqual(0, result.rc, result.stderr)
                expected = backend == "systemd" and as_root
                locks = [root / area / "monitor/cron.lock" for area in AREAS]
                if expected:
                    owner = pwd.getpwuid(result.project.stat().st_uid)
                    self.assertEqual(
                        sorted((lock.lstat().st_ino, owner.pw_uid, owner.pw_gid) for lock in locks),
                        sorted(chowns),
                    )
                else:
                    self.assertEqual([], chowns)
                    self.assertEqual([], [lock for lock in locks if os.path.lexists(lock)])
                if supervisor:
                    resolve.assert_not_called()   # Docker frozen: v3.1.1's start, no operator rule
                    patches["_start_supervisor_program"].assert_called_once()
                else:
                    self.assertEqual(["prod"], self.worker_scopes(result))


if __name__ == "__main__":
    unittest.main()
