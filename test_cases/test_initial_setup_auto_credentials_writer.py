"""Independent selected auto.env writer contracts; O draft, NOT RUN.

Actual C2 selection, ProjectPasswordPolicy, native verifier, writer and reader
are the workflow. This does not wire MAIN/cron or prove device authentication.
Only owned syscall boundary faults are MODEL; successful effects are real.
The old None writer/reader contract and all existing test modules stay intact.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, redirect_stdout, redirect_stderr
from functools import wraps
import errno
import hmac
import inspect
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases import test_initial_setup_target_credentials_workflow as basis

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
C2 = ROOT / "ztp/config/nvos/template/90-c2-generate_configs.py"
SAFE = "auto.env credential cannot be published safely; operator HOLD; credentials preserved"
PUBLIC_INITIAL = "PUBLIC-WRITER-INITIAL-17!"
PUBLIC_OOB = "PUBLIC-WRITER-OOB-91!"
PUBLIC_NATIVE_ERROR = "PUBLIC-private-boundary-do-not-project"
KEYS = {"NVOS_INITIAL_PASSWORD", "NVOS_TARGET_PASSWORD",
        "ZTP_ETH_PASSWORD_EXAMPLE_JUMP01"}
FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
          "st_size", "st_mtime_ns", "st_ctime_ns")


def _nine(info):
    return tuple(getattr(info, name) for name in FIELDS)


def _bound(path):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_nlink != 1 or before.st_size > 1048576):
        raise RuntimeError("FIXTURE HOLD: owned regular qualification unavailable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if _nine(os.fstat(fd)) != _nine(before):
            raise RuntimeError("FIXTURE HOLD: owned file identity changed")
        results = []
        for unused in (0, 1):
            os.lseek(fd, 0, os.SEEK_SET)
            chunks, total = [], 0
            while True:
                part = os.read(fd, min(65536, 1048577 - total))
                if not part:
                    break
                total += len(part)
                if total > 1048576:
                    raise RuntimeError("FIXTURE HOLD: owned file cap exceeded")
                chunks.append(part)
            results.append(b"".join(chunks))
            if not (_nine(os.fstat(fd)) == _nine(path.lstat()) == _nine(before)):
                raise RuntimeError("FIXTURE HOLD: owned file changed during read")
        if results[0] != results[1]:
            raise RuntimeError("FIXTURE HOLD: independent EOF bodies differ")
        return _nine(before), results[0]
    finally:
        os.close(fd)


def _outcome(call):
    """Keep actual private errors in RAM; never unittest-render their args."""
    output, errors = io.StringIO(), io.StringIO()
    result = problem = None
    with redirect_stdout(output), redirect_stderr(errors):
        try:
            result = call()
        except BaseException as caught:
            problem = caught
    return result, problem, output.getvalue(), errors.getvalue()


@contextmanager
def _observe(app, path, *, short=False, fault=None, program=None, rebind=None):
    """Transparent own-FD observer. Never fakes native success or metadata.

    Patch only process-local syscall symbols; non-owned descriptors delegate.
    Fixture-only drain is recorded separately and cannot satisfy SUT custody.
    """
    real_open, real_close, real_write, real_read = os.open, os.close, os.write, os.read
    real_fstat, real_fchmod, real_fsync = os.fstat, os.fchmod, os.fsync
    real_mkdir, real_stat, real_lstat, real_seek = os.mkdir, os.stat, os.lstat, os.lseek
    real_project, real_native = app._ib_project_value, app.verify_password_hash
    witness = dict(events=[], helper=0, native=0, mkdir=0, create_attempt=0,
                   file_fd=None, file9=None, parents={}, closed={}, closed_ok=[],
                   fixture_drain=[], qualified_before_secret=[], actual_prefix=b"",
                   fsync=0, writes=0, injected=0, rebind=0, watch=0,
                   file_io=[], actual_read=b"", read_eof=False, replaced=None,
                   parent_flags=[], leaf_flags=None, inheritable=[])
    active = {}
    expected_parent = path.parent
    def owned(fd):
        entry = active.get(fd)
        if entry is None:
            return None
        try:
            info = real_fstat(fd)
        except OSError:
            return None
        if (info.st_dev, info.st_ino) != entry["identity"]:
            return None
        return entry
    def parent_identity():
        try:
            value = real_stat(expected_parent, follow_symlinks=True)
        except FileNotFoundError:
            return None
        return value.st_dev, value.st_ino
    def owned_request(name, dir_fd):
        entry = owned(dir_fd)
        if entry is not None and entry["role"] == "parent":
            return os.fspath(name) == path.name
        try:
            return os.path.abspath(os.fspath(name)) == os.path.abspath(os.fspath(path))
        except TypeError:
            return False
    def opening(name, flags, mode=0o777, *, dir_fd=None):
        ours = bool(flags & os.O_CREAT) and owned_request(name, dir_fd)
        if ours:
            witness["create_attempt"] += 1
            witness["events"].append("create-entry")
        fd = real_open(name, flags, mode, dir_fd=dir_fd)
        info = real_fstat(fd)
        ident = (info.st_dev, info.st_ino)
        if stat.S_ISDIR(info.st_mode) and ident == parent_identity():
            witness["parents"][fd] = ident
            witness["parent_flags"].append(flags)
            witness["inheritable"].append(os.get_inheritable(fd))
            active[fd] = dict(identity=ident, role="parent",
                              counter=("parent", len(witness["parent_flags"]), fd))
            witness["events"].append("parent-open")
        if ours:
            witness["file_fd"], witness["file9"] = fd, _nine(info)
            witness["leaf_flags"] = flags
            witness["inheritable"].append(os.get_inheritable(fd))
            active[fd] = dict(identity=ident, role="file", counter=fd)
            witness["events"].append("file-open")
        return fd
    def mkdir(name, mode=0o777, *, dir_fd=None):
        witness["mkdir"] += 1
        witness["events"].append("mkdir-entry")
        return real_mkdir(name, mode, dir_fd=dir_fd)
    def project(*args, **kw):
        witness["helper"] += 1
        result = real_project(*args, **kw)
        witness["events"].append("authority-return")
        return result
    def native(*args, **kw):
        witness["native"] += 1
        return real_native(*args, **kw)
    def chmod(fd, mode):
        entry = owned(fd)
        result = real_fchmod(fd, mode)
        if entry is not None and entry["role"] == "file":
            witness["events"].append("file-fchmod")
        return result
    def fstat(fd):
        entry = owned(fd)
        result = real_fstat(fd)
        if entry is not None and entry["role"] == "file":
            witness["file_io"].append(("fstat", _nine(result)))
        return result
    def named(operation, name, *args, **kw):
        entry = owned(witness["file_fd"])
        result = operation(name, *args, **kw)
        if (entry is not None and entry["role"] == "file"
                and (result.st_dev, result.st_ino) == entry["identity"]):
            witness["file_io"].append(("named", _nine(result)))
        return result
    def read(fd, size):
        entry = owned(fd)
        result = real_read(fd, size)
        if entry is None or entry["role"] != "file":
            return result
        witness["file_io"].append(("read", _nine(real_fstat(fd))))
        if not witness["read_eof"]:
            witness["actual_read"] += result
        if result == b"" and witness["actual_read"]:
            witness["read_eof"] = True
        if (fault == "same-size-after-read" and witness["injected"] == 0
                and witness["actual_read"] == witness["actual_prefix"]
                and witness["actual_read"]):
            # Boundary qualification is actual os.read of this own writer FD.
            # An alternative legal IO mechanism would need an equivalent
            # fixture, not a weakened product oracle or a fabricated RED.
            before = _nine(real_fstat(fd))
            position = real_seek(fd, 0, os.SEEK_CUR)
            public = b"PUBLIC-EQUAL-SIZE-REPLACEMENT-NO-CREDENTIAL\n"
            replacement = (public * (len(witness["actual_read"]) // len(public) + 1))[:len(witness["actual_read"])]
            real_seek(fd, 0, os.SEEK_SET)
            offset = 0
            while offset < len(replacement):
                step = real_write(fd, replacement[offset:])
                if type(step) is not int or step <= 0:
                    raise RuntimeError("FIXTURE HOLD: actual PUBLIC replacement made no progress")
                offset += step
            real_fsync(fd)
            real_seek(fd, position, os.SEEK_SET)
            after = _nine(real_fstat(fd))
            if before[:7] != after[:7] or before == after:
                raise RuntimeError("FIXTURE HOLD: same-inode equal-size change was not observable")
            witness["injected"] += 1
            witness["replaced"] = replacement
        return result
    def write(fd, value):
        entry = owned(fd)
        if entry is None or entry["role"] != "file":
            return real_write(fd, value)
        witness["writes"] += 1
        info = real_fstat(fd)
        witness["qualified_before_secret"].append(
            stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
            and "file-fchmod" in witness["events"])
        witness["events"].append("write-entry")
        if fault in {"zero-after-prefix", "io-after-prefix"} and witness["writes"] == 2:
            witness["injected"] += 1
            if fault == "zero-after-prefix":
                return 0
            raise OSError(errno.EIO, PUBLIC_NATIVE_ERROR)
        amount = min(len(value), 11 if fault in {"zero-after-prefix", "io-after-prefix"} else 7) if short or fault in {"zero-after-prefix", "io-after-prefix"} else len(value)
        actual = real_write(fd, value[:amount])
        witness["actual_prefix"] += bytes(value[:actual])
        if fault == "program-after-write" and witness["injected"] == 0:
            witness["injected"] += 1
            raise program
        return actual
    def sync(fd):
        entry = owned(fd)
        result = real_fsync(fd)
        if entry is not None and entry["role"] == "file":
            witness["fsync"] += 1
            witness["events"].append("file-fsync-return")
            if fault == "fsync-after-real" and witness["injected"] == 0:
                witness["injected"] += 1
                raise OSError(errno.EIO, PUBLIC_NATIVE_ERROR)
            if rebind is not None and witness["rebind"] == 0:
                witness["rebind"] += 1
                rebind()
        return result
    def close(fd):
        entry = owned(fd)
        if entry is None:
            return real_close(fd)
        counter = entry["counter"]
        witness["closed"][counter] = witness["closed"].get(counter, 0) + 1
        result = real_close(fd)
        if active.get(fd) is entry:
            active.pop(fd)
        witness["closed_ok"].append(fd)
        if entry["role"] == "file":
            witness["events"].append("file-close-return")
            if fault in {"close-after-real", "program-after-write"}:
                witness["injected"] += 1
                raise OSError(errno.EIO, PUBLIC_NATIVE_ERROR)
        return result
    def watch(*args, **kw):
        witness["watch"] += 1
        raise AssertionError("PUBLIC writer must not install watch")
    try:
        with ExitStack() as stack:
            for name, replacement in (("open", opening), ("mkdir", mkdir),
                                      ("write", write), ("fchmod", chmod),
                                      ("fstat", fstat), ("read", read),
                                      ("stat", lambda name, *a, **k: named(real_stat, name, *a, **k)),
                                      ("lstat", lambda name, *a, **k: named(real_lstat, name, *a, **k)),
                                      ("fsync", sync), ("close", close)):
                stack.enter_context(mock.patch.object(app.os, name, new=replacement))
            stack.enter_context(mock.patch.object(app, "_ib_project_value", new=wraps(real_project)(project)))
            stack.enter_context(mock.patch.object(app, "verify_password_hash", new=wraps(real_native)(native)))
            stack.enter_context(mock.patch.object(app, "_install_auto_watch", new=watch))
            yield witness
    finally:
        # No retry of a successfully closed (even error-reporting) slot.
        # Drain only an actual still-open own FD with its recorded dev/ino.
        for fd, entry in tuple(active.items()):
            try:
                info = real_fstat(fd)
            except OSError as error:
                if error.errno == errno.EBADF:
                    raise RuntimeError("NOT_READY: own FD closed outside observed boundary") from None
                raise
            if (info.st_dev, info.st_ino) != entry["identity"]:
                raise RuntimeError("FIXTURE HOLD: owned FD reused before fixture drain")
            real_close(fd)
            witness["fixture_drain"].append(fd)
            if active.get(fd) is entry:
                active.pop(fd)


class AutoCredentialsSelectedWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Source ABI is a prerequisite, not MissingAPI/Ran0 behavior RED.
        probe = load_script("selected_writer_readiness", SOURCE)
        signature = inspect.signature(probe._write_auto_credentials)
        for name in ("_password_policy", "_ib_user"):
            value = signature.parameters.get(name)
            if (value is None or value.kind is not inspect.Parameter.KEYWORD_ONLY
                    or value.default is not None):
                raise RuntimeError("NOT_READY: selected auto credential writer ABI absent")
        cls.kat = basis.required_external_kat()
        for algorithm in ("SHA512", "YESCRYPT"):
            if (probe.verify_password_hash(cls.kat["PASSWORD"], cls.kat[algorithm]) is not True
                    or probe.verify_password_hash("Incorrect123!", cls.kat[algorithm]) is not False):
                raise RuntimeError("FIXTURE HOLD: real native KAT unavailable")
        with mock.patch.object(sys, "argv", ["90-c2-generate_configs.py"]):
            cls.c2 = load_script("selected_writer_actual_c2", C2)

    def _fixture(self, folder, *, alias=False, policy=True):
        root = Path(folder)
        global_path = root / "01-global.yaml"
        global_path.write_text(basis.global_text(self.kat), encoding="utf-8")
        global_path.chmod(0o600)
        app = load_script("selected_writer_" + root.name.replace("-", "_"), SOURCE)
        directory = root / "private-log"
        directory.mkdir(mode=0o700)
        parent = root / "managed-log" if alias else directory
        if alias:
            parent.symlink_to(directory, target_is_directory=True)
        out = parent / "auto.env"
        device = app.Device("EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
                            "203.0.113.1", "02:00:00:00:00:17", "", "")
        leaf = app.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        target = app.Target(device, leaf, "swp7", "eth0")
        selected_policy = (app.ProjectPasswordPolicy(
            global_path, "admin", target_password=self.kat["PASSWORD"], interactive=False)
            if policy else None)
        return dict(root=root, global_path=global_path, app=app, directory=directory,
                    parent=parent, out=out, target=target, policy=selected_policy,
                    initial=PUBLIC_INITIAL, passwords={"example-jump01": PUBLIC_OOB})

    def _call(self, f, **kw):
        return _outcome(lambda: f["app"]._write_auto_credentials(
            f["out"], f["initial"], f["passwords"], [f["target"]], **kw))

    def _selected(self, f):
        return dict(_password_policy=f["policy"], _ib_user="admin")

    def _private(self, f, result):
        self.assertTrue(all(not secret or secret not in result[2] + result[3]
                            for secret in (f["initial"], *f["passwords"].values(), self.kat["PASSWORD"],
                                           self.kat["YESCRYPT"], PUBLIC_NATIVE_ERROR)),
                        "writer projected private boundary data; details suppressed")

    def _safe(self, f, result):
        error = result[1]
        self.assertTrue(type(error) is f["app"].SetupError,
                        "writer did not report exact safe domain failure")
        self.assertTrue(error.args == (SAFE,) and error.__cause__ is None
                        and error.__context__ is None and error.__dict__ == {},
                        "writer error message/chain/attributes violate fixed safe contract")
        self._private(f, result)

    def _closed(self, trace):
        self.assertTrue(not trace["fixture_drain"],
                        "only fixture drain closed a writer-owned descriptor")
        self.assertTrue(all(count == 1 for count in trace["closed"].values()),
                        "writer retried an ambiguous owned close")
        self.assertTrue(trace["watch"] == 0, "writer installed watch")

    def _complete(self, f, trace, result):
        self.assertTrue(result[1] is None and result[0] is None,
                        "selected writer did not complete; private details suppressed")
        self.assertTrue(trace["helper"] >= 1 and trace["native"] > 0,
                        "selected writer bypassed actual policy/native authority")
        self.assertTrue(trace["parents"] and trace["create_attempt"] == 1
                        and trace["events"].index("authority-return") < trace["events"].index("create-entry")
                        and all(trace["events"].index("authority-return") < index
                                for index, event in enumerate(trace["events"]) if event == "mkdir-entry")
                        and trace["events"].index("parent-open") < trace["events"].index("file-open"),
                        "authority or held parent did not precede secret creation")
        parent_flags, leaf_flags = os.O_DIRECTORY | os.O_CLOEXEC, os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        self.assertTrue(all(flags & parent_flags == parent_flags for flags in trace["parent_flags"])
                        and trace["leaf_flags"] & leaf_flags == leaf_flags
                        and not any(trace["inheritable"]),
                        "actual parent/credential descriptor flags are unsafe")
        self.assertTrue(trace["qualified_before_secret"]
                        and all(trace["qualified_before_secret"]) and trace["fsync"] >= 1,
                        "actual secret write lacked fd-mode qualification/fsync")
        reads = [index for index, (kind, unused) in enumerate(trace["file_io"]) if kind == "read"]
        if not reads:
            self.fixed_read_hold()
        first_read, last_read = reads[0], reads[-1]
        before = [value for kind, value in trace["file_io"][:first_read] if kind == "fstat"]
        after = [value for kind, value in trace["file_io"][last_read + 1:] if kind == "fstat"]
        named = [value for kind, value in trace["file_io"][last_read + 1:] if kind == "named"]
        self.assertTrue(before and after and named and before[-1] == after[-1] == named[-1]
                        and trace["read_eof"]
                        and hmac.compare_digest(trace["actual_read"], trace["actual_prefix"]),
                        "actual same-FD complete read lacked full9 before/after/named seal")
        values_result = _outcome(lambda: f["app"].read_auto_credentials(f["out"]))
        self.assertTrue(values_result[1] is None and type(values_result[0]) is dict,
                        "actual reader rejected complete selected credentials")
        values = values_result[0]
        self.assertTrue(set(values) == KEYS
                        and hmac.compare_digest(values["NVOS_INITIAL_PASSWORD"], PUBLIC_INITIAL)
                        and hmac.compare_digest(values["NVOS_TARGET_PASSWORD"], self.kat["PASSWORD"])
                        and hmac.compare_digest(values["ZTP_ETH_PASSWORD_EXAMPLE_JUMP01"],
                                                f["passwords"]["example-jump01"]),
                        "complete credential roles differ from independent inputs")
        info, raw = _bound(f["out"])
        self.assertTrue(stat.S_IMODE(info[2]) == 0o600 and info[5] == 1
                        and len(raw) == len(trace["actual_prefix"])
                        and hmac.compare_digest(raw, trace["actual_prefix"]),
                        "complete actual write/reader/file custody mismatch")
        self._private(f, result)
        self._closed(trace)

    @staticmethod
    def fixed_read_hold():
        raise RuntimeError("NOT_READY: actual own writer-FD os.read boundary unavailable") from None

    def test_legacy_none_real_writer_reader_does_not_acquire_target(self):
        for explicit in (False, True):
            with self.subTest(explicit_none=explicit), tempfile.TemporaryDirectory() as folder:
                f = self._fixture(folder)
                with _observe(f["app"], f["out"]) as trace:
                    result = self._call(f, **({"_password_policy": None, "_ib_user": None}
                                             if explicit else {}))
                self.assertTrue(result[1] is None and trace["helper"] == trace["native"] == 0,
                                "legacy None caller acquired target authority or failed")
                read = _outcome(lambda: f["app"].read_auto_credentials(f["out"]))
                self.assertTrue(read[1] is None and set(read[0]) ==
                                {"NVOS_INITIAL_PASSWORD", "ZTP_ETH_PASSWORD_EXAMPLE_JUMP01"}
                                and hmac.compare_digest(read[0]["NVOS_INITIAL_PASSWORD"], PUBLIC_INITIAL)
                                and hmac.compare_digest(read[0]["ZTP_ETH_PASSWORD_EXAMPLE_JUMP01"], PUBLIC_OOB),
                                "legacy reader/writer contract changed")
                self._closed(trace)

    def test_actual_c2_policy_native_shortwrite_writer_reader_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            f = self._fixture(folder, policy=False)
            with mock.patch.object(self.c2, "_GLOBAL_FILE", str(f["global_path"])):
                selection = _outcome(lambda: self.c2.load_global("ib"))
            self.assertTrue(selection[1] is None and type(selection[0]) is dict,
                            "real C2 IB selection failed; details suppressed")
            selected = selection[0]["system"]
            self.assertTrue(selected["dns"]["server"] == ["203.0.113.53"]
                            and selected["ntp"]["server"] == ["ntp.ubuntu.com", "time.ib.example.test"]
                            and selected["date-time"]["timezone"] == "Asia/Taipei"
                            and hmac.compare_digest(selected["aaa"]["user"]["admin"]["password"],
                                                    self.kat["YESCRYPT"]),
                            "real C2 producer did not select independent IB literals")
            f["policy"] = f["app"].ProjectPasswordPolicy(
                f["global_path"], "admin", target_password=self.kat["PASSWORD"], interactive=False)
            initial_global = _bound(f["global_path"])
            with _observe(f["app"], f["out"], short=True) as trace:
                result = self._call(f, **self._selected(f))
            self.assertTrue(trace["writes"] > 1, "real short-write loop not reached")
            self._complete(f, trace, result)
            self.assertTrue(_bound(f["global_path"]) == initial_global,
                            "workflow changed project authority input")

    def test_owned_managed_parent_alias_is_supported_without_flattening(self):
        with tempfile.TemporaryDirectory() as folder:
            f = self._fixture(folder, alias=True)
            before, raw_link = _nine(f["parent"].lstat()), os.readlink(f["parent"])
            with _observe(f["app"], f["out"]) as trace:
                result = self._call(f, **self._selected(f))
            self._complete(f, trace, result)
            self.assertTrue(_nine(f["parent"].lstat()) == before
                            and os.readlink(f["parent"]) == raw_link,
                            "writer flattened or rewrote managed directory alias")

    def test_selected_complete_payload_cap_and_plus_one_are_independent(self):
        # The existing fixed cap is 65536, not copied from a SUT response.
        prefix_bytes = len(("NVOS_INITIAL_PASSWORD=" + PUBLIC_INITIAL + "\n"
                            "NVOS_TARGET_PASSWORD=" + self.kat["PASSWORD"] + "\n"
                            "ZTP_ETH_PASSWORD_EXAMPLE_JUMP01=\n").encode("utf-8"))
        for extra in (0, 1):
            with self.subTest(over_cap=extra), tempfile.TemporaryDirectory() as folder:
                f = self._fixture(folder)
                f["passwords"] = {"example-jump01": "A" * (65536 - prefix_bytes + extra)}
                with _observe(f["app"], f["out"]) as trace:
                    result = self._call(f, **self._selected(f))
                if extra == 0:
                    self._complete(f, trace, result)
                    self.assertTrue(len(_bound(f["out"])[1]) == 65536,
                                    "complete payload boundary differs from fixed independent cap")
                else:
                    self._safe(f, result)
                    self.assertTrue(trace["create_attempt"] == 0 and not os.path.lexists(f["out"]),
                                    "oversize full payload created credential leaf")
                    self._closed(trace)

    def test_mixed_invalid_exact_context_rejects_before_native_and_creation(self):
        for case in ("mixed-policy", "mixed-user", "foreign-policy", "wrong-account", "user-subclass"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                f = self._fixture(folder)
                class User(str):
                    pass
                kwargs = {
                    "mixed-policy": {"_password_policy": f["policy"], "_ib_user": None},
                    "mixed-user": {"_password_policy": None, "_ib_user": "admin"},
                    "foreign-policy": {"_password_policy": object(), "_ib_user": "admin"},
                    "wrong-account": {"_password_policy": f["policy"], "_ib_user": "other"},
                    "user-subclass": {"_password_policy": f["policy"], "_ib_user": User("admin")},
                }[case]
                with _observe(f["app"], f["out"]) as trace:
                    result = self._call(f, **kwargs)
                self._safe(f, result)
                self.assertTrue(trace["helper"] == trace["native"] == trace["mkdir"]
                                == trace["create_attempt"] == 0 and not os.path.lexists(f["out"]),
                                "invalid private context reached authority/output effects")
                self._closed(trace)

    def test_actual_stale_or_wrong_target_cannot_create_credentials(self):
        for case in ("stale", "wrong-target"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                f = self._fixture(folder)
                if case == "stale":
                    with f["global_path"].open("a", encoding="ascii") as stream:
                        stream.write("# PUBLIC changed after actual policy admission\n")
                else:
                    f["policy"] = f["app"].ProjectPasswordPolicy(
                        f["global_path"], "admin", target_password="Incorrect123!", interactive=False)
                with _observe(f["app"], f["out"]) as trace:
                    result = self._call(f, **self._selected(f))
                self._safe(f, result)
                self.assertTrue(trace["helper"] == 1 and trace["create_attempt"] == trace["mkdir"] == 0
                                and not os.path.lexists(f["out"]),
                                "actual project rejection created credentials")
                self.assertTrue(case != "wrong-target" or trace["native"] > 0,
                                "wrong target was not tested by actual native verifier")
                self._closed(trace)

    def test_actual_unsafe_owned_parent_rejects_before_secret_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            f = self._fixture(folder)
            f["directory"].chmod(0o722)
            before = _nine(f["directory"].lstat())
            try:
                with _observe(f["app"], f["out"]) as trace:
                    result = self._call(f, **self._selected(f))
                self._safe(f, result)
                self.assertTrue(trace["create_attempt"] == 0
                                and not os.path.lexists(f["out"])
                                and _nine(f["directory"].lstat()) == before,
                                "unsafe parent was changed or allowed credential creation")
                self._closed(trace)
            finally:
                # Only this exact owned fixture directory, never a host parent.
                f["directory"].chmod(0o700)

    def test_selected_payload_invalid_controls_or_key_collision_never_publish(self):
        for case in ("initial-control", "oob-separator", "env-key-collision"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                f = self._fixture(folder)
                targets = [f["target"]]
                if case == "initial-control":
                    f["initial"] = PUBLIC_INITIAL + "\n"
                elif case == "oob-separator":
                    f["passwords"] = {"example-jump01": PUBLIC_OOB + "\u2028"}
                else:
                    app = f["app"]
                    other = app.Device("EXAMPLE_JUMP01", "eth_jump", "192.0.2.11", "", "", "", "", "")
                    targets.append(app.Target(f["target"].ib, other, "swp8", "eth0"))
                    f["passwords"]["example_jump01"] = "PUBLIC-WRITER-SECOND-OOB!"
                with _observe(f["app"], f["out"]) as trace:
                    result = _outcome(lambda: f["app"]._write_auto_credentials(
                        f["out"], f["initial"], f["passwords"], targets, **self._selected(f)))
                self._safe(f, result)
                self.assertTrue(trace["create_attempt"] == 0 and not os.path.lexists(f["out"]),
                                "invalid selected payload created credential leaf")
                self._closed(trace)

    def test_exclusive_collision_preserves_existing_file_and_symlink(self):
        for case in ("regular", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                f = self._fixture(folder)
                old = f["directory"] / "preserved-control"
                old.write_bytes(b"PUBLIC existing credential/canary\n")
                old.chmod(0o600)
                if case == "regular":
                    f["out"].write_bytes(b"PUBLIC existing destination\n")
                    f["out"].chmod(0o600)
                    before = _bound(f["out"])
                else:
                    f["out"].symlink_to(old)
                    before = _nine(f["out"].lstat()), os.readlink(f["out"])
                old_before = _bound(old)
                with _observe(f["app"], f["out"]) as trace:
                    result = self._call(f, **self._selected(f))
                self._safe(f, result)
                after = (_bound(f["out"]) if case == "regular" else
                         (_nine(f["out"].lstat()), os.readlink(f["out"])))
                self.assertTrue(after == before and _bound(old) == old_before
                                and trace["file_fd"] is None and trace["create_attempt"] == 1,
                                "O_EXCL failure removed or changed an existing object")
                self._closed(trace)

    def test_partial_real_write_then_zero_or_eio_is_hold_not_success(self):
        for fault in ("zero-after-prefix", "io-after-prefix"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as folder:
                f = self._fixture(folder)
                with _observe(f["app"], f["out"], fault=fault) as trace:
                    result = self._call(f, **self._selected(f))
                self._safe(f, result)
                self.assertTrue(trace["injected"] == 1 and trace["writes"] == 2
                                and len(trace["actual_prefix"]) == 11,
                                "fault was not reached after actual prefix write")
                nine, raw = _bound(f["out"])
                self.assertTrue(raw == trace["actual_prefix"] and len(raw) == 11
                                and nine[:2] == trace["file9"][:2]
                                and stat.S_IMODE(nine[2]) == 0o600
                                and trace["qualified_before_secret"]
                                and all(trace["qualified_before_secret"]),
                                "failed writer did not preserve actual private prefix")
                # A partial file MAY be accepted by the reader. This case makes
                # no reader-rejection inference; actual writer error is required.
                self._closed(trace)

    def test_real_fsync_or_close_then_error_never_acknowledges_publication(self):
        for fault in ("fsync-after-real", "close-after-real"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as folder:
                f = self._fixture(folder)
                with _observe(f["app"], f["out"], fault=fault) as trace:
                    result = self._call(f, **self._selected(f))
                self._safe(f, result)
                self.assertTrue(trace["injected"] == 1 and trace["fsync"] >= 1
                                and trace["closed"].get(trace["file_fd"]) == 1,
                                "actual effect/fault/single close witness missing")
                nine, raw = _bound(f["out"])
                self.assertTrue(stat.S_IMODE(nine[2]) == 0o600
                                and nine[:2] == trace["file9"][:2]
                                and hmac.compare_digest(raw, trace["actual_prefix"]),
                                "failed publication did not preserve private bytes")
                self._closed(trace)

    def test_program_primary_identity_survives_actual_close_then_known_error(self):
        with tempfile.TemporaryDirectory() as folder:
            f = self._fixture(folder)
            primary = RuntimeError("PUBLIC-program-primary-retain-object")
            with _observe(f["app"], f["out"], fault="program-after-write", program=primary) as trace:
                result = self._call(f, **self._selected(f))
            self.assertTrue(result[1] is primary and primary.args ==
                            ("PUBLIC-program-primary-retain-object",)
                            and primary.__cause__ is None and primary.__context__ is None,
                            "cleanup replaced or changed program-error primary")
            self.assertTrue(trace["injected"] == 2
                            and trace["closed"].get(trace["file_fd"]) == 1
                            and _bound(f["out"])[0][:2] == trace["file9"][:2]
                            and len(_bound(f["out"])[1]) > 0,
                            "actual write and close-error paths were not both reached")
            self._closed(trace)

    def test_actual_parent_rebind_after_real_file_fsync_is_hold_no_unlink(self):
        with tempfile.TemporaryDirectory() as folder:
            f = self._fixture(folder)
            replacement = f["root"] / "replacement"
            replacement.mkdir(mode=0o700)
            control = replacement / "PUBLIC-control"
            control.write_bytes(b"PUBLIC replacement parent control\n")
            control.chmod(0o600)
            before = _bound(control)
            retired = f["root"] / "retired-original-log"
            def rebind():
                f["directory"].rename(retired)
                replacement.rename(f["directory"])
            with _observe(f["app"], f["out"], rebind=rebind) as trace:
                result = self._call(f, **self._selected(f))
            self._safe(f, result)
            self.assertTrue(trace["rebind"] == 1 and trace["fsync"] >= 1
                            and not os.path.lexists(f["out"])
                            and _bound(f["directory"] / "PUBLIC-control") == before,
                            "parent rebound fixture was not reached or foreign parent changed")
            nine, raw = _bound(retired / "auto.env")
            self.assertTrue(stat.S_IMODE(nine[2]) == 0o600
                            and nine[:2] == trace["file9"][:2]
                            and hmac.compare_digest(raw, trace["actual_prefix"]),
                            "rebound-parent failure deleted original private publication")
            self._closed(trace)

    def test_actual_correct_read_then_same_inode_equal_size_replace_is_hold(self):
        with tempfile.TemporaryDirectory() as folder:
            f = self._fixture(folder)
            with _observe(f["app"], f["out"], fault="same-size-after-read") as trace:
                result = self._call(f, **self._selected(f))
            if trace["injected"] != 1 or trace["replaced"] is None:
                self.fixed_read_hold()
            self._safe(f, result)
            nine, raw = _bound(f["out"])
            self.assertTrue(hmac.compare_digest(trace["actual_read"], trace["actual_prefix"])
                            and raw == trace["replaced"]
                            and nine[:2] == trace["file9"][:2]
                            and len(raw) == len(trace["actual_prefix"])
                            and stat.S_IMODE(nine[2]) == 0o600,
                            "real read/replacement identity or preserved private file unavailable")
            self._closed(trace)

    def test_fixed_known_error_has_no_context_inside_external_except(self):
        with tempfile.TemporaryDirectory() as folder:
            f = self._fixture(folder)
            primary = ValueError("PUBLIC-unrelated-exception-context")
            with _observe(f["app"], f["out"], fault="fsync-after-real") as trace:
                try:
                    raise primary
                except ValueError:
                    result = self._call(f, **self._selected(f))
            self.assertTrue(trace["injected"] == 1 and trace["fsync"] == 1,
                            "known fault inside existing exception context was not reached")
            self._safe(f, result)
            self.assertTrue(primary.args == ("PUBLIC-unrelated-exception-context",)
                            and primary.__cause__ is None and primary.__context__ is None,
                            "writer changed the unrelated handled exception")
            self._closed(trace)


if __name__ == "__main__":
    unittest.main()
