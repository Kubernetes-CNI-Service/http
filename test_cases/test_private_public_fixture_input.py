"""PUBLIC toy and physical-locator controls; original five values remain private.

Proposed canonical destination: test_cases/test_private_public_fixture_input.py.
Ordinary canonical import is intentional; no SUBJECT/sys.modules/__file__ seam.
Physical canonical sibling-source identity replaces the old external MODEL binding.
MODEL controls replace only the reader module's os global with ToyOS;
path-only controls use a disposable PUBLIC file under an owned temp parent.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import private_public_fixture_input as READER

SOURCE_PIN = None
ROOT_BINDING = None
EXPECTED_READER_BYTES = 16478  # frozen reader source, never subject-generated
EXPECTED_READER_SHA256 = "526cf837ed8b294a2ce8cce113616a91a80207a2b38d209df2abed148fb09d48"
TOY_EXPECTED_BYTES = 246
TOY_EXPECTED_SHA256 = "e7dc82d27f0987034b05af8de7bfdc00df9622f61c129aaa154b1f27011fcac9"
KEYS = (
    "handoff_transport_password", "pending_diff_password",
    "collector_prefix_secret", "cache_admission_key_0", "cache_admission_key_1",
)
TOY_VALUES = dict(zip(KEYS, ("toy-one", "toy-two", "toy-three", "toy-four", "toy-five")))
TOY_RAW = json.dumps({
    "schema": "http-test.private-public-fixture-input/v1", "values": TOY_VALUES,
}, sort_keys=True, separators=(",", ":")).encode()
_SOURCE_QUALIFICATION = {"unknown": False, "secondary": []}


def info(mode, *, ino, size, uid=501, gid=20, links=1, mtime=31, ctime=32):
    return SimpleNamespace(
        st_dev=7, st_ino=ino, st_mode=mode, st_uid=uid, st_gid=gid,
        st_nlink=links, st_size=size, st_mtime_ns=mtime, st_ctime_ns=ctime,
    )


def native9(value):
    return [str(getattr(value, field)) for field in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns",
    )]


class ToyOS:
    path = os.path
    O_RDONLY, O_DIRECTORY = os.O_RDONLY, os.O_DIRECTORY
    O_NOFOLLOW, O_CLOEXEC = os.O_NOFOLLOW, os.O_CLOEXEC
    O_NONBLOCK = os.O_NONBLOCK
    SEEK_SET = os.SEEK_SET

    def __init__(self, raw=TOY_RAW):
        self.raw = raw
        self.environ = {}
        self.root = info(stat.S_IFDIR | 0o755, ino=1, size=80, links=2)
        self.ancestor = info(stat.S_IFDIR | 0o755, ino=11, size=80, links=2)
        self.swap_fifo = False
        self.ancestor_symlink = False
        self.parent = info(stat.S_IFDIR | 0o700, ino=12, size=80, links=2)
        self.file = info(stat.S_IFREG | 0o600, ino=13, size=len(raw))
        self.calls = []
        self.position = 0
        self.file_stat_count = 0
        self.file_fstat_count = 0
        self.parent_lstat_count = 0
        self.seeks = 0
        self.fault = None
        self.first_fstat_error = None
        self.first_fstat_fd = None
        self.fstat_by_fd = {}
        self.recycle_on_read = False
        self.foreign_file = False
        self.foreign_reads = 0
        self.foreign_fstats = 0
        self.recycle_after_close_error = False
        self.read_error = None
        self.close_error = None

    def geteuid(self):
        return 501

    def getegid(self):
        return 20

    def lstat(self, name):
        self.calls.append(("lstat", name))
        if name == "/toy/private":
            self.parent_lstat_count += 1
            value = copy.copy(self.parent)
            if self.fault == "parent-rebind":
                value.st_ino += 1
            return value
        assert name == "/"
        return copy.copy(self.root)

    def stat(self, name, *, dir_fd, follow_symlinks):
        self.calls.append(("stat", name, dir_fd, follow_symlinks))
        assert follow_symlinks is False
        if (name, dir_fd) == ("toy", 8):
            value = copy.copy(self.ancestor)
            if self.ancestor_symlink:
                value.st_mode = stat.S_IFLNK | 0o777
            return value
        if (name, dir_fd) == ("private", 9):
            return copy.copy(self.parent)
        assert (name, dir_fd) == ("input.json", 10)
        self.file_stat_count += 1
        value = copy.copy(self.file)
        if self.fault == "named-rebind" and self.file_stat_count >= 2:
            value.st_ino += 1
        return value

    def open(self, name, flags, *, dir_fd=None):
        self.calls.append(("open", name, flags, dir_fd))
        directory_flags = (self.O_RDONLY | self.O_DIRECTORY | self.O_NOFOLLOW
                           | self.O_CLOEXEC | self.O_NONBLOCK)
        if (name, dir_fd) in (("/", None), ("toy", 8), ("private", 9)):
            assert flags == directory_flags
            return {"/": 8, "toy": 9, "private": 10}[name]
        assert name == "input.json" and dir_fd == 10
        assert flags == self.O_RDONLY | self.O_NOFOLLOW | self.O_CLOEXEC | self.O_NONBLOCK
        if self.swap_fifo:
            self.file.st_mode = stat.S_IFIFO | 0o600
        return 11

    def fstat(self, descriptor):
        self.calls.append(("fstat", descriptor))
        self.fstat_by_fd[descriptor] = self.fstat_by_fd.get(descriptor, 0) + 1
        if descriptor == self.first_fstat_fd and self.fstat_by_fd[descriptor] == 1:
            raise self.first_fstat_error
        if descriptor == 8:
            return copy.copy(self.root)
        if descriptor == 9:
            return copy.copy(self.ancestor)
        if descriptor == 10:
            return copy.copy(self.parent)
        assert descriptor == 11
        self.file_fstat_count += 1
        value = copy.copy(self.file)
        if self.foreign_file:
            self.foreign_fstats += 1
            value.st_ino += 1000
            return value
        if self.fault == "held-clock-change" and self.file_fstat_count >= 4:
            value.st_mtime_ns += 1
        return value

    def read(self, descriptor, amount):
        self.calls.append(("read", descriptor, amount))
        assert descriptor == 11 and 0 < amount <= 131072
        if self.read_error is not None:
            raise self.read_error
        if self.foreign_file:
            self.foreign_reads += 1
        raw = self.raw
        if self.fault == "second-content-change" and self.seeks:
            raw = raw[:-1] + b"!"
        result = raw[self.position:self.position + amount]
        self.position += len(result)
        if self.recycle_on_read:
            self.foreign_file = True
        return result

    def lseek(self, descriptor, offset, whence):
        self.calls.append(("lseek", descriptor, offset, whence))
        assert (descriptor, offset, whence) == (11, 0, self.SEEK_SET)
        self.position = 0
        self.seeks += 1
        return 0

    def close(self, descriptor):
        self.calls.append(("close", descriptor))
        assert descriptor in (8, 9, 10, 11)
        if descriptor == 11 and self.close_error is not None:
            if self.recycle_after_close_error:
                self.foreign_file = True
            raise self.close_error


def binding(toy):
    return {
        "path": "/toy/private/input.json", "bytes": len(toy.raw),
        "SHA256": hashlib.sha256(toy.raw).hexdigest(),
        "native9": native9(toy.file), "parent_native9": native9(toy.parent),
        "original_input": {"bytes": len(toy.raw),
                           "SHA256": hashlib.sha256(toy.raw).hexdigest()},
    }


def _source_nine(info):
    return tuple(getattr(info, key) for key in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def _held_source_identity(path, expected_bytes, expected_sha, source_os, state):
    """Qualify one source FD; an unverified descriptor is never probed/closed."""
    if state["unknown"]:
        raise RuntimeError("HOLD: source FD qualification is sticky UNKNOWN")
    fd = None
    trusted = False
    primary = None
    named_before = None
    try:
        named_before = source_os.lstat(path)
        if not stat.S_ISREG(named_before.st_mode) or named_before.st_nlink != 1:
            raise RuntimeError("HOLD: canonical reader is not a single regular leaf")
        flags = (source_os.O_RDONLY | source_os.O_NOFOLLOW
                 | source_os.O_NONBLOCK | source_os.O_CLOEXEC)
        fd = source_os.open(path, flags)

        def checked_fstat():
            nonlocal trusted
            try:
                current = source_os.fstat(fd)
                same = _source_nine(current) == _source_nine(named_before)
            except BaseException:
                trusted = False
                raise
            if not same:
                trusted = False
                raise RuntimeError("HOLD: canonical reader named/held identity differs")
            trusted = True
            return current

        checked_fstat()  # First birth check; failure leaves the returned FD pending.
        reads = []
        for index in range(2):
            chunks = []
            total = 0
            while True:
                try:
                    chunk = source_os.read(fd, min(131072, expected_bytes + 1 - total))
                except BaseException:
                    trusted = False
                    raise
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > expected_bytes:
                    raise RuntimeError("HOLD: canonical reader source exceeds pin")
            try:
                explicit_eof = source_os.read(fd, 1)
            except BaseException:
                trusted = False
                raise
            if explicit_eof != b"":
                raise RuntimeError("HOLD: canonical reader explicit EOF differs")
            checked_fstat()
            reads.append(b"".join(chunks))
            if index == 0:
                try:
                    source_os.lseek(fd, 0, source_os.SEEK_SET)
                except BaseException:
                    trusted = False
                    raise
        named_after = source_os.lstat(path)
        if (_source_nine(named_after) != _source_nine(named_before)
                or reads[0] != reads[1]
                or len(reads[0]) != expected_bytes
                or hashlib.sha256(reads[0]).hexdigest() != expected_sha):
            raise RuntimeError("HOLD: canonical reader source bytes changed")
    except BaseException:
        primary = sys.exc_info()
        state["unknown"] = True
    if fd is not None:
        if trusted:
            trusted = False  # Consume the one close right before the call.
            try:
                source_os.close(fd)
            except BaseException:
                state["unknown"] = True
                if primary is None:
                    primary = sys.exc_info()
                else:
                    state["secondary"].append(sys.exc_info()[1])
        else:
            state["unknown"] = True  # Pending/unknown birth: no probe or close.
    if primary is not None:
        raise primary[1].with_traceback(primary[2]) from None
    if state["unknown"]:
        raise RuntimeError("HOLD: source FD qualification is sticky UNKNOWN")


def _canonical_reader_source_identity():
    # The real package import must name the regular sibling source file.
    if _SOURCE_QUALIFICATION["unknown"]:
        raise RuntimeError("HOLD: source FD qualification is sticky UNKNOWN")
    if SOURCE_PIN is not None or ROOT_BINDING is not None:
        raise RuntimeError("HOLD: external MODEL source substitution is forbidden")
    path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                        "private_public_fixture_input.py"))
    if (os.path.abspath(READER.__file__) != path
            or os.path.abspath(READER.__spec__.origin) != path
            or type(EXPECTED_READER_BYTES) is not int
            or type(EXPECTED_READER_SHA256) is not str):
        raise RuntimeError("HOLD: canonical reader source/origin is unbound")
    _held_source_identity(path, EXPECTED_READER_BYTES, EXPECTED_READER_SHA256,
                          os, _SOURCE_QUALIFICATION)


class PrivatePublicFixtureReaderModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _canonical_reader_source_identity()

    def setUp(self):
        self.original_state = (
            READER.ROOT_BINDING, READER._UNKNOWN, READER._SECONDARY,
            READER.ORIGINAL_PAYLOAD_BYTES, READER.ORIGINAL_PAYLOAD_SHA256,
        )
        self.addCleanup(self.restore_state)
        self.toy = None

    def restore_state(self):
        (READER.ROOT_BINDING, READER._UNKNOWN, READER._SECONDARY,
         READER.ORIGINAL_PAYLOAD_BYTES,
         READER.ORIGINAL_PAYLOAD_SHA256) = self.original_state

    def install(self, toy, data=None):
        # PUBLIC MODEL only: substitute its independently declared toy anchor
        # temporarily; the production reader has no proof-bypass branch.
        supplied = binding(toy) if data is None else data
        original = supplied.get("original_input") if type(supplied) is dict else None
        proof = (original if type(original) is dict
                 and set(original) == {"bytes", "SHA256"}
                 else binding(toy)["original_input"])
        READER.ORIGINAL_PAYLOAD_BYTES = proof["bytes"]
        READER.ORIGINAL_PAYLOAD_SHA256 = proof["SHA256"]
        READER.ROOT_BINDING = supplied
        READER._UNKNOWN, READER._SECONDARY = False, []
        self.toy = toy
        return mock.patch.object(READER, "os", toy)

    def rejected(self, toy):
        with self.assertRaises(READER.PrivateFixtureInputError):
            READER.require_fixture_value(KEYS[0])
        self.assertTrue(READER._UNKNOWN)
        before = list(toy.calls)
        with self.assertRaises(READER.PrivateFixtureInputError):
            READER.require_fixture_value(KEYS[1])
        self.assertEqual(before, toy.calls)

    def test_path_only_real_public_file_uses_fixed_toy_anchor(self):
        self.assertEqual(TOY_EXPECTED_BYTES, len(TOY_RAW))
        self.assertEqual(TOY_EXPECTED_SHA256, hashlib.sha256(TOY_RAW).hexdigest())
        with tempfile.TemporaryDirectory(
                prefix="public-private-reader-",
                dir=os.path.realpath(tempfile.gettempdir())) as parent:
            os.chmod(parent, 0o700)
            path = os.path.join(parent, "input.json")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                total = 0
                while total < len(TOY_RAW):
                    written = os.write(fd, TOY_RAW[total:])
                    self.assertGreater(written, 0)
                    total += written
            finally:
                os.close(fd)
            READER.ROOT_BINDING = None
            READER._UNKNOWN, READER._SECONDARY = False, []
            READER.ORIGINAL_PAYLOAD_BYTES = TOY_EXPECTED_BYTES
            READER.ORIGINAL_PAYLOAD_SHA256 = TOY_EXPECTED_SHA256
            with mock.patch.dict(os.environ, {READER.LOCATOR_ENV: path}, clear=True):
                self.assertEqual("toy-one", READER.require_fixture_value(KEYS[0]))
                self.assertFalse(READER._UNKNOWN)

    def test_path_only_wrong_content_and_legacy_self_pin_rejected(self):
        toy = ToyOS()
        with self.install(toy):
            READER.ROOT_BINDING = None
            READER.ORIGINAL_PAYLOAD_BYTES = TOY_EXPECTED_BYTES
            READER.ORIGINAL_PAYLOAD_SHA256 = TOY_EXPECTED_SHA256
            toy.environ[READER.LOCATOR_ENV] = "/toy/private/input.json"
            toy.raw = TOY_RAW.replace(b'"toy-one"', b'"toy-ONE"', 1)
            self.assertEqual(len(TOY_RAW), len(toy.raw))
            with self.assertRaises(READER.PrivateFixtureInputError) as caught:
                READER.require_fixture_value(KEYS[0])
            self.assertEqual(("private fixture complete content pin differs",),
                             caught.exception.args)
            self.assertGreaterEqual(
                len([call for call in toy.calls if call[0] == "read"]), 1)
            self.assertTrue(READER._UNKNOWN)
            before = list(toy.calls)
            with self.assertRaises(READER.PrivateFixtureInputError):
                READER.require_fixture_value(KEYS[1])
            self.assertEqual(before, toy.calls)
        toy = ToyOS()
        with self.install(toy):
            READER.ROOT_BINDING = None
            toy.environ[READER.LOCATOR_ENV] = "/toy/private/input.json"
            toy.environ[READER.INPUT_ENV] = json.dumps(binding(toy))
            self.rejected(toy)
        self.assertEqual([], toy.calls)

    def test_path_only_stat_to_open_fifo_swap_remains_nonblocking(self):
        toy = ToyOS()
        toy.swap_fifo = True
        with self.install(toy):
            READER.ROOT_BINDING = None
            toy.environ[READER.LOCATOR_ENV] = "/toy/private/input.json"
            self.rejected(toy)
        opened = [call for call in toy.calls if call[0] == "open"
                  and call[1] == "input.json"]
        self.assertEqual(1, len(opened))
        self.assertTrue(opened[0][2] & os.O_NONBLOCK)
        self.assertFalse(any(call[0] == "read" for call in toy.calls))

    def test_self_authored_root_digests_cannot_replace_code_bound_original(self):
        toy = ToyOS()
        supplied = binding(toy)
        supplied["SHA256"] = "1" * 64
        supplied["original_input"]["SHA256"] = "1" * 64
        READER.ROOT_BINDING = supplied
        with mock.patch.object(READER, "os", toy):
            with self.assertRaises(READER.PrivateFixtureInputError) as caught:
                READER.require_fixture_value(KEYS[0])
        self.assertEqual(("private fixture original proof differs from fixed source anchor",),
                         caught.exception.args)
        self.assertEqual([], toy.calls)
        self.assertTrue(READER._UNKNOWN)

    def test_root_and_new_locator_conflict_or_bad_locator_is_zero_io(self):
        for case in ("two-sources", "relative-locator"):
            with self.subTest(case=case):
                toy = ToyOS()
                with self.install(toy):
                    if case == "two-sources":
                        toy.environ[READER.LOCATOR_ENV] = "/toy/private/input.json"
                        expected = "private fixture metadata has two binding sources"
                    else:
                        READER.ROOT_BINDING = None
                        toy.environ[READER.LOCATOR_ENV] = "toy/private/input.json"
                        expected = "private fixture input path is not canonical absolute metadata"
                    with self.assertRaises(READER.PrivateFixtureInputError) as caught:
                        READER.require_fixture_value(KEYS[0])
                    self.assertEqual((expected,), caught.exception.args)
                    self.assertTrue(READER._UNKNOWN)
                self.assertEqual([], toy.calls)

    def test_locator_route_first_fstat_unknown_never_reprobes_or_closes_that_fd(self):
        for descriptor in (8, 9, 10, 11):
            with self.subTest(descriptor=descriptor):
                toy = ToyOS()
                primary = OSError("public locator first fstat fault")
                toy.first_fstat_fd, toy.first_fstat_error = descriptor, primary
                with self.install(toy):
                    READER.ROOT_BINDING = None
                    toy.environ[READER.LOCATOR_ENV] = "/toy/private/input.json"
                    with self.assertRaises(OSError) as caught:
                        READER.require_fixture_value(KEYS[0])
                    self.assertIs(primary, caught.exception)
                    self.assertTrue(READER._UNKNOWN)
                    before = list(toy.calls)
                    with self.assertRaises(READER.PrivateFixtureInputError):
                        READER.require_fixture_value(KEYS[1])
                    self.assertEqual(before, toy.calls)
                self.assertEqual(1, toy.fstat_by_fd[descriptor])
                self.assertNotIn(("close", descriptor), toy.calls)
                self.assertFalse(any(call[0] == "read" for call in toy.calls))

    def test_valid_toy_reads_one_held_fd_twice_and_closes_once(self):
        toy = ToyOS()
        with self.install(toy):
            self.assertEqual("toy-one", READER.require_fixture_value(KEYS[0]))
        self.assertEqual(2, toy.seeks)
        self.assertEqual([("close", 11), ("close", 10), ("close", 9), ("close", 8)],
                         [call for call in toy.calls if call[0] == "close"])
        self.assertEqual(6, len([call for call in toy.calls if call[0] == "read"]))
        self.assertFalse(READER._UNKNOWN)

    def test_absent_extra_or_conflicting_binding_is_zero_open(self):
        for case in ("absent", "extra-key", "two-sources"):
            with self.subTest(case=case):
                toy = ToyOS()
                with self.install(toy):
                    if case == "absent":
                        READER.ROOT_BINDING = None
                    elif case == "extra-key":
                        READER.ROOT_BINDING["extra"] = None
                    else:
                        toy.environ[READER.INPUT_ENV] = json.dumps(binding(toy))
                    self.rejected(toy)
                self.assertEqual([], toy.calls)

    def test_malformed_duplicate_or_wrong_payload_schema_is_rejected(self):
        raws = (
            b"{",
            b'{"schema":"http-test.private-public-fixture-input/v1","schema":"duplicate","values":{}}',
            b'{"schema":"wrong","values":{}}',
        )
        for raw in raws:
            with self.subTest(case=raws.index(raw)):
                toy = ToyOS(raw)
                with self.install(toy):
                    self.rejected(toy)

    def test_file_owner_group_mode_link_or_type_defects_are_rejected(self):
        for case in ("uid", "gid", "mode", "nlink", "symlink"):
            with self.subTest(case=case):
                toy = ToyOS()
                if case == "uid":
                    toy.file.st_uid = 502
                elif case == "gid":
                    toy.file.st_gid = 21
                elif case == "mode":
                    toy.file.st_mode = stat.S_IFREG | 0o644
                elif case == "nlink":
                    toy.file.st_nlink = 2
                else:
                    toy.file.st_mode = stat.S_IFLNK | 0o777
                expected = binding(toy)  # Pin the defective full9 itself.
                with self.install(toy, expected):
                    self.rejected(toy)

    def test_named_held_or_parent_identity_race_is_rejected(self):
        for fault in ("named-rebind", "held-clock-change", "parent-rebind"):
            with self.subTest(fault=fault):
                toy = ToyOS()
                toy.fault = fault
                with self.install(toy):
                    self.rejected(toy)

    def test_wrong_digest_or_changed_second_complete_read_is_rejected(self):
        for case in ("wrong-digest", "changed-second-read"):
            with self.subTest(case=case):
                toy = ToyOS()
                data = binding(toy)
                if case == "wrong-digest":
                    data["SHA256"] = "0" * 64
                    data["original_input"]["SHA256"] = "0" * 64
                else:
                    toy.fault = "second-content-change"
                with self.install(toy, data):
                    self.rejected(toy)

    def test_primary_read_error_identity_survives_one_close_secondary(self):
        toy = ToyOS()
        primary, secondary = KeyboardInterrupt("toy-primary"), OSError("toy-secondary")
        toy.read_error, toy.close_error = primary, secondary
        with self.install(toy):
            with self.assertRaises(KeyboardInterrupt) as caught:
                READER.require_fixture_value(KEYS[0])
            self.assertIs(primary, caught.exception)
            self.assertEqual([secondary], READER._SECONDARY)
            self.assertTrue(READER._UNKNOWN)
        self.assertEqual([("close", 11), ("close", 10), ("close", 9), ("close", 8)],
                         [call for call in toy.calls if call[0] == "close"])

    def test_close_failure_is_primary_and_sticky_without_return_or_retry(self):
        toy = ToyOS()
        secondary = OSError("toy-only-close")
        toy.close_error = secondary
        with self.install(toy):
            with self.assertRaises(OSError) as caught:
                READER.require_fixture_value(KEYS[0])
            self.assertIs(secondary, caught.exception)
            self.assertTrue(READER._UNKNOWN)
            before = list(toy.calls)
            with self.assertRaises(READER.PrivateFixtureInputError):
                READER.require_fixture_value(KEYS[1])
            self.assertEqual(before, toy.calls)
        self.assertEqual([("close", 11), ("close", 10), ("close", 9), ("close", 8)],
                         [call for call in toy.calls if call[0] == "close"])


    def test_first_fstat_unknown_consumes_without_probe_or_close(self):
        for descriptor in (10, 11):
            with self.subTest(descriptor=descriptor):
                toy = ToyOS()
                primary = OSError("toy-first-fstat")
                toy.first_fstat_fd, toy.first_fstat_error = descriptor, primary
                with self.install(toy):
                    with self.assertRaises(OSError) as caught:
                        READER.require_fixture_value(KEYS[0])
                    self.assertIs(primary, caught.exception)
                    self.assertTrue(READER._UNKNOWN)
                    before = list(toy.calls)
                    with self.assertRaises(READER.PrivateFixtureInputError):
                        READER.require_fixture_value(KEYS[1])
                    self.assertEqual(before, toy.calls)
                self.assertEqual(1, toy.fstat_by_fd[descriptor])
                self.assertNotIn(("close", descriptor), toy.calls)
                self.assertEqual([("close", 9), ("close", 8)] if descriptor == 10 else [("close", 10), ("close", 9), ("close", 8)],
                                 [call for call in toy.calls if call[0] == "close"])

    def test_recycled_read_descriptor_is_not_read_probed_or_closed_again(self):
        toy = ToyOS()
        toy.recycle_on_read = True
        with self.install(toy):
            self.rejected(toy)
        self.assertEqual(1, toy.foreign_fstats)
        self.assertEqual(0, toy.foreign_reads)
        self.assertNotIn(("close", 11), toy.calls)
        self.assertEqual([("close", 10), ("close", 9), ("close", 8)],
                         [call for call in toy.calls if call[0] == "close"])

    def test_close_after_effect_error_never_reprobes_or_recloses_number(self):
        toy = ToyOS()
        primary = OSError("toy-close-after-effect")
        toy.close_error = primary
        toy.recycle_after_close_error = True
        with self.install(toy):
            with self.assertRaises(OSError) as caught:
                READER.require_fixture_value(KEYS[0])
            self.assertIs(primary, caught.exception)
            self.assertTrue(READER._UNKNOWN)
            before = list(toy.calls)
            with self.assertRaises(READER.PrivateFixtureInputError):
                READER.require_fixture_value(KEYS[1])
            self.assertEqual(before, toy.calls)
        self.assertEqual(1, toy.calls.count(("close", 11)))
        self.assertEqual(0, toy.foreign_fstats)
        after_close = toy.calls[toy.calls.index(("close", 11)) + 1:]
        self.assertFalse(any(call[0] in ("read", "lseek", "fstat", "close")
                             and call[1] == 11 for call in after_close))
        self.assertEqual([("close", 11), ("close", 10), ("close", 9), ("close", 8)],
                         [call for call in toy.calls if call[0] == "close"])

    def test_invalid_utf8_has_only_fixed_safe_error_without_raw_context(self):
        toy = ToyOS(b"\xffprivate-toy-input")
        with self.install(toy):
            with self.assertRaises(READER.PrivateFixtureInputError) as caught:
                READER.require_fixture_value(KEYS[0])
            error = caught.exception
            self.assertEqual(("private fixture UTF-8 is invalid",), error.args)
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertTrue(READER._UNKNOWN)
            self.assertEqual([], READER._SECONDARY)
            before = list(toy.calls)
            with self.assertRaises(READER.PrivateFixtureInputError):
                READER.require_fixture_value(KEYS[1])
            self.assertEqual(before, toy.calls)


    def test_environment_self_authored_pin_without_root_is_zero_io(self):
        toy = ToyOS()
        with self.install(toy):
            READER.ROOT_BINDING = None
            toy.environ[READER.INPUT_ENV] = json.dumps(binding(toy))
            self.rejected(toy)
        self.assertEqual([], toy.calls)

    def test_original_input_digest_is_independent_of_locator_metadata(self):
        toy = ToyOS()
        data = binding(toy)
        data["SHA256"] = "1" * 64
        # Original proof remains the independent public toy pin, not the new pin.
        with self.install(toy, data):
            self.rejected(toy)
        self.assertEqual([], toy.calls)

    def test_missing_or_extra_original_proof_is_zero_io(self):
        for case in ("missing", "extra"):
            with self.subTest(case=case):
                toy = ToyOS()
                data = binding(toy)
                if case == "missing":
                    del data["original_input"]
                else:
                    data["original_input"]["extra"] = True
                with self.install(toy, data):
                    self.rejected(toy)
                self.assertEqual([], toy.calls)

    def test_parent_defective_identity_itself_is_pinned_and_rejected(self):
        for case in ("uid", "gid", "mode", "type", "nlink"):
            with self.subTest(case=case):
                toy = ToyOS()
                if case == "uid":
                    toy.parent.st_uid = 502
                elif case == "gid":
                    toy.parent.st_gid = 21
                elif case == "mode":
                    toy.parent.st_mode = stat.S_IFDIR | 0o755
                elif case == "type":
                    toy.parent.st_mode = stat.S_IFLNK | 0o700
                else:
                    toy.parent.st_nlink = 0
                data = binding(toy)
                self.assertEqual(native9(toy.parent), data["parent_native9"])
                with self.install(toy, data):
                    self.rejected(toy)
                self.assertFalse(any(call[0] == "open" and call[1] == "private"
                                     for call in toy.calls))

    def test_pinned_fifo_is_rejected_before_leaf_open(self):
        toy = ToyOS()
        toy.file.st_mode = stat.S_IFIFO | 0o600
        data = binding(toy)
        self.assertEqual(native9(toy.file), data["native9"])
        with self.install(toy, data):
            self.rejected(toy)
        self.assertFalse(any(call[0] == "open" and call[1] == "input.json"
                             for call in toy.calls))

    def test_stat_to_open_fifo_swap_is_nonblocking_and_never_read(self):
        toy = ToyOS()
        toy.swap_fifo = True
        with self.install(toy):
            self.rejected(toy)
        opened = [call for call in toy.calls if call[0] == "open"
                  and call[1] == "input.json"]
        self.assertEqual(1, len(opened))
        self.assertTrue(opened[0][2] & os.O_NONBLOCK)
        self.assertFalse(any(call[0] == "read" for call in toy.calls))
        self.assertNotIn(("close", 11), toy.calls)
        self.assertEqual(1, toy.fstat_by_fd[11])

    def test_ancestor_symlink_cannot_be_used_for_any_descendant_open(self):
        toy = ToyOS()
        toy.ancestor_symlink = True
        with self.install(toy):
            self.rejected(toy)
        self.assertEqual([("/", None)],
                         [(call[1], call[3]) for call in toy.calls if call[0] == "open"])
        self.assertEqual([("close", 8)],
                         [call for call in toy.calls if call[0] == "close"])

    def test_every_ancestor_open_is_relative_to_verified_previous_fd(self):
        toy = ToyOS()
        with self.install(toy):
            self.assertEqual("toy-five", READER.require_fixture_value(KEYS[4]))
        self.assertEqual([("/", None), ("toy", 8), ("private", 9), ("input.json", 10)],
                         [(call[1], call[3]) for call in toy.calls if call[0] == "open"])
        for call in toy.calls:
            if call[0] == "open":
                self.assertTrue(call[2] & os.O_NOFOLLOW)
                self.assertTrue(call[2] & os.O_NONBLOCK)

    def test_nested_duplicate_and_nonstandard_json_have_safe_error_surface(self):
        raws = (
            b'{"schema":"http-test.private-public-fixture-input/v1","values":{"x":"one","x":"two"}}',
            b'{"schema":NaN,"values":{}}',
            b'{"schema":"unterminated',
            b'{"schema":Infinity,"values":{}}',
            b'[' * 1100 + b'0' + b']' * 1100,
        )
        for index, raw in enumerate(raws):
            with self.subTest(case=index):
                toy = ToyOS(raw)
                with self.install(toy):
                    with self.assertRaises(READER.PrivateFixtureInputError) as caught:
                        READER.require_fixture_value(KEYS[0])
                    self.assertEqual(("private fixture JSON is invalid",), caught.exception.args)
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertIsNone(caught.exception.__context__)
                    self.assertTrue(READER._UNKNOWN)

    def test_closed_payload_and_value_boundaries_reject_public_literals(self):
        variants = []
        base = {"schema": "http-test.private-public-fixture-input/v1",
                "values": dict(TOY_VALUES)}
        for case in ("top-extra", "value-extra", "empty", "nul", "number", "list"):
            data = copy.deepcopy(base)
            if case == "top-extra":
                data["extra"] = "public"
            elif case == "value-extra":
                data["values"]["extra"] = "public"
            elif case == "empty":
                data["values"][KEYS[0]] = ""
            elif case == "nul":
                data["values"][KEYS[0]] = "\0"
            elif case == "number":
                data["values"][KEYS[0]] = 1
            else:
                data["values"] = []
            variants.append(json.dumps(data).encode())
        for index, raw in enumerate(variants):
            with self.subTest(case=index):
                toy = ToyOS(raw)
                with self.install(toy):
                    self.rejected(toy)

    def test_metadata_bounds_and_types_are_zero_io(self):
        for case in ("zero", "over", "bool", "sha", "nine"):
            with self.subTest(case=case):
                toy = ToyOS()
                data = binding(toy)
                if case == "zero":
                    data["bytes"] = 0
                elif case == "over":
                    data["bytes"] = 65537
                elif case == "bool":
                    data["bytes"] = True
                elif case == "sha":
                    data["SHA256"] = "z" * 64
                else:
                    data["native9"][0] = 7
                with self.install(toy, data):
                    self.rejected(toy)
                self.assertEqual([], toy.calls)

    def test_non_main_thread_is_rejected_and_sticky_before_io(self):
        toy = ToyOS()
        main, worker = object(), object()
        thread_api = SimpleNamespace(current_thread=lambda: worker,
                                     main_thread=lambda: main)
        with self.install(toy), mock.patch.object(READER, "threading", thread_api):
            self.rejected(toy)
        self.assertEqual([], toy.calls)

    def test_reentrant_entry_latches_unknown_and_prevents_outer_success(self):
        toy = ToyOS()
        with self.install(toy):
            READER._CALL_LOCK.acquire()
            try:
                self.rejected(toy)
            finally:
                READER._CALL_LOCK.release()
            self.assertTrue(READER._UNKNOWN)
        self.assertEqual([], toy.calls)

    def test_concurrent_failure_seen_during_read_forbids_successful_return(self):
        toy = ToyOS()
        original = toy.read
        seen = []
        def read_once(descriptor, amount):
            if not seen:
                seen.append(True)
                with self.assertRaises(READER.PrivateFixtureInputError):
                    READER.require_fixture_value(KEYS[1])
            return original(descriptor, amount)
        toy.read = read_once
        with self.install(toy):
            self.rejected(toy)
        self.assertEqual([True], seen)



    def test_same_length_full9_wrong_public_content_reaches_digest_gate(self):
        expected = TOY_RAW  # Independently declared public closed-schema input.
        actual = TOY_RAW.replace(b'"toy-one"', b'"toy-ONE"', 1)
        self.assertEqual(len(expected), len(actual))
        self.assertNotEqual(expected, actual)
        toy = ToyOS(actual)
        data = binding(toy)
        expected_digest = hashlib.sha256(expected).hexdigest()
        data["SHA256"] = expected_digest
        data["original_input"]["SHA256"] = expected_digest
        expected9 = list(data["native9"])
        self.assertEqual(native9(toy.file), expected9)
        with self.install(toy, data):
            with self.assertRaises(READER.PrivateFixtureInputError) as caught:
                READER.require_fixture_value(KEYS[0])
            self.assertEqual(("private fixture complete content pin differs",),
                             caught.exception.args)
            self.assertTrue(READER._UNKNOWN)
            self.assertEqual([], READER._SECONDARY)
            before = list(toy.calls)
            with self.assertRaises(READER.PrivateFixtureInputError):
                READER.require_fixture_value(KEYS[1])
            self.assertEqual(before, toy.calls)
        self.assertEqual(expected9, native9(toy.file))
        self.assertEqual(3, len([call for call in toy.calls if call[0] == "read"]))
        self.assertEqual(0, toy.seeks)
        self.assertEqual([("close", 11), ("close", 10), ("close", 9), ("close", 8)],
                         [call for call in toy.calls if call[0] == "close"])

    def test_root_or_intermediate_first_fstat_unknown_is_never_reprobed_or_closed(self):
        for descriptor in (8, 9):
            with self.subTest(descriptor=descriptor):
                toy = ToyOS()
                primary = OSError("toy-ancestor-first-fstat")
                toy.first_fstat_fd, toy.first_fstat_error = descriptor, primary
                with self.install(toy):
                    with self.assertRaises(OSError) as caught:
                        READER.require_fixture_value(KEYS[0])
                    self.assertIs(primary, caught.exception)
                    self.assertTrue(READER._UNKNOWN)
                    self.assertEqual([], READER._SECONDARY)
                    before = list(toy.calls)
                    with self.assertRaises(READER.PrivateFixtureInputError):
                        READER.require_fixture_value(KEYS[1])
                    self.assertEqual(before, toy.calls)
                self.assertEqual(1, toy.fstat_by_fd[descriptor])
                self.assertNotIn(("close", descriptor), toy.calls)
                self.assertEqual([] if descriptor == 8 else [("close", 8)],
                                 [call for call in toy.calls if call[0] == "close"])
                self.assertFalse(any(call[0] == "read" for call in toy.calls))
                self.assertFalse(any(call[0] == "open" and call[1] in ("private", "input.json")
                                     for call in toy.calls))



class PublicSourceQualificationToy:
    """No real FD, source module or original private fixture enters this model."""

    O_RDONLY = os.O_RDONLY
    O_NOFOLLOW = os.O_NOFOLLOW
    O_NONBLOCK = os.O_NONBLOCK
    O_CLOEXEC = os.O_CLOEXEC
    SEEK_SET = os.SEEK_SET
    raw = b"public-source\n"

    def __init__(self):
        self.named = info(stat.S_IFREG | 0o600, ino=71, size=len(self.raw))
        self.position = 0
        self.opens = []
        self.fstats = 0
        self.lstats = 0
        self.reads = 0
        self.closes = 0
        self.closed = False
        self.fstat_error_at = None
        self.fstat_error = None
        self.lstat_error_at = None
        self.lstat_error = None
        self.close_error = None

    def lstat(self, path):
        assert path == "/public/source.py"
        self.lstats += 1
        if self.lstats == self.lstat_error_at:
            raise self.lstat_error
        return copy.copy(self.named)

    def open(self, path, flags):
        assert path == "/public/source.py"
        self.opens.append(flags)
        return 17

    def fstat(self, descriptor):
        assert descriptor == 17 and not self.closed
        self.fstats += 1
        if self.fstats == self.fstat_error_at:
            raise self.fstat_error
        return copy.copy(self.named)

    def read(self, descriptor, amount):
        assert descriptor == 17 and not self.closed and amount > 0
        self.reads += 1
        result = self.raw[self.position:self.position + amount]
        self.position += len(result)
        return result

    def lseek(self, descriptor, offset, whence):
        assert (descriptor, offset, whence) == (17, 0, self.SEEK_SET)
        self.position = 0
        return 0

    def close(self, descriptor):
        assert descriptor == 17 and not self.closed
        self.closes += 1
        self.closed = True  # after-effect close error must not trigger retry
        if self.close_error is not None:
            raise self.close_error


class SourceQualificationPublicModelTests(unittest.TestCase):
    FIXED_BYTES = 14
    FIXED_SHA256 = "6fe179054dd0253da066b1115ee226acf08cf6328edcab5281f7a3351a0aa439"

    def qualify(self, toy, state):
        return _held_source_identity("/public/source.py", self.FIXED_BYTES,
                                     self.FIXED_SHA256, toy, state)

    def test_verified_source_uses_nonblocking_nofollow_and_one_close(self):
        toy = PublicSourceQualificationToy()
        state = {"unknown": False, "secondary": []}
        self.assertEqual(self.FIXED_BYTES, len(toy.raw))
        self.assertEqual(self.FIXED_SHA256, hashlib.sha256(toy.raw).hexdigest())
        self.assertIsNone(self.qualify(toy, state))
        self.assertEqual([os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                          os.O_CLOEXEC], toy.opens)
        self.assertEqual(1, toy.closes)
        self.assertEqual(2, toy.lstats)
        self.assertEqual(3, toy.fstats)
        self.assertFalse(state["unknown"])
        self.assertEqual([], state["secondary"])

    def test_first_fstat_error_preserves_primary_and_never_probes_or_closes_fd(self):
        toy = PublicSourceQualificationToy()
        original = OSError("public first fstat fault")
        toy.fstat_error_at, toy.fstat_error = 1, original
        state = {"unknown": False, "secondary": []}
        with self.assertRaises(OSError) as caught:
            self.qualify(toy, state)
        self.assertIs(original, caught.exception)
        self.assertTrue(state["unknown"])
        self.assertEqual((1, 0, 0), (toy.fstats, toy.reads, toy.closes))
        before = (list(toy.opens), toy.fstats, toy.reads, toy.closes)
        with self.assertRaises(RuntimeError):
            self.qualify(toy, state)
        self.assertEqual(before, (toy.opens, toy.fstats, toy.reads, toy.closes))

    def test_late_fstat_error_stops_held_fd_probes_and_close(self):
        toy = PublicSourceQualificationToy()
        original = OSError("public late fstat fault")
        toy.fstat_error_at, toy.fstat_error = 2, original
        state = {"unknown": False, "secondary": []}
        with self.assertRaises(OSError) as caught:
            self.qualify(toy, state)
        self.assertIs(original, caught.exception)
        self.assertTrue(state["unknown"])
        self.assertEqual(2, toy.fstats)
        self.assertGreater(toy.reads, 0)
        self.assertEqual(0, toy.closes)

    def test_close_after_effect_is_one_attempt_and_sticky_unknown(self):
        toy = PublicSourceQualificationToy()
        original = OSError("public close after effect")
        toy.close_error = original
        state = {"unknown": False, "secondary": []}
        with self.assertRaises(OSError) as caught:
            self.qualify(toy, state)
        self.assertIs(original, caught.exception)
        self.assertTrue(toy.closed)
        self.assertEqual(1, toy.closes)
        self.assertTrue(state["unknown"])
        before = (list(toy.opens), toy.fstats, toy.reads, toy.closes)
        with self.assertRaises(RuntimeError):
            self.qualify(toy, state)
        self.assertEqual(before, (toy.opens, toy.fstats, toy.reads, toy.closes))

    def test_original_primary_and_close_secondary_keep_object_identity(self):
        toy = PublicSourceQualificationToy()
        primary = OSError("public final named stat fault")
        secondary = OSError("public close after effect")
        toy.lstat_error_at, toy.lstat_error = 2, primary
        toy.close_error = secondary
        state = {"unknown": False, "secondary": []}
        with self.assertRaises(OSError) as caught:
            self.qualify(toy, state)
        self.assertIs(primary, caught.exception)
        self.assertEqual([secondary], state["secondary"])
        self.assertEqual(1, toy.closes)
        self.assertTrue(state["unknown"])


class ZCanonicalReaderAfterModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _canonical_reader_source_identity()

    def test_later_consumer_like_call_sees_unpatched_reader(self):
        # A later class must see the actual module, not a toy os/Root binding or
        # UNKNOWN inherited from any of the 28 earlier MODEL methods.
        self.assertIs(READER.os, os)
        self.assertIsNone(READER.ROOT_BINDING)
        self.assertFalse(READER._UNKNOWN)
        self.assertEqual([], READER._SECONDARY)
        self.assertFalse(READER._CALL_LOCK.locked())
        self.assertEqual(507, READER.ORIGINAL_PAYLOAD_BYTES)
        self.assertEqual(
            "3dbf3ead249c15db03371d1e7db9758d14978a22778d34193c084a14d0677453",
            READER.ORIGINAL_PAYLOAD_SHA256)
        with tempfile.TemporaryDirectory(
                prefix="public-later-consumer-",
                dir=os.path.realpath(tempfile.gettempdir())) as parent:
            os.chmod(parent, 0o700)
            path = os.path.join(parent, "input.json")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                total = 0
                while total < len(TOY_RAW):
                    written = os.write(fd, TOY_RAW[total:])
                    self.assertGreater(written, 0)
                    total += written
            finally:
                os.close(fd)
            with (mock.patch.object(READER, "ORIGINAL_PAYLOAD_BYTES", TOY_EXPECTED_BYTES),
                  mock.patch.object(READER, "ORIGINAL_PAYLOAD_SHA256", TOY_EXPECTED_SHA256),
                  mock.patch.dict(os.environ, {READER.LOCATOR_ENV: path}, clear=True)):
                def later_consumer_like():
                    return READER.require_fixture_value(KEYS[4])
                self.assertEqual("toy-five", later_consumer_like())
        self.assertIs(READER.os, os)
        self.assertIsNone(READER.ROOT_BINDING)
        self.assertFalse(READER._UNKNOWN)
        self.assertFalse(READER._CALL_LOCK.locked())
        self.assertEqual(507, READER.ORIGINAL_PAYLOAD_BYTES)


if __name__ == "__main__":
    raise SystemExit("STOPPED: never run this module as a script")
