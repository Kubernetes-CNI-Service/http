"""Independent original-FD entry/cleanup boundaries, private IO only.

No native manager grant, authenticated request or remote device execution.
Old 9 tests remain unchanged; these controls do not read/close foreign FDs.
"""
import contextlib
import errno
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import importlib.util
import sys

MAIN=Path(__file__).resolve().parents[1]

def subject():
    spec=importlib.util.spec_from_file_location('parent_cleanup_subject',MAIN/'tools/ibsw_upgrade_scp.py')
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    return module


class CleanupBoundaryTests(unittest.TestCase):
    def module(self):
        module=subject()
        self.assertTrue(callable(getattr(module,'package_content_owner',None)),
                        'MISSING_PARENT_CONTENT_OWNER_FEATURE_NOT_AN_EXPLOIT')
        return module

    def original(self,module,root):
        package=root/'source.bin';package.write_bytes(b'abc');package.chmod(0o600)
        opened=[];real_open=os.open
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        with patch.object(module.os,'open',opening):
            owner=module.package_content_owner(root,[package],deadline=time.monotonic()+4,max_fds=64)
        return owner,package,opened

    def assert_closed(self,opened,except_fd=None):
        leaked=[]
        for fd in opened:
            if fd==except_fd:continue
            try:os.fstat(fd)
            except OSError as error:self.assertEqual(errno.EBADF,error.errno)
            else:leaked.append(fd)
        self.assertEqual([],leaked,'every original descriptor must be closed')

    def rescue_test_opened(self,opened):
        for fd in opened:
            with contextlib.suppress(OSError):os.close(fd)

    def close_fault(self,module):
        real_close=os.close;attempts=[];refused=[]
        def closing(fd):
            attempts.append(fd)
            if not refused:
                refused.append(fd)
                raise OSError(errno.EIO,'private injected critical close failure')
            real_close(fd)
        return patch.object(module.os,'close',closing),attempts,refused

    def test_failed_enter_closes_originals_and_preserves_replacement_file(self):
        module=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();owner,package,opened=self.original(module,root)
            replacement=root/'replacement';replacement.write_bytes(b'xyz');replacement.chmod(0o600)
            replacement.replace(package)
            before=package.stat();payload=package.read_bytes()
            try:
                with self.assertRaises(module.ContentHold):
                    with owner:self.fail('changed source cannot enter a live body')
                self.assert_closed(opened)
                after=package.stat()
                self.assertEqual((before.st_dev,before.st_ino,before.st_size),(after.st_dev,after.st_ino,after.st_size))
                self.assertEqual(b'xyz',payload);self.assertEqual(payload,package.read_bytes())
            finally:self.rescue_test_opened(opened)

    def test_repeated_close_keeps_unknown_failure_without_retrying_fd_slots(self):
        module=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            owner,package,opened=self.original(module,Path(tmp).resolve())
            fault,attempts,refused=self.close_fault(module)
            try:
                with fault:
                    with self.assertRaises(module.ContentHold):owner.close()
                    first=tuple(attempts)
                    with self.assertRaises(module.ContentHold):owner.close()
                    self.assertEqual(first,tuple(attempts),'UNKNOWN close must not retry potentially reused slots')
                self.assert_closed(opened,refused[0])
                with self.assertRaises(module.ContentHold):owner.bind(b'request',b'dispatch')
            finally:self.rescue_test_opened(opened)

    def test_enter_operator_identity_and_existing_cause_survive_cleanup_failure(self):
        module=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            owner,package,opened=self.original(module,Path(tmp).resolve())
            primary=KeyboardInterrupt('literal enter interruption');cause=RuntimeError('literal original cause')
            primary.__cause__=cause
            fault,attempts,refused=self.close_fault(module)
            try:
                with patch.object(owner,'verify',side_effect=primary),fault:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        with owner:self.fail('interrupted entry cannot run a body')
                self.assertIs(primary,raised.exception)
                self.assertIs(cause,primary.__cause__)
                self.assertTrue(refused,'entry failure must attempt owned cleanup')
                self.assertTrue(owner.cleanup_issues,'critical cleanup remains explicit evidence')
                self.assert_closed(opened,refused[0])
                with self.assertRaises(module.ContentHold):owner.bind(b'request',b'dispatch')
            finally:self.rescue_test_opened(opened)

    def test_body_operator_identity_and_existing_cause_survive_cleanup_failure(self):
        module=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            owner,package,opened=self.original(module,Path(tmp).resolve())
            primary=SystemExit(19);cause=RuntimeError('literal existing body cause');primary.__cause__=cause
            fault,attempts,refused=self.close_fault(module)
            try:
                with fault,self.assertRaises(SystemExit) as raised:
                    with owner:raise primary
                self.assertIs(primary,raised.exception)
                self.assertIs(cause,primary.__cause__)
                self.assertTrue(owner.cleanup_issues)
                self.assert_closed(opened,refused[0])
            finally:self.rescue_test_opened(opened)

    def test_constructor_operator_identity_and_existing_cause_survive_cleanup_failure(self):
        module=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();package=root/'source.bin';package.write_bytes(b'abc');package.chmod(0o600)
            primary=KeyboardInterrupt('literal read interruption');cause=RuntimeError('literal read cause');primary.__cause__=cause
            opened=[];real_open=os.open
            def opening(*args,**kwargs):
                fd=real_open(*args,**kwargs);opened.append(fd);return fd
            fault,attempts,refused=self.close_fault(module)
            try:
                with patch.object(module.os,'open',opening),patch.object(module.os,'read',side_effect=primary),fault:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        module.package_content_owner(root,[package],deadline=time.monotonic()+4,max_fds=64)
                self.assertIs(primary,raised.exception)
                self.assertIs(cause,primary.__cause__)
                self.assertTrue(refused)
                self.assert_closed(opened,refused[0])
            finally:self.rescue_test_opened(opened)


if __name__=='__main__':unittest.main()
