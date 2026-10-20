"""Independent private parent-FD/oncehash proposal, not native SCP authority.

Real current planner -> candidate -> receiver/PTY with external SCP stub only.
Request/dispatch byte inputs are DATA, not authenticated manager originals.
"""
import contextlib
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

MAIN = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MAIN/'tools'))
import ibsw_upgrade_contract as contract

ABC_SHA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
GLOBAL = '''common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.254
      port: 8088
      http_root: /var/www/html
switches:
  - ib:
      version: '25.03.1010'
      upgrade:
        packages:
          os:
            files:
              - file: nvosv25-02-7002amd64.bin
              - file: nvos-amd64-25.03.1010.bin
'''


def subject():
    spec = importlib.util.spec_from_file_location('parent_owner_subject', MAIN/'tools/ibsw_upgrade_scp.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ParentContentOwnerTests(unittest.TestCase):
    def factory(self, module):
        factory = getattr(module, 'package_content_owner', None)
        self.assertTrue(callable(factory), 'MISSING_PARENT_CONTENT_OWNER_FEATURE_NOT_AN_EXPLOIT')
        return factory

    def fixture(self, root):
        package = root/'package.bin'
        package.write_bytes(b'abc')
        package.chmod(0o600)
        return package

    def test_needed_package_is_hashed_once_across_two_request_documents(self):
        module=subject(); factory=self.factory(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); package=self.fixture(root)
            real_read=os.read; received=[]
            def read(fd, count):
                chunk=real_read(fd,count)
                received.append(chunk)
                return chunk
            with patch.object(module.os,'read',read):
                with factory(root,[package],deadline=time.monotonic()+4,max_fds=64) as owner:
                    a=owner.bind(b'first-request',b'first-dispatch')
                    b=owner.bind(b'second-request',b'second-dispatch')
                    owner.verify()
            self.assertEqual(b'abc',b''.join(received),'no per-device source rehash')
            self.assertEqual({str(package):{'size':3,'sha256':ABC_SHA}},a['content_binding']['packages'])
            self.assertEqual(a['content_binding']['packages'],b['content_binding']['packages'])
            self.assertNotEqual(a['content_binding']['binding_sha256'],b['content_binding']['binding_sha256'])
            self.assertFalse((root/'unneeded-package.bin').exists())

    def test_same_size_inplace_change_poison_stops_later_requests_even_after_restore(self):
        module=subject(); factory=self.factory(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); package=self.fixture(root)
            with factory(root,[package],deadline=time.monotonic()+4,max_fds=64) as owner:
                original=package.stat()
                owner.bind(b'first',b'dispatch-one')
                package.write_bytes(b'xyz')
                os.utime(package,ns=(original.st_atime_ns,original.st_mtime_ns))
                with self.assertRaises(module.ContentHold):owner.bind(b'peer',b'dispatch-two')
                package.write_bytes(b'abc')
                with self.assertRaises(module.ContentHold):owner.bind(b'restored',b'dispatch-three')

    def test_nonregular_shared_link_and_parent_symlink_sources_are_refused(self):
        module=subject(); factory=self.factory(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); package=self.fixture(root)
            fifo=root/'fifo'; os.mkfifo(fifo)
            linked=root/'linked'; os.link(package,linked)
            alias=root/'alias'; alias.symlink_to(root,target_is_directory=True)
            for path in (fifo,package):
                with self.subTest(path=str(path)),self.assertRaises(module.ContentHold):
                    with factory(root,[path],deadline=time.monotonic()+4,max_fds=64):pass
            linked.unlink()
            self.assertEqual(1,package.stat().st_nlink)
            with self.assertRaises(module.ContentHold):
                with factory(root,[alias/'package.bin'],deadline=time.monotonic()+4,max_fds=64):pass

    def test_fd_cap_and_expired_acquisition_deadline_fail_before_any_open(self):
        module=subject(); factory=self.factory(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); package=self.fixture(root)
            for cap,deadline in ((1,time.monotonic()+4),(64,time.monotonic()-1)):
                with self.subTest(cap=cap),patch.object(module.os,'open',wraps=os.open) as opens:
                    with self.assertRaises(module.ContentHold):
                        factory(root,[package],deadline=deadline,max_fds=cap)
                    self.assertEqual(0,opens.call_count)

    def test_hash_io_failure_closes_all_descriptors_opened_by_this_acquisition(self):
        module=subject(); factory=self.factory(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); package=self.fixture(root)
            original_open=os.open; opened=[]
            def opening(*args,**kwargs):
                fd=original_open(*args,**kwargs); opened.append(fd); return fd
            with patch.object(module.os,'open',opening),patch.object(module.os,'read',side_effect=OSError(errno.EIO,'owned synthetic read failure')):
                with self.assertRaises(module.ContentHold):factory(root,[package],deadline=time.monotonic()+4,max_fds=64)
            self.assertTrue(opened)
            for fd in opened:
                with self.subTest(fd=fd),self.assertRaises(OSError) as error:os.fstat(fd)
                self.assertEqual(errno.EBADF,error.exception.errno)

    def test_closed_or_close_failed_owner_never_releases_another_document(self):
        module=subject(); factory=self.factory(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); package=self.fixture(root)
            owner=factory(root,[package],deadline=time.monotonic()+4,max_fds=64)
            owner.close(); owner.close()
            with self.assertRaises(module.ContentHold):owner.bind(b'after-close',b'dispatch')
            owner=factory(root,[package],deadline=time.monotonic()+4,max_fds=64)
            real_close=os.close; refused=[]
            def close(fd):
                if not refused:refused.append(fd);raise OSError(errno.EIO,'owned synthetic close failure')
                return real_close(fd)
            try:
                with patch.object(module.os,'close',close),self.assertRaises(module.ContentHold):owner.close()
                with self.assertRaises(module.ContentHold):owner.bind(b'after-failed-close',b'dispatch')
            finally:
                for fd in refused:
                    with contextlib.suppress(OSError):real_close(fd)

    def test_first_fstat_failure_cannot_leak_a_just_opened_directory_or_package(self):
        module=subject(); factory=self.factory(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); package=self.fixture(root)
            for kind in ('directory','package'):
                opened=[]; failing=[]; real_open=os.open;real_stat=os.fstat
                def opening(path,flags,*args,**kwargs):
                    fd=real_open(path,flags,*args,**kwargs);opened.append(fd)
                    is_dir=bool(flags & os.O_DIRECTORY)
                    if not failing and is_dir==(kind=='directory'):failing.append(fd)
                    return fd
                already_failed=[]
                def checking(fd):
                    if failing and fd==failing[0] and not already_failed:
                        already_failed.append(fd)
                        raise OSError(errno.EIO,'synthetic first metadata read failure')
                    return real_stat(fd)
                with self.subTest(kind=kind):
                    try:
                        with patch.object(module.os,'open',opening),patch.object(module.os,'fstat',checking):
                            with self.assertRaises(module.ContentHold):factory(root,[package],deadline=time.monotonic()+4,max_fds=64)
                        self.assertEqual(failing,already_failed)
                        leaked=[]
                        for fd in opened:
                            try:real_stat(fd)
                            except OSError as error:self.assertEqual(errno.EBADF,error.errno)
                            else:leaked.append(fd)
                        self.assertEqual([],leaked,'new open ownership must survive first fstat failure')
                    finally:
                        for fd in opened:
                            with contextlib.suppress(OSError):os.close(fd)

    def workflow(self, corrupt):
        module=subject(); factory=self.factory(module)
        with tempfile.TemporaryDirectory(prefix='parent-content-private-') as tmp:
            root=Path(tmp).resolve(); packages=root/'packages'; packages.mkdir()
            policy=contract.normalize_upgrade(contract.load_global_text(GLOBAL),selected=('os',),method='local',package_dir=str(packages))
            path=packages/'nvosv25-02-7002amd64.bin'
            self.assertEqual(str(path),policy.os[0].path)
            path.write_bytes(b'abc');path.chmod(0o600)
            self.assertFalse(Path(policy.os[1].path).exists(),'unneeded later package is not opened')
            with factory(packages,[Path(policy.os[0].path)],deadline=time.monotonic()+4,max_fds=64) as owner:
                public=owner.bind(b'literal-request-DATA',b'literal-dispatch-DATA')
                self.assertEqual({str(path):{'size':3,'sha256':ABC_SHA}},public['content_binding']['packages'])
                external=root/'private-scp.py';trace=root/'pulls'
                external.write_text('#!'+sys.executable+'\nimport os,sys\n'
                    'a=sys.argv[1:];assert "-O" in a and "StrictHostKeyChecking=yes" in a\n'
                    'assert "IBSW_SCP_AUTH" not in os.environ\n'
                    'sys.stderr.write("source password:");sys.stderr.flush();assert input()=="SYNTHETIC_PARENT_SECRET"\n'
                    'with open('+repr(str(trace))+',"a") as f:f.write(a[-2]+"\\n")\n'
                    'with open(a[-1],"wb") as f:f.write('+repr(b'xyz' if corrupt else b'abc')+')\n')
                external.chmod(0o700)
                helper=module.remote_helper_bytes().decode().replace("SSH = '/usr/bin/ssh'",'SSH = '+repr(str(external))).replace("SCP = '/usr/bin/scp'",'SCP = '+repr(str(external)))
                receiver=root/'receiver.py';receiver.write_text(helper)
                cfg=dict(host='192.0.2.254',user='sourceuser',port=22,host_keys='SYNTHETIC wire only\n',password='SYNTHETIC_PARENT_SECRET',paths={str(path):3},timeout_seconds=3,content_binding=public['content_binding'])
                result=subprocess.run([sys.executable,'-B',str(receiver),'fetch',str(path),str(root/'received.bin')],stdin=subprocess.DEVNULL,capture_output=True,timeout=10,env=dict(os.environ,IBSW_SCP_AUTH=json.dumps(cfg)))
                owner.verify()
            self.assertEqual(['sourceuser@192.0.2.254:'+str(path)],trace.read_text().splitlines())
            self.assertNotIn(b'SYNTHETIC_PARENT_SECRET',result.stdout+result.stderr)
            self.assertFalse(list(root.glob('.ibsw-scp-*')))
            return result.returncode,result.stdout+result.stderr

    def test_real_current_planner_parent_and_receiver_pty_matching_bytes(self):
        code,raw=self.workflow(False)
        self.assertEqual(0,code,raw)
        self.assertIn(b'IBSW_SCP_CONTENT_VERIFIED=',raw)

    def test_real_current_planner_parent_and_receiver_pty_same_size_wrong_bytes(self):
        code,raw=self.workflow(True)
        self.assertNotEqual(0,code)
        self.assertIn(b'IBSW_SCP_ERROR=CONTENT_MISMATCH',raw)


if __name__=='__main__':unittest.main()
