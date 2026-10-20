"""Canonical SCP source/receiver contracts, not upgrade execution authority.

Source factory -> real endpoint and SSH-key parsers is a three-script workflow.
Helper/PTY controls replace only external executable paths with private stubs.
The main HTTP-only entry is deliberately NOT relaxed by this library slice.
"""
import base64
import importlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'tools/ibsw_upgrade_scp.py'
ABC_SHA='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
PACKAGE='/srv/ib-upgrade/image/literal-test.bin'


class ScpSourceBindingTests(unittest.TestCase):
    def module(self):
        self.assertTrue(SOURCE.is_file(),'new canonical SCP source/receiver module is not landed')
        if str(ROOT/'tools') not in sys.path:sys.path.insert(0,str(ROOT/'tools'))
        module=importlib.import_module('ibsw_upgrade_scp')
        self.assertEqual(SOURCE,module.__file__ and Path(module.__file__).resolve())
        return module

    def source(self,root,module):
        wire=struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+b'z'*32
        trust=root/'known_hosts'
        trust.write_bytes(b'192.0.2.254 ssh-ed25519 '+base64.b64encode(wire)+b'\n')
        trust.chmod(0o600)
        return trust,module.source_from_known_hosts('192.0.2.254','sourceuser',22,trust,'SYNTHETIC_ONLY')

    def test_real_source_factory_key_and_endpoint_workflow_keeps_original_trust(self):
        module=self.module()
        with tempfile.TemporaryDirectory(prefix='http-scp-source-') as name:
            trust,source=self.source(Path(name),module)
            source.verify()
            self.assertEqual('scp',source.public_document()['method'])
            self.assertNotIn('SYNTHETIC_ONLY',json.dumps(source.public_document()))
            before=source.host_keys
            trust.write_bytes(trust.read_bytes().replace(b'192.0.2.254',b'192.0.2.253'))
            with self.assertRaises(module.ScpHold):source.verify()
            self.assertEqual(before,source.host_keys,'never refresh a changed baseline')

    def test_size_only_execution_payload_is_rejected_without_fake_owner(self):
        module=self.module()
        with tempfile.TemporaryDirectory(prefix='http-scp-wire-') as name:
            _,source=self.source(Path(name),module)
            with self.assertRaises(module.ScpHold) as held:
                module.launch_payload(source,((PACKAGE,3),))
            self.assertEqual('SCP_CONTENT_BINDING_REQUIRED',held.exception.reason_code)

    def test_unintegrated_source_preflight_has_no_device_or_auth_side_effect(self):
        module=self.module()
        failure=None
        try:
            module.preflight_source(object(),object(),0,object())
        except Exception as error:
            failure=error
        self.assertIsInstance(failure,module.ScpHold)
        self.assertEqual('SCP_CONTENT_BINDING_REQUIRED',failure.reason_code)

    def receiver(self,*,wrong=False,missing=False):
        module=self.module()
        with tempfile.TemporaryDirectory(prefix='http-scp-receiver-') as name:
            root=Path(name).resolve();trace=root/'pulls'
            external=root/'private-scp.py'
            external.write_text('#!'+sys.executable+'\nimport os,sys\n'
                'a=sys.argv[1:]\nassert "-O" in a and "StrictHostKeyChecking=yes" in a\n'
                'assert "IBSW_SCP_AUTH" not in os.environ\n'
                'sys.stderr.write("source password:");sys.stderr.flush()\n'
                'assert input()=="SYNTHETIC_ONLY"\n'
                'with open('+repr(str(trace))+',"a") as f:f.write(a[-2]+"\\n")\n'
                'with open(a[-1],"wb") as f:f.write('+repr(b'xyz' if wrong else b'abc')+')\n')
            external.chmod(0o700)
            helper=module.remote_helper_bytes().decode()
            helper=helper.replace("SSH = '/usr/bin/ssh'",'SSH = '+repr(str(external)))
            helper=helper.replace("SCP = '/usr/bin/scp'",'SCP = '+repr(str(external)))
            program=root/'helper.py';program.write_text(helper)
            context=dict(host='192.0.2.254',user='sourceuser',port=22,host_keys='synthetic private stub\n',
                password='SYNTHETIC_ONLY',paths={PACKAGE:3},timeout_seconds=3)
            if not missing:
                context['content_binding']=dict(version=1,binding_sha256='1'*64,
                    packages={PACKAGE:dict(size=3,sha256=ABC_SHA)})
            observed=subprocess.run(['/usr/bin/python3','-B',str(program),'fetch',PACKAGE,str(root/'image')],
                stdin=subprocess.DEVNULL,capture_output=True,timeout=10,
                env=dict(os.environ,IBSW_SCP_AUTH=json.dumps(context)))
            raw=observed.stdout+observed.stderr
            self.assertNotIn(b'SYNTHETIC_ONLY',raw)
            self.assertFalse(list(root.glob('.ibsw-scp-*')))
            pulls=trace.read_text().splitlines() if trace.exists() else []
            image=(root/'image').read_bytes() if (root/'image').exists() else None
            return observed.returncode,raw,pulls,image

    def test_receiver_healthy_exact_envelope_and_literal_bytes(self):
        code,raw,pulls,image=self.receiver()
        self.assertEqual(0,code,raw)
        self.assertEqual(['sourceuser@192.0.2.254:'+PACKAGE],pulls)
        self.assertEqual(b'abc',image)
        self.assertIn(b'IBSW_SCP_CONTENT_VERIFIED=1|',raw)

    def test_receiver_same_size_wrong_bytes_are_not_success(self):
        code,raw,pulls,image=self.receiver(wrong=True)
        self.assertEqual(['sourceuser@192.0.2.254:'+PACKAGE],pulls)
        self.assertEqual(b'xyz',image)
        self.assertNotEqual(0,code)
        self.assertIn(b'IBSW_SCP_ERROR=CONTENT_MISMATCH',raw)
        self.assertNotIn(b'IBSW_SCP_CONTENT_VERIFIED=',raw)

    def test_receiver_missing_digest_is_controlled_hold_before_pull(self):
        code,raw,pulls,image=self.receiver(missing=True)
        self.assertNotEqual(0,code)
        self.assertEqual([],pulls)
        self.assertIsNone(image)
        self.assertIn(b'IBSW_SCP_ERROR=CONTENT_CONTEXT_INVALID',raw)
        self.assertNotIn(b'Traceback',raw)
