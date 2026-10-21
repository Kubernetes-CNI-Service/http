"""UNRUN one protocol whole; request/companion bindings are synthetic DATA."""
import importlib
import json
from pathlib import Path
import unittest

from test_cases import test_ibsw3_scp_source_binding as SOURCE
from test_cases import scp_stdin_cpld_protocol_fixture as FIXTURE


class ScpStdinOwnedCpldProtocolTests(unittest.TestCase):
    def test_fixed_stdin_launcher_carries_one_context_to_two_pulls_without_secret_exports(self):
        provider=SOURCE.ScpSourceBindingTests().module()
        generate=getattr(provider,'_stdin_launch_command',None)
        self.assertTrue(callable(generate),
            'MISSING_STDIN_LAUNCHER_CAPABILITY; CPLD/helper/native dispatch NOT_REACHED')
        import inspect
        self.assertEqual(('remote','runner_sha256','step_sha256'),tuple(inspect.signature(generate).parameters))
        component=importlib.import_module('ibsw_upgrade_component')
        contract=importlib.import_module('ibsw_upgrade_contract')
        executor=importlib.import_module('ibsw_upgrade_executor')
        for case in ('healthy','second_fail','wrong_bytes','empty_frame','two_frames','oversize','missing_eof'):
            with self.subTest(case=case):
                tree=FIXTURE.OwnedProtocolTree()
                try:
                    original=FIXTURE.artifacts(tree.root,component,contract,executor,case)
                    self.assertEqual({'host','user','port','host_keys','password','paths','timeout_seconds','content_binding'},set(original['context']))
                    self.assertEqual({'version','binding_sha256','request_id','request_sha256','companion_sha256','packages'},set(original['context']['content_binding']))
                    self.assertEqual('44444444444444444444444444444444',original['context']['content_binding']['request_id'])
                    self.assertEqual(300,original['context']['timeout_seconds'],'firmware helper budget, not a probe default')
                    command=generate(str(original['step']),original['runner_sha'],original['step_sha'])
                    frame=original['frame']
                    if case=='empty_frame':frame=b''
                    elif case=='two_frames':frame+=b'{}\n'
                    elif case=='oversize':frame=b'x'*65536+b'\n'
                    result,out,err=FIXTURE.run_fixed_command(tree.root,command,frame,
                        original['context'],case=='missing_eof')
                    framesafe=case in ('healthy','second_fail','wrong_bytes')
                    self.assertEqual([True] if framesafe else [],result['stdin_closed'])
                    if framesafe:
                        self.assertEqual(0,result['launch'],'only delivery, not child success')
                        self.assertIn(b'IBSW_LAUNCH_REQUESTED',out)
                        self.assertEqual(1,len(result['codes']))
                        owned=(original['remote']/'owned-exit.record').read_text().splitlines()
                        self.assertEqual(['IBSW_OWNED_EXIT_V1',FIXTURE.RUN,'ib.example.test','cpld','cpld',original['step_sha']],owned[:6])
                        self.assertEqual(7,len(owned))
                        self.assertEqual(result['codes'][0],int(owned[6]))
                        pulls=[json.loads(x) for x in original['scp_trace'].read_text().splitlines()]
                        self.assertEqual(['source_test@198.51.100.44:'+FIXTURE.BURN,
                                          'source_test@198.51.100.44:'+FIXTURE.REFRESH],pulls)
                        if case=='healthy':
                            self.assertEqual([93],result['codes'])
                            nv=[json.loads(x) for x in original['nv_trace'].read_text().splitlines()]
                            self.assertEqual([['action','fetch','platform','firmware','CPLD1',
                                'file://'+str(original['switch']/Path(FIXTURE.BURN).name)]],nv)
                        else:
                            self.assertNotEqual(0,result['codes'][0])
                            self.assertFalse(original['nv_trace'].exists(),'second pull/content refusal precedes EVERY NV')
                    else:
                        self.assertNotEqual(0,result['launch'])
                        self.assertEqual([],result['codes'],'invalid frame must refuse BEFORE actual runner Popen')
                        self.assertNotIn(b'IBSW_LAUNCH_REQUESTED',out)
                        self.assertFalse(original['scp_trace'].exists())
                        self.assertFalse(original['nv_trace'].exists())
                        self.assertFalse((original['remote']/'owned-exit.record').exists())
                    combined=out+err+b''.join((original['remote']/name).read_bytes()
                                             for name in ('execution.stdout','execution.stderr'))
                    self.assertNotIn(FIXTURE.SECRET.encode(),combined)
                    for marker in (b'IBSW_COMPONENT_STAGE=BURN_REQUESTED',b'IBSW_COMPONENT_STAGE=REFRESH_REQUESTED',b'IBSW_STAGE=INSTALL_REQUESTED'):
                        self.assertNotIn(marker,combined)
                    for path in tree.root.rglob('*'):
                        if path.is_file():self.assertNotIn(FIXTURE.SECRET.encode(),path.read_bytes())
                    self.assertEqual([],list(tree.root.rglob('.ibsw-scp-*')),'fixed helper synchronous cleanup')
                    tree.safe=True  # Actual retained runner Popen waited; helper completed before child exit.
                finally:
                    tree.finish()
