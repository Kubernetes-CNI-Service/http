"""Independent CPLD dual-original request DATA contract; not native/ACK."""
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import stat
import subprocess
import time
import unittest
from unittest.mock import patch

from test_cases import test_ibsw3_scp_stage_scope as BASE
from test_cases.ibsw3_scp_cpld_test_isolation import isolated_whole

driver=BASE.driver
NAME='scp-source-request.json'
ORIGINALS=('request.json','step.sh','step-binding.json','runner.sh','runner-binding.json')
BURN='FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'
REFRESH='FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'

class ScpCpldRequestSourcesTests(unittest.TestCase):
    def capabilities(self):
        for name in ('freeze_scp_package_sources','_capture_scp_request_content_locked'):
            self.assertTrue(callable(getattr(driver._PreparedRunScope,name,None)),
                            'MISSING_SCP_CPLD_SOURCE_CAPABILITY_NOT_AN_EXPLOIT: '+name)

    @contextlib.contextmanager
    def graph(self):
        import yaml
        fixture=BASE.StagePackageSourceBoundaryV3Tests()
        manual=BASE.manual.ManualTests()
        with fixture.owned_tree() as raw:
            root=Path(raw)
            project,home,known,logs=manual.fixture(root)
            path=project/'01-global.yaml'
            document=yaml.safe_load(path.read_text())
            document['switches'][0]['ib']['upgrade']['packages']['cpld']={
                'burn':{'file':BURN},'refresh':{'file':REFRESH}}
            path.write_text(yaml.safe_dump(document,sort_keys=False))
            packages=root/'packages';packages.mkdir(mode=0o700)
            burn,refresh=packages/BURN,packages/REFRESH
            burn.write_bytes(b'abc');refresh.write_bytes(b'defg')
            burn.chmod(0o600);refresh.chmod(0o600)
            # Unselected, deliberately empty source must never be opened/hashed.
            (packages/'unselected.bin').write_bytes(b'')
            args=('--project',str(project),'--standalone-inputs','--cpld-only',
                  '--method','scp','--yes','--package-dir',str(packages))
            with manual.no_deployment_or_filesystem_locks(), \
                 patch.object(subprocess,'Popen',side_effect=AssertionError('no native process')), \
                 patch.object(socket,'create_connection',side_effect=AssertionError('no network')):
                prepared=driver.prepare_manual_run(BASE.app.__file__,str(project),args)
                with driver.open_manual_run(BASE.app.__file__,str(project),args,prepared['run_directory']) as parent:
                    owner=parent.freeze_scp_package_sources((('cpld',0),),
                        deadline=time.monotonic()+8,max_fds=64)
                    self.assertEqual({burn,refresh},set(owner._files))
                    with parent.fork_readiness_scope(BASE.HOST) as child:
                        child.prepare_requested_step(BASE.HOST,'cpld',0)
                        child.request_prepared_step(BASE.HOST,'cpld',0)
                        with child.open_readonly_query_inputs(BASE.HOST,known_hosts_path=str(known),
                                identity_path=None,management_public_path=None,user='admin') as leaf:
                            remote=(child.parsed.switch_dir+'/.ibsw-'+child.run_id+'-'
                                    +BASE.HOST+'-cpld-'+'1'*32+'/step.sh')
                            child.prepare_owned_runner_data(leaf,'cpld',0,remote_script=remote)
                            stage=child.session._directory(child.run_directory/BASE.HOST/'cpld')
                            held={name:child._hold(stage,name) for name in ORIGINALS}
                            yield parent,child,leaf,owner,burn,refresh,stage,held
                # Actual parent/child owners closed; retained fixture still lives.
                if hasattr(self,'cold_path'):
                    self.cold_bytes=self.cold_path.read_bytes()

    @isolated_whole
    def test_real_cpld_two_needed_originals_bind_once_and_remain_cold_data_only(self):
        self.capabilities()
        with self.graph() as (parent,child,leaf,owner,burn,refresh,stage,held):
            original_rows={name:(obj,obj.fd,obj.payload) for name,obj in held.items()}
            self.assertIs(owner,parent._package_source_owner)
            self.assertIs(owner,child._package_source_owner)
            before={p:(row[0],row[4]) for p,row in owner._files.items()}
            expected=dict(schema_version=2,state='SCP_REQUEST_CONTENT_DATA_ONLY',
                execution_state='NOT_EXECUTED',activation_state='UNKNOWN',declared_method='scp',
                binding=json.loads(held['step-binding.json'].payload),
                request_id=json.loads(held['request.json'].payload)['request_id'],
                originals_sha256={name:hashlib.sha256(obj.payload).hexdigest() for name,obj in held.items()},
                packages={str(burn):dict(size=3,sha256=hashlib.sha256(b'abc').hexdigest()),
                          str(refresh):dict(size=4,sha256=hashlib.sha256(b'defg').hexdigest())})
            keys={(p.stat().st_dev,p.stat().st_ino,stat.S_IFMT(p.stat().st_mode))
                  for p in (burn,refresh)}
            real_read=driver.os.read
            def reading(fd,count):
                info=driver.os.fstat(fd)
                self.assertNotIn((info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)),keys,
                                 'no repeated package hash/read')
                return real_read(fd,count)
            with patch.object(driver.os,'read',reading):
                with child._request_namespace_lease():
                    self.assertIsNone(child._capture_scp_request_content_locked(leaf,'cpld',0))
                with child._request_namespace_lease():
                    self.assertIsNone(child._capture_scp_request_content_locked(leaf,'cpld',0))
            record=child._hold(stage,NAME)
            self.assertEqual(expected,json.loads(record.payload))
            self.assertEqual(before,{p:(row[0],row[4]) for p,row in owner._files.items()})
            for name,(obj,fd,payload) in original_rows.items():
                self.assertIs(obj,child._hold(stage,name))
                self.assertEqual((fd,payload),(obj.fd,obj.payload))
            self.assertFalse((stage.path/'package-source.json').exists())
            self.assertFalse((stage.path/'component-dispatch.json').exists())
            self.assertFalse((stage.path/'download-ack').exists())
            self.assertEqual('UNKNOWN',child.inspect_step(BASE.HOST,'cpld',0)['state'])
            self.cold_path=stage.path/NAME
            payload=record.payload
        self.assertEqual(payload,self.cold_bytes)
        with self.assertRaises(ValueError):
            owner.verify()

    @isolated_whole
    def test_second_cpld_original_drift_revokes_group_without_companion_or_ack(self):
        self.capabilities()
        errors={}
        try:
            with self.graph() as (parent,child,leaf,owner,burn,refresh,stage,held):
                originals={name:(obj,obj.fd,obj.payload) for name,obj in held.items()}
                refresh.write_bytes(b'changed second original')
                def capture():
                    with child._request_namespace_lease():
                        child._capture_scp_request_content_locked(leaf,'cpld',0)
                for label,operation in (('capture',capture),('parent',parent.verify),
                        ('child',child.verify),('retry',capture),
                        ('new-borrow',lambda:parent.fork_readiness_scope(BASE.HOST))):
                    try:
                        operation()
                    except Exception as error:
                        errors[label]=error
                self.assertFalse((stage.path/NAME).exists())
                self.assertFalse((stage.path/'component-dispatch.json').exists())
                self.assertFalse((stage.path/'download-ack').exists())
                for name,(obj,fd,payload) in originals.items():
                    self.assertIs(obj,child.files[(str(stage.path),name)])
                    self.assertEqual((fd,payload),(obj.fd,obj.payload))
        except Exception as error:
            errors['cleanup']=error
        self.assertEqual({'capture','parent','child','retry','new-borrow','cleanup'},set(errors))
