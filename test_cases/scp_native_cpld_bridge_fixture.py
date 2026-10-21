"""UNRUN mechanical native IO carrier; original workflow assertions retained.

Target queries/SSH-home remain synthetic; the optional bridge uses physical
owned switch files and original Bash with private executable stubs. Synthetic
package bytes are transferred, never actual firmware or device instructions.
"""

# Fixed canonical header; invoke has the explicitly reviewed bridge IO seams.
import unittest as _ibsw225_unittest
from test_cases.ibsw225_fixture_support.runtime_source_support import support as _ibsw225_support
_ibsw225_runtime = _ibsw225_support(_ibsw225_unittest.TestCase())
from test_cases.ibsw225_fixture_support.fixed_fixture_registry import install_fixed_fixtures as _ibsw225_install_fixed_fixtures
_ibsw225_fixed_fixture_modules = _ibsw225_install_fixed_fixtures()

import contextlib
import os
import csv
import io
import json
from pathlib import Path
import shlex
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
import time
from unittest.mock import patch

import test_upgrade_cli as fixtures
import test_known_hosts as trust
import test_manual_execution as manual
import test_nvos_observations as tables
import ibsw_upgrade_executor as executor
import ibsw_upgrade_observer as observer
import ibsw_upgrade_pipeline as pipeline

app,driver=fixtures.app,fixtures.driver
HOST='ew-spine01.example'
MISSING=b'nv set system config auto-save state enabled'
BACKUP=b'nv set system hostname ew-spine01.example\n'+MISSING+b'\n'


class ThreeComponentWorkflowTests(unittest.TestCase):
    def invoke(self,root,*,selection=(),fail=None,missing=False,inspect=False,old_os=True,bad_firmware=False,
               two=False,os_chain=False,delayed_exit=0,missing_exit=False,wrong_version=False,peer_final=False,
               parallel_barrier=False,bad_bios=False,drop_keys=False,bad_password=False,bad_initial_key=False,
               ssh_symlink=False,auth_drop=False,restore_fail=False,post_host_key=False,post_identity=False,
               reject_recheck=False,other_key_loss=False,extra_key_after=False,password_changes_after_os=False,
               access_close_failure=None,sftp_unavailable=False,auth_drop_after_restore=False,sdk_auth_drop=False,
               drop_keys_on_apply=False,initial_keys_missing=False,initial_other_keys=False,
               initial_ssh_missing=False,initial_identity_mismatch=False,initial_host_key=False,
               unlisted_os=False,first_final=False,unsafe_exit=False,controlled_grace=False,no_reboot=False,
               different_canaries=False,unplanned_downgrade=False,no_write_health_fail=False,
               ssd_version=None,ssd_actual='CE00A474',ssd_query_failure=False,
               wipe_remote_on_reboot=False,boot_changes_during_verify=False,
               nvued_states=None,completion_seconds=None,nvos_initializing=False,
               nvos_initializing_rounds=0,nvos_probe_error=None,firmware_at_target=False,
               os_branch_case=None,os_branch_hook=None,skip_canary=False,os_branch_drift=None,
               os_branch_fail_target=None,health_payloads=None,pre_boot_exit=None,download_telemetry=False,
               jitter_window=0,preboot_uid_timeout_once=False,password_prompt_attempts=1,pre_boot_log=None,
               download_ack_disappears=False,remote_hook=None,prewrite_query_timeout=None,bridge=None):
        project,home,known=fixtures.WorkflowTests().fixture(root)
        from test_access_recovery import install_pair
        install_pair(home)
        count=len(os_branch_case['currents']) if os_branch_case else 9 if parallel_barrier else 3 if different_canaries else 2
        if parallel_barrier or different_canaries or os_branch_case:
            with (project/'02-devices_config.csv').open('a',newline='') as handle:
                writer=csv.writer(handle)
                for number in range(3,count+1):
                    writer.writerow([f'ew-spine{number:02d}.example','ib','NA',f'192.0.2.{number}','24','192.0.2.254',
                                     f'02:00:00:00:00:{number:02x}']+['']*12)
        if two or parallel_barrier or different_canaries or os_branch_case:
            original=known.read_text()
            known.write_text(original+''.join(original.replace('192.0.2.1 ',f'192.0.2.{number} ') for number in range(2,count+1)))
        package_root=root/'packages'
        (package_root/'image').mkdir(parents=True)
        (package_root/'firmware').mkdir()
        text=tables.COMPLETE_GLOBAL.replace('        os:\n','        os:\n          sub_dir: image\n')
        text=text.replace('        bios:\n','        bios:\n          sub_dir: firmware\n')
        text=text.replace('        cpld:\n','        cpld:\n          sub_dir: firmware\n')
        if os_chain:
            text=text.replace('          - file: nvos-amd64-25.03.1010.bin',
                '          - file: nvos-amd64-25.02.9000.bin\n          - file: nvos-amd64-25.03.1010.bin')
        text=text.replace('http_root: /var/www/html','http_root: '+str(package_root))
        if ssd_version is not None:
            text+='        ssd:\n          version: '+json.dumps(ssd_version)+'\n'
        branch_versions=None
        if os_branch_case:
            import yaml
            doc=yaml.safe_load(text)
            ib=doc['switches'][0]['ib']; ib['version']='25.03.1014'
            priority=os_branch_case.get('priority',('25.02.8008','25.02.8010'))
            branch_versions=['25.02.7002',*priority,'25.03.1014']
            ib['upgrade']['packages']['os']['files']=[{'file':'nvosv25-02-7002amd64.bin'},
                {'alternatives':[{'file':'nvos-amd64-'+v+'.bin'} for v in priority]},
                {'file':'nvos-amd64-25.03.1014.bin'}]
            if os_branch_case.get('flat'):
                ib['upgrade']['packages']['os']['files']=[{'file':'nvosv25-02-7002amd64.bin'},
                    *[{'file':'nvos-amd64-'+v+'.bin'} for v in priority],
                    {'file':'nvos-amd64-25.03.1014.bin'}]
            text=yaml.safe_dump(doc,sort_keys=False)
        (project/'01-global.yaml').write_text(text)
        package_names=(tuple('nvos-amd64-'+v+'.bin' for v in os_branch_case['available']) if os_branch_case else
                       ('nvos-amd64-25.02.8008.bin','nvos-amd64-25.02.9000.bin','nvos-amd64-25.03.1010.bin'))
        for name in package_names:
            (package_root/'image'/name).write_bytes(b'SYNTHETIC-NOT-FIRMWARE')
        for name in ('0ACQF.cab',
            'FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme',
            'FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'):
            (package_root/'firmware'/name).write_bytes(b'SYNTHETIC-NOT-FIRMWARE')
        remote=manual.MemorySFTP()
        if bridge is not None: remote=bridge.remote(remote)
        remote.modes['/home/admin/.ssh']=stat.S_IFDIR|0o700
        remote.modes['/home/admin/.ssh/authorized_keys']=stat.S_IFREG|0o600
        remote.files['/home/admin/.ssh/authorized_keys']=trust.PUBLIC+b' synthetic-management\n'
        from test_access_recovery import public
        if initial_other_keys:
            remote.files['/home/admin/.ssh/authorized_keys']=public(2)
        if initial_keys_missing or initial_ssh_missing:
            remote.files.pop('/home/admin/.ssh/authorized_keys',None)
            remote.modes.pop('/home/admin/.ssh/authorized_keys',None)
        if initial_ssh_missing:
            remote.modes.pop('/home/admin/.ssh',None)
        if other_key_loss:
            remote.files['/home/admin/.ssh/authorized_keys']+=public(2)
        current={name:{'os':'25.02.8008' if old_os else '25.03.1010','bios':False,'cpld':False,
                       'config':BACKUP.replace(HOST.encode(),name.encode()),'pending':b''}
                 for name in (f'ew-spine{number:02d}.example' for number in range(1,count+1))}
        if firmware_at_target:
            for node in current.values(): node.update(bios=True,cpld=True)
        if os_branch_case:
            for number,version in enumerate(os_branch_case['currents'],1): current[f'ew-spine{number:02d}.example']['os']=version
        if different_canaries:
            current[HOST].update(bios=True,cpld=True)
            current['ew-spine02.example'].update(os='25.03.1010',cpld=True)
            current['ew-spine03.example'].update(os='25.03.1010',bios=True)
        if peer_final: current['ew-spine02.example']['os']='25.03.1010'
        if first_final: current[HOST]['os']='25.03.1010'
        if unlisted_os: current[HOST]['os']='25.01.9999'
        calls=[]
        self._ssd_query_context=[]
        virtual=SimpleNamespace(now=time.monotonic())
        boot_times={}
        ready_times={}
        service_times={}
        previous_commands={}
        nvued_counts={}
        self._nvued_checks=[]
        guarded=[]
        installs=[]
        self._download_ack_verified=False
        consumed_acks={}
        if download_ack_disappears:
            original_rename=remote.rename
            def consume_ack(old,new):
                original_rename(old,new)
                if new.endswith('/download-ack'):
                    consumed_acks[new]=remote.files.pop(new)
                    remote.modes.pop(new)
            remote.rename=consume_ack
        self._preboot_uid_timeouts=0
        download_waiting={}
        preboot_failures=set()
        def close_access():
            if access_close_failure=='backup' or (access_close_failure=='restore' and installs):
                raise OSError('SYNTHETIC SFTP cleanup failure')
        if access_close_failure:
            remote.close=close_access
        self._auth_attempts=[]
        delayed={}
        delayed_boot={}
        original_lstat=remote.lstat
        def lstat(path):
            if parallel_barrier and path.endswith('/owned-exit.record') and HOST not in path and len(installs)<6:
                # Canary is done, then five real workers must launch before the
                # first worker can finish. Serial execution cannot pass this.
                self.assertIsNone(delayed[path][1]._active_request_lease)
                raise FileNotFoundError(path)
            if path in delayed and delayed[path][0] > 0:
                remaining,scope=delayed[path]
                self.assertIsNone(scope._active_request_lease,'waiting for an installer must not hold the global journal transaction')
                delayed[path]=(remaining-1,scope)
                raise FileNotFoundError(path)
            if missing_exit and path.endswith('/owned-exit.record'):
                raise FileNotFoundError(path)
            return original_lstat(path)
        remote.lstat=lstat
        class Rejected(Exception): pass
        class ProtocolError(Exception): pass
        dropped=[False]
        def transport_factory(connection):
            name='ew-spine%02d.example'%int(connection.endpoint[0].rsplit('.',1)[1])
            def key_login(*a,**k):
                self._auth_attempts.append(('key',bool(installs)))
                if auth_drop_after_restore and installs and not dropped[0] and trust.PUBLIC in remote.files.get('/home/admin/.ssh/authorized_keys',b''):
                    dropped[0]=True
                    raise EOFError('SYNTHETIC connection lost during key-only recheck')
                if auth_drop and installs and not dropped[0]:
                    dropped[0]=True
                    raise EOFError('SYNTHETIC transport lost, not a rejected key')
                if sdk_auth_drop and installs and not dropped[0]:
                    dropped[0]=True
                    raise Rejected('Authentication failed: transport shut down or saw EOF')
                if bad_initial_key or (reject_recheck and installs) or trust.PUBLIC not in remote.files.get('/home/admin/.ssh/authorized_keys',b''):
                    raise Rejected('Authentication failed.')
            def password_login(*a,**k):
                self._auth_attempts.append(('password',bool(installs)))
                if (bad_password and name==HOST) or (password_changes_after_os and installs):
                    raise Rejected('Authentication failed.')
            return SimpleNamespace(start_client=lambda **k:None,
                get_remote_server_key=lambda:SimpleNamespace(asbytes=lambda:b'OTHER-HOST' if initial_host_key or (post_host_key and installs) else trust.WIRE),
                auth_password=password_login,auth_publickey=key_login,is_authenticated=lambda:True,
                is_active=lambda:True,
                get_username=lambda:'admin',close=lambda:None,
                **({'open_session':bridge.open_channel} if bridge is not None else {}))
        def open_sftp(transport):
            if sftp_unavailable:
                raise OSError('SYNTHETIC SFTP unavailable')
            return remote
        if remote_hook: remote_hook(remote)
        sdk=SimpleNamespace(Transport=transport_factory,SFTPClient=SimpleNamespace(from_transport=open_sftp),
                            AuthenticationException=Rejected,SSHException=ProtocolError)
        def sock(*a,**k):
            connection=SimpleNamespace(settimeout=lambda value:None,close=lambda:None)
            connection.connect=lambda endpoint:setattr(connection,'endpoint',endpoint)
            return connection
        if restore_fail:
            def failed_rename(*a): raise OSError('SYNTHETIC failed replacement')
            remote.rename=failed_rename
        def query(leaf,transport,command,deadline):
            name=leaf.node.hostname
            node=current[name]
            calls.append((name,command))
            if bridge is not None and command.startswith(('/usr/bin/python3 -c ', '/usr/bin/nohup ')):
                return bridge.query(leaf,transport,command,deadline)
            if (prewrite_query_timeout==command and getattr(leaf.scope,'_native_schedule_started',False)
                    and not installs):
                leaf._last_query_diagnostic=dict(command=command,reason_code='READONLY_QUERY_TIMEOUT',
                    budget_seconds=25.0,elapsed_seconds=25.1)
                return b'',b'',None,False
            if os_branch_hook: os_branch_hook(root,name,command,installs)
            if (os_branch_drift and name in os_branch_drift and command=='nv show system version'
                    and getattr(leaf,'_cooperative_completion',False)):
                node['os']=os_branch_drift.pop(name)
            previous=previous_commands.get(name)
            previous_commands[name]=command
            cli_probe=(command=='nv show system version' and previous==
                'systemctl show nvued.service --property=ActiveState --property=SubState --no-pager')
            generation=sum(n==name for n,c,v in installs)
            if controlled_grace and generation:
                key=(name,generation)
                if command==pipeline._BOOT_COMMAND:
                    boot_times.setdefault(key,pipeline._now())
                elif command in ('nv show system version','nv show platform firmware',
                                  'nv config show -o commands','nv config diff -o commands','nv show system health'):
                    self._grace_latest=(key,command,pipeline._now(),boot_times.get(key))
                    self.assertIn(key,boot_times,'business queries require post-boot authentication first')
                    required=service_times if cli_probe else ready_times
                    self.assertIn(key,required,'NVUE business queries require parsed CLI readiness on this boot')
                    self.assertGreaterEqual(pipeline._now(),required[key])
                    guarded.append((key,command,required[key],pipeline._now()))
            if command==observer._IDENTITY_COMMAND:
                payload=(('wrong-host' if initial_identity_mismatch or (post_identity and installs) else name)+'\n'+leaf.node.mac+'\n').encode()
            elif command=='nv show system version':
                if cli_probe and nvos_probe_error is not None:
                    return nvos_probe_error
                if (generation and getattr(leaf,'_cooperative_completion',False) and
                        (nvos_initializing or (cli_probe and nvued_counts[(name,generation)]<=nvos_initializing_rounds))):
                    return b'',b'Error: NVOS CLI is unavailable\nSystem is initializing!\nThis may take a few minutes\n',1,True
                if unplanned_downgrade and getattr(leaf.scope,'_native_schedule_started',False):
                    node['os']='25.02.8008'
                payload=fixtures.OS_TABLE.replace(b'25.03.1010',node['os'].encode())
                if cli_probe:
                    ready_times[(name,generation)]=pipeline._now()
            elif command=='nv show platform firmware':
                if ssd_version is not None:
                    import threading
                    self._ssd_query_context.append(dict(hostname=name,os=node['os'],
                        postcheck=bool(getattr(leaf,'_cooperative_completion',False)),
                        thread=threading.current_thread().name))
                    if ssd_query_failure and getattr(leaf,'_cooperative_completion',False):
                        return b'',b'PRIVATE_SSD_QUERY_ERROR',1,True
                if bad_firmware:
                    return b'',b'UNSELECTED-FIRMWARE-QUERY-FAILED',1,True
                payload=tables.FW
                if ssd_version is not None:
                    payload=payload.replace(b'CE00A400',ssd_actual.encode())
                if not node['bios']: payload=payload.replace(b'0ACQF_06.01.009',b'0ACQF_06.01.008')
                if bad_bios: payload=payload.replace(b'0ACQF_06.01.008',b'N/A'.ljust(15))
                if not node['cpld']:
                    payload=payload.replace(b'CPLD000232_REV0900',b'CPLD000232_REV0800')
                    payload=payload.replace(b'CPLD000383_REV0800',b'CPLD000383_REV0700')
                    payload=payload.replace(b'CPLD000389_REV0600',b'CPLD000389_REV0500')
            elif command=='nv config show -o commands': payload=node['config']
            elif command=='nv config diff -o commands': payload=node['pending']
            elif command=='nv show system health':
                payload=manual.HEALTH
                if health_payloads:
                    stage=('after_install' if generation else 'before_install'
                           if getattr(leaf.scope,'_native_schedule_started',False) else 'startup')
                    payload=health_payloads.get((name,stage),payload)
                    if type(payload) is tuple: return payload
                if no_write_health_fail and name==HOST and calls.count((name,command))>=2:
                    payload=manual.HEALTH.replace(b'OK',b'FAIL')
            elif command=='id -u':
                if preboot_uid_timeout_once and download_waiting and not self._preboot_uid_timeouts:
                    self._preboot_uid_timeouts+=1
                    leaf._last_query_diagnostic=dict(command='id -u',reason_code='READONLY_QUERY_TIMEOUT',elapsed_seconds=25.0)
                    return b'',b'',None,False
                payload=(str(os.geteuid()).encode()+b'\n') if bridge is not None else b'1000\n'
            elif command=='systemctl show nvued.service --property=ActiveState --property=SubState --no-pager':
                key=(name,generation)
                number=nvued_counts.get(key,0)
                states=nvued_states or [('active','running')]
                active,sub=states[min(number,len(states)-1)]
                nvued_counts[key]=number+1
                self._nvued_checks.append(dict(hostname=name,generation=generation,attempt=number+1,
                    at=pipeline._now(),active=active,sub=sub,installs=len(installs)))
                if (active,sub)==('active','running'):
                    service_times[key]=pipeline._now()
                payload=f'ActiveState={active}\nSubState={sub}\n'.encode()
            elif command==pipeline._BOOT_COMMAND:
                number=1 if no_reboot else 1+sum(n==name for n,c,v in installs)-int(name in preboot_failures)
                if not no_reboot and name in delayed_boot:
                    exit_path,previous_boot=delayed_boot[name]
                    if delayed[exit_path][0]>0:
                        number=previous_boot
                if name in download_waiting:
                    private,local=download_waiting[name]
                    ack=remote.files.get(private+'/download-ack',consumed_acks.get(private+'/download-ack'))
                    if ack is None:
                        number=1
                    else:
                        from ibsw_upgrade_component import download_ack_bytes
                        from test_os_download_telemetry import LINE
                        self.assertEqual(ack,download_ack_bytes(leaf.scope.run_directory.name,LINE.rstrip(b'\n')))
                        saved=json.loads((local/'download-attempt-01.json').read_text())
                        self.assertEqual(saved['measurement']['bytes_downloaded'],2966461709)
                        self._download_ack_verified=True
                        del download_waiting[name]
                        if wipe_remote_on_reboot:
                            for path in tuple(remote.modes):
                                if '/.ibsw-' in path:
                                    remote.files.pop(path,None); remote.modes.pop(path,None)
                if parallel_barrier and name!=HOST and number>1 and len(installs)<6:
                    number=1  # Wait for five actual peer dispatches, not a remote exit file.
                if (boot_changes_during_verify and number>1
                        and calls.count((name,command))>=5):
                    number+=1
                payload=(f'00000000-0000-0000-0000-{number:012x}\n').encode()
            elif command=='id -u; getent passwd "$(id -u)"':
                payload=(f'{os.geteuid()}\nadmin:x:{os.geteuid()}:{os.getegid()}:Admin:/home/admin:/bin/bash\n'.encode() if bridge is not None else b'1000\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\n')
            elif command==executor._CAPABILITY_COMMAND: payload=b''
            elif command.startswith('/usr/bin/nohup '):
                private=str(Path(shlex.split(command)[2]).parent)
                previous_boot=(1+sum(n==name for n,c,v in installs)-int(name in preboot_failures)
                               if delayed_exit>0 else None)
                script=remote.files[private+'/step.sh'].decode()
                declaration=next(line.split('=',1)[1] for line in script.splitlines() if line.startswith('IBSW_BINDING_JSON='))
                binding=json.loads(shlex.split(declaration)[0])
                run_id,hostname,address,mac,component,target=binding
                stage=(('os-'+format(branch_versions.index(target),'04d')) if branch_versions else
                       ('os-0002' if os_chain and target=='25.03.1010' else 'os-0001')) if component=='os' else component
                local=leaf.scope.run_directory/name/stage
                self.assertEqual((local/'before.commands').read_bytes(),node['config'])
                self.assertTrue((local/'request.json').is_file(),'backup and request must precede the one launch')
                step=json.loads((local/'step-binding.json').read_text())
                child_exit=7 if fail==(name,component) or (component=='os' and os_branch_fail_target==(name,target)) else 0
                preboot_code=(pre_boot_exit.get((name,component,target))
                              if isinstance(pre_boot_exit,dict) else pre_boot_exit)
                if preboot_code is not None: child_exit=preboot_code
                effect='POWER_CYCLE_EXPECTED' if component=='cpld' else 'REBOOT_EXPECTED'
                remote.files[private+'/execution.stdout']=(json.dumps(binding,separators=(',',':'))+'\n'
                    +f'IBSW_EXECUTION_RC={child_exit} IBSW_ACTIVATION_STATE=UNKNOWN\nIBSW_EXPECTED_EFFECT={effect}\n').encode()
                remote.files[private+'/execution.stderr']=b''
                if download_telemetry and component=='os':
                    from test_os_download_telemetry import LINE
                    remote.files[private+'/execution.stdout']=(json.dumps(binding,separators=(',',':'))+'\n').encode()+LINE+b'IBSW_STAGE=WAIT_DOWNLOAD_RECORD\n'
                    download_waiting[name]=(private,local)
                if preboot_code is not None:
                    preboot_failures.add(name)
                    header=(json.dumps(binding,separators=(',',':'))+'\n').encode()
                    footer=f'IBSW_EXECUTION_RC={child_exit} IBSW_ACTIVATION_STATE=UNKNOWN\n'.encode()
                    remote.files[private+'/execution.stdout']=header+(pre_boot_log or b'IBSW_STAGE=PACKAGE_DOWNLOAD\n')+footer
                    remote.files[private+'/execution.stderr']=b'curl: (22) The requested URL returned error: 404\n'
                remote.files[private+'/owned-exit.record']=('\n'.join(['IBSW_OWNED_EXIT_V1',run_id,hostname,component,stage,step['script_sha256'],str(child_exit)])+'\n').encode()
                remote.modes[private+'/owned-exit.record']=stat.S_IFREG|0o600
                if unsafe_exit: remote.modes[private+'/owned-exit.record']=stat.S_IFREG|0o644
                delayed[private+'/owned-exit.record']=(delayed_exit,leaf.scope)
                if delayed_exit>0:
                    # Keep this hop on its original boot until the original
                    # lstat closure really consumes each delayed missing read.
                    delayed_boot[name]=(private+'/owned-exit.record',previous_boot)
                installs.append((name,component,target))
                if child_exit==0:
                    if component=='os':
                        if not wrong_version: node['os']=target
                    else: node[component]=True
                if drop_keys:
                    remote.files.pop('/home/admin/.ssh/authorized_keys',None)
                    remote.modes.pop('/home/admin/.ssh/authorized_keys',None)
                if other_key_loss:
                    remote.files['/home/admin/.ssh/authorized_keys']=trust.PUBLIC+b' synthetic-management\n'
                if extra_key_after:
                    remote.files['/home/admin/.ssh/authorized_keys']=public(3)
                    remote.modes['/home/admin/.ssh/authorized_keys']=stat.S_IFREG|0o600
                if ssh_symlink:
                    remote.modes['/home/admin/.ssh']=stat.S_IFLNK|0o777
                if wipe_remote_on_reboot and not download_telemetry:
                    for path in tuple(remote.files):
                        if '/.ibsw-' in path:
                            remote.files.pop(path,None)
                            remote.modes.pop(path,None)
                    for path in tuple(remote.modes):
                        if '/.ibsw-' in path:
                            remote.modes.pop(path,None)
                if missing: node['config']=node['config'].replace(MISSING+b'\n',b'')
                payload=b'IBSW_LAUNCH_REQUESTED\n'
            elif command.startswith('nv config patch '):
                node['pending']=remote.files[shlex.split(command)[-1]]; payload=b''
            elif command=='nv config apply -y':
                node['config']+=node['pending']; node['pending']=b''; payload=b''
                if drop_keys_on_apply:
                    remote.files.pop('/home/admin/.ssh/authorized_keys',None)
                    remote.modes.pop('/home/admin/.ssh/authorized_keys',None)
            elif command=='nv config save': payload=b''
            else: raise AssertionError('Unexpected remote operation: '+command)
            return payload,b'',0,True
        class FakeTCP:
            def __init__(self): self.events=[]; self.pending={}
            def request(self,job): self.events.append((job,True))
            def poll(self): result,self.events=self.events,[]; return result
            def close(self): pass
        def controlled_idle(seconds):
            # Optional TEST OWNER cancellation at the pre-existing controlled
            # clock IO seam. Absent/unarmed callback preserves the old exact
            # setattr advance. Never alter manager/timeout/production _idle.
            before_idle = getattr(bridge, 'before_idle', None) if bridge is not None else None
            if before_idle is not None:
                before_idle()
            return setattr(virtual,'now',virtual.now+seconds)
        with manual.ManualTests().no_deployment_or_filesystem_locks(), \
             patch.object(Path,'home',return_value=home),patch.object(app,'_check_runtime'), \
             patch.object(app,'_read_password',return_value='SYNTHETIC') as password_prompt, \
             patch.object(socket,'socket',side_effect=sock), \
             patch.object(observer,'_fixed_sdk',return_value=sdk),patch.object(executor,'_fixed_sdk',return_value=sdk), \
             patch.object(observer,'_original_private_key',return_value=object()), \
             patch.object(observer,'_COMPLETION_SECONDS',completion_seconds if completion_seconds is not None else
                          0.3 if no_reboot else 60 if parallel_barrier else 1800,create=True), \
             patch.object(pipeline,'ParentTCPProbes',FakeTCP), \
             patch.object(pipeline,'_now',(lambda:virtual.now) if controlled_grace else pipeline._now), \
             patch.object(pipeline,'_idle',controlled_idle if controlled_grace else pipeline._idle), \
             patch.object(pipeline,'_OS_DOWNLOAD_OBSERVATION_SECONDS',0 if no_reboot or completion_seconds is not None else 2715), \
             patch.object(observer,'_read_channel',side_effect=query),patch.object(executor,'_read_channel',side_effect=query), \
             contextlib.redirect_stdout(io.StringIO()) as out,contextlib.redirect_stderr(io.StringIO()) as err:
            code=app.main(['--project',str(project),'--devices','ew-spine*' if two or parallel_barrier or different_canaries or (os_branch_case and count>1) else HOST,
                '--method','scp','--package-dir',str(package_root),
                *(['--local-dir',str(bridge.switch)] if bridge is not None else []),
                '--mgmt-server','198.51.100.44','--mgmt-user','source_test',
                '--mgmt-port','2222','--scp-known-hosts',str(root/'scp-source-known_hosts'),
                *([] if jitter_window is None else ['--os-download-jitter',str(jitter_window)]),*selection,
                *(['--inspect-only'] if inspect else ['--upgrade','--yes']),
                *(['--skip-canary'] if skip_canary else [])])
        self.assertEqual(password_prompt.call_count,0 if inspect else password_prompt_attempts)
        self._last_access_snapshot=remote.files.get('/home/admin/.ssh/authorized_keys',b'')
        self._grace_guarded_queries=guarded
        return code,json.loads(out.getvalue()) if out.getvalue() else {},err.getvalue(),calls,installs
