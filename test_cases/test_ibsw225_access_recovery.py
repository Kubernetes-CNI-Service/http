"""Access preservation contract. No network, real passwords or device writes."""

# NEW canonical test-header binding; original named bodies below are unchanged.
import unittest as _ibsw225_unittest
from test_cases.ibsw225_fixture_support.runtime_source_support import support as _ibsw225_support
_ibsw225_runtime = _ibsw225_support(_ibsw225_unittest.TestCase())
from test_cases.ibsw225_fixture_support.fixed_fixture_registry import install_fixed_fixtures as _ibsw225_install_fixed_fixtures
_ibsw225_fixed_fixture_modules = _ibsw225_install_fixed_fixtures()

import base64
import contextlib
import io
import json
from pathlib import Path
import stat
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import test_upgrade_cli as fixtures
import test_known_hosts as trust
import test_three_component_workflow as workflow


def install_pair(home):
    key = home / '.ssh/id_ed25519'
    key.write_bytes(b'SYNTHETIC-PRIVATE-KEY-NOT-A-REAL-SECRET\n')
    key.chmod(0o600)
    key.with_suffix('.pub').write_bytes(trust.PUBLIC+b' synthetic-management\n')


def access_fixture(home):
    from test_manual_execution import MemorySFTP
    install_pair(home)
    remote=MemorySFTP()
    remote.modes['/home/admin/.ssh']=stat.S_IFDIR|0o700
    remote.modes['/home/admin/.ssh/authorized_keys']=stat.S_IFREG|0o600
    remote.files['/home/admin/.ssh/authorized_keys']=trust.PUBLIC+b' synthetic-management\n'
    return remote,SimpleNamespace(SFTPClient=SimpleNamespace(from_transport=lambda transport:remote))


def public(number):
    wire = struct.pack('>I', 11)+b'ssh-ed25519'+struct.pack('>I', 32)+bytes([number])*32
    return b'ssh-ed25519 '+base64.b64encode(wire)+b' synthetic\n'


class MergeTests(unittest.TestCase):
    def merge(self, old, new):
        import ibsw_upgrade_access as access
        return access.merge_authorized_keys(old, new)

    def test_missing_file_restores_exact_backup_including_options_and_comments(self):
        old=b'# retain\nfrom="192.0.2.0/24" '+public(1)
        self.assertEqual(self.merge(old, b''), old)

    def test_restore_preserves_new_authorizations_and_appends_only_missing_keys(self):
        old=public(1)+public(2)
        new=public(2)+public(3)
        self.assertEqual(self.merge(old,new),new+public(1))

    def test_same_key_different_restrictions_is_not_silently_weakened(self):
        import ibsw_upgrade_access as access
        with self.assertRaises(access.AccessHold):
            self.merge(public(1),b'restrict '+public(1))

    def test_comment_only_changes_are_not_authorization_changes(self):
        self.assertEqual(self.merge(public(1),public(1).replace(b'synthetic',b'new-comment')),
                         public(1).replace(b'synthetic',b'new-comment'))

    def test_malformed_and_oversized_backups_are_refused(self):
        import ibsw_upgrade_access as access
        for old in (b'not a public key\n', b'x'*(1024*1024+1)):
            with self.subTest(size=len(old)),self.assertRaises(access.AccessHold):
                self.merge(old,b'')


class AccessWorkflowTests(unittest.TestCase):
    invoke=workflow.ThreeComponentWorkflowTests.invoke
    # Tests below use the real entry, driver, access, signed sessions, executor,
    # all three templates and completion; only external SSH/filesystem IO fake.
    def test_os_bios_and_cpld_each_restore_lost_keys_then_reverify_key(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True)
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual([x[1] for x in installs],['os','bios','cpld'])
            root=Path(report['run_directory'])/workflow.HOST/'ssh-access'
            backup=root/'authorized_keys.before'
            self.assertTrue(backup.is_file())
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode),0o600)
            self.assertEqual(len(list(root.glob('recovery-*/access-result.json'))),3)
            for path in root.glob('recovery-*/access-result.json'):
                self.assertEqual(json.loads(path.read_text())['state'],'KEY_LOGIN_VERIFIED')
            self.assertIn('KEY_REJECTED_PASSWORD_FALLBACK',err)
            self.assertIn('AUTHORIZED_KEYS_RESTORED',err)
            self.assertIn('POSTCHECK_VERIFIED',err)
            self.assertNotIn('SYNTHETIC',err)
            self.assertIn('IB Upgrade Summary',err)
            self.assertEqual([r['component'] for r in report['component_results']],['os','bios','cpld'])
            self.assertTrue(all(r['action']=='UPGRADE_PERFORMED_AND_VERIFIED' for r in report['component_results']))
            self.assertTrue(all(r['ssh_key_restored_verified'] for r in report['component_results']))

    def test_bad_password_blocks_that_device_before_any_installer_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),two=True,bad_password=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertTrue(installs)
            self.assertTrue(all(name=='ew-spine02.example' for name,_,_ in installs))
            self.assertEqual(report['skipped_devices'][0]['reasons'],['PASSWORD_PREFLIGHT_REJECTED'])

    def test_present_but_rejected_key_is_not_duplicated_or_weakened(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),bad_initial_key=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(report['skipped_devices'][0]['reasons'],['KEY_PREFLIGHT_RECHECK_FAILED'])
            self.assertEqual(self._last_access_snapshot,trust.PUBLIC+b' synthetic-management\n')

    def test_initial_password_login_imports_management_key_before_upgrade_baseline(self):
        for option in ('initial_keys_missing','initial_other_keys','initial_ssh_missing'):
            with self.subTest(option=option),tempfile.TemporaryDirectory() as folder:
                code,report,err,calls,installs=self.invoke(Path(folder).resolve(),
                    **{option:True},drop_keys=True,selection=('--os-only',))
                self.assertEqual(code,0,err+repr(report))
                self.assertEqual(len(installs),1)
                root=Path(report['run_directory'])/workflow.HOST/'ssh-access'
                baseline=(root/'authorized_keys.before').read_bytes()
                self.assertIn(trust.PUBLIC,baseline)
                record=json.loads(next(root.glob('recovery-*/access-bootstrap.json')).read_text())
                expected=public(2) if option=='initial_other_keys' else b''
                self.assertEqual(base64.b64decode(record['original_base64']),expected)
                if option=='initial_other_keys':
                    self.assertIn(public(2),baseline)
                    self.assertIn(public(2),self._last_access_snapshot)
                result=json.loads(next(root.glob('recovery-*/access-bootstrap-result.json')).read_text())
                self.assertEqual(result['state'],'MANAGEMENT_KEY_IMPORT_VERIFIED')
                events=[row['stage'] for row in report['progress_events'] if row['component']=='ACCESS']
                self.assertIn('MANAGEMENT_KEY_IMPORTED',events)
                self.assertLess(events.index('MANAGEMENT_KEY_IMPORTED'),events.index('ACCESS_BACKUP_SAVED'))
                self.assertNotIn('ACCESS_BACKUP_SAVED',err[:err.index('[READY ')])

    def test_initial_wrong_password_never_imports_key_or_launches_installer(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),initial_keys_missing=True,bad_password=True,
                                                   password_prompt_attempts=3)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(self._last_access_snapshot,b'')
            self.assertEqual(report['skipped_devices'][0]['reasons'],['PASSWORD_PREFLIGHT_REJECTED'])
            self.assertFalse(list(Path(report['run_directory']).glob('*/ssh-access')))

    def test_initial_identity_mismatch_never_imports_management_key(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),initial_keys_missing=True,initial_identity_mismatch=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(self._last_access_snapshot,b'')
            self.assertEqual(report['skipped_devices'][0]['reasons'],['DEVICE_IDENTITY_MISMATCH'])

    def test_initial_import_failure_is_a_single_device_skip_and_no_installer(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),initial_keys_missing=True,restore_fail=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(report['skipped_devices'][0]['reasons'],['MANAGEMENT_KEY_IMPORT_FAILED'])
            self.assertFalse(list(Path(report['run_directory']).glob('*/ssh-access/authorized_keys.before')))

    def test_inspection_with_missing_initial_key_does_not_import_or_prompt(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),initial_keys_missing=True,inspect=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(self._last_access_snapshot,b'')
            self.assertFalse(list(Path(report['run_directory']).glob('*/ssh-access')))

    def test_initial_host_pin_mismatch_does_not_attempt_password_or_key_import(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),initial_keys_missing=True,initial_host_key=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(self._auth_attempts,[])
            self.assertEqual(self._last_access_snapshot,b'')
            self.assertEqual(report['skipped_devices'][0]['reasons'],['SSH_HOST_KEY_MISMATCH'])

    def test_initial_key_import_requires_valid_version_plan(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),initial_keys_missing=True,unlisted_os=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(self._last_access_snapshot,b'')
            self.assertEqual(report['skipped_devices'][0]['reasons'],['OS_UPGRADE_PATH_REJECTED'])
            self.assertFalse(list(Path(report['run_directory']).glob('*/ssh-access')))

    def test_import_without_successful_initial_key_recheck_never_creates_baseline(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),initial_keys_missing=True,bad_initial_key=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertIn(trust.PUBLIC,self._last_access_snapshot)
            root=Path(report['run_directory'])/workflow.HOST/'ssh-access'
            result=json.loads(next(root.glob('recovery-*/access-bootstrap-result.json')).read_text())
            self.assertEqual(result['state'],'MANAGEMENT_KEY_IMPORT_UNVERIFIED')
            self.assertFalse((root/'authorized_keys.before').exists())
            self.assertEqual(report['skipped_devices'][0]['reasons'],['KEY_PREFLIGHT_RECHECK_FAILED'])

    def test_ssh_symlink_after_reboot_is_never_followed_or_repaired(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,ssh_symlink=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(len(installs),1)
            self.assertIn('AUTHORIZED_KEYS_UNSAFE',repr(report))
            self.assertFalse(any(c.startswith('nv config patch') for _,c in calls))

    def test_auth_transport_drop_reconnects_without_resending_installer(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),auth_drop=True,selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(len(installs),1)

    def test_restore_readback_failure_is_unknown_and_stops_own_later_components(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,restore_fail=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual([x[1] for x in installs],['os'])
            self.assertIn('AUTHORIZED_KEYS_RESTORE_FAILED',repr(report))

    def test_readonly_inspection_neither_prompts_for_backup_password_nor_installs_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),inspect=True)
            self.assertEqual(code,0,err+repr(report))
            self.assertFalse(list(Path(report['run_directory']).glob('*/ssh-access')))
            self.assertNotIn('ACCESS_PREFLIGHT',err)
            self.assertFalse(any(c=='id -u' for _,c in calls))
            self.assertIn('[OS PLAN]\n  UPGRADE_REQUIRED (1):\n    - '+workflow.HOST,err)

    def test_versions_targets_os_chain_and_per_component_upgrade_lists_are_printed(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),os_chain=True)
            self.assertEqual(code,0,err+repr(report))
            self.assertIn('OS current=25.02.8008 target=25.03.1010 action=UPGRADE_REQUIRED',err)
            self.assertIn('OS path: 25.02.8008 -> 25.02.9000 -> 25.03.1010',err)
            self.assertIn('BIOS current=0ACQF_06.01.008 target=0ACQF_06.01.009',err)
            self.assertIn('[OS PLAN]\n  UPGRADE_REQUIRED (1):\n    - '+workflow.HOST,err)
            self.assertIn('[BIOS PLAN]\n  UPGRADE_REQUIRED (1):\n    - '+workflow.HOST,err)
            self.assertEqual(len(report['version_plan']),3)

    def test_changed_host_pin_never_tries_password_or_restores_authorizations(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,post_host_key=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(len(installs),1)
            self.assertIn('SSH_HOST_KEY_MISMATCH',repr(report))
            self.assertNotIn(('password',True),self._auth_attempts)
            self.assertFalse(list(Path(report['run_directory']).glob('*/ssh-access/recovery-*')))

    def test_wrong_device_identity_after_password_takeover_is_never_written(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,post_identity=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(len(installs),1)
            self.assertIn('DEVICE_IDENTITY_MISMATCH',repr(report))
            self.assertEqual(self._last_access_snapshot,b'')
            self.assertFalse(list(Path(report['run_directory']).glob('*/ssh-access/recovery-*')))

    def test_restoring_file_without_successful_key_recheck_is_not_complete(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,reject_recheck=True)
            self.assertEqual(code,3,err+repr(report))
            results=list(Path(report['run_directory']).glob('*/ssh-access/recovery-*/access-result.json'))
            self.assertEqual(len(results),1)
            self.assertEqual(json.loads(results[0].read_text())['state'],'KEY_LOGIN_RECHECK_FAILED')
            self.assertEqual(len(installs),1)

    def test_other_original_keys_are_preserved_even_when_management_key_survives(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),other_key_loss=True)
            self.assertEqual(code,0,err+repr(report))
            self.assertIn(public(2),self._last_access_snapshot)
            self.assertNotIn('KEY_REJECTED_PASSWORD_FALLBACK',err)

    def test_recovery_does_not_delete_new_postupgrade_authorizations(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,extra_key_after=True)
            self.assertEqual(code,0,err+repr(report))
            self.assertIn(public(3),self._last_access_snapshot)
            self.assertIn(trust.PUBLIC,self._last_access_snapshot)

    def test_password_is_revalidated_before_each_later_component_write(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),password_changes_after_os=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual([x[1] for x in installs],['os'])
            self.assertIn('PASSWORD_PREWRITE_REJECTED',repr(report))

    def test_final_summary_does_not_count_at_target_or_unknown_as_actual_upgrades(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),old_os=False,selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(report['component_results'][0]['action'],'AT_TARGET_PREFLIGHT')
            self.assertEqual(report['component_results'][0]['state'],'PREFLIGHT_NO_CHANGE')
            self.assertIn('Upgraded and verified: 0',err)
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,reject_recheck=True,selection=('--os-only',))
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(report['component_results'][0]['state'],'UNKNOWN')
            self.assertIn('Upgraded and verified: 0',err)
            self.assertIn('Unverified / failed',err)

    def test_access_backup_cleanup_failure_skips_only_device_before_any_install(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),access_close_failure='backup')
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(report['skipped_devices'][0]['state'],'SKIPPED_ACCESS_BACKUP')
            self.assertEqual(report['skipped_devices'][0]['reasons'],['AUTHORIZED_KEYS_READ_FAILED'])

    def test_restore_cleanup_failure_is_not_retried_as_network_reconnect(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,access_close_failure='restore')
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(len(installs),1)
            self.assertIn('AUTHORIZED_KEYS_RESTORE_FAILED',repr(report))
            self.assertEqual(len(list(Path(report['run_directory']).glob('*/ssh-access/recovery-*'))),1)

    def test_unavailable_sftp_is_a_device_backup_skip_not_a_batch_exception(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),sftp_unavailable=True)
            self.assertEqual(code,3,err+repr(report))
            self.assertEqual(installs,[])
            self.assertEqual(report['skipped_devices'][0]['reasons'],['AUTHORIZED_KEYS_READ_FAILED'])

    def test_network_drop_during_key_recheck_retries_only_login_not_restore_or_install(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,
                auth_drop_after_restore=True,selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(len(installs),1)
            records=list(Path(report['run_directory']).glob('*/ssh-access/recovery-*/access-result.json'))
            self.assertEqual(len(records),1)
            self.assertEqual(json.loads(records[0].read_text())['state'],'KEY_LOGIN_VERIFIED')

    def test_sdk_wrapped_eof_during_key_auth_reconnects_before_password_takeover(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),drop_keys=True,
                sdk_auth_drop=True,selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(len(installs),1)
            self.assertIn('WAIT_REBOOT',err)
            self.assertIn('KEY_REJECTED_PASSWORD_FALLBACK',err)

    def test_configuration_repair_cannot_erase_keys_after_the_last_access_check(self):
        with tempfile.TemporaryDirectory() as folder:
            code,report,err,calls,installs=self.invoke(Path(folder).resolve(),missing=True,
                drop_keys_on_apply=True,selection=('--os-only',))
            self.assertEqual(code,0,err+repr(report))
            self.assertEqual(len(installs),1)
            self.assertIn(trust.PUBLIC,self._last_access_snapshot)
            self.assertTrue(report['component_results'][0]['ssh_key_restored_verified'])
            self.assertIn('FINAL_KEY_ACCESS_CHECK',err)


class NativeAuthenticationTests(unittest.TestCase):
    def probe(self, exception, *, password_mode=True):
        from types import SimpleNamespace
        import ibsw_upgrade_observer as observer
        app,driver=fixtures.app,fixtures.driver
        class Rejected(Exception): pass
        class Protocol(Exception): pass
        errors={'reject':Rejected('Authentication failed.'),'eof':EOFError('PRIVATE-WIRE'),
            'protocol':Protocol('PRIVATE-PROTOCOL'),
            'sdk_eof':Rejected('Authentication failed: transport shut down or saw EOF'),
            'timeout':Rejected('Authentication timeout.'),'unknown':Rejected('PRIVATE-PASSWORD')}
        error=errors[exception]
        with tempfile.TemporaryDirectory() as folder:
            project,home,known=fixtures.WorkflowTests().fixture(Path(folder).resolve())
            install_pair(home)
            args=('--project',str(project),'--os-only')
            prepared=driver.prepare_manual_run(app.__file__,str(project),args)
            socket=SimpleNamespace(connect=lambda target:None,settimeout=lambda timeout:None,close=lambda:None)
            def reject(*a,**k): raise error
            transport=SimpleNamespace(start_client=lambda **k:None,
                get_remote_server_key=lambda:SimpleNamespace(asbytes=lambda:trust.WIRE),
                auth_password=reject,auth_publickey=reject,is_active=lambda:True,close=lambda:None)
            sdk=SimpleNamespace(Transport=lambda socket:transport,AuthenticationException=Rejected,SSHException=Protocol)
            with driver.open_manual_run(app.__file__,str(project),args,prepared['run_directory']) as scope:
                with scope.open_readonly_query_inputs(workflow.HOST,known_hosts_path=str(known),identity_path=str(home/'.ssh/id_ed25519'),
                    management_public_path=str(home/'.ssh/id_ed25519.pub'),user='admin') as leaf:
                    leaf._native_observation_consumed=True
                    with patch.object(observer.socket,'socket',return_value=socket),patch.object(observer,'_fixed_sdk',return_value=sdk), \
                         patch.object(observer,'_original_private_key',return_value=object()):
                        with self.assertRaises(observer._NativeObservationHold) as caught:
                            with observer._signed_session_single(leaf,password='secret-value' if password_mode else None):
                                self.fail('Authentication did not complete')
            self.assertNotIn('PRIVATE',str(caught.exception))
            self.assertNotIn('secret-value',str(caught.exception))
            return caught.exception.reason_code

    def test_explicit_server_rejection_is_not_a_reboot_network_failure(self):
        self.assertEqual(self.probe('reject'),'SSH_AUTHENTICATION_REJECTED')

    def test_authentication_eof_is_not_misreported_as_bad_password(self):
        self.assertEqual(self.probe('eof'),'SSH_AUTH_TRANSPORT_LOST')

    def test_protocol_failure_is_separate_from_explicit_credential_rejection(self):
        self.assertEqual(self.probe('protocol'),'SSH_AUTH_PROTOCOL_FAILED')

    def test_sdk_wrapped_key_eof_is_not_explicit_server_rejection(self):
        self.assertEqual(self.probe('sdk_eof',password_mode=False),'SSH_AUTH_TRANSPORT_LOST')

    def test_sdk_wrapped_password_eof_does_not_trigger_repeated_password_attempts(self):
        self.assertEqual(self.probe('sdk_eof'),'SSH_PASSWORD_AUTH_RESULT_UNKNOWN')

    def test_sdk_key_timeout_is_not_bad_password(self):
        self.assertEqual(self.probe('timeout',password_mode=False),'SSH_AUTH_TIMEOUT')

    def test_sdk_password_timeout_has_unknown_result_and_no_guessing(self):
        self.assertEqual(self.probe('timeout'),'SSH_PASSWORD_AUTH_RESULT_UNKNOWN')

    def test_unrecognized_authentication_exception_is_not_assumed_rejection(self):
        self.assertEqual(self.probe('unknown'),'SSH_AUTH_RESULT_UNKNOWN')


class ProgressTests(unittest.TestCase):
    def test_canary_and_regular_worker_have_parent_drained_stage_and_wait_heartbeat(self):
        app=fixtures.app
        parent=threading.get_ident()
        bus=app._ProgressBus()
        writes=[]
        class Output(io.StringIO):
            def write(self,text):
                writes.append(threading.get_ident())
                return super().write(text)
        def execute(name,component,canary,stop):
            bus.emit(name,component,'WAIT_REBOOT')
            time.sleep(0.035)
            return {'hostname':name,'component':component,'state':'COMPLETE'}
        with patch.object(app,'_PROGRESS_HEARTBEAT_SECONDS',0.01), \
             patch.object(app,'_PROGRESS_POLL_SECONDS',0.005),contextlib.redirect_stderr(Output()) as out:
            report=app._run_component_queue(['a','b'],('os',),execute,verify_shared=lambda:None,
                                            skip_canary=False,progress=bus)
        self.assertEqual(report['state'],'COMPLETE')
        self.assertIn('[a] WAIT_REBOOT',out.getvalue())
        self.assertIn('[b] WAIT_REBOOT',out.getvalue())
        self.assertIn('elapsed=',out.getvalue())
        self.assertIn('still waiting',out.getvalue())
        self.assertEqual(set(writes),{parent})


# New independent SFTP lifetime contracts; runtime/fixtures are the same
# canonical modules already bound above, not substitute production APIs.
import errno
import ibsw_upgrade_access as access
import ibsw_upgrade_observer as observer
import test_manual_execution as manual
runtime = _ibsw225_runtime


@contextlib.contextmanager
def no_thread_phase(owners, deadline):
    """Direct-only seam; genuine observer deadline scopes run in workflow."""
    yield threading.Event()


class SftpInterruptionDirectTests(unittest.TestCase):
    def test_successful_acquisition_leaves_one_close_to_the_consumer(self):
        events = []
        transport = object()
        def settimeout(value):
            self.assertGreater(value, 0)
            self.assertLessEqual(value, 20)
            events.append("settimeout")
        channel = SimpleNamespace(settimeout=settimeout)
        def get_channel():
            events.append("get-channel")
            return channel
        client = SimpleNamespace(get_channel=get_channel, close=lambda: events.append("client-close"))
        def acquire(actual):
            self.assertIs(actual, transport)
            events.append("factory-return")
            return client
        sdk = SimpleNamespace(SFTPClient=SimpleNamespace(from_transport=acquire))
        with patch.object(observer, "_fixed_sdk", return_value=sdk), patch.object(observer, "_owned_phase", no_thread_phase):
            returned = access._sftp(transport, time.monotonic() + 20)
            self.assertIs(returned, client)
            self.assertEqual(events, ["factory-return", "get-channel", "settimeout"])
            try:
                events.append("consumer-body")
            finally:
                access._close_sftp(returned, "AUTHORIZED_KEYS_READ_FAILED")
        self.assertEqual(events, ["factory-return", "get-channel", "settimeout", "consumer-body", "client-close"])

    def test_ordinary_channel_setup_errors_close_once_and_keep_open_failed(self):
        for point in ("get_channel", "settimeout"):
            with self.subTest(point=point):
                events = []
                def failure(*args):
                    raise OSError("PRIVATE_CHANNEL_FAILURE")
                channel = SimpleNamespace(settimeout=failure if point == "settimeout" else lambda value: None)
                client = SimpleNamespace(
                    get_channel=failure if point == "get_channel" else lambda: channel,
                    close=lambda: events.append("client-close"))
                sdk = SimpleNamespace(SFTPClient=SimpleNamespace(from_transport=lambda actual: client))
                with patch.object(observer, "_fixed_sdk", return_value=sdk), patch.object(observer, "_owned_phase", no_thread_phase):
                    with self.assertRaises(access.AccessHold) as caught:
                        access._sftp(object(), time.monotonic() + 20)
                self.assertIs(type(caught.exception), access.AccessHold)
                self.assertEqual(caught.exception.reason_code, "AUTHORIZED_KEYS_READ_FAILED")
                self.assertEqual(caught.exception.diagnostic["check_code"], "SFTP_CHANNEL_OPEN_FAILED")
                self.assertEqual(caught.exception.diagnostic["role"], "SFTP_CHANNEL")
                self.assertEqual(caught.exception.diagnostic["operation"], "OPEN_SFTP")
                self.assertNotIn("PRIVATE_CHANNEL_FAILURE", str(caught.exception))
                self.assertEqual(events, ["client-close"])

    def test_deadline_reason_closes_once_and_keeps_open_timeout(self):
        for point in ("get_channel", "settimeout"):
            with self.subTest(point=point):
                events = []
                def failure(*args):
                    raise observer._NativeObservationHold(reason_code="READONLY_DEADLINE_EXCEEDED")
                channel = SimpleNamespace(settimeout=failure if point == "settimeout" else lambda value: None)
                client = SimpleNamespace(
                    get_channel=failure if point == "get_channel" else lambda: channel,
                    close=lambda: events.append("client-close"))
                sdk = SimpleNamespace(SFTPClient=SimpleNamespace(from_transport=lambda actual: client))
                with patch.object(observer, "_fixed_sdk", return_value=sdk), patch.object(observer, "_owned_phase", no_thread_phase):
                    with self.assertRaises(access.AccessHold) as caught:
                        access._sftp(object(), time.monotonic() + 20)
                self.assertIs(type(caught.exception), access.AccessHold)
                self.assertEqual(caught.exception.reason_code, "AUTHORIZED_KEYS_READ_FAILED")
                self.assertEqual(caught.exception.diagnostic["check_code"], "SFTP_CHANNEL_OPEN_TIMEOUT")
                self.assertEqual(caught.exception.diagnostic["role"], "SFTP_CHANNEL")
                self.assertEqual(caught.exception.diagnostic["operation"], "OPEN_SFTP")
                self.assertEqual(events, ["client-close"])

    def test_acquired_client_cleanup_does_not_reclassify_shared_or_resource_stop(self):
        from ibsw_upgrade_contract import SharedUpgradeHold
        for stop in (SharedUpgradeHold("ORIGINAL_SHARED_HOLD"), OSError(errno.EMFILE, "ORIGINAL_RESOURCE_HOLD")):
            with self.subTest(kind=type(stop).__name__):
                events = []
                def get_channel():
                    raise stop
                client = SimpleNamespace(get_channel=get_channel, close=lambda: events.append("client-close"))
                sdk = SimpleNamespace(SFTPClient=SimpleNamespace(from_transport=lambda transport: client))
                with patch.object(observer, "_fixed_sdk", return_value=sdk), patch.object(observer, "_owned_phase", no_thread_phase):
                    try:
                        access._sftp(object(), time.monotonic() + 20)
                    except BaseException as observed:
                        self.assertIs(observed, stop)
                    else:
                        self.fail("Shared/resource stop cannot become success")
                self.assertEqual(events, ["client-close"])

    def test_acquired_client_is_closed_when_channel_setup_is_interrupted(self):
        for point in ("get_channel", "settimeout"):
            for exception_type in (KeyboardInterrupt, SystemExit):
                with self.subTest(point=point, kind=exception_type.__name__):
                    stop = exception_type("ORIGINAL_STOP")
                    events = []
                    def stop_here(*args):
                        raise stop
                    channel = SimpleNamespace(settimeout=stop_here if point == "settimeout" else lambda value: None)
                    client = SimpleNamespace(
                        get_channel=stop_here if point == "get_channel" else lambda: channel,
                        close=lambda: events.append("client-close"))
                    sdk = SimpleNamespace(SFTPClient=SimpleNamespace(from_transport=lambda transport: client))
                    with patch.object(observer, "_fixed_sdk", return_value=sdk), \
                         patch.object(observer, "_owned_phase", no_thread_phase):
                        try:
                            access._sftp(object(), time.monotonic() + 20)
                        except BaseException as observed:
                            self.assertIs(observed, stop)
                        else:
                            self.fail("Interrupted acquisition cannot return a client")
                    self.assertEqual(events, ["client-close"])

    def test_pending_operator_interrupt_has_priority_over_cleanup_interrupt(self):
        for exception_type, cleanup_type in ((KeyboardInterrupt, SystemExit), (SystemExit, KeyboardInterrupt)):
            with self.subTest(kind=exception_type.__name__):
                cause = ValueError("original-cause")
                stop, cleanup = exception_type("ORIGINAL_STOP"), cleanup_type("CLEANUP_STOP")
                def close():
                    raise cleanup
                client = SimpleNamespace(close=close)
                try:
                    try:
                        raise stop from cause
                    finally:
                        access._close_sftp(client, "AUTHORIZED_KEYS_READ_FAILED")
                except BaseException as observed:
                    self.assertIs(observed, stop)
                    self.assertIs(observed.__cause__, cause)
                else:
                    self.fail("Original operator interruption was lost")

    def test_close_without_primary_failure_keeps_safe_failure_classification(self):
        for cleanup in (OSError("PRIVATE_DETAIL"), KeyboardInterrupt("NEW_STOP")):
            with self.subTest(kind=type(cleanup).__name__):
                def close():
                    raise cleanup
                try:
                    access._close_sftp(SimpleNamespace(close=close), "AUTHORIZED_KEYS_READ_FAILED")
                except BaseException as observed:
                    if isinstance(cleanup, Exception):
                        self.assertIs(type(observed), access.AccessHold)
                        self.assertEqual(observed.diagnostic["check_code"], "SFTP_CLOSE_FAILED")
                        self.assertNotIn("PRIVATE_DETAIL", str(observed))
                    else:
                        self.assertIs(observed, cleanup)
                else:
                    self.fail("A failed close cannot be reported as success")


class SftpInterruptionOwnerWorkflowTests(unittest.TestCase):
    def test_real_signed_session_releases_all_original_owners_and_preserves_stop(self):
        # Real driver private input scope -> real signed-session authentication,
        # trust/identity checks -> real SFTP acquisition -> owner cleanup.
        # Only socket/SDK/channel wire IO are doubles; no transport/session
        # context manager or original input verification method is replaced.
        for exception_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=exception_type.__name__), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                project, home, known = fixtures.WorkflowTests().fixture(root)
                args = ("--project", str(project), "--os-only")
                events = []
                stop = exception_type("ORIGINAL_OPERATOR_STOP")
                cleanup_stop = SystemExit("CLEANUP_OPERATOR_STOP")
                def socket_close():
                    events.append("socket-close")
                connection = SimpleNamespace(connect=lambda address: None, settimeout=lambda value: None, close=socket_close)
                def transport_close():
                    events.append("transport-close")
                    raise cleanup_stop
                transport = SimpleNamespace(start_client=lambda **kwargs: None,
                    get_remote_server_key=lambda: SimpleNamespace(asbytes=lambda: trust.WIRE),
                    auth_password=lambda *args, **kwargs: events.append("password-auth"),
                    is_authenticated=lambda: True, get_username=lambda: "admin", close=transport_close)
                def get_channel():
                    events.append("client-get-channel")
                    raise stop
                def client_close():
                    events.append("client-close")
                    raise OSError("PRIVATE_CLOSE_DETAIL")
                client = SimpleNamespace(get_channel=get_channel, close=client_close)
                class AuthenticationError(Exception):
                    pass
                class ProtocolError(Exception):
                    pass
                sdk = SimpleNamespace(Transport=lambda actual: transport,
                    AuthenticationException=AuthenticationError, SSHException=ProtocolError,
                    SFTPClient=SimpleNamespace(from_transport=lambda actual: client))
                with manual.ManualTests().no_deployment_or_filesystem_locks():
                    prepared = runtime.driver.prepare_manual_run(runtime.app.__file__, str(project), args)
                    with runtime.driver.open_manual_run(runtime.app.__file__, str(project), args, prepared["run_directory"]) as scope:
                        with scope.open_readonly_query_inputs("ew-spine01.example", known_hosts_path=str(known),
                                identity_path=None, management_public_path=None, user="admin") as leaf:
                            leaf._native_observation_consumed = True
                            def identity(actual_leaf, actual_transport, command, deadline):
                                self.assertIs(actual_leaf, leaf)
                                self.assertIs(actual_transport, transport)
                                self.assertEqual(command, "hostname; cat /sys/class/net/eth0/address")
                                return b"ew-spine01.example\n02:00:00:00:00:01\n", b"", 0, True
                            with patch.object(observer.socket, "socket", return_value=connection), \
                                 patch.object(observer, "_fixed_sdk", return_value=sdk), \
                                 patch.object(observer, "_read_channel", side_effect=identity):
                                try:
                                    with observer._signed_session_single(leaf, password="secret-value") as (actual, deadline, *_):
                                        self.assertIs(actual, transport)
                                        access._sftp(actual, deadline)
                                except BaseException as observed:
                                    self.assertIs(observed, stop)
                                else:
                                    self.fail("Operator stop cannot become successful workflow completion")
                            self.assertEqual(events, ["password-auth", "client-get-channel", "client-close",
                                                      "transport-close", "socket-close"])
                            leaf.verify()  # The original shared input scope remains valid.

if __name__=='__main__':
    unittest.main()
