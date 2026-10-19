"""Prepared actual local Bash file composition, not a live SSH key installer."""
import base64,hashlib,os,stat,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest import mock
from test_cases.test_f01_recovery_project_key_install import MANAGEMENT,LAPTOP,public_line,subject
FACTS=[]
ARGV=('/bin/bash','--noprofile','--norc','-p','-s','--')

CMP_BACKUP_OBSERVER="#!/bin/bash\nset -eu\ncase \"${3:-}\" in\n  */authorized_keys.original)\n    cat \"$2\" > \"$HOME/original-at-backup-comparison.raw\"\n    set +e\n    /usr/bin/cmp \"$@\"\n    original_status=$?\n    set -e\n    printf '%s\\n' \"$original_status\" > \"$HOME/backup-original-compare-status\"\n    printf '%s\\n' backup-compared > \"$HOME/backup-comparison-event\"\n    if test \"$original_status\" -ne 0; then exit \"$original_status\"; fi\n    if test -f \"$HOME/inject-backup-compare-failure\"; then exit 1; fi\n    exit 0\n    ;;\nesac\nexec /usr/bin/cmp \"$@\"\n"
class KeyBashFixturePremiseError(RuntimeError):pass

def _original_owned_bash(script,home,*,backup_observer=False,controlled_term=False):
    cls=subprocess.Popen
    original_init=cls.__init__;original_try_wait=cls._try_wait;original_read=os.read
    child=None;owned_pid=None;objects=[];pipes=[];kernel=[];cleanup=[];primary=None;out=err=None
    env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','__CF_USER_TEXT_ENCODING':'0x1F5:0:0','HOME':str(home)}
    if backup_observer:
        compare=home/'fixture-bin'/'cmp'
        info=compare.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                or stat.S_IMODE(info.st_mode)!=0o700 or compare.read_text()!=CMP_BACKUP_OBSERVER):
            raise KeyBashFixturePremiseError('owned exact compare observer is absent')
        env['PATH']=str(compare.parent)+':/usr/bin:/bin'
    def capture():
        nonlocal owned_pid
        if child is None:return
        if not objects:
            for role in ('stdin','stdout','stderr'):
                obj=getattr(child,role,None)
                if obj is not None:objects.append((role,obj))
        if owned_pid is None and getattr(child,'_child_created',False) is True:
            pid=getattr(child,'pid',None)
            if type(pid) is int and pid>0:owned_pid=pid
    def try_wait(obj,flags):
        result=original_try_wait(obj,flags) # original call ONCE, no extra wait
        if obj is child and owned_pid is not None and result[0]==owned_pid:kernel.append(result)
        return result
    def read(fd,size):
        result=original_read(fd,size)
        for record in pipes:
            if fd==record['fd'] and not record['object'].closed:
                actual=os.fstat(fd)
                if (actual.st_dev,actual.st_ino)!=record['key']:
                    raise AssertionError('owned Bash original output pipe changed')
                if not result:record['EOF']=True
        return result
    try:
        child=cls.__new__(cls)
        original_init(child,list(ARGV),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                      cwd=str(home),env=env,close_fds=True,start_new_session=True)
        capture()
        for role,obj in objects:
            if role!='stdin':
                info=os.fstat(obj.fileno())
                pipes.append({'role':role,'fd':obj.fileno(),'object':obj,'key':(info.st_dev,info.st_ino),'EOF':False})
        with mock.patch.object(cls,'_try_wait',new=try_wait),mock.patch.object(os,'read',new=read):
            out,err=child.communicate(input=script,timeout=5)
    except BaseException as error:primary=error
    finally:
        capture()
        if owned_pid is not None and child.returncode is None:
            stop=time.monotonic()+2
            try:child.kill()
            except BaseException as error:cleanup.append(error)
            try:
                remaining=stop-time.monotonic()
                if remaining<=0:raise TimeoutError('fixed original cleanup budget expired')
                with mock.patch.object(cls,'_try_wait',new=try_wait):
                    child.communicate(timeout=remaining)
            except BaseException as error:cleanup.append(error)
        for role,obj in objects:
            try:
                if not obj.closed:obj.close()
            except BaseException as error:cleanup.append(error)
        FACTS.append({'scope':'actual local Bash only, no live SSH or native issuer',
          'pid':owned_pid,'kernel':kernel,'returncode':None if child is None else child.returncode,
          'streams_closed':[(role,obj.closed) for role,obj in objects],
          'raw_output_EOF':[(p['role'],p['EOF']) for p in pipes],
          'cleanup_types':[type(e).__name__ for e in cleanup],
          'stdio_empty_stderr':err==b'', 'waitpid_read_restored':cls._try_wait is original_try_wait and os.read is original_read})
    selected=primary
    for error in cleanup:
        if selected is None or isinstance(selected,Exception) and not isinstance(error,Exception):selected=error
    if selected is not None:
        selected.key_template_cleanup_errors=tuple(cleanup)
        raise selected
    known_returncode=(child.returncode in (0,143) if controlled_term
                      else child.returncode in (0,34) if backup_observer else child.returncode==0)
    if not (known_returncode and kernel==[(owned_pid,child.returncode<<8)] and (backup_observer or err==b'')
            and len(pipes)==2 and all(p['EOF'] for p in pipes)
            and all(obj.closed for role,obj in objects) and not cleanup):
        raise KeyBashFixturePremiseError('original Bash status/EOF/owned cleanup unconfirmed')
    if backup_observer or controlled_term:return out,err,child.returncode
    return out

class F01ProjectKeyInstallBashWorkflowTests(unittest.TestCase):
    def test_original_authorized_keys_without_final_newline_retains_old_options_and_installs_two_separate_identities(self):
        api=subject(self)
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/'home';home.mkdir(mode=0o700)
            directory=home/'.ssh';directory.mkdir(mode=0o700)
            existing=b'no-agent-forwarding,no-port-forwarding '+public_line(23,b'existing-key')[:-1]
            auth=directory/'authorized_keys';auth.write_bytes(existing);auth.chmod(0o600)
            raw=api.render_project_key_install_script(MANAGEMENT,LAPTOP)
            output=_original_owned_bash(raw,home)
            self.assertEqual(b'F01_PROJECT_KEYS_INSTALLED_NOT_DEPLOYED\n',output)
            wanted=existing+b'\n'+b' '.join(MANAGEMENT.split()[:2])+b'\n'+b' '.join(LAPTOP.split()[:2])+b'\n'
            self.assertEqual(wanted,auth.read_bytes())
            self.assertEqual(0o600,stat.S_IMODE(auth.stat().st_mode))
            self.assertEqual([],list(directory.glob('.authorized_keys.*')))
    def test_verified_exclusive_backup_precedes_replacement_and_failed_comparison_preserves_original_and_backup(self):
        api=subject(self)
        for failed_compare in (False,True):
            with self.subTest(failed_compare=failed_compare):
                with tempfile.TemporaryDirectory() as temporary:
                    home=Path(temporary)/'home';home.mkdir(mode=0o700)
                    directory=home/'.ssh';directory.mkdir(mode=0o700)
                    existing=b'no-agent-forwarding,no-port-forwarding '+public_line(23,b'existing-key')
                    auth=directory/'authorized_keys';auth.write_bytes(existing);auth.chmod(0o600)
                    compare=home/'fixture-bin';compare.mkdir(mode=0o700)
                    utility=compare/'cmp';utility.write_text(CMP_BACKUP_OBSERVER);utility.chmod(0o700)
                    if failed_compare:(home/'inject-backup-compare-failure').write_bytes(b'controlled fixture failure\n')
                    raw=api.render_project_key_install_script(MANAGEMENT,LAPTOP)
                    out,err,returncode=_original_owned_bash(raw,home,backup_observer=True)
                    # Nonzero capability/environment outcomes are fixture errors,
                    # not the independent backup/refusal behavior expectation.
                    stages=list(home.glob('.xdr-key-stage-*'))
                    self.assertEqual(1,len(stages),'Original configuration needs one private non-overwrite backup stage')
                    state=stages[0].lstat()
                    self.assertTrue(stat.S_ISDIR(state.st_mode));self.assertEqual(0o700,stat.S_IMODE(state.st_mode))
                    self.assertEqual(os.geteuid(),state.st_uid)
                    backup=stages[0]/'authorized_keys.original'
                    self.assertEqual(existing,backup.read_bytes())
                    state=backup.lstat()
                    self.assertTrue(stat.S_ISREG(state.st_mode));self.assertEqual(1,state.st_nlink)
                    self.assertEqual(0o600,stat.S_IMODE(state.st_mode));self.assertEqual(os.geteuid(),state.st_uid)
                    self.assertEqual(existing,(home/'original-at-backup-comparison.raw').read_bytes())
                    self.assertEqual(b'backup-compared\n',(home/'backup-comparison-event').read_bytes())
                    self.assertEqual(b'0\n',(home/'backup-original-compare-status').read_bytes())
                    if failed_compare:
                        self.assertEqual(34,returncode);self.assertEqual(existing,auth.read_bytes())
                        self.assertEqual(b'',out);self.assertEqual(b'F01_BLOCKED_BACKUP\n',err)
                    else:
                        self.assertEqual(0,returncode);self.assertEqual(b'',err)
                        self.assertEqual(b'F01_PROJECT_KEYS_INSTALLED_NOT_DEPLOYED\n',out)
                        expected=existing+b' '.join(MANAGEMENT.split()[:2])+b'\n'+b' '.join(LAPTOP.split()[:2])+b'\n'
                        self.assertEqual(expected,auth.read_bytes())
                    self.assertEqual([],list(directory.glob('.authorized_keys.*')))

    def test_term_after_registered_cleanup_before_composition_stops_without_replacement_and_retains_backup(self):
        api=subject(self)
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/'home';home.mkdir(mode=0o700)
            directory=home/'.ssh';directory.mkdir(mode=0o700)
            existing=b'no-agent-forwarding,no-port-forwarding '+public_line(23,b'existing-key')
            auth=directory/'authorized_keys';auth.write_bytes(existing);auth.chmod(0o600)
            raw=api.render_project_key_install_script(MANAGEMENT,LAPTOP)
            pipeline=b'{ if test -f "$auth"; then'
            self.assertEqual(1,raw.count(pipeline),'Only the fixed original key-composition pipeline is injected')
            after=raw.index(pipeline)
            self.assertGreater(raw[:after].rfind(b'\ntrap '),raw[:after].rfind(b'tmp="$(mktemp'))
            # Only fixture code injects self-TERM; the production source/body
            # is otherwise original and no external PID is signalled.
            controlled=raw[:after]+b'kill -TERM "$$"\n'+raw[after:]
            out,err,returncode=_original_owned_bash(controlled,home,controlled_term=True)
            self.assertEqual(143,returncode,'TERM must exit rather than resume the original composition/mv')
            self.assertEqual(b'',out);self.assertEqual(b'',err)
            self.assertEqual(existing,auth.read_bytes())
            self.assertEqual([],list(directory.glob('.authorized_keys.*')))
            stages=list(home.glob('.xdr-key-stage-*'));self.assertEqual(1,len(stages))
            self.assertEqual(existing,(stages[0]/'authorized_keys.original').read_bytes())
            self.assertEqual(0o600,stat.S_IMODE((stages[0]/'authorized_keys.original').stat().st_mode))
