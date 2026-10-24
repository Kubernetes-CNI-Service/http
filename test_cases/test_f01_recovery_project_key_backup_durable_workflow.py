"""PREPARED ONLY: real new-password SSH/SFTP -> durable local backup -> apply.
Local AF_UNIX/Bash protocol fixture, not UFM permission/service conformance.
No readonly owner/DTO or successful issuer/retrieval/fsync result is mocked.
The fixed production live entry is implemented; this native workflow is still
PREPARED / ACTUAL NOT RUN. The original entry-absence evidence remains only
structural RED. Root schedules actual execution and any missing native premise
continues to be setup ERROR, not a substitute for a genuine behavior result.
The entry proves the production F01 SDK identity, so outside a venv the test
runs unchanged in the venv-ibsw-upgrade child (test_cases/f01_sdk_venv.py).
"""
import contextlib,hashlib,os,queue,socket,stat,tempfile,threading,time,unittest
from pathlib import Path
from unittest import mock
import paramiko
from test_cases.f01_sdk_venv import sdk_identity_test
from tools import ufm_bootstrap_auth_adapter as auth
from test_cases.test_f01_recovery_project_key_install_bash_workflow import _original_owned_bash
from test_cases import test_f01_recovery_stage_script_builder as site
from test_cases.test_f01_recovery_project_key_install import public_line

IDENTITY=("hostname","ip -j link show dev eno8303","ip -j address show dev eno8303")
BASH="bash --noprofile --norc -p -s --"
HOME_PROBE = "bash --noprofile --norc -p -c 'printf '\"'\"'%s\\0'\"'\"' \"$HOME\" \"$UID\"'"
FACTS=[]
class KeyWorkflowPremiseError(RuntimeError):pass

def _close_key_fixture_contexts(contexts,primary):
    """Attempt every owned context; never turn fixture assistance into proof."""
    errors=[]
    for ctx in reversed(contexts):
        try:ctx.__exit__(type(primary) if primary else None,primary,primary.__traceback__ if primary else None)
        except BaseException as error:errors.append(error)
    if not errors:return
    if primary is not None:
        primary.key_workflow_fixture_errors=tuple(errors)
        if not isinstance(primary,Exception):raise primary
    operator=next((error for error in errors if not isinstance(error,Exception)),None)
    if operator is not None:raise operator from primary
    if primary is not None:raise primary
    raise KeyWorkflowPremiseError('all owned context cleanup UNKNOWN') from errors[0]

@contextlib.contextmanager
def actual_key_peer(test,host_key,management_key,home,authentication,events,api_deadline):
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    stop=threading.Event();requests=queue.Queue();acks={};errors=[]
    clients=[];client_channels=[];server_channels=[];handles=[];subsystems=[]
    commands=[];attempts=[];close_status=[];bash_facts=[];closing_backup=False
    def capture():
        for item in threading.enumerate():
            if type(item) is paramiko.Transport and item.sock is left and not item.server_mode and item not in clients:
                clients.append(item)
        for item in clients:
            for ch in list(item._channels.values()):
                if ch not in client_channels:client_channels.append(ch)
    class Handle(paramiko.SFTPHandle):
        def __init__(self,fd,path):
            super().__init__();self.fd=fd;self.path=path
            value=os.fstat(fd);self.key=(value.st_dev,value.st_ino);self.closed_original=False
            handles.append(self)
        def stat(self):
            capture();v=os.fstat(self.fd);test.assertEqual(self.key,(v.st_dev,v.st_ino))
            return paramiko.SFTPAttributes.from_stat(v)
        def read(self,offset,length):
            capture();v=os.fstat(self.fd);test.assertEqual(self.key,(v.st_dev,v.st_ino))
            raw=os.pread(self.fd,length,offset)
            if not raw and self.path.name=="authorized_keys.original":events.append("backup-SFTP-physical-EOF")
            return raw
        def close(self):
            nonlocal closing_backup
            if not self.closed_original:
                v=os.fstat(self.fd);test.assertEqual(self.key,(v.st_dev,v.st_ino))
                os.close(self.fd);self.closed_original=True
                closing_backup=self.path.name=="authorized_keys.original"
    class Backend(paramiko.SFTPServerInterface):
        def checked(self,path):
            p=Path(path)
            test.assertTrue(p.is_absolute());test.assertNotIn("..",p.parts)
            if p==home/".ssh/authorized_keys":return p
            test.assertEqual(home,p.parent.parent)
            test.assertRegex(p.parent.name,r"\A\.xdr-key-stage-[0-9a-f]{32}\Z")
            test.assertIn(p.name,{"authorized_keys.original","backup.state"})
            return p
        def lstat(self,path):
            try:return paramiko.SFTPAttributes.from_stat(self.checked(path).lstat())
            except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)
        def open(self,path,flags,attrs):
            p=self.checked(path);test.assertEqual(os.O_RDONLY,flags)
            return Handle(os.open(p,flags|os.O_NOFOLLOW),p)
    class ServerTransport(paramiko.Transport):
        def _send_message(self,msg):
            raw=msg.asbytes();result=super()._send_message(msg)
            if raw[:1]==b"\x63" and len(raw)==5:
                acks.setdefault(int.from_bytes(raw[1:],"big"),threading.Event()).set()
            return result
    class ObservedSftp(paramiko.SFTPServer):
        def __init__(self,*args,**kw):
            super().__init__(*args,**kw);subsystems.append(self)
        def _process(self,command,request,msg):
            nonlocal closing_backup
            if command==4:closing_backup=False
            self.current_command=command
            return super()._process(command,request,msg)
        def _send_status(self,request,code,*args,**kw):
            result=super()._send_status(request,code,*args,**kw)
            if self.current_command==4:
                close_status.append((request,code))
                if closing_backup and code==0:events.append("backup-SFTP-CLOSE-STATUS")
            return result
    class Peer(paramiko.ServerInterface):
        def get_allowed_auths(self,user):return "password" if authentication=="new-password" else "publickey"
        def check_auth_password(self,user,password):
            capture()
            # Test credential stays in memory, never recorded/printed.
            good=user=="admin" and authentication=="new-password" and password=="EPHEMERAL_NEW_KEY_SETUP"
            attempts.append(("password",good))
            if good:events.append("new-password-authenticated")
            return paramiko.AUTH_SUCCESSFUL if good else paramiko.AUTH_FAILED
        def check_auth_publickey(self,user,key):
            capture()
            content=(home/".ssh/authorized_keys").read_bytes()
            wire=(key.get_name()+" "+key.get_base64()).encode()
            good=(user=="admin" and authentication=="management-key" and key==management_key
                  and wire in content)
            attempts.append(("publickey",good))
            if good:events.append("fresh-management-key-authenticated")
            return paramiko.AUTH_SUCCESSFUL if good else paramiko.AUTH_FAILED
        def check_channel_request(self,kind,channel_id):
            return paramiko.OPEN_SUCCEEDED if kind=="session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_exec_request(self,ch,raw):
            capture();command=raw.decode("ascii")
            if command not in IDENTITY and command not in (BASH,HOME_PROBE):return False
            commands.append(command);server_channels.append(ch);requests.put((ch,command));return True
        def check_channel_subsystem_request(self,ch,name):
            capture()
            if authentication!="new-password" or name!="sftp":return False
            server_channels.append(ch);return super().check_channel_subsystem_request(ch,name)
    server=None;dispatcher=None;production=None
    def dispatch():
        try:
            while not stop.is_set():
                try:ch,command=requests.get(timeout=.1)
                except queue.Empty:continue
                if not acks.setdefault(ch.remote_chanid,threading.Event()).wait(2):
                    raise KeyWorkflowPremiseError("original exec ACK absent")
                if command==BASH:
                    ch.settimeout(.1);body=bytearray()
                    while True:
                        if time.monotonic()>=api_deadline:raise KeyWorkflowPremiseError("fixture original API stdin bound incomplete")
                        try:chunk=ch.recv(32768)
                        except socket.timeout:continue
                        if not chunk:break
                        body.extend(chunk);test.assertLessEqual(len(body),131072)
                    # Execution admission only. Behavioral expected bytes and
                    # operation order below are independent of this body.
                    test.assertTrue(bytes(body).startswith(b"#!/usr/bin/env bash\nset -euo pipefail\n"))
                    test.assertNotIn(b"EPHEMERAL_",body)
                    applying=b'mv -f "$tmp" "$auth"' in body
                    events.append("apply-Bash-start" if applying else "backup-only-Bash-start")
                    out=_original_owned_bash(bytes(body),home)
                    test.assertLess(time.monotonic(),api_deadline,"Bash fixture cannot extend original entry deadline")
                    events.append("apply-Bash-exit0" if applying else "backup-only-Bash-exit0")
                    bash_facts.append({"kind":"apply" if applying else "backup-only","stdin_EOF":True})
                elif command==HOME_PROBE:
                    out=str(home).encode()+b"\0"+str(os.getuid()).encode()+b"\0"
                elif command==IDENTITY[0]:out=b"factory-ufm01\n"
                elif command==IDENTITY[1]:out=b'[{"ifname":"eno8303","address":"02:00:00:00:00:21"}]'
                else:
                    out=b'[{"ifname":"eno8303","addr_info":[{"family":"inet","local":"192.0.2.21"}]}]'
                    events.append("actual-MAC-IP-hostname-read-set")
                ch.sendall(out);ch.send_exit_status(0);ch.shutdown_write();ch.close()
        except BaseException as e:errors.append(e)
    try:
        server=ServerTransport(right);server.add_server_key(host_key)
        server.set_subsystem_handler("sftp",ObservedSftp,Backend);ready=threading.Event()
        server.start_server(event=ready,server=Peer())
        dispatcher=threading.Thread(target=dispatch,daemon=True);dispatcher.start()
        yield left
    finally:
        primary=__import__("sys").exc_info()[1]
        try:capture()
        except BaseException as error:errors.append(error)
        production={"client_count":len(clients),"clients_alive":[c.is_alive() for c in clients],
            "clients_active":[c.is_active() for c in clients],"client_channels_closed":[c.closed for c in client_channels],
            "original_handles_closed":[h.closed_original for h in handles],"left_closed":left.fileno()==-1}
        stop.set()
        actions=[ch.close for ch in server_channels]
        if server is not None:actions.extend((server.close,lambda:server.join(2)))
        if dispatcher is not None:actions.append(lambda:dispatcher.join(2))
        actions.extend((left.close,right.close))
        actions.extend(lambda item=item:item.join(2) for item in subsystems)
        for action in actions:
            try:action()
            except BaseException as error:errors.append(error)
        facts={"authentication":authentication,"production_before_fixture_cleanup":production,
            "commands":commands,"attempts":attempts,"close_status":close_status,"bash":bash_facts,
            "server_dead":server is not None and not server.is_alive(),"dispatcher_dead":dispatcher is not None and not dispatcher.is_alive(),
            "subsystems_dead":[not s.is_alive() for s in subsystems],
            "sockets_closed":[left.fileno()==-1,right.fileno()==-1],"errors_types":[type(e).__name__ for e in errors]}
        FACTS.append(facts)
        if errors:
            if primary is not None:
                primary.key_workflow_fixture_errors=tuple(errors)
                for e in errors:
                    if not isinstance(e,Exception) and isinstance(primary,Exception):raise e from primary
            else:raise KeyWorkflowPremiseError("actual key-peer fixture failed") from errors[0]

class F01ProjectKeyBackupDurableWorkflowTests(unittest.TestCase):
    @sdk_identity_test
    def test_real_new_password_backup_pull_fsync_apply_and_failed_local_fsync_never_applies(self):
        entry=getattr(auth,"establish_project_direct_management_key_access",None)
        if not callable(entry):
            raise KeyWorkflowPremiseError("actual live key-install entry not yet implemented")
        for fault in (False,True):
            with self.subTest(local_fsync_failure=fault),site.actual_site() as (_http,project,logs):
                host_key=paramiko.ECDSAKey.generate();management=paramiko.RSAKey.generate(2048)
                laptop=paramiko.RSAKey.generate(2048)
                def public(k):return (k.get_name()+" "+k.get_base64()+"\n").encode()
                (project/"mgmt-server.pub").write_bytes(public(management));(project/"laptop.pub").write_bytes(public(laptop))
                identity=project/"management-private";management.write_private_key_file(str(identity));identity.chmod(0o600)
                known=project/"known-hosts";known.write_text("192.0.2.21 "+host_key.get_name()+" "+host_key.get_base64()+"\n");known.chmod(0o600)
                expected_pin=hashlib.sha256(known.read_bytes()).hexdigest()
                home=logs.parent/"remote-home";home.mkdir(mode=0o700);(home/".ssh").mkdir(mode=0o700)
                original=b"no-agent-forwarding,no-port-forwarding "+public_line(23,b"old-key")[:-1]
                original_path=home/".ssh/authorized_keys";original_path.write_bytes(original);original_path.chmod(0o600)
                events=[];owned_local={};backup_parent=[];fsync_faults=[];sessions=[];contexts=[];api_deadline=None
                original_open=os.open;original_fsync=os.fsync;main_thread=threading.get_ident()
                def observe_open(path,flags,*args,**kw):
                    fd=original_open(path,flags,*args,**kw)
                    # Observe real originals only. Standard SFTP attributes
                    # are not used to manufacture local FD ownership.
                    if threading.get_ident()==main_thread:
                        value=os.fstat(fd)
                        if (str(path)=="authorized_keys.original" and flags&os.O_CREAT and flags&os.O_EXCL):
                            owned_local[fd]=("file",(value.st_dev,value.st_ino))
                            parent=kw.get("dir_fd")
                            if type(parent) is not int:raise KeyWorkflowPremiseError("backup must use actual held parent FD")
                            parent_value=os.fstat(parent);backup_parent.append((parent,(parent_value.st_dev,parent_value.st_ino)))
                    return fd
                def fsync(fd):
                    value=os.fstat(fd);captured=owned_local.get(fd)
                    if captured is not None and captured[1]==(value.st_dev,value.st_ino):
                        kind=captured[0]
                        if kind=="file" and fault:
                            fsync_faults.append(True)
                            import errno
                            raise OSError(errno.EIO,"controlled original local backup fsync failure")
                        result=original_fsync(fd)
                        events.append("local-backup-file-fsync" if kind=="file" else "local-directory-fsync")
                        return result
                    if (fd,(value.st_dev,value.st_ino)) in backup_parent:
                        result=original_fsync(fd);events.append("local-directory-fsync");return result
                    return original_fsync(fd)
                def connect(address,timeout):
                    self.assertEqual("192.0.2.21",address);self.assertGreater(timeout,0)
                    phase="new-password" if not sessions else "management-key"
                    self.assertLess(len(sessions),2)
                    context=actual_key_peer(self,host_key,management,home,phase,events,api_deadline)
                    stream=context.__enter__();contexts.append(context);sessions.append(phase);return stream
                try:
                    with mock.patch.object(auth,"_direct_ipv4_connected_stream",new=connect),mock.patch.object(os,"open",new=observe_open),mock.patch.object(os,"fsync",new=fsync):
                        api_deadline=time.monotonic()+10 # Fixture is at least as strict as the original call, never per-phase renewed.
                        if fault:
                            with self.assertRaises(auth.BootstrapAuthError):
                                entry(project,"192.0.2.21",known,expected_pin,identity,
                                    new_password="EPHEMERAL_NEW_KEY_SETUP",default_password="EPHEMERAL_DEFAULT_NOT_USED",
                                    timeout=10,private_logs_root=logs)
                        else:
                            result=entry(project,"192.0.2.21",known,expected_pin,identity,
                                new_password="EPHEMERAL_NEW_KEY_SETUP",default_password="EPHEMERAL_DEFAULT_NOT_USED",
                                timeout=10,private_logs_root=logs)
                            self.assertEqual("PROJECT_KEY_ACCESS_ESTABLISHED_NOT_DEPLOYED",result["state"])
                            self.assertIs(False,result["completion"]);self.assertIs(False,result["execution_permitted"])
                finally:
                    primary=__import__("sys").exc_info()[1]
                    _close_key_fixture_contexts(contexts,primary)
                local=list(logs.rglob("authorized_keys.original"));self.assertEqual(1,len(local))
                self.assertEqual(original,local[0].read_bytes());self.assertEqual(0o600,stat.S_IMODE(local[0].stat().st_mode))
                if fault:
                    self.assertEqual([True],fsync_faults);self.assertNotIn("apply-Bash-start",events)
                    self.assertEqual(["new-password"],sessions);self.assertEqual(original,original_path.read_bytes())
                else:
                    self.assertEqual(["new-password","management-key"],sessions)
                    self.assertEqual(original+b"\n"+public(management)+public(laptop),original_path.read_bytes())
                    order=("backup-only-Bash-exit0","backup-SFTP-physical-EOF","backup-SFTP-CLOSE-STATUS",
                           "local-backup-file-fsync","local-directory-fsync","apply-Bash-start","apply-Bash-exit0","fresh-management-key-authenticated")
                    previous=-1
                    for event in order:
                        positions=[i for i,e in enumerate(events) if e==event and i>previous]
                        self.assertTrue(positions,event+" must occur after preceding actual prerequisite")
                        previous=positions[0]
                for fact in FACTS[-len(sessions):]:
                    production=fact["production_before_fixture_cleanup"]
                    self.assertEqual(1,production["client_count"]);self.assertEqual([False],production["clients_alive"])
                    self.assertEqual([False],production["clients_active"]);self.assertTrue(production["left_closed"])
                    self.assertTrue(all(production["client_channels_closed"]));self.assertTrue(all(production["original_handles_closed"]))
                    self.assertTrue(fact["server_dead"]);self.assertTrue(fact["dispatcher_dead"])
                    self.assertTrue(all(fact["subsystems_dead"]));self.assertEqual([True,True],fact["sockets_closed"])
                    self.assertEqual([],fact["errors_types"])
