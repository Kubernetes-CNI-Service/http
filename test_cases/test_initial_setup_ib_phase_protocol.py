"""Independent typed inner-IB phase protocol: O-only tests-first, NOT RUN.

Actual run_on_ib/Responder/PTY/read/write/reap, with only owned SSH exec MODEL.
Private operation/selector ABI below is proposed source contract, not a test hook.
Current missing interfaces are prerequisite HOLD, never behavior RED.
"""
from __future__ import annotations
import errno
import hashlib
import inspect
import json
import os
import re
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock
from test_cases.module_loader import load_script
from test_cases.test_initial_setup_target_password_policy import required_external_kat

ROOT=Path(__file__).resolve().parents[1]
INITIAL=ROOT/"infiniband/bringup/xdr-initial-setup/initial-setup.py"
APP=load_script("independent_ib_phase_protocol",INITIAL)
FIELDS=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
READ=["nv","config","show","-o","commands"]
PAYLOAD="nv set system hostname nvos\nnv set service lldp state enabled\n"
OOB="PUBLIC-OOB-CURRENT-47!"
def nine(info):
    return tuple(getattr(info,x)for x in FIELDS)
def snapshot(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=nine(os.fstat(fd))
        if not stat.S_ISREG(before[2])or before[5]!=1 or before[6]>65536:
            raise RuntimeError("FIXTURE HOLD: bounded owned REG required")
        raw=os.read(fd,before[6]+1)
        if len(raw)!=before[6]or os.read(fd,1)or nine(os.fstat(fd))!=before or nine(path.lstat())!=before:
            raise RuntimeError("FIXTURE HOLD: changing owned input")
        return before,raw
    finally:os.close(fd)

PEER_PROGRAM=r'''import json, os, re, select, shlex, signal, sys, termios, time
from pathlib import Path
P = Path(sys.argv[1]); C = json.loads(P.read_text()); home = P.parent
def emit(text):
    os.write(1, text.encode())
def event(kind, **values):
    data=(json.dumps(dict(kind=kind, **values),sort_keys=True)+"\n").encode()
    if len(data)>2048: raise ValueError("observer bound")
    fd=os.open(home/"peer-events.jsonl",os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
    try:
        if os.fstat(fd).st_size>65536: raise ValueError("observer cap")
        os.write(fd,data)
    finally: os.close(fd)
def receive():
    deadline=time.monotonic()+2;raw=b""
    while len(raw)<=130:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([0],[],[],remaining)[0]:return None
        part=os.read(0,131-len(raw))
        if not part:return None
        raw+=part
        if b"\n"in raw:
            if not raw.endswith(b"\n")or raw.count(b"\n")!=1:return None
            return raw[:-1].rstrip(b"\r").decode()
    return None
def answer(prompt):
    emit(prompt)
    return receive()
def roles(value):
    return dict(initial=value==C["initial"],target=value==C["target"],oob=value==C["oob"])
def parse():
    args=sys.argv[2:]
    prefix=["-tt","-o","ConnectTimeout=2","-o","ServerAliveInterval=10","-o","ServerAliveCountMax=2",
            "-o","StrictHostKeyChecking=accept-new","-o","LogLevel=ERROR",
            "-o","ControlMaster=no","-o","ControlPath=none","cumulus@192.0.2.10"]
    if args[:-1]!=prefix: raise ValueError("outer vector")
    shell=shlex.split(args[-1])
    carrier="export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
    if len(shell)!=3 or shell[:2]!=["sh","-c"]or not shell[2].startswith(carrier):raise ValueError("PATH carrier")
    phase=shlex.split(shell[2][len(carrier):])
    if len(phase)!=3 or phase[:2]!=["sh","-c"]:raise ValueError("phase shell")
    source=phase[2]
    m=re.match(r'^printf "\\n__HTTP_IB_AUTH_([0-9a-f]{32})_(auth-probe-readonly|password-change|post-change-read|ordinary-operation)__=BEGIN\\n"; ',source)
    if not m:raise ValueError("phase prefix")
    nonce,op=m.groups()
    tail='; inner_rc=$?; printf "\\n__HTTP_IB_AUTH_'+nonce+'_'+op+'__=EXIT:%s\\n" "$inner_rc"; exit "$inner_rc"'
    if not source.endswith(tail):raise ValueError("phase suffix")
    inner=shlex.split(source[m.end():-len(tail)])
    base=["ip","vrf","exec","default","ssh","-6","-tt","-o","ConnectTimeout=2",
          "-o","StrictHostKeyChecking=accept-new","-o","LogLevel=ERROR","-o","ControlMaster=no",
          "-o","ControlPath=none","-o","NumberOfPasswordPrompts=1"]
    extra=["-o","PubkeyAuthentication=no","-o","PreferredAuthentications=password,keyboard-interactive"]
    required=base+extra if op in("auth-probe-readonly","password-change","post-change-read")else base
    if inner[:-4]!=required or inner[-4:-1]!=["-B","vlan1","admin@fe80::17"]:raise ValueError("inner vector")
    cmd=shlex.split(inner[-1])
    if len(cmd)!=3 or cmd[:2]!=["sh","-c"]:raise ValueError("command shell")
    start='printf "\\n__HTTP_IB_BEGIN_'+nonce+'__\\n"; '
    end='; task_rc=$?; printf "\\n__HTTP_IB_END_'+nonce+'__=%s\\n" "$task_rc"; exit "$task_rc"'
    if not cmd[2].startswith(start)or not cmd[2].endswith(end):raise ValueError("frame request")
    if shlex.split(cmd[2][len(start):-len(end)])!=["nv","config","show","-o","commands"]:raise ValueError("not sole readonly request")
    return nonce,op
def run():
    attrs=termios.tcgetattr(0);attrs[3]&=~termios.ECHO;termios.tcsetattr(0,termios.TCSANOW,attrs)
    nonce,op=parse();case=C["case"]
    if case=="uncertain":signal.signal(signal.SIGHUP,signal.SIG_IGN)
    event("request",nonce=nonce,operation=op)
    outer=answer("cumulus@192.0.2.10's password: ")
    event("outer-answer",**roles(outer))
    if outer!=C["oob"]:return 255
    realnonce=nonce
    if case=="wrong-nonce":nonce="0"*32 if nonce!="0"*32 else "1"*32
    wireop="ordinary-operation"if case=="wrong-operation"else op
    begin="\n__HTTP_IB_AUTH_"+nonce+"_"+wireop+"__=BEGIN\n"
    end=lambda code:"\n__HTTP_IB_AUTH_"+nonce+"_"+wireop+"__=EXIT:"+str(code)+"\n"
    denied="\nadmin@fe80::17: Permission denied (password).\n"
    if case=="reverse-phase":emit(end(255))
    if case not in ("no-phase","missing-begin"):emit(begin)
    if case=="double-begin":emit(begin)
    if case=="diagnostic-before-full-write":
        # One actual <=PIPE_BUF write. Parent must independently witness that
        # actual os.read observed prompt+denied before any full credential write.
        emit("admin@fe80::17's password: "+denied)
        got=receive()
    elif case=="prompt-absent":
        got=None
    elif case=="double-prompt":
        got=answer("admin@fe80::17's password: \nadmin@fe80::17's password: ")
    else:
        got=answer("admin@fe80::17's password: ")
    event("inner-answer",complete=got is not None,**roles(got))
    if case in ("timeout","uncertain"):
        (home/"ready").write_bytes(b"PUBLIC-READY\n")
        event("ready")
        select.select([],[],[],10)
        return 255
    if case=="readonly-expiry":
        event("expiry")
        emit("\nYour password has expired.\n(current) UNIX password: ")
        select.select([],[],[],10)
        return 1
    if case in ("pam","global-before-new"):
        if op!="password-change":raise ValueError("test requested wrong PAM operation")
        old=answer("\nYour password has expired.\n(current) UNIX password: ")
        event("pam-current",complete=old is not None,initial=old==C["initial"])
        if case=="global-before-new":
            with open(C["global"],"a")as stream:stream.write("# PUBLIC global changed before new password\n")
            event("global-changed")
        new=answer("\nNew password: ")
        event("pam-new",complete=new is not None,target=new==C["target"])
        confirm=answer("\nRetype new password: ")
        event("pam-confirm",complete=confirm is not None,target=confirm==C["target"])
        if old!=C["initial"]or new!=C["target"]or confirm!=C["target"]:return 1
        emit("\npasswd: all authentication tokens updated successfully\n");emit(end(0));event("finish",declared=0);return 0
    good=case in ("success","post-change-success","duplicate-command-frame","payload-status-mismatch","hostname-notice-value","unexpected-password-notice")
    if case=="candidate-select":good=got==C["target"]
    if case=="both-reject":good=False
    if case=="network":emit("\nssh: connect to host fe80::17 port 22: Network is unreachable\n"+denied)
    elif case=="hostkey":emit("\nWARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"+denied)
    elif case=="outside-diag":
        emit(end(255));emit(denied);event("finish",declared=255);return 255
    elif case=="wrong-endpoint":emit("\nadmin@fe80::99: Permission denied (password).\n")
    elif not good and case!="diagnostic-before-full-write":emit(denied)
    body="nv set system hostname nvos\nnv set service lldp state enabled\n"
    if case=="hostname-notice-value":body="nv set system hostname password-updated-success\n"
    frame="\n__HTTP_IB_BEGIN_"+realnonce+"__\n"+body+"\n__HTTP_IB_END_"+realnonce+"__="
    if case=="unexpected-password-notice":
        try:
            emit("\npasswd: all authentication tokens updated successfully\n"+frame+"0\n"+end(0))
        except OSError as exc:
            import errno
            if exc.errno not in (errno.EIO,errno.EPIPE):raise
            event("notice-terminal-close")
            return 1
        event("finish",declared=0)
        return 0
    if good or case=="command-frame-present":
        emit(frame+("1"if case=="payload-status-mismatch"else"0")+"\n")
        if case=="duplicate-command-frame":emit(frame+"0\n")
    status=0 if good else 255
    if case not in ("no-phase","missing-exit"):emit(end(255 if case in ("actual-zero","actual-signal")else status))
    if case=="double-exit":emit(end(status))
    event("finish",declared=status)
    if case=="actual-signal":os.kill(os.getpid(),signal.SIGTERM)
    return 0 if case=="actual-zero"else status
try:rc=run()
except BaseException as exc:
    try:event("adapter-error",exception_type=type(exc).__name__)
    except BaseException:pass
    rc=86
raise SystemExit(rc)
'''

class IndependentIBPhaseProtocolDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required={"_phase_operation","_password_policy"}
        if not required.issubset(inspect.signature(APP.run_on_ib).parameters)or not hasattr(APP,"IBAuthenticationError")or not callable(getattr(APP,"_authenticate_ib_read",None)):
            raise RuntimeError("PREREQUISITE HOLD: reviewed phase/selector ABI not implemented; not a behavior RED")
        cls.kat=required_external_kat()
        for algorithm in ("SHA512","YESCRYPT"):
            if not APP.verify_password_hash(cls.kat["PASSWORD"],cls.kat[algorithm])or APP.verify_password_hash("Incorrect123!",cls.kat[algorithm]):
                raise RuntimeError("FIXTURE HOLD: original native KAT unavailable")

    def fixture(self,folder,case,*,initial="admin"):
        root=Path(folder)
        global_path=root/"01-global.yaml"
        global_path.write_text("schema_version: 2\ncommon:\n  switch:\n    system:\n      hostname: PUBLIC-COMMON\nswitches:\n- ib:\n    system:\n      aaa:\n        user:\n          admin:\n            password: "
            +json.dumps(self.kat["YESCRYPT"])
            +"\n",encoding="utf-8")
        env=root/"auto.env"
        env.write_text("NVOS_INITIAL_PASSWORD="+initial+"\nNVOS_TARGET_PASSWORD="+self.kat["PASSWORD"]+"\nZTP_ETH_PASSWORD_EXAMPLE_JUMP01="+OOB+"\n",encoding="utf-8")
        env.chmod(0o600)
        # Actual data reader, not a dictionary injected into a consumer.
        values=APP.read_auto_credentials(env)
        self.assertTrue(values["NVOS_INITIAL_PASSWORD"]==initial and values["NVOS_TARGET_PASSWORD"]==self.kat["PASSWORD"])
        control=root/"foreign-control";control.write_bytes(b"PUBLIC-CONTROL\n");control.chmod(0o600)
        peer=root/"owned-peer.py";peer.write_text(PEER_PROGRAM,encoding="utf-8");peer.chmod(0o600)
        config=root/"peer-config.json";config.write_text(json.dumps({"case":case,"initial":initial,"target":self.kat["PASSWORD"],"oob":OOB,"global":str(global_path)}),encoding="utf-8");config.chmod(0o600)
        ib=APP.Device("EXAMPLE-IB01","ib","203.0.113.2","203.0.113.2/24","203.0.113.1","02:00:00:00:00:17","","")
        eth=APP.Device("EXAMPLE-JUMP01","eth_jump","192.0.2.10","","","","","")
        target=APP.Target(ib,eth,"swp7","eth0")
        neighbor=APP.Neighbor("fe80::17","vlan1","02:00:00:00:00:17","default")
        return dict(root=root,global_path=global_path,env=env,env_before=snapshot(env),
                    control=control,control_before=snapshot(control),peer=peer,config=config,
                    target=target,neighbor=neighbor,initial=initial)
    def setcase(self,f,case):
        c=json.loads(f["config"].read_text());c["case"]=case
        f["config"].write_text(json.dumps(c),encoding="utf-8")
        f["config"].chmod(0o600)
    def peer_events(self,f):
        p=f["root"]/"peer-events.jsonl"
        return []if not p.exists()else[json.loads(x)for x in snapshot(p)[1].decode().splitlines()]

    def drive(self,f,operation="auth-probe-readonly",*,policy=None,password=None,allow=False,
              selector=False,write_fault=None,uncertain=False,timeout=False,input_error=None,ib_user="admin",ib_command=None,read_notice=False,read_errno=None):
        # Transparent observations of real kernel calls; no fake CP/result/error.
        real_fork=APP.pty.fork;real_exec=os.execve;real_read=os.read;real_write=os.write
        real_close=os.close;real_fstat=os.fstat;real_wait=os.waitpid
        real_kill=os.kill;real_killpg=os.killpg;real_clock=time.monotonic
        active=set();slots=[];order=[];boundary_errors=[];actual_reaps=[];fixture_drains=[]
        fault_used=False;short_pending=None;in_transport=False;last_master=None
        eagain_count=0
        input_progress={}
        notice_seen=False;notice_tail=""
        original_interactive=APP.interactive_run
        controlled=f["root"]/"ready"
        controlfd=os.open(f["control"],os.O_RDONLY|os.O_NOFOLLOW)
        controlnine=nine(real_fstat(controlfd))
        def log(kind,**facts):
            order.append(dict(kind=kind,index=len(order),**facts))
        def fork():
            nonlocal last_master
            pair=real_fork()
            if pair[0]>0:
                slots.append((pair[0],pair[1],nine(real_fstat(pair[1]))))
                active.add(pair[1]);last_master=pair[1];log("fork")
            return pair
        def execute(name,argv):
            try:
                if name!="ssh"or type(argv)is not list or not argv or argv[0]!="ssh":
                    raise AssertionError("outside owned SSH executable boundary")
                real_exec(sys.executable,[sys.executable,"-I","-S","-B",str(f["peer"]),str(f["config"]),*argv[1:]],
                          dict(PATH=os.defpath,LC_ALL="C",LANG="C",PYTHONDONTWRITEBYTECODE="1"))
            except BaseException as exc:
                raw=(json.dumps(dict(kind="adapter-error",stage="exec",exception_type=type(exc).__name__))+"\n").encode()
                fd=os.open(f["root"]/"peer-events.jsonl",os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
                try:real_write(fd,raw)
                finally:real_close(fd)
                os._exit(86)
        read_prefix=""
        read_observed=False
        def errno_read(fd,size):
            nonlocal read_prefix,read_observed
            model=read_errno
            facts=model["facts"]
            planned=None
            before_complete=facts["prefix_complete"]
            before_reap=bool(actual_reaps)
            def fixture_error(stage,error):
                label=type(error).__name__
                if label not in ("OSError","AssertionError","RuntimeError","ValueError","TypeError","KeyError"):
                    label="OTHER"
                facts["errors"].append(dict(stage=stage,exception_type=label))
            def qualify():
                identity=next(identity for _,master,identity in slots if master==fd)
                if nine(real_fstat(fd))[:6]!=identity[:6]:
                    raise RuntimeError("FIXTURE HOLD: read observer lost its actual owned master")
                facts["owned_live"]=True
            def mark():
                facts["injections"]+=1
                facts["point"]=model["point"]
                facts["complete_before"]=before_complete
                facts["reaped_before"]=before_reap
                facts["known_status_before"]=actual_reaps[-1] if actual_reaps else None
            try:
                qualify()
                if (model["kind"]=="fatal" and model["point"]=="drain" and
                        before_complete and before_reap and facts["injections"]==0):
                    mark()
                    planned=model["error"]
            except BaseException as error:
                fixture_error("pre-read",error)
                raise
            if planned is not None:
                # Modeled errno at the actual owned drain read call, not a
                # fake syscall return/reap or a replacement result object.
                raise planned
            try:
                raw=real_read(fd,size)
            except OSError as error:
                if error.errno==errno.EIO:
                    facts["real_eio_calls"]+=1
                    facts["real_eio_after_complete"]|=before_complete
                elif error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):
                    fixture_error("unmodeled-real-read",error)
                raise
            try:
                if raw==b"":
                    facts["real_eof_calls"]+=1
                    facts["real_eof_after_complete_calls"]+=int(before_complete)
                    facts["real_eof_after_known_reap_calls"]+=int(before_reap)
                    facts["real_eof_complete_known_reap_calls"]+=int(before_complete and before_reap)
                    facts["real_eof_complete_known_zero_calls"]+=int(before_complete and before_reap and actual_reaps[-1]==0)
                    facts["real_eof_known_zero_calls"]+=int(before_reap and actual_reaps[-1]==0)
                    facts["real_eof_known_255_calls"]+=int(before_reap and actual_reaps[-1]==255)
                if raw:
                    text=raw.decode("utf-8","replace").replace("\r","")
                    log("read",prompt="admin@fe80::17's password:"in text,
                        denied="admin@fe80::17: Permission denied (password)."in text,
                        begin="__HTTP_IB_AUTH_"in text and "__=BEGIN"in text)
                    read_prefix+=text
                    if len(read_prefix)>4*1024*1024:
                        raise RuntimeError("FIXTURE HOLD: read observer prefix exceeded its existing bound")
                    status=model["declared"]
                    phase=bool(re.search(
                        r"(?m)^__HTTP_IB_AUTH_[0-9a-f]{32}_auth-probe-readonly__=EXIT:"+str(status)+r"\n",
                        read_prefix))
                    body=(PAYLOAD in read_prefix and bool(re.search(
                        r"(?m)^__HTTP_IB_END_[0-9a-f]{32}__=0\n",read_prefix))
                        if status==0 else
                        "admin@fe80::17: Permission denied (password).\n"in read_prefix)
                    facts["prefix_complete"]=phase and body
                    if model["point"]=="main" and facts["prefix_complete"] and not read_observed:
                        with (f["root"]/"read-observed").open("xb")as stream:
                            stream.write(b"PUBLIC-PREFIX-OBSERVED\n")
                        read_observed=True
                    if (model["point"]=="main" and before_complete and not before_reap
                            and "\nPUBLIC-READ-PROBE\n"in text and facts["injections"]==0):
                        qualify()
                        facts["probe_actual_read"]=True
                        mark()
                        with (f["root"]/"read-release").open("xb")as stream:
                            stream.write(b"PUBLIC-RELEASE\n")
                        if model["kind"]=="eagain":
                            planned=BlockingIOError(errno.EAGAIN,"PUBLIC modeled owned read temporarily unavailable")
                        elif model["kind"]=="fatal":
                            planned=model["error"]
                        else:
                            raise RuntimeError("FIXTURE HOLD: unsupported main read model")
            except BaseException as error:
                fixture_error("post-read",error)
                raise
            if planned is not None:
                # Only the known PUBLIC probe has been consumed by this
                # observer; the product already received the full prefix.
                # This models an errno at that call, never a native errno claim.
                raise planned
            return raw
        def read(fd,size):
            if read_errno is not None and fd in active:
                return errno_read(fd,size)
            nonlocal notice_seen,notice_tail
            raw=real_read(fd,size)
            if fd in active and raw:
                text=raw.decode("utf-8","replace").replace("\r","")
                if read_notice:
                    line="\npasswd: all authentication tokens updated successfully\n"
                    notice_seen=notice_seen or line in notice_tail+text
                    notice_tail=(notice_tail+text)[-(len(line)-1):]
                log("read",prompt="admin@fe80::17's password:"in text,
                    denied="admin@fe80::17: Permission denied (password)."in text,
                    begin="__HTTP_IB_AUTH_"in text and "__=BEGIN"in text)
            return raw
        def written(fd,raw,n):
            if fd not in active:return
            progress=input_progress.get(fd,b"")+raw[:n]
            known=(("current",f["initial"].encode()+b"\n"),("target",self.kat["PASSWORD"].encode()+b"\n"),("oob",OOB.encode()+b"\n"))
            complete=next((role for role,value in known if progress==value),None)
            if complete is not None:
                log("write",role=complete,full=True,written=len(progress));input_progress[fd]=b""
            elif any(value.startswith(progress)for _,value in known)and len(progress)<=130:
                input_progress[fd]=progress;log("write",role="fragment",full=False,written=n)
            else:
                input_progress[fd]=b"";log("write",role="other",full=False,written=n)
        def write(fd,data):
            nonlocal fault_used,short_pending,eagain_count
            raw=bytes(data)
            is_current=raw==f["initial"].encode()+b"\n"
            if fd in active and is_current and write_fault in ("eagain-once","eagain-deadline"):
                if write_fault=="eagain-deadline"or eagain_count==0:
                    eagain_count+=1
                    log("input-eagain",nonblocking=os.get_blocking(fd)is False)
                    if write_fault=="eagain-deadline"and eagain_count>=2:
                        controlled.write_bytes(b"PUBLIC existing-deadline clock MODEL\\n")
                    raise BlockingIOError(errno.EAGAIN,"PUBLIC owned credential-input would block")
            if fd in active and is_current and write_fault and not fault_used:
                fault_used=True
                if write_fault=="short-zero":
                    n=real_write(fd,raw[:2]);short_pending=raw[n:]
                    written(fd,raw,n);log("partial-current",written=n);return n
                if write_fault=="eio":
                    log("input-eio")
                    raise input_error if input_error is not None else OSError(errno.EIO,"PUBLIC credential-input fault")
            if fd in active and short_pending is not None and raw==short_pending:
                log("zero-current");return 0
            n=real_write(fd,data)
            written(fd,raw,n)
            return n
        def close(fd):
            own=fd in active
            if in_transport and fd==last_master:log("master-close-attempt")
            if own:active.remove(fd);log("close")
            real_close(fd)
            if own:
                try:real_fstat(fd)
                except OSError as exc:
                    if exc.errno!=errno.EBADF:raise
                else:raise AssertionError("owned master was not actually closed")
        def wait(pid,flags):
            result=real_wait(pid,flags)
            if any(p==pid for p,_,_ in slots):
                log("wait",flags=flags,reaped=result[0]==pid,zero=result[0]==0)
            if any(p==pid for p,_,_ in slots)and result[0]==pid:
                actual_reaps.append(os.waitstatus_to_exitcode(result[1]))
                log("reap",actual_exit=actual_reaps[-1])
            return result
        def ready(pid):
            return uncertain and controlled.is_file()and any(p==pid for p,_,_ in slots)
        def killpg(pid,sig):
            if ready(pid):raise PermissionError(1,"PUBLIC modeled owned group refusal")
            return real_killpg(pid,sig)
        def kill(pid,sig):
            if ready(pid):raise PermissionError(1,"PUBLIC modeled owned signal refusal")
            return real_kill(pid,sig)
        def clock():
            return real_clock()+(1000 if (uncertain or timeout) and controlled.is_file() else 0)
        def interactive(*args,**kwargs):
            nonlocal in_transport
            in_transport=True
            try:return original_interactive(*args,**kwargs)
            finally:in_transport=False
        def observe(stage,func):
            def wrapped(*args,**kwargs):
                try:return func(*args,**kwargs)
                except (AssertionError,RuntimeError)as exc:
                    boundary_errors.append(dict(stage=stage,exception_type=type(exc).__name__))
                    raise
            return wrapped
        returned,caught=None,None
        try:
            with mock.patch.object(APP.pty,"fork",new=observe("fork",fork)),mock.patch.object(APP.os,"execvp",new=execute),\
                 mock.patch.object(APP.os,"read",new=observe("read",read)),mock.patch.object(APP.os,"write",new=observe("write",write)),\
                 mock.patch.object(APP.os,"close",new=observe("close",close)),mock.patch.object(APP.os,"waitpid",new=observe("wait",wait)),\
                 mock.patch.object(APP.os,"killpg",new=killpg),mock.patch.object(APP.os,"kill",new=kill),\
                 mock.patch.object(APP.time,"monotonic",new=clock),mock.patch.object(APP,"interactive_run",new=interactive):
                try:
                    args=(f["target"],f["neighbor"],"cumulus",OOB,ib_user,password if password is not None else f["initial"],2)
                    if selector:
                        returned=APP._authenticate_ib_read(*args,_password_policy=policy,local=False)
                    else:
                        returned=APP.run_on_ib(*args,READ if ib_command is None else ib_command,local=False,allow_password_change=allow,
                                               ib_new_password=self.kat["PASSWORD"]if allow else None,
                                               _phase_operation=operation,_password_policy=policy)
                    log("returned")
                except BaseException as exc:
                    caught=exc;log("caught",exception_type=type(exc).__name__)
        finally:
            # Fixture-only bounded custody. This is never counted as SUT reap.
            for pid,fd,identity in slots:
                try:seen,_=real_wait(pid,os.WNOHANG)
                except ChildProcessError:continue
                if seen==0:
                    try:real_killpg(pid,signal.SIGKILL)
                    except ProcessLookupError:
                        try:real_kill(pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                    deadline=real_clock()+2
                    while real_clock()<deadline:
                        seen,_=real_wait(pid,os.WNOHANG)
                        if seen:break
                        time.sleep(0.01)
                    if not seen:raise RuntimeError("FIXTURE HOLD: owned child custody unresolved")
                    fixture_drains.append(True)
            for fd in tuple(active):
                if nine(real_fstat(fd))!=next(n for _,x,n in slots if x==fd):
                    raise RuntimeError("FIXTURE HOLD: owned master rebound")
                real_close(fd);active.remove(fd)
            self.assertEqual(controlnine,nine(real_fstat(controlfd)))
            real_close(controlfd)
        events=self.peer_events(f)
        self.assertEqual([],boundary_errors)
        self.assertEqual([],[e for e in events if e["kind"]=="adapter-error"],
                         "peer prerequisite failure is fixture HOLD, never a product rejection PASS")
        self.assertTrue(f["env_before"]==snapshot(f["env"]),"protocol must preserve credential full9/bytes")
        self.assertEqual(f["control_before"],snapshot(f["control"]))
        text=repr(events)+(" "+str(caught)+" "+repr(caught.args)if caught is not None else"")
        self.assertTrue(all(v not in text for v in (OOB,self.kat["PASSWORD"],self.kat["SHA512"],self.kat["YESCRYPT"])),
                        "observer/error data must not contain credential/KAT values")
        return dict(result=returned,error=caught,order=order,peer=events,reaps=actual_reaps,
                    fixture_drains=fixture_drains,forks=len(slots),notice_read=notice_seen)

    def assert_custody(self,out,*,count=1):
        self.assertEqual(count,out["forks"])
        self.assertEqual(count,len(out["reaps"]),"actual SUT must reap its exact children")
        self.assertEqual(count,sum(x["kind"]=="master-close-attempt"for x in out["order"]))
        self.assertEqual([],out["fixture_drains"],"fixture custody cannot stand in for product reap")
    def test_admin_rejection_requires_actual_complete_input_then_diagnostic_and_reap(self):
        with tempfile.TemporaryDirectory(prefix="ib-phase-admin-")as folder:
            f=self.fixture(folder,"reject")
            out=self.drive(f)
            self.assertTrue(isinstance(out["error"],APP.IBAuthenticationError),"expected attributed IB rejection; raw error suppressed")
            self.assertTrue(out["result"]is None,"unexpected result; raw output suppressed")
            self.assert_custody(out)
            self.assertEqual([255],out["reaps"])
            prompt=[e["index"]for e in out["order"]if e["kind"]=="read"and e["prompt"]]
            sent=[e["index"]for e in out["order"]if e["kind"]=="write"and e["role"]=="current"and e["full"]]
            denied=[e["index"]for e in out["order"]if e["kind"]=="read"and e["denied"]]
            self.assertTrue(prompt and sent and denied)
            self.assertLess(prompt[0],sent[0])
            self.assertLess(sent[0],denied[0],"final text order cannot replace real read/write order")
            self.assertTrue(any(e["kind"]=="inner-answer"and e["initial"]and e["complete"]for e in out["peer"]))
            self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))
            self.assertFalse(getattr(out["error"],"cleanup_uncertain",False))
            # The literal admin is simultaneously a username and factory
            # credential. Real classification must precede broad redaction.
            self.assertTrue("admin"in f["initial"])
    def test_marker_status_prompt_and_non_auth_temporal_failures_never_yield_typed_rejection(self):
        cases=("no-phase","missing-begin","missing-exit","double-begin","double-exit",
               "reverse-phase","wrong-nonce","wrong-operation","actual-zero","actual-signal",
               "command-frame-present","duplicate-command-frame","payload-status-mismatch",
               "outside-diag","wrong-endpoint","prompt-absent","double-prompt",
               "diagnostic-before-full-write","network","hostkey","timeout")
        for case in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory(prefix="ib-phase-negative-")as folder:
                f=self.fixture(folder,case)
                with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("non-auth HOLD cannot request a target"))as backend,\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("non-auth HOLD cannot prompt"))as prompt:
                    policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                    out=self.drive(f,timeout=case=="timeout",selector=True,policy=policy)
                if case=="diagnostic-before-full-write":
                    witnesses=[e for e in out["order"]if e["kind"]=="read"and e["prompt"]and e["denied"]]
                    if not witnesses:
                        raise RuntimeError("FIXTURE HOLD: required coalesced actual read witness absent; not a product result")
                self.assertEqual(0,backend.call_count)
                self.assertEqual(0,prompt.call_count)
                self.assertTrue(out["result"]is None,"unexpected result; raw output suppressed")
                self.assertTrue(isinstance(out["error"],APP.SetupError),"expected safe domain HOLD; raw error suppressed")
                self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),"uncertain/non-auth failure must not authorize fallback")
                self.assert_custody(out)
                self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]),
                                 "a protocol error cannot create another credential session")
                if case=="actual-zero":
                    self.assertEqual([0],out["reaps"])
                if case=="actual-signal":
                    self.assertEqual([-signal.SIGTERM],out["reaps"])
                if case=="diagnostic-before-full-write":
                    full=[e["index"]for e in out["order"]if e["kind"]=="write"and e["role"]=="current"and e["full"]]
                    self.assertTrue(not full or witnesses[0]["index"]<full[0],
                                    "independent witness must expose denial before any completed input")
    def test_credential_short_write_and_uncertain_custody_cannot_confirm_authentication(self):
        for fault in ("short-zero","eio"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix="ib-phase-input-")as folder:
                f=self.fixture(folder,"reject")
                with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("input uncertainty cannot request a target"))as backend,\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("input uncertainty cannot prompt"))as prompt:
                    policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                    out=self.drive(f,write_fault=fault,selector=True,policy=policy)
                self.assertEqual(0,backend.call_count)
                self.assertEqual(0,prompt.call_count)
                self.assertTrue(out["result"]is None,"unexpected result; raw output suppressed")
                self.assertTrue(isinstance(out["error"],(APP.SetupError,OSError)),"expected bounded input failure; raw error suppressed")
                self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),"uncertain/non-auth failure must not authorize fallback")
                self.assert_custody(out)
                self.assertFalse(any(e["kind"]=="write"and e["role"]=="current"and e["full"]for e in out["order"]))
                self.assertTrue(any(e["kind"]==("partial-current"if fault=="short-zero"else"input-eio")for e in out["order"]),
                                "actual credential input fault must be reached")
        with tempfile.TemporaryDirectory(prefix="ib-phase-uncertain-")as folder:
            f=self.fixture(folder,"uncertain")
            with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("unconfirmed reap cannot request a target"))as backend,\
                 mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("unconfirmed reap cannot prompt"))as prompt:
                policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                out=self.drive(f,uncertain=True,selector=True,policy=policy)
            self.assertEqual(0,backend.call_count)
            self.assertEqual(0,prompt.call_count)
            self.assertTrue(out["result"]is None,"unexpected result; raw output suppressed")
            self.assertTrue(isinstance(out["error"],APP.SetupError),"expected safe domain HOLD; raw error suppressed")
            self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),"uncertain/non-auth failure must not authorize fallback")
            self.assertTrue(getattr(out["error"],"cleanup_uncertain",None)is True)
            self.assertEqual([],out["reaps"],"fixture drain is not a product reap")
            self.assertEqual([True],out["fixture_drains"])
            self.assertTrue(any(e["kind"]=="wait"and e["zero"]and e["flags"]==os.WNOHANG for e in out["order"]))
            self.assertEqual(1,sum(e["kind"]=="master-close-attempt"for e in out["order"]))
    def test_lazy_candidates_and_explicit_pam_require_real_project_guards_and_fresh_post_read(self):
        with tempfile.TemporaryDirectory(prefix="ib-phase-lazy-")as folder:
            f=self.fixture(folder,"success")
            with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("pure initial read must not verify a target"))as backend,\
                 mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("pure initial read must not prompt"))as prompt:
                policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",interactive=True)
                out=self.drive(f,selector=True,policy=policy)
            self.assertTrue(out["error"]is None,"unexpected failure; raw error suppressed")
            self.assertTrue(PAYLOAD==out["result"].read_result.output,"independent command payload mismatch; raw output suppressed")
            self.assertTrue(out["result"].current_password==f["initial"],"initial source selected by real read")
            self.assertEqual(0,backend.call_count)
            self.assertEqual(0,prompt.call_count)
            self.assert_custody(out)
            self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))
        for case,equal,wanted in (("candidate-select",False,2),("both-reject",False,2),("both-reject",True,1)):
            with self.subTest(case=case,equal=equal),tempfile.TemporaryDirectory(prefix="ib-phase-select-")as folder:
                f=self.fixture(folder,case,initial=self.kat["PASSWORD"]if equal else"admin")
                native=APP.verify_password_hash;observed=[]
                def genuine(password,setting):
                    observed.append(sum(e["kind"]=="request"for e in self.peer_events(f)))
                    return native(password,setting)
                with mock.patch.object(APP,"verify_password_hash",new=genuine),\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("formal auto may not prompt"))as prompt:
                    policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                    out=self.drive(f,selector=True,policy=policy)
                self.assert_custody(out,count=wanted)
                self.assertEqual(wanted,sum(e["kind"]=="request"for e in out["peer"]))
                self.assertTrue(bool(observed),"only a needed second known value is actually verified")
                self.assertEqual(1,observed[0],"target cannot be prompted/verified before the first actual probe")
                self.assertEqual(0,prompt.call_count)
                if case=="candidate-select":
                    self.assertTrue(out["error"]is None,"unexpected failure; raw error suppressed")
                    self.assertTrue(out["result"].current_password==self.kat["PASSWORD"])
                    self.assertTrue(PAYLOAD==out["result"].read_result.output,"independent command payload mismatch; raw output suppressed")
                    requests=[e for e in out["peer"]if e["kind"]=="request"]
                    self.assertEqual(2,len({e["nonce"]for e in requests}))
                else:
                    self.assertTrue(isinstance(out["error"],APP.SetupError),"expected safe domain HOLD; raw error suppressed")
                    self.assertTrue(out["result"]is None,"unexpected result; raw output suppressed")
        with tempfile.TemporaryDirectory(prefix="ib-phase-pam-")as folder:
            f=self.fixture(folder,"readonly-expiry")
            expired=self.drive(f)
            self.assertTrue(expired["error"]is None,"unexpected failure; raw error suppressed")
            self.assertTrue(expired["result"].password_change_required)
            self.assertFalse(expired["result"].password_changed)
            self.assertNotEqual(0,expired["result"].exit_code)
            self.assert_custody(expired)
            self.assertFalse(any(e["kind"]in("pam-new","pam-confirm")for e in expired["peer"]))
            self.setcase(f,"pam")
            policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
            self.assertTrue(policy.matches(policy.password()),"actual native project target before authorized action")
            changed=self.drive(f,"password-change",policy=policy,allow=True)
            self.assertTrue(changed["error"]is None,"unexpected failure; raw error suppressed")
            self.assertTrue(changed["result"].password_changed)
            self.assertEqual(0,changed["result"].exit_code)
            self.assertFalse("__HTTP_IB_BEGIN_"in changed["result"].output,
                             "password update notification is not a command result")
            self.assert_custody(changed)
            self.assertTrue(any(e["kind"]=="pam-new"and e["target"]and e["complete"]for e in changed["peer"]))
            self.assertTrue(any(e["kind"]=="pam-confirm"and e["target"]and e["complete"]for e in changed["peer"]))
            self.setcase(f,"post-change-success")
            post=self.drive(f,"post-change-read",password=self.kat["PASSWORD"],policy=policy)
            self.assertTrue(post["error"]is None,"unexpected failure; raw error suppressed")
            self.assertTrue(PAYLOAD==post["result"].output,"fresh target read payload mismatch; raw output suppressed")
            self.assertFalse(post["result"].password_changed)
            self.assert_custody(post)
            requests=[e for e in post["peer"]if e["kind"]=="request"]
            self.assertEqual(["auth-probe-readonly","password-change","post-change-read"],[e["operation"]for e in requests])
            self.assertEqual(3,len({e["nonce"]for e in requests}))
            self.setcase(f,"reject")
            before=len(requests)
            rejected=self.drive(f,"post-change-read",password=self.kat["PASSWORD"],policy=policy)
            self.assertTrue(isinstance(rejected["error"],APP.SetupError),"post-change rejection is HOLD; raw error suppressed")
            self.assertFalse(isinstance(rejected["error"],APP.IBAuthenticationError),"post-change failure cannot authorize fallback")
            self.assertEqual(before+1,sum(e["kind"]=="request"for e in rejected["peer"]))
            self.assert_custody(rejected)
        for guard in ("no-authorization","no-policy","wrong-target","changed-before-new"):
            with self.subTest(guard=guard),tempfile.TemporaryDirectory(prefix="ib-phase-guard-")as folder:
                f=self.fixture(folder,"global-before-new"if guard=="changed-before-new"else"pam")
                policy=None if guard=="no-policy"else APP.ProjectPasswordPolicy(
                    f["global_path"],"admin",target_password="PUBLIC-Wrong-Target-81!"if guard=="wrong-target"else self.kat["PASSWORD"],interactive=False)
                if guard=="changed-before-new":
                    self.assertTrue(policy.matches(policy.password()))
                out=self.drive(f,"password-change",policy=policy,allow=guard!="no-authorization")
                self.assertTrue(isinstance(out["error"],APP.SetupError),"expected safe domain HOLD; raw error suppressed")
                self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),"uncertain/non-auth failure must not authorize fallback")
                self.assertFalse(any(e["kind"]=="write"and e["role"]=="target"for e in out["order"]),
                                 "no new target bytes before actual unchanged project authority")
                if guard=="changed-before-new":
                    self.assertTrue(any(e["kind"]=="global-changed"for e in out["peer"]))
                    self.assert_custody(out)
                else:
                    self.assertEqual(0,out["forks"],"invalid PAM authority must fail before SSH birth")


    def test_known_strict_failures_drop_private_args_and_chains_but_program_errors_propagate(self):
        with tempfile.TemporaryDirectory(prefix="ib-phase-private-backend-")as folder:
            f=self.fixture(folder,"candidate-select")
            seed=APP.SetupError("PUBLIC backend-private "+self.kat["PASSWORD"])
            cause=OSError(errno.EIO,self.kat["SHA512"])
            context=RuntimeError(self.kat["YESCRYPT"])
            seed.__cause__=cause
            seed.__context__=context
            program_error=RuntimeError("PUBLIC observer program sentinel")
            native=APP.verify_password_hash
            reached=[]
            mode="domain"
            def verifier(password,setting):
                exact_target=password==self.kat["PASSWORD"]
                exact_hash=setting==self.kat["YESCRYPT"]
                reached.append({"requests":sum(e["kind"]=="request"for e in self.peer_events(f)),
                                "target":exact_target,"IB":exact_hash})
                if exact_target and exact_hash:
                    raise seed if mode=="domain"else program_error
                return native(password,setting)
            for expected in ("domain","program"):
                mode=expected
                before=sum(e["kind"]=="request"for e in self.peer_events(f))
                first_call=len(reached)
                with mock.patch.object(APP,"verify_password_hash",new=verifier),\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("explicit auto target must not prompt"))as prompt:
                    policy=None
                    born_error=None
                    try:
                        policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                    except BaseException as exc:
                        born_error=exc
                    self.assertTrue(born_error is None,
                                    "policy birth failed before actual phase; private exception suppressed")
                    out=self.drive(f,selector=True,policy=policy)
                self.assert_custody(out)
                self.assertEqual([255],out["reaps"],"first real rejected session must finish before target verification")
                self.assertEqual(before+1,sum(e["kind"]=="request"for e in out["peer"]),"backend failure cannot birth second session")
                self.assertEqual(0,prompt.call_count)
                self.assertEqual(1,len(reached)-first_call,"one exact needed native-verifier seam call")
                actual=reached[-1]
                self.assertTrue(actual["target"]and actual["IB"]and actual["requests"]==before+1,
                                "actual target/hash verification must follow the first real peer request")
                if expected=="domain":
                    error=out["error"]
                    self.assertTrue(type(error)is APP.SetupError and error is not seed,
                                    "known strict backend error must become a fresh safe domain error")
                    self.assertTrue(error.args==("IB phase project authority failed; device state is UNKNOWN",),
                                    "fixed backend failure args only; private error values suppressed")
                    self.assertTrue(error.__cause__ is None and error.__context__ is None,
                                    "fromNone alone is insufficient: no private cause/context may escape")
                    self.assertTrue(getattr(error,"cleanup_uncertain",False)is False)
                else:
                    self.assertTrue(out["error"]is program_error,
                                    "program/observer RuntimeError must propagate unchanged, not become business HOLD")
                    self.assertFalse(isinstance(out["error"],APP.SetupError))
            self.assertTrue(seed.__cause__ is cause and seed.__context__ is context and
                            seed.args==("PUBLIC backend-private "+self.kat["PASSWORD"],),
                            "sanitization must not mutate the original private exception")
        with tempfile.TemporaryDirectory(prefix="ib-phase-private-input-")as folder:
            f=self.fixture(folder,"reject")
            seed=OSError(errno.EIO,"PUBLIC input-private "+self.kat["PASSWORD"])
            cause=RuntimeError(self.kat["SHA512"])
            context=RuntimeError(self.kat["YESCRYPT"])
            seed.__cause__=cause
            seed.__context__=context
            with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("failed input cannot request target"))as backend,\
                 mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("failed input cannot prompt"))as prompt:
                policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                out=self.drive(f,selector=True,policy=policy,write_fault="eio",input_error=seed)
            self.assert_custody(out)
            self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))
            self.assertEqual(0,backend.call_count)
            self.assertEqual(0,prompt.call_count)
            prompts=[e["index"]for e in out["order"]if e["kind"]=="read"and e["prompt"]]
            faults=[e["index"]for e in out["order"]if e["kind"]=="input-eio"]
            self.assertTrue(prompts and faults and prompts[0]<faults[0],
                            "real owned credential FD fault must follow its actual prompt; early refusal is not evidence")
            error=out["error"]
            self.assertTrue(type(error)is APP.SetupError and error is not seed,
                            "known strict input failure must become a fresh safe domain error")
            self.assertTrue(error.args==("IB phase transport failed; device state is UNKNOWN",),
                            "fixed transport failure args only; private error values suppressed")
            self.assertTrue(error.__cause__ is None and error.__context__ is None,
                            "private IO cause/context must not escape the strict boundary")
            self.assertTrue(getattr(error,"io_errno",None)==errno.EIO,
                            "bounded errno semantics survive without arbitrary IO args")
            self.assertTrue(getattr(error,"cleanup_uncertain",False)is False)
            self.assertTrue(seed.__cause__ is cause and seed.__context__ is context and
                            seed.args==(errno.EIO,"PUBLIC input-private "+self.kat["PASSWORD"]),
                            "original private IO exception remains unmodified")

    def test_owned_nonblocking_input_recovers_after_one_eagain_before_auth_rejection(self):
        with tempfile.TemporaryDirectory(prefix="ib-phase-eagain-once-")as folder:
            f=self.fixture(folder,"reject")
            with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("initial probe must not fetch target"))as backend,\
                 mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("initial probe must not prompt"))as prompt:
                out=self.drive(f,write_fault="eagain-once")
            self.assertTrue(type(out["error"])is APP.IBAuthenticationError,
                            "only complete real credential input plus attributable reaped255 may authorize retry")
            self.assertTrue(out["result"]is None,"typed rejection is not a successful read")
            attempts=[e for e in out["order"]if e["kind"]=="input-eagain"]
            full=[e for e in out["order"]if e["kind"]=="write"and e["role"]=="current"and e["full"]]
            denied=[e for e in out["order"]if e["kind"]=="read"and e["denied"]]
            self.assertEqual(1,len(attempts))
            self.assertTrue(all(e["nonblocking"]is True for e in attempts),
                            "actual owned master must already be nonblocking at credential write")
            self.assertTrue(full and denied and attempts[0]["index"]<full[0]["index"]<denied[0]["index"],
                            "recovered full write must precede the actual denial read")
            self.assertEqual([255],out["reaps"])
            self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))
            self.assertEqual(0,backend.call_count)
            self.assertEqual(0,prompt.call_count)
            self.assert_custody(out)

    def test_owned_nonblocking_input_stops_at_original_deadline_without_fallback(self):
        with tempfile.TemporaryDirectory(prefix="ib-phase-eagain-deadline-")as folder:
            f=self.fixture(folder,"reject")
            with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("incomplete input cannot fetch target"))as backend,\
                 mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("incomplete input cannot prompt"))as prompt:
                policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                out=self.drive(f,selector=True,policy=policy,write_fault="eagain-deadline",timeout=True)
            attempts=[e for e in out["order"]if e["kind"]=="input-eagain"]
            self.assertGreaterEqual(len(attempts),2,"fault must reach the actual owned credential FD repeatedly")
            self.assertTrue(all(e["nonblocking"]is True for e in attempts))
            self.assertFalse(any(e["kind"]=="write"and e["role"]=="current"and e["full"]for e in out["order"]),
                             "persistent EAGAIN cannot be promoted to a completed credential write")
            self.assertTrue(type(out["error"])is APP.SetupError,"deadline uncertainty is safe domain HOLD")
            self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),"deadline cannot authorize second known value")
            self.assertTrue(out["error"].args==("IB phase transport failed; device state is UNKNOWN",),
                            "fixed safe deadline error only; raw error values suppressed")
            self.assertTrue(out["error"].__cause__ is None and out["error"].__context__ is None)
            self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))
            self.assertEqual(0,backend.call_count)
            self.assertEqual(0,prompt.call_count)
            self.assertEqual(1,len(out["reaps"]),"real SUT custody must finish before return")
            self.assert_custody(out)

    def test_real_policy_for_other_account_is_rejected_before_read_or_pam_birth(self):
        for operation in ("auth-probe-readonly","password-change"):
            with self.subTest(operation=operation),tempfile.TemporaryDirectory(prefix="ib-phase-other-account-")as folder:
                f=self.fixture(folder,"pam"if operation=="password-change"else"reject")
                with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("wrong account cannot verify target"))as backend,\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("wrong account cannot prompt"))as prompt,\
                     mock.patch.object(APP.ProjectPasswordPolicy,"password",side_effect=AssertionError("wrong account cannot fetch target"))as target_fetch:
                    policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                    out=self.drive(f,operation,policy=policy,ib_user="otheradmin",allow=operation=="password-change")
                self.assertTrue(policy.user=="admin","real policy belongs to independent original account")
                self.assertTrue(type(out["error"])is APP.SetupError,"wrong account is fixed domain HOLD")
                self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),"authority mismatch is not authentication fallback")
                self.assertTrue(out["error"].args==("IB phase project authority failed; device state is UNKNOWN",),
                                "wrong account must use fixed safe authority error")
                self.assertTrue(out["error"].__cause__ is None and out["error"].__context__ is None)
                self.assertTrue(out["result"]is None)
                self.assertEqual(0,backend.call_count)
                self.assertEqual(0,prompt.call_count)
                self.assertEqual(0,target_fetch.call_count)
                self.assertEqual(0,out["forks"],"policy account mismatch must reject before actual PTY birth")
                self.assertEqual([],out["peer"],"peer-side username rejection cannot stand in for preIO account qualification")
                self.assertEqual([],out["reaps"])
                self.assertEqual([],out["fixture_drains"])

    def test_closed_private_operation_cannot_borrow_general_ib_command_authority(self):
        cases=(
            ("unknown-operation",READ),
            (17,READ),
            ("ordinary-operation",READ),
            ("auth-probe-readonly",["nv","config","apply","-y"]),
            ("password-change",["nv","config","apply","-y"]),
            ("post-change-read",["nv","config","apply","-y"]),
            ("auth-probe-readonly",["true"]),
            ("auth-probe-readonly",["nv","show","system","ztp"]),
            ("auth-probe-readonly",["nv","config","diff","-o","commands"]),
            ("auth-probe-readonly",["nv","config","save"]),
        )
        for index,(operation,command)in enumerate(cases):
            with self.subTest(case=index),tempfile.TemporaryDirectory(prefix="ib-phase-closed-operation-")as folder:
                f=self.fixture(folder,"success")
                self.assertEqual(command,APP.ib_command_argv(command),
                                 "independent PUBLIC vector is allowed generally, not by this private operation")
                with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("unbound operation cannot verify target"))as backend,\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("unbound operation cannot prompt"))as prompt,\
                     mock.patch.object(APP.ProjectPasswordPolicy,"password",side_effect=AssertionError("unbound operation cannot fetch target"))as target_fetch:
                    policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                    out=self.drive(f,operation,policy=policy,ib_command=command,
                                   allow=operation=="password-change")
                self.assertTrue(type(out["error"])is APP.SetupError,"closed operation mismatch must reject safely")
                self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),"unbound operation cannot authorize fallback")
                self.assertTrue(out["result"]is None)
                self.assertEqual(0,backend.call_count)
                self.assertEqual(0,prompt.call_count)
                self.assertEqual(0,target_fetch.call_count)
                self.assertEqual(0,out["forks"],"unknown/unbound operation must reject before any actual PTY")
                self.assertEqual([],out["peer"],"a peer parser failure is not preIO qualification")
                self.assertEqual([],out["reaps"])
                self.assertEqual([],out["fixture_drains"])

    def test_post_change_read_requires_real_account_policy_and_verified_target_before_birth(self):
        for case in ("missing-policy","wrong-account","wrong-current"):
            with self.subTest(case=case),tempfile.TemporaryDirectory(prefix="ib-phase-post-target-")as folder:
                f=self.fixture(folder,"post-change-success")
                native=APP.verify_password_hash
                real_password=APP.ProjectPasswordPolicy.password
                verified=[];fetched=[]
                def genuine(password,setting):
                    verified.append(dict(target=password==self.kat["PASSWORD"],IB=setting==self.kat["YESCRYPT"],
                                         peer_requests=len(self.peer_events(f))))
                    return native(password,setting)
                def fetch(policy):
                    fetched.append(True)
                    return real_password(policy)
                with mock.patch.object(APP,"verify_password_hash",new=genuine),\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("explicit post target may not prompt"))as prompt,\
                     mock.patch.object(APP.ProjectPasswordPolicy,"password",new=fetch):
                    policy=None if case=="missing-policy"else APP.ProjectPasswordPolicy(
                        f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                    current="PUBLIC-Other-Current-79!"if case=="wrong-current"else self.kat["PASSWORD"]
                    out=self.drive(f,"post-change-read",policy=policy,password=(current),
                                   ib_user="otheradmin"if case=="wrong-account"else"admin")
                self.assertTrue(type(out["error"])is APP.SetupError,"post-change role mismatch is fixed safe domain HOLD")
                self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),"post-change qualification cannot authorize retry")
                self.assertTrue(out["error"].args==("IB phase project authority failed; device state is UNKNOWN",),
                                "fixed authority error only; credentials suppressed")
                self.assertTrue(out["error"].__cause__ is None and out["error"].__context__ is None)
                self.assertTrue(out["result"]is None)
                self.assertEqual(0,prompt.call_count)
                self.assertEqual(0,out["forks"],"post-change role must qualify before any SSH/PTY birth")
                self.assertEqual([],out["peer"])
                self.assertEqual([],out["reaps"])
                self.assertEqual([],out["fixture_drains"])
                if case=="wrong-current":
                    self.assertTrue(bool(fetched),"actual same-project target fetch must be reached")
                    self.assertTrue(any(e["target"]and e["IB"]and e["peer_requests"]==0 for e in verified),
                                    "real native target verification must precede rejecting the different current value")
                else:
                    self.assertEqual([],fetched,"missing/wrong-account policy cannot fetch target")
                    self.assertEqual([],verified,"missing/wrong-account policy cannot enter native backend")

    def test_show_hostname_password_words_are_data_but_actual_notification_is_not(self):
        cases=(("auth-probe-readonly","hostname-notice-value"),
               ("post-change-read","hostname-notice-value"),
               ("auth-probe-readonly","unexpected-password-notice"))
        for operation,case in cases:
            with self.subTest(operation=operation,case=case),tempfile.TemporaryDirectory(prefix="ib-phase-notice-line-")as folder:
                f=self.fixture(folder,case)
                native=APP.verify_password_hash;native_calls=[]
                def genuine(password,setting):
                    native_calls.append(True)
                    return native(password,setting)
                with mock.patch.object(APP,"verify_password_hash",new=genuine),\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("explicit phase fixture must not prompt"))as prompt:
                    policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)if operation=="post-change-read"else None
                    out=self.drive(f,operation,policy=policy,
                                   password=self.kat["PASSWORD"]if operation=="post-change-read"else None,
                                   read_notice=case=="unexpected-password-notice")
                self.assertEqual(0,prompt.call_count)
                self.assert_custody(out)
                self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))
                if case=="hostname-notice-value":
                    self.assertEqual([0],out["reaps"],"actual owned peer completed normally; payload classification is separate")
                    self.assertTrue(out["error"]is None,"valid NVUE hostname must not be classified as a passwd notification")
                    self.assertTrue(out["result"].output=="nv set system hostname password-updated-success\n",
                                    "independent exact PUBLIC hostname payload")
                    self.assertFalse(out["result"].password_changed)
                else:
                    if out["notice_read"]is not True:
                        raise RuntimeError("FIXTURE HOLD: actual parent-read canonical notice witness absent")
                    self.assertEqual(1,len(out["reaps"]),"actual own reap required; valid early cancellation need not be exit0")
                    self.assertEqual(0,len(native_calls),"notification HOLD must not request a target candidate")
                    self.assertTrue(type(out["error"])is APP.SetupError,"actual passwd notice in a read is safe HOLD")
                    self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError))
                    self.assertTrue(out["result"]is None)

    def test_actual_frames_and_pam_current_must_belong_to_the_live_phase(self):
        # Normal read remains a positive control, not a roundtrip-generated oracle.
        with tempfile.TemporaryDirectory(prefix="ib-phase-order-positive-")as folder:
            f=self.fixture(folder,"success")
            out=self.drive(f)
            self.assertTrue(out["error"]is None,"normal phase positive failed; raw error suppressed")
            self.assertTrue(out["result"]is not None,"normal read must return actual result")
            self.assertTrue(out["result"].output=="nv set system hostname nvos\nnv set service lldp state enabled\n",
                            "independent normal payload mismatch; raw result suppressed")
            self.assertEqual([0],out["reaps"])
            self.assert_custody(out)
        cases=(
            ("A-frame-before-phase","auth-probe-readonly","frame_before_phase"),
            ("A-frame-after-phase","auth-probe-readonly","frame_after_phase"),
            ("A-pam-current-before-phase","password-change","pam_current_before_phase"),
        )
        for case,operation,witness in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory(prefix="ib-phase-order-negative-")as folder:
                f=self.fixture(folder,case)
                f["peer"].write_text(_phase_order_peer_script(),encoding="utf-8")
                policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",
                        target_password=self.kat["PASSWORD"],interactive=False)if operation=="password-change"else None
                out,facts=_phase_order_drive(self,f,operation=operation,policy=policy,
                                             allow=operation=="password-change")
                if not facts[witness]:
                    raise RuntimeError("FIXTURE HOLD: malformed order not actually read from owned PTY")
                self.assertTrue(out["result"]is None,"phase-external evidence must not return success; raw result suppressed")
                self.assertTrue(isinstance(out["error"],APP.SetupError),"expected safe domain HOLD; raw error suppressed")
                self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),
                                 "phase-external evidence cannot authorize another candidate")
                self.assert_custody(out)
                self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))
                if operation=="password-change":
                    self.assertFalse(any(e["kind"]in("pam-current","pam-new","pam-confirm")and e.get("complete")
                                         for e in out["peer"]),
                                     "a stale outside-phase current prompt must not authorize PAM answers")


    def _read_errno_fixture(self,folder,case,point,kind,declared):
        if (case not in ("success","reject") or point not in ("main","drain")
                or kind not in ("fatal","eagain","real-eio")
                or type(declared)is not int or declared not in (0,255)
                or (kind=="eagain"and(point!="main"or case!="success"))
                or (kind=="real-eio"and(point!="drain"or case!="success"))):
            raise RuntimeError("FIXTURE HOLD: outside closed read-errno scene table")
        f=self.fixture(folder,case)
        if point=="main":
            f["peer"].write_text(READ_ERRNO_PEER_PROGRAM,encoding="utf-8")
            config=json.loads(f["config"].read_text(encoding="utf-8"))
            config["read_errno_barrier"]="main"
            f["config"].write_text(json.dumps(config),encoding="utf-8")
        error=OSError(errno.EACCES,"PUBLIC read-errno seed must not escape")
        cause=RuntimeError("PUBLIC read-errno cause")
        context=RuntimeError("PUBLIC read-errno context")
        error.__cause__=cause
        error.__context__=context
        model=dict(point=point,kind=kind,declared=declared,error=error,
                   cause=cause,context=context,
                   facts=dict(injections=0,point=None,owned_live=False,
                              prefix_complete=False,complete_before=False,
                              probe_actual_read=False,reaped_before=False,
                              known_status_before=None,real_eio_calls=0,
                              real_eof_calls=0,real_eof_after_complete_calls=0,
                              real_eof_after_known_reap_calls=0,real_eof_complete_known_reap_calls=0,
                              real_eof_complete_known_zero_calls=0,
                              real_eof_known_zero_calls=0,real_eof_known_255_calls=0,
                              real_eio_after_complete=False,errors=[]))
        return f,model

    def _assert_strict_read_errno_hold(self,point):
        for case,declared in (("success",0),("reject",255)):
            with self.subTest(point=point,case=case),tempfile.TemporaryDirectory(prefix="ib-phase-read-errno-")as folder:
                f,model=self._read_errno_fixture(folder,case,point,"fatal",declared)
                with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("read uncertainty cannot request target"))as backend,\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("read uncertainty cannot prompt"))as prompt:
                    policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",target_password=self.kat["PASSWORD"],interactive=False)
                    out=self.drive(f,selector=True,policy=policy,read_errno=model)
                facts=model["facts"]
                self.assertEqual([],facts["errors"],"read observer prerequisite failure is not product proof")
                self.assertEqual(1,facts["injections"],"actual owned read-errno boundary must be reached once")
                self.assertTrue(facts["owned_live"]and facts["complete_before"],
                                "actual live master and complete independent prefix must precede errno")
                self.assertEqual(point,facts["point"])
                if point=="main":
                    self.assertTrue(facts["probe_actual_read"]and not facts["reaped_before"],
                                    "main fault needs actual PUBLIC probe after prefix, before actual reap")
                else:
                    self.assertTrue(facts["reaped_before"]and facts["known_status_before"]==declared,
                                    "drain fault must follow the actual known child reap")
                    self.assertEqual([declared],out["reaps"],"known actual status cannot become process UNKNOWN")
                self.assert_custody(out)
                self.assertEqual(1,out["forks"],"read uncertainty cannot birth a fallback session")
                self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))
                self.assertEqual(0,backend.call_count)
                self.assertEqual(0,prompt.call_count)
                self.assertTrue(out["result"]is None,"read failure cannot yield successful configuration")
                error=out["error"]
                self.assertTrue(type(error)is APP.SetupError and error is not model["error"],
                                "unknown read errno must be a fresh fixed safe domain HOLD")
                self.assertFalse(isinstance(error,APP.IBAuthenticationError),
                                 "read failure cannot authorize credential fallback")
                self.assertTrue(error.args==("IB phase transport failed; device state is UNKNOWN",),
                                "no arbitrary read errno args may escape")
                self.assertTrue(error.__cause__ is None and error.__context__ is None,
                                "private read-error chain must be detached")
                self.assertTrue(getattr(error,"io_errno",None)==errno.EACCES)
                self.assertTrue(getattr(error,"cleanup_uncertain",False)is False)
                self.assertTrue(model["error"].__cause__ is model["cause"] and
                                model["error"].__context__ is model["context"] and
                                model["error"].args==(errno.EACCES,"PUBLIC read-errno seed must not escape"),
                                "read normalization must not mutate original modeled error")

    def test_strict_main_read_errno_cannot_be_silently_ignored(self):
        self._assert_strict_read_errno_hold("main")

    def test_strict_drain_read_errno_cannot_be_silently_ignored(self):
        self._assert_strict_read_errno_hold("drain")

    def test_strict_read_eagain_and_real_pty_eio_preserve_qualified_success(self):
        if sys.platform not in ("linux","darwin"):
            raise RuntimeError("FIXTURE HOLD: genuine terminal-read contract is qualified only for Linux or Darwin")
        for kind,point in (("eagain","main"),("real-eio","drain")):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix="ib-phase-read-benign-")as folder:
                f,model=self._read_errno_fixture(folder,"success",point,kind,0)
                with mock.patch.object(APP,"verify_password_hash",side_effect=AssertionError("successful initial read needs no target"))as backend,\
                     mock.patch.object(APP.getpass,"getpass",side_effect=AssertionError("successful initial read cannot prompt"))as prompt:
                    policy=APP.ProjectPasswordPolicy(f["global_path"],"admin",interactive=True)
                    out=self.drive(f,selector=True,policy=policy,read_errno=model)
                facts=model["facts"]
                self.assertEqual([],facts["errors"],"unmodeled observer error is fixture HOLD")
                if kind=="eagain":
                    self.assertEqual(1,facts["injections"])
                    self.assertTrue(facts["probe_actual_read"]and facts["complete_before"]and
                                    not facts["reaped_before"],"modeled EAGAIN must be reached at its owned main read")
                else:
                    self.assertEqual(0,facts["injections"],"PTY EIO positive is a real syscall witness")
                    # Historical real-eio scene name is retained; Darwin qualifies
                    # genuine EOF, never an observed or synthesized PTY EIO.
                    if sys.platform=="linux":
                        if not(facts["real_eio_calls"]and facts["real_eio_after_complete"]):
                            diagnostic={key:facts[key]for key in (
                                "real_eio_calls","real_eio_after_complete","prefix_complete",
                                "real_eof_calls","real_eof_after_complete_calls",
                                "real_eof_after_known_reap_calls","real_eof_complete_known_reap_calls",
                                "real_eof_known_zero_calls","real_eof_known_255_calls")}
                            diagnostic["actual_reap_count"]=len(out["reaps"])
                            diagnostic["actual_reap_zero_count"]=sum(code==0 for code in out["reaps"])
                            diagnostic["actual_reap_255_count"]=sum(code==255 for code in out["reaps"])
                            if any(type(value)not in(bool,int)or(type(value)is int and value<0)
                                   for value in diagnostic.values()):
                                raise RuntimeError("FIXTURE HOLD: invalid fixed terminal-read diagnostic facts")
                            print("FIXTURE_DIAGNOSTIC_TERMINAL_READ "+
                                  json.dumps(diagnostic,sort_keys=True,separators=(",",":")),
                                  file=sys.stderr,flush=True)
                            raise RuntimeError("FIXTURE HOLD: actual owned PTY EIO after complete prefix not observed")
                    elif sys.platform=="darwin":
                        if not facts["real_eof_complete_known_zero_calls"]:
                            raise RuntimeError("FIXTURE HOLD: actual owned Darwin EOF after complete prefix and known actual reap0 not observed")
                    else:
                        raise RuntimeError("FIXTURE HOLD: unsupported genuine terminal-read platform")
                self.assertTrue(out["error"]is None,"benign read completion cannot fail; raw error suppressed")
                self.assertTrue(PAYLOAD==out["result"].read_result.output,
                                "qualified positive payload must match independent literal")
                self.assertTrue(out["result"].current_password==f["initial"])
                self.assert_custody(out)
                self.assertEqual([0],out["reaps"],"EOF/EIO alone cannot supply an invented exit status")
                self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))
                self.assertEqual(0,backend.call_count)
                self.assertEqual(0,prompt.call_count)


    def test_complete_owned_frame_must_follow_actual_current_input(self):
        with tempfile.TemporaryDirectory(prefix="ib-phase-frame-before-current-")as folder:
            f=self.fixture(folder,"A-frame-before-current")
            f["peer"].write_text(_phase_before_current_peer_script(),encoding="utf-8")
            out,witness=_phase_before_current_drive(self,f)
            if not witness:
                raise RuntimeError("FIXTURE HOLD: complete owned frame not actually read before current input")
            self.assertTrue(out["result"]is None,"early command evidence must not return success; raw result suppressed")
            self.assertTrue(isinstance(out["error"],APP.SetupError),"expected safe domain HOLD; raw error suppressed")
            self.assertFalse(isinstance(out["error"],APP.IBAuthenticationError),
                             "early frame cannot authorize another credential candidate")
            self.assert_custody(out)
            self.assertEqual(1,sum(e["kind"]=="request"for e in out["peer"]))


# Additive test-only peer extension; never a production hook or generic model.
_PHASE_ORDER_EXTENSION = r'''    if case in ("A-frame-before-phase", "A-frame-after-phase", "A-pam-current-before-phase"):
        # Independent PUBLIC wire oracle. Existing cases below are untouched.
        payload="nv set system hostname nvos\nnv set service lldp state enabled\n"
        frame="\n__HTTP_IB_BEGIN_"+realnonce+"__\n"+payload+"\n__HTTP_IB_END_"+realnonce+"__=0\n"
        try:
            if case=="A-frame-before-phase":
                emit(frame+begin+"admin@fe80::17's password: ")
                got=receive();event("inner-answer",complete=got is not None,**roles(got))
                if got is None:return 255
                emit(end(0));event("finish",declared=0);return 0
            if case=="A-frame-after-phase":
                emit(begin+"admin@fe80::17's password: ")
                got=receive();event("inner-answer",complete=got is not None,**roles(got))
                if got is None:return 255
                emit(end(0)+frame);event("finish",declared=0);return 0
            if op!="password-change":raise ValueError("order case requires explicit PAM")
            # The only current-PAM prompt is OUTSIDE the live phase.
            emit("\n(current) UNIX password: \n"+begin+"admin@fe80::17's password: ")
            got=receive();event("inner-answer",complete=got is not None,**roles(got))
            if got is None:return 255
            emit("\nYour password has expired.\n")
            old=receive();event("pam-current",complete=old is not None,initial=old==C["initial"])
            if old is None:return 255
            new=answer("\nNew password: ")
            event("pam-new",complete=new is not None,target=new==C["target"])
            if new is None:return 255
            confirm=answer("\nRetype new password: ")
            event("pam-confirm",complete=confirm is not None,target=confirm==C["target"])
            if old!=C["initial"]or new!=C["target"]or confirm!=C["target"]:return 1
            emit("\npasswd: all authentication tokens updated successfully\n"+end(0))
            event("finish",declared=0);return 0
        except OSError as exc:
            # Actual owned slave can close when product rejects the malformed
            # prefix. This expected terminal end is not an adapter failure.
            if exc.errno not in (5,32):raise
            event("order-peer-terminal-closed",code=exc.errno)
            return 1
'''

def _phase_order_peer_script():
    anchor=r'    denied="\nadmin@fe80::17: Permission denied (password).\n"'+"\n"
    if PEER_PROGRAM.count(anchor)!=1:
        raise RuntimeError("FIXTURE HOLD: original peer insertion point changed")
    return PEER_PROGRAM.replace(anchor,_PHASE_ORDER_EXTENSION+anchor,1)

def _phase_order_drive(test,f,*,operation="auth-probe-readonly",policy=None,allow=False):
    # Transparent outer observers: the original drive's delegates still perform
    # the actual fork/read/close. No read result, status, prompt or wait is faked.
    real_fork,real_read,real_close=APP.pty.fork,APP.os.read,APP.os.close
    owned=set();chunks=[];total=0;observer_errors=[]
    def fork():
        pair=real_fork()
        if pair[0]>0:owned.add(pair[1])
        return pair
    def read(fd,size):
        nonlocal total
        raw=real_read(fd,size)
        if fd in owned and raw:
            total+=len(raw)
            if total>65536:
                observer_errors.append("order-wire-cap")
                raise RuntimeError("FIXTURE HOLD: bounded PUBLIC wire witness exceeded")
            chunks.append(raw)
        return raw
    def close(fd):
        owned.discard(fd)
        return real_close(fd)
    with mock.patch.object(APP.pty,"fork",new=fork),mock.patch.object(APP.os,"read",new=read),\
         mock.patch.object(APP.os,"close",new=close):
        out=test.drive(f,operation,policy=policy,allow=allow)
    test.assertEqual([],observer_errors,"observer errors cannot become business HOLD")
    wire=b"".join(chunks).decode("utf-8","replace").replace("\r","")
    requests=[e for e in out["peer"]if e["kind"]=="request"]
    if len(requests)!=1:
        raise RuntimeError("FIXTURE HOLD: one actual owned request witness required")
    nonce=requests[0]["nonce"]
    begin="__HTTP_IB_AUTH_"+nonce+"_"+operation+"__=BEGIN\n"
    end="__HTTP_IB_AUTH_"+nonce+"_"+operation+"__=EXIT:0\n"
    frame="__HTTP_IB_BEGIN_"+nonce+"__\n"+\
          "nv set system hostname nvos\nnv set service lldp state enabled\n"+\
          "\n__HTTP_IB_END_"+nonce+"__=0\n"
    prefix="(current) UNIX password: \n"
    facts=dict(
        frame_before_phase=frame in wire and begin in wire and wire.index(frame)+len(frame)<=wire.index(begin),
        frame_after_phase=frame in wire and end in wire and wire.index(end)+len(end)<=wire.index(frame),
        pam_current_before_phase=prefix in wire and begin in wire and wire.index(prefix)+len(prefix)<=wire.index(begin),
    )
    return out,facts

READ_ERRNO_PEER_PROGRAM=r'''import json, os, re, select, shlex, signal, sys, termios, time
from pathlib import Path
P = Path(sys.argv[1]); C = json.loads(P.read_text()); home = P.parent
def emit(text):
    os.write(1, text.encode())
def event(kind, **values):
    data=(json.dumps(dict(kind=kind, **values),sort_keys=True)+"\n").encode()
    if len(data)>2048: raise ValueError("observer bound")
    fd=os.open(home/"peer-events.jsonl",os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
    try:
        if os.fstat(fd).st_size>65536: raise ValueError("observer cap")
        os.write(fd,data)
    finally: os.close(fd)
def receive():
    deadline=time.monotonic()+2;raw=b""
    while len(raw)<=130:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([0],[],[],remaining)[0]:return None
        part=os.read(0,131-len(raw))
        if not part:return None
        raw+=part
        if b"\n"in raw:
            if not raw.endswith(b"\n")or raw.count(b"\n")!=1:return None
            return raw[:-1].rstrip(b"\r").decode()
    return None
def answer(prompt):
    emit(prompt)
    return receive()
def roles(value):
    return dict(initial=value==C["initial"],target=value==C["target"],oob=value==C["oob"])
def parse():
    args=sys.argv[2:]
    prefix=["-tt","-o","ConnectTimeout=2","-o","ServerAliveInterval=10","-o","ServerAliveCountMax=2",
            "-o","StrictHostKeyChecking=accept-new","-o","LogLevel=ERROR",
            "-o","ControlMaster=no","-o","ControlPath=none","cumulus@192.0.2.10"]
    if args[:-1]!=prefix: raise ValueError("outer vector")
    shell=shlex.split(args[-1])
    carrier="export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
    if len(shell)!=3 or shell[:2]!=["sh","-c"]or not shell[2].startswith(carrier):raise ValueError("PATH carrier")
    phase=shlex.split(shell[2][len(carrier):])
    if len(phase)!=3 or phase[:2]!=["sh","-c"]:raise ValueError("phase shell")
    source=phase[2]
    m=re.match(r'^printf "\\n__HTTP_IB_AUTH_([0-9a-f]{32})_(auth-probe-readonly|password-change|post-change-read|ordinary-operation)__=BEGIN\\n"; ',source)
    if not m:raise ValueError("phase prefix")
    nonce,op=m.groups()
    tail='; inner_rc=$?; printf "\\n__HTTP_IB_AUTH_'+nonce+'_'+op+'__=EXIT:%s\\n" "$inner_rc"; exit "$inner_rc"'
    if not source.endswith(tail):raise ValueError("phase suffix")
    inner=shlex.split(source[m.end():-len(tail)])
    base=["ip","vrf","exec","default","ssh","-6","-tt","-o","ConnectTimeout=2",
          "-o","StrictHostKeyChecking=accept-new","-o","LogLevel=ERROR","-o","ControlMaster=no",
          "-o","ControlPath=none","-o","NumberOfPasswordPrompts=1"]
    extra=["-o","PubkeyAuthentication=no","-o","PreferredAuthentications=password,keyboard-interactive"]
    required=base+extra if op in("auth-probe-readonly","password-change","post-change-read")else base
    if inner[:-4]!=required or inner[-4:-1]!=["-B","vlan1","admin@fe80::17"]:raise ValueError("inner vector")
    cmd=shlex.split(inner[-1])
    if len(cmd)!=3 or cmd[:2]!=["sh","-c"]:raise ValueError("command shell")
    start='printf "\\n__HTTP_IB_BEGIN_'+nonce+'__\\n"; '
    end='; task_rc=$?; printf "\\n__HTTP_IB_END_'+nonce+'__=%s\\n" "$task_rc"; exit "$task_rc"'
    if not cmd[2].startswith(start)or not cmd[2].endswith(end):raise ValueError("frame request")
    if shlex.split(cmd[2][len(start):-len(end)])!=["nv","config","show","-o","commands"]:raise ValueError("not sole readonly request")
    return nonce,op
def run():
    attrs=termios.tcgetattr(0);attrs[3]&=~termios.ECHO;termios.tcsetattr(0,termios.TCSANOW,attrs)
    nonce,op=parse();case=C["case"]
    if case=="uncertain":signal.signal(signal.SIGHUP,signal.SIG_IGN)
    event("request",nonce=nonce,operation=op)
    outer=answer("cumulus@192.0.2.10's password: ")
    event("outer-answer",**roles(outer))
    if outer!=C["oob"]:return 255
    realnonce=nonce
    if case=="wrong-nonce":nonce="0"*32 if nonce!="0"*32 else "1"*32
    wireop="ordinary-operation"if case=="wrong-operation"else op
    begin="\n__HTTP_IB_AUTH_"+nonce+"_"+wireop+"__=BEGIN\n"
    end=lambda code:"\n__HTTP_IB_AUTH_"+nonce+"_"+wireop+"__=EXIT:"+str(code)+"\n"
    denied="\nadmin@fe80::17: Permission denied (password).\n"
    if case=="reverse-phase":emit(end(255))
    if case not in ("no-phase","missing-begin"):emit(begin)
    if case=="double-begin":emit(begin)
    if case=="diagnostic-before-full-write":
        # One actual <=PIPE_BUF write. Parent must independently witness that
        # actual os.read observed prompt+denied before any full credential write.
        emit("admin@fe80::17's password: "+denied)
        got=receive()
    elif case=="prompt-absent":
        got=None
    elif case=="double-prompt":
        got=answer("admin@fe80::17's password: \nadmin@fe80::17's password: ")
    else:
        got=answer("admin@fe80::17's password: ")
    event("inner-answer",complete=got is not None,**roles(got))
    if case in ("timeout","uncertain"):
        (home/"ready").write_bytes(b"PUBLIC-READY\n")
        event("ready")
        select.select([],[],[],10)
        return 255
    if case=="readonly-expiry":
        event("expiry")
        emit("\nYour password has expired.\n(current) UNIX password: ")
        select.select([],[],[],10)
        return 1
    if case in ("pam","global-before-new"):
        if op!="password-change":raise ValueError("test requested wrong PAM operation")
        old=answer("\nYour password has expired.\n(current) UNIX password: ")
        event("pam-current",complete=old is not None,initial=old==C["initial"])
        if case=="global-before-new":
            with open(C["global"],"a")as stream:stream.write("# PUBLIC global changed before new password\n")
            event("global-changed")
        new=answer("\nNew password: ")
        event("pam-new",complete=new is not None,target=new==C["target"])
        confirm=answer("\nRetype new password: ")
        event("pam-confirm",complete=confirm is not None,target=confirm==C["target"])
        if old!=C["initial"]or new!=C["target"]or confirm!=C["target"]:return 1
        emit("\npasswd: all authentication tokens updated successfully\n");emit(end(0));event("finish",declared=0);return 0
    good=case in ("success","post-change-success","duplicate-command-frame","payload-status-mismatch")
    if case=="candidate-select":good=got==C["target"]
    if case=="both-reject":good=False
    if case=="network":emit("\nssh: connect to host fe80::17 port 22: Network is unreachable\n"+denied)
    elif case=="hostkey":emit("\nWARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"+denied)
    elif case=="outside-diag":
        emit(end(255));emit(denied);event("finish",declared=255);return 255
    elif case=="wrong-endpoint":emit("\nadmin@fe80::99: Permission denied (password).\n")
    elif not good and case!="diagnostic-before-full-write":emit(denied)
    body="nv set system hostname nvos\nnv set service lldp state enabled\n"
    frame="\n__HTTP_IB_BEGIN_"+realnonce+"__\n"+body+"\n__HTTP_IB_END_"+realnonce+"__="
    if good or case=="command-frame-present":
        emit(frame+("1"if case=="payload-status-mismatch"else"0")+"\n")
        if case=="duplicate-command-frame":emit(frame+"0\n")
    status=0 if good else 255
    if case not in ("no-phase","missing-exit"):emit(end(255 if case in ("actual-zero","actual-signal")else status))
    if case=="double-exit":emit(end(status))
    event("finish",declared=status)
    if C.get("read_errno_barrier")=="main":
        # Only this independent fixture owns the handshake. No source hook.
        deadline=time.monotonic()+10
        event("read-barrier-ready")
        while not (home/"read-observed").is_file():
            if time.monotonic()>=deadline:raise ValueError("read-prefix handshake deadline")
            select.select([],[],[],0.01)
        emit("\nPUBLIC-READ-PROBE\n")
        while not (home/"read-release").is_file():
            if time.monotonic()>=deadline:raise ValueError("read-release handshake deadline")
            select.select([],[],[],0.01)
        event("read-barrier-released")
    if case=="actual-signal":os.kill(os.getpid(),signal.SIGTERM)
    return 0 if case=="actual-zero"else status
try:rc=run()
except BaseException as exc:
    try:event("adapter-error",exception_type=type(exc).__name__)
    except BaseException:pass
    rc=86
raise SystemExit(rc)
'''


_PHASE_BEFORE_CURRENT_EXTENSION = r'''    if case=="A-frame-before-current":
        payload="nv set system hostname nvos\nnv set service lldp state enabled\n"
        frame="\n__HTTP_IB_BEGIN_"+realnonce+"__\n"+payload+"\n__HTTP_IB_END_"+realnonce+"__=0\n"
        try:
            # Entire command frame is inside AUTH, but precedes any current input.
            emit(begin+"admin@fe80::17's password: \n"+frame)
            got=receive();event("inner-answer",complete=got is not None,**roles(got))
            if got is None:return 255
            emit(end(0));event("finish",declared=0);return 0
        except OSError as exc:
            if exc.errno not in (5,32):raise
            event("order-peer-terminal-closed",code=exc.errno)
            return 1
'''

def _phase_before_current_peer_script():
    anchor=r'    denied="\nadmin@fe80::17: Permission denied (password).\n"'+"\n"
    original=_phase_order_peer_script()
    if original.count(anchor)!=1:
        raise RuntimeError("FIXTURE HOLD: original peer insertion point changed")
    return original.replace(anchor,_PHASE_BEFORE_CURRENT_EXTENSION+anchor,1)

def _phase_before_current_drive(test,f):
    # Transparent syscall observers outside the original custody driver.
    # Full actual reads and successful write counts determine ordering; no
    # prompt, return code, syscall result or write completion is manufactured.
    real_fork,real_read,real_write,real_close=APP.pty.fork,APP.os.read,APP.os.write,APP.os.close
    owned=set();reads=[];current_writes=[];progress={};serial=0;total=0;observer_errors=[]
    def fork():
        pair=real_fork()
        if pair[0]>0:owned.add(pair[1])
        return pair
    def read(fd,size):
        nonlocal serial,total
        raw=real_read(fd,size)
        if fd in owned and raw:
            serial+=1;total+=len(raw)
            if total>65536:
                observer_errors.append("before-current-read-cap")
                raise RuntimeError("FIXTURE HOLD: bounded PUBLIC ordering witness exceeded")
            reads.append((serial,raw))
        return raw
    def write(fd,data):
        nonlocal serial
        count=real_write(fd,data)
        if fd in owned and count>0:
            serial+=1
            raw=progress.get(fd,b"")+bytes(data)[:count]
            if len(raw)>512:
                observer_errors.append("before-current-write-cap")
                raise RuntimeError("FIXTURE HOLD: bounded input ordering witness exceeded")
            parts=raw.split(b"\n")
            for line in parts[:-1]:
                if line==f["initial"].encode("utf-8"):
                    current_writes.append(serial)
            progress[fd]=parts[-1]
        return count
    def close(fd):
        owned.discard(fd);progress.pop(fd,None)
        return real_close(fd)
    with mock.patch.object(APP.pty,"fork",new=fork),mock.patch.object(APP.os,"read",new=read),\
         mock.patch.object(APP.os,"write",new=write),mock.patch.object(APP.os,"close",new=close):
        out=test.drive(f)
    test.assertEqual([],observer_errors,"observer failures cannot become a business HOLD")
    requests=[e for e in out["peer"]if e["kind"]=="request"]
    if len(requests)!=1:
        raise RuntimeError("FIXTURE HOLD: one actual owned request witness required")
    nonce=requests[0]["nonce"]
    begin="__HTTP_IB_AUTH_"+nonce+"_auth-probe-readonly__=BEGIN\n"
    frame="__HTTP_IB_BEGIN_"+nonce+"__\n"+\
          "nv set system hostname nvos\nnv set service lldp state enabled\n"+\
          "\n__HTTP_IB_END_"+nonce+"__=0\n"
    wire="";frame_read=None
    for sequence,raw in reads:
        wire+=raw.decode("utf-8","replace").replace("\r","")
        if frame_read is None and begin in wire and frame in wire and wire.index(begin)+len(begin)<=wire.index(frame):
            frame_read=sequence
    # No current write on correct early refusal is legitimate. A complete read
    # witness is still mandatory; absent read evidence is never a green result.
    witness=frame_read is not None and all(frame_read<sequence for sequence in current_writes)
    return out,witness


if __name__=="__main__":
    unittest.main()
