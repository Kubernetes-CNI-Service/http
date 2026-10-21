"""UNRUN fixed protocol fixture; no live-source/native execution authority."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import tempfile

SECRET='STDIN-CARRIER-TEST-ONLY-7c91'
BURN='/srv/ib-upgrade/firmware/FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'
REFRESH='/srv/ib-upgrade/firmware/FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'
BURN_SHA='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
REFRESH_SHA='a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
RUN='stdin-protocol-001'
RETAINED_TREES=[]

# A test-owned interpreter runs the EXACT generated Python expression. Passive
# profile records actual original Popen objects created by that expression;
# retaining/waiting them does not replace subprocess or change launcher behavior.
# This avoids adopting a remembered PID or treating an exit file as kernel exit.
SUPERVISOR=r'''
import json,subprocess,sys
expression=sys.argv[1];arguments=sys.argv[2:]
constructor=subprocess.Popen.__init__
children=[]
def observe(frame,event,result):
    if event=='return' and frame.f_code is constructor.__code__ and frame.f_globals is constructor.__globals__:
        child=frame.f_locals.get('self')
        if type(child) is subprocess.Popen and type(getattr(child,'pid',None)) is int:
            if all(child is not value for value in children):children.append(child)
launch=0;problem=False
sys.argv=['-c',*arguments]
try:
    sys.setprofile(observe)
    exec(compile(expression,'<fixed-generated-launcher>','exec'),{'__name__':'__main__'})
except SystemExit as error:
    launch=error.code if type(error.code) is int else 0 if error.code is None else 2
except BaseException:
    launch=2
finally:
    sys.setprofile(None)
codes=[];stdin_closed=[]
for child in children:
    try:
        codes.append(child.wait(timeout=15))
    except subprocess.TimeoutExpired:
        # Only the retained original handle. Uncertain descendants keep tree.
        child.kill();child.wait(timeout=5);problem=True
        codes.append(child.returncode)
    stdin_closed.append(child.stdin is None or child.stdin.closed)
print('TEST_OWNED_LAUNCHER_END='+json.dumps(dict(launch=launch,codes=codes,
    stdin_closed=stdin_closed,unknown=problem)),flush=True)
raise SystemExit(2 if problem else 0)
'''


class OwnedProtocolTree:
    def __init__(self):
        self.root=Path(tempfile.mkdtemp(prefix='scp-stdin-cpld-protocol-')).resolve()
        self.safe=False

    def finish(self):
        if self.safe:
            shutil.rmtree(self.root)
        else:
            RETAINED_TREES.append(str(self.root))
            print('SCP_STDIN_PROTOCOL_RETAINED='+str(self.root))


def artifacts(root,component,contract,executor,case):
    switch=root/'switch';switch.mkdir(mode=0o700)
    node=contract.InventoryDevice('ib.example.test','192.0.2.1','02:00:00:00:00:01')
    policy=contract.UpgradePolicy(package_dir='/srv/ib-upgrade',final_os='25.03.1010',
        cpld_burn=contract.Package(Path(BURN).name,None,BURN),
        cpld_refresh=contract.Package(Path(REFRESH).name,None,REFRESH),
        cpld_targets=(('CPLD000232','REV0900'),('CPLD000383','REV0800'),('CPLD000389','REV0600')))
    remote=switch/('.ibsw-'+RUN+'-'+node.hostname+'-cpld-'+'a'*32)
    remote.mkdir(mode=0o700)
    trace,nvtrace=root/'scp.trace',root/'nv.trace'
    scp,ssh,nv=root/'private-scp',root/'private-ssh',root/'private-nv'
    wire=struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+bytes((17,))*32
    pin=b'[198.51.100.44]:2222 ssh-ed25519 '+base64.b64encode(wire)+b'\n'
    common='#!/usr/bin/python3\nimport hashlib,json,os,stat,sys\nfrom pathlib import Path\n'
    scp.write_text(common+
        'a=sys.argv[1:]\n'
        'if "-O" not in a or "StrictHostKeyChecking=yes" not in a or "-P" not in a: raise SystemExit(90)\n'
        'if a[a.index("-P")+1]!="2222" or "GlobalKnownHostsFile=/dev/null" not in a: raise SystemExit(91)\n'
        'pins=[v.split("=",1)[1] for v in a if v.startswith("UserKnownHostsFile=")]\n'
        'if len(pins)!=1: raise SystemExit(97)\n'
        'trust=Path(pins[0]);metadata=trust.lstat()\n'
        'if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_uid!=os.geteuid() or stat.S_IMODE(metadata.st_mode)!=0o600: raise SystemExit(98)\n'
        'if trust.read_bytes()!='+repr(pin)+': raise SystemExit(99)\n'
        'sys.stderr.write("source password:");sys.stderr.flush()\n'
        'secret=sys.stdin.readline().rstrip("\\n")\n'
        'if hashlib.sha256(secret.encode()).hexdigest()!='+repr(hashlib.sha256(SECRET.encode()).hexdigest())+': raise SystemExit(92)\n'
        'if "IBSW_SCP_AUTH" in os.environ or any(secret in v for v in a+list(os.environ.values())): raise SystemExit(94)\n'
        'source=a[-2]\n'
        'with Path('+repr(str(trace))+').open("a") as h:h.write(json.dumps(source)+"\\n")\n'
        'if source not in '+repr(('source_test@198.51.100.44:'+BURN,'source_test@198.51.100.44:'+REFRESH))+': raise SystemExit(95)\n'
        'if source.endswith('+repr(REFRESH)+') and '+repr(case)+'=="second_fail": raise SystemExit(1)\n'
        'value=b"abc" if source.endswith('+repr(BURN)+') else (b"321" if '+repr(case)+'=="wrong_bytes" else b"123")\n'
        'Path(a[-1]).write_bytes(value)\n'
        'print(secret)\n')
    ssh.write_text(common+'raise SystemExit(96) # fetch fixture must not call real SSH\n')
    nv.write_text(common+
        'if any("STDIN-CARRIER-TEST-ONLY-" in v for v in sys.argv+list(os.environ.values())): raise SystemExit(94)\n'
        'with Path('+repr(str(nvtrace))+').open("a") as h:h.write(json.dumps(sys.argv[1:])+"\\n")\n'
        'raise SystemExit(93)\n')
    for executable in (scp,ssh,nv):executable.chmod(0o700)
    rendered=component.render_declared_step(policy,node,component='cpld',package_index=0,
        run_id=RUN,method='scp',switch_dir=str(switch))
    script=rendered.script
    fields=[line for line in script.splitlines() if line.startswith('IBSW_SCP_HELPER_B64=')]
    if len(fields)!=1:
        raise AssertionError('fixed SCP renderer helper carrier required; do not invent script authority')
    values=shlex.split(fields[0].split('=',1)[1])
    if len(values)!=1:raise AssertionError('one fixed helper encoding required')
    helper=base64.b64decode(values[0],validate=True)
    for old,new in ((b"SSH = '/usr/bin/ssh'",('SSH = '+repr(str(ssh))).encode()),
                    (b"SCP = '/usr/bin/scp'",('SCP = '+repr(str(scp))).encode())):
        if helper.count(old)!=1:raise AssertionError('exact single external executable seam')
        helper=helper.replace(old,new)
    replacement='IBSW_SCP_HELPER_B64='+shlex.quote(base64.b64encode(helper).decode())
    script=script.replace(fields[0],replacement)
    if script.count('\nnv ')!=4:raise AssertionError('four fixed CPLD NV command sites required')
    script=script.replace('\nnv ','\n'+shlex.quote(str(nv))+' ')
    step=remote/'step.sh';step.write_bytes(script.encode());step.chmod(0o600)
    step_sha=hashlib.sha256(step.read_bytes()).hexdigest()
    binding=dict(run_id=RUN,node=dict(hostname=node.hostname),component='cpld',stage='cpld',script_sha256=step_sha)
    runner=remote/'runner.sh';runner.write_bytes(executor._owned_runner_bytes(binding,str(step)));runner.chmod(0o600)
    for name in ('execution.stdout','execution.stderr'):
        path=remote/name;path.write_bytes(b'');path.chmod(0o600)
    context=dict(host='198.51.100.44',user='source_test',port=2222,host_keys=pin.decode(),
        password=SECRET,paths={BURN:3,REFRESH:3},timeout_seconds=300,
        content_binding=dict(version=1,binding_sha256='1'*64,request_id='44444444444444444444444444444444',
            request_sha256='2'*64,companion_sha256='3'*64,
            packages={BURN:dict(size=3,sha256=BURN_SHA),REFRESH:dict(size=3,sha256=REFRESH_SHA)}))
    frame=(json.dumps(context,ensure_ascii=True,separators=(',',':'))+'\n').encode('ascii')
    return dict(step=step,runner=runner,step_sha=step_sha,runner_sha=hashlib.sha256(runner.read_bytes()).hexdigest(),
        frame=frame,context=context,remote=remote,switch=switch,scp_trace=trace,nv_trace=nvtrace)


def run_fixed_command(root,command,frame,inherited_context,keep_stdin=False):
    words=shlex.split(command)
    if len(words)!=6 or words[:2]!=['/usr/bin/python3','-c']:
        raise AssertionError('fixed Python expression + step/runnerSHA/stepSHA argv only')
    if SECRET in command:raise AssertionError('credential in command string')
    poison=json.loads(json.dumps(inherited_context))
    poison['password']='WRONG-ENV-CONTEXT'
    environment=dict(PATH='/usr/bin:/bin',HOME=str(root),TMPDIR=str(root),LC_ALL='C',
        PYTHONDONTWRITEBYTECODE='1',IBSW_SCP_AUTH=json.dumps(poison,separators=(',',':')))
    process=subprocess.Popen([words[0],'-B','-c',SUPERVISOR,words[2],*words[3:]],
        cwd=root,env=environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        close_fds=True)
    feed=None
    try:
        if keep_stdin:
            feed=process.stdin
            feed.write(frame);feed.flush()
            # communicate must not supply EOF for the missing-EOF negative.
            process.stdin=None
            out,err=process.communicate(timeout=12)
        else:
            out,err=process.communicate(input=frame,timeout=25)
    except subprocess.TimeoutExpired:
        process.kill();out,err=process.communicate()
        raise AssertionError('owned launcher timeout UNKNOWN; retain tree, no PID/FD rescue')
    finally:
        if feed is not None and not feed.closed:feed.close()
        for handle in (process.stdin,process.stdout,process.stderr):
            if handle is not None and not handle.closed:handle.close()
    records=[json.loads(line.split(b'=',1)[1]) for line in out.splitlines()
             if line.startswith(b'TEST_OWNED_LAUNCHER_END=')]
    if len(records)!=1 or process.returncode!=0 or records[0]['unknown']:
        raise AssertionError('owned exact launcher/child exit not confirmed; retain tree')
    return records[0],out,err
