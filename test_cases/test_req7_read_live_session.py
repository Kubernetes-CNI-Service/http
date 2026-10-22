"""SOURCE NOT RUN. Process/pipe control only, no source/SDK permission."""
import errno,importlib.util,json,os,signal,subprocess,sys,time,unittest
from pathlib import Path
from unittest import mock

NONCE='a'*64
DATA={'answer':7,'rows':['literal','only']}
READY=b'{"v":1,"nonce":"'+NONCE.encode()+b'","event":"READY","data":{"answer":7,"rows":["literal","only"]}}\n'
PROGRAM=r'''
import json,os,sys,time
mode=sys.argv[1];nonce=sys.argv[2]
if mode=='delay':time.sleep(26.0)
if mode=='stdout-over':
 os.write(1,b'x'*(2097152+1));time.sleep(90);raise SystemExit(0)
if mode=='stderr-over':
 os.write(2,b'w'*(65536+1));time.sleep(90);raise SystemExit(0)
if mode=='wrong':
 os.write(1,b'{"v":1,"nonce":"wrong","event":"READY","data":{}}\n');time.sleep(90);raise SystemExit(0)
if mode=='partial':
 os.write(1,b'{"v":1');raise SystemExit(0)
if mode=='warning':os.write(2,b'FutureWarning: synthetic supported-diagnostic observation\n')
wire=('{"v":1,"nonce":"'+nonce+'","event":"READY","data":{"answer":7,"rows":["literal","only"]}}\n').encode()
os.write(1,wire)
for line in sys.stdin.buffer:
 request=json.loads(line)
 assert request=={'v':1,'nonce':nonce,'command':request['command']}
 if request['command']=='CHECK':
  os.write(1,('{"v":1,"nonce":"'+nonce+'","event":"LIVE","data":{"answer":7,"rows":["literal","only"]}}\n').encode())
 elif request['command']=='CLOSE':
  os.write(1,('{"v":1,"nonce":"'+nonce+'","event":"CLOSED"}\n').encode());break
 else:raise SystemExit(4)
'''
def product(test):
 test.assertIsNotNone(importlib.util.find_spec('monitor.issue_tracker_read_live_session'),
  'MISSING_OWNED_READ_LIVE_SESSION_DOWNSTREAM_NOT_REACHED')
 from monitor import issue_tracker_read_live_session as module
 return module

def capture(action):
 try:return action(),None
 except BaseException as error:return None,error

def groupgone(process):
 try:os.killpg(process.pid,0)
 except ProcessLookupError:return True
 return False

def isclosed(fd):
 try:os.fstat(fd)
 except OSError as error:return error.errno==errno.EBADF
 return False

class OwnedChild:
 """Only this genuinely retained child; no process discovery/FD rescue."""
 def __init__(self,mode,*,prelaunch_delay=0):
  self.started=time.monotonic()
  if prelaunch_delay:time.sleep(prelaunch_delay)
  self.process=subprocess.Popen([sys.executable,'-B','-c',PROGRAM,mode,NONCE],
   stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
   start_new_session=True,close_fds=True,pass_fds=(),
   env={'LC_ALL':'C','HOME':os.path.expanduser('~')})
  self.fds=tuple(stream.fileno() for stream in (self.process.stdin,self.process.stdout,self.process.stderr))
 def facts(self):
  return dict(reaped=self.process.returncode is not None,groupgone=groupgone(self.process),
   closed=all(s.closed for s in (self.process.stdin,self.process.stdout,self.process.stderr)),
   EBADF=[isclosed(fd) for fd in self.fds])
 def rescue_after_snapshot(self):
  # Fixture fallback after first-result facts only, not product cleanup.
  # Never signal a reaped PID: live retained Popen handle is the sole anchor.
  if self.process.returncode is None:
   self.process.kill()
   self.process.wait(timeout=5)
  for stream in (self.process.stdin,self.process.stdout,self.process.stderr):
   if not stream.closed:stream.close()

class ReadLiveSessionDirectTests(unittest.TestCase):
 def test_owned_ready_lifetime_deadline_protocol_caps_and_first_close(self):
  m=product(self)
  self.assertIsNotNone(importlib.util.find_spec('monitor.issue_tracker_read_live_protocol'),
   'MISSING_FIXED_LIVE_READ_PROTOCOL_DOWNSTREAM_NOT_REACHED')
  from monitor import issue_tracker_read_live_protocol as codec
  self.assertEqual(READY,codec.encode_event(NONCE,'READY',DATA))
  self.assertEqual('CHECK',codec.decode_command(
   b'{"v":1,"nonce":"'+NONCE.encode()+b'","command":"CHECK"}\n',NONCE))
  for malformed in (b'{"v":1,"v":1}\n',b'{"v":1,"nonce":"wrong","command":"CLOSE"}\n',
   b'{"v":1,"nonce":"'+NONCE.encode()+b'","command":"CHECK","extra":0}\n'):
   value,error=capture(lambda:codec.decode_command(malformed,NONCE))
   self.assertIsNone(value);self.assertIsInstance(error,ValueError)
  foreign,error=capture(lambda:m.adopt_owned_read_session(object(),
   started_monotonic=time.monotonic(),nonce=NONCE))
  self.assertIsNone(foreign);self.assertIsInstance(error,ValueError)
  records=[];bodyNI=KeyboardInterrupt('owned-close-first');cause=RuntimeError('owned-cause')
  bodyNI.__cause__=cause
  # Healthy genuine child first. Fixed60 is real wallclock, never fakeclock.
  child=OwnedChild('warning');session=None
  try:
   session=m.adopt_owned_read_session(child.process,started_monotonic=child.started,nonce=NONCE)
   data,error=capture(session.read_once);ready_at=time.monotonic()
   first=child.facts()
   _,again=capture(session.read_once)
   current,current_error=capture(session.current_ready)
   time.sleep(30.0)
   later,later_error=capture(session.current_ready)
   live_before_expiry=child.facts()
   time.sleep(max(0,ready_at+60.2-time.monotonic()))
   expired,expiry_error=capture(session.current_ready)
   session.close();terminal=child.facts()
   records.append(('healthy',data,error,first,again,current,current_error,later,later_error,
    live_before_expiry,expired,expiry_error,terminal))
  finally:child.rescue_after_snapshot()
  # True health prerequisite outside all owners/finalizers, before any fault.
  health=records[0]
  self.assertEqual(DATA,health[1]);self.assertIsNone(health[2])
  self.assertEqual(dict(reaped=True,groupgone=True,closed=True,EBADF=[True]*3),health[12])
  # Prelaunch2.5+child26 exceeds fixed work28; no resetting at adoption.
  for mode,delay in (('delay',2.5),('stdout-over',0),('stderr-over',0),('wrong',0),('partial',0)):
   child=OwnedChild(mode,prelaunch_delay=delay);session=None
   try:
    session=m.adopt_owned_read_session(child.process,started_monotonic=child.started,nonce=NONCE)
    value,error=capture(session.read_once);at_result=child.facts()
    elapsed=time.monotonic()-child.started
    _,repeat=capture(session.read_once);_,closed=capture(session.close)
    records.append((mode,value,error,at_result,elapsed,repeat,closed))
   finally:child.rescue_after_snapshot()
  # Actual successful close then firstNI, laterEIO; exact original pipes unchanged.
  child=OwnedChild('warning');session=None;attempts=[]
  original=m._close_stream
  def close(stream):
   result=original(stream);attempts.append(stream)
   if len(attempts)==1:raise bodyNI
   if len(attempts)==2:raise OSError(errno.EIO,'later-owned-close')
   return result
  try:
   session=m.adopt_owned_read_session(child.process,started_monotonic=child.started,nonce=NONCE)
   data,health_error=capture(session.read_once)
   with mock.patch.object(m,'_close_stream',close):
    _,cleanup_error=capture(session.close)
    firstclose=child.facts()
   _,failed_reuse=capture(session.read_once)
   records.append(('closeNI',data,health_error,cleanup_error,firstclose,tuple(attempts),failed_reuse))
  finally:child.rescue_after_snapshot()
  # All behavior assertions outside product scopes/hooks/finalizers.
  h=records[0];self.assertEqual(DATA,h[1]);self.assertIsNone(h[2])
  self.assertEqual(dict(reaped=False,groupgone=False,closed=False,EBADF=[False]*3),h[3])
  self.assertIsInstance(h[4],ValueError);self.assertEqual(DATA,h[5]);self.assertIsNone(h[6])
  self.assertEqual(DATA,h[7]);self.assertIsNone(h[8]);self.assertFalse(h[9]['reaped'])
  self.assertIsNone(h[10]);self.assertIsInstance(h[11],ValueError)
  self.assertEqual(dict(reaped=True,groupgone=True,closed=True,EBADF=[True]*3),h[12])
  for r in records[1:-1]:
   with self.subTest(mode=r[0]):
    self.assertIsNone(r[1]);self.assertIsInstance(r[2],ValueError)
    self.assertEqual(dict(reaped=True,groupgone=True,closed=True,EBADF=[True]*3),r[3])
    self.assertLess(r[4],30.0,'CLEANUP_NOT_INSIDE_ORIGINAL_TOTAL30')
    self.assertIsInstance(r[5],ValueError)
  r=records[-1];self.assertEqual(DATA,r[1]);self.assertIsNone(r[2])
  self.assertIs(r[3],bodyNI);self.assertIs(bodyNI.__cause__,cause)
  self.assertEqual(dict(reaped=True,groupgone=True,closed=True,EBADF=[True]*3),r[4])
  self.assertEqual(3,len(r[5]));self.assertEqual(3,len(set(map(id,r[5]))))
  self.assertIsInstance(r[6],ValueError)
