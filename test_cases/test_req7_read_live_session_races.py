"""SOURCE NOT RUN. Additional two wholes; old independent two stay byte-exact."""
import errno,os,subprocess,sys,time,unittest
from unittest import mock
from test_cases import test_req7_read_live_session as old

BAD=b'{"v":1,"nonce":"'+old.NONCE.encode()+b'","event":"NOT_A_PROTOCOL_EVENT","data":{}}\n'
ATOMIC=old.READY+BAD
ATOMIC_CHILD=r'''
import os,sys,time
payload=bytes.fromhex(sys.argv[1])
assert len(payload)<=os.fpathconf(1,'PC_PIPE_BUF')
count=os.write(1,payload)  # One actual write, no separate READY publication.
assert count==len(payload)
time.sleep(90)
'''
def facts(process,fds):
 return dict(reaped=process.returncode is not None,groupgone=old.groupgone(process),
  closed=[stream.closed for stream in (process.stdin,process.stdout,process.stderr)],
  EBADF=[old.isclosed(fd) for fd in fds])

def fallback(process):
 # Only AFTER product first-result facts. No descriptor scans or rescue numbers.
 if process.returncode is None:
  process.kill();process.wait(timeout=5)
 for stream in (process.stdin,process.stdout,process.stderr):
  if not stream.closed:stream.close()

class IOView:
 def __init__(self,real,fd,identity):
  self.real=real;self.fd=fd;self.identity=identity;self.reads=[]
 def __getattr__(self,name):return getattr(self.real,name)
 def read(self,fd,size):
  value=self.real.read(fd,size)
  if fd==self.fd:
   actual=self.real.fstat(fd)
   identity=(actual.st_dev,actual.st_ino)
   if identity!=self.identity:raise RuntimeError('observer original pipe identity changed')
   self.reads.append(value)
  return value

def healthy(test,m):
 child=old.OwnedChild('warning');session=None
 try:
  session=m.adopt_owned_read_session(child.process,started_monotonic=child.started,nonce=old.NONCE)
  value,error=old.capture(session.read_once)
  _,close_error=old.capture(session.close)
  first=child.facts()
 finally:child.rescue_after_snapshot()
 # prerequisite outside product lifecycle/fallback, never fake a healthy return.
 test.assertEqual(old.DATA,value);test.assertIsNone(error);test.assertIsNone(close_error)
 test.assertEqual(dict(reaped=True,groupgone=True,closed=True,EBADF=[True]*3),first)

class ReadSessionRaceSupplementTests(unittest.TestCase):
 def test_atomic_ready_plus_illegal_frame_is_not_a_successful_first_result(self):
  m=old.product(self);healthy(self,m)
  started=time.monotonic()
  process=subprocess.Popen([sys.executable,'-B','-c',ATOMIC_CHILD,ATOMIC.hex()],
   stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
   start_new_session=True,close_fds=True,pass_fds=(),
   env={'LC_ALL':'C','HOME':os.path.expanduser('~')})
  fds=tuple(s.fileno() for s in (process.stdin,process.stdout,process.stderr))
  identity=os.fstat(fds[1]);view=IOView(m.os,fds[1],(identity.st_dev,identity.st_ino))
  cap=os.fpathconf(fds[1],'PC_PIPE_BUF')
  try:
   with mock.patch.object(m,'os',view):
    session=m.adopt_owned_read_session(process,started_monotonic=started,nonce=old.NONCE)
    value,error=old.capture(session.read_once);first=facts(process,fds)
    _,again=old.capture(session.read_once)
    observed=tuple(view.reads)
  finally:fallback(process)
  # IO observation prerequisite first: a split/unobserved write is fixture scope,
  # not evidence of the targeted already-buffered-frame publication race.
  self.assertLessEqual(len(ATOMIC),cap)
  self.assertIn(ATOMIC,observed,'ATOMIC_BATCH_OBSERVATION_NOT_REACHED')
  self.assertIsNone(value,'BUFFERED_ILLEGAL_FRAME_MUST_PREVENT_READY_SUCCESS')
  self.assertIsInstance(error,ValueError);self.assertIsInstance(again,ValueError)
  self.assertEqual(dict(reaped=True,groupgone=True,closed=[True]*3,EBADF=[True]*3),first)

 def test_real_thread_started_then_first_ni_aborts_before_io_and_closes_all(self):
  m=old.product(self);healthy(self,m)
  child=old.OwnedChild('warning')
  first_ni=KeyboardInterrupt('synthetic-start-after-delegate')
  cause=RuntimeError('synthetic-existing-cause');first_ni.__cause__=cause
  real_threading=m.threading;real_thread_type=real_threading.Thread
  threads=[];start_returns=[];close_attempts=[]
  original_close=m._close_stream
  identity=os.fstat(child.fds[1]);view=IOView(m.os,child.fds[1],(identity.st_dev,identity.st_ino))
  class ThreadView:
   def __getattr__(self,name):return getattr(real_threading,name)
   def Thread(self,*args,**kwargs):
    thread=real_thread_type(*args,**kwargs);threads.append(thread)
    def start():
     value=real_thread_type.start(thread)  # Actual thread genuinely starts.
     start_returns.append(value)
     raise first_ni
    thread.start=start
    return thread
  def close(stream):
   value=original_close(stream);close_attempts.append(stream)
   if len(close_attempts)==1:raise OSError(errno.EIO,'synthetic-later-close')
   return value
  try:
   with mock.patch.object(m,'threading',ThreadView()),mock.patch.object(m,'os',view),mock.patch.object(m,'_close_stream',close):
    session=m.adopt_owned_read_session(child.process,started_monotonic=child.started,nonce=old.NONCE)
    value,error=old.capture(session.read_once);first=child.facts()
    _,reused=old.capture(session.read_once)
   # Join is bounded test hygiene after FIRST product facts; it cannot close
   # pipes or be counted as product cleanup. Original actual target must abort.
   for thread in threads:thread.join(timeout=2)
   alive=[thread.is_alive() for thread in threads]
   observed=tuple(view.reads)
  finally:child.rescue_after_snapshot()
  self.assertEqual(1,len(threads));self.assertIs(type(threads[0]),real_thread_type)
  self.assertEqual([None],start_returns)
  self.assertIsNone(value);self.assertIs(error,first_ni);self.assertIs(first_ni.__cause__,cause)
  self.assertIsInstance(reused,ValueError)
  self.assertEqual(dict(reaped=True,groupgone=True,closed=True,EBADF=[True]*3),first)
  self.assertEqual(3,len(close_attempts));self.assertEqual(3,len(set(map(id,close_attempts))))
  self.assertEqual(set(map(id,(child.process.stdin,child.process.stdout,child.process.stderr))),set(map(id,close_attempts)))
  self.assertEqual([False],alive);self.assertEqual((),observed,'ABORTED_PUMP_MUST_NOT_READ')
