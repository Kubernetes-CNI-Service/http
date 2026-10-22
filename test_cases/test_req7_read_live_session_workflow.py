"""SOURCE NOT RUN. Real protocol codec <-> retained live supervisor workflow."""
import importlib.util,os,subprocess,sys,time,unittest
from pathlib import Path
from unittest import mock
from test_cases import test_req7_read_live_session as direct

CHILD=r'''
import os,sys
sys.path[:0]=[sys.argv[1],sys.argv[1]+'/tools']
from monitor import issue_tracker_read_live_protocol as codec
nonce=sys.argv[2]
ready=codec.encode_event(nonce,'READY',{'answer':7,'rows':['literal','only']})
assert ready==('{"v":1,"nonce":"'+nonce+'","event":"READY","data":{"answer":7,"rows":["literal","only"]}}\n').encode()
os.write(2,b'FutureWarning: synthetic bounded warning\n')
os.write(1,ready)
for raw in sys.stdin.buffer:
 command=codec.decode_command(raw,nonce)
 assert raw==('{"v":1,"nonce":"'+nonce+'","command":"'+command+'"}\n').encode()
 if command=='CHECK':
  os.write(1,codec.encode_event(nonce,'LIVE',{'answer':7,'rows':['literal','only']}))
 elif command=='CLOSE':
  os.write(1,codec.encode_event(nonce,'CLOSED'));break
 else:raise SystemExit(5)
'''

class ReadLiveProtocolWorkflowTests(unittest.TestCase):
 def test_actual_codec_child_supervisor_terminal_and_no_pid_reuse_work(self):
  m=direct.product(self)
  self.assertIsNotNone(importlib.util.find_spec('monitor.issue_tracker_read_live_protocol'),
   'MISSING_FIXED_LIVE_READ_PROTOCOL_DOWNSTREAM_NOT_REACHED')
  root=Path(__file__).resolve().parents[1]
  started=time.monotonic()
  process=subprocess.Popen([sys.executable,'-B','-c',CHILD,str(root),direct.NONCE],
   stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
   close_fds=True,pass_fds=(),start_new_session=True,
   env={'LC_ALL':'C','HOME':os.path.expanduser('~')})
  fds=tuple(s.fileno() for s in (process.stdin,process.stdout,process.stderr))
  signals=[];original=m._killpg;session=None
  def killpg(group,sig):
   signals.append((group,sig));return original(group,sig)
  try:
   with mock.patch.object(m,'_killpg',killpg):
    session=m.adopt_owned_read_session(process,started_monotonic=started,nonce=direct.NONCE)
    ready,ready_error=direct.capture(session.read_once)
    first=(process.returncode,direct.groupgone(process))
    current,current_error=direct.capture(session.current_ready)
    _,close_error=direct.capture(session.close)
    terminal=(process.returncode is not None,direct.groupgone(process),
     [stream.closed for stream in (process.stdin,process.stdout,process.stderr)],
     [direct.isclosed(fd) for fd in fds])
    signal_count=len(signals)
    _,close_again_error=direct.capture(session.close)
    _,reuse_error=direct.capture(session.read_once)
    _,getter_error=direct.capture(session.current_ready)
    no_new_signals=len(signals)==signal_count
  finally:
   # Only exact retained child; fallback is AFTER all captured product facts.
   if process.returncode is None:
    process.kill();process.wait(timeout=5)
   for stream in (process.stdin,process.stdout,process.stderr):
    if not stream.closed:stream.close()
  self.assertEqual(direct.DATA,ready);self.assertIsNone(ready_error)
  self.assertEqual((None,False),first)
  self.assertEqual(direct.DATA,current);self.assertIsNone(current_error)
  self.assertIsNone(close_error);self.assertEqual((True,True,[True]*3,[True]*3),terminal)
  self.assertIsNone(close_again_error);self.assertTrue(no_new_signals)
  self.assertIsInstance(reuse_error,ValueError);self.assertIsInstance(getter_error,ValueError)
