"""SOURCE NOT RUN. Real delayed-copy acquisition resource deadline only."""
import json,os,time,unittest
from unittest import mock
from test_cases import test_req7_read_live_session as old

class ReadSessionCopyBudgetTests(unittest.TestCase):
 def test_real_copy_pending_at_work_deadline_cannot_extend_acquisition_to_live60(self):
  m=old.product(self)
  # Real short healthy same entry first; not another whole or a fake return.
  healthy=old.OwnedChild('warning');health_session=None
  try:
   health_session=m.adopt_owned_read_session(healthy.process,
    started_monotonic=healthy.started,nonce=old.NONCE)
   health_value,health_error=old.capture(health_session.read_once)
   _,health_close_error=old.capture(health_session.close)
   health_first=healthy.facts()
  finally:healthy.rescue_after_snapshot()
  self.assertEqual(old.DATA,health_value);self.assertIsNone(health_error)
  self.assertIsNone(health_close_error)
  self.assertEqual(dict(reaped=True,groupgone=True,closed=True,EBADF=[True]*3),health_first)

  child=old.OwnedChild('warning');session=None
  real_copy=m.copy;real_deepcopy=real_copy.deepcopy
  original_close=m._close_stream
  copies=[];close_events=[]
  class CopyIO:
   def __getattr__(self,name):return getattr(real_copy,name)
   def deepcopy(self,value,*args,**kwargs):
    copied=real_deepcopy(value,*args,**kwargs)  # Actual full original copy first.
    copy_started=time.monotonic()
    while True:
     remaining=child.started+29.15-time.monotonic()
     if remaining<=0:break
     time.sleep(remaining)  # Real elapsed stall; never a clock/result override.
    copies.append(dict(input=value,copied=copied,started=copy_started,
     returning=time.monotonic(),resources_at_copy_return=child.facts()))
    return copied
  def close(stream):
   result=original_close(stream)  # Observe actual original close only.
   close_events.append((stream,time.monotonic()))
   return result
  try:
   with mock.patch.object(m,'copy',CopyIO()),mock.patch.object(m,'_close_stream',close):
    session=m.adopt_owned_read_session(child.process,
     started_monotonic=child.started,nonce=old.NONCE)
    value,error=old.capture(session.read_once)
    returned_at=time.monotonic()
    first=child.facts()
    observed_copies=tuple(copies);observed_closes=tuple(close_events)
    _,repeat_error=old.capture(session.read_once)
  finally:
   # Fallback is after first result/observations, never product deadline proof.
   # Only exact retained child/original streams; no numeric FD/PID rescue.
   child.rescue_after_snapshot()

  # All fault behavior assertions outside scopes/hooks/finalizers.
  # Observation/prerequisite assertions distinguish missing copy seam from
  # resource deadline behavior, without manufacturing a negative success.
  print('LIVE_COPY_BUDGET_FACTS='+json.dumps(dict(
   copies=len(observed_copies),returned_type=type(value).__name__,
   error_type=type(error).__name__ if error is not None else None,
   elapsed=returned_at-child.started,first=first,
   copy_timings=[dict(started=row['started']-child.started,
    returning=row['returning']-child.started,resources=row['resources_at_copy_return'])
    for row in observed_copies],
   close_times=[at-child.started for stream,at in observed_closes]),sort_keys=True),flush=True)
  self.assertEqual(1,len(observed_copies),'REAL_COPY_WINDOW_NOT_REACHED')
  copied=observed_copies[0]
  self.assertEqual(old.DATA,copied['input']);self.assertEqual(old.DATA,copied['copied'])
  self.assertLess(copied['started']-child.started,28.0,'READY_COPY_WINDOW_NOT_REACHED')
  self.assertGreaterEqual(copied['returning']-child.started,29.15)
  self.assertIsNone(value,'SLOW_FIRST_COPY_MUST_NOT_RETURN_READY_DATA')
  self.assertIsInstance(error,ValueError)
  self.assertEqual(dict(reaped=True,groupgone=True,closed=True,EBADF=[True]*3),first)
  self.assertLess(returned_at-child.started,30.0,'FAILURE_CLEANUP_OUTSIDE_ORIGINAL_TOTAL30')
  # The child's own command loop promptly honors CLOSE. Actual resources must
  # already be gone while caller still waits in the copy, not just after return.
  self.assertEqual(dict(reaped=True,groupgone=True,closed=True,EBADF=[True]*3),
   copied['resources_at_copy_return'])
  self.assertEqual(3,len(observed_closes))
  self.assertEqual(3,len(set(id(stream) for stream,at in observed_closes)))
  self.assertEqual(set(map(id,(child.process.stdin,child.process.stdout,child.process.stderr))),
   {id(stream) for stream,at in observed_closes})
  self.assertTrue(all(28.0<=at-child.started<29.15 for stream,at in observed_closes),
   'PUMP_MUST_ACTIVELY_CLEANUP_AT_ORIGINAL_WORK28_WHILE_COPY_STILL_PENDING')
  self.assertIsInstance(repeat_error,ValueError)
