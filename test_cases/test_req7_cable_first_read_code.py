"""SOURCE NOT RUN. Fixed finite public code-only prerequisite; no SA or request."""
import errno,importlib,importlib.util,os,stat,types,unittest
from importlib import metadata
from unittest import mock

# Independent literal inventory; never read candidate rows/slots for expected files.
FILES=(
 'google/oauth2/service_account.py','google/oauth2/credentials.py','google/auth/credentials.py',
 'google/auth/_credentials_base.py','google/auth/crypt/rsa.py','google_auth_httplib2.py',
 'googleapiclient/discovery.py','googleapiclient/http.py','googleapiclient/_helpers.py',
 'google/auth/crypt/_cryptography_rsa.py','google/auth/crypt/base.py','google/auth/_helpers.py',
 'google/auth/_service_account_info.py','google/auth/transport/__init__.py','httplib2/__init__.py',
 'google/auth/_refresh_worker.py','google/auth/_regional_access_boundary_utils.py',
 'google/oauth2/_client.py','google/auth/jwt.py','google/auth/metrics.py','google/auth/_exponential_backoff.py')

def capture(action):
 try:return action(),None
 except BaseException as error:return None,error
def key(s):return (s.st_dev,s.st_ino,stat.S_IFMT(s.st_mode))
def ebadf(fd):
 try:os.fstat(fd)
 except OSError as error:return error.errno==errno.EBADF
 return False
def module(test):
 test.assertIsNotNone(importlib.util.find_spec('monitor.issue_tracker_cable_first_read_code'),
  'MISSING_FIXED_FIRST_READ_CODE_PREREQUISITE_DOWNSTREAM_NOT_REACHED')
 return importlib.import_module('monitor.issue_tracker_cable_first_read_code')

def expected():
 out={}
 for relative in FILES:
  distribution=('google-auth-httplib2' if relative=='google_auth_httplib2.py' else
   'google-api-python-client' if relative.startswith('googleapiclient/') else
   'httplib2' if relative.startswith('httplib2/') else 'google-auth')
  path=metadata.distribution(distribution).locate_file(relative)
  out[key(path.stat())]=relative
 return out

class OSView:
 def __init__(self,real,known,inject=False,first_ni=None):
  self.real,self.known,self.inject,self.first_ni=real,known,inject,first_ni
  self.opens=[];self.closes=[];self.observer_errors=[]
 def __getattr__(self,name):return getattr(self.real,name)
 def open(self,*args,**kwargs):
  fd=self.real.open(*args,**kwargs)
  try:self.opens.append((fd,key(self.real.fstat(fd))))
  except BaseException as error:self.observer_errors.append(type(error).__name__)
  return fd
 def close(self,fd):
  identity=key(self.real.fstat(fd))
  result=self.real.close(fd)  # Critical close is genuine before injected failure.
  closed=ebadf(fd);self.closes.append((fd,identity,closed))
  role=self.known.get(identity)
  if self.inject and role=='google/auth/_exponential_backoff.py':raise self.first_ni
  if self.inject and role=='google/auth/metrics.py':raise OSError(errno.EIO,'synthetic-later-close')
  return result

def run_once(m,*,inject=False,first_ni=None):
 from monitor import issue_tracker_publish_runtime as runtime
 known=expected();view=OSView(runtime.os,known,inject=inject,first_ni=first_ni)
 pins=None;entered=False;body_error=close_error=None;constructors=[];requests=[]
 # Passive profile only; code-only scope must not construct SA or issue Request.
 import sys
 prior=sys.getprofile()
 def profile(frame,event,value):
  if event=='call':
   name=frame.f_globals.get('__name__');fn=frame.f_code.co_name
   if name=='google.oauth2.service_account' and fn=='__init__':constructors.append(True)
   if name=='google_auth_httplib2' and fn=='__call__':requests.append(True)
 try:
  with mock.patch.object(runtime,'os',view):
   sys.setprofile(profile)
   try:
    pins=m._CableSdkFirstReadCodePins()
    _,body_error=capture(pins.acquire);entered=body_error is None
    if entered:
     before=len(view.opens);_,verify_error=capture(pins.verify)
     _,second_verify_error=capture(pins.verify);no_new_opens=len(view.opens)==before
    else:verify_error=second_verify_error=None;no_new_opens=None
   finally:
    sys.setprofile(prior)
    if pins is not None:_,close_error=capture(pins.close)
   first_closed=[ebadf(fd) for fd,identity in view.opens]
   _,revoked=capture(pins.verify) if pins is not None else (None,None)
 finally:
  sys.setprofile(prior)
 # No numeric rescue: normal/counterfactual tests are expected to settle all.
 # Any fixture FD leak is evidence/error and root isolated process owns cleanup.
 return dict(entered=entered,body_error=body_error,verify_error=verify_error,
  second_verify_error=second_verify_error,no_new_opens=no_new_opens,close_error=close_error,
  opens=tuple(view.opens),closes=tuple(view.closes),known=known,closed=first_closed,
  revoked=revoked,observer_errors=tuple(view.observer_errors),
  constructors=constructors,requests=requests,profile_restored=sys.getprofile() is prior)

class FirstReadCodeTests(unittest.TestCase):
 def healthy(self,m):
  r=run_once(m)
  self.assertTrue(r['entered']);self.assertIsNone(r['body_error'])
  self.assertIsNone(r['verify_error']);self.assertIsNone(r['second_verify_error'])
  self.assertTrue(r['no_new_opens']);self.assertIsNone(r['close_error'])
  self.assertEqual([],r['constructors']);self.assertEqual([],r['requests'])
  self.assertEqual((),r['observer_errors']);self.assertTrue(r['profile_restored'])
  actual=[r['known'][identity] for fd,identity in r['opens'] if identity in r['known']]
  self.assertEqual(sorted(FILES),sorted(actual))
  self.assertEqual(tuple(reversed(r['opens'])),tuple((fd,identity) for fd,identity,closed in r['closes']))
  self.assertTrue(all(closed for fd,identity,closed in r['closes']))
  self.assertEqual([True]*len(r['opens']),r['closed']);self.assertIsInstance(r['revoked'],ValueError)

 def test_real_fixed_twenty_one_sources_verify_and_reverse_close(self):
  m=module(self);self.healthy(m)

 def test_preexisting_request_method_default_and_sa_client_alias_refuse_before_io(self):
  m=module(self);self.healthy(m)
  adapter=importlib.import_module('google_auth_httplib2')
  sa=importlib.import_module('google.oauth2.service_account')
  old_call=adapter.Request.__call__;old_defaults=old_call.__defaults__;old_alias=sa._client
  entries=[];results=[]
  def delegated(self,*args,**kwargs):
   entries.append(True);return old_call(self,*args,**kwargs)
  try:
   adapter.Request.__call__=delegated
   results.append(run_once(m))
  finally:adapter.Request.__call__=old_call
  try:
   old_call.__defaults__=('POST',None,None,None)
   results.append(run_once(m))
  finally:old_call.__defaults__=old_defaults
  try:
   sa._client=types.SimpleNamespace(jwt_grant=old_alias.jwt_grant)
   results.append(run_once(m))
  finally:sa._client=old_alias
  # All rejection assertions outside patches/product lifetime. No assertRaises trap.
  self.assertEqual(3,len(results));self.assertEqual([],entries)
  for r in results:
   self.assertFalse(r['entered']);self.assertIsInstance(r['body_error'],ValueError)
   self.assertIsNone(r['close_error']);self.assertEqual([],r['constructors']);self.assertEqual([],r['requests'])
   self.assertEqual((),r['observer_errors']);self.assertEqual([True]*len(r['opens']),r['closed'])
   self.assertIsInstance(r['revoked'],ValueError)

 def test_extra_sources_close_first_ni_identity_and_later_eio_all_slots_attempted(self):
  m=module(self);self.healthy(m)
  first=KeyboardInterrupt('synthetic-first-extra-close')
  cause=RuntimeError('synthetic-existing-cause');first.__cause__=cause
  r=run_once(m,inject=True,first_ni=first)
  self.assertTrue(r['entered']);self.assertIsNone(r['body_error'])
  self.assertIs(r['close_error'],first);self.assertIs(first.__cause__,cause)
  self.assertEqual(tuple(reversed(r['opens'])),tuple((fd,identity) for fd,identity,closed in r['closes']))
  self.assertTrue(all(closed for fd,identity,closed in r['closes']))
  self.assertEqual([True]*len(r['opens']),r['closed'])
  self.assertEqual((),r['observer_errors']);self.assertEqual([],r['constructors']);self.assertEqual([],r['requests'])
  self.assertIsInstance(r['revoked'],ValueError)

