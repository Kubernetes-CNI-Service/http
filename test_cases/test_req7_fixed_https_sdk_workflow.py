"""Actual public SDK -> genuine owned TLS peer; protocol utility, not authority."""
import base64
import json
import unittest
from urllib.parse import parse_qs
from test_cases import fixed_https_peer_fixture as fixture


class FixedHttpsSdkWorkflowTests(unittest.TestCase):
    def test_actual_refresh_and_authorized_httprequest_use_one_fixed_post_and_get(self):
        transport=fixture.entry(self)
        from cryptography.hazmat.primitives.asymmetric import rsa,padding
        from cryptography.hazmat.primitives import hashes,serialization
        from google.oauth2 import service_account,credentials
        from google_auth_httplib2 import Request,AuthorizedHttp
        from googleapiclient.discovery import build
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        info={'type':'service_account','client_email':'owned-protocol@example.invalid',
              'token_uri':'https://oauth2.googleapis.com/token',
              'private_key':key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode('ascii')}
        for fault in ('healthy','redirect','unauthorized','half-response','server-error','quota'):
            with self.subTest(fault=fault):
                sa=service_account.Credentials.from_service_account_info(info,
                    scopes=('https://www.googleapis.com/auth/spreadsheets',),always_use_jwt_access=False)
                token=transport._protocol_only_http('token')
                grid=transport._protocol_only_http('sheets-read',target=fixture.TARGET)
                token_body=b'{"access_token":"secret-value","expires_in":3600,"token_type":"Bearer"}'
                grid_body=b'{"spreadsheetId":"synthetic_spreadsheet_id_0001"}'
                reply=(fixture.response(200,grid_body) if fault=='healthy' else
                       fixture.response(302,grid_body,location=True) if fault=='redirect' else
                       fixture.response(401,grid_body) if fault=='unauthorized' else
                       fixture.response(500,grid_body) if fault=='server-error' else
                       fixture.response(429,grid_body) if fault=='quota' else
                       fixture.response(200,grid_body,length=999))
                result=error=None
                with fixture.peer(self,[fixture.response(200,token_body),reply]) as peer:
                    with peer.client(transport) as sockets:
                        sa.refresh(Request(token))
                        self.assertEqual('secret-value',sa.token)
                        frozen=credentials.Credentials(token=sa.token,expiry=sa.expiry,
                            scopes=('https://www.googleapis.com/auth/spreadsheets',))
                        authenticated=AuthorizedHttp(frozen,http=grid,max_refresh_attempts=0)
                        service=build('sheets','v4',http=authenticated,static_discovery=True,cache_discovery=False)
                        request=service.spreadsheets().get(spreadsheetId=fixture.TARGET,fields='spreadsheetId')
                        try:result=request.execute(num_retries=0)
                        except transport.FixedHttpsHold as caught:error=caught
                        first=(len(sockets.lookups),len(sockets.created),len(peer.records),tuple(peer.closed))
                        with self.assertRaises(transport.FixedHttpsHold):request.execute(num_retries=0)
                        after=(len(sockets.lookups),len(sockets.created),len(peer.records),tuple(peer.closed))
                        self.assertEqual(first,after,'SDK_REUSE_MUST_NOT_RELAUNCH_OR_CLOSE_AGAIN')
                        service.close()
                    self.assertEqual([],peer.errors)
                    self.assertEqual(2,len(peer.accepts))
                    self.assertEqual(['oauth2.googleapis.com','sheets.googleapis.com'],peer.sni)
                    self.assertEqual([('oauth2.googleapis.com',443),('sheets.googleapis.com',443)],sockets.lookups)
                    self.assertEqual(2,len(peer.records))
                    post,get=peer.records
                    self.assertEqual(b'POST /token HTTP/1.1\r\n',post[0])
                    self.assertIn(b'Host: oauth2.googleapis.com\r\n',post[1])
                    form=parse_qs(post[2].decode('ascii'),strict_parsing=True)
                    self.assertEqual({'grant_type','assertion'},set(form))
                    self.assertEqual(['urn:ietf:params:oauth:grant-type:jwt-bearer'],form['grant_type'])
                    parts=form['assertion'][0].split('.')
                    self.assertEqual(3,len(parts))
                    decode=lambda value:base64.urlsafe_b64decode(value+'='*(-len(value)%4))
                    claims=json.loads(decode(parts[1]))
                    self.assertEqual('owned-protocol@example.invalid',claims['iss'])
                    self.assertEqual('https://oauth2.googleapis.com/token',claims['aud'])
                    self.assertEqual('https://www.googleapis.com/auth/spreadsheets',claims['scope'])
                    self.assertNotIn('sub',claims)
                    key.public_key().verify(decode(parts[2]),('.'.join(parts[:2])).encode('ascii'),padding.PKCS1v15(),hashes.SHA256())
                    self.assertEqual(b'GET /v4/spreadsheets/synthetic_spreadsheet_id_0001?fields=spreadsheetId&alt=json HTTP/1.1\r\n',get[0])
                    self.assertIn(b'Host: sheets.googleapis.com\r\n',get[1])
                    self.assertIn(b'Authorization: Bearer secret-value\r\n',get[1])
                    self.assertEqual(b'',get[2])
                    self.assertEqual(6,len(peer.closed))
                    self.assertTrue(all(closed for _kind,closed in peer.closed))
                if fault=='healthy':
                    self.assertIsNone(error)
                    self.assertEqual({'spreadsheetId':'synthetic_spreadsheet_id_0001'},result)
                else:
                    self.assertIsNone(result)
                    self.assertIsNotNone(error)
                    self.assertEqual('fixed_https_denied',str(error))
                    self.assertIsNone(error.__context__)
                    self.assertIsNone(error.__cause__)

        # Genuine SDK token failures must not trigger its normal OAuth retry
        # or hidden reconnect: one peer transcript, then sticky zero extra IO.
        for status,length in ((302,None),(401,None),(200,999),(500,None),(429,None)):
            with self.subTest(token_status=status,token_length=length):
                sa=service_account.Credentials.from_service_account_info(info,
                    scopes=('https://www.googleapis.com/auth/spreadsheets',),always_use_jwt_access=False)
                token=transport._protocol_only_http('token')
                adapter=Request(token)
                payload=b'{"access_token":"secret-value","expires_in":3600}'
                with fixture.peer(self,[fixture.response(status,payload,length=length,location=status==302)]) as peer:
                    with peer.client(transport) as sockets:
                        caught=None
                        try:sa.refresh(adapter)
                        except transport.FixedHttpsHold as error:caught=error
                        self.assertIsNotNone(caught)
                        first=(len(sockets.lookups),len(sockets.created),len(peer.records),tuple(peer.closed))
                        with self.assertRaises(transport.FixedHttpsHold):sa.refresh(adapter)
                        self.assertEqual(first,(len(sockets.lookups),len(sockets.created),len(peer.records),tuple(peer.closed)))
                        self.assertIsNone(sa.token)
                        self.assertIsNone(caught.__context__)
                        self.assertIsNone(caught.__cause__)
                    self.assertEqual(1,len(peer.records))
                    self.assertEqual(1,len(peer.accepts))
                    self.assertEqual([],peer.errors)
                    self.assertEqual(3,len(peer.closed))
                    self.assertTrue(all(closed for _kind,closed in peer.closed))


if __name__=='__main__':unittest.main(verbosity=2)
