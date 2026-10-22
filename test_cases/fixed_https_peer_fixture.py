"""Owned loopback TLS and module-local IO views; no product result mocks."""
from contextlib import contextmanager
from datetime import datetime, timedelta
import errno
import json
import os
from pathlib import Path
import selectors
import socket
import ssl
import stat
import tempfile
import threading
from types import SimpleNamespace

TARGET = 'synthetic_spreadsheet_id_0001'
TOKEN_URL = 'https://oauth2.googleapis.com/token'
READ_URL = 'https://sheets.googleapis.com/v4/spreadsheets/' + TARGET + '?fields=spreadsheetId&alt=json'


def entry(test):
    import importlib.util
    test.assertIsNotNone(importlib.util.find_spec('monitor.issue_tracker_cable_fixed_https'),
                         'MISSING_FIXED_ONE_EMISSION_HTTPS_UTILITY')
    from monitor import issue_tracker_cable_fixed_https as transport
    test.assertTrue(callable(getattr(transport, '_protocol_only_http', None)),
                    'MISSING_FIXED_ONE_EMISSION_HTTPS_UTILITY')
    return transport


def response(status=200, body=b'{}', *, length=None, location=False):
    line = ('HTTP/1.1 %d Owned\r\nContent-Length: %d\r\n' %
            (status, len(body) if length is None else length)).encode('ascii')
    if location:
        line += b'Location: https://foreign.invalid/never\r\n'
    return line + b'Connection: close\r\nContent-Type: application/json\r\n\r\n' + body


class RootIO:
    """Only the actual TLS module's fixed CA filesystem IO is remapped."""
    def __init__(self, original, root):
        self.original, self.root = original, root
    def __getattr__(self, name):
        return getattr(self.original, name)
    def geteuid(self):
        return 0
    def open(self, name, flags, *args, **kwargs):
        if flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND | os.O_WRONLY | os.O_RDWR):
            raise AssertionError('CA_VIEW_READONLY')
        return self.original.open(self.root if name == '/' else name, flags, *args, **kwargs)
    @staticmethod
    def metadata(value):
        names = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size',
                 'st_atime','st_mtime','st_ctime','st_atime_ns','st_mtime_ns','st_ctime_ns')
        result = SimpleNamespace(**{name:getattr(value,name) for name in names})
        result.st_uid = 0
        return result
    def stat(self, *args, **kwargs):
        return self.metadata(self.original.stat(*args, **kwargs))
    def fstat(self, fd):
        return self.metadata(self.original.fstat(fd))


class ClientSockets:
    def __init__(self, original, address):
        self.original, self.address = original, address
        self.lookups, self.created = [], []
    def __getattr__(self, name):
        return getattr(self.original, name)
    def getaddrinfo(self, host, port, *args, **kwargs):
        if host not in ('oauth2.googleapis.com', 'sheets.googleapis.com') or port != 443:
            raise AssertionError('NO_FOREIGN_OR_ONLINE_DNS')
        self.lookups.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', self.address)]
    def socket(self, family, kind, protocol=0):
        result = self.original.socket(family, kind, protocol)
        self.created.append(result)
        return result


class Peer:
    def __init__(self, test):
        self.test = test
        self.temp = tempfile.TemporaryDirectory(prefix='req7-owned-fixed-https-')
        self.root = Path(self.temp.name)
        self.records, self.errors, self.sni, self.accepts = [], [], [], []
        self.replies = []
        self.closed = []
        self.listener = self.stop_read = self.stop_write = self.thread = None
        self.started = False
        primary = None
        try:
            self.context = self.material()
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.bind(('127.0.0.1', 0))
            self.listener.listen(8)
            self.address = self.listener.getsockname()
            self.stop_read, self.stop_write = socket.socketpair()
            self.thread = threading.Thread(target=self.serve, daemon=True)
            self.thread.start()
            self.started = True
        except BaseException as error:
            primary = error
        if primary is not None:
            try:self.close()
            except BaseException as error:
                if isinstance(primary,Exception) and not isinstance(error,Exception):primary=error
            raise primary

    def material(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Owned fixed HTTPS CA')])
        before, after = datetime.utcnow()-timedelta(days=1), datetime.utcnow()+timedelta(days=1)
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
              .public_key(key.public_key()).serial_number(11)
              .not_valid_before(before).not_valid_after(after)
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
              .sign(key,hashes.SHA256()))
        server_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Owned fixed HTTPS server')])
        leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(name)
                .public_key(server_key.public_key()).serial_number(12)
                .not_valid_before(before).not_valid_after(after)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('oauth2.googleapis.com'),
                    x509.DNSName('sheets.googleapis.com')]),False)
                .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
                .sign(key,hashes.SHA256()))
        ca_path = self.root/'etc/ssl/certs/ca-certificates.crt'
        ca_path.parent.mkdir(parents=True)
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        cert, private = self.root/'server.pem', self.root/'server-key.pem'
        cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        private.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert,private)
        context.set_servername_callback(lambda _socket,name,_context:self.sni.append(name))
        return context

    def serve(self):
        try:
            while True:
                with selectors.DefaultSelector() as select:
                    select.register(self.listener,selectors.EVENT_READ)
                    select.register(self.stop_read,selectors.EVENT_READ)
                    ready={key.fileobj for key,_events in select.select()}
                if self.stop_read in ready:
                    return
                raw,_address=self.listener.accept()
                self.accepts.append(True)
                raw.settimeout(4)
                with raw, self.context.wrap_socket(raw,server_side=True) as stream:
                    with stream.makefile('rb') as incoming:
                        line=incoming.readline(8193)
                        if len(line)>8192 or not line.endswith(b'\r\n'):
                            raise AssertionError('PEER_BAD_REQUEST_LINE')
                        headers=[]
                        for _ in range(100):
                            row=incoming.readline(8193)
                            if row==b'\r\n':break
                            if len(row)>8192 or not row.endswith(b'\r\n'):
                                raise AssertionError('PEER_BAD_HEADER')
                            headers.append(row)
                        else:raise AssertionError('PEER_HEADER_LIMIT')
                        lengths=[int(row.split(b':',1)[1]) for row in headers
                                 if row.lower().startswith(b'content-length:')]
                        if len(lengths)>1 or lengths and not 0<=lengths[0]<=65536:
                            raise AssertionError('PEER_BAD_LENGTH')
                        body=incoming.read(lengths[0] if lengths else 0)
                        if lengths and len(body)!=lengths[0]:raise AssertionError('PEER_SHORT_BODY')
                        self.records.append((line,tuple(headers),body))
                    index=len(self.records)-1
                    if index>=len(self.replies):raise AssertionError('UNEXPECTED_SECOND_HTTP_EMISSION')
                    stream.sendall(self.replies[index])
        except BaseException as error:
            self.errors.append(type(error).__name__)

    @contextmanager
    def client(self, transport):
        from monitor import issue_tracker_tls_inputs as tls
        old_os,old_socket,old_close=tls.os,transport._socket,transport._close_resource
        sockets=ClientSockets(socket,self.address)
        def close(resource):
            result=old_close(resource)
            if hasattr(resource,'isclosed'):
                closed=resource.isclosed()
            else:
                closed=resource.fileno()==-1
            self.closed.append((type(resource).__name__,closed))
            return result
        tls.os=RootIO(old_os,self.root)
        transport._socket=sockets
        transport._close_resource=close
        try:
            yield sockets
        finally:
            transport._close_resource=old_close
            transport._socket=old_socket
            tls.os=old_os

    def close(self):
        primary=None
        if self.started:
            try:
                self.stop_write.sendall(b'x')
                self.thread.join(5)
                self.test.assertFalse(self.thread.is_alive(),'OWNED_PEER_THREAD_NOT_TERMINATED')
            except BaseException as error:primary=error
        for resource in (self.stop_write,self.stop_read,self.listener,self.temp):
            if resource is None:continue
            try:
                if resource is self.temp:resource.cleanup()
                else:resource.close()
            except BaseException as error:
                if primary is None or (isinstance(primary,Exception) and not isinstance(error,Exception)):primary=error
        if primary is not None:raise primary


@contextmanager
def peer(test, replies):
    owned=Peer(test)
    owned.replies=list(replies)
    primary=None
    try:yield owned
    except BaseException as error:primary=error
    try:owned.close()
    except BaseException as error:
        if primary is None or (isinstance(primary,Exception) and not isinstance(error,Exception)):primary=error
    if primary is not None:raise primary
