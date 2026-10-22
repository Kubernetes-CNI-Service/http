"""Restricted one-emission HTTPS IO; no source/native/worker authority.

The target is bounded DATA, not admission. Only an explicitly qualified future
caller may wire this utility into a native factory. No refresh/retry/proxy,
arbitrary URL/CA or default worker route is installed. Per-operation timeouts
are not whole30/fixed60 or uninterruptible-kernel supervision.
"""
import http.client
import re
import socket as _socket
import ssl
import threading

from monitor import issue_tracker_tls_inputs as _tls

_TOKEN_URL = 'https://oauth2.googleapis.com/token'
_TARGET = re.compile(r'[A-Za-z0-9_-]{20,160}\Z')
_BEARER = re.compile(r'Bearer [A-Za-z0-9._~+/\-]+=*\Z')
_MAX_BODY = 65536
_MAX_RESPONSE = 2 * 1024 * 1024


class FixedHttpsHold(ValueError):
    def __init__(self):
        super().__init__('fixed_https_denied')


class _Response(dict):
    """Only bounded non-secret response metadata for actual SDK consumers."""
    status = 200
    reason = 'OK'


class _WireResponse(http.client.HTTPResponse):
    def _read_status(self):
        # Keep the actual bounded stdlib parser, but do not let its automatic
        # 100-Continue loop consume unbounded interim messages.
        version, status, reason = super()._read_status()
        if status < 200:
            raise FixedHttpsHold()
        return version, status, reason


def _fixed_spec(kind, target):
    if type(kind) is str and kind == 'token' and target is None:
        return 'oauth2.googleapis.com', '/token', 'POST', _TOKEN_URL
    if (type(kind) is str and kind == 'sheets-read' and type(target) is str
            and _TARGET.fullmatch(target) is not None):
        path = '/v4/spreadsheets/' + target + '?fields=spreadsheetId&alt=json'
        return 'sheets.googleapis.com', path, 'GET', 'https://sheets.googleapis.com' + path
    if (type(kind) is str and kind == 'sheets-grid' and type(target) is str
            and _TARGET.fullmatch(target) is not None):
        from urllib.parse import urlencode
        from monitor.issue_tracker_cable_grid import FIELDS, RANGES
        query = urlencode([('includeGridData','true'),
                           *(('ranges',value) for value in RANGES),
                           ('fields',FIELDS),('alt','json')])
        path = '/v4/spreadsheets/' + target + '?' + query
        return 'sheets.googleapis.com', path, 'GET', 'https://sheets.googleapis.com' + path
    raise FixedHttpsHold()


def _close_resource(resource):
    """Private IO action only; tests may delegate real close then observe it."""
    resource.close()


class _FixedHttps:
    def __init__(self, kind, target):
        _fixed_spec(kind, target)
        self._kind, self._target = kind, target
        self._used = False
        self._guard = threading.Lock()

    def close(self):
        # No connection pool/resources survive request(). Do not resolve a
        # stream/PID/FD from caller DATA, and do not repair a prior result.
        with self._guard:
            self._used = True

    def _wire(self, uri, method, body, headers, redirections, connection_type, kwargs):
        # Re-derive fixed values and retain locals through the whole IO call;
        # mutable instance attributes never become an arbitrary host/path.
        host, path, fixed_method, fixed_uri = _fixed_spec(self._kind, self._target)
        if (type(uri) is not str or uri != fixed_uri or type(method) is not str
                or method != fixed_method or type(headers) is not dict
                or len(headers) > 12 or type(redirections) is not int
                or redirections not in (0, 5) or connection_type is not None or kwargs):
            raise FixedHttpsHold()
        # 5 is the installed httplib2-compatible SDK default, accepted as
        # syntax ONLY. No value enables a redirect or any second request.
        if fixed_method == 'POST':
            if type(body) is not bytes or not 1 <= len(body) <= _MAX_BODY:
                raise FixedHttpsHold()
        elif body is not None and (type(body) is not bytes or body != b''):
            raise FixedHttpsHold()
        actual = {}
        allowed = {'content-type','authorization','accept','accept-encoding',
                   'user-agent','x-goog-api-client','content-length'}
        for key, value in headers.items():
            if (type(key) is not str or key.lower() not in allowed
                    or key.lower() in actual or type(value) is not str
                    or not 1 <= len(value) <= (8199 if key.lower() == 'authorization' else 1024)
                    or any(not 32 <= ord(char) <= 126 for char in value)):
                raise FixedHttpsHold()
            actual[key.lower()] = value
        if fixed_method == 'POST':
            if (actual.get('content-type') != 'application/x-www-form-urlencoded'
                    or 'authorization' in actual):
                raise FixedHttpsHold()
        elif (_BEARER.fullmatch(actual.get('authorization', '')) is None
                or len(actual['authorization']) > 8199
                or actual.get('content-type', 'application/json') != 'application/json'):
            raise FixedHttpsHold()
        if actual.get('accept', 'application/json') != 'application/json':
            raise FixedHttpsHold()
        if actual.get('accept-encoding', 'identity') not in ('identity','gzip','gzip, deflate'):
            raise FixedHttpsHold()
        if 'content-length' in actual and actual['content-length'] != str(len(body or b'')):
            raise FixedHttpsHold()
        # Never ask for compression; a SDK's default encoding preference is
        # not permission for a second codec/unbounded decoded response.
        actual.pop('accept-encoding', None)
        actual.pop('content-length', None)
        lines = [fixed_method + ' ' + path + ' HTTP/1.1',
                 'Host: ' + host, 'Connection: close', 'Accept-Encoding: identity']
        if fixed_method == 'POST':
            lines.append('Content-Length: ' + str(len(body)))
        names = {'content-type':'Content-Type','authorization':'Authorization',
                 'accept':'Accept','user-agent':'User-Agent','x-goog-api-client':'x-goog-api-client'}
        for key in sorted(actual):
            lines.append(names[key] + ': ' + actual[key])
        wire = ('\r\n'.join(lines) + '\r\n\r\n').encode('ascii')
        if len(wire) > 16384:
            raise FixedHttpsHold()
        return host, fixed_method, wire + (body or b'')

    def request(self, uri, method='GET', body=None, headers=None,
                redirections=5, connection_type=None, **kwargs):
        # Sticky consumption precedes validation, CA, DNS, connect or encoding.
        with self._guard:
            consumed = self._used
            self._used = True
        if consumed:
            raise FixedHttpsHold()
        raw = secure = response = None
        primary = None
        result = None
        try:
            host, fixed_method, wire = self._wire(uri, method, body, headers, redirections, connection_type, kwargs)
            context, _identity = _tls.controlled_tls_context()
            if (type(context) is not ssl.SSLContext
                    or context.verify_mode != ssl.CERT_REQUIRED or context.check_hostname is not True):
                raise FixedHttpsHold()
            addresses = _socket.getaddrinfo(host, 443, _socket.AF_UNSPEC,
                                           _socket.SOCK_STREAM, _socket.IPPROTO_TCP)
            if type(addresses) is not list or not 1 <= len(addresses) <= 32:
                raise FixedHttpsHold()
            # Exactly one chosen address. Failure never tries another answer.
            family, kind, protocol, _canonical, address = addresses[0]
            if (family not in (_socket.AF_INET, _socket.AF_INET6)
                    or kind != _socket.SOCK_STREAM or protocol != _socket.IPPROTO_TCP):
                raise FixedHttpsHold()
            raw = _socket.socket(family, kind, protocol)
            raw.settimeout(10.0)
            raw.connect(address)
            secure = context.wrap_socket(raw, server_hostname=host)
            secure.settimeout(10.0)
            if secure.selected_alpn_protocol() not in (None, 'http/1.1'):
                raise FixedHttpsHold()
            # One HTTP emission, not a claim of one socket.write syscall.
            secure.sendall(wire)
            response = _WireResponse.__new__(_WireResponse)
            http.client.HTTPResponse.__init__(response, secure, method=fixed_method)
            response.begin()
            if type(response.status) is not int or response.status != 200:
                raise FixedHttpsHold()
            pairs = response.getheaders()
            if type(pairs) is not list or len(pairs) > 100:
                raise FixedHttpsHold()
            seen = {}
            total = 0
            for name, value in pairs:
                if (type(name) is not str or re.fullmatch(r'[!#$%&\'*+.^_`|~0-9A-Za-z-]{1,256}',name) is None
                        or name.lower() in seen or type(value) is not str or len(value) > 8192
                        or any(not 32 <= ord(char) <= 126 for char in value)):
                    raise FixedHttpsHold()
                total += len(name) + len(value)
                seen[name.lower()] = value
            length = seen.get('content-length')
            if (total > 65536 or 'transfer-encoding' in seen
                    or seen.get('content-encoding','identity').lower() != 'identity'
                    or re.fullmatch(r'application/json(?:; *charset=utf-8)?',
                                    seen.get('content-type',''), re.IGNORECASE) is None
                    or type(length) is not str or re.fullmatch(r'[0-9]{1,10}',length) is None
                    or int(length) > _MAX_RESPONSE):
                raise FixedHttpsHold()
            content = response.read(int(length)+1)
            if type(content) is not bytes or len(content) != int(length):
                raise FixedHttpsHold()
            # This exact URI has already passed the fixed role check above.
            # Validate original JSON before SDK parsing can lose duplicate keys.
            if fixed_method == 'GET' and '?includeGridData=true&' in uri:
                from monitor.issue_tracker_cable_grid import decode_current_grid
                target = uri.split('/v4/spreadsheets/',1)[1].split('?',1)[0]
                decode_current_grid(target, content)
            # Do not reflect arbitrary response headers/reason into SDK-visible
            # metadata, logs or denial messages. Content is the private SDK IO
            # payload, not a non-secret repr or a public token API.
            result = (_Response({'status':'200','content-type':'application/json',
                                  'content-length':str(len(content))}), content)
        except BaseException as error:
            primary = error
        finally:
            for resource in (response, secure, raw):
                if resource is None:
                    continue
                try:
                    _close_resource(resource)
                except BaseException as error:
                    if primary is None or (isinstance(primary,Exception)
                                           and not isinstance(error,Exception)):
                        primary = error
        if primary is not None:
            if not isinstance(primary,Exception):
                raise primary
            # Outside all handlers: no secret/SDK/parser exception context.
            raise FixedHttpsHold() from None
        return result


def _protocol_only_http(kind, *, target=None):
    """No credential/source gate or sending permission; fixed protocol IO only."""
    return _FixedHttps(kind, target)
