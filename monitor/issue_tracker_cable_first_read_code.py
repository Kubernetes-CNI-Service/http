"""Finite first-read public CODE ONLY prerequisite. No credential or IO grant.

SOURCE candidate: old public15/constructor17 implementations are unchanged.
Four extra originals precede inherited imports and are owned separately.
This is not a complete RAB, cryptography, native or stdlib image.
"""
import ast
import builtins
import functools
import hashlib
import stat
import sys
from importlib import import_module, metadata
from pathlib import Path
from types import CodeType, ModuleType

from monitor import issue_tracker_publish_runtime as rt

_EXTRA = (
    ('google.oauth2._client', 'google/oauth2/_client.py',
     'd9b38a5fa113fc217a9296ba6e29bc5cab459b3907f7d2937837ee8507f23c75'),
    ('google.auth.jwt', 'google/auth/jwt.py',
     '0b156583d57131b81d49a4fbff88484833642fd78154d8b88c29a91495e23893'),
    ('google.auth.metrics', 'google/auth/metrics.py',
     'bac8c84ef4c598ed18a202490e2df5fe1825da480436e28c7e05b2e8b4c68718'),
    ('google.auth._exponential_backoff', 'google/auth/_exponential_backoff.py',
     'ab103d7a4f34ac1928011c741209766f5325614d03fa940d56a80299487e9605'),
)

# Bodies/defaults are compared with compiled held originals, never a snapshot
# of preexisting mutable function objects. These are selected finite edges.
_SELECTED = (
    ('google.oauth2._client', (
        ('_handle_error_response',), ('_can_retry',), ('_parse_expiry',),
        ('_token_endpoint_request_no_throw',), ('_token_endpoint_request',),
        ('jwt_grant',))),
    ('google.auth.jwt', (('encode',),)),
    ('google.auth.metrics', (
        ('python_and_auth_lib_version',), ('token_request_access_token_sa_assertion',),
        ('add_metric_header',))),
    ('google.auth._exponential_backoff', (
        ('_BaseExponentialBackoff', '__init__'),
        ('_BaseExponentialBackoff', 'total_attempts'),
        ('_BaseExponentialBackoff', 'backoff_count'),
        ('_BaseExponentialBackoff', '_reset'),
        ('_BaseExponentialBackoff', '_calculate_jitter'),
        ('ExponentialBackoff', '__init__'), ('ExponentialBackoff', '__iter__'),
        ('ExponentialBackoff', '__next__'))),
    ('google_auth_httplib2', (
        ('Request', '__init__'), ('Request', '__call__'),
        ('_Response', '__init__'), ('_Response', 'status'),
        ('_Response', 'headers'), ('_Response', 'data'),
        ('AuthorizedHttp', '__init__'), ('AuthorizedHttp', 'request'),
        ('AuthorizedHttp', 'close'))),
    ('google.auth.credentials', (
        ('Credentials', 'expired'), ('Credentials', 'valid'),
        ('Credentials', 'quota_project_id'), ('Credentials', 'universe_domain'),
        ('Credentials', 'apply'), ('Credentials', '_blocking_refresh'),
        ('Credentials', '_non_blocking_refresh'),
        ('CredentialsWithRegionalAccessBoundary', 'refresh'),
        ('CredentialsWithRegionalAccessBoundary', 'apply'),
        ('CredentialsWithRegionalAccessBoundary', 'before_request'),
        ('CredentialsWithRegionalAccessBoundary', '_is_regional_access_boundary_lookup_required'),
        ('CredentialsWithRegionalAccessBoundary', '_maybe_start_regional_access_boundary_refresh'))),
    ('google.auth._credentials_base', (('_BaseCredentials', '_apply'),)),
    ('google.oauth2.service_account', (
        ('Credentials', '_make_authorization_grant_assertion'),
        ('Credentials', '_perform_refresh_token'),
        ('Credentials', '_use_self_signed_jwt'),
        ('Credentials', '_metric_header_for_usage'))),
    ('google.auth._regional_access_boundary_utils', (
        ('_RegionalAccessBoundaryManager', 'apply_headers'),
        ('_RegionalAccessBoundaryManager', 'maybe_start_refresh'),
        ('_RegionalAccessBoundaryManager', 'start_blocking_refresh'),
        ('_RegionalAccessBoundaryManager', 'process_regional_access_boundary_info'),
        ('_RegionalAccessBoundaryRefreshManager', 'start_refresh'))),
    ('google.auth._helpers', (
        ('utcnow',), ('datetime_to_secs',), ('scopes_to_string',),
        ('unpadded_urlsafe_b64encode',), ('from_bytes',))),
)


class _CableSdkFirstReadCodePins(rt._CableSdkConstructorCodePins):
    """Fixed 21-file code prerequisite; accepts no caller rows/SA/checker/FD.

    The lru_cache wrapper's internal callable/cache, background/IAM alternatives,
    transitive crypto/native and mutable stdlib dependencies are NOT attested.
    No refresh, Request, cache-enable call or credential constructor occurs here.
    """
    def __init__(self):
        super().__init__()
        self._extra = rt._CableSdkCodePins()
        self._first_read_bindings = None
        self._first_close_started = False

    def _hold_extra(self):
        owner = self._extra
        for module_name, relative, expected in _EXTRA:
            path = Path(metadata.distribution('google-auth').locate_file(relative))
            if (not path.is_absolute() or '..' in path.parts
                    or path.parts[-len(Path(relative).parts):] != Path(relative).parts):
                raise rt.CableSourceHold('Cable first-read code locator differs')
            parent = owner._directory(path.parent)[0]
            before = rt.os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or not 0 < before.st_size <= 1048576):
                raise rt.CableSourceHold('Cable first-read code is not regular source')
            fd = rt.os.open(path.name, rt.os.O_RDONLY | rt.os.O_NOFOLLOW | rt.os.O_CLOEXEC,
                            dir_fd=parent)
            owner.slots.append((fd, (before.st_dev, before.st_ino)))

            def full():
                raw = b''
                while len(raw) < before.st_size:
                    block = rt.os.pread(fd, min(1048576, before.st_size-len(raw)), len(raw))
                    if not block:
                        raise rt.CableSourceHold('Cable first-read source shortened')
                    raw += block
                if rt.os.pread(fd, 1, len(raw)):
                    raise rt.CableSourceHold('Cable first-read source grew')
                return raw

            if rt._cable_identity(rt.os.fstat(fd)) != rt._cable_identity(before):
                raise rt.CableSourceHold('Cable first-read source acquisition changed')
            raw = full()
            if (full() != raw or hashlib.sha256(raw).hexdigest() != expected
                    or rt._cable_identity(rt.os.fstat(fd)) != rt._cable_identity(before)
                    or rt._cable_identity(rt.os.stat(path.name, dir_fd=parent,
                        follow_symlinks=False)) != rt._cable_identity(before)):
                raise rt.CableSourceHold('Cable first-read held source differs')
            owner.files.append((path, fd, parent, before, expected))
            code = compile(raw, str(path), 'exec', dont_inherit=True)
            tree = ast.parse(raw, filename=str(path))

            def codes(item, trail=()):
                for value in item.co_consts:
                    if type(value) is CodeType:
                        key = trail + (value.co_name,)
                        self.codes[(module_name, key)] = value
                        codes(value, key)

            def nodes(node, trail=()):
                for value in node.body:
                    if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        key = trail + (value.name,)
                        self.nodes[(module_name, key)] = value
                        nodes(value, key)

            codes(code)
            nodes(tree)
            self.constants[module_name] = {
                node.targets[0].id: node.value for node in tree.body
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)}
            self.paths[module_name] = path

    def acquire(self):
        if (self.closed or self.failure is not None or self.slots
                or self._extra.slots or self._first_close_started):
            raise rt.CableSourceHold('Cable first-read code acquisition is unavailable')
        try:
            self._hold_extra()
            # Do NOT insert extra slots into self.slots: original seventeen's
            # acquire entry remains unchanged and requires its empty owner.
            super().acquire()
        except BaseException as error:
            self.failure = error
            raise

    def _check_extra_files(self):
        owner = self._extra
        if (owner.closed or owner.failure is not None
                or owner.execution != (rt.os.getpid(), rt.threading.get_ident())):
            raise rt.CableSourceHold('Cable first-read extra owner is unavailable')
        for path, (fd, parent, before) in owner.directories.items():
            now = rt.os.fstat(fd)
            if ((now.st_dev, now.st_ino, now.st_mode, now.st_uid, now.st_gid)
                    != (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid)):
                raise rt.CableSourceHold('Cable first-read ancestor changed')
            named = rt.os.stat('/' if parent is None else path.name,
                               dir_fd=parent, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
                raise rt.CableSourceHold('Cable first-read named ancestor changed')
        for path, fd, parent, before, expected in owner.files:
            if (rt._cable_identity(rt.os.fstat(fd)) != rt._cable_identity(before)
                    or rt._cable_identity(rt.os.stat(path.name, dir_fd=parent,
                        follow_symlinks=False)) != rt._cable_identity(before)
                    or rt._CableOriginals._digest(rt.os, fd, before.st_size) != expected):
                raise rt.CableSourceHold('Cable first-read original changed')

    def _check_bindings(self, *, first=False):
        super()._check_bindings(first=first)
        found = []
        for module_name, _relative, _expected in _EXTRA:
            if first:
                if module_name in self.modules:
                    raise rt.CableSourceHold('Cable first-read module selection overlaps')
                self.modules[module_name] = import_module(module_name)
            module = self.modules[module_name]
            if (type(module) is not ModuleType or sys.modules.get(module_name) is not module
                    or module.__name__ != module_name
                    or Path(module.__file__) != self.paths[module_name]
                    or vars(module).get('__builtins__') is not vars(builtins)):
                raise rt.CableSourceHold('Cable first-read original module differs')
            found.append(module)
        for module_name, selectors in _SELECTED:
            module = self.modules[module_name]
            for selector in selectors:
                owner = module if len(selector) == 1 else self._class(module_name, selector[0])
                descriptor = vars(owner).get(selector[-1])
                fn = descriptor
                if type(descriptor) is property:
                    if descriptor.fset is not None or descriptor.fdel is not None:
                        raise rt.CableSourceHold('Cable first-read property changed')
                    fn = descriptor.fget
                elif type(descriptor) in (classmethod, staticmethod):
                    fn = descriptor.__func__
                self._function(fn, module_name, selector)
                found.extend((owner, descriptor, fn))

        aliases = (
            ('google.oauth2.service_account', '_client', 'google.oauth2._client'),
            ('google.oauth2.service_account', 'jwt', 'google.auth.jwt'),
            ('google.oauth2.service_account', 'metrics', 'google.auth.metrics'),
            ('google.oauth2.service_account', '_helpers', 'google.auth._helpers'),
            ('google.oauth2._client', '_exponential_backoff', 'google.auth._exponential_backoff'),
            ('google.oauth2._client', '_helpers', 'google.auth._helpers'),
            ('google.oauth2._client', 'credentials', 'google.auth.credentials'),
            ('google.oauth2._client', 'jwt', 'google.auth.jwt'),
            ('google.oauth2._client', 'metrics', 'google.auth.metrics'),
            ('google.oauth2._client', 'transport', 'google.auth.transport'),
            ('google.auth.jwt', '_helpers', 'google.auth._helpers'),
            ('google.auth.jwt', '_service_account_info', 'google.auth._service_account_info'),
            ('google.auth.credentials', 'metrics', 'google.auth.metrics'),
            ('google.auth.credentials', '_helpers', 'google.auth._helpers'),
            ('google.auth.credentials', '_regional_access_boundary_utils',
                'google.auth._regional_access_boundary_utils'),
            ('google.auth._credentials_base', '_helpers', 'google.auth._helpers'),
            ('google.auth._regional_access_boundary_utils', '_helpers', 'google.auth._helpers'),
            ('google_auth_httplib2', 'transport', 'google.auth.transport'),
            ('google_auth_httplib2', 'httplib2', 'httplib2'),
        )
        for module_name, name, target in aliases:
            if vars(self.modules[module_name]).get(name) is not self.modules[target]:
                raise rt.CableSourceHold('Cable first-read provider alias differs')
            found.append(self.modules[target])

        # Fixed class/base relationships, not matching class names.
        for module_name, name, base_module, base_name in (
                ('google_auth_httplib2', 'Request', 'google.auth.transport', 'Request'),
                ('google_auth_httplib2', '_Response', 'google.auth.transport', 'Response'),
                ('google.auth._exponential_backoff', 'ExponentialBackoff',
                    'google.auth._exponential_backoff', '_BaseExponentialBackoff')):
            cls, base = self._class(module_name, name), self._class(base_module, base_name)
            if cls.__bases__ != (base,):
                raise rt.CableSourceHold('Cable first-read class base differs')
            found.extend((cls, base))
        adapter = self.modules['google_auth_httplib2']
        for name in ('Request', '_Response'):
            if vars(adapter).get(name) is not self._class(adapter.__name__, name):
                raise rt.CableSourceHold('Cable first-read adapter class alias differs')
        for module_name, names in (
                ('google_auth_httplib2', ('Request', '_Response')),
                ('google.auth._exponential_backoff', ('_BaseExponentialBackoff', 'ExponentialBackoff'))):
            for name in names:
                cls = self._class(module_name, name)
                if (cls.__new__ is not object.__new__
                        or cls.__getattribute__ is not object.__getattribute__
                        or cls.__setattr__ is not object.__setattr__
                        or cls.__delattr__ is not object.__delattr__
                        or type(cls).__call__ is not type.__call__
                        or '__getattr__' in vars(cls)):
                    raise rt.CableSourceHold('Cable first-read ordinary class dispatch differs')
        # Actual inherited SA apply/refresh dispatch, not a wrapper DTO.
        sa_cls = self._class('google.oauth2.service_account', 'Credentials')
        cred_cls = self._class('google.auth.credentials', 'Credentials')
        rab_cls = self._class('google.auth.credentials', 'CredentialsWithRegionalAccessBoundary')
        base_cls = self._class('google.auth._credentials_base', '_BaseCredentials')
        for name in ('apply', 'refresh'):
            if getattr(sa_cls, name) is not vars(rab_cls)[name]:
                raise rt.CableSourceHold('Cable first-read inherited dispatch differs')
        if getattr(sa_cls, '_apply') is not vars(base_cls)['_apply']:
            raise rt.CableSourceHold('Cable first-read base apply dispatch differs')
        # Source literal constants used by the selected branch.
        for module_name, names in (
                ('google.oauth2._client', ('_URLENCODED_CONTENT_TYPE', '_JSON_CONTENT_TYPE', '_JWT_GRANT_TYPE')),
                ('google.auth.metrics', ('API_CLIENT_HEADER', 'REQUEST_TYPE_ACCESS_TOKEN', 'CRED_TYPE_SA_ASSERTION')),
                ('google.oauth2.service_account', ('_DEFAULT_TOKEN_LIFETIME_SECS', '_GOOGLE_OAUTH2_TOKEN_ENDPOINT')),
                ('google.auth._regional_access_boundary_utils', ('_REGIONAL_ACCESS_BOUNDARY_HEADER',))):
            for name in names:
                value = self._literal(self.constants[module_name][name], module_name)
                if not self._same(vars(self.modules[module_name]).get(name), value):
                    raise rt.CableSourceHold('Cable first-read source constant differs')

        # An opaque C wrapper is NOT authenticated by its __wrapped__ attr.
        # Check this finite exposed surface only; never execute/clear the cache.
        rab = self.modules['google.auth._regional_access_boundary_utils']
        cached = vars(rab).get('is_regional_access_boundary_enabled')
        if type(cached) is not functools._lru_cache_wrapper or rab.functools is not functools:
            raise rt.CableSourceHold('Cable first-read cache wrapper surface differs')
        body = vars(cached).get('__wrapped__')
        self._function(body, rab.__name__, ('is_regional_access_boundary_enabled',))
        found.extend((cached, body))
        # Every selected actual provider is kept stable after source validation.
        if first:
            self._first_read_bindings = tuple(found)
        elif (self._first_read_bindings is None
                or len(found) != len(self._first_read_bindings)
                or any(a is not b for a, b in zip(found, self._first_read_bindings))):
            raise rt.CableSourceHold('Cable first-read provider was replaced')

    def verify(self):
        if (self.closed or self.failure is not None or self._first_close_started
                or self.execution != (rt.os.getpid(), rt.threading.get_ident())):
            raise rt.CableSourceHold('Cable first-read code scope is unavailable')
        try:
            self._check_extra_files()
            super().verify()
        except BaseException as error:
            self.failure = error
            raise

    def close(self):
        if self._first_close_started:
            return
        self._first_close_started = True  # Revoke before any known close.
        primary = None
        try:
            super().close()
        except BaseException as error:
            primary = error
        try:
            self._extra.close()
        except BaseException as error:
            if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
                primary = error
        if primary is not None:
            raise primary
