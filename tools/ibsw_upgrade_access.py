"""Private SSH authorization backup and missing-only post-reboot recovery.

Only explicitly confirmed upgrade runs use this module. Passwords stay in
memory; no private key is uploaded. Every write follows fresh pin, account,
hostname and eth0-MAC verification on the password-authenticated session.
"""
import base64
import errno
import hashlib
import json
import os
from pathlib import PurePosixPath
import posixpath
import secrets
import shlex
import stat
import sys
import time

from ibsw_upgrade_contract import SharedUpgradeHold
from ssh_key_preparation import public_key_identity_bytes

LIMIT = 1024 * 1024
ACCOUNT_COMMAND = 'id -u; getent passwd "$(id -u)"'
ACCESS_CHECK_HINTS = {
    'ACCESS_CHECK_UNCLASSIFIED': 'Authorization preservation failed a safety check; review the private evidence.',
    'SYMLINK_NOT_ALLOWED': 'A required authorization path is a symbolic link; it was not followed.',
    'PATH_NOT_DIRECTORY': 'A required home/SSH directory is not a directory.',
    'PATH_NOT_REGULAR': 'The authorization file is not a regular file.',
    'OWNER_MISMATCH': 'The authorization path is not owned by the verified SSH account.',
    'GROUP_OR_WORLD_WRITABLE': 'The authorization path permits group or world writes.',
    'METADATA_INVALID': 'Remote ownership, type or size metadata is missing or invalid.',
    'HOME_PATH_INVALID': 'The verified account home is not a supported canonical absolute path.',
    'KEY_FILE_SIZE_INVALID': 'The authorization file size is outside the supported 0..1MiB range.',
    'KEY_FILE_CONTROL_BYTES': 'The authorization file contains unsupported control bytes or line endings.',
    'KEY_FILE_ENCODING_INVALID': 'The authorization file is not valid UTF-8 text.',
    'KEY_FILE_FORMAT_INVALID': 'An authorization line is not a supported SSH public key/options record.',
    'KEY_FILE_AMBIGUOUS_OPTIONS': 'The same public key has conflicting authorization options.',
    'KEY_FILE_CHANGED_DURING_READ': 'Authorization metadata or contents changed during the two-pass read.',
    'KEY_READ_INCOMPLETE': 'The authorization read did not return the advertised file length.',
    'REMOTE_STAT_FAILED': 'SFTP could not read the named authorization path metadata.',
    'REMOTE_READ_FAILED': 'SFTP could not open/read the authorization file reliably.',
    'SFTP_CHANNEL_OPEN_FAILED': 'The authenticated SSH session could not open an SFTP channel.',
    'SFTP_CHANNEL_OPEN_TIMEOUT': 'Opening the SFTP channel exhausted its bounded deadline.',
    'SFTP_CLOSE_FAILED': 'The SFTP channel or file handle did not close reliably.',
    'REMOTE_ACCOUNT_QUERY_FAILED': 'The remote account UID/home query was not complete or consistent.',
}
_ACCESS_ROLES = {'HOME_DIRECTORY','HOME_ANCESTOR','SSH_DIRECTORY','AUTHORIZED_KEYS','SSH_ACCOUNT','SFTP_CHANNEL'}
_ACCESS_PHASES = {'UNSPECIFIED','INITIAL_KEY_PROBE','PASSWORD_ACCOUNT_CHECK','INITIAL_AUTHORIZATION_READ',
    'INITIAL_KEY_IMPORT','KEY_LOGIN_RECHECK','BASELINE_AUTHORIZATION_READ','ACCESS_BACKUP_COMMIT',
    'BEFORE_INSTALL_AUTHORIZATION_READ','POST_REBOOT_AUTHORIZATION_READ'}
_ACCESS_OPERATIONS = {'LSTAT','OPEN_READ','READ','FSTAT','CLOSE','OPEN_SFTP'}


class AccessHold(ValueError):
    def __init__(self, code="AUTHORIZED_KEYS_UNSAFE", *, check_code='ACCESS_CHECK_UNCLASSIFIED',
                 role=None, operation=None, native_errno=None, metadata=None, expected_uid=None,
                 line_number=None):
        super().__init__("SSH access preservation requires review")
        self.reason_code = code
        self.phase = 'UNSPECIFIED'
        self._diagnostic = dict(check_code=check_code if check_code in ACCESS_CHECK_HINTS else 'ACCESS_CHECK_UNCLASSIFIED')
        if role in _ACCESS_ROLES: self._diagnostic['role']=role
        if operation in _ACCESS_OPERATIONS: self._diagnostic['operation']=operation
        if native_errno in set(errno.errorcode.values())|{'UNKNOWN'}: self._diagnostic['native_errno']=native_errno
        if type(expected_uid) is int and expected_uid >= 0: self._diagnostic['expected_uid']=expected_uid
        if type(line_number) is int and line_number > 0: self._diagnostic['line_number']=line_number
        if metadata is not None:
            mode,uid,size=(getattr(metadata,name,None) for name in ('st_mode','st_uid','st_size'))
            if type(mode) is int and mode >= 0: self._diagnostic['mode']=format(stat.S_IMODE(mode),'04o')
            if type(uid) is int and uid >= 0: self._diagnostic['owner_uid']=uid
            if type(size) is int and size >= 0: self._diagnostic['size_bytes']=size

    @property
    def diagnostic(self):
        return dict(self._diagnostic,phase=self.phase if self.phase in _ACCESS_PHASES else 'UNSPECIFIED')


def access_failure_detail(error):
    """Finite codes/metadata only: never native exceptions, account text or keys."""
    if not isinstance(error,AccessHold): return None
    info=error.diagnostic
    fields=['check='+info['check_code'],'phase='+info['phase']]
    fields += [key+'='+str(info[key]) for key in ('role','operation','mode','owner_uid','expected_uid',
        'size_bytes','line_number','native_errno') if key in info]
    return ACCESS_CHECK_HINTS[info['check_code']]+' '+', '.join(fields)


def _remote_read_failure(operation,role,error):
    if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS):
        raise error
    return AccessHold('AUTHORIZED_KEYS_READ_FAILED',check_code='REMOTE_STAT_FAILED' if operation=='LSTAT' else
        'REMOTE_READ_FAILED',role=role,operation=operation,native_errno=errno.errorcode.get(getattr(error,'errno',None),'UNKNOWN'))


def _key_lines(payload):
    if type(payload) is not bytes or len(payload) > LIMIT:
        raise AccessHold(check_code='KEY_FILE_SIZE_INVALID',role='AUTHORIZED_KEYS')
    if b'\x00' in payload or b'\r' in payload:
        raise AccessHold(check_code='KEY_FILE_CONTROL_BYTES',role='AUTHORIZED_KEYS')
    result = {}
    try:
        for number,raw in enumerate(payload.decode('utf-8').splitlines(),1):
            if not raw.strip() or raw.lstrip().startswith('#'):
                continue
            words = shlex.split(raw)
            positions = [i for i, value in enumerate(words) if value.startswith(('ssh-', 'ecdsa-', 'sk-'))]
            if not positions or positions[0] not in (0, 1):
                raise AccessHold(check_code='KEY_FILE_FORMAT_INVALID',role='AUTHORIZED_KEYS',line_number=number)
            i = positions[0]
            algorithm, blob = public_key_identity_bytes((' '.join(words[i:i+2])+'\n').encode())
            fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b'=').decode()
            authorization = tuple(words[:i]) + (algorithm.decode(), base64.b64encode(blob).decode())
            if fingerprint in result and result[fingerprint][0] != authorization:
                raise AccessHold(check_code='KEY_FILE_AMBIGUOUS_OPTIONS',role='AUTHORIZED_KEYS',line_number=number)
            result.setdefault(fingerprint, (authorization, raw.encode()+b'\n'))
    except AccessHold: raise
    except UnicodeError:
        raise AccessHold(check_code='KEY_FILE_ENCODING_INVALID',role='AUTHORIZED_KEYS') from None
    except (ValueError, IndexError):
        raise AccessHold(check_code='KEY_FILE_FORMAT_INVALID',role='AUTHORIZED_KEYS',line_number=number) from None
    return result


def merge_authorized_keys(before, current):
    """Union only missing identities; never remove new keys or weaken options."""
    old, new = _key_lines(before), _key_lines(current)
    if not old:
        raise AccessHold()
    for key in old.keys() & new.keys():
        if old[key][0] != new[key][0]:
            raise AccessHold('AUTHORIZED_KEYS_OPTIONS_CHANGED')
    if not current:
        return before
    missing = [line for key, (_auth, line) in old.items() if key not in new]
    return current + (b'\n' if missing and not current.endswith(b'\n') else b'') + b''.join(missing)


def _metadata(item, uid, *, directory=False, role='AUTHORIZED_KEYS'):
    mode,owner,size=(getattr(item,name,None) for name in ('st_mode','st_uid','st_size'))
    code=None
    if any(type(value) is not int for value in (mode,owner,size)) or min(mode,owner,size)<0: code='METADATA_INVALID'
    elif stat.S_ISLNK(mode): code='SYMLINK_NOT_ALLOWED'
    elif not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)): code='PATH_NOT_DIRECTORY' if directory else 'PATH_NOT_REGULAR'
    elif owner!=uid: code='OWNER_MISMATCH'
    elif mode & 0o022: code='GROUP_OR_WORLD_WRITABLE'
    elif not directory and size>LIMIT: code='KEY_FILE_SIZE_INVALID'
    if code: raise AccessHold(check_code=code,role=role,metadata=item,expected_uid=uid)
    return item.st_mode, item.st_uid, item.st_size


def _home_check(sftp, home, uid):
    if (not home.startswith('/') or home == '/' or str(PurePosixPath(home)) != home
            or '..' in PurePosixPath(home).parts or home.startswith(('/tmp/', '/var/tmp/'))):
        raise AccessHold(check_code='HOME_PATH_INVALID',role='HOME_DIRECTORY')
    path = '/'
    for part in PurePosixPath(home).parts[1:]:
        path = posixpath.join(path, part)
        role='HOME_DIRECTORY' if path==home else 'HOME_ANCESTOR'
        try: item = sftp.lstat(path)
        except (OSError,EOFError) as error: raise _remote_read_failure('LSTAT',role,error) from None
        _metadata(item,uid if path==home else getattr(item,'st_uid',None),directory=True,role=role)


def _read_keys(sftp, home, uid):
    _home_check(sftp, home, uid)
    directory = posixpath.join(home, '.ssh')
    try:
        item = sftp.lstat(directory)
    except FileNotFoundError:
        return b'', False
    except (OSError,EOFError) as error: raise _remote_read_failure('LSTAT','SSH_DIRECTORY',error) from None
    _metadata(item, uid, directory=True,role='SSH_DIRECTORY')
    path = posixpath.join(directory, 'authorized_keys')
    try:
        named = sftp.lstat(path)
    except FileNotFoundError:
        return b'', True
    except (OSError,EOFError) as error: raise _remote_read_failure('LSTAT','AUTHORIZED_KEYS',error) from None
    initial = _metadata(named, uid)
    captures = []
    for _ in range(2):
        try: handle = sftp.open(path, 'rb')
        except (OSError,EOFError) as error: raise _remote_read_failure('OPEN_READ','AUTHORIZED_KEYS',error) from None
        operation='FSTAT'
        try:
            if _metadata(handle.stat(), uid) != initial:
                raise AccessHold(check_code='KEY_FILE_CHANGED_DURING_READ',role='AUTHORIZED_KEYS')
            operation='READ'
            payload = handle.read(LIMIT+1)
            if type(payload) is not bytes or len(payload) != initial[2]:
                raise AccessHold(check_code='KEY_READ_INCOMPLETE',role='AUTHORIZED_KEYS')
            operation='FSTAT'
            if _metadata(handle.stat(), uid) != initial:
                raise AccessHold(check_code='KEY_FILE_CHANGED_DURING_READ',role='AUTHORIZED_KEYS')
            captures.append(payload)
        except (OSError,EOFError) as error: raise _remote_read_failure(operation,'AUTHORIZED_KEYS',error) from None
        finally:
            original=sys.exc_info()[1]
            try: handle.close()
            except Exception as cleanup:
                if isinstance(cleanup,OSError) and cleanup.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS): raise
                if original is None: raise AccessHold('AUTHORIZED_KEYS_READ_FAILED',check_code='SFTP_CLOSE_FAILED',role='AUTHORIZED_KEYS',operation='CLOSE') from None
        try: fresh=sftp.lstat(path)
        except (OSError,EOFError) as error: raise _remote_read_failure('LSTAT','AUTHORIZED_KEYS',error) from None
        if _metadata(fresh, uid) != initial:
            raise AccessHold(check_code='KEY_FILE_CHANGED_DURING_READ',role='AUTHORIZED_KEYS')
    if captures[0] != captures[1]:
        raise AccessHold(check_code='KEY_FILE_CHANGED_DURING_READ',role='AUTHORIZED_KEYS')
    _key_lines(captures[0])
    return captures[0], True


def _account(leaf, transport, deadline):
    from ibsw_upgrade_observer import _read_channel
    raw, err, rc, complete = _read_channel(leaf, transport, ACCOUNT_COMMAND, deadline)
    try:
        lines = raw.decode('utf-8').splitlines()
        fields = lines[1].split(':')
        uid = int(lines[0])
        if (rc != 0 or err or not complete or len(lines) != 2 or len(fields) != 7
                or fields[0] != leaf.user or int(fields[2]) != uid):
            raise ValueError()
        return uid, fields[5]
    except (ValueError, IndexError, UnicodeError):
        raise AccessHold(check_code='REMOTE_ACCOUNT_QUERY_FAILED',role='SSH_ACCOUNT') from None


def _directory(leaf, *, create=False, recovery=False):
    scope = leaf.scope
    node = scope.run_directory / leaf.node.hostname
    directory = node / 'ssh-access'
    paths = (node, directory) if create else ()
    for path in paths:
        parent = scope.session._directory(path.parent)
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent.fd)
            os.fsync(parent.fd)
        except FileExistsError:
            pass
        scope._private_directory(scope.session._directory(path))
    if recovery:
        parent = scope.session._directory(directory)
        name = 'recovery-'+secrets.token_hex(16)
        os.mkdir(name, 0o700, dir_fd=parent.fd)
        os.fsync(parent.fd)
        directory /= name
    opened = scope.session._directory(directory)
    scope._private_directory(opened)
    return opened


def _binding(leaf, uid, home, payload):
    return dict(schema_version=1, run_id=leaf.scope.run_id, plan_sha256=leaf.scope.plan_sha256,
        hostname=leaf.node.hostname, address=leaf.node.address, mac=leaf.node.mac, user=leaf.user,
        uid=uid, home=home, management_key=leaf.management_public,
        authorized_keys_sha256=hashlib.sha256(payload).hexdigest())


def _backup(leaf):
    from ibsw_upgrade_driver import _json_bytes
    try:
        directory = _directory(leaf)
        payload = leaf.scope._hold(directory, 'authorized_keys.before').payload
        document = json.loads(leaf.scope._hold(directory, 'access-backup.json').payload)
        if _json_bytes(document) != _json_bytes(_binding(leaf, document['uid'], document['home'], payload)):
            raise ValueError()
        if leaf.management_public not in _key_lines(payload):
            raise ValueError()
        return document, payload
    except Exception as error:
        raise SharedUpgradeHold('SSH access backup is missing, changed or belongs to another target') from error


def _sftp(transport, deadline):
    from ibsw_upgrade_observer import _fixed_sdk, _remaining, _owned_phase
    sftp, expired = None, None
    try:
        with _owned_phase((transport,),min(deadline,time.monotonic()+25.0)) as expired:
            sftp = _fixed_sdk().SFTPClient.from_transport(transport)
        sftp.get_channel().settimeout(min(25.0, _remaining(deadline)))
        return sftp
    except SharedUpgradeHold:
        raise
    except Exception as error:
        if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS): raise
        if sftp is not None:
            _close_sftp(sftp,'AUTHORIZED_KEYS_READ_FAILED')
        raise AccessHold('AUTHORIZED_KEYS_READ_FAILED',check_code='SFTP_CHANNEL_OPEN_TIMEOUT' if
            (expired is not None and expired.is_set()) or getattr(error,'reason_code',None)=='READONLY_DEADLINE_EXCEEDED' else 'SFTP_CHANNEL_OPEN_FAILED',
            role='SFTP_CHANNEL',operation='OPEN_SFTP') from None


def _close_sftp(sftp, code):
    original = sys.exc_info()[1]
    try:
        sftp.close()
    except BaseException as cleanup:
        if not isinstance(cleanup, Exception):
            raise
        if original is not None and not isinstance(original,Exception): return
        if isinstance(cleanup,OSError) and cleanup.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS): raise
        if original is not None:
            return  # Preserve the original stop, especially a SharedUpgradeHold.
        raise AccessHold(code,check_code='SFTP_CLOSE_FAILED',role='SFTP_CHANNEL',operation='CLOSE') from None


def prepare_upgrade_access(leaf, password):
    try: return _prepare_upgrade_access(leaf,password)
    except AccessHold as error:
        error.phase=getattr(leaf,'_access_diagnostic_phase','UNSPECIFIED')
        raise


def _prepare_upgrade_access(leaf, password):
    """Ensure both logins work; import missing management key before baseline."""
    from ibsw_upgrade_observer import _signed_session, _NativeObservationHold, _progress
    from ibsw_upgrade_driver import _json_bytes
    if not password or leaf._identity is None:
        raise AccessHold('UPGRADE_DUAL_AUTH_REQUIRED')
    leaf._native_observation_consumed = True
    _progress(leaf, 'ACCESS', 'ACCESS_PREFLIGHT')
    leaf._access_diagnostic_phase='INITIAL_KEY_PROBE'
    try:
        with _signed_session(leaf, _authentication='key') as (_t, _d, _i, _a, _p):
            pass
    except _NativeObservationHold as error:
        if error.reason_code != 'SSH_AUTHENTICATION_REJECTED':
            raise
        _progress(leaf, 'ACCESS', 'INITIAL_KEY_PASSWORD_FALLBACK')
    bootstrap = None
    try:
        with _signed_session(leaf, password=password, _authentication='password') as (transport, deadline, _i, _a, _p):
            leaf._access_diagnostic_phase='PASSWORD_ACCOUNT_CHECK'
            uid, home = _account(leaf, transport, deadline)
            sftp = _sftp(transport, deadline)
            try:
                leaf._access_diagnostic_phase='INITIAL_AUTHORIZATION_READ'
                try:
                    payload, ssh_exists = _read_keys(sftp, home, uid)
                except (OSError, EOFError) as error:
                    raise _remote_read_failure('READ','AUTHORIZED_KEYS',error) from None
                if leaf.management_public not in _key_lines(payload):
                    public_source = leaf._original_selection[5]
                    public_source.verify()
                    manager = _key_lines(public_source.payload)
                    if set(manager) != {leaf.management_public}:
                        raise AccessHold('AUTHORIZED_KEYS_MANAGEMENT_KEY_MISSING')
                    desired = merge_authorized_keys(manager[leaf.management_public][1], payload)
                    try:
                        with leaf.scope._request_namespace_lease():
                            _directory(leaf, create=True)
                            bootstrap = _directory(leaf, recovery=True)
                            record = dict(state='MANAGEMENT_KEY_IMPORT_REQUESTED',
                                binding=_binding(leaf, uid, home, payload),
                                original_base64=base64.b64encode(payload).decode(),
                                desired_sha256=hashlib.sha256(desired).hexdigest())
                            leaf.scope._commit_exclusive_binding(bootstrap, _json_bytes(record), 'access-bootstrap.json')
                    except Exception as error:
                        raise SharedUpgradeHold('Initial authorization evidence could not be saved; no key imported') from error
                    _progress(leaf, 'ACCESS', 'MANAGEMENT_KEY_IMPORTING')
                    leaf._access_diagnostic_phase='INITIAL_KEY_IMPORT'
                    _replace_keys(sftp, home, uid, payload, desired, ssh_exists,
                                  failure='MANAGEMENT_KEY_IMPORT_FAILED')
                    payload = desired
            finally:
                _close_sftp(sftp, 'AUTHORIZED_KEYS_READ_FAILED')
    except _NativeObservationHold as error:
        if error.reason_code == 'SSH_AUTHENTICATION_REJECTED':
            raise AccessHold('PASSWORD_PREFLIGHT_REJECTED') from None
        raise
    # A password session and file readback are not proof of key access. Also
    # check an already-present key without appending an unrestricted duplicate.
    try:
        leaf._access_diagnostic_phase='KEY_LOGIN_RECHECK'
        with _signed_session(leaf, _authentication='key') as (transport, deadline, _i, _a, _p):
            verified_uid, verified_home = _account(leaf, transport, deadline)
            if (uid, home) != (verified_uid, verified_home):
                raise AccessHold('AUTHORIZED_KEYS_ACCOUNT_CHANGED')
            sftp = _sftp(transport, deadline)
            try:
                leaf._access_diagnostic_phase='BASELINE_AUTHORIZATION_READ'
                actual, _exists = _read_keys(sftp, home, uid)
                if actual != payload:
                    raise AccessHold('AUTHORIZED_KEYS_CHANGED_DURING_RECOVERY')
            finally:
                _close_sftp(sftp, 'AUTHORIZED_KEYS_READ_FAILED')
    except BaseException as error:
        if bootstrap is not None:
            _record_bootstrap(leaf, bootstrap, verified=False)
        if isinstance(error, _NativeObservationHold) and error.reason_code == 'SSH_AUTHENTICATION_REJECTED':
            raise AccessHold('KEY_PREFLIGHT_RECHECK_FAILED') from None
        raise
    if bootstrap is not None:
        _record_bootstrap(leaf, bootstrap, verified=True)
        _progress(leaf, 'ACCESS', 'MANAGEMENT_KEY_IMPORTED')
    try:
        leaf._access_diagnostic_phase='ACCESS_BACKUP_COMMIT'
        with leaf.scope._request_namespace_lease():
            directory = _directory(leaf, create=True)
            leaf.scope._commit_exclusive_binding(directory, payload, 'authorized_keys.before')
            leaf.scope._commit_exclusive_binding(directory, _json_bytes(_binding(leaf, uid, home, payload)), 'access-backup.json')
            _backup(leaf)
    except Exception as error:
        raise SharedUpgradeHold('SSH access backup could not be saved reliably; no upgrade dispatched') from error
    _progress(leaf, 'ACCESS', 'ACCESS_BACKUP_SAVED')


def _record_bootstrap(leaf, directory, *, verified):
    from ibsw_upgrade_driver import _json_bytes
    try:
        with leaf.scope._request_namespace_lease():
            leaf.scope._commit_exclusive_binding(directory, _json_bytes(dict(
                state='MANAGEMENT_KEY_IMPORT_VERIFIED' if verified else 'MANAGEMENT_KEY_IMPORT_UNVERIFIED',
                hostname=leaf.node.hostname, management_key=leaf.management_public)), 'access-bootstrap-result.json')
    except Exception as error:
        raise SharedUpgradeHold('Initial authorization result could not be saved reliably') from error


def _replace_keys(sftp, home, uid, current, desired, ssh_exists, *, failure):
    """Common atomic missing-only write, after caller has saved its preimage."""
    try:
        target_dir = posixpath.join(home, '.ssh')
        if not ssh_exists:
            sftp.mkdir(target_dir, 0o700)
            sftp.chmod(target_dir, 0o700)
        _metadata(sftp.lstat(target_dir), uid, directory=True)
        path = posixpath.join(target_dir, 'authorized_keys')
        temporary = posixpath.join(target_dir, '.authorized_keys-ibsw-'+secrets.token_hex(16))
        handle = sftp.open(temporary, 'w+x')
        try:
            sftp.chmod(temporary, 0o600)
            handle.write(desired)
            handle.flush()
            handle.seek(0)
            if handle.read(LIMIT+1) != desired:
                raise AccessHold(failure)
            _metadata(handle.stat(), uid)
        finally:
            handle.close()
        fresh, _exists = _read_keys(sftp, home, uid)
        if fresh != current:
            raise AccessHold('AUTHORIZED_KEYS_CHANGED_DURING_RECOVERY')
        try:
            sftp.lstat(path)
        except FileNotFoundError:
            sftp.rename(temporary, path)
        else:
            sftp.posix_rename(temporary, path)
        actual, _exists = _read_keys(sftp, home, uid)
        if actual != desired:
            raise AccessHold(failure)
    except (AccessHold, SharedUpgradeHold):
        raise
    except Exception:
        raise AccessHold(failure) from None


def verify_access_before_write(leaf, transport, deadline):
    try: return _verify_access_before_write(leaf,transport,deadline)
    except AccessHold as error:
        error.phase='BEFORE_INSTALL_AUTHORIZATION_READ'
        raise


def _verify_access_before_write(leaf, transport, deadline):
    """Retain the pre-upgrade original; reject drift rather than rebase backup."""
    document, original = _backup(leaf)
    uid, home = _account(leaf, transport, deadline)
    if (uid, home) != (document['uid'], document['home']):
        raise AccessHold('AUTHORIZED_KEYS_ACCOUNT_CHANGED')
    sftp = _sftp(transport, deadline)
    try:
        current, _exists = _read_keys(sftp, home, uid)
    finally:
        _close_sftp(sftp, 'AUTHORIZED_KEYS_READ_FAILED')
    # Additions after an earlier component recovery are safe; changes/removals
    # before a new installer must not be silently treated as a fresh baseline.
    if merge_authorized_keys(original, current) != current:
        raise AccessHold('AUTHORIZED_KEYS_CHANGED_BEFORE_UPGRADE')


def restore_access(leaf, transport, deadline):
    try: return _restore_access(leaf,transport,deadline)
    except AccessHold as error:
        error.phase='POST_REBOOT_AUTHORIZATION_READ'
        raise


def _restore_access(leaf, transport, deadline):
    """Password session is already identity-verified. No shell or key upload."""
    from ibsw_upgrade_observer import _progress
    from ibsw_upgrade_driver import _json_bytes
    document, original = _backup(leaf)
    uid, home = _account(leaf, transport, deadline)
    if (uid, home) != (document['uid'], document['home']):
        raise AccessHold('AUTHORIZED_KEYS_ACCOUNT_CHANGED')
    sftp = _sftp(transport, deadline)
    try:
        current, ssh_exists = _read_keys(sftp, home, uid)
        merged = merge_authorized_keys(original, current)
        if merged == current:
            return None
        with leaf.scope._request_namespace_lease():
            directory = _directory(leaf, recovery=True)
            request = dict(state='RESTORE_REQUESTED', binding=document,
                current_base64=base64.b64encode(current).decode(),
                desired_sha256=hashlib.sha256(merged).hexdigest())
            leaf.scope._commit_exclusive_binding(directory, _json_bytes(request), 'access-request.json')
        _progress(leaf, 'ACCESS', 'AUTHORIZED_KEYS_RESTORING')
        _replace_keys(sftp, home, uid, current, merged, ssh_exists,
                      failure='AUTHORIZED_KEYS_RESTORE_FAILED')
        _progress(leaf, 'ACCESS', 'AUTHORIZED_KEYS_RESTORED')
        return directory
    except (AccessHold, SharedUpgradeHold):
        raise
    except Exception:
        raise AccessHold('AUTHORIZED_KEYS_RESTORE_FAILED') from None
    finally:
        _close_sftp(sftp, 'AUTHORIZED_KEYS_RESTORE_FAILED')


def record_key_recheck(leaf, directory, *, verified):
    from ibsw_upgrade_driver import _json_bytes
    try:
        with leaf.scope._request_namespace_lease():
            leaf.scope._commit_exclusive_binding(directory, _json_bytes(dict(
                state='KEY_LOGIN_VERIFIED' if verified else 'KEY_LOGIN_RECHECK_FAILED',
                hostname=leaf.node.hostname, management_key=leaf.management_public)), 'access-result.json')
    except Exception as error:
        raise SharedUpgradeHold('SSH access recovery result could not be recorded reliably') from error
