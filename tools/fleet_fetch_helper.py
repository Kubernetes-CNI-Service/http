"""Package fetch helper for switch fleet jobs; runs ON the switch (owner 2026-10-23).

Not a standalone entry: a family adapter (tools/ibsw_v2_device.py for IB) starts it with
/usr/bin/python3 -c and
writes one JSON context line to its stdin (the password travels only that way, never
in argv, environment, files or output). It pulls one package into the switch's
directory either over HTTP from the ztp-server or with scp (password only) from the
ztp-server or a peer switch, checks size and sha256, and only then renames the unique
temporary file to the final name. It prints exactly one line:
  IBSW_FETCH_RESULT=<json>   {"ok", "class", "code", "attempts", "bytes", "seconds", "speed"}
class is "source" (the side we pull from), "receiver" (this switch) or "unknown". scp
terminal output is scanned locally for a reason and never reflected: a prompt or
banner could carry a secret.
"""
import errno
import hashlib
import json
import os
import pty
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
MARGIN = 64 * 1024 * 1024
TRANSIENT = {5, 6, 7, 18, 28, 52, 56}
TRANSIENT_HTTP = {408, 429, 500, 502, 503, 504}
SCP_REASONS = (
    (r"Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|No [A-Z0-9-]+ host key is known",
     "source", "SOURCE_HOST_KEY"),
    (r"Permission denied|Too many authentication failures", "source", "SOURCE_AUTH_FAILED"),
    (r"Connection refused|Connection timed out|No route to host|Network is unreachable|Connection closed"
     r"|Connection reset|lost connection", "source", "SOURCE_CONNECT_FAILED"),
    (r"No such file or directory|not a regular file", "source", "SOURCE_FILE_MISSING"),
    (r"No space left on device|Disk quota exceeded", "receiver", "NO_SPACE"),
    (r"unknown option|illegal option", "receiver", "SCP_UNSUPPORTED"),
)


class Failure(Exception):
    def __init__(self, side, code):
        super().__init__(code)
        self.side, self.code = side, code


def finish(ok, side="none", code="OK", attempts=(), size=0, seconds=0.0):
    speed = size / seconds if ok and seconds > 0 else 0.0
    print("IBSW_FETCH_RESULT=" + json.dumps(dict(ok=ok, **{"class": side}, code=code, attempts=list(attempts),
                                                   bytes=size, seconds=round(seconds, 3), speed=round(speed, 1)),
                                              sort_keys=True), flush=True)
    raise SystemExit(0 if ok else 1)


def context():
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise Failure("receiver", "CONTEXT_INVALID")
    try:
        cfg = json.loads(raw.decode("utf-8"))
        if (cfg.get("method") not in ("http", "scp") or not isinstance(cfg.get("dest_dir"), str)
                or not cfg["dest_dir"].startswith("/") or not NAME.fullmatch(cfg.get("name", ""))
                or type(cfg.get("size")) is not int or cfg["size"] <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", cfg.get("sha256", ""))
                or type(cfg.get("timeout")) is not int or not 1 <= cfg["timeout"] <= 7200
                or type(cfg.get("attempts", 4)) is not int or not 1 <= cfg.get("attempts", 4) <= 4
                or type(cfg.get("retry_sleep", 5)) not in (int, float) or not 0 <= cfg.get("retry_sleep", 5) <= 60):
            raise ValueError()
        if cfg["method"] == "http":
            if (not isinstance(cfg.get("url"), str) or not cfg["url"].startswith("http://")
                    or re.search(r"[\x00-\x20\x7f]", cfg["url"])):
                raise ValueError()
        else:
            password = cfg.get("password")
            if (not isinstance(password, str) or not password or len(password.encode()) > 4096
                    or any(ord(c) < 32 or ord(c) == 127 for c in password)
                    or not re.fullmatch(r"[0-9.]{7,15}", cfg.get("host", ""))
                    or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,63}", cfg.get("user", ""))
                    or type(cfg.get("port")) is not int or not 1 <= cfg["port"] <= 65535
                    or not isinstance(cfg.get("host_keys"), str) or not cfg["host_keys"].strip()
                    or not isinstance(cfg.get("path"), str) or not cfg["path"].startswith("/")
                    or re.search(r"[\x00-\x1f\x7f]", cfg["path"])):
                raise ValueError()
    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise Failure("receiver", "CONTEXT_INVALID") from None
    return cfg


def destination(cfg):
    try:
        item = os.lstat(cfg["dest_dir"])
    except OSError:
        raise Failure("receiver", "DESTINATION_UNSAFE") from None
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid() or item.st_mode & 0o022:
        raise Failure("receiver", "DESTINATION_UNSAFE")
    return os.path.join(cfg["dest_dir"], cfg["name"])


def digest(path, deadline):
    value = hashlib.sha256()
    count = 0
    with open(path, "rb") as handle:
        while True:
            if time.monotonic() > deadline:
                raise Failure("unknown", "TIMEOUT")
            block = handle.read(1024 * 1024)
            if not block:
                return count, value.hexdigest()
            count += len(block)
            value.update(block)


def present(final, cfg, deadline):
    try:
        item = os.lstat(final)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or item.st_size != cfg["size"]:
        return False
    return digest(final, deadline) == (cfg["size"], cfg["sha256"])


def http(cfg, temporary, attempts):
    curl = cfg.get("curl", "/usr/bin/curl")
    for attempt in range(1, int(cfg.get("attempts", 4)) + 1):
        started = time.time()
        done = subprocess.run([curl, "-q", "-fsS", "--proto", "=http", "--connect-timeout", "10",
                               "--max-time", str(cfg["timeout"]),
                               "-w", "%{http_code}|%{size_download}|%{time_total}|%{speed_download}",
                               "-o", temporary, cfg["url"]],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        fields = done.stdout.decode("ascii", "replace").strip().split("|")
        code = int(fields[0]) if fields and fields[0].isdigit() else 0
        attempts.append(dict(attempt=attempt, started=int(started), finished=int(time.time()), rc=done.returncode,
                             http=code, bytes=int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0))
        if done.returncode == 0 and code == 200:
            return
        if done.returncode == 23:
            raise Failure("receiver", "WRITE_FAILED")
        transient = done.returncode in TRANSIENT or (done.returncode == 22 and code in TRANSIENT_HTTP)
        if not transient or attempt == int(cfg.get("attempts", 4)):
            raise Failure("source", "HTTP_FAILED" if code else "HTTP_CONNECT_FAILED")
        time.sleep(cfg.get("retry_sleep", 5))


def scp(cfg, temporary, attempts):
    program = cfg.get("scp", "/usr/bin/scp")
    with tempfile.TemporaryDirectory(prefix=".fleet-trust-", dir=cfg["dest_dir"]) as directory:
        trust = os.path.join(directory, "known_hosts")
        with open(trust, "x", encoding="ascii") as handle:
            handle.write(cfg["host_keys"] if cfg["host_keys"].endswith("\n") else cfg["host_keys"] + "\n")
        os.chmod(trust, 0o600)
        command = [program, "-O", "-F", "/dev/null", "-o", "StrictHostKeyChecking=yes",
                   "-o", "UserKnownHostsFile=" + trust, "-o", "GlobalKnownHostsFile=/dev/null",
                   "-o", "UpdateHostKeys=no", "-o", "PubkeyAuthentication=no",
                   "-o", "PreferredAuthentications=password,keyboard-interactive",
                   "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
                   "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", "-P", str(cfg["port"]),
                   cfg["user"] + "@" + cfg["host"] + ":" + shlex.quote(cfg["path"]), temporary]
        started = time.time()
        code, output, timed_out = pty_run(command, cfg["password"], cfg["timeout"])
        attempts.append(dict(attempt=1, started=int(started), finished=int(time.time()), rc=code))
    if code == 0:
        return
    if timed_out:
        raise Failure("unknown", "TIMEOUT")
    text = output.decode("utf-8", "replace")
    for pattern, side, reason in SCP_REASONS:
        if re.search(pattern, text):
            raise Failure(side, reason)
    raise Failure("unknown", "SCP_FAILED")


def pty_run(command, password, timeout):
    """Run under a pty, answer one password prompt, keep the last 4 KiB of output locally."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execv(command[0], command)
        finally:
            os._exit(127)
    deadline, sent, tail, status, timed_out = time.monotonic() + timeout, False, b"", None, False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            ready, _, _ = select.select([fd], [], [], min(0.5, remaining))
            if ready:
                try:
                    data = os.read(fd, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    data = b""
                if data:
                    tail = (tail + data)[-4096:]
                    if re.search(rb"(?i)password[^\n]*:\s*$", tail):
                        if sent:
                            break                       # asked twice: the password was rejected
                        os.write(fd, password.encode() + b"\n")
                        sent = True
                        tail = b""
                    continue
            found, value = os.waitpid(pid, os.WNOHANG)
            if found:
                status = value
                break
        if status is None:
            for signal_number in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(pid, signal_number)
                except ProcessLookupError:
                    break
                until = time.monotonic() + 1
                while time.monotonic() < until:
                    found, value = os.waitpid(pid, os.WNOHANG)
                    if found:
                        status = value
                        break
                    time.sleep(0.05)
                if status is not None:
                    break
            if status is None:
                _, status = os.waitpid(pid, 0)
            if not timed_out and sent:
                tail += b"\nPermission denied"
            return (124 if timed_out else 1), tail, timed_out
        return (os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)), tail, False
    finally:
        os.close(fd)


def main():
    started, attempts, temporary = time.monotonic(), [], None
    try:
        cfg = context()
        final = destination(cfg)
        deadline = started + cfg["timeout"] * max(1, int(cfg.get("attempts", 1))) + 600
        if present(final, cfg, deadline):
            finish(True, code="ALREADY_PRESENT", size=cfg["size"], seconds=time.monotonic() - started)
        space = os.statvfs(cfg["dest_dir"])
        if space.f_bavail * space.f_frsize < cfg["size"] + MARGIN:
            raise Failure("receiver", "NO_SPACE")
        handle, temporary = tempfile.mkstemp(prefix=".fleet-fetch-", dir=cfg["dest_dir"])
        os.close(handle)
        os.chmod(temporary, 0o600)
        (http if cfg["method"] == "http" else scp)(cfg, temporary, attempts)
        item = os.lstat(temporary)
        if not stat.S_ISREG(item.st_mode) or item.st_size != cfg["size"]:
            raise Failure("source", "SIZE_MISMATCH")
        if digest(temporary, deadline) != (cfg["size"], cfg["sha256"]):
            raise Failure("source", "CONTENT_MISMATCH")
        os.replace(temporary, final)
        temporary = None
        directory = os.open(cfg["dest_dir"], os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        finish(True, attempts=attempts, size=cfg["size"], seconds=time.monotonic() - started)
    except Failure as failure:
        finish(False, failure.side, failure.code, attempts)
    except OSError as error:
        finish(False, "receiver" if error.errno in (errno.ENOSPC, errno.EDQUOT, errno.EACCES, errno.EROFS)
               else "unknown", "LOCAL_" + errno.errorcode.get(error.errno, "ERROR"), attempts)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


if __name__ == "__main__":
    main()
