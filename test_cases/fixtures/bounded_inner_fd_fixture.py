"""NOT RUN. Fixed local command fixture, never an SSH/device executable."""
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def main():
    if os.getuid() != 501:
        raise ValueError("fixed UID501 fixture required")
    if len(sys.argv) != 3 or sys.argv[2] != "normal17":
        raise ValueError("fixed owned normal17 fixture only")
    root = Path(sys.argv[1])
    metadata = root.lstat()
    if not (root.is_absolute() and stat.S_ISDIR(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_uid == os.getuid()):
        raise ValueError("original private fixture root required")
    path = root / "protocol-originals.json"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        held = os.fstat(fd)
        if not (stat.S_ISREG(held.st_mode) and held.st_nlink == 1
                and stat.S_IMODE(held.st_mode) == 0o600
                and held.st_uid == os.getuid() and held.st_size <= 4096):
            raise ValueError("owned bounded protocol evidence required")
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    rows = json.loads(raw.decode("ascii"))
    if (len(rows) != 4 or [r["role"] for r in rows]
            != ["request_read", "request_write", "status_read", "status_write"]
            or len({r["fd"] for r in rows}) != 4
            or any(type(r["fd"]) is not int or r["fd"] < 3 for r in rows)):
        raise ValueError("fixed four original slots required")
    observations = []
    for row in rows:
        try:
            actual = os.fstat(row["fd"])
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
            observations.append({"role": row["role"], "state": "EBADF"})
        else:
            # A reused descriptor number is not proof of a protocol leak or
            # proof that its original pipe was closed. Never close this slot.
            key = [actual.st_dev, actual.st_ino, actual.st_mode,
                   actual.st_uid, actual.st_gid]
            if key == row["identity"]:
                raise AssertionError("original private pipe identity inherited by inner command")
            raise AssertionError("UNKNOWN reused slot; no private-FD isolation claim")
    expected_env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                    "ANCHOR_LOCAL_LITERAL": "owned-normal17",
                    "__CF_USER_TEXT_ENCODING": "0x1F5:0:0"}
    # No values or extra environment names are emitted on mismatch.
    if dict(os.environ) != expected_env:
        raise AssertionError("complete literal inner environment mismatch")
    original_pipe_keys = {(r["identity"][0], r["identity"][1],
                           stat.S_IFMT(r["identity"][2])) for r in rows}
    enumeration = []
    seen = set()
    # The iterator owns its directory FD while entries are inspected. Do not
    # list first then close: that would introduce a stale enumerator slot.
    with os.scandir("/dev/fd") as entries:
        for entry in entries:
            if len(enumeration) >= 128 or not entry.name.isascii() or not entry.name.isdecimal():
                raise AssertionError("UNKNOWN bounded self-FD enumeration")
            number = int(entry.name)
            if number in seen:
                raise AssertionError("UNKNOWN duplicate self-FD entry")
            seen.add(number)
            try:
                first = os.fstat(number)
                second = os.fstat(number)
            except OSError:
                # Even EBADF is UNKNOWN here: a listed FD disappeared. Never
                # drop it and manufacture an exhaustive no-alias receipt.
                raise AssertionError("UNKNOWN disappearing self-FD entry") from None
            key1 = (first.st_dev, first.st_ino, stat.S_IFMT(first.st_mode))
            key2 = (second.st_dev, second.st_ino, stat.S_IFMT(second.st_mode))
            if key1 != key2:
                raise AssertionError("UNKNOWN reused self-FD entry")
            if key1 in original_pipe_keys:
                raise AssertionError("original private pipe alias inherited by inner command")
            enumeration.append({"fd": number, "key": list(key1), "stable": True})
    if not {0, 1, 2} <= seen:
        raise AssertionError("UNKNOWN missing stdio in self-FD enumeration")
    body = {"kind": "OWNED_NORMAL17", "protocol_slots": observations,
            "protocol_evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "complete_literal_env_match": True, "argv_tail": sys.argv[2:],
            "self_fd_enumeration": enumeration, "no_original_pipe_alias": True}
    os.write(1, json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
    os.write(2, b"OWNED-NORMAL17-STDERR\n")
    return 17


if __name__ == "__main__":
    raise SystemExit(main())
