"""TEST DATA child, not a production launcher or SDK/source provider."""
import hashlib
import json
import os
import sys
import time

nonce, mode = sys.argv[1:]
data = {'unicode': '界' * 690000, 'literal': ['A', 7, None, True]}
raw_data = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
digest = hashlib.sha256(raw_data).hexdigest()

def frame(value):
    return (json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')

def write(raw, fd=1):
    while raw:
        size = os.write(fd, raw)
        if size <= 0:
            raise RuntimeError('test_pipe')
        raw = raw[size:]

if mode == 'silent':
    time.sleep(120)
    raise SystemExit(9)
now = time.clock_gettime(time.CLOCK_MONOTONIC)
ready = dict(v=2, nonce=nonce, event='READY', data=data,
             ready_at=now, expires_at=now + 60.0, digest=digest)
if mode == 'future':
    ready['ready_at'] += 120
    ready['expires_at'] += 120
if mode == 'expired':
    ready['ready_at'] -= 120
    ready['expires_at'] -= 120
if mode == 'ready-extra':
    # Large READY uses multiple actual writes; trailing frames share final
    # actual write so no successful early publication is a valid outcome.
    raw = frame(ready)
    write(raw[:-512])
    write(raw[-512:] + frame(dict(v=2, nonce=nonce, event='LIVE', serial=1, digest=digest)))
else:
    write(frame(ready))
write(b'finite synthetic warning\n', 2)
for line in sys.stdin.buffer:
    command = json.loads(line)
    if command.get('command') == 'CLOSE':
        write(frame(dict(v=2, nonce=nonce, event='CLOSED')))
        if mode == 'closed-extra':
            write(frame(dict(v=2, nonce=nonce, event='CLOSED')))
        break
    serial = command['serial']
    if mode == 'delayed-check':
        time.sleep(1.2)  # Genuine delay proves no old one-second deadline.
    if mode == 'stderr-over':
        write(b'W' * 65537, 2)
    if mode == 'partial':
        write(b'{"v":2')
        continue
    write(frame(dict(v=2, nonce=nonce, event='LIVE',
                     serial=serial + (1 if mode == 'wrong-serial' else 0),
                     digest='0' * 64 if mode == 'wrong-digest' else digest)))
