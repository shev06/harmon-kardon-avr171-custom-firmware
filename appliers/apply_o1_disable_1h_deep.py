"""Applies O1 (disable the stock 1-hour sleep->deep timer expiry) on top of Option 4b r3.

One byte: 0x08010a57  d1 -> e0   ('bne 0x08010a80' becomes 'b 0x08010a80' in FUN_0801074c, skipping the block that
sets c038|=0x80, c03c&=0xfd, c2b5=100 when bfd8 reaches 0).  bfd8 has no other reader (only stores of 0xe10 / 0).

Dry run by default.  --apply writes the target after a timestamped backup and post-verifies.
Target: paths.DELIVERABLE (override: AVR_DELIVERABLE=<path>).  Must be exactly r3 (37ba4f65...).
"""
import hashlib
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'harness'))
import paths

TARGET = paths.DELIVERABLE
BASE = 0x08000000
SITE = 0x08010A56
SRC_SHA = '37ba4f65aa35b1a43bc0c8f6b45c5b346d1ed33bd262f543c579c394681f50e6'  # r3
NEW_SHA = '85c78bc916a2'  # prefix of r3+O1 (full value is printed and compared to the 4c builder output)
STOCK, NEW = bytes.fromhex('13d1'), bytes.fromhex('13e0')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main(apply):
    src = open(TARGET, 'rb').read()
    print('target', TARGET, sha(src))
    if sha(src) != SRC_SHA:
        print('ABORT: target is not Option 4b r3 (%s)' % SRC_SHA)
        return 1
    o = SITE - BASE
    if src[o:o + 2] != STOCK:
        print('ABORT: unexpected bytes at the O1 site: %s' % src[o:o + 2].hex())
        return 1
    new = bytearray(src)
    new[o:o + 2] = NEW
    new = bytes(new)
    diff = [hex(BASE + i) for i in range(len(src)) if src[i] != new[i]]
    print('diff:', diff)
    assert diff == [hex(SITE + 1)]
    print('result sha256', sha(new))
    if not sha(new).startswith(NEW_SHA):
        print('ABORT: result does not match the reviewed 4c candidate prefix %s' % NEW_SHA)
        return 1
    if not apply:
        print('DRY RUN complete: nothing written.')
        return 0
    backup = '%s.pre-o1-%d.bak' % (TARGET, int(time.time()))
    shutil.copy2(TARGET, backup)
    assert sha(open(backup, 'rb').read()) == SRC_SHA
    print('backup written:', backup)
    open(TARGET, 'wb').write(new)
    assert sha(open(TARGET, 'rb').read()) == sha(new)
    print('post-write verification OK; new sha256', sha(new))
    return 0


if __name__ == '__main__':
    sys.exit(main('--apply' in sys.argv))
