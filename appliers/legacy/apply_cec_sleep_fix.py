"""Applies the 'CEC standby == button/network power-off' fix to the real deliverable.

Dry run by default (all checks, no write).  Pass --apply to write.

Edits (all guarded, built by /tmp/avrwork/build_candidate.py):
  1. restore the 3 `bl FUN_08019638` call sites that patch #4 had redirected to a no-op trampoline
  2. FUN_0802d230 case 4 (CEC Standby / power off) and case 0x20 (power toggle) "Zone 2 off" blocks:
     replace the deep-power-down marker + 2b5 countdown with a plain `bl FUN_080192e2` (button/network flow)
  3. reset the now-unreferenced 28-byte no-op trampoline at 0x080c8a1a to erased flash (0xFF)
"""
import hashlib
import os
import shutil
import struct
import sys
import time

sys.path.insert(0, '/tmp/avrwork')
import build_candidate as bc

TARGET = "/Users/allisonbulner/AVR1710_USB(V002_23)_patched.fw"
PRISTINE = bc.PRISTINE_PATH
CANDIDATE = '/tmp/avrwork/candidate.fw'
BASE = 0x08000000
SIZE = 6291456
EXPECT_SRC_SHA = 'a39f47f29a43eb4124abe20031fc5f09a12728c3ef9bd25ec7d01dfb2d94898e'
EXPECT_NEW_SHA = '629cd9a756c4d74069682ad0302f2b865495e00bf29ccd5a72d6dc7f96c0c66f'

# every byte that may differ from the pristine firmware (inclusive ranges)
ALLOWED = [
    (0x0802d302, 0x0802d329),  # FUN_0802d230 case 4 block   (this fix)
    (0x0802d39a, 0x0802d3c1),  # FUN_0802d230 case 0x20 block (this fix)
    (0x08044e24, 0x08044e29),  # query-status fix
    (0x0804ae70, 0x0804ae73),  # volume/mute call-site redirect
    (0x0804ae8e, 0x0804ae91),  # volume/mute call-site redirect
    (0x08064e0e, 0x08064e12),  # WFI -> NOP (STOP-mode sleep disable)
    (0x0809b44a, 0x0809b44c),  # CEC additive power-off (FUN_0809b3fc)
    (0x0809b4bc, 0x0809b4bf),  # CEC Active Source length fix
    (0x080c4c7e, 0x080c4c7e),  # version byte
    (0x080c89b4, 0x080c8a19),  # code cave (trampolines/handlers)
    (0x080c8a38, 0x080c8d57),  # code cave (volume/mute handlers)
]
DEAD_TRAMP = (0x080c8a1a, 0x080c8a35)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def thumb_branch_targets(data, lo=BASE, hi=BASE + 0x00c9000):
    """All BL / B.W 32-bit targets plus 16-bit B / Bcc targets, as {target: [src,...]}."""
    out = {}
    for a in range(lo, hi, 2):
        o = a - BASE
        h1, h2 = struct.unpack('<HH', data[o:o + 4])
        if (h1 & 0xF800) == 0xF000 and (h2 & 0xD000) in (0xD000, 0x9000):
            s = (h1 >> 10) & 1
            j1 = (h2 >> 13) & 1
            j2 = (h2 >> 11) & 1
            i1 = (~(j1 ^ s)) & 1
            i2 = (~(j2 ^ s)) & 1
            imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1)
            if s:
                imm -= 1 << 25
            out.setdefault(a + 4 + imm, []).append(a)
        if (h1 & 0xF800) == 0xE000:  # 16-bit B
            imm = (h1 & 0x7FF) << 1
            if imm & 0x800:
                imm -= 0x1000
            out.setdefault(a + 4 + imm, []).append(a)
        if (h1 & 0xF000) == 0xD000 and (h1 & 0x0F00) < 0x0E00:  # 16-bit Bcc
            imm = (h1 & 0xFF) << 1
            if imm & 0x100:
                imm -= 0x200
            out.setdefault(a + 4 + imm, []).append(a)
    return out


def main(apply):
    src = open(TARGET, 'rb').read()
    pristine = open(PRISTINE, 'rb').read()
    print('target   sha256 %s (%d B)' % (sha(src), len(src)))
    print('pristine sha256 %s (%d B)' % (sha(pristine), len(pristine)))
    assert len(src) == len(pristine) == SIZE, 'unexpected image size'
    if sha(src) != EXPECT_SRC_SHA:
        print('ABORT: target is not the expected pre-fix deliverable (patch #4 + volmute). Not writing.')
        return 1

    new = bc.build(src)
    assert len(new) == SIZE
    print('built    sha256 %s' % sha(new))
    if sha(new) != EXPECT_NEW_SHA:
        print('ABORT: built image differs from the reviewed/emulated candidate.')
        return 1
    if os.path.exists(CANDIDATE):
        assert open(CANDIDATE, 'rb').read() == new, 'built image != candidate.fw'

    # independent diff accounting vs pristine
    bad = [BASE + i for i in range(SIZE)
           if new[i] != pristine[i] and not any(lo <= BASE + i <= hi for lo, hi in ALLOWED)]
    if bad:
        print('ABORT: %d byte(s) differ from pristine outside the allowed ranges, first: %s'
              % (len(bad), [hex(x) for x in bad[:8]]))
        return 1
    for lo, hi in ALLOWED:
        if all(new[a - BASE] == pristine[a - BASE] for a in range(lo, hi + 1)):
            print('ABORT: allowed range %08x..%08x is identical to pristine (patch missing)' % (lo, hi))
            return 1
    print('diff accounting OK: %d changed bytes, all inside %d allowed ranges'
          % (sum(1 for i in range(SIZE) if new[i] != pristine[i]), len(ALLOWED)))

    # the old no-op trampoline must now be erased flash and unreferenced
    t0, t1 = DEAD_TRAMP
    assert new[t0 - BASE:t1 - BASE + 1] == b'\xff' * (t1 - t0 + 1)
    assert pristine[t0 - BASE:t1 - BASE + 1] == b'\xff' * (t1 - t0 + 1)
    tg = thumb_branch_targets(new)
    refs = [(t, s) for t, srcs in tg.items() if t0 <= t <= t1 for s in srcs]
    words = [BASE + o for o in range(0, SIZE - 3, 2)
             if t0 <= struct.unpack('<I', new[o:o + 4])[0] <= t1 + 1]
    print('branches into %08x..%08x: %s' % (t0, t1, [(hex(t), hex(s)) for t, s in refs]))
    print('literal words into that range: %s' % [hex(w) for w in words])
    if refs or words:
        print('ABORT: something still references the erased trampoline.')
        return 1

    # the 3 restored sites + 2 new calls must target the right functions
    tg_new = thumb_branch_targets(new)
    for a in (0x08019294, 0x0801930e, 0x08019348):
        assert a in tg_new.get(0x08019638, []), 'site %08x does not call FUN_08019638' % a
    for a in (0x0802d302, 0x0802d39a):
        assert a in tg_new.get(0x080192e2, []), 'site %08x does not call FUN_080192e2' % a
    for a in (0x0802d32a, 0x0802d3c2):  # preserved branches after each block
        assert new[a - BASE:a - BASE + 2] == pristine[a - BASE:a - BASE + 2], 'branch at %08x changed' % a
    print('call-site checks OK')

    if not apply:
        print('DRY RUN complete: nothing written.')
        return 0

    backup = '%s.pre-cec-sleep-fix-%d.bak' % (TARGET, int(time.time()))
    shutil.copy2(TARGET, backup)
    assert sha(open(backup, 'rb').read()) == EXPECT_SRC_SHA
    print('backup written: %s' % backup)

    tmp = TARGET + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(new)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, TARGET)

    verify = open(TARGET, 'rb').read()
    assert len(verify) == SIZE and verify == new, 'post-write verification FAILED'
    print('post-write verification OK')
    print('new sha256: %s' % sha(verify))
    return 0


if __name__ == '__main__':
    sys.exit(main('--apply' in sys.argv))
