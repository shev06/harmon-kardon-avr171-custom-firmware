"""Applies the Option 4b 'CEC standby == normal reachable sleep' fix to the real deliverable.

Dry run by default (all checks, no write).  Pass --apply to write.

Edits (all guarded, built by harness/build_candidate_4b.py):
  1. restore to stock the 3 `bl FUN_08019638` call sites that patch #4 had redirected to a no-op trampoline, and the
     `bl 0x0808c9c8` hook at 0x0809b44a in FUN_0809b3fc that the old "CEC additive power-off" patch had redirected to a
     cave trampoline (that trampoline skipped the dispatcher's Auto-Power-Off timer reset)
  2. FUN_0802d230 case 4 (CEC Standby / power off) and case 0x20 (power toggle): the stock "Zone 2 off" deep-power-down
     blocks (c038|=0x80; c03c&=0xfd; c2b5=100) become `bl cec_sleep_helper` + NOPs; the `bl FUN_080192e2` sites of the
     "Zone 2 on" branches call the helper too
  3. erase the now-unreferenced 12-byte cave callback trampoline (0x080c8a0e) and 28-byte no-op trampoline (0x080c8a1a)
     (one contiguous 40-byte run, back to 0xFF)
  4. add the 64-byte cec_sleep_helper in the free cave at 0x080c8d58
     (clears any pending c2b5/c2b6 countdown before scheduling exactly one shutdown path)
"""
import hashlib
import os
import shutil
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'harness'))
import build_candidate_4b as bc
import paths

TARGET = paths.DELIVERABLE  # AVR_DELIVERABLE=<path> overrides (e.g. a copy of the baseline for a dry-run replay)
PRISTINE = bc.PRISTINE_PATH
CANDIDATE = paths.build('candidate4b.fw')
BASE = 0x08000000
SIZE = 6291456
EXPECT_SRC_SHA = 'a39f47f29a43eb4124abe20031fc5f09a12728c3ef9bd25ec7d01dfb2d94898e'  # patch #4 + volmute
EXPECT_NEW_SHA = '37ba4f65aa35b1a43bc0c8f6b45c5b346d1ed33bd262f543c579c394681f50e6'  # r3 candidate (countdown-clear fix + callback hook restored)
EXPECT_CHANGED_BYTES = 199  # vs the deliverable

# every byte that may differ from the pristine firmware (inclusive ranges)
ALLOWED = [
    (0x0802d302, 0x0802d329),  # FUN_0802d230 case 4 block        (4b)
    (0x0802d33c, 0x0802d33f),  # FUN_0802d230 case 4 `bl helper`  (4b)
    (0x0802d39a, 0x0802d3c1),  # FUN_0802d230 case 0x20 block     (4b)
    (0x0802d3d4, 0x0802d3d7),  # FUN_0802d230 case 0x20 `bl helper` (4b)
    (0x08044e24, 0x08044e29),  # query-status fix
    (0x0804ae70, 0x0804ae73),  # volume/mute call-site redirect
    (0x0804ae8e, 0x0804ae91),  # volume/mute call-site redirect
    (0x08064e0e, 0x08064e12),  # WFI -> NOP (STOP-mode sleep disable)
    (0x0809b4bc, 0x0809b4bf),  # CEC Active Source length fix
    (0x080c4c7e, 0x080c4c7e),  # version byte
    (0x080c89b4, 0x080c8a0d),  # code cave (query-status handler + CEC Active Source fix); 0x080c8a0e.. is erased again
    (0x080c8a38, 0x080c8d97),  # code cave (volume/mute handlers + the 4b helper at 0x080c8d58..0x080c8d97)
]
DEAD_TRAMP = (0x080c8a0e, 0x080c8a35)  # cave callback trampoline + patch #4 no-op trampoline, both erased
HELPER_CALLERS = [0x0802d302, 0x0802d33c, 0x0802d39a, 0x0802d3d4]
CALLBACK_HOOK = bc.CALLBACK_HOOK  # 0x0809b44a: must be the stock `bl 0x0808c9c8` again


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


def movw_movt_refs(data, t0, t1, lo=BASE, hi=BASE + 0x00c9000, window=12):
    """(movw_addr, movt_addr, value) for MOVW/MOVT pairs (same Rd, within `window` halfwords) that build an address in [t0, t1+1]."""
    movw, movt = [], []
    for a in range(lo, hi, 2):
        o = a - BASE
        h1, h2 = struct.unpack('<HH', data[o:o + 4])
        if (h1 & 0xFBF0) in (0xF240, 0xF2C0) and (h2 & 0x8000) == 0:
            imm16 = ((h1 & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
            (movw if (h1 & 0xFBF0) == 0xF240 else movt).append((a, (h2 >> 8) & 0xF, imm16))
    out = []
    for wa, wrd, wv in movw:
        for ta, trd, tv in movt:
            if trd == wrd and abs(ta - wa) <= 2 * window:
                val = (tv << 16) | wv
                if t0 <= val <= t1 + 1:
                    out.append((wa, ta, val))
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
        assert open(CANDIDATE, 'rb').read() == new, 'built image != candidate4b.fw'

    # diff accounting vs the deliverable: only the builder's ranges, exactly EXPECT_CHANGED_BYTES bytes
    changed = [BASE + i for i in range(SIZE) if new[i] != src[i]]
    outside = [a for a in changed if not any(lo <= a < hi for lo, hi in bc.CHANGED_RANGES)]
    if outside or len(changed) != EXPECT_CHANGED_BYTES:
        print('ABORT: %d changed bytes vs deliverable (expected %d), %d outside builder ranges %s'
              % (len(changed), EXPECT_CHANGED_BYTES, len(outside), [hex(x) for x in outside[:8]]))
        return 1
    print('diff vs deliverable OK: %d changed bytes, all inside the builder ranges' % len(changed))

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
    print('diff vs pristine OK: %d changed bytes, all inside %d allowed ranges'
          % (sum(1 for i in range(SIZE) if new[i] != pristine[i]), len(ALLOWED)))

    # the old cave callback trampoline and the old no-op trampoline must now be erased flash and unreferenced
    t0, t1 = DEAD_TRAMP
    assert new[t0 - BASE:t1 - BASE + 1] == b'\xff' * (t1 - t0 + 1)
    assert pristine[t0 - BASE:t1 - BASE + 1] == b'\xff' * (t1 - t0 + 1)
    tg = thumb_branch_targets(new)
    refs = [(t, s) for t, srcs in tg.items() if t0 <= t <= t1 for s in srcs]
    words = [BASE + o for o in range(0, SIZE - 3, 2)
             if t0 <= struct.unpack('<I', new[o:o + 4])[0] <= t1 + 1]
    print('branches into %08x..%08x: %s' % (t0, t1, [(hex(t), hex(s)) for t, s in refs]))
    print('literal words into that range: %s' % [hex(w) for w in words])
    mm = movw_movt_refs(new, t0, t1)
    # scanner positive control: the Active Source cave builds 0x08099678 with movw r0/movt r0 at 0x080c89fc / 0x080c8a00
    assert [(a, b) for a, b, _ in movw_movt_refs(new, 0x08099678, 0x08099678)] == [(0x080c89fc, 0x080c8a00)], 'MOVW/MOVT scanner self-test failed'
    print('MOVW/MOVT pairs building an address in that range: %s' % [(hex(a), hex(b), hex(v)) for a, b, v in mm])
    if refs or words or mm:
        print('ABORT: something still references the erased trampolines.')
        return 1

    # call-site checks
    for a in (0x08019294, 0x0801930e, 0x08019348):
        assert a in tg.get(0x08019638, []), 'site %08x does not call FUN_08019638' % a
        assert new[a - BASE:a - BASE + 4] == pristine[a - BASE:a - BASE + 4], 'site %08x != stock' % a
    helper_refs = sorted(tg.get(bc.HELPER, []))
    if helper_refs != sorted(HELPER_CALLERS):
        print('ABORT: references to the helper are %s, expected %s'
              % ([hex(x) for x in helper_refs], [hex(x) for x in sorted(HELPER_CALLERS)]))
        return 1
    ho = CALLBACK_HOOK - BASE
    assert new[ho:ho + 4] == pristine[ho:ho + 4] == bytes.fromhex('f1f7bdfa'), 'callback hook is not the stock bytes'
    assert CALLBACK_HOOK in tg.get(0x0808c9c8, []), 'callback hook does not call FUN_0808c9c8'
    for a in (0x0802d32a, 0x0802d3c2):  # preserved branches after each block
        assert new[a - BASE:a - BASE + 2] == pristine[a - BASE:a - BASE + 2], 'branch at %08x changed' % a
    o = bc.HELPER - BASE
    n = len(bc.HELPER_BYTES)
    assert new[o:o + n] == bc.HELPER_BYTES, 'helper bytes differ'
    assert new[o + n:0x080c8dc1 - BASE] == b'\xff' * (0x080c8dc1 - bc.HELPER - n), 'cave after helper is not erased'
    assert 0x0802d33c not in tg.get(0x080192e2, []) and 0x0802d3d4 not in tg.get(0x080192e2, [])
    assert bc.HELPER + bc.HELPER_BL_OFF in tg.get(0x080192e2, []), "helper's own bl FUN_080192e2 missing"
    print('call-site checks OK (3 restored sites, stock callback hook, %d helper callers, helper bytes, erased cave tail)' % len(helper_refs))

    if not apply:
        print('DRY RUN complete: nothing written.')
        return 0

    backup = '%s.pre-cec-sleep-fix-4b-%d.bak' % (TARGET, int(time.time()))
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
