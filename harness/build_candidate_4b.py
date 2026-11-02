"""Builds the Option 4b 'CEC standby == normal sleep' candidate image.

build(img) takes the current deliverable bytes (patch #4 + volmute) and returns the new bytes.
Every edit is guarded by an expected-old-bytes assertion; no byte outside the listed ranges changes.

Edits (r3):
  1. restore to stock the 3 `bl FUN_08019638` call sites (undo the patch #4 no-op trampoline) AND the
     `bl 0x0808c9c8` hook at 0x0809b44a in FUN_0809b3fc (undo the old "CEC additive power-off" hook, whose cave
     trampoline skipped the dispatcher's Auto-Power-Off timer reset)
  2. FUN_0802d230 case 4 and case 0x20 'zone 2 off' blocks -> `bl cec_sleep_helper` + NOPs
  3. FUN_0802d230 case 4 / 0x20 'zone 2 on' `bl FUN_080192e2` -> `bl cec_sleep_helper`
  4. erase to 0xFF the now-unreferenced cave CEC-callback trampoline (0x080c8a0e..19) and the dead patch #4
     no-op trampoline (0x080c8a1a..35): one contiguous 40-byte erase
  5. add cec_sleep_helper (64 bytes, assembled from cec_sleep_helper.S) in the free cave
"""
import struct, sys
from paths import PRISTINE as PRISTINE_PATH

BASE = 0x08000000

FUN_080192E2 = 0x080192E2
HELPER = 0x080C8D58
# arm-none-eabi-as/ld output of cec_sleep_helper.S linked at 0x080c8d58 (see cec_sleep_helper.S)
HELPER_BYTES = bytes.fromhex(
    '10b50b4c2078800711d50a4c20787f2108402070084c2068084c002121706170'
    '642802d250f7b1fa10bd6420207010bd30c0012038c00120b8bf0120b5c20120')
assert len(HELPER_BYTES) == 64
HELPER_BL_OFF = 0x24


def enc_bl(src, dst):
    off = dst - (src + 4)
    assert off % 2 == 0 and -(1 << 24) <= off < (1 << 24)
    s = (off >> 24) & 1
    i1 = (off >> 23) & 1
    i2 = (off >> 22) & 1
    imm10 = (off >> 12) & 0x3FF
    imm11 = (off >> 1) & 0x7FF
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = 0xD000 | (j1 << 13) | (j2 << 11) | imm11
    return struct.pack('<HH', hw1, hw2)


NOP = bytes.fromhex('00bf')

# the helper's own `bl FUN_080192e2` is at HELPER+HELPER_BL_OFF; the assembler/linker and enc_bl must agree
assert HELPER_BYTES[HELPER_BL_OFF:HELPER_BL_OFF + 4] == enc_bl(HELPER + HELPER_BL_OFF, FUN_080192E2)

# 1) call sites restored to stock: (addr, patched bytes in the deliverable, stock bytes)
RESTORES = [
    (0x08019294, 'aff0c1fb', '00f0d0f9'),  # bl FUN_08019638 (was -> no-op trampoline)
    (0x0801930e, 'aff084fb', '00f093f9'),
    (0x08019348, 'aff067fb', '00f076f9'),
    (0x0809B44A, '2df0e0fa', 'f1f7bdfa'),  # bl 0x0808c9c8 in FUN_0809b3fc (was -> cave trampoline 0x080c8a0e)
]
CALLBACK_HOOK = 0x0809B44A
# 2) blocks that stock fills with "c038|=0x80; c03c&=0xfd; c2b5=100" (deep power-down request)
BLOCKS = [(0x0802D302, 0x0802D32A), (0x0802D39A, 0x0802D3C2)]
# 3) stock `bl FUN_080192e2` sites that now call the helper
BL_SITES = [0x0802D33C, 0x0802D3D4]
# 4) cave CEC-callback trampoline (bl 0x0808c9c8; bl FUN_080192e2; b.w 0x0809b44e), then the dead patch #4 trampoline
#    (bx lr + 13 NOPs); erased flash is 0xff
CB_TRAMP = 0x080C8A0E
TRAMP = (CB_TRAMP, bytes.fromhex('c3f7dbff50f766fcd2f71abd') + bytes.fromhex('7047') + NOP * 13)
assert len(TRAMP[1]) == 40 and TRAMP[0] + 40 == 0x080C8A36

# every byte range this builder may change relative to the deliverable (inclusive start, exclusive end)
CHANGED_RANGES = (
    [(a, a + 4) for a, _, _ in RESTORES]
    + list(BLOCKS)
    + [(a, a + 4) for a in BL_SITES]
    + [(TRAMP[0], TRAMP[0] + len(TRAMP[1]))]
    + [(HELPER, HELPER + len(HELPER_BYTES))]
)


def build(img):
    data = bytearray(img)
    n = len(data)
    pristine = open(PRISTINE_PATH, 'rb').read()
    # (1) call-site restores
    for addr, patched, stock in RESTORES:
        o = addr - BASE
        assert bytes(data[o:o + 4]) == bytes.fromhex(patched), 'unexpected bytes at %08x' % addr
        assert pristine[o:o + 4] == bytes.fromhex(stock)
        data[o:o + 4] = bytes.fromhex(stock)
    # (2) the two deep-request blocks
    for start, end in BLOCKS:
        o0, o1 = start - BASE, end - BASE
        assert bytes(data[o0:o1]) == pristine[o0:o1], 'block %08x differs from pristine' % start
        blk = enc_bl(start, HELPER) + NOP * ((end - start - 4) // 2)
        assert len(blk) == end - start
        data[o0:o1] = blk
    # (3) bl FUN_080192e2 -> bl helper
    for a in BL_SITES:
        o = a - BASE
        assert bytes(data[o:o + 4]) == enc_bl(a, FUN_080192E2), 'unexpected bytes at %08x' % a
        data[o:o + 4] = enc_bl(a, HELPER)
    # (4) both dead cave trampolines back to erased flash
    taddr, tbytes = TRAMP
    o = taddr - BASE
    assert bytes(data[o:o + len(tbytes)]) == tbytes, 'unexpected trampoline bytes'
    assert pristine[o:o + len(tbytes)] == b'\xff' * len(tbytes)
    data[o:o + len(tbytes)] = b'\xff' * len(tbytes)
    # (5) helper in the free cave
    o = HELPER - BASE
    assert bytes(data[o:o + len(HELPER_BYTES)]) == b'\xff' * len(HELPER_BYTES), 'helper area is not erased'
    assert pristine[o:o + len(HELPER_BYTES)] == b'\xff' * len(HELPER_BYTES)
    data[o:o + len(HELPER_BYTES)] = HELPER_BYTES
    assert len(data) == n
    return bytes(data)


if __name__ == '__main__':
    pristine = open(PRISTINE_PATH, 'rb').read()
    for a in (0x0802D33C, 0x0802D3D4):
        got, ref = enc_bl(a, FUN_080192E2), pristine[a - BASE:a - BASE + 4]
        print('%08x enc=%s stock=%s %s' % (a, got.hex(), ref.hex(), 'OK' if got == ref else 'MISMATCH'))
        assert got == ref
    print('encoder self-test passed; helper bl matches assembler output')
