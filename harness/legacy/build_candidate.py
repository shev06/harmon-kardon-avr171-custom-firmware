"""Builds the 'CEC standby == button/network power-off' candidate image.

build(img) takes the current deliverable bytes (patch #4 + volmute) and returns new bytes.
Every edit is guarded by an expected-old-bytes assertion.
"""
import struct, sys
sys.path.insert(0, '/tmp/avrwork')

BASE = 0x08000000
PRISTINE_PATH = '/Users/allisonbulner/AVR1710_USB(V002_23).fw'

FUN_080192E2 = 0x080192E2


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

# (address, expected deliverable bytes, new bytes)
SITES = []

# 1) restore the three `bl FUN_08019638` call sites that patch #4 redirected to the no-op trampoline
for addr, stock, patched in [
    (0x08019294, '00f0d0f9', 'aff0c1fb'),
    (0x0801930e, '00f093f9', 'aff084fb'),
    (0x08019348, '00f076f9', 'aff067fb'),
]:
    SITES.append((addr, bytes.fromhex(patched), bytes.fromhex(stock), 'restore bl FUN_08019638'))

# 2) FUN_0802d230 case 4 (Standby / power-off) and case 0x20 (power toggle, ON path),
#    "gate B (zone 2) clear" block: stock sets the DEEP-power-down marker (c038 bit7), clears c03c bit1 and
#    arms the 2b5 "switched off" countdown.  Replace with a plain `bl FUN_080192e2` (the button/network path).
for start, end, orig_hex in [
    (0x0802d302, 0x0802d32a, None),   # case 4: block ends before the `b 0x0802d356` at 0x0802d32a
    (0x0802d39a, 0x0802d3c2, None),   # case 0x20: block ends before the `b 0x0802d3ee` at 0x0802d3c2
]:
    SITES.append((start, None, None, 'rewrite gate-B-clear block %08x..%08x' % (start, end - 1)))
BLOCKS = [(0x0802d302, 0x0802d32a), (0x0802d39a, 0x0802d3c2)]

# 3) dead patch #4 trampoline (bx lr + NOP padding); old pre-#4 trampoline was 28 bytes at 0x080c8a1a
TRAMP = (0x080C8A1A, bytes.fromhex('7047') + NOP * 13)


def build(img, expect_stock_blocks=True):
    data = bytearray(img)
    n = len(data)
    # (1) call-site restores
    for addr, old, new, why in [s for s in SITES if s[1] is not None]:
        o = addr - BASE
        assert bytes(data[o:o + 4]) == old, 'unexpected bytes at %08x: %s' % (addr, bytes(data[o:o + 4]).hex())
        data[o:o + 4] = new
    # (2) rewrite the two blocks
    pristine = open(PRISTINE_PATH, 'rb').read()
    for start, end in BLOCKS:
        o0, o1 = start - BASE, end - BASE
        assert bytes(data[o0:o1]) == pristine[o0:o1], 'block %08x differs from pristine' % start
        blk = enc_bl(start, FUN_080192E2) + NOP * ((end - start - 4) // 2)
        assert len(blk) == end - start
        data[o0:o1] = blk
    # (3) clear the dead trampoline back to the erased-flash value
    taddr, tbytes = TRAMP
    o = taddr - BASE
    assert bytes(data[o:o + len(tbytes)]) == tbytes, 'unexpected trampoline bytes'
    data[o:o + len(tbytes)] = b'\xff' * len(tbytes)
    assert bytes(pristine[o:o + len(tbytes)]) == b'\xff' * len(tbytes)
    assert len(data) == n
    return bytes(data)


if __name__ == '__main__':
    # self-test: encoder reproduces the stock `bl FUN_080192e2` at 0x0802d33c and 0x0802d3d4
    pristine = open(PRISTINE_PATH, 'rb').read()
    for a in (0x0802d33c, 0x0802d3d4):
        got = enc_bl(a, FUN_080192E2)
        ref = pristine[a - BASE:a - BASE + 4]
        print('%08x enc=%s stock=%s %s' % (a, got.hex(), ref.hex(), 'OK' if got == ref else 'MISMATCH'))
        assert got == ref
    print('encoder self-test passed')
