import struct, sys
from avrlib import fw, BASE
from fastscan import func_of

def bl_targets(limit=0x080C9000):
    out = {}
    for a in range(BASE, limit, 2):
        o = a - BASE
        h1, h2 = struct.unpack('<HH', fw[o:o+4])
        if (h1 & 0xF800) == 0xF000 and (h2 & 0xD000) in (0xD000, 0x9000):
            S = (h1 >> 10) & 1
            imm10 = h1 & 0x3FF
            J1 = (h2 >> 13) & 1
            J2 = (h2 >> 11) & 1
            imm11 = h2 & 0x7FF
            I1 = (~(J1 ^ S)) & 1
            I2 = (~(J2 ^ S)) & 1
            imm = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
            if S:
                imm -= 1 << 25
            tgt = a + 4 + imm
            kind = 'bl' if (h2 & 0x4000) else 'b.w'
            out.setdefault(tgt, []).append((a, kind))
    return out

if __name__ == '__main__':
    t = bl_targets()
    for name in sys.argv[1:]:
        tg = int(name, 16)
        print(hex(tg), func_of(tg))
        for a, k in t.get(tg, []):
            print('    %s from %#x  %s' % (k, a, func_of(a)))
