import sys, struct
from avrlib import *
# scan for Thumb-2 BL encodings targeting given addresses
targets = {int(a,16) & ~1 for a in sys.argv[1:]}
res = {t: [] for t in targets}
end = min(len(fw), 0x100000)
i = 0
while i < end - 4:
    h1 = struct.unpack_from('<H', fw, i)[0]
    h2 = struct.unpack_from('<H', fw, i+2)[0]
    if (h1 & 0xF800) == 0xF000 and (h2 & 0xD000) in (0xD000, 0xC000):
        s = (h1 >> 10) & 1
        imm10 = h1 & 0x3FF
        j1 = (h2 >> 13) & 1
        j2 = (h2 >> 11) & 1
        imm11 = h2 & 0x7FF
        i1 = (~(j1 ^ s)) & 1
        i2 = (~(j2 ^ s)) & 1
        imm = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
        if s: imm -= (1 << 25)
        tgt = (BASE + i + 4 + imm) & ~1
        if tgt in targets and (h2 & 0xD000) == 0xD000:
            res[tgt].append(BASE + i)
        i += 4
    else:
        i += 2
for t, l in res.items():
    print('%08x callers(%d): %s' % (t, len(l), ' '.join('%08x' % a for a in l)))
