"""Fast RAM-flag usage scanner for the AVR1710 pristine firmware.

usage: python fastscan.py <ramaddr> [bit]
Classifies every ldr-literal load of the RAM byte into SET/CLEAR/TEST/OTHER with the bit
mask involved, and names the containing Ghidra function (from funcranges.txt).
"""
import sys, re, bisect
import paths
from avrlib import *
_ldr_index = None
_funcs = None


def ldr_index():
    global _ldr_index
    if _ldr_index is not None:
        return _ldr_index
    idx = {}
    n = len(fw)
    for a in range(BASE, BASE + n - 4, 2):
        h = u16(a)
        if (h & 0xF800) == 0x4800:  # ldr Rt,[pc,#imm8*4]
            slot = ((a + 4) & ~3) + (h & 0xFF) * 4
            idx.setdefault(slot, []).append((a, (h >> 8) & 7))
        elif h in (0xF8DF, 0xF85F):  # ldr.w Rt,[pc,#+-imm12]
            h2 = u16(a + 2)
            base = (a + 4) & ~3
            slot = base + (h2 & 0xFFF) if h == 0xF8DF else base - (h2 & 0xFFF)
            idx.setdefault(slot, []).append((a, (h2 >> 12) & 0xF))
    _ldr_index = idx
    return idx


def pool_slots(val):
    pat = struct.pack('<I', val)
    out = []
    i = 0
    while True:
        j = fw.find(pat, i)
        if j < 0:
            break
        if j % 4 == 0:
            out.append(BASE + j)
        i = j + 1
    return out


def loads_of(ramaddr):
    idx = ldr_index()
    sites = []
    for s in pool_slots(ramaddr):
        for (a, reg) in idx.get(s, []):
            sites.append((a, reg))
    sites.sort()
    return sites


def funcs():
    global _funcs
    if _funcs is None:
        rows = []
        for line in open(paths.FUNCRANGES):
            p = line.split()
            if len(p) >= 5 and p[0] == 'FUNC':
                rows.append((int(p[2], 16), int(p[3], 16), int(p[1], 16), p[4]))
        rows.sort()
        _funcs = (rows, [r[0] for r in rows])
    return _funcs


def func_of(addr):
    rows, starts = funcs()
    i = bisect.bisect_right(starts, addr) - 1
    if i >= 0 and rows[i][0] <= addr <= rows[i][1]:
        return '%s' % rows[i][3]
    return '?'


def classify(a, reg):
    """Look at the instructions after the load and describe what is done to the byte."""
    ins = dis(a, 40)
    if not ins:
        return 'OTHER'
    # ins[0] is the ldr (word) of the pointer; next is ldrb rX,[reg]
    seq = ins[1:8]
    desc = []
    val = None
    for i in seq:
        m, o = i.mnemonic, i.op_str
        if m.startswith('ldrb') and ('[r%d]' % reg) in o.replace(' ', ''):
            val = o.split(',')[0].strip()
            continue
        if val is None:
            # store through the pointer (strb rX,[reg]) = plain write
            if m.startswith('strb') and ('[r%d]' % reg) in o.replace(' ', ''):
                desc.append('STORE(const?)')
            break
        mm = re.match(r'(%s), (%s), #(0x[0-9a-f]+|\d+)$' % (val, val), o)
        if m.startswith('orr') and mm:
            desc.append('SET %#04x' % int(mm.group(3), 0))
            break
        if m.startswith('and') and mm:
            desc.append('CLEAR %#04x' % (~int(mm.group(3), 0) & 0xFF))
            break
        m2 = re.match(r'(%s), (%s), #(\d+), #(\d+)$' % (val, val), o)
        if m.startswith('ubfx') and m2:
            desc.append('TEST bit%s w%s' % (m2.group(3), m2.group(4)))
            break
        m3 = re.match(r'(%s), (%s), #(0x[0-9a-f]+|\d+)$' % (val, val), o)
        if m.startswith('lsls') and m3:
            sh = int(m3.group(3), 0)
            desc.append('TEST bit%d' % (7 if sh == 0x18 else 0 if sh == 0x1f else -sh))
            break
        if m.startswith(('bfi', 'bfc')):
            desc.append('BITFIELD %s %s' % (m, o))
            break
        if m.startswith('cmp') or m.startswith('tst'):
            desc.append('CMP %s %s' % (m, o))
            break
        if m.startswith(('sbfx',)):
            desc.append('TEST %s %s' % (m, o))
            break
        if m.startswith(('bl', 'b', 'pop')):
            desc.append('?? %s %s' % (m, o))
            break
    return ', '.join(desc) if desc else 'OTHER'


if __name__ == '__main__':
    ram = int(sys.argv[1], 0)
    bit = int(sys.argv[2], 0) if len(sys.argv) > 2 else None
    sites = loads_of(ram)
    print('RAM %#x: %d load sites' % (ram, len(sites)))
    for a, reg in sites:
        c = classify(a, reg)
        if bit is not None:
            if not re.search(r'(SET|CLEAR) (0x[0-9a-f]+)', c) and ('TEST bit%d' % bit) not in c:
                continue
            m = re.search(r'(SET|CLEAR) (0x[0-9a-f]+)', c)
            if m and not (int(m.group(2), 16) >> bit) & 1:
                continue
        print('%08x r%d %-26s %s' % (a, reg, func_of(a), c))
