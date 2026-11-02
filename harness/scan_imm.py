import re, struct, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from avrlib import BASE, FW_PATH
from fastscan import func_of

P = open(FW_PATH, 'rb').read()
md2 = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
md2.detail = False
md2.skipdata = True


def scan(pattern, lo=0x08010000, hi=0x080c6000, skip_pc=True):
    rx = re.compile(pattern)
    out = []
    for i in md2.disasm(P[lo - BASE:hi - BASE], lo):
        if i.mnemonic == '.byte' or i.mnemonic == '.word':
            continue
        if skip_pc and 'pc' in i.op_str and i.mnemonic.startswith('ldr'):
            continue
        if rx.search(i.op_str):
            out.append((i.address, i.mnemonic, i.op_str))
    return out


if __name__ == '__main__':
    pat = sys.argv[1]
    lo = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x08010000
    hi = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x080c6000
    for a, m, o in scan(pat, lo, hi):
        print('%08x %-8s %-28s %s' % (a, m, o, func_of(a)))
