"""Disassemble FUN_08012c88 (Auto Power Off, ~1 Hz) with literal-pool annotation, from a given image."""
import sys
import struct
import avrlib as L

path = sys.argv[1] if len(sys.argv) > 1 else L.FW_PATH
data = L.load(path)
start, end = 0x08012c88, 0x08012d7a
for i in L.dis(start, end - start, data):
    note = ''
    if i.mnemonic.startswith('ldr') and '[pc' in i.op_str:
        try:
            imm = i.operands[1].mem.disp
            ea = ((i.address + 4) & ~3) + imm
            note = '   ; [0x%08x] = 0x%08x' % (ea, L.u32(ea, data))
        except Exception:
            pass
    print('%08x  %-8s %s%s' % (i.address, i.mnemonic, i.op_str, note))
