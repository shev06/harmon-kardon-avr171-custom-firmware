import sys
import avrlib

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
md.detail = True


def pool_target(insn):
    # ldr rX, [pc, #imm] (literal load): resolve the literal word
    m = re.match(r'^\[pc(?:, #(-?0x[0-9a-f]+|-?\d+))?\]$', insn.op_str.split(', ', 1)[1]) if insn.mnemonic.startswith('ldr') and 'pc' in insn.op_str else None
    if not m:
        return None
    imm = int(m.group(1), 0) if m.group(1) else 0
    base = (insn.address + 4) & ~3
    return avrlib.u32(base + imm)


def annot(start, length, fw=None):
    base = 0x08000000
    data = avrlib.fw[start - base:start - base + length]
    for insn in md.disasm(bytes(data), start):
        extra = ''
        if insn.mnemonic.startswith('ldr') and 'pc' in insn.op_str:
            v = pool_target(insn)
            if v is not None:
                extra = '   ; =0x%08x' % v
        print('%08x  %-8s %s%s' % (insn.address, insn.mnemonic, insn.op_str, extra))


if __name__ == '__main__':
    a = int(sys.argv[1], 16)
    n = int(sys.argv[2], 16)
    annot(a, n)
