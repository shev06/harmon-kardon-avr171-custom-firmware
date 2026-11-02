import sys, re, bisect
from avrlib import *
from capstone import *
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
md.detail = True
base = int(sys.argv[1], 16)
offs = {int(x, 0) for x in sys.argv[2:]}
funcs = []
import paths
for line in open(paths.FUNCRANGES):
    p = line.split()
    if len(p) >= 5 and p[0] == 'FUNC':
        funcs.append((int(p[2],16), int(p[3],16), p[4]))
funcs.sort()
starts = [f[0] for f in funcs]
def fn(a):
    i = bisect.bisect_right(starts, a) - 1
    if i >= 0 and funcs[i][0] <= a <= funcs[i][1]:
        return funcs[i][2]
    return '?'
# find literal pool words == base
sites = []
for off in range(0, min(len(fw), 0x100000) - 4, 4):
    if u32(BASE + off) == base:
        sites.append(BASE + off)
# find ldr pc-rel instructions that reference these literals
out = []
end = min(len(fw), 0x100000)
a = 0
import struct
while a < end - 4:
    addr = BASE + a
    h = struct.unpack_from('<H', fw, a)[0]
    # ldr rX, [pc, #imm8*4] (T1) 0x4800..0x4FFF ; ldr.w literal 0xF8DF
    lit = None
    if (h & 0xF800) == 0x4800:
        rd = (h >> 8) & 7
        imm = (h & 0xFF) * 4
        lit = ((addr + 4) & ~3) + imm
        sz = 2
    elif h == 0xF8DF or h == 0xF85F:
        h2 = struct.unpack_from('<H', fw, a + 2)[0]
        rd = (h2 >> 12) & 0xF
        imm = h2 & 0xFFF
        lit = ((addr + 4) & ~3) + (imm if h == 0xF8DF else -imm)
        sz = 4
    if lit is not None and lit in sites:
        # decode next instructions
        code = bytes(fw[a + sz: a + sz + 24])
        for ins in md.disasm(code, addr + sz):
            if ins.mnemonic.startswith(('ldr', 'str')) and '[' in ins.op_str:
                m = re.search(r'\[(r\d+|sp|lr)(?:, #(-?0x[0-9a-f]+|-?\d+))?\]', ins.op_str)
                if m and m.group(1) == 'r%d' % rd:
                    o = int(m.group(2), 0) if m.group(2) else 0
                    if o in offs:
                        out.append((addr, fn(addr), ins.address, ins.mnemonic, ins.op_str, o))
                        break
                    # fallthrough: keep scanning
            if ins.mnemonic.startswith(('b', 'bl', 'bx', 'pop', 'cbz', 'cbnz')):
                break
        a += sz
    else:
        a += 2 if (h & 0xF800) not in (0xE800, 0xF000, 0xF800) else 4
for r in out:
    print('%08x %-14s -> %08x %-6s %s  (off %#x)' % r)
