"""Optional patch O1: disable the stock 1-hour 'sleep -> deep' timer expiry.

bne 0x08010a80 (13d1) at 0x08010a56  ->  b 0x08010a80 (13e0).
Checks (1) encoding/target, (2) no other branch in FUN_0801074c enters the expiry
block 0x08010a58..0x08010a7f, (3) micro-emulation of 0x08010a36..0x08010a80 for stock vs O1.
usage: test_o1.py <stock.fw> <o1.fw>
"""
import sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS, CS_GRP_JUMP, CS_OP_IMM
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_PC

BASE = 0x08000000
SITE = 0x08010a56
EXP_LO, EXP_HI = 0x08010a58, 0x08010a80  # expiry block [lo, hi)
BFD8, C038, C03C, C2B5, C030 = 0x2001bfd8, 0x2001c038, 0x2001c03c, 0x2001c2b5, 0x2001c030
FUN_RANGES = [(0x0801074c, 0x08010d85), (0x08010d8c, 0x08011125)]

stock = open(sys.argv[1], 'rb').read()
o1 = open(sys.argv[2], 'rb').read()
fails = 0


def chk(cond, msg):
    global fails
    print(('  ok   ' if cond else '  FAIL ') + msg)
    if not cond:
        fails += 1


print('== 1. byte-level diff and encoding ==')
diff = [i for i in range(len(stock)) if stock[i] != o1[i]]
chk(len(stock) == len(o1), 'same size')
chk(diff == [SITE - BASE + 1], 'exactly 1 byte differs, at %s (d1 -> e0; the low byte 0x13 is shared by bne/b)' % [hex(BASE + d) for d in diff])
chk(stock[SITE - BASE:SITE - BASE + 2].hex() == '13d1', 'stock bytes 13d1 (bne)')
chk(o1[SITE - BASE:SITE - BASE + 2].hex() == '13e0', 'O1 bytes 13e0 (b)')
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
md.detail = True
for tag, img in (('stock', stock), ('O1', o1)):
    ins = list(md.disasm(img[SITE - BASE:SITE - BASE + 2], SITE))[0]
    tgt = int(ins.op_str.lstrip('#'), 0)
    chk(tgt == EXP_HI, '%s: %s %s -> target 0x%08x' % (tag, ins.mnemonic, ins.op_str, tgt))

print('== 2. nothing else branches into the expiry block ==')
hits = []
tables = []
for lo, hi in FUN_RANGES:
    off = lo
    while off < hi:
        got = list(md.disasm(stock[off - BASE:off - BASE + 4], off))
        if not got:
            off += 2
            continue
        i = got[0]
        if i.mnemonic in ('tbb', 'tbh'):
            tables.append(i.address)
        if CS_GRP_JUMP in i.groups or i.mnemonic in ('cbz', 'cbnz'):
            for op in i.operands:
                if op.type == CS_OP_IMM and EXP_LO <= op.imm < EXP_HI:
                    hits.append((hex(i.address), i.mnemonic, hex(op.imm)))
        off += i.size
print('  direct branches whose target is inside the expiry block [0x%08x,0x%08x): %s' % (EXP_LO, EXP_HI, hits))
chk(hits == [], 'no direct branch targets 0x08010a58..0x08010a7f (expiry is entered only by fall-through from 0x08010a56)')
print('  tbb/tbh in FUN_0801074c ranges (cannot be resolved statically):', [hex(a) for a in tables])


def micro(img, bfd8, c038=0x00, c03c=0x03, c2b5=0x00):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(BASE, 0x600000)
    uc.mem_write(BASE, img)
    uc.mem_map(0x20000000, 0x40000)
    uc.mem_write(BFD8, bfd8.to_bytes(4, 'little'))
    uc.mem_write(C038, bytes([c038]))
    uc.mem_write(C03C, bytes([c03c]))
    uc.mem_write(C2B5, bytes([c2b5]))
    uc.reg_write(UC_ARM_REG_SP, 0x2003f000)
    uc.emu_start(0x08010a36 | 1, EXP_HI, count=200)
    pc = uc.reg_read(UC_ARM_REG_PC)
    return (pc & ~1,
            int.from_bytes(uc.mem_read(BFD8, 4), 'little'),
            uc.mem_read(C038, 1)[0], uc.mem_read(C03C, 1)[0], uc.mem_read(C2B5, 1)[0])


print('== 3. micro-emulation of 0x08010a36..0x08010a80 (one slow tick) ==')
for bfd8 in (0, 1, 2, 3, 100, 3600):
    s = micro(stock, bfd8)
    o = micro(o1, bfd8)
    exp_s_exp = (bfd8 == 1)
    # stock: expiry only when the decrement reaches 0 (bfd8 == 1)
    stock_expired = s[2] == 0x80 and s[3] == 0x01 and s[4] == 100
    o1_expired = o[2] == 0x80 or o[3] != 0x03 or o[4] != 0
    chk(s[0] == EXP_HI and o[0] == EXP_HI, 'bfd8=%d: both reach 0x08010a80 (pc stock=%x o1=%x)' % (bfd8, s[0], o[0]))
    exp_bfd8 = max(bfd8 - 1, 0) if bfd8 else 0
    chk(s[1] == exp_bfd8 and o[1] == exp_bfd8, 'bfd8=%d: counter -> %d in both (stock %d, O1 %d)' % (bfd8, exp_bfd8, s[1], o[1]))
    chk(stock_expired == exp_s_exp, 'bfd8=%d: stock expiry (c038|=0x80, c03c&=0xfd, c2b5=100) fired=%s' % (bfd8, stock_expired))
    chk(not o1_expired, 'bfd8=%d: O1 expiry did NOT fire (c038=%02x c03c=%02x c2b5=%d)' % (bfd8, o[2], o[3], o[4]))
    if not exp_s_exp:
        chk(s[1:] == o[1:], 'bfd8=%d: non-expiry ticks are bit-identical stock vs O1' % bfd8)

print('TOTAL FAILURES:', fails)
sys.exit(1 if fails else 0)
