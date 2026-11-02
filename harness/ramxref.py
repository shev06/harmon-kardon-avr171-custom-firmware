import sys, struct, re
from avrlib import *
# Find all literal-pool slots whose value == given RAM addr, then all ldr instructions that load from those slots.
def pool_slots(val):
    pat=struct.pack('<I',val)
    out=[]; i=0
    while True:
        j=fw.find(pat,i)
        if j<0: break
        if j%4==0: out.append(BASE+j)
        i=j+1
    return out
def ldr_users(slot):
    # scan all halfword positions for ldr (literal) T1/T2 targeting slot
    users=[]
    for a in range(BASE, BASE+len(fw)-2, 2):
        h=u16(a)
        # T1: LDR Rt,[PC,#imm8*4]  0100 1ttt iiii iiii
        if (h&0xF800)==0x4800:
            imm=(h&0xFF)*4
            if ((a+4)&~3)+imm==slot: users.append((a,'T1',(h>>8)&7))
        # T2 (ldr.w literal): F8DF Rt:imm12 or F85F
        if h in (0xF8DF,0xF85F):
            h2=u16(a+2)
            imm=h2&0xFFF
            base=(a+4)&~3
            tgt= base+imm if h==0xF8DF else base-imm
            if tgt==slot: users.append((a,'T2',(h2>>12)&0xF))
    return users
if __name__=='__main__':
    for arg in sys.argv[1:]:
        val=int(arg,0)
        slots=pool_slots(val)
        print('RAM %#x: pool slots %s'%(val,[hex(s) for s in slots]))
        for s in slots:
            for u in ldr_users(s):
                print('   slot %08x loaded at %08x (%s r%d)'%(s,u[0],u[1],u[2]))
