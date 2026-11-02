import sys, re, struct
from avrlib import *
from capstone.arm_const import *

def bl_target(a):
    o=a-BASE
    h1,h2=struct.unpack('<HH',fw[o:o+4])
    if (h1&0xF800)!=0xF000: return None
    if (h2&0xD000)!=0xD000: return None   # BL
    S=(h1>>10)&1
    imm10=h1&0x3FF
    J1=(h2>>13)&1; J2=(h2>>11)&1
    imm11=h2&0x7FF
    I1=1-(J1^S); I2=1-(J2^S)
    imm=(S<<24)|(I1<<23)|(I2<<22)|(imm10<<12)|(imm11<<1)
    if S: imm-=1<<25
    return a+4+imm

def find_calls(target, lo=0x08000000, hi=0x08000000+len(fw)-4):
    out=[]
    for a in range(lo,hi,2):
        t=bl_target(a)
        if t==target: out.append(a)
    return out

def back_insns(a, maxback=24):
    # find a clean linear disassembly that ends exactly at address a
    best=[]
    for back in range(maxback,1,-2):
        s=a-back
        ins=dis(s,back)
        if ins and ins[-1].address+ins[-1].size==a:
            if len(ins)>len(best): best=ins
    return best

def resolve_regs(a):
    ins=back_insns(a)
    regs={}
    for i in ins:
        m=i.mnemonic; ops=i.op_str
        mm=re.match(r'(r\d+|sp|lr), \[pc, #(0x[0-9a-f]+|\d+)\]',ops)
        if m.startswith('ldr') and mm:
            pcv=((i.address+4)&~3)+int(mm.group(2),0)
            try:
                regs[mm.group(1)]=u32(pcv)
            except Exception: regs[mm.group(1)]=None
            continue
        mm=re.match(r'(r\d+), #(0x[0-9a-f]+|\d+)$',ops)
        if m in('movs','mov','mov.w','movw','movs.w') and mm:
            regs[mm.group(1)]=int(mm.group(2),0); continue
        mm=re.match(r'(r\d+), (r\d+)$',ops)
        if m in('mov','movs') and mm:
            regs[mm.group(1)]=regs.get(mm.group(2)); continue
        mm=re.match(r'(r\d+), (r\d+)$',ops)
        if m in('uxth','uxtb') and mm:
            v=regs.get(mm.group(2))
            if v is not None: regs[mm.group(1)]=v & (0xffff if m=='uxth' else 0xff)
            continue
        # any other write to r0/r1 kills knowledge
        mm=re.match(r'(r\d+),',ops)
        if mm and m not in('cmp','tst','str','strh','strb','push','b','bl','bx','beq','bne'):
            regs[mm.group(1)]=None
    return regs

PORTS={0x40020000:'GPIOA',0x40020400:'GPIOB',0x40020800:'GPIOC',0x40020c00:'GPIOD',0x40021000:'GPIOE',0x40021400:'GPIOF',0x40021800:'GPIOG',0x40021c00:'GPIOH',0x40022000:'GPIOI'}
if __name__=='__main__':
    which={'SET(high)':0x0804b208,'RESET(low)':0x0804b20c}
    for nm,t in which.items():
        sites=find_calls(t)
        print('=====',nm,hex(t),len(sites),'call sites')
        for s in sites:
            r=resolve_regs(s)
            port=r.get('r0'); pin=r.get('r1')
            pn=PORTS.get(port, hex(port) if port is not None else '?')
            pp=('0x%x'%pin) if pin is not None else '?'
            print('  %08x  %-6s pin %-8s'%(s,pn,pp))
