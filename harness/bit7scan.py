import sys, re
from avrlib import *
from ramxref import pool_slots, ldr_users

def fnstarts():
    # crude: function entries recorded from Ghidra function list file if present
    return None

def window(a, n=26):
    return dis(a, n)

TARGET=int(sys.argv[1],0)
slots=pool_slots(TARGET)
sites=[]
for s in slots:
    for (a,kind,reg) in ldr_users(s):
        sites.append((a,reg))
sites.sort()
print('RAM %#x: %d load sites'%(TARGET,len(sites)))
for a,reg in sites:
    ins=dis(a, 30)
    # print up to ~8 following instructions (stop at bl/bx/pop)
    out=[]
    for i in ins[:9]:
        out.append('%08x %s %s'%(i.address,i.mnemonic,i.op_str))
    print('--- load r%d at %08x'%(reg,a))
    for l in out: print('   ',l)
