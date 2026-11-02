import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from paths import PRISTINE as FW_PATH
BASE=0x08000000
def load(path=FW_PATH):
    return open(path,'rb').read()
fw=load()
md=Cs(CS_ARCH_ARM, CS_MODE_THUMB|CS_MODE_MCLASS)
md.detail=True
def u32(a, data=None):
    d=data or fw
    o=a-BASE
    return struct.unpack('<I',d[o:o+4])[0]
def u16(a):
    o=a-BASE
    return struct.unpack('<H',fw[o:o+2])[0]
def dis(a, n=0x40, data=None):
    d=data or fw
    o=a-BASE
    return list(md.disasm(d[o:o+n], a))
def show(a,n=0x40,data=None):
    for i in dis(a,n,data):
        print('%08x  %-8s %s'%(i.address,i.mnemonic,i.op_str))
