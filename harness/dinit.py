import sys
import avrlib
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE, UcError
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

FLASH = 0x08000000
RAM = 0x20000000


def run_data_init(fw=None, entry=0x080befdc, max_insns=5_000_000):
    img = fw if fw is not None else bytes(avrlib.fw)
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(FLASH, (len(img) + 0xFFF) & ~0xFFF)
    uc.mem_write(FLASH, img)
    uc.mem_map(RAM, 0x40000)
    sentinel = 0x08000100
    uc.reg_write(UC_ARM_REG_SP, 0x2001d300)
    uc.reg_write(UC_ARM_REG_LR, sentinel | 1)
    try:
        uc.emu_start(entry | 1, sentinel, count=max_insns)
    except UcError as e:
        print('emu error', e, hex(uc.reg_read(UC_ARM_REG_PC)))
    return uc


if __name__ == '__main__':
    uc = run_data_init()
    for name, a, n in [('inc1 CC1', 0x2000be9e, 2), ('inc2 CC2', 0x2000bea0, 2), ('inc3 CC3', 0x2000bea2, 2),
                       ('bfd8', 0x2001bfd8, 4), ('c090', 0x2001c090, 4)]:
        print(name, hex(a), int.from_bytes(uc.mem_read(a, n), 'little'))
    print('RAM 0x2000be90..0x2000beb0:')
    print(bytes(uc.mem_read(0x2000be90, 0x20)).hex())
