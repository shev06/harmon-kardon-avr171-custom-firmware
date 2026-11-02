"""Unicorn differential harness for the AVR1710 power-down logic.

Real code is executed for a small whitelist of power/tick functions; every other Ghidra
function entry is replaced (in the emulator's private flash copy only) by `movs r0,#N; bx lr`.
GPIO BSRR writes, stubbed-call entries and writes to watched RAM bytes are logged so that
different entry scenarios can be compared.
"""
import sys, struct, random
from paths import FUNCRANGES
from unicorn import *
from unicorn.arm_const import *

BASE = 0x08000000
FSIZE = 0x600000
RAM = 0x20000000
RAMSZ = 0x40000
SENT = 0x0F000000
STACK_TOP = 0x2003F000

A = dict(
    c030=0x2001c030, c038=0x2001c038, c03c=0x2001c03c, c050=0x2001c050, c09c=0x2001c09c,
    c0d8=0x2001c0d8, b2b5=0x2001c2b5, b2b6=0x2001c2b6, bfb8=0x2001bfb8, bfd8=0x2001bfd8,
    c27f=0x2001c27f, c2ab=0x2001c2ab,
)
WATCH_BYTES = {v: k for k, v in A.items() if k not in ('bfb8', 'bfd8')}
WATCH_WORDS = {A['bfb8']: 'bfb8', A['bfd8']: 'bfd8'}

PORTS = 'ABCDEFGHI'


def load_funcs(path=FUNCRANGES):
    funcs = {}
    for line in open(path):
        p = line.split()
        if len(p) >= 5 and p[0] == 'FUNC':
            entry = int(p[1], 16)
            f = funcs.setdefault(entry, dict(name=p[4], ranges=[]))
            f['ranges'].append((int(p[2], 16), int(p[3], 16)))
    return funcs


FUNCS = load_funcs()
BYNAME = {f['name']: e for e, f in FUNCS.items()}


def E(name):
    return BYNAME[name]


DEFAULT_WHITELIST = [
    'FUN_08011910', 'FUN_08013c0c', 'FUN_080192e2', 'FUN_08019272', 'FUN_08019378',
    'FUN_08019638', 'FUN_0802d230', 'FUN_0804b208', 'FUN_0804b20c', 'FUN_08060c64',
]


class Emu:
    def __init__(self, image, whitelist=DEFAULT_WHITELIST, stub_ret=None, init_bytes=None,
                 extra_real=(), verbose=False):
        self.image = bytearray(image)
        self.verbose = verbose
        self.real_ranges = []
        self.real_entries = set()
        for n in list(whitelist) + list(extra_real):
            e = E(n) if isinstance(n, str) else n
            self.real_entries.add(e)
            self.real_ranges += FUNCS[e]['ranges']
        self.stub_ret = stub_ret or {}
        self.stubs = {}
        for e, f in FUNCS.items():
            if e in self.real_entries:
                continue
            lo = min(r[0] for r in f['ranges'])
            hi = max(r[1] for r in f['ranges'])
            if hi - lo + 1 < 4:
                continue
            if any(rl <= e <= rh for rl, rh in self.real_ranges):
                continue
            ret = self.stub_ret.get(f['name'], self.stub_ret.get(e, 0))
            o = e - BASE
            if o + 4 > len(self.image):
                continue
            self.image[o:o + 4] = bytes([ret & 0xFF, 0x20, 0x70, 0x47])
            self.stubs[e] = f['name']
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc = uc
        uc.mem_map(BASE, FSIZE)
        uc.mem_write(BASE, bytes(self.image))
        uc.mem_map(RAM, RAMSZ)
        uc.mem_map(0x10000000, 0x10000)
        uc.mem_map(SENT, 0x1000)
        if init_bytes:
            for a, b in init_bytes.items():
                uc.mem_write(a, bytes(b) if not isinstance(b, int) else bytes([b]))
        self.events = []
        self.tick = 0
        self.mapped = set()
        self.pc_hist = {}
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self._unmapped)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._gpio_w, begin=0x40020000, end=0x400223FF)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._ram_w, begin=0x2001bf00, end=0x2001c500)
        uc.hook_add(UC_HOOK_BLOCK, self._blk)
        self.unexpected = {}
        self.stub_names = self.stubs

    # ---- hooks
    def _unmapped(self, uc, access, address, size, value, ud):
        page = address & ~0xFFF
        if page in self.mapped:
            return False
        try:
            uc.mem_map(page, 0x1000)
            self.mapped.add(page)
            return True
        except UcError:
            return False

    def _gpio_w(self, uc, access, address, size, value, ud):
        off = address - 0x40020000
        port = PORTS[off // 0x400]
        reg = off % 0x400
        pc = uc.reg_read(UC_ARM_REG_PC)
        if reg == 0x18 and size == 2:
            self.events.append(('GPIO', port, 'SET', value & 0xFFFF))
        elif reg == 0x1A and size == 2:
            self.events.append(('GPIO', port, 'RST', value & 0xFFFF))
        elif reg == 0x18 and size == 4:
            if value & 0xFFFF:
                self.events.append(('GPIO', port, 'SET', value & 0xFFFF))
            if value >> 16:
                self.events.append(('GPIO', port, 'RST', value >> 16))
        else:
            self.events.append(('GPIOREG', port, hex(reg), size, value))

    def _ram_w(self, uc, access, address, size, value, ud):
        for a, n in WATCH_BYTES.items():
            if address <= a < address + size:
                v = (value >> (8 * (a - address))) & 0xFF
                self.events.append(('W', n, v))
        for a, n in WATCH_WORDS.items():
            if address == a and size == 4:
                self.events.append(('W', n, value))

    def _blk(self, uc, address, size, ud):
        nm = self.stubs.get(address)
        if nm is not None:
            r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            lr = uc.reg_read(UC_ARM_REG_LR) & ~1
            self.events.append(('CALL', nm, tuple(r[:2]), hex(lr)))
        else:
            # detect execution of flash outside whitelisted functions (not stubbed)
            if BASE <= address < BASE + FSIZE and not any(lo <= address <= hi for lo, hi in self.real_ranges):
                self.unexpected[address] = self.unexpected.get(address, 0) + 1

    # ---- helpers
    def rb(self, a):
        return self.uc.mem_read(a, 1)[0]

    def rw(self, a):
        return struct.unpack('<I', self.uc.mem_read(a, 4))[0]

    def wb(self, a, v):
        self.uc.mem_write(a, bytes([v & 0xFF]))

    def ww(self, a, v):
        self.uc.mem_write(a, struct.pack('<I', v))

    def snapshot(self):
        d = {k: self.rb(v) for k, v in A.items() if k not in ('bfb8', 'bfd8')}
        d['bfb8'] = self.rw(A['bfb8'])
        d['bfd8'] = self.rw(A['bfd8'])
        return d

    def ram_image(self, lo=0x2001bf00, hi=0x2001c500):
        return bytes(self.uc.mem_read(lo, hi - lo))

    def call(self, name_or_addr, args=(), maxinsn=3_000_000):
        e = E(name_or_addr) if isinstance(name_or_addr, str) else name_or_addr
        uc = self.uc
        for i, a in enumerate(args):
            uc.reg_write((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)[i], a)
        uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM_REG_LR, SENT | 1)
        try:
            uc.emu_start(e | 1, SENT, count=maxinsn)
        except UcError as ex:
            self.events.append(('ERR', str(ex), hex(uc.reg_read(UC_ARM_REG_PC))))
            return False
        pc = uc.reg_read(UC_ARM_REG_PC)
        if pc != SENT:
            self.events.append(('TIMEOUT', hex(pc)))
            return False
        return True

    def ticks(self, n, stop_when=None):
        for i in range(n):
            self.tick += 1
            self.events.append(('TICK', self.tick))
            ok = self.call('FUN_08011910')
            if not ok:
                return False
            if stop_when and stop_when(self):
                return True
        return True


def fmt_event(ev):
    return ' '.join(str(x) for x in ev)


def poweron_state(emu, **over):
    """Make the emulated device 'ON' with the default-zero RAM (plus overrides)."""
    emu.wb(A['c030'], emu.rb(A['c030']) | 2)
    for k, v in over.items():
        if k in ('bfb8', 'bfd8'):
            emu.ww(A[k], v)
        else:
            emu.wb(A[k], v)
