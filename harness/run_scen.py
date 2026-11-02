import sys
import paths
from emu import *

PRISTINE = open(paths.PRISTINE, 'rb').read()
DELIV = open(paths.BASELINE, 'rb').read()  # the frozen pre-4b image, not the live deliverable


def compact(events, show_calls=True):
    out = []
    t = 0
    last = {}
    lastw = {}
    for ev in events:
        if ev[0] == 'TICK':
            t = ev[1]
            continue
        if ev[0] == 'CALL':
            if not show_calls:
                continue
            key = (ev[1], ev[2][0], ev[3])
            if last.get(ev[1]) == key:
                continue
            last[ev[1]] = key
            out.append('t%03d CALL %s r0=%#x lr=%s' % (t, ev[1], ev[2][0], ev[3]))
            continue
        if ev[0] == 'W' and ev[1] in ('b2b5', 'b2b6', 'bfb8'):
            pv = lastw.get(ev[1])
            lastw[ev[1]] = ev[2]
            if pv is not None and ev[2] == pv - 1 and ev[2] != 0:
                continue
        out.append('t%03d %s' % (t, fmt_event(ev)))
    return out


def scenario(image, steps, nticks=520, over=None, whitelist=DEFAULT_WHITELIST, stub_ret=None, init_bytes=None):
    emu = Emu(image, whitelist=whitelist, stub_ret=stub_ret, init_bytes=init_bytes)
    poweron_state(emu, **(over or {}))
    init = emu.ram_image()
    for s in steps:
        if s[0] == 'call':
            emu.events.append(('STEP', s[1], s[2] if len(s) > 2 else ()))
            emu.call(s[1], s[2] if len(s) > 2 else ())
        elif s[0] == 'ticks':
            emu.ticks(s[1])
        elif s[0] == 'poke8':
            emu.wb(s[1], s[2])
        elif s[0] == 'poke32':
            emu.ww(s[1], s[2])
        elif s[0] == 'path':
            # execute straight-line code from s[1] up to the address s[2] (e.g. the middle of a non-whitelisted function)
            uc = emu.uc
            emu.events.append(('STEP', 'path_%08x' % s[1], ()))
            uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
            uc.reg_write(UC_ARM_REG_LR, SENT | 1)
            uc.reg_write(UC_ARM_REG_R0, 1)
            try:
                uc.emu_start(s[1] | 1, s[2], count=100000)
            except UcError as ex:
                emu.events.append(('ERR', str(ex), hex(uc.reg_read(UC_ARM_REG_PC))))
            if uc.reg_read(UC_ARM_REG_PC) != s[2]:
                emu.events.append(('TIMEOUT', hex(uc.reg_read(UC_ARM_REG_PC))))
    return emu, init


if __name__ == '__main__':
    which = sys.argv[1]
    img = PRISTINE if sys.argv[2] == 'stock' else DELIV
    steps = {
        'cec': [('call', 'FUN_0802d230', (4,)), ('ticks', 520)],
        'cec20': [('call', 'FUN_0802d230', (0x20,)), ('ticks', 520)],
        'btn': [('call', 'FUN_08019272'), ('ticks', 520)],
        'net': [('call', 'FUN_080192e2'), ('ticks', 520)],
        'cec_btn': [('call', 'FUN_0802d230', (4,)), ('ticks', 200), ('call', 'FUN_08019272'), ('ticks', 400)],
    }[which]
    emu, init = scenario(img, steps)
    for l in compact(emu.events):
        print(l)
    print('FINAL', emu.snapshot())
    print('UNEXPECTED real-code blocks:', {hex(k): v for k, v in list(emu.unexpected.items())[:20]})
