import sys, random
sys.path.insert(0, '/tmp/avrwork')
from compare import *


def norm2(ev):
    out = []
    for e in norm(ev):
        if e[0] == 'CALL':
            out.append(('CALL', e[1], e[3]))
        else:
            out.append(e)
    return out


def ram(emu):
    # exclude the dispatcher's own idle-timer record (0x2001c15e..0x2001c161), rewritten by the FUN_0802d230 tail for every key action
    b = bytearray(emu.ram_image())
    lo = 0x2001c15e - 0x2001bf00
    b[lo:lo + 4] = b'\0\0\0\0'
    return bytes(b)


def bad(ev):
    return any(e[0] in ('ERR', 'TIMEOUT') for e in ev)


def deep(ev):
    return ('W', 'c2ab', 7) in ev


def make_init(rng, marker, gateb, c050=None, bfb8=0):
    rnd = bytes(rng.randrange(256) for _ in range(0x600))
    init = {0x2001bf00: rnd}
    over = dict(
        c030=2 | rng.randrange(256),
        c09c=(rng.randrange(256) & ~1) | gateb,
        c0d8=rng.randrange(256) & ~1,
        b2b5=0, b2b6=0, bfb8=bfb8, bfd8=0,
    )
    over['c038'] = (rng.randrange(256) & 0x7F) | (0x80 if marker else 0)
    if c050 is not None:
        over['c050'] = c050
    return init, over


def go(image, entry, init, over, n=520):
    steps = [('call',) + entry, ('ticks', n)]
    emu, init_ram = scenario(image, steps, over=over, init_bytes=init)
    ev = [e for e in emu.events if e[0] not in ('STEP', 'TICK')]
    return emu, ev


def main(N=300, seed=1234):
    rng = random.Random(seed)
    stats = dict(runs=0, skipped=0)
    fails = []
    for mode in ('marker_clear', 'marker_stale'):
        for gateb in (0, 1):
            ok_net = ok_btn = ok_20 = ok_stockeq = n = nodeep = 0
            for i in range(N):
                init, over = make_init(rng, mode == 'marker_stale', gateb)
                cec4, ev4 = go(CAND, ('FUN_0802d230', (4,)), init, over)
                cec20, ev20 = go(CAND, ('FUN_0802d230', (0x20,)), init, over)
                net, evn = go(PRISTINE, ('FUN_080192e2',), init, over)
                btn, evb = go(PRISTINE, ('FUN_08019272',), init, over)
                stk4, evs4 = go(PRISTINE, ('FUN_0802d230', (4,)), init, over)
                if any(bad(x) for x in (ev4, ev20, evn, evb, evs4)):
                    stats['skipped'] += 1
                    continue
                n += 1
                if ram(cec4) == ram(net) and norm2(ev4) == norm2(evn):
                    ok_net += 1
                elif gateb == 0:
                    fails.append(('cec4!=net', mode, gateb, i))
                if ram(cec20) == ram(net) and norm2(ev20) == norm2(evn):
                    ok_20 += 1
                elif gateb == 0:
                    fails.append(('cec20!=net', mode, gateb, i))
                if ram(cec4) == ram(btn) and norm2(ev4) == norm2(evb):
                    ok_btn += 1
                # gate-B-true path must be untouched by the patch: candidate == stock
                if ram(cec4) == ram(stk4) and norm2(ev4) == norm2(evs4):
                    ok_stockeq += 1
                if mode == 'marker_clear' and gateb == 0 and deep(ev4):
                    nodeep += 1
            print('%-13s gateB=%d runs=%3d | cand-CEC4==stock-NET %3d | cand-CEC0x20==stock-NET %3d | cand-CEC4==stock-BTN %3d | cand==stock-CEC %3d | deep-after-cand-CEC=%d'
                  % (mode, gateb, n, ok_net, ok_20, ok_btn, ok_stockeq, nodeep))
    print('skipped (timeouts/errors):', stats['skipped'])
    print('FAILS:', fails[:10], 'total', len(fails))


if __name__ == '__main__':
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 100, int(sys.argv[2]) if len(sys.argv) > 2 else 1234)
