import sys, random
sys.path.insert(0, '/tmp/avrwork')
from run_scen import *

CAND = open('/tmp/avrwork/candidate.fw', 'rb').read()


def run(image, steps, over=None, init_bytes=None):
    emu, init = scenario(image, steps, over=over, init_bytes=init_bytes)
    ev = [e for e in emu.events if e[0] not in ('STEP', 'TICK')]
    return emu, ev, init


def norm(ev):
    # the dispatcher tail (FUN_08012f6c) only exists on the CEC route; ignore it for equivalence
    return [e for e in ev if not (e[0] == 'CALL' and e[1] == 'FUN_08012f6c')]


def gpio_only(ev):
    return [e for e in ev if e[0] == 'GPIO']


def summarize(name, emu, ev):
    g = gpio_only(ev)
    print('%-34s GPIO writes=%3d  final=%s' % (name, len(g), emu.snapshot()))


if __name__ == '__main__':
    T = [('ticks', 520)]
    res = {}
    cases = [
        ('S1 stock  CEC  case4', PRISTINE, [('call', 'FUN_0802d230', (4,))] + T),
        ('S1b stock CEC  case0x20', PRISTINE, [('call', 'FUN_0802d230', (0x20,))] + T),
        ('S2 stock  BUTTON', PRISTINE, [('call', 'FUN_08019272')] + T),
        ('S5 stock  NETWORK power-off', PRISTINE, [('call', 'FUN_080192e2')] + T),
        ('S3 cand   CEC  case4', CAND, [('call', 'FUN_0802d230', (4,))] + T),
        ('S3b cand  CEC  case0x20', CAND, [('call', 'FUN_0802d230', (0x20,))] + T),
        ('S3c cand  CEC then BUTTON(+200t)', CAND, [('call', 'FUN_0802d230', (4,)), ('ticks', 200), ('call', 'FUN_08019272'), ('ticks', 400)]),
        ('S3d cand  BUTTON', CAND, [('call', 'FUN_08019272')] + T),
        ('S3e cand  NETWORK power-off', CAND, [('call', 'FUN_080192e2')] + T),
        ('S4 deliv  CEC case4 (patch#4)', DELIV, [('call', 'FUN_0802d230', (4,))] + T),
    ]
    for name, img, steps in cases:
        emu, ev, init = run(img, steps)
        res[name] = (emu, ev, init)
        summarize(name, emu, ev)
    print()

    def same(a, b):
        ea, eb = res[a], res[b]
        ra = ea[0].ram_image() == eb[0].ram_image()
        # events after tick 0 handling: compare full event lists ignoring the dispatcher tail call
        va = norm(ea[1]) == norm(eb[1])
        return ra, va

    for a, b in [
        ('S3 cand   CEC  case4', 'S2 stock  BUTTON'),
        ('S3 cand   CEC  case4', 'S5 stock  NETWORK power-off'),
        ('S3b cand  CEC  case0x20', 'S2 stock  BUTTON'),
        ('S3 cand   CEC  case4', 'S3b cand  CEC  case0x20'),
        ('S3d cand  BUTTON', 'S2 stock  BUTTON'),
        ('S3e cand  NETWORK power-off', 'S5 stock  NETWORK power-off'),
        ('S3 cand   CEC  case4', 'S1 stock  CEC  case4'),
    ]:
        ra, va = same(a, b)
        print('%-32s vs %-30s  RAM identical=%s  event-log identical=%s' % (a, b, ra, va))
