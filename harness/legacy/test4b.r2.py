"""Option 4b validation: helper unit tests, dispatcher matrix, differential vs stock references, trampoline.

usage: python test4b.py [candidate.fw]
"""
import sys, random, itertools, collections
sys.path.insert(0, '/tmp/avrwork')
import emu as E_
from emu import *
from run_scen import *
from build_candidate_4b import HELPER, HELPER_BYTES

CAND_PATH = sys.argv[1] if len(sys.argv) > 1 else '/tmp/avrwork/candidate4b.fw'
CAND = open(CAND_PATH, 'rb').read()

# make the cave helper "real" code for the emulator (it is not a Ghidra function of the pristine image)
E_.FUNCS[HELPER] = dict(name='cec_sleep_helper', ranges=[(HELPER, HELPER + len(HELPER_BYTES) - 1)])
E_.BYNAME['cec_sleep_helper'] = HELPER
WL = DEFAULT_WHITELIST + ['cec_sleep_helper']

NTICKS = 900


def run(image, steps, over=None, init_bytes=None):
    emu, init = scenario(image, steps, over=over, init_bytes=init_bytes, whitelist=WL)
    ev = [e for e in emu.events if e[0] not in ('STEP', 'TICK')]
    return emu, ev


def bad(ev):
    return any(e[0] in ('ERR', 'TIMEOUT') for e in ev)


def deep(emu, ev, init_c09c=0):
    # the DEEP step of the sequencer writes c2ab = 7 and sets c09c bit 6
    return ('W', 'c2ab', 7) in ev or (bool(emu.rb(A['c09c']) & 0x40) and not (init_c09c & 0x40))


def shutdowns(ev):
    """number of FUN_08019638 completions (it ends with bfb8 = 250 or 300)"""
    return sum(1 for e in ev if e[0] == 'W' and e[1] == 'bfb8' and e[2] in (250, 300))


def on(emu):
    return bool(emu.rb(A['c030']) & 2)


def first_shutdown_tick(emu):
    t = 0
    for e in emu.events:
        if e[0] == 'TICK':
            t = e[1]
        elif e[0] == 'W' and e[1] == 'bfb8' and e[2] in (250, 300):
            return t
    return None


def marker_clean(emu):
    """CEC must never raise the deep marker (c038 bit 7): from the first CEC/helper call on, no write sets it, and it is
    clear at the end.  (Earlier events are not CEC's: the stock wake path FUN_08019378 itself passes a stale value through.)"""
    evs = emu.events
    start = next((i for i, e in enumerate(evs) if e[0] == 'STEP' and e[1] in ('FUN_0802d230', 'cec_sleep_helper')), 0)
    return (not any(e[0] == 'W' and e[1] == 'c038' and (e[2] & 0x80) for e in evs[start:])) and not (emu.rb(A['c038']) & 0x80)


# ---------------------------------------------------------------------------------------------
# 0. reference outcomes on the pristine firmware (zero RAM, ON, bfb8=0)
# ---------------------------------------------------------------------------------------------
def reference_signatures():
    out = {}
    for name, img, steps in [
        ('stock CEC case4', PRISTINE, [('call', 'FUN_0802d230', (4,)), ('ticks', NTICKS)]),
        ('stock BUTTON', PRISTINE, [('call', 'FUN_08019272'), ('ticks', NTICKS)]),
        ('stock NETWORK', PRISTINE, [('call', 'FUN_080192e2'), ('ticks', NTICKS)]),
        ('4b CEC case4', CAND, [('call', 'FUN_0802d230', (4,)), ('ticks', NTICKS)]),
        ('4b CEC case0x20', CAND, [('call', 'FUN_0802d230', (0x20,)), ('ticks', NTICKS)]),
    ]:
        emu, ev = run(img, steps)
        out[name] = (emu, ev)
        print('%-18s deep=%-5s on_at_end=%-5s shutdowns=%d first_shutdown_tick=%s  c03c=%#x c27f=%#x c09c=%#x' % (
            name, deep(emu, ev), on(emu), shutdowns(ev), first_shutdown_tick(emu),
            emu.rb(A['c03c']), emu.rb(A['c27f']), emu.rb(A['c09c'])))
    return out


# ---------------------------------------------------------------------------------------------
# 1. helper unit tests (call the helper itself)
# ---------------------------------------------------------------------------------------------
def unit_helper():
    print('\n== 1. helper unit tests ==')
    fails = 0
    n = 0
    table = collections.Counter()
    for is_on, marker, bfb8 in itertools.product((0, 1), (0x00, 0x80, 0x45, 0xC5), (0, 1, 50, 99, 100, 101, 150, 199, 200)):
        over = dict(c030=2 if is_on else 0, c038=marker, bfb8=bfb8, b2b5=0, b2b6=0, bfd8=0)
        emu, ev = run(CAND, [('call', 'cec_sleep_helper'), ('ticks', NTICKS)], over=over)
        n += 1
        if bad(ev):
            print('  ERR/TIMEOUT', over, [e for e in ev if e[0] in ('ERR', 'TIMEOUT')])
            fails += 1
            continue
        if not is_on:
            # nothing at all may change
            ref, evr = run(CAND, [('ticks', NTICKS)], over=over)
            same = emu.ram_image() == ref.ram_image() and ev == evr
            if not same:
                print('  FAIL OFF case changed state', over)
                fails += 1
            table[('OFF', 'no-op', 'mid-shutdown deep marker' if (marker & 0x80 and bfb8 >= 100) else 'idle')] += 1
            continue
        # the stale marker must have been cleared before the call and never raised again
        ok = (not deep(emu, ev)) and (not on(emu)) and shutdowns(ev) == 1 and marker_clean(emu) and not any(
            e[0] == 'W' and e[1] == 'bfb8' and e[2] == 300 for e in ev)
        if not ok:
            fails += 1
            print('  FAIL', over, 'deep', deep(emu, ev), 'on', on(emu), 'shutdowns', shutdowns(ev),
                  'marker_clean', marker_clean(emu))
        table[('ON', 'deferred' if bfb8 >= 100 else 'direct', 'first_shutdown_tick=%s' % (
            'imm' if first_shutdown_tick(emu) is not None and first_shutdown_tick(emu) < 5 else
            ('~%d' % (first_shutdown_tick(emu) // 10 * 10) if first_shutdown_tick(emu) else None)))] += 1
    print('  %d runs, %d failures' % (n, fails))
    for k, v in sorted(table.items(), key=str):
        print('   ', k, v)
    return fails


# ---------------------------------------------------------------------------------------------
# 2. whole dispatcher path matrix
# ---------------------------------------------------------------------------------------------
def matrix():
    print('\n== 2. FUN_0802d230 case matrix (candidate) ==')
    fails = 0
    n = 0
    table = collections.Counter()
    for case, zone2, marker, bfb8, c050 in itertools.product(
            (4, 0x20), (0, 1), (0x00, 0x80), (0, 1, 50, 99, 100, 101, 150, 199, 200), (0x00, 0x08, 0x80, 0x88)):
        over = dict(c038=marker, c09c=zone2, bfb8=bfb8, c050=c050, b2b5=0, b2b6=0, bfd8=0)
        emu, ev = run(CAND, [('call', 'FUN_0802d230', (case,)), ('ticks', NTICKS)], over=over)
        n += 1
        if bad(ev):
            print('  ERR/TIMEOUT', case, over)
            fails += 1
            continue
        ok = (not deep(emu, ev)) and (not on(emu)) and shutdowns(ev) == 1 and marker_clean(emu)
        if not ok:
            fails += 1
            print('  FAIL case=%#x' % case, over, 'deep', deep(emu, ev), 'on', on(emu), 'shutdowns', shutdowns(ev),
                  'marker_clean', marker_clean(emu), 'first', first_shutdown_tick(emu))
        table[(('zone2' if zone2 else 'nozone2'), 'bfb8>=100' if bfb8 >= 100 else 'bfb8<100',
               'stale' if marker else 'clean', 'OK' if ok else 'FAIL')] += 1
    print('  %d runs, %d failures' % (n, fails))
    for k, v in sorted(table.items(), key=str):
        print('   ', k, v)
    return fails


# ---------------------------------------------------------------------------------------------
# 3. differential: candidate vs stock-derived reference with random RAM
# ---------------------------------------------------------------------------------------------
def norm2(ev):
    out = []
    for e in ev:
        if e[0] == 'CALL' and e[1] == 'FUN_08012f6c':
            continue
        if e[0] == 'W' and e[1] == 'c038':
            continue
        if e[0] == 'CALL':
            out.append(('CALL', e[1], e[3]))
        else:
            out.append(e)
    return out


def ram_nodisp(emu):
    # exclude the dispatcher's idle-timer record rewritten by the FUN_0802d230 tail for every key action
    b = bytearray(emu.ram_image())
    lo = 0x2001c15e - 0x2001bf00
    b[lo:lo + 4] = b'\0\0\0\0'
    return bytes(b)


def make_init(rng, marker, zone2, bfb8, c050):
    rnd = bytes(rng.randrange(256) for _ in range(0x600))
    over = dict(
        c030=2 | rng.randrange(256),
        c09c=(rng.randrange(256) & ~1) | zone2,
        c0d8=rng.randrange(256) & ~1,
        b2b5=0, b2b6=0, bfb8=bfb8, bfd8=0,
        c050=c050,
        c038=(rng.randrange(256) & 0x7F) | (0x80 if marker else 0),
    )
    return {0x2001bf00: rnd}, over


def differential(N=25, seed=4242):
    print('\n== 3. differential vs stock references (random RAM) ==')
    rng = random.Random(seed)
    fails = []
    stats = collections.Counter()
    for marker in (0, 1):
        for zone2 in (0, 1):
            for bfb8 in (0, 40, 99, 100, 150, 200):
                for c050 in (0x00, 0x20, 0x08, 0x88):
                    for i in range(N // 5 + 1):
                        init, over = make_init(rng, marker, zone2, bfb8, c050)
                        for case in (4, 0x20):
                            cand, evc = run(CAND, [('call', 'FUN_0802d230', (case,)), ('ticks', NTICKS)], over=over, init_bytes=init)
                            # ---- reference: stock firmware, marker pre-cleared by the oracle (CEC must never request DEEP)
                            over_ref = dict(over)
                            over_ref['c038'] = over['c038'] & 0x7F
                            if zone2:
                                ref_entry = ('call', 'FUN_0802d230', (case,))
                            else:
                                ref_entry = ('call', 'FUN_080192e2')
                            steps = [ref_entry]
                            deferred = (bfb8 >= 100) and not (c050 & 0x08)
                            if deferred:
                                steps.append(('poke8', A['b2b5'], 100))
                            steps.append(('ticks', NTICKS))
                            ref, evr = run(PRISTINE, steps, over=over_ref, init_bytes=init)
                            if bad(evc) or bad(evr):
                                stats['skipped'] += 1
                                continue
                            stats['runs'] += 1
                            # absolute property: never deep, ON cleared, exactly one shutdown
                            if deep(cand, evc, over['c09c']) or on(cand) or shutdowns(evc) != 1 or not marker_clean(cand):
                                fails.append(('ABS', marker, zone2, bfb8, hex(c050), hex(case), deep(cand, evc, over['c09c']), on(cand), shutdowns(evc), marker_clean(cand)))
                                continue
                            stats['abs_ok'] += 1
                            if (bfb8 >= 100 and (c050 & 0x08)):
                                # stock reference would shut down immediately (forced); candidate defers: only absolute check
                                stats['abs_only_force_early'] += 1
                                continue
                            same_ram = ram_nodisp(cand) == ram_nodisp(ref)
                            nc, nr = norm2(evc), norm2(evr)
                            # the helper's own countdown-cancel stores (strb c2b5=0; strb c2b6=0) appear as exactly one
                            # adjacent pair that stock never writes; remove it (RAM equality below still checks the end state)
                            pair = [i for i in range(len(nc) - 1) if nc[i] == ('W', 'b2b5', 0) and nc[i + 1] == ('W', 'b2b6', 0)]
                            if len(pair) != 1:
                                fails.append(('CLEAR-WRITES', marker, zone2, bfb8, hex(c050), hex(case), len(pair)))
                                continue
                            del nc[pair[0]:pair[0] + 2]
                            if deferred:
                                # the helper's own deferral store (strb c2b5=100); the reference models it with a silent poke8.
                                # Exactly one such event must exist, and only in the deferred class.
                                if nc.count(('W', 'b2b5', 100)) != 1:
                                    fails.append(('DEFER-WRITE', marker, zone2, bfb8, hex(c050), hex(case), nc.count(('W', 'b2b5', 100))))
                                    continue
                                nc.remove(('W', 'b2b5', 100))
                            same_ev = nc == nr
                            if same_ram and same_ev:
                                stats['diff_equal'] += 1
                            else:
                                fails.append(('DIFF', marker, zone2, bfb8, hex(c050), hex(case), same_ram, same_ev))
    print('  stats:', dict(stats))
    print('  FAILS:', len(fails))
    for f in fails[:15]:
        print('   ', f)
    return len(fails)


# ---------------------------------------------------------------------------------------------
# 4. cave callback trampoline (0x080c8a0e): runs the 0x080c8a12 `bl helper`, must equal the helper alone
# ---------------------------------------------------------------------------------------------
def trampoline():
    print('\n== 4. cave callback trampoline ==')
    fails = 0
    for marker, bfb8, zone2 in itertools.product((0, 0x80), (0, 99, 100, 200), (0, 1)):
        over = dict(c038=marker, bfb8=bfb8, c09c=zone2, b2b5=0, b2b6=0, bfd8=0)
        # (a) helper alone
        a, eva = run(CAND, [('call', 'cec_sleep_helper'), ('ticks', NTICKS)], over=over)
        # (b) trampoline body from 0x080c8a12 (the `bl helper`) up to the following `b.w` at 0x080c8a16
        emu = Emu(CAND, whitelist=WL)
        poweron_state(emu, **over)
        uc = emu.uc
        uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM_REG_LR, SENT | 1)
        uc.emu_start(0x080C8A12 | 1, 0x080C8A16)
        pc = uc.reg_read(UC_ARM_REG_PC)
        okpc = (pc == 0x080C8A16)
        emu.ticks(NTICKS)
        evb = [e for e in emu.events if e[0] not in ('STEP', 'TICK')]
        same = (a.ram_image() == emu.ram_image())
        if not (okpc and same and not deep(emu, evb)):
            fails += 1
            print('  FAIL', over, 'pc', hex(pc), 'same', same, 'deep', deep(emu, evb))
    print('  failures:', fails)
    return fails


# ---------------------------------------------------------------------------------------------
# 5. countdown overlap (reviewer blocker): c2b5/c2b6 already pending when the helper runs; repeated Standby
# ---------------------------------------------------------------------------------------------
def invariants(emu, ev):
    """what must hold after ANY sequence of CEC Standby requests on the candidate"""
    return dict(no_err=not bad(ev), not_deep=not deep(emu, ev), off=not on(emu), one_entry=shutdowns(ev) == 1,
                marker_clean=marker_clean(emu))


def countdown_unit():
    print('\n== 5a. helper entered with c2b5/c2b6 already pending ==')
    fails = n = 0
    vals = (0, 1, 50, 100)
    for b5, b6, bfb8, c050, zone2 in itertools.product(
            vals, vals, (0, 50, 99, 100, 150, 200), (0x00, 0x08, 0x80, 0x88), (0, 1)):
        over = dict(c038=0x80, c09c=zone2, bfb8=bfb8, c050=c050, b2b5=b5, b2b6=b6, bfd8=0)
        emu, ev = run(CAND, [('call', 'cec_sleep_helper'), ('ticks', NTICKS)], over=over)
        n += 1
        immediate = bfb8 < 100 and bool(zone2 or c050 & 0x88)
        inv, ft = invariants(emu, ev), first_shutdown_tick(emu)
        # independent timing oracle: forced shutdown right away, else exactly one ~2 s countdown (100 ticks)
        if not (all(inv.values()) and ft == (0 if immediate else 100)):
            fails += 1
            print('  FAIL', over, [k for k, v in inv.items() if not v], 'first_shutdown_tick', ft)
    print('  %d runs, %d failures' % (n, fails))
    return fails


def seq_steps(sched):
    steps = [('call', 'FUN_08019272')]          # wake from OFF: power-on sequence, bfb8 = 200
    for d, case in sched:
        steps += [('ticks', d), ('call', 'FUN_0802d230', (case,))]
    steps.append(('ticks', NTICKS))
    return steps


def seq_model(sched):
    """independent oracle (Zone 2 off, no c050 bits): a Standby that arrives while the receiver is still ON
    (re)starts ONE ~2 s countdown; one that arrives after the shutdown has begun changes nothing"""
    t, due = 0, None
    for d, _ in sched:
        t += d
        if due is None or t < due:
            due = t + 100
    return due


WAKE_OVER = dict(c030=0, bfb8=0, b2b5=0, b2b6=0, bfd8=0)


def reviewer_trace():
    """the reviewer's reproduction: wake, Standby @50 (deferred), Standby @110 -> must be ONE shutdown entry"""
    print('\n== 5b. reviewer trace: wake, Standby @50, Standby @110 ==')
    sched = [(50, 4), (60, 4)]
    emu, ev = run(CAND, seq_steps(sched), over=dict(WAKE_OVER, c038=0))
    inv, ft = invariants(emu, ev), first_shutdown_tick(emu)
    ok = all(inv.values()) and ft == seq_model(sched) == 210
    print('  shutdown entries=%d first_tick=%s invariants=%s -> %s' % (shutdowns(ev), ft, inv, 'OK' if ok else 'FAIL'))
    return 0 if ok else 1


def countdown_seq(n=400, seed=777):
    print('\n== 5c. wake + random CEC Standby sequences (deferral window and fade) ==')
    rng = random.Random(seed)
    fails = 0
    stats = collections.Counter()
    for i in range(n):
        k = rng.randrange(1, 5)
        sched = []
        for j in range(k):
            d = rng.choice((0, 1, 2, 3, rng.randrange(4, 60), rng.randrange(60, 130), rng.randrange(130, 260)))
            sched.append((d, rng.choice((4, 0x20)) if j == 0 else 4))
        std = rng.random() < 0.5
        over = dict(WAKE_OVER, c038=rng.choice((0x00, 0x80)),
                    c09c=0 if std else rng.randrange(2), c050=0 if std else rng.choice((0x00, 0x08, 0x80, 0x88)))
        emu, ev = run(CAND, seq_steps(sched), over=over)
        inv, ft = invariants(emu, ev), first_shutdown_tick(emu)
        ok = all(inv.values())
        if std:
            ok = ok and ft == seq_model(sched)
            stats['std'] += 1
        t, seen = 0, 0
        due = None
        for d, _ in sched:
            t += d
            if due is None or t < due:
                seen += 1
                due = t + 100
        stats['standbys_while_on>=2'] += seen >= 2
        stats['first_in_deferral_window(t<=100)'] += sched[0][0] <= 100
        stats['ok' if ok else 'FAIL'] += 1
        if not ok:
            fails += 1
            print('  FAIL', sched, over, [k for k, v in inv.items() if not v], 'first', ft, 'model', seq_model(sched))
    print('  %d runs, %d failures; stats %s' % (n, fails, dict(stats)))
    return fails


if __name__ == '__main__':
    print('candidate:', CAND_PATH)
    reference_signatures()
    total = 0
    total += unit_helper()
    total += matrix()
    total += trampoline()
    total += countdown_unit()
    total += reviewer_trace()
    total += countdown_seq(max(400, 8 * int(sys.argv[2])) if len(sys.argv) > 2 else 400)
    total += differential(int(sys.argv[2]) if len(sys.argv) > 2 else 25, int(sys.argv[3]) if len(sys.argv) > 3 else 4242)
    print('\nTOTAL FAILURES:', total)
